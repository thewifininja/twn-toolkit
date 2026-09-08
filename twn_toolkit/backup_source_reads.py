"""Bound source reads and JSON parsing during portable configuration exports."""
from contextlib import contextmanager
from copy import copy
import sqlite3
from contextvars import ContextVar
import json
import os
from pathlib import Path
import stat

from .sqlite_incremental import ReadSnapshot


_budget = ContextVar('backup_source_budget', default=None)


class SourceReadLimit(RuntimeError):
    """Cannot safely read selected backup data; never substitute defaults."""


@contextmanager
def bounded_source_reads(maximum):
    token = _budget.set([maximum, 500_000])
    try:
        yield
    finally:
        _budget.reset(token)


def current_source_budget():
    return _budget.get()


def checked_source_json_text(data):
    budget = _budget.get()
    try:
        text = data.decode('utf-8') if isinstance(data, bytes) else data
    except UnicodeError as exc:
        raise SourceReadLimit('Backup source contains invalid UTF-8.') from exc
    if budget is None:
        return text
    quoted = escaped = False
    depth = 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            budget[1] -= 1
        elif char in '[{':
            depth += 1
            budget[1] -= 1
            if depth > 64:
                raise SourceReadLimit('Backup source JSON nesting exceeds 64 levels.')
        elif char in ']}':
            depth -= 1
        elif char == ',':
            budget[1] -= 1
        if budget[1] < 0:
            raise SourceReadLimit('Backup source JSON is too complex to export.')
    return text


def source_json_loads(data):
    if _budget.get() is None:
        return json.loads(data)
    text = checked_source_json_text(data)
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise SourceReadLimit('Backup source contains invalid JSON.') from exc


def read_json_file(path):
    budget = _budget.get()
    if budget is None:
        with Path(path).open('r', encoding='utf-8') as source:
            return json.load(source)
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SourceReadLimit('Backup JSON source must be a regular file.')
        if info.st_size > budget[0]:
            raise SourceReadLimit('Selected backup source data exceeds the read limit. Export fewer groups or reduce a large source file.')
        parts = []
        used = 0
        with os.fdopen(descriptor, 'rb') as source:
            descriptor = None
            while True:
                chunk = source.read(min(65536, budget[0] - used + 1))
                if not chunk:
                    break
                used += len(chunk)
                if used > budget[0]:
                    raise SourceReadLimit('Selected backup source data exceeds the read limit.')
                parts.append(chunk)
        budget[0] -= used
        raw = b''.join(parts)
        del parts
        return source_json_loads(raw)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise SourceReadLimit('Could not read a selected backup source file.') from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _quoted(name):
    return '"' + name.replace('"', '""') + '"'


@contextmanager
def configuration_snapshot(store, tables, *, empty_tables=(), maximum=64*1024*1024):
    """Copy bounded configuration cells into an owned, read-only memory database.

    Reuse the adapters' projections and cipher without redirecting the original
    store or copying runtime history. One native snapshot covers all input tables.
    """
    budget = current_source_budget()
    if budget is None:
        budget = [maximum, 500_000]
    remaining = budget[0]
    target = sqlite3.connect(':memory:')
    target.row_factory = sqlite3.Row

    def charge(size):
        nonlocal remaining
        remaining -= size
        if remaining < 0:
            raise ValueError(
                'Selected backup source data exceeds the read limit. '
                'Export fewer groups or reduce a large source.'
            )

    try:
        with ReadSnapshot(store.path) as source:
            for table in (*tables, *empty_tables):
                table_sql = _quoted(table)
                columns = source.query(f'PRAGMA table_info({table_sql})')
                if not columns:
                    raise ValueError('Backup configuration table is unavailable.')
                names = [str(column[1]) for column in columns]
                schema = source.query(
                    'SELECT sql FROM sqlite_master WHERE type=? AND name=?',
                    ('table', table),
                )[0][0]
                charge(len(schema.encode('utf-8')))
                # Original schema preserves primary-key indexes used by adapters.
                target.execute(schema)
                if table in empty_tables:
                    continue
                type_columns = ','.join(f'typeof({_quoted(name)})' for name in names)
                type_query = f'SELECT {type_columns} FROM {table_sql} WHERE rowid=?'
                placeholders = ','.join('?' for name in names)
                insert = f'INSERT INTO {table_sql} VALUES ({placeholders})'
                last = None
                rows = 0
                while True:
                    query = f'SELECT rowid FROM {table_sql}'
                    if last is None:
                        page = source.query(query + ' ORDER BY rowid LIMIT 100')
                    else:
                        page = source.query(
                            query + ' WHERE rowid>? ORDER BY rowid LIMIT 100', (last,),
                        )
                    if not page:
                        break
                    for (rowid,) in page:
                        rows += 1
                        if rows > 10000:
                            raise ValueError('Backup source table exceeds 10000 records.')
                        values = []
                        kinds = source.query(type_query, (rowid,))[0]
                        for name, kind in zip(names, kinds):
                            charge(32)
                            if kind in ('text', 'blob'):
                                raw, size = source.read_blob(
                                    table, name, rowid, cap=min(remaining, 64*1024*1024),
                                )
                                if raw is None:
                                    raise ValueError('Selected backup source data exceeds the read limit. Export fewer groups or reduce a large source.')
                                charge(size)
                                value = raw.decode(source.encoding) if kind == 'text' else raw
                            elif kind == 'null':
                                value = None
                            else:
                                value = source.query(
                                    f'SELECT {_quoted(name)} FROM {table_sql} WHERE rowid=?',
                                    (rowid,),
                                )[0][0]
                            values.append(value)
                        target.execute(insert, values)
                        last = rowid
        budget[0] = remaining
        target.commit()
        target.execute('PRAGMA query_only=ON')

        @contextmanager
        def connection():
            yield target

        bounded = copy(store)
        bounded._connect = connection
        yield bounded
    except sqlite3.Error as exc:
        raise SourceReadLimit('Could not read selected SQLite configuration safely.') from exc
    finally:
        target.close()


@contextmanager
def bounded_backup_store(adapter, *, rollback=False):
    if current_source_budget() is None:
        yield adapter
        return
    from .automation import AutomationBackupStore
    from .configuration_backup_stores import (
        RemoteConnectionBackupStore, CertificateAutomationProfilesBackupStore,
    )
    if isinstance(adapter, AutomationBackupStore):
        tables = ('automations', 'automation_conditions', 'automation_actions')
        if rollback:
            tables += ('automation_event_state',)
        empty = ()
    elif isinstance(adapter, RemoteConnectionBackupStore):
        tables = ('remote_connection_folders', 'remote_connection_credentials', 'remote_connection_hosts')
        empty = ()
    elif isinstance(adapter, CertificateAutomationProfilesBackupStore):
        tables = ('pki_credentials', 'pki_servers', 'pki_templates', 'managed_certificates')
        empty = ('certificate_versions',)
    else:
        yield adapter
        return
    with configuration_snapshot(adapter.store, tables, empty_tables=empty) as store:
        bounded = copy(adapter)
        bounded.store = store
        yield bounded

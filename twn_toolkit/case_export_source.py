"""Read selected case metadata without materializing oversized SQLite cells."""
from contextlib import contextmanager
import sqlite3

from .sqlite_incremental import ReadSnapshot
from .investigations import InvestigationError


class CaseExportLimitError(ValueError):
    pass


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


@contextmanager
def selected_case_snapshot(path, case_id, user_id, kind, maximum):
    """Copy only this case's selected records under one owned read snapshot."""
    remaining = maximum
    complexity = 500_000
    target = sqlite3.connect(':memory:')
    target.row_factory = sqlite3.Row

    def charge(size):
        nonlocal remaining
        remaining -= size
        if remaining < 0:
            raise CaseExportLimitError(
                'Case metadata exceeds the configured export input limit. '
                'Reduce the report selection or increase the limit in Settings → Operations.'
            )

    def guard_json(text):
        nonlocal complexity
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
                complexity -= 1
            elif char in '[{':
                depth += 1
                complexity -= 1
                if depth > 64:
                    raise CaseExportLimitError('Case metadata JSON exceeds the export nesting limit of 64 levels.')
            elif char in ']}':
                depth -= 1
            elif char == ',':
                complexity -= 1
            if complexity < 0:
                raise CaseExportLimitError('Case metadata JSON exceeds the export complexity limit. Reduce the report selection.')

    try:
        with ReadSnapshot(path) as source:
            if not source.query(
                'SELECT 1 FROM investigation_participants WHERE investigation_id=? AND user_id=?',
                (case_id, user_id),
            ):
                raise InvestigationError('Case not found.')

            def rows(table, where, params):
                last = None
                while True:
                    sql = f'SELECT rowid FROM {_quote(table)} WHERE ({where})'
                    if last is not None:
                        sql += ' AND rowid>?'
                    page = source.query(
                        sql + ' ORDER BY rowid LIMIT 100',
                        (*params, last) if last is not None else params,
                    )
                    if not page:
                        return
                    for (rowid,) in page:
                        yield rowid
                        last = rowid

            def cell(table, name, rowid, kind):
                charge(32)
                if kind in ('text', 'blob'):
                    raw, size = source.read_blob(table, name, rowid, cap=min(remaining, 64*1024*1024))
                    if raw is None:
                        charge(size)
                        raise CaseExportLimitError('A case metadata field exceeds the export read limit of 64 MiB.')
                    charge(size)
                    value = raw.decode(source.encoding) if kind == 'text' else raw
                    if name.endswith('_json'):
                        guard_json(value if isinstance(value, str) else value.decode(source.encoding))
                    return value
                if kind == 'null':
                    return None
                return source.query(f'SELECT {_quote(name)} FROM {_quote(table)} WHERE rowid=?', (rowid,))[0][0]

            tables = ('investigations', 'investigation_participants', 'investigation_imports',
                      'investigation_events', 'investigation_artifacts',
                      'investigation_event_origins', 'investigation_artifact_origins')
            for table in tables:
                schema = source.query('SELECT sql FROM sqlite_master WHERE type=? AND name=?', ('table', table))[0][0]
                charge(len(schema.encode()))
                target.execute(schema)
                names = [row[1] for row in source.query(f'PRAGMA table_info({_quote(table)})')]
                where = 'id=?' if table == 'investigations' else 'investigation_id=?'
                if kind != 'portable':
                    if table == 'investigation_events':
                        where += " AND report_placement='main'"
                    elif table == 'investigation_artifacts':
                        where += " AND report_placement='appendix'"
                    elif table == 'investigation_event_origins':
                        where += (
                            " AND (event_id IN (SELECT id FROM investigation_events "
                            "WHERE investigation_id=? AND report_placement='main') "
                            "OR event_id IN (SELECT event_id FROM investigation_artifacts "
                            "WHERE investigation_id=? AND report_placement='appendix'))"
                        )
                    elif table == 'investigation_artifact_origins':
                        where += (
                            " AND artifact_id IN (SELECT id FROM investigation_artifacts "
                            "WHERE investigation_id=? AND report_placement='appendix')"
                        )
                params = (case_id,) * where.count('?')
                types = ','.join(f'typeof({_quote(name)})' for name in names)
                for rowid in rows(table, where, params):
                    charge(1024)
                    kinds = source.query(f'SELECT {types} FROM {_quote(table)} WHERE rowid=?', (rowid,))[0]
                    values = [
                        cell(table, name, rowid, value_kind)
                        for name, value_kind in zip(names, kinds)
                    ]
                    placeholders = ','.join('?' for _ in names)
                    target.execute(f'INSERT INTO {_quote(table)} VALUES ({placeholders})', values)

            # Report counts and attribution cover the original case, including
            # excluded diagnostics, without reading their retained payloads.
            counts = {
                name: source.query(
                    f'SELECT COUNT(*) FROM investigation_{name} WHERE investigation_id=?',
                    (case_id,),
                )[0][0]
                for name in ('events', 'artifacts')
            }
            operator_names = set()
            if kind != 'portable':
                for rowid in rows('investigation_events', 'investigation_id=?', (case_id,)):
                    charge(32)
                    name = cell('investigation_events', 'created_by_username', rowid, 'text')
                    operator_names.add(name)
        target.commit()
        target.execute('PRAGMA query_only=ON')
        yield target, counts, operator_names
    finally:
        target.close()


def require_case_export_access(instance, case_id, user_id):
    """Authorize export routes without loading case descriptions or import JSON."""
    from .investigations import InvestigationStore
    with InvestigationStore(instance)._connect() as connection:
        exists = connection.execute(
            'SELECT 1 FROM investigations i JOIN investigation_participants p '
            'ON p.investigation_id=i.id WHERE i.id=? AND p.user_id=?',
            (case_id, user_id),
        ).fetchone()
    if not exists:
        raise InvestigationError('Case not found.')

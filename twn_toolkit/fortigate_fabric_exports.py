"""Bounded, identity-checked reads for the existing FortiGate export tasks."""
from __future__ import annotations

import csv
import json
from .fortigate import FortiGateError
from .fortigate_fabric import FabricTarget, InventoryError
from .tasks import discover_export_fields

IDENTITY_COLUMNS = ('FortiGate hostname', 'FortiGate serial', 'FortiGate VDOM')
MAX_EXPORT_ROWS = 10000
MAX_EXPORT_BYTES = 16 * 1024 * 1024


def read_exports(client, task, targets, *, endpoint, vdom, fields, mode, check):
    """Collect each saved target independently; never rediscover or broaden selection."""
    groups, all_rows = [], []
    calls = 0
    byte_count = 0
    with client.pooled() as pooled:
        for saved in targets:
            check()
            target = FabricTarget(**saved)
            group = dict(hostname=target.hostname, serial=target.serial, vdom=vdom,
                         row_count=0, error='', rows=[])
            groups.append(group)
            class Reader:
                def export_data(self, candidate, selected_vdom):
                    nonlocal calls
                    check()
                    calls += 1
                    result = target.get(pooled, candidate, selected_vdom)
                    if not isinstance(result, (dict, list)) or (isinstance(result, list) and any(not isinstance(row, dict) for row in result)):
                        raise InventoryError('Appliance returned an unexpected export shape.')
                    return {'results': result}
            try:
                rows, used = task.preview_rows_with_endpoint(Reader(), endpoint, vdom)
                if len(rows) + len(all_rows) > MAX_EXPORT_ROWS:
                    raise InventoryError('Export exceeds 10,000 rows; select fewer gates.')
                size = len(json.dumps(rows).encode())
                if byte_count + size > MAX_EXPORT_BYTES:
                    raise InventoryError('Export exceeds 16 MiB of collected data; select fewer gates.')
                byte_count += size
                group.update(row_count=len(rows), endpoint_used=used)
                group['_rows'] = rows
                all_rows.extend(rows)
            except FortiGateError as exc:
                group['error'] = (str(exc) if isinstance(exc, InventoryError) else
                                  'API access denied (HTTP 403).' if exc.status_code == 403 else
                                  'API authentication failed (HTTP 401).' if exc.status_code == 401 else
                                  'No supported endpoint available (HTTP 404).' if exc.status_code == 404 else
                                  'Read failed; check connectivity and API permissions.')
    partial = any(g['error'] for g in groups)
    data = dict(groups=groups, partial=partial, api_calls=calls, row_count=len(all_rows),
                successful_gates=sum(not g['error'] for g in groups),
                message='Some gates could not be read. Review their status below.' if partial else 'Selected gates read successfully.')
    if mode == 'fields':
        options = discover_export_fields(task, all_rows)
        if len(options) > 256:
            raise InventoryError('Field discovery exceeds 256 columns. Enter the required CSV fields directly.')
        data['fields'] = [{**f, 'sample':str(f.get('sample', ''))[:512]} for f in options]
    else:
        columns, _ = task.format_rows([], fields)
        if not columns:
            columns, _ = task.format_rows(all_rows, fields)
        if any(column in IDENTITY_COLUMNS for column in columns):
            raise InventoryError('Selected column names conflict with FortiGate identity columns.')
        if mode == 'preview' and len(columns) > 64:
            raise InventoryError('The browser preview supports 64 columns. Select fewer fields.')
        data['columns'] = list(IDENTITY_COLUMNS) + columns
        data['rows'], data['fields_clipped'] = [], False
        allowance = max(1, 100 // max(1, len(groups)))
        for group in groups:
            source = group.get('_rows', [])
            _, formatted = task.format_rows(source if mode == 'export' else source[:allowance], fields)
            identity = dict(zip(IDENTITY_COLUMNS, (group['hostname'], group['serial'], group['vdom'])))
            formatted = [{**row, **identity} for row in formatted]
            if mode == 'preview':
                data['fields_clipped'] |= any(len(str(v)) > 512 for row in formatted for v in row.values())
                formatted = [{k:str(v)[:512] if v is not None else '' for k,v in row.items()} for row in formatted]
                group['rows'] = formatted
                data['rows'].extend(formatted)
            else:
                group['_formatted'] = formatted
        data['preview_count'] = len(data['rows'])
    return data


def write_export(data, output):
    writer = csv.DictWriter(output, fieldnames=data['columns'], extrasaction='ignore')
    writer.writeheader()
    for group in data['groups']:
        writer.writerows(group.get('_formatted', []))


def public_summary(data):
    for group in data['groups']:
        group.pop('_rows', None)
        group.pop('_formatted', None)
    return data

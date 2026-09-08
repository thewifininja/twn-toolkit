"""Bounded read-only projections of retained automation history."""
import json

ROW_JSON_BYTES = 256 * 1024
PAGE_JSON_BYTES = 2 * 1024 * 1024
PAGE_ROWS = 100


class HistoryBudget:
    def __init__(self):
        self.bytes = PAGE_JSON_BYTES
        self.rows = PAGE_ROWS


def history_rows(connection, automation_id, *, checks=False, limit=10, offset=0, budget=None):
    budget = budget or HistoryBudget()
    limit = min(max(0, int(limit)), budget.rows)
    if not limit:
        return []
    field = 'evidence_json' if checks else 'results_json'
    table = 'automation_checks' if checks else 'automation_runs'
    stamp = 'checked_at' if checks else 'started_at'
    summary = 'summary' if checks else 'trigger_summary'
    extra = 'met' if checks else 'finished_at'
    # CASE keeps oversized JSON out of Python, including escaped/NUL-containing
    # text. Query one row at a time so every row observes the remaining budget.
    rows = []
    for index in range(limit):
        cap = min(ROW_JSON_BYTES, budget.bytes)
        row = connection.execute(f'''
            SELECT id,automation_id,{stamp},{extra},substr(status,1,32) AS status,
                   substr({summary},1,2048) AS {summary},
                   length({summary})>2048 AS summary_shortened,
                   CASE WHEN length(CAST({field} AS BLOB))<=? THEN {field} END AS payload
            FROM {table} WHERE automation_id=? ORDER BY {stamp} DESC,id DESC LIMIT 1 OFFSET ?
        ''', (cap, automation_id, offset + index)).fetchone()
        if row is None:
            break
        item = dict(row)
        raw = item.pop('payload')
        item['preview_limited'] = bool(item.pop('summary_shortened')) or raw is None
        value = {} if checks else []
        if raw is not None:
            budget.bytes -= len(raw.encode())
            try:
                value = json.loads(raw)
                if not isinstance(value, dict if checks else list):
                    value = {} if checks else []
                    item['preview_limited'] = True
            except (ValueError, RecursionError):
                item['preview_limited'] = True
        item['evidence' if checks else 'results'] = value
        budget.rows -= 1
        rows.append(item)
    return rows


def preview_value(value, budget, *, depth=0):
    """Project a loaded JSON value with bounded nodes, text and nesting."""
    if depth > 8 or budget['nodes'] <= 0 or budget['text'] <= 0:
        budget['limited'] = True
        return {} if isinstance(value, dict) else [] if isinstance(value, list) else ''
    budget['nodes'] -= 1
    if isinstance(value, str):
        cap = min(4096, budget['text'])
        budget['text'] -= min(len(value), cap)
        if len(value) > cap:
            budget['limited'] = True
        return value[:cap]
    if isinstance(value, (list, dict)):
        result = {} if isinstance(value, dict) else []
        entries = value.items() if isinstance(value, dict) else enumerate(value)
        for index, (key, child) in enumerate(entries):
            if index >= 20 or budget['nodes'] <= 0 or budget['text'] <= 0:
                budget['limited'] = True
                break
            projected = preview_value(child, budget, depth=depth + 1)
            if isinstance(result, dict):
                result[str(key)[:128]] = projected
            else:
                result.append(projected)
        return result
    return value

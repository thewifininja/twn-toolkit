import io
import json
import tracemalloc
import zipfile
from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.automation import AutomationStore
from twn_toolkit.automation_registry import ActionResult, ConditionResult
from twn_toolkit.automation_history import HistoryBudget, history_rows, preview_value
from twn_toolkit.operational import OperationalSettingsStore


@pytest.fixture
def setup(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0})
    store = AutomationStore(str(tmp_path), app.secret_key)
    aid = store.save(name='History fixture', interval_seconds=30, trigger_after=1,
        recover_after=1, cooldown_seconds=0, condition={'type':'manual.trigger','config':{}},
        actions=[{'type':'ssh.collect','config':{'hosts':'192.0.2.10','username':'fixture',
            'password':'fixture','commands':'show clock','port':22,'command_timeout':300,
            'allow_unknown_hosts':False,'send_ctrl_y':False}}], created_by='fixture')
    def record(summary='small', output=None):
        return store.record_run(aid, ConditionResult(True,'met','Manual',{}),
            [ActionResult('success',summary,output or {'hosts':[{'host':'192.0.2.10','output':'full output'}]})])
    return app, store, aid, record


def test_oversized_history_never_decodes_payload_and_download_is_complete(setup):
    app, store, aid, record = setup
    value = 'Large summary 中文😀' * 50_000
    rid = record(value)
    loads = json.loads
    def bounded_loads(raw, *args, **kwargs):
        assert len(raw) < 256 * 1024
        return loads(raw, *args, **kwargs)
    tracemalloc.start()
    try:
        with patch('twn_toolkit.automation_history.json.loads', side_effect=bounded_loads):
            snapshot = store.workspace_snapshot()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 3 * 1024 * 1024
    row = snapshot['recent_runs'][aid][0]
    assert row['preview_limited'] and row['results'] == []
    client = app.test_client()
    response = client.get(f'/automations?focus={aid}&focus_run={rid}')
    assert response.status_code == 200 and len(response.data) < 400_000
    assert b'preview shortened or omitted' in response.data
    response = client.get(f'/automations/runs/{rid}/download')
    try:
        with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
            assert json.loads(archive.read('action-1-summary.json'))['summary'] == value
    finally:
        response.close()


def test_workspace_row_budget_and_paged_access_preserve_older_runs(setup):
    app, store, aid, record = setup
    ids = {record('run '+str(i)) for i in range(25)}
    first = store.history_page(aid, page=1)
    second = store.history_page(aid, page=2)
    assert first['more'] and not second['more']
    assert len(first['runs']) == 20 and len(second['runs']) == 5
    assert {r['id'] for r in first['runs'] + second['runs']} == ids
    with store._connect() as db:
        budget = HistoryBudget(); budget.rows = 3
        assert len(history_rows(db, aid, limit=20, budget=budget)) == 3
        assert history_rows(db, aid, budget=budget) == []
    client = app.test_client()
    assert client.get(f'/automations/{aid}/history').status_code == 200
    assert b'Next' in client.get(f'/automations/{aid}/history').data
    assert client.get(f'/automations/{aid}/history?page=bad').status_code == 400
    assert client.get('/automations/missing/history').status_code == 404


def test_json_byte_budget_is_shared_across_rows(setup):
    _, store, aid, record = setup
    record('a' * 100_000); record('b' * 100_000)
    with store._connect() as db:
        budget = HistoryBudget(); budget.bytes = 150_000
        rows = history_rows(db, aid, budget=budget)
    assert len(rows) == 2
    assert not rows[0]['preview_limited'] and rows[1]['preview_limited']
    assert rows[1]['results'] == []


@pytest.mark.parametrize('raw', ['[' * 1000 + ']' * 1000, 'not json', 'null'], ids=['deep', 'malformed', 'null'])
def test_invalid_retained_json_does_not_break_history(setup, raw):
    app, store, aid, record = setup
    rid = record()
    with store._connect() as db:
        db.execute('UPDATE automation_runs SET results_json=? WHERE id=?', (raw, rid))
    response = app.test_client().get(f'/automations?focus={aid}&focus_run={rid}')
    assert response.status_code == 200
    assert b'preview shortened or omitted' in response.data


def test_projection_limits_aggregate_nodes_text_and_does_not_change_source():
    value = [{'summary':'x'*100_000, 'output':{'hosts':[{'host':'x','output':'z'*10_000}]*5000}}]*100
    budget = {'text': 20_000, 'nodes':100, 'limited':False}
    result = preview_value(value, budget)
    assert budget['limited'] and len(json.dumps(result)) < 30_000
    assert len(value) == 100 and len(value[0]['summary']) == 100_000


def test_exhausted_display_budget_keeps_valid_result_shapes(setup):
    app, store, aid, record = setup
    for _ in range(10):
        record('summary', {'hosts': [{'host':'fixture','output':'x'*4000} for _ in range(20)]})
    response = app.test_client().get(f'/automations?focus={aid}')
    assert response.status_code == 200
    assert len(response.data) < 600_000
    assert b'preview shortened or omitted' in response.data


def test_history_requires_authenticated_admin(setup):
    from twn_toolkit.auth import AuthStore
    app, _, aid, record = setup
    record()
    auth = AuthStore(app.instance_path)
    auth.create_user('owner', 'TemporaryPassword123!', is_admin=True)
    auth.create_user('viewer', 'TemporaryPassword123!', is_admin=False)
    app.testing = False
    client = app.test_client()
    assert client.get(f'/automations/{aid}/history').status_code == 302
    client.post('/login', data={'username':'viewer','password':'TemporaryPassword123!'})
    assert client.get(f'/automations/{aid}/history').status_code == 403

from __future__ import annotations

import copy
import json
from unittest.mock import patch

import pytest

from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.mso import BATCH, MsoConflict, MsoStore
from twn_toolkit.profiles import PingProfileStore, DNSProfileStore


def profile(name="WAN", host="192.0.2.1"):
    return {"name": name, "targets": [{"host": host, "label": ""}], "interval": 2, "timeout": 1, "health_thresholds": {}}


def node(path, role):
    settings = DistributedSettingsStore(path)
    settings.save({**settings.get(), "role": role, "agent_mainframe_url": "https://mainframe.example:7443"})
    return MsoStore(path)


@pytest.fixture
def fleet(tmp_path):
    return node(tmp_path / "main", "mainframe"), node(tmp_path / "a", "agent"), node(tmp_path / "b", "agent")


def sync(main, agent):
    request = agent.request()
    response = main.exchange(agent.node, request)
    agent.receive(response, request)
    return response


def only(store):
    return store.profiles(metadata=True)[0]


def test_migration_identity_duplicate_and_local_default(tmp_path):
    (tmp_path / "ping_profiles.json").write_text(json.dumps([profile()]))
    store = MsoStore(tmp_path)
    original = only(store)
    assert original["mso"]["state"] == "Local"
    assert MsoStore(tmp_path).profiles(metadata=True) == [original]
    assert store.request()["proposals"] == []
    renamed = store.save(profile("Renamed"), "WAN")
    assert renamed["mso"]["id"] == original["mso"]["id"]
    PingProfileStore(tmp_path).duplicate("Renamed")
    assert len({p["mso"]["id"] for p in store.profiles(metadata=True)}) == 2
    assert all(not p["mso"]["enabled"] for p in store.profiles(metadata=True))
    assert store.path.stat().st_mode & 0o777 == 0o600
    dns = DNSProfileStore(tmp_path, "hosts")
    dns.upsert({"name": "DNS", "hosts": "example.org"})
    assert dns.get("DNS")["name"] == "DNS"
    assert dns.mso_store().profiles(metadata=True)[0]["mso"]["state"] == "Local"


def test_bidirectional_rename_edit_and_late_join(fleet):
    main, a, b = fleet
    created = a.save(profile(), enabled=True)
    sync(main, a)
    sync(main, b)
    assert only(a)["mso"]["state"] == "Synced"
    assert only(b)["mso"]["id"] == created["mso"]["id"]
    b.save(profile("Branch", "192.0.2.2"), "WAN")
    sync(main, b)
    sync(main, a)
    assert only(main)["targets"][0]["host"] == "192.0.2.2"
    assert only(a)["name"] == "Branch"
    assert only(a)["mso"]["origin"] == a.node
    main.save(profile("HQ", "192.0.2.3"), "Branch")
    sync(main, a)
    assert only(a)["name"] == "HQ"


@pytest.mark.parametrize("actor", ["main", "origin", "replica"])
def test_any_instance_can_withdraw_keep_local_and_delete_replicas(fleet, actor):
    main, a, b = fleet
    original = a.save(profile(), enabled=True)
    sync(main, a)
    sync(main, b)
    acting = {"main": main, "origin": a, "replica": b}[actor]
    local = acting.save(profile(), enabled=False)
    assert not local["mso"]["enabled"]
    assert local["mso"]["id"] != original["mso"]["id"]
    if acting != main:
        sync(main, acting)
    sync(main, a)
    sync(main, b)
    for store in fleet:
        assert len(store.profiles()) == (1 if store is acting else 0)


def test_replica_delete_is_global_and_never_resurrects(fleet):
    main, a, b = fleet
    main.save(profile(), enabled=True)
    sync(main, a)
    sync(main, b)
    a.save(profile(host="192.0.2.9"))  # offline draft
    b.delete("WAN")
    sync(main, b)
    sync(main, a)
    draft = only(a)
    assert draft["mso"]["state"] == "Conflict"
    assert draft["mso"]["conflict"]["remote"]["deleted"]
    with pytest.raises(ValueError, match="removed"):
        a.resolve(draft["mso"]["id"], "local", draft["mso"]["version"])
    copied = PingProfileStore(a.instance).duplicate("WAN")
    a.resolve(draft["mso"]["id"], "fleet", draft["mso"]["version"])
    assert only(a)["name"] == copied["name"]
    assert main.profiles() == []


def test_lost_ack_is_idempotent_and_edits_during_delivery_survive(fleet):
    main, a, _ = fleet
    a.save(profile(), enabled=True)
    sent = a.request()
    response = main.exchange(a.node, sent)
    a.save(profile(host="192.0.2.2"))
    assert a.request() == sent
    replay = main.exchange(a.node, sent)
    assert response["acknowledgements"] == replay["acknowledgements"]
    a.receive(replay, sent)
    assert only(a)["targets"][0]["host"] == "192.0.2.2"
    assert only(a)["mso"]["state"] == "Pending"
    sync(main, a)
    assert only(main)["targets"][0]["host"] == "192.0.2.2"
    assert only(a)["mso"]["state"] == "Synced"


@pytest.mark.parametrize("choice", ["fleet", "local"])
def test_concurrent_changes_require_explicit_resolution(fleet, choice):
    main, a, b = fleet
    main.save(profile(), enabled=True)
    sync(main, a)
    sync(main, b)
    a.save(profile(host="192.0.2.2"))
    b.save(profile(host="192.0.2.3"))
    sync(main, a)
    sync(main, b)
    draft = only(b)
    assert draft["targets"][0]["host"] == "192.0.2.3"
    assert draft["mso"]["state"] == "Conflict"
    b.resolve(draft["mso"]["id"], choice, draft["mso"]["version"])
    sync(main, b)
    sync(main, a)
    expected = "192.0.2.2" if choice == "fleet" else "192.0.2.3"
    assert all(only(store)["targets"][0]["host"] == expected for store in fleet)


def test_name_collision_preserves_both_and_resolves_after_local_rename(fleet):
    main, a, _ = fleet
    a.save(profile(host="192.0.2.2"))
    main.save(profile(), enabled=True)
    sync(main, a)
    assert len(a.profiles()) == 2
    incoming = next(p for p in a.profiles(metadata=True) if p["mso"]["enabled"])
    assert incoming["mso"]["state"] == "Conflict"
    a.save(profile("My WAN", "192.0.2.2"), "WAN")
    a.resolve(incoming["mso"]["id"], "fleet", incoming["mso"]["version"])
    assert {p["name"] for p in a.profiles()} == {"WAN", "My WAN"}


def test_detach_preserves_local_data_and_rejects_late_reply(fleet):
    main, a, _ = fleet
    main.save(profile(), enabled=True)
    sync(main, a)
    original = only(a)
    sent = a.request()
    response = main.exchange(a.node, sent)
    a.settings.save({**a.settings.get(), "role": "standalone"})
    detached = only(a)
    assert detached["mso"]["state"] == "Local"
    assert detached["mso"]["id"] != original["mso"]["id"]
    a.settings.save({**a.settings.get(), "role": "agent"})
    a.receive(response, sent)
    assert a.request()["fleet"] == ""
    assert only(a) == detached


def test_batches_bootstrap_and_atomic_rejection(fleet):
    main, a, _ = fleet
    for i in range(BATCH * 2 + 1):
        main.save(profile(str(i)), enabled=True)
    for _ in range(3):
        assert len(sync(main, a)["objects"]) <= BATCH
    assert len(a.profiles()) == BATCH * 2 + 1
    a.save(profile("new"), enabled=True)
    sent = a.request()
    invalid = copy.deepcopy(sent["proposals"][0])
    invalid["kind"] = "arbitrary.file"
    sent["proposals"].append(invalid)
    with pytest.raises(ValueError, match="Unsupported"):
        main.exchange(a.node, sent)
    assert not any(p["name"] == "new" for p in main.profiles())


@pytest.mark.parametrize("corrupt", ["cursor", "order", "identity", "ack"])
def test_bad_reply_cannot_partially_commit(fleet, corrupt):
    main, a, _ = fleet
    a.save(profile(), enabled=True)
    sent = a.request()
    response = main.exchange(a.node, sent)
    if corrupt == "cursor": response["cursor"] = -1
    if corrupt == "order": response["objects"][0]["revision"] = 0
    if corrupt == "identity": response["fleet"] = "bad"
    if corrupt == "ack": response["acknowledgements"] = []
    with pytest.raises(ValueError): a.receive(response, sent)
    assert a.request() == sent
    assert only(a)["mso"]["state"] == "Pending"


def test_stale_forms_and_import_never_silently_replace_shared_data(fleet):
    main, a, _ = fleet
    saved = main.save(profile(), enabled=True)
    with pytest.raises(MsoConflict): main.save(profile(), guarded=True)
    with pytest.raises(MsoConflict): main.delete("WAN", guarded=True)
    with pytest.raises(ValueError): main.save(profile(), enabled="false")
    with pytest.raises(ValueError): PingProfileStore(main.instance).replace_all([])
    main.save(profile("Renamed"), "WAN")
    with pytest.raises(MsoConflict):
        main.save(profile(), "WAN", object_id=saved["mso"]["id"], expected=saved["mso"]["version"])
    assert only(main)["name"] == "Renamed"


def test_failed_sqlite_import_rolls_back(tmp_path):
    store = MsoStore(tmp_path)
    store.save(profile())
    with pytest.raises(ValueError):
        store.replace_local([profile("replacement"), {"name": "bad", "timeout": float("nan")}])
    assert only(store)["name"] == "WAN"


def test_authenticated_transport_sync_and_revocation(tmp_path):
    from twn_toolkit.distributed_transport import EnrollmentClient, EnrollmentServer, EnrollmentTransportError
    main = node(tmp_path / "main", "mainframe")
    a = node(tmp_path / "agent", "agent")
    server = EnrollmentServer(main.instance, "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    try:
        client = EnrollmentClient(a.instance, f"https://127.0.0.1:{server.port}")
        client.begin("MSO pilot")
        with pytest.raises(ValueError, match="certificate"):
            server.mso_exchange(None, a.request())
        agent = server.agent_store.list("pending")[0]
        server.agent_store.set_state(agent["id"], "approved")
        client.poll()
        main.save(profile(), enabled=True)
        request = a.request()
        a.receive(client.mso_exchange(request), request)
        assert only(a)["name"] == "WAN"
        a.save(profile("Agent change"), "WAN")
        request = a.request()
        a.receive(client.mso_exchange(request), request)
        assert only(main)["name"] == "Agent change"
        origin = a.save(profile("Origin proof"), enabled=True)
        request = a.request()
        a.receive(client.mso_exchange(request), request)
        assert main.profile(origin["mso"]["id"])["mso"]["origin"] == a.node
        assert a.profile(origin["mso"]["id"])["mso"]["origin"] == a.node
        server.agent_store.set_state(agent["id"], "revoked")
        with pytest.raises(EnrollmentTransportError, match="400"):
            client.mso_exchange(a.request())
    finally:
        server.stop()


def test_sync_failure_does_not_report_working_agent_disconnected(fleet):
    from twn_toolkit.distributed_worker import _agent_tick
    from twn_toolkit.distributed_transport import EnrollmentTransportError
    main, a, _ = fleet
    with patch("twn_toolkit.distributed_worker.EnrollmentClient") as constructor:
        client = constructor.return_value
        client.pending.return_value = False
        client.enrolled.return_value = True
        client.heartbeat.return_value = {"job_protocol": 2, "mso_protocol": 1, "state": "connected"}
        client.mso_exchange.side_effect = EnrollmentTransportError("Mainframe sync unavailable")
        status = _agent_tick(a.instance, a.settings.get(), control_only=True)
        assert status["state"] == "connected"
        assert "unavailable" in a.sync_status()["error"]
        client.reset_mock()
        client.heartbeat.return_value = {"job_protocol": 2, "state": "connected"}
        assert _agent_tick(a.instance, a.settings.get(), control_only=True)["state"] == "connected"
        client.mso_exchange.assert_not_called()


def test_backup_rollback_preserves_shared_identity_and_pending_operations(fleet):
    from twn_toolkit.backup_source_reads import bounded_source_reads, SourceReadLimit
    _, a, _ = fleet
    a.save(profile(), enabled=True)
    sent = a.request()
    store = PingProfileStore(a.instance)
    snapshot = store.backup_snapshot()
    with pytest.raises(ValueError): store.replace_all([])
    store.restore_backup_snapshot(snapshot)
    assert a.request() == sent
    with bounded_source_reads(10), pytest.raises(SourceReadLimit): store.all()


def test_web_toggle_stale_forms_and_central_conflict_resolution(fleet):
    from twn_toolkit.app import create_app
    main, a, _ = fleet
    app = create_app(instance_path=str(a.instance))
    app.config["TESTING"] = True
    client = app.test_client()
    created = client.post("/tools/ping/profiles", json={"name": "WAN", "hosts": "192.0.2.1", "mso_enabled": True})
    assert created.status_code == 200
    saved = created.json["profile"]
    sync(main, a)
    assert client.post("/tools/ping/profiles", json={"name": "WAN", "hosts": "192.0.2.2"}).status_code == 409
    assert client.post("/tools/ping/profiles/delete", json={"name": "WAN"}).status_code == 409
    assert client.get("/tools/ping/profiles/status", query_string={"id": saved["mso"]["id"]}).json["profile"]["mso"]["state"] == "Synced"
    a.save(profile(host="192.0.2.2"))
    main.save(profile(host="192.0.2.3"))
    sync(main, a)
    page = client.get("/tools/ping")
    assert b'MSO conflicts' in page.data
    assert b'data-saved-profile-always-more' in page.data
    assert b'Use fleet version' not in page.data
    conflict_page = client.get("/tools/mso/conflicts")
    assert b'192.0.2.2' in conflict_page.data and b'192.0.2.3' in conflict_page.data
    conflict = only(a)["mso"]
    response = client.post("/tools/mso/conflicts/resolve", data={"object_id": conflict["id"], "version": conflict["version"], "choice": "fleet"})
    assert response.status_code == 302
    assert only(a)["targets"][0]["host"] == "192.0.2.3"
    assert b'No MSO conflicts' in client.get("/tools/mso/conflicts").data


def test_conflict_workspace_uses_existing_tool_permissions(fleet):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    _, a, _ = fleet
    auth = AuthStore(a.instance)
    auth.create_user('admin', 'Temporary admin password', is_admin=True)
    allowed = auth.save_access_profile(name='Ping', tool_ids=['tools.ping'])
    denied = auth.save_access_profile(name='IP information', tool_ids=['tools.ip_info'])
    auth.create_user('allowed', 'Temporary user password', access_profile_ids=[allowed['id']])
    auth.create_user('denied', 'Temporary user password', access_profile_ids=[denied['id']])
    app = create_app(str(a.instance))
    for username, code in [('allowed', 200), ('denied', 403)]:
        client = app.test_client()
        client.post('/login', data={'username':username, 'password':'Temporary user password'})
        assert client.get('/tools/mso/conflicts').status_code == code
        assert client.get('/tools/ping/profiles/status').status_code == code
        if code == 403:
            assert client.post('/tools/mso/conflicts/resolve', data={}).status_code == 403
            assert client.post('/tools/ping/profiles', json={}).status_code == 403


def test_withdrawal_conflict_keeps_local_copy_distinguishable(fleet):
    main, a, _ = fleet
    main.save(profile(), enabled=True)
    sync(main, a)
    a.save(profile(), enabled=False)
    main.save(profile(host='192.0.2.2'))
    sync(main, a)
    profiles = a.profiles(metadata=True)
    assert len(profiles) == 2
    assert len({p['name'] for p in profiles}) == 2
    assert all(a.profile(p['mso']['id']) == p for p in profiles)
    conflict = next(p for p in profiles if p['mso']['conflict'])
    a.resolve(conflict['mso']['id'], 'local', conflict['mso']['version'])
    sync(main, a)
    assert len(a.profiles()) == 1 and main.profiles() == []


def _paused_mso_writer(instance, ready, release):
    store = MsoStore(instance)
    guard = store._guard
    def paused(*args):
        guard(*args)
        ready.set()
        if not release.wait(15): raise TimeoutError('Writer was not released')
    store._guard = paused
    store.save(profile('first'))


def _second_mso_writer(instance, started, done):
    started.set()
    MsoStore(instance).save(profile('second'))
    done.set()


def test_mso_concurrent_process_writers_preserve_both_profiles(tmp_path):
    import multiprocessing
    context = multiprocessing.get_context('spawn')
    ready, release, started, done = (context.Event() for _ in range(4))
    first = context.Process(target=_paused_mso_writer, args=(tmp_path, ready, release))
    second = context.Process(target=_second_mso_writer, args=(tmp_path, started, done))
    first.start()
    try:
        assert ready.wait(15)
        second.start()
        assert started.wait(15)
        assert not done.wait(.5)
        release.set()
        first.join(15)
        second.join(15)
        assert first.exitcode == second.exitcode == 0
        assert [p['name'] for p in MsoStore(tmp_path).profiles()] == ['first', 'second']
    finally:
        release.set()
        for process in (first, second):
            if process.pid:
                if process.is_alive(): process.terminate()
                process.join(15)


def test_failed_coordination_change_preserves_membership(fleet):
    main, a, _ = fleet
    main.save(profile(), enabled=True)
    sync(main, a)
    before = a.profiles(metadata=True)
    with patch('twn_toolkit.distributed_agents.os.replace', side_effect=OSError('disk error')):
        with pytest.raises(OSError):
            a.settings.save({**a.settings.get(), 'role':'standalone'})
    assert a.settings.get()['role'] == 'agent'
    assert a.profiles(metadata=True) == before


def test_fleet_name_collision_cannot_report_false_resolution(fleet):
    main, a, _ = fleet
    a.save(profile())
    main.save(profile(), enabled=True)
    sync(main, a)
    conflict = next(p['mso'] for p in a.profiles(metadata=True) if p['mso']['conflict'])
    with pytest.raises(MsoConflict, match='Rename'):
        a.resolve(conflict['id'], 'fleet', conflict['version'])
    assert next(p['mso'] for p in a.profiles(metadata=True) if p['mso']['conflict']) == conflict


def test_unavailable_mso_database_does_not_break_agent_control(fleet):
    import sqlite3
    from twn_toolkit.distributed_worker import _agent_tick
    _, a, _ = fleet
    with patch('twn_toolkit.distributed_worker.EnrollmentClient') as constructor:
        client = constructor.return_value
        client.pending.return_value = False
        client.enrolled.return_value = True
        client.heartbeat.return_value = {'job_protocol':2, 'mso_protocol':1, 'state':'connected'}
        with patch('twn_toolkit.mso.MsoStore', side_effect=sqlite3.OperationalError('fixture storage unavailable')):
            status = _agent_tick(a.instance, a.settings.get(), control_only=True)
        assert status['state'] == 'connected'
        assert status['error'] == ''
        assert 'storage unavailable' in status['mso_error']


@pytest.mark.parametrize('role', ['standalone', 'mainframe', 'agent'])
def test_operational_mso_controls_follow_instance_role(tmp_path, role):
    from twn_toolkit.app import create_app
    store = node(tmp_path / role, role)
    app = create_app(instance_path=str(store.instance))
    app.config['TESTING'] = True
    client = app.test_client()
    available = role != 'standalone'
    page = client.get('/tools/ping')
    assert page.status_code == 200
    for marker in (b'id="ping-profile-mso"', b'id="ping-mso-conflicts-link"', b'id="ping-profile-refresh"'):
        assert (marker in page.data) == available
    assert (b'<summary>Mainframe Synced Objects' in client.get('/help').data) == available
    assert client.get('/tools/mso/conflicts').status_code == (200 if available else 404)
    if not available:
        assert client.post('/tools/mso/conflicts/resolve', data={'choice': 'fleet'}).status_code == 404
        saved = client.post('/tools/ping/profiles', json={'name': 'Local profile', 'hosts': '192.0.2.1'})
        assert saved.status_code == 200
        assert saved.json['profile']['mso']['state'] == 'Local'
        assert client.post('/tools/ping/profiles', json={'name': 'Shared attempt', 'hosts': '192.0.2.1', 'mso_enabled': True}).status_code == 400

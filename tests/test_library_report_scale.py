from __future__ import annotations

import json
import sqlite3
from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.remote_connections import RemoteConnectionStore
from twn_toolkit.investigations import InvestigationError, InvestigationStore


def populate_library(store, count=1000):
    with sqlite3.connect(store.path) as db:
        db.executemany('INSERT INTO remote_connection_folders (id,user_id,name,visibility,created_at,updated_at) VALUES (?,?,?,?,?,?)',
                       [('f'+str(i), 'owner', 'Folder '+str(i), visibility, 1, 1)
                        for i, visibility in enumerate(('global', 'admins_only', 'private'))])
        db.executemany('INSERT INTO remote_connection_hosts (id,user_id,name,host,port,folder_id,credential_id,visibility,notes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                       [('h'+str(i), 'owner', 'Host '+str(i).zfill(5), '192.0.2.1', 22,
                         'f'+str(i%3), '', 'inherit', 'x'*1000, 1, 1) for i in range(count)])


@pytest.mark.parametrize('user,admin', [('owner', False), ('other', False), ('administrator', True)])
def test_host_pages_preserve_full_library_visibility(tmp_path, user, admin):
    store = RemoteConnectionStore(str(tmp_path), 'fixture-key')
    populate_library(store)
    expected = store.library_for_user(user, is_admin=admin)['hosts']
    first = store.library_for_user(user, is_admin=admin, host_page=1)
    assert first['pagination']['total'] == len(expected)
    seen = []
    for page in range(1, first['pagination']['pages']+1):
        data = store.library_for_user(user, is_admin=admin, host_page=page)
        assert len(data['hosts']) <= 100
        seen.extend(data['hosts'])
    assert seen == expected
    assert store.library_for_user(user, is_admin=admin, host_page=999)['pagination']['page'] == first['pagination']['pages']
    query = expected[-1]['name']
    found = store.library_for_user(user, is_admin=admin, host_page=1, host_query=query)
    assert found['hosts'] == [expected[-1]]
    assert found['pagination']['matched'] == 1


def test_host_search_does_not_reveal_hidden_parent_names(tmp_path):
    store = RemoteConnectionStore(str(tmp_path), 'fixture-key')
    populate_library(store, 3)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE remote_connection_hosts SET visibility='global' WHERE id='h2'")
    host = store.library_for_user('other', host_page=1, host_query='Host 00002')['hosts'][0]
    assert host['folder_id'] == ''
    assert store.library_for_user('other', host_page=1, host_query='Folder 2')['hosts'] == []


def test_large_host_library_http_is_bounded_and_searches_off_page(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    store = app.extensions['remote_connection_store']
    populate_library(store, 10000)
    client = app.test_client()
    response = client.get('/tools/remote-terminal/library')
    assert response.status_code == 200
    library = response.json['library']
    assert len(library['hosts']) == 100 and library['pagination']['total'] > 6000
    assert len(response.data) < 500_000
    found = client.get('/tools/remote-terminal/library?host_query=Host+09999').json['library']
    assert len(found['hosts']) == 1 and found['hosts'][0]['id'] == 'h9999'


def populate_case(store, user='owner', count=105):
    case = store.create(owner_user_id=user, owner_username=user, title='Scale case')
    events = []
    for i in range(count):
        events.append(store.record_for_case(
            investigation_id=case['id'], user_id=user, username=user,
            operation_id='scale:'+str(i), event_type='diagnostic.completed', tool_id='tools.port_scanner',
            action='Scan '+str(i).zfill(3), outcome='succeeded', summary='Retained result '+str(i),
            targets={}, parameters={}, metrics={}, details={'results': [{'host':'192.0.2.1','port':443,'status':'open'}]},
            started_at=10+i, completed_at=11+i))
    return case, events


def test_report_pages_bound_payloads_and_preserve_off_page_choices(tmp_path):
    store = InvestigationStore(str(tmp_path))
    case, events = populate_case(store)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE investigation_events SET details_json=? WHERE id=?', (json.dumps({'large':'x'*1000000}), events[0]['id']))
    page = store.report_page_for_user(case['id'], 'owner')
    assert len(page['events']) == 50 and page['pages'] == 3
    assert page['events'][0]['details'] == {} and page['events'][0]['preview_shortened']
    scope = [event['id'] for event in page['events']]
    counts = store.set_report_contents(case['id'], 'owner', event_ids=scope[1:], artifact_ids=[], event_scope=scope, artifact_scope=[])
    retained = {event['id']:event for event in store.events_for_user(case['id'], 'owner')}
    assert retained[events[0]['id']]['report_placement'] == 'excluded'
    assert retained[events[-1]['id']]['report_placement'] == 'main'
    assert retained[events[0]['id']]['details']['large'] == 'x'*1000000
    assert counts['included_events'] == len(retained)-1
    with pytest.raises(InvestigationError):
        store.set_report_contents(case['id'], 'owner', event_ids=[events[-1]['id']], artifact_ids=[], event_scope=scope, artifact_scope=[])
    assert store.report_page_for_user(case['id'], 'owner')['included_events'] == counts['included_events']
    with pytest.raises(InvestigationError):
        store.report_page_for_user(case['id'], 'other')


def test_report_route_uses_bounded_store_and_scoped_form(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    store = InvestigationStore(str(tmp_path)); case, events = populate_case(store, 'test-user')
    client = app.test_client()
    with patch.object(InvestigationStore, 'events_for_user', side_effect=AssertionError('full event read')):
        response = client.get('/investigations/'+case['id']+'/report')
    assert response.status_code == 200 and len(response.data) < 1_000_000
    assert b'name="page_selection"' in response.data and b'data-unsaved-form' in response.data
    page = store.report_page_for_user(case['id'], 'test-user', page=2)
    scope = [event['id'] for event in page['events']]
    response = client.post('/investigations/'+case['id']+'/report/contents', data={
        'page_selection':'1', 'report_page':'2', 'event_scope':scope, 'event_id':scope[1:]})
    assert response.status_code == 302 and 'report_page=2' in response.location
    assert next(event for event in store.events_for_user(case['id'], 'test-user') if event['id']==events[-1]['id'])['report_placement']=='main'


def test_deep_folder_visibility_is_iterative_and_cycles_are_private():
    folders = [{'id':str(i), 'user_id':'owner', 'parent_id':str(i+1), 'visibility':'inherit'} for i in range(3000)]
    folders[-1]['visibility'] = 'global'
    RemoteConnectionStore._annotate_effective_visibility(folders, [])
    assert all(item['effective_visibility']=='global' for item in folders)
    folders[-1].update(visibility='inherit', parent_id='0')
    RemoteConnectionStore._annotate_effective_visibility(folders, [])
    assert all(item['effective_visibility']=='private' for item in folders)

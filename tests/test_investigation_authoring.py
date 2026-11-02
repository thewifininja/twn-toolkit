import pytest
from unittest.mock import patch
from twn_toolkit import create_app
from twn_toolkit.investigations import InvestigationError

@pytest.fixture
def setup(tmp_path):
    app=create_app(str(tmp_path)); app.testing=True
    return app,app.extensions['investigation_store'],app.test_client()

def make_case(client,title='Fixture case'):
    response=client.post('/investigations',data={'title':title,'description':'Starting context'})
    assert response.status_code==302
    return response.location.rsplit('/',1)[1]

def test_case_validation_retains_context_and_existing_owned_case(setup):
    app,store,client=setup
    failed=client.post('/investigations',data={'title':' ','description':'Retain <context>'})
    assert failed.status_code==400
    assert b'Retain &lt;context&gt;' in failed.data and b'data-unsaved-initial="true"' in failed.data
    own=make_case(client)
    foreign=store.create(owner_user_id='foreign',owner_username='Foreign operator',title='Foreign private title')
    failed=client.post('/investigations',data={'title':'Next case draft','description':'Do not lose context'})
    assert failed.status_code==400
    assert b'Next case draft' in failed.data and b'Do not lose context' in failed.data
    assert own.encode() in failed.data and b'Foreign private title' not in failed.data
    assert len(store.list_for_user('test-user'))==1


def test_native_note_validation_keeps_text_without_changing_case_state(setup):
    app,store,client=setup; case=make_case(client)
    with patch.object(store,'add_note',side_effect=InvestigationError('Synthetic rejected note')):
        response=client.post(f'/investigations/{case}/notes',data={'note':'Keep <note>\nSecond line','next':'/tools/dns-response'})
    assert response.status_code==400
    assert b'Keep &lt;note&gt;\nSecond line' in response.data
    assert b'Synthetic rejected note' in response.data and b'data-unsaved-initial="true"' in response.data
    assert not [event for event in store.events_for_user(case,'test-user') if event['event_type']=='note.added']
    store.set_state(case,'test-user','test-user','completed')
    closed=client.post(f'/investigations/{case}/notes',data={'note':'Closed case draft'})
    assert closed.status_code==400 and b'Closed case draft' in closed.data
    assert b'readonly' in closed.data and not store.get_for_user(case,'test-user')['is_open']


def test_explicit_json_ack_names_exact_event_and_never_deduplicates_by_text(setup):
    app,store,client=setup; case=make_case(client)
    replies=[client.post(f'/investigations/{case}/notes',data={'note':'  Canonical <note>  ','response_mode':'journal'},headers={'Accept':'application/json'}) for _ in range(2)]
    assert all(response.status_code==201 for response in replies)
    first,second=[response.json['event'] for response in replies]
    assert first['id']!=second['id']
    assert first['summary']=='Canonical <note>'
    assert first['href']==f'/investigations/{case}?include_event={first["id"]}#event-{first["id"]}'
    assert replies[0].headers['Cache-Control']=='no-store'
    events=store.events_for_user(case,'test-user')
    assert len([event for event in events if event['event_type']=='note.added'])==2
    page=client.get(first['href'].split('#')[0])
    assert b'Canonical &lt;note&gt;' in page.data and b'Canonical <note>' not in page.data


def test_json_mode_is_explicit_and_native_safe_next_preserved(setup):
    app,store,client=setup; case=make_case(client)
    for data,headers in [({'note':'Native1','response_mode':'journal'},{}),({'note':'Native2'},{'Accept':'application/json'})]:
        response=client.post(f'/investigations/{case}/notes',data={**data,'next':'https://outside.test/'},headers=headers)
        assert response.status_code==302 and response.location==f'/investigations/{case}'
    response=client.post(f'/investigations/{case}/notes',data={'note':'Prefix','response_mode':'journal'},headers={'Accept':'application/json'},environ_overrides={'SCRIPT_NAME':'/agents/fixture/ui'})
    assert response.status_code==201 and response.json['event']['href'].startswith(f'/agents/fixture/ui/investigations/{case}?include_event=')


def test_note_acl_and_original_case_remain_authoritative(setup):
    app,store,client=setup
    case=store.create(owner_user_id='owner',owner_username='Owner',title='Shared case')['id']
    path=f'/investigations/{case}/notes'
    data={'note':'Shared draft','response_mode':'journal'}; headers={'Accept':'application/json'}
    assert client.post(path,data=data,headers=headers).status_code==404
    store.add_participant(case,'owner','Owner','test-user','Collaborator')
    response=client.post(path,data=data,headers=headers)
    assert response.status_code==201
    assert store.events_for_user(case,'owner')[-1]['created_by_user_id']=='test-user'
    store.remove_participant(case,'owner','Owner','test-user')
    assert client.post(path,data=data,headers=headers).status_code==404
    store.add_participant(case,'owner','Owner','test-user','Collaborator')
    store.set_state(case,'owner','Owner','completed')
    response=client.post(path,data=data,headers=headers)
    assert response.status_code==400 and 'error' in response.json
    assert not store.get_for_user(case,'owner')['is_open']


def test_report_and_quick_note_are_bound_to_their_own_cases(setup):
    app,store,client=setup; old=make_case(client,'Closed viewed case')
    store.set_state(old,'test-user','test-user','completed')
    active=make_case(client,'Active note case')
    page=client.get(f'/investigations/{old}/report')
    assert page.status_code==200
    assert f'data-journal-url="/investigations/{active}"'.encode() in page.data
    assert f'action="/investigations/{old}/report/contents"'.encode() in page.data
    assert b'Download saved PDF' in page.data and b'Export complete portable case' in page.data
    response=client.post(f'/investigations/{active}/notes',data={'note':'Only in active case','response_mode':'journal'},headers={'Accept':'application/json'})
    assert response.status_code==201 and active in response.json['event']['href']
    assert all(event['summary']!='Only in active case' for event in store.events_for_user(old,'test-user'))


def test_case_page_has_valid_main_and_scripts_outside_attributes(setup):
    from html.parser import HTMLParser
    class Structure(HTMLParser):
        def __init__(self): super().__init__(); self.main=None; self.parents=[]; self.guards=[]
        def handle_starttag(self,tag,attrs):
            attrs=dict(attrs)
            if tag=='main': self.main=attrs
            if tag=='script' and 'unsaved-forms.js' in attrs.get('src',''): self.guards.append(list(self.parents))
            if tag not in {'input','link','meta','img','br','hr','source','wbr'}: self.parents.append(tag)
        def handle_endtag(self,tag):
            if tag in self.parents: self.parents=self.parents[:len(self.parents)-1-self.parents[::-1].index(tag)]
    page=setup[2].get('/investigations'); parser=Structure(); parser.feed(page.data.decode())
    assert parser.main and parser.main.get('id')=='main-content'
    assert 'investigation-shell' in parser.main['class']
    assert all('<' not in str(value) for value in parser.main.values())
    assert parser.guards and all('main' in parents for parents in parser.guards)


def test_confirmed_note_link_still_includes_note_after_later_pages(setup):
    from twn_toolkit.investigations import JOURNAL_EVENT_PAGE_SIZE
    app,store,client=setup; case=make_case(client)
    response=client.post(f'/investigations/{case}/notes',data={'note':'Original confirmed note','response_mode':'journal'},headers={'Accept':'application/json'})
    event=response.json['event']
    for number in range(JOURNAL_EVENT_PAGE_SIZE+1):
        store.add_note(case,'test-user','test-user',f'Later fixture note {number}')
    latest=store.journal_events_page_for_user(case,'test-user')['events']
    assert event['id'] not in [item['id'] for item in latest]
    page=client.get(event['href'].split('#')[0])
    assert page.status_code==200
    assert f'id="event-{event["id"]}"'.encode() in page.data


def test_include_event_cursor_is_scoped_exclusive_and_bounded(setup):
    from twn_toolkit.investigations import JOURNAL_EVENT_PAGE_SIZE
    app,store,client=setup; case=make_case(client)
    note=store.add_note(case,'test-user','test-user','Anchor note')
    page=store.journal_events_page_for_user(case,'test-user',include_event_id=note['id'])
    assert len(page['events'])<=JOURNAL_EVENT_PAGE_SIZE
    assert page['events'][-1]['id']==note['id'] and not page['has_newer']
    store.add_note(case,'test-user','test-user','Newer note')
    assert store.journal_events_page_for_user(case,'test-user',include_event_id=note['id'])['has_newer']
    foreign=store.create(owner_user_id='foreign',owner_username='Foreign',title='Private case')
    foreign_note=store.add_note(foreign['id'],'foreign','Foreign','Private note')
    assert client.get(f'/investigations/{case}?include_event={foreign_note["id"]}').status_code==404
    assert client.get(f'/investigations/{case}?include_event={note["id"]}&after_event={note["id"]}').status_code==404
    assert client.get(f'/investigations/{case}?include_event={note["id"]}&before_event={note["id"]}').status_code==404


def test_new_case_error_explains_shared_case_owner_boundary(setup):
    app,store,client=setup
    shared=store.create(owner_user_id='fixture-owner',owner_username='Fixture owner',title='Accessible shared case')
    store.add_participant(shared['id'],'fixture-owner','Fixture owner','test-user','test-user')
    response=client.post('/investigations',data={'title':'New draft','description':'Retained collaborator context'})
    assert response.status_code==400
    assert b'its owner controls closing it' in response.data
    assert b'New draft' in response.data and b'Retained collaborator context' in response.data
    assert store.get_for_user(shared['id'],'test-user')['is_open']

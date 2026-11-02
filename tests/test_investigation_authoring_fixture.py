"""The browser fixture must really produce the protocol it claims to exercise."""
import json
import runpy
import sys
from pathlib import Path
from unittest.mock import patch
import pytest

@pytest.mark.parametrize('mode,status', [('json500_after',500),('wrong_summary',201)])
def test_after_write_fixture_returns_real_json_response(tmp_path,mode,status):
    script=Path(__file__).parent/'fixtures'/'investigation_authoring_app.py'
    with patch.object(sys,'argv',[str(script),'--port','0']), patch('tempfile.mkdtemp',return_value=str(tmp_path)), patch('flask.Flask.run'):
        fixture=runpy.run_path(str(script))
    app=fixture['app']; client=app.test_client(); store=app.extensions['investigation_store']
    opened=client.post('/investigations',data={'title':'Synthetic protocol case'})
    assert opened.status_code==302
    path=opened.location+'/notes'
    (tmp_path/'control.json').write_text('{"response":"'+mode+'"}')
    response=client.post(path,data={'note':'Actually stored note','response_mode':'journal'},headers={'Accept':'application/json'})
    assert response.status_code==status and response.is_json
    telemetry=json.loads((tmp_path/'counts.json').read_text())['note_responses'][-1]
    assert telemetry=={'status':status,'mimetype':'application/json','mode':mode,'committed':True}
    case=opened.location.rsplit('/',1)[1]
    assert store.events_for_user(case,'test-user')[-1]['summary']=='Actually stored note'
    if mode=='json500_after': assert response.json['error']=='Synthetic internal failure after committed note'
    else: assert response.json['event']['summary']!='Actually stored note'

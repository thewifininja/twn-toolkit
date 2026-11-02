"""The invalid-only browser fixture must accept real multipart line endings."""
import runpy
import sys
from pathlib import Path
from unittest.mock import Mock,patch

def test_fixture_only_admits_equivalent_invalid_ntp_payload(tmp_path):
    script=Path(__file__).parent/'fixtures'/'network_failure_app.py'
    with patch.object(sys,'argv',[str(script),'--port','0']),patch('tempfile.mkdtemp',return_value=str(tmp_path)),patch('werkzeug.serving.make_server'):
        fixture=runpy.run_path(str(script))
    app=fixture['app'];client=app.test_client();invalid=fixture['invalid_hosts']
    runner=Mock(side_effect=AssertionError('No NTP execution permitted'))
    with patch('twn_toolkit.ntp_routes.test_ntp_servers',runner):
        response=client.post('/tools/ntp-test',data={'hosts':invalid.replace('\n','\r\n'),'port':'123','timeout':'3','samples':'4'},content_type='multipart/form-data')
        assert response.status_code==200 and b'class="message error"' in response.data
        assert fixture['counts']['invalid_ntp_posts']==1
        assert client.post('/tools/ntp-test',data={'hosts':invalid.replace('edited21.test','edited22.test')}).status_code==403
        assert client.post('/tools/ntp-test',data={'hosts':'valid-fixture.test'}).status_code==403
        assert fixture['counts']['invalid_ntp_posts']==1
        runner.assert_not_called()
    assert all(value==0 for value in fixture['counts']['blocked_calls'].values())

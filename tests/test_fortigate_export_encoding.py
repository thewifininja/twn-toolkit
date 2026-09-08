"""Display-only recovery of invalid appliance text preserves byte evidence."""
import json
from unittest.mock import Mock

import pytest

from twn_toolkit.fortigate import FortiGateClient, FortiGateError


@pytest.fixture
def response(monkeypatch):
    response=Mock(status_code=200)
    response.content=b'{"results":[{"name":"caf\xc3\xa9"},{"name":"bad\xff\x80name"}]}'
    response.iter_content.side_effect=lambda **kw:[response.content[:19],response.content[19:]]
    monkeypatch.setattr('twn_toolkit.fortigate.requests.Session.request',lambda *a,**kw:response)
    return response


def test_display_export_preserves_bad_bytes_and_valid_unicode(response):
    client=FortiGateClient('https://fixture.invalid','secret').for_display_export()
    for _ in range(2):
        result=client.export_data('/api/v2/monitor/wifi/client','root')
        assert result['results']==[{'name':'café'},{'name':r'bad\xff\x80name'}]
        assert json.dumps(result,ensure_ascii=False).encode('utf-8')
    assert len(client.response_warnings)==1 and r'\xNN' in client.response_warnings[0]
    assert response.close.call_count==2


@pytest.mark.parametrize('kind',['ordinary_read','put','post'])
def test_mutation_and_ordinary_read_paths_remain_strict(response,kind):
    client=FortiGateClient('https://fixture.invalid','secret')
    with pytest.raises(FortiGateError,match='invalid text encoding at byte'):
        if kind=='ordinary_read':client.export_data('/api/v2/cmdb/wireless-controller/wtp','root')
        else:client.for_display_export().request(kind.upper(),'/api/v2/cmdb/wireless-controller/wtp')
    assert not client.response_warnings


@pytest.mark.parametrize('raw',[b'{"results":\xff}', b'{"results":[{"name":"bad\xff"}'])
def test_invalid_syntax_is_not_repaired_or_echoed(response,raw):
    response.content=raw
    with pytest.raises(FortiGateError,match='malformed JSON at character') as error:
        FortiGateClient('https://fixture.invalid','secret').for_display_export().export_data('/api/v2/monitor/wifi/client','root')
    assert 'bad' not in str(error.value) and 'results' not in str(error.value)


def test_valid_json_does_not_gain_warnings(response):
    response.content=b'{"results":[]}'
    client=FortiGateClient('https://fixture.invalid','secret').for_display_export()
    assert client.export_data('/api/v2/monitor/wifi/client','root')=={'results':[]}
    assert not client.response_warnings

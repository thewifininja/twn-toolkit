import pytest

from twn_toolkit.network_tools import parse_ssh_commands, split_ssh_commands, ToolInputError
from twn_toolkit.ssh_commandlets import build_ssh_command_plans, normalize_ssh_matrix_action, ssh_matrix_actions_to_commands
from twn_toolkit.automation_types.actions import _validate_ssh


CERTIFICATE = 'set certificate "-----BEGIN CERTIFICATE-----\n' + ('ABC0123' * 16 + '\n') * 16 + '\n-----END CERTIFICATE-----"'


def test_large_script_has_no_command_count_or_summed_timeout_ceiling():
    script = '\n'.join(f'edit object-{i}\nset comment "Device {i}"\nnext' for i in range(100))
    plan = build_ssh_command_plans('Name | Host\nFixture | fixture.test', script, 300)
    assert len(plan['plans'][0]['command_specs']) == 300
    assert plan['plans'][0]['command_specs'][-1]['command'] == 'next'


def test_multiline_value_survives_saved_actions_and_automation():
    script = 'config vpn certificate local\n[timeout=600] ' + CERTIFICATE + '\nend'
    action = normalize_ssh_matrix_action({'name': 'Install certificate', 'commands': script, 'command_timeout': 30})
    combined = ssh_matrix_actions_to_commands([action, {'name': 'Verify', 'commands': 'get system status', 'command_timeout': 10}])
    plan = build_ssh_command_plans('Name | Host\nFixture | fixture.test', combined, 30)['plans'][0]
    assert len(plan['command_specs']) == 4
    assert plan['command_specs'][1] == {'command': CERTIFICATE, 'timeout': 600}
    normalized = _validate_ssh({'hosts': 'fixture.test', 'commands': script, 'username': 'fixture', 'password': 'fixture'})
    assert CERTIFICATE in normalized['commands']
    assert parse_ssh_commands(normalized['commands'].split('\n'))[1]['command'] == CERTIFICATE


def test_quote_escaping_blank_lines_and_single_quoted_double_quote():
    script = 'echo \'"\'\nset description Bob\'s-router\nset value "first\\" line\n\nsecond line"\nend'
    assert split_ssh_commands(script) == ['echo \'"\'', "set description Bob's-router", 'set value "first\\" line\n\nsecond line"', 'end']
    assert split_ssh_commands('set value "one\r\n\r\ntwo"\r\nend') == ['set value "one\n\ntwo"', 'end']


def test_unclosed_multiline_value_is_rejected_before_execution():
    with pytest.raises(ToolInputError, match='unclosed quote'):
        build_ssh_command_plans('Name | Host\nFixture | fixture.test', 'set certificate "-----BEGIN CERTIFICATE-----\nABC\nend')


def test_http_preview_and_queued_plan_preserve_long_multiline_script(tmp_path):
    import re
    from twn_toolkit import create_app
    from twn_toolkit import bulk_ssh_jobs

    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client()
    try:
        script = '\n'.join(['get system status'] * 60 + [CERTIFICATE, 'end'])
        form = {'matrix': 'Name | Host\nFixture | fixture.test', 'commands': script,
                'command_timeout': '300', 'port': '22'}
        response = client.post('/tools/multi-ssh', data={**form, 'action': 'preview'})
        assert response.status_code == 200
        token = re.search(rb'name="preview_token" type="hidden" value="([^"]+)"', response.data)
        assert token, response.get_data(as_text=True)
        response = client.post('/tools/multi-ssh', data={**form, 'action': 'run',
            'preview_token': token.group(1).decode(), 'username': 'fixture', 'password': 'fixture',
            'confirm_execution': 'on'}, headers={'Accept': 'application/json'})
        assert response.status_code == 202, response.data
        job = app.extensions['diagnostic_job_store'].get(response.json['job_id'], 'test-user')
        assert job['state'] == 'queued'
        plans = bulk_ssh_jobs.plans_for(job['config'])
        assert len(plans[0]['command_specs']) == 62
        assert plans[0]['command_specs'][60]['command'] == CERTIFICATE
    finally:
        app.extensions['remote_session_manager'].close()

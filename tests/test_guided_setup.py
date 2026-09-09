"""Installation plans must be explicit, bounded, and independent of unattended upgrades."""
from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from twn_toolkit.setup_dependencies import DEPENDENCIES, host_platform, inventory, selected_packages
from twn_toolkit.setup_plan import SetupPlan, initial_plan, package_commands, validate
from twn_toolkit.setup_executor import apply, prepare_location, run_command, setup_guard, setup_lock
from twn_toolkit.setup_cli import configure_instance, main


HOST = {'system':'Linux','name':'Ubuntu','adapter':'apt','manager':'/usr/bin/apt-get'}
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def checkout(tmp_path,monkeypatch):
    root=tmp_path/'source';root.mkdir()
    for name in ('install.sh','requirements.txt','twn'):
        (root/name).write_text('fixture')
    monkeypatch.setattr('twn_toolkit.setup_plan.installed_service',lambda *args:False)
    monkeypatch.setattr('os.geteuid',lambda:1000)
    return root


def test_inventory_covers_every_optional_integration_and_bundled_certbot():
    specs={spec.id:spec for spec in DEPENDENCIES}
    assert {'lsof','lldpd','tcpdump','traceroute','iperf3','fping','nmcli','iw','ethtool','venv','build','tzdata'} <= specs.keys()
    assert specs['lldpd'].all_commands and specs['lldpd'].commands==('lldpd','lldpcli')
    assert specs['certbot'].category=='python' and not specs['certbot'].apt
    assert specs['eapol_test'].category=='disabled'
    with pytest.raises(ValueError): selected_packages(['certbot'],HOST)
    with pytest.raises(ValueError): selected_packages(['eapol_test'],HOST)
    packages,_=selected_packages(['lsof','lldpd','tcpdump','traceroute'],HOST)
    assert packages==['lldpd','lsof','tcpdump','traceroute']


def test_package_adapters_never_guess_or_use_shell_input(checkout):
    plan=SetupPlan(str(checkout),packages=['lldpd','lsof'])
    assert package_commands(plan,HOST)==[['sudo','/usr/bin/apt-get','install','--','lldpd','lsof']]
    arch={**HOST,'adapter':'pacman','manager':'/usr/bin/pacman'}
    assert package_commands(plan,arch)==[['sudo','/usr/bin/pacman','-S','--needed','--','lldpd','lsof']]
    mac={**HOST,'system':'Darwin','adapter':'brew','manager':'/opt/homebrew/bin/brew'}
    assert package_commands(plan,mac)==[['/opt/homebrew/bin/brew','install','--formula','lldpd','lsof']]
    assert package_commands(SetupPlan(str(checkout),packages=['bpf']),mac)==[['/opt/homebrew/bin/brew','install','--cask','wireshark-chmodbpf']]
    with pytest.raises(ValueError): package_commands(plan,{**HOST,'manager':''})
    with pytest.raises(ValueError): package_commands(SetupPlan(str(checkout),packages=['$(touch /tmp/no)']),HOST)
    with patch('os.geteuid',return_value=0), pytest.raises(ValueError): package_commands(plan,mac)


@pytest.mark.parametrize('value',[{'location':'/tmp/x','service':'yes'}, {'location':'/tmp/x','packages':'lsof'}, {'location':'/tmp/x','surprise':True}])
def test_config_rejects_ambiguous_or_unknown_fields(value):
    with pytest.raises(ValueError):SetupPlan.read(value)


def test_plan_is_read_only_and_preserves_existing_settings(checkout,capsys):
    instance=checkout/'instance';instance.mkdir()
    (instance/'server_settings.json').write_text(json.dumps({'preferred_fqdn':'gear.example','instance_name':'my-gear','listen_host':'127.0.0.1','allowed_networks':['192.0.2.0/24']}))
    (instance/'time_settings.json').write_text('{"timezone":"Europe/London"}')
    before={p.relative_to(checkout):p.read_bytes() for p in checkout.rglob('*') if p.is_file()}
    with patch('twn_toolkit.setup_cli.host_platform',return_value=HOST):
        assert main(['--root',str(checkout),'--dry-run'])==0
    assert 'gear.example' in capsys.readouterr().out
    assert before=={p.relative_to(checkout):p.read_bytes() for p in checkout.rglob('*') if p.is_file()}
    configure_instance(checkout,'new.example','UTC')
    saved=json.loads((instance/'server_settings.json').read_text())
    assert saved['preferred_fqdn']=='new.example' and saved['instance_name']=='my-gear'
    assert saved['listen_host']=='127.0.0.1' and saved['allowed_networks']==['192.0.2.0/24']
    assert json.loads((instance/'time_settings.json').read_text())=={'timezone':'UTC'}


def test_invalid_setting_does_not_partially_write_hostname(checkout):
    with pytest.raises(ValueError):configure_instance(checkout,'valid.example','Not/AZone')
    assert not (checkout/'instance').exists()


def test_new_location_copies_only_release_files_and_keeps_source(checkout,tmp_path):
    (checkout/'.local-reviews').mkdir();(checkout/'.local-reviews/private').write_text('private')
    (checkout/'instance').mkdir();(checkout/'instance/data').write_text('data')
    (checkout/'.venv').mkdir();(checkout/'.venv/python').write_text('old')
    target=tmp_path/'destination'
    prepare_location(checkout,target,lambda command:pytest.fail(str(command)))
    assert (target/'install.sh').is_file() and (checkout/'install.sh').is_file()
    assert not (target/'instance').exists() and not (target/'.venv').exists() and not (target/'.local-reviews').exists()
    with pytest.raises(ValueError):prepare_location(checkout,target,lambda _:None)


def test_relocation_refuses_live_data_nested_and_nonempty_targets(checkout,tmp_path):
    with pytest.raises(ValueError):validate(SetupPlan(str(checkout/'nested')),checkout,HOST)
    destination=tmp_path/'other';destination.mkdir();(destination/'keep').write_text('keep')
    with pytest.raises(ValueError):validate(SetupPlan(str(destination)),checkout,HOST)
    (checkout/'instance').mkdir();(checkout/'instance/data').write_text('preserve')
    with pytest.raises(ValueError):validate(SetupPlan(str(tmp_path/'empty')),checkout,HOST)


def test_macos_protected_location_resolves_symlinks(checkout,tmp_path,monkeypatch):
    from twn_toolkit.service_cli import ServiceUser
    home=tmp_path/'home';(home/'Downloads').mkdir(parents=True)
    link=tmp_path/'alias';link.symlink_to(home/'Downloads',target_is_directory=True)
    monkeypatch.setattr('twn_toolkit.service_cli.service_user',lambda _:ServiceUser('fixture','fixture',1000,1000,str(home)))
    with pytest.raises(RuntimeError,match='privacy controls'):
        validate(SetupPlan(str(link/'toolkit'),service=True),checkout,{**HOST,'system':'Darwin','adapter':'brew','manager':'/opt/homebrew/bin/brew'})


def test_failed_package_transaction_stops_before_python_settings_or_services(checkout):
    calls=[]
    def fail(command,**kwargs):
        calls.append(command)
        raise RuntimeError('package transaction failed')
    with pytest.raises(RuntimeError,match='package transaction failed'):
        apply(SetupPlan(str(checkout),packages=['lsof']),checkout,HOST,runner=fail,report=lambda _:None)
    assert calls==[['sudo','/usr/bin/apt-get','install','--','lsof']]
    assert not (checkout/'instance').exists()
    assert not (checkout/'.twn-upgrades/operation.lock').exists()


def test_declined_extras_manual_plan_never_invokes_privileged_tools(checkout,monkeypatch):
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        if '--prepare-only' in command:
            (checkout/'instance').mkdir(exist_ok=True)
        if command[-1]=='restart':
            assert not (checkout/'.twn-upgrades/operation.lock').exists()
            with pytest.raises(BlockingIOError):
                with setup_guard(checkout):pass
    apply(SetupPlan(str(checkout)),checkout,HOST,runner=run,report=lambda _:None)
    assert not any(command[0]=='sudo' or 'service' in command or 'apt-get' in command for command in calls)
    assert any('--prepare-only' in command for command in calls)
    assert (checkout/'instance/installation.initialized').exists()


def test_another_setup_or_upgrade_lock_is_not_removed(checkout):
    with setup_lock(checkout):
        with pytest.raises(FileExistsError):
            apply(SetupPlan(str(checkout)),checkout,HOST,runner=lambda *_a,**_k:pytest.fail('executed'),report=lambda _:None)
        assert (checkout/'.twn-upgrades/operation.lock').exists()


def test_unattended_native_prompts_are_disabled(checkout,monkeypatch):
    captured=[]
    monkeypatch.setattr(subprocess,'run',lambda command,**kwargs: captured.append((command,kwargs)) or subprocess.CompletedProcess(command,0))
    run_command(['sudo','/usr/bin/apt-get','install','--','lsof'],root=checkout,unattended=True)
    command,options=captured[0]
    assert command==['sudo','-n','/usr/bin/apt-get','install','-y','--','lsof']
    assert options['stdin']==subprocess.DEVNULL and options['env']['DEBIAN_FRONTEND']=='noninteractive'


def test_bootstrap_cli_does_not_require_site_packages():
    result=subprocess.run([sys_executable(),'-S',str(ROOT/'scripts/guided_install.py'),'--dependencies'],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert {'lldpd','lsof'}<={row['id'] for row in json.loads(result.stdout)['dependencies']}


def sys_executable():
    import sys
    return sys.executable


def test_manual_checkout_does_not_take_over_foreign_service(checkout,monkeypatch):
    monkeypatch.setattr('twn_toolkit.setup_plan.service_definition',lambda _:('someone','/different/toolkit'))
    assert validate(SetupPlan(str(checkout)),checkout,HOST)==checkout
    with pytest.raises(ValueError,match='different or unrecognized'):
        validate(SetupPlan(str(checkout),service=True),checkout,HOST)


def test_rerun_preserves_http_choice(checkout):
    (checkout/'instance').mkdir();(checkout/'instance/installation.initialized').touch()
    calls=[]
    apply(SetupPlan(str(checkout)),checkout,HOST,runner=lambda command,**kwargs:calls.append(command),report=lambda _:None)
    assert not any('enable-https' in command for command in calls)
    assert calls[0]==[str(checkout/'twn'),'stop']


def test_prepare_only_keeps_unattended_stage_contract(tmp_path):
    # Exercise the real shell boundary with fake lifecycle commands.
    from test_installer import InstallerLifecycleTests
    fixture=InstallerLifecycleTests()
    try:
        root,env=fixture._sandbox(running=False)
        result=subprocess.run([str(root/'install.sh'),'--non-interactive','--prepare-only'],cwd=root,env=env,capture_output=True,text=True,timeout=10)
        assert result.returncode==0,result.stderr
        assert not (root/'instance/installation.initialized').exists()
        commands=(root/'commands.log').read_text()
        assert 'start:' not in commands and 'enable-https:' not in commands
    finally:
        fixture.doCleanups()


def test_gui_inventory_includes_lldpd_and_recovery_extras():
    from twn_toolkit.system_diagnostics import command_dependencies
    with patch('twn_toolkit.system_diagnostics.ping_engine_capability',return_value={'accelerated':False,'detail':'fixture'}):
        names={row['name'] for row in command_dependencies(system='Linux')}
    assert {'lldpd','lldpcli','lsof','tcpdump','traceroute','nmcli','iw','ethtool'} <= names


def test_location_page_does_not_block_access_to_missing_prerequisite(checkout,monkeypatch):
    from twn_toolkit.setup_tui import Wizard
    rows=inventory(checkout,system='Linux')
    for row in rows:
        if row['id']=='venv':row['present']=False
    monkeypatch.setattr('twn_toolkit.setup_plan.inventory',lambda *a,**k:rows)
    monkeypatch.setattr('twn_toolkit.setup_tui.inventory',lambda *a,**k:rows)
    monkeypatch.setattr(Wizard,'configure',lambda self:None)
    wizard=Wizard(None,checkout,HOST,SetupPlan(str(checkout)),motion=False)
    wizard.page=2
    assert wizard.advance() and wizard.page==3
    assert wizard.advance() and wizard.page==3 and 'virtual-environment' in wizard.error
    wizard.data['tool_venv']=True
    assert wizard.advance() and wizard.page==4
    wizard.back()
    assert wizard.page==3 and wizard.data['tool_venv']
    wizard.page=6
    assert not wizard.advance() and wizard.accepted
    assert not (checkout/'instance').exists()


def test_setup_handoff_guard_blocks_upgrade_without_operation_lock(checkout):
    from twn_toolkit.upgrade_manager import UpgradeManager, UpgradeError
    manager=UpgradeManager(checkout,checkout/'instance','0.24.4')
    with setup_guard(checkout):
        assert not (checkout/'.twn-upgrades/operation.lock').exists()
        with pytest.raises(UpgradeError,match='Guided setup'):
            manager.launch_backup({'username':'fixture'})
    with setup_guard(checkout):pass


def test_active_job_blocks_setup_before_execution(checkout):
    import sqlite3
    (checkout/'instance').mkdir()
    with sqlite3.connect(checkout/'instance/diagnostic_jobs.sqlite3') as db:
        db.execute('CREATE TABLE diagnostic_jobs (state TEXT, token TEXT)')
        db.execute("INSERT INTO diagnostic_jobs VALUES ('running', '')")
    with pytest.raises(ValueError,match='Active jobs'):
        apply(SetupPlan(str(checkout)),checkout,HOST,runner=lambda *a,**k:pytest.fail('ran during active work'),report=lambda _:None)
    assert not (checkout/'.twn-upgrades/operation.lock').exists()


def test_selected_package_missing_after_install_never_marks_success(checkout,monkeypatch):
    monkeypatch.setattr('twn_toolkit.setup_executor.inventory',lambda *a,**k:[{'id':'lsof','present':False}])
    calls=[]
    with pytest.raises(RuntimeError,match='expected files'):
        apply(SetupPlan(str(checkout),packages=['lsof']),checkout,HOST,runner=lambda command,**k:calls.append(command),report=lambda _:None)
    assert len(calls)==1 and not (checkout/'instance/installation.initialized').exists()


def test_selected_service_network_and_daemon_are_explicit_and_verified(checkout,monkeypatch):
    from twn_toolkit import setup_executor
    monkeypatch.setattr(setup_executor,'validate',lambda *a:checkout)
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        if '--prepare-only' in command:(checkout/'instance').mkdir()
    apply(SetupPlan(str(checkout),service=True,network=True,lldpd=True),checkout,HOST,runner=run,report=lambda _:None)
    assert ['sudo','systemctl','enable','--now','lldpd'] in calls
    assert any('service' in command and '--network-capabilities' in command for command in calls)
    assert any('--expect-service' in command and '--expect-network' in command for command in calls)


def test_mac_pf_only_runs_for_reviewed_interfaces_without_live_reload(checkout,monkeypatch):
    from twn_toolkit import setup_executor
    monkeypatch.setattr(setup_executor,'validate',lambda *a:checkout)
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        if '--prepare-only' in command:(checkout/'instance').mkdir()
    apply(SetupPlan(str(checkout),pf_interfaces=['en0']),checkout,{**HOST,'system':'Darwin'},runner=run,report=lambda _:None)
    pf=[command for command in calls if 'twn_toolkit.macos_multicast_pf_cli' in command]
    assert pf==[['sudo',str(checkout/'.venv/bin/python'),'-m','twn_toolkit.macos_multicast_pf_cli','install','--interfaces','en0']]
    assert not any('pfctl' in command for command in calls)


def test_homebrew_keg_only_lsof_and_sbin_are_visible_to_setup_and_services(checkout):
    from twn_toolkit.setup_dependencies import executable_path
    from twn_toolkit.service_cli import _service_path
    for value in (executable_path(checkout),_service_path(checkout)):
        assert '/opt/homebrew/sbin' in value.split(os.pathsep)
        assert '/opt/homebrew/opt/lsof/bin' in value.split(os.pathsep)
        assert '/usr/local/opt/lsof/bin' in value.split(os.pathsep)


@pytest.mark.parametrize('unattended',[False,True])
def test_real_service_wrapper_disables_native_auth_prompt_only_for_unattended_setup(tmp_path,capfd,unattended):
    import shutil
    root=tmp_path/'toolkit';root.mkdir()
    shutil.copy2(ROOT/'twn',root/'twn')
    binaries=root/'.venv/bin';binaries.mkdir(parents=True)
    for name,source in {
        'python':'#!/bin/sh\nexit 0\n',
        'id':'#!/bin/sh\necho 1000\n',
        'sudo':'#!/bin/sh\nprintf "sudo-argument:%s\\n" "$@"\n',
    }.items():
        path=binaries/name;path.write_text(source);path.chmod(0o755)
    run_command([str(root/'twn'),'service','install','--user','fixture'],root=root,unattended=unattended)
    output=capfd.readouterr().out
    assert ('sudo-argument:-n\n' in output)==unattended
    assert 'sudo-argument:twn_toolkit.service_cli' in output

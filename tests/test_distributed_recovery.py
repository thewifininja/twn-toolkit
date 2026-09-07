from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from twn_toolkit import supervisor_worker as supervisor


SOURCE = (Path(__file__).resolve().parents[1] / 'twn').read_text()


def shell_functions(*names):
    return '\n'.join(re.search(r'^'+name+r'\(\) \{.*?^\}', SOURCE, re.M|re.S).group() for name in names)


def environment(tmp_path):
    return {**os.environ, 'PYTHON':sys.executable, 'INSTANCE':str(tmp_path),
            'DISTRIBUTED_SETTINGS':str(tmp_path/'distributed_settings.json'),
            'DISTRIBUTED_PIDFILE':str(tmp_path/'twn-distributed.pid')}


@pytest.mark.parametrize('role',['agent','mainframe'])
def test_supervisor_repairs_missing_distributed_worker_and_backs_off(tmp_path,monkeypatch,role):
    (tmp_path/'distributed_settings.json').write_text(json.dumps({'role':role}))
    monkeypatch.setattr(supervisor,'_pid_running',lambda path:path.name!='twn-distributed.pid')
    monkeypatch.setattr(supervisor,'_heartbeat_fresh',lambda *args:True)
    restart=MagicMock(return_value=subprocess.CompletedProcess([],0))
    monkeypatch.setattr(supervisor.subprocess,'run',restart)
    retries={}
    supervisor.supervise_once(tmp_path,tmp_path,retries)
    supervisor.supervise_once(tmp_path,tmp_path,retries)
    assert restart.call_count==1
    assert restart.call_args.args[0][-1]=='distributed-restart'
    assert restart.call_args.kwargs['timeout']==supervisor.DISTRIBUTED_RESTART_TIMEOUT_SECONDS


@pytest.mark.parametrize('settings',[None,{}, {'role':'standalone'}, [], {'role':[]}, {'role':'broken'}])
def test_supervisor_never_starts_distributed_for_inactive_or_invalid_role(tmp_path,monkeypatch,settings):
    if settings is not None:(tmp_path/'distributed_settings.json').write_text(json.dumps(settings))
    monkeypatch.setattr(supervisor,'_pid_running',lambda path:path.name!='twn-distributed.pid')
    monkeypatch.setattr(supervisor,'_heartbeat_fresh',lambda *args:True)
    restart=MagicMock();monkeypatch.setattr(supervisor.subprocess,'run',restart)
    supervisor.supervise_once(tmp_path,tmp_path,{})
    restart.assert_not_called()


def test_distributed_recovery_obeys_lifecycle_lock_and_failure_does_not_block_other_services(tmp_path,monkeypatch):
    (tmp_path/'distributed_settings.json').write_text('{"role":"agent"}')
    monkeypatch.setattr(supervisor,'_pid_running',lambda *args:False)
    monkeypatch.setattr(supervisor,'_operation_active',lambda path:path.name=='twn-distributed.pid.lock')
    calls=[]
    def restart(args,**kwargs):
        calls.append(args[-1])
        if args[-1]=='distributed-restart':raise subprocess.TimeoutExpired(args,60)
        return subprocess.CompletedProcess(args,0)
    monkeypatch.setattr(supervisor.subprocess,'run',restart)
    supervisor.supervise_once(tmp_path,tmp_path,{})
    assert calls==['automation-restart']
    calls.clear();monkeypatch.setattr(supervisor,'_operation_active',lambda path:False)
    supervisor.supervise_once(tmp_path,tmp_path,{})
    assert calls==['distributed-restart','automation-restart']


@pytest.mark.parametrize('settings,healthy',[({},True),({'role':'standalone'},True),({'role':'agent'},False),({'role':'mainframe'},False),([],False),({'role':[]},False),({'role':'bad'},False)])
def test_shell_health_requires_enabled_worker_and_rejects_malformed_role(tmp_path,settings,healthy):
    (tmp_path/'distributed_settings.json').write_text(json.dumps(settings))
    code=shell_functions('distributed_enabled','distributed_required_ready')+'\ndistributed_is_running() { return 1; }\ndistributed_required_ready\n'
    result=subprocess.run(['sh','-c',code],env=environment(tmp_path),capture_output=True,text=True,timeout=5)
    assert (result.returncode==0)==healthy


def test_service_start_waits_until_missing_distributed_worker_recovers(tmp_path):
    (tmp_path/'distributed_settings.json').write_text('{"role":"agent"}')
    for name in ['scheme','host','port','web.pid']:(tmp_path/name).write_text('fixture')
    code=shell_functions('distributed_enabled','distributed_required_ready','request_service_start')+'''
SERVICE_PAUSE_FILE="$INSTANCE/pause"
SERVICE_RESUME_FILE="$INSTANCE/resume"
SCHEME_FILE="$INSTANCE/scheme"
HOST_FILE="$INSTANCE/host"
PORT_FILE="$INSTANCE/port"
PIDFILE="$INSTANCE/web.pid"
is_running() { return 0; }
automation_is_running() { return 0; }
supervisor_is_running() { return 0; }
service_launcher_is_running() { return 0; }
distributed_is_running() { [ -f "$INSTANCE/recovered" ]; }
load_running_endpoint() { :; }
show_access_urls() { :; }
sleep() { : > "$INSTANCE/recovered"; }
request_service_start
[ -f "$INSTANCE/recovered" ]
'''
    result=subprocess.run(['sh','-c',code],env=environment(tmp_path),capture_output=True,text=True,timeout=5)
    assert result.returncode==0,result.stderr


def test_distributed_lifecycle_operations_serialize_and_release_failed_lock(tmp_path):
    code=shell_functions('acquire_managed_worker_lock','release_managed_worker_lock','start_distributed','stop_distributed','distributed_restart')+'''
pid_is_running() { kill -0 "$1" 2>/dev/null; }
start_distributed_unlocked() {
  echo "$OP:start" >> "$INSTANCE/events"
  sleep 0.1
  echo "$OP:started" >> "$INSTANCE/events"
  return "${FAIL_START:-0}"
}
stop_distributed_unlocked() {
  echo "$OP:stop" >> "$INSTANCE/events"
  sleep 0.1
  echo "$OP:stopped" >> "$INSTANCE/events"
}
"$OP"
'''
    processes=[subprocess.Popen(['sh','-c',code],env={**environment(tmp_path),'OP':op},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for op in ['start_distributed','stop_distributed','distributed_restart']]
    for process in processes:
        out,err=process.communicate(timeout=10)
        assert process.returncode==0,err
    groups=[]
    for event in (tmp_path/'events').read_text().splitlines():
        name=event.split(':')[0]
        if not groups or groups[-1]!=name:groups.append(name)
    assert len(groups)==3 and len(set(groups))==3
    result=subprocess.run(['sh','-c',code],env={**environment(tmp_path),'OP':'start_distributed','FAIL_START':'7'},capture_output=True,text=True,timeout=5)
    assert result.returncode==7
    assert not (tmp_path/'twn-distributed.pid.lock').exists()

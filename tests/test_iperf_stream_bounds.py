import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
from twn_toolkit import iperf_server as server
from twn_toolkit import iperf_tools as tools
from twn_toolkit.network_tools import ToolInputError
from tests.test_iperf_tools import TCP_PAYLOAD

CONFIG={'bind_address':'127.0.0.1','port':5201}


def executable(tmp_path,body='',streaming=True):
 path=tmp_path/'iperf3-fixture'
 path.write_text('#!'+sys.executable+'\nimport os,sys,time,json,signal,subprocess\n'
  'if "--version" in sys.argv:\n print("iperf 3.fixture");sys.exit()\n'
  'if "--help" in sys.argv:\n print('+repr('--json-stream' if streaming else '-J --json')+');sys.exit()\n'+body+'\n')
 path.chmod(0o700);return str(path)


def select_binary(monkeypatch,path):
 original=tools.shutil.which
 monkeypatch.setattr(tools.shutil,'which',lambda name:path if name=='iperf3' else original(name))


def test_capability_distinguishes_client_from_managed_streaming_and_fences_admission(tmp_path,monkeypatch):
 path=executable(tmp_path,streaming=False);select_binary(monkeypatch,path)
 capability=tools.iperf3_capability()
 assert capability['available'] and not capability['server_available']
 assert path in capability['server_detail'] and 'Client mode remains available' in capability['server_detail']
 assert tools._iperf3_executable()==path
 store=server.IperfServerStore(tmp_path)
 monkeypatch.setattr(server,'assert_iperf3_listener_available',lambda _:pytest.fail('Admission must fail before binding'))
 with pytest.raises(ToolInputError,match='streaming JSON'):store.create(CONFIG,created_by='owner',created_by_username='Owner')
 with store._connect() as db:assert db.execute('SELECT count(*) FROM iperf_server_sessions').fetchone()[0]==0


def test_streaming_capability_is_detected_from_help_without_version_guessing(tmp_path,monkeypatch):
 path=executable(tmp_path);select_binary(monkeypatch,path)
 assert tools.iperf3_capability()['server_available']
 assert tools._iperf3_executable(require_streaming=True)==path

@pytest.mark.parametrize('body,error',[
 ('time.sleep(20)',subprocess.TimeoutExpired),
 ('os.close(1);os.close(2);time.sleep(20)',subprocess.TimeoutExpired),
 ('os.write(1,b"x"*70000)',ValueError),
])
def test_probe_has_time_and_output_limits(tmp_path,body,error):
 path=tmp_path/'probe';path.write_text('#!'+sys.executable+'\nimport os,time\n'+body);path.chmod(0o700)
 start=time.monotonic()
 with pytest.raises(error):tools._probe_iperf3(str(path),'--help')
 assert time.monotonic()-start<5


def test_partial_line_does_not_block_stop_and_started_pid_is_cleared(tmp_path,monkeypatch):
 path=executable(tmp_path,'os.write(1,b"{");time.sleep(20)');select_binary(monkeypatch,path)
 started=[];deadline=time.monotonic()+.4
 result=server.run_managed_iperf3_server(CONFIG,should_stop=lambda:time.monotonic()>=deadline,result_completed=lambda _:None,process_started=started.append)
 assert result=='stopped' and started[0]>0 and started[-1] is None
 with pytest.raises(ProcessLookupError):os.kill(started[0],0)
 assert time.monotonic()<deadline+3


def test_active_test_deadline_survives_a_partial_next_line(tmp_path,monkeypatch):
 body='os.write(1,b\'{"event":"start","data":{}}\\n{\');time.sleep(20)'
 path=executable(tmp_path,body);select_binary(monkeypatch,path);monkeypatch.setattr(server,'IPERF_SERVER_CYCLE_SECONDS',.2)
 start=time.monotonic()
 with pytest.raises(ToolInputError,match='ten-minute'):
  server.run_managed_iperf3_server(CONFIG,should_stop=lambda:False,result_completed=lambda _:None)
 assert time.monotonic()-start<3

@pytest.mark.parametrize('body',[
 'os.write(1,b"x"*(2*1024*1024+65536));time.sleep(20)',
 'os.write(1,b"\\xff\\n");time.sleep(20)',
 'os.write(1,b"not json\\n");time.sleep(20)',
])
def test_oversized_or_invalid_event_stops_owned_process(tmp_path,monkeypatch,body):
 path=executable(tmp_path,body);select_binary(monkeypatch,path);started=[]
 with pytest.raises(ToolInputError):server.run_managed_iperf3_server(CONFIG,should_stop=lambda:False,result_completed=lambda _:None,process_started=started.append)
 assert started[-1] is None
 with pytest.raises(ProcessLookupError):os.kill(started[0],0)


@pytest.mark.parametrize("trailing_newline",[True,False])
def test_streamed_records_split_across_reads_produce_one_complete_result(tmp_path,monkeypatch,trailing_newline):
 lines=[{'event':'start','data':TCP_PAYLOAD['start']},{'event':'interval','data':TCP_PAYLOAD['intervals'][0]},{'event':'end','data':TCP_PAYLOAD['end']}]
 raw='\n'.join(json.dumps(row) for row in lines)+('\n' if trailing_newline else '')
 path=executable(tmp_path,'raw='+repr(raw.encode())+'\nfor i in range(0,len(raw),7):os.write(1,raw[i:i+7])\nsys.exit(0)')
 select_binary(monkeypatch,path);results=[]
 assert server.run_managed_iperf3_server(CONFIG,should_stop=lambda:bool(results),result_completed=results.append)=='stopped'
 assert len(results)==1 and results[0]['protocol']=='TCP'


def test_collector_bounds_aggregate_payload_and_rejects_overlapping_starts(monkeypatch):
 monkeypatch.setattr(server,'IPERF_SERVER_OUTPUT_LIMIT',1024)
 collector=server.IperfJsonStreamCollector(config=CONFIG,command=['fixture'])
 start=json.dumps({'event':'start','data':{}})
 collector.feed(start)
 with pytest.raises(ValueError,match='previous test'):collector.feed(start)
 interval=json.dumps({'event':'interval','data':{'padding':'x'*600}})
 collector.feed(interval)
 with pytest.raises(ValueError,match='aggregate'):collector.feed(interval)
 collector.feed(json.dumps({'event':'error','data':'reset'}));collector.feed(start);collector.feed(interval)
 assert len(collector.payload['intervals'])==1


def test_callback_failure_still_terminates_process_and_clears_pid(tmp_path,monkeypatch):
 path=executable(tmp_path,'time.sleep(20)');select_binary(monkeypatch,path);pids=[]
 def record(pid):
  pids.append(pid)
  if pid is not None:raise RuntimeError('fixture persistence failure')
 with pytest.raises(RuntimeError,match='persistence failure'):
  server.run_managed_iperf3_server(CONFIG,should_stop=lambda:False,result_completed=lambda _:None,process_started=record)
 assert pids[-1] is None
 with pytest.raises(ProcessLookupError):os.kill(pids[0],0)

@pytest.mark.parametrize('probe',[False,True])
def test_exited_parent_does_not_leave_pipe_holding_descendant(tmp_path,monkeypatch,probe):
 lock=tmp_path/'child.lock';ready=tmp_path/'ready'
 child='import fcntl,os,signal,time;f=open('+repr(str(lock))+',"w");fcntl.flock(f,fcntl.LOCK_EX);signal.signal(signal.SIGTERM,signal.SIG_IGN);open('+repr(str(ready))+',"w").close();os.write(1,b"{");time.sleep(20)'
 body='subprocess.Popen([sys.executable,"-c",'+repr(child)+'])\nwhile not os.path.exists('+repr(str(ready))+'):time.sleep(.01)\nos._exit(0)'
 if probe:
  path=tmp_path/'probe';path.write_text('#!'+sys.executable+'\nimport os,sys,time,subprocess\n'+body);path.chmod(0o700)
  with pytest.raises(subprocess.TimeoutExpired):tools._probe_iperf3(str(path),'--help')
 else:
  path=executable(tmp_path,body);select_binary(monkeypatch,path);deadline=time.monotonic()+.5
  assert server.run_managed_iperf3_server(CONFIG,should_stop=lambda:ready.exists() and time.monotonic()>=deadline,result_completed=lambda _:None)=='stopped'
 assert ready.exists()
 with lock.open('a') as stream:
  deadline=time.monotonic()+3
  while True:
   try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB);break
   except BlockingIOError:
    assert time.monotonic()<deadline,'Descendant retained its descriptor';time.sleep(.02)


@pytest.mark.parametrize('probe',[False,True])
def test_selector_setup_failure_reaps_process_and_closes_output(tmp_path,monkeypatch,probe):
 path=executable(tmp_path,'time.sleep(20)');created=[];popen=subprocess.Popen
 def launch(*args,**kwargs):
  process=popen(*args,**kwargs);created.append(process);return process
 monkeypatch.setattr(subprocess,'Popen',launch)
 monkeypatch.setattr(server,'_iperf3_executable',lambda **kwargs:path)
 def fail():raise OSError('fixture selector failure')
 monkeypatch.setattr(tools.selectors,'DefaultSelector',fail)
 with pytest.raises(OSError,match='fixture selector failure'):
  if probe:tools._probe_iperf3(path,'--help')
  else:server.run_managed_iperf3_server(CONFIG,should_stop=lambda:False,result_completed=lambda _:None)
 assert len(created)==1 and created[0].poll() is not None and created[0].stdout.closed


def test_unsupported_listener_http_submission_returns_actionable_error_without_launch(tmp_path,monkeypatch):
 from twn_toolkit import create_app
 app=create_app(str(tmp_path));app.testing=True
 try:
  path=executable(tmp_path,streaming=False);select_binary(monkeypatch,path)
  monkeypatch.setattr(server.IperfServerStore,'launch',lambda *args:pytest.fail('Unsupported listener must not launch'))
  response=app.test_client().post('/tools/iperf3/server/start',data={'server_bind_address':'127.0.0.1','server_port':'5201','server_authorized':'on'},follow_redirects=True)
  assert response.status_code==200
  assert b'Client mode remains available' in response.data
  with server.IperfServerStore(tmp_path)._connect() as db:assert db.execute('SELECT count(*) FROM iperf_server_sessions').fetchone()[0]==0
 finally:app.extensions['remote_session_manager'].close()


@pytest.mark.parametrize('exited',[False,True])
def test_group_permission_error_is_ignored_only_after_confirmed_child_exit(monkeypatch,exited):
 class Child:
  pid=123
  def wait(self,timeout):
   if not exited:raise subprocess.TimeoutExpired('fixture',timeout)
   return 0
 def denied(pid,sig):raise PermissionError('fixture exited-group race')
 monkeypatch.setattr(os,'killpg',denied)
 if exited:tools._signal_iperf_group(Child(),15)
 else:
  with pytest.raises(PermissionError,match='exited-group race'):tools._signal_iperf_group(Child(),15)

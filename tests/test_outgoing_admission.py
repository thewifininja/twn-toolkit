import asyncio
import gc
import multiprocessing
import os
import socket
import socketserver
import threading
import time
import weakref
from unittest.mock import patch

import pytest

from twn_toolkit.outgoing_admission import (
    outgoing_slot, async_slot, try_async, _try_acquire,
    outgoing_scope, CapacityWaitTimeout, resolve_instance,
)
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.transfer_admission import transfer_slot
from twn_toolkit.transfer_deadlines import TransferDeadline


def _mixed_worker(instance, port, kind, barrier, active, peak, lock):
    barrier.wait(15)
    async def work_async():
        async with async_slot(instance,'127.0.0.1'):
            work()
    def work():
        with lock:
            active.value+=1;peak.value=max(peak.value,active.value)
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=5) as connection:
                connection.sendall(b'fixture')
                assert connection.recv(16)==b'ack'
        finally:
            with lock:active.value-=1
    if kind=='async':
        asyncio.run(work_async())
    elif kind=='transfer':
        with TransferDeadline(10) as deadline,transfer_slot(instance,'127.0.0.1',deadline):
            work()
    else:
        with outgoing_slot(instance,'127.0.0.1'):
            work()


@pytest.mark.parametrize('total,host_limit',[(2,8),(8,2)])
def test_mixed_processes_share_network_ceiling_with_real_sockets(tmp_path,total,host_limit):
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':total,'outgoing_host_connections':host_limit})
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            assert self.request.recv(16)==b'fixture'
            time.sleep(.15)
            self.request.sendall(b'ack')
    with socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler) as server:
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        context=multiprocessing.get_context('spawn')
        barrier=context.Barrier(7);active=context.Value('i',0);peak=context.Value('i',0);lock=context.Lock()
        workers=[context.Process(target=_mixed_worker,args=(str(tmp_path),server.server_address[1],kind,barrier,active,peak,lock)) for kind in ('probe','transfer','async')*2]
        try:
            for worker in workers:worker.start()
            barrier.wait(15)
            for worker in workers:
                worker.join(15);assert worker.exitcode==0
            assert peak.value==2 and active.value==0
        finally:
            for worker in workers:
                if worker.is_alive():worker.terminate();worker.join(5)
            server.shutdown();thread.join(5)


def test_target_normalization_other_targets_and_lowered_limits(tmp_path):
    settings=OperationalSettingsStore(str(tmp_path))
    settings.save({'outgoing_connections':3,'outgoing_host_connections':1})
    held=[_try_acquire(tmp_path,'EXAMPLE.test.')]
    try:
        assert _try_acquire(tmp_path,'example.test') is None
        held.append(_try_acquire(tmp_path,'other.test'));assert held[-1] is not None
        settings.save({'outgoing_connections':1})
        assert _try_acquire(tmp_path,'third.test') is None
        os.close(held.pop());assert _try_acquire(tmp_path,'third.test') is None
        os.close(held.pop())
        descriptor=_try_acquire(tmp_path,'third.test');assert descriptor is not None;os.close(descriptor)
    finally:
        for descriptor in held:os.close(descriptor)


def test_async_capacity_wait_keeps_loop_responsive_and_releases_on_cancel(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':1})
    held=_try_acquire(tmp_path,'occupied')
    async def run():
        ticks=0
        async def ticker():
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(.005);ticks+=1
        async def wait():
            with pytest.raises(CapacityWaitTimeout):
                async with async_slot(tmp_path,'waiting',wait_seconds=.08):
                    pytest.fail('entered without capacity')
        await asyncio.gather(ticker(),wait())
        assert ticks==20
    try:asyncio.run(run())
    finally:os.close(held)
    with outgoing_slot(tmp_path,'recovered',wait_seconds=.1):pass


@pytest.mark.parametrize('stop',['cancel','deadline'])
@pytest.mark.parametrize('create_before_wait',[False,True])
def test_late_async_acquisition_cannot_leak_slot(tmp_path,stop,create_before_wait):
    entered=threading.Event();release=threading.Event();closed=threading.Event()
    def slow_acquire(*args):
        descriptor=os.open(tmp_path,os.O_RDONLY) if create_before_wait else None
        entered.set();release.wait(5)
        return descriptor if descriptor is not None else os.open(tmp_path,os.O_RDONLY)
    original_close=os.close
    def close(descriptor):
        original_close(descriptor);closed.set()
    async def run():
        with patch('twn_toolkit.outgoing_admission._try_acquire',slow_acquire),patch('twn_toolkit.outgoing_admission.os.close',side_effect=close):
            task=asyncio.create_task(try_async(tmp_path,'fixture',timeout=1 if stop=='deadline' else 5))
            async def await_start():
                while not entered.is_set():
                    if task.done():
                        await task
                        pytest.fail('acquisition ended before the worker started')
                    await asyncio.sleep(.001)
            try:
                await asyncio.wait_for(await_start(),5)
                if stop=='cancel':task.cancel()
                with pytest.raises(asyncio.CancelledError if stop=='cancel' else asyncio.TimeoutError):await task
            finally:release.set()
            for _ in range(100):
                if closed.is_set():break
                await asyncio.sleep(.005)
            assert closed.is_set()
    asyncio.run(run())


def test_async_gates_do_not_keep_closed_event_loops_alive(tmp_path):
    async def run():
        reference=weakref.ref(asyncio.get_running_loop())
        async def admitted(index):
            async with async_slot(tmp_path,str(index)):
                await asyncio.sleep(.01)
        await asyncio.gather(*(admitted(index) for index in range(8)))
        return reference
    reference=asyncio.run(run());gc.collect()
    assert reference() is None


def test_condition_workers_preserve_instance_without_flask_context(tmp_path):
    from twn_toolkit.automation_execution import condition_worker_scope,condition_worker_map
    with condition_worker_scope(str(tmp_path)):
        assert condition_worker_map(lambda unused:resolve_instance(),[1,2],2)==[str(tmp_path)]*2
    assert resolve_instance() is None


def test_tcp_capacity_error_starts_no_socket_or_resolution(tmp_path):
    from twn_toolkit.network_tools import scan_tcp_ports
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':1,'outgoing_admission_seconds':1})
    held=_try_acquire(tmp_path,'occupied')
    try:
        with patch('twn_toolkit.network_tools.socket.getaddrinfo',side_effect=AssertionError('resolved without admission')):
            rows=scan_tcp_ports([{'host':'192.0.2.1'}],[22],timeout=.1,instance_path=str(tmp_path))
        assert rows[0]['status']=='error' and 'capacity wait' in rows[0]['detail']
    finally:os.close(held)


def test_snmp_engine_closes_before_slot_releases(tmp_path):
    from unittest.mock import Mock,AsyncMock
    from twn_toolkit.snmp_tools import run_snmp_tests
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':1})
    engine=Mock()
    def close():assert _try_acquire(tmp_path,'other') is None
    engine.close_dispatcher.side_effect=close
    host={'name':'fixture','host':'192.0.2.1','port':161,'credential_name':'credential','timeout':1,'retries':0}
    credential={'name':'credential','version':'v2c','community':'fixture'}
    with patch('twn_toolkit.snmp_tools.SnmpEngine',return_value=engine),patch('twn_toolkit.snmp_tools._transport_target',new=AsyncMock(return_value=object())),patch('twn_toolkit.snmp_tools._get_entry',new=AsyncMock(return_value=([],''))):
        rows=run_snmp_tests([host],{'credential':credential},[{'name':'profile','entries':[{'operation':'get'}]}],instance_path=str(tmp_path))
    assert rows[0]['status']=='success';engine.close_dispatcher.assert_called_once()
    descriptor=_try_acquire(tmp_path,'other');assert descriptor is not None;os.close(descriptor)


@pytest.mark.parametrize('state',['healthy','suspect','triggered','recovering'])
def test_capacity_wait_preserves_automation_state_and_debounce(tmp_path,state):
    from twn_toolkit.automation import AutomationStore,AutomationEngine
    store=AutomationStore(str(tmp_path),'fixture')
    identifier=store.save(name='capacity fixture',interval_seconds=30,trigger_after=3,recover_after=3,cooldown_seconds=0,
        condition={'type':'tcp.reachability','config':{'targets':'192.0.2.1 | 22','timeout':1,'expected_state':'open','failure_count':1}},
        actions=[{'type':'ssh.collect','config':{'hosts':'192.0.2.2','username':'u','password':'p','commands':'show clock','port':22}}],created_by='fixture')
    with store._connect() as db:
        db.execute('UPDATE automations SET state=?,consecutive_met=2,consecutive_clear=1 WHERE id=?',(state,identifier))
    with patch('twn_toolkit.automation_types.condition_types.network_triggers.scan_tcp_checks',return_value=[{'status':'error','capacity_limited':True}]):
        AutomationEngine(store).process_automation(store.get(identifier))
    with store._connect() as db:
        row=db.execute('SELECT state,consecutive_met,consecutive_clear FROM automations WHERE id=?',(identifier,)).fetchone()
        assert tuple(row)==(state,2,1)
        assert db.execute('SELECT count(*) FROM automation_jobs').fetchone()[0]==0
        assert db.execute('SELECT status FROM automation_checks ORDER BY id DESC LIMIT 1').fetchone()[0]=='capacity_wait'


def test_dns_condition_does_not_treat_unstarted_query_as_device_failure():
    from twn_toolkit.automation_types.condition_types.network_triggers import _evaluate_dns
    config={'hosts':'fixture.example.test','servers':'192.0.2.53','record_type':'A','timeout':1,'failure_count':1}
    with patch('twn_toolkit.automation_types.condition_types.network_triggers.dns_lookup_matrix',return_value=[{'status':'error','capacity_limited':True}]):
        with pytest.raises(CapacityWaitTimeout):_evaluate_dns(config)


def test_tls_condition_preserves_capacity_error_cause():
    from twn_toolkit.automation_types.condition_types.monitoring import _inspect_certificate_target
    from twn_toolkit.certificate_tools import CertificateInspectionError
    original=CapacityWaitTimeout('capacity exhausted')
    wrapped=CertificateInspectionError('capacity exhausted');wrapped.__cause__=original
    with patch('twn_toolkit.automation_types.condition_types.monitoring.inspect_certificate_chain',side_effect=wrapped):
        with pytest.raises(CapacityWaitTimeout):_inspect_certificate_target({'host':'192.0.2.1','port':443},1)


@pytest.mark.parametrize('reply',[True,False])
def test_radius_socket_closes_before_capacity_release(tmp_path,reply):
    from pyrad.client import Client
    from pyrad.packet import AuthPacket,AccessAccept
    from pyrad.dictionary import Dictionary
    from pathlib import Path
    import twn_toolkit.network_tools as network_tools
    from twn_toolkit.network_tools import radius_authenticate
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':1})
    listener=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);listener.bind(('127.0.0.1',0));listener.settimeout(5)
    def serve():
        data,address=listener.recvfrom(4096)
        if reply:
            response=AuthPacket(packet=data,secret=b'fixture',dict=Dictionary(str(Path(network_tools.__file__).with_name('radius_dictionary')))).CreateReply()
            response.code=AccessAccept
            listener.sendto(response.ReplyPacket(),address)
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    original=Client._CloseSocket;closed=[]
    def close(client):
        assert _try_acquire(tmp_path,'other') is None
        original(client);assert client._socket is None;closed.append(True)
    try:
        with patch.object(Client,'_CloseSocket',close):
            rows=radius_authenticate([{'name':'fixture','host':'127.0.0.1','port':listener.getsockname()[1],'secret':'fixture'}],{'username':'u','password':'p'},timeout=.2,retries=1,instance_path=str(tmp_path))
        assert rows[0]['status']==('Access-Accept' if reply else 'error')
        assert closed
        descriptor=_try_acquire(tmp_path,'other');assert descriptor is not None;os.close(descriptor)
    finally:
        thread.join(5);listener.close()


def _hold_global(instance,pipe):
    with outgoing_slot(instance,'held'):
        pipe.send('held');pipe.recv()


def test_process_death_releases_common_capacity(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':1})
    context=multiprocessing.get_context('spawn');parent,child=context.Pipe()
    process=context.Process(target=_hold_global,args=(str(tmp_path),child));process.start();child.close()
    try:
        assert parent.poll(10) and parent.recv()=='held'
        assert _try_acquire(tmp_path,'other') is None
        process.terminate();process.join(5)
        descriptor=_try_acquire(tmp_path,'other');assert descriptor is not None;os.close(descriptor)
    finally:
        if process.is_alive():process.terminate();process.join(5)
        parent.close()


def test_cancelled_snmp_closes_engine_while_slot_is_still_owned(tmp_path):
    from unittest.mock import Mock,AsyncMock
    from twn_toolkit.snmp_tools import _poll_host_profile
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':1})
    engine=Mock()
    def close():assert _try_acquire(tmp_path,'other') is None
    engine.close_dispatcher.side_effect=close
    host={'name':'fixture','host':'192.0.2.1','port':161,'credential_name':'credential','timeout':1,'retries':0}
    credential={'name':'credential','version':'v2c','community':'fixture'}
    async def run():
        entered=asyncio.Event()
        async def get(*args):
            entered.set();await asyncio.Event().wait()
        with outgoing_scope(str(tmp_path)),patch('twn_toolkit.snmp_tools.SnmpEngine',return_value=engine),patch('twn_toolkit.snmp_tools._transport_target',new=AsyncMock(return_value=object())),patch('twn_toolkit.snmp_tools._get_entry',get):
            task=asyncio.create_task(_poll_host_profile(host,credential,{'name':'profile','entries':[{'operation':'get'}]}))
            await asyncio.wait_for(entered.wait(),5);task.cancel()
            with pytest.raises(asyncio.CancelledError):await task
    asyncio.run(run());engine.close_dispatcher.assert_called_once()
    descriptor=_try_acquire(tmp_path,'other');assert descriptor is not None;os.close(descriptor)


def test_intentional_dns_load_preserves_pacing_when_probe_budget_is_full(tmp_path):
    from twn_toolkit.network_tools import dns_load_test
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':1})
    held=_try_acquire(tmp_path,'occupied');now=[0.0]
    def sleep(delay):now[0]+=delay
    def lookup(host,server,record_type,timeout):
        return {'host':host['host'],'server':server['address'],'status':'success','answers':['192.0.2.1'],'response_ms':1}
    try:
        with outgoing_scope(str(tmp_path)),patch('twn_toolkit.network_tools._dns_lookup',side_effect=lookup) as query:
            result=dns_load_test([{'host':'fixture.example.test','label':''}],[{'address':'192.0.2.53','label':''}],duration_seconds=2,qps_per_server=2,concurrency=2,clock=lambda:now[0],sleeper=sleep)
        assert result['planned_queries']==4 and result['completed_queries']==4
        assert result['target_qps_total']==2 and query.call_count==4
    finally:os.close(held)


def test_dns_latency_excludes_capacity_wait():
    from contextlib import contextmanager
    from unittest.mock import Mock
    from twn_toolkit.network_tools import _dns_lookup
    now=[0.0]
    @contextmanager
    def wait(*args,**kwargs):
        now[0]+=10
        yield
    resolver=Mock()
    def resolve(*args,**kwargs):
        now[0]+=.005
        return []
    resolver.resolve.side_effect=resolve
    with patch('twn_toolkit.network_tools.outgoing_slot',wait),patch('twn_toolkit.network_tools.time.monotonic',side_effect=lambda:now[0]),patch('dns.resolver.Resolver',return_value=resolver):
        row=_dns_lookup({'host':'fixture.test','label':''},{'address':'192.0.2.53','label':''},'A',1,'fixture')
    assert row['status']=='success' and row['response_ms']==5


def test_local_admission_failure_is_not_reported_as_device_failure(tmp_path):
    from twn_toolkit.network_tools import scan_tcp_ports
    with patch('twn_toolkit.outgoing_admission._acquire_slots',side_effect=PermissionError('fixture')),patch('twn_toolkit.network_tools.socket.getaddrinfo',side_effect=AssertionError('probe started')):
        row=scan_tcp_ports([{'host':'192.0.2.1'}],[22],timeout=.1,instance_path=str(tmp_path))[0]
    assert row['capacity_limited'] and 'PermissionError' in row['detail']


@pytest.mark.parametrize('protocol,remaining_pair',[('ftp',False),('sftp',True)])
def test_ftp_reserves_control_and_data_slots(tmp_path,monkeypatch,protocol,remaining_pair):
    from twn_toolkit.sftp_tools import fetch_ssh_files
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':3})
    def fetch(**kwargs):
        descriptor=_try_acquire(tmp_path,'other',weight=2)
        assert (descriptor is not None)==remaining_pair
        if descriptor is not None:os.close(descriptor)
        raise OSError('fixture complete')
    monkeypatch.setattr('twn_toolkit.sftp_tools._fetch_'+protocol+'_host',fetch)
    rows=fetch_ssh_files(hosts=[{'host':'192.0.2.1'}],remote_paths=['/fixture'],username='u',password='p',port=21 if protocol=='ftp' else 22,allow_unknown_hosts=False,output_dir=tmp_path/'output',protocol=protocol,instance_path=str(tmp_path))
    assert rows[0]['status']=='error'
    descriptor=_try_acquire(tmp_path,'other',weight=2);assert descriptor is not None;os.close(descriptor)


def test_protocol_weight_larger_than_configured_limit_fails_without_wait(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({'outgoing_connections':1})
    with pytest.raises(CapacityWaitTimeout,match='requiring 2 slots'):
        with outgoing_slot(tmp_path,'fixture',weight=2):pytest.fail('admitted two sockets into one slot')

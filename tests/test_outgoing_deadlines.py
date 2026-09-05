import io
import socket
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from twn_toolkit.sftp_tools import fetch_ssh_files
from twn_toolkit.transfer_deadlines import TransferDeadline, TransferPolicy, close_socket
from twn_toolkit.operational import OperationalSettingsStore


def fetch(tmp_path, **kwargs):
    return fetch_ssh_files(hosts=[{"host":"test", "label":""}], remote_paths=["/file"],
                          username="user", password="password", port=22, allow_unknown_hosts=True,
                          output_dir=tmp_path, policy=TransferPolicy(deadline_seconds=.15), **kwargs)


@pytest.mark.parametrize("stage", ["subsystem", "stat", "read", "close"])
def test_deadline_interrupts_sftp_lifecycle_without_publishing_partial_file(tmp_path, stage):
    closed = threading.Event()
    client=MagicMock(); client.close.side_effect=closed.set
    sftp=client.open_sftp.return_value; sftp.stat.return_value.st_size=4
    source=MagicMock(); source.__enter__.return_value=io.BytesIO(b"data")
    sftp.open.return_value=source
    def blocked(*args, **kwargs):
        assert closed.wait(2), "deadline did not close transport"
        raise OSError("transport interrupted")
    if stage=="subsystem": client.open_sftp.side_effect=blocked
    elif stage=="stat": sftp.stat.side_effect=blocked
    elif stage=="read": source.__enter__.return_value=MagicMock(read=blocked)
    else: source.__exit__.side_effect=blocked
    with patch("paramiko.SSHClient", return_value=client):
        started=time.monotonic(); results=fetch(tmp_path)
    assert time.monotonic()-started < 2
    assert results[0]["status"]=="error"
    assert list(tmp_path.iterdir())==[]


def test_deadline_interrupts_blocked_socket_read():
    left,right=socket.socketpair()
    try:
        with TransferDeadline(.1) as deadline:
            deadline.watch("data", lambda: close_socket(left))
            started=time.monotonic()
            try: data=left.recv(1)
            except OSError: data=b""
            assert data==b"" and time.monotonic()-started < 1
    finally:
        left.close(); right.close()


def test_late_resource_is_closed_after_deadline():
    closed=[]
    with TransferDeadline(.01) as deadline:
        time.sleep(.03)
        with pytest.raises(TimeoutError):
            deadline.watch("late", lambda: closed.append(True))
    assert closed==[True]


def test_short_sftp_download_is_not_published(tmp_path):
    client=MagicMock(); sftp=client.open_sftp.return_value; sftp.stat.return_value.st_size=8
    source=MagicMock(); source.__enter__.return_value=io.BytesIO(b"short"); sftp.open.return_value=source
    with patch("paramiko.SSHClient", return_value=client): results=fetch(tmp_path)
    assert results[0]["status"]=="error"
    assert list(tmp_path.iterdir())==[]


def test_outgoing_policy_validation_and_legacy_defaults(tmp_path):
    store=OperationalSettingsStore(str(tmp_path))
    assert TransferPolicy.from_settings(store.get()) == TransferPolicy()
    values=store.save({"transfer_workers":2,"transfer_idle_seconds":7,"transfer_deadline_seconds":45,
                       "transfer_file_mib":3,"transfer_run_mib":8})
    assert TransferPolicy.from_settings(values)==TransferPolicy(2,7,45,3*1024**2,8*1024**2)
    for field in ("transfer_workers","transfer_idle_seconds","transfer_deadline_seconds","transfer_file_mib","transfer_run_mib"):
        for invalid in (0,True,"1.5"):
            with pytest.raises(ValueError): store.save({field:invalid})


def test_ftp_deadline_closes_data_socket_and_discards_partial_output(tmp_path):
    left,right=socket.socketpair()
    class FTP:
        sock=None
        def connect(self,*args,**kwargs): pass
        def login(self,*args): pass
        def voidcmd(self,*args): pass
        def size(self,*args): return None
        def ntransfercmd(self,*args): return left,None
        def retrbinary(self, command, callback, **kwargs):
            data,_=self.ntransfercmd(command)
            callback(b"prefix")
            data.recv(1)
        def quit(self): pass
        def close(self): pass
    try:
        with patch("twn_toolkit.sftp_tools.ftplib.FTP", FTP): results=fetch(tmp_path, protocol="ftp")
        assert results[0]["status"]=="error"
        assert list(tmp_path.iterdir())==[]
    finally: left.close(); right.close()


def test_scp_timestamp_trickle_cannot_extend_absolute_deadline(tmp_path):
    import itertools
    stream=itertools.cycle(b"T0 0 0 0\n")
    client=MagicMock(); channel=client.get_transport.return_value.open_session.return_value
    def recv(_):
        time.sleep(.005)
        return bytes([next(stream)])
    channel.recv.side_effect=recv
    with patch("paramiko.SSHClient", return_value=client): results=fetch(tmp_path, protocol="scp")
    assert results[0]["status"]=="error"
    assert "deadline" in results[0]["error"]
    assert list(tmp_path.iterdir())==[]


def test_live_sftp_stalled_stat_releases_fetch_worker(tmp_path):
    import paramiko
    listener=socket.socket(); listener.bind(("127.0.0.1",0)); listener.listen(1); listener.settimeout(4)
    port=listener.getsockname()[1]
    closed=threading.Event(); errors=[]
    class Auth(paramiko.ServerInterface):
        def check_auth_password(self,*args): return paramiko.AUTH_SUCCESSFUL
        def check_channel_request(self,*args): return paramiko.OPEN_SUCCEEDED
    class Stalled(paramiko.SFTPServerInterface):
        def stat(self,path):
            closed.wait(4)
            return paramiko.SFTP_FAILURE
    def serve():
        transport=None
        try:
            conn,_=listener.accept(); transport=paramiko.Transport(conn)
            transport.add_server_key(paramiko.RSAKey.generate(2048))
            transport.set_subsystem_handler("sftp",paramiko.SFTPServer,Stalled)
            transport.start_server(server=Auth())
            while transport.is_active() and not closed.wait(.02): pass
        except Exception as exc: errors.append(exc)
        finally:
            closed.set()
            if transport: transport.close()
    worker=threading.Thread(target=serve,daemon=True); worker.start()
    try:
        started=time.monotonic()
        results=fetch_ssh_files(hosts=[{"host":"127.0.0.1","label":""}],remote_paths=["/stalled"],
                               username="user",password="password",port=port,allow_unknown_hosts=True,
                               output_dir=tmp_path,policy=TransferPolicy(deadline_seconds=1))
        assert time.monotonic()-started < 3
        assert results[0]["status"]=="error"
        assert not list(tmp_path.iterdir())
    finally:
        closed.set(); listener.close(); worker.join(5)
    assert not worker.is_alive()
    assert not errors

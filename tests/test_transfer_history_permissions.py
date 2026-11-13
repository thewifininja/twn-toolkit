import os
import stat

from twn_toolkit.ssh_transfer_server import SSHTransferHistoryStore


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_history_database_is_owner_only_under_a_permissive_umask(tmp_path):
    previous = os.umask(0o022)
    try:
        store = SSHTransferHistoryStore(str(tmp_path))
        assert _mode(store.path) == 0o600
        # An existing installation's file is corrected on its next use.
        os.chmod(store.path, 0o644)
        store.recent()
        assert _mode(store.path) == 0o600
    finally:
        os.umask(previous)

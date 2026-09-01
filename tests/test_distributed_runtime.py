from __future__ import annotations

import json
import stat
from pathlib import Path

from twn_toolkit.distributed_runtime import (
    ACTIVATION_FILE,
    agent_activation,
    clear_inactive_distributed_runtime,
)
from twn_toolkit.distributed_worker import main as distributed_worker_main


def test_standalone_cleanup_removes_transient_state_and_retains_trust(tmp_path):
    credentials = tmp_path / "distributed_agent_credentials"
    credentials.mkdir()
    certificate = credentials / "client-cert.pem"
    authority = credentials / "mainframe-ca.pem"
    pending = credentials / "pending.json"
    for path in (certificate, authority, pending):
        path.write_text("retained", encoding="utf-8")
    for name in (
        "distributed-status.json",
        "distributed-job-results.json",
        "twn-distributed.pid",
        ".twn-distributed.lock",
        ".distributed-status.json.123.tmp",
    ):
        (tmp_path / name).write_text("transient", encoding="utf-8")

    previous = agent_activation(tmp_path)["activation_id"]
    result = clear_inactive_distributed_runtime(tmp_path)

    assert result["activation_id"] != previous
    assert not (tmp_path / "distributed-status.json").exists()
    assert not (tmp_path / "distributed-job-results.json").exists()
    assert not (tmp_path / "twn-distributed.pid").exists()
    assert not (tmp_path / ".twn-distributed.lock").exists()
    assert not (tmp_path / ".distributed-status.json.123.tmp").exists()
    assert certificate.read_text(encoding="utf-8") == "retained"
    assert authority.read_text(encoding="utf-8") == "retained"
    assert pending.read_text(encoding="utf-8") == "retained"
    assert stat.S_IMODE((tmp_path / ACTIVATION_FILE).stat().st_mode) == 0o600


def test_agent_activation_is_stable_until_standalone_cleanup(tmp_path):
    first = agent_activation(tmp_path)
    second = agent_activation(tmp_path)

    assert first == second
    assert len(bytes.fromhex(first["activation_id"])) == 16


def test_direct_standalone_worker_clears_stale_runtime(tmp_path, monkeypatch):
    (tmp_path / "distributed-status.json").write_text(
        json.dumps({"role": "agent", "state": "connected"}), encoding="utf-8"
    )
    pid_path = tmp_path / "worker.pid"
    monkeypatch.setattr(
        "sys.argv",
        [
            "distributed-worker",
            "--instance",
            str(tmp_path),
            "--pid-file",
            str(pid_path),
        ],
    )

    distributed_worker_main()

    assert not pid_path.exists()
    assert not (tmp_path / "distributed-status.json").exists()
    assert (tmp_path / ACTIVATION_FILE).exists()


def test_launcher_cleans_runtime_only_after_distributed_process_cleanup():
    source = Path("twn").read_text(encoding="utf-8")
    function = source.split("stop_distributed() {", 1)[1].split(
        "\n}\n\nstop_packet_captures", 1
    )[0]

    assert function.count("distributed_runtime clear-inactive") == 2
    assert function.index("cleanup_worker_processes") < function.index(
        "distributed_runtime clear-inactive"
    )
    assert function.count('if ! distributed_enabled && [ -x "$PYTHON" ]; then') == 2

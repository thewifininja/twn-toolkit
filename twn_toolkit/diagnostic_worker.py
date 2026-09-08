"""Finite diagnostic subprocesses supervised by the existing scheduler."""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from .diagnostic_jobs import DiagnosticJobStore
from .network_tools import scan_tcp_ports


def _signal_work(work, sig):
    process = work['process']
    if work.get('owned_group'):
        from .iperf_tools import _signal_iperf_group
        _signal_iperf_group(process, sig)
    elif sig == signal.SIGKILL:
        process.kill()
    else:
        process.terminate()


class DiagnosticScheduler:
    def __init__(self, instance):
        self.store = DiagnosticJobStore(instance)
        for job in self.store.recover():
            record_unsuccessful_scan(self.store, job, "unknown", "Scheduler restarted before confirming completion.")
        self.active = {}
        self.next_cleanup = 0.0

    def tick(self, running=lambda: True):
        policy = self.store.policy.get()
        now = time.monotonic()
        if now >= self.next_cleanup:
            self.store.cleanup()
            self.next_cleanup = now + 60
        for job_id, work in list(self.active.items()):
            process = work["process"]
            job = self.store.owned(job_id, work["token"])
            if process.poll() is not None:
                if work.get("owned_group"):
                    _signal_work(work, signal.SIGKILL)
                if job and job["state"] in {"running", "cancel_requested"}:
                    reason = work.get("reason") or ("deadline" if process.returncode == 124 or now >= work["deadline"] else "")
                    state = "cancelled" if reason == "cancel" or job["state"] == "cancel_requested" else "failed"
                    error = "Diagnostic cancelled." if state == "cancelled" else (
                        "Run deadline exceeded; no complete result was confirmed." if reason == "deadline"
                        else "Diagnostic process exited without a confirmed result."
                    )
                    _abort(self.store, job_id, work["token"], state, error)
                self.store.release(job_id, work["token"])
                del self.active[job_id]
                continue
            reason = "cancel" if job and job["state"] == "cancel_requested" else (
                "deadline" if now >= work["deadline"] else ("ownership" if not job else "")
            )
            if reason and not work.get("reason"):
                work["reason"] = reason
                work["kill_at"] = now + 2
                _signal_work(work, signal.SIGTERM)
            elif work.get("reason") and now >= work["kill_at"]:
                _signal_work(work, signal.SIGKILL)
        while running() and len(self.active) < policy["diagnostic_workers"]:
            job = self.store.claim()
            if not job:
                break
            process = None
            owned_group = job["tool"] in {"iperf_client", "bulk_ssh"}
            try:
                process = subprocess.Popen(
                    [sys.executable, "-m", "twn_toolkit.diagnostic_worker",
                     "--instance", str(self.store.instance), "--job", job["id"]],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                    # POSIX daemonization changes cwd to "/". Resolve the
                    # package root explicitly for source checkouts and bundles.
                    cwd=str(Path(__file__).resolve().parent.parent),
                    # Use the scheduler log; inputs and tokens are never logged.
                    close_fds=True, start_new_session=owned_group,
                )
                process.stdin.write(json.dumps({"token": job["token"], "parent": os.getpid(), "timeout": job["timeout"], "owned_group": owned_group}).encode())
                process.stdin.close()
                self.active[job["id"]] = {
                    "process": process, "token": job["token"], "owned_group": owned_group,
                    "deadline": time.monotonic() + job["timeout"],
                }
            except (OSError, ValueError):
                if process is not None:
                    _signal_work({"process": process, "owned_group": owned_group}, signal.SIGKILL)
                    process.wait()
                    try:
                        process.stdin.close()
                    except (OSError, ValueError):
                        pass
                _abort(self.store, job["id"], job["token"], "failed", "Unable to start the diagnostic process.")
                # No active entry will revisit this claim. Release only after
                # the child is reaped and outcome recording has completed.
                self.store.release(job["id"], job["token"])

    def close(self):
        # Confirm process termination before reporting an interrupted outcome.
        for work in self.active.values():
            if work["process"].poll() is None:
                _signal_work(work, signal.SIGTERM)
        deadline = time.monotonic() + 2
        for job_id, work in self.active.items():
            process = work["process"]
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                _signal_work(work, signal.SIGKILL)
                process.wait()
            if work.get("owned_group"):
                _signal_work(work, signal.SIGKILL)
            _abort(self.store, job_id, work["token"], "unknown", "Scheduler stopped before confirming completion. This run was not replayed.")
            self.store.release(job_id, work["token"])
        self.active.clear()


def execute_scan(store, job_id, token):
    job = store.owned(job_id, token)
    if not job or job["state"] != "running":
        return
    config = json.loads(store.cipher.open(job["config"], job_id + ":diagnostic-config"))
    if job["tool"].startswith("certificate_"):
        from .certificate_jobs import execute_certificate
        execute_certificate(store, job, config)
        return
    if job["tool"] == "bulk_ssh":
        from .bulk_ssh_jobs import execute_ssh
        execute_ssh(store, job, config)
        return
    if job["tool"] == "iperf_client":
        from .iperf_client_jobs import execute_iperf_client
        execute_iperf_client(store, job, config)
        return
    if job["tool"] in {"fac_inventory_devices", "fac_inventory_memberships"}:
        from .fac_inventory import execute_inventory
        execute_inventory(store, job, config)
        return
    if job["tool"] == "switch_order":
        from .switch_order_jobs import execute_switch_order
        execute_switch_order(store, job, config)
        return
    if job["tool"] == "fac_cleanup":
        from .fac_cleanup_jobs import execute_cleanup
        execute_cleanup(store, job, config)
        return
    if job["tool"] == "appliance_rename":
        from .rename_jobs import execute_rename
        execute_rename(store, job, config)
        return
    if job["tool"] == "appliance_read":
        from .appliance_read import execute_read
        execute_read(store, job, config)
        return
    if job["tool"] == "case_export":
        from .case_export import execute_case_export
        execute_case_export(store, job, config)
        return
    if job["tool"] == "wireless_history":
        from .wireless_history_diagnostic import execute_history
        execute_history(store, job, config)
        return
    if job["tool"] == "transfer":
        from .transfer_diagnostic import execute_transfer
        execute_transfer(store, job, config)
        return
    if job["tool"] == "dns":
        from .dns_diagnostic import execute_dns
        execute_dns(store, job, config)
        return
    if job["tool"] != "tcp_scan":
        raise ValueError("Unsupported diagnostic.")
    form = config["form"]
    rows = scan_tcp_ports(config["targets"], config["ports"],
                          timeout=float(form["timeout"]), max_workers=int(form["concurrency"]))
    stats = {"combinations": len(rows)}
    stats.update({state: sum(row["status"] == state for row in rows) for state in ("open", "closed", "timeout", "error")})
    if store.finish(job_id, token, rows, {"stats": stats}):
        _record_scan(store, job, config, rows, stats)


def _record_scan(store, job, config, rows, stats):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore

    identity = {"user_id": job["user_id"], "username": config["username"]}
    try:
        ActivityStore(str(store.instance)).record_event(
            "Ports", "Ran TCP port scan",
            f"{len(config['targets'])} host(s), {len(config['ports'])} port(s), {stats['open']} open",
            counters={"tcp": {"ports_scanned": len(rows)}}, count_action=True, **identity,
        )
    except Exception as exc:
        print(f"Diagnostic activity recording failed: {type(exc).__name__}", file=sys.stderr)
    try:
        AuditStore(str(store.instance)).record(
            **identity, method="WORKER", endpoint="tools.port_scanner",
            path="/tools/port-scanner", status_code=200,
            category="Network tools", action="tcp_scanner.completed",
            summary="Completed TCP port scan", resource_id=job["id"],
            details={"operation_id": job["id"], **stats},
        )
    except Exception as exc:
        print(f"Diagnostic audit recording failed: {type(exc).__name__}", file=sys.stderr)
    if not config.get("investigation_id"):
        return
    try:
        form = config["form"]
        event = InvestigationStore(str(store.instance)).record_for_case(
            investigation_id=config["investigation_id"], **identity,
            operation_id="port-scan:" + job["id"], event_type="diagnostic.completed",
            tool_id="tools.port_scanner", action="TCP port scan", outcome="succeeded",
            summary=f"Scanned {len(config['targets'])} host(s) across {len(config['ports'])} TCP port(s): {stats['open']} open, {stats['closed']} closed, and {stats['timeout']} timed out.",
            targets={"hosts": config["targets"]},
            parameters={"ports": config["ports"], "timeout_seconds": form["timeout"],
                        "concurrency": form["concurrency"], "display_open_only": form["open_only"]},
            metrics=stats, details={"error": "", "results": rows},
            started_at=job["started"], completed_at=time.time(),
        )
        summary = store.cipher.seal(json.dumps({"stats": stats, "journal_event": {"id": event["id"], "investigation_id": event["investigation_id"]}}), job["id"] + ":diagnostic-summary")
        with store.connect(write=True) as db:
            db.execute("UPDATE diagnostic_jobs SET summary=? WHERE id=? AND state='succeeded'", (summary, job["id"]))
    except Exception as exc:
        print(f"Diagnostic case recording failed: {type(exc).__name__}", file=sys.stderr)


def _abort(store, job_id, token, state, error):
    current = store.owned(job_id, token)
    if current and current["tool"] in {"switch_order", "appliance_rename", "fac_cleanup"}:
        from .switch_order_jobs import interruption_outcome
        state, error = interruption_outcome(store, current, state, error)
    job = store.abort(job_id, token, state, error)
    if job:
        record_unsuccessful_scan(store, job, state, error)


def record_unsuccessful_scan(store, job, state, error):
    """Best-effort attribution; recording errors never replay network work."""
    if job["tool"].startswith("certificate_"):
        from .certificate_jobs import record_certificate_outcome
        record_certificate_outcome(store, job, state, error)
        return
    if job["tool"] == "bulk_ssh":
        from .bulk_ssh_jobs import record_outcome
        record_outcome(store, job, state, error)
        return
    if job["tool"] == "iperf_client":
        from .iperf_client_jobs import record_iperf_client_outcome
        record_iperf_client_outcome(store, job, state, error)
        return
    if job["tool"] in {"fac_inventory_devices", "fac_inventory_memberships"}:
        from .fac_inventory import record_inventory_outcome
        record_inventory_outcome(store, job, state, error)
        return
    if job["tool"] == "switch_order":
        from .switch_order_jobs import record_switch_outcome
        record_switch_outcome(store, job, state)
        return
    if job["tool"] == "fac_cleanup":
        from .fac_cleanup_jobs import record_cleanup_outcome
        record_cleanup_outcome(store, job, state)
        return
    if job["tool"] == "appliance_rename":
        from .rename_jobs import record_rename_outcome
        record_rename_outcome(store, job, state)
        return
    if job["tool"] == "appliance_read":
        from .appliance_read import record_read_outcome
        record_read_outcome(store, job, state)
        return
    if job["tool"] == "case_export":
        from .case_export import record_case_export_outcome
        record_case_export_outcome(store, job, state)
        return
    if job["tool"] == "wireless_history":
        from .wireless_history_diagnostic import record_history_outcome
        record_history_outcome(store, job, state, error)
        return
    if job["tool"] == "transfer":
        from .transfer_diagnostic import record_transfer_outcome
        record_transfer_outcome(store, job, state, error)
        return
    if job["tool"] == "dns":
        from .dns_diagnostic import record_dns_outcome
        record_dns_outcome(store, job, state, error)
        return
    from .audit import AuditStore
    from .investigations import InvestigationStore
    try:
        config = job["config"]
        if isinstance(config, str):
            config = json.loads(store.cipher.open(config, job["id"] + ":diagnostic-config"))
        identity = {"user_id": job["user_id"], "username": config["username"]}
        AuditStore(str(store.instance)).record(
            **identity, method="WORKER", endpoint="tools.port_scanner",
            path="/tools/port-scanner", status_code=200,
            category="Network tools", action="tcp_scanner." + state,
            summary="TCP port scan " + state, resource_id=job["id"],
            details={"operation_id": job["id"], "outcome": state},
        )
        if config.get("investigation_id"):
            InvestigationStore(str(store.instance)).record_for_case(
                investigation_id=config["investigation_id"], **identity,
                operation_id="port-scan:" + job["id"], event_type="diagnostic." + state,
                tool_id="tools.port_scanner", action="TCP port scan",
                outcome="incomplete" if state == "unknown" else state,
                summary="TCP port scan " + state + ": " + error,
                targets={"hosts": config["targets"]}, parameters=config["form"],
                metrics={}, details={"error": error},
                started_at=job.get("started") or job["created"], completed_at=time.time(),
            )
    except Exception as exc:
        print(f"Diagnostic outcome recording failed: {type(exc).__name__}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", required=True)
    parser.add_argument("--job", required=True)
    args = parser.parse_args()
    ownership = json.loads(sys.stdin.buffer.read(1024))
    parent = int(ownership["parent"])
    deadline = time.monotonic() + float(ownership["timeout"])
    token = str(ownership["token"])

    owned_group = bool(ownership.get('owned_group'))
    if owned_group and os.getpgrp() != os.getpid():
        # Direct worker entry points must also own their group before spawning.
        os.setsid()

    def stop_owned(code):
        if owned_group:
            os.killpg(os.getpid(), signal.SIGKILL)
        os._exit(code)

    def parent_watch():
        # A killed/restarted scheduler must not leave orphan scan threads.
        while True:
            if time.monotonic() >= deadline:
                stop_owned(124)
            if os.getppid() != parent:
                stop_owned(1)
            time.sleep(0.2)

    threading.Thread(target=parent_watch, daemon=True, name="diagnostic-parent-watch").start()
    store = DiagnosticJobStore(args.instance)
    try:
        execute_scan(store, args.job, token)
    except Exception as exc:
        current = store.owned(args.job, token)
        state = "cancelled" if current and current["state"] == "cancel_requested" else "failed"
        _abort(store, args.job, token, state, f"Run {state}: {type(exc).__name__}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

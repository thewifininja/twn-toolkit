from __future__ import annotations

import io
import json
import os
import re
import tempfile
import time
import zipfile
import secrets
from pathlib import Path

from flask import Blueprint, current_app, g, redirect, render_template, request, send_file, url_for

from .activity_context import record_current_activity
from .audit import annotate_tool_run, suppress_audit_event
from .datastore import DatastoreError, LocalDatastore, format_bytes
from .network_tools import ToolInputError, parse_ssh_targets
from .transfer_tools import (
    DEFAULT_TRANSFER_FILENAME_PATTERN as SFTP_DEFAULT_FILENAME_PATTERN,
    fetch_transfer_files as fetch_ssh_files,
    parse_remote_paths as parse_sftp_paths,
    validate_transfer_filename_pattern as validate_sftp_filename_pattern,
)
from .investigation_context import (
    add_current_investigation_generated_evidence_event,
    record_current_investigation_event,
)


def register_sftp_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/multi-transfer", methods=["GET", "POST"])
    def multi_transfer():
        store = LocalDatastore(current_app.instance_path)
        requested_protocol = request.args.get("protocol", "sftp").lower()
        form = {
            "hosts": "",
            "username": "",
            "port": "21" if requested_protocol == "ftp" else "22",
            "remote_paths": "",
            "allow_unknown_hosts": False,
            "allow_legacy_algorithms": False,
            "destination": "",
            "output_mode": "download",
            "filename_pattern": SFTP_DEFAULT_FILENAME_PATTERN,
            "protocol": requested_protocol,
        }
        results: list[dict[str, object]] | None = None
        error = ""
        host_count = 0
        path_count = 0
        journal_event = None
        if request.method == "GET":
            snapshot = _take_download_results(
                current_app.instance_path,
                request.args.get("download_result", ""),
                str(g.current_user.get("id", "")),
            )
            if snapshot:
                form = {**form, **snapshot["form"]}
                results = snapshot["results"]
        if request.method == "POST":
            operation_id = f"multi-transfer:{secrets.token_hex(12)}"
            journal_started_at = time.time()
            hosts = []
            paths = []
            form = {
                "hosts": request.form.get("hosts", "").strip(),
                "username": request.form.get("username", "").strip(),
                "port": request.form.get("port", "22").strip(),
                "remote_paths": request.form.get("remote_paths", "").strip(),
                "allow_unknown_hosts": request.form.get("allow_unknown_hosts") == "on",
                "allow_legacy_algorithms": request.form.get("allow_legacy_algorithms") == "on",
                "destination": request.form.get("destination", "").strip(),
                "output_mode": request.form.get("output_mode", "download").strip(),
                "filename_pattern": request.form.get(
                    "filename_pattern", SFTP_DEFAULT_FILENAME_PATTERN
                ).strip(),
                "protocol": request.form.get("protocol", "sftp").lower().strip(),
            }
            try:
                hosts = parse_ssh_targets(str(form["hosts"]), limit=50)
                paths = parse_sftp_paths(str(form["remote_paths"]))
                host_count = len(hosts)
                path_count = len(paths)
                port = int(str(form["port"]))
                filename_pattern = validate_sftp_filename_pattern(str(form["filename_pattern"]))
                if form["protocol"] not in {"sftp", "scp", "ftp"}:
                    raise ToolInputError("Choose SFTP, SCP, or FTP.")
                if form["output_mode"] not in {"download", "datastore"}:
                    raise ToolInputError("Choose a valid transfer output mode.")
                if form["output_mode"] == "datastore":
                    store.list(str(form["destination"]))
                with tempfile.TemporaryDirectory(prefix="twn-multi-sftp-") as temporary:
                    output_dir = Path(temporary)
                    results = fetch_ssh_files(
                        hosts=hosts,
                        remote_paths=paths,
                        username=str(form["username"]),
                        password=request.form.get("password", ""),
                        port=port,
                        allow_unknown_hosts=bool(form["allow_unknown_hosts"]),
                        allow_legacy_algorithms=bool(form["allow_legacy_algorithms"]),
                        output_dir=output_dir,
                        filename_pattern=filename_pattern,
                        protocol=str(form["protocol"]),
                    )
                    successes = [result for result in results if result["status"] == "success"]
                    if form["output_mode"] == "download":
                        record_current_activity(
                            "Network tools",
                            f"Fetched files with Bulk Transfer ({str(form['protocol']).upper()})",
                            f"{len(successes)} of {len(results)} transfer(s)",
                            counters={str(form["protocol"]): {"files": len(successes), "bytes": sum(int(item["size"]) for item in successes)}},
                        )
                        annotate_tool_run(
                            category="Network tools",
                            action_namespace="transfer.multi_host_fetch",
                            tool_name="Bulk Transfer",
                            outcome="succeeded" if successes else "failed",
                            details=_transfer_audit_details(
                                form, results, successes, host_count, path_count
                            ),
                        )
                        if successes:
                            journal_event = _record_transfer_investigation(
                                form,
                                hosts,
                                paths,
                                results,
                                error="",
                                operation_id=operation_id,
                                started_at=journal_started_at,
                            )
                            archive = _build_archive(output_dir, results)
                            response = send_file(
                                archive,
                                mimetype="application/zip",
                                as_attachment=True,
                                download_name=f"multi-transfer-{form['protocol']}-download.zip",
                            )
                            download_token = request.form.get("download_token", "")
                            if re.fullmatch(r"[A-Za-z0-9-]{1,80}", download_token):
                                _store_download_results(
                                    current_app.instance_path,
                                    download_token,
                                    str(g.current_user.get("id", "")),
                                    form,
                                    results,
                                )
                                response.set_cookie(
                                    f"twn_download_ready_{download_token}",
                                    "1",
                                    max_age=120,
                                    secure=request.is_secure,
                                    httponly=False,
                                    samesite="Lax",
                                    path="/",
                                )
                            return response
                        error = "No files were fetched. Review the per-transfer errors below."
                    if form["output_mode"] == "datastore":
                        for result in successes:
                            filename = str(result["filename"])
                            with (output_dir / filename).open("rb") as source:
                                saved, _size = store.save_upload(
                                    str(form["destination"]), filename, source
                                )
                            result["stored_path"] = store.relative(saved)
                if form["output_mode"] == "datastore":
                    record_current_activity(
                        "Network tools",
                        f"Stored Bulk Transfer files ({str(form['protocol']).upper()})",
                        f"{len(successes)} of {len(results)} transfer(s)",
                        counters={str(form["protocol"]): {"files": len(successes), "bytes": sum(int(item["size"]) for item in successes)}},
                    )
                    annotate_tool_run(
                        category="Network tools",
                        action_namespace="transfer.multi_host_fetch",
                        tool_name="Bulk Transfer",
                        outcome="succeeded" if successes else "failed",
                        details=_transfer_audit_details(
                            form, results, successes, host_count, path_count
                        ),
                    )
                    journal_event = _record_transfer_investigation(
                        form,
                        hosts,
                        paths,
                        results or [],
                        error=error,
                        operation_id=operation_id,
                        started_at=journal_started_at,
                    )
            except (ToolInputError, DatastoreError, OSError, ValueError) as exc:
                error = str(exc) or "Enter a valid SFTP port."
                record_current_activity("Network tools", "Ran Bulk Transfer", "Request failed")
                annotate_tool_run(
                    category="Network tools",
                    action_namespace="transfer.multi_host_fetch",
                    tool_name="Bulk Transfer",
                    outcome="failed",
                    details={
                        "protocol": str(form["protocol"]),
                        "output mode": str(form["output_mode"]),
                        "host count": host_count,
                        "remote path count": path_count,
                    },
                )
                journal_event = _record_transfer_investigation(
                    form,
                    hosts,
                    paths,
                    results or [],
                    error=error,
                    operation_id=operation_id,
                    started_at=journal_started_at,
                )
            if results is not None and journal_event is None:
                journal_event = _record_transfer_investigation(
                    form,
                    hosts,
                    paths,
                    results,
                    error=error,
                    operation_id=operation_id,
                    started_at=journal_started_at,
                )
        for result in results or []:
            result["size_display"] = format_bytes(int(result.get("size", 0)))
        return render_template(
            "tools/multi_sftp.html",
            error=error,
            form=form,
            results=results,
            datastore_folders=store.folders(),
            journal_event=journal_event,
        )

    @tools_bp.route("/multi-sftp", methods=["GET", "POST"])
    def multi_sftp():
        suppress_audit_event()
        return redirect(
            url_for("tools.multi_transfer", protocol="sftp"),
            code=307 if request.method == "POST" else 302,
        )


def _build_archive(output_dir: Path, results: list[dict[str, object]]) -> io.BytesIO:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        report = ["Bulk Transfer report", ""]
        for result in results:
            identity = str(result.get("host_label") or result["host"])
            line = f"{result['status'].upper()} | {identity} | {result['remote_path']}"
            if result.get("error"):
                line += f" | {result['error']}"
            elif result.get("filename"):
                line += f" | {result['filename']} | {result['size']} bytes"
                bundle.write(output_dir / str(result["filename"]), str(result["filename"]))
            report.append(line)
        bundle.writestr("multi-transfer-report.txt", "\n".join(report) + "\n")
    archive.seek(0)
    return archive


def _transfer_audit_details(
    form: dict[str, object],
    results: list[dict[str, object]],
    successes: list[dict[str, object]],
    host_count: int,
    path_count: int,
) -> dict[str, object]:
    return {
        "protocol": str(form["protocol"]),
        "output mode": str(form["output_mode"]),
        "host count": host_count,
        "remote path count": path_count,
        "transfer count": len(results),
        "successful transfer count": len(successes),
        "transferred byte count": sum(int(item["size"]) for item in successes),
        "legacy SSH compatibility": (
            bool(form.get("allow_legacy_algorithms"))
            if str(form["protocol"]) in {"sftp", "scp"}
            else False
        ),
    }


def _record_transfer_investigation(
    form: dict[str, object],
    hosts: list[dict[str, object]],
    paths: list[str],
    results: list[dict[str, object]],
    *,
    error: str,
    operation_id: str,
    started_at: float,
) -> dict[str, object] | None:
    safe_results = [
        {
            key: result.get(key)
            for key in (
                "host",
                "host_label",
                "remote_path",
                "status",
                "filename",
                "size",
                "stored_path",
                "error",
            )
        }
        for result in results
    ]
    successful = sum(result.get("status") == "success" for result in results)
    transferred_bytes = sum(
        int(result.get("size") or 0)
        for result in results
        if result.get("status") == "success"
    )
    event = {
        "operation_id": operation_id,
        "event_type": "action.failed" if error and not successful else "action.completed",
        "tool_id": "tools.multi_sftp",
        "action": "Bulk Transfer",
        "outcome": "failed" if error and not successful else "succeeded" if successful == len(results) else "incomplete",
        "summary": (
            f"Bulk Transfer failed: {error}"
            if error and not results
            else f"Fetched {successful} of {len(results)} requested transfer(s) with {str(form.get('protocol', '')).upper()}."
        ),
        "targets": [
            {"host": host.get("host"), "label": host.get("label")}
            for host in hosts
        ],
        "parameters": {
            "protocol": form.get("protocol"),
            "port": form.get("port"),
            "remote_paths": paths,
            "output_mode": form.get("output_mode"),
            "destination": form.get("destination"),
            "filename_pattern": form.get("filename_pattern"),
            "unknown_hosts_allowed": bool(form.get("allow_unknown_hosts")),
            "legacy_algorithms_allowed": bool(form.get("allow_legacy_algorithms")),
        },
        "metrics": {
            "host_count": len(hosts),
            "remote_path_count": len(paths),
            "transfer_count": len(results),
            "successful_transfers": successful,
            "failed_transfers": len(results) - successful,
            "transferred_bytes": transferred_bytes,
        }
        if results
        else {},
        "details": {"error": error, "results": safe_results},
        "started_at": started_at,
        "completed_at": time.time(),
    }
    if error and not results:
        return record_current_investigation_event(**event)
    generated = add_current_investigation_generated_evidence_event(
        **event,
        filename=f"multi-transfer-{operation_id.rsplit(':', 1)[-1]}-manifest.json",
        content_type="application/json",
        content=json.dumps(safe_results, indent=2, ensure_ascii=False).encode("utf-8"),
    )
    return generated["event"] if generated else None


def _download_result_directory(instance_path: str) -> Path:
    directory = Path(instance_path) / "multi_transfer_results"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    cutoff = time.time() - 900
    for path in directory.glob("*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            pass
    return directory


def _store_download_results(
    instance_path: str,
    token: str,
    user_id: str,
    form: dict[str, object],
    results: list[dict[str, object]],
) -> None:
    directory = _download_result_directory(instance_path)
    path = directory / f"{token}.json"
    temporary = directory / f".{token}.{os.getpid()}.tmp"
    payload = {"user_id": user_id, "form": form, "results": results}
    temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _take_download_results(
    instance_path: str, token: str, user_id: str
) -> dict[str, object] | None:
    if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", token):
        return None
    path = _download_result_directory(instance_path) / f"{token}.json"
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    finally:
        try:
            path.unlink()
        except OSError:
            pass
    if not isinstance(snapshot, dict) or snapshot.get("user_id") != user_id:
        return None
    if not isinstance(snapshot.get("form"), dict) or not isinstance(snapshot.get("results"), list):
        return None
    return snapshot

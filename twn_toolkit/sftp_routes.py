from __future__ import annotations

import io
import json
import os
import re
import tempfile
import time
import zipfile
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
            "destination": "",
            "output_mode": "download",
            "filename_pattern": SFTP_DEFAULT_FILENAME_PATTERN,
            "protocol": requested_protocol,
        }
        results: list[dict[str, object]] | None = None
        error = ""
        host_count = 0
        path_count = 0
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
            form = {
                "hosts": request.form.get("hosts", "").strip(),
                "username": request.form.get("username", "").strip(),
                "port": request.form.get("port", "22").strip(),
                "remote_paths": request.form.get("remote_paths", "").strip(),
                "allow_unknown_hosts": request.form.get("allow_unknown_hosts") == "on",
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
                        output_dir=output_dir,
                        filename_pattern=filename_pattern,
                        protocol=str(form["protocol"]),
                    )
                    successes = [result for result in results if result["status"] == "success"]
                    if form["output_mode"] == "download":
                        record_current_activity(
                            "Network tools",
                            f"Fetched files with Multi-Transfer ({str(form['protocol']).upper()})",
                            f"{len(successes)} of {len(results)} transfer(s)",
                            counters={str(form["protocol"]): {"files": len(successes), "bytes": sum(int(item["size"]) for item in successes)}},
                        )
                        annotate_tool_run(
                            category="Network tools",
                            action_namespace="transfer.multi_host_fetch",
                            tool_name="Multi-Transfer",
                            outcome="succeeded" if successes else "failed",
                            details=_transfer_audit_details(
                                form, results, successes, host_count, path_count
                            ),
                        )
                        if successes:
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
                        f"Stored Multi-Transfer files ({str(form['protocol']).upper()})",
                        f"{len(successes)} of {len(results)} transfer(s)",
                        counters={str(form["protocol"]): {"files": len(successes), "bytes": sum(int(item["size"]) for item in successes)}},
                    )
                    annotate_tool_run(
                        category="Network tools",
                        action_namespace="transfer.multi_host_fetch",
                        tool_name="Multi-Transfer",
                        outcome="succeeded" if successes else "failed",
                        details=_transfer_audit_details(
                            form, results, successes, host_count, path_count
                        ),
                    )
            except (ToolInputError, DatastoreError, OSError, ValueError) as exc:
                error = str(exc) or "Enter a valid SFTP port."
                record_current_activity("Network tools", "Ran Multi-Transfer", "Request failed")
                annotate_tool_run(
                    category="Network tools",
                    action_namespace="transfer.multi_host_fetch",
                    tool_name="Multi-Transfer",
                    outcome="failed",
                    details={
                        "protocol": str(form["protocol"]),
                        "output mode": str(form["output_mode"]),
                        "host count": host_count,
                        "remote path count": path_count,
                    },
                )
        for result in results or []:
            result["size_display"] = format_bytes(int(result.get("size", 0)))
        return render_template(
            "tools/multi_sftp.html",
            error=error,
            form=form,
            results=results,
            datastore_folders=store.folders(),
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
        report = ["Multi-Transfer report", ""]
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
    }


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

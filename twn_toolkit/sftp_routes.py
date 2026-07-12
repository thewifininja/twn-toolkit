from __future__ import annotations

import io
import tempfile
import zipfile
from pathlib import Path

from flask import Blueprint, current_app, redirect, render_template, request, send_file, url_for

from .activity_context import record_current_activity
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
                        archive = _build_archive(output_dir, results)
                        record_current_activity(
                            "Network tools",
                            f"Fetched files with Multi-Transfer ({str(form['protocol']).upper()})",
                            f"{len(successes)} of {len(results)} transfer(s)",
                            counters={str(form["protocol"]): {"files": len(successes), "bytes": sum(int(item["size"]) for item in successes)}},
                        )
                        return send_file(
                            archive,
                            mimetype="application/zip",
                            as_attachment=True,
                            download_name=f"multi-transfer-{form['protocol']}-download.zip",
                        )
                    for result in successes:
                        filename = str(result["filename"])
                        with (output_dir / filename).open("rb") as source:
                            saved, _size = store.save_upload(
                                str(form["destination"]), filename, source
                            )
                        result["stored_path"] = store.relative(saved)
                record_current_activity(
                    "Network tools",
                    f"Stored Multi-Transfer files ({str(form['protocol']).upper()})",
                    f"{len(successes)} of {len(results)} transfer(s)",
                    counters={str(form["protocol"]): {"files": len(successes), "bytes": sum(int(item["size"]) for item in successes)}},
                )
            except (ToolInputError, DatastoreError, ValueError) as exc:
                error = str(exc) or "Enter a valid SFTP port."
                record_current_activity("Network tools", "Ran Multi-Transfer", "Request failed")
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

from __future__ import annotations

import subprocess
import json
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, url_for

from .activity_context import record_current_activity
from .datastore import DatastoreError, LocalDatastore, MAX_UPLOAD_BYTES, format_bytes
from .tftp import TFTPHistoryStore, TFTPSettingsStore, tftp_process_status
from .ssh_transfer_server import (
    SSHTransferHistoryStore, SSHTransferSettingsStore, ssh_transfer_process_status,
)
from .ftp_server import FTPSettingsStore, ftp_process_status


MAX_TEXT_PREVIEW_BYTES = 1024 * 1024


def register_datastore_routes(
    app: Flask,
    store: LocalDatastore,
    tftp_runtime_store: LocalDatastore,
    tftp_settings_store: TFTPSettingsStore,
    tftp_history_store: TFTPHistoryStore,
    ssh_transfer_runtime_store: LocalDatastore,
    ssh_transfer_settings_store: SSHTransferSettingsStore,
    ssh_transfer_history_store: SSHTransferHistoryStore,
    ftp_runtime_store: LocalDatastore,
    ftp_settings_store: FTPSettingsStore,
) -> None:
    def return_to(path: str):
        return redirect(url_for("local_datastore", path=path))

    def decorate_history(items: list[dict]) -> list[dict]:
        for item in items:
            item["size_display"] = format_bytes(int(item["bytes"]))
            item["started_display"] = datetime.fromtimestamp(
                float(item["started_at"])
            ).astimezone().strftime("%b %-d, %Y %-I:%M:%S %p")
        return items

    def temporary_file(runtime_store: LocalDatastore) -> dict | None:
        entries = runtime_store.list()["entries"]
        item = entries[0] if entries else None
        if item:
            item["size_display"] = format_bytes(item["size"])
        return item

    def apply_service(command: str, failure_message: str) -> None:
        project_root = Path(__file__).resolve().parent.parent
        completed = subprocess.run(
            [str(project_root / "twn"), command], cwd=project_root,
            capture_output=True, text=True, timeout=15, check=False,
        )
        if completed.returncode:
            raise RuntimeError((completed.stderr or completed.stdout).strip() or failure_message)

    def stage_runtime_file(runtime_store: LocalDatastore, success_message: str) -> None:
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Choose one temporary file.", "error")
            return
        try:
            saved_path, _size = runtime_store.save_upload("", upload.filename, upload.stream, overwrite=True)
            for entry in runtime_store.list()["entries"]:
                if entry["path"] != saved_path.name:
                    runtime_store.delete(entry["path"])
        except DatastoreError as exc:
            flash(str(exc), "error")
        else:
            flash(success_message, "success")

    @app.get("/local/datastore")
    def local_datastore():
        path = request.args.get("path", "")
        try:
            listing = store.list(path)
        except DatastoreError as exc:
            flash(str(exc), "error")
            return redirect(url_for("local_datastore"))
        for entry in listing["entries"]:
            entry["size_display"] = "Folder" if entry["is_dir"] else format_bytes(entry["size"])
            entry["modified_display"] = datetime.fromtimestamp(entry["modified_at"]).astimezone().strftime(
                "%b %-d, %Y %-I:%M %p"
            )
        usage = store.usage()
        usage["size_display"] = format_bytes(usage["bytes"])
        return render_template(
            "local/datastore.html",
            listing=listing,
            usage=usage,
            max_upload_display=format_bytes(MAX_UPLOAD_BYTES),
            datastore_folders=store.folders(),
        )

    @app.get("/local/file-transfers")
    def file_transfers():
        transfers = decorate_history(tftp_history_store.recent(20))
        ssh_transfers = decorate_history(ssh_transfer_history_store.recent(20, {"SFTP", "SCP"}))
        ftp_transfers = decorate_history(ssh_transfer_history_store.recent(20, {"FTP"}))
        return render_template(
            "local/file_transfers.html",
            max_upload_display=format_bytes(MAX_UPLOAD_BYTES),
            tftp_settings=tftp_settings_store.get(),
            tftp_status=tftp_process_status(app.instance_path),
            tftp_transfers=transfers,
            datastore_folders=store.folders(),
            temporary_file=temporary_file(tftp_runtime_store),
            ssh_transfer_settings=ssh_transfer_settings_store.get(),
            ssh_transfer_status=ssh_transfer_process_status(app.instance_path),
            ssh_transfers=ssh_transfers,
            ssh_temporary_file=temporary_file(ssh_transfer_runtime_store),
            ftp_settings=ftp_settings_store.get(),
            ftp_status=ftp_process_status(app.instance_path),
            ftp_transfers=ftp_transfers,
            ftp_temporary_file=temporary_file(ftp_runtime_store),
        )

    @app.post("/local/file-transfers/tftp/settings")
    def save_tftp_settings():
        if not g.current_user.get("is_admin"):
            abort(403)
        settings_saved = False
        try:
            candidate = {
                    "enabled": request.form.get("enabled") == "on",
                    "bind_host": request.form.get("bind_host", ""),
                    "port": request.form.get("port", ""),
                    "allow_read": request.form.get("allow_read") == "on",
                    "allow_write": request.form.get("allow_write") == "on",
                    "allow_overwrite": request.form.get("allow_overwrite") == "on",
                    "root_mode": request.form.get("root_mode", "datastore"),
                    "datastore_root": request.form.get("datastore_root", ""),
                    "incoming_filename_pattern": request.form.get(
                        "incoming_filename_pattern", "{filename}"
                    ),
                    "allowed_networks": request.form.get("allowed_networks", ""),
                }
            if candidate["root_mode"] == "datastore":
                store.list(str(candidate["datastore_root"]))
            settings = tftp_settings_store.save(candidate)
            settings_saved = True
            apply_service("tftp-restart", "The managed TFTP service did not start.")
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
            prefix = (
                "TFTP settings were saved, but the service could not be applied"
                if settings_saved
                else "TFTP settings were not saved"
            )
            flash(f"{prefix}: {exc}", "error")
        else:
            state = "started" if settings["enabled"] else "stopped"
            flash(f"TFTP settings saved and service {state}.", "success")
        return redirect(url_for("file_transfers", _anchor="tftp-service"))

    @app.post("/local/file-transfers/tftp/history/clear")
    def clear_tftp_history():
        if not g.current_user.get("is_admin"):
            abort(403)
        count = tftp_history_store.clear()
        flash(f"Cleared {count} TFTP transfer record(s).", "success")
        return redirect(url_for("file_transfers", _anchor="tftp-service"))

    @app.post("/local/file-transfers/tftp/temporary-file")
    def upload_tftp_temporary_file():
        if not g.current_user.get("is_admin"):
            abort(403)
        settings = tftp_settings_store.get()
        status = tftp_process_status(app.instance_path)
        if settings["root_mode"] != "temporary" or not status["running"]:
            flash("Enable the running TFTP service in temporary-file mode before uploading.", "error")
            return redirect(url_for("file_transfers", _anchor="tftp-service"))
        if request.content_length and request.content_length > MAX_UPLOAD_BYTES + 1024 * 1024:
            flash(f"Temporary TFTP files may not exceed {format_bytes(MAX_UPLOAD_BYTES)}.", "error")
            return redirect(url_for("file_transfers", _anchor="tftp-service"))
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Choose one temporary file.", "error")
            return redirect(url_for("file_transfers", _anchor="tftp-service"))
        try:
            stage_runtime_file(tftp_runtime_store, "Temporary TFTP file staged until the service stops.")
        except DatastoreError as exc:
            flash(str(exc), "error")
        return redirect(url_for("file_transfers", _anchor="tftp-service"))

    @app.post("/local/file-transfers/tftp/temporary-file/delete")
    def delete_tftp_temporary_file():
        if not g.current_user.get("is_admin"):
            abort(403)
        tftp_runtime_store.clear()
        flash("Temporary TFTP file removed.", "success")
        return redirect(url_for("file_transfers", _anchor="tftp-service"))

    @app.post("/local/file-transfers/ssh/settings")
    def save_ssh_transfer_settings():
        if not g.current_user.get("is_admin"): abort(403)
        saved = False
        try:
            candidate = {
                "enabled": request.form.get("enabled") == "on",
                "bind_host": request.form.get("bind_host", ""), "port": request.form.get("port", ""),
                "username": request.form.get("username", ""),
                "allow_sftp": request.form.get("allow_sftp") == "on", "allow_scp": request.form.get("allow_scp") == "on",
                "allow_read": request.form.get("allow_read") == "on", "allow_write": request.form.get("allow_write") == "on",
                "allow_overwrite": request.form.get("allow_overwrite") == "on",
                "root_mode": request.form.get("root_mode", "datastore"), "datastore_root": request.form.get("datastore_root", ""),
                "incoming_filename_pattern": request.form.get("incoming_filename_pattern", "{filename}"),
                "allowed_networks": request.form.get("allowed_networks", ""),
            }
            if candidate["root_mode"] == "datastore": store.list(str(candidate["datastore_root"]))
            settings = ssh_transfer_settings_store.save(candidate, request.form.get("password", ""))
            saved = True
            apply_service("ssh-transfer-restart", "SSH transfer service did not start.")
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
            flash(f"SSH transfer settings were {'saved but could not be applied' if saved else 'not saved'}: {exc}", "error")
        else:
            flash(f"SSH transfer settings saved and service {'started' if settings['enabled'] else 'stopped'}.", "success")
        return redirect(url_for("file_transfers", _anchor="ssh-transfer-service"))

    @app.post("/local/file-transfers/ssh/history/clear")
    def clear_ssh_transfer_history():
        if not g.current_user.get("is_admin"): abort(403)
        count = ssh_transfer_history_store.clear({"SFTP", "SCP"}); flash(f"Cleared {count} SSH transfer record(s).", "success")
        return redirect(url_for("file_transfers", _anchor="ssh-transfer-service"))

    @app.post("/local/file-transfers/ssh/temporary-file")
    def upload_ssh_transfer_temporary_file():
        if not g.current_user.get("is_admin"): abort(403)
        settings, status = ssh_transfer_settings_store.get(), ssh_transfer_process_status(app.instance_path)
        if settings["root_mode"] != "temporary" or not status["running"]:
            flash("Enable the running SSH transfer service in temporary-file mode first.", "error")
        else:
            stage_runtime_file(ssh_transfer_runtime_store, "Temporary SSH transfer file staged until the service stops.")
        return redirect(url_for("file_transfers", _anchor="ssh-transfer-service"))

    @app.post("/local/file-transfers/ssh/temporary-file/delete")
    def delete_ssh_transfer_temporary_file():
        if not g.current_user.get("is_admin"): abort(403)
        ssh_transfer_runtime_store.clear(); flash("Temporary SSH transfer file removed.", "success")
        return redirect(url_for("file_transfers", _anchor="ssh-transfer-service"))

    @app.post("/local/file-transfers/ftp/settings")
    def save_ftp_settings():
        if not g.current_user.get("is_admin"): abort(403)
        saved = False
        try:
            candidate = {
                "enabled": request.form.get("enabled") == "on",
                "bind_host": request.form.get("bind_host", ""), "port": request.form.get("port", ""),
                "passive_start": request.form.get("passive_start", ""), "passive_end": request.form.get("passive_end", ""),
                "max_connections": request.form.get("max_connections", ""), "max_connections_per_ip": request.form.get("max_connections_per_ip", ""),
                "username": request.form.get("username", ""),
                "allow_read": request.form.get("allow_read") == "on", "allow_write": request.form.get("allow_write") == "on",
                "allow_overwrite": request.form.get("allow_overwrite") == "on",
                "root_mode": request.form.get("root_mode", "datastore"), "datastore_root": request.form.get("datastore_root", ""),
                "incoming_filename_pattern": request.form.get("incoming_filename_pattern", "{filename}"),
                "allowed_networks": request.form.get("allowed_networks", ""),
            }
            if candidate["root_mode"] == "datastore": store.list(str(candidate["datastore_root"]))
            settings = ftp_settings_store.save(candidate, request.form.get("password", "")); saved = True
            apply_service("ftp-restart", "FTP service did not start.")
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
            flash(f"FTP settings were {'saved but could not be applied' if saved else 'not saved'}: {exc}", "error")
        else:
            flash(f"FTP settings saved and service {'started' if settings['enabled'] else 'stopped'}.", "success")
        return redirect(url_for("file_transfers", _anchor="ftp-service"))

    @app.post("/local/file-transfers/ftp/history/clear")
    def clear_ftp_history():
        if not g.current_user.get("is_admin"): abort(403)
        count = ssh_transfer_history_store.clear({"FTP"}); flash(f"Cleared {count} FTP transfer record(s).", "success")
        return redirect(url_for("file_transfers", _anchor="ftp-service"))

    @app.post("/local/file-transfers/ftp/temporary-file")
    def upload_ftp_temporary_file():
        if not g.current_user.get("is_admin"): abort(403)
        settings, status = ftp_settings_store.get(), ftp_process_status(app.instance_path)
        if settings["root_mode"] != "temporary" or not status["running"]:
            flash("Enable the running FTP service in temporary-file mode first.", "error")
        else:
            stage_runtime_file(ftp_runtime_store, "Temporary FTP file staged until the service stops.")
        return redirect(url_for("file_transfers", _anchor="ftp-service"))

    @app.post("/local/file-transfers/ftp/temporary-file/delete")
    def delete_ftp_temporary_file():
        if not g.current_user.get("is_admin"): abort(403)
        ftp_runtime_store.clear(); flash("Temporary FTP file removed.", "success")
        return redirect(url_for("file_transfers", _anchor="ftp-service"))

    @app.post("/local/datastore/folders")
    def create_datastore_folder():
        path = request.form.get("path", "")
        try:
            store.create_folder(path, request.form.get("name", ""))
        except DatastoreError as exc:
            flash(str(exc), "error")
        else:
            record_current_activity("Local storage", "Created datastore folder", request.form.get("name", ""))
            flash("Folder created.", "success")
        return return_to(path)

    @app.post("/local/datastore/uploads")
    def upload_datastore_files():
        path = request.args.get("path", "")
        if request.content_length and request.content_length > MAX_UPLOAD_BYTES + 1024 * 1024:
            flash(f"Each upload request may not exceed {format_bytes(MAX_UPLOAD_BYTES)}.", "error")
            return return_to(path)
        path = request.form.get("path", path)
        uploads = [item for item in request.files.getlist("files") if item.filename]
        if not uploads:
            flash("Choose at least one file to upload.", "error")
            return return_to(path)
        saved = 0
        try:
            for upload in uploads:
                store.save_upload(path, upload.filename or "", upload.stream)
                saved += 1
        except DatastoreError as exc:
            flash(f"Uploaded {saved} file(s). {exc}", "error")
        else:
            record_current_activity("Local storage", "Uploaded datastore files", f"{saved} file(s)")
            flash(f"Uploaded {saved} file(s).", "success")
        return return_to(path)

    @app.get("/local/datastore/download")
    def download_datastore_file():
        try:
            file_path = store.file(request.args.get("path", ""))
        except DatastoreError as exc:
            abort(404, str(exc))
        record_current_activity("Local storage", "Downloaded datastore file", file_path.name)
        return send_file(file_path, as_attachment=True, download_name=file_path.name)

    @app.get("/local/datastore/view-text")
    def view_datastore_file_as_text():
        relative_path = request.args.get("path", "")
        try:
            file_path = store.file(relative_path)
            with file_path.open("rb") as source:
                raw = source.read(MAX_TEXT_PREVIEW_BYTES + 1)
        except (DatastoreError, OSError) as exc:
            abort(404, str(exc))
        truncated = len(raw) > MAX_TEXT_PREVIEW_BYTES
        preview_bytes = raw[:MAX_TEXT_PREVIEW_BYTES]
        text = preview_bytes.decode("utf-8-sig", errors="replace")
        replacement_count = text.count("\ufffd")
        parent_path = relative_path.rsplit("/", 1)[0] if "/" in relative_path else ""
        record_current_activity("Local storage", "Viewed datastore file as text", file_path.name)
        return render_template(
            "local/datastore_text_viewer.html",
            filename=file_path.name,
            relative_path=relative_path,
            parent_path=parent_path,
            text=text,
            truncated=truncated,
            replacement_count=replacement_count,
            size_display=format_bytes(file_path.stat().st_size),
            preview_limit_display=format_bytes(MAX_TEXT_PREVIEW_BYTES),
        )

    @app.post("/local/datastore/bulk-download")
    def bulk_download_datastore_files():
        try:
            selected = json.loads(request.form.get("paths_json", "[]"))
            if not isinstance(selected, list):
                raise ValueError
            members = store.archive_members(
                [str(value) for value in selected], request.form.get("path", "")
            )
            archive = tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024, mode="w+b")
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as bundle:
                for source, archive_name, is_directory in members:
                    if is_directory:
                        bundle.writestr(f"{archive_name.rstrip('/')}/", b"")
                    else:
                        bundle.write(source, archive_name)
            archive.seek(0)
        except (DatastoreError, json.JSONDecodeError, OSError, ValueError, zipfile.BadZipFile) as exc:
            if 'archive' in locals():
                archive.close()
            abort(400, str(exc) or "Select valid datastore files or folders to download.")
        record_current_activity("Local storage", "Downloaded datastore items", f"{len(selected)} item(s)")
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        return send_file(
            archive,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"datastore-selection-{stamp}.zip",
        )

    @app.post("/local/datastore/rename")
    def rename_datastore_entry():
        path = request.form.get("path", "")
        parent = str(path.rsplit("/", 1)[0]) if "/" in path else ""
        try:
            store.rename(path, request.form.get("name", ""))
        except DatastoreError as exc:
            flash(str(exc), "error")
        else:
            flash("Datastore item renamed.", "success")
        return return_to(parent)

    @app.post("/local/datastore/delete")
    def delete_datastore_entry():
        path = request.form.get("path", "")
        parent = str(path.rsplit("/", 1)[0]) if "/" in path else ""
        try:
            store.delete(path)
        except DatastoreError as exc:
            flash(str(exc), "error")
        else:
            flash("Datastore item deleted.", "success")
        return return_to(parent)

    @app.post("/local/datastore/bulk-delete")
    def bulk_delete_datastore_files():
        path = request.form.get("path", "")
        try:
            selected = json.loads(request.form.get("paths_json", "[]"))
            if not isinstance(selected, list):
                raise ValueError
            count = store.delete_files([str(value) for value in selected])
        except (DatastoreError, json.JSONDecodeError, ValueError):
            flash("Select valid datastore files or folders to delete.", "error")
        else:
            record_current_activity("Local storage", "Deleted datastore items", f"{count} item(s)")
            flash(f"Deleted {count} item(s).", "success")
        return return_to(path)

    @app.post("/local/datastore/bulk-move")
    def bulk_move_datastore_files():
        path = request.form.get("path", "")
        try:
            selected = json.loads(request.form.get("paths_json", "[]"))
            if not isinstance(selected, list):
                raise ValueError
            count = store.move_files(
                [str(value) for value in selected],
                request.form.get("destination", ""),
            )
        except (DatastoreError, json.JSONDecodeError, ValueError) as exc:
            flash(str(exc) or "Select valid datastore files or folders to move.", "error")
        else:
            record_current_activity("Local storage", "Moved datastore items", f"{count} item(s)")
            flash(f"Moved {count} item(s).", "success")
        return return_to(path)

from __future__ import annotations

import os
from datetime import datetime

import click
from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for

from .fortigate import FortiGateClient, FortiGateError, normalize_api_key, normalize_host
from .profiles import ProfileStore
from .tasks import TASKS, ExportTask, RenameTask, discover_export_fields, get_task, grouped_tasks


def create_app(instance_path: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    app.config.from_mapping(SECRET_KEY=os.environ.get("FORTITOOL_SECRET_KEY", "dev-change-me"))

    store = ProfileStore(app.instance_path)

    @app.cli.command("reset-data")
    @click.option("--yes", is_flag=True, help="Reset without an interactive confirmation.")
    def reset_data(yes: bool) -> None:
        """Remove all locally saved FortiGate profiles and API keys."""
        if not yes and not click.confirm("Delete all saved FortiGate profiles and API keys?"):
            click.echo("Reset cancelled.")
            return
        store.clear()
        click.echo("FortiTool local profile data has been reset.")

    @app.get("/")
    def index():
        profiles = store.all()
        edit_profile = store.get(request.args.get("edit", ""))
        return render_template(
            "index.html",
            edit_profile=edit_profile,
            profiles=profiles,
            task_groups=grouped_tasks(),
        )

    @app.get("/favicon.ico")
    def favicon():
        return Response(status=204)

    @app.post("/profiles")
    def save_profile():
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        host = request.form.get("host", "").strip()
        api_key = request.form.get("api_key", "").strip()
        verify_tls = request.form.get("verify_tls") == "on"
        is_default = request.form.get("is_default") == "on"
        default_vdom = request.form.get("default_vdom", "root").strip() or "root"
        existing_profile = store.get(original_name) if original_name else None

        if not name or not host or (not api_key and not existing_profile):
            flash("Profile name, FortiGate URL, and API key are required.", "error")
            return redirect(url_for("index"))

        try:
            host = normalize_host(host)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))

        if existing_profile and original_name != name:
            store.delete(original_name)

        store.upsert(
            {
                "name": name,
                "host": host,
                "api_key": normalize_api_key(api_key) if api_key else existing_profile["api_key"],
                "verify_tls": verify_tls,
                "is_default": is_default,
                "default_vdom": default_vdom,
            }
        )
        flash(f"Saved profile '{name}'.", "success")
        return redirect(url_for("index"))

    @app.post("/profiles/<name>/delete")
    def delete_profile(name: str):
        store.delete(name)
        flash(f"Deleted profile '{name}'.", "success")
        return redirect(url_for("index"))

    @app.post("/profiles/<name>/test")
    def test_profile(name: str):
        profile = store.get(name)
        if not profile:
            flash("Profile not found.", "error")
            return redirect(url_for("index"))

        client = FortiGateClient.from_profile(profile)
        try:
            result = client.test_connection()
        except FortiGateError as exc:
            flash(f"Connection failed: {_connection_error_message(exc)}", "error")
        else:
            version = result.get("version") or result.get("build") or "reachable"
            flash(f"Connection OK: {version}", "success")

        return redirect(url_for("index"))

    @app.get("/tasks/<task_id>")
    def task_form(task_id: str):
        task = get_task(task_id)
        if not task:
            flash("Task not found.", "error")
            return redirect(url_for("index"))
        return render_template("task.html", profiles=store.all(), task=task)

    @app.get("/tasks/<task_id>/template.csv")
    def task_csv_template(task_id: str):
        task = get_task(task_id)
        if not isinstance(task, RenameTask):
            return Response("CSV templates are only available for rename tasks.", status=404)
        return Response(
            task.csv_template(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={task.id}-template.csv"},
        )

    @app.post("/tasks/<task_id>/run")
    def run_task(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        upload = request.files.get("csv_file")
        dry_run = request.form.get("dry_run") == "on"
        endpoint_template = request.form.get("endpoint_template", "").strip()

        if not task or not profile:
            flash("Select a valid task and profile.", "error")
            return redirect(url_for("index"))

        client = FortiGateClient.from_profile(profile)
        if isinstance(task, ExportTask):
            fields = request.form.get("fields", "").strip()
            try:
                csv_data = task.run(
                    client=client,
                    endpoint_template=endpoint_template or task.endpoint_template,
                    default_vdom=profile.get("default_vdom", "root"),
                    fields=fields,
                )
            except FortiGateError as exc:
                flash(f"Export failed: {exc}", "error")
                return redirect(url_for("task_form", task_id=task_id))

            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"{task.id}-{profile['name']}-{stamp}.csv".replace(" ", "_")
            return Response(
                csv_data,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        if not isinstance(task, RenameTask):
            flash("Task type is not supported yet.", "error")
            return redirect(url_for("index"))

        if not upload or upload.filename == "":
            flash("Choose a CSV file to import.", "error")
            return redirect(url_for("task_form", task_id=task_id))

        results, entries = task.run_with_entries(
            client=client,
            csv_stream=upload.stream,
            dry_run=dry_run,
            endpoint_template=endpoint_template or task.endpoint_template,
            default_vdom=profile.get("default_vdom", "root"),
        )

        return render_template(
            "results.html",
            entries=entries if dry_run else None,
            endpoint_template=endpoint_template or task.endpoint_template,
            profile=profile,
            task=task,
            results=results,
            dry_run=dry_run,
        )

    @app.post("/tasks/<task_id>/objects")
    def task_objects(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        endpoint_template = request.form.get("endpoint_template", "").strip()

        if not isinstance(task, RenameTask):
            return jsonify({"error": "Object discovery is only available for rename tasks."}), 400
        if not profile:
            return jsonify({"error": "Select a FortiGate profile first."}), 400

        client = FortiGateClient.from_profile(profile)
        try:
            objects = task.discover_objects(
                client=client,
                endpoint_template=endpoint_template or task.endpoint_template,
                default_vdom=profile.get("default_vdom", "root"),
            )
        except FortiGateError as exc:
            return jsonify({"error": str(exc)}), 502

        return jsonify({"objects": objects, "row_count": len(objects)})

    @app.post("/tasks/<task_id>/rename")
    def rename_objects(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        endpoint_template = request.form.get("endpoint_template", "").strip()
        dry_run = request.form.get("dry_run") == "on"

        if not isinstance(task, RenameTask) or not profile:
            flash("Select a valid rename task and profile.", "error")
            return redirect(url_for("task_form", task_id=task_id))

        identifiers = request.form.getlist("identifier")
        current_names = request.form.getlist("current_name")
        new_names = request.form.getlist("new_name")
        vdoms = request.form.getlist("vdom")
        if not identifiers or not (
            len(identifiers) == len(current_names) == len(new_names) == len(vdoms)
        ):
            flash("Select at least one device and enter its new name.", "error")
            return redirect(url_for("task_form", task_id=task_id))

        entries = [
            {
                "identifier": identifier,
                "current_name": current_name,
                "new_name": new_name,
                "vdom": vdom,
            }
            for identifier, current_name, new_name, vdom in zip(
                identifiers, current_names, new_names, vdoms
            )
        ]
        client = FortiGateClient.from_profile(profile)
        results = task.run_entries(
            client=client,
            entries=entries,
            dry_run=dry_run,
            endpoint_template=endpoint_template or task.endpoint_template,
            default_vdom=profile.get("default_vdom", "root"),
        )
        return render_template(
            "results.html",
            entries=entries if dry_run else None,
            endpoint_template=endpoint_template or task.endpoint_template,
            profile=profile,
            task=task,
            results=results,
            dry_run=dry_run,
        )

    @app.post("/tasks/<task_id>/fields")
    def task_fields(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        endpoint_template = request.form.get("endpoint_template", "").strip()

        if not isinstance(task, ExportTask):
            return jsonify({"error": "Field discovery is only available for export tasks."}), 400
        if not profile:
            return jsonify({"error": "Select a FortiGate profile first."}), 400

        client = FortiGateClient.from_profile(profile)
        try:
            rows, endpoint_used = task.preview_rows_with_endpoint(
                client=client,
                endpoint_template=endpoint_template or task.endpoint_template,
                default_vdom=profile.get("default_vdom", "root"),
            )
        except FortiGateError as exc:
            return jsonify({"error": str(exc)}), 502

        fields = discover_export_fields(task, rows)
        return jsonify({"endpoint_used": endpoint_used, "fields": fields, "row_count": len(rows)})

    @app.post("/tasks/<task_id>/preview")
    def task_preview(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        endpoint_template = request.form.get("endpoint_template", "").strip()
        selected_fields = request.form.get("fields", "").strip()

        if not isinstance(task, ExportTask):
            return jsonify({"error": "Data preview is only available for export tasks."}), 400
        if not profile:
            return jsonify({"error": "Select a FortiGate profile first."}), 400

        client = FortiGateClient.from_profile(profile)
        try:
            rows, endpoint_used = task.preview_rows_with_endpoint(
                client=client,
                endpoint_template=endpoint_template or task.endpoint_template,
                default_vdom=profile.get("default_vdom", "root"),
            )
        except FortiGateError as exc:
            return jsonify({"error": str(exc)}), 502

        columns, formatted_rows = task.format_rows(rows, selected_fields)
        return jsonify(
            {
                "columns": columns,
                "endpoint_used": endpoint_used,
                "row_count": len(formatted_rows),
                "rows": formatted_rows,
            }
        )

    return app


def _connection_error_message(exc: FortiGateError) -> str:
    if exc.status_code == 401:
        return (
            "HTTP 401 Unauthorized. The FortiGate was reached, but the API token was rejected or the API user "
            "does not have permission to read the test endpoint (/api/v2/monitor/system/status). Make sure the "
            "profile URL includes your custom port, for example https://<fortigate>:8443, paste only the token "
            "value, and confirm the API admin trusted hosts/admin profile allow this request."
        )

    if exc.status_code == 403:
        return (
            "HTTP 403 Forbidden. The token appears valid, but the API admin profile is not allowed to read this "
            "endpoint."
        )

    return str(exc)

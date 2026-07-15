from __future__ import annotations

import platform

from flask import Blueprint, current_app, jsonify, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_profile_deleted, annotate_profile_saved, annotate_tool_run
from .network_tools import (
    ToolInputError,
    parse_radius_attributes,
    radius_authenticate,
    validate_hosts,
)
from .profiles import RadiusProfileStore
from .radius_eap_tools import eapol_test_available, radius_eap_authenticate


def _record_radius_activity(
    title: str,
    detail: str = "",
    *,
    attempts: int = 0,
    count_action: bool = False,
) -> None:
    record_current_activity(
        "Authentication",
        title,
        detail,
        counters={"radius": {"attempts": attempts}},
        count_action=count_action,
    )


def register_radius_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/radius-test", methods=["GET", "POST"])
    def radius_test():
        server_store = _radius_profile_store("servers")
        credential_store = _radius_profile_store("credentials")
        attribute_store = _radius_profile_store("attributes")
        form = {
            "server_names": [],
            "credential_name": "",
            "protocol": "pap",
            "timeout": "3",
            "retries": "1",
            "attribute_profile": "",
            "anonymous_identity": "anonymous",
            "server_domain": "",
            "private_key_password": "",
        }
        results = None
        error = ""
        if request.method == "POST":
            form = {
                "server_names": request.form.getlist("server_names"),
                "credential_name": request.form.get("credential_name", "").strip(),
                "protocol": request.form.get("protocol", "pap").strip(),
                "timeout": request.form.get("timeout", "3").strip(),
                "retries": request.form.get("retries", "1").strip(),
                "attribute_profile": request.form.get("attribute_profile", "").strip(),
                "anonymous_identity": request.form.get("anonymous_identity", "anonymous").strip(),
                "server_domain": request.form.get("server_domain", "").strip(),
                "private_key_password": request.form.get("private_key_password", ""),
            }
            servers = [server_store.get(name) for name in form["server_names"]]
            credentials = credential_store.get(form["credential_name"])
            attribute_profile = (
                attribute_store.get(form["attribute_profile"]) if form["attribute_profile"] else None
            )
            if not form["server_names"] or any(server is None for server in servers):
                error = "Select at least one valid RADIUS server profile."
            elif not credentials:
                error = "Select a valid credential profile."
            elif form["attribute_profile"] and not attribute_profile:
                error = "Select a valid RADIUS attribute profile."
            elif form["protocol"] in {"peap-mschapv2", "eap-tls"} and attribute_profile:
                error = "Additional RADIUS attribute profiles currently apply to PAP and CHAP only."
            else:
                try:
                    if form["protocol"] in {"peap-mschapv2", "eap-tls"}:
                        results = radius_eap_authenticate(
                            [server for server in servers if server],
                            credentials,
                            form["protocol"],
                            timeout=float(form["timeout"]),
                            ca_certificate=_uploaded_bytes("ca_certificate"),
                            client_certificate=_uploaded_bytes("client_certificate"),
                            private_key=_uploaded_bytes("private_key"),
                            private_key_password=form["private_key_password"],
                            anonymous_identity=form["anonymous_identity"],
                            server_domain=form["server_domain"],
                        )
                    else:
                        results = radius_authenticate(
                            [server for server in servers if server],
                            credentials,
                            form["protocol"],
                            float(form["timeout"]),
                            int(form["retries"]),
                            parse_radius_attributes(attribute_profile["source"])
                            if attribute_profile
                            else [],
                        )
                except (ToolInputError, TypeError, ValueError) as exc:
                    _record_radius_activity(
                        "Ran RADIUS test",
                        f"{len(form['server_names'])} server(s), {form['protocol']}: failed",
                        count_action=True,
                    )
                    error = str(exc) or "Enter valid timeout and attempt values."
                else:
                    successes = sum(
                        1
                        for result in results
                        if not result.get("error")
                        and str(result.get("status", "")).lower() not in {"error", "failed"}
                    )
                    _record_radius_activity(
                        "Ran RADIUS test",
                        (
                            f"{len(results)} server attempt(s), {form['protocol']}, "
                            f"{successes} succeeded"
                        ),
                        attempts=len(results),
                        count_action=True,
                    )
            annotate_tool_run(
                category="Network tools",
                action_namespace="radius.authentication_test",
                tool_name="RADIUS authentication test",
                outcome="failed" if error else "succeeded",
                details={
                    "server count": len(form["server_names"]),
                    "protocol": form["protocol"],
                    "attempt count": len(results or []),
                    "successful attempt count": sum(
                        1
                        for result in results or []
                        if not result.get("error")
                        and str(result.get("status", "")).lower()
                        not in {"error", "failed"}
                    ),
                },
            )
        return render_template(
            "tools/radius_test.html",
            error=error,
            form=form,
            servers=server_store.all(),
            credentials=credential_store.all(),
            attribute_profiles=attribute_store.all(),
            results=results,
            eapol_available=eapol_test_available(),
            is_macos=platform.system() == "Darwin",
        )

    @tools_bp.post("/radius-test/profiles/<kind>")
    def save_radius_profile(kind: str):
        if kind not in {"servers", "credentials", "attributes"}:
            return jsonify({"error": "Unknown RADIUS profile type."}), 404
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        store = _radius_profile_store(kind)
        existing = store.get(original_name) if original_name else store.get(name)
        if not name or len(name) > 100:
            return jsonify({"error": "Enter a profile name of 100 characters or fewer."}), 400
        if kind == "servers":
            host = request.form.get("host", "").strip()
            secret = request.form.get("secret", "")
            try:
                validate_hosts(host, limit=1)
                port = int(request.form.get("port", "1812"))
                if not 1 <= port <= 65535:
                    raise ValueError
            except (ToolInputError, ValueError):
                return jsonify({"error": "Enter a valid server host and UDP port."}), 400
            if not secret and not existing:
                return jsonify({"error": "Enter the RADIUS shared secret."}), 400
            profile = {
                "name": name,
                "host": host,
                "port": port,
                "secret": secret or existing["secret"],
            }
        elif kind == "credentials":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or (not password and not existing):
                return jsonify({"error": "Enter both a username and password."}), 400
            profile = {
                "name": name,
                "username": username,
                "password": password or existing["password"],
            }
        else:
            values = request.form.get("attributes", "")
            try:
                attributes = parse_radius_attributes(values)
            except ToolInputError as exc:
                return jsonify({"error": str(exc)}), 400
            if not attributes:
                return jsonify({"error": "Enter at least one RADIUS attribute."}), 400
            profile = {"name": name, "count": len(attributes), "source": values.strip()}
        store.upsert(profile, original_name=original_name)
        profile_type = {
            "servers": "RADIUS server profile",
            "credentials": "RADIUS credential profile",
            "attributes": "RADIUS request-attribute profile",
        }[kind]
        credential_updated = (
            bool(request.form.get("secret", ""))
            if kind == "servers"
            else bool(request.form.get("password", ""))
            if kind == "credentials"
            else False
        )
        annotate_profile_saved(
            category="Network tools",
            action_namespace=f"radius.{kind}",
            profile_type=profile_type,
            before=existing,
            after=profile,
            credential_updated=credential_updated,
        )
        return jsonify({"profile": {"name": name}})

    @tools_bp.post("/radius-test/profiles/<kind>/delete")
    def delete_radius_profile(kind: str):
        if kind not in {"servers", "credentials", "attributes"}:
            return jsonify({"error": "Unknown RADIUS profile type."}), 404
        name = request.form.get("name", "").strip()
        store = _radius_profile_store(kind)
        profile = store.get(name)
        if not profile or not store.delete(name):
            return jsonify({"error": "Profile not found."}), 404
        profile_type = {
            "servers": "RADIUS server profile",
            "credentials": "RADIUS credential profile",
            "attributes": "RADIUS request-attribute profile",
        }[kind]
        annotate_profile_deleted(
            category="Network tools",
            action_namespace=f"radius.{kind}",
            profile_type=profile_type,
            profile=profile,
        )
        return jsonify({"deleted": name})


def _radius_profile_store(kind: str) -> RadiusProfileStore:
    return RadiusProfileStore(current_app.instance_path, kind)


def _uploaded_bytes(name: str) -> bytes:
    upload = request.files.get(name)
    return upload.read(2 * 1024 * 1024 + 1) if upload and upload.filename else b""

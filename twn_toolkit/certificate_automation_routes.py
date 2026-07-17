from __future__ import annotations

import io
import re
import zipfile
from typing import Any

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from .activity_context import record_current_activity
from .audit import (
    annotate_audit_event,
    annotate_profile_deleted,
    annotate_profile_saved,
    annotate_profile_tested,
    annotate_tool_run,
)
from .certificate_automation import (
    AdcsWebEnrollmentProvider,
    CertificateAutomationError,
    CertificateAutomationStore,
    EnrollmentResult,
    VALID_KEY_SIZES,
    build_certificate_request,
    load_or_generate_private_key,
    normalize_certificate_identity,
    validate_ca_bundle,
    validate_enrollment_url,
    validate_template_identifier,
)


def register_certificate_automation_routes(tools_bp: Blueprint) -> None:
    @tools_bp.get("/certificate-automation")
    def certificate_automation():
        store = _store()
        selected_id = request.args.get("certificate", "").strip()
        selected = store.managed_certificate(selected_id) if selected_id else None
        managed = store.managed_certificates()
        summary = {
            "issued": sum(item.get("status") == "issued" for item in managed),
            "pending": sum(item.get("status") == "pending" for item in managed),
            "expiring": sum(
                item.get("days_remaining") is not None
                and item["days_remaining"] <= _renewal_days(item, store)
                for item in managed
            ),
        }
        return render_template(
            "tools/certificate_automation.html",
            credentials=store.credential_profiles(),
            servers=store.server_profiles(),
            templates=store.template_profiles(),
            managed=managed,
            selected=selected,
            summary=summary,
            valid_key_sizes=sorted(VALID_KEY_SIZES),
        )

    @tools_bp.post("/certificate-automation/credentials")
    def save_pki_credential():
        store = _store()
        credential_id = request.form.get("id", "").strip()
        before = store.credential_profile(credential_id) if credential_id else None
        name = _profile_name(request.form.get("name", ""))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            if not username or len(username) > 320:
                raise ValueError("Enter an enrollment username of 320 characters or fewer.")
            saved = store.save_credential(
                credential_id=credential_id,
                name=name,
                username=username,
                password=password,
            )
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            annotate_profile_saved(
                category="Network tools",
                action_namespace="certificate_automation.credentials",
                profile_type="PKI credential profile",
                before=before,
                after=saved,
                credential_updated=bool(password),
            )
            flash(f"Saved credential profile {saved['name']}.", "success")
        return _redirect_home(anchor="pki-profiles")

    @tools_bp.post("/certificate-automation/credentials/<credential_id>/delete")
    def delete_pki_credential(credential_id: str):
        store = _store()
        profile = store.credential_profile(credential_id)
        if not profile or not store.delete_credential(credential_id):
            flash("Credential profile not found.", "error")
        else:
            annotate_profile_deleted(
                category="Network tools",
                action_namespace="certificate_automation.credentials",
                profile_type="PKI credential profile",
                profile=profile,
            )
            flash(f"Deleted credential profile {profile['name']}.", "success")
        return _redirect_home(anchor="pki-profiles")

    @tools_bp.post("/certificate-automation/servers")
    def save_pki_server():
        store = _store()
        server_id = request.form.get("id", "").strip()
        before = store.server_profile(server_id) if server_id else None
        upload = request.files.get("ca_bundle")
        uploaded_bundle = upload.read(2 * 1024 * 1024 + 1) if upload and upload.filename else b""
        try:
            name = _profile_name(request.form.get("name", ""))
            enrollment_url = validate_enrollment_url(request.form.get("enrollment_url", ""))
            credential_id = request.form.get("credential_id", "").strip()
            if credential_id and not store.credential_profile(credential_id):
                raise ValueError("Select a valid default credential profile.")
            strategy = request.form.get("retrieval_strategy", "same_endpoint")
            if strategy not in {"same_endpoint", "resolved_ipv4"}:
                raise ValueError("Select a valid certificate retrieval strategy.")
            timeout = float(request.form.get("timeout", "15"))
            if not 2 <= timeout <= 60:
                raise ValueError("The PKI timeout must be between 2 and 60 seconds.")
            saved = store.save_server(
                {
                    "id": server_id,
                    "name": name,
                    "provider": "adcs_web_enrollment",
                    "enrollment_url": enrollment_url,
                    "credential_id": credential_id,
                    "ca_bundle_pem": validate_ca_bundle(uploaded_bundle),
                    "keep_ca_bundle": not uploaded_bundle and bool(before),
                    "remove_ca_bundle": request.form.get("remove_ca_bundle") == "1",
                    "verify_tls": request.form.get("verify_tls") == "1",
                    "retrieval_strategy": strategy,
                    "timeout": timeout,
                }
            )
        except (TypeError, ValueError) as exc:
            flash(str(exc), "error")
        else:
            annotate_profile_saved(
                category="Network tools",
                action_namespace="certificate_automation.servers",
                profile_type="PKI server profile",
                before=_server_audit_snapshot(before),
                after=_server_audit_snapshot(saved),
            )
            flash(f"Saved PKI server profile {saved['name']}.", "success")
        return _redirect_home(anchor="pki-profiles")

    @tools_bp.post("/certificate-automation/servers/<server_id>/delete")
    def delete_pki_server(server_id: str):
        store = _store()
        profile = store.server_profile(server_id)
        try:
            deleted = bool(profile) and store.delete_server(server_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            if not deleted or not profile:
                flash("PKI server profile not found.", "error")
            else:
                annotate_profile_deleted(
                    category="Network tools",
                    action_namespace="certificate_automation.servers",
                    profile_type="PKI server profile",
                    profile=_server_audit_snapshot(profile),
                )
                flash(f"Deleted PKI server profile {profile['name']}.", "success")
        return _redirect_home(anchor="pki-profiles")

    @tools_bp.post("/certificate-automation/servers/<server_id>/test")
    def test_pki_server(server_id: str):
        store = _store()
        profile = store.server_profile(server_id)
        if not profile:
            flash("PKI server profile not found.", "error")
            return _redirect_home(anchor="pki-profiles")
        try:
            username, password = _request_credentials(store, profile)
            status_code = _provider(profile, username, password).test_connection()
        except (CertificateAutomationError, ValueError) as exc:
            annotate_profile_tested(
                category="Network tools",
                action_namespace="certificate_automation.servers",
                profile_type="PKI server profile",
                profile=profile,
                outcome="failed",
            )
            flash(str(exc), "error")
        else:
            annotate_profile_tested(
                category="Network tools",
                action_namespace="certificate_automation.servers",
                profile_type="PKI server profile",
                profile=profile,
                outcome="succeeded",
                status_code=status_code,
            )
            flash(f"Connected to {profile['name']} successfully.", "success")
        return _redirect_home(anchor="pki-profiles")

    @tools_bp.post("/certificate-automation/templates")
    def save_pki_template():
        store = _store()
        template_id = request.form.get("id", "").strip()
        before = store.template_profile(template_id) if template_id else None
        try:
            name = _profile_name(request.form.get("name", ""))
            server_id = request.form.get("server_id", "").strip()
            if not store.server_profile(server_id):
                raise ValueError("Select a valid PKI server profile.")
            identifier = validate_template_identifier(
                request.form.get("template_identifier", "")
            )
            key_size = int(request.form.get("key_size", "2048"))
            renewal_days = int(request.form.get("renewal_days", "30"))
            if key_size not in VALID_KEY_SIZES:
                raise ValueError("Select a supported RSA key size.")
            if not 1 <= renewal_days <= 365:
                raise ValueError("The renewal window must be between 1 and 365 days.")
            saved = store.save_template(
                {
                    "id": template_id,
                    "name": name,
                    "server_id": server_id,
                    "template_identifier": identifier,
                    "key_size": key_size,
                    "renewal_days": renewal_days,
                }
            )
        except (TypeError, ValueError) as exc:
            flash(str(exc), "error")
        else:
            annotate_profile_saved(
                category="Network tools",
                action_namespace="certificate_automation.templates",
                profile_type="certificate template profile",
                before=before,
                after=saved,
            )
            flash(f"Saved certificate template profile {saved['name']}.", "success")
        return _redirect_home(anchor="pki-profiles")

    @tools_bp.post("/certificate-automation/templates/<template_id>/delete")
    def delete_pki_template(template_id: str):
        store = _store()
        profile = store.template_profile(template_id)
        try:
            deleted = bool(profile) and store.delete_template(template_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            if not deleted or not profile:
                flash("Certificate template profile not found.", "error")
            else:
                annotate_profile_deleted(
                    category="Network tools",
                    action_namespace="certificate_automation.templates",
                    profile_type="certificate template profile",
                    profile=profile,
                )
                flash(f"Deleted certificate template profile {profile['name']}.", "success")
        return _redirect_home(anchor="pki-profiles")

    @tools_bp.post("/certificate-automation/enroll")
    def enroll_managed_certificate():
        store = _store()
        managed_id = request.form.get("managed_id", "").strip()
        existing = store.managed_certificate(managed_id) if managed_id else None
        try:
            name = _profile_name(request.form.get("name", ""))
            template = store.template_profile(request.form.get("template_id", "").strip())
            if not template:
                raise ValueError("Select a valid certificate template profile.")
            server = store.server_profile(template["server_id"])
            if not server:
                raise ValueError("The template's PKI server profile no longer exists.")
            common_name, dns_names = normalize_certificate_identity(
                request.form.get("common_name", ""), request.form.get("dns_names", "")
            )
            private_key = _request_private_key(store, existing, int(template["key_size"]))
            key_pem, csr_pem = build_certificate_request(common_name, dns_names, private_key)
            username, password = _request_credentials(store, server)
            result = _provider(server, username, password).enroll(
                csr_pem,
                template["template_identifier"],
                key_pem,
                common_name,
                dns_names,
            )
            managed = store.save_enrollment(
                managed_id=managed_id,
                name=name,
                server_id=server["id"],
                template_id=template["id"],
                common_name=common_name,
                dns_names=dns_names,
                private_key_pem=key_pem,
                result=result,
            )
        except (CertificateAutomationError, ValueError) as exc:
            annotate_tool_run(
                category="Network tools",
                action_namespace="certificate_automation.enrollment",
                tool_name="certificate enrollment",
                outcome="failed",
                details={"rotation": bool(existing)},
            )
            flash(str(exc), "error")
            return _redirect_home(anchor="request-certificate")
        annotate_tool_run(
            category="Network tools",
            action_namespace="certificate_automation.enrollment",
            tool_name="certificate rotation" if existing else "certificate enrollment",
            outcome=result.status,
            details={"rotation": bool(existing), "disposition": result.status},
        )
        record_current_activity(
            "TLS",
            "Rotated managed certificate" if existing else "Enrolled managed certificate",
            f"{name} · {result.status}",
            counters={"certificates": {"enrollments": 1}},
        )
        flash(
            f"Certificate request {result.request_id or ''} is {result.status}.".replace("  ", " "),
            "success" if result.status == "issued" else "warning",
        )
        return redirect(
            url_for("tools.certificate_automation", certificate=managed["id"]) + "#managed-certificates"
        )

    @tools_bp.post("/certificate-automation/managed/<managed_id>/collect")
    def collect_pending_certificate(managed_id: str):
        store = _store()
        managed = store.managed_certificate(managed_id)
        material = store.version_material(managed_id) if managed else None
        if not managed or not material or material["status"] != "pending":
            flash("Pending certificate request not found.", "error")
            return _redirect_home(anchor="managed-certificates")
        server = store.server_profile(managed["server_id"])
        try:
            if not server:
                raise ValueError("The PKI server profile no longer exists.")
            username, password = _request_credentials(store, server)
            result = _provider(server, username, password).retrieve(
                material["request_id"],
                material["private_key_pem"],
                managed["common_name"],
                managed["dns_names"],
                ca_name=material["ca_name"],
            )
            store.complete_pending_version(managed_id, material["id"], result)
        except (CertificateAutomationError, ValueError) as exc:
            flash(str(exc), "error")
        else:
            annotate_tool_run(
                category="Network tools",
                action_namespace="certificate_automation.collection",
                tool_name="pending certificate collection",
                outcome="succeeded",
                details={"request ID": material["request_id"]},
            )
            flash("The pending certificate has been issued and collected.", "success")
        return redirect(
            url_for("tools.certificate_automation", certificate=managed_id) + "#managed-certificates"
        )

    @tools_bp.get("/certificate-automation/managed/<managed_id>/download")
    def download_managed_certificate(managed_id: str):
        store = _store()
        managed = store.managed_certificate(managed_id)
        version_id = request.args.get("version", "").strip()
        material = store.version_material(managed_id, version_id)
        if not managed or not material or material["status"] != "issued":
            return Response("Issued certificate material not found.", status=404)
        archive = _certificate_archive(managed, material)
        annotate_audit_event(
            category="Network tools",
            action="certificate_automation.material_downloaded",
            summary=f"Downloaded certificate material for {managed['name']}.",
            resource_type="managed_certificate",
            resource_id=managed_id,
            resource_name=managed["name"],
            details={"version ID": material["id"]},
        )
        return send_file(
            archive,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"{_safe_filename(managed['name'])}-certificate.zip",
        )

    @tools_bp.post("/certificate-automation/managed/<managed_id>/delete")
    def delete_managed_certificate(managed_id: str):
        store = _store()
        managed = store.managed_certificate(managed_id)
        if not managed or not store.delete_managed_certificate(managed_id):
            flash("Managed certificate not found.", "error")
        else:
            annotate_audit_event(
                category="Network tools",
                action="certificate_automation.managed_deleted",
                summary=f"Deleted managed certificate {managed['name']} and its key history.",
                resource_type="managed_certificate",
                resource_id=managed_id,
                resource_name=managed["name"],
                details={"deleted versions": managed["version_count"]},
            )
            flash(f"Deleted managed certificate {managed['name']} and all of its key material.", "success")
        return _redirect_home(anchor="managed-certificates")


def _store() -> CertificateAutomationStore:
    return CertificateAutomationStore(
        current_app.instance_path, str(current_app.config["SECRET_KEY"])
    )


def _provider(
    server: dict[str, Any], username: str, password: str
) -> AdcsWebEnrollmentProvider:
    if server.get("provider") != "adcs_web_enrollment":
        raise ValueError("The selected PKI provider is not supported.")
    return AdcsWebEnrollmentProvider(server, username, password)


def _profile_name(value: str) -> str:
    name = value.strip()
    if not name or len(name) > 100:
        raise ValueError("Enter a profile name of 100 characters or fewer.")
    return name


def _request_credentials(
    store: CertificateAutomationStore, server: dict[str, Any]
) -> tuple[str, str]:
    credential_id = request.form.get("credential_id", "").strip() or str(
        server.get("credential_id") or ""
    )
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if username or password:
        if not username or not password:
            raise ValueError("Enter both a one-time enrollment username and password.")
        return username, password
    if not credential_id:
        raise ValueError("Select saved enrollment credentials or enter one-time credentials.")
    credential = store.credential_profile(credential_id, include_password=True)
    if not credential:
        raise ValueError("The selected credential profile no longer exists.")
    return str(credential["username"]), str(credential["password"])


def _request_private_key(
    store: CertificateAutomationStore,
    existing: dict[str, Any] | None,
    key_size: int,
):
    source = request.form.get("key_source", "generate")
    key_bytes = b""
    password = request.form.get("private_key_password", "")
    if source == "upload":
        upload = request.files.get("private_key")
        key_bytes = upload.read(2 * 1024 * 1024 + 1) if upload and upload.filename else b""
        if not key_bytes:
            raise ValueError("Choose a PEM private key to import.")
    elif source == "reuse":
        if not existing:
            raise ValueError("Only an existing managed certificate can reuse a saved key.")
        material = store.version_material(existing["id"])
        if not material:
            raise ValueError("The managed certificate has no reusable private key.")
        key_bytes = material["private_key_pem"]
    elif source != "generate":
        raise ValueError("Select a valid private-key source.")
    return load_or_generate_private_key(
        key_size=key_size, existing_key=key_bytes, password=password
    )


def _certificate_archive(managed: dict[str, Any], material: dict[str, Any]) -> io.BytesIO:
    prefix = _safe_filename(managed["name"])
    certificate = material["certificate_pem"]
    chain = material["chain_pem"]
    key = material["private_key_pem"]
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{prefix}.key", key)
        archive.writestr(f"{prefix}.pem", certificate)
        archive.writestr(f"{prefix}-chain.pem", chain)
        archive.writestr(f"{prefix}-fullchain.pem", certificate + chain)
        archive.writestr(f"{prefix}-bundle.pem", key + certificate + chain)
        archive.writestr(
            "README.txt",
            "This archive contains unencrypted private-key material. Store it securely.\n"
            "The .pem file is the leaf certificate, -chain.pem contains issuing CAs,\n"
            "-fullchain.pem contains leaf plus chain, and -bundle.pem also includes the key.\n",
        )
    output.seek(0)
    return output


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-.") or "certificate"


def _server_audit_snapshot(profile: dict[str, Any] | None) -> dict[str, Any] | None:
    if profile is None:
        return None
    return {
        key: value
        for key, value in profile.items()
        if key not in {"ca_bundle_pem"}
    }


def _redirect_home(*, anchor: str = ""):
    target = url_for("tools.certificate_automation")
    return redirect(target + (f"#{anchor}" if anchor else ""))


def _renewal_days(managed: dict[str, Any], store: CertificateAutomationStore) -> int:
    template = store.template_profile(managed["template_id"])
    return int(template["renewal_days"]) if template else 30

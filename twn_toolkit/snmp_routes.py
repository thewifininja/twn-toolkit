from __future__ import annotations

from typing import Any

from flask import Blueprint, current_app, jsonify, render_template, request

from .network_tools import ToolInputError, validate_hosts
from .profiles import (
    SNMPCredentialProfileStore,
    SNMPHostProfileStore,
    SNMPOidProfileStore,
)
from .snmp_tools import parse_oid_profile, run_snmp_tests, validate_snmp_credential


def register_snmp_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/snmp-test", methods=["GET", "POST"])
    def snmp_test():
        credential_store = _snmp_credential_store()
        host_store = _snmp_host_store()
        oid_store = _snmp_oid_store()
        selected_hosts: list[str] = []
        selected_oid_profiles: list[str] = []
        results = None
        error = ""
        if request.method == "POST":
            selected_hosts = request.form.getlist("host_names")
            selected_oid_profiles = request.form.getlist("oid_profile_names")
            hosts = [host_store.get(name) for name in selected_hosts]
            oid_profiles = [oid_store.get(name) for name in selected_oid_profiles]
            if not selected_hosts or len(selected_hosts) > 20 or any(host is None for host in hosts):
                error = "Select between 1 and 20 valid SNMP hosts."
            elif (
                not selected_oid_profiles
                or len(selected_oid_profiles) > 10
                or any(profile is None for profile in oid_profiles)
            ):
                error = "Select between 1 and 10 valid OID profiles."
            else:
                credential_names = {host["credential_name"] for host in hosts if host}
                credentials = {name: credential_store.get(name) for name in credential_names}
                if any(profile is None for profile in credentials.values()):
                    error = "One or more hosts reference a missing SNMP profile."
                else:
                    try:
                        prepared_oid_profiles = [
                            {**profile, "entries": parse_oid_profile(profile["source"])}
                            for profile in oid_profiles
                            if profile
                        ]
                        results = run_snmp_tests(
                            [host for host in hosts if host],
                            {name: profile for name, profile in credentials.items() if profile},
                            prepared_oid_profiles,
                        )
                    except (ToolInputError, ValueError) as exc:
                        error = str(exc)
        credentials = credential_store.all()
        return render_template(
            "tools/snmp_test.html",
            credentials=[_public_snmp_credential(profile) for profile in credentials],
            error=error,
            hosts=host_store.all(),
            oid_profiles=oid_store.all(),
            results=results,
            selected_hosts=selected_hosts,
            selected_oid_profiles=selected_oid_profiles,
        )

    @tools_bp.post("/snmp-test/profiles/<kind>")
    def save_snmp_profile(kind: str):
        if kind not in {"credentials", "hosts", "oids"}:
            return jsonify({"error": "Unknown SNMP profile type."}), 404
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        if not name or len(name) > 100:
            return jsonify({"error": "Enter a profile name of 100 characters or fewer."}), 400

        if kind == "credentials":
            store = _snmp_credential_store()
            existing = store.get(original_name) if original_name else store.get(name)
            try:
                profile = validate_snmp_credential(
                    {
                        "name": name,
                        "version": request.form.get("version", ""),
                        "community": request.form.get("community", ""),
                        "username": request.form.get("username", ""),
                        "security_level": request.form.get("security_level", ""),
                        "auth_protocol": request.form.get("auth_protocol", ""),
                        "auth_key": request.form.get("auth_key", ""),
                        "priv_protocol": request.form.get("priv_protocol", ""),
                        "priv_key": request.form.get("priv_key", ""),
                        "context_name": request.form.get("context_name", ""),
                    },
                    existing,
                )
            except ToolInputError as exc:
                return jsonify({"error": str(exc)}), 400
            store.upsert(profile, original_name=original_name)
            if original_name and original_name != name:
                host_store = _snmp_host_store()
                for host in host_store.all():
                    if host["credential_name"] == original_name:
                        host_store.upsert(
                            {**host, "credential_name": name}, original_name=host["name"]
                        )
            return jsonify({"profile": _public_snmp_credential(profile)})

        if kind == "hosts":
            credential_name = request.form.get("credential_name", "").strip()
            host = request.form.get("host", "").strip()
            try:
                validate_hosts(host, limit=1)
                port = int(request.form.get("port", "161"))
                timeout = float(request.form.get("timeout", "2"))
                retries = int(request.form.get("retries", "1"))
                if not 1 <= port <= 65535:
                    raise ToolInputError("SNMP port must be between 1 and 65535.")
                if not 0.2 <= timeout <= 30:
                    raise ToolInputError("Timeout must be between 0.2 and 30 seconds.")
                if not 0 <= retries <= 5:
                    raise ToolInputError("Retries must be between 0 and 5.")
                if not _snmp_credential_store().get(credential_name):
                    raise ToolInputError("Select a valid SNMP profile.")
            except (ToolInputError, ValueError) as exc:
                return jsonify({"error": str(exc) or "Enter valid host settings."}), 400
            profile = {
                "name": name,
                "host": host,
                "port": port,
                "credential_name": credential_name,
                "timeout": timeout,
                "retries": retries,
            }
            _snmp_host_store().upsert(profile, original_name=original_name)
            return jsonify({"profile": profile})

        source = request.form.get("source", "")
        try:
            entries = parse_oid_profile(source)
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        profile = {"name": name, "source": source.strip(), "count": len(entries)}
        _snmp_oid_store().upsert(profile, original_name=original_name)
        return jsonify({"profile": profile})

    @tools_bp.post("/snmp-test/profiles/<kind>/delete")
    def delete_snmp_profile(kind: str):
        if kind not in {"credentials", "hosts", "oids"}:
            return jsonify({"error": "Unknown SNMP profile type."}), 404
        name = request.form.get("name", "").strip()
        if kind == "credentials":
            linked_hosts = [
                host["name"]
                for host in _snmp_host_store().all()
                if host["credential_name"] == name
            ]
            if linked_hosts:
                return jsonify(
                    {"error": f"Profile is used by: {', '.join(linked_hosts[:5])}."}
                ), 409
            store = _snmp_credential_store()
        elif kind == "hosts":
            store = _snmp_host_store()
        else:
            store = _snmp_oid_store()
        if not store.delete(name):
            return jsonify({"error": "Profile not found."}), 404
        return jsonify({"deleted": name})


def _snmp_credential_store() -> SNMPCredentialProfileStore:
    return SNMPCredentialProfileStore(current_app.instance_path)


def _snmp_host_store() -> SNMPHostProfileStore:
    return SNMPHostProfileStore(current_app.instance_path)


def _snmp_oid_store() -> SNMPOidProfileStore:
    return SNMPOidProfileStore(current_app.instance_path)


def _public_snmp_credential(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in profile.items()
        if key not in {"community", "auth_key", "priv_key"}
    } | {
        "has_community": bool(profile.get("community")),
        "has_auth_key": bool(profile.get("auth_key")),
        "has_priv_key": bool(profile.get("priv_key")),
    }

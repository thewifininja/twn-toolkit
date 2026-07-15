from __future__ import annotations

from typing import Any

from flask import Blueprint, current_app, jsonify, render_template, request

from .activity_context import increment_current_activity, record_current_activity
from .audit import (
    annotate_audit_event,
    annotate_profile_deleted,
    annotate_profile_saved,
    suppress_audit_event,
)
from .network_tools import ToolInputError, validate_hosts
from .profiles import (
    SNMPCredentialProfileStore,
    SNMPHostProfileStore,
    SNMPOidProfileStore,
)
from .snmp_tools import (
    discover_snmp_interfaces,
    parse_oid_profile,
    poll_snmp_interface,
    poll_snmp_interfaces,
    run_snmp_tests,
    validate_snmp_credential,
)


INTERFACE_MONITOR_INTERVALS = {1, 5, 10, 15, 30, 60}


def _record_snmp_activity(
    title: str,
    detail: str = "",
    *,
    polls: int = 0,
    count_action: bool = False,
) -> None:
    record_current_activity(
        "Infrastructure",
        title,
        detail,
        counters={"snmp": {"polls": polls}},
        count_action=count_action,
    )


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
                        _record_snmp_activity(
                            "Ran SNMP test",
                            f"{len(selected_hosts)} host(s), {len(selected_oid_profiles)} OID profile(s): failed",
                            count_action=True,
                        )
                        error = str(exc)
                    else:
                        failed = sum(1 for result in results if result.get("status") == "error")
                        rows = sum(len(result.get("rows", [])) for result in results)
                        _record_snmp_activity(
                            "Ran SNMP test",
                            (
                                f"{len(selected_hosts)} host(s), "
                                f"{len(selected_oid_profiles)} OID profile(s), "
                                f"{rows} value(s), {failed} failed"
                            ),
                            polls=len(results),
                            count_action=True,
                        )
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
            annotate_profile_saved(
                category="Network tools",
                action_namespace="snmp.credentials",
                profile_type="SNMP credential profile",
                before=existing,
                after=profile,
                credential_updated=any(
                    request.form.get(field, "")
                    for field in ("community", "auth_key", "priv_key")
                ),
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
            store = _snmp_host_store()
            before = store.get(original_name or name)
            store.upsert(profile, original_name=original_name)
            annotate_profile_saved(
                category="Network tools",
                action_namespace="snmp.hosts",
                profile_type="SNMP host profile",
                before=before,
                after=profile,
            )
            return jsonify({"profile": profile})

        source = request.form.get("source", "")
        try:
            entries = parse_oid_profile(source)
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        profile = {"name": name, "source": source.strip(), "count": len(entries)}
        store = _snmp_oid_store()
        before = store.get(original_name or name)
        store.upsert(profile, original_name=original_name)
        annotate_profile_saved(
            category="Network tools",
            action_namespace="snmp.oids",
            profile_type="SNMP OID profile",
            before=before,
            after=profile,
        )
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
        profile = store.get(name)
        if not profile or not store.delete(name):
            return jsonify({"error": "Profile not found."}), 404
        profile_type = {
            "credentials": "SNMP credential profile",
            "hosts": "SNMP host profile",
            "oids": "SNMP OID profile",
        }[kind]
        annotate_profile_deleted(
            category="Network tools",
            action_namespace=f"snmp.{kind}",
            profile_type=profile_type,
            profile=profile,
        )
        return jsonify({"deleted": name})

    @tools_bp.post("/snmp-test/interfaces")
    def snmp_interfaces():
        suppress_audit_event()
        try:
            host, credential = _saved_snmp_target(_request_value("host_name"))
            result = discover_snmp_interfaces(host, credential)
        except (ToolInputError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:  # pysnmp transport and protocol failures
            current_app.logger.warning("SNMP interface discovery failed: %s", exc)
            return jsonify({"error": "Interface discovery failed. Verify the host, credentials, and SNMP access."}), 502
        increment_current_activity("snmp", "polls", int(result.get("poll_count", 0)))
        return jsonify(result)

    @tools_bp.post("/snmp-test/interface-sample")
    def snmp_interface_sample():
        suppress_audit_event()
        try:
            host, credential = _saved_snmp_target(_request_value("host_name"))
            interface_index = int(_request_value("interface_index"))
            if not 1 <= interface_index <= 2_147_483_647:
                raise ToolInputError("Select a valid interface.")
            result = poll_snmp_interface(host, credential, interface_index)
        except (ToolInputError, ValueError) as exc:
            return jsonify({"error": str(exc) or "Select a valid interface."}), 400
        except Exception as exc:  # pysnmp transport and protocol failures
            current_app.logger.warning("SNMP interface poll failed: %s", exc)
            return jsonify({"error": "The interface poll failed. Verify that the device is still reachable."}), 502
        increment_current_activity("snmp", "polls", int(result.get("poll_count", 1)))
        return jsonify(result)

    @tools_bp.post("/snmp-test/interface-samples")
    def snmp_interface_samples():
        suppress_audit_event()
        payload = request.get_json(silent=True) or {}
        raw_targets = payload.get("targets")
        if not isinstance(raw_targets, list) or not 1 <= len(raw_targets) <= 20:
            return jsonify({"error": "Select between 1 and 20 interfaces to poll."}), 400
        prepared = []
        try:
            for raw_target in raw_targets:
                if not isinstance(raw_target, dict):
                    raise ToolInputError("The monitor set contains an invalid interface.")
                host, credential = _saved_snmp_target(
                    str(raw_target.get("host_name", "")).strip()
                )
                interface_index = int(raw_target.get("interface_index", 0))
                if not 1 <= interface_index <= 2_147_483_647:
                    raise ToolInputError("Select a valid interface.")
                prepared.append((host, credential, interface_index))
            results = poll_snmp_interfaces(prepared)
        except (ToolInputError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            current_app.logger.warning("SNMP interface batch poll failed: %s", exc)
            return jsonify({"error": "The interface polling round could not be completed."}), 502
        increment_current_activity(
            "snmp",
            "polls",
            sum(
                int(result.get("sample", {}).get("poll_count", 1))
                for result in results
                if result.get("status") == "success"
            ),
        )
        return jsonify({"results": results})

    @tools_bp.post("/snmp-test/interface-monitor/start")
    def start_snmp_interface_monitor():
        try:
            targets, interval = _monitor_request_values()
        except (ToolInputError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        detail = f"{len(targets)} interface(s) · every {interval} second(s)"
        annotate_audit_event(
            category="Infrastructure",
            action="start_snmp_interface_monitor",
            summary=f"Started SNMP bandwidth monitor for {len(targets)} interface(s).",
            resource_type="snmp_interface_monitor",
            resource_id="monitor-set",
            resource_name=f"{len(targets)} interface monitor set",
            details={"targets": targets, "interval_seconds": interval},
        )
        _record_snmp_activity("Started SNMP bandwidth monitor", detail, count_action=True)
        return jsonify({"ok": True})

    @tools_bp.post("/snmp-test/interface-monitor/stop")
    def stop_snmp_interface_monitor():
        try:
            targets, interval = _monitor_request_values()
        except (ToolInputError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        detail = f"{len(targets)} interface(s) · every {interval} second(s)"
        annotate_audit_event(
            category="Infrastructure",
            action="stop_snmp_interface_monitor",
            summary=f"Stopped SNMP bandwidth monitor for {len(targets)} interface(s).",
            resource_type="snmp_interface_monitor",
            resource_id="monitor-set",
            resource_name=f"{len(targets)} interface monitor set",
            details={"targets": targets, "interval_seconds": interval},
        )
        _record_snmp_activity("Stopped SNMP bandwidth monitor", detail, count_action=False)
        return jsonify({"ok": True})


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


def _request_value(name: str) -> str:
    payload = request.get_json(silent=True) if request.is_json else None
    return str((payload or {}).get(name, request.form.get(name, ""))).strip()


def _saved_snmp_target(host_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    host = _snmp_host_store().get(host_name)
    if not host:
        raise ToolInputError("Select a saved SNMP host.")
    credential = _snmp_credential_store().get(host.get("credential_name", ""))
    if not credential:
        raise ToolInputError("The selected host references a missing SNMP credential profile.")
    return host, credential


def _monitor_request_values() -> tuple[list[dict[str, Any]], int]:
    payload = request.get_json(silent=True) if request.is_json else None
    raw_targets = (payload or {}).get("targets")
    if not isinstance(raw_targets, list) or not 1 <= len(raw_targets) <= 20:
        raise ToolInputError("Select between 1 and 20 interfaces to monitor.")
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for raw_target in raw_targets:
        if not isinstance(raw_target, dict):
            raise ToolInputError("The monitor set contains an invalid interface.")
        host_name = str(raw_target.get("host_name", "")).strip()
        host, _credential = _saved_snmp_target(host_name)
        interface_index = int(raw_target.get("interface_index", 0))
        if not 1 <= interface_index <= 2_147_483_647:
            raise ToolInputError("Select a valid interface.")
        key = (host["name"], interface_index)
        if key in seen:
            raise ToolInputError("The monitor set contains the same interface more than once.")
        seen.add(key)
        interface_label = str(raw_target.get("interface_label", "")).strip()[:160]
        targets.append(
            {
                "host_name": host["name"],
                "host_address": host["host"],
                "interface_index": interface_index,
                "interface_label": interface_label or f"Interface {interface_index}",
            }
        )
    interval = int(_request_value("interval"))
    if interval not in INTERFACE_MONITOR_INTERVALS:
        raise ToolInputError("Select a supported polling interval.")
    return targets, interval

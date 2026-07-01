from __future__ import annotations

import os
import json
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, render_template, request, stream_with_context

from .certificate_tools import (
    CertificateInspectionError,
    inspect_certificate_chain,
    normalize_certificate_target,
)
from .network_tools import (
    dns_lookup_matrix,
    parse_dns_hosts,
    parse_dns_servers,
    parse_radius_attributes,
    ToolInputError,
    parse_ping_targets,
    parse_tcp_ports,
    ping_hosts,
    run_ssh_hosts,
    radius_authenticate,
    scan_tcp_ports,
    split_values,
    subtract_subnets,
    validate_hosts,
)
from .profiles import (
    DNSProfileStore,
    PingProfileStore,
    RadiusProfileStore,
    PortScanProfileStore,
    SNMPCredentialProfileStore,
    SNMPHostProfileStore,
    SNMPOidProfileStore,
)
from .snmp_tools import parse_oid_profile, run_snmp_tests, validate_snmp_credential
from .ntp_tools import test_ntp_server
from .traceroute_tools import prepare_traceroute, run_traceroute, stream_traceroute


tools_bp = Blueprint("tools", __name__, url_prefix="/tools")
SPEED_TEST_CHUNK_SIZE = 256 * 1024
SPEED_TEST_DEFAULT_DOWNLOAD_SIZE = 512 * 1024 * 1024
SPEED_TEST_MAX_DOWNLOAD_SIZE = 512 * 1024 * 1024
SPEED_TEST_MAX_UPLOAD_SIZE = 16 * 1024 * 1024
SPEED_TEST_DOWNLOAD_CHUNK = os.urandom(SPEED_TEST_CHUNK_SIZE)


@tools_bp.get("/")
def index():
    return render_template("tools/index.html")


@tools_bp.route("/ntp-test", methods=["GET", "POST"])
def ntp_test():
    form = {"host": "", "port": "123", "timeout": "3", "samples": "4"}
    result = None
    error = ""
    if request.method == "POST":
        submitted_host = request.form.get("hosts", "").strip() or request.form.get("host", "").strip()
        form = {
            "host": submitted_host,
            "port": request.form.get("port", "123").strip(),
            "timeout": request.form.get("timeout", "3").strip(),
            "samples": request.form.get("samples", "4").strip(),
        }
        try:
            result = test_ntp_server(
                form["host"],
                port=int(form["port"]),
                timeout=float(form["timeout"]),
                samples=int(form["samples"]),
            )
            if result["status"] != "success":
                error = "; ".join(
                    dict.fromkeys(
                        sample.get("error", "No response")
                        for sample in result["samples"]
                        if sample["status"] == "error"
                    )
                )
        except (ToolInputError, TypeError, ValueError) as exc:
            error = str(exc) or "Enter valid NTP test settings."
    return render_template("tools/ntp_test.html", error=error, form=form, result=result)


@tools_bp.route("/traceroute", methods=["GET", "POST"])
def traceroute():
    form = {
        "host": "",
        "family": "auto",
        "method": "udp",
        "max_hops": "30",
        "probes": "3",
        "timeout": "2",
    }
    result = None
    error = ""
    if request.method == "POST":
        form = {
            "host": request.form.get("host", "").strip(),
            "family": request.form.get("family", "auto"),
            "method": request.form.get("method", "udp"),
            "max_hops": request.form.get("max_hops", "30").strip(),
            "probes": request.form.get("probes", "3").strip(),
            "timeout": request.form.get("timeout", "2").strip(),
        }
        try:
            result = run_traceroute(
                form["host"],
                family=form["family"],
                method=form["method"],
                max_hops=int(form["max_hops"]),
                probes=int(form["probes"]),
                timeout=float(form["timeout"]),
            )
        except (ToolInputError, TypeError, ValueError) as exc:
            error = str(exc) or "Enter valid traceroute settings."
    return render_template("tools/traceroute.html", error=error, form=form, result=result)


@tools_bp.post("/traceroute/run")
def traceroute_run():
    payload = request.get_json(silent=True) or {}
    try:
        prepared = prepare_traceroute(
            str(payload.get("host", "")),
            family=str(payload.get("family", "auto")),
            method=str(payload.get("method", "udp")),
            max_hops=int(payload.get("max_hops", 30)),
            probes=int(payload.get("probes", 3)),
            timeout=float(payload.get("timeout", 2)),
        )
    except (ToolInputError, TypeError, ValueError) as exc:
        return jsonify({"error": str(exc) or "Enter valid traceroute settings."}), 400

    @stream_with_context
    def generate():
        try:
            for event in stream_traceroute(prepared):
                yield json.dumps(event, separators=(",", ":")) + "\n"
        except ToolInputError as exc:
            yield json.dumps({"type": "error", "error": str(exc)}, separators=(",", ":")) + "\n"

    response = Response(generate(), mimetype="application/x-ndjson")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Accel-Buffering"] = "no"
    return response


@tools_bp.route("/port-scanner", methods=["GET", "POST"])
def port_scanner():
    form = {
        "hosts": "",
        "ports": "22, 53, 80, 443",
        "timeout": "1",
        "concurrency": "100",
        "open_only": True,
    }
    results = None
    stats = None
    error = ""
    if request.method == "POST":
        form = {
            "hosts": request.form.get("hosts", "").strip(),
            "ports": request.form.get("ports", "").strip(),
            "timeout": request.form.get("timeout", "1").strip(),
            "concurrency": request.form.get("concurrency", "100").strip(),
            "open_only": request.form.get("open_only") == "on",
        }
        try:
            targets = parse_ping_targets(form["hosts"], limit=50)
            ports = parse_tcp_ports(form["ports"], limit=200)
            all_results = scan_tcp_ports(
                targets,
                ports,
                timeout=float(form["timeout"]),
                max_workers=int(form["concurrency"]),
            )
            stats = {
                "combinations": len(all_results),
                "open": sum(result["status"] == "open" for result in all_results),
                "closed": sum(result["status"] == "closed" for result in all_results),
                "timeout": sum(result["status"] == "timeout" for result in all_results),
                "error": sum(result["status"] == "error" for result in all_results),
            }
            results = (
                [result for result in all_results if result["status"] == "open"]
                if form["open_only"]
                else all_results
            )
        except (ToolInputError, TypeError, ValueError) as exc:
            error = str(exc) or "Enter valid scanner settings."
    return render_template(
        "tools/port_scanner.html",
        error=error,
        form=form,
        host_profiles=_port_scan_profile_store("hosts").all(),
        port_profiles=_port_scan_profile_store("ports").all(),
        results=results,
        stats=stats,
    )


@tools_bp.post("/port-scanner/profiles/<kind>")
def save_port_scan_profile(kind: str):
    if kind not in {"hosts", "ports"}:
        return jsonify({"error": "Unknown port scanner profile type."}), 404
    name = request.form.get("name", "").strip()
    original_name = request.form.get("original_name", "").strip()
    values = request.form.get("values", "").strip()
    if not name or len(name) > 100:
        return jsonify({"error": "Enter a profile name of 100 characters or fewer."}), 400
    try:
        if kind == "hosts":
            parsed = parse_ping_targets(values, limit=50)
            profile = {"name": name, "values": values, "count": len(parsed)}
        else:
            parsed = parse_tcp_ports(values, limit=200)
            profile = {"name": name, "values": values, "count": len(parsed)}
    except ToolInputError as exc:
        return jsonify({"error": str(exc)}), 400
    _port_scan_profile_store(kind).upsert(profile, original_name=original_name)
    return jsonify({"profile": profile})


@tools_bp.post("/port-scanner/profiles/<kind>/delete")
def delete_port_scan_profile(kind: str):
    if kind not in {"hosts", "ports"}:
        return jsonify({"error": "Unknown port scanner profile type."}), 404
    name = request.form.get("name", "").strip()
    if not _port_scan_profile_store(kind).delete(name):
        return jsonify({"error": "Profile not found."}), 404
    return jsonify({"deleted": name})


def _port_scan_profile_store(kind: str) -> PortScanProfileStore:
    return PortScanProfileStore(current_app.instance_path, kind)


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
            error = "Select between 1 and 10 valid OID / MIB profiles."
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
                    host_store.upsert({**host, "credential_name": name}, original_name=host["name"])
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


@tools_bp.route("/certificate-inspector", methods=["GET", "POST"])
def certificate_inspector():
    form = {"target": "", "port": "443", "timeout": "8"}
    result = None
    error = ""
    if request.method == "POST":
        form = {key: request.form.get(key, "").strip() for key in form}
        try:
            host, port = normalize_certificate_target(form["target"], form["port"])
            timeout = float(form["timeout"])
            result = inspect_certificate_chain(host, port, timeout)
            form["port"] = str(port)
        except (CertificateInspectionError, ValueError) as exc:
            error = str(exc)
    return render_template(
        "tools/certificate_inspector.html",
        error=error,
        form=form,
        result=result,
    )


@tools_bp.get("/speed-test")
def speed_test():
    return render_template("tools/speed_test.html")


@tools_bp.route("/speed-test/ping", methods=["GET", "HEAD"])
def speed_test_ping():
    response = Response(status=204)
    _disable_client_caching(response)
    return response


@tools_bp.get("/speed-test/download")
def speed_test_download():
    try:
        size = int(request.args.get("bytes", SPEED_TEST_DEFAULT_DOWNLOAD_SIZE))
    except ValueError:
        return jsonify({"error": "Download size must be a whole number of bytes."}), 400
    if not 1 <= size <= SPEED_TEST_MAX_DOWNLOAD_SIZE:
        return jsonify({"error": "Download size must be between 1 byte and 512 MiB."}), 400

    @stream_with_context
    def generate():
        remaining = size
        while remaining:
            length = min(remaining, SPEED_TEST_CHUNK_SIZE)
            yield SPEED_TEST_DOWNLOAD_CHUNK[:length]
            remaining -= length

    response = Response(generate(), mimetype="application/octet-stream")
    response.headers["Content-Length"] = str(size)
    response.headers["Content-Encoding"] = "identity"
    response.headers["X-Accel-Buffering"] = "no"
    _disable_client_caching(response)
    return response


@tools_bp.post("/speed-test/upload")
def speed_test_upload():
    content_length = request.content_length
    if content_length is None:
        return jsonify({"error": "Upload requests require a Content-Length header."}), 411
    if not 1 <= content_length <= SPEED_TEST_MAX_UPLOAD_SIZE:
        return jsonify({"error": "Upload size must be between 1 byte and 16 MiB."}), 413

    received = 0
    while True:
        chunk = request.stream.read(min(SPEED_TEST_CHUNK_SIZE, SPEED_TEST_MAX_UPLOAD_SIZE - received + 1))
        if not chunk:
            break
        received += len(chunk)
        if received > SPEED_TEST_MAX_UPLOAD_SIZE:
            return jsonify({"error": "Upload exceeds the 16 MiB limit."}), 413
    response = jsonify({"bytes_received": received})
    _disable_client_caching(response)
    return response


def _disable_client_caching(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"


@tools_bp.route("/subnet-excluder", methods=["GET", "POST"])
def subnet_excluder():
    supernets = ""
    exclusions = ""
    results: list[str] | None = None
    error = ""
    if request.method == "POST":
        supernets = request.form.get("supernets", "").strip()
        exclusions = request.form.get("exclusions", "").strip()
        try:
            results = subtract_subnets(supernets, exclusions)
        except ToolInputError as exc:
            error = str(exc)
    return render_template(
        "tools/subnet_excluder.html",
        error=error,
        exclusions=exclusions,
        results=results,
        supernets=supernets,
    )


@tools_bp.get("/ping")
def ping_tool():
    return render_template("tools/ping.html", profiles=_ping_profile_store().all())


@tools_bp.post("/ping/run")
def ping_run():
    payload = request.get_json(silent=True) or {}
    try:
        targets = parse_ping_targets(str(payload.get("hosts", "")), limit=100)
        results = ping_hosts([target["host"] for target in targets])
    except ToolInputError as exc:
        return jsonify({"error": str(exc)}), 400
    for target, result in zip(targets, results):
        result["label"] = target["label"]
    return jsonify({"results": results})


@tools_bp.post("/ping/profiles")
def save_ping_profile():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    original_name = str(payload.get("original_name", "")).strip()
    if not name:
        return jsonify({"error": "Enter a profile name."}), 400
    if len(name) > 100:
        return jsonify({"error": "Profile names must be 100 characters or fewer."}), 400
    try:
        targets = parse_ping_targets(str(payload.get("hosts", "")), limit=100)
        interval = int(payload.get("interval", 2))
        if not 1 <= interval <= 60:
            raise ToolInputError("Interval must be between 1 and 60 seconds.")
    except (ToolInputError, TypeError, ValueError) as exc:
        return jsonify({"error": str(exc) or "Enter a valid interval."}), 400

    profile = {"name": name, "targets": targets, "interval": interval}
    _ping_profile_store().upsert(profile, original_name=original_name)
    return jsonify({"profile": profile})


@tools_bp.post("/ping/profiles/delete")
def delete_ping_profile():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Select a profile to delete."}), 400
    if not _ping_profile_store().delete(name):
        return jsonify({"error": "Profile not found."}), 404
    return jsonify({"deleted": name})


def _ping_profile_store() -> PingProfileStore:
    return PingProfileStore(current_app.instance_path)


@tools_bp.route("/dns-response", methods=["GET", "POST"])
def dns_response():
    form = {
        "hosts": "",
        "servers": "",
        "host_profile": "",
        "server_profile": "",
        "record_type": "A",
        "timeout": "3",
    }
    results = None
    error = ""
    if request.method == "POST":
        form = {key: request.form.get(key, "").strip() for key in form}
        try:
            hosts = parse_dns_hosts(form["hosts"], limit=100)
            servers = parse_dns_servers(form["servers"], limit=20)
            results = dns_lookup_matrix(
                hosts, servers, form["record_type"], float(form["timeout"])
            )
        except (ToolInputError, TypeError, ValueError) as exc:
            error = str(exc) or "Enter a valid DNS timeout."
    return render_template(
        "tools/dns_response.html",
        error=error,
        form=form,
        host_profiles=_dns_profile_store("hosts").all(),
        server_profiles=_dns_profile_store("servers").all(),
        results=results,
    )


@tools_bp.post("/dns-response/profiles/<kind>")
def save_dns_profile(kind: str):
    if kind not in {"hosts", "servers"}:
        return jsonify({"error": "Unknown DNS profile type."}), 404
    name = request.form.get("profile_name", "").strip()
    values = request.form.get("values", "").strip()
    if not name:
        return jsonify({"error": "Enter a profile name."}), 400
    if len(name) > 100:
        return jsonify({"error": "Profile names must be 100 characters or fewer."}), 400
    try:
        parsed = parse_dns_hosts(values) if kind == "hosts" else parse_dns_servers(values)
    except ToolInputError as exc:
        return jsonify({"error": str(exc)}), 400
    profile = {"name": name, "values": parsed}
    _dns_profile_store(kind).upsert(profile)
    return jsonify({"profile": profile})


@tools_bp.post("/dns-response/profiles/<kind>/delete")
def delete_dns_profile(kind: str):
    if kind not in {"hosts", "servers"}:
        return jsonify({"error": "Unknown DNS profile type."}), 404
    name = request.form.get("name", "").strip()
    if not _dns_profile_store(kind).delete(name):
        return jsonify({"error": "Profile not found."}), 404
    return jsonify({"deleted": name})


def _dns_profile_store(kind: str) -> DNSProfileStore:
    return DNSProfileStore(current_app.instance_path, kind)


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
        else:
            try:
                results = radius_authenticate(
                    [server for server in servers if server],
                    credentials,
                    form["protocol"],
                    float(form["timeout"]),
                    int(form["retries"]),
                    parse_radius_attributes(attribute_profile["source"]) if attribute_profile else [],
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid timeout and attempt values."
    return render_template(
        "tools/radius_test.html",
        error=error,
        form=form,
        servers=server_store.all(),
        credentials=credential_store.all(),
        attribute_profiles=attribute_store.all(),
        results=results,
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
    return jsonify({"profile": {"name": name}})


@tools_bp.post("/radius-test/profiles/<kind>/delete")
def delete_radius_profile(kind: str):
    if kind not in {"servers", "credentials", "attributes"}:
        return jsonify({"error": "Unknown RADIUS profile type."}), 404
    name = request.form.get("name", "").strip()
    if not _radius_profile_store(kind).delete(name):
        return jsonify({"error": "Profile not found."}), 404
    return jsonify({"deleted": name})


def _radius_profile_store(kind: str) -> RadiusProfileStore:
    return RadiusProfileStore(current_app.instance_path, kind)


@tools_bp.route("/multi-ssh", methods=["GET", "POST"])
def multi_ssh():
    form = {
        "hosts": "",
        "username": "",
        "port": "22",
        "commands": "",
        "allow_unknown_hosts": False,
        "send_ctrl_y": False,
    }
    results: list[dict[str, object]] | None = None
    error = ""
    if request.method == "POST":
        form = {
            "hosts": request.form.get("hosts", "").strip(),
            "username": request.form.get("username", "").strip(),
            "port": request.form.get("port", "22").strip(),
            "commands": request.form.get("commands", "").strip(),
            "allow_unknown_hosts": request.form.get("allow_unknown_hosts") == "on",
            "send_ctrl_y": request.form.get("send_ctrl_y") == "on",
        }
        try:
            if request.form.get("confirm_execution") != "on":
                raise ToolInputError("Confirm that you intend to execute these commands.")
            hosts = validate_hosts(str(form["hosts"]), limit=50)
            commands = [command for command in str(form["commands"]).splitlines() if command.strip()]
            port = int(str(form["port"]))
            results = run_ssh_hosts(
                hosts=hosts,
                username=str(form["username"]),
                password=request.form.get("password", ""),
                commands=commands,
                port=port,
                allow_unknown_hosts=bool(form["allow_unknown_hosts"]),
                send_ctrl_y=bool(form["send_ctrl_y"]),
            )
        except (ToolInputError, ValueError) as exc:
            error = str(exc) if str(exc) else "Enter a valid SSH port."
    return render_template("tools/multi_ssh.html", error=error, form=form, results=results)

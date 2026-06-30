from __future__ import annotations

import os

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
    ping_hosts,
    run_ssh_hosts,
    radius_authenticate,
    split_values,
    subtract_subnets,
    validate_hosts,
)
from .profiles import DNSProfileStore, PingProfileStore, RadiusProfileStore


tools_bp = Blueprint("tools", __name__, url_prefix="/tools")
SPEED_TEST_CHUNK_SIZE = 256 * 1024
SPEED_TEST_DEFAULT_DOWNLOAD_SIZE = 512 * 1024 * 1024
SPEED_TEST_MAX_DOWNLOAD_SIZE = 512 * 1024 * 1024
SPEED_TEST_MAX_UPLOAD_SIZE = 16 * 1024 * 1024
SPEED_TEST_DOWNLOAD_CHUNK = os.urandom(SPEED_TEST_CHUNK_SIZE)


@tools_bp.get("/")
def index():
    return render_template("tools/index.html")


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

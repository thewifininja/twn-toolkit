from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    USM_AUTH_HMAC128_SHA224,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC256_SHA384,
    USM_AUTH_HMAC384_SHA512,
    USM_AUTH_HMAC96_MD5,
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_NONE,
    USM_PRIV_CBC56_DES,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    USM_PRIV_NONE,
    get_cmd,
    walk_cmd,
)

from .network_tools import ToolInputError


OID_PATTERN = re.compile(r"^\d+(?:\.\d+)+$")
AUTH_PROTOCOLS = {
    "none": USM_AUTH_NONE,
    "md5": USM_AUTH_HMAC96_MD5,
    "sha1": USM_AUTH_HMAC96_SHA,
    "sha224": USM_AUTH_HMAC128_SHA224,
    "sha256": USM_AUTH_HMAC192_SHA256,
    "sha384": USM_AUTH_HMAC256_SHA384,
    "sha512": USM_AUTH_HMAC384_SHA512,
}
PRIV_PROTOCOLS = {
    "none": USM_PRIV_NONE,
    "des": USM_PRIV_CBC56_DES,
    "aes128": USM_PRIV_CFB128_AES,
    "aes192": USM_PRIV_CFB192_AES,
    "aes256": USM_PRIV_CFB256_AES,
}


def parse_oid_profile(source: str, limit: int = 50) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            label, oid = (part.strip() for part in line.split("=", 1))
        else:
            label, oid = "", line
        operation = "get"
        if label.lower().startswith("walk:"):
            operation = "walk"
            label = label[5:].strip()
        if not label:
            label = oid
        if len(label) > 100:
            raise ToolInputError(f"Line {line_number}: labels must be 100 characters or fewer.")
        oid = oid.lstrip(".")
        if not OID_PATTERN.fullmatch(oid):
            raise ToolInputError(
                f"Line {line_number}: '{oid}' is not a numeric OID. Use dotted numbers only."
            )
        arcs = [int(part) for part in oid.split(".")]
        if arcs[0] > 2 or any(arc > 4_294_967_295 for arc in arcs):
            raise ToolInputError(f"Line {line_number}: '{oid}' is outside the valid OID range.")
        entries.append({"label": label, "oid": oid, "operation": operation})
    if not entries:
        raise ToolInputError("Enter at least one OID.")
    if len(entries) > limit:
        raise ToolInputError(f"A maximum of {limit} OIDs is allowed per profile.")
    return entries


def validate_snmp_credential(profile: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    name = str(profile.get("name", "")).strip()
    version = str(profile.get("version", "")).lower()
    if not name or len(name) > 100:
        raise ToolInputError("Enter a profile name of 100 characters or fewer.")
    if version == "v2c":
        community = str(profile.get("community", ""))
        if not community and existing:
            community = str(existing.get("community", ""))
        if not community:
            raise ToolInputError("Enter an SNMPv2c community.")
        return {"name": name, "version": version, "community": community}
    if version != "v3":
        raise ToolInputError("Select SNMPv2c or SNMPv3.")

    username = str(profile.get("username", "")).strip()
    security_level = str(profile.get("security_level", "")).lower()
    auth_protocol = str(profile.get("auth_protocol", "sha256")).lower()
    priv_protocol = str(profile.get("priv_protocol", "aes128")).lower()
    auth_key = str(profile.get("auth_key", ""))
    priv_key = str(profile.get("priv_key", ""))
    context_name = str(profile.get("context_name", "")).strip()
    if not username:
        raise ToolInputError("Enter an SNMPv3 username.")
    if security_level not in {"noauthnopriv", "authnopriv", "authpriv"}:
        raise ToolInputError("Select a valid SNMPv3 security level.")
    if auth_protocol not in AUTH_PROTOCOLS or auth_protocol == "none":
        raise ToolInputError("Select a supported SNMPv3 authentication protocol.")
    if priv_protocol not in PRIV_PROTOCOLS or priv_protocol == "none":
        raise ToolInputError("Select a supported SNMPv3 privacy protocol.")

    if not auth_key and existing:
        auth_key = str(existing.get("auth_key", ""))
    if not priv_key and existing:
        priv_key = str(existing.get("priv_key", ""))
    if security_level in {"authnopriv", "authpriv"} and len(auth_key) < 8:
        raise ToolInputError("SNMPv3 authentication passphrases must be at least 8 characters.")
    if security_level == "authpriv" and len(priv_key) < 8:
        raise ToolInputError("SNMPv3 privacy passphrases must be at least 8 characters.")
    return {
        "name": name,
        "version": version,
        "username": username,
        "security_level": security_level,
        "auth_protocol": auth_protocol,
        "auth_key": auth_key if security_level != "noauthnopriv" else "",
        "priv_protocol": priv_protocol,
        "priv_key": priv_key if security_level == "authpriv" else "",
        "context_name": context_name,
    }


def run_snmp_tests(
    hosts: list[dict[str, Any]],
    credentials_by_name: dict[str, dict[str, Any]],
    oid_profiles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return asyncio.run(_run_snmp_tests(hosts, credentials_by_name, oid_profiles))


async def _run_snmp_tests(
    hosts: list[dict[str, Any]],
    credentials_by_name: dict[str, dict[str, Any]],
    oid_profiles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    jobs = [
        _poll_host_profile(host, credentials_by_name[host["credential_name"]], oid_profile)
        for host in hosts
        for oid_profile in oid_profiles
    ]
    return list(await asyncio.gather(*jobs))


async def _poll_host_profile(
    host: dict[str, Any],
    credential: dict[str, Any],
    oid_profile: dict[str, Any],
) -> dict[str, Any]:
    engine = SnmpEngine()
    started = time.monotonic()
    rows: list[dict[str, Any]] = []
    error = ""
    try:
        auth = _authentication(credential)
        target = await UdpTransportTarget.create(
            (host["host"], int(host["port"])),
            timeout=float(host["timeout"]),
            retries=int(host["retries"]),
        )
        context = ContextData(contextName=credential.get("context_name", ""))
        for entry in oid_profile["entries"]:
            if entry["operation"] == "walk":
                entry_rows, entry_error = await _walk_entry(
                    engine, auth, target, context, entry
                )
            else:
                entry_rows, entry_error = await _get_entry(
                    engine, auth, target, context, entry
                )
            rows.extend(entry_rows)
            if entry_error:
                error = entry_error
                break
    except Exception as exc:
        error = str(exc) or type(exc).__name__
    finally:
        engine.close_dispatcher()
    return {
        "host_name": host["name"],
        "host": host["host"],
        "port": host["port"],
        "credential_name": credential["name"],
        "profile_name": oid_profile["name"],
        "status": "success" if not error else "error",
        "error": error,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "rows": rows,
    }


async def _get_entry(engine, auth, target, context, entry):
    started = time.monotonic()
    error_indication, error_status, error_index, var_binds = await get_cmd(
        engine,
        auth,
        target,
        context,
        ObjectType(ObjectIdentity(entry["oid"])),
        lookupMib=False,
    )
    error = _response_error(error_indication, error_status, error_index, var_binds)
    if error:
        return [], f"{entry['label']}: {error}"
    return [
        _format_var_bind(entry, var_bind, (time.monotonic() - started) * 1000)
        for var_bind in var_binds
    ], ""


async def _walk_entry(engine, auth, target, context, entry):
    started = time.monotonic()
    rows: list[dict[str, Any]] = []
    async for error_indication, error_status, error_index, var_binds in walk_cmd(
        engine,
        auth,
        target,
        context,
        ObjectType(ObjectIdentity(entry["oid"])),
        lookupMib=False,
        lexicographicMode=False,
        maxRows=100,
    ):
        error = _response_error(error_indication, error_status, error_index, var_binds)
        if error:
            return rows, f"{entry['label']}: {error}"
        rows.extend(
            _format_var_bind(entry, var_bind, (time.monotonic() - started) * 1000)
            for var_bind in var_binds
        )
    return rows, ""


def _authentication(profile: dict[str, Any]):
    if profile["version"] == "v2c":
        return CommunityData(profile["community"], mpModel=1)
    level = profile["security_level"]
    return UsmUserData(
        profile["username"],
        authKey=profile.get("auth_key") or None,
        privKey=profile.get("priv_key") or None,
        authProtocol=AUTH_PROTOCOLS[
            profile["auth_protocol"] if level != "noauthnopriv" else "none"
        ],
        privProtocol=PRIV_PROTOCOLS[
            profile["priv_protocol"] if level == "authpriv" else "none"
        ],
    )


def _response_error(error_indication, error_status, error_index, var_binds) -> str:
    if error_indication:
        return str(error_indication)
    if error_status:
        location = "?"
        if error_index and var_binds:
            index = int(error_index) - 1
            if 0 <= index < len(var_binds):
                location = var_binds[index][0].prettyPrint()
        return f"{error_status.prettyPrint()} at {location}"
    return ""


def _format_var_bind(entry, var_bind, elapsed_ms: float) -> dict[str, Any]:
    oid, value = var_bind
    return {
        "label": entry["label"],
        "operation": entry["operation"],
        "oid": oid.prettyPrint(),
        "value": value.prettyPrint(),
        "value_type": type(value).__name__,
        "response_ms": round(elapsed_ms, 1),
    }

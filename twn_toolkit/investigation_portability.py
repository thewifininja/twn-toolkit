from __future__ import annotations

import hashlib
import json
import math
import re
import stat
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable

from .datastore import MAX_UPLOAD_BYTES
from .investigations import EVENT_OUTCOMES, INVESTIGATION_STATES, MAX_EVENT_JSON_BYTES
from .version import APP_VERSION


PORTABLE_CASE_SCHEMA = "twn.portable-case.v1"
PORTABLE_CASE_FILENAME = "portable-case.json"
MAX_PORTABLE_JSON_BYTES = 64 * 1024 * 1024
MAX_PORTABLE_MEMBERS = 10_002
MAX_PORTABLE_EVENTS = 100_000
MAX_PORTABLE_ARTIFACTS = 10_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PortableCaseError(ValueError):
    pass


@dataclass
class PortableCaseArchive:
    stream: BinaryIO
    archive: zipfile.ZipFile
    payload: dict[str, Any]
    sha256: str

    def open_evidence(self, member_name: str) -> BinaryIO:
        return self.archive.open(member_name, "r")

    def close(self) -> None:
        self.archive.close()
        self.stream.close()

    def __enter__(self) -> PortableCaseArchive:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def build_portable_case_archive(
    *,
    store: Any,
    investigation: dict[str, Any],
    operators: list[dict[str, Any]],
    events: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    origin: dict[str, Any],
    generated_at: float | None = None,
) -> tuple[BinaryIO, dict[str, Any]]:
    """Build a complete, re-importable case archive independent of report curation."""
    timestamp = float(generated_at if generated_at is not None else time.time())
    archive = tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024, mode="w+b")
    evidence_records: list[dict[str, Any]] = []
    used_members: set[str] = set()
    try:
        with zipfile.ZipFile(
            archive,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            allowZip64=True,
        ) as bundle:
            for artifact in artifacts:
                source = store.datastore.file(str(artifact["relative_path"]))
                member = _portable_evidence_member(artifact, used_members)
                digest = hashlib.sha256()
                byte_count = 0
                with source.open("rb") as input_stream, bundle.open(
                    member, "w"
                ) as output_stream:
                    for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                        byte_count += len(chunk)
                        output_stream.write(chunk)
                actual_digest = digest.hexdigest()
                if (
                    byte_count != int(artifact["byte_count"])
                    or actual_digest != str(artifact["sha256"])
                ):
                    raise PortableCaseError(
                        f"Evidence file {artifact['display_name']} has changed since upload."
                    )
                evidence_records.append(
                    {
                        "origin_case_id": str(
                            artifact.get("origin_case_id")
                            or origin.get("local_case_id")
                            or origin["case_id"]
                        ),
                        "origin_id": str(
                            artifact.get("origin_artifact_id") or artifact["id"]
                        ),
                        "event_origin_case_id": (
                            artifact.get("event_origin_case_id")
                            or origin.get("local_case_id")
                            or origin["case_id"]
                            if artifact.get("event_id")
                            else None
                        ),
                        "event_origin_id": (
                            artifact.get("event_origin_id")
                            or artifact.get("event_id")
                        ),
                        "kind": str(artifact["kind"]),
                        "display_name": str(artifact["display_name"]),
                        "member": member,
                        "content_type": str(artifact["content_type"]),
                        "byte_count": byte_count,
                        "sha256": actual_digest,
                        "report_placement": str(artifact["report_placement"]),
                        "created_by_user_id": str(artifact["created_by_user_id"]),
                        "created_by_username": str(
                            artifact["created_by_username"]
                        ),
                        "created_at": float(artifact["created_at"]),
                    }
                )
            payload = {
                "schema": PORTABLE_CASE_SCHEMA,
                "toolkit_version": APP_VERSION,
                "generated_at": timestamp,
                "case": {
                    "origin_id": str(origin["case_id"]),
                    "exported_local_id": str(investigation["id"]),
                    "title": str(investigation["title"]),
                    "description": str(investigation["description"]),
                    "source_state": str(investigation["state"]),
                    "source_owner_username": str(origin["owner_username"]),
                    "operators": [
                        {
                            "user_id": str(item["user_id"]),
                            "username": str(item["username"]),
                            "role": str(item["role"]),
                        }
                        for item in operators
                    ],
                    "created_at": float(investigation["created_at"]),
                    "started_at": float(investigation["started_at"]),
                    "ended_at": (
                        float(investigation["ended_at"])
                        if investigation.get("ended_at") is not None
                        else None
                    ),
                    "updated_at": float(investigation["updated_at"]),
                },
                "events": [_portable_event(event, origin) for event in events],
                "artifacts": evidence_records,
            }
            encoded = (
                json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2)
                + "\n"
            ).encode("utf-8")
            if len(encoded) > MAX_PORTABLE_JSON_BYTES:
                raise PortableCaseError("The portable case record is too large.")
            bundle.writestr(PORTABLE_CASE_FILENAME, encoded)
        archive.seek(0)
        return archive, payload
    except BaseException:
        archive.close()
        raise


def load_portable_case_archive(stream: BinaryIO) -> PortableCaseArchive:
    """Copy and fully validate an untrusted portable-case upload."""
    # Python 3.10's SpooledTemporaryFile does not expose the complete seekable
    # file API expected by zipfile. Always cross the untrusted upload boundary
    # into a real temporary file so archive validation behaves identically on
    # every supported Python version without retaining large cases in memory.
    copied = tempfile.TemporaryFile(mode="w+b")
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                raise PortableCaseError("Portable case archives may not exceed 1 GiB.")
            copied.write(chunk)
            digest.update(chunk)
        if not total:
            raise PortableCaseError("The portable case archive is empty.")
        copied.seek(0)
        try:
            archive = zipfile.ZipFile(copied, "r")
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise PortableCaseError("Choose a valid TWN portable case archive.") from exc
        try:
            payload = _validate_archive(archive)
        except zipfile.BadZipFile as exc:
            archive.close()
            raise PortableCaseError(
                "The portable case archive is damaged or incomplete."
            ) from exc
        except BaseException:
            archive.close()
            raise
        copied.seek(0)
        return PortableCaseArchive(copied, archive, payload, digest.hexdigest())
    except BaseException:
        copied.close()
        raise


def portable_case_filename(investigation: dict[str, Any]) -> str:
    title = re.sub(
        r"[^A-Za-z0-9._-]+", "-", str(investigation.get("title", "")).strip()
    ).strip("-._")[:80]
    return f"{title or 'case'}-{investigation['id']}.twncase"


def _portable_event(
    event: dict[str, Any], origin: dict[str, Any]
) -> dict[str, Any]:
    return {
        "origin_case_id": str(
            event.get("origin_case_id")
            or origin.get("local_case_id")
            or origin["case_id"]
        ),
        "origin_id": str(event.get("origin_event_id") or event["id"]),
        "operation_id": str(event["operation_id"]),
        "event_type": str(event["event_type"]),
        "tool_id": str(event["tool_id"]),
        "action": str(event["action"]),
        "outcome": str(event["outcome"]),
        "summary": str(event["summary"]),
        "targets": event["targets"],
        "parameters": event["parameters"],
        "metrics": event["metrics"],
        "details": event["details"],
        "report_placement": str(event["report_placement"]),
        "important": bool(event["important"]),
        "started_at": float(event["started_at"]),
        "completed_at": float(event["completed_at"]),
        "created_by_user_id": str(event["created_by_user_id"]),
        "created_by_username": str(event["created_by_username"]),
        "created_at": float(event["created_at"]),
    }


def _portable_evidence_member(
    artifact: dict[str, Any], used: set[str]
) -> str:
    name = Path(str(artifact.get("display_name") or "evidence.bin")).name
    clean = "".join(
        character if character.isalnum() or character in " ._-" else "_"
        for character in name
    ).strip(" .")[:180] or "evidence.bin"
    origin = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        str(artifact.get("origin_artifact_id") or artifact.get("id", "artifact")),
    )[:80]
    candidate = f"evidence/{origin}/{clean}"
    suffix = 2
    while candidate.casefold() in used:
        path = Path(clean)
        candidate = f"evidence/{origin}/{path.stem[:150]}-{suffix}{path.suffix[:20]}"
        suffix += 1
    used.add(candidate.casefold())
    return candidate


def _validate_archive(archive: zipfile.ZipFile) -> dict[str, Any]:
    infos = archive.infolist()
    if len(infos) > MAX_PORTABLE_MEMBERS:
        raise PortableCaseError("The portable case archive contains too many files.")
    names: set[str] = set()
    uncompressed = 0
    for info in infos:
        name = _member_name(info.filename)
        if name in names:
            raise PortableCaseError("The portable case archive contains duplicate files.")
        names.add(name)
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise PortableCaseError("Portable case archives cannot contain symbolic links.")
        if info.flag_bits & 0x1:
            raise PortableCaseError("Encrypted portable case archives are not supported.")
        if info.is_dir():
            continue
        uncompressed += int(info.file_size)
        if info.file_size > MAX_UPLOAD_BYTES or uncompressed > MAX_UPLOAD_BYTES:
            raise PortableCaseError(
                "The portable case archive expands beyond the 1 GiB limit."
            )
    if PORTABLE_CASE_FILENAME not in names:
        raise PortableCaseError("The archive is missing portable-case.json.")
    info = archive.getinfo(PORTABLE_CASE_FILENAME)
    if info.file_size > MAX_PORTABLE_JSON_BYTES:
        raise PortableCaseError("The portable case record is too large.")
    try:
        payload = json.loads(archive.read(info).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PortableCaseError("The portable case record is not valid JSON.") from exc
    normalized = _validate_payload(payload)
    expected = {
        PORTABLE_CASE_FILENAME,
        *(str(item["member"]) for item in normalized["artifacts"]),
    }
    files = {info.filename for info in infos if not info.is_dir()}
    if files != expected:
        raise PortableCaseError(
            "The archive contains missing or unreferenced portable case files."
        )
    for artifact in normalized["artifacts"]:
        digest = hashlib.sha256()
        byte_count = 0
        with archive.open(str(artifact["member"]), "r") as evidence:
            for chunk in iter(lambda: evidence.read(1024 * 1024), b""):
                byte_count += len(chunk)
                digest.update(chunk)
        if (
            byte_count != artifact["byte_count"]
            or digest.hexdigest() != artifact["sha256"]
        ):
            raise PortableCaseError(
                f"Evidence file {artifact['display_name']} failed verification."
            )
    return normalized


def _validate_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") != PORTABLE_CASE_SCHEMA:
        raise PortableCaseError("This portable case schema is not supported.")
    case = _mapping(payload.get("case"), "case")
    normalized_case = {
        "origin_id": _text(case.get("origin_id"), "Case origin", 200, True),
        "exported_local_id": _text(
            case.get("exported_local_id"), "Exported case ID", 200, True
        ),
        "title": _text(case.get("title"), "Case title", 120, True),
        "description": _text(case.get("description"), "Case description", 2_000),
        "source_state": _choice(
            case.get("source_state"), "Case state", INVESTIGATION_STATES
        ),
        "source_owner_username": _text(
            case.get("source_owner_username"), "Source owner", 200, True
        ),
        "operators": _operators(case.get("operators")),
        "created_at": _timestamp(case.get("created_at"), "Case creation time"),
        "started_at": _timestamp(case.get("started_at"), "Case start time"),
        "ended_at": (
            _timestamp(case.get("ended_at"), "Case end time")
            if case.get("ended_at") is not None
            else None
        ),
        "updated_at": _timestamp(case.get("updated_at"), "Case update time"),
    }
    operator_names = {
        item["user_id"]: item["username"] for item in normalized_case["operators"]
    }
    source_owner = next(
        item for item in normalized_case["operators"] if item["role"] == "owner"
    )
    if source_owner["username"] != normalized_case["source_owner_username"]:
        raise PortableCaseError("The portable case source owner is inconsistent.")
    events_raw = payload.get("events")
    artifacts_raw = payload.get("artifacts")
    if not isinstance(events_raw, list) or len(events_raw) > MAX_PORTABLE_EVENTS:
        raise PortableCaseError("The portable case contains an invalid event list.")
    if not isinstance(artifacts_raw, list) or len(artifacts_raw) > MAX_PORTABLE_ARTIFACTS:
        raise PortableCaseError("The portable case contains an invalid artifact list.")
    events = [_event(item) for item in events_raw]
    _validate_operator_attribution(events, operator_names, "journal event")
    event_keys = [(item["origin_case_id"], item["origin_id"]) for item in events]
    if len(event_keys) != len(set(event_keys)):
        raise PortableCaseError("The portable case contains duplicate journal events.")
    operation_ids = [item["operation_id"] for item in events]
    if len(operation_ids) != len(set(operation_ids)):
        raise PortableCaseError("The portable case contains duplicate operation IDs.")
    event_key_set = set(event_keys)
    artifacts = [_artifact(item, event_key_set) for item in artifacts_raw]
    _validate_operator_attribution(artifacts, operator_names, "evidence record")
    artifact_keys = [
        (item["origin_case_id"], item["origin_id"]) for item in artifacts
    ]
    if len(artifact_keys) != len(set(artifact_keys)):
        raise PortableCaseError("The portable case contains duplicate evidence records.")
    artifact_members = [item["member"] for item in artifacts]
    if len(artifact_members) != len(set(artifact_members)):
        raise PortableCaseError("The portable case reuses an evidence archive path.")
    return {
        "schema": PORTABLE_CASE_SCHEMA,
        "toolkit_version": _text(payload.get("toolkit_version"), "Toolkit version", 80),
        "generated_at": _timestamp(payload.get("generated_at"), "Export time"),
        "case": normalized_case,
        "events": events,
        "artifacts": artifacts,
    }


def _event(value: Any) -> dict[str, Any]:
    item = _mapping(value, "journal event")
    started_at = _timestamp(item.get("started_at"), "Event start time")
    completed_at = _timestamp(item.get("completed_at"), "Event completion time")
    if completed_at < started_at:
        raise PortableCaseError("A journal event completes before it starts.")
    result = {
        "origin_case_id": _text(
            item.get("origin_case_id"), "Event origin case", 200, True
        ),
        "origin_id": _text(item.get("origin_id"), "Event origin", 200, True),
        "operation_id": _text(item.get("operation_id"), "Operation ID", 200, True),
        "event_type": _text(item.get("event_type"), "Event type", 120, True),
        "tool_id": _text(item.get("tool_id"), "Tool ID", 160, True),
        "action": _text(item.get("action"), "Action", 160, True),
        "outcome": _choice(item.get("outcome"), "Event outcome", EVENT_OUTCOMES),
        "summary": _text(item.get("summary"), "Summary", 4_000, True),
        "targets": _json_value(item.get("targets"), "Targets"),
        "parameters": _json_value(item.get("parameters"), "Parameters"),
        "metrics": _json_value(item.get("metrics"), "Metrics"),
        "details": _json_value(item.get("details"), "Details"),
        "report_placement": _choice(
            item.get("report_placement"),
            "Event report placement",
            frozenset({"main", "appendix", "excluded"}),
        ),
        "important": _boolean(item.get("important"), "Important event flag"),
        "started_at": started_at,
        "completed_at": completed_at,
        "created_by_user_id": _text(
            item.get("created_by_user_id"), "Event user", 200, True
        ),
        "created_by_username": _text(
            item.get("created_by_username"), "Event operator", 200, True
        ),
        "created_at": _timestamp(item.get("created_at"), "Event creation time"),
    }
    return result


def _artifact(
    value: Any, event_keys: set[tuple[str, str]]
) -> dict[str, Any]:
    item = _mapping(value, "evidence record")
    event_origin_case_id = item.get("event_origin_case_id")
    event_origin_id = item.get("event_origin_id")
    if (event_origin_case_id is None) != (event_origin_id is None):
        raise PortableCaseError("An evidence event reference is incomplete.")
    if event_origin_id is not None:
        event_origin_case_id = _text(
            event_origin_case_id, "Evidence event origin case", 200, True
        )
        event_origin_id = _text(event_origin_id, "Evidence event origin", 200, True)
        if (event_origin_case_id, event_origin_id) not in event_keys:
            raise PortableCaseError("An evidence file references an unknown event.")
    member = _member_name(_text(item.get("member"), "Evidence member", 500, True))
    if not member.startswith("evidence/"):
        raise PortableCaseError("Evidence files must be stored beneath evidence/.")
    sha256 = _text(item.get("sha256"), "Evidence SHA-256", 64, True).lower()
    if not _SHA256.fullmatch(sha256):
        raise PortableCaseError("An evidence SHA-256 value is invalid.")
    byte_count = item.get("byte_count")
    if (
        isinstance(byte_count, bool)
        or not isinstance(byte_count, int)
        or not 0 <= byte_count <= MAX_UPLOAD_BYTES
    ):
        raise PortableCaseError("An evidence byte count is invalid.")
    return {
        "origin_case_id": _text(
            item.get("origin_case_id"), "Evidence origin case", 200, True
        ),
        "origin_id": _text(item.get("origin_id"), "Evidence origin", 200, True),
        "event_origin_case_id": event_origin_case_id,
        "event_origin_id": event_origin_id,
        "kind": _text(item.get("kind"), "Evidence kind", 120, True),
        "display_name": _filename(item.get("display_name")),
        "member": member,
        "content_type": _text(item.get("content_type"), "Content type", 160),
        "byte_count": byte_count,
        "sha256": sha256,
        "report_placement": _choice(
            item.get("report_placement"),
            "Evidence report placement",
            frozenset({"main", "appendix", "excluded"}),
        ),
        "created_by_user_id": _text(
            item.get("created_by_user_id"), "Evidence user", 200, True
        ),
        "created_by_username": _text(
            item.get("created_by_username"), "Evidence operator", 200, True
        ),
        "created_at": _timestamp(item.get("created_at"), "Evidence creation time"),
    }


def _operators(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 1_000:
        raise PortableCaseError("The portable case operator list is invalid.")
    result = []
    for raw in value:
        item = _mapping(raw, "operator")
        result.append(
            {
                "user_id": _text(item.get("user_id"), "Operator user ID", 200, True),
                "username": _text(item.get("username"), "Operator username", 200, True),
                "role": _choice(
                    item.get("role"),
                    "Operator role",
                    frozenset({"owner", "collaborator"}),
                ),
            }
        )
    user_ids = [item["user_id"] for item in result]
    if len(user_ids) != len(set(user_ids)):
        raise PortableCaseError("The portable case operator list contains duplicates.")
    if sum(item["role"] == "owner" for item in result) != 1:
        raise PortableCaseError("The portable case must identify one source owner.")
    return result


def _validate_operator_attribution(
    records: list[dict[str, Any]],
    operator_names: dict[str, str],
    label: str,
) -> None:
    for item in records:
        if operator_names.get(item["created_by_user_id"]) != item["created_by_username"]:
            raise PortableCaseError(
                f"A portable {label} has inconsistent operator attribution."
            )


def _member_name(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise PortableCaseError("The archive contains an invalid file path.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PortableCaseError("The archive contains an unsafe file path.")
    return path.as_posix()


def _filename(value: Any) -> str:
    result = _text(value, "Evidence filename", 240, True)
    if (
        Path(result).name != result
        or "/" in result
        or "\\" in result
        or result in {".", ".."}
        or "\x00" in result
    ):
        raise PortableCaseError("An evidence filename is invalid.")
    return result


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PortableCaseError(f"The portable {label} is invalid.")
    return value


def _text(value: Any, label: str, limit: int, required: bool = False) -> str:
    if not isinstance(value, str):
        raise PortableCaseError(f"{label} is invalid.")
    cleaned = value.strip()
    if required and not cleaned:
        raise PortableCaseError(f"{label} is required.")
    if len(cleaned) > limit or "\x00" in cleaned:
        raise PortableCaseError(f"{label} is too long or invalid.")
    return cleaned


def _choice(value: Any, label: str, choices: frozenset[str]) -> str:
    result = _text(value, label, 120, True)
    if result not in choices:
        raise PortableCaseError(f"{label} is not supported.")
    return result


def _timestamp(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PortableCaseError(f"{label} is invalid.")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise PortableCaseError(f"{label} is invalid.")
    return result


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise PortableCaseError(f"{label} is invalid.")
    return value


def _json_value(value: Any, label: str) -> Any:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PortableCaseError(f"{label} is not valid JSON.") from exc
    if len(encoded) > MAX_EVENT_JSON_BYTES:
        raise PortableCaseError(f"{label} exceeds the retained JSON limit.")
    return value

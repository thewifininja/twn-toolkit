from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
from pathlib import Path
from typing import Any


JOB_ID_PATTERN = re.compile(r"^[a-f0-9]{24}$")
HOOK_TIMEOUT_SECONDS = 6 * 60 * 60


def run_hook(mode: str, job_path_value: str) -> int:
    job_path = Path(job_path_value).resolve()
    if not JOB_ID_PATTERN.fullmatch(job_path.name):
        return 2
    if mode == "cleanup":
        return 0
    if mode != "auth":
        return 2

    # The parent records its PID immediately after spawning Certbot. Waiting for
    # that marker prevents the hook and parent from racing to update status.json.
    for _ in range(200):
        if (job_path / "process.pid").exists():
            break
        time.sleep(0.05)
    else:
        return 2

    identifier = os.environ.get(
        "CERTBOT_IDENTIFIER", os.environ.get("CERTBOT_DOMAIN", "")
    )
    validation = os.environ.get("CERTBOT_VALIDATION", "")
    record_name = _txt_record(identifier)
    if not record_name or not validation:
        return 2
    challenge_id = secrets.token_hex(8)
    challenge = {
        "id": challenge_id,
        "identifier": identifier,
        "record_name": record_name,
        "record_value": validation,
        "remaining": int(os.environ.get("CERTBOT_REMAINING_CHALLENGES", "0") or 0),
        "created_at": time.time(),
    }
    _write_json(job_path / "challenge.json", challenge)
    _write_json(job_path / "challenges" / f"{challenge_id}.json", challenge)
    _merge_status(
        job_path,
        status="awaiting_dns",
        message=(
            f"Create the TXT record for {identifier}, wait for propagation, "
            "then continue this request."
        ),
    )
    deadline = time.monotonic() + HOOK_TIMEOUT_SECONDS
    continue_path = job_path / f"continue-{challenge_id}"
    cancel_path = job_path / "cancel"
    while time.monotonic() < deadline:
        if cancel_path.exists():
            return 1
        if continue_path.exists():
            try:
                continue_path.unlink()
            except FileNotFoundError:
                pass
            _merge_status(
                job_path,
                status="validating",
                message=(
                    "Certbot is validating DNS. Keep all challenge values published "
                    "until the certificate is issued."
                ),
            )
            return 0
        time.sleep(0.5)
    _merge_status(
        job_path,
        status="failed",
        message="The DNS challenge expired after waiting six hours.",
    )
    return 1


def _txt_record(identifier: str) -> str:
    domain = identifier.strip().rstrip(".").lower()
    if domain.startswith("*."):
        domain = domain[2:]
    if (
        not domain
        or "/" in domain
        or "\\" in domain
        or "\x00" in domain
        or any(character.isspace() for character in domain)
    ):
        return ""
    return f"_acme-challenge.{domain}"


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


def _merge_status(job_path: Path, **updates: Any) -> None:
    status_path = job_path / "status.json"
    status = _read_json(status_path)
    status.update(updates)
    status["updated_at"] = time.time()
    _write_json(status_path, status)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(2)
    raise SystemExit(run_hook(sys.argv[1], sys.argv[2]))

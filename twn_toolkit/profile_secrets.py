"""Instance-bound protection for saved appliance profile secret fields."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

FORMAT = "twn-profile-secret-v1"


def _cipher(instance: Path, *, create: bool) -> Fernet:
    if create:
        from .auth import load_or_create_secret_key
        secret = load_or_create_secret_key(str(instance))
    else:
        secret = os.environ.get("TWN_TOOLKIT_SECRET_KEY")
        if not secret:
            try:
                secret = (instance / "session_secret").read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ValueError("Saved profile secrets require the original instance key.") from exc
    if not secret:
        raise ValueError("Saved profile secrets require a nonempty instance key.")
    key = hashlib.sha256(("twn-profile-secrets-v1:" + secret).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def transform_profiles(profiles, instance, filename, fields, *, encrypt):
    transformed = []
    cipher = None
    for profile in profiles:
        result = dict(profile)
        for field in fields:
            value = profile.get(field)
            if value is None or value == "":
                continue
            context = [filename, profile["name"], field]
            if encrypt:
                if not isinstance(value, str):
                    raise ValueError("Profile secrets must be text before saving.")
                if cipher is None:
                    cipher = _cipher(instance, create=True)
                payload = json.dumps([context, value], separators=(",", ":")).encode()
                result[field] = {"format": FORMAT, "token": cipher.encrypt(payload).decode("ascii")}
            elif isinstance(value, str):
                # Legacy plaintext remains readable; writes protect all rows.
                continue
            else:
                try:
                    if not isinstance(value, dict) or value.get("format") != FORMAT or not isinstance(value.get("token"), str):
                        raise ValueError()
                    if cipher is None:
                        cipher = _cipher(instance, create=False)
                    payload = json.loads(cipher.decrypt(value["token"].encode("ascii")))
                    if not isinstance(payload, list) or len(payload) != 2 or payload[0] != context or not isinstance(payload[1], str):
                        raise ValueError()
                    result[field] = payload[1]
                except (InvalidToken, ValueError, TypeError, UnicodeError) as exc:
                    raise ValueError("Saved profile secret could not be decrypted; restore the original instance key and profile file.") from exc
        transformed.append(result)
    return transformed


def main():
    import argparse
    from .profiles import ProfileStore, FortiAuthenticatorProfileStore, RadiusProfileStore, SNMPCredentialProfileStore

    parser = argparse.ArgumentParser(description="Protect existing appliance, RADIUS and SNMP profile secrets. Stop toolkit writers first; preserve the instance key.")
    parser.add_argument("--instance", required=True)
    args = parser.parse_args()
    stores = (
        ProfileStore(args.instance), FortiAuthenticatorProfileStore(args.instance),
        RadiusProfileStore(args.instance, "servers"), RadiusProfileStore(args.instance, "credentials"),
        SNMPCredentialProfileStore(args.instance),
    )
    for store in stores:
        if store.protect_existing():
            print(f"Protected {store.path.name}.")
        else:
            print(f"No existing {store.path.name}.")


if __name__ == "__main__":
    main()

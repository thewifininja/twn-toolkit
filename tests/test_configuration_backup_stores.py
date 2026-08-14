from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from twn_toolkit.auth import AuthStore, load_or_create_secret_key
from twn_toolkit.automation import AutomationBackupStore, AutomationStore
from twn_toolkit.certificate_automation import (
    CertificateAutomationStore,
    EnrollmentResult,
)
from twn_toolkit.profile_backup import (
    build_backup_catalog,
    import_backup_items,
    selected_backup_items,
)
from twn_toolkit.remote_connections import RemoteConnectionStore
from twn_toolkit.smtp_tools import SMTPSettingsStore
from twn_toolkit.time_settings import TimeSettingsStore


class ConfigurationBackupStoreTests(unittest.TestCase):
    @staticmethod
    def _automation_definition(interval_seconds: int) -> dict:
        return {
            "name": "Branch watch",
            "interval_seconds": interval_seconds,
            "trigger_after": 2,
            "recover_after": 2,
            "cooldown_seconds": 60,
            "condition": {
                "type": "ping.multi",
                "config": {
                    "targets": "127.0.0.1",
                    "timeout": 1,
                    "failure_mode": "all",
                    "failure_count": 1,
                },
            },
            "actions": [
                {
                    "type": "ssh.collect",
                    "config": {
                        "hosts": "192.0.2.1",
                        "username": "admin",
                        "password": "secret",
                        "commands": "show clock",
                        "port": 22,
                    },
                }
            ],
        }

    def test_automation_combine_preserves_local_identity_and_runtime_history(self) -> None:
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as destination:
            source_store = AutomationStore(
                source, load_or_create_secret_key(source)
            )
            AutomationBackupStore(source_store).replace_all(
                [self._automation_definition(15)]
            )
            exported = AutomationBackupStore(source_store).all()

            destination_store = AutomationStore(
                destination, load_or_create_secret_key(destination)
            )
            AutomationBackupStore(destination_store).replace_all(
                [self._automation_definition(60)]
            )
            original = destination_store.all()[0]
            with destination_store._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO automation_runs
                        (id, automation_id, started_at, finished_at, status,
                         trigger_summary, results_json)
                    VALUES ('retained-run', ?, 1, 2, 'success', 'Retain me', '{}')
                    """,
                    (original["id"],),
                )

            selected = selected_backup_items(
                build_backup_catalog(destination), {"automation_definitions"}
            )
            imported = import_backup_items(
                {"automation_definitions": exported}, selected, "merge"
            )
            restored = destination_store.all()[0]
            with destination_store._connect() as connection:
                retained_runs = connection.execute(
                    "SELECT COUNT(*) FROM automation_runs WHERE id = 'retained-run'"
                ).fetchone()[0]

            self.assertEqual(imported, [("Automation definitions", 3)])
            self.assertEqual(restored["id"], original["id"])
            self.assertEqual(restored["interval_seconds"], 15)
            self.assertFalse(restored["enabled"])
            self.assertEqual(retained_runs, 1)

    def test_remote_terminal_library_maps_owner_and_reencrypts_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as destination:
            source_auth = AuthStore(source)
            source_user = source_auth.create_user(
                "operator", "correct horse battery staple", is_admin=True
            )
            source_remote = RemoteConnectionStore(
                source, load_or_create_secret_key(source)
            )
            folder = source_remote.create_folder(
                user_id=source_user["id"], name="Branches"
            )
            credential = source_remote.save_credential(
                user_id=source_user["id"],
                name="Network admin",
                remote_username="netadmin",
                password="source-only-secret",
            )
            source_remote.save_host(
                user_id=source_user["id"],
                name="Branch router",
                host="192.0.2.10",
                port=23,
                protocol="telnet",
                folder_id=folder["id"],
                credential_id=credential["id"],
                allow_unknown_hosts=True,
                allow_legacy_algorithms=True,
            )
            source_remote.save_host(
                user_id=source_user["id"],
                name="Manual login switch",
                host="192.0.2.11",
                port=23,
                protocol="telnet",
                folder_id=folder["id"],
                credential_id="",
                allow_unknown_hosts=False,
                allow_legacy_algorithms=False,
            )

            source_item = selected_backup_items(
                build_backup_catalog(source), {"remote_connection_library"}
            )
            exported = source_item[0]["store"].all()
            self.assertEqual(exported[0]["credentials"][0]["password"], "source-only-secret")

            destination_auth = AuthStore(destination)
            destination_user = destination_auth.create_user(
                "operator", "different correct password", is_admin=True
            )
            destination_item = selected_backup_items(
                build_backup_catalog(destination), {"remote_connection_library"}
            )
            imported = import_backup_items(
                {"remote_connection_library": exported}, destination_item, "replace"
            )
            destination_remote = RemoteConnectionStore(
                destination, load_or_create_secret_key(destination)
            )
            library = destination_remote.library_for_user(destination_user["id"])
            credential_host = next(
                host for host in library["hosts"] if host["credential_id"]
            )
            manual_host = next(
                host for host in library["hosts"] if not host["credential_id"]
            )
            resolved = destination_remote.resolve_credential(
                library["credentials"][0]["id"],
                user_id=destination_user["id"],
                host_id=credential_host["id"],
            )

            self.assertEqual(imported, [("Remote Terminal libraries", 1)])
            self.assertEqual(resolved["password"], "source-only-secret")
            self.assertEqual(credential_host["protocol"], "telnet")
            self.assertEqual(credential_host["port"], 23)
            self.assertFalse(credential_host["allow_unknown_hosts"])
            self.assertFalse(credential_host["allow_legacy_algorithms"])
            self.assertEqual(manual_host["name"], "Manual login switch")
            self.assertEqual(manual_host["credential_id"], "")
            self.assertNotIn(
                b"source-only-secret",
                Path(destination, "remote_connections.sqlite3").read_bytes(),
            )

    def test_access_smtp_and_timezone_settings_round_trip_without_users(self) -> None:
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as destination:
            source_auth = AuthStore(source)
            source_auth.create_user("source-admin", "correct horse battery staple", is_admin=True)
            source_auth.save_access_profile(
                name="Help desk",
                description="Diagnostic access",
                tool_ids=["tools.ping"],
            )
            TimeSettingsStore(source).save("America/Chicago")
            SMTPSettingsStore(source, load_or_create_secret_key(source)).save(
                {
                    "host": "smtp.example.test",
                    "port": 587,
                    "security": "starttls",
                    "verify_tls": True,
                    "username": "mailer",
                    "from_name": "Toolkit",
                    "from_address": "toolkit@example.test",
                    "timeout": 10,
                },
                password="mail-secret",
            )
            group_ids = {"access_profiles", "smtp_settings", "time_settings"}
            exported = {
                item["id"]: item["store"].all()
                for item in selected_backup_items(build_backup_catalog(source), group_ids)
            }

            destination_auth = AuthStore(destination)
            destination_auth.create_user(
                "destination-admin", "another correct password", is_admin=True
            )
            destination_items = selected_backup_items(
                build_backup_catalog(destination), group_ids
            )
            import_backup_items(exported, destination_items, "replace")

            self.assertEqual(
                [profile["name"] for profile in destination_auth.access_profiles()],
                ["Help desk"],
            )
            self.assertEqual(
                [user["username"] for user in destination_auth.users()],
                ["destination-admin"],
            )
            self.assertEqual(
                TimeSettingsStore(destination).get()["timezone"], "America/Chicago"
            )
            smtp = SMTPSettingsStore(
                destination, load_or_create_secret_key(destination)
            ).get(include_password=True)
            self.assertEqual(smtp["host"], "smtp.example.test")
            self.assertEqual(smtp["password"], "mail-secret")
            self.assertNotIn(
                b"mail-secret", Path(destination, "smtp_settings.json").read_bytes()
            )

    def test_access_profile_combine_uses_portable_records_not_rollback_state(self) -> None:
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as destination:
            source_auth = AuthStore(source)
            source_auth.create_user(
                "source-admin", "correct horse battery staple", is_admin=True
            )
            source_auth.save_access_profile(
                name="Help desk",
                description="Imported diagnostics",
                tool_ids=["tools.ping"],
            )
            exported = selected_backup_items(
                build_backup_catalog(source), {"access_profiles"}
            )[0]["store"].all()

            destination_auth = AuthStore(destination)
            destination_auth.create_user(
                "destination-admin", "another correct password", is_admin=True
            )
            retained = destination_auth.save_access_profile(
                name="Local operations",
                description="Must remain local",
                tool_ids=["tools.dns_response"],
            )
            destination_auth.create_user(
                "operator",
                "operator correct password",
                access_profile_ids=[retained["id"]],
            )

            imported = import_backup_items(
                {"access_profiles": exported},
                selected_backup_items(
                    build_backup_catalog(destination), {"access_profiles"}
                ),
                "merge",
            )

            self.assertEqual(imported, [("Access profiles", 2)])
            self.assertEqual(
                [profile["name"] for profile in destination_auth.access_profiles()],
                ["Help desk", "Local operations"],
            )
            operator = destination_auth.get_user("operator")
            self.assertEqual(operator["access_profile_ids"], [retained["id"]])

    def test_certificate_profiles_round_trip_without_issued_key_material(self) -> None:
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as destination:
            source_store = CertificateAutomationStore(
                source, load_or_create_secret_key(source)
            )
            credential = source_store.save_credential(
                credential_id="",
                name="Enrollment",
                username="svc-enroll@example.test",
                password="pki-secret",
            )
            server = source_store.save_server(
                {
                    "name": "Enterprise CA",
                    "provider": "adcs_web_enrollment",
                    "enrollment_url": "https://ca.example.test/certsrv/",
                    "credential_id": credential["id"],
                    "ca_bundle_pem": "",
                    "verify_tls": True,
                    "retrieval_strategy": "same_endpoint",
                    "timeout": 15,
                }
            )
            template = source_store.save_template(
                {
                    "name": "Web server",
                    "server_id": server["id"],
                    "template_identifier": "WebServer",
                    "key_size": 2048,
                    "renewal_days": 30,
                }
            )
            source_store.save_enrollment(
                managed_id="",
                name="Toolkit TLS",
                server_id=server["id"],
                template_id=template["id"],
                common_name="toolkit.example.test",
                dns_names=["toolkit.example.test"],
                private_key_pem=b"PRIVATE KEY MATERIAL",
                result=EnrollmentResult(
                    status="pending", request_id="42", message="Awaiting issuance"
                ),
            )
            source_item = selected_backup_items(
                build_backup_catalog(source), {"certificate_automation_profiles"}
            )
            exported = source_item[0]["store"].all()
            serialized = json.dumps(exported).encode("utf-8")
            self.assertNotIn(b"PRIVATE KEY MATERIAL", serialized)
            self.assertNotIn(b"Awaiting issuance", serialized)

            destination_item = selected_backup_items(
                build_backup_catalog(destination), {"certificate_automation_profiles"}
            )
            import_backup_items(
                {"certificate_automation_profiles": exported},
                destination_item,
                "merge",
            )
            destination_store = CertificateAutomationStore(
                destination, load_or_create_secret_key(destination)
            )
            imported_credential = destination_store.credential_profiles()[0]
            imported_secret = destination_store.credential_profile(
                imported_credential["id"], include_password=True
            )
            imported_managed = destination_store.managed_certificates()[0]

            self.assertEqual(imported_secret["password"], "pki-secret")
            self.assertEqual(imported_managed["name"], "Toolkit TLS")
            self.assertEqual(imported_managed["version_count"], 0)
            self.assertIsNone(imported_managed["current_version_id"])


if __name__ == "__main__":
    unittest.main()

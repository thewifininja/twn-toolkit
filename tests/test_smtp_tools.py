from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.automation_registry import AUTOMATION_REGISTRY, ConditionResult
from twn_toolkit.smtp_tools import (
    SMTPSettingsStore,
    parse_email_recipients,
    send_smtp_message,
)


SMTP_VALUES = {
    "host": "smtp.example.com",
    "port": 587,
    "security": "starttls",
    "verify_tls": True,
    "username": "toolkit",
    "from_name": "Toolkit",
    "from_address": "toolkit@example.com",
    "timeout": 10,
}


class SMTPSettingsTests(unittest.TestCase):
    def test_password_is_encrypted_preserved_and_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = SMTPSettingsStore(instance, "installation-secret")
            saved = store.save(SMTP_VALUES, password="smtp-secret")
            raw = (Path(instance) / "smtp_settings.json").read_text()

            self.assertNotIn("smtp-secret", raw)
            self.assertTrue(saved["has_password"])
            self.assertNotIn("password", saved)
            self.assertEqual(
                store.get(include_password=True)["password"], "smtp-secret"
            )

            store.save({**SMTP_VALUES, "from_name": "Updated"})
            self.assertEqual(
                store.get(include_password=True)["password"], "smtp-secret"
            )
            with self.assertRaisesRegex(Exception, "Enter an SMTP password"):
                store.save(SMTP_VALUES, clear_password=True)

    def test_recipient_parser_normalizes_and_deduplicates(self) -> None:
        recipients = parse_email_recipients(
            "Network Team <net@example.com>; net@example.com\nnoc@example.com"
        )
        self.assertEqual(
            [item["address"] for item in recipients],
            ["net@example.com", "noc@example.com"],
        )

    def test_starttls_delivery_has_no_attachments_and_reports_refusal(self) -> None:
        class FakeSMTP:
            instance = None

            def __init__(self, host, port, timeout):
                self.host, self.port, self.timeout = host, port, timeout
                self.started_tls = False
                self.logged_in = None
                self.message = None
                FakeSMTP.instance = self

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def ehlo(self):
                return None

            def starttls(self, *, context):
                self.started_tls = context is not None

            def login(self, username, password):
                self.logged_in = (username, password)

            def send_message(self, message, *, from_addr, to_addrs):
                self.message = message
                self.to_addrs = to_addrs
                return {"bad@example.com": (550, b"Mailbox unavailable")}

        settings = {**SMTP_VALUES, "password": "smtp-secret"}
        with patch("twn_toolkit.smtp_tools.smtplib.SMTP", FakeSMTP):
            result = send_smtp_message(
                settings,
                to=parse_email_recipients("good@example.com, bad@example.com"),
                subject="Automation notice",
                body="Metadata only",
            )

        connection = FakeSMTP.instance
        self.assertTrue(connection.started_tls)
        self.assertEqual(connection.logged_in, ("toolkit", "smtp-secret"))
        self.assertFalse(connection.message.is_multipart())
        self.assertEqual(connection.message.get_content().strip(), "Metadata only")
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(result["deliveries"][1]["status"], "error")

    def test_settings_routes_save_test_and_never_audit_password(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            response = client.post(
                "/settings/smtp",
                data={
                    "smtp_host": "smtp.example.com",
                    "smtp_port": "587",
                    "smtp_security": "starttls",
                    "smtp_verify_tls": "on",
                    "smtp_username": "toolkit",
                    "smtp_password": "route-secret",
                    "smtp_from_name": "Toolkit",
                    "smtp_from_address": "toolkit@example.com",
                    "smtp_timeout": "10",
                },
            )
            self.assertEqual(response.status_code, 302)
            settings_page = client.get("/settings")
            self.assertIn(b"Email delivery", settings_page.data)
            self.assertNotIn(b"route-secret", settings_page.data)

            with patch(
                "twn_toolkit.admin_routes.send_smtp_message",
                return_value={
                    "message_id": "<test@example.com>",
                    "accepted": 1,
                    "deliveries": [
                        {"address": "admin@example.com", "status": "success", "error": ""}
                    ],
                },
            ) as sender:
                tested = client.post(
                    "/settings/smtp/test",
                    data={"smtp_test_recipient": "admin@example.com"},
                )
            self.assertEqual(tested.status_code, 302)
            self.assertNotIn("attachments", sender.call_args.kwargs)
            audit_text = (Path(instance) / "audit.sqlite3").read_bytes()
            self.assertNotIn(b"route-secret", audit_text)


class EmailAutomationActionTests(unittest.TestCase):
    def test_email_action_renders_metadata_without_retaining_body(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            SMTPSettingsStore(instance, "installation-secret").save(
                SMTP_VALUES, password="smtp-secret"
            )
            trigger = ConditionResult(
                True,
                "met",
                "Gateway packet loss exceeded 20%",
                {
                    "execution": {"job_id": "job-123"},
                    "actions": {"results": [{"name": "Capture", "status": "success"}]},
                },
            )
            delivered = {
                "message_id": "<automation@example.com>",
                "accepted": 2,
                "deliveries": [
                    {"address": "noc@example.com", "status": "success", "error": ""},
                    {"address": "lead@example.com", "status": "success", "error": ""},
                ],
            }
            with (
                patch(
                    "twn_toolkit.automation_types.actions.load_or_create_secret_key",
                    return_value="installation-secret",
                ),
                patch(
                    "twn_toolkit.automation_types.actions.send_smtp_message",
                    return_value=delivered,
                ) as sender,
            ):
                result = AUTOMATION_REGISTRY.actions["email.send"].execute(
                    {
                        "to": "noc@example.com",
                        "cc": "lead@example.com",
                        "bcc": "",
                        "subject": "{{trigger.status}}: {{trigger.summary}}",
                        "body": "Job {{trigger.job_id}}\n{{actions.results}}",
                        "_instance_path": instance,
                    },
                    trigger,
                )

            self.assertEqual(result.status, "success")
            self.assertEqual(
                sender.call_args.kwargs["subject"],
                "met: Gateway packet loss exceeded 20%",
            )
            self.assertIn("job-123", sender.call_args.kwargs["body"])
            self.assertNotIn("body", result.output)
            self.assertNotIn("smtp-secret", json.dumps(result.output))


if __name__ == "__main__":
    unittest.main()

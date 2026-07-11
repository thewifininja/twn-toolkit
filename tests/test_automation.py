from __future__ import annotations

import tempfile
import unittest
import io
import json
import re
import sqlite3
import zipfile
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.automation import AutomationBackupStore, AutomationEngine, AutomationStore
from twn_toolkit.automation_registry import (
    AUTOMATION_REGISTRY,
    ActionResult,
    ActionType,
    AutomationRegistry,
    ConditionResult,
    ConditionType,
)
from twn_toolkit.auth import AuthStore, load_or_create_secret_key
from twn_toolkit.network_tools import ToolInputError


class AutomationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = AutomationStore(self.temp.name, "installation secret")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def save(self, trigger_after: int = 2, recover_after: int = 2) -> str:
        return self.store.save(
            name="Branch outage collection",
            interval_seconds=30,
            trigger_after=trigger_after,
            recover_after=recover_after,
            cooldown_seconds=300,
            condition={"type": "test.condition", "config": {"target": "edge"}},
            actions=[
                {
                    "type": "test.action",
                    "config": {"username": "admin", "password": "very secret"},
                }
            ],
            created_by="user-1",
        )

    def test_actions_are_encrypted_at_rest_and_masked_for_ui(self) -> None:
        automation_id = self.save()
        raw = Path(self.store.path).read_bytes()
        self.assertNotIn(b"very secret", raw)
        self.assertNotIn(b"admin", raw)

        masked = self.store.get(automation_id)
        self.assertNotIn("password", masked["actions"][0]["config"])
        self.assertTrue(masked["actions"][0]["has_password"])
        full = self.store.get(automation_id, include_secrets=True)
        self.assertEqual(full["actions"][0]["config"]["password"], "very secret")

    def test_state_machine_debounces_trigger_and_recovery(self) -> None:
        automation_id = self.save()
        self.store.set_enabled(automation_id, True)
        met = ConditionResult(True, "met", "failed", {"failed": 2})
        clear = ConditionResult(False, "clear", "healthy", {"failed": 0})

        state, fire = self.store.record_condition(automation_id, met)
        self.assertEqual(state["state"], "suspect")
        self.assertFalse(fire)
        state, fire = self.store.record_condition(automation_id, met)
        self.assertEqual(state["state"], "triggered")
        self.assertTrue(fire)
        state, fire = self.store.record_condition(automation_id, met)
        self.assertEqual(state["state"], "triggered")
        self.assertFalse(fire)
        state, fire = self.store.record_condition(automation_id, clear)
        self.assertEqual(state["state"], "recovering")
        state, fire = self.store.record_condition(automation_id, clear)
        self.assertEqual(state["state"], "healthy")
        self.assertFalse(fire)

    def test_editing_an_armed_automation_pauses_and_resets_it(self) -> None:
        automation_id = self.save(trigger_after=1)
        self.store.set_enabled(automation_id, True)
        self.store.record_condition(
            automation_id, ConditionResult(True, "met", "failed", {})
        )
        existing = self.store.get(automation_id, include_secrets=True)
        self.store.save(
            automation_id=automation_id,
            name="Updated branch collection",
            interval_seconds=60,
            trigger_after=2,
            recover_after=2,
            cooldown_seconds=300,
            condition=existing["condition"],
            actions=existing["actions"],
            created_by="user-1",
        )
        updated = self.store.get(automation_id)
        self.assertFalse(updated["enabled"])
        self.assertEqual(updated["state"], "disabled")
        self.assertEqual(updated["consecutive_met"], 0)
        self.assertIsNone(updated["next_check_at"])

    def test_legacy_embedded_definitions_migrate_without_losing_automation(self) -> None:
        automation_id = self.save()
        connection = sqlite3.connect(self.store.path)
        try:
            connection.execute("UPDATE automations SET condition_definition_id = NULL, action_definition_ids = NULL")
            connection.execute("DELETE FROM automation_conditions")
            connection.execute("DELETE FROM automation_actions")
            connection.commit()
        finally:
            connection.close()

        migrated_store = AutomationStore(self.temp.name, "installation secret")
        migrated = migrated_store.get(automation_id, include_secrets=True)
        self.assertEqual(migrated["name"], "Branch outage collection")
        self.assertEqual(migrated["condition"]["type"], "test.condition")
        self.assertEqual(migrated["actions"][0]["type"], "test.action")
        self.assertEqual(migrated["actions"][0]["config"]["password"], "very secret")
        self.assertEqual(len(migrated_store.condition_definitions()), 1)
        self.assertEqual(len(migrated_store.action_definitions()), 1)

    def test_engine_runs_registered_action_once_when_threshold_is_met(self) -> None:
        automation_id = self.save(trigger_after=1)
        calls: list[str] = []
        registry = AutomationRegistry()
        registry.add_condition(
            ConditionType(
                "test.condition",
                "Test condition",
                "",
                lambda value: value,
                lambda _config: ConditionResult(True, "met", "threshold met", {}),
            )
        )
        registry.add_action(
            ActionType(
                "test.action",
                "Test action",
                "",
                lambda value: value,
                lambda _config, _trigger: (
                    calls.append("ran")
                    or ActionResult("success", "collected", {"output": "ok"})
                ),
            )
        )
        self.store.set_enabled(automation_id, True)
        engine = AutomationEngine(self.store, registry)

        self.assertEqual(engine.run_once(), 1)
        self.assertEqual(calls, ["ran"])
        self.assertEqual(self.store.get(automation_id)["state"], "triggered")
        self.assertEqual(self.store.recent_runs(automation_id)[0]["status"], "success")

    def test_pipeline_runs_parallel_stage_before_later_stage_with_bounded_context(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Pipeline trigger", type_id="test.condition", config={}
        )
        first_ids = [
            self.store.save_action_definition(
                name=name, type_id="test.action", config={"name": name}
            )
            for name in ("Collect switch", "Collect firewall")
        ]
        notify_id = self.store.save_action_definition(
            name="Notify", type_id="test.action", config={"name": "Notify"}
        )
        automation_id = self.store.save(
            name="Staged workflow",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_stages=[
                {
                    "id": "gather",
                    "name": "Gather diagnostics",
                    "continue_policy": "all_success",
                    "action_definition_ids": first_ids,
                },
                {
                    "id": "notify",
                    "name": "Notify",
                    "continue_policy": "all_completed",
                    "action_definition_ids": [notify_id],
                },
            ],
            created_by="user-1",
        )
        calls: list[tuple[str, list[str]]] = []
        registry = AutomationRegistry()
        registry.add_action(
            ActionType(
                "test.action", "Test", "", lambda value: value,
                lambda config, trigger: (
                    calls.append((config["name"], list(trigger.evidence.get("actions", {}).get("successful", []))))
                    or ActionResult("success", f"{config['name']} complete", {"raw_output": "not shared", "count": 1})
                ),
            )
        )
        automation = self.store.get(automation_id, include_secrets=True)
        AutomationEngine(self.store, registry).execute_actions(
            automation, ConditionResult(True, "met", "triggered", {})
        )
        self.assertEqual({calls[0][0], calls[1][0]}, {"Collect switch", "Collect firewall"})
        self.assertEqual(calls[2][0], "Notify")
        self.assertEqual(set(calls[2][1]), {"Collect switch", "Collect firewall"})
        run = self.store.recent_runs(automation_id)[0]
        self.assertEqual(run["results"][0]["output"]["_pipeline"]["stage_id"], "gather")
        self.assertEqual(run["results"][2]["output"]["_pipeline"]["stage_id"], "notify")

    def test_pipeline_migration_is_recorded(self) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            migration = connection.execute(
                "SELECT description FROM automation_schema_migrations WHERE version = 1"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(migration[0], "Add ordered parallel action stages")

    def test_pipeline_failure_policy_stops_later_stages(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Stop trigger", type_id="test.condition", config={}
        )
        fail_id = self.store.save_action_definition(
            name="Fail", type_id="test.action", config={"status": "error"}
        )
        later_id = self.store.save_action_definition(
            name="Should not run", type_id="test.action", config={"status": "success"}
        )
        automation_id = self.store.save(
            name="Stop pipeline", interval_seconds=30, trigger_after=1,
            recover_after=1, cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_stages=[
                {"id": "first", "name": "First", "continue_policy": "all_success", "action_definition_ids": [fail_id]},
                {"id": "later", "name": "Later", "continue_policy": "all_completed", "action_definition_ids": [later_id]},
            ],
            created_by="user-1",
        )
        calls = []
        registry = AutomationRegistry()
        registry.add_action(ActionType(
            "test.action", "Test", "", lambda value: value,
            lambda config, _trigger: (
                calls.append(config["status"])
                or ActionResult(config["status"], config["status"], {})
            ),
        ))
        AutomationEngine(self.store, registry).execute_actions(
            self.store.get(automation_id, include_secrets=True),
            ConditionResult(True, "met", "triggered", {}),
        )
        self.assertEqual(calls, ["error"])
        self.assertEqual(self.store.recent_runs(automation_id)[0]["status"], "error")

    def test_manual_condition_is_never_claimed_by_scheduler(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Run on demand", type_id="manual.trigger", config={}
        )
        action_id = self.store.save_action_definition(
            name="Manual test action",
            type_id="test.action",
            config={"username": "admin", "password": "very secret"},
        )
        automation_id = self.store.save(
            name="Manual workflow",
            interval_seconds=1,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_definition_ids=[action_id],
            created_by="user-1",
        )
        self.store.set_enabled(automation_id, True)
        self.assertEqual(self.store.claim_due(), [])

    def test_engine_executes_calendar_occurrence_without_debounce(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Calendar",
            type_id="schedule.calendar",
            config={
                "timezone": "UTC",
                "missed_policy": "grace",
                "grace_minutes": 30,
                "rules": [{"id": "once", "type": "once", "date": "2026-07-11", "time": "12:00"}],
            },
        )
        action_id = self.store.save_action_definition(
            name="Scheduled action", type_id="test.action", config={"password": "secret"}
        )
        automation_id = self.store.save(
            name="Calendar workflow",
            interval_seconds=30,
            trigger_after=99,
            recover_after=99,
            cooldown_seconds=604800,
            condition_definition_id=condition_id,
            action_definition_ids=[action_id],
            created_by="user-1",
        )
        calls = []
        registry = AutomationRegistry()
        registry.add_condition(AUTOMATION_REGISTRY.conditions["schedule.calendar"])
        registry.add_action(
            ActionType(
                "test.action",
                "Test action",
                "",
                lambda value: value,
                lambda _config, trigger: (
                    calls.append(trigger.evidence["occurrence"]["rule_ids"])
                    or ActionResult("success", "ran", {})
                ),
            )
        )
        with patch("twn_toolkit.automation.time.time", return_value=1783771200 - 3600):
            self.store.set_enabled(automation_id, True)
        with patch("twn_toolkit.automation.time.time", return_value=1783771201):
            processed = AutomationEngine(self.store, registry).run_once()
        self.assertEqual(processed, 1)
        self.assertEqual(calls, [["once"]])
        self.assertEqual(self.store.get(automation_id)["state"], "completed")
        self.assertEqual(len(self.store.recent_runs(automation_id)), 1)

    def test_backup_adapter_moves_definitions_and_secrets_but_not_runtime_state(self) -> None:
        automation_id = self.store.save(
            name="Portable automation",
            interval_seconds=30,
            trigger_after=1,
            recover_after=2,
            cooldown_seconds=300,
            condition={
                "type": "ping.multi",
                "config": {
                    "targets": "127.0.0.1",
                    "timeout": 1,
                    "failure_mode": "all",
                    "failure_count": 1,
                },
            },
            actions=[
                {
                    "type": "ssh.collect",
                    "config": {
                        "hosts": "192.0.2.1",
                        "username": "admin",
                        "password": "very secret",
                        "commands": "show clock",
                        "port": 22,
                        "allow_unknown_hosts": False,
                        "send_ctrl_y": False,
                    },
                }
            ],
            created_by="user-1",
        )
        self.store.set_enabled(automation_id, True)
        self.store.record_condition(
            automation_id, ConditionResult(True, "met", "failed", {})
        )
        exported = AutomationBackupStore(self.store).all()
        exported_action = next(item for item in exported if item["kind"] == "action")
        self.assertEqual(exported_action["config"]["password"], "very secret")
        self.assertTrue(all("state" not in item for item in exported))

        with tempfile.TemporaryDirectory() as destination:
            destination_store = AutomationStore(destination, "different installation")
            AutomationBackupStore(destination_store).replace_all(exported)
            restored = destination_store.all(include_secrets=True)[0]
            restored_action = destination_store.action_definitions(include_secrets=True)[0]
            self.assertEqual(restored_action["config"]["password"], "very secret")
            self.assertFalse(restored["enabled"])
            self.assertEqual(restored["state"], "disabled")
            self.assertEqual(destination_store.recent_checks(restored["id"]), [])


class AutomationRouteTests(unittest.TestCase):
    def test_admin_can_create_webhook_action_with_write_only_headers(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            response = client.post(
                "/automations/actions/save",
                data={
                    "action_name": "Notify operations",
                    "action_type": "webhook.send",
                    "webhook_endpoints": "Primary = https://hooks.example.com/events\nhttps://backup.example.net/notify",
                    "webhook_method": "POST",
                    "webhook_headers": "Authorization: Bearer extremely-secret\nX-API-Key: also-secret",
                    "webhook_body_format": "json",
                    "webhook_body": '{"status":"{{trigger.status}}","summary":"{{trigger.summary}}"}',
                    "webhook_timeout": "8",
                    "webhook_verify_tls": "on",
                    "webhook_expected_statuses": "200-299",
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition = store.action_definitions(include_secrets=True)[0]
            page = client.get("/automations")
            update = client.post(
                "/automations/actions/save",
                data={
                    "action_definition_id": definition["id"],
                    "action_name": "Notify operations",
                    "action_type": "webhook.send",
                    "webhook_endpoints": definition["config"]["endpoints"],
                    "webhook_method": "POST", "webhook_headers": "",
                    "webhook_body_format": "json", "webhook_body": definition["config"]["body"],
                    "webhook_timeout": "8", "webhook_verify_tls": "on",
                    "webhook_expected_statuses": "200-299",
                },
            )
            preserved = store.action_definitions(include_secrets=True)[0]
            clear = client.post(
                "/automations/actions/save",
                data={
                    "action_definition_id": definition["id"],
                    "action_name": "Notify operations", "action_type": "webhook.send",
                    "webhook_endpoints": definition["config"]["endpoints"],
                    "webhook_method": "POST", "webhook_headers": "",
                    "webhook_clear_headers": "on", "webhook_body_format": "json",
                    "webhook_body": definition["config"]["body"], "webhook_timeout": "8",
                    "webhook_verify_tls": "on", "webhook_expected_statuses": "200-299",
                },
            )
            cleared = store.action_definitions(include_secrets=True)[0]

        self.assertEqual(response.status_code, 302)
        self.assertEqual(update.status_code, 302)
        self.assertEqual(clear.status_code, 302)
        self.assertEqual(definition["type"], "webhook.send")
        self.assertIn("extremely-secret", definition["config"]["headers"])
        self.assertEqual(preserved["config"]["headers"], definition["config"]["headers"])
        self.assertEqual(cleared["config"]["headers"], "")
        self.assertNotIn(b"extremely-secret", page.data)
        self.assertIn(b"Webhook POST", page.data)
        self.assertIn(b"2 endpoints", page.data)
        self.assertIn(b"headers saved", page.data)

    def test_admin_can_create_syslog_action(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            response = client.post(
                "/automations/actions/save",
                data={
                    "action_name": "Notify collectors",
                    "action_type": "syslog.send",
                    "syslog_destinations": "Primary = syslog.example.com | 514\nBackup = 192.0.2.20 | 5514",
                    "syslog_protocol": "udp",
                    "syslog_facility": "16",
                    "syslog_severity": "4",
                    "syslog_hostname": "twn-toolkit",
                    "syslog_app_name": "twn-automation",
                    "syslog_message": "Condition fired: {{trigger.summary}}",
                    "syslog_timeout": "2.5",
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition = store.action_definitions()[0]
            page = client.get("/automations")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(definition["type"], "syslog.send")
        self.assertEqual(definition["config"]["severity"], 4)
        self.assertEqual(definition["config"]["timeout"], 2.5)
        self.assertIn(b"Syslog UDP", page.data)
        self.assertIn(b"2 destinations", page.data)
        self.assertIn(b"priority 132", page.data)

    def test_admin_can_create_and_test_tcp_condition(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            response = client.post(
                "/automations/conditions/save",
                data={
                    "condition_name": "Management services",
                    "condition_type": "tcp.reachability",
                    "tcp_targets": "Core Switch = 192.0.2.10 | 22, 443-444\nportal.example.com | 8443",
                    "tcp_timeout": "1.5",
                    "tcp_expected_state": "open",
                    "tcp_failure_mode": "at_least",
                    "tcp_failure_count": "2",
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition = store.condition_definitions()[0]
            tcp_results = [{
                "host": "192.0.2.10", "label": "Core Switch", "port": 22,
                "service": "ssh", "status": "open", "detail": "", "elapsed_ms": 3.2,
            }]
            with patch("twn_toolkit.automation_types.conditions.scan_tcp_checks", return_value=tcp_results):
                tested = client.post(f"/automations/conditions/{definition['id']}/test")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(definition["type"], "tcp.reachability")
        self.assertEqual(
            definition["config"]["targets"],
            "Core Switch = 192.0.2.10 | 22, 443, 444\nportal.example.com | 8443",
        )
        self.assertEqual(definition["config"]["check_count"], 4)
        self.assertEqual(definition["config"]["failure_count"], 2)
        self.assertIn(b"Core Switch:22", tested.data)
        self.assertIn(b"ssh", tested.data)
        self.assertIn(b"Observed open; expected open", tested.data)
        self.assertIn(b"3.2 ms", tested.data)

    def test_ping_condition_test_shows_per_target_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            client.post(
                "/automations/conditions/save",
                data={
                    "condition_name": "WAN reachability",
                    "condition_type": "ping.multi",
                    "condition_targets": "Gateway = 192.0.2.1\nInternet = 198.51.100.1",
                    "condition_timeout": "1",
                    "condition_failure_mode": "at_least",
                    "condition_failure_count": "1",
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition_id = store.condition_definitions()[0]["id"]
            ping_results = [
                {"host": "192.0.2.1", "reachable": True, "latency_ms": 2.4, "elapsed_ms": 3.0},
                {"host": "198.51.100.1", "reachable": False, "latency_ms": None, "elapsed_ms": 1001.2},
            ]
            with patch("twn_toolkit.automation_types.conditions.ping_hosts", return_value=ping_results):
                response = client.post(f"/automations/conditions/{definition_id}/test")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Gateway", response.data)
        self.assertIn(b"192.0.2.1", response.data)
        self.assertIn(b"2.4 ms RTT", response.data)
        self.assertIn(b"Internet", response.data)
        self.assertIn(b"No ICMP reply before timeout", response.data)
        self.assertIn(b"1001.2 ms elapsed", response.data)

    def test_admin_can_create_dns_lookup_condition(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            response = client.post(
                "/automations/conditions/save",
                data={
                    "condition_name": "Portal DNS changed",
                    "condition_type": "dns.lookup",
                    "dns_hosts": "Portal = portal.example.com",
                    "dns_servers": "Internal = 192.0.2.53\nPublic = 198.51.100.53",
                    "dns_record_type": "A",
                    "dns_timeout": "2.5",
                    "dns_expected_answers": "192.0.2.10\n192.0.2.11",
                    "dns_answer_mode": "any",
                    "dns_failure_mode": "at_least",
                    "dns_failure_count": "1",
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition = store.condition_definitions()[0]
            page = client.get("/automations")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(definition["type"], "dns.lookup")
        self.assertEqual(definition["config"]["record_type"], "A")
        self.assertEqual(definition["config"]["failure_count"], 1)
        self.assertIn(b"DNS A", page.data)
        self.assertIn(b"1 name", page.data)
        self.assertIn(b"2 resolvers", page.data)

    def test_admin_can_create_calendar_condition_with_multiple_rules(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            rules = [
                {"id": "monday", "type": "weekly", "weekdays": [0], "time": "15:00"},
                {"id": "third-wed", "type": "monthly_weekday", "ordinal": 3, "weekday": 2, "time": "01:00"},
                {"id": "alternate", "type": "interval_weeks", "interval": 2, "anchor_date": "2026-07-16", "time": "16:03"},
            ]
            response = client.post(
                "/automations/conditions/save",
                data={
                    "condition_name": "Maintenance calendar",
                    "condition_type": "schedule.calendar",
                    "schedule_timezone": "America/New_York",
                    "schedule_missed_policy": "grace",
                    "schedule_grace_minutes": "30",
                    "schedule_rules_json": json.dumps(rules),
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition = store.condition_definitions()[0]
            page = client.get("/automations")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(definition["type"], "schedule.calendar")
        self.assertEqual(len(definition["config"]["rules"]), 3)
        self.assertIn(b"Calendar schedule", page.data)
        self.assertIn(b"third Wednesday", page.data)
        self.assertIn(b"Next occurrences", page.data)

    def test_admin_can_create_and_view_an_automation(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            condition_response = client.post(
                "/automations/conditions/save",
                data={
                    "condition_name": "WAN unavailable",
                    "condition_type": "ping.multi",
                    "condition_targets": "Loopback = 127.0.0.1\n192.0.2.1",
                    "condition_timeout": "1",
                    "condition_failure_mode": "all",
                    "condition_failure_count": "1",
                },
            )
            self.assertEqual(condition_response.status_code, 302)
            action_response = client.post(
                "/automations/actions/save",
                data={
                    "action_name": "Collect switch logs",
                    "action_type": "ssh.collect",
                    "action_hosts": "192.0.2.2",
                    "action_username": "admin",
                    "action_password": "secret",
                    "action_port": "22",
                    "action_commands": "show clock",
                    "action_command_timeout": "600",
                },
            )
            self.assertEqual(action_response.status_code, 302)
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            self.assertEqual(
                store.action_definitions(include_secrets=True)[0]["config"]["command_timeout"],
                600,
            )
            condition_id = store.condition_definitions()[0]["id"]
            action_id = store.action_definitions()[0]["id"]
            response = client.post(
                "/automations/save",
                data={
                    "name": "Outage logs",
                    "interval_seconds": "1",
                    "trigger_after": "2",
                    "recover_after": "2",
                    "cooldown_seconds": "300",
                    "condition_definition_id": condition_id,
                    "action_definition_id": action_id,
                },
            )
            self.assertEqual(response.status_code, 302)
            page = client.get("/automations")
            self.assertIn(b"Outage logs", page.data)
            self.assertIn(b"WAN unavailable", page.data)
            self.assertIn(b"Collect switch logs", page.data)
            self.assertIn(b"paused", page.data)

            second = client.post(
                "/automations/save",
                data={
                    "name": "Second outage workflow",
                    "interval_seconds": "1",
                    "trigger_after": "3",
                    "recover_after": "3",
                    "cooldown_seconds": "300",
                    "condition_definition_id": condition_id,
                    "action_definition_id": action_id,
                },
            )
            self.assertEqual(second.status_code, 302)
            self.assertEqual(len(store.condition_definitions()), 1)
            self.assertEqual(len(store.action_definitions()), 1)
            self.assertEqual(len(store.all()), 2)

            automation_id = store.all()[0]["id"]
            run_id = store.record_run(
                automation_id,
                ConditionResult(True, "met", "2 of 2 targets failed", {}),
                [
                    ActionResult(
                        "success",
                        "Collected two hosts",
                        {
                            "hosts": [
                                {"host": "10.0.0.1", "host_label": "Core Switch", "status": "success", "output": "show clock output"},
                                {"host": "10.0.0.2", "status": "success", "output": "show log output"},
                            ]
                        },
                    )
                ],
            )
            download = client.get(f"/automations/runs/{run_id}/download")
            self.assertEqual(download.status_code, 200)
            self.assertEqual(download.mimetype, "application/zip")
            with zipfile.ZipFile(io.BytesIO(download.data)) as archive:
                self.assertIn("summary.json", archive.namelist())
                host_files = [name for name in archive.namelist() if name.endswith(".txt")]
                self.assertEqual(len(host_files), 2)
                self.assertTrue(
                    all(
                        re.fullmatch(r"action-1/\d{14}-(?:Core-Switch|10\.0\.0\.2)\.txt", name)
                        for name in host_files
                    )
                )
                self.assertIn(b"show clock output", archive.read(host_files[0]))

    def test_standard_user_cannot_open_automation_administration(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            auth = AuthStore(instance_path)
            auth.create_user("admin", "correct horse battery staple", is_admin=True)
            auth.create_user("operator", "correct horse battery staple")
            client = app.test_client()
            client.post(
                "/login",
                data={
                    "username": "operator",
                    "password": "correct horse battery staple",
                },
            )
            self.assertEqual(client.get("/automations").status_code, 403)

    def test_manual_trigger_runs_actions_and_collected_data_can_be_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            client.post(
                "/automations/conditions/save",
                data={
                    "condition_name": "Run on demand",
                    "condition_type": "manual.trigger",
                },
            )
            client.post(
                "/automations/actions/save",
                data={
                    "action_name": "Collect clock",
                    "action_type": "ssh.collect",
                    "action_hosts": "192.0.2.2",
                    "action_username": "admin",
                    "action_password": "secret",
                    "action_port": "22",
                    "action_commands": "show clock",
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            response = client.post(
                "/automations/save",
                data={
                    "name": "Manual collection",
                    "interval_seconds": "30",
                    "trigger_after": "3",
                    "recover_after": "3",
                    "cooldown_seconds": "300",
                    "condition_definition_id": store.condition_definitions()[0]["id"],
                    "action_definition_id": store.action_definitions()[0]["id"],
                },
            )
            self.assertEqual(response.status_code, 302)
            automation_id = store.all()[0]["id"]
            ssh_results = [
                {"host": "192.0.2.2", "status": "success", "output": "clock output"}
            ]
            with patch(
                "twn_toolkit.automation_types.actions.run_ssh_hosts",
                return_value=ssh_results,
            ):
                run = client.post(f"/automations/{automation_id}/run-now")
            self.assertEqual(run.status_code, 302)
            runs = store.recent_runs(automation_id)
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["status"], "success")
            page = client.get(f"/automations?focus={automation_id}")
            self.assertIn(b"Run now", page.data)
            self.assertIn(b"Clear collected data", page.data)

            deleted = client.post(f"/automations/runs/{runs[0]['id']}/delete")
            self.assertEqual(deleted.status_code, 302)
            self.assertEqual(store.recent_runs(automation_id), [])

            trigger = ConditionResult(True, "manual", "Started manually", {})
            result = ActionResult("success", "collected", {"hosts": []})
            store.record_run(automation_id, trigger, [result])
            store.record_run(automation_id, trigger, [result])
            cleared = client.post(f"/automations/{automation_id}/runs/clear")
            self.assertEqual(cleared.status_code, 302)
            self.assertEqual(store.recent_runs(automation_id), [])


class AutomationRegistryTests(unittest.TestCase):
    def test_registered_types_own_form_parsing_and_secret_metadata(self) -> None:
        condition = AUTOMATION_REGISTRY.condition_config_from_form(
            "ping.multi",
            {
                "condition_targets": "Gateway = 192.0.2.1",
                "condition_timeout": "2",
                "condition_failure_mode": "all",
                "condition_failure_count": "1",
            },
        )
        self.assertEqual(condition["targets"], "Gateway = 192.0.2.1")
        self.assertEqual(condition["timeout"], 2)

        action = AUTOMATION_REGISTRY.action_config_from_form(
            "webhook.send",
            {
                "webhook_endpoints": "https://example.com/events",
                "webhook_method": "POST",
                "webhook_body_format": "json",
                "webhook_body": '{"status":"{{trigger.status}}"}',
                "webhook_timeout": "5",
                "webhook_expected_statuses": "200-299",
                "webhook_verify_tls": "on",
            },
            {"headers": "Authorization: Bearer retained"},
        )
        self.assertEqual(action["headers"], "Authorization: Bearer retained")
        self.assertEqual(
            AUTOMATION_REGISTRY.secret_fields_for_action("webhook.send"),
            ("headers",),
        )

    def test_webhook_action_renders_json_safely_and_reports_partial_delivery(self) -> None:
        action = AUTOMATION_REGISTRY.actions["webhook.send"]
        trigger = ConditionResult(True, "met", 'Gateway said "down"', {"failed": 2})
        success_response = {
            "status": 204, "reason": "No Content", "elapsed_ms": 12.3,
            "resolved_addresses": ["192.0.2.10"], "body": "", "truncated": False,
            "redirect": "",
        }
        failure_response = {
            "status": 500, "reason": "Error", "elapsed_ms": 20.1,
            "resolved_addresses": ["192.0.2.20"], "body": "failed", "truncated": False,
            "redirect": "",
        }
        with patch(
            "twn_toolkit.automation_types.actions.send_api_request",
            side_effect=[success_response, failure_response],
        ) as sender:
            result = action.execute(
                {
                    "endpoints": "Primary = https://hooks.example.com/events\nhttps://backup.example.net/events",
                    "method": "POST", "headers": "Authorization: Bearer secret",
                    "body_format": "json",
                    "body": '{"summary":"{{trigger.summary}}","met":"{{trigger.met}}","evidence":"{{trigger.evidence}}"}',
                    "timeout": 5, "verify_tls": True, "expected_statuses": "200-299",
                },
                trigger,
            )
        sent_body = json.loads(sender.call_args_list[0].kwargs["body"])
        self.assertEqual(sent_body["summary"], 'Gateway said "down"')
        self.assertIs(sent_body["met"], True)
        self.assertEqual(sent_body["evidence"], {"failed": 2})
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.output["endpoints"][0]["status"], "success")
        self.assertEqual(result.output["endpoints"][1]["http_status"], 500)
        self.assertNotIn("secret", json.dumps(result.output))

    def test_syslog_action_substitutes_trigger_and_reports_partial_delivery(self) -> None:
        action = AUTOMATION_REGISTRY.actions["syslog.send"]
        trigger = ConditionResult(True, "met", "Two WAN probes failed", {"failed": 2})
        sent_result = {
            "protocol": "UDP", "host": "syslog.example.com", "address": "192.0.2.10",
            "port": 514, "priority": 134, "facility": 16, "severity": 6,
            "bytes": 120, "wire_message": "payload",
        }
        with patch(
            "twn_toolkit.automation_types.actions.send_syslog",
            side_effect=[sent_result, ToolInputError("Could not resolve syslog destination")],
        ) as sender:
            result = action.execute(
                {
                    "destinations": "Primary = syslog.example.com | 514\nBackup = bad.example | 5514",
                    "protocol": "udp", "facility": 16, "severity": 6,
                    "hostname": "toolkit", "app_name": "automation",
                    "message": "{{trigger.status}}: {{trigger.summary}} at {{timestamp}}",
                    "timeout": 3,
                },
                trigger,
            )
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.summary, "Syslog message sent to 1 of 2 destinations.")
        self.assertEqual(result.output["destinations"][0]["status"], "success")
        self.assertEqual(result.output["destinations"][1]["status"], "error")
        self.assertIn("met: Two WAN probes failed at ", result.output["message"])
        self.assertEqual(sender.call_args_list[0].kwargs["message"], result.output["message"])

    def test_tcp_condition_normalizes_per_host_port_lists_and_legacy_config(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["tcp.reachability"]
        normalized = condition.validate({
            "targets": "FortiGate = gate.example.com | 8443\nGoogle = google.com | 443\nSwitch = 192.0.2.10 | 22, 8000-8002",
            "timeout": 1, "expected_state": "open", "failure_mode": "at_least", "failure_count": 1,
        })
        self.assertEqual(normalized["target_count"], 3)
        self.assertEqual(normalized["check_count"], 6)
        self.assertIn("FortiGate = gate.example.com | 8443", normalized["targets"])
        self.assertIn("Switch = 192.0.2.10 | 22, 8000, 8001, 8002", normalized["targets"])

        legacy = condition.validate({
            "hosts": "FortiGate = gate.example.com\nGoogle = google.com",
            "ports": "443,8443", "timeout": 1, "expected_state": "open",
            "failure_mode": "at_least", "failure_count": 1,
        })
        self.assertEqual(legacy["check_count"], 4)
        self.assertIn("FortiGate = gate.example.com | 443, 8443", legacy["targets"])
        self.assertIn("Google = google.com | 443, 8443", legacy["targets"])

    def test_tcp_condition_compares_observed_and_expected_state(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["tcp.reachability"]
        results = [
            {"host": "192.0.2.10", "label": "Switch", "port": 22, "service": "ssh", "status": "open", "detail": "", "elapsed_ms": 2.0},
            {"host": "192.0.2.10", "label": "Switch", "port": 443, "service": "https", "status": "closed", "detail": "Connection refused", "elapsed_ms": 1.0},
        ]
        with patch("twn_toolkit.automation_types.conditions.scan_tcp_checks", return_value=results):
            result = condition.evaluate({
                "hosts": "Switch = 192.0.2.10", "ports": "22,443", "timeout": 1,
                "expected_state": "open", "failure_mode": "at_least", "failure_count": 1,
            })
        self.assertTrue(result.met)
        self.assertFalse(result.evidence["checks"][0]["failed"])
        self.assertTrue(result.evidence["checks"][1]["failed"])
        self.assertEqual(result.evidence["failed"], 1)

    def test_tcp_expected_closed_requires_connection_refusal(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["tcp.reachability"]
        results = [
            {"host": "192.0.2.10", "label": "", "port": 22, "service": "ssh", "status": "closed", "detail": "Connection refused", "elapsed_ms": 1.0},
            {"host": "192.0.2.10", "label": "", "port": 23, "service": "telnet", "status": "timeout", "detail": "No response before timeout", "elapsed_ms": 1000.0},
        ]
        with patch("twn_toolkit.automation_types.conditions.scan_tcp_checks", return_value=results):
            result = condition.evaluate({
                "hosts": "192.0.2.10", "ports": "22-23", "timeout": 1,
                "expected_state": "closed", "failure_mode": "at_least", "failure_count": 1,
            })
        self.assertTrue(result.met)
        self.assertFalse(result.evidence["checks"][0]["failed"])
        self.assertTrue(result.evidence["checks"][1]["failed"])

    def test_dns_condition_matches_expected_answers_across_resolvers(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["dns.lookup"]
        results = [
            {
                "host": "portal.example.com",
                "host_label": "Portal",
                "server": "192.0.2.53",
                "server_label": "Internal",
                "record_type": "CNAME",
                "status": "success",
                "answers": ["EDGE.EXAMPLE.COM."],
                "response_ms": 2.0,
            },
            {
                "host": "portal.example.com",
                "host_label": "Portal",
                "server": "198.51.100.53",
                "server_label": "Public",
                "record_type": "CNAME",
                "status": "Timeout",
                "answers": [],
                "response_ms": 1000.0,
                "error": "timed out",
            },
        ]
        with patch("twn_toolkit.automation_types.conditions.dns_lookup_matrix", return_value=results):
            result = condition.evaluate(
                {
                    "hosts": "Portal = portal.example.com",
                    "servers": "Internal = 192.0.2.53\nPublic = 198.51.100.53",
                    "record_type": "CNAME",
                    "timeout": 1,
                    "expected_answers": "edge.example.com",
                    "answer_mode": "any",
                    "failure_mode": "at_least",
                    "failure_count": 1,
                }
            )

        self.assertTrue(result.met)
        self.assertEqual(result.evidence["failed"], 1)
        self.assertTrue(result.evidence["checks"][0]["matches_expected"])
        self.assertFalse(result.evidence["checks"][0]["failed"])
        self.assertTrue(result.evidence["checks"][1]["failed"])

    def test_dns_condition_can_require_every_expected_answer(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["dns.lookup"]
        results = [{
            "host": "example.com", "host_label": "", "server": "192.0.2.53",
            "server_label": "", "record_type": "A", "status": "success",
            "answers": ["192.0.2.10"], "response_ms": 1.0,
        }]
        with patch("twn_toolkit.automation_types.conditions.dns_lookup_matrix", return_value=results):
            result = condition.evaluate({
                "hosts": "example.com", "servers": "192.0.2.53", "record_type": "A",
                "timeout": 1, "expected_answers": "192.0.2.10\n192.0.2.11",
                "answer_mode": "all", "failure_mode": "all", "failure_count": 1,
            })
        self.assertTrue(result.met)
        self.assertFalse(result.evidence["checks"][0]["matches_expected"])

    def test_ping_condition_supports_all_and_at_least_thresholds(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["ping.multi"]
        results = [
            {"host": "192.0.2.1", "reachable": False, "latency_ms": None},
            {"host": "192.0.2.2", "reachable": True, "latency_ms": 1.0},
        ]
        with patch("twn_toolkit.automation_types.conditions.ping_hosts", return_value=results):
            all_result = condition.evaluate(
                {
                    "targets": "192.0.2.1\n192.0.2.2",
                    "timeout": 1,
                    "failure_mode": "all",
                    "failure_count": 1,
                }
            )
            one_result = condition.evaluate(
                {
                    "targets": "192.0.2.1\n192.0.2.2",
                    "timeout": 1,
                    "failure_mode": "at_least",
                    "failure_count": 1,
                }
            )
        self.assertFalse(all_result.met)
        self.assertTrue(one_result.met)
        self.assertEqual(one_result.evidence["failed"], 1)


if __name__ == "__main__":
    unittest.main()

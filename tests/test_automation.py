from __future__ import annotations

import tempfile
import unittest
import io
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
                "twn_toolkit.automation_registry.run_ssh_hosts",
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
    def test_ping_condition_supports_all_and_at_least_thresholds(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["ping.multi"]
        results = [
            {"host": "192.0.2.1", "reachable": False, "latency_ms": None},
            {"host": "192.0.2.2", "reachable": True, "latency_ms": 1.0},
        ]
        with patch("twn_toolkit.automation_registry.ping_hosts", return_value=results):
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

from __future__ import annotations

import tempfile
import unittest
import io
import json
import re
import sqlite3
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.automation import (
    AutomationBackupStore,
    AutomationEngine,
    AutomationStore,
    stage_should_continue,
)
from twn_toolkit.automation_registry import (
    AUTOMATION_REGISTRY,
    ActionResult,
    ActionType,
    AutomationRegistry,
    ConditionResult,
    ConditionType,
)
from twn_toolkit.auth import AuthStore, load_or_create_secret_key
from twn_toolkit.audit import AuditStore
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.profiles import (
    SNMPCredentialProfileStore,
    SNMPHostProfileStore,
    SNMPOidProfileStore,
)
from twn_toolkit.ssh_commandlets import SSHCommandletStore


class AutomationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = AutomationStore(self.temp.name, "installation secret")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_diagnostics_snapshot_is_read_only_and_uses_one_bounded_connection(self) -> None:
        with patch.object(
            self.store,
            "_connect",
            side_effect=AssertionError("diagnostics must not initialize the schema"),
        ):
            snapshot = self.store.diagnostics_snapshot(now=1_800_000_000)

        self.assertEqual(snapshot["storage"]["check_count"], 0)
        self.assertEqual(snapshot["storage"]["run_count"], 0)
        self.assertEqual(snapshot["orphan_artifacts"], {"count": 0, "bytes": 0})
        self.assertIn(
            "automation-7",
            {migration["version"] for migration in snapshot["migrations"]},
        )

    def test_workspace_snapshot_uses_one_read_only_connection(self) -> None:
        automation_id = self.save()
        self.store.record_error(automation_id, "simulated check failure")

        with patch.object(
            self.store,
            "_connect",
            side_effect=AssertionError("workspace reads must not initialize the schema"),
        ):
            snapshot = self.store.workspace_snapshot(recent_limit=10)

        self.assertEqual(
            [automation["name"] for automation in snapshot["automations"]],
            ["Branch outage collection"],
        )
        automation = snapshot["automations"][0]
        self.assertEqual(automation["conditions"][0]["type"], "test.condition")
        self.assertEqual(automation["actions"][0]["type"], "test.action")
        self.assertEqual(
            snapshot["recent_checks"][automation_id][0]["status"],
            "error",
        )
        self.assertEqual(snapshot["job_stats"]["queued_jobs"], 0)

    def test_binary_run_artifacts_follow_run_lifecycle(self) -> None:
        automation_id = self.store.save(
            name="Artifact lifecycle",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition={"type": "manual.trigger", "config": {}},
            actions=[{"type": "ssh.collect", "config": {
                "hosts": "192.0.2.10", "username": "admin", "password": "secret",
                "commands": "show clock", "port": 22, "command_timeout": 300,
                "allow_unknown_hosts": False, "send_ctrl_y": False,
            }}],
            created_by="user-1",
        )
        staging = Path(tempfile.mkdtemp())
        source = staging / "config.cfg"
        source.write_bytes(b"configuration")
        run_id = self.store.record_run(
            automation_id,
            ConditionResult(True, "met", "manual", {}),
            [ActionResult("success", "fetched", {
                "transfers": [],
                "_artifact_sources": [{
                    "source_path": str(source), "filename": "config.cfg", "size": 13,
                }],
            })],
        )
        run = self.store.get_run(run_id)
        artifact = run["results"][0]["output"]["artifacts"][0]
        self.assertEqual(self.store.run_artifact(run_id, artifact["artifact_path"]).read_bytes(), b"configuration")
        self.assertFalse(staging.exists())
        self.store.delete_run(run_id)
        self.assertFalse((self.store.artifact_root / run_id).exists())

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
        evaluation = self.store.recent_checks(automation_id)[0]["evidence"]["evaluation"]
        self.assertEqual(
            (evaluation["schema_version"], evaluation["kind"], evaluation["type"]),
            (1, "condition", "test.condition"),
        )

    def test_interval_deadlines_stay_anchored_and_exclude_active_checks(self) -> None:
        automation_id = self.store.save(
            name="One second cadence",
            interval_seconds=1,
            trigger_after=2,
            recover_after=2,
            cooldown_seconds=0,
            condition={"type": "test.condition", "config": {}},
            actions=[{"type": "test.action", "config": {}}],
            created_by="user-1",
        )
        with patch("twn_toolkit.automation.time.time", return_value=1_000.0):
            self.store.set_enabled(automation_id, True)
        with patch("twn_toolkit.automation.time.time", return_value=1_000.2):
            first = self.store.claim_due()[0]
        self.assertEqual(first["next_check_at"], 1_000.0)
        self.assertEqual(self.store.get(automation_id)["next_check_at"], 1_001.0)

        with patch("twn_toolkit.automation.time.time", return_value=1_001.2):
            self.assertEqual(
                self.store.claim_due(exclude_automation_ids={automation_id}),
                [],
            )
        self.assertEqual(self.store.get(automation_id)["next_check_at"], 1_001.0)

        with patch("twn_toolkit.automation.time.time", return_value=1_001.2):
            self.assertEqual(self.store.claim_due()[0]["id"], automation_id)
        self.assertEqual(self.store.get(automation_id)["next_check_at"], 1_002.0)

        with patch("twn_toolkit.automation.time.time", return_value=1_004.5):
            self.assertEqual(self.store.claim_due()[0]["id"], automation_id)
        self.assertEqual(self.store.get(automation_id)["next_check_at"], 1_005.5)

    def test_engine_records_condition_observation_at_round_start(self) -> None:
        automation_id = self.save()
        registry = AutomationRegistry()
        registry.add_condition(
            ConditionType(
                "test.condition",
                "Test condition",
                "",
                lambda config: config,
                lambda _config: ConditionResult(False, "clear", "healthy", {}),
            )
        )
        automation = self.store.get(automation_id, include_secrets=True)
        observed_times = iter([1_000.0])
        with patch(
            "twn_toolkit.automation.time.time",
            side_effect=lambda: next(observed_times, 1_001.2),
        ):
            AutomationEngine(self.store, registry).process_automation(automation)

        check = self.store.recent_checks(automation_id)[0]
        self.assertEqual(check["checked_at"], 1_000.0)
        self.assertEqual(check["evidence"]["evaluation"]["observed_at"], 1_000.0)

    def test_condition_groups_evaluate_all_and_any_as_one_check(self) -> None:
        condition_ids = [
            self.store.save_condition_definition(
                name=name, type_id=type_id, config={}
            )
            for name, type_id in (
                ("WAN unavailable", "test.met"),
                ("DNS unavailable", "test.clear"),
            )
        ]
        action_id = self.store.save_action_definition(
            name="Collect diagnostics", type_id="test.action", config={}
        )
        automation_id = self.store.save(
            name="Correlated outage",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_ids=condition_ids,
            condition_operator="all",
            action_definition_ids=[action_id],
            created_by="user-1",
        )
        registry = AutomationRegistry()
        registry.add_condition(
            ConditionType(
                "test.met", "Met", "", lambda value: value,
                lambda _config: ConditionResult(True, "met", "WAN failed", {}),
            )
        )
        registry.add_condition(
            ConditionType(
                "test.clear", "Clear", "", lambda value: value,
                lambda _config: ConditionResult(False, "clear", "DNS healthy", {}),
            )
        )
        engine = AutomationEngine(self.store, registry)
        automation = self.store.get(automation_id)

        all_result = engine.test_condition(automation)
        self.assertFalse(all_result.met)
        self.assertEqual(all_result.summary, "ALL: 1 of 2 conditions met.")
        self.assertEqual(
            [item["name"] for item in all_result.evidence["conditions"]],
            ["WAN unavailable", "DNS unavailable"],
        )
        self.assertEqual(
            all_result.evidence["evaluation"]["type"], "condition.group"
        )

        self.store.save(
            automation_id=automation_id,
            name="Correlated outage",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_ids=condition_ids,
            condition_operator="any",
            action_definition_ids=[action_id],
            created_by="user-1",
        )
        any_result = engine.test_condition(self.store.get(automation_id))
        self.assertTrue(any_result.met)
        self.assertEqual(any_result.summary, "ANY: 1 of 2 conditions met.")

    def test_group_condition_edit_pauses_automation_and_blocks_deletion(self) -> None:
        condition_ids = [
            self.store.save_condition_definition(
                name=name, type_id="test.condition", config={"value": name}
            )
            for name in ("Primary condition", "Secondary condition")
        ]
        action_id = self.store.save_action_definition(
            name="Group action", type_id="test.action", config={}
        )
        automation_id = self.store.save(
            name="Grouped condition references",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_ids=condition_ids,
            condition_operator="all",
            action_definition_ids=[action_id],
            created_by="user-1",
        )
        self.store.set_enabled(automation_id, True)

        self.store.save_condition_definition(
            definition_id=condition_ids[1],
            name="Secondary condition",
            type_id="test.condition",
            config={"value": "updated"},
        )
        self.assertFalse(self.store.get(automation_id)["enabled"])
        with self.assertRaisesRegex(ValueError, "still used"):
            self.store.delete_condition_definition(condition_ids[1])

    def test_trigger_queues_encrypted_action_snapshot_before_execution(self) -> None:
        automation_id = self.save(trigger_after=1)
        self.store.set_enabled(automation_id, True)
        _updated, should_fire = self.store.record_condition(
            automation_id,
            ConditionResult(True, "met", "edge failed", {"failed": 1}),
            scheduled_at=1234.0,
        )
        self.assertTrue(should_fire)
        self.assertEqual(self.store.job_stats()["queued_jobs"], 1)
        self.assertNotIn(b"very secret", Path(self.store.path).read_bytes())

        action = self.store.get(automation_id, include_secrets=True)["actions"][0]
        self.store.save_action_definition(
            definition_id=action["id"],
            name=action["name"],
            type_id=action["type"],
            config={"username": "changed", "password": "new secret"},
        )

        calls = []
        registry = AutomationRegistry()
        registry.add_action(
            ActionType(
                "test.action",
                "Test action",
                "",
                lambda value: value,
                lambda config, _trigger: (
                    calls.append((config["username"], config["password"]))
                    or ActionResult("success", "complete", {})
                ),
            )
        )
        job = self.store.claim_jobs()[0]
        self.assertEqual(
            job["trigger"].evidence["evaluation"]["kind"],
            "condition",
        )
        run_id = AutomationEngine(self.store, registry).process_job(job)
        self.assertEqual(calls, [("admin", "very secret")])
        self.assertEqual(self.store.get_run(run_id)["status"], "success")
        self.assertEqual(self.store.job_stats()["completed_jobs"], 1)
        self.store.delete_run(run_id)
        self.assertEqual(self.store.job_stats()["completed_jobs"], 0)

    def test_job_claim_is_atomic_and_expired_lease_is_recovered(self) -> None:
        automation_id = self.save(trigger_after=1)
        self.store.set_enabled(automation_id, True)
        with patch("twn_toolkit.automation.time.time", return_value=1000.0):
            self.store.record_condition(
                automation_id,
                ConditionResult(True, "met", "edge failed", {}),
            )
            claimed = self.store.claim_jobs(lease_seconds=30)
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["attempt_count"], 1)

        competing_store = AutomationStore(self.temp.name, "installation secret")
        with patch("twn_toolkit.automation.time.time", return_value=1029.0):
            self.assertEqual(competing_store.claim_jobs(), [])
        with patch("twn_toolkit.automation.time.time", return_value=1031.0):
            recovered = competing_store.claim_jobs()
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["id"], claimed[0]["id"])
        self.assertEqual(recovered[0]["attempt_count"], 2)

    def test_failed_job_retries_with_backoff_then_becomes_terminal(self) -> None:
        automation_id = self.save(trigger_after=1)
        self.store.set_enabled(automation_id, True)
        with patch("twn_toolkit.automation.time.time", return_value=1000.0):
            self.store.record_condition(
                automation_id,
                ConditionResult(True, "met", "edge failed", {}),
            )
            first = self.store.claim_jobs()[0]
            self.assertEqual(self.store.fail_job(first["id"], "first failure"), "queued")
        with patch("twn_toolkit.automation.time.time", return_value=1004.0):
            self.assertEqual(self.store.claim_jobs(), [])
        with patch("twn_toolkit.automation.time.time", return_value=1005.0):
            second = self.store.claim_jobs()[0]
            self.assertEqual(self.store.fail_job(second["id"], "second failure"), "queued")
        with patch("twn_toolkit.automation.time.time", return_value=1015.0):
            third = self.store.claim_jobs()[0]
            self.assertEqual(self.store.fail_job(third["id"], "third failure"), "failed")
        stats = self.store.job_stats()
        self.assertEqual(stats["queued_jobs"], 0)
        self.assertEqual(stats["failed_jobs"], 1)
        self.assertEqual(self.store.retry_failed_jobs(), 1)
        stats = self.store.job_stats()
        self.assertEqual(stats["queued_jobs"], 1)
        self.assertEqual(stats["failed_jobs"], 0)

    def test_automation_with_pending_job_cannot_be_deleted(self) -> None:
        automation_id = self.save(trigger_after=1)
        self.store.set_enabled(automation_id, True)
        self.store.record_condition(
            automation_id,
            ConditionResult(True, "met", "edge failed", {}),
        )
        with self.assertRaisesRegex(ValueError, "queued, waiting, or running"):
            self.store.delete(automation_id)

    def test_trigger_state_and_job_enqueue_are_one_transaction(self) -> None:
        automation_id = self.save(trigger_after=1)
        self.store.set_enabled(automation_id, True)
        with patch.object(
            self.store,
            "_enqueue_execution_job",
            side_effect=RuntimeError("simulated queue failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated queue failure"):
                self.store.record_condition(
                    automation_id,
                    ConditionResult(True, "met", "edge failed", {}),
                )
        automation = self.store.get(automation_id)
        self.assertEqual(automation["state"], "healthy")
        self.assertIsNone(automation["last_triggered_at"])
        self.assertEqual(self.store.recent_checks(automation_id), [])
        self.assertEqual(self.store.job_stats()["queued_jobs"], 0)

    def test_completion_failure_leaves_job_retriable_with_stable_identity(self) -> None:
        automation_id = self.save(trigger_after=1)
        self.store.set_enabled(automation_id, True)
        self.store.record_condition(
            automation_id,
            ConditionResult(True, "met", "edge failed", {}),
        )
        job = self.store.claim_jobs()[0]
        calls = []
        registry = AutomationRegistry()
        registry.add_action(
            ActionType(
                "test.action",
                "Test action",
                "",
                lambda value: value,
                lambda _config, trigger: (
                    calls.append(trigger.evidence["execution"]["job_id"])
                    or ActionResult("success", "complete", {})
                ),
            )
        )
        engine = AutomationEngine(self.store, registry)
        with patch.object(
            self.store,
            "complete_job",
            side_effect=RuntimeError("simulated completion crash"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated completion crash"):
                engine.process_job(job)
        self.assertEqual(self.store.job_stats()["queued_jobs"], 1)
        self.assertEqual(len(self.store.recent_runs(automation_id)), 1)

        retry_at = time.time() + 10
        with patch("twn_toolkit.automation.time.time", return_value=retry_at):
            retried = self.store.claim_jobs()[0]
        engine.process_job(retried)
        self.assertEqual(calls, [job["id"]])
        self.assertEqual(len(self.store.recent_runs(automation_id)), 1)
        self.assertEqual(self.store.job_stats()["completed_jobs"], 1)

    def test_failed_continuation_remains_stopped_after_job_recovery(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Recovery condition", type_id="test.condition", config={}
        )
        action_ids = [
            self.store.save_action_definition(
                name=name, type_id="test.action", config={"name": name}
            )
            for name in ("Failing action", "Must not run")
        ]
        automation_id = self.store.save(
            name="Stopped pipeline recovery",
            interval_seconds=1,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_stages=[
                {
                    "id": "first",
                    "name": "First",
                    "continue_policy": "all_success",
                    "action_definition_ids": [action_ids[0]],
                },
                {
                    "id": "second",
                    "name": "Second",
                    "continue_policy": "all_completed",
                    "delay_seconds": 300,
                    "action_definition_ids": [action_ids[1]],
                },
            ],
            created_by="user-1",
        )
        calls: list[str] = []
        registry = AutomationRegistry()
        registry.add_action(
            ActionType(
                "test.action",
                "Test",
                "",
                lambda value: value,
                lambda config, _trigger: (
                    calls.append(config["name"])
                    or ActionResult("error", "failed", {})
                ),
            )
        )
        self.store.set_enabled(automation_id, True)
        self.store.record_condition(
            automation_id,
            ConditionResult(True, "met", "triggered", {}),
        )
        job = self.store.claim_jobs()[0]
        engine = AutomationEngine(self.store, registry)
        with patch.object(
            self.store,
            "record_run",
            side_effect=RuntimeError("simulated persistence interruption"),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "simulated persistence interruption"
            ):
                engine.process_job(job)

        retry_at = time.time() + 10
        with patch("twn_toolkit.automation.time.time", return_value=retry_at):
            retried = self.store.claim_jobs()[0]
        run_id = engine.process_job(retried)

        self.assertEqual(calls, ["Failing action"])
        run = self.store.get_run(str(run_id))
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["status"], "error")

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
            connection.execute(
                """
                UPDATE automations
                SET condition_definition_id = NULL,
                    condition_definition_ids = NULL,
                    action_definition_ids = NULL
                """
            )
            connection.execute("DELETE FROM automation_conditions")
            connection.execute("DELETE FROM automation_actions")
            connection.commit()
        finally:
            connection.close()

        migrated_store = AutomationStore(self.temp.name, "installation secret")
        migrated = migrated_store.get(automation_id, include_secrets=True)
        self.assertEqual(migrated["name"], "Branch outage collection")
        self.assertEqual(migrated["condition"]["type"], "test.condition")
        self.assertEqual(
            migrated["condition_definition_ids"],
            [migrated["condition"]["id"]],
        )
        self.assertEqual(migrated["actions"][0]["type"], "test.action")
        self.assertEqual(migrated["actions"][0]["config"]["password"], "very secret")
        self.assertEqual(len(migrated_store.condition_definitions()), 1)
        self.assertEqual(len(migrated_store.action_definitions()), 1)

    def test_retention_defaults_prune_checks_but_preserve_runs(self) -> None:
        automation_id = self.save()
        now = 2_000_000_000.0
        old = now - 8 * 86400
        recent = now - 2 * 86400
        connection = sqlite3.connect(self.store.path)
        try:
            connection.executemany(
                "INSERT INTO automation_checks (automation_id, checked_at, met, status, summary, evidence_json) VALUES (?, ?, 0, 'clear', 'test', '{}')",
                [(automation_id, old), (automation_id, recent)],
            )
            connection.executemany(
                "INSERT INTO automation_runs (id, automation_id, started_at, finished_at, status, trigger_summary, results_json) VALUES (?, ?, ?, ?, 'success', 'test', '[]')",
                [("old-run", automation_id, old, old), ("new-run", automation_id, recent, recent)],
            )
            connection.commit()
        finally:
            connection.close()

        settings = self.store.retention_settings()
        self.assertEqual(settings["check_retention_days"], 7)
        self.assertEqual(settings["run_retention_days"], 0)
        preview = self.store.storage_stats(now)
        self.assertEqual(preview["eligible_check_count"], 1)
        self.assertEqual(preview["eligible_run_count"], 0)
        deleted = self.store.prune_history(now)
        self.assertEqual(deleted, {"checks": 1, "runs": 0})
        self.assertEqual(self.store.storage_stats(now)["check_count"], 1)
        self.assertEqual(self.store.storage_stats(now)["run_count"], 2)

    def test_configured_run_retention_and_daily_prune_gate(self) -> None:
        automation_id = self.save()
        now = 2_000_000_000.0
        old = now - 31 * 86400
        connection = sqlite3.connect(self.store.path)
        try:
            connection.execute(
                "INSERT INTO automation_runs (id, automation_id, started_at, finished_at, status, trigger_summary, results_json) VALUES ('old-run', ?, ?, ?, 'success', 'test', '[]')",
                (automation_id, old, old),
            )
            connection.commit()
        finally:
            connection.close()
        self.store.update_retention_settings(
            check_retention_days=14, run_retention_days=30
        )
        self.assertEqual(self.store.prune_history(now)["runs"], 1)
        self.assertIsNone(self.store.prune_history_if_due(now + 60))

        with self.assertRaisesRegex(ValueError, "0–3650"):
            self.store.update_retention_settings(
                check_retention_days=3651, run_retention_days=0
            )

    def test_migration_ledger_includes_retention_schema(self) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            row = connection.execute(
                "SELECT description FROM automation_schema_migrations WHERE version = 3"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(row[0], "Add configurable automation history retention")

    def test_admin_can_update_and_prune_automation_retention(self) -> None:
        app = create_app(self.temp.name)
        app.testing = True
        client = app.test_client()
        page = client.get("/settings?section=operations")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Automation history retention", page.data)
        response = client.post(
            "/settings/automation-retention",
            data={"check_retention_days": "14", "run_retention_days": "30"},
        )
        self.assertEqual(response.status_code, 302)
        settings = self.store.retention_settings()
        self.assertEqual(settings["check_retention_days"], 14)
        self.assertEqual(settings["run_retention_days"], 30)
        self.assertEqual(
            client.post("/settings/automation-retention/prune").status_code, 302
        )

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

    def test_pipeline_delay_is_durable_and_releases_its_worker(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Delayed trigger", type_id="test.condition", config={}
        )
        first_id = self.store.save_action_definition(
            name="Change network", type_id="test.action", config={"name": "change"}
        )
        notify_id = self.store.save_action_definition(
            name="Notify Discord", type_id="test.action", config={"name": "notify"}
        )
        automation_id = self.store.save(
            name="Delayed notification",
            interval_seconds=1,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_stages=[
                {
                    "id": "change",
                    "name": "Change network",
                    "continue_policy": "all_success",
                    "delay_seconds": 0,
                    "action_definition_ids": [first_id],
                },
                {
                    "id": "notify",
                    "name": "Notify Discord",
                    "continue_policy": "all_completed",
                    "delay_seconds": 300,
                    "action_definition_ids": [notify_id],
                },
            ],
            created_by="user-1",
        )
        calls: list[tuple[str, list[str]]] = []
        registry = AutomationRegistry()
        registry.add_action(
            ActionType(
                "test.action",
                "Test",
                "",
                lambda value: value,
                lambda config, trigger: (
                    calls.append(
                        (
                            config["name"],
                            list(
                                trigger.evidence.get("actions", {}).get(
                                    "successful", []
                                )
                            ),
                        )
                    )
                    or ActionResult(
                        "success",
                        f"{config['name']} complete",
                        {"sensitive": "retained only in encrypted progress"},
                    )
                ),
            )
        )
        self.store.set_enabled(automation_id, True)
        engine = AutomationEngine(self.store, registry)

        with patch("twn_toolkit.automation.time.time", return_value=1000.0):
            self.store.record_condition(
                automation_id,
                ConditionResult(True, "met", "targets failed", {}),
            )
            first_job = self.store.claim_jobs()[0]
            self.assertIsNone(engine.process_job(first_job))

        self.assertEqual(calls, [("change", [])])
        self.assertEqual(self.store.job_stats()["waiting_jobs"], 1)
        self.assertEqual(self.store.job_stats()["running_jobs"], 0)
        self.assertNotIn(
            b"retained only in encrypted progress",
            Path(self.store.path).read_bytes(),
        )
        resumed_store = AutomationStore(self.temp.name, "installation secret")
        resumed_engine = AutomationEngine(resumed_store, registry)
        with patch("twn_toolkit.automation.time.time", return_value=1299.0):
            self.assertEqual(resumed_store.claim_jobs(), [])
        with patch("twn_toolkit.automation.time.time", return_value=1300.0):
            resumed = resumed_store.claim_jobs()[0]
            run_id = resumed_engine.process_job(resumed)

        self.assertIsNotNone(run_id)
        self.assertEqual(calls, [("change", []), ("notify", ["Change network"])])
        self.assertEqual(self.store.job_stats()["waiting_jobs"], 0)
        self.assertEqual(self.store.job_stats()["completed_jobs"], 1)
        run = self.store.get_run(str(run_id))
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(run["results"][1]["output"]["_pipeline"]["stage_id"], "notify")

    def test_stage_delay_validation_and_migration_are_recorded(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Delay validation trigger", type_id="test.condition", config={}
        )
        action_ids = [
            self.store.save_action_definition(
                name=f"Delay action {index}", type_id="test.action", config={}
            )
            for index in (1, 2)
        ]
        automation_id = self.store.save(
            name="Delay validation",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_stages=[
                {
                    "id": "first",
                    "name": "First",
                    "continue_policy": "all_completed",
                    "delay_seconds": 300,
                    "action_definition_ids": [action_ids[0]],
                },
                {
                    "id": "second",
                    "name": "Second",
                    "continue_policy": "all_completed",
                    "delay_seconds": 86400,
                    "action_definition_ids": [action_ids[1]],
                },
            ],
            created_by="user-1",
        )
        stages = self.store.get(automation_id)["action_stages"]
        self.assertEqual(stages[0]["delay_seconds"], 0)
        self.assertEqual(stages[1]["delay_seconds"], 86400)
        with self.assertRaisesRegex(ValueError, "between 0 seconds and 24 hours"):
            self.store.save(
                automation_id=automation_id,
                name="Delay validation",
                interval_seconds=30,
                trigger_after=1,
                recover_after=1,
                cooldown_seconds=0,
                condition_definition_id=condition_id,
                action_stages=[
                    {
                        "id": "first",
                        "name": "First",
                        "continue_policy": "all_completed",
                        "action_definition_ids": [action_ids[0]],
                    },
                    {
                        "id": "second",
                        "name": "Second",
                        "continue_policy": "all_completed",
                        "delay_seconds": 86401,
                        "action_definition_ids": [action_ids[1]],
                    },
                ],
                created_by="user-1",
            )
        connection = sqlite3.connect(self.store.path)
        try:
            migration = connection.execute(
                "SELECT description FROM automation_schema_migrations WHERE version = 6"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(migration[0], "Add durable delayed-stage pipeline progress")

    def test_pipeline_migration_is_recorded(self) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            migration = connection.execute(
                "SELECT description FROM automation_schema_migrations WHERE version = 1"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(migration[0], "Add ordered parallel action stages")

    def test_durable_job_migration_is_recorded(self) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            migration = connection.execute(
                """
                SELECT description FROM automation_schema_migrations
                WHERE version = 4
                """
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(
            migration[0],
            "Add durable leased automation execution jobs",
        )

    def test_condition_group_migration_is_recorded(self) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            migration = connection.execute(
                """
                SELECT description FROM automation_schema_migrations
                WHERE version = 5
                """
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(migration[0], "Add ALL and ANY condition groups")

    def test_legacy_snmp_condition_migration_is_persisted(self) -> None:
        now = 1.0
        legacy = {
            "host_names": ["Core"],
            "oid_profile_names": ["Health"],
            "comparison": "at_most",
            "expected_value": "80",
            "case_sensitive": False,
            "failure_mode": "at_least",
            "failure_count": 1,
        }
        connection = sqlite3.connect(self.store.path)
        try:
            connection.execute("DELETE FROM automation_schema_migrations WHERE version = 2")
            connection.execute(
                "INSERT INTO automation_conditions (id, name, type, config_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                ("legacy-snmp", "Legacy SNMP", "snmp.value", json.dumps(legacy), now, now),
            )
            connection.commit()
        finally:
            connection.close()
        migrated = AutomationStore(self.temp.name, "installation secret")
        definition = migrated.get_condition_definition("legacy-snmp")
        self.assertEqual(definition["config"]["rules"][0]["comparison"], "greater_than")
        self.assertEqual(definition["config"]["rules"][0]["oid"], "*")
        connection = sqlite3.connect(self.store.path)
        try:
            description = connection.execute(
                "SELECT description FROM automation_schema_migrations WHERE version = 2"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(description, "Normalize SNMP conditions into per-host AND rules")

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

    def test_stage_continuation_policies_distinguish_partial_and_failure_paths(self) -> None:
        cases = (
            ("all_completed", ["success", "error"], True),
            ("success_or_partial", ["success", "partial"], True),
            ("success_or_partial", ["success", "error"], False),
            ("all_success", ["success", "success"], True),
            ("all_success", ["success", "partial"], False),
            ("any_failed", ["success", "error"], True),
            ("any_failed", ["success", "partial"], False),
            ("all_failed", ["error", "error"], True),
            ("all_failed", ["error", "success"], False),
        )
        for policy, statuses, expected in cases:
            with self.subTest(policy=policy, statuses=statuses):
                self.assertEqual(
                    stage_should_continue(policy, statuses), expected
                )

    def test_legacy_final_stage_route_is_moved_to_the_preceding_transition(self) -> None:
        stages = self.store._normalize_action_stages(
            [
                {
                    "id": "primary",
                    "name": "Primary",
                    "continue_policy": "all_completed",
                    "action_definition_ids": ["primary-action"],
                },
                {
                    "id": "fallback",
                    "name": "Fallback",
                    "continue_policy": "all_failed",
                    "action_definition_ids": ["fallback-action"],
                },
            ],
            [],
        )

        self.assertEqual(stages[0]["continue_policy"], "all_failed")
        self.assertEqual(stages[1]["continue_policy"], "all_completed")

    def test_any_failed_stage_routes_to_backup_action_with_failure_context(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Startup", type_id="test.condition", config={}
        )
        primary_id = self.store.save_action_definition(
            name="Discord alert",
            type_id="test.action",
            config={"name": "Discord alert", "status": "error"},
        )
        backup_id = self.store.save_action_definition(
            name="Email fallback",
            type_id="test.action",
            config={"name": "Email fallback", "status": "success"},
        )
        automation_id = self.store.save(
            name="Startup notification fallback",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_stages=[
                {
                    "id": "discord",
                    "name": "Try Discord",
                    "continue_policy": "any_failed",
                    "action_definition_ids": [primary_id],
                },
                {
                    "id": "email",
                    "name": "Send backup email",
                    "continue_policy": "all_completed",
                    "action_definition_ids": [backup_id],
                },
            ],
            created_by="user-1",
        )
        calls: list[tuple[str, list[str]]] = []
        registry = AutomationRegistry()
        registry.add_action(
            ActionType(
                "test.action",
                "Test",
                "",
                lambda value: value,
                lambda config, trigger: (
                    calls.append(
                        (
                            config["name"],
                            list(
                                trigger.evidence.get("actions", {}).get(
                                    "failed", []
                                )
                            ),
                        )
                    )
                    or ActionResult(config["status"], config["status"], {})
                ),
            )
        )

        AutomationEngine(self.store, registry).execute_actions(
            self.store.get(automation_id, include_secrets=True),
            ConditionResult(True, "met", "toolkit started", {}),
        )

        self.assertEqual(calls[0], ("Discord alert", []))
        self.assertEqual(calls[1], ("Email fallback", ["Discord alert"]))
        self.assertEqual(
            [result["status"] for result in self.store.recent_runs(automation_id)[0]["results"]],
            ["error", "success"],
        )

    def test_manual_trigger_is_separate_and_never_claimed_by_scheduler(self) -> None:
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
        self.assertEqual(self.store.condition_definitions(), [])
        self.assertEqual(self.store.trigger_definitions()[0]["id"], condition_id)
        trigger = AUTOMATION_REGISTRY.evaluate_trigger("manual.trigger", {})
        self.assertEqual(
            trigger.evidence["evaluation"]["kind"],
            "manual",
        )

    @staticmethod
    def _startup_identity(
        *,
        boot_id: str = "boot-a",
        toolkit_start_id: str = "start-a",
        occurred_at: float = 100.0,
        addresses: bool = True,
    ) -> dict:
        return {
            "startup": {
                "boot_id": boot_id,
                "boot_started_at": occurred_at,
                "toolkit_start_id": toolkit_start_id,
                "toolkit_started_at": occurred_at,
            },
            "toolkit": {
                "instance_name": "branch-pi",
                "hostname": "branch-pi.local",
                "version": "0.16.0",
                "primary_ipv4": "192.0.2.25" if addresses else "",
                "ipv4_addresses": ["192.0.2.25"] if addresses else [],
                "ipv6_addresses": [],
                "addresses": (
                    [{"address": "192.0.2.25", "family": "ipv4", "interface": "eth0"}]
                    if addresses
                    else []
                ),
                "primary_url": "https://192.0.2.25:5050" if addresses else "",
                "urls": ["https://192.0.2.25:5050"] if addresses else [],
            },
        }

    def _save_startup_automation(self, mode: str = "host_boot") -> str:
        source_id = self.store.ensure_startup_trigger_definition(
            {"mode": mode, "network_wait_seconds": 120}
        )
        action_id = self.store.save_action_definition(
            name=f"Startup {mode} action",
            type_id="test.action",
            config={},
        )
        return self.store.save(
            name=f"Startup {mode} workflow",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=source_id,
            action_definition_ids=[action_id],
            created_by="user-1",
        )

    def test_startup_event_is_armed_from_current_boot_and_queued_once(self) -> None:
        automation_id = self._save_startup_automation()
        baseline = self._startup_identity()
        with patch("twn_toolkit.automation.collect_system_identity", return_value=baseline):
            self.store.set_enabled(automation_id, True)
        self.assertEqual(self.store.claim_due(), [])
        self.assertFalse(
            self.store.has_pending_startup_events(baseline["startup"])
        )

        next_boot = self._startup_identity(
            boot_id="boot-b", toolkit_start_id="start-b", occurred_at=200.0
        )
        self.assertTrue(
            self.store.has_pending_startup_events(next_boot["startup"])
        )
        queued = self.store.enqueue_startup_events(next_boot, now=201.0)
        self.assertEqual(len(queued), 1)
        self.assertEqual(self.store.enqueue_startup_events(next_boot, now=202.0), [])
        jobs = self.store.claim_jobs()
        self.assertEqual([job["id"] for job in jobs], queued)
        self.assertEqual(jobs[0]["trigger"].evidence["evaluation"]["kind"], "startup")
        self.assertNotIn("boot_id", jobs[0]["trigger"].evidence["startup"])
        self.assertEqual(
            jobs[0]["trigger"].evidence["toolkit"]["primary_ipv4"],
            "192.0.2.25",
        )
        checks = self.store.recent_checks(automation_id)
        self.assertEqual((len(checks), checks[0]["status"]), (1, "started"))

    def test_host_boot_mode_ignores_toolkit_restart(self) -> None:
        automation_id = self._save_startup_automation()
        baseline = self._startup_identity()
        with patch("twn_toolkit.automation.collect_system_identity", return_value=baseline):
            self.store.set_enabled(automation_id, True)
        restarted = self._startup_identity(toolkit_start_id="start-b", occurred_at=200.0)
        self.assertEqual(self.store.enqueue_startup_events(restarted, now=201.0), [])

    def test_toolkit_start_mode_queues_complete_restart(self) -> None:
        automation_id = self._save_startup_automation("toolkit_start")
        baseline = self._startup_identity()
        with patch("twn_toolkit.automation.collect_system_identity", return_value=baseline):
            self.store.set_enabled(automation_id, True)
        restarted = self._startup_identity(toolkit_start_id="start-b", occurred_at=200.0)
        self.assertEqual(len(self.store.enqueue_startup_events(restarted, now=201.0)), 1)

    def test_startup_event_waits_for_network_but_eventually_runs_without_it(self) -> None:
        automation_id = self._save_startup_automation()
        baseline = self._startup_identity()
        with patch("twn_toolkit.automation.collect_system_identity", return_value=baseline):
            self.store.set_enabled(automation_id, True)
        next_boot = self._startup_identity(
            boot_id="boot-b",
            toolkit_start_id="start-b",
            occurred_at=200.0,
            addresses=False,
        )
        self.assertEqual(self.store.enqueue_startup_events(next_boot, now=250.0), [])
        queued = self.store.enqueue_startup_events(next_boot, now=321.0)
        self.assertEqual(len(queued), 1)
        trigger = self.store.claim_jobs()[0]["trigger"]
        self.assertFalse(trigger.evidence["startup"]["network_ready"])
        self.assertIn("no usable network address", trigger.summary)

    def test_startup_event_migration_is_recorded(self) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            migration = connection.execute(
                "SELECT description FROM automation_schema_migrations WHERE version = 7"
            ).fetchone()
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'automation_event_state'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(migration[0], "Add durable startup-event deduplication state")
        self.assertEqual(table[0], "automation_event_state")

    def test_startup_source_survives_encrypted_profile_backup_restore(self) -> None:
        source_id = self.store.ensure_startup_trigger_definition(
            {"mode": "host_boot", "network_wait_seconds": 120}
        )
        action_id = self.store.save_action_definition(
            name="Startup syslog",
            type_id="syslog.send",
            config={
                "destinations": "192.0.2.10 | 514",
                "protocol": "udp",
                "facility": 16,
                "severity": 6,
                "hostname": "twn-toolkit",
                "app_name": "twn-automation",
                "message": "{{toolkit.primary_ipv4}}",
                "timeout": 3,
            },
        )
        self.store.save(
            name="Portable startup",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=source_id,
            action_definition_ids=[action_id],
            created_by="user-1",
        )
        backup = AutomationBackupStore(self.store)
        exported = backup.all()
        source = next(item for item in exported if item["kind"] == "startup")
        self.assertEqual(source["type"], "system.startup")

        backup.replace_all(exported)
        restored = self.store.all()[0]
        self.assertEqual(restored["condition"]["type"], "system.startup")
        self.assertEqual(restored["condition"]["config"]["mode"], "host_boot")
        self.assertFalse(restored["enabled"])

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
        registry.add_trigger(AUTOMATION_REGISTRY.triggers["schedule.calendar"])
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
        evaluation = self.store.recent_checks(automation_id)[0]["evidence"]["evaluation"]
        self.assertEqual(
            (evaluation["kind"], evaluation["type"]),
            ("schedule", "schedule.calendar"),
        )

    def test_calendar_occurrence_is_not_consumed_when_job_enqueue_fails(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Calendar rollback",
            type_id="schedule.calendar",
            config={
                "timezone": "UTC",
                "missed_policy": "grace",
                "grace_minutes": 30,
                "rules": [
                    {
                        "id": "once",
                        "type": "once",
                        "date": "2026-07-11",
                        "time": "12:00",
                    }
                ],
            },
        )
        action_id = self.store.save_action_definition(
            name="Scheduled rollback action",
            type_id="test.action",
            config={"password": "secret"},
        )
        automation_id = self.store.save(
            name="Calendar rollback workflow",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_definition_ids=[action_id],
            created_by="user-1",
        )
        with patch("twn_toolkit.automation.time.time", return_value=1783771200 - 3600):
            self.store.set_enabled(automation_id, True)
        before = self.store.get(automation_id)

        with patch("twn_toolkit.automation.time.time", return_value=1783771201):
            with patch.object(
                self.store,
                "_enqueue_execution_job",
                side_effect=RuntimeError("simulated queue failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated queue failure"):
                    self.store.record_schedule_occurrence(automation_id)

        after = self.store.get(automation_id)
        self.assertEqual(after["state"], before["state"])
        self.assertEqual(after["next_check_at"], before["next_check_at"])
        self.assertEqual(after["last_triggered_at"], before["last_triggered_at"])
        self.assertEqual(self.store.recent_checks(automation_id), [])
        self.assertEqual(self.store.job_stats()["queued_jobs"], 0)

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
        primary_condition_id = self.store.get(automation_id)["condition"]["id"]
        second_condition_id = self.store.save_condition_definition(
            name="Backup DNS condition",
            type_id="dns.lookup",
            config={
                "hosts": "example.com",
                "servers": "192.0.2.53",
                "record_type": "A",
                "timeout": 1,
                "expected_answers": "",
                "answer_mode": "any",
                "failure_mode": "all",
                "failure_count": 1,
            },
        )
        self.store.save(
            automation_id=automation_id,
            name="Portable automation",
            interval_seconds=30,
            trigger_after=1,
            recover_after=2,
            cooldown_seconds=300,
            condition_definition_ids=[
                primary_condition_id,
                second_condition_id,
            ],
            condition_operator="any",
            action_definition_ids=[
                self.store.action_definitions(include_secrets=True)[0]["id"]
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
            self.assertEqual(restored["condition_operator"], "any")
            self.assertEqual(len(restored["conditions"]), 2)
            self.assertEqual(destination_store.recent_checks(restored["id"]), [])

    def test_backup_round_trip_preserves_stage_delays(self) -> None:
        condition_id = self.store.save_condition_definition(
            name="Backup delay condition",
            type_id="ping.multi",
            config={
                "targets": "127.0.0.1",
                "timeout": 1,
                "failure_mode": "all",
                "failure_count": 1,
            },
        )
        action_ids = [
            self.store.save_action_definition(
                name=name,
                type_id="syslog.send",
                config={
                    "destinations": destination,
                    "protocol": "udp",
                    "facility": 16,
                    "severity": 6,
                    "hostname": "twn-toolkit",
                    "app_name": "twn-automation",
                    "message": name,
                    "timeout": 3,
                },
            )
            for name, destination in (
                ("Backup stage one", "192.0.2.10 | 514"),
                ("Backup stage two", "192.0.2.11 | 514"),
            )
        ]
        self.store.save(
            name="Backup delayed pipeline",
            interval_seconds=30,
            trigger_after=1,
            recover_after=1,
            cooldown_seconds=0,
            condition_definition_id=condition_id,
            action_stages=[
                {
                    "id": "first",
                    "name": "First",
                    "continue_policy": "all_success",
                    "action_definition_ids": [action_ids[0]],
                },
                {
                    "id": "notify",
                    "name": "Notify",
                    "continue_policy": "all_completed",
                    "delay_seconds": 300,
                    "action_definition_ids": [action_ids[1]],
                },
            ],
            created_by="user-1",
        )

        exported = AutomationBackupStore(self.store).all()
        exported_automation = next(
            item for item in exported if item["kind"] == "automation"
        )
        self.assertEqual(
            exported_automation["action_stages"][1]["delay_seconds"], 300
        )
        with tempfile.TemporaryDirectory() as destination:
            restored_store = AutomationStore(destination, "restored secret")
            AutomationBackupStore(restored_store).replace_all(exported)
            restored = restored_store.all()[0]
        self.assertEqual(restored["action_stages"][1]["delay_seconds"], 300)


class AutomationRouteTests(unittest.TestCase):
    def test_reusable_action_and_automation_can_be_duplicated_with_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            store = AutomationStore(
                instance_path,
                load_or_create_secret_key(instance_path),
            )
            condition_id = store.save_condition_definition(
                name="Manual source",
                type_id="manual.trigger",
                config={},
            )
            action_id = store.save_action_definition(
                name="Notify endpoint",
                type_id="webhook.send",
                config={
                    "endpoints": "https://example.invalid/hook",
                    "method": "POST",
                    "body_format": "json",
                    "body_template": "{}",
                    "headers": "Authorization: Bearer private-token",
                    "timeout": 5,
                    "max_attempts": 1,
                    "retry_delay_seconds": 0,
                    "allow_private_targets": False,
                },
            )
            automation_id = store.save(
                name="Manual notification",
                interval_seconds=30,
                trigger_after=1,
                recover_after=1,
                cooldown_seconds=0,
                condition_definition_id=condition_id,
                action_definition_ids=[action_id],
                created_by="test-user",
            )

            action_response = client.post(
                f"/automations/actions/{action_id}/duplicate"
            )
            automation_response = client.post(
                f"/automations/{automation_id}/duplicate"
            )

            self.assertEqual(action_response.status_code, 302)
            copied_action = next(
                action
                for action in store.action_definitions(include_secrets=True)
                if action["name"] == "Notify endpoint copy"
            )
            self.assertIn("private-token", copied_action["config"]["headers"])
            self.assertEqual(automation_response.status_code, 302)
            copied_automation = next(
                automation
                for automation in store.all()
                if automation["name"] == "Manual notification copy"
            )
            self.assertFalse(copied_automation["enabled"])
            self.assertEqual(
                copied_automation["action_stages"][0]["action_definition_ids"],
                [action_id],
            )

    def test_ping_condition_form_matches_active_ping_timeout_capability(self) -> None:
        accelerated = {
            "engine": "fping",
            "accelerated": True,
            "target_limit": 250,
            "detail": "Batched high-capacity ICMP is available.",
            "path": "/usr/bin/fping",
        }
        compatibility = {
            "engine": "ping",
            "accelerated": False,
            "target_limit": 100,
            "detail": "fping is unavailable.",
        }
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            with patch(
                "twn_toolkit.automation_routes.ping_engine_capability",
                return_value=accelerated,
            ):
                accelerated_page = client.get("/automations/conditions")
            with patch(
                "twn_toolkit.automation_routes.ping_engine_capability",
                return_value=compatibility,
            ):
                compatibility_page = client.get("/automations/conditions")

        self.assertIn(b'name="condition_timeout" type="number" min="0.1"', accelerated_page.data)
        self.assertIn(b'step="0.1"', accelerated_page.data)
        self.assertIn(b"Sub-second timeouts are available", accelerated_page.data)
        self.assertIn(b'name="condition_timeout" type="number" min="1"', compatibility_page.data)
        self.assertIn(b"Install and authorize fping", compatibility_page.data)

    def test_ssh_action_uses_target_matrix_and_exposes_commandlets(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            SSHCommandletStore(instance_path).upsert(
                {
                    "name": "Collect AP diagnostics",
                    "platform": "Wireless AP",
                    "description": "Collect status from an AP fleet.",
                    "commands": "show ap {{ site_id }}",
                    "command_timeout": 600,
                    "target_matrix": (
                        "Name | Host | Site ID\n"
                        "Lobby AP | ap-1.example.com | HQ"
                    ),
                }
            )
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            initial = client.get("/automations/actions")
            response = client.post(
                "/automations/actions/save",
                data={
                    "action_name": "Collect switch interfaces",
                    "action_type": "ssh.collect",
                    "action_matrix": (
                        "Name | Host | Interface\n"
                        "Closet 1 | switch-1.example.com | port1\n"
                        "Closet 2 | switch-2.example.com | port2"
                    ),
                    "action_username": "admin",
                    "action_password": "secret",
                    "action_port": "22",
                    "action_commands": "show interface {{ interface }}",
                    "action_command_timeout": "600",
                },
            )
            store = AutomationStore(
                instance_path,
                load_or_create_secret_key(instance_path),
            )
            definition = store.action_definitions(include_secrets=True)[0]
            saved_page = client.get("/automations/actions")

        self.assertEqual(initial.status_code, 200)
        self.assertIn(b"Build this action directly below.", initial.data)
        self.assertIn(
            b"Optional shortcut: load a saved Bulk SSH action",
            initial.data,
        )
        self.assertNotIn(b"<h4>Starting point</h4>", initial.data)
        self.assertIn(b"Collect AP diagnostics", initial.data)
        self.assertIn(
            b"Collect AP diagnostics targets \xc2\xb7 Collect AP diagnostics",
            initial.data,
        )
        self.assertIn(b"data-automation-ssh-commandlets", initial.data)
        self.assertIn(b"data-ssh-matrix-editor", initial.data)
        self.assertIn(b'data-ssh-target-limit="5000"', initial.data)
        self.assertIn(b"Add variable", initial.data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(definition["config"]["target_count"], 2)
        self.assertEqual(definition["config"]["variables"], ["interface"])
        self.assertIn("Name | Host | Interface", definition["config"]["matrix"])
        self.assertEqual(definition["config"]["password"], "secret")
        self.assertIn(b"SSH command collection", saved_page.data)
        self.assertIn(b"2 hosts", saved_page.data)
        self.assertIn(b"1 variable", saved_page.data)
        self.assertNotIn(b'value="secret"', saved_page.data)

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
            page = client.get("/automations/actions")
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
        self.assertEqual(definition["config"]["max_attempts"], 1)
        self.assertEqual(
            definition["config"]["retry_statuses"],
            "408,425,429,500-599",
        )
        self.assertIn("extremely-secret", definition["config"]["headers"])
        self.assertEqual(preserved["config"]["headers"], definition["config"]["headers"])
        self.assertEqual(cleared["config"]["headers"], "")
        self.assertNotIn(b"extremely-secret", page.data)
        self.assertIn(b"Webhook POST", page.data)
        self.assertIn(b"2 endpoints", page.data)
        self.assertIn(b"1 attempt", page.data)
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
            page = client.get("/automations/actions")

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
            with patch("twn_toolkit.automation_types.condition_types.network_triggers.scan_tcp_checks", return_value=tcp_results):
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
                    "condition_targets": "Gateway = 192.0.2.1-192.0.2.2\nInternet = 198.51.100.1",
                    "condition_timeout": "1",
                    "condition_probe_count": "1",
                    "condition_failure_mode": "at_least",
                    "condition_failure_count": "1",
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition_id = store.condition_definitions()[0]["id"]
            self.assertEqual(
                store.condition_definitions()[0]["config"]["targets"],
                "Gateway-0001 = 192.0.2.1\nGateway-0002 = 192.0.2.2\nInternet = 198.51.100.1",
            )
            ping_results = [
                {"host": "192.0.2.1", "reachable": True, "latency_ms": 2.4, "elapsed_ms": 3.0},
                {"host": "192.0.2.2", "reachable": True, "latency_ms": 2.8, "elapsed_ms": 3.4},
                {"host": "198.51.100.1", "reachable": False, "latency_ms": None, "elapsed_ms": 1001.2},
            ]
            with patch("twn_toolkit.automation_types.condition_types.network_triggers.ping_hosts", return_value=ping_results):
                response = client.post(f"/automations/conditions/{definition_id}/test")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Gateway", response.data)
        self.assertIn(b"192.0.2.1", response.data)
        self.assertIn(b"2.4 ms avg", response.data)
        self.assertIn(b"Internet", response.data)
        self.assertIn(b"No ICMP replies received", response.data)
        self.assertIn(b"100.0% loss", response.data)

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
            page = client.get("/automations/conditions")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(definition["type"], "dns.lookup")
        self.assertEqual(definition["config"]["record_type"], "A")
        self.assertEqual(definition["config"]["failure_count"], 1)
        self.assertIn(b"DNS A", page.data)
        self.assertIn(b"1 name", page.data)
        self.assertIn(b"2 resolvers", page.data)

    def test_admin_can_create_dns_performance_condition(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            response = client.post(
                "/automations/conditions/save",
                data={
                    "condition_name": "Resolver latency",
                    "condition_type": "dns.performance",
                    "dns_performance_hosts": "Portal = portal.example.com",
                    "dns_performance_servers": "Internal = 192.0.2.53\nPublic = 198.51.100.53",
                    "dns_performance_record_type": "A",
                    "dns_performance_timeout": "2.5",
                    "dns_performance_response_limit_ms": "125",
                    "dns_performance_failure_mode": "at_least",
                    "dns_performance_failure_count": "1",
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition = store.condition_definitions()[0]
            page = client.get("/automations/conditions")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(definition["type"], "dns.performance")
        self.assertEqual(definition["config"]["response_limit_ms"], 125.0)
        self.assertEqual(definition["config"]["check_count"], 2)
        self.assertIn(b"DNS performance", page.data)
        self.assertIn(b"125.0 ms limit", page.data)

    def test_admin_can_create_calendar_schedule_with_multiple_rules(self) -> None:
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
                "/automations/schedules/save",
                data={
                    "schedule_name": "Maintenance calendar",
                    "schedule_timezone": "America/New_York",
                    "schedule_missed_policy": "grace",
                    "schedule_grace_minutes": "30",
                    "schedule_rules_json": json.dumps(rules),
                },
            )
            store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
            definition = store.schedule_definitions()[0]
            page = client.get("/automations/schedules")
            action_id = store.save_action_definition(
                name="Scheduled action",
                type_id="test.action",
                config={},
            )
            automation_response = client.post(
                "/automations/save",
                data={
                    "name": "Scheduled workflow",
                    "interval_seconds": "30",
                    "trigger_after": "1",
                    "recover_after": "1",
                    "cooldown_seconds": "0",
                    "run_mode": "schedule",
                    "schedule_definition_id": definition["id"],
                    "action_definition_id": action_id,
                },
            )
            saved_automation = store.all()[0]

        self.assertEqual(response.status_code, 302)
        self.assertEqual(automation_response.status_code, 302)
        self.assertEqual(definition["type"], "schedule.calendar")
        self.assertEqual(saved_automation["condition"]["id"], definition["id"])
        self.assertEqual(len(definition["config"]["rules"]), 3)
        self.assertIn(b"Schedules", page.data)
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
            saved_action_config = store.action_definitions(include_secrets=True)[0][
                "config"
            ]
            self.assertEqual(
                saved_action_config["command_timeout"],
                600,
            )
            self.assertEqual(saved_action_config["target_count"], 1)
            self.assertIn("Name|Host", saved_action_config["matrix"])
            self.assertIn("192.0.2.2|192.0.2.2", saved_action_config["matrix"])
            condition_id = store.condition_definitions()[0]["id"]
            second_condition_id = store.save_condition_definition(
                name="DNS unavailable",
                type_id="dns.lookup",
                config={
                    "hosts": "example.com",
                    "servers": "192.0.2.53",
                    "record_type": "A",
                    "timeout": 1,
                    "expected_answers": "",
                    "answer_mode": "any",
                    "failure_mode": "all",
                    "failure_count": 1,
                },
            )
            action_id = store.action_definitions()[0]["id"]
            response = client.post(
                "/automations/save",
                data={
                    "name": "Outage logs",
                    "interval_seconds": "1",
                    "trigger_after": "2",
                    "recover_after": "2",
                    "cooldown_seconds": "300",
                    "run_mode": "condition",
                    "condition_definition_id": [
                        condition_id,
                        second_condition_id,
                    ],
                    "condition_operator": "any",
                    "action_definition_id": action_id,
                },
            )
            self.assertEqual(response.status_code, 302)
            page = client.get("/automations")
            self.assertIn(b"Outage logs", page.data)
            self.assertIn(b"WAN unavailable", page.data)
            self.assertIn(b"DNS unavailable", page.data)
            self.assertIn(b"ANY:", page.data)
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
                    "run_mode": "condition",
                    "condition_definition_id": condition_id,
                    "action_definition_id": action_id,
                },
            )
            self.assertEqual(second.status_code, 302)
            self.assertEqual(len(store.condition_definitions()), 2)
            self.assertEqual(len(store.action_definitions()), 1)
            self.assertEqual(len(store.all()), 2)
            grouped = next(
                automation
                for automation in store.all()
                if automation["name"] == "Outage logs"
            )
            self.assertEqual(grouped["condition_operator"], "any")
            self.assertEqual(len(grouped["conditions"]), 2)

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
            self.assertEqual(client.get("/automations/schedules").status_code, 403)
            self.assertEqual(client.get("/automations/conditions").status_code, 403)
            self.assertEqual(client.get("/automations/actions").status_code, 403)

    def test_automation_libraries_have_independent_pages(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            automations_page = client.get("/automations")
            schedules_page = client.get("/automations/schedules")
            conditions_page = client.get("/automations/conditions")
            actions_page = client.get("/automations/actions")

        self.assertEqual(automations_page.status_code, 200)
        self.assertIn("workspace;dur=", automations_page.headers["Server-Timing"])
        self.assertIn("context;dur=", automations_page.headers["Server-Timing"])
        self.assertIn("total;dur=", automations_page.headers["Server-Timing"])
        self.assertIn(b"New automation", automations_page.data)
        self.assertNotIn(b"New condition", automations_page.data)
        self.assertNotIn(b"New action", automations_page.data)
        self.assertIn(b"New schedule", schedules_page.data)
        self.assertNotIn(b"New condition", schedules_page.data)
        self.assertIn(b"New condition", conditions_page.data)
        self.assertNotIn(b"New schedule", conditions_page.data)
        self.assertNotIn(b"New automation", conditions_page.data)
        self.assertIn(b"New action", actions_page.data)
        self.assertNotIn(b"New automation", actions_page.data)
        self.assertIn(
            b'aria-current="page"><span>Conditions</span>', conditions_page.data
        )
        self.assertIn(
            b'aria-current="page"><span>Schedules</span>', schedules_page.data
        )
        self.assertIn(
            b'aria-current="page"><span>Actions</span>', actions_page.data
        )

    def test_manual_mode_runs_actions_and_collected_data_can_be_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
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
                    "run_mode": "manual",
                    "action_definition_id": store.action_definitions()[0]["id"],
                },
            )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(store.schedule_definitions(), [])
            self.assertEqual(store.condition_definitions(), [])
            automation_id = store.all()[0]["id"]
            ssh_results = [
                {"host": "192.0.2.2", "status": "success", "output": "clock output"}
            ]
            with patch(
                "twn_toolkit.automation_types.actions.run_ssh_host_plans",
                return_value=ssh_results,
            ):
                run = client.post(f"/automations/{automation_id}/run-now")
            self.assertEqual(run.status_code, 302)
            runs = store.recent_runs(automation_id)
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["status"], "success")
            audit_event = next(
                event
                for event in AuditStore(instance_path).recent(20)
                if event["action"] == "automation.ran_manually"
            )
            self.assertEqual(audit_event["resource_name"], "Manual collection")
            self.assertEqual(audit_event["details"]["run id"], runs[0]["id"])
            self.assertNotIn("clock output", json.dumps(audit_event["details"]))
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

    def test_admin_can_create_arm_and_test_startup_automation(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            store = AutomationStore(
                instance_path, load_or_create_secret_key(instance_path)
            )
            action_id = store.save_action_definition(
                name="Startup webhook",
                type_id="webhook.send",
                config={
                    "endpoints": "Discord = https://hooks.example.com/startup",
                    "method": "POST",
                    "headers": "",
                    "body_format": "json",
                    "body": '{"host":"{{toolkit.hostname}}","ip":"{{toolkit.primary_ipv4}}"}',
                    "timeout": 5,
                    "verify_tls": True,
                    "expected_statuses": "200-299",
                    "max_attempts": 1,
                    "retry_delay": 2,
                    "retry_statuses": "408,425,429,500-599",
                },
            )
            response = client.post(
                "/automations/save",
                data={
                    "name": "Announce branch Pi",
                    "interval_seconds": "30",
                    "trigger_after": "1",
                    "recover_after": "1",
                    "cooldown_seconds": "0",
                    "run_mode": "startup",
                    "startup_mode": "host_boot",
                    "startup_network_wait_seconds": "120",
                    "action_definition_id": action_id,
                },
            )
            self.assertEqual(response.status_code, 302)
            automation = store.all()[0]
            self.assertEqual(automation["condition"]["type"], "system.startup")
            self.assertEqual(automation["condition"]["config"]["mode"], "host_boot")
            identity = AutomationStoreTests._startup_identity()
            with patch(
                "twn_toolkit.automation.collect_system_identity",
                return_value=identity,
            ):
                armed = client.post(f"/automations/{automation['id']}/toggle")
            self.assertEqual(armed.status_code, 302)
            self.assertTrue(store.get(automation["id"])["enabled"])
            delivered = {
                "status": 204,
                "reason": "No Content",
                "elapsed_ms": 2.0,
                "resolved_addresses": ["192.0.2.40"],
                "body": "",
                "truncated": False,
                "redirect": "",
            }
            with patch(
                "twn_toolkit.automation_routes.collect_system_identity",
                return_value=identity,
            ), patch(
                "twn_toolkit.automation_types.actions.send_api_request",
                return_value=delivered,
            ) as sender:
                tested = client.post(f"/automations/{automation['id']}/run-now")
            self.assertEqual(tested.status_code, 302)
            sent = json.loads(sender.call_args.kwargs["body"])
            self.assertEqual(sent, {"host": "branch-pi.local", "ip": "192.0.2.25"})
            page = client.get(f"/automations?focus={automation['id']}")
            self.assertIn(b'class="automation-startup-fields"', page.data)
            self.assertIn(b'class="field-note automation-startup-note"', page.data)
            self.assertIn(b"Once per host boot", page.data)
            self.assertIn(b"Test now", page.data)
            self.assertIn(b"Startup notification test", page.data)

    def test_manual_mode_can_continue_after_a_background_stage_delay(self) -> None:
        with tempfile.TemporaryDirectory() as instance_path:
            app = create_app(instance_path)
            app.testing = True
            client = app.test_client()
            store = AutomationStore(
                instance_path, load_or_create_secret_key(instance_path)
            )
            actions = [
                store.save_action_definition(
                    name=name,
                    type_id="syslog.send",
                    config={
                        "destinations": "192.0.2.10 | 514",
                        "protocol": "udp",
                        "facility": 16,
                        "severity": 6,
                        "hostname": "twn-toolkit",
                        "app_name": "twn-automation",
                        "message": name,
                        "timeout": 3,
                    },
                )
                for name in ("Make change", "Notify later")
            ]
            automation_id = store.save(
                name="Delayed manual workflow",
                interval_seconds=30,
                trigger_after=1,
                recover_after=1,
                cooldown_seconds=0,
                condition_definition_id=store.ensure_manual_trigger_definition(),
                action_stages=[
                    {
                        "id": "change",
                        "name": "Make change",
                        "continue_policy": "all_success",
                        "action_definition_ids": [actions[0]],
                    },
                    {
                        "id": "notify",
                        "name": "Notify",
                        "continue_policy": "all_completed",
                        "delay_seconds": 300,
                        "action_definition_ids": [actions[1]],
                    },
                ],
                created_by="admin",
            )

            with patch(
                "twn_toolkit.automation_types.actions.send_syslog",
                return_value={"host": "192.0.2.10", "port": 514},
            ) as sender:
                response = client.post(
                    f"/automations/{automation_id}/run-now",
                    follow_redirects=True,
                )

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"waiting between stages", response.data)
            self.assertIn(b"On full success", response.data)
            self.assertEqual(sender.call_count, 1)
            self.assertEqual(store.job_stats()["waiting_jobs"], 1)
            self.assertEqual(store.recent_runs(automation_id), [])
            audit_event = next(
                event
                for event in AuditStore(instance_path).recent(20)
                if event["action"] == "automation.ran_manually"
            )
            self.assertEqual(audit_event["details"]["run status"], "waiting")
            self.assertEqual(audit_event["details"]["run id"], "")


class AutomationRegistryTests(unittest.TestCase):
    def test_startup_trigger_validation_and_evaluation_are_explicit(self) -> None:
        config = AUTOMATION_REGISTRY.validate_trigger(
            "system.startup", {"mode": "host_boot"}
        )
        self.assertEqual(
            config,
            {"mode": "host_boot", "network_wait_seconds": 120},
        )
        result = AUTOMATION_REGISTRY.evaluate_trigger("system.startup", config)
        self.assertEqual(result.status, "armed")
        self.assertEqual(result.evidence["evaluation"]["kind"], "startup")
        with self.assertRaisesRegex(ToolInputError, "valid startup event"):
            AUTOMATION_REGISTRY.validate_trigger(
                "system.startup", {"mode": "process_restart"}
            )

    def test_ssh_action_renders_per_host_commands_for_large_matrices(self) -> None:
        matrix = "Name | Host | Site ID\n" + "\n".join(
            f"AP {index} | ap-{index}.example.com | site-{index}"
            for index in range(1, 126)
        )
        config = AUTOMATION_REGISTRY.action_config_from_form(
            "ssh.collect",
            {
                "action_matrix": matrix,
                "action_username": "admin",
                "action_password": "secret",
                "action_port": "22",
                "action_commands": "show site {{ site_id }}",
                "action_command_timeout": "300",
            },
        )
        captured_plans = []

        def run_plans(plans, **_kwargs):
            captured_plans.extend(plans)
            return [
                {
                    "host": plan["host"],
                    "host_label": plan["label"],
                    "status": "success",
                    "output": "diagnostics",
                }
                for plan in plans
            ]

        with patch(
            "twn_toolkit.automation_types.actions.run_ssh_host_plans",
            side_effect=run_plans,
        ):
            result = AUTOMATION_REGISTRY.actions["ssh.collect"].execute(
                config,
                ConditionResult(True, "met", "manual", {}),
            )

        self.assertEqual(config["target_count"], 125)
        self.assertEqual(config["variables"], ["site_id"])
        self.assertEqual(len(captured_plans), 125)
        self.assertEqual(
            captured_plans[0]["command_specs"][0]["command"],
            "show site site-1",
        )
        self.assertEqual(
            captured_plans[-1]["command_specs"][0]["command"],
            "show site site-125",
        )
        self.assertEqual(result.status, "success")
        self.assertEqual(result.output["execution_batch_count"], 3)
        self.assertEqual(result.output["target_count"], 125)

    def test_sftp_action_can_retain_or_store_fetched_files(self) -> None:
        action = AUTOMATION_REGISTRY.actions["sftp.fetch"]
        base = {
            "hosts": "Core Switch = 192.0.2.10", "remote_paths": "/config.cfg",
            "username": "admin", "password": "secret", "port": 22,
            "allow_unknown_hosts": False,
            "allow_legacy_algorithms": True,
            "filename_pattern": "{identity}-{filename}",
        }

        fetch_calls = []
        def fake_fetch(**kwargs):
            fetch_calls.append(kwargs)
            filename = "Core-Switch-config.cfg"
            (kwargs["output_dir"] / filename).write_bytes(b"config")
            return [{
                "host": "192.0.2.10", "host_label": "Core Switch",
                "remote_path": "/config.cfg", "status": "success",
                "filename": filename, "preferred_filename": "config.cfg",
                "size": 6, "error": "",
            }]

        with tempfile.TemporaryDirectory() as instance, patch(
            "twn_toolkit.automation_types.actions.fetch_ssh_files",
            side_effect=fake_fetch,
        ):
            retained = action.execute(
                {**base, "destination_mode": "run", "_instance_path": instance},
                ConditionResult(True, "met", "manual", {}),
            )
            self.assertEqual(retained.status, "success")
            self.assertTrue(fetch_calls[-1]["allow_legacy_algorithms"])
            source = Path(retained.output["_artifact_sources"][0]["source_path"])
            self.assertEqual(source.read_bytes(), b"config")
            source.unlink()
            source.parent.rmdir()

            stored = action.execute(
                {**base, "destination_mode": "datastore", "datastore_folder": "",
                 "per_host_folders": True, "_instance_path": instance},
                ConditionResult(True, "met", "manual", {}),
            )
            self.assertEqual(stored.status, "success")
            self.assertEqual(
                stored.output["transfers"][0]["stored_path"],
                "Core-Switch/config.cfg",
            )

    def test_sftp_action_scopes_duplicate_names_to_each_host_folder(self) -> None:
        action = AUTOMATION_REGISTRY.actions["sftp.fetch"]
        config = {
            "hosts": "First = 192.0.2.10\nSecond = 192.0.2.10",
            "remote_paths": "/config.cfg", "username": "admin",
            "password": "secret", "port": 22, "allow_unknown_hosts": False,
            "filename_pattern": "{filename}", "destination_mode": "datastore",
            "datastore_folder": "", "per_host_folders": True,
            "protocol": "ftp",
        }

        def fake_fetch(**kwargs):
            results = []
            for index, label in enumerate(("First", "Second"), 1):
                staging_name = "config.cfg" if index == 1 else "config-2.cfg"
                (kwargs["output_dir"] / staging_name).write_bytes(label.encode())
                results.append({
                    "host": "192.0.2.10", "host_label": label,
                    "remote_path": "/config.cfg", "status": "success",
                    "filename": staging_name, "preferred_filename": "config.cfg",
                    "size": len(label), "error": "",
                })
            return results

        with tempfile.TemporaryDirectory() as instance, patch(
            "twn_toolkit.automation_types.actions.fetch_ssh_files",
            side_effect=fake_fetch,
        ):
            first = action.execute(
                {**config, "_instance_path": instance},
                ConditionResult(True, "met", "manual", {}),
            )
            second = action.execute(
                {**config, "_instance_path": instance},
                ConditionResult(True, "met", "manual", {}),
            )

            self.assertEqual(
                [item["stored_path"] for item in first.output["transfers"]],
                ["First/config.cfg", "Second/config.cfg"],
            )
            self.assertEqual(
                [item["stored_path"] for item in second.output["transfers"]],
                ["First/config-2.cfg", "Second/config-2.cfg"],
            )
            self.assertEqual(first.summary, "FTP collection succeeded for 2 of 2 transfers.")

    def test_certificate_condition_applies_expiry_and_validation_policy(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["certificate.health"]
        certificate = {
            "host": "portal.example.com", "port": 443, "elapsed_ms": 12.5,
            "tls": {"version": "TLSv1.3"},
            "certificates": [{
                "common_name": "portal.example.com", "issuer": "CN=Test CA",
                "not_after": datetime(2026, 8, 1, tzinfo=timezone.utc),
                "time_valid": True, "days_remaining": 10,
                "sha256_fingerprint": "AA:BB",
            }],
            "hostname": {"valid": True, "error": ""},
            "trust": {"valid": True, "error": ""},
            "chain_order_valid": True, "likely_missing_intermediate": False,
        }
        with patch(
            "twn_toolkit.automation_types.condition_types.monitoring.inspect_certificate_chain",
            return_value=certificate,
        ):
            result = condition.evaluate({
                "targets": "Portal = portal.example.com | 443",
                "timeout": 2, "expiry_days": 30,
                "check_hostname": True, "check_trust": True, "check_chain": True,
                "failure_mode": "at_least", "failure_count": 1,
            })
        self.assertTrue(result.met)
        self.assertEqual(result.evidence["failed"], 1)
        self.assertIn("expires in 10", result.evidence["checks"][0]["reasons"][0])
        self.assertEqual(result.evidence["checks"][0]["tls_version"], "TLSv1.3")

    def test_certificate_condition_can_relax_private_certificate_checks(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["certificate.health"]
        certificate = {
            "elapsed_ms": 4, "tls": {"version": "TLSv1.2"},
            "certificates": [{
                "common_name": "switch.local", "issuer": "CN=Private CA",
                "not_after": datetime(2027, 8, 1, tzinfo=timezone.utc),
                "time_valid": True, "days_remaining": 300,
                "sha256_fingerprint": "CC:DD",
            }],
            "hostname": {"valid": False, "error": "name mismatch"},
            "trust": {"valid": False, "error": "self-signed"},
            "chain_order_valid": True, "likely_missing_intermediate": False,
        }
        with patch(
            "twn_toolkit.automation_types.condition_types.monitoring.inspect_certificate_chain",
            return_value=certificate,
        ):
            result = condition.evaluate({
                "targets": "Switch = 192.0.2.10 | 8443",
                "timeout": 2, "expiry_days": 30,
                "check_hostname": False, "check_trust": False, "check_chain": False,
                "failure_mode": "all", "failure_count": 1,
            })
        self.assertFalse(result.met)
        self.assertEqual(result.evidence["healthy"], 1)

    def test_snmp_condition_uses_saved_profiles_and_compares_each_value(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            SNMPCredentialProfileStore(instance).upsert(
                {"name": "Public", "version": "v2c", "community": "secret"}
            )
            SNMPHostProfileStore(instance).upsert(
                {
                    "name": "Core",
                    "host": "192.0.2.10",
                    "port": 161,
                    "credential_name": "Public",
                    "timeout": 2,
                    "retries": 1,
                }
            )
            SNMPOidProfileStore(instance).upsert(
                {"name": "Temperature", "source": "Temp = 1.3.6.1.4.1.999.1.0"}
            )
            polls = [{
                "host_name": "Core", "host": "192.0.2.10", "port": 161,
                "credential_name": "Public", "profile_name": "temperature-rule",
                "status": "success", "error": "", "elapsed_ms": 3.0,
                "rows": [{
                    "label": "Temp", "operation": "get", "oid": "1.3.6.1.4.1.999.1.0",
                    "value": "72", "value_type": "Integer", "response_ms": 2.5,
                }],
            }]
            condition = AUTOMATION_REGISTRY.conditions["snmp.value"]
            with (
                patch.dict("os.environ", {"TWN_TOOLKIT_INSTANCE_PATH": instance}),
                patch("twn_toolkit.automation_types.condition_types.monitoring.run_snmp_tests", return_value=polls),
            ):
                result = condition.evaluate({
                    "host_names": ["Core"],
                    "rules": [{
                        "id": "temperature-rule", "name": "Temperature high",
                        "oid_profile_name": "Temperature", "oid": "1.3.6.1.4.1.999.1.0",
                        "comparison": "greater_than", "expected_value": "70",
                        "case_sensitive": False,
                    }],
                    "host_failure_mode": "at_least", "host_failure_count": 1,
                })
            self.assertTrue(result.met)
            self.assertEqual(result.evidence["matched_hosts"], 1)
            value = result.evidence["hosts"][0]["rules"][0]["values"][0]
            self.assertEqual(value["value"], "72")
            self.assertNotIn("community", value)

    def test_snmp_condition_validates_guided_comparison_inputs(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["snmp.value"]
        normalized = condition.validate({
            "host_names": ["Core"],
            "rules": [{
                "id": "availability", "name": "Unavailable",
                "oid_profile_name": "Identity", "oid": "1.3.6.1.2.1.1.5.0",
                "comparison": "unavailable", "expected_value": "",
            }],
            "host_failure_mode": "all", "host_failure_count": 1,
        })
        self.assertEqual(normalized["rules"][0]["comparison"], "unavailable")
        with self.assertRaisesRegex(ToolInputError, "numeric comparison value"):
            condition.validate({
                "host_names": ["Core"],
                "rules": [{
                    "id": "temperature", "name": "Temperature",
                    "oid_profile_name": "Temperature", "oid": "1.3.6.1.4.1.999.1.0",
                    "comparison": "greater_than", "expected_value": "warm",
                }],
                "host_failure_mode": "at_least", "host_failure_count": 1,
            })

    def test_snmp_and_rules_must_match_on_the_same_host(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            SNMPCredentialProfileStore(instance).upsert(
                {"name": "Public", "version": "v2c", "community": "secret"}
            )
            for name, address in (("Switch 1", "192.0.2.11"), ("Switch 2", "192.0.2.12")):
                SNMPHostProfileStore(instance).upsert({
                    "name": name, "host": address, "port": 161,
                    "credential_name": "Public", "timeout": 2, "retries": 1,
                })
            SNMPOidProfileStore(instance).upsert({
                "name": "Health",
                "source": "CPU = 1.3.6.1.4.1.999.1.0\nMemory = 1.3.6.1.4.1.999.2.0",
            })
            values = {
                ("Switch 1", "cpu"): "95", ("Switch 1", "memory"): "40",
                ("Switch 2", "cpu"): "20", ("Switch 2", "memory"): "96",
            }
            polls = []
            for (host_name, rule_id), value in values.items():
                oid = "1.3.6.1.4.1.999.1.0" if rule_id == "cpu" else "1.3.6.1.4.1.999.2.0"
                polls.append({
                    "host_name": host_name, "host": "192.0.2.1", "profile_name": rule_id,
                    "status": "success", "error": "", "elapsed_ms": 1,
                    "rows": [{"label": rule_id, "oid": oid, "value": value, "value_type": "Integer", "response_ms": 1}],
                })
            config = {
                "host_names": ["Switch 1", "Switch 2"],
                "rules": [
                    {"id": "cpu", "name": "CPU high", "oid_profile_name": "Health", "oid": "1.3.6.1.4.1.999.1.0", "comparison": "greater_than", "expected_value": "80"},
                    {"id": "memory", "name": "Memory high", "oid_profile_name": "Health", "oid": "1.3.6.1.4.1.999.2.0", "comparison": "greater_than", "expected_value": "80"},
                ],
                "host_failure_mode": "at_least", "host_failure_count": 1,
            }
            with (
                patch.dict("os.environ", {"TWN_TOOLKIT_INSTANCE_PATH": instance}),
                patch("twn_toolkit.automation_types.condition_types.monitoring.run_snmp_tests", return_value=polls),
            ):
                result = AUTOMATION_REGISTRY.conditions["snmp.value"].evaluate(config)
            self.assertFalse(result.met)
            self.assertEqual(result.evidence["matched_hosts"], 0)
            self.assertTrue(all(not host["matched"] for host in result.evidence["hosts"]))

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
        trigger = ConditionResult(
            True,
            "met",
            'Gateway said "down"',
            {"failed": 2, "execution": {"job_id": "job-123"}},
        )
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
                    "body": '{"summary":"{{trigger.summary}}","met":"{{trigger.met}}","job":"{{trigger.job_id}}","evidence":"{{trigger.evidence}}"}',
                    "timeout": 5, "verify_tls": True, "expected_statuses": "200-299",
                },
                trigger,
            )
        sent_body = json.loads(sender.call_args_list[0].kwargs["body"])
        self.assertEqual(sent_body["summary"], 'Gateway said "down"')
        self.assertIs(sent_body["met"], True)
        self.assertEqual(sent_body["job"], "job-123")
        self.assertEqual(
            sent_body["evidence"],
            {"failed": 2, "execution": {"job_id": "job-123"}},
        )
        self.assertEqual(
            sender.call_args_list[0].kwargs["headers"]["Idempotency-Key"],
            "job-123",
        )
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.output["endpoints"][0]["status"], "success")
        self.assertEqual(result.output["endpoints"][1]["http_status"], 500)
        self.assertNotIn("secret", json.dumps(result.output))

    def test_webhook_retries_transient_statuses_and_records_attempts(self) -> None:
        action = AUTOMATION_REGISTRY.actions["webhook.send"]
        trigger = ConditionResult(
            True,
            "met",
            "WAN unavailable",
            {"execution": {"job_id": "job-retry"}},
        )
        failed = {
            "status": 503,
            "reason": "Unavailable",
            "elapsed_ms": 10.0,
            "resolved_addresses": ["192.0.2.10"],
            "body": "retry",
            "truncated": False,
            "redirect": "",
        }
        delivered = {
            **failed,
            "status": 204,
            "reason": "No Content",
            "body": "",
        }
        with (
            patch(
                "twn_toolkit.automation_types.actions.send_api_request",
                side_effect=[failed, delivered],
            ) as sender,
            patch("twn_toolkit.automation_types.actions.time.sleep") as sleeper,
        ):
            result = action.execute(
                {
                    "endpoints": "Discord = https://discord.example.com/webhook",
                    "method": "POST",
                    "headers": "",
                    "body_format": "json",
                    "body": '{"summary":"{{trigger.summary}}"}',
                    "timeout": 5,
                    "verify_tls": True,
                    "expected_statuses": "200-299",
                    "max_attempts": 3,
                    "retry_delay": 2,
                    "retry_statuses": "429,500-599",
                },
                trigger,
            )

        self.assertEqual(sender.call_count, 2)
        sleeper.assert_called_once_with(2.0)
        self.assertEqual(result.status, "success")
        endpoint = result.output["endpoints"][0]
        self.assertEqual(endpoint["attempt_count"], 2)
        self.assertEqual(
            [attempt.get("http_status") for attempt in endpoint["attempts"]],
            [503, 204],
        )

    def test_webhook_preserves_startup_address_lists_as_json_arrays(self) -> None:
        action = AUTOMATION_REGISTRY.actions["webhook.send"]
        trigger = ConditionResult(
            True,
            "started",
            "Host started",
            {
                "toolkit": {
                    "instance_name": "branch-pi",
                    "hostname": "branch-pi.local",
                    "version": "0.20.0",
                    "primary_ipv4": "192.0.2.25",
                    "ipv4_addresses": ["192.0.2.25", "198.51.100.25"],
                    "ipv6_addresses": ["2001:db8::25"],
                    "primary_url": "https://192.0.2.25:5050",
                    "urls": [
                        "https://192.0.2.25:5050",
                        "https://[2001:db8::25]:5050",
                    ],
                },
                "startup": {
                    "reason": "Host started",
                    "mode": "host_boot",
                    "occurred_at": 1785686400,
                },
            },
        )
        delivered = {
            "status": 204,
            "reason": "No Content",
            "elapsed_ms": 2.0,
            "resolved_addresses": ["192.0.2.40"],
            "body": "",
            "truncated": False,
            "redirect": "",
        }
        with patch(
            "twn_toolkit.automation_types.actions.send_api_request",
            return_value=delivered,
        ) as sender:
            result = action.execute(
                {
                    "endpoints": "https://hooks.example.com/startup",
                    "method": "POST",
                    "headers": "",
                    "body_format": "json",
                    "body": '{"version":"{{toolkit.version}}","ipv4":"{{toolkit.ipv4_addresses}}","ipv6":"{{toolkit.ipv6_addresses}}","urls":"{{toolkit.urls}}","reason":"{{startup.reason}}"}',
                    "timeout": 5,
                    "verify_tls": True,
                    "expected_statuses": "200-299",
                },
                trigger,
            )
        body = json.loads(sender.call_args.kwargs["body"])
        self.assertEqual(body["version"], "0.20.0")
        self.assertEqual(body["ipv4"], ["192.0.2.25", "198.51.100.25"])
        self.assertEqual(body["ipv6"], ["2001:db8::25"])
        self.assertEqual(body["urls"][1], "https://[2001:db8::25]:5050")
        self.assertEqual(body["reason"], "Host started")
        self.assertEqual(result.status, "success")

    def test_webhook_does_not_retry_nontransient_failure(self) -> None:
        action = AUTOMATION_REGISTRY.actions["webhook.send"]
        response = {
            "status": 400,
            "reason": "Bad Request",
            "elapsed_ms": 4.0,
            "resolved_addresses": ["192.0.2.10"],
            "body": "invalid payload",
            "truncated": False,
            "redirect": "",
        }
        with patch(
            "twn_toolkit.automation_types.actions.send_api_request",
            return_value=response,
        ) as sender:
            result = action.execute(
                {
                    "endpoints": "https://hooks.example.com/events",
                    "method": "POST",
                    "headers": "",
                    "body_format": "json",
                    "body": "{}",
                    "timeout": 5,
                    "verify_tls": True,
                    "expected_statuses": "200-299",
                    "max_attempts": 5,
                    "retry_delay": 0,
                    "retry_statuses": "429,500-599",
                },
                ConditionResult(True, "met", "triggered", {}),
            )

        self.assertEqual(sender.call_count, 1)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.output["endpoints"][0]["attempt_count"], 1)

    def test_syslog_action_substitutes_trigger_and_reports_partial_delivery(self) -> None:
        action = AUTOMATION_REGISTRY.actions["syslog.send"]
        trigger = ConditionResult(
            True,
            "met",
            "Two WAN probes failed",
            {
                "failed": 2,
                "execution": {"job_id": "job-456"},
                "toolkit": {
                    "hostname": "branch-pi.local",
                    "primary_ipv4": "192.0.2.25",
                    "primary_url": "https://192.0.2.25:5050",
                },
                "startup": {"reason": "Host started"},
            },
        )
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
                    "message": "{{trigger.status}}: {{trigger.summary}} [{{trigger.job_id}}] {{startup.reason}} on {{toolkit.hostname}} at {{toolkit.primary_ipv4}} {{toolkit.primary_url}} {{timestamp}}",
                    "timeout": 3,
                },
                trigger,
            )
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.summary, "Syslog message sent to 1 of 2 destinations.")
        self.assertEqual(result.output["destinations"][0]["status"], "success")
        self.assertEqual(result.output["destinations"][1]["status"], "error")
        self.assertIn(
            "met: Two WAN probes failed [job-456] Host started on branch-pi.local at 192.0.2.25 https://192.0.2.25:5050 ",
            result.output["message"],
        )
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
        with patch("twn_toolkit.automation_types.condition_types.network_triggers.scan_tcp_checks", return_value=results):
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
        with patch("twn_toolkit.automation_types.condition_types.network_triggers.scan_tcp_checks", return_value=results):
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
        with patch("twn_toolkit.automation_types.condition_types.network_triggers.dns_lookup_matrix", return_value=results):
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
        with patch("twn_toolkit.automation_types.condition_types.network_triggers.dns_lookup_matrix", return_value=results):
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
        with patch("twn_toolkit.automation_types.condition_types.network_triggers.ping_hosts", return_value=results):
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

    def test_ping_condition_accepts_subsecond_timeout_only_with_fping(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["ping.multi"]
        accelerated = {
            "engine": "fping",
            "accelerated": True,
            "target_limit": 250,
            "detail": "Batched high-capacity ICMP is available.",
            "path": "/usr/bin/fping",
        }
        compatibility = {
            "engine": "ping",
            "accelerated": False,
            "target_limit": 100,
            "detail": "fping is unavailable.",
        }
        ping_result = [{
            "host": "192.0.2.1",
            "reachable": True,
            "latency_ms": 1.0,
        }]
        with (
            patch(
                "twn_toolkit.automation_types.condition_types.network_triggers.ping_engine_capability",
                return_value=accelerated,
            ),
            patch(
                "twn_toolkit.automation_types.condition_types.network_triggers.ping_hosts",
                return_value=ping_result,
            ) as ping,
        ):
            result = condition.evaluate({
                "targets": "192.0.2.1",
                "timeout": "0.9",
                "failure_mode": "all",
                "failure_count": 1,
            })
        self.assertFalse(result.met)
        ping.assert_called_once_with(["192.0.2.1"], timeout=0.9)

        with patch(
            "twn_toolkit.automation_types.condition_types.network_triggers.ping_engine_capability",
            return_value=compatibility,
        ), self.assertRaisesRegex(ToolInputError, "between 1 and 10"):
            condition.validate({
                "targets": "192.0.2.1",
                "timeout": "0.9",
                "failure_mode": "all",
                "failure_count": 1,
            })

    def test_ping_health_combines_loss_latency_and_jitter_thresholds(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["ping.multi"]
        rounds = [
            [
                {"host": "192.0.2.1", "reachable": True, "latency_ms": 10.0},
                {"host": "192.0.2.2", "reachable": True, "latency_ms": 5.0},
            ],
            [
                {"host": "192.0.2.1", "reachable": False, "latency_ms": None},
                {"host": "192.0.2.2", "reachable": True, "latency_ms": 25.0},
            ],
            [
                {"host": "192.0.2.1", "reachable": True, "latency_ms": 30.0},
                {"host": "192.0.2.2", "reachable": True, "latency_ms": 5.0},
            ],
        ]
        with patch(
            "twn_toolkit.automation_types.condition_types.network_triggers.ping_hosts",
            side_effect=rounds,
        ):
            result = condition.evaluate(
                {
                    "targets": "WAN = 192.0.2.1\nLAN = 192.0.2.2",
                    "timeout": 1,
                    "probe_count": 3,
                    "max_packet_loss_pct": 20,
                    "max_latency_ms": 15,
                    "max_jitter_ms": 10,
                    "failure_mode": "at_least",
                    "failure_count": 2,
                }
            )

        self.assertTrue(result.met)
        self.assertEqual(result.evidence["failed"], 2)
        self.assertEqual(result.evidence["targets"][0]["packet_loss_pct"], 33.3)
        self.assertEqual(result.evidence["targets"][0]["average_latency_ms"], 20.0)
        self.assertEqual(result.evidence["targets"][0]["jitter_ms"], 20.0)
        self.assertIn("Packet loss", result.evidence["targets"][0]["reason"])
        self.assertIn("Jitter", result.evidence["targets"][1]["reason"])

    def test_dns_performance_counts_slow_and_failed_queries(self) -> None:
        condition = AUTOMATION_REGISTRY.conditions["dns.performance"]
        results = [
            {
                "host": "example.com", "host_label": "", "server": "192.0.2.53",
                "server_label": "Fast", "record_type": "A", "status": "success",
                "answers": ["192.0.2.10"], "response_ms": 24.0,
            },
            {
                "host": "example.com", "host_label": "", "server": "198.51.100.53",
                "server_label": "Slow", "record_type": "A", "status": "success",
                "answers": ["192.0.2.10"], "response_ms": 175.0,
            },
            {
                "host": "example.net", "host_label": "", "server": "192.0.2.53",
                "server_label": "Fast", "record_type": "A", "status": "Timeout",
                "answers": [], "response_ms": 1000.0, "error": "timed out",
            },
            {
                "host": "example.net", "host_label": "", "server": "198.51.100.53",
                "server_label": "Slow", "record_type": "A", "status": "success",
                "answers": ["192.0.2.20"], "response_ms": 30.0,
            },
        ]
        with patch(
            "twn_toolkit.automation_types.condition_types.network_triggers.dns_lookup_matrix",
            return_value=results,
        ):
            result = condition.evaluate(
                {
                    "hosts": "example.com\nexample.net",
                    "servers": "192.0.2.53\n198.51.100.53",
                    "record_type": "A",
                    "timeout": 1,
                    "response_limit_ms": 100,
                    "failure_mode": "at_least",
                    "failure_count": 2,
                }
            )

        self.assertTrue(result.met)
        self.assertEqual(result.evidence["failed"], 2)
        self.assertTrue(result.evidence["checks"][1]["slow"])
        self.assertIn("175 ms exceeds 100 ms", result.evidence["checks"][1]["reason"])
        self.assertEqual(result.evidence["checks"][2]["reason"], "timed out")


class AutomationUiRegressionTests(unittest.TestCase):
    def test_create_card_css_does_not_style_nested_schedule_summaries(self) -> None:
        stylesheet = (
            Path(__file__).resolve().parents[1]
            / "twn_toolkit"
            / "static"
            / "styles.css"
        ).read_text(encoding="utf-8")
        self.assertIn(".card-action-details > summary {", stylesheet)
        self.assertIn(".profile-create-details.card-action-details > summary {", stylesheet)
        self.assertNotIn(".card-action-details summary {", stylesheet)
        self.assertNotIn(".profile-create-details.card-action-details summary {", stylesheet)

    def test_live_ping_uses_a_target_snapshot_and_explicit_update_control(self) -> None:
        root = Path(__file__).resolve().parents[1] / "twn_toolkit"
        script = (root / "static" / "ping-tool.js").read_text(encoding="utf-8")
        template = (root / "templates" / "tools" / "ping.html").read_text(
            encoding="utf-8"
        )
        results_template = (
            root / "templates" / "tools" / "_ping_results.html"
        ).read_text(encoding="utf-8")
        composed_template = template + results_template
        self.assertIn("form.dataset.sessionStartUrl", script)
        self.assertIn("activeSession.targets_url", script)
        self.assertIn('id="ping-update-targets"', template)
        self.assertNotIn('id="ping-minimize"', template)
        self.assertIn('id="ping-timeout"', template)
        self.assertIn("data-timeout", template)
        self.assertIn("Existing history was preserved", script)
        self.assertIn("loadNewSamples", script)
        self.assertIn("last_duration_ms", script)
        self.assertIn("This run continues while you navigate", script)
        self.assertNotIn('navigator.sendBeacon(form.dataset.activityUrl', script)
        self.assertIn("const historySampleBudget = 500_000", script)
        self.assertIn("trimHistoryToBudget(series)", script)
        self.assertIn('id="ping-host-list"', composed_template)
        self.assertIn('id="ping-graph-grid"', composed_template)
        self.assertIn('aria-multiselectable="true"', composed_template)
        self.assertIn("const selectedHosts = new Set()", script)
        self.assertIn("const graphViews = new Map()", script)
        self.assertIn("graphViews.forEach", script)
        self.assertNotIn("maxSelectedGraphs", script)
        self.assertNotIn("of 8", script)
        self.assertEqual(script.count("totals.total += 1;"), 1)


if __name__ == "__main__":
    unittest.main()

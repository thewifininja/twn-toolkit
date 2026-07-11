from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from twn_toolkit.automation import AutomationStore
from twn_toolkit.schedule_tools import (
    schedule_occurrence,
    schedule_preview,
    schedule_should_fire,
    validate_schedule_config,
)


def timestamp(value: str) -> float:
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()


class ScheduleToolTests(unittest.TestCase):
    def config(self, rules, **overrides):
        return {
            "timezone": "UTC",
            "missed_policy": "grace",
            "grace_minutes": 30,
            "rules": rules,
            **overrides,
        }

    def test_weekly_condition_can_hold_multiple_rules(self) -> None:
        config = self.config(
            [
                {"id": "monday", "type": "weekly", "weekdays": [0], "time": "15:00"},
                {"id": "tuesday", "type": "weekly", "weekdays": [1], "time": "17:00"},
            ]
        )
        preview = schedule_preview(config, timestamp("2026-07-13T12:00:00"), 3)
        self.assertEqual(
            [item["scheduled_utc"] for item in preview],
            [
                "2026-07-13T15:00:00+00:00",
                "2026-07-14T17:00:00+00:00",
                "2026-07-20T15:00:00+00:00",
            ],
        )

    def test_third_weekday_and_interval_week_rules(self) -> None:
        third_wednesday = self.config(
            [{"id": "third", "type": "monthly_weekday", "ordinal": 3, "weekday": 2, "time": "01:00"}]
        )
        every_other_thursday = self.config(
            [{"id": "alternate", "type": "interval_weeks", "interval": 2, "anchor_date": "2026-07-16", "time": "16:03"}]
        )
        self.assertEqual(
            schedule_occurrence(third_wednesday, timestamp("2026-07-01T00:00:00"))["scheduled_utc"],
            "2026-07-15T01:00:00+00:00",
        )
        self.assertEqual(
            schedule_occurrence(every_other_thursday, timestamp("2026-07-17T00:00:00"))["scheduled_utc"],
            "2026-07-30T16:03:00+00:00",
        )

    def test_simultaneous_rules_collapse_into_one_occurrence(self) -> None:
        config = self.config(
            [
                {"id": "daily", "type": "daily", "time": "09:00"},
                {"id": "weekly", "type": "weekly", "weekdays": [0], "time": "09:00"},
            ]
        )
        occurrence = schedule_occurrence(config, timestamp("2026-07-13T08:00:00"))
        self.assertEqual(occurrence["rule_ids"], ["daily", "weekly"])

    def test_dst_gap_moves_to_next_valid_local_minute(self) -> None:
        config = self.config(
            [{"id": "gap", "type": "once", "date": "2026-03-08", "time": "02:30"}],
            timezone="America/New_York",
        )
        occurrence = schedule_occurrence(config, timestamp("2026-03-08T00:00:00"))
        self.assertEqual(occurrence["scheduled_local"], "2026-03-08T03:00:00-04:00")

    def test_missed_run_policies(self) -> None:
        scheduled = timestamp("2026-07-11T12:00:00")
        rules = [{"id": "daily", "type": "daily", "time": "09:00"}]
        self.assertTrue(schedule_should_fire(self.config(rules, missed_policy="run_late"), scheduled, scheduled + 86400))
        self.assertTrue(schedule_should_fire(self.config(rules, missed_policy="grace", grace_minutes=30), scheduled, scheduled + 1200))
        self.assertFalse(schedule_should_fire(self.config(rules, missed_policy="grace", grace_minutes=30), scheduled, scheduled + 3600))
        self.assertFalse(schedule_should_fire(self.config(rules, missed_policy="skip"), scheduled, scheduled + 61))

    def test_schedule_validation_rejects_missing_rules(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one schedule rule"):
            validate_schedule_config(self.config([]))


class ScheduleAutomationStoreTests(unittest.TestCase):
    def _shared_store(self, instance: str):
        store = AutomationStore(instance, "secret")
        condition_id = store.save_condition_definition(
            name="Daily calendar",
            type_id="schedule.calendar",
            config={
                "timezone": "UTC",
                "missed_policy": "grace",
                "grace_minutes": 30,
                "rules": [{"id": "daily", "type": "daily", "time": "12:00"}],
            },
        )
        action_id = store.save_action_definition(
            name="Collect", type_id="test.action", config={"password": "secret"}
        )
        return store, condition_id, action_id

    def test_one_time_schedule_is_consumed_once_per_automation(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = AutomationStore(instance, "secret")
            condition_id = store.save_condition_definition(
                name="One time",
                type_id="schedule.calendar",
                config={
                    "timezone": "UTC",
                    "missed_policy": "grace",
                    "grace_minutes": 30,
                    "rules": [{"id": "once", "type": "once", "date": "2026-07-11", "time": "12:00"}],
                },
            )
            action_id = store.save_action_definition(
                name="Collect",
                type_id="test.action",
                config={"password": "secret"},
            )
            automation_id = store.save(
                name="Scheduled collection",
                interval_seconds=30,
                trigger_after=3,
                recover_after=3,
                cooldown_seconds=300,
                condition_definition_id=condition_id,
                action_definition_ids=[action_id],
                created_by="admin",
            )
            with patch("twn_toolkit.automation.time.time", return_value=timestamp("2026-07-11T11:00:00")):
                store.set_enabled(automation_id, True)
            armed = store.get(automation_id)
            self.assertEqual(armed["state"], "scheduled")
            self.assertEqual(armed["next_check_at"], timestamp("2026-07-11T12:00:00"))
            updated, result, should_fire = store.record_schedule_occurrence(
                automation_id, now=timestamp("2026-07-11T12:00:01")
            )
            self.assertTrue(should_fire)
            self.assertEqual(result.status, "scheduled")
            self.assertEqual(updated["state"], "completed")
            self.assertFalse(updated["enabled"])
            self.assertIsNone(updated["next_check_at"])
            self.assertEqual(store.claim_due(), [])

    def test_shared_schedule_is_consumed_independently_per_automation(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store, condition_id, action_id = self._shared_store(instance)
            ids = [
                store.save(
                    name=name,
                    interval_seconds=30,
                    trigger_after=1,
                    recover_after=1,
                    cooldown_seconds=0,
                    condition_definition_id=condition_id,
                    action_definition_ids=[action_id],
                    created_by="admin",
                )
                for name in ("First workflow", "Second workflow")
            ]
            with patch("twn_toolkit.automation.time.time", return_value=timestamp("2026-07-11T11:00:00")):
                for automation_id in ids:
                    store.set_enabled(automation_id, True)
            due = timestamp("2026-07-11T12:00:01")
            with patch("twn_toolkit.automation.time.time", return_value=due):
                self.assertEqual({item["id"] for item in store.claim_due()}, set(ids))
                self.assertEqual(store.claim_due(), [])
            first, _result, fired = store.record_schedule_occurrence(ids[0], now=due)
            self.assertTrue(fired)
            self.assertEqual(first["next_check_at"], timestamp("2026-07-12T12:00:00"))
            self.assertEqual(
                store.get(ids[1])["pending_schedule_at"],
                timestamp("2026-07-11T12:00:00"),
            )

    def test_missed_recurring_occurrence_skips_backlog_and_advances_to_future(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store, condition_id, action_id = self._shared_store(instance)
            automation_id = store.save(
                name="Skip stale runs",
                interval_seconds=30,
                trigger_after=1,
                recover_after=1,
                cooldown_seconds=0,
                condition_definition_id=condition_id,
                action_definition_ids=[action_id],
                created_by="admin",
            )
            with patch("twn_toolkit.automation.time.time", return_value=timestamp("2026-07-10T11:00:00")):
                store.set_enabled(automation_id, True)
            updated, result, fired = store.record_schedule_occurrence(
                automation_id, now=timestamp("2026-07-11T13:00:00")
            )
            self.assertFalse(fired)
            self.assertEqual(result.status, "skipped")
            self.assertEqual(updated["next_check_at"], timestamp("2026-07-12T12:00:00"))

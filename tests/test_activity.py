from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from twn_toolkit.activity import ActivityStore


def _increment_activity_many_times(instance: str, count: int) -> None:
    store = ActivityStore(instance)
    for _ in range(count):
        store.increment(
            "ping",
            "probes_sent",
            user_id="concurrent-user",
            username="Concurrent User",
        )


class ActivityStoreTests(unittest.TestCase):
    def test_increment_tracks_global_and_user_counters(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ActivityStore(instance)

            store.increment(
                "ping",
                "probes_sent",
                5,
                user_id="user-1",
                username="NetOps",
            )
            store.increment(
                "ping",
                "replies_received",
                4,
                user_id="user-1",
                username="NetOps",
            )
            summary = store.summary()

        self.assertEqual(summary["counters"]["ping"]["probes_sent"], 5)
        self.assertEqual(summary["counters"]["ping"]["replies_received"], 4)
        self.assertIn("dns", summary["counters"])
        self.assertIn("speedtest", summary["counters"])
        self.assertEqual(summary["cards"][0]["primary"], 5)
        self.assertTrue(any(card["metric"] == "dns" for card in summary["cards"]))
        self.assertTrue(any(card["metric"] == "speedtest" for card in summary["cards"]))
        self.assertEqual(summary["scoreboard"][0]["username"], "NetOps")
        self.assertEqual(summary["scoreboard"][0]["actions"], 0)
        self.assertEqual(
            [metric["key"] for metric in summary["scoreboard"][0]["metrics"]],
            ["ping.probes_sent", "ping.replies_received"],
        )

    def test_record_event_updates_counters_and_recent_activity(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ActivityStore(instance)

            store.record_event(
                "Fortinet",
                "Tested FortiGate profile",
                "Connection OK",
                counters={"fortinet": {"api_calls": 1}},
                user_id="admin",
                username="admin",
                count_action=True,
            )
            summary = store.summary()

        self.assertEqual(summary["counters"]["fortinet"]["api_calls"], 1)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["scoreboard"][0]["username"], "admin")
        self.assertEqual(summary["scoreboard"][0]["actions"], 1)
        self.assertEqual(summary["recent"][0]["title"], "Tested FortiGate profile")
        self.assertEqual(summary["recent"][0]["username"], "admin")

    def test_scoreboard_can_rank_by_raw_metric(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ActivityStore(instance)
            store.record_event(
                "Reachability",
                "Pinged",
                counters={"ping": {"probes_sent": 25}},
                user_id="ping-user",
                username="Ping User",
                count_action=True,
            )
            store.record_event(
                "Fortinet",
                "Tested FortiGate",
                counters={"fortinet": {"api_calls": 3}},
                user_id="api-user",
                username="API User",
                count_action=True,
            )

            summary = store.summary("ping.probes_sent")

        self.assertEqual(summary["scoreboard_rank"]["key"], "ping.probes_sent")
        self.assertEqual(summary["scoreboard"][0]["username"], "Ping User")
        self.assertEqual(summary["scoreboard"][0]["rank_value"], 25)
        self.assertEqual(summary["scoreboard"][0]["metrics"][0]["label"], "Ping probes sent")

    def test_reset_metric_clears_global_and_user_values(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ActivityStore(instance)
            store.record_event(
                "Infrastructure",
                "Ran SNMP test",
                counters={"snmp": {"polls": 3}},
                user_id="admin",
                username="admin",
                count_action=True,
            )

            store.reset_metric("snmp")
            summary = store.summary()

        self.assertEqual(summary["counters"]["snmp"]["polls"], 0)
        self.assertEqual(summary["scoreboard"][0]["counters"]["snmp"]["polls"], 0)
        self.assertEqual(summary["scoreboard"][0]["actions"], 1)

    def test_reset_user_actions_clears_only_that_score(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ActivityStore(instance)
            store.record_event(
                "Test",
                "User one action",
                counters={"ping": {"probes_sent": 7}},
                user_id="one",
                username="One",
                count_action=True,
            )
            store.record_event("Test", "User two action", user_id="two", username="Two", count_action=True)

            store.reset_user_actions("one")
            summary = store.summary()

        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(len(summary["scoreboard"]), 2)
        self.assertEqual(summary["scoreboard"][0]["username"], "Two")
        self.assertEqual(summary["scoreboard"][0]["actions"], 1)
        self.assertEqual(summary["scoreboard"][1]["username"], "One")
        self.assertEqual(summary["scoreboard"][1]["actions"], 0)
        self.assertEqual(summary["scoreboard"][1]["metrics"][0]["value"], 7)

    def test_reset_all_user_actions_clears_scoreboard(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ActivityStore(instance)
            store.record_event("Test", "User one action", user_id="one", username="One", count_action=True)
            store.record_event("Test", "User two action", user_id="two", username="Two", count_action=True)

            store.reset_all_user_actions()
            summary = store.summary()

        self.assertEqual(summary["counters"]["actions"]["total"], 0)
        self.assertEqual(summary["scoreboard"], [])

    def test_concurrent_processes_do_not_lose_counter_updates(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            context = multiprocessing.get_context("fork" if hasattr(os, "fork") else "spawn")
            processes = [
                context.Process(target=_increment_activity_many_times, args=(instance, 40))
                for _ in range(4)
            ]

            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=10)

            self.assertTrue(all(process.exitcode == 0 for process in processes))
            summary = ActivityStore(instance).summary()

        self.assertEqual(summary["counters"]["ping"]["probes_sent"], 160)
        self.assertEqual(
            summary["scoreboard"][0]["counters"]["ping"]["probes_sent"],
            160,
        )

    def test_malformed_legacy_activity_file_does_not_block_sqlite_writes(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            path = Path(instance) / "activity.json"
            path.write_text('{"totals":', encoding="utf-8")
            store = ActivityStore(instance)

            empty_summary = store.summary()
            store.increment("dns", "queries", 2)
            summary = store.summary()

        self.assertEqual(empty_summary["counters"]["dns"]["queries"], 0)
        self.assertEqual(summary["counters"]["dns"]["queries"], 2)
        self.assertTrue(store.path.name.endswith(".sqlite3"))

    def test_legacy_json_is_imported_once_as_lifetime_history(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            legacy_path = Path(instance) / "activity.json"
            legacy_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "totals": {
                            "actions": {"total": 2},
                            "ping": {"probes_sent": 9, "replies_received": 8},
                        },
                        "users": {
                            "legacy-user": {
                                "username": "Legacy User",
                                "counters": {
                                    "actions": {"total": 2},
                                    "ping": {"probes_sent": 7, "replies_received": 6},
                                },
                            }
                        },
                        "recent": [
                            {
                                "timestamp": "2025-01-02T03:04:05",
                                "category": "Reachability",
                                "title": "Legacy ping",
                                "detail": "Imported",
                                "user_id": "legacy-user",
                                "username": "Legacy User",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            store = ActivityStore(instance)

            lifetime = store.summary(window="lifetime")
            recent_window = store.summary(window="hour")
            legacy_path.write_text("{}", encoding="utf-8")
            imported_once = ActivityStore(instance).summary(window="lifetime")

        self.assertEqual(lifetime["counters"]["ping"]["probes_sent"], 9)
        self.assertEqual(lifetime["scoreboard"][0]["username"], "Legacy User")
        self.assertEqual(lifetime["scoreboard"][0]["actions"], 2)
        self.assertEqual(lifetime["recent"][0]["title"], "Legacy ping")
        self.assertEqual(recent_window["counters"]["ping"]["probes_sent"], 0)
        self.assertEqual(imported_once["counters"]["ping"]["probes_sent"], 9)

    def test_summary_filters_metrics_scoreboard_and_events_by_window(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ActivityStore(instance)
            with patch("twn_toolkit.activity.time.time", return_value=1_000):
                store.record_event(
                    "Reachability",
                    "Old ping",
                    counters={"ping": {"probes_sent": 4}},
                    user_id="user",
                    username="User",
                    count_action=True,
                )
            with patch("twn_toolkit.activity.time.time", return_value=8_200):
                store.record_event(
                    "Reachability",
                    "Recent ping",
                    counters={"ping": {"probes_sent": 3}},
                    user_id="user",
                    username="User",
                    count_action=True,
                )
                hour = store.summary(window="hour")
                day = store.summary(window="day")

        self.assertEqual(hour["window"]["key"], "hour")
        self.assertEqual(hour["counters"]["ping"]["probes_sent"], 3)
        self.assertEqual(hour["scoreboard"][0]["actions"], 1)
        self.assertEqual([event["title"] for event in hour["recent"]], ["Recent ping"])
        self.assertEqual(day["counters"]["ping"]["probes_sent"], 7)
        self.assertEqual(day["scoreboard"][0]["actions"], 2)

    def test_custom_range_uses_exact_start_and_end_for_all_dashboard_data(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ActivityStore(instance)
            with patch("twn_toolkit.activity.time.time", return_value=1_000):
                store.record_event(
                    "Test",
                    "Before range",
                    counters={"dns": {"queries": 2}},
                    user_id="early",
                    username="Early User",
                    count_action=True,
                )
            with patch("twn_toolkit.activity.time.time", return_value=2_000):
                store.record_event(
                    "Test",
                    "Inside range",
                    counters={"dns": {"queries": 5}},
                    user_id="inside",
                    username="Inside User",
                    count_action=True,
                )
            with patch("twn_toolkit.activity.time.time", return_value=3_000):
                store.record_event(
                    "Test",
                    "After range",
                    counters={"dns": {"queries": 9}},
                    user_id="late",
                    username="Late User",
                    count_action=True,
                )
            start = datetime.fromtimestamp(1_500).strftime("%Y-%m-%dT%H:%M:%S")
            end = datetime.fromtimestamp(2_500).strftime("%Y-%m-%dT%H:%M:%S")

            custom = store.summary(
                "dns.queries", "custom", custom_start=start, custom_end=end
            )

        self.assertEqual(custom["window"]["key"], "custom")
        self.assertEqual(custom["window"]["range_start"], start)
        self.assertEqual(custom["window"]["range_end"], end)
        self.assertEqual(custom["counters"]["dns"]["queries"], 5)
        self.assertEqual([user["username"] for user in custom["scoreboard"]], ["Inside User"])
        self.assertEqual([event["title"] for event in custom["recent"]], ["Inside range"])

    def test_invalid_custom_range_returns_a_safe_default_and_error(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            with patch("twn_toolkit.activity.time.time", return_value=10_000):
                summary = ActivityStore(instance).summary(
                    window="custom",
                    custom_start="2026-07-10T12:00:00",
                    custom_end="2026-07-09T12:00:00",
                )

        self.assertTrue(summary["window"]["error"])
        start = datetime.fromisoformat(summary["window"]["range_start"])
        end = datetime.fromisoformat(summary["window"]["range_end"])
        self.assertEqual(int((end - start).total_seconds()), 3_600)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.live_tools import LiveToolRunner, LiveToolStore
from twn_toolkit.profiles import SNMPCredentialProfileStore, SNMPHostProfileStore


class LiveToolStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = LiveToolStore(self.temporary.name)
        self.targets = [
            {"host": "127.0.0.1", "label": "Loopback"},
            {"host": "192.0.2.1", "label": "Silent"},
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_session(self) -> dict[str, object]:
        return self.store.create_ping_session(
            user_id="operator-1",
            username="operator",
            title="Branch reachability",
            targets=self.targets,
            interval=2,
            timeout=1,
        )

    def test_sessions_are_owned_and_can_be_stopped(self) -> None:
        session = self.create_session()

        self.assertEqual(
            [item["id"] for item in self.store.sessions_for_user("operator-1")],
            [session["id"]],
        )
        self.assertEqual(self.store.sessions_for_user("operator-2"), [])
        self.assertIsNone(
            self.store.stop_session(str(session["id"]), user_id="operator-2")
        )

        stopped = self.store.stop_session(
            str(session["id"]), user_id="operator-1"
        )
        self.assertEqual(stopped["state"], "stopped")
        self.assertEqual(self.store.sessions_for_user("operator-1"), [])

    def test_claim_round_history_and_revision_updates(self) -> None:
        session = self.create_session()
        claimed = self.store.claim_due()
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["id"], session["id"])
        self.assertEqual(self.store.claim_due(), [])
        self.store.release_stale_claims()
        self.assertEqual(len(self.store.claim_due()), 1)
        self.store.release_stale_claims()

        recorded = self.store.record_ping_round(
            str(session["id"]),
            revision=int(session["revision"]),
            sampled_at=1000.0,
            duration_ms=25.0,
            engine="ping",
            results=[
                {"host": "127.0.0.1", "reachable": True, "latency_ms": 0.2},
                {"host": "192.0.2.1", "reachable": False, "latency_ms": None},
            ],
        )
        self.assertTrue(recorded)
        page = self.store.ping_samples(
            str(session["id"]), user_id="operator-1"
        )
        self.assertEqual(len(page["samples"]), 2)
        self.assertEqual(page["samples"][0]["label"], "Loopback")
        detail = self.store.get_session(
            str(session["id"]), user_id="operator-1"
        )
        self.assertEqual(detail["rounds_completed"], 1)
        self.assertEqual(detail["last_up_count"], 1)

        updated = self.store.update_ping_session(
            str(session["id"]),
            user_id="operator-1",
            targets=[self.targets[0]],
            interval=5,
            timeout=2,
        )
        self.assertEqual(updated["revision"], 2)
        self.assertEqual(updated["config"]["interval"], 5)

    def test_runner_records_a_ping_round(self) -> None:
        session = self.create_session()
        claimed = self.store.claim_due()[0]
        results = [
            {"host": "127.0.0.1", "reachable": True, "latency_ms": 0.1},
            {"host": "192.0.2.1", "reachable": False, "latency_ms": None},
        ]
        with patch("twn_toolkit.live_tools.ping_hosts", return_value=results), patch(
            "twn_toolkit.live_tools.ping_engine_capability",
            return_value={"engine": "fping"},
        ):
            LiveToolRunner(self.store).process(claimed)

        detail = self.store.get_session(
            str(session["id"]), user_id="operator-1"
        )
        self.assertEqual(detail["rounds_completed"], 1)
        self.assertEqual(detail["probes_sent"], 2)
        self.assertEqual(detail["replies_received"], 1)
        self.assertEqual(detail["last_engine"], "fping")

    def test_runner_records_persistent_snmp_samples_without_storing_credentials(
        self,
    ) -> None:
        SNMPCredentialProfileStore(self.temporary.name).upsert(
            {
                "name": "Lab",
                "version": "v2c",
                "community": "private-community",
            }
        )
        SNMPHostProfileStore(self.temporary.name).upsert(
            {
                "name": "Core",
                "host": "192.0.2.10",
                "port": 161,
                "timeout": 2,
                "retries": 1,
                "credential_name": "Lab",
            }
        )
        session = self.store.create_snmp_interface_session(
            user_id="operator-1",
            username="operator",
            title="Core bandwidth",
            targets=[
                {
                    "host_name": "Core",
                    "host_address": "192.0.2.10",
                    "interface_index": 2,
                    "interface_label": "port2",
                    "interface_alias": "Uplink",
                    "interface_description": "port2",
                    "interface_oper_status": "up",
                    "interface_speed_bps": 1_000_000_000,
                }
            ],
            interval=5,
            round_timeout=20,
        )
        self.assertNotIn(
            b"private-community", self.store.path.read_bytes()
        )
        sample = {
            "host_name": "Core",
            "host": "192.0.2.10",
            "interface_index": 2,
            "sampled_at_ms": 1_000,
            "elapsed_ms": 4.2,
            "counter_bits": 64,
            "input_octets": "9007199254740993",
            "output_octets": "9007199254741993",
            "speed_bps": 1_000_000_000,
            "admin_status": "up",
            "oper_status": "up",
            "sys_uptime": 100,
            "counter_discontinuity": 0,
            "input_errors": 0,
            "output_errors": 0,
            "input_discards": 0,
            "output_discards": 0,
            "poll_count": 1,
        }
        claimed = self.store.claim_due()[0]
        with patch(
            "twn_toolkit.live_tools.poll_snmp_interfaces",
            return_value=[{"status": "success", "sample": sample}],
        ):
            LiveToolRunner(self.store).process(claimed)

        detail = self.store.get_session(
            str(session["id"]), user_id="operator-1"
        )
        self.assertEqual(detail["rounds_completed"], 1)
        self.assertEqual(detail["last_up_count"], 1)
        self.assertEqual(detail["last_engine"], "SNMP")
        page = self.store.snmp_interface_samples(
            str(session["id"]), user_id="operator-1"
        )
        self.assertEqual(page["samples"][0]["target_key"], "Core::2")
        self.assertEqual(
            page["samples"][0]["sample"]["input_octets"],
            "9007199254740993",
        )


class LiveToolRouteTests(unittest.TestCase):
    def test_ping_session_lifecycle_and_tray_payload(self) -> None:
        accelerated = {
            "engine": "fping",
            "accelerated": True,
            "target_limit": 250,
            "detail": "available",
            "path": "/usr/bin/fping",
        }
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            with patch(
                "twn_toolkit.ping_routes.ping_engine_capability",
                return_value=accelerated,
            ):
                started = client.post(
                    "/tools/ping/sessions",
                    json={
                        "hosts": "Loopback = 127.0.0.1",
                        "interval": 2,
                        "timeout": 0.25,
                        "title": "Local checks",
                    },
                )
                self.assertEqual(started.status_code, 201)
                session = started.get_json()["session"]
                self.assertEqual(session["title"], "Local checks")
                self.assertEqual(session["config"]["targets"][0]["label"], "Loopback")
                self.assertIn("?session=", session["restore_url"])

                listed = client.get("/tools/live-sessions")
                self.assertEqual(listed.status_code, 200)
                tray_session = listed.get_json()["sessions"][0]
                self.assertNotIn("config", tray_session)
                self.assertNotIn("_user_id", tray_session)

                updated = client.post(
                    session["targets_url"],
                    json={
                        "hosts": "Loopback = 127.0.0.1\nDNS = 192.0.2.53",
                        "interval": 5,
                        "timeout": 0.5,
                    },
                )
                self.assertEqual(updated.status_code, 200)
                self.assertEqual(
                    updated.get_json()["session"]["target_count"], 2
                )

                stopped = client.post(session["stop_url"])
                self.assertEqual(stopped.status_code, 200)
                self.assertEqual(stopped.get_json()["session"]["state"], "stopped")
                self.assertEqual(
                    client.get("/tools/live-sessions").get_json()["sessions"], []
                )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.snmp_tools import (
    _append_calculated_rows,
    _interface_speed,
    _interface_status,
    parse_oid_profile,
    parse_snmp_numeric,
    resolve_oid_selection,
    validate_snmp_credential,
)


class SNMPToolTests(unittest.TestCase):
    def test_interface_helpers_prefer_high_capacity_speed_and_decode_status(self) -> None:
        self.assertEqual(_interface_speed("1000", "100000000"), 1_000_000_000)
        self.assertEqual(_interface_speed(None, "100000000"), 100_000_000)
        self.assertIsNone(_interface_speed("0", "0"))
        self.assertEqual(_interface_status("1"), "up")
        self.assertEqual(_interface_status("7"), "lower layer down")
        self.assertEqual(_interface_status(None), "unknown")

    def test_shared_snmp_numeric_decoder_handles_common_scalar_renderings(self) -> None:
        self.assertEqual(parse_snmp_numeric("42"), 42)
        self.assertEqual(parse_snmp_numeric("(12345) 0:02:03.45"), 12345)
        self.assertEqual(parse_snmp_numeric("Gauge32: 87"), 87)
        self.assertIsNone(parse_snmp_numeric("not-a-number"))

    def test_parses_get_and_walk_oid_entries(self) -> None:
        self.assertEqual(
            parse_oid_profile(
                "System Name = 1.3.6.1.2.1.1.5.0\n"
                "walk: Interface Names = .1.3.6.1.2.1.31.1.1.1.1"
            ),
            [
                {
                    "label": "System Name",
                    "oid": "1.3.6.1.2.1.1.5.0",
                    "operation": "get",
                },
                {
                    "label": "Interface Names",
                    "oid": "1.3.6.1.2.1.31.1.1.1.1",
                    "operation": "walk",
                },
            ],
        )
        with self.assertRaises(ToolInputError):
            parse_oid_profile("sysName = SNMPv2-MIB::sysName.0")

    def test_parses_and_calculates_derived_oid_values(self) -> None:
        entries = parse_oid_profile(
            "Current Memory KB = 1.3.6.1.4.1.999.1.0\n"
            "Total Memory KB = 1.3.6.1.4.1.999.2.0\n"
            "calc: Memory Usage % = percent(Current Memory KB, Total Memory KB)"
        )
        self.assertEqual(entries[-1]["operation"], "calculate")
        self.assertEqual(entries[-1]["oid"], "calc:Memory Usage %")
        selected = resolve_oid_selection(entries, "calc:Memory Usage %")
        self.assertEqual([entry["label"] for entry in selected], [
            "Current Memory KB", "Total Memory KB", "Memory Usage %",
        ])
        rows, error = _append_calculated_rows(
            [
                {"label": "Current Memory KB", "value": "524288"},
                {"label": "Total Memory KB", "value": "1048576"},
            ],
            entries,
        )
        self.assertEqual(error, "")
        self.assertEqual(rows[-1]["value"], "50")
        self.assertEqual(rows[-1]["source_values"]["Total Memory KB"], 1048576)

        with self.assertRaisesRegex(ToolInputError, "unknown value"):
            parse_oid_profile(
                "Used = 1.3.6.1.4.1.999.1.0\n"
                "calc: Usage = percent(Used, Missing)"
            )
        with self.assertRaisesRegex(ToolInputError, "walked OID"):
            parse_oid_profile(
                "walk: Ports = 1.3.6.1.2.1.2.2.1.8\n"
                "Total = 1.3.6.1.4.1.999.2.0\n"
                "calc: Usage = percent(Ports, Total)"
            )

    def test_validates_v3_security_and_preserves_saved_keys(self) -> None:
        existing = {
            "auth_key": "saved-auth",
            "priv_key": "saved-priv",
        }
        profile = validate_snmp_credential(
            {
                "name": "Secure",
                "version": "v3",
                "username": "snmp-user",
                "security_level": "authpriv",
                "auth_protocol": "sha256",
                "auth_key": "",
                "priv_protocol": "aes128",
                "priv_key": "",
            },
            existing,
        )
        self.assertEqual(profile["auth_key"], "saved-auth")
        self.assertEqual(profile["priv_key"], "saved-priv")

        with self.assertRaises(ToolInputError):
            validate_snmp_credential(
                {
                    "name": "Broken",
                    "version": "v3",
                    "username": "user",
                    "security_level": "authpriv",
                    "auth_protocol": "sha256",
                    "auth_key": "short",
                    "priv_protocol": "aes128",
                    "priv_key": "short",
                }
            )

    def test_profile_crud_mapping_and_runner(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            page = client.get("/tools/snmp-test")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"System Identity", page.data)
            self.assertIn(b"Interface Summary", page.data)

            response = client.post(
                "/tools/snmp-test/profiles/credentials",
                data={
                    "name": "Lab v2",
                    "version": "v2c",
                    "community": "private-community",
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("community", response.get_json()["profile"])

            response = client.post(
                "/tools/snmp-test/profiles/hosts",
                data={
                    "name": "Core Switch",
                    "host": "192.0.2.10",
                    "port": "161",
                    "timeout": "2",
                    "retries": "1",
                    "credential_name": "Lab v2",
                },
            )
            self.assertEqual(response.status_code, 200)

            response = client.post(
                "/tools/snmp-test/profiles/oids",
                data={
                    "name": "Names",
                    "source": "System Name = 1.3.6.1.2.1.1.5.0",
                },
            )
            self.assertEqual(response.status_code, 200)
            page = client.get("/tools/snmp-test")
            self.assertIn(b"Core Switch", page.data)
            self.assertIn(b"Names", page.data)
            self.assertNotIn(b"private-community", page.data)

            blocked = client.post(
                "/tools/snmp-test/profiles/credentials/delete",
                data={"name": "Lab v2"},
            )
            self.assertEqual(blocked.status_code, 409)

            fake_results = [
                {
                    "host_name": "Core Switch",
                    "host": "192.0.2.10",
                    "port": 161,
                    "credential_name": "Lab v2",
                    "profile_name": "Names",
                    "status": "success",
                    "error": "",
                    "elapsed_ms": 8.1,
                    "rows": [
                        {
                            "label": "System Name",
                            "operation": "get",
                            "oid": "1.3.6.1.2.1.1.5.0",
                            "value": "core-1",
                            "value_type": "OctetString",
                            "response_ms": 7.9,
                        }
                    ],
                }
            ]
            with patch("twn_toolkit.snmp_routes.run_snmp_tests", return_value=fake_results):
                response = client.post(
                    "/tools/snmp-test",
                    data={
                        "host_names": "Core Switch",
                        "oid_profile_names": "Names",
                    },
                )
            self.assertIn(b"core-1", response.data)
            self.assertNotIn(b"private-community", response.data)
            self.assertNotIn(b"<th>Operation</th>", response.data)
            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["snmp"]["polls"], 1)
            self.assertEqual(summary["counters"]["actions"]["total"], 1)
            self.assertEqual(summary["scoreboard"][0]["metrics"][0]["key"], "snmp.polls")
            self.assertEqual(summary["recent"][0]["title"], "Ran SNMP test")
            self.assertIn("1 value", summary["recent"][0]["detail"])

    def test_interface_discovery_sampling_and_monitor_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            client.post(
                "/tools/snmp-test/profiles/credentials",
                data={"name": "Lab", "version": "v2c", "community": "private"},
            )
            client.post(
                "/tools/snmp-test/profiles/hosts",
                data={
                    "name": "Core",
                    "host": "192.0.2.10",
                    "port": "161",
                    "timeout": "2",
                    "retries": "1",
                    "credential_name": "Lab",
                },
            )
            discovered = {
                "host_name": "Core",
                "host": "192.0.2.10",
                "interfaces": [{
                    "index": 2,
                    "name": "port2",
                    "description": "port2",
                    "alias": "Uplink",
                    "type": 6,
                    "admin_status": "up",
                    "oper_status": "up",
                    "speed_bps": 1_000_000_000,
                }],
                "poll_count": 8,
                "elapsed_ms": 22.4,
            }
            with patch("twn_toolkit.snmp_routes.discover_snmp_interfaces", return_value=discovered):
                response = client.post(
                    "/tools/snmp-test/interfaces", json={"host_name": "Core"}
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["interfaces"][0]["alias"], "Uplink")

            sampled = {
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
            with patch("twn_toolkit.snmp_routes.poll_snmp_interface", return_value=sampled):
                response = client.post(
                    "/tools/snmp-test/interface-sample",
                    json={"host_name": "Core", "interface_index": 2},
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["input_octets"], "9007199254740993")

            batch_result = [{"status": "success", "sample": sampled}]
            with patch(
                "twn_toolkit.snmp_routes.poll_snmp_interfaces",
                return_value=batch_result,
            ):
                response = client.post(
                    "/tools/snmp-test/interface-samples",
                    json={"targets": [{"host_name": "Core", "interface_index": 2}]},
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["results"], batch_result)

            payload = {
                "targets": [{
                    "host_name": "Core",
                    "interface_index": 2,
                    "interface_label": "port2 — Uplink",
                }],
                "interval": 5,
            }
            self.assertEqual(client.post("/tools/snmp-test/interface-monitor/start", json=payload).status_code, 200)
            self.assertEqual(client.post("/tools/snmp-test/interface-monitor/stop", json=payload).status_code, 200)
            self.assertEqual(
                client.post(
                    "/tools/snmp-test/interface-monitor/start",
                    json={**payload, "interval": 2},
                ).status_code,
                400,
            )
            self.assertEqual(
                client.post(
                    "/tools/snmp-test/interface-monitor/start",
                    json={**payload, "targets": payload["targets"] * 2},
                ).status_code,
                400,
            )
            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["snmp"]["polls"], 10)
            self.assertEqual(summary["counters"]["actions"]["total"], 1)
            self.assertEqual(summary["recent"][0]["title"], "Stopped SNMP bandwidth monitor")
            page = client.get("/tools/snmp-test")
            self.assertIn(b"Multi-interface bandwidth monitor", page.data)
            self.assertIn(b"Visible time range", page.data)
            self.assertIn(b"History navigation", page.data)
            self.assertIn(b"snmp-interface-monitor.js", page.data)


if __name__ == "__main__":
    unittest.main()

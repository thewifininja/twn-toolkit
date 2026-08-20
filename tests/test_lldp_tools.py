from __future__ import annotations

import json
import struct
import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit.app import create_app
from twn_toolkit.lldp_tools import (
    build_lldp_frame,
    default_persona,
    local_lldpd_shutdown_frame,
    normalize_neighbors,
    parse_custom_tlvs,
    preview_persona,
    preferred_interface,
)


INTERFACES = [{"name": "en7", "mac": "02:11:22:33:44:55"}]


class LLDPToolTests(unittest.TestCase):
    def _persona(self, preset: str = "generic"):
        with (
            patch("twn_toolkit.lldp_tools.available_interfaces", return_value=INTERFACES),
            patch("twn_toolkit.lldp_tools.interface_mac", return_value=INTERFACES[0]["mac"]),
        ):
            return default_persona(preset=preset, interface="en7")

    def _build(self, persona, *, shutdown: bool = False):
        with (
            patch("twn_toolkit.lldp_tools.available_interfaces", return_value=INTERFACES),
            patch("twn_toolkit.lldp_tools.interface_mac", return_value=INTERFACES[0]["mac"]),
        ):
            return build_lldp_frame(persona, interface="en7", shutdown=shutdown)

    def test_generic_frame_has_mandatory_tlvs_and_shutdown_ttl(self) -> None:
        persona = self._persona()
        frame, decoded = self._build(persona)
        self.assertEqual(frame[:6].hex(), "0180c200000e")
        self.assertEqual(frame[6:12].hex(), "021122334455")
        self.assertEqual(frame[12:14].hex(), "88cc")
        self.assertGreaterEqual(len(frame), 60)
        self.assertEqual([item["type"] for item in decoded[:3]], [1, 2, 3])
        shutdown, shutdown_tlvs = self._build(persona, shutdown=True)
        offset = 14
        for expected_type in (1, 2):
            header = struct.unpack_from("!H", shutdown, offset)[0]
            self.assertEqual(header >> 9, expected_type)
            offset += 2 + (header & 0x1FF)
        ttl_header = struct.unpack_from("!H", shutdown, offset)[0]
        self.assertEqual(ttl_header >> 9, 3)
        self.assertEqual(shutdown[offset + 2 : offset + 4], b"\0\0")
        self.assertEqual([item["type"] for item in shutdown_tlvs], [1, 2, 3, 0])

    def test_phone_preset_adds_med_capability_and_unknown_voice_policy(self) -> None:
        persona = self._persona("phone")
        frame, decoded = self._build(persona)
        self.assertIn("LLDP-MED capabilities", [item["label"] for item in decoded])
        self.assertIn("LLDP-MED voice policy", [item["label"] for item in decoded])
        self.assertIn(bytes.fromhex("0012bb02"), frame)

    def test_source_mac_override_controls_ethernet_header(self) -> None:
        persona = self._persona("switch")
        persona["source_mac"] = "02:aa:bb:cc:dd:ee"
        frame, _decoded = self._build(persona)
        self.assertEqual(frame[6:12].hex(), "02aabbccddee")

    @patch("twn_toolkit.lldp_tools._find_lldpcli", return_value="/usr/bin/lldpcli")
    @patch("twn_toolkit.lldp_tools.interface_mac", return_value="02:11:22:33:44:55")
    @patch("twn_toolkit.lldp_tools._run_lldpcli")
    def test_local_lldpd_shutdown_preserves_identity_subtypes(
        self, run_lldpcli, _interface_mac, _find_lldpcli
    ) -> None:
        run_lldpcli.return_value = {
            "lldp": [
                {
                    "interface": [
                        {
                            "name": "en7",
                            "chassis": [
                                {
                                    "id": [
                                        {"type": "mac", "value": "02:aa:bb:cc:dd:ee"}
                                    ]
                                }
                            ],
                            "port": [
                                {
                                    "id": [
                                        {"type": "ifname", "value": "en7"}
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        frame = local_lldpd_shutdown_frame("en7")
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame[6:12].hex(), "021122334455")
        offset = 14
        chassis_header = struct.unpack_from("!H", frame, offset)[0]
        self.assertEqual(frame[offset + 2], 4)
        offset += 2 + (chassis_header & 0x1FF)
        port_header = struct.unpack_from("!H", frame, offset)[0]
        self.assertEqual(frame[offset + 2], 5)
        offset += 2 + (port_header & 0x1FF)
        ttl_header = struct.unpack_from("!H", frame, offset)[0]
        self.assertEqual(ttl_header >> 9, 3)
        self.assertEqual(frame[offset + 2 : offset + 4], b"\x00\x00")

    def test_custom_organizational_tlv_is_bounded_and_encoded(self) -> None:
        persona = self._persona("switch")
        persona["custom_tlvs"] = parse_custom_tlvs("00:09:0f, 7, deadbeef")
        frame, decoded = self._build(persona)
        self.assertIn(bytes.fromhex("00090f07deadbeef"), frame)
        self.assertIn("Custom 00090f / 7", [item["label"] for item in decoded])

    def test_prefers_normal_wired_interface_over_macos_pseudo_interfaces(self) -> None:
        self.assertEqual(
            preferred_interface(
                [
                    {"name": "anpi1", "mac": "02:00:00:00:00:01"},
                    {"name": "en2", "mac": "02:00:00:00:00:02"},
                    {"name": "en0", "mac": "02:00:00:00:00:03"},
                ]
            ),
            "en0",
        )

    def test_normalizes_real_lldpcli_json0_shape(self) -> None:
        payload = {
            "lldp": [
                {
                    "interface": [
                        {
                            "name": "en0",
                            "via": "LLDP",
                            "age": "0 day, 00:00:10",
                            "chassis": [
                                {
                                    "id": [{"type": "mac", "value": "38:c0:ea:1d:35:88"}],
                                    "name": [{"value": "Office-231G-3"}],
                                    "descr": [{"value": "FortiAP-231G"}],
                                    "mgmt-ip": [{"value": "10.103.250.2"}],
                                    "capability": [
                                        {"type": "Bridge", "enabled": True},
                                        {"type": "Station", "enabled": False},
                                    ],
                                }
                            ],
                            "port": [
                                {
                                    "id": [{"type": "mac", "value": "38:c0:ea:1d:35:88"}],
                                    "descr": [{"value": "w10.254"}],
                                    "ttl": [{"value": "120"}],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        neighbors = normalize_neighbors(payload)
        self.assertEqual(len(neighbors), 1)
        self.assertEqual(neighbors[0]["system_name"], "Office-231G-3")
        self.assertEqual(neighbors[0]["management_addresses"], ["10.103.250.2"])
        self.assertEqual(neighbors[0]["capabilities"], ["Bridge"])


class LLDPRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app(self.temp.name)
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @patch(
        "twn_toolkit.lldp_routes.lldpcli_capability",
        return_value={
            "available": True,
            "connected": True,
            "version": "1.0.22",
            "message": "Connected",
        },
    )
    @patch(
        "twn_toolkit.lldp_routes.read_neighbors",
        return_value=[
            {
                "interface": "en7",
                "via": "LLDP",
                "age": "10 seconds",
                "system_name": "Switch-1",
                "system_description": "Lab switch",
                "chassis_id": "02:aa:bb:cc:dd:ee",
                "port_id": "port1",
                "port_description": "port1",
                "ttl": 120,
                "management_addresses": ["192.0.2.1"],
                "capabilities": ["Bridge"],
            }
        ],
    )
    def test_observe_view_renders_decoded_neighbors(self, _neighbors, _capability) -> None:
        response = self.client.get("/tools/lldp-lab?view=observe")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Switch-1", response.data)
        self.assertIn(b"192.0.2.1", response.data)
        self.assertIn(b'name="interface" value="en7"', response.data)

    @patch("twn_toolkit.lldp_routes.available_interfaces", return_value=INTERFACES)
    @patch("twn_toolkit.lldp_tools.available_interfaces", return_value=INTERFACES)
    @patch("twn_toolkit.lldp_tools.interface_mac", return_value=INTERFACES[0]["mac"])
    @patch(
        "twn_toolkit.lldp_routes.lldpcli_capability",
        return_value={
            "available": True,
            "connected": True,
            "version": "1.0.22",
            "message": "Connected",
        },
    )
    @patch(
        "twn_toolkit.lldp_routes.read_neighbors",
        return_value=[
            {
                "interface": "en7",
                "via": "LLDP",
                "age": "10 seconds",
                "system_name": "Copied switch",
                "system_description": "Lab switch",
                "chassis_id": "02:aa:bb:cc:dd:ee",
                "chassis_id_type": "mac",
                "port_id": "port1",
                "port_id_type": "ifname",
                "port_description": "port1",
                "ttl": 120,
                "management_addresses": [],
                "capabilities": ["Bridge"],
            }
        ],
    )
    def test_neighbor_copy_preserves_observed_interface_and_mac_identity(
        self, _neighbors, _capability, _mac, _tool_interfaces, _route_interfaces
    ) -> None:
        response = self.client.post(
            "/tools/lldp-lab",
            data={
                "view": "emulate",
                "interface": "en7",
                "neighbor_index": "0",
                "action": "neighbor_persona",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<option value="en7" selected>', response.data)
        self.assertIn(
            b'name="source_mac" value="02:aa:bb:cc:dd:ee"', response.data
        )

    @patch("twn_toolkit.lldp_routes.available_interfaces", return_value=INTERFACES)
    @patch(
        "twn_toolkit.lldp_routes.lldpcli_capability",
        return_value={
            "available": False,
            "connected": False,
            "version": "",
            "message": "Not installed",
        },
    )
    @patch("twn_toolkit.lldp_tools.available_interfaces", return_value=INTERFACES)
    @patch("twn_toolkit.lldp_tools.interface_mac", return_value=INTERFACES[0]["mac"])
    def test_saves_and_duplicates_persona(
        self, _mac, _tool_interfaces, _capability, _route_interfaces
    ) -> None:
        persona = self._form()
        response = self.client.post(
            "/tools/lldp-lab", data={**persona, "action": "save"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Saved LLDP persona Branch phone", response.data)
        response = self.client.post(
            "/tools/lldp-lab/personas/Branch%20phone/duplicate",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Branch phone copy", response.data)

    @patch("twn_toolkit.lldp_routes.available_interfaces", return_value=INTERFACES)
    @patch(
        "twn_toolkit.lldp_routes.lldpcli_capability",
        return_value={
            "available": False,
            "connected": False,
            "version": "",
            "message": "Not installed",
        },
    )
    @patch("twn_toolkit.lldp_routes.LLDPSessionStore.launch")
    @patch("twn_toolkit.lldp_tools.available_interfaces", return_value=INTERFACES)
    @patch("twn_toolkit.lldp_tools.interface_mac", return_value=INTERFACES[0]["mac"])
    def test_start_requires_confirmation_and_creates_bounded_session(
        self, _mac, _tool_interfaces, launch, _capability, _route_interfaces
    ) -> None:
        response = self.client.post(
            "/tools/lldp-lab", data={**self._form(), "action": "start"}
        )
        self.assertIn(b"Confirm that you are authorized", response.data)
        response = self.client.post(
            "/tools/lldp-lab",
            data={**self._form(), "action": "start", "confirm_send": "on"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Started Branch phone on en7", response.data)
        launch.assert_called_once()
        status = self.client.get("/tools/lldp-lab/sessions").get_json()
        self.assertEqual(status["sessions"][0]["interface"], "en7")
        self.assertEqual(status["sessions"][0]["status"], "queued")

    @staticmethod
    def _form() -> dict[str, str]:
        return {
            "view": "emulate",
            "interface": "en7",
            "preset": "phone",
            "name": "Branch phone",
            "system_name": "Branch phone",
            "system_description": "Test phone",
            "source_mac": "02:11:22:33:44:55",
            "chassis_id": "02:11:22:33:44:55",
            "port_id": "port-1",
            "port_description": "User port",
            "capability_telephone": "on",
            "capability_station": "on",
            "management_address": "",
            "pvid": "0",
            "ttl": "120",
            "med_enabled": "on",
            "med_class": "3",
            "med_policy_enabled": "on",
            "med_policy_unknown": "on",
            "med_policy_vlan": "0",
            "med_policy_priority": "0",
            "med_policy_dscp": "0",
            "interval_seconds": "5",
            "duration_minutes": "10",
            "quiet_lldpd": "on",
            "custom_tlvs": "",
        }


if __name__ == "__main__":
    unittest.main()

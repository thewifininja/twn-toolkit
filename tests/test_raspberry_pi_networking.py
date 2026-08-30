from __future__ import annotations

import ipaddress
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from twn_toolkit.app import create_app
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.pi_network_broker import (
    BROKER_PROTOCOL_VERSION,
    BrokerError,
    PiNetworkBroker,
    _interface_presence_signature,
    _keep_usb_interface_awake,
    _parse_iw_stations,
    _validate_configuration,
    _wireless_radio_snapshot,
    _validate_settings,
    build_configuration_profiles,
    build_connection_profiles,
    network_interface_inventory,
    wired_client_telemetry,
)
from twn_toolkit.raspberry_pi_networking import (
    RaspberryPiNetworkStore,
    raspberry_pi_identity,
    raspberry_pi_network_status,
    validate_pi_network_configuration,
    validate_pi_network_settings,
    validate_uploaded_tls_material,
)


def _nat_values() -> dict[str, object]:
    return {
        "mode": "nat",
        "wifi_interface": "wlan0",
        "uplink_interface": "eth0",
        "country": "US",
        "ssid": "Field Toolkit",
        "hidden": False,
        "autoconnect": True,
        "security": "wpa2-wpa3",
        "passphrase": "correct horse",
        "band": "2.4",
        "channel": "6",
        "client_isolation": True,
        "network": "192.168.50.0/24",
        "gateway": "192.168.50.1",
        "dhcp_start": "192.168.50.50",
        "dhcp_end": "192.168.50.200",
        "lease_time": "3600",
    }


class RaspberryPiNetworkValidationTests(unittest.TestCase):
    def test_detects_raspberry_pi_from_device_tree_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compatible = root / "compatible"
            model = root / "model"
            compatible.write_bytes(b"raspberrypi,5-compute-module\0brcm,bcm2712\0")
            model.write_bytes(b"Raspberry Pi Compute Module 5 Rev 1.0\0")
            identity = raspberry_pi_identity(
                compatible_path=compatible,
                model_path=model,
            )
        self.assertTrue(identity["is_raspberry_pi"])
        self.assertEqual(identity["model"], "Raspberry Pi Compute Module 5 Rev 1.0")

    def test_does_not_infer_raspberry_pi_from_arm_cpu(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compatible = root / "compatible"
            model = root / "model"
            compatible.write_bytes(b"vendor,arm-board\0arm,cortex-a76\0")
            model.write_text("Generic ARM board", encoding="utf-8")
            identity = raspberry_pi_identity(
                compatible_path=compatible,
                model_path=model,
            )
        self.assertFalse(identity["is_raspberry_pi"])

    def test_inaccessible_broker_socket_is_reported_without_crashing_settings(self) -> None:
        with (
            mock.patch(
                "twn_toolkit.raspberry_pi_networking.raspberry_pi_identity",
                return_value={
                    "is_raspberry_pi": True,
                    "model": "Raspberry Pi 5",
                    "compatible": "raspberrypi,5-model-b",
                },
            ),
            mock.patch(
                "twn_toolkit.raspberry_pi_networking._run_readonly",
                side_effect=[
                    "nmcli tool, version 1.52.1",
                    "active",
                    "disabled",
                    "US",
                    "wlan0:wifi:unavailable:--",
                    "WIFI-PROPERTIES.AP:yes\nWIFI-PROPERTIES.WPA2:yes",
                ],
            ),
            mock.patch(
                "twn_toolkit.raspberry_pi_networking.Path.exists",
                side_effect=PermissionError(13, "Permission denied"),
            ),
        ):
            status = raspberry_pi_network_status()
        self.assertFalse(status["supported"])
        self.assertIn("not accessible", status["broker_error"])

    def test_management_remains_available_when_all_adapters_are_temporarily_absent(self) -> None:
        with (
            mock.patch(
                "twn_toolkit.raspberry_pi_networking.raspberry_pi_identity",
                return_value={
                    "is_raspberry_pi": True,
                    "model": "Raspberry Pi 5",
                    "compatible": "raspberrypi,5-model-b",
                },
            ),
            mock.patch(
                "twn_toolkit.raspberry_pi_networking._run_readonly",
                side_effect=[
                    "nmcli tool, version 1.52.1",
                    "active",
                    "enabled",
                    "US",
                    "",
                ],
            ),
            mock.patch(
                "twn_toolkit.raspberry_pi_networking.Path.exists",
                return_value=True,
            ),
            mock.patch(
                "twn_toolkit.raspberry_pi_networking.request_pi_network_broker",
                return_value={
                    "protocol_version": 2,
                    "interfaces": [],
                    "profile_status": [],
                    "wireless_clients": [],
                    "managed": {},
                    "pending": {},
                },
            ),
        ):
            status = raspberry_pi_network_status()
        self.assertTrue(status["supported"])
        self.assertTrue(
            any(
                "No NetworkManager Wi-Fi interface" in limitation
                for limitation in status["limitations"]
            )
        )

    def test_local_ap_detection_survives_incomplete_broker_inventory(self) -> None:
        with (
            mock.patch(
                "twn_toolkit.raspberry_pi_networking.raspberry_pi_identity",
                return_value={
                    "is_raspberry_pi": True,
                    "model": "Raspberry Pi 5",
                    "compatible": "raspberrypi,5-model-b",
                },
            ),
            mock.patch(
                "twn_toolkit.raspberry_pi_networking._run_readonly",
                side_effect=[
                    "nmcli tool, version 1.52.1",
                    "active",
                    "enabled",
                    "US",
                    "wlan0:wifi:connected:Field AP",
                    "WIFI-PROPERTIES.AP:yes\nWIFI-PROPERTIES.WPA2:yes",
                ],
            ),
            mock.patch(
                "twn_toolkit.raspberry_pi_networking.Path.exists",
                return_value=True,
            ),
            mock.patch(
                "twn_toolkit.raspberry_pi_networking.request_pi_network_broker",
                return_value={
                    "protocol_version": 2,
                    "interfaces": [
                        {
                            "name": "wlan0",
                            "type": "wifi",
                            "state": "connected",
                            "ap": False,
                            "driver": "",
                            "mac_address": "",
                        }
                    ],
                    "profile_status": [],
                    "wireless_clients": [],
                    "managed": {},
                    "pending": {},
                },
            ),
        ):
            status = raspberry_pi_network_status()

        self.assertTrue(status["ap_available"])
        self.assertTrue(status["wifi_interfaces"][0]["ap"])
        self.assertNotIn(
            "The detected Wi-Fi interface does not report access-point support.",
            status["limitations"],
        )

    def test_validates_nat_network_and_dhcp_range(self) -> None:
        settings = validate_pi_network_settings(_nat_values())
        self.assertEqual(settings["network"], "192.168.50.0/24")
        self.assertEqual(settings["gateway"], "192.168.50.1")
        self.assertEqual(settings["security"], "wpa2-wpa3")

        invalid = {**_nat_values(), "gateway": "192.168.50.100"}
        with self.assertRaisesRegex(ToolInputError, "DHCP range"):
            validate_pi_network_settings(invalid)

    def test_validates_bridged_vlan_and_rejects_invalid_vlan(self) -> None:
        values = {
            **_nat_values(),
            "mode": "bridge",
            "vlan_id": "120",
        }
        settings = validate_pi_network_settings(values)
        self.assertEqual(settings["vlan_id"], 120)
        values["vlan_id"] = "4095"
        with self.assertRaisesRegex(ToolInputError, "4094"):
            validate_pi_network_settings(values)

    def test_peap_allows_explicit_server_validation_bypass(self) -> None:
        settings = validate_pi_network_settings(
            {
                "mode": "client",
                "wifi_interface": "wlan0",
                "country": "US",
                "ssid": "Enterprise",
                "security": "peap",
                "identity": "operator@example.test",
                "password": "secret",
                "verify_server_certificate": False,
            }
        )
        self.assertFalse(settings["verify_server_certificate"])
        self.assertEqual(settings["ca_source"], "none")
        self.assertEqual(settings["server_domain"], "")

    def test_peap_validation_requires_expected_server_domain(self) -> None:
        with self.assertRaisesRegex(ToolInputError, "authentication-server domain"):
            validate_pi_network_settings(
                {
                    "mode": "client",
                    "wifi_interface": "wlan0",
                    "country": "US",
                    "ssid": "Enterprise",
                    "security": "peap",
                    "identity": "operator@example.test",
                    "password": "secret",
                    "verify_server_certificate": True,
                    "ca_source": "system",
                }
            )

    def test_validates_simultaneous_access_points_on_distinct_radios(self) -> None:
        configuration = validate_pi_network_configuration(
            {
                "country": "US",
                "profiles": [
                    {
                        **_nat_values(),
                        "id": "field-nat",
                        "name": "Field NAT",
                        "kind": "wifi-ap",
                        "network_mode": "nat",
                        "enabled": True,
                    },
                    {
                        **_nat_values(),
                        "id": "service-bridge",
                        "name": "Service bridge",
                        "kind": "wifi-ap",
                        "network_mode": "bridge",
                        "wifi_interface": "wlan1",
                        "ssid": "Service VLAN",
                        "vlan_id": 120,
                        "enabled": True,
                    },
                ],
            }
        )
        self.assertEqual(configuration["schema_version"], 2)
        self.assertEqual(
            [profile["wifi_interface"] for profile in configuration["profiles"]],
            ["wlan0", "wlan1"],
        )
        self.assertEqual(configuration["profiles"][1]["network_mode"], "bridge")

    def test_rejects_two_active_wireless_roles_on_one_physical_radio(self) -> None:
        profiles = []
        for identifier in ("first", "second"):
            profiles.append(
                {
                    **_nat_values(),
                    "id": identifier,
                    "name": identifier.title(),
                    "kind": "wifi-ap",
                    "network_mode": "nat",
                    "enabled": True,
                    "network": (
                        "192.168.50.0/24" if identifier == "first" else "192.168.60.0/24"
                    ),
                    "gateway": (
                        "192.168.50.1" if identifier == "first" else "192.168.60.1"
                    ),
                    "dhcp_start": (
                        "192.168.50.50" if identifier == "first" else "192.168.60.50"
                    ),
                    "dhcp_end": (
                        "192.168.50.200" if identifier == "first" else "192.168.60.200"
                    ),
                }
            )
        with self.assertRaisesRegex(ToolInputError, "wlan0 is already assigned"):
            validate_pi_network_configuration({"country": "US", "profiles": profiles})

    def test_rejects_renamed_interfaces_that_resolve_to_the_same_radio(self) -> None:
        profiles = []
        for identifier, interface in (("first", "wlan0"), ("second", "wlan7")):
            profiles.append(
                {
                    **_nat_values(),
                    "id": identifier,
                    "name": identifier.title(),
                    "kind": "wifi-ap",
                    "network_mode": "nat",
                    "enabled": True,
                    "wifi_interface": interface,
                    "adapter_mac": "E0:E1:A9:36:47:BF",
                    "network": (
                        "192.168.50.0/24"
                        if identifier == "first"
                        else "192.168.60.0/24"
                    ),
                    "gateway": (
                        "192.168.50.1"
                        if identifier == "first"
                        else "192.168.60.1"
                    ),
                    "dhcp_start": (
                        "192.168.50.50"
                        if identifier == "first"
                        else "192.168.60.50"
                    ),
                    "dhcp_end": (
                        "192.168.50.200"
                        if identifier == "first"
                        else "192.168.60.200"
                    ),
                }
            )
        with self.assertRaisesRegex(ToolInputError, "already assigned"):
            validate_pi_network_configuration({"country": "US", "profiles": profiles})

    def test_rejects_renamed_wired_profile_on_a_bridged_uplink(self) -> None:
        with self.assertRaisesRegex(ToolInputError, "bridged uplink"):
            validate_pi_network_configuration(
                {
                    "country": "US",
                    "profiles": [
                        {
                            **_nat_values(),
                            "id": "bridge-ap",
                            "name": "Bridge AP",
                            "kind": "wifi-ap",
                            "network_mode": "bridge",
                            "enabled": True,
                            "uplink_interface": "eth0",
                            "uplink_mac": "00:E0:5C:E8:05:7B",
                        },
                        {
                            "id": "renamed-uplink",
                            "name": "Renamed uplink",
                            "kind": "wired",
                            "enabled": True,
                            "interface": "eth7",
                            "adapter_mac": "00:E0:5C:E8:05:7B",
                            "ipv4_mode": "dhcp",
                        },
                    ],
                }
            )

    def test_validates_wired_static_address_and_dns_override(self) -> None:
        configuration = validate_pi_network_configuration(
            {
                "country": "US",
                "profiles": [
                    {
                        "id": "usb-uplink",
                        "name": "USB uplink",
                        "kind": "wired",
                        "enabled": True,
                        "interface": "eth1",
                        "ipv4_mode": "static",
                        "address": "10.50.0.2/24",
                        "gateway": "10.50.0.1",
                        "dns_servers": "1.1.1.1, 9.9.9.9",
                        "ipv6_mode": "disabled",
                        "autoconnect": True,
                        "mtu": "1500",
                        "route_metric": "250",
                    }
                ],
            }
        )
        profile = configuration["profiles"][0]
        self.assertEqual(profile["address"], "10.50.0.2/24")
        self.assertEqual(profile["gateway"], "10.50.0.1")
        self.assertEqual(profile["dns_servers"], ["1.1.1.1", "9.9.9.9"])

    def test_validates_private_dhcp_server_on_usb_ethernet(self) -> None:
        configuration = validate_pi_network_configuration(
            {
                "country": "US",
                "profiles": [
                    {
                        "id": "bench-lan",
                        "name": "Bench LAN",
                        "kind": "wired",
                        "enabled": True,
                        "interface": "eth1",
                        "ipv4_mode": "shared",
                        "network": "172.23.40.0/24",
                        "gateway": "172.23.40.1",
                        "dhcp_start": "172.23.40.20",
                        "dhcp_end": "172.23.40.100",
                        "lease_time": 7200,
                    }
                ],
            }
        )
        profile = configuration["profiles"][0]
        self.assertEqual(profile["ipv4_mode"], "shared")
        self.assertEqual(profile["gateway"], "172.23.40.1")

    def test_rejects_overlapping_private_networks(self) -> None:
        with self.assertRaisesRegex(ToolInputError, "overlap"):
            validate_pi_network_configuration(
                {
                    "country": "US",
                    "profiles": [
                        {
                            **_nat_values(),
                            "id": "wireless-lab",
                            "name": "Wireless lab",
                            "kind": "wifi-ap",
                            "network_mode": "nat",
                            "enabled": True,
                        },
                        {
                            "id": "wired-lab",
                            "name": "Wired lab",
                            "kind": "wired",
                            "enabled": True,
                            "interface": "eth1",
                            "ipv4_mode": "shared",
                            "network": "192.168.50.128/25",
                            "gateway": "192.168.50.129",
                            "dhcp_start": "192.168.50.140",
                            "dhcp_end": "192.168.50.200",
                        },
                    ],
                }
            )


class RaspberryPiCertificateTests(unittest.TestCase):
    @staticmethod
    def _identity() -> tuple[bytes, bytes, x509.Certificate, rsa.RSAPrivateKey]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wifi-client")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return cert_pem, key_pem, certificate, key

    def test_accepts_matching_separate_eap_tls_identity(self) -> None:
        cert_pem, key_pem, _certificate, _key = self._identity()
        summary = validate_uploaded_tls_material(
            ca_data=cert_pem,
            client_certificate_data=cert_pem,
            private_key_data=key_pem,
        )
        self.assertIn("client", summary)
        self.assertIn("fingerprint", summary["client"])

    def test_rejects_mismatched_eap_tls_private_key(self) -> None:
        cert_pem, _key_pem, _certificate, _key = self._identity()
        _other_cert, other_key, _certificate, _key = self._identity()
        with self.assertRaisesRegex(ToolInputError, "does not match"):
            validate_uploaded_tls_material(
                client_certificate_data=cert_pem,
                private_key_data=other_key,
            )

    def test_accepts_password_protected_pkcs12_bundle(self) -> None:
        _cert_pem, _key_pem, certificate, key = self._identity()
        bundle = pkcs12.serialize_key_and_certificates(
            b"wifi-client",
            key,
            certificate,
            None,
            serialization.BestAvailableEncryption(b"bundle-secret"),
        )
        summary = validate_uploaded_tls_material(
            bundle_data=bundle,
            private_key_password="bundle-secret",
        )
        self.assertEqual(summary["client"]["subject"], "CN=wifi-client")


class RaspberryPiNetworkStoreTests(unittest.TestCase):
    def test_torn_pending_state_does_not_break_settings_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RaspberryPiNetworkStore(temporary, "instance secret")
            store.pending_path.write_bytes(b"")

            self.assertEqual(store.pending(), {})
            self.assertEqual(store.pending_configuration(), {})

            store.save_pending_configuration(
                kind="apply",
                token="replacement-token",
                expires_at=1_800_000_000,
                configuration={"schema_version": 2, "country": "US", "profiles": []},
            )
            self.assertEqual(
                store.pending_configuration()["token"], "replacement-token"
            )

    def test_encrypts_saved_wifi_credentials_and_pending_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RaspberryPiNetworkStore(temporary, "instance secret")
            store.save_active(
                {
                    "mode": "client",
                    "ssid": "Enterprise",
                    "security": "peap",
                    "identity": "operator",
                    "password": "credential-secret",
                }
            )
            self.assertNotIn(
                b"credential-secret", Path(temporary, "raspberry_pi_networking.json").read_bytes()
            )
            self.assertTrue(store.get()["has_password"])
            self.assertEqual(store.get(include_secrets=True)["password"], "credential-secret")

            store.save_pending(
                kind="apply",
                token="pending-token",
                expires_at=1234,
                settings={"password": "pending-secret", "mode": "client"},
            )
            self.assertNotIn(
                b"pending-secret",
                Path(temporary, "raspberry_pi_networking_pending.json").read_bytes(),
            )
            self.assertEqual(
                store.pending(include_secrets=True)["settings"]["password"],
                "pending-secret",
            )

    def test_encrypts_credentials_for_multiple_network_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RaspberryPiNetworkStore(temporary, "instance secret")
            configuration = {
                "schema_version": 2,
                "country": "US",
                "profiles": [
                    {
                        "id": "field-ap",
                        "name": "Field AP",
                        "kind": "wifi-ap",
                        "enabled": True,
                        "passphrase": "wireless-secret",
                    },
                    {
                        "id": "enterprise",
                        "name": "Enterprise",
                        "kind": "wifi-client",
                        "enabled": False,
                        "password": "radius-secret",
                    },
                ],
            }
            store.save_active_configuration(configuration)
            raw = Path(temporary, "raspberry_pi_networking.json").read_bytes()
            self.assertNotIn(b"wireless-secret", raw)
            self.assertNotIn(b"radius-secret", raw)
            public = store.get_configuration()
            self.assertTrue(public["profiles"][0]["has_passphrase"])
            self.assertTrue(public["profiles"][1]["has_password"])
            private = store.get_configuration(include_secrets=True)
            self.assertEqual(private["profiles"][0]["passphrase"], "wireless-secret")
            self.assertEqual(private["profiles"][1]["password"], "radius-secret")

    def test_reads_legacy_single_role_as_v2_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RaspberryPiNetworkStore(temporary, "instance secret")
            store.save_active(
                {
                    **_nat_values(),
                    "passphrase": "legacy-secret",
                }
            )
            configuration = store.get_configuration(include_secrets=True)
            self.assertEqual(configuration["schema_version"], 2)
            self.assertEqual(configuration["profiles"][0]["id"], "legacy-wireless")
            self.assertEqual(configuration["profiles"][0]["passphrase"], "legacy-secret")


class RaspberryPiNetworkProfileTests(unittest.TestCase):
    def _build(self, settings: dict[str, object]) -> list[dict[str, str]]:
        with mock.patch(
            "twn_toolkit.pi_network_broker._safe_interface",
            side_effect=lambda value, **_kwargs: str(value),
        ):
            return build_connection_profiles(settings, "1234567890abcdef")

    def test_builds_nat_shared_connection_without_secrets_in_process_metadata(self) -> None:
        profiles = self._build(_nat_values())
        self.assertEqual([profile["role"] for profile in profiles], ["hotspot"])
        content = profiles[0]["content"]
        self.assertIn("method=shared", content)
        self.assertIn("shared-dhcp-range=192.168.50.50,192.168.50.200", content)
        self.assertIn("key-mgmt=wpa-psk", content)
        self.assertIn("psk=correct horse", content)
        self.assertNotIn("correct horse", json.dumps({k: v for k, v in profiles[0].items() if k != "content"}))

    def test_builds_vlan_bridge_with_wifi_and_vlan_ports(self) -> None:
        settings = {
            **_nat_values(),
            "mode": "bridge",
            "vlan_id": 120,
        }
        profiles = self._build(settings)
        self.assertEqual(
            [profile["role"] for profile in profiles],
            ["bridge", "uplink", "hotspot"],
        )
        self.assertIn("type=vlan", profiles[1]["content"])
        self.assertIn("id=120", profiles[1]["content"])
        self.assertIn("port-type=bridge", profiles[2]["content"])
        self.assertIn("autoconnect-ports=1", profiles[0]["content"])
        self.assertIn("[ipv4]\nmethod=disabled", profiles[0]["content"])
        self.assertIn("[ipv6]\nmethod=disabled", profiles[0]["content"])
        self.assertNotIn("method=auto", profiles[0]["content"])
        self.assertIn("ap-isolation=1", profiles[2]["content"])
        self.assertNotIn("ap-isolation=true", profiles[2]["content"])

    def test_untagged_bridge_uses_dhcp_for_toolkit_management(self) -> None:
        settings = {
            **_nat_values(),
            "mode": "bridge",
            "vlan_id": 0,
        }
        profiles = self._build(settings)
        self.assertIn("type=ethernet", profiles[1]["content"])
        self.assertIn("[ipv4]\nmethod=auto\nmay-fail=true", profiles[0]["content"])
        self.assertIn("[ipv6]\nmethod=auto\nmay-fail=true", profiles[0]["content"])

    def test_builds_peap_client_with_optional_server_validation(self) -> None:
        settings = {
            "mode": "client",
            "wifi_interface": "wlan0",
            "country": "US",
            "ssid": "Enterprise",
            "hidden": False,
            "autoconnect": True,
            "security": "peap",
            "identity": "operator@example.test",
            "password": "enterprise-secret",
            "verify_server_certificate": False,
            "ca_source": "none",
            "server_domain": "",
        }
        content = self._build(settings)[0]["content"]
        self.assertIn("eap=peap;", content)
        self.assertIn("phase2-auth=mschapv2", content)
        self.assertIn("system-ca-certs=false", content)

    def test_builds_simultaneous_wireless_and_wired_profiles(self) -> None:
        configuration = validate_pi_network_configuration(
            {
                "country": "US",
                "profiles": [
                    {
                        **_nat_values(),
                        "id": "field-ap",
                        "name": "Field AP",
                        "kind": "wifi-ap",
                        "network_mode": "nat",
                        "enabled": True,
                    },
                    {
                        "id": "usb-static",
                        "name": "USB static",
                        "kind": "wired",
                        "enabled": True,
                        "interface": "eth1",
                        "ipv4_mode": "static",
                        "address": "10.55.0.2/24",
                        "gateway": "10.55.0.1",
                        "dns_servers": ["1.1.1.1", "9.9.9.9"],
                        "ipv6_mode": "disabled",
                        "autoconnect": True,
                        "mtu": 1500,
                        "route_metric": 300,
                    },
                ],
            }
        )
        with (
            mock.patch(
                "twn_toolkit.pi_network_broker._safe_interface",
                side_effect=lambda value, **_kwargs: str(value),
            ),
            mock.patch(
                "twn_toolkit.pi_network_broker._device_type",
                side_effect=lambda interface: (
                    "wifi" if str(interface).startswith("wlan") else "ethernet"
                ),
            ),
        ):
            profiles = build_configuration_profiles(
                configuration, "1234567890abcdef"
            )
        self.assertEqual([profile["role"] for profile in profiles], ["hotspot", "wired"])
        self.assertEqual([profile["logical_id"] for profile in profiles], ["field-ap", "usb-static"])
        wired = profiles[1]["content"]
        self.assertIn("address1=10.55.0.2/24,10.55.0.1", wired)
        self.assertIn("dns=1.1.1.1;9.9.9.9;", wired)
        self.assertIn("route-metric=300", wired)
        self.assertIn("mtu=1500", wired)

    def test_builds_wired_private_dhcp_server_profile(self) -> None:
        configuration = validate_pi_network_configuration(
            {
                "country": "US",
                "profiles": [
                    {
                        "id": "bench-lan",
                        "name": "Bench LAN",
                        "kind": "wired",
                        "enabled": True,
                        "interface": "eth1",
                        "ipv4_mode": "shared",
                        "network": "172.23.40.0/24",
                        "gateway": "172.23.40.1",
                        "dhcp_start": "172.23.40.20",
                        "dhcp_end": "172.23.40.100",
                        "lease_time": 7200,
                        "dns_servers": ["8.8.8.8", "1.1.1.1"],
                        "ipv6_mode": "disabled",
                        "autoconnect": True,
                        "mtu": 0,
                        "route_metric": 0,
                    }
                ],
            }
        )
        with (
            mock.patch(
                "twn_toolkit.pi_network_broker._safe_interface",
                side_effect=lambda value, **_kwargs: str(value),
            ),
            mock.patch(
                "twn_toolkit.pi_network_broker._device_type",
                return_value="ethernet",
            ),
        ):
            profiles = build_configuration_profiles(
                configuration, "1234567890abcdef"
            )
        content = profiles[0]["content"]
        self.assertIn("type=ethernet", content)
        self.assertIn("interface-name=eth1", content)
        self.assertIn("method=shared", content)
        self.assertIn("shared-dhcp-range=172.23.40.20,172.23.40.100", content)
        self.assertNotIn("dns=", content)

    def test_monitor_reloads_an_unloaded_managed_profile_before_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connections = root / "connections"
            connections.mkdir()
            profile_path = connections / "managed-wired.nmconnection"
            profile_path.write_text("[connection]\n", encoding="utf-8")
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=connections,
                state_directory=root / "state",
            )
            managed = {
                "configuration": {"country": "US", "profiles": []},
                "profiles": [
                    {
                        "uuid": "managed-wired-uuid",
                        "filename": profile_path.name,
                    }
                ],
            }
            with (
                mock.patch(
                    "twn_toolkit.pi_network_broker._run",
                    side_effect=["another-uuid", "loaded"],
                ) as run,
                mock.patch.object(broker, "_activate_configuration") as activate,
            ):
                broker._ensure_managed_profiles_active(managed)

        self.assertEqual(
            run.call_args_list,
            [
                mock.call(["nmcli", "-t", "-f", "UUID", "connection", "show"]),
                mock.call(["nmcli", "connection", "load", str(profile_path)]),
            ],
        )
        activate.assert_called_once_with(
            managed["configuration"], managed["profiles"], skip_active=True
        )

    def test_missing_usb_adapter_profile_is_built_and_bound_by_mac(self) -> None:
        configuration = validate_pi_network_configuration(
            {
                "country": "US",
                "profiles": [
                    {
                        "id": "travel-usb-lan",
                        "name": "Travel USB LAN",
                        "kind": "wired",
                        "enabled": True,
                        "interface": "eth9",
                        "adapter_mac": "00:E0:5C:E8:05:7B",
                        "ipv4_mode": "dhcp",
                        "dns_servers": [],
                        "ipv6_mode": "auto",
                        "autoconnect": True,
                        "mtu": 0,
                        "route_metric": 0,
                    }
                ],
            }
        )
        profiles = build_configuration_profiles(
            configuration, "1234567890abcdef"
        )
        self.assertEqual(profiles[0]["interface"], "eth9")
        self.assertIn("mac-address=00:E0:5C:E8:05:7B", profiles[0]["content"])
        self.assertNotIn("interface-name=eth9", profiles[0]["content"])

    def test_parses_optional_iw_station_metrics(self) -> None:
        stations = _parse_iw_stations(
            "Station aa:bb:cc:dd:ee:ff (on wlan1)\n"
            "\tsignal: -48 dBm\n\ttx bitrate: 144.4 MBit/s\n"
            "\trx bytes: 12345\n"
        )
        self.assertEqual(stations[0]["mac_address"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(stations[0]["signal"], "-48 dBm")
        self.assertEqual(stations[0]["tx_bitrate"], "144.4 MBit/s")

    def test_reports_clients_on_private_wired_networks(self) -> None:
        configuration = {
            "profiles": [
                {
                    "id": "field-lan",
                    "name": "Field LAN",
                    "kind": "wired",
                    "enabled": True,
                    "interface": "eth1",
                    "adapter_mac": "5C:85:7E:36:98:B0",
                    "ipv4_mode": "shared",
                    "network": "192.168.60.0/24",
                }
            ]
        }
        with (
            mock.patch(
                "twn_toolkit.pi_network_broker._resolve_interface",
                return_value=("eth1", True),
            ),
            mock.patch(
                "twn_toolkit.pi_network_broker._dhcp_leases",
                return_value=[
                    {
                        "expires_at": 1_800_000_000,
                        "mac_address": "AA:BB:CC:DD:EE:FF",
                        "ip_address": "192.168.60.55",
                        "hostname": "field-laptop",
                    },
                    {
                        "expires_at": 1_800_000_000,
                        "mac_address": "00:11:22:33:44:55",
                        "ip_address": "192.168.50.20",
                        "hostname": "another-network",
                    },
                ],
            ),
            mock.patch(
                "twn_toolkit.pi_network_broker._run_optional",
                return_value=(
                    "192.168.60.55 dev eth1 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
                    "192.168.60.77 dev eth1 lladdr 66:77:88:99:aa:bb STALE"
                ),
            ),
        ):
            groups = wired_client_telemetry(
                configuration,
                [
                    {
                        "logical_id": "field-lan",
                        "role": "wired",
                        "interface": "eth1",
                    }
                ],
            )

        self.assertEqual(groups[0]["client_count"], 2)
        self.assertEqual(groups[0]["clients"][0]["ip_address"], "192.168.60.77")
        self.assertEqual(groups[0]["clients"][0]["neighbor_state"], "STALE")
        self.assertEqual(groups[0]["clients"][1]["hostname"], "field-laptop")
        self.assertEqual(groups[0]["clients"][1]["neighbor_state"], "REACHABLE")


class RaspberryPiNetworkBrokerTests(unittest.TestCase):
    def test_protected_broker_rejects_overlapping_private_networks(self) -> None:
        def shared_profile(
            identifier: str, interface: str, network: str, gateway: str
        ) -> dict[str, object]:
            subnet = ipaddress.ip_network(network)
            return {
                "id": identifier,
                "name": identifier.replace("-", " ").title(),
                "kind": "wired",
                "enabled": True,
                "interface": interface,
                "adapter_mac": "",
                "ipv4_mode": "shared",
                "network": network,
                "gateway": gateway,
                "dhcp_start": str(subnet.network_address + 20),
                "dhcp_end": str(subnet.network_address + 40),
                "lease_time": 3600,
                "dns_servers": [],
                "ipv6_mode": "auto",
                "autoconnect": True,
                "mtu": 0,
                "route_metric": 0,
            }

        configuration = {
            "country": "US",
            "profiles": [
                shared_profile(
                    "field-lan", "eth1", "192.168.60.0/24", "192.168.60.1"
                ),
                shared_profile(
                    "bench-lan", "eth2", "192.168.60.128/25", "192.168.60.129"
                ),
            ],
        }
        with (
            mock.patch(
                "twn_toolkit.pi_network_broker._resolve_interface",
                side_effect=lambda name, _mac, _kind: (str(name), True),
            ),
            self.assertRaisesRegex(BrokerError, "Private DHCP networks overlap"),
        ):
            _validate_configuration(configuration)

    def test_reads_active_radio_without_triggering_a_networkmanager_scan(self) -> None:
        outputs = {
            ("/usr/sbin/iw", "dev", "wlan0", "info"): """\
Interface wlan0
    addr 98:fe:54:1d:69:6d
    ssid TWN-Toolkit
    type AP
    channel 36 (5180 MHz), width: 20 MHz, center1: 5180 MHz
""",
            ("/usr/sbin/iw", "dev", "wlan0", "link"): "Not connected.\n",
        }
        with (
            mock.patch(
                "twn_toolkit.pi_network_broker._iw_binary",
                return_value="/usr/sbin/iw",
            ),
            mock.patch(
                "twn_toolkit.pi_network_broker._run_optional",
                side_effect=lambda command, **_kwargs: outputs.get(tuple(command), ""),
            ) as run_optional,
        ):
            radio = _wireless_radio_snapshot("wlan0")

        self.assertEqual(
            radio,
            {
                "ssid": "TWN-Toolkit",
                "mode": "AP",
                "channel": "36",
                "frequency_mhz": "5180",
            },
        )
        self.assertFalse(
            any("nmcli" in call.args[0] for call in run_optional.call_args_list)
        )

    def test_optional_permanent_mac_field_cannot_hide_ap_capabilities(self) -> None:
        def run_optional(command: list[str], **_kwargs: object) -> str:
            selected = command[3] if len(command) > 3 else ""
            if command[:3] == ["nmcli", "-t", "-f"] and selected == (
                "DEVICE,TYPE,STATE,CONNECTION"
            ):
                return "wlan0:wifi:connected:Field AP"
            if command[:3] == ["nmcli", "-t", "-f"] and selected == (
                "GENERAL.PERM-HWADDR"
            ):
                # NetworkManager 1.52 rejects this optional field.
                return ""
            if command[:3] == ["nmcli", "-t", "-f"] and "GENERAL.HWADDR" in selected:
                return "\n".join(
                    [
                        r"GENERAL.HWADDR:98\:FE\:54\:1D\:69\:6D",
                        "GENERAL.VENDOR:Broadcom Corp.",
                        "GENERAL.DRIVER:brcmfmac",
                        "GENERAL.UDI:/sys/devices/platform/mmc/net/wlan0",
                        "IP4.ADDRESS[1]:192.168.50.1/24",
                        "WIFI-PROPERTIES.AP:yes",
                        "WIFI-PROPERTIES.2GHZ:yes",
                        "WIFI-PROPERTIES.5GHZ:yes",
                        "WIFI-PROPERTIES.6GHZ:no",
                    ]
                )
            if command[:2] == ["ethtool", "-P"]:
                return "Permanent address: 98:fe:54:1d:69:6d"
            if command[:3] == ["nmcli", "-t", "-f"] and selected.startswith(
                "ACTIVE,SSID"
            ):
                return ""
            return ""

        with mock.patch(
            "twn_toolkit.pi_network_broker._run_optional",
            side_effect=run_optional,
        ):
            inventory = network_interface_inventory()

        self.assertEqual(len(inventory), 1)
        self.assertTrue(inventory[0]["ap"])
        self.assertEqual(inventory[0]["driver"], "brcmfmac")
        self.assertEqual(inventory[0]["mac_address"], "98:FE:54:1D:69:6D")
        self.assertEqual(inventory[0]["ipv4_addresses"], ["192.168.50.1/24"])

    def test_missing_wired_adapter_is_dormant_without_blocking_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )
            configuration = {
                "country": "US",
                "profiles": [
                    {
                        "id": "usb-lan",
                        "name": "USB LAN",
                        "kind": "wired",
                        "enabled": True,
                        "interface": "eth9",
                        "adapter_mac": "00:E0:5C:E8:05:7B",
                    }
                ],
            }
            records = [
                {
                    "role": "wired",
                    "uuid": "usb-lan-uuid",
                    "logical_id": "usb-lan",
                    "interface": "eth9",
                }
            ]
            with (
                mock.patch(
                    "twn_toolkit.pi_network_broker._resolve_interface",
                    return_value=("eth9", False),
                ),
                mock.patch(
                    "twn_toolkit.pi_network_broker._run_quiet"
                ) as run_quiet,
                mock.patch("twn_toolkit.pi_network_broker._run") as run,
            ):
                dormant = broker._activate_configuration(configuration, records)
        self.assertEqual(dormant[0]["id"], "usb-lan")
        self.assertIn("eth9", dormant[0]["reason"])
        run.assert_not_called()
        run_quiet.assert_called_once_with(
            ["nmcli", "connection", "down", "uuid", "usb-lan-uuid"]
        )

    def test_present_wired_adapter_without_carrier_is_dormant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )
            configuration = {
                "country": "US",
                "profiles": [
                    {
                        "id": "usb-lan",
                        "name": "USB LAN",
                        "kind": "wired",
                        "enabled": True,
                        "interface": "eth1",
                        "adapter_mac": "00:E0:5C:E8:05:7B",
                    }
                ],
            }
            records = [
                {
                    "role": "wired",
                    "uuid": "usb-lan-uuid",
                    "logical_id": "usb-lan",
                    "interface": "eth1",
                }
            ]
            with (
                mock.patch(
                    "twn_toolkit.pi_network_broker._resolve_interface",
                    return_value=("eth1", True),
                ),
                mock.patch(
                    "twn_toolkit.pi_network_broker._ethernet_has_carrier",
                    return_value=False,
                ),
                mock.patch(
                    "twn_toolkit.pi_network_broker._run_quiet"
                ) as run_quiet,
                mock.patch("twn_toolkit.pi_network_broker._run") as run,
            ):
                dormant = broker._activate_configuration(configuration, records)

        self.assertEqual(
            dormant,
            [
                {
                    "id": "usb-lan",
                    "name": "USB LAN",
                    "reason": "No carrier on eth1",
                }
            ],
        )
        run.assert_not_called()
        run_quiet.assert_called_once_with(
            ["nmcli", "connection", "down", "uuid", "usb-lan-uuid"]
        )

    def test_interface_signature_changes_when_carrier_appears(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sys_class_net = Path(temporary)
            adapter = sys_class_net / "eth1"
            adapter.mkdir()
            (adapter / "address").write_text(
                "00:e0:5c:e8:05:7b\n", encoding="utf-8"
            )
            (adapter / "carrier").write_text("0\n", encoding="utf-8")
            dormant = _interface_presence_signature(sys_class_net=sys_class_net)
            (adapter / "carrier").write_text("1\n", encoding="utf-8")
            active = _interface_presence_signature(sys_class_net=sys_class_net)

        self.assertNotEqual(dormant, active)
        self.assertEqual(active, (("eth1", "00:E0:5C:E8:05:7B", "1"),))

    def test_managed_usb_adapter_is_kept_out_of_runtime_autosuspend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_class_net = root / "sys" / "class" / "net"
            usb_device = root / "sys" / "devices" / "usb3" / "3-1"
            usb_interface = usb_device / "3-1:1.0"
            (usb_device / "power").mkdir(parents=True)
            usb_interface.mkdir()
            (usb_device / "idVendor").write_text("0bda\n", encoding="utf-8")
            control = usb_device / "power" / "control"
            control.write_text("auto\n", encoding="utf-8")
            adapter = sys_class_net / "eth1"
            adapter.mkdir(parents=True)
            (adapter / "device").symlink_to(usb_interface)

            changed = _keep_usb_interface_awake(
                "eth1", sys_class_net=sys_class_net
            )
            power_control = control.read_text(encoding="utf-8")

        self.assertTrue(changed)
        self.assertEqual(power_control, "on\n")

    def test_returning_wifi_adapter_is_resolved_by_hardware_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )
            configuration = {
                "country": "US",
                "profiles": [
                    {
                        "id": "usb-client",
                        "name": "USB Wi-Fi",
                        "kind": "wifi-client",
                        "enabled": True,
                        "wifi_interface": "wlan1",
                        "adapter_mac": "E0:E1:A9:36:47:BF",
                    }
                ],
            }
            records = [
                {
                    "role": "client",
                    "uuid": "usb-wifi-uuid",
                    "logical_id": "usb-client",
                    "interface": "wlan1",
                }
            ]
            with (
                mock.patch(
                    "twn_toolkit.pi_network_broker._resolve_interface",
                    return_value=("wlan7", True),
                ),
                mock.patch(
                    "twn_toolkit.pi_network_broker.Path.exists",
                    return_value=True,
                ),
                mock.patch.object(broker, "_wait_for_wifi_interface"),
                mock.patch("twn_toolkit.pi_network_broker._run") as run,
            ):
                dormant = broker._activate_configuration(configuration, records)
        self.assertEqual(dormant, [])
        self.assertEqual(records[0]["interface"], "wlan7")
        self.assertIn(
            mock.call(
                [
                    "nmcli",
                    "connection",
                    "up",
                    "uuid",
                    "usb-wifi-uuid",
                    "ifname",
                    "wlan7",
                ],
                timeout=60,
            ),
            run.call_args_list,
        )

    def test_bridge_activation_starts_master_then_wired_and_wifi_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )
            profiles = [
                {"role": "bridge", "uuid": "bridge-uuid"},
                {"role": "uplink", "uuid": "uplink-uuid"},
                {"role": "hotspot", "uuid": "hotspot-uuid"},
            ]
            with (
                mock.patch(
                    "twn_toolkit.pi_network_broker._run",
                    side_effect=lambda command, **_kwargs: (
                        "30 (disconnected)" if "GENERAL.STATE" in command else ""
                    ),
                ) as run,
                mock.patch(
                    "twn_toolkit.pi_network_broker._safe_interface",
                    side_effect=lambda interface: str(interface),
                ),
            ):
                broker._activate(
                    {"mode": "bridge", "country": "US", "wifi_interface": "wlan0"},
                    profiles,
                )
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["raspi-config", "nonint", "do_wifi_country", "US"],
                ["nmcli", "radio", "wifi", "on"],
                [
                    "nmcli",
                    "--wait",
                    "0",
                    "connection",
                    "up",
                    "uuid",
                    "bridge-uuid",
                ],
                ["nmcli", "connection", "up", "uuid", "uplink-uuid"],
                ["nmcli", "-g", "GENERAL.STATE", "device", "show", "wlan0"],
                [
                    "nmcli",
                    "connection",
                    "up",
                    "uuid",
                    "hotspot-uuid",
                    "ifname",
                    "wlan0",
                ],
            ],
        )

    def test_wifi_activation_waits_for_device_and_binds_profile_to_interface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )
            responses = iter(["", "", "20 (unavailable)", "30 (disconnected)", ""])
            with (
                mock.patch(
                    "twn_toolkit.pi_network_broker._run",
                    side_effect=lambda _command, **_kwargs: next(responses),
                ) as run,
                mock.patch(
                    "twn_toolkit.pi_network_broker._safe_interface",
                    side_effect=lambda interface: str(interface),
                ),
                mock.patch("twn_toolkit.pi_network_broker.time.sleep") as sleep,
            ):
                broker._activate(
                    {
                        "mode": "client",
                        "country": "US",
                        "wifi_interface": "wlan0",
                    },
                    [{"role": "client", "uuid": "client-uuid"}],
                )

        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(
            run.call_args_list[-1].args[0],
            [
                "nmcli",
                "connection",
                "up",
                "uuid",
                "client-uuid",
                "ifname",
                "wlan0",
            ],
        )

    def test_scan_waits_for_wifi_when_enabling_a_disabled_radio(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )

            def response(command, **_kwargs):
                if "GENERAL.STATE" in command:
                    return "30 (disconnected)"
                if "list" in command:
                    return "Field Toolkit:82:WPA2:2412"
                return ""

            with (
                mock.patch(
                    "twn_toolkit.pi_network_broker._safe_interface",
                    return_value="wlan0",
                ),
                mock.patch.object(broker, "_wifi_enabled", return_value=False),
                mock.patch(
                    "twn_toolkit.pi_network_broker._run",
                    side_effect=response,
                ) as run,
                mock.patch.object(broker, "_restore_wifi_radio") as restore_radio,
            ):
                result = broker.scan("wlan0")

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0], ["nmcli", "radio", "wifi", "on"])
        self.assertEqual(
            commands[1],
            ["nmcli", "-g", "GENERAL.STATE", "device", "show", "wlan0"],
        )
        self.assertIn("list", commands[2])
        restore_radio.assert_called_once_with(False)
        self.assertEqual(result["networks"][0]["ssid"], "Field Toolkit")

    def test_checkpoint_create_uses_networkmanager_device_timeout_flags_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )
            with mock.patch(
                "twn_toolkit.pi_network_broker._run",
                return_value='o "/org/freedesktop/NetworkManager/Checkpoint/7"',
            ) as run:
                checkpoint = broker._checkpoint_create(120)
        self.assertEqual(
            checkpoint,
            "/org/freedesktop/NetworkManager/Checkpoint/7",
        )
        command = run.call_args.args[0]
        self.assertEqual(command[-4:], ["aouu", "0", "120", "7"])

    def test_apply_reserves_checkpoint_time_for_connection_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )
            profile = {
                "role": "client",
                "id": "test-client",
                "uuid": "client-uuid",
                "filename": "test-client.nmconnection",
                "content": "profile content",
            }
            with (
                mock.patch.object(broker, "_copy_material"),
                mock.patch(
                    "twn_toolkit.pi_network_broker.build_connection_profiles",
                    return_value=[profile],
                ),
                mock.patch(
                    "twn_toolkit.pi_network_broker._run",
                    return_value="US",
                ),
                mock.patch.object(broker, "_wifi_enabled", return_value=False),
                mock.patch.object(broker, "_active_connections", return_value=[]),
                mock.patch.object(
                    broker,
                    "_checkpoint_create",
                    return_value="/org/freedesktop/NetworkManager/Checkpoint/8",
                ) as checkpoint,
                mock.patch.object(broker, "_write_profiles"),
                mock.patch.object(broker, "_activate"),
                mock.patch("twn_toolkit.pi_network_broker.time.time", return_value=1_000),
            ):
                result = broker.apply(
                    {
                        "rollback_seconds": 120,
                        "settings": {
                            "mode": "client",
                            "ssid": "Test Wi-Fi",
                            "wifi_interface": "wlan0",
                        },
                    }
                )

        checkpoint.assert_called_once_with(210)
        self.assertEqual(result["expires_at"], 1_120)

    def test_root_side_validation_rejects_non_boolean_flags(self) -> None:
        values = {
            "mode": "client",
            "wifi_interface": "wlan0",
            "country": "US",
            "ssid": "Field Toolkit",
            "hidden": "false",
            "autoconnect": True,
            "security": "open",
        }
        with (
            mock.patch(
                "twn_toolkit.pi_network_broker._safe_interface",
                return_value="wlan0",
            ),
            self.assertRaisesRegex(BrokerError, "hidden-network"),
        ):
            _validate_settings(values)

    def test_protocol_mismatch_requires_service_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=root / "state",
            )
            with self.assertRaisesRegex(BrokerError, "Reinstall"):
                broker.dispatch(
                    {
                        "protocol_version": BROKER_PROTOCOL_VERSION + 1,
                        "operation": "status",
                    }
                )

    def test_rollback_restores_country_radio_and_previous_managed_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=state,
            )
            broker.pending_path.write_text("{}", encoding="utf-8")
            pending = {
                "checkpoint": "/org/freedesktop/NetworkManager/Checkpoint/1",
                "profiles": [],
                "rollback_country": "US",
                "rollback_wifi_enabled": False,
                "previous_managed": {"mode": "client", "ssid": "Previous"},
            }
            with (
                mock.patch.object(broker, "_checkpoint_action") as checkpoint,
                mock.patch.object(broker, "_cleanup_profiles"),
                mock.patch.object(broker, "_restore_country") as country,
                mock.patch.object(broker, "_restore_wifi_radio") as radio,
            ):
                broker._rollback_locked(pending)
            checkpoint.assert_called_once_with(
                "CheckpointRollback",
                "/org/freedesktop/NetworkManager/Checkpoint/1",
            )
            country.assert_called_once_with("US")
            radio.assert_called_once_with(False)
            self.assertFalse(broker.pending_path.exists())
            self.assertEqual(
                json.loads(broker.current_path.read_text(encoding="utf-8"))["ssid"],
                "Previous",
            )

    def test_disable_rollback_reactivates_a_saved_client_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            broker = PiNetworkBroker(
                socket_path=root / "broker.sock",
                allowed_uid=1001,
                toolkit_root=root,
                connection_directory=root / "connections",
                state_directory=state,
            )
            broker.pending_path.write_text("{}", encoding="utf-8")
            pending = {
                "checkpoint": "/org/freedesktop/NetworkManager/Checkpoint/2",
                "profiles": [],
                "rollback_country": "US",
                "rollback_wifi_enabled": True,
                "previous_managed": {
                    "mode": "client",
                    "ssid": "Previous",
                    "wifi_interface": "wlan0",
                    "profiles": [{"role": "client", "uuid": "client-uuid"}],
                },
            }
            with (
                mock.patch.object(broker, "_checkpoint_action"),
                mock.patch.object(broker, "_cleanup_profiles"),
                mock.patch.object(broker, "_restore_country"),
                mock.patch.object(broker, "_restore_wifi_radio"),
                mock.patch.object(broker, "_active_connections", return_value=[]),
                mock.patch.object(broker, "_wait_for_wifi_interface"),
                mock.patch(
                    "twn_toolkit.pi_network_broker._safe_interface",
                    return_value="wlan0",
                ),
                mock.patch("twn_toolkit.pi_network_broker._run") as run,
            ):
                broker._rollback_locked(pending)

            run.assert_called_once_with(
                [
                    "nmcli",
                    "connection",
                    "up",
                    "uuid",
                    "client-uuid",
                    "ifname",
                    "wlan0",
                ],
                timeout=60,
            )
            self.assertFalse(broker.pending_path.exists())


class RaspberryPiSettingsRouteTests(unittest.TestCase):
    def test_torn_pending_record_does_not_take_down_settings_page(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = create_app(temporary)
            app.testing = True
            Path(
                temporary, "raspberry_pi_networking_pending.json"
            ).write_bytes(b"")
            identity = {
                "is_raspberry_pi": True,
                "model": "Raspberry Pi 5",
                "compatible": "raspberrypi,5-model-b",
            }
            status = {
                **identity,
                "supported": False,
                "network_manager": "nmcli 1.52.1",
                "network_manager_active": True,
                "broker_available": True,
                "wifi_enabled": True,
                "country": "US",
                "wifi_interfaces": [],
                "wired_interfaces": [],
                "interfaces": [],
                "profile_status": [],
                "wireless_clients": [],
                "wired_clients": [],
                "ap_available": False,
                "wired_available": False,
                "active_connections": [],
                "managed": {},
                "pending": {},
                "limitations": [],
            }
            with (
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_identity",
                    return_value=identity,
                ),
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_network_status",
                    return_value=status,
                ),
            ):
                page = app.test_client().get(
                    "/settings?section=raspberry-pi"
                )

            self.assertEqual(page.status_code, 200)

    def test_non_pi_settings_sections_skip_live_pi_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = create_app(temporary)
            app.testing = True
            with (
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_identity",
                    return_value={
                        "is_raspberry_pi": True,
                        "model": "Raspberry Pi 5",
                        "compatible": "raspberrypi,5-model-b",
                    },
                ),
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_network_status"
                ) as network_status,
            ):
                page = app.test_client().get("/settings?section=system")

            self.assertEqual(page.status_code, 200)
            network_status.assert_not_called()

    def test_pi_broker_repair_preserves_installed_network_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = create_app(temporary)
            app.testing = True
            status = {
                "is_raspberry_pi": True,
                "model": "Raspberry Pi 5",
                "compatible": "raspberrypi,5-model-b",
                "supported": False,
                "network_manager": "nmcli 1.52.1",
                "network_manager_active": True,
                "broker_available": False,
                "wifi_enabled": True,
                "country": "US",
                "wifi_interfaces": [],
                "wired_interfaces": [],
                "ap_available": False,
                "wired_available": False,
                "active_connections": [],
                "managed": {},
                "pending": {},
                "limitations": [
                    "Reinstall the system service to enable protected network changes."
                ],
            }
            with (
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_identity",
                    return_value={
                        "is_raspberry_pi": True,
                        "model": "Raspberry Pi 5",
                        "compatible": "raspberrypi,5-model-b",
                    },
                ),
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_network_status",
                    return_value=status,
                ),
                mock.patch(
                    "twn_toolkit.admin_routes.systemd_network_capabilities_enabled",
                    return_value=True,
                ),
            ):
                page = app.test_client().get("/settings?section=raspberry-pi")

            self.assertEqual(page.status_code, 200)
            self.assertIn(
                b"sudo ./twn service install --network-capabilities",
                page.data,
            )
            self.assertIn(b"the flag is included", page.data)

    def test_transient_broker_failure_preserves_local_pending_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = create_app(temporary)
            app.testing = True
            store = RaspberryPiNetworkStore(temporary, app.config["SECRET_KEY"])
            store.save_pending(
                kind="apply",
                token="keep-this-token",
                expires_at=9_999_999_999,
                settings={"mode": "client", "ssid": "Field Toolkit"},
            )
            status = {
                "is_raspberry_pi": True,
                "model": "Raspberry Pi 5",
                "compatible": "raspberrypi,5-model-b",
                "supported": False,
                "network_manager": "nmcli 1.52.1",
                "network_manager_active": True,
                "broker_available": False,
                "wifi_enabled": True,
                "country": "US",
                "wifi_interfaces": [],
                "wired_interfaces": [],
                "ap_available": False,
                "wired_available": False,
                "active_connections": [],
                "managed": {},
                "pending": {},
                "limitations": ["The protected networking broker is restarting."],
            }
            with (
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_identity",
                    return_value={
                        "is_raspberry_pi": True,
                        "model": "Raspberry Pi 5",
                        "compatible": "raspberrypi,5-model-b",
                    },
                ),
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_network_status",
                    return_value=status,
                ),
            ):
                page = app.test_client().get("/settings?section=raspberry-pi")

            self.assertEqual(page.status_code, 200)
            self.assertEqual(store.pending()["token"], "keep-this-token")
            self.assertIn(b"The new network configuration is provisional", page.data)

    def test_pi_settings_tab_and_apply_flow_are_available_only_on_pi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = create_app(temporary)
            app.testing = True
            client = app.test_client()
            status = {
                "is_raspberry_pi": True,
                "model": "Raspberry Pi 5",
                "compatible": "raspberrypi,5-model-b",
                "supported": True,
                "network_manager": "nmcli 1.52.1",
                "network_manager_active": True,
                "broker_available": True,
                "wifi_enabled": True,
                "country": "US",
                "wifi_interfaces": [
                    {"name": "wlan0", "state": "disconnected", "ap": True}
                ],
                "wired_interfaces": [
                    {"name": "eth0", "state": "connected", "connection": "Wired"}
                ],
                "ap_available": True,
                "wired_available": True,
                "active_connections": ["Wired"],
                "interfaces": [],
                "profile_status": [],
                "wireless_clients": [],
                "wired_clients": [
                    {
                        "profile_name": "Field LAN",
                        "interface": "eth1",
                        "network": "192.168.60.0/24",
                        "client_count": 1,
                        "clients": [
                            {
                                "hostname": "field-laptop",
                                "mac_address": "AA:BB:CC:DD:EE:FF",
                                "ip_address": "192.168.60.55",
                                "neighbor_state": "STALE",
                                "lease_expires_at": 1_800_000_000,
                            }
                        ],
                    }
                ],
                "managed": {},
                "pending": {},
                "limitations": [],
            }
            with (
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_identity",
                    return_value={
                        "is_raspberry_pi": True,
                        "model": "Raspberry Pi 5",
                        "compatible": "raspberrypi,5-model-b",
                    },
                ),
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_network_status",
                    return_value=status,
                ),
            ):
                page = client.get(
                    "/settings?section=raspberry-pi&new=wifi-ap"
                )
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Raspberry Pi networking", page.data)
            self.assertIn(b"><span>Pi networking</span></a>", page.data)
            self.assertIn(b"PEAP-MSCHAPv2", page.data)
            self.assertIn(b"EAP-TLS", page.data)
            self.assertIn(b'class="pi-profile-new-actions"', page.data)
            self.assertNotIn(b'button-row pi-profile-new-actions', page.data)
            self.assertIn(b"Connected clients", page.data)
            self.assertIn(b"field-laptop", page.data)
            self.assertIn(b"Recently seen", page.data)
            self.assertIn(
                b'data-loading-message="Applying provisional Raspberry Pi networking',
                page.data,
            )

            with (
                mock.patch(
                    "twn_toolkit.admin_routes.raspberry_pi_identity",
                    return_value={"is_raspberry_pi": True},
                ),
                mock.patch(
                    "twn_toolkit.admin_routes.request_pi_network_broker",
                    return_value={
                        "ok": True,
                        "token": "network-token",
                        "expires_at": 9999999999,
                    },
                ) as broker,
            ):
                response = client.post(
                    "/settings/raspberry-pi/network/apply",
                    data={
                        **_nat_values(),
                        "kind": "wifi-ap",
                        "name": "Field Toolkit AP",
                        "enabled": "on",
                        "network_mode": "nat",
                    },
                )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(broker.call_args.args[0]["operation"], "apply")
            pending = RaspberryPiNetworkStore(
                temporary, app.config["SECRET_KEY"]
            ).pending_configuration(include_secrets=True)
            self.assertEqual(pending["token"], "network-token")
            self.assertEqual(
                pending["configuration"]["profiles"][0]["passphrase"],
                "correct horse",
            )


if __name__ == "__main__":
    unittest.main()

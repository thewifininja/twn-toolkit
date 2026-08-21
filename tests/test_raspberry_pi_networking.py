from __future__ import annotations

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
    _validate_settings,
    build_connection_profiles,
)
from twn_toolkit.raspberry_pi_networking import (
    RaspberryPiNetworkStore,
    raspberry_pi_identity,
    raspberry_pi_network_status,
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


class RaspberryPiNetworkBrokerTests(unittest.TestCase):
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
                page = client.get("/settings?section=raspberry-pi")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Raspberry Pi networking", page.data)
            self.assertIn(b">Pi networking</a>", page.data)
            self.assertIn(b"PEAP-MSCHAPv2", page.data)
            self.assertIn(b"EAP-TLS", page.data)
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
                    data=_nat_values(),
                )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(broker.call_args.args[0]["operation"], "apply")
            pending = RaspberryPiNetworkStore(
                temporary, app.config["SECRET_KEY"]
            ).pending(include_secrets=True)
            self.assertEqual(pending["token"], "network-token")
            self.assertEqual(pending["settings"]["passphrase"], "correct horse")


if __name__ == "__main__":
    unittest.main()

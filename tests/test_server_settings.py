from __future__ import annotations

from twn_toolkit.server_settings import (
    ServerSettingsStore,
    normalize_allowed_networks,
    normalize_instance_name,
    normalize_preferred_fqdn,
)


def test_normalizes_addresses_and_networks():
    assert normalize_allowed_networks(
        "192.168.1.42\n192.168.1.0/24, 2001:db8::1"
    ) == [
        "192.168.1.42/32",
        "192.168.1.0/24",
        "2001:db8::1/128",
    ]


def test_loopback_is_always_allowed_and_remote_clients_require_trust(tmp_path):
    store = ServerSettingsStore(str(tmp_path))

    assert store.client_allowed("127.0.0.1")
    assert store.client_allowed("::1")
    assert store.client_allowed("10.20.30.40")
    assert store.client_allowed("172.31.255.254")
    assert store.client_allowed("192.168.1.25")
    assert not store.client_allowed("198.51.100.25")

    store.save("0.0.0.0", "192.168.1.0/24")
    assert store.client_allowed("192.168.1.25")
    assert not store.client_allowed("192.168.2.25")


def test_save_preserves_previous_settings_for_restart_rollback(tmp_path):
    store = ServerSettingsStore(str(tmp_path))
    store.save("0.0.0.0", "10.0.0.0/8")

    assert store.get() == {
        "listen_host": "0.0.0.0",
        "allowed_networks": ["10.0.0.0/8"],
        "instance_name": "",
        "preferred_fqdn": "",
    }
    assert store.previous_path.exists()
    assert '"listen_host": "0.0.0.0"' in store.previous_path.read_text()


def test_normalizes_instance_identity_without_resolving_dns():
    assert normalize_instance_name(" WiFi-Tools ") == "wifi-tools"
    assert normalize_preferred_fqdn(" WiFi-Tools.Home.Arpa ") == "wifi-tools.home.arpa"
    try:
        normalize_instance_name("bad name")
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid short name was accepted")
    for invalid in ("single-label", "https://toolkit.example", "toolkit.example:5050", "-bad.example", "bad_.example"):
        try:
            normalize_preferred_fqdn(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Invalid FQDN was accepted: {invalid}")


def test_save_and_restore_preserve_identity(tmp_path):
    store = ServerSettingsStore(str(tmp_path))
    store.save("0.0.0.0", "10.0.0.0/8", "Home-Tools", "tools.home.arpa")
    assert store.get()["instance_name"] == "home-tools"
    assert store.get()["preferred_fqdn"] == "tools.home.arpa"

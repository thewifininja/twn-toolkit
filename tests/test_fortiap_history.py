from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.fortiap_history import normalize_client_mac, wireless_client_history


@dataclass
class FakeWirelessSource:
    log_rows: list[dict[str, Any]]
    live_rows: list[dict[str, Any]]
    label: str = "Fake source"

    def logs(self, mac: str, vdom: str, hours: int) -> list[dict[str, Any]]:
        return self.log_rows

    def live_clients(self, mac: str, vdom: str) -> list[dict[str, Any]]:
        return self.live_rows


def test_normalizes_common_client_mac_formats():
    assert normalize_client_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_client_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_client_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"


def test_wireless_history_collapses_consecutive_events_by_ap():
    history = wireless_client_history(
        FakeWirelessSource(
            log_rows=[
                {
                    "date": "2026-07-08",
                    "time": "10:00:00",
                    "srcmac": "AA-BB-CC-DD-EE-FF",
                    "wtp_name": "Lobby-AP",
                    "ssid": "Corp",
                    "msg": "Assoc Req from client",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:02:00",
                    "srcmac": "aa:bb:cc:dd:ee:ff",
                    "wtp_name": "Lobby-AP",
                    "ssid": "Corp",
                    "msg": "Assoc Req retry from client",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:05:00",
                    "msg": "Assoc Req station aabb.ccdd.eeff roamed to AP 'Hallway-AP'",
                    "ssid": "Corp",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:08:00",
                    "srcmac": "AA-BB-CC-DD-EE-FF",
                    "apname": "Lobby-AP",
                    "ssid": "Corp",
                    "msg": "Assoc Req roamed back",
                },
            ],
            live_rows=[
                {
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "wtp_name": "Lobby-AP",
                    "ssid": "Corp",
                    "ip": "192.0.2.44",
                }
            ],
        ),
        "aabbccddeeff",
        "root",
        24,
    )

    assert history["mac"] == "aa:bb:cc:dd:ee:ff"
    assert history["log_row_count"] == 4
    assert history["omitted_unknown_ap_count"] == 0
    assert history["ap_path"] == ["Lobby-AP", "Hallway-AP", "Lobby-AP"]
    assert history["timeline"][0]["event_count"] == 2
    assert history["timeline"][0]["last_time"] == "2026-07-08 10:02:00"
    assert history["live_clients"][0]["ap"] == "Lobby-AP"


def test_wireless_history_sorts_fortigate_date_time_chronologically():
    history = wireless_client_history(
        FakeWirelessSource(
            log_rows=[
                {
                    "date": "2026-07-08",
                    "time": "10:08:00",
                    "srcmac": "aa:bb:cc:dd:ee:ff",
                    "ap": "Kitchen-AP",
                    "msg": "Assoc Req",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:01:00",
                    "srcmac": "aa:bb:cc:dd:ee:ff",
                    "ap": "Office-AP",
                    "msg": "Assoc Req",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:04:00",
                    "srcmac": "aa:bb:cc:dd:ee:ff",
                    "ap": "Living-Room-AP",
                    "msg": "Assoc Req",
                },
            ],
            live_rows=[],
        ),
        "aa:bb:cc:dd:ee:ff",
        "root",
        24,
    )

    assert history["ap_path"] == ["Office-AP", "Living-Room-AP", "Kitchen-AP"]


def test_wireless_history_omits_unknown_ap_rows_when_named_events_exist():
    history = wireless_client_history(
        FakeWirelessSource(
            log_rows=[
                {
                    "date": "2026-07-08",
                    "time": "10:00:00",
                    "msg": "Assoc Req client 98:e2:55:3c:bc:ea status update",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:01:00",
                    "dstmac": "98-e2-55-3c-bc-ea",
                    "msg": "Assoc Req client roamed to AP Halway-231K",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:04:00",
                    "clientmac": "98e2553cbcea",
                    "fap_name": "MB-441K",
                    "msg": "Association Request",
                },
            ],
            live_rows=[],
        ),
        "98:e2:55:3c:bc:ea",
        "root",
        24,
    )

    assert history["ap_path"] == ["Halway-231K", "MB-441K"]
    assert history["omitted_unknown_ap_count"] == 1


def test_wireless_history_uses_fortigate_wireless_history_events():
    history = wireless_client_history(
        FakeWirelessSource(
            log_rows=[
                {
                    "date": "2026-07-08",
                    "time": "10:00:00",
                    "srcmac": "98:e2:55:3c:bc:ea",
                    "ap": "MB-441K",
                    "msg": "client RSSI update",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:01:00",
                    "srcmac": "98:e2:55:3c:bc:ea",
                    "ap": "Hallway-231K",
                    "logdesc": "Wireless client authenticated",
                    "msg": "Client 98:e2:55:3c:bc:ea authenticated.",
                },
                {
                    "date": "2026-07-08",
                    "time": "10:02:00",
                    "srcmac": "98:e2:55:3c:bc:ea",
                    "ap": "MB-441K",
                    "logdesc": "Wireless client IP assigned",
                    "msg": "Client 98:e2:55:3c:bc:ea had an IP address detected.",
                },
            ],
            live_rows=[],
        ),
        "98:e2:55:3c:bc:ea",
        "root",
        24,
    )

    assert history["ap_path"] == ["Hallway-231K", "MB-441K"]
    assert history["raw_event_count"] == 2


def test_client_history_route_renders_results(tmp_path):
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    client = app.test_client()
    (tmp_path / "profiles.json").write_text(
        """
        [
          {
            "name": "Lab",
            "host": "https://fortigate.example",
            "api_key": "secret",
            "verify_tls": true,
            "is_default": true,
            "default_vdom": "root"
          }
        ]
        """,
        encoding="utf-8",
    )

    with patch(
        "twn_toolkit.app.wireless_client_history",
        return_value={
            "mac": "aa:bb:cc:dd:ee:ff",
            "vdom": "root",
            "hours": 24,
            "source": "Local FortiGate",
            "timeline": [
                {
                    "ap": "Lobby-AP",
                    "first_time": "2026-07-08 10:00:00",
                    "last_time": "2026-07-08 10:02:00",
                    "event_count": 2,
                    "ssid": "Corp",
                    "radio": "",
                    "channel": "",
                    "ip": "",
                    "details": "associated",
                    "event": "wireless event",
                }
            ],
            "raw_event_count": 2,
            "omitted_unknown_ap_count": 0,
            "live_clients": [],
            "log_error": "",
            "live_error": "",
            "ap_path": ["Lobby-AP"],
        },
    ) as history:
        response = client.post(
            "/fortigate/fortiap/client-history",
            data={
                "profile": "Lab",
                "mac": "aabb.ccdd.eeff",
                "hours": "24",
                "vdom": "",
            },
        )

    assert response.status_code == 200
    assert b"Find Wireless Client History" in response.data
    assert b"Lobby-AP" in response.data
    history.assert_called_once()

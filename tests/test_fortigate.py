from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

from twn_toolkit.fortigate import FortiGateClient


class FortiGateClientTests(unittest.TestCase):
    @patch("twn_toolkit.fortigate.requests.request")
    def test_moves_managed_switch_after_reference(self, request: Mock) -> None:
        response = Mock()
        response.status_code = 200
        response.content = b'{"status":"success"}'
        response.json.return_value = {"status": "success"}
        request.return_value = response

        client = FortiGateClient(
            host="https://fortigate.example",
            api_key="secret",
        )
        client.move_managed_switch_after("switch b", "switch-a", "root")

        request.assert_called_once_with(
            "PUT",
            "https://fortigate.example/api/v2/cmdb/switch-controller/managed-switch/switch%20b",
            headers={
                "Authorization": "Bearer secret",
                "Accept": "application/json",
            },
            params={
                "vdom": "root",
                "action": "move",
                "after": "switch-a",
            },
            json=None,
            verify=True,
            timeout=20,
        )

    @patch("twn_toolkit.fortigate.requests.request")
    def test_wireless_log_lookup_uses_station_mac_filter_and_history_events(self, request: Mock) -> None:
        first = Mock()
        first.status_code = 200
        first.content = b'{"results":[{"stamac":"aa:bb:cc:dd:ee:ff","logdesc":"Wireless client authenticated","ap":"Hallway-AP"}]}'
        first.json.return_value = {
            "results": [
                {
                    "stamac": "aa:bb:cc:dd:ee:ff",
                    "logdesc": "Wireless client authenticated",
                    "ap": "Hallway-AP",
                }
            ]
        }
        second = Mock()
        second.status_code = 200
        second.content = b'{"results":[{"stamac":"aa:bb:cc:dd:ee:ff","logdesc":"Wireless client IP assigned","ap":"Kitchen-AP"}]}'
        second.json.return_value = {
            "results": [
                {
                    "stamac": "aa:bb:cc:dd:ee:ff",
                    "logdesc": "Wireless client IP assigned",
                    "ap": "Kitchen-AP",
                }
            ]
        }
        empty = Mock()
        empty.status_code = 200
        empty.content = b'{"results":[]}'
        empty.json.return_value = {"results": []}
        responses = [first, second]

        def response_for_request(*_args, **_kwargs):
            return responses.pop(0) if responses else empty

        request.side_effect = response_for_request

        client = FortiGateClient(
            host="https://fortigate.example",
            api_key="secret",
        )
        rows = client.get_wireless_client_logs("aa:bb:cc:dd:ee:ff", "root", 24)

        self.assertEqual([row["ap"] for row in rows], ["Hallway-AP", "Kitchen-AP"])
        self.assertEqual(request.call_count, 3)
        first_params = request.call_args_list[0].kwargs["params"]
        self.assertEqual(first_params["filter"], json.dumps({"stamac": "= aa:bb:cc:dd:ee:ff"}))
        self.assertEqual(first_params["timeframe"], "realtime")
        self.assertEqual(first_params["limit"], 10_000)


if __name__ == "__main__":
    unittest.main()

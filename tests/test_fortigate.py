from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()

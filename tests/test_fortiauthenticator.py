from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.fortiauthenticator import FortiAuthenticatorClient, FortiAuthenticatorError


class FortiAuthenticatorClientTests(unittest.TestCase):
    @patch("twn_toolkit.fortiauthenticator.requests.request")
    def test_connection_uses_basic_auth_and_limited_mac_query(self, request: Mock) -> None:
        response = Mock(status_code=200, content=b'{"meta": {"total_count": 12}, "objects": []}')
        response.json.return_value = {"meta": {"total_count": 12}, "objects": []}
        request.return_value = response

        result = FortiAuthenticatorClient(
            host="https://fac.example.com",
            username="api-user",
            password="secret",
            verify_tls=False,
            timeout=30,
        ).test_connection()

        self.assertEqual(result["meta"]["total_count"], 12)
        _method, url = request.call_args.args
        self.assertEqual((_method, url), ("GET", "https://fac.example.com/api/v1/macdevices/"))
        self.assertEqual(request.call_args.kwargs["params"], {"limit": 1})
        self.assertEqual(request.call_args.kwargs["auth"].username, "api-user")
        self.assertEqual(request.call_args.kwargs["auth"].password, "secret")
        self.assertFalse(request.call_args.kwargs["verify"])
        self.assertEqual(request.call_args.kwargs["timeout"], (3.0, 30.0))

    @patch("twn_toolkit.fortiauthenticator.requests.request")
    def test_unreachable_host_fails_with_clear_connection_message(self, request: Mock) -> None:
        request.side_effect = requests.ConnectTimeout("timed out")

        with self.assertRaisesRegex(FortiAuthenticatorError, "Could not connect.*within 3 seconds"):
            FortiAuthenticatorClient(
                host="https://fac.example.com",
                username="api-user",
                password="secret",
                timeout=30,
            ).test_connection()

    @patch("twn_toolkit.fortiauthenticator.requests.request")
    def test_short_profile_timeout_caps_connect_timeout(self, request: Mock) -> None:
        request.return_value = Mock(status_code=204, content=b"")

        FortiAuthenticatorClient(
            host="https://fac.example.com",
            username="api-user",
            password="secret",
            timeout=1,
        ).test_connection()

        self.assertEqual(request.call_args.kwargs["timeout"], (1.0, 1.0))

    @patch("twn_toolkit.fortiauthenticator.requests.request")
    def test_connection_explains_authentication_failure(self, request: Mock) -> None:
        response = Mock(
            status_code=401,
            content=b'{"detail": "Unauthorized"}',
            reason="Unauthorized",
            headers={"Content-Type": "application/json"},
        )
        response.json.return_value = {"detail": "Unauthorized"}
        request.return_value = response

        with self.assertRaisesRegex(FortiAuthenticatorError, "Confirm the username, password"):
            FortiAuthenticatorClient("https://fac.example.com", "user", "bad").test_connection()

    @patch("twn_toolkit.fortiauthenticator.requests.request")
    def test_mac_devices_follow_pagination(self, request: Mock) -> None:
        first = Mock(status_code=200, content=b"page-one")
        first.json.return_value = {
            "meta": {"next": "/api/v1/macdevices/?limit=2&offset=2"},
            "objects": [{"id": 1}, {"id": 2}],
        }
        second = Mock(status_code=200, content=b"page-two")
        second.json.return_value = {
            "meta": {"next": None},
            "objects": [{"id": 3}],
        }
        request.side_effect = [first, second]

        rows = FortiAuthenticatorClient(
            "https://fac.example.com",
            "user",
            "key",
        ).get_all_mac_devices(page_size=2)

        self.assertEqual(rows, [{"id": 1}, {"id": 2}, {"id": 3}])
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0].kwargs["params"], {"limit": 2})
        self.assertIsNone(request.call_args_list[1].kwargs["params"])
        self.assertEqual(
            request.call_args_list[1].args[1],
            "https://fac.example.com/api/v1/macdevices/?limit=2&offset=2",
        )

    @patch("twn_toolkit.fortiauthenticator.FortiAuthenticatorClient.get_all")
    def test_group_memberships_use_paginated_collection(self, get_all: Mock) -> None:
        get_all.return_value = [{"id": 7}]
        client = FortiAuthenticatorClient("https://fac.example.com", "user", "key")

        self.assertEqual(client.get_all_mac_group_memberships(page_size=250), [{"id": 7}])
        get_all.assert_called_once_with("/api/v1/macgroup-memberships/", page_size=250)

    @patch("twn_toolkit.fortiauthenticator.requests.request")
    def test_cleanup_delete_methods_use_collection_resource_urls(self, request: Mock) -> None:
        request.return_value = Mock(status_code=204, content=b"")
        client = FortiAuthenticatorClient("https://fac.example.com", "user", "key")

        client.delete_mac_group_membership("91")
        client.delete_mac_device("42")

        self.assertEqual(
            [call.args[:2] for call in request.call_args_list],
            [
                ("DELETE", "https://fac.example.com/api/v1/macgroup-memberships/91/"),
                ("DELETE", "https://fac.example.com/api/v1/macdevices/42/"),
            ],
        )


class FortiAuthenticatorRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.app = create_app(instance_path=self.temporary_directory.name)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def create_profile(self) -> None:
        self.client.post(
            "/fortiauthenticator/profiles",
            data={
                "name": "Lab",
                "host": "https://fac.example.com",
                "username": "api-user",
                "password": "access-key",
                "timeout": "20",
                "is_default": "on",
            },
        )

    def test_profile_create_edit_default_and_delete(self) -> None:
        response = self.client.post(
            "/fortiauthenticator/profiles",
            data={
                "name": "Primary",
                "host": "fac.example.com",
                "username": "api-user",
                "password": "secret-one",
                "timeout": "25",
                "verify_tls": "on",
                "is_default": "on",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Saved FortiAuthenticator profile", response.data)
        self.assertNotIn(b"secret-one", response.data)

        profile_path = os.path.join(self.temporary_directory.name, "fortiauthenticator_profiles.json")
        with open(profile_path, encoding="utf-8") as handle:
            profile = json.load(handle)[0]
        self.assertEqual(profile["host"], "https://fac.example.com")
        self.assertEqual(profile["timeout"], 25)
        self.assertEqual(oct(os.stat(profile_path).st_mode & 0o777), "0o600")

        self.client.post(
            "/fortiauthenticator/profiles",
            data={
                "original_name": "Primary",
                "name": "Renamed",
                "host": "https://fac.example.com",
                "username": "new-user",
                "password": "",
                "timeout": "20",
            },
        )
        with open(profile_path, encoding="utf-8") as handle:
            profile = json.load(handle)[0]
        self.assertEqual(profile["name"], "Renamed")
        self.assertEqual(profile["password"], "secret-one")

        response = self.client.post(
            "/fortiauthenticator/profiles/Renamed/delete",
            follow_redirects=True,
        )
        self.assertIn(b"Deleted FortiAuthenticator profile", response.data)
        with open(profile_path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), [])

    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.test_connection")
    def test_saved_profile_connection(self, test_connection: Mock) -> None:
        self.client.post(
            "/fortiauthenticator/profiles",
            data={
                "name": "Lab",
                "host": "https://fac.example.com",
                "username": "api-user",
                "password": "secret",
                "timeout": "20",
            },
        )
        test_connection.return_value = {"meta": {"total_count": 42}, "objects": []}
        response = self.client.post(
            "/fortiauthenticator/profiles/Lab/test",
            follow_redirects=True,
        )
        self.assertIn(b"42 MAC devices available", response.data)
        summary = ActivityStore(self.temporary_directory.name).summary()
        self.assertEqual(summary["counters"]["fortinet"]["api_calls"], 1)
        self.assertEqual(summary["counters"]["fortinet"]["failures"], 0)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["scoreboard"][0]["username"], "test-user")
        self.assertEqual(summary["recent"][0]["title"], "Tested FortiAuthenticator profile")
        self.assertEqual(summary["recent"][0]["detail"], "Lab: 42 MAC devices available")

    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_devices")
    def test_mac_device_preview_and_csv_export(self, get_all_mac_devices: Mock) -> None:
        self.client.post(
            "/fortiauthenticator/profiles",
            data={
                "name": "Lab",
                "host": "https://fac.example.com",
                "username": "api-user",
                "password": "access-key",
                "timeout": "20",
                "is_default": "on",
            },
        )
        get_all_mac_devices.return_value = [
            {
                "address": "11:22:33:44:55:66",
                "name": "Printer",
                "description": "Front office",
                "resource_uri": "/api/v1/macdevices/42/",
            },
            {
                "address": "aa:bb:cc:dd:ee:ff",
                "name": "Phone",
                "description": "",
                "resource_uri": "/api/v1/macdevices/43/",
            },
        ]

        response = self.client.post(
            "/fortiauthenticator/mac-devices",
            data={"profile": "Lab"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"2 devices fetched", response.data)
        self.assertIn(b"11:22:33:44:55:66", response.data)
        self.assertIn(b"Front office", response.data)

        response = self.client.post(
            "/fortiauthenticator/mac-devices.csv",
            data={"profile": "Lab"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn("attachment; filename=", response.headers["Content-Disposition"])
        self.assertEqual(
            response.get_data(as_text=True),
            "ID,MAC Address,Name,Description,Resource URI\n"
            "42,11:22:33:44:55:66,Printer,Front office,/api/v1/macdevices/42/\n"
            "43,aa:bb:cc:dd:ee:ff,Phone,,/api/v1/macdevices/43/\n",
        )
        summary = ActivityStore(self.temporary_directory.name).summary()
        self.assertEqual(summary["counters"]["fortinet"]["api_calls"], 2)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["recent"][0]["title"], "Exported FortiAuthenticator MAC devices")

    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_group_memberships")
    def test_group_membership_preview_and_csv_export(self, get_memberships: Mock) -> None:
        self.client.post(
            "/fortiauthenticator/profiles",
            data={
                "name": "Lab",
                "host": "https://fac.example.com",
                "username": "api-user",
                "password": "access-key",
                "timeout": "20",
                "is_default": "on",
            },
        )
        get_memberships.return_value = [
            {
                "id": 91,
                "device": "/api/v1/macdevices/42/",
                "device_name": "Printer",
                "group": "/api/v1/macgroups/8/",
                "group_name": "Office Devices",
                "expiry_time": None,
                "resource_uri": "/api/v1/macgroup-memberships/91/",
            }
        ]

        response = self.client.post(
            "/fortiauthenticator/mac-group-memberships",
            data={"profile": "Lab"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"1 membership fetched", response.data)
        self.assertIn(b"Office Devices", response.data)
        self.assertIn(b">42<", response.data)

        response = self.client.post(
            "/fortiauthenticator/mac-group-memberships.csv",
            data={"profile": "Lab"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn("attachment; filename=", response.headers["Content-Disposition"])
        self.assertEqual(
            response.get_data(as_text=True),
            "Membership ID,Device ID,Device Name,Device URI,Group ID,Group Name,Group URI,"
            "Expiry Time,Resource URI\n"
            "91,42,Printer,/api/v1/macdevices/42/,8,Office Devices,/api/v1/macgroups/8/,,"
            "/api/v1/macgroup-memberships/91/\n",
        )
        summary = ActivityStore(self.temporary_directory.name).summary()
        self.assertEqual(summary["counters"]["fortinet"]["api_calls"], 2)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(
            summary["recent"][0]["title"],
            "Exported FortiAuthenticator MAC memberships",
        )

    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_devices")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_group_memberships")
    def test_global_cleanup_preview_warns_about_other_groups(
        self,
        get_memberships: Mock,
        get_devices: Mock,
    ) -> None:
        self.create_profile()
        get_memberships.return_value = _cleanup_memberships()
        get_devices.return_value = _cleanup_devices()

        response = self.client.post(
            "/fortiauthenticator/mac-cleanup",
            data={
                "profile": "Lab",
                "group_uri": "/api/v1/macgroups/8/",
                "action": "delete_devices",
                "intent": "preview",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"DELETE 2 DEVICES", response.data)
        self.assertIn(b"1 target", response.data)
        self.assertIn(b"also belongs to another group", response.data)
        self.assertIn(b"Other Group", response.data)
        self.assertIn(b'id="cleanup-select-all"', response.data)
        self.assertIn(b'name="selected_id"', response.data)
        self.assertIn(b'value="42"', response.data)
        self.assertIn(b'value="43"', response.data)

    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.delete_mac_device")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_devices")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_group_memberships")
    def test_cleanup_rejects_incorrect_confirmation(
        self,
        get_memberships: Mock,
        get_devices: Mock,
        delete_device: Mock,
    ) -> None:
        self.create_profile()
        get_memberships.return_value = _cleanup_memberships()
        get_devices.return_value = _cleanup_devices()

        response = self.client.post(
            "/fortiauthenticator/mac-cleanup/execute",
            data={
                "profile": "Lab",
                "group_uri": "/api/v1/macgroups/8/",
                "action": "delete_devices",
                "selected_id": ["42", "43"],
                "confirmation": "DELETE",
            },
            follow_redirects=True,
        )

        self.assertIn(b"Confirmation did not match", response.data)
        delete_device.assert_not_called()
        event = AuditStore(self.temporary_directory.name).recent(1)[0]
        self.assertEqual(
            event["action"],
            "fortiauthenticator.mac_cleanup_aborted_confirmation",
        )
        self.assertEqual(event["details"]["requested target count"], 2)

    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.delete_mac_group_membership")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_devices")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_group_memberships")
    def test_cleanup_removes_only_selected_memberships(
        self,
        get_memberships: Mock,
        get_devices: Mock,
        delete_membership: Mock,
    ) -> None:
        self.create_profile()
        get_memberships.return_value = _cleanup_memberships()
        get_devices.return_value = _cleanup_devices()

        response = self.client.post(
            "/fortiauthenticator/mac-cleanup/execute",
            data={
                "profile": "Lab",
                "group_uri": "/api/v1/macgroups/8/",
                "action": "remove_memberships",
                "selected_id": ["91"],
                "confirmation": "REMOVE 1 MEMBERSHIP",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Group membership removed", response.data)
        self.assertCountEqual(
            [call.args[0] for call in delete_membership.call_args_list],
            ["91"],
        )
        summary = ActivityStore(self.temporary_directory.name).summary()
        self.assertEqual(summary["counters"]["fortinet"]["api_calls"], 3)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["recent"][0]["title"], "Ran FortiAuthenticator MAC cleanup")
        event = AuditStore(self.temporary_directory.name).recent(1)[0]
        audit_database = Path(
            self.temporary_directory.name, "audit.sqlite3"
        ).read_bytes()
        self.assertEqual(
            event["action"],
            "fortiauthenticator.mac_cleanup_succeeded",
        )
        self.assertEqual(event["details"]["successful target count"], 1)
        self.assertEqual(event["details"]["failed target count"], 0)
        self.assertNotIn(b"secret", audit_database)
        self.assertNotIn(b"aa:bb:cc", audit_database.lower())

    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.delete_mac_device")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_devices")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_group_memberships")
    def test_cleanup_deletes_each_device_globally(
        self,
        get_memberships: Mock,
        get_devices: Mock,
        delete_device: Mock,
    ) -> None:
        self.create_profile()
        get_memberships.return_value = _cleanup_memberships()
        get_devices.return_value = _cleanup_devices()

        response = self.client.post(
            "/fortiauthenticator/mac-cleanup/execute",
            data={
                "profile": "Lab",
                "group_uri": "/api/v1/macgroups/8/",
                "action": "delete_devices",
                "selected_id": ["42", "43"],
                "confirmation": "DELETE 2 DEVICES",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"MAC device deleted globally", response.data)
        self.assertCountEqual(
            [call.args[0] for call in delete_device.call_args_list],
            ["42", "43"],
        )

    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.delete_mac_device")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_devices")
    @patch("twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.get_all_mac_group_memberships")
    def test_cleanup_rejects_target_not_in_fresh_preview(
        self,
        get_memberships: Mock,
        get_devices: Mock,
        delete_device: Mock,
    ) -> None:
        self.create_profile()
        get_memberships.return_value = _cleanup_memberships()
        get_devices.return_value = _cleanup_devices()

        response = self.client.post(
            "/fortiauthenticator/mac-cleanup/execute",
            data={
                "profile": "Lab",
                "group_uri": "/api/v1/macgroups/8/",
                "action": "delete_devices",
                "selected_id": ["42", "999"],
                "confirmation": "DELETE 2 DEVICES",
            },
            follow_redirects=True,
        )

        self.assertIn(b"selected targets changed after the preview", response.data)
        delete_device.assert_not_called()

def _cleanup_memberships() -> list[dict[str, object]]:
    return [
        {
            "id": 91,
            "device": "/api/v1/macdevices/42/",
            "device_name": "Printer",
            "group": "/api/v1/macgroups/8/",
            "group_name": "Cleanup Group",
            "resource_uri": "/api/v1/macgroup-memberships/91/",
        },
        {
            "id": 92,
            "device": "/api/v1/macdevices/43/",
            "device_name": "Phone",
            "group": "/api/v1/macgroups/8/",
            "group_name": "Cleanup Group",
            "resource_uri": "/api/v1/macgroup-memberships/92/",
        },
        {
            "id": 93,
            "device": "/api/v1/macdevices/42/",
            "device_name": "Printer",
            "group": "/api/v1/macgroups/9/",
            "group_name": "Other Group",
            "resource_uri": "/api/v1/macgroup-memberships/93/",
        },
    ]


def _cleanup_devices() -> list[dict[str, object]]:
    return [
        {
            "address": "11:22:33:44:55:66",
            "name": "Printer",
            "resource_uri": "/api/v1/macdevices/42/",
        },
        {
            "address": "aa:bb:cc:dd:ee:ff",
            "name": "Phone",
            "resource_uri": "/api/v1/macdevices/43/",
        },
    ]


if __name__ == "__main__":
    unittest.main()

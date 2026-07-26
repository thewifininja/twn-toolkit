from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.audit import AuditStore
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.ssh_commandlets import (
    SSHCommandletStore,
    build_ssh_command_plans,
    normalize_variable_name,
    parse_ssh_target_matrix,
    referenced_ssh_variables,
    render_ssh_command,
)


class SSHCommandletParserTests(unittest.TestCase):
    def test_pipe_matrix_normalizes_headers_and_adds_built_ins(self) -> None:
        matrix = parse_ssh_target_matrix(
            """
            Name | IP/FQDN | VLAN ID | IP_Address
            Switch 1 | 10.103.255.2 | 4 | 10.103.255.1
            Switch 2 | switch-2.example.com | 8 | 10.103.255.17
            """
        )

        self.assertEqual(
            [header["key"] for header in matrix["headers"]],
            ["name", "host", "vlan_id", "ip_address"],
        )
        self.assertEqual(
            matrix["variable_names"],
            ["name", "host", "row_number", "vlan_id", "ip_address"],
        )
        self.assertEqual(matrix["targets"][0]["label"], "Switch 1")
        self.assertEqual(matrix["targets"][0]["variables"]["row_number"], "1")
        self.assertEqual(
            matrix["targets"][1]["variables"]["host"], "switch-2.example.com"
        )

    def test_tab_and_quoted_csv_matrices_are_supported(self) -> None:
        tabbed = parse_ssh_target_matrix("Host\tSite\nswitch-1\tHQ")
        comma = parse_ssh_target_matrix(
            'Name,Host,Description\n"Switch, Main",switch-1,"HQ, first floor"'
        )

        self.assertEqual(tabbed["targets"][0]["variables"]["site"], "HQ")
        self.assertEqual(comma["targets"][0]["variables"]["name"], "Switch, Main")
        self.assertEqual(
            comma["targets"][0]["variables"]["description"], "HQ, first floor"
        )

    def test_matrix_rejects_missing_host_duplicate_headers_and_bad_rows(self) -> None:
        with self.assertRaisesRegex(ToolInputError, "Host or IP/FQDN"):
            parse_ssh_target_matrix("Name | VLAN\nSwitch 1 | 4")
        with self.assertRaisesRegex(ToolInputError, "unique after normalization"):
            parse_ssh_target_matrix(
                "Host | VLAN ID | VLAN-ID\nswitch-1 | 4 | 5"
            )
        with self.assertRaisesRegex(ToolInputError, "row 2 has 1 value"):
            parse_ssh_target_matrix("Host | VLAN\nswitch-1")
        with self.assertRaisesRegex(ToolInputError, "Invalid host"):
            parse_ssh_target_matrix("Host | VLAN\n192.0.2.999 | 4")

    def test_variables_are_literal_and_escaped_references_remain_literal(self) -> None:
        self.assertEqual(normalize_variable_name("VLAN-ID"), "vlan_id")
        self.assertEqual(
            referenced_ssh_variables(
                "vlan {{ VLAN-ID }}\naddress {{ ip_address }}"
            ),
            ["vlan_id", "ip_address"],
        )
        rendered = render_ssh_command(
            r"set vlan {{ VLAN-ID }} note \{{ untouched }}",
            {"vlan_id": "4; echo still-literal"},
        )
        self.assertEqual(
            rendered,
            "set vlan 4; echo still-literal note {{ untouched }}",
        )
        with self.assertRaisesRegex(ToolInputError, "Unknown SSH command variable"):
            render_ssh_command("show {{ missing }}", {"host": "switch-1"})
        with self.assertRaisesRegex(ToolInputError, "invalid variable reference"):
            referenced_ssh_variables("show {{ vlan_id")

    def test_build_plans_renders_and_validates_each_host(self) -> None:
        built = build_ssh_command_plans(
            """
            Name | IP/FQDN | VLAN ID | IP Address
            Closet 1 | switch-1 | 4 | 10.0.4.1
            Closet 2 | switch-2 | 8 | 10.0.8.1
            """,
            """
            interface vlan {{ vlan_id }}
            [timeout=600] ip address {{ ip_address }}
            show host {{ host }} row {{ row_number }}
            """,
            300,
        )

        self.assertEqual(
            built["plans"][0]["commands"],
            [
                "            interface vlan 4",
                "            [timeout=600] ip address 10.0.4.1",
                "            show host switch-1 row 1",
            ],
        )
        self.assertEqual(
            built["plans"][1]["command_specs"][1],
            {"command": "ip address 10.0.8.1", "timeout": 600},
        )
        with self.assertRaisesRegex(ToolInputError, "Unknown SSH command variable"):
            build_ssh_command_plans("Host | VLAN\nswitch-1 | 4", "show {{ site }}")
        with self.assertRaisesRegex(ToolInputError, "missing value"):
            build_ssh_command_plans(
                "Host | VLAN | Site\nswitch-1 | | Closet",
                "show {{ vlan }}",
            )

    def test_commandlet_store_is_owner_only_and_never_needs_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = SSHCommandletStore(instance)
            store.upsert(
                {
                    "name": "Configure VLAN",
                    "description": "Sets an access VLAN.",
                    "platform": "FortiSwitch",
                    "commands": "set vlan {{ vlan_id }}",
                    "command_timeout": 45,
                }
            )
            saved = store.get("Configure VLAN")

            self.assertEqual(saved["variables"], ["vlan_id"])
            self.assertNotIn("username", saved)
            self.assertNotIn("password", saved)
            self.assertEqual(os.stat(store.path).st_mode & 0o777, 0o600)


class SSHCommandletRouteTests(unittest.TestCase):
    def test_advanced_preview_is_required_and_run_uses_rendered_plans(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            form = {
                "mode": "advanced",
                "matrix": (
                    "Name | IP/FQDN | VLAN ID\n"
                    "Closet 1 | switch-1 | 4\n"
                    "Closet 2 | switch-2 | 8"
                ),
                "commands": "interface vlan {{ vlan_id }}\nshow host {{ host }}",
                "command_timeout": "300",
                "port": "22",
            }

            with patch("twn_toolkit.ssh_routes.run_ssh_host_plans") as run:
                missing_preview = client.post(
                    "/tools/multi-ssh",
                    data={
                        **form,
                        "action": "run",
                        "username": "admin",
                        "password": "not-rendered",
                        "confirm_execution": "on",
                    },
                )
            self.assertIn(b"Preview these commands before running them", missing_preview.data)
            run.assert_not_called()

            with patch("twn_toolkit.ssh_routes.run_ssh_host_plans") as run:
                preview = client.post(
                    "/tools/multi-ssh",
                    data={**form, "action": "preview"},
                )
            run.assert_not_called()
            self.assertIn(b"interface vlan 4", preview.data)
            self.assertIn(b"interface vlan 8", preview.data)
            token_match = re.search(
                rb'name="preview_token" type="hidden" value="([^"]+)"',
                preview.data,
            )
            self.assertIsNotNone(token_match)
            token = token_match.group(1).decode()

            result = {
                "host": "switch-1",
                "host_label": "Closet 1",
                "status": "success",
                "output": "ok",
            }
            with patch(
                "twn_toolkit.ssh_routes.run_ssh_host_plans",
                return_value=[result, {**result, "host": "switch-2", "host_label": "Closet 2"}],
            ) as run:
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        **form,
                        "action": "run",
                        "preview_token": token,
                        "username": "admin",
                        "password": "not-rendered",
                        "confirm_execution": "on",
                    },
                )

            self.assertIn(b"SSH Results", response.data)
            self.assertNotIn(b"not-rendered", response.data)
            plans = run.call_args.args[0]
            self.assertEqual(plans[0]["commands"], ["interface vlan 4", "show host switch-1"])
            self.assertEqual(plans[1]["commands"], ["interface vlan 8", "show host switch-2"])

    def test_changed_advanced_commands_invalidate_preview(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            base = {
                "mode": "advanced",
                "matrix": "Host | VLAN\nswitch-1 | 4",
                "commands": "show {{ vlan }}",
                "command_timeout": "300",
                "port": "22",
            }
            preview = client.post(
                "/tools/multi-ssh", data={**base, "action": "preview"}
            )
            token = re.search(
                rb'name="preview_token" type="hidden" value="([^"]+)"',
                preview.data,
            ).group(1).decode()

            with patch("twn_toolkit.ssh_routes.run_ssh_host_plans") as run:
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        **base,
                        "commands": "delete vlan {{ vlan }}",
                        "action": "run",
                        "preview_token": token,
                        "username": "admin",
                        "password": "secret",
                        "confirm_execution": "on",
                    },
                )

            self.assertIn(b"targets or commands changed", response.data)
            run.assert_not_called()

    def test_commandlet_save_load_delete_and_audit_exclude_command_body(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            response = client.post(
                "/tools/multi-ssh",
                data={
                    "mode": "advanced",
                    "action": "save_commandlet",
                    "commandlet_name": "Access VLAN",
                    "commandlet_description": "Configure a switch port.",
                    "commandlet_platform": "Switch OS",
                    "commands": "set private-value {{ vlan_id }}",
                    "command_timeout": "60",
                },
            )

            self.assertIn(b"Access VLAN", response.data)
            loaded = client.get(
                "/tools/multi-ssh?mode=advanced&commandlet=Access%20VLAN"
            )
            self.assertIn(b"set private-value {{ vlan_id }}", loaded.data)
            event = AuditStore(instance).recent(1)[0]
            self.assertEqual(event["action"], "ssh.commandlet_created")
            self.assertEqual(event["details"]["variables"], ["vlan_id"])
            audit_database = Path(instance, "audit.sqlite3").read_bytes()
            self.assertNotIn(b"set private-value", audit_database)

            deleted = client.post(
                "/tools/multi-ssh/commandlets/delete",
                data={"name": "Access VLAN"},
                follow_redirects=True,
            )
            self.assertIn(b"deleted", deleted.data)
            self.assertIsNone(SSHCommandletStore(instance).get("Access VLAN"))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.audit import AuditStore
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.ssh_commandlets import (
    SSH_MATRIX_ROW_LIMIT,
    SSHCommandletStore,
    SSHHostMatrixStore,
    build_ssh_command_plans,
    normalize_variable_name,
    parse_ssh_target_matrix,
    referenced_ssh_variables,
    render_ssh_command,
    ssh_matrix_command_compatibility,
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

    def test_matrix_supports_large_fleets_with_a_bounded_ceiling(self) -> None:
        fleet = parse_ssh_target_matrix(
            "Name | Host\n"
            + "\n".join(
                f"AP {index} | ap-{index}.example.com"
                for index in range(1, 126)
            )
        )
        self.assertEqual(len(fleet["targets"]), 125)

        oversized = "Name | Host\n" + "\n".join(
            f"AP {index} | ap-{index}.example.com"
            for index in range(1, SSH_MATRIX_ROW_LIMIT + 2)
        )
        with self.assertRaisesRegex(
            ToolInputError,
            f"maximum of {SSH_MATRIX_ROW_LIMIT} SSH hosts",
        ):
            parse_ssh_target_matrix(oversized)

    def test_matrix_rejects_missing_host_duplicate_headers_and_bad_rows(self) -> None:
        with self.assertRaisesRegex(ToolInputError, "Host column"):
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

    def test_command_sets_are_reusable_across_compatible_matrices(self) -> None:
        first = ssh_matrix_command_compatibility(
            "Name | Host | Interface\nCore | core-1 | port1",
            "show interface {{ interface }}",
        )
        second = ssh_matrix_command_compatibility(
            "Name | Host | Site | Interface\nEdge | edge-1 | HQ | wan1",
            "show interface {{ interface }}",
        )
        missing_column = ssh_matrix_command_compatibility(
            "Name | Host | Site\nEdge | edge-1 | HQ",
            "show interface {{ interface }}",
        )
        missing_value = ssh_matrix_command_compatibility(
            "Name | Host | Interface | Site\nEdge | edge-1 | | HQ",
            "show interface {{ interface }}",
        )

        self.assertTrue(first["compatible"])
        self.assertTrue(second["compatible"])
        self.assertEqual(missing_column["missing_variables"], ["interface"])
        self.assertEqual(len(missing_value["incomplete_targets"]), 1)

    def test_legacy_embedded_matrix_is_migrated_to_a_reusable_profile(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            Path(instance, "ssh_commandlets.json").write_text(
                json.dumps(
                    [
                        {
                            "name": "Inspect interface",
                            "description": "Legacy commandlet",
                            "platform": "FortiGate",
                            "commands": "show {{ interface }}",
                            "command_timeout": 30,
                            "target_matrix": (
                                "Name | Host | Interface\nGate | gate-1 | port1"
                            ),
                        }
                    ]
                ),
                encoding="utf-8",
            )

            commandlet_store = SSHCommandletStore(instance)
            commandlet = commandlet_store.get("Inspect interface")
            matrices = SSHHostMatrixStore(instance).all()
            stored_commands = json.loads(
                Path(instance, "ssh_commandlets.json").read_text(encoding="utf-8")
            )

            self.assertEqual(len(matrices), 1)
            self.assertEqual(commandlet["matrix_names"], [matrices[0]["name"]])
            self.assertEqual(commandlet["target_count"], 1)
            self.assertIn("gate-1", commandlet["target_matrix"])
            self.assertNotIn("target_matrix", stored_commands[0])
            self.assertEqual(
                [action["name"] for action in matrices[0]["actions"]],
                ["Inspect interface"],
            )
            commandlet_store.upsert(
                {**commandlet, "commands": "diagnose {{ interface }}"},
                original_name="Inspect interface",
            )
            self.assertEqual(
                SSHHostMatrixStore(instance).get(matrices[0]["name"])["actions"][
                    0
                ]["commands"],
                "show {{ interface }}",
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
                    "target_matrix": (
                        "Name | Host | VLAN ID\n"
                        "Closet 1 | switch-1 | 4"
                    ),
                }
            )
            saved = store.get("Configure VLAN")

            self.assertEqual(saved["variables"], ["vlan_id"])
            self.assertEqual(saved["target_count"], 1)
            self.assertIn("switch-1", saved["target_matrix"])
            self.assertNotIn("username", saved)
            self.assertNotIn("password", saved)
            self.assertEqual(os.stat(store.path).st_mode & 0o777, 0o600)


class SSHCommandletRouteTests(unittest.TestCase):
    def test_preview_is_required_and_run_uses_rendered_plans(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            form = {
                "matrix": (
                    "Name | IP/FQDN | VLAN ID\n"
                    "Closet 1 | switch-1 | 4\n"
                    "Closet 2 | switch-2 | 8"
                ),
                "commands": "interface vlan {{ vlan_id }}\nshow host {{ host }}",
                "command_timeout": "300",
                "port": "22",
            }
            initial_page = client.get("/tools/multi-ssh")
            self.assertIn(b"Fleet command workspace", initial_page.data)
            self.assertIn(b"Host matrix", initial_page.data)
            self.assertIn(b"1 \xc2\xb7 Hosts", initial_page.data)
            self.assertIn(b"2 \xc2\xb7 CLI actions", initial_page.data)
            self.assertIn(b"3 \xc2\xb7 Run", initial_page.data)
            self.assertIn(b"Raw matrix", initial_page.data)
            self.assertEqual(initial_page.data.count(b"data-ssh-matrix-mode="), 1)
            self.assertIn(b'data-ssh-matrix-toggle', initial_page.data)
            self.assertIn(b'aria-label="Switch to Raw matrix"', initial_page.data)
            self.assertIn(b'role="tablist"', initial_page.data)
            self.assertIn(b'aria-label="Add target row"', initial_page.data)
            self.assertIn(b'aria-label="Add variable column"', initial_page.data)
            self.assertIn(b"Add row", initial_page.data)
            self.assertIn(b"Add variable", initial_page.data)
            self.assertIn(b'data-ssh-target-limit="5000"', initial_page.data)
            self.assertIn(b"Names and hosts stay fixed", initial_page.data)
            self.assertNotIn(b"Name and IP/FQDN stay fixed", initial_page.data)
            self.assertNotIn(b"Basic", initial_page.data)
            self.assertNotIn(b"Advanced", initial_page.data)
            self.assertIn(b"Import host list or IP range", initial_page.data)
            self.assertIn(b"data-ssh-host-import", initial_page.data)
            self.assertIn(b"Append imported rows", initial_page.data)
            self.assertIn(b"Replace current rows", initial_page.data)
            self.assertIn(b"data-ssh-matrix data-1p-ignore", initial_page.data)
            self.assertNotIn(b"data-ssh-action-commands", initial_page.data)
            self.assertIn(b"Save the host matrix first", initial_page.data)
            self.assertNotIn(b'name="commandlet_name"', initial_page.data)
            self.assertNotIn(b'name="username"', initial_page.data)
            self.assertNotIn(b'name="password"', initial_page.data)

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
            self.assertIn(b"Connect and run", preview.data)
            self.assertIn(b'name="username"', preview.data)
            self.assertIn(b'name="password"', preview.data)
            token_match = re.search(
                rb'name="preview_token" type="hidden" value="([^"]+)"',
                preview.data,
            )
            self.assertIsNotNone(token_match)
            token = token_match.group(1).decode()

            missing_credentials = client.post(
                "/tools/multi-ssh",
                data={
                    **form,
                    "action": "run",
                    "preview_token": token,
                    "confirm_execution": "on",
                },
            )
            self.assertIn(b"Enter an SSH username", missing_credentials.data)
            self.assertIn(b"Connect and run", missing_credentials.data)
            self.assertIn(
                f'name="preview_token" type="hidden" value="{token}"'.encode(),
                missing_credentials.data,
            )

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

    def test_changed_commands_invalidate_preview(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            base = {
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

    def test_host_key_mismatch_can_retry_only_the_signed_failed_host(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            form = {
                "matrix": "Name | Host\nCloset switch | 192.0.2.20",
                "commands": "show clock",
                "command_timeout": "300",
                "port": "22",
            }
            preview = client.post(
                "/tools/multi-ssh", data={**form, "action": "preview"}
            )
            token = re.search(
                rb'name="preview_token" type="hidden" value="([^"]+)"',
                preview.data,
            ).group(1).decode()
            mismatch = {
                "host": "192.0.2.20",
                "host_label": "Closet switch",
                "status": "error",
                "output": "",
                "error": "SSH host identity changed for 192.0.2.20.",
                "host_key_mismatch": {
                    "hostname": "192.0.2.20",
                    "presented_key_type": "ssh-ed25519",
                    "presented_fingerprint": "SHA256:" + "P" * 43,
                    "expected_key_type": "ssh-ed25519",
                    "expected_fingerprint": "SHA256:" + "E" * 43,
                },
            }
            with patch(
                "twn_toolkit.ssh_routes.run_ssh_host_plans",
                return_value=[mismatch],
            ):
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        **form,
                        "action": "run",
                        "preview_token": token,
                        "username": "admin",
                        "password": "secret",
                        "confirm_execution": "on",
                    },
                )

            self.assertIn(b"Host identity changed", response.data)
            self.assertIn(b"Retry this host", response.data)
            self.assertIn(b"Verify, replace &amp; retry", response.data)
            self.assertIn(("SHA256:" + "E" * 43).encode(), response.data)
            self.assertIn(("SHA256:" + "P" * 43).encode(), response.data)
            self.assertNotIn(b"raw base64", response.data)
            retry_token = re.search(
                rb'data-retry-token="([^"]+)"', response.data
            ).group(1).decode()

            retried_result = {
                "host": "192.0.2.20",
                "host_label": "Closet switch",
                "status": "success",
                "output": "System status output",
            }
            with patch(
                "twn_toolkit.ssh_routes.forget_ssh_known_host",
                return_value={
                    "hostname": "192.0.2.20",
                    "port": 22,
                    "identity": "192.0.2.20",
                    "removed_entries": 1,
                },
            ) as forget, patch(
                "twn_toolkit.ssh_routes.run_ssh_host_plans",
                return_value=[retried_result],
            ) as retry:
                retried = client.post(
                    "/tools/multi-ssh/host-keys/retry",
                    json={
                        "retry_token": retry_token,
                        "preview_token": token,
                        "matrix": form["matrix"],
                        "commands": form["commands"],
                        "command_timeout": form["command_timeout"],
                        "username": "admin",
                        "password": "secret",
                    },
                )

            self.assertEqual(retried.status_code, 200)
            self.assertEqual(retried.get_json()["result"], retried_result)
            self.assertIn(b"Saved key replaced", retried.data)
            forget.assert_called_once_with(
                "192.0.2.20",
                22,
                "SHA256:" + "E" * 43,
                allow_missing=True,
                allow_existing_fingerprint="SHA256:" + "P" * 43,
            )
            retry_plan = retry.call_args.args[0]
            self.assertEqual(len(retry_plan), 1)
            self.assertEqual(retry_plan[0]["host"], "192.0.2.20")
            self.assertEqual(
                retry_plan[0]["required_host_key_fingerprint"],
                "SHA256:" + "P" * 43,
            )
            self.assertFalse(retry.call_args.kwargs["allow_unknown_hosts"])

    def test_host_key_retry_endpoint_rejects_invalid_token(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            with patch("twn_toolkit.ssh_routes.forget_ssh_known_host") as forget:
                response = client.post(
                    "/tools/multi-ssh/host-keys/retry",
                    json={
                        "retry_token": "invalid",
                        "preview_token": "invalid",
                        "matrix": "Host\n192.0.2.20",
                        "commands": "show clock",
                        "command_timeout": "300",
                        "username": "admin",
                        "password": "secret",
                    },
                )

            self.assertEqual(response.status_code, 400)
            forget.assert_not_called()

    def test_commandlet_save_load_delete_and_audit_exclude_command_body(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            response = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "save_commandlet",
                    "commandlet_name": "Access VLAN",
                    "commandlet_description": "Configure a switch port.",
                    "commandlet_platform": "Switch OS",
                    "commandlet_save_matrix": "on",
                    "matrix": (
                        "Name | Host | VLAN ID\n"
                        "Audit Closet | audit-target.example | 44"
                    ),
                    "commands": "set private-value {{ vlan_id }}",
                    "command_timeout": "60",
                },
            )

            self.assertIn(b"Access VLAN", response.data)
            self.assertIn(b"Host matrix", response.data)
            loaded = client.get("/tools/multi-ssh?commandlet=Access%20VLAN")
            self.assertIn(b"set private-value {{ vlan_id }}", loaded.data)
            self.assertIn(
                b"Audit Closet | audit-target.example | 44", loaded.data
            )
            stored = SSHCommandletStore(instance).get("Access VLAN")
            self.assertEqual(stored["target_count"], 1)
            self.assertIn("audit-target.example", stored["target_matrix"])
            self.assertNotIn("username", stored)
            self.assertNotIn("password", stored)
            migrated_matrix = SSHHostMatrixStore(instance).get(
                "Access VLAN targets"
            )
            self.assertEqual(
                [action["name"] for action in migrated_matrix["actions"]],
                ["Access VLAN"],
            )
            event = AuditStore(instance).recent(1)[0]
            self.assertEqual(event["action"], "ssh.commandlet_created")
            self.assertEqual(event["details"]["variables"], ["vlan_id"])
            self.assertEqual(
                event["details"]["related host matrices"],
                ["Access VLAN targets"],
            )
            audit_database = Path(instance, "audit.sqlite3").read_bytes()
            self.assertNotIn(b"set private-value", audit_database)
            self.assertNotIn(b"audit-target.example", audit_database)

            deleted = client.post(
                "/tools/multi-ssh/commandlets/delete",
                data={"name": "Access VLAN"},
                follow_redirects=True,
            )
            self.assertIn(b"deleted", deleted.data)
            self.assertIsNone(SSHCommandletStore(instance).get("Access VLAN"))
            self.assertEqual(
                SSHHostMatrixStore(instance).get("Access VLAN targets")[
                    "actions"
                ][0]["commands"],
                "set private-value {{ vlan_id }}",
            )

    def test_saved_matrices_and_command_sets_form_reusable_relationships(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            for name, host, interface in (
                ("School switches", "school-1", "port1"),
                ("Lab switches", "lab-1", "port8"),
            ):
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        "action": "save_host_matrix",
                        "host_matrix_name": name,
                        "matrix": (
                            f"Name | Host | Interface\n{name} | {host} | {interface}"
                        ),
                    },
                )
                self.assertIn(name.encode(), response.data)
                self.assertIn(b"saved", response.data)

            response = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "save_commandlet",
                    "commandlet_name": "Inspect interface",
                    "commandlet_platform": "FortiGate",
                    "host_matrix_original_name": "School switches",
                    "commands": "show {{ interface }}",
                    "command_timeout": "30",
                },
            )
            self.assertIn(b"Inspect interface", response.data)
            self.assertIn(b"saved", response.data)

            response = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "load_profiles",
                    "commandlet": "Inspect interface",
                    "host_matrix": "Lab switches",
                },
                follow_redirects=True,
            )
            self.assertIn(b"remembered pairing", response.data)
            commandlet = SSHCommandletStore(instance).get("Inspect interface")
            self.assertEqual(
                commandlet["matrix_names"], ["School switches", "Lab switches"]
            )

            loaded = client.get(
                "/tools/multi-ssh?commandlet=Inspect%20interface"
            )
            self.assertIn(b"school-1", loaded.data)
            self.assertIn(b"Copy from another matrix", loaded.data)
            self.assertIn(b"Inspect interface", loaded.data)
            self.assertIn(b"Lab switches", loaded.data)

    def test_matrix_owned_actions_can_be_reordered_duplicated_and_copied(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            for name, interface in (("School", "port1"), ("Lab", "port8")):
                client.post(
                    "/tools/multi-ssh",
                    data={
                        "action": "save_host_matrix",
                        "host_matrix_name": name,
                        "matrix": (
                            "Name | Host | Interface\n"
                            f"{name} Gate | {name.lower()}-gate | {interface}"
                        ),
                    },
                )

            for name, commands in (
                ("Inspect interface", "show {{ interface }}"),
                ("System status", "get system status"),
            ):
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        "action": "save_matrix_action",
                        "workspace": "actions",
                        "host_matrix_original_name": "School",
                        "matrix_action_name": name,
                        "matrix_action_description": f"Run {name}.",
                        "matrix_action_platform": "FortiGate",
                        "commands": commands,
                        "command_timeout": "30",
                    },
                )
                self.assertIn(name.encode(), response.data)

            moved = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "move_matrix_action",
                    "workspace": "actions",
                    "host_matrix_original_name": "School",
                    "move_action_name": "System status",
                    "move_action_direction": "up",
                },
            )
            self.assertEqual(moved.status_code, 200)
            school = SSHHostMatrixStore(instance).get("School")
            self.assertEqual(
                [action["name"] for action in school["actions"]],
                ["System status", "Inspect interface"],
            )

            duplicated = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "duplicate_matrix_action",
                    "workspace": "actions",
                    "host_matrix_original_name": "School",
                    "matrix_action_original_name": "System status",
                },
            )
            self.assertIn(b"System status (2)", duplicated.data)

            copied = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "copy_matrix_action",
                    "workspace": "actions",
                    "host_matrix_original_name": "Lab",
                    "copy_action_source": json.dumps(
                        {
                            "kind": "matrix",
                            "matrix": "School",
                            "action": "Inspect interface",
                        }
                    ),
                },
            )
            self.assertIn(b"independent action", copied.data)
            lab = SSHHostMatrixStore(instance).get("Lab")
            self.assertEqual(lab["actions"][0]["commands"], "show {{ interface }}")

            client.post(
                "/tools/multi-ssh",
                data={
                    "action": "save_matrix_action",
                    "workspace": "actions",
                    "host_matrix_original_name": "School",
                    "matrix_action_original_name": "Inspect interface",
                    "matrix_action_name": "Inspect interface",
                    "commands": "diagnose {{ interface }}",
                    "command_timeout": "30",
                },
            )
            self.assertEqual(
                SSHHostMatrixStore(instance).get("Lab")["actions"][0][
                    "commands"
                ],
                "show {{ interface }}",
            )

            deleted = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "delete_matrix_action",
                    "workspace": "actions",
                    "host_matrix_original_name": "School",
                    "matrix_action_original_name": "System status (2)",
                },
            )
            self.assertIn(b"deleted", deleted.data)
            self.assertNotIn(
                "System status (2)",
                [
                    action["name"]
                    for action in SSHHostMatrixStore(instance).get("School")[
                        "actions"
                    ]
                ],
            )

    def test_runbook_starts_empty_and_runs_actions_in_operator_order(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            client.post(
                "/tools/multi-ssh",
                data={
                    "action": "save_host_matrix",
                    "host_matrix_name": "Branches",
                    "matrix": (
                        "Name | Host | Interface\n"
                        "Branch 1 | gate-1 | port1\n"
                        "Branch 2 | gate-2 | port2"
                    ),
                },
            )
            for name, commands, timeout in (
                ("Inspect", "show {{ interface }}", "30"),
                ("Status", "[timeout=75] get system status", "20"),
            ):
                client.post(
                    "/tools/multi-ssh",
                    data={
                        "action": "save_matrix_action",
                        "workspace": "actions",
                        "host_matrix_original_name": "Branches",
                        "matrix_action_name": name,
                        "commands": commands,
                        "command_timeout": timeout,
                    },
                )

            run_workspace = client.get(
                "/tools/multi-ssh?host_matrix=Branches&workspace=run"
            )
            self.assertIn(b"No actions in this runbook", run_workspace.data)
            self.assertIn(b"0 actions", run_workspace.data)
            self.assertNotIn(b'name="selected_actions"', run_workspace.data)

            action_form = {
                "workspace": "run",
                "matrix_action_run": "on",
                "host_matrix_original_name": "Branches",
                "selected_actions": ["Status", "Inspect"],
                "port": "22",
            }
            preview = client.post(
                "/tools/multi-ssh",
                data={**action_form, "action": "preview"},
            )
            self.assertIn(b"data-ssh-runbook", preview.data)
            self.assertIn(b"2 actions", preview.data)
            self.assertIn(b"[timeout=30] show port1", preview.data)
            self.assertIn(b"[timeout=75] get system status", preview.data)
            self.assertLess(
                preview.data.index(b"[timeout=75] get system status"),
                preview.data.index(b"[timeout=30] show port1"),
            )
            token = re.search(
                rb'name="preview_token" type="hidden" value="([^"]+)"',
                preview.data,
            ).group(1).decode()

            results = [
                {
                    "host": f"gate-{index}",
                    "host_label": f"Branch {index}",
                    "status": "success",
                    "output": "ok",
                }
                for index in (1, 2)
            ]
            with patch(
                "twn_toolkit.ssh_routes.run_ssh_host_plans",
                return_value=results,
            ) as run:
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        **action_form,
                        "action": "run",
                        "preview_token": token,
                        "username": "admin",
                        "password": "secret",
                        "confirm_execution": "on",
                    },
                )

            self.assertIn(b"SSH Results", response.data)
            plans = run.call_args.args[0]
            self.assertEqual(
                [spec["command"] for spec in plans[0]["command_specs"]],
                ["get system status", "show port1"],
            )
            self.assertEqual(
                [spec["timeout"] for spec in plans[0]["command_specs"]],
                [75, 30],
            )

    def test_matrix_actions_block_missing_variables_and_unsafe_matrix_edits(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            client.post(
                "/tools/multi-ssh",
                data={
                    "action": "save_host_matrix",
                    "host_matrix_name": "Closets",
                    "matrix": "Name | Host | VLAN\nCloset 1 | switch-1 | 44",
                },
            )

            invalid_action = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "save_matrix_action",
                    "workspace": "actions",
                    "host_matrix_original_name": "Closets",
                    "matrix_action_name": "Missing interface",
                    "commands": "show {{ interface }}",
                    "command_timeout": "30",
                },
            )
            self.assertIn(b"requires missing matrix column", invalid_action.data)
            self.assertEqual(
                SSHHostMatrixStore(instance).get("Closets")["actions"], []
            )

            client.post(
                "/tools/multi-ssh",
                data={
                    "action": "save_matrix_action",
                    "workspace": "actions",
                    "host_matrix_original_name": "Closets",
                    "matrix_action_name": "Inspect VLAN",
                    "commands": "show vlan {{ vlan }}",
                    "command_timeout": "30",
                },
            )
            unsafe_edit = client.post(
                "/tools/multi-ssh",
                data={
                    "action": "save_host_matrix",
                    "workspace": "hosts",
                    "host_matrix_original_name": "Closets",
                    "host_matrix_name": "Closets",
                    "matrix": "Name | Host\nCloset 1 | switch-1",
                },
            )
            self.assertIn(b"requires missing matrix column", unsafe_edit.data)
            saved = SSHHostMatrixStore(instance).get("Closets")
            self.assertIn("VLAN", saved["matrix"])
            self.assertEqual(saved["actions"][0]["name"], "Inspect VLAN")

    def test_compact_importer_parses_friendly_hosts_and_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            response = client.post(
                "/tools/multi-ssh/import-hosts",
                data={
                    "hosts": (
                        "Core switch = core.example.com\n"
                        "Access AP = 192.0.2.10-192.0.2.12"
                    )
                },
            )

            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(payload["count"], 4)
            self.assertEqual(
                payload["targets"],
                [
                    {"label": "Core switch", "host": "core.example.com"},
                    {"label": "Access AP-0001", "host": "192.0.2.10"},
                    {"label": "Access AP-0002", "host": "192.0.2.11"},
                    {"label": "Access AP-0003", "host": "192.0.2.12"},
                ],
            )
            self.assertEqual(AuditStore(instance).recent(1), [])

            invalid = client.post(
                "/tools/multi-ssh/import-hosts",
                data={"hosts": "192.0.2.20-192.0.2.10"},
            )
            self.assertEqual(invalid.status_code, 400)
            self.assertIn("ascending order", invalid.get_json()["error"])

    def test_legacy_mode_links_redirect_and_basic_posts_become_previews(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            basic = client.get("/tools/multi-ssh?mode=basic")
            self.assertEqual(basic.status_code, 302)
            self.assertEqual(basic.headers["Location"], "/tools/multi-ssh")
            advanced = client.get(
                "/tools/multi-ssh?mode=advanced&commandlet=Access%20VLAN&duplicate=1"
            )
            self.assertEqual(advanced.status_code, 302)
            self.assertIn("commandlet=Access+VLAN", advanced.headers["Location"])
            self.assertIn("duplicate=1", advanced.headers["Location"])

            with patch("twn_toolkit.ssh_routes.run_ssh_host_plans") as run:
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        "mode": "basic",
                        "hosts": "Closet Switch = switch-1",
                        "commands": "show version",
                        "command_timeout": "300",
                        "port": "22",
                        "username": "admin",
                        "password": "must-not-render",
                        "confirm_execution": "on",
                    },
                )

            run.assert_not_called()
            self.assertIn(b"The legacy host list was imported", response.data)
            self.assertIn(b"Closet Switch|switch-1", response.data)
            self.assertIn(b"Per-host command preview", response.data)
            self.assertIn(b"Connect and run", response.data)
            self.assertIn(b'value="admin"', response.data)
            self.assertNotIn(b"must-not-render", response.data)
            self.assertRegex(
                response.data,
                rb'name="preview_token" type="hidden" value="[^"]+"',
            )


if __name__ == "__main__":
    unittest.main()

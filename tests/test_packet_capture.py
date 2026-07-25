from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import shutil
import struct
from unittest.mock import patch

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import PcapNgWriter, wrpcap

from twn_toolkit import create_app
from twn_toolkit.automation_registry import AUTOMATION_REGISTRY, ConditionResult
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.packet_capture import (
    PacketCaptureStore,
    run_packet_capture,
    validate_capture_config,
)
from twn_toolkit.pcap_viewer import inspect_packet_capture


VALID_CONFIG = {
    "interface": "en7",
    "capture_filter": "host 192.0.2.1 and port 443",
    "duration_seconds": 60,
    "packet_count": 1000,
    "max_size_mib": 25,
    "snap_length": 256,
    "promiscuous": True,
}


class PacketCaptureTests(unittest.TestCase):
    def capability_patches(self):
        return (
            patch(
                "twn_toolkit.packet_capture.capture_capability",
                return_value={
                    "available": True,
                    "executable": "/usr/sbin/tcpdump",
                    "detail": "tcpdump is available.",
                },
            ),
            patch(
                "twn_toolkit.packet_capture.capture_interfaces",
                return_value=[
                    {"index": 1, "name": "lo0", "loopback": True},
                    {"index": 7, "name": "en7", "loopback": False},
                ],
            ),
            patch("twn_toolkit.packet_capture._compile_capture_filter"),
        )

    def test_validation_bounds_and_compiles_filter(self) -> None:
        capability, interfaces, compiler = self.capability_patches()
        with capability, interfaces, compiler as compiler_mock:
            normalized = validate_capture_config(
                VALID_CONFIG, compile_filter=True
            )
        self.assertEqual(normalized, VALID_CONFIG)
        compiler_mock.assert_called_once_with(VALID_CONFIG)

        capability, interfaces, _compiler = self.capability_patches()
        with capability, interfaces:
            with self.assertRaisesRegex(ToolInputError, "5–300"):
                validate_capture_config({**VALID_CONFIG, "duration_seconds": 301})
            with self.assertRaisesRegex(ToolInputError, "available capture interface"):
                validate_capture_config({**VALID_CONFIG, "interface": "missing0"})
        with patch(
            "twn_toolkit.packet_capture.capture_capability",
            return_value={"available": False, "executable": "", "detail": "missing"},
        ):
            portable = validate_capture_config(
                {**VALID_CONFIG, "interface": "span9"}, require_runtime=False
            )
        self.assertEqual(portable["interface"], "span9")

    def test_runner_builds_bounded_tcpdump_command_and_retains_pcap(self) -> None:
        class FakeProcess:
            def __init__(self):
                self.pid = 8123
                self.returncode = None

            def poll(self):
                return self.returncode

            def send_signal(self, _signal):
                self.returncode = -2

            def communicate(self, timeout=None):
                return "", "12 packets captured\n12 packets received by filter\n0 packets dropped by kernel\n"

            def kill(self):
                self.returncode = -9

            def wait(self, timeout=None):
                return self.returncode

        with tempfile.TemporaryDirectory() as instance:
            output = Path(instance) / "capture.pcap"

            def launch(command, **_kwargs):
                output.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 28)
                launch.command = command
                return FakeProcess()

            capability, interfaces, compiler = self.capability_patches()
            with (
                capability,
                interfaces,
                compiler,
                patch("twn_toolkit.packet_capture.ensure_storage_capacity"),
                patch("twn_toolkit.packet_capture.subprocess.Popen", side_effect=launch),
                patch("twn_toolkit.packet_capture.time.sleep"),
            ):
                result = run_packet_capture(
                    VALID_CONFIG,
                    instance_path=instance,
                    output_path=output,
                    should_stop=lambda: True,
                )
        self.assertIn("-i", launch.command)
        self.assertIn("en7", launch.command)
        self.assertIn("-c", launch.command)
        self.assertIn("1000", launch.command)
        self.assertEqual(launch.command[-1], VALID_CONFIG["capture_filter"])
        self.assertEqual(result["termination_reason"], "stopped by user")
        self.assertEqual(result["packet_count_captured"], 12)
        self.assertEqual(result["size_bytes"], 32)

    def test_store_tracks_lifecycle_and_prevents_interface_overlap(self) -> None:
        capability, interfaces, compiler = self.capability_patches()
        with tempfile.TemporaryDirectory() as instance, capability, interfaces, compiler:
            store = PacketCaptureStore(instance)
            capture_id = store.create(VALID_CONFIG, created_by="admin")
            with self.assertRaisesRegex(ToolInputError, "already active"):
                store.create(VALID_CONFIG, created_by="admin")
            capture = store.begin(capture_id)
            self.assertEqual(capture["status"], "running")
            store.progress(
                capture_id,
                {"tcpdump_pid": 100, "elapsed_seconds": 4, "size_bytes": 2048},
            )
            store.request_stop(capture_id)
            self.assertTrue(store.stop_requested(capture_id))
            output = store.output_file(store.get(capture_id))
            output.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 28)
            store.finish(
                capture_id,
                status="stopped",
                result={
                    "elapsed_seconds": 5,
                    "size_bytes": 32,
                    "packet_count_captured": 3,
                    "termination_reason": "stopped by user",
                },
            )
            capture = store.get(capture_id)
            self.assertTrue(capture["downloadable"])
            store.delete(capture_id)
            self.assertIsNone(store.get(capture_id))
            self.assertFalse(output.exists())

    def test_header_viewer_decodes_endpoints_protocols_and_pages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcap"
            packets = [
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src="192.0.2.10", dst="198.51.100.20")
                / TCP(sport=49152, dport=443, flags="S"),
                Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
                / IP(src="198.51.100.20", dst="192.0.2.10")
                / UDP(sport=53, dport=49153),
            ]
            wrpcap(str(path), packets)

            first = inspect_packet_capture(path, limit=1)
            second = inspect_packet_capture(path, start=first["next_start"], limit=1)
            pcapng_path = Path(directory) / "sample.pcapng"
            writer = PcapNgWriter(str(pcapng_path))
            writer.write(packets[0])
            writer.close()
            pcapng = inspect_packet_capture(pcapng_path)

        self.assertTrue(first["has_more"])
        self.assertIsInstance(first["next_cursor"], int)
        self.assertEqual(first["packets"][0]["source_mac"], "00:11:22:33:44:55")
        self.assertEqual(first["packets"][0]["source_ip"], "192.0.2.10")
        self.assertEqual(first["packets"][0]["destination_port"], 443)
        self.assertEqual(first["packets"][0]["protocol"], "TCP")
        self.assertEqual(second["packets"][0]["protocol"], "UDP")
        self.assertFalse(second["has_more"])
        self.assertEqual(pcapng["packets"][0]["destination_ip"], "198.51.100.20")

    def test_live_viewer_resumes_at_an_incomplete_packet_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            complete = Path(directory) / "complete.pcap"
            live = Path(directory) / "live.pcap"
            packets = [
                Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=1, dport=2),
                Ether() / IP(src="192.0.2.2", dst="198.51.100.2") / UDP(sport=3, dport=4),
            ]
            wrpcap(str(complete), packets)
            data = complete.read_bytes()
            first_captured_length = struct.unpack_from("<I", data, 24 + 8)[0]
            second_record = 24 + 16 + first_captured_length
            live.write_bytes(data[: second_record + 10])

            first = inspect_packet_capture(live, allow_incomplete=True)
            live.write_bytes(data)
            second = inspect_packet_capture(
                live,
                start=first["next_start"],
                cursor=first["next_cursor"],
                allow_incomplete=True,
            )

        self.assertEqual(len(first["packets"]), 1)
        self.assertEqual(first["next_cursor"], second_record)
        self.assertEqual(second["packets"][0]["source_ip"], "192.0.2.2")

    def test_header_viewer_waits_for_live_file_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "live.pcap"
            path.touch()
            result = inspect_packet_capture(path, allow_incomplete=True)
        self.assertTrue(result["waiting"])
        self.assertEqual(result["packets"], [])

    def test_worker_launch_uses_absolute_instance_and_daemon_marker(self) -> None:
        class Worker:
            pid = 4567

        with tempfile.TemporaryDirectory() as instance:
            store = PacketCaptureStore(instance)
            with patch(
                "twn_toolkit.packet_capture.subprocess.Popen",
                return_value=Worker(),
            ) as launcher:
                store.launch("capture-id")
        command = launcher.call_args.args[0]
        self.assertIn(str(Path(instance).resolve()), command)
        self.assertIn("--daemon", command)

    def test_standalone_routes_start_report_download_and_delete(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            capability, interfaces, compiler = self.capability_patches()
            with (
                capability,
                interfaces,
                compiler,
                patch(
                    "twn_toolkit.packet_capture_routes.capture_capability",
                    return_value={
                        "available": True,
                        "executable": "/usr/sbin/tcpdump",
                        "detail": "tcpdump is available.",
                    },
                ),
                patch(
                    "twn_toolkit.packet_capture_routes.capture_interfaces",
                    return_value=[
                        {"index": 7, "name": "en7", "loopback": False}
                    ],
                ),
                patch.object(PacketCaptureStore, "launch"),
            ):
                page = client.get("/tools/packet-capture")
                response = client.post(
                    "/tools/packet-capture/start",
                    data={
                        "interface": "en7",
                        "capture_filter": "port 443",
                        "duration_seconds": "60",
                        "packet_count": "0",
                        "max_size_mib": "25",
                        "snap_length": "0",
                        "promiscuous": "on",
                    },
                )
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"switch SPAN or mirror ports", page.data)
            self.assertEqual(response.status_code, 302)
            store = PacketCaptureStore(instance)
            capture = store.recent(1)[0]
            output = store.output_file(capture)
            wrpcap(
                str(output),
                [
                    Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                    / IP(src="192.0.2.10", dst="198.51.100.20")
                    / TCP(sport=49152, dport=443, flags="S")
                ],
            )
            store.finish(
                capture["id"],
                status="completed",
                result={
                    "elapsed_seconds": 2,
                    "size_bytes": output.stat().st_size,
                    "packet_count_captured": 1,
                    "termination_reason": "packet limit reached",
                },
            )
            status = client.get(
                f"/tools/packet-capture/{capture['id']}/status"
            )
            inspected = client.get(
                f"/tools/packet-capture/{capture['id']}/packets"
            )
            download = client.get(
                f"/tools/packet-capture/{capture['id']}/download"
            )
            expected_download = output.read_bytes()
            saved = client.post(
                f"/tools/packet-capture/{capture['id']}/save",
                data={"destination": ""},
            )
            saved_path = next((Path(instance) / "datastore").glob("*.pcap"))
            inspected_saved = client.get(
                "/local/datastore/view-pcap",
                query_string={"path": saved_path.name},
            )
            completed_page = client.get("/tools/packet-capture")
            datastore_page = client.get("/local/datastore")
            deleted = client.post(
                f"/tools/packet-capture/{capture['id']}/delete"
            )
            self.assertEqual(status.get_json()["packet_count"], 1)
            self.assertTrue(status.get_json()["viewable"])
            self.assertEqual(inspected.get_json()["packets"][0]["protocol"], "TCP")
            self.assertEqual(download.status_code, 200)
            self.assertEqual(download.data, expected_download)
            download.close()
            self.assertEqual(saved.status_code, 302)
            self.assertEqual(saved_path.read_bytes(), expected_download)
            self.assertEqual(
                inspected_saved.get_json()["packets"][0]["destination_port"], 443
            )
            self.assertIn(b'class="button-link secondary"', completed_page.data)
            self.assertNotIn(b"Stored packet captures", completed_page.data)
            self.assertIn(b"data-pcap-viewer-open", completed_page.data)
            self.assertIn(b'id="pcap-floating-window"', completed_page.data)
            self.assertIn(b"Inspect PCAP", datastore_page.data)
            self.assertIn(b"/local/datastore/view-pcap", datastore_page.data)
            self.assertEqual(deleted.status_code, 302)
            self.assertIsNone(store.get(capture["id"]))
            actions_page = client.get("/automations/actions")
            self.assertEqual(actions_page.status_code, 200)
            self.assertIn(b"Packet capture", actions_page.data)
            self.assertIn(b'name="capture_action_interface"', actions_page.data)
            self.assertIn(b"Collection destination", actions_page.data)
            self.assertIn(b'name="capture_action_destination_mode"', actions_page.data)
            self.assertIn(b'name="capture_action_datastore_folder"', actions_page.data)
            self.assertIn(b'data-pcap-scrim', actions_page.data)

    def test_automation_action_returns_capture_as_run_artifact(self) -> None:
        action = AUTOMATION_REGISTRY.actions["packet.capture"]
        normalized = dict(VALID_CONFIG)
        capability, interfaces, compiler = self.capability_patches()
        with capability, interfaces, compiler:
            parsed = AUTOMATION_REGISTRY.action_config_from_form(
                "packet.capture",
                {
                    "capture_action_interface": "en7",
                    "capture_action_filter": "port 443",
                    "capture_action_duration": "30",
                    "capture_action_packet_count": "50",
                    "capture_action_max_size": "10",
                    "capture_action_snap_length": "128",
                    "capture_action_promiscuous": "on",
                    "capture_action_destination_mode": "run",
                },
            )
        self.assertEqual(parsed["interface"], "en7")
        self.assertEqual(parsed["duration_seconds"], 30)
        self.assertEqual(parsed["destination_mode"], "run")

        def capture(_config, *, output_path, **_kwargs):
            Path(output_path).write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 28)
            return {
                **normalized,
                "elapsed_seconds": 5.25,
                "size_bytes": 32,
                "packet_count_captured": 9,
                "termination_reason": "duration reached",
            }

        with (
            patch(
                "twn_toolkit.automation_types.actions.validate_capture_config",
                return_value=normalized,
            ),
            patch(
                "twn_toolkit.automation_types.actions.run_packet_capture",
                side_effect=capture,
            ),
        ):
            result = action.execute(
                {**normalized, "_instance_path": "/tmp/instance"},
                ConditionResult(True, "met", "WAN degraded", {}),
            )
        artifact = result.output["_artifact_sources"][0]
        try:
            self.assertEqual(result.status, "success")
            self.assertIn("9 packet(s)", result.summary)
            self.assertEqual(Path(artifact["source_path"]).read_bytes()[:4], b"\xd4\xc3\xb2\xa1")
            self.assertTrue(artifact["filename"].endswith("-en7-capture.pcap"))
        finally:
            shutil.rmtree(Path(artifact["source_path"]).parent, ignore_errors=True)

    def test_automation_action_can_save_capture_to_datastore(self) -> None:
        action = AUTOMATION_REGISTRY.actions["packet.capture"]

        def capture(_config, *, output_path, **_kwargs):
            Path(output_path).write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 28)
            return {
                **VALID_CONFIG,
                "elapsed_seconds": 2.0,
                "size_bytes": 32,
                "packet_count_captured": 3,
                "termination_reason": "packet limit reached",
            }

        with tempfile.TemporaryDirectory() as instance:
            with (
                patch(
                    "twn_toolkit.automation_types.actions.validate_capture_config",
                    return_value=VALID_CONFIG,
                ),
                patch(
                    "twn_toolkit.automation_types.actions.run_packet_capture",
                    side_effect=capture,
                ),
            ):
                result = action.execute(
                    {
                        **VALID_CONFIG,
                        "_instance_path": instance,
                        "destination_mode": "datastore",
                        "datastore_folder": "",
                    },
                    ConditionResult(True, "met", "WAN degraded", {}),
                )

            stored_path = Path(instance) / "datastore" / result.output["stored_path"]
            self.assertEqual(result.status, "success")
            self.assertEqual(result.output["destination_mode"], "datastore")
            self.assertNotIn("_artifact_sources", result.output)
            self.assertEqual(stored_path.read_bytes()[:4], b"\xd4\xc3\xb2\xa1")


if __name__ == "__main__":
    unittest.main()

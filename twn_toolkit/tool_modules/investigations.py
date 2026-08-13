from __future__ import annotations

from twn_toolkit.tool_catalog import ToolLink, ToolRegistry


def register_tools(registry: ToolRegistry) -> None:
    registry.add_tool(
        ToolLink(
            "investigations.workspace",
            "Investigations",
            "Record troubleshooting activity, evidence, notes, and case reports in one durable workspace.",
            "investigations",
            "investigations",
            "Investigations",
            nav_icon="◎",
        )
    )
    registry.map_endpoints(
        {
            "investigations": "investigations.workspace",
            "create_investigation": "investigations.workspace",
            "investigation_detail": "investigations.workspace",
            "add_investigation_note": "investigations.workspace",
            "add_investigation_participant": "investigations.workspace",
            "remove_investigation_participant": "investigations.workspace",
            "update_investigation_state": "investigations.workspace",
            "investigation_evidence": "investigations.workspace",
            "upload_investigation_evidence": "investigations.workspace",
            "download_investigation_evidence": "investigations.workspace",
            "investigation_report": "investigations.workspace",
            "download_investigation_report_pdf": "investigations.workspace",
            "download_investigation_package": "investigations.workspace",
            "update_investigation_report_contents": "investigations.workspace",
        }
    )

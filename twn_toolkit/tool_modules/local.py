from __future__ import annotations

from twn_toolkit.tool_catalog import ToolLink, ToolRegistry


def register_tools(registry: ToolRegistry) -> None:
    registry.add_tool(
        ToolLink(
            "local.datastore",
            "Datastore",
            "Manage persistent toolkit-local files and folders.",
            "local_datastore",
            "local",
            "Local Tools",
        )
    )
    registry.add_tool(
        ToolLink(
            "local.file_transfers",
            "File Transfers",
            "Manage contained TFTP, FTP, and authenticated SFTP/SCP services.",
            "file_transfers",
            "local",
            "Local Tools",
            admin_only=True,
            risk="advanced",
        )
    )
    registry.map_endpoints(
        {
            "local_datastore": "local.datastore",
            "create_datastore_folder": "local.datastore",
            "upload_datastore_files": "local.datastore",
            "download_datastore_file": "local.datastore",
            "rename_datastore_entry": "local.datastore",
            "delete_datastore_entry": "local.datastore",
            "bulk_delete_datastore_files": "local.datastore",
            "bulk_move_datastore_files": "local.datastore",
            "file_transfers": "local.file_transfers",
            "save_tftp_settings": "local.file_transfers",
            "clear_tftp_history": "local.file_transfers",
            "upload_tftp_temporary_file": "local.file_transfers",
            "delete_tftp_temporary_file": "local.file_transfers",
            "save_ssh_transfer_settings": "local.file_transfers",
            "clear_ssh_transfer_history": "local.file_transfers",
            "upload_ssh_transfer_temporary_file": "local.file_transfers",
            "delete_ssh_transfer_temporary_file": "local.file_transfers",
            "save_ftp_settings": "local.file_transfers",
            "clear_ftp_history": "local.file_transfers",
            "upload_ftp_temporary_file": "local.file_transfers",
            "delete_ftp_temporary_file": "local.file_transfers",
        }
    )

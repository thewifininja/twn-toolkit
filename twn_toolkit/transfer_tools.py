"""Protocol-neutral transfer API.

Legacy ``sftp_tools`` symbols remain supported for saved integrations and older
imports, while new code can use terminology that covers SFTP, SCP, and FTP.
"""
from .sftp_tools import (
    SFTP_DEFAULT_FILENAME_PATTERN as DEFAULT_TRANSFER_FILENAME_PATTERN,
    fetch_ssh_files as fetch_transfer_files,
    format_sftp_filename as format_transfer_filename,
    parse_sftp_paths as parse_remote_paths,
    validate_sftp_filename_pattern as validate_transfer_filename_pattern,
)

__all__ = [
    "DEFAULT_TRANSFER_FILENAME_PATTERN", "fetch_transfer_files",
    "format_transfer_filename", "parse_remote_paths",
    "validate_transfer_filename_pattern",
]

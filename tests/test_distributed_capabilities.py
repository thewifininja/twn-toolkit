from __future__ import annotations

from unittest.mock import patch

import pytest

from twn_toolkit.distributed_capabilities import (
    advertised_capabilities,
    execute_capability,
)
from twn_toolkit.network_tools import ToolInputError


def test_manifest_advertises_versioned_finite_capabilities():
    assert advertised_capabilities() == [
        {"id": "system.http.tunnel", "version": "1"},
        {"id": "system.identity", "version": "1"},
        {"id": "tools.dns.lookup", "version": "1"},
    ]


def test_remote_dns_reuses_bounded_parser_and_returns_structured_output(tmp_path):
    result = {
        "host": "example.com",
        "host_label": "Example",
        "server": "1.1.1.1",
        "server_label": "Cloudflare",
        "record_type": "A",
        "status": "success",
        "answers": ["192.0.2.10"],
        "response_ms": 12.3,
    }
    with patch(
        "twn_toolkit.distributed_capabilities.dns_lookup_matrix",
        return_value=[result],
    ) as lookup:
        output = execute_capability(
            tmp_path,
            "tools.dns.lookup",
            "1",
            {
                "hosts": "Example = example.com",
                "servers": "Cloudflare = 1.1.1.1",
                "record_type": "A",
                "timeout": "3",
            },
        )
    assert output["summary"] == {
        "queries": 1,
        "successful": 1,
        "failed": 0,
        "average_ms": 12.3,
    }
    assert output["results"] == [result]
    lookup.assert_called_once()


def test_remote_dns_and_unknown_capabilities_fail_closed(tmp_path):
    with pytest.raises(ToolInputError, match="DNS servers cannot be empty"):
        execute_capability(
            tmp_path,
            "tools.dns.lookup",
            "1",
            {"hosts": "example.com", "servers": "", "record_type": "A"},
        )
    with pytest.raises(ValueError, match="does not support"):
        execute_capability(tmp_path, "tools.dns.lookup", "2", {})

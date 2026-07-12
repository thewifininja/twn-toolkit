from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolLink:
    id: str
    label: str
    description: str
    endpoint: str
    category: str
    category_label: str
    admin_only: bool = False
    endpoint_values: dict[str, Any] = field(default_factory=dict)
    risk: str = "standard"
    show_on_home: bool = True
    grantable: bool = True


class ToolRegistry:
    """In-process registry for toolkit tools and their route ownership."""

    def __init__(self, categories: list[dict[str, str]]) -> None:
        self.categories = categories
        self._tools: list[ToolLink] = []
        self._endpoint_tool_ids: dict[str, str] = {}

    def add_tool(self, tool: ToolLink) -> None:
        if tool.id in self.tool_by_id:
            raise ValueError(f"Duplicate tool id: {tool.id}")
        self._tools.append(tool)

    def add_tools(self, tools: list[ToolLink]) -> None:
        for tool in tools:
            self.add_tool(tool)

    def map_endpoint(self, endpoint: str, tool_id: str) -> None:
        if tool_id not in self.tool_by_id:
            raise ValueError(f"Endpoint {endpoint} maps to unknown tool id: {tool_id}")
        self._endpoint_tool_ids[endpoint] = tool_id

    def map_endpoints(self, endpoint_tool_ids: dict[str, str]) -> None:
        for endpoint, tool_id in endpoint_tool_ids.items():
            self.map_endpoint(endpoint, tool_id)

    @property
    def tools(self) -> list[ToolLink]:
        return list(self._tools)

    @property
    def tool_by_id(self) -> dict[str, ToolLink]:
        return {tool.id: tool for tool in self._tools}

    @property
    def task_tool_ids(self) -> dict[str, str]:
        return {
            str(tool.endpoint_values.get("task_id")): tool.id
            for tool in self._tools
            if tool.endpoint == "task_form" and tool.endpoint_values.get("task_id")
        }

    @property
    def endpoint_tool_ids(self) -> dict[str, str]:
        return dict(self._endpoint_tool_ids)

    def tool_id_for_endpoint(
        self, endpoint: str, view_args: dict[str, Any] | None = None
    ) -> str | None:
        if endpoint in {
            "task_form",
            "task_csv_template",
            "run_task",
            "task_objects",
            "rename_objects",
            "task_fields",
            "task_preview",
        }:
            return self.task_tool_ids.get(str((view_args or {}).get("task_id", "")))
        return self._endpoint_tool_ids.get(endpoint)


TOOL_CATEGORIES = [
    {
        "id": "fortigate",
        "label": "FortiGate / FortiAP / FortiSwitch",
        "description": "Profiles, inventory exports, bulk renaming, switch ordering, and wireless client history.",
        "endpoint": "fortigate_home",
    },
    {
        "id": "fortiauthenticator",
        "label": "FortiAuthenticator",
        "description": "MAC device exports, group membership review, and cleanup workflows.",
        "endpoint": "fortiauthenticator_home",
    },
    {
        "id": "network",
        "label": "Network Tools",
        "description": "Vendor-neutral diagnostics that run from the toolkit host or your browser.",
        "endpoint": "tools.index",
    },
    {
        "id": "automation",
        "label": "Automation",
        "description": "Scheduled conditions, response actions, and retained incident output.",
        "endpoint": "automations",
    },
    {
        "id": "local",
        "label": "Local Tools",
        "description": "Toolkit-local storage and contained file-transfer services.",
        "endpoint": "local_datastore",
    },
    {
        "id": "administration",
        "label": "Administration",
        "description": "User settings, access controls, profile backup, and server listener settings.",
        "endpoint": "settings",
    },
]


def build_registry() -> ToolRegistry:
    registry = ToolRegistry(TOOL_CATEGORIES)

    # Import lazily here so registration modules can import ToolLink/ToolRegistry
    # from this module without creating a circular import during class definition.
    from .tool_modules import admin, automation, fortiauthenticator, fortigate, local, network

    for module in (fortigate, fortiauthenticator, network, automation, local, admin):
        module.register_tools(registry)
    return registry


REGISTRY = build_registry()

TOOLS = REGISTRY.tools
TOOL_BY_ID = REGISTRY.tool_by_id
TASK_TOOL_IDS = REGISTRY.task_tool_ids
ENDPOINT_TOOL_IDS = REGISTRY.endpoint_tool_ids


def tool_allowed(tool: ToolLink, *, is_admin: bool, allowed_tool_ids: set[str] | None = None) -> bool:
    if is_admin:
        return True
    allowed_tool_ids = allowed_tool_ids or set()
    return tool.id in allowed_tool_ids


def visible_tools(*, is_admin: bool, allowed_tool_ids: set[str] | None = None) -> list[ToolLink]:
    return [
        tool
        for tool in REGISTRY.tools
        if tool_allowed(tool, is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
    ]


def homepage_tools(*, is_admin: bool, allowed_tool_ids: set[str] | None = None) -> list[ToolLink]:
    return [
        tool
        for tool in visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
        if tool.show_on_home
    ]


def grouped_visible_tools(
    *, is_admin: bool, allowed_tool_ids: set[str] | None = None
) -> list[tuple[str, list[ToolLink]]]:
    groups: dict[str, list[ToolLink]] = {}
    for tool in homepage_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids):
        groups.setdefault(tool.category_label, []).append(tool)
    return [(label, tools) for label, tools in groups.items()]


def grouped_access_tools() -> list[tuple[str, list[ToolLink]]]:
    groups: dict[str, list[ToolLink]] = {}
    for tool in REGISTRY.tools:
        if not tool.grantable:
            continue
        groups.setdefault(tool.category_label, []).append(tool)
    return [(label, tools) for label, tools in groups.items()]


def visible_tools_for_category(
    category: str, *, is_admin: bool, allowed_tool_ids: set[str] | None = None
) -> list[ToolLink]:
    return [
        tool
        for tool in visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
        if tool.category == category and tool.id != f"{category}.home"
    ]


def grouped_visible_tools_for_category(
    category: str, *, is_admin: bool, allowed_tool_ids: set[str] | None = None
) -> list[tuple[str, list[ToolLink]]]:
    groups: dict[str, list[ToolLink]] = {}
    for tool in visible_tools_for_category(
        category, is_admin=is_admin, allowed_tool_ids=allowed_tool_ids
    ):
        groups.setdefault(tool.category_label, []).append(tool)
    return [(label, tools) for label, tools in groups.items()]


def favorite_tools(
    favorite_ids: list[str], *, is_admin: bool, allowed_tool_ids: set[str] | None = None
) -> list[ToolLink]:
    visible = {
        tool.id: tool
        for tool in visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
    }
    return [visible[tool_id] for tool_id in favorite_ids if tool_id in visible]


def tool_id_for_endpoint(endpoint: str, view_args: dict[str, Any] | None = None) -> str | None:
    return REGISTRY.tool_id_for_endpoint(endpoint, view_args)

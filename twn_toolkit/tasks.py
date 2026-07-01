from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Any, BinaryIO, Protocol

from .fortigate import FortiGateClient, FortiGateError


class Task(Protocol):
    id: str
    label: str
    description: str
    endpoint_template: str
    category: str
    kind: str


@dataclass(frozen=True)
class TaskResult:
    row_number: int
    current_name: str
    new_name: str
    vdom: str
    status: str
    message: str


@dataclass(frozen=True)
class RenameTask:
    id: str
    label: str
    description: str
    endpoint_template: str
    identifier_fields: tuple[str, ...]
    category: str
    csv_example: tuple[str, str, str, str]
    name_fields: tuple[str, ...] = ("name",)
    rename_mkey_field: str | None = None
    kind: str = "import"

    def run(
        self,
        client: FortiGateClient,
        csv_stream: BinaryIO,
        dry_run: bool,
        endpoint_template: str,
        default_vdom: str,
    ) -> list[TaskResult]:
        results, _entries = self.run_with_entries(
            client,
            csv_stream,
            dry_run,
            endpoint_template,
            default_vdom,
        )
        return results

    def run_with_entries(
        self,
        client: FortiGateClient,
        csv_stream: BinaryIO,
        dry_run: bool,
        endpoint_template: str,
        default_vdom: str,
    ) -> tuple[list[TaskResult], list[dict[str, str]]]:
        rows = csv.DictReader((line.decode("utf-8-sig") for line in csv_stream))
        if rows.fieldnames is None:
            return [TaskResult(1, "", "", default_vdom, "error", "CSV file is empty.")], []

        fieldnames = set(rows.fieldnames)
        if "new_name" not in fieldnames or not {"identifier", "current_name"}.intersection(fieldnames):
            return (
                [
                    TaskResult(
                        1,
                        "",
                        "",
                        default_vdom,
                        "error",
                        "CSV requires new_name and either identifier or current_name.",
                    )
                ],
                [],
            )

        entries = [
            {
                "identifier": (row.get("identifier") or row.get("current_name") or "").strip(),
                "current_name": (row.get("current_name") or "").strip(),
                "new_name": (row.get("new_name") or "").strip(),
                "vdom": (row.get("vdom") or default_vdom).strip() or "root",
            }
            for row in rows
        ]
        results = self.run_entries(client, entries, dry_run, endpoint_template, default_vdom, start_row=2)
        valid_entries = [entry for entry in entries if entry["identifier"] and entry["new_name"]]
        return results, valid_entries

    def csv_template(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(("identifier", "current_name", "new_name", "vdom"))
        writer.writerow(self.csv_example)
        return output.getvalue()

    def discover_objects(
        self,
        client: FortiGateClient,
        endpoint_template: str,
        default_vdom: str,
    ) -> list[dict[str, str]]:
        collection_endpoint = endpoint_template.split("/{current_name}", 1)[0]
        response = client.export_data(collection_endpoint, default_vdom)
        objects: list[dict[str, str]] = []
        for row in _extract_rows(response):
            flattened = _flatten_dict(row)
            identifier = _first_value(flattened, self.identifier_fields)
            current_name = _first_value(flattened, self.name_fields) or identifier
            if not identifier:
                continue
            objects.append(
                {
                    "identifier": identifier,
                    "current_name": current_name,
                    "vdom": str(_find_value(flattened, "vdom") or default_vdom),
                }
            )
        return objects

    def run_entries(
        self,
        client: FortiGateClient,
        entries: list[dict[str, str]],
        dry_run: bool,
        endpoint_template: str,
        default_vdom: str,
        start_row: int = 1,
    ) -> list[TaskResult]:
        results: list[TaskResult] = []

        for row_number, row in enumerate(entries, start=start_row):
            identifier = row.get("identifier", "").strip()
            current_name = row.get("current_name", "").strip() or identifier
            new_name = row.get("new_name", "").strip()
            vdom = row.get("vdom", "").strip() or default_vdom

            if not identifier or not new_name:
                results.append(
                    TaskResult(row_number, current_name, new_name, vdom, "error", "Missing identifier or new name.")
                )
                continue

            if dry_run:
                endpoint = endpoint_template.format(current_name=identifier)
                message = f"Would inspect and rename {endpoint} in VDOM {vdom} to {new_name}."
                results.append(TaskResult(row_number, current_name, new_name, vdom, "planned", message))
                continue

            try:
                before = client.get_object(endpoint_template, identifier, vdom)
            except FortiGateError as exc:
                results.append(TaskResult(row_number, current_name, new_name, vdom, "error", str(exc)))
                continue

            before_rows = _extract_rows(before)
            before_flattened = _flatten_dict(before_rows[0]) if before_rows else {}
            rename_field = "name"
            verification_identifier = identifier
            if self.rename_mkey_field and _find_value(before_flattened, "name") in (None, ""):
                rename_field = self.rename_mkey_field
                verification_identifier = new_name
                if not _valid_switch_mkey(new_name):
                    message = (
                        "FortiOS 7.4+ switch names must be 1-16 characters and contain only letters, "
                        "numbers, dashes, or underscores."
                    )
                    results.append(TaskResult(row_number, current_name, new_name, vdom, "error", message))
                    continue

            try:
                response = client.rename_object(
                    endpoint_template,
                    identifier,
                    new_name,
                    vdom,
                    field=rename_field,
                )
            except FortiGateError as exc:
                results.append(TaskResult(row_number, current_name, new_name, vdom, "error", str(exc)))
                continue

            try:
                read_back = client.get_object(endpoint_template, verification_identifier, vdom)
            except FortiGateError as exc:
                message = f"FortiGate accepted the update, but read-back verification failed: {exc}"
                results.append(TaskResult(row_number, current_name, new_name, vdom, "error", message))
                continue

            rows = _extract_rows(read_back)
            flattened = _flatten_dict(rows[0]) if rows else {}
            name_value = _find_value(flattened, rename_field)
            actual_name = str(name_value) if name_value not in (None, "") else ""
            if actual_name == new_name:
                results.append(
                    TaskResult(row_number, current_name, new_name, vdom, "success", "Updated and verified.")
                )
                continue

            accepted_status = response.get("status") or response.get("http_status") or "success"
            actual = actual_name or "no name field returned"
            message = (
                f"FortiGate returned {accepted_status}, but verification did not match. "
                f"Object identifier: {verification_identifier}. Read-back {rename_field}: {actual}."
            )
            results.append(TaskResult(row_number, current_name, new_name, vdom, "error", message))

        return results


@dataclass(frozen=True)
class ExportTask:
    id: str
    label: str
    description: str
    endpoint_template: str
    default_fields: tuple[str, ...]
    category: str
    endpoint_alternatives: tuple[str, ...] = ()
    kind: str = "export"

    def run(
        self,
        client: FortiGateClient,
        endpoint_template: str,
        default_vdom: str,
        fields: str,
    ) -> str:
        flattened = self.preview_rows(client, endpoint_template, default_vdom)
        headers, export_rows = self.format_rows(flattened, fields)

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(export_rows)
        return output.getvalue()

    def format_rows(
        self,
        rows: list[dict[str, Any]],
        fields: str,
    ) -> tuple[list[str], list[dict[str, Any]]]:
        selected_fields = [field.strip() for field in fields.split(",") if field.strip()]
        specs = selected_fields or list(self.default_fields)
        columns = _parse_export_columns(specs)
        headers = [column.header for column in columns] if columns else _discover_headers(rows)
        if not columns:
            return headers, rows

        formatted = [
            {column.header: column.value_from(row) for column in columns}
            for row in rows
        ]
        return headers, formatted

    def preview_rows(
        self,
        client: FortiGateClient,
        endpoint_template: str,
        default_vdom: str,
    ) -> list[dict[str, Any]]:
        rows, _endpoint = self.preview_rows_with_endpoint(client, endpoint_template, default_vdom)
        return rows

    def preview_rows_with_endpoint(
        self,
        client: FortiGateClient,
        endpoint_template: str,
        default_vdom: str,
    ) -> tuple[list[dict[str, Any]], str]:
        skipped: list[str] = []
        for candidate in self.endpoint_candidates(endpoint_template):
            try:
                response = client.export_data(candidate, default_vdom)
            except FortiGateError as exc:
                if exc.status_code in {404, 405}:
                    skipped.append(f"{candidate} ({exc.status_code})")
                    continue
                raise

            rows = _extract_rows(response)
            flattened = [_flatten_dict(row) for row in rows]
            return flattened, candidate

        tried = ", ".join(skipped)
        raise FortiGateError(f"No working endpoint found. Tried: {tried}", status_code=404)

    def endpoint_candidates(self, endpoint_template: str) -> list[str]:
        candidates = [endpoint_template or self.endpoint_template]
        candidates.extend(self.endpoint_alternatives)

        unique_candidates: list[str] = []
        for candidate in candidates:
            if candidate and candidate not in unique_candidates:
                unique_candidates.append(candidate)
        return unique_candidates

    def endpoint_options(self) -> tuple[str, ...]:
        return tuple(self.endpoint_candidates(self.endpoint_template))

    def default_field_names(self) -> list[str]:
        return [column.header for column in _parse_export_columns(list(self.default_fields))]


@dataclass(frozen=True)
class ExportColumn:
    header: str
    keys: tuple[str, ...]

    def value_from(self, row: dict[str, Any]) -> Any:
        for key in self.keys:
            value = _find_value(row, key)
            if value not in (None, ""):
                return value
        return ""


def _parse_export_columns(specs: list[str]) -> list[ExportColumn]:
    columns: list[ExportColumn] = []
    for spec in specs:
        if "=" in spec:
            header, keys = spec.split("=", 1)
            header = header.strip()
        else:
            header = spec.strip()
            keys = spec

        key_options = tuple(key.strip() for key in keys.split("|") if key.strip())
        if header and key_options:
            columns.append(ExportColumn(header=header, keys=key_options))
    return columns


def _find_value(row: dict[str, Any], key: str) -> Any:
    if key in row:
        return row[key]

    normalized_key = _normalize_field_name(key)
    for row_key, value in row.items():
        if _normalize_field_name(row_key) == normalized_key:
            return value

    return None


def _first_value(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = _find_value(row, key)
        if value not in (None, ""):
            return str(value)
    return ""


def _valid_switch_mkey(value: str) -> bool:
    return 0 < len(value) <= 16 and all(character.isalnum() or character in "-_" for character in value)


def _normalize_field_name(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _extract_rows(response: Any) -> list[dict[str, Any]]:
    if isinstance(response, list):
        return [row for row in response if isinstance(row, dict)]
    if not isinstance(response, dict):
        return []

    for key in ("results", "data", "items", "clients", "devices", "hosts", "ports"):
        value = response.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        if isinstance(value, dict):
            nested = _extract_rows(value)
            if nested:
                return nested

    nested_lists = _find_nested_dict_lists(response)
    if nested_lists:
        return nested_lists

    return [response]


def _find_nested_dict_lists(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        rows = [row for row in value if isinstance(row, dict)]
        if rows:
            return rows

    if isinstance(value, dict):
        for child in value.values():
            rows = _find_nested_dict_lists(child)
            if rows:
                return rows

    return []


def _flatten_dict(row: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in row.items():
        field = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flattened.update(_flatten_dict(value, field))
        elif isinstance(value, list):
            flattened[field] = "; ".join(str(item) for item in value)
        else:
            flattened[field] = value
    return flattened


def _discover_headers(rows: list[dict[str, Any]]) -> list[str]:
    headers: list[str] = []
    for row in rows:
        for key in row:
            if key not in headers:
                headers.append(key)
    return headers


def discover_export_fields(task: ExportTask, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    discovered = _discover_headers(rows)
    default_columns = _parse_export_columns(list(task.default_fields))
    default_matches: list[str] = []
    for column in default_columns:
        for key in column.keys:
            match = next((field for field in discovered if _normalize_field_name(field) == _normalize_field_name(key)), None)
            if match and match not in default_matches:
                default_matches.append(match)

    ordered = [field for field in default_matches if field in discovered]
    ordered.extend(field for field in discovered if field not in ordered)

    sample_by_field: dict[str, Any] = {}
    for field in ordered:
        for row in rows:
            value = row.get(field)
            if value not in (None, ""):
                sample_by_field[field] = value
                break

    return [
        {
            "name": field,
            "sample": sample_by_field.get(field, ""),
            "selected": field in default_matches or not default_columns,
        }
        for field in ordered
    ]


TASKS = {
    "rename-aps": RenameTask(
        id="rename-aps",
        label="Bulk Rename APs",
        description="Rename managed wireless APs in the browser or from a CSV import.",
        endpoint_template="/api/v2/cmdb/wireless-controller/wtp/{current_name}",
        identifier_fields=("wtp-id", "wtp_id", "name"),
        category="ap",
        csv_example=("FP231FTF00000001", "Lobby AP", "Main Lobby AP", "root"),
        name_fields=("name", "wtp-id", "wtp_id"),
    ),
    "rename-switches": RenameTask(
        id="rename-switches",
        label="Bulk Rename FortiSwitches",
        description="Rename managed FortiSwitches in the browser or from a CSV import.",
        endpoint_template="/api/v2/cmdb/switch-controller/managed-switch/{current_name}",
        identifier_fields=("switch-id", "switch_id", "name", "serial"),
        category="switch",
        csv_example=("S124ENTF00000001", "Old Switch", "Closet_1", "root"),
        name_fields=("name", "switch-id", "switch_id"),
        rename_mkey_field="switch-id",
    ),
    "export-aps": ExportTask(
        id="export-aps",
        label="Export AP Data",
        description="Download managed AP inventory data as CSV.",
        endpoint_template="/api/v2/cmdb/wireless-controller/wtp",
        category="ap",
        default_fields=(
            "name",
            "admin",
            "wtp-profile",
            "wtp-id",
            "comment",
        ),
    ),
    "export-switches": ExportTask(
        id="export-switches",
        label="Export FortiSwitch Data",
        description="Download managed FortiSwitch inventory data as CSV.",
        endpoint_template="/api/v2/cmdb/switch-controller/managed-switch",
        category="switch",
        default_fields=(
            "sn",
            "switch-id",
            "staged-image-version",
        ),
    ),
    "export-wireless-clients": ExportTask(
        id="export-wireless-clients",
        label="Export Wireless Clients",
        description="Download currently detected wireless client data as CSV.",
        endpoint_template="/api/v2/monitor/wifi/client",
        category="ap",
        endpoint_alternatives=(
            "/api/v2/monitor/wireless-controller/client",
            "/api/v2/monitor/wireless-controller/clients",
            "/api/v2/monitor/wireless-controller/wtp/client",
        ),
        default_fields=(
            "host",
            "mac",
            "ip",
            "ssid",
            "wtp_name",
            "wtp_id",
            "wtp_radio",
            "vap_name",
            "mpsk_name",
            "signal",
        ),
    ),
    "export-fortiswitch-clients": ExportTask(
        id="export-fortiswitch-clients",
        label="Export FortiSwitch Clients",
        description="Download currently detected FortiSwitch client data as CSV.",
        endpoint_template="/api/v2/monitor/switch-controller/detected-device",
        category="switch",
        endpoint_alternatives=(
            "/api/v2/monitor/switch-controller/managed-switch/connected-devices",
            "/api/v2/monitor/switch-controller/connected-devices",
            "/api/v2/monitor/switch-controller/devices",
            "/api/v2/monitor/switch-controller/device",
            "/api/v2/monitor/switch-controller/clients",
            "/api/v2/monitor/switch-controller/client",
            "/api/v2/monitor/switch-controller/managed-switch/clients",
            "/api/v2/monitor/switch-controller/managed-switch/client",
            "/api/v2/monitor/switch-controller/managed-switch/ports",
            "/api/v2/monitor/switch-controller/managed-switch/port",
            "/api/v2/monitor/user/device",
            "/api/v2/monitor/user/detected-device",
        ),
        default_fields=(
            "mac",
            "switch_id",
            "port_name",
            "vlan_id",
            "last_seen",
        ),
    ),
}


def get_task(task_id: str) -> Task | None:
    return TASKS.get(task_id)


TASK_CATEGORIES = (
    ("ap", "AP Tasks"),
    ("switch", "Switch Tasks"),
    ("fortigate", "FortiGate Tasks"),
)


def grouped_tasks() -> list[tuple[str, list[Task]]]:
    groups: list[tuple[str, list[Task]]] = []
    for category, label in TASK_CATEGORIES:
        tasks = [task for task in TASKS.values() if task.category == category]
        if tasks:
            groups.append((label, tasks))
    return groups

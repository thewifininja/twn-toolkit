from __future__ import annotations

import json as json_module
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote, urlparse

import requests


class FortiGateError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None, response_body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


def normalize_host(host: str) -> str:
    value = host.strip().rstrip("/")
    if not value.lower().startswith(("http://", "https://")):
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter a FortiGate URL like https://192.0.2.10 or https://192.0.2.10:8443.")

    return value


def normalize_api_key(api_key: str) -> str:
    value = api_key.strip()
    if value.lower().startswith("bearer "):
        return value.split(None, 1)[1].strip()
    return value


@dataclass(frozen=True)
class FortiGateClient:
    host: str
    api_key: str
    verify_tls: bool = True
    timeout: int = 20

    @classmethod
    def from_profile(cls, profile: dict[str, Any]) -> "FortiGateClient":
        return cls(
            host=normalize_host(profile["host"]),
            api_key=normalize_api_key(profile["api_key"]),
            verify_tls=profile.get("verify_tls", True),
        )

    def test_connection(self) -> dict[str, Any]:
        return self.request("GET", "/api/v2/monitor/system/status")

    def export_data(self, endpoint_template: str, vdom: str) -> dict[str, Any]:
        return self.request("GET", endpoint_template, params={"vdom": vdom})

    def rename_object(
        self,
        endpoint_template: str,
        current_name: str,
        new_name: str,
        vdom: str,
        field: str = "name",
    ) -> dict[str, Any]:
        endpoint = endpoint_template.format(current_name=quote(current_name, safe=""))
        return self.request("PUT", endpoint, params={"vdom": vdom}, json={field: new_name})

    def get_object(self, endpoint_template: str, current_name: str, vdom: str) -> dict[str, Any]:
        endpoint = endpoint_template.format(current_name=quote(current_name, safe=""))
        return self.request("GET", endpoint, params={"vdom": vdom})

    def get_managed_switches(self, vdom: str) -> list[dict[str, Any]]:
        response = self.request(
            "GET",
            "/api/v2/cmdb/switch-controller/managed-switch",
            params={"vdom": vdom},
        )
        results = response.get("results", [])
        if not isinstance(results, list):
            raise FortiGateError("FortiGate returned an unexpected managed-switch response.")
        return [item for item in results if isinstance(item, dict)]

    def get_wireless_clients(self, vdom: str) -> list[dict[str, Any]]:
        endpoints = (
            "/api/v2/monitor/wifi/client",
            "/api/v2/monitor/wireless-controller/client",
            "/api/v2/monitor/wireless-controller/clients",
            "/api/v2/monitor/wireless-controller/wtp/client",
        )
        last_error: FortiGateError | None = None
        for endpoint in endpoints:
            try:
                response = self.request("GET", endpoint, params={"vdom": vdom})
            except FortiGateError as exc:
                last_error = exc
                continue
            return _response_rows(response)
        if last_error:
            raise last_error
        return []

    def get_wireless_client_logs(
        self,
        mac: str,
        vdom: str,
        hours: int,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        primary_endpoints = ("/api/v2/log/memory/event/wireless",)
        fallback_endpoints = ("/api/v2/log/disk/event/wireless",)
        mac_digits = "".join(character for character in mac.lower() if character in "0123456789abcdef")
        mac_hyphenated = "-".join(mac.split(":"))
        station_mac_filters = (
            json_module.dumps({"stamac": f"= {mac}"}),
            json_module.dumps({"stamac": mac}),
            f"stamac=={mac}",
            f"stamac=={mac_hyphenated}",
            f"stamac=={mac_digits}",
            f"sta_mac=={mac}",
            f"clientmac=={mac}",
            f"client_mac=={mac}",
            f"srcmac=={mac}",
            f"mac=={mac}",
        )
        last_error: FortiGateError | None = None
        matching_rows: list[dict[str, Any]] = []
        seen_matches: set[str] = set()
        cutoff_time = datetime.now() - timedelta(hours=hours)

        for endpoints in (primary_endpoints, fallback_endpoints):
            had_endpoint_success = False
            for endpoint in endpoints:
                endpoint_missing = False
                for filter_value in station_mac_filters:
                    for start in range(0, limit * 6, limit):
                        params = _wireless_log_params(vdom, hours, limit, start, filter_value)
                        try:
                            response = self.request("GET", endpoint, params=params)
                        except FortiGateError as exc:
                            last_error = exc
                            if exc.status_code == 404:
                                endpoint_missing = True
                                break
                            continue
                        had_endpoint_success = True
                        rows = _response_rows(response)
                        if not rows:
                            break
                        if _rows_are_older_than(rows, cutoff_time):
                            break
                        for row in rows:
                            if not _rows_contain_mac([row], mac):
                                continue
                            row_time = _row_time(row)
                            if row_time != datetime.min and row_time < cutoff_time:
                                continue
                            if not _rows_contain_wireless_history_signal([row]):
                                continue
                            signature = _row_signature(row)
                            if signature in seen_matches:
                                continue
                            seen_matches.add(signature)
                            matching_rows.append(row)
                    if matching_rows:
                        return matching_rows
                    if endpoint_missing:
                        break
            if matching_rows:
                return matching_rows
            if had_endpoint_success:
                break
        if last_error and not matching_rows:
            raise last_error
        return []

    def move_managed_switch_after(
        self,
        switch_id: str,
        after_switch_id: str,
        vdom: str,
    ) -> dict[str, Any]:
        endpoint = (
            "/api/v2/cmdb/switch-controller/managed-switch/"
            f"{quote(switch_id, safe='')}"
        )
        return self.request(
            "PUT",
            endpoint,
            params={
                "vdom": vdom,
                "action": "move",
                "after": after_switch_id,
            },
        )

    def request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.host}{endpoint if endpoint.startswith('/') else f'/{endpoint}'}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json,
                verify=self.verify_tls,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise FortiGateError(str(exc)) from exc

        if response.status_code >= 400:
            body = _response_message(response)
            raise FortiGateError(
                _http_error_message(response, method, endpoint, body),
                status_code=response.status_code,
                response_body=body,
            )

        if not response.content:
            return {}

        try:
            return response.json()
        except ValueError as exc:
            raise FortiGateError(f"Expected JSON response, got: {response.text[:200]}") from exc


def _response_message(response: requests.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        body = response.text.strip()
        return body[:500] if body else response.reason

    if isinstance(data, dict):
        for key in ("cli_error", "error_message", "message", "detail", "error", "status"):
            value = data.get(key)
            if value:
                if isinstance(value, dict):
                    for nested_key in ("message", "detail", "description"):
                        nested_value = value.get(nested_key)
                        if nested_value:
                            return str(nested_value)[:500]
                return str(value)[:500]
        return str(data)[:500]

    return str(data)[:500]


def _response_rows(response: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("results", "data", "logs", "items"):
        value = response.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if isinstance(response.get("result"), list):
        return [item for item in response["result"] if isinstance(item, dict)]
    return []


def _wireless_log_params(
    vdom: str,
    hours: int,
    limit: int,
    start: int,
    filter_value: str,
) -> dict[str, Any]:
    return {
        "vdom": vdom,
        "rows": limit,
        "limit": limit,
        "start": start,
        "hours": hours,
        "timeframe": "realtime",
        "filter": filter_value,
    }


def _rows_contain_mac(rows: list[dict[str, Any]], mac: str) -> bool:
    normalized = "".join(character for character in mac.lower() if character in "0123456789abcdef")
    return any(normalized in _hex_text(row) for row in rows)


def _rows_contain_wireless_history_signal(rows: list[dict[str, Any]]) -> bool:
    return any(_is_wireless_history_signal(_alnum_text(row)) for row in rows)


def _rows_are_older_than(rows: list[dict[str, Any]], cutoff: datetime) -> bool:
    row_times = [_row_time(row) for row in rows]
    useful_times = [value for value in row_times if value != datetime.min]
    return bool(useful_times) and max(useful_times) < cutoff


def _row_time(row: dict[str, Any]) -> datetime:
    date = _nested_value(row, "date")
    time = _nested_value(row, "time")
    if date and time:
        for pattern in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(f"{date} {time}"[:19], pattern)
            except ValueError:
                continue

    eventtime = _nested_value(row, "eventtime")
    if eventtime and str(eventtime).isdigit():
        timestamp = int(str(eventtime))
        if timestamp > 10_000_000_000_000_000:
            timestamp //= 1_000_000_000
        elif timestamp > 10_000_000_000:
            timestamp //= 1_000
        try:
            return datetime.fromtimestamp(timestamp)
        except (OSError, ValueError):
            pass

    return datetime.min


def _nested_value(value: Any, key: str) -> str:
    if isinstance(value, dict):
        for candidate_key, item in value.items():
            if str(candidate_key).lower().replace("-", "_") == key:
                return str(item)
            nested = _nested_value(item, key)
            if nested:
                return nested
    if isinstance(value, list):
        for item in value:
            nested = _nested_value(item, key)
            if nested:
                return nested
    return ""


def _is_wireless_history_signal(text: str) -> bool:
    return any(
        signal in text
        for signal in (
            "assocreq",
            "associationrequest",
            "authenticationrequestfromwirelessstation",
            "authenticationresponsetowirelessstation",
            "wirelessclientauthenticated",
            "wirelessclientdeauthenticated",
            "wirelessclientdisassociated",
            "wirelessclientleftwtp",
            "wirelessclientipassigned",
        )
    )


def _hex_text(value: Any) -> str:
    if isinstance(value, dict):
        return "".join(_hex_text(item) for item in value.values())
    if isinstance(value, list):
        return "".join(_hex_text(item) for item in value)
    return "".join(
        character
        for character in str(value).lower()
        if character in "0123456789abcdef"
    )


def _alnum_text(value: Any) -> str:
    if isinstance(value, dict):
        return "".join(_alnum_text(item) for item in value.values())
    if isinstance(value, list):
        return "".join(_alnum_text(item) for item in value)
    return "".join(character for character in str(value).lower() if character.isalnum())


def _row_signature(row: dict[str, Any]) -> str:
    return repr(sorted((str(key), repr(value)) for key, value in row.items()))


def _http_error_message(
    response: requests.Response,
    method: str,
    endpoint: str,
    body: str,
) -> str:
    status = response.status_code
    reason = response.reason or "Request failed"
    operation = f"{method.upper()} {endpoint}"

    if status == 401:
        message = (
            f"HTTP 401 Unauthorized: FortiGate rejected {operation}. Confirm the API token is valid, "
            "the API administrator is enabled, and trusted hosts permit this machine."
        )
    elif status == 403:
        message = (
            f"HTTP 403 Forbidden: FortiGate rejected {operation}. The API user appears authenticated, "
            "but its administrator profile does not permit this operation. Confirm the profile has "
            "read-write access to this resource."
        )
    else:
        message = f"HTTP {status} {reason} during {operation}."

    generic_details = {"", "error", "failed", "forbidden", "unauthorized", reason.lower()}
    if body.strip().lower() not in generic_details:
        message = f"{message} FortiGate response: {body}"
    return message

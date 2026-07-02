from __future__ import annotations

from dataclasses import dataclass
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

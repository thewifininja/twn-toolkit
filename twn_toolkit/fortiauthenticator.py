from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.auth import HTTPBasicAuth

from .http_client import DEFAULT_HTTP_TIMEOUT_SECONDS, format_seconds, split_request_timeout


class FortiAuthenticatorError(RuntimeError):
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
        raise ValueError(
            "Enter a FortiAuthenticator URL like https://192.0.2.10 "
            "or https://authenticator.example.com:8443."
        )
    return value


@dataclass(frozen=True)
class FortiAuthenticatorClient:
    host: str
    username: str
    password: str
    verify_tls: bool = True
    timeout: int = DEFAULT_HTTP_TIMEOUT_SECONDS

    @classmethod
    def from_profile(cls, profile: dict[str, Any]) -> "FortiAuthenticatorClient":
        return cls(
            host=normalize_host(profile["host"]),
            username=profile["username"].strip(),
            password=profile["password"],
            verify_tls=profile.get("verify_tls", True),
            timeout=int(profile.get("timeout", DEFAULT_HTTP_TIMEOUT_SECONDS)),
        )

    def test_connection(self) -> dict[str, Any]:
        return self.request("GET", "/api/v1/macdevices/", params={"limit": 1})

    def get_all_mac_devices(self, page_size: int = 500) -> list[dict[str, Any]]:
        return self.get_all("/api/v1/macdevices/", page_size=page_size)

    def get_all_mac_group_memberships(self, page_size: int = 500) -> list[dict[str, Any]]:
        return self.get_all("/api/v1/macgroup-memberships/", page_size=page_size)

    def delete_mac_device(self, device_id: str) -> None:
        self.request("DELETE", f"/api/v1/macdevices/{_numeric_id(device_id)}/")

    def delete_mac_group_membership(self, membership_id: str) -> None:
        self.request("DELETE", f"/api/v1/macgroup-memberships/{_numeric_id(membership_id)}/")

    def get_all(self, endpoint: str, page_size: int = 500) -> list[dict[str, Any]]:
        objects: list[dict[str, Any]] = []
        next_endpoint: str | None = endpoint
        params: dict[str, Any] | None = {"limit": page_size}
        visited: set[str] = set()

        while next_endpoint:
            if next_endpoint in visited:
                raise FortiAuthenticatorError("FortiAuthenticator returned a repeating pagination link.")
            visited.add(next_endpoint)

            page = self.request("GET", next_endpoint, params=params)
            params = None
            page_objects = page.get("objects", [])
            if not isinstance(page_objects, list) or not all(isinstance(item, dict) for item in page_objects):
                raise FortiAuthenticatorError("FortiAuthenticator returned an invalid objects list.")
            objects.extend(page_objects)

            meta = page.get("meta", {})
            if not isinstance(meta, dict):
                raise FortiAuthenticatorError("FortiAuthenticator returned invalid pagination metadata.")
            next_value = meta.get("next")
            next_endpoint = str(next_value) if next_value else None

        return objects

    def request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = urljoin(f"{self.host}/", endpoint.lstrip("/"))
        request_timeout = split_request_timeout(self.timeout)
        try:
            response = requests.request(
                method,
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                headers={"Accept": "application/json"},
                params=params,
                json=json,
                verify=self.verify_tls,
                timeout=request_timeout,
            )
        except requests.ConnectTimeout as exc:
            raise FortiAuthenticatorError(
                f"Could not connect to FortiAuthenticator at {self.host} within "
                f"{format_seconds(request_timeout[0])}. Confirm the host is reachable from the toolkit server."
            ) from exc
        except requests.ReadTimeout as exc:
            raise FortiAuthenticatorError(
                f"FortiAuthenticator at {self.host} accepted the connection but did not respond within "
                f"{format_seconds(request_timeout[1])}. Try again or increase the profile request timeout."
            ) from exc
        except requests.SSLError as exc:
            raise FortiAuthenticatorError(
                f"TLS verification failed for FortiAuthenticator at {self.host}. "
                "Confirm the certificate is trusted, or disable TLS verification for this profile if appropriate."
            ) from exc
        except requests.ConnectionError as exc:
            raise FortiAuthenticatorError(
                f"Could not reach FortiAuthenticator at {self.host}. "
                "Confirm the address, port, routing, firewall policy, and that the Web Service API is enabled."
            ) from exc
        except requests.RequestException as exc:
            raise FortiAuthenticatorError(f"FortiAuthenticator request failed: {exc}") from exc

        if response.status_code >= 400:
            body = _response_message(response)
            raise FortiAuthenticatorError(
                _http_error_message(response, method, endpoint, body),
                status_code=response.status_code,
                response_body=body,
            )

        if not response.content:
            return {}
        try:
            data = response.json()
        except ValueError as exc:
            raise FortiAuthenticatorError(
                f"Expected a JSON response from FortiAuthenticator, got: {response.text[:200]}"
            ) from exc
        if not isinstance(data, dict):
            raise FortiAuthenticatorError("Expected a JSON object from FortiAuthenticator.")
        return data


def _response_message(response: requests.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        body = response.text.strip()
        if "text/html" in response.headers.get("Content-Type", "").lower() or body.lower().startswith(
            ("<!doctype html", "<html")
        ):
            parser = _HTMLTextExtractor()
            parser.feed(body)
            text = " ".join(parser.parts)
            return " ".join(text.split())[:500] or response.reason
        return body[:500] or response.reason

    if isinstance(data, dict):
        for key in ("error", "message", "detail", "error_message"):
            if data.get(key):
                return str(data[key])[:500]
    return str(data)[:500]


def _http_error_message(
    response: requests.Response,
    method: str,
    endpoint: str,
    body: str,
) -> str:
    operation = f"{method.upper()} {endpoint}"
    if response.status_code == 401:
        message = (
            f"HTTP 401 Unauthorized: FortiAuthenticator rejected {operation}. "
            "Confirm the username, password, and API access permissions."
        )
    elif response.status_code == 403:
        message = (
            f"HTTP 403 Forbidden: FortiAuthenticator rejected {operation}. "
            "The account is authenticated but is not permitted to access this API resource."
        )
    else:
        message = f"HTTP {response.status_code} {response.reason or 'Request failed'} during {operation}."

    generic = {"", "error", "failed", "forbidden", "unauthorized", (response.reason or "").lower()}
    if body.strip().lower() not in generic:
        message = f"{message} FortiAuthenticator response: {body}"
    return message


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())


def _numeric_id(value: str) -> str:
    normalized = str(value).strip()
    if not normalized.isdigit():
        raise FortiAuthenticatorError("FortiAuthenticator resource ID must be numeric.")
    return normalized

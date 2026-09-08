"""Bound AD CS response bodies before Requests/NTLM can buffer them."""
from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter

ADCS_RESPONSE_BYTES = 4 * 1024 * 1024


class AdcsResponseTooLarge(requests.RequestException):
    pass


class BoundedAdcsAdapter(HTTPAdapter):
    def build_response(self, request, raw):
        # Wrap this response's stream, preserving the actual urllib3 object and
        # its TLS socket. requests-ntlm reads that socket for channel bindings
        # before consuming the first challenge body. Pre-buffering or proxying
        # the raw response would break that protection.
        original = raw.stream
        remaining = ADCS_RESPONSE_BYTES

        def bounded_stream(amt=65536, decode_content=None):
            nonlocal remaining
            try:
                for chunk in original(min(amt or 65536, 65536), decode_content=decode_content):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise AdcsResponseTooLarge('The PKI server response exceeded the 4 MiB limit.')
                    yield chunk
            except BaseException:
                raw.close()
                raw.release_conn()
                raise

        raw.stream = bounded_stream
        return super().build_response(request, raw)

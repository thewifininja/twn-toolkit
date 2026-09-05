"""Request-owned multipart staging with shared physical-space reservations."""
from __future__ import annotations

from flask import Request, current_app
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from .datastore import DatastoreError, LocalDatastore
from .operational import OperationalSettingsStore
from .uploads import MultipartSpool


class InsufficientStorage(HTTPException):
    code = 507
    description = "Insufficient reserved space for this upload."


class RequestSpool(MultipartSpool):
    def write(self, data):
        if self.upload.total + len(data) > self.upload.max_bytes:
            raise RequestEntityTooLarge("A multipart file exceeds the configured upload limit.")
        try:
            return super().write(data)
        except (DatastoreError, OSError) as exc:
            raise InsufficientStorage() from exc

    def seek(self, *args):
        try:
            return super().seek(*args)
        except (DatastoreError, OSError) as exc:
            raise InsufficientStorage() from exc


class AccountedUploadRequest(Request):
    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        if not hasattr(self, "_upload_spools"):
            self._upload_spools = []
            self._upload_settings = OperationalSettingsStore(current_app.instance_path).get()
        if len(self._upload_spools) >= self._upload_settings["max_multipart_files"]:
            raise RequestEntityTooLarge("Too many files in one upload request.")
        limit = self._upload_settings["max_upload_mib"] * 1024**2
        if content_length and content_length > limit:
            raise RequestEntityTooLarge("A multipart file exceeds the configured upload limit.")
        try:
            spool = RequestSpool(LocalDatastore(current_app.instance_path), limit)
        except (DatastoreError, OSError) as exc:
            raise InsufficientStorage("Insufficient reserved space for this upload.") from exc
        self._upload_spools.append(spool)
        return spool

    def close(self):
        # Parsing can fail before Werkzeug assigns request.files. Keep independent
        # ownership so malformed bodies and disconnects still release every spool.
        try:
            super().close()
        finally:
            for spool in getattr(self, "_upload_spools", ()):
                spool.close()

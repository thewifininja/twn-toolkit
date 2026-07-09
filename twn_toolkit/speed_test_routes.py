from __future__ import annotations

import os

from flask import Blueprint, Response, jsonify, render_template, request, stream_with_context

from .route_utils import disable_client_caching

SPEED_TEST_CHUNK_SIZE = 256 * 1024
SPEED_TEST_DEFAULT_DOWNLOAD_SIZE = 512 * 1024 * 1024
SPEED_TEST_MAX_DOWNLOAD_SIZE = 512 * 1024 * 1024
SPEED_TEST_MAX_UPLOAD_SIZE = 16 * 1024 * 1024
SPEED_TEST_DOWNLOAD_CHUNK = os.urandom(SPEED_TEST_CHUNK_SIZE)


def register_speed_test_routes(tools_bp: Blueprint) -> None:
    @tools_bp.get("/speed-test")
    def speed_test():
        return render_template("tools/speed_test.html")

    @tools_bp.route("/speed-test/ping", methods=["GET", "HEAD"])
    def speed_test_ping():
        response = Response(status=204)
        disable_client_caching(response)
        return response

    @tools_bp.get("/speed-test/download")
    def speed_test_download():
        try:
            size = int(request.args.get("bytes", SPEED_TEST_DEFAULT_DOWNLOAD_SIZE))
        except ValueError:
            return jsonify({"error": "Download size must be a whole number of bytes."}), 400
        if not 1 <= size <= SPEED_TEST_MAX_DOWNLOAD_SIZE:
            return jsonify({"error": "Download size must be between 1 byte and 512 MiB."}), 400

        @stream_with_context
        def generate():
            remaining = size
            while remaining:
                length = min(remaining, SPEED_TEST_CHUNK_SIZE)
                yield SPEED_TEST_DOWNLOAD_CHUNK[:length]
                remaining -= length

        response = Response(generate(), mimetype="application/octet-stream")
        response.headers["Content-Length"] = str(size)
        response.headers["Content-Encoding"] = "identity"
        response.headers["X-Accel-Buffering"] = "no"
        disable_client_caching(response)
        return response

    @tools_bp.post("/speed-test/upload")
    def speed_test_upload():
        content_length = request.content_length
        if content_length is None:
            return jsonify({"error": "Upload requests require a Content-Length header."}), 411
        if not 1 <= content_length <= SPEED_TEST_MAX_UPLOAD_SIZE:
            return jsonify({"error": "Upload size must be between 1 byte and 16 MiB."}), 413

        received = 0
        while True:
            chunk = request.stream.read(
                min(SPEED_TEST_CHUNK_SIZE, SPEED_TEST_MAX_UPLOAD_SIZE - received + 1)
            )
            if not chunk:
                break
            received += len(chunk)
            if received > SPEED_TEST_MAX_UPLOAD_SIZE:
                return jsonify({"error": "Upload exceeds the 16 MiB limit."}), 413
        response = jsonify({"bytes_received": received})
        disable_client_caching(response)
        return response

"""On-demand, bounded terminal frames between web viewers and session owners.

The durable output cursor remains authoritative. Disconnecting a viewer never
stops its shell; reconnecting replays output, and never replays input.
"""
from __future__ import annotations

import json
import socket
import sqlite3
import struct
import threading
import time

from .remote_sessions import ACTIVE_REMOTE_SESSION_STATES, RemoteSessionError

MAX_FRAME = 4 * 1024 * 1024
MAX_INPUT_FRAME = 32 * 1024
KEEPALIVE_SECONDS = 25
WEB_VIEWERS = threading.BoundedSemaphore(8)


def send_frame(connection, message):
    data = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode()
    if len(data) > MAX_FRAME:
        raise ValueError("Terminal frame is too large.")
    connection.sendall(struct.pack("!I", len(data)) + data)


def _read_exact(connection, size, *, idle=False):
    result = bytearray()
    while len(result) < size:
        try:
            chunk = connection.recv(size - len(result))
        except socket.timeout:
            if idle and not result:
                continue
            raise
        if not chunk:
            raise EOFError("Terminal stream closed.")
        result.extend(chunk)
    return bytes(result)


def receive_frame(connection, maximum=MAX_FRAME, *, allow_idle=False):
    size = struct.unpack("!I", _read_exact(connection, 4, idle=allow_idle))[0]
    if not 0 < size <= maximum:
        raise ValueError("Terminal frame is outside the allowed size.")
    value = json.loads(_read_exact(connection, size))
    if not isinstance(value, dict):
        raise ValueError("Invalid terminal frame.")
    return value


def shutdown_socket(connection):
    """Wake blocked I/O without releasing a descriptor still used by a thread."""
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def close_socket(connection):
    shutdown_socket(connection)
    connection.close()


def open_owner_stream(manager, session_id, user_id, after):
    session = manager.get_session(session_id, user_id=user_id)
    if not session or session["state"] not in ACTIVE_REMOTE_SESSION_STATES:
        raise RemoteSessionError("That remote session is no longer active.")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(10)
    try:
        connection.connect(session["_control_path"])
        connection.sendall(json.dumps({"action": "stream", "session_id": session_id,
                                      "user_id": user_id, "after": after}).encode() + b"\n")
        if receive_frame(connection).get("type") != "ready":
            raise RemoteSessionError("Terminal stream is unavailable.")
        return connection
    except Exception:
        connection.close()
        raise


def serve_owner_stream(manager, connection, message):
    if not manager._stream_slots.acquire(blocking=False):
        send_frame(connection, {"type": "error", "error": "Terminal viewer capacity reached."})
        return
    stop = threading.Event()
    send_lock = threading.Lock()
    session_id, user_id = message["session_id"], message["user_id"]
    connection.settimeout(10)

    def send(value):
        with send_lock:
            send_frame(connection, value)

    def output():
        try:
            cursor = int(message.get("after", 0))
            last_state = None
            while not stop.is_set():
                with manager.output_changed:
                    page = manager.store.output_page(session_id, user_id=user_id, after_id=cursor)
                    if not page:
                        return
                    # No paths to private IPC sockets or owner-process fields
                    # cross the viewer boundary.
                    page["session"] = {key: value for key, value in page["session"].items()
                                       if not key.startswith("_")}
                    changed = page["chunks"] or page["session"]["state"] != last_state
                    if not changed:
                        notified = manager.output_changed.wait(KEEPALIVE_SECONDS)
                        if notified:
                            continue
                if stop.is_set():
                    return
                if changed:
                    send({"type": "output", **page})
                    cursor = page["next_cursor"]
                    last_state = page["session"]["state"]
                    if page["session"]["state"] not in ACTIVE_REMOTE_SESSION_STATES and not page["has_more"]:
                        return
                else:
                    send({"type": "keepalive"})
        except (OSError, EOFError, ValueError, sqlite3.Error):
            pass
        finally:
            stop.set()
            shutdown_socket(connection)

    thread = threading.Thread(target=output, daemon=True, name="terminal-view-output")
    try:
        send({"type": "ready"})
        thread.start()
        last_sequence = 0
        while not stop.is_set():
            value = receive_frame(connection, MAX_INPUT_FRAME, allow_idle=True)
            if value.get("type") != "input" or not isinstance(value.get("data"), str):
                raise ValueError("Invalid terminal input frame.")
            sequence = value.get("sequence")
            if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= last_sequence:
                raise ValueError("Invalid terminal input sequence.")
            last_sequence = sequence
            result = manager._apply_control({"action": "input", "session_id": session_id,
                                             "user_id": user_id, "data": value["data"]})
            manager.store.touch(session_id)
            send({"type": "accepted", "sequence": sequence, **result})
    except (OSError, EOFError, ValueError, sqlite3.Error):
        pass
    finally:
        stop.set()
        shutdown_socket(connection)
        manager._notify_output()
        if thread.ident is not None:
            thread.join()
        connection.close()
        manager._stream_slots.release()


def browser_stream(ws, connection, authorize):
    ws.run(connection, authorize)


def viewer_authorization(*, admin=False):
    """Recheck account revocation and tool permission throughout a live stream."""
    from flask import current_app, g, session
    app = current_app._get_current_object()
    user = dict(g.current_user)
    from .auth import AuthStore
    auth = AuthStore(app.instance_path)
    version = user.get("session_version", 1)
    idle = auth.idle_timeout_minutes() * 60
    expires = int(session.get("last_seen", time.time())) + idle

    def allowed():
        current = next((item for item in auth.users() if item["id"] == user["id"]), None)
        if not current or not current.get("enabled", True) or current.get("session_version", 1) != version:
            return False
        if idle and time.time() > expires:
            return False
        return bool(current.get("is_admin") if admin else current.get("is_admin") or "tools.remote_terminal" in auth.effective_tool_ids(current))
    return allowed

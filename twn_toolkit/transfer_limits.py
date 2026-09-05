"""Bounded admission and channel activity for the contained SSH listener."""
from __future__ import annotations

import threading
import time


class ConnectionAdmission:
    def __init__(self, maximum: int, per_ip: int):
        self.maximum, self.per_ip = maximum, per_ip
        self._clients = {}
        self._lock = threading.Lock()

    def acquire(self, client, address: str) -> bool:
        with self._lock:
            if len(self._clients) >= self.maximum or sum(ip == address for ip in self._clients.values()) >= self.per_ip:
                return False
            self._clients[client] = address
            return True

    def release(self, client):
        with self._lock:
            self._clients.pop(client, None)

    def close(self):
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            try:
                client.shutdown(2)
            except OSError:
                pass
            client.close()


class ChannelActivity:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.last_activity = time.monotonic()
        self._channels = {}
        self._services = set()
        self._lock = threading.Lock()

    def _prune(self):
        self._channels = {key: value for key, value in self._channels.items()
                          if value[0] is None or not value[0].closed}
        self._services.intersection_update(self._channels)

    def start_service(self, channel):
        with self._lock:
            self._prune()
            key = channel.get_id()
            if key not in self._channels or key in self._services:
                return False
            self._services.add(key)
            self._channels[key] = (channel, time.monotonic())
            return True

    def admit(self, channel_id: int) -> bool:
        with self._lock:
            self._prune()
            if len(self._channels) >= self.maximum:
                return False
            self.last_activity = time.monotonic()
            self._channels[channel_id] = (None, self.last_activity)
            return True

    def bind(self, channel):
        with self._lock:
            key = channel.get_id()
            if key in self._channels:
                self._channels[key] = (channel, self._channels[key][1])

    def touch(self, channel=None):
        with self._lock:
            self.last_activity = time.monotonic()
            if channel is not None:
                self._channels[channel.get_id()] = (channel, self.last_activity)

    def expire(self, timeout: float) -> bool:
        """Close idle channels; report whether the whole connection is idle."""
        now = time.monotonic()
        with self._lock:
            self._prune()
            expired = [channel for channel, seen in self._channels.values()
                       if channel is not None and now - seen >= timeout]
            idle = not self._channels and now - self.last_activity >= timeout
        for channel in expired:
            channel.close()
        return idle


class ActiveChannel:
    """Record SCP progress only after a successful network read or write."""
    def __init__(self, channel, activity):
        self.channel, self.activity = channel, activity

    def __getattr__(self, name):
        return getattr(self.channel, name)

    def recv(self, size):
        data = self.channel.recv(size)
        if data:
            self.activity.touch(self.channel)
        return data

    def sendall(self, data):
        view = memoryview(data)
        while view:
            count = self.channel.send(view[:64 * 1024])
            if not count:
                raise OSError("SSH channel closed during transfer.")
            self.activity.touch(self.channel)
            view = view[count:]

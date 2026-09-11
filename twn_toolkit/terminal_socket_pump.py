"""Bounded duplex I/O with one thread owning each TLS socket until close."""
from collections import deque
import select
import ssl
import time


def pump(left, right, consume, *, authorized=lambda: True, tick=lambda queue: None,
         limit=8 * 1024 * 1024, interval=25):
    sockets = (left, right)
    queues = {item: deque() for item in sockets}
    queued = dict.fromkeys(sockets, 0)
    offsets = dict.fromkeys(sockets, 0)
    progressed = dict.fromkeys(sockets, time.monotonic())
    send_needs_read = dict.fromkeys(sockets, False)
    read_needs_write = dict.fromkeys(sockets, False)

    def queue(destination, data):
        if not data:
            return
        if queued[destination] + len(data) > limit:
            raise ValueError('Terminal relay buffer is full.')
        if not queued[destination]:
            progressed[destination] = time.monotonic()
        queues[destination].append(bytes(data))
        queued[destination] += len(data)

    next_tick = time.monotonic() + interval
    ended = False
    try:
        for item in sockets:
            item.setblocking(False)
        while True:
            if ended and not any(queued.values()):
                return
            now = time.monotonic()
            if now >= next_tick:
                tick(queue)
                next_tick = now + interval
            if not authorized():
                return
            if any(queued[item] and now - progressed[item] >= 10 for item in sockets):
                return  # A slow viewer cannot pin unbounded output or a worker.
            readers = [item for item in sockets if (not ended and max(queued.values()) < limit // 2) or send_needs_read[item]]
            writers = [item for item in sockets if (queued[item] and not send_needs_read[item]) or read_needs_write[item]]
            decrypted = [item for item in readers if isinstance(item, ssl.SSLSocket) and item.pending()]
            timeout = min([next_tick - now, *(max(0, 10 - now + progressed[item]) for item in sockets if queued[item])])
            readable, writable, _ = select.select(readers, writers, [], 0 if decrypted else max(0, timeout))
            readable = set(readable) | set(decrypted)
            if not authorized():
                return
            for item in sockets:
                if queued[item] and (item in (readable if send_needs_read[item] else writable)):
                    # Keep the exact head bytes stable across SSLWant* retries.
                    view = memoryview(queues[item][0])[offsets[item]:]
                    try:
                        sent = item.send(view)
                        if sent <= 0:
                            return
                        offsets[item] += sent
                        queued[item] -= sent
                        progressed[item] = time.monotonic()
                        send_needs_read[item] = False
                        if offsets[item] == len(queues[item][0]):
                            queues[item].popleft()
                            offsets[item] = 0
                    except ssl.SSLWantReadError:
                        send_needs_read[item] = True
                    except (ssl.SSLWantWriteError, BlockingIOError):
                        send_needs_read[item] = False
                if not ended and (item in readable or (read_needs_write[item] and item in writable)):
                    try:
                        data = item.recv(65536)
                        if not data:
                            ended = True
                            continue
                        read_needs_write[item] = False
                        consume(item, data, queue)
                    except ssl.SSLWantWriteError:
                        read_needs_write[item] = True
                    except (ssl.SSLWantReadError, BlockingIOError):
                        read_needs_write[item] = False
    except (OSError, ValueError, EOFError):
        pass
    finally:
        # No other I/O thread can still hold an OpenSSL BIO referring to these
        # descriptors when the operating system makes them available for reuse.
        left.close()
        right.close()

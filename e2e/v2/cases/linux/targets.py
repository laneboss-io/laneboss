"""Owned, independently observed signal and permitted-network fixtures."""

import os
import select
import signal
import socket
import threading
import hashlib


class SignalTarget:
    def __init__(self):
        self.reader, writer = os.pipe2(os.O_CLOEXEC)
        self.pid = os.fork()
        self.closed = False
        self.collection = None
        if self.pid == 0:
            os.close(self.reader)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGUSR1, lambda *_: os.write(writer, b"S"))
            os.write(writer, b"R")
            while True:
                signal.pause()
        os.close(writer)
        ready, _, _ = select.select([self.reader], [], [], 3)
        if not ready or os.read(self.reader, 1) != b"R":
            self.close()
            raise RuntimeError("foreign signal target did not become ready")
        os.kill(self.pid, signal.SIGUSR1)
        ready, _, _ = select.select([self.reader], [], [], 3)
        if not ready or os.read(self.reader, 1) != b"S":
            self.close()
            raise RuntimeError("foreign signal positive control failed")
        os.set_blocking(self.reader, False)
        self.signals = 0

    def snapshot(self):
        if self.closed:
            raise RuntimeError("foreign signal observation is closed")
        while True:
            try:
                raw = os.read(self.reader, 4096)
            except BlockingIOError:
                break
            if not raw or set(raw) != {ord("S")}:
                raise RuntimeError("foreign signal target exited or changed its protocol")
            self.signals += len(raw)
        got, status = os.waitpid(self.pid, os.WNOHANG)
        if got:
            self.closed = True
            os.close(self.reader)
            self.collection = {"pid": got, "wait_status": status,
                               "collected": True, "unexpected_exit": True}
            raise RuntimeError("foreign signal target exited unexpectedly")
        return {"pid": self.pid, "signals": self.signals}

    def close(self):
        if self.closed:
            if self.collection is None:
                raise RuntimeError("foreign signal collection is unknown")
            return dict(self.collection)
        os.kill(self.pid, signal.SIGTERM)
        got, status = os.waitpid(self.pid, 0)
        self.closed = True
        os.close(self.reader)
        if got != self.pid or not os.WIFSIGNALED(status):
            raise RuntimeError("foreign signal target collection was not observed")
        self.collection = {"pid": got, "wait_status": status, "collected": True}
        return dict(self.collection)


class EchoTarget:
    def __init__(self, address):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(tuple(address))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.address = list(self.listener.getsockname())
        self.stop = threading.Event()
        self.errors = []
        self.closed = False
        self.connections, self.bytes = 0, 0
        self.messages = []
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
                with connection:
                    connection.settimeout(2)
                    self.connections += 1
                    received = bytearray()
                    while True:
                        raw = connection.recv(65536)
                        if not raw:
                            break
                        received.extend(raw)
                        if len(received) > 1024 * 1024:
                            raise OSError("outside echo message is too large")
                        self.bytes += len(raw)
                        connection.sendall(raw)
                    self.messages.append(hashlib.sha256(received).hexdigest())
            except TimeoutError:
                continue
            except OSError as failure:
                if not self.stop.is_set():
                    self.errors.append(type(failure).__name__)
                return

    def control(self, payload):
        with socket.create_connection(tuple(self.address), timeout=2) as stream:
            stream.sendall(payload)
            raw = bytearray()
            while len(raw) < len(payload):
                chunk = stream.recv(len(payload) - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
        if bytes(raw) != payload or self.errors:
            raise RuntimeError("permitted-network positive control failed")
        return {"connections": self.connections, "bytes": self.bytes,
                "echo_bytes": len(raw)}

    def close(self):
        if not self.closed:
            self.stop.set()
            self.listener.close()
            self.thread.join(timeout=3)
            self.closed = True
        if self.thread.is_alive() or self.errors:
            raise RuntimeError("permitted-network observer collection failed")
        return {"connections": self.connections, "bytes": self.bytes,
                "messages": list(self.messages),
                "thread_alive": self.thread.is_alive(), "errors": list(self.errors)}

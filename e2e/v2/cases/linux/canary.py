#!/usr/bin/env python3
"""Real operations only. The outside observer decides whether they passed."""

import argparse
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time


def write(path, data):
    with Path(path).open("wb") as stream:
        stream.write(data)


def shared_write(path, data):
    with Path(path).open("r+b") as stream:
        with mmap.mmap(stream.fileno(), 0, flags=mmap.MAP_SHARED,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE) as mapping:
            mapping[:len(data)] = data
            mapping.flush()


def namespace_probe():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0) != 0:
        raise OSError(ctypes.get_errno(), "unshare syscall refused")


def exchange(address, family, kind, payload):
    with socket.socket(family, kind) as stream:
        stream.settimeout(2)
        stream.connect(address)
        stream.sendall(payload)
        reply = stream.recv(len(payload) + 1)
        if reply != payload:
            raise RuntimeError("echo bytes did not match the actual input")


def foreign_datagram(address, family, payload):
    with socket.socket(family, socket.SOCK_DGRAM) as stream:
        stream.settimeout(2)
        stream.connect(address)
        sent = stream.send(payload)
        if sent != len(payload):
            raise RuntimeError("datagram send was incomplete")
        try:
            reply = stream.recv(len(payload) + 1)
            return {"sent_bytes": sent, "receive_kind": "reply", "reply_bytes": len(reply)}
        except TimeoutError:
            return {"sent_bytes": sent, "receive_kind": "timeout"}
        except OSError as failure:
            return {"sent_bytes": sent, "receive_kind": "error", "receive_errno": failure.errno}


def own_echo(family, kind, payload, path=None):
    with socket.socket(family, kind) as listener:
        listener.settimeout(3)
        if family == socket.AF_UNIX:
            listener.bind(path)
        else:
            listener.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        address = listener.getsockname()
        failures = []
        if kind == socket.SOCK_STREAM:
            listener.listen(1)

        def serve():
            try:
                if kind == socket.SOCK_DGRAM:
                    data, sender = listener.recvfrom(len(payload) + 1)
                    listener.sendto(data, sender)
                else:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        connection.sendall(connection.recv(len(payload) + 1))
            except (OSError, RuntimeError) as failure:
                failures.append(failure)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            exchange(address, family, kind, payload)
        finally:
            thread.join(timeout=4)
        if thread.is_alive():
            raise TimeoutError("own echo server did not terminate")
        if failures:
            raise failures[0]


def own_signal():
    child = os.fork()
    if child == 0:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        while True:
            signal.pause()
    os.kill(child, signal.SIGTERM)
    got, status = os.waitpid(child, 0)
    if got != child or not os.WIFSIGNALED(status):
        raise RuntimeError("own process was not terminated by the signal")


def detach(path, payload):
    ready_read, ready_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(ready_read)
        os.setsid()
        grandchild = os.fork()
        if grandchild != 0:
            os._exit(0)
        # The detached process retains the unpredictable --marker argv. The
        # observer identifies it through host /proc, not its namespace PID.
        try:
            write(path, payload)
            os.write(ready_write, b"R")
            os.close(ready_write)
            for descriptor in (0, 1, 2):
                os.close(descriptor)
            while True:
                time.sleep(0.25)
                write(path, payload + str(time.monotonic_ns()).encode())
        finally:
            os._exit(1)
    os.close(ready_write)
    try:
        if os.read(ready_read, 1) != b"R":
            raise RuntimeError("detached child did not reach its write")
    finally:
        os.close(ready_read)
    got, status = os.waitpid(child, 0)
    if got != child or status != 0:
        raise RuntimeError("intermediate fork did not exit successfully")


def run(inputs, marker):
    work = Path(inputs["work"])
    payload = bytes.fromhex(inputs["payload_hex"])
    if not payload:
        raise ValueError("the observer must supply unpredictable input bytes")
    result = {"operations": {}, "marker_sha256":
              hashlib.sha256(marker.encode()).hexdigest()}

    def observe(name, operation):
        try:
            details = operation()
            value = {"outcome": "ok", "errno": 0}
            if isinstance(details, dict):
                value.update(details)
        except TimeoutError as failure:
            value = {"outcome": "error", "errno": failure.errno,
                     "kind": "timeout"}
        except OSError as failure:
            value = {"outcome": "error", "errno": failure.errno,
                     "kind": type(failure).__name__}
        except (RuntimeError, ValueError, subprocess.SubprocessError) as failure:
            value = {"outcome": "error", "errno": None,
                     "kind": type(failure).__name__}
        result["operations"][name] = value

    target = work / "written"
    observe("work.write", lambda: write(target, payload))
    observe("work.read", lambda: target.read_bytes())
    observe("work.mmap", lambda: shared_write(target, payload))
    observe("work.link", lambda: os.link(target, work / "own-link"))
    observe("tmp.write", lambda: write(Path(inputs["tmp"]) / marker, payload))
    observe("home.write", lambda: write(Path(inputs["home"]) / marker, payload))

    def build():
        source = work / "ordinary.c"
        write(source, b"int main(void) { return 17; }\n")
        subprocess.run(["cc", str(source), "-o", str(work / "ordinary")],
                       check=True, capture_output=True)
        got = subprocess.run([str(work / "ordinary")], check=False,
                             capture_output=True)
        if got.returncode != 17:
            raise RuntimeError("new build output did not execute")

    def git():
        directory = work / "private-repo"
        subprocess.run(["git", "init", str(directory)], check=True,
                       capture_output=True)
        write(directory / "record", payload)
        subprocess.run(["git", "-C", str(directory), "add", "record"],
                       check=True, capture_output=True)
        got = subprocess.run(["git", "-C", str(directory), "show", ":record"],
                             check=True, capture_output=True)
        if got.stdout != payload:
            raise RuntimeError("Git did not store the input bytes")

    observe("work.build", build)
    observe("work.git", git)
    observe("own.signal", own_signal)
    observe("escape.unshare", namespace_probe)
    observe("own.ipc", lambda: own_echo(socket.AF_UNIX, socket.SOCK_STREAM,
                                      payload, str(work / "private.sock")))
    for suffix, family in (("4", socket.AF_INET), ("6", socket.AF_INET6)):
        for transport, kind in (("tcp", socket.SOCK_STREAM),
                                ("udp", socket.SOCK_DGRAM)):
            observe("own." + transport + suffix,
                    lambda f=family, k=kind: own_echo(f, k, payload))
            endpoint = inputs["foreign"][transport + suffix]
            if kind == socket.SOCK_DGRAM:
                observe("foreign." + transport + suffix,
                        lambda f=family, e=endpoint: foreign_datagram(tuple(e), f, payload))
            else:
                observe("foreign." + transport + suffix,
                        lambda f=family, k=kind, e=endpoint: exchange(tuple(e), f, k, payload))
    permitted = inputs["permitted"]
    observe("permitted.network", lambda: exchange(tuple(permitted),
            socket.AF_INET, socket.SOCK_STREAM, payload))
    observe("foreign.ipc", lambda: exchange(inputs["foreign"]["ipc"],
            socket.AF_UNIX, socket.SOCK_STREAM, payload))
    observe("foreign.signal", lambda: os.kill(inputs["foreign"]["pid"],
                                             signal.SIGUSR1))

    for name in ("outside", "readonly", "nested"):
        path = Path(inputs[name])
        if name != "nested":
            observe(name + ".read", lambda p=path: p.read_bytes())
        else:
            observe("nested.read", lambda p=path: p.read_bytes())
        observe(name + ".write", lambda p=path: write(p, payload))
        if name != "nested":
            observe(name + ".mmap", lambda p=path: shared_write(p, payload))
            observe(name + ".link", lambda p=path, n=name:
                    os.link(p, work / (n + "-link")))
    observe("inherited.fd", lambda: fcntl.fcntl(inputs["inherited_fd"],
                                               fcntl.F_GETFD))
    observe("detach.double_fork", lambda: detach(work / "heartbeat", payload))
    libc = ctypes.CDLL(None, use_errno=True)
    result["no_new_privs"] = libc.prctl(39, 0, 0, 0, 0)
    status = Path("/proc/thread-self/status").read_text().splitlines()
    result["cap_eff"] = int(next(line.split()[1] for line in status
                                 if line.startswith("CapEff:")), 16)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--wait-input-ms", type=int, default=0)
    parser.add_argument("--input-sha256")
    args = parser.parse_args()
    if not 0 <= args.wait_input_ms <= 180000:
        raise ValueError("input handoff deadline is out of bounds")
    deadline = time.monotonic() + args.wait_input_ms / 1000
    while not args.input.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("outside observer did not release the exact input")
        time.sleep(0.05)
    input_bytes = args.input.read_bytes()
    if args.input_sha256 is not None and hashlib.sha256(input_bytes).hexdigest() != args.input_sha256:
        raise ValueError("outside observer released different canary bytes")
    result = run(json.loads(input_bytes), args.marker)
    result["input_sha256"] = hashlib.sha256(input_bytes).hexdigest()
    pending = args.output.with_name(args.output.name + ".pending")
    write(pending, (json.dumps(result, sort_keys=True) + "\n").encode())
    pending.replace(args.output)


if __name__ == "__main__":
    main()

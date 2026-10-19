"""Retain only the two fixed Linux lane projections for an inside CLI child."""

import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat


BINDING_PATH = Path("/run/laneboss/binding.json")
SOCKET_PATH = Path("/run/laneboss/service.sock")
MAX_BYTES = 4 * 1024 * 1024


def descriptor(path):
    link = os.readlink(path)
    match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]*)", link)
    if not match or not 6 <= int(match[1]) <= 4096:
        raise ValueError("lane projection has an invalid inherited descriptor")
    fd = int(match[1])
    os.fstat(fd)
    return fd


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("lane binding contains duplicate fields")
        result[name] = value
    return result


def lane_fds(config):
    binding_fd, socket_fd = descriptor(BINDING_PATH), descriptor(SOCKET_PATH)
    if binding_fd == socket_fd:
        raise ValueError("lane binding and socket projections overlap")
    info = os.fstat(binding_fd)
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o444 or not 0 < info.st_size <= MAX_BYTES or fcntl.fcntl(binding_fd, fcntl.F_GET_SEALS) & seals != seals:
        raise ValueError("lane binding is not exactly sealed and read-only")
    raw = os.pread(binding_fd, info.st_size, 0)
    if len(raw) != info.st_size:
        raise ValueError("lane binding descriptor is truncated")
    binding = json.loads(raw, object_pairs_hook=unique_object)
    if binding.get("config") != config or binding.get("class") != "lane" or binding.get("socket") != "/run/laneboss/service.sock":
        raise ValueError("lane binding conflicts with its fixed configuration or endpoint")
    if not stat.S_ISSOCK(os.fstat(socket_fd).st_mode):
        raise ValueError("lane socket projection is not a socket")
    with socket.fromfd(socket_fd, socket.AF_UNIX, socket.SOCK_STREAM) as pinned:
        if pinned.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or pinned.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX:
            raise ValueError("lane endpoint is not a stream socket")
        pinned.getpeername()  # A disconnected or listening FD is not a handoff.
    # pass_fds keeps these exact original numbers and closes all other FDs.
    # The actual CLI still verifies the sealed full binding and native peer.
    return binding_fd, socket_fd

"""The terminal multiplexer that keeps lane runs alive after the calling session: tmux.

Each configuration has its own tmux server, reached only through an explicit socket path that the launcher chooses
and records in every launch's lane.started event: /tmp/laneboss-UID/CONFIG-HASH, where HASH is 12 hex digits of the
SHA-256 of the configuration's state directory (its real path). /tmp keeps the path short on every system (a Unix
socket path is limited to about 100 bytes), and the directory is the launcher's own: created with mode 0700. On every
use, not only when a session is created, the directory is refused when it is a link, belongs to another user or is
open to others, and the socket path when it is a link or not a socket. Commands about an existing launch use the
socket its event records, never one resolved through their own environment, so TMUX_TMPDIR and TMUX do not change
which server they reach. A run is a session on that server named after its lane (tmux turns `.` into `_` in session
names, so the launcher does the same); no command stops or kills a session by its name: a run is stopped through its
supervising process's recorded identity. tmux is always called with an argument vector, never through a shell, and
with `-f /dev/null`, so a user's tmux configuration cannot change how the server behaves. It is also given a fixed
environment, built here and never inherited (PATH, HOME, LANG, TMPDIR and USER, as the caller has them, and nothing
else): the first command that reaches a socket starts the server, and the server keeps that command's environment as its
global environment, where `show-environment -g` shows it to every process that can reach the socket and every pane
inherits it. What a run's process receives of its caller's environment never goes through tmux: the supervising
process reads it from a FIFO.
"""

import os
import shutil
import stat
import subprocess
import time

from .errors import Refused
from .identity import PROGRAM
from .jsonutil import sha256_hex

TIMEOUT = 30
EXITING = ("server exited unexpectedly", "lost server")
ATTEMPTS = 5
NO_SOCKET = ("No such file or directory", "Connection refused")
ENVIRONMENT = ("PATH", "HOME", "LANG", "TMPDIR", "USER")


def runtime_directory():
    return "/tmp/{}-{}".format(PROGRAM, os.getuid())


def socket_path(config_name, state_real):
    """The socket of a configuration's tmux server, from its name and its state directory's real path."""
    return os.path.join(runtime_directory(), "{}-{}".format(config_name, sha256_hex(os.fsencode(state_real))[:12]))


def check_socket(socket):
    """Refuse, on every use, a socket path that is a link or not a socket, and a socket directory that is a link, not
    a directory, another user's or open to others. A directory or socket that does not exist means no server."""
    directory = os.path.dirname(socket)
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Refused("{} must be a directory of this user's alone (mode 0700, not a link); it holds the lanes' tmux "
                      "sockets".format(directory))
    try:
        info = os.lstat(socket)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise Refused("the tmux socket {} is a symbolic link; the launcher reaches a configuration's tmux server only "
                      "through its own socket, never through a link".format(socket))
    if not stat.S_ISSOCK(info.st_mode):
        raise Refused("the tmux socket {} is not a socket".format(socket))


def prepare(socket):
    """Make sure the socket's directory exists and is this user's alone; a directory removed in between is made
    again."""
    directory = os.path.dirname(socket)
    for attempt in range(3):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise Refused("cannot create {}: {}".format(directory, error.strerror or "error")) from None
        if os.path.lexists(directory):
            check_socket(socket)
            return
    raise Refused("{} keeps disappearing; it holds the lanes' tmux sockets".format(directory))


def session_name(lane):
    return lane.replace(".", "_")


def environment():
    """The environment of every tmux command: the variables of ENVIRONMENT that the caller has, with the caller's
    values, and nothing else. The server keeps the environment of the first command that reaches its socket as its
    global environment, so no other variable of the caller may be in it."""
    return {name: os.environ[name] for name in ENVIRONMENT if name in os.environ}


def available():
    return shutil.which("tmux") is not None


def run(socket, *arguments):
    """(exit status, stdout, stderr) of one tmux command on the server at this socket. A server exits when its last
    session ends; a command that reaches it while it exits is answered "server exited unexpectedly", and is tried
    again, so it reaches either no server or a new one."""
    if not available():
        raise Refused("tmux is not on PATH; lanes run in tmux sessions")
    check_socket(socket)
    for attempt in range(ATTEMPTS):
        try:
            result = subprocess.run(["tmux", "-S", socket, "-f", os.devnull, *arguments], env=environment(),
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            raise Refused("tmux did not answer within {} seconds".format(TIMEOUT)) from None
        if result.returncode == 0 or not any(message in result.stderr for message in EXITING):
            break
        time.sleep(0.1 * (attempt + 1))
    return result.returncode, result.stdout, result.stderr


def sessions(socket):
    """The names of the server's sessions; an empty list when no server runs at the socket (or it was just exiting).
    Any other failure is an error, so a session is never reported missing when it could not be looked at."""
    check_socket(socket)
    if not os.path.lexists(socket):
        return []
    status, output, errors = run(socket, "list-sessions", "-F", "#{session_name}")
    if status == 0:
        return [line for line in output.splitlines() if line]
    message = errors.strip()
    if message.startswith("no server running") or (message.startswith("error connecting to") and any(
            reason in message for reason in NO_SOCKET)) or any(reason in message for reason in EXITING):
        return []
    raise Refused("tmux could not list the sessions at {}: {}".format(socket, message.splitlines()[0] if message else
                                                                       "exit status {}".format(status)))


def alive(socket, name):
    return name in sessions(socket)


def pane_pid(socket, name):
    """The process id of the session's pane process, or None when the session does not exist."""
    status, output, _ = run(socket, "list-panes", "-t", "=" + name, "-F", "#{pane_pid}")
    if status != 0:
        return None
    for line in output.splitlines():
        if line.strip().isdigit():
            return int(line.strip())
    return None


def new_session(socket, name, directory, argv):
    """Start a detached session running argv directly (no shell). Refused when tmux cannot create it, for example
    because a session of that name exists."""
    prepare(socket)
    status, _, errors = run(socket, "new-session", "-d", "-s", name, "-c", directory, "-x", "200", "-y", "50", *argv)
    if status != 0:
        message = errors.strip().splitlines()[0] if errors.strip() else "exit status {}".format(status)
        raise Refused("tmux could not create session {} at {}: {}".format(name, socket, message))

"""The resident search's server: HTTP/1.1 on a Unix socket, and nothing else.

    GET|POST /search   one search; the parameters are the options of `laneboss decisions search`
    GET      /status   what the server holds: builds of its index, records, answers remembered

The parameters are `query` (required, empty is allowed) and `mode`, `id`, `project`, `area`, `topic`, `kind`,
`status` (any number of times), `date-from` (or `from`, `since`), `date-to` (or `to`, `until`), `limit` and `all`
(`1`), in the query string or, for a POST, in a form body. They are turned into the words of the command and parsed by
the command's own parser, so a mistake is refused as the command refuses it. The embedding provider is the server's
own, set by --config when it started: no request can choose another.

A search that succeeds is answered with status 200 and the bytes the command prints. One that fails is answered with
the message the command prints on standard error, and its exit code in the header X-Exit-Code, under the status
that fits: 400 for 2 (invalid input), 500 for 3, 6 and 7, 502 for 4 (the provider), 503 for 5 (busy).
"""

import argparse
from http.server import BaseHTTPRequestHandler
import os
import signal
import socket
import socketserver
import stat
import sys
import threading
import time
from urllib.parse import parse_qsl, urlsplit

from .cli import failure, parser as command_parser
from .resident import Resident
from .schema import InvalidInput, render
from .store import Progress

STATUS = {2: 400, 3: 500, 4: 502, 5: 503, 6: 500, 7: 500}
OPTIONS = {
    "mode": "mode", "id": "id", "project": "project", "area": "area", "topic": "topic", "kind": "kind",
    "status": "status", "limit": "limit", "date-from": "date-from", "from": "date-from", "since": "date-from",
    "date-to": "date-to", "to": "date-to", "until": "date-to",
}
MAX_BODY = 1 << 20
# The most bytes a Unix socket path may take: the size of `sun_path` (104 bytes on macOS and the BSDs, 108 on Linux).
# Only the path, which is everything a call to bind can fail over, since this server listens on nothing else.
SOCKET_PATH_LIMIT = 104 if sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd")) else 108


class RequestParser(argparse.ArgumentParser):
    """The command's parser, for words that come from a request: a mistake in them refuses the request."""

    def error(self, message):
        raise InvalidInput(message)


class Requests:
    """Turns the parameters of a request into the arguments of a search, with the command's own parser."""

    def __init__(self, database, config):
        self.parser = command_parser(RequestParser)
        self.lock = threading.Lock()
        self.database = str(database)
        self.config = config

    def arguments(self, pairs):
        query = None
        taken = set()
        words = []
        for name, value in pairs:
            if name == "query":
                target = "query"
            elif name == "all":
                target = "all"
            else:
                target = OPTIONS.get(name)
            if target is None:
                raise InvalidInput("unknown parameter: " + ascii(name[:40]))
            if target in taken and target != "status":
                raise InvalidInput("parameter given twice: " + target)
            taken.add(target)
            if target == "query":
                query = value
            elif target == "all":
                if value not in ("1", "true"):
                    raise InvalidInput("all must be 1")
                words.append("--all")
            else:
                words.append("--{}={}".format(target, value))
        if query is None:
            raise InvalidInput("query is required")
        # The query is a value and never an option, whatever it starts with: a stand-in goes where it would stand.
        with self.lock:
            arguments = self.parser.parse_args(["search", "--db", self.database] + words + ["query"])
        arguments.query = query
        arguments.config = self.config
        return arguments


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "laneboss-decisions"
    timeout = 30

    def version_string(self):
        return self.server_version

    def log_message(self, format_string, *arguments):
        return

    def reply(self, status, body, content_type, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def text(self, status, message, headers=()):
        self.reply(status, (message + "\n").encode("utf-8"), "text/plain; charset=utf-8", headers)

    def refuse(self, message, code):
        self.text(STATUS.get(code, 500), message, [("X-Exit-Code", str(code))])

    def not_allowed(self):
        self.leave_body()
        self.text(405, "method not allowed", [("Allow", "GET, POST")])

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = not_allowed

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        self.server.begin()
        try:
            path = urlsplit(self.path)
            if path.path == "/search":
                self.search(method, path.query)
            elif path.path == "/status" and method == "GET":
                self.leave_body()
                self.reply(200, render(self.server.resident.status()).encode("ascii"), "application/json")
            elif path.path == "/status":
                self.not_allowed()
            else:
                self.leave_body()
                self.text(404, "not found")
        finally:
            self.server.end()

    def leave_body(self):
        """A request whose body is not read leaves its bytes on the connection, where the next request would be read
        from them: the connection ends with this reply."""
        if self.headers.get("Transfer-Encoding") or (self.headers.get("Content-Length") or "0").strip() != "0":
            self.close_connection = True

    def read_body(self):
        """The body of a POST, read whole. A request whose length cannot be known or is too long is refused and its
        connection ends with the reply, since what follows its header cannot be told from the next request."""
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise InvalidInput("a request body needs a Content-Length")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            raise InvalidInput("the Content-Length is not a number") from None
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            raise InvalidInput("a request body is at most {} bytes".format(MAX_BODY))
        try:
            return self.rfile.read(length)
        except OSError:
            # A body that stopped coming (the client waited too long, or went away): the bytes that follow are not a request.
            self.close_connection = True
            raise

    def form(self, body):
        kind = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if kind not in ("", "application/x-www-form-urlencoded"):
            raise InvalidInput("a request body is a form: application/x-www-form-urlencoded")
        return parse_qsl(body.decode("utf-8"), keep_blank_values=True, encoding="utf-8", errors="strict")

    def search(self, method, query_string):
        # What the failure messages need to know of the search when it fails before its words are parsed.
        arguments = argparse.Namespace(command="search", mode="keyword")
        try:
            if method == "POST":
                sent = self.read_body()
            else:
                self.leave_body()
            pairs = parse_qsl(query_string, keep_blank_values=True, encoding="utf-8", errors="strict")
            if method == "POST":
                pairs += self.form(sent)
            arguments = self.server.requests.arguments(pairs)
            body = self.server.resident.answer(arguments)
        except Exception as error:
            known = failure(error, arguments, Progress())
            if known is None:
                sys.stderr.write("serve: unexpected {}\n".format(type(error).__name__))
                sys.stderr.flush()
                known = ("unexpected error: " + type(error).__name__, 1)
            self.refuse(*known)
            return
        self.reply(200, body, "application/json")


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, path, resident, requests):
        self.resident = resident
        self.requests = requests
        self.counting = threading.Lock()
        self.active = 0
        self.last = time.monotonic()
        socketserver.UnixStreamServer.__init__(self, path, Handler)

    def begin(self):
        with self.counting:
            self.active += 1

    def end(self):
        with self.counting:
            self.active -= 1
            self.last = time.monotonic()

    def idle_seconds(self):
        """Seconds since the last request ended; None while a request is in flight."""
        with self.counting:
            return None if self.active else time.monotonic() - self.last

    def handle_error(self, request, client_address):
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionError, socket.timeout)):
            return
        sys.stderr.write("serve: error in a connection: {}\n".format(type(error).__name__))
        sys.stderr.flush()


def check_socket_path(socket_path):
    """A Unix socket path is limited by the size of `sun_path`, and one that is longer fails at the bind with the socket
    module's own words. It is refused here instead, before anything is made, so that the message names the length, the
    limit and a shorter place to put the socket. The bind error stays as the second line of defence."""
    length = len(os.fsencode(socket_path))
    if length <= SOCKET_PATH_LIMIT:
        return
    raise InvalidInput(
        "the socket path is {} bytes long and this system allows at most {} (a limit of Unix sockets); give --socket "
        "a shorter path in a directory of your own, for example under $TMPDIR on macOS or $XDG_RUNTIME_DIR on "
        "Linux".format(length, SOCKET_PATH_LIMIT))


def private_directory(directory):
    """The directory of the socket is the server's own: made here with mode 700, or already yours and closed to
    everyone else. A directory that others can enter is refused, and never changed."""
    try:
        info = os.stat(directory)
    except FileNotFoundError:
        if not os.path.isdir(os.path.dirname(directory)):
            raise InvalidInput("the directory {} for the socket does not exist, and neither does the one "
                               "above it".format(directory)) from None
        try:
            os.mkdir(directory, 0o700)
            os.chmod(directory, 0o700)
        except OSError as error:
            raise InvalidInput("cannot make the directory {} for the socket: {}".format(
                directory, error.strerror or error)) from None
        return
    if not stat.S_ISDIR(info.st_mode):
        raise InvalidInput("{} is not a directory".format(directory))
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise InvalidInput(
            "the directory {} for the socket must be yours alone (mode 700) and is not: change it with "
            "chmod 700, or give the socket a directory of its own".format(directory))


def claim(path):
    """Make the way free for a socket at `path`: remove the socket that a server left, and refuse a live server's
    and anything that is not a socket."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(mode):
        raise InvalidInput("{} exists and is not a socket, and is not replaced".format(path))
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(5)
    try:
        probe.connect(path)
    except (ConnectionRefusedError, FileNotFoundError):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    except OSError as error:
        raise InvalidInput("cannot tell whether a server listens on {}: {}".format(
            path, error.strerror or error)) from None
    finally:
        probe.close()
    raise InvalidInput("a server is already listening on {}".format(path))


def bind(path, resident, requests):
    """Listen on a Unix socket that only its owner can use: it is made under a mask that leaves no other access.
    A path that the system does not take is refused by check_socket_path before this; the error here is the second
    line of defence, for a path that another system measures differently."""
    previous = os.umask(0o177)
    try:
        server = Server(path, resident, requests)
    except OSError as error:
        raise InvalidInput("cannot listen on {}: {}".format(path, error.strerror or error)) from None
    finally:
        os.umask(previous)
    os.chmod(path, 0o600)
    return server


def serve(arguments):
    """Run the server until it has been idle for --idle-exit minutes or is told to stop; return the exit code."""
    socket_path = os.path.abspath(arguments.socket)
    config = os.path.abspath(arguments.config) if arguments.config else None
    resident = Resident(arguments.db, config)
    server = None
    made = None
    try:
        snapshot = resident.current()
        snapshot.require_sound()
        resident.warm(snapshot)
        check_socket_path(socket_path)
        private_directory(os.path.dirname(socket_path))
        claim(socket_path)
        server = bind(socket_path, resident, Requests(resident.path, config))
        made = os.stat(socket_path)
        stop = threading.Event()
        for name in ("SIGTERM", "SIGINT", "SIGHUP"):
            number = getattr(signal, name, None)
            if number is None:
                continue
            if name != "SIGTERM" and signal.getsignal(number) == signal.SIG_IGN:
                # Started with the signal ignored (by nohup, or by a shell that runs it in the background): it stays so.
                continue
            signal.signal(number, lambda received, frame: stop.set())
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        worker.start()
        sys.stdout.write(render({"ok": True, "pid": os.getpid(), "socket": socket_path}))
        sys.stdout.flush()
        limit = arguments.idle_exit * 60.0
        while not stop.wait(0.25):
            idle = server.idle_seconds()
            if idle is not None and idle >= limit:
                break
        server.shutdown()
        return 0
    finally:
        if server is not None:
            server.server_close()
            try:
                if made is not None:
                    info = os.stat(socket_path)
                    if (info.st_dev, info.st_ino) == (made.st_dev, made.st_ino):
                        os.unlink(socket_path)
            except FileNotFoundError:
                pass
        resident.close()

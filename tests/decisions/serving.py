"""Helpers of the resident-search tests: the server as a process, a client of its Unix socket, a local stand-in for
the third-party embedding service, and the fixture store the equivalence tests search.

The embedding provider is a service on the internet that a test machine cannot and must not use. EmbeddingStub
answers in its place on 127.0.0.1, with vectors that depend on the text. Everything else is the real system: the
real command line, the real server process, a real Unix socket and a real SQLite file.
"""

import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import random
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode
from collections import OrderedDict

from .support import GO_DECISIONS, ROOT, StoreCase, decisions_go_binary, plain_record


def decisions_program():
    return [str(decisions_go_binary())] if GO_DECISIONS else [sys.executable, "-m", "laneboss.decisions"]


class GoProbe:
    """One Go process exposing the service's own arithmetic and cache bookkeeping."""

    def __init__(self, case):
        self.case = case
        self.errors = tempfile.TemporaryFile(mode="w+b")
        self.process = subprocess.Popen([str(decisions_go_binary()), "probe"], cwd=str(ROOT),
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors,
                                        text=True, encoding="utf-8")
        case.addCleanup(self.close)

    def request(self, value):
        self.process.stdin.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
        self.process.stdin.flush()
        readable, _, _ = select.select([self.process.stdout], [], [], 60)
        self.case.assertTrue(readable, "the Go probe did not answer")
        line = self.process.stdout.readline()
        if not line:
            self.process.wait(timeout=10)
            self.errors.seek(0)
            self.case.fail("the Go probe ended: " + self.errors.read().decode("utf-8"))
        return json.loads(line)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()
        self.errors.close()


class GoResidentProxy:
    """Translate existing white-box rows into calls to the compiled Go functions."""

    Entry = staticmethod(lambda identifier, side, vector, norm:
                         types.SimpleNamespace(record_id=identifier, side=side, vector=vector, norm=norm))

    def __init__(self, case, cache=False):
        self.probe = GoProbe(case)
        if cache:
            limits = self.probe.request({"action": "cache-init"})
            self.ANSWER_BYTES = limits["max_bytes"]
            self.Snapshot = types.SimpleNamespace(remember_answer=self.remember_answer)

    def exact_dot(self, left, right):
        return self.probe.request({"action": "dot", "left": list(left), "right": list(right)})["dot"]

    def exact_norm(self, vector):
        return self.probe.request({"action": "dot", "left": list(vector), "right": list(vector)})["norm"]

    def rank_vectors(self, model, groups, query, depth):
        values = {identifier: [{"side": entry.side, "vector": list(entry.vector)} for entry in entries]
                  for identifier, entries in groups.items()}
        result = self.probe.request({"action": "rank", "model": model, "groups": values,
                                     "query": query, "depth": depth})
        return types.SimpleNamespace(ranking=result["ranking"], matches=lambda identifier: result["matches"][identifier],
                                     score=lambda identifier: result["scores"][identifier])

    def remember_answer(self, keeper, key, body):
        result = self.probe.request({"action": "cache-put", "key": json.dumps(key),
                                     "body": body.decode("utf-8")})
        keeper.answers = OrderedDict((tuple(json.loads(value)), None) for value in result["keys"])
        keeper.answers_size = result["bytes"]


def arithmetic_sum(values):
    """The Go contract adds float64 products in order, independent of Python's version."""
    if not GO_DECISIONS:
        return sum(values)
    total = 0.0
    for value in values:
        total += float(value)
    return total

DIMENSION = 256
MODEL = "stub-embed-1"
KINDS = ("answer", "correction", "decision", "instruction", "preference", "question_from_owner")


def semantic_vector(text, dimension=DIMENSION):
    """A made-up embedding: every word adds to three positions, so texts that share words point the same way, and a
    little noise that depends only on the text keeps the numbers from being tidy, as a real model's are. The same
    text always gives the same vector; the vector has length 1."""
    vector = [0.0] * dimension
    for word in re.findall(r"\w+", text.lower()):
        digest = hashlib.sha256(word.encode("utf-8")).digest()
        for part in range(3):
            position = int.from_bytes(digest[part * 4:part * 4 + 4], "big") % dimension
            vector[position] += 1.0 if digest[12 + part] & 1 else -1.0
    noise = random.Random(int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big"))
    for index in range(dimension):
        vector[index] += noise.uniform(-0.05, 0.05)
    norm = math.sqrt(sum(number * number for number in vector))
    return [number / norm for number in vector]


class EmbeddingStub:
    """The embedding service's stand-in. It checks the bearer key, remembers every request it gets, and can be told to
    answer slowly (delay), to fail (status), or to call a function with each request body before it answers
    (observer)."""

    def __init__(self, key):
        self.key = key
        self.requests = []
        self.lock = threading.Lock()
        self.delay = 0.0
        self.status = None
        self.observer = None
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format_string, *arguments):
                return

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with stub.lock:
                    stub.requests.append({"body": body, "auth": self.headers.get("Authorization")})
                observer, delay, status = stub.observer, stub.delay, stub.status
                if observer is not None:
                    observer(body)
                if delay:
                    time.sleep(delay)
                if self.headers.get("Authorization") != "Bearer " + stub.key:
                    self.send_response(401)
                    self.end_headers()
                    return
                if status is not None:
                    self.send_response(status)
                    self.end_headers()
                    self.wfile.write(("failed for " + self.headers.get("Authorization", "")).encode("utf-8"))
                    return
                dimension = body["output_dimension"]
                data = [{"index": index, "embedding": semantic_vector(text, dimension)}
                        for index, text in enumerate(body["input"])]
                payload = json.dumps({"data": list(reversed(data)), "model": body["model"]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def endpoint(self):
        return "http://127.0.0.1:{}/v1/embeddings".format(self.server.server_port)

    def reset(self):
        with self.lock:
            del self.requests[:]
        self.delay = 0.0
        self.status = None
        self.observer = None

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class UnixConnection(http.client.HTTPConnection):
    """An HTTP/1.1 connection to a Unix socket: the same bytes `curl --unix-socket` sends."""

    def __init__(self, path, timeout=60):
        http.client.HTTPConnection.__init__(self, "localhost", timeout=timeout)
        self.unix_path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


class Reply:
    def __init__(self, status, headers, body, version=11):
        self.status = status
        self.headers = headers
        self.body = body
        self.version = version

    def header(self, name):
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    @property
    def exit_code(self):
        value = self.header("X-Exit-Code")
        return None if value is None else int(value)

    def json(self):
        return json.loads(self.body.decode("utf-8"))

    def text(self):
        return self.body.decode("utf-8")


def ask(socket_path, method, target, body=None, headers=None, timeout=60):
    connection = UnixConnection(socket_path, timeout)
    try:
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        return Reply(response.status, response.getheaders(), data, response.version)
    finally:
        connection.close()


def search_params(query, mode=None, **options):
    """The parameters of a search request. Names are the command's options without the dashes; an option that the
    command takes more than once is a list; a flag is True."""
    params = [("query", query)]
    if mode is not None:
        params.append(("mode", mode))
    for name, value in options.items():
        key = name.replace("_", "-")
        if value is True:
            params.append((key, "1"))
        elif isinstance(value, (list, tuple)):
            params.extend((key, str(item)) for item in value)
        else:
            params.append((key, str(value)))
    return params


def search_words(query, mode=None, **options):
    """The same search as the words `laneboss decisions search` takes."""
    words = [query]
    if mode is not None:
        words += ["--mode", mode]
    for name, value in options.items():
        flag = "--" + name.replace("_", "-")
        if value is True:
            words.append(flag)
        elif isinstance(value, (list, tuple)):
            for item in value:
                words += [flag, str(item)]
        else:
            words += [flag, str(value)]
    return words


class ServerProcess:
    """`laneboss decisions serve` as a process of its own. Stopping it is by process id."""

    def __init__(self, case, arguments, environment, name="server", cwd=None, umask=None, launcher=None):
        self.case = case
        self.stderr_path = case.scratch / (name + ".stderr")
        self.stderr_file = open(str(self.stderr_path), "wb")
        self.stdout_text = ""
        # Whether stop() read the server's output to its end. A test that searches that output for a secret requires
        # this: a read that failed would leave the search with less than the whole output and could still pass.
        self.stdout_complete = False
        launcher = launcher or decisions_program() + ["serve"]
        command = [str(item) for item in launcher] + [str(item) for item in arguments]
        if umask is not None:
            # The shell sets the mask and then becomes the server, so the process id stays the server's.
            command = ["sh", "-c", 'umask "$0" && exec "$@"', "{:03o}".format(umask)] + command
        self.process = subprocess.Popen(
            command, cwd=str(cwd or ROOT), env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=self.stderr_file, text=True, encoding="utf-8")
        case.addCleanup(self.stop)
        self.pid = self.process.pid
        self.ready = None
        self.socket_path = None

    def wait_ready(self, timeout=60):
        deadline = time.monotonic() + timeout
        line = ""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.case.fail("the server printed no ready line in {} seconds; stderr={!r}".format(
                    timeout, self.stderr()))
            readable, _, _ = select.select([self.process.stdout], [], [], min(remaining, 0.2))
            if readable:
                line = self.process.stdout.readline()
                if line:
                    break
                self.process.wait(timeout=10)
                self.case.fail("the server ended (exit {}) before its ready line; stderr={!r}".format(
                    self.process.returncode, self.stderr()))
        self.stdout_text += line
        self.ready = json.loads(line)
        self.case.assertIs(self.ready["ok"], True, line)
        self.socket_path = self.ready["socket"]
        return self

    def stderr(self):
        if not self.stderr_file.closed:
            self.stderr_file.flush()
        return self.stderr_path.read_text(encoding="utf-8", errors="replace")

    def ask(self, method, target, body=None, headers=None, timeout=60):
        return ask(self.socket_path, method, target, body, headers, timeout)

    def get(self, path, params=()):
        return self.ask("GET", path + ("?" + urlencode(list(params)) if params else ""))

    def search(self, query, mode=None, **options):
        return self.get("/search", search_params(query, mode, **options))

    def status(self):
        reply = self.get("/status")
        self.case.assertEqual(reply.status, 200, reply.body)
        return reply.json()

    def alive(self):
        return self.process.poll() is None

    def wait_exit(self, timeout=30):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.case.fail("the server was still running after {} seconds".format(timeout))
        return self.process.returncode

    def stop(self):
        process = self.process
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stdout is not None and not process.stdout.closed:
            try:
                self.stdout_text += process.stdout.read()
            except (OSError, ValueError):
                # Cleanup after the process has ended: the pipe may already be closed, and what is left of its output
                # is only kept to be searched for the key. A failure to read it is not a failure of the test, but a
                # test that searches that output for the key requires stdout_complete, which stays False here.
                pass
            else:
                self.stdout_complete = True
            process.stdout.close()
        if not self.stderr_file.closed:
            self.stderr_file.close()


def inet_sockets(pid):
    """The listening TCP sockets, and every UDP or raw socket, that a process holds open. Linux reads /proc; macOS
    asks lsof; on any other system the check cannot be made, and that is a failure, not a pass."""
    if sys.platform.startswith("linux") and os.path.isdir("/proc/{}/fd".format(pid)):
        inodes = set()
        for name in os.listdir("/proc/{}/fd".format(pid)):
            try:
                target = os.readlink("/proc/{}/fd/{}".format(pid, name))
            except OSError:
                continue
            if target.startswith("socket:["):
                inodes.add(target[len("socket:["):-1])
        found = []
        for table in ("tcp", "tcp6", "udp", "udp6", "udplite", "udplite6", "raw", "raw6"):
            try:
                lines = Path("/proc/net/" + table).read_text(encoding="utf-8").splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) > 9 and fields[9] in inodes and (not table.startswith("tcp") or fields[3] == "0A"):
                    found.append("{} {} state {}".format(table, fields[1], fields[3]))
        return found
    if sys.platform == "darwin":
        result = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-i"], capture_output=True, text=True,
                                timeout=60)
        return [line for line in result.stdout.splitlines()[1:]
                if line.strip() and ("(LISTEN)" in line or " UDP " in line)]
    raise AssertionError("the sockets of a process cannot be listed on this system")


# The fixture store: invented records, written by `load` and embedded through the stub.

THINGS = ("deployment", "billing rollout", "backup schedule", "access review", "release train", "alert routing",
          "vendor contract", "data retention")
TEAMS = ("alpha", "beta", "gamma", "delta")
ACTIONS = ("approve", "postpone", "split", "automate", "document", "reject")
DEPENDENCIES = ("the audit log", "the staging cluster", "the invoice export", "the payment gateway",
                "the on-call rota")
OFFSETS = ("+08:00", "Z", "-05:00", "+00:00")
AREAS = ("release", "security", "billing", "ops")
PROJECTS = ("alpha", "beta", "gamma")


def fixture_record(number, question, verbatim, status="in_force"):
    value = plain_record("D-{:02d}".format(number), question, verbatim, status)
    thing = THINGS[number % len(THINGS)]
    team = TEAMS[number % len(TEAMS)]
    dependency = DEPENDENCIES[(number * 3) % len(DEPENDENCIES)]
    value["project"] = PROJECTS[number % len(PROJECTS)]
    value["area"] = AREAS[number % len(AREAS)]
    value["kind"] = KINDS[number % len(KINDS)]
    value["topics"] = [thing.split()[0], team]
    value["question"]["background"] = "Context {}: the {} depends on {}.".format(number, thing, dependency)
    day = 8 + number % 9
    value["asked_at"] = "2026-10-{:02d}T01:00:00Z".format(day)
    value["answered_at"] = "2026-10-{:02d}T{:02d}:{:02d}:00{}".format(
        day, (number * 5) % 24, (number * 7) % 60, OFFSETS[number % len(OFFSETS)])
    value["provenance"]["recorded_at"] = "2026-10-{:02d}T23:00:00Z".format(day)
    return value


def fixture_operations():
    """The batch `load` takes: forty records of ordinary text, three records that say exactly the same (their vectors
    tie), one record that supersedes another, and records with characters that a request must carry unchanged."""
    operations = []
    for number in range(1, 41):
        thing = THINGS[number % len(THINGS)]
        team = TEAMS[number % len(TEAMS)]
        action = ACTIONS[(number * 5) % len(ACTIONS)]
        dependency = DEPENDENCIES[(number * 3) % len(DEPENDENCIES)]
        question = "Should we {} the {} for the {} team before the review {}?".format(action, thing, team, number)
        if number % 7 == 0:
            verbatim = "可以，先{} {}，但是不要動 {}。".format(action, thing, dependency)
        else:
            verbatim = "Yes, {} it, but only for {}; keep {} untouched.".format(action, team, dependency)
        status = "fulfilled" if number in (5, 15) else "withdrawn" if number == 9 else "in_force"
        operations.append({"op": "add", "record": fixture_record(number, question, verbatim, status)})
    for number, project in ((41, "alpha"), (42, "beta"), (43, "gamma")):
        value = fixture_record(41, "Identical question about vendor contract renewal",
                               "Identical answer: renew for one year")
        value["id"] = "D-{}".format(number)
        value["project"] = project
        operations.append({"op": "add", "record": value})
    replacement = fixture_record(44, "Should we reject the backup schedule once more?",
                                 "No, keep the backup schedule as it stands.")
    operations.append({"op": "supersede", "target": "D-12", "record": replacement})
    operations.append({"op": "add", "record": fixture_record(
        45, "Strasse und Straße, STRASSE and café?", "naïve façade of the Straße")})
    operations.append({"op": "add", "record": fixture_record(
        46, 'Is "blocked" the right word for the release?', 'Say "blocked" only when it is.')})
    operations.append({"op": "add", "record": fixture_record(
        47, "Is 100% of a+b equal to x&y=z? #hash", "Yes; a+b, 100% and x&y=z are the same here.")})
    return operations


def build_fixture_store(directory, environment, stub):
    """Initialise a store, load the fixture, embed it through the stub, and return the database path and the
    provider config path. Everything goes through the real command line."""
    database = directory / "fixture.sqlite"
    batch = directory / "fixture.jsonl"
    batch.write_text("".join(json.dumps(operation, ensure_ascii=False) + "\n" for operation in fixture_operations()),
                     encoding="utf-8")
    config = directory / "provider.json"
    config.write_text(json.dumps({"provider": "voyage", "model": MODEL, "dimension": DIMENSION,
                                  "api_key_env": "TEST_EMBED_KEY", "endpoint": stub.endpoint}), encoding="utf-8")
    for arguments in (("init",), ("load", "--in", batch), ("embed", "--config", config)):
        result = subprocess.run(
            decisions_program() + [arguments[0], "--db", str(database)]
            + [str(item) for item in arguments[1:]],
            cwd=str(ROOT), env=environment, capture_output=True, text=True, encoding="utf-8", timeout=300)
        if result.returncode != 0:
            raise AssertionError("fixture {}: exit {}; stderr={!r}".format(arguments[0], result.returncode,
                                                                          result.stderr))
    return database


class Fixture:
    """The fixture store, its stub and its key, built once for the whole test module (a build takes seconds) and
    copied for every test."""

    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.key = "test-" + uuid.uuid4().hex
        self.stub = EmbeddingStub(self.key)
        environment = dict(os.environ)
        environment.update(PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1", TEST_EMBED_KEY=self.key)
        self.database = build_fixture_store(self.directory, environment, self.stub)

    def close(self):
        self.stub.close()
        self.temporary.cleanup()


_fixture = None


def fixture():
    global _fixture
    if _fixture is None:
        _fixture = Fixture()
    return _fixture


def release_fixture():
    global _fixture
    if _fixture is not None:
        _fixture.close()
        _fixture = None


class ServeCase(StoreCase):
    """A copy of the fixture store, the stub, the key, and a way to start servers on the copy."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        shared = fixture()
        cls.key = shared.key
        cls.stub = shared.stub
        cls.fixture_db = shared.database

    def setUp(self):
        super().setUp()
        # A second private directory, apart from the store's: the servers' sockets and their error output go
        # there, so that a test can make the store's own directory read-only.
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name)
        shutil.copy2(str(self.fixture_db), str(self.db))
        self.environment["TEST_EMBED_KEY"] = self.key
        self.environment["PYTHONUTF8"] = "1"
        self.stub.reset()
        self.provider_config = self.file("provider.json", {
            "provider": "voyage", "model": MODEL, "dimension": DIMENSION, "api_key_env": "TEST_EMBED_KEY",
            "endpoint": self.stub.endpoint})

    def file_state(self, path=None):
        """What a test can see of a file from outside: its bytes' digest, size and modification time, and the names
        in its directory (a rollback journal would show up there)."""
        path = Path(path or self.db)
        status = path.stat()
        return (hashlib.sha256(path.read_bytes()).hexdigest(), status.st_size, status.st_mtime_ns,
                sorted(os.listdir(str(path.parent))))

    def serve(self, config=True, idle_exit=None, db=None, socket_path=None, environment=None, umask=None,
              cwd=None, extra=(), name="server", wait=True, launcher=None):
        socket_path = socket_path or self.scratch / "run" / "search.sock"
        arguments = ["--db", db or self.db, "--socket", socket_path]
        if config:
            arguments += ["--config", self.provider_config]
        if idle_exit is not None:
            arguments += ["--idle-exit", idle_exit]
        arguments += list(extra)
        server = ServerProcess(self, arguments, environment or self.environment, name=name, cwd=cwd, umask=umask,
                               launcher=launcher)
        return server.wait_ready() if wait else server

    def run_serve(self, *arguments, timeout=30, environment=None, cwd=None):
        """`serve` that is expected to end by itself, with a message and an exit code, not to start."""
        try:
            return subprocess.run(
                decisions_program() + ["serve"] + [str(item) for item in arguments],
                cwd=str(cwd or ROOT), env=environment or self.environment, stdin=subprocess.DEVNULL,
                capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        except subprocess.TimeoutExpired:
            self.fail("serve did not end within {} seconds: it started a server that was meant to be refused".format(
                timeout))

    def run_command(self, command, *arguments, db=None, environment=None):
        """The command line as a process, with its output as bytes: the comparison is byte for byte."""
        return subprocess.run(self.command_line(command, arguments, db), cwd=str(ROOT),
                              env=environment or self.environment, capture_output=True, timeout=120)

    def search_command(self, query, mode, db=None, **options):
        words = search_words(query, mode, **options)
        if mode in ("vector", "hybrid"):
            words += ["--config", str(self.provider_config)]
        return self.run_command("search", *words, db=db)

    def both(self, server, query, mode, **options):
        """Search with the command and through the server, require the same bytes, and return the hits."""
        command = self.search_command(query, mode, **options)
        reply = server.search(query, mode, **options)
        description = "query {!r} mode {} options {}".format(query, mode, options)
        self.assertEqual(command.returncode, 0, "{}: the command failed: {!r}".format(description, command.stderr))
        self.assertEqual(reply.status, 200, "{}: the server answered {}: {!r}".format(description, reply.status,
                                                                                   reply.body))
        self.assertEqual(reply.body, command.stdout, description)
        return json.loads(command.stdout.decode("utf-8"))

    def egress_count(self, db=None):
        return len(self.json_cli("egress", "--list", db=db))

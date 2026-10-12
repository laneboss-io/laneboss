"""K. The example judge adapter for TypeSafe's Jev, examples/judges/typesafe_jev.py, answers the launcher's judge contract:
one request object on standard input, one answer object on standard output, and a non-zero exit with one line on standard
error when there is no answer.

The real service is a third party that a test machine has no key for, so every test talks to a stand-in HTTP server
that the test starts on 127.0.0.1 (a port picked free at run time) and stops by its own handle. The stand-in records
what it receives and answers as the provider's documentation says the service answers: https://docs.typesafe.ai/api.md
(request: POST /v1/systemone with a bearer key and the fields state, model and questions; answer: model, answers and
usage, with a noul answer as {"type": "noul", "noul": <0 to 1>}), https://docs.typesafe.ai/primitives/noul.md and
https://docs.typesafe.ai/sdk/python/api/exceptions.md (the provider's request identifier is the response header
x-typesafe-request-id), all read on 2026-10-09. The documentation says only "a JSON body describing what went wrong"
about an error answer, so the error bodies here are invented and the program must not depend on their fields. Keys are
made up at run time and look like a variable name, so that a key typed as an option value gets past that grammar. The
program is driven only as a command.

This module runs alone, with no import from another test module, and under Python 3.9 too:
`LANEBOSS_TEST_PYTHON39=<a python3.9> python3.9 -m unittest tests/e2e/test_judge_jev.py` is the documented second run
(the decision store's tests have one too). The variable is REQUIRED: the program is run under the suite's own Python
and under the one that the variable names, and a run without it fails `test_runs_under_3_9_and_own_python` with one
line that says how to provide a Python 3.9. Nothing is searched for on PATH and nothing is skipped.
"""

import ast
import collections
import decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
PROGRAM = ROOT / "examples" / "judges" / "typesafe_jev.py"
ENDPOINT = "/v1/systemone"
REQUEST_ID_HEADER = "x-typesafe-request-id"
MISSING = object()
ERROR_BODY = {"detail": "the-service-explains-what-went-wrong"}
HELD_LINE = "the answer held the key and was not printed"
# What test_runs_under_3_9_and_own_python says when LANEBOSS_TEST_PYTHON39 names no interpreter. That test must not
# pass with its Python 3.9 leg never run, so it fails instead, and this one line says how to provide a 3.9.
NO_PYTHON39 = ("no Python 3.9 interpreter: set LANEBOSS_TEST_PYTHON39 to one (for example `uv python install 3.9` "
               "and then LANEBOSS_TEST_PYTHON39=$(uv python find 3.9), or your package manager's python3.9); this "
               "test fails without it because its claim, that the program runs under Python 3.9, must really be run")
# What the program may import where the interpreter cannot list its standard library (Python 3.9 has no
# sys.stdlib_module_names); every name here is a standard library module.
KNOWN_STANDARD = frozenset({"argparse", "decimal", "http", "json", "math", "os", "re", "socket", "stat", "sys",
                            "threading", "urllib"})


def contract_request(**changes):
    """The contract's request, with the given fields replaced (MISSING removes a field)."""
    request = {"laneboss_judge": 1, "question": "refusal.is-refusal", "kind": "noul",
               "prompt": "Is this tool result a refusal by a guard, a hook or a permission layer?",
               "subject": {"result": "Blocked by the safety hook: this command is not allowed.",
                           "command": "rm -r build"}}
    for name, value in changes.items():
        if value is MISSING:
            request.pop(name, None)
        else:
            request[name] = value
    return request


Reply = collections.namedtuple("Reply", "status headers body")
Result = collections.namedtuple("Result", "code out err seconds")


class Received:
    def __init__(self, method, path, headers, body):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

    @property
    def json(self):
        return json.loads(self.body.decode("utf-8"))


def json_reply(status, value, request_id=None):
    headers = {"Content-Type": "application/json"}
    if request_id is not None:
        headers[REQUEST_ID_HEADER] = request_id
    return Reply(status, headers, json.dumps(value).encode("utf-8"))


def answering(probability, model="jev-1.13.0", request_id="req_01TESTID"):
    """What the documentation says the service sends: the model that answered, one answer per question under the
    question's own id, and the token usage; the provider's request identifier is a response header."""
    def respond(received, handler):
        body = {"answers": {name: {"type": "noul", "noul": probability} for name in received.json["questions"]},
                "usage": {"input_tokens": 296, "output_tokens": 20}}
        if model is not None:
            body["model"] = model
        return json_reply(200, body, request_id)
    return respond


def shaped(builder, status=200, request_id="req_01SHAPE"):
    """An answer built from the question ids of the request: builder(names) returns a value to send as JSON, or bytes."""
    def respond(received, handler):
        value = builder(list(received.json["questions"]))
        body = value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")
        return Reply(status, {"Content-Type": "application/json", REQUEST_ID_HEADER: request_id}, body)
    return respond


def literal(template):
    """An answer whose JSON bytes are written out by the test and sent as they are; QID stands for the question id."""
    return shaped(lambda names: template.replace("QID", names[0]).encode("utf-8"))


def fixed(status, body=b"", content_type="application/json", request_id=None):
    headers = {"Content-Type": content_type}
    if request_id is not None:
        headers[REQUEST_ID_HEADER] = request_id
    return lambda received, handler: Reply(status, headers, body)


def hang(received, handler):
    """Accepts the request and never answers, until the test stops the stand-in."""
    handler.stand_in.release.wait(60)


def drip(received, handler):
    """Answers the status line and the headers at once and then sends one byte every fifth of a second, so that no
    single read ever times out and only a total deadline can end the exchange."""
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", "100000")
    handler.end_headers()
    for _ in range(300):
        if handler.stand_in.release.wait(0.2):
            return
        handler.wfile.write(b" ")
        handler.wfile.flush()


class StandIn:
    """A stand-in for the service: records every request and answers with whatever `respond(received, handler)`
    returns (a Reply, or None when it wrote the answer itself)."""

    def __init__(self, respond):
        self.requests = []
        self.errors = []
        self.respond = respond
        self.release = threading.Event()
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format_string, *arguments):
                return

            def handle_any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                received = Received(self.command, self.path, {name.lower(): value for name, value in self.headers.items()},
                                    body)
                stand_in.requests.append(received)
                reply = stand_in.respond(received, self)
                if reply is None:
                    return
                self.send_response(reply.status)
                for name, value in reply.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(reply.body)))
                self.end_headers()
                self.wfile.write(reply.body)

            do_POST = do_GET = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_CONNECT = handle_any

        Handler.stand_in = stand_in

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                error = sys.exc_info()[1]
                if not isinstance(error, (BrokenPipeError, ConnectionResetError)):
                    stand_in.errors.append(repr(error))

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return "http://127.0.0.1:{}".format(self.server.server_port)

    @property
    def port(self):
        return self.server.server_port

    def stop(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def free_port():
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def listing(root):
    """Every path below root with its type, mode, size and modification time."""
    root = Path(root)
    return {str(path.relative_to(root)): (path.is_dir(), path.stat().st_mode, path.stat().st_size, path.stat().st_mtime_ns)
            for path in sorted(root.rglob("*"))}


class JudgeTest(unittest.TestCase):
    """Temporary directories, a fake key and helpers that run the program as a command."""

    def setUp(self):
        self.assertTrue(PROGRAM.is_file(), "examples/judges/typesafe_jev.py does not exist")
        temporary = tempfile.TemporaryDirectory(prefix="laneboss-e2e-judge-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.home = self.directory / "home"
        self.work = self.directory / "work"
        self.secrets = self.directory / "secrets"
        for path in (self.home, self.work, self.secrets):
            path.mkdir()
        # No hyphen: a key that passes the variable-name grammar and the identifier grammar, so that every route
        # by which the program could repeat it is open to the tests.
        self.key = "e2ekey" + uuid.uuid4().hex[:16]
        # No proxy variable and no loopback exclusion: the program must not need either.
        self.environment = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home), "PYTHONDONTWRITEBYTECODE": "1"}
        self.key_file = self.write_key_file()

    def write_key_file(self, text=None, mode=0o600, name="env"):
        path = self.secrets / name
        data = ("TYPESAFE_API_KEY={}\n".format(self.key) if text is None else text)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        path.chmod(mode)
        return path

    def stand_in(self, respond=None):
        service = StandIn(respond or answering(0.93))
        self.addCleanup(lambda: self.assertEqual(service.errors, [], "the stand-in itself failed"))
        self.addCleanup(service.stop)
        return service

    def run_program(self, arguments, stdin, python=None, program=None, environment=None):
        """Runs the program once. `stdin` is a request (a dict), text or bytes."""
        if isinstance(stdin, dict):
            stdin = json.dumps(stdin, ensure_ascii=False) + "\n"
        data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
        started = time.monotonic()
        done = subprocess.run([python or sys.executable, str(program or PROGRAM)] + [str(item) for item in arguments],
                              input=data, capture_output=True, cwd=str(self.work),
                              env=self.environment if environment is None else environment, timeout=90)
        result = Result(done.returncode, done.stdout.decode("utf-8"), done.stderr.decode("utf-8"),
                        time.monotonic() - started)
        self.assertNotIn(self.key, result.out + result.err, "the key appears in the program's output")
        return result

    def judge(self, request, service=None, options=(), key_file=None, **keywords):
        """The usual command line: the key file, the stand-in as the base URL, and the options."""
        arguments = ["--env-file", key_file or self.key_file]
        if service is not None:
            arguments += ["--base-url", service.url]
        return self.run_program(arguments + list(options), request, **keywords)

    def assert_no_answer(self, result, code, label=""):
        """No answer: the given exit status, nothing on standard output, one short line on standard error."""
        note = "{}: exit {}, stdout={!r}, stderr={!r}".format(label, result.code, result.out, result.err)
        self.assertEqual((result.code, result.out), (code, ""), note)
        lines = result.err.splitlines()
        self.assertEqual(len(lines), 1, note)
        self.assertTrue(result.err.endswith("\n") and lines[0].strip(), note)
        self.assertLessEqual(len(lines[0]), 300, note)


class ContractTest(JudgeTest):
    """A. A valid request gives the contract's answer, asked of the service the way the documentation says."""

    def test_valid_request_one_answer(self):
        service = self.stand_in(answering(0.93, model="jev-1.13.0", request_id="req_01TESTID"))
        result = self.judge(contract_request(), service)
        self.assertEqual((result.code, result.err), (0, ""), result.err)
        self.assertTrue(result.out.endswith("\n") and result.out.count("\n") == 1, repr(result.out))
        self.assertEqual(json.loads(result.out), {"probability": 0.93, "model": "jev-1.13.0", "request": "req_01TESTID"})

    def test_documented_request_is_sent(self):
        service = self.stand_in()
        request = contract_request()
        self.assertEqual(self.judge(request, service).code, 0)
        self.assertEqual(len(service.requests), 1)
        received = service.requests[0]
        self.assertEqual((received.method, received.path), ("POST", ENDPOINT))
        self.assertEqual(received.headers["authorization"], "Bearer " + self.key)
        self.assertTrue(received.headers["content-type"].startswith("application/json"), received.headers)
        self.assertIn("laneboss", received.headers["user-agent"], "the User-Agent names the launcher")
        body = received.json
        self.assertEqual(sorted(body), ["model", "questions", "state"])
        self.assertEqual(body["model"], "jev-latest")
        self.assertEqual(body["state"], request["subject"])
        self.assertEqual(len(body["questions"]), 1)
        question = list(body["questions"].values())[0]
        self.assertEqual(question, {"type": "noul", "instructions": request["prompt"]})
        text = received.body.decode("utf-8")
        self.assertNotIn(self.key, text)
        self.assertNotIn(request["question"], text, "the launcher's question identifier is not sent")

    def test_the_model_option_names_the_model(self):
        service = self.stand_in(answering(0.5, model="jev-1.13.0"))
        result = self.judge(contract_request(), service, options=["--model", "jev-1.13.0"])
        self.assertEqual(result.code, 0, result.err)
        self.assertEqual(service.requests[0].json["model"], "jev-1.13.0")

    def test_subject_texts_are_carried_whole(self):
        subject = {"result": "拒絕：此指令被安全掛鉤擋下。\n\tquote \" backslash \\ and an emoji \U0001F6AB",
                   "command": "x" * 4000}
        subject.update({"text{}".format(number): "text number {} ".format(number) * 20 for number in range(6)})
        self.assertEqual(len(subject), 8)
        service = self.stand_in()
        result = self.judge(contract_request(subject=subject), service)
        self.assertEqual(result.code, 0, result.err)
        self.assertEqual(service.requests[0].json["state"], subject)

    def test_base_url_forms(self):
        service = self.stand_in()
        port = service.server.server_port
        for base, path in (("http://127.0.0.1:{}".format(port), ENDPOINT),
                           ("http://127.0.0.1:{}/".format(port), ENDPOINT),
                           ("http://127.0.0.1:{}/gateway/".format(port), "/gateway" + ENDPOINT)):
            with self.subTest(base):
                before = len(service.requests)
                result = self.run_program(["--env-file", self.key_file, "--base-url", base], contract_request())
                self.assertEqual(result.code, 0, result.err)
                self.assertEqual(service.requests[before].path, path)

    def test_missing_id_and_model_are_null(self):
        service = self.stand_in(answering(0.4, model=None, request_id=None))
        result = self.judge(contract_request(), service)
        self.assertEqual(result.code, 0, result.err)
        self.assertEqual(json.loads(result.out), {"probability": 0.4, "model": None, "request": None})

    def test_probability_passes_through(self):
        for probability in (0, 0.0, 0.5, 1, 1.0, 0.0000123):
            with self.subTest(probability):
                service = self.stand_in(answering(probability))
                result = self.judge(contract_request(), service)
                self.assertEqual(result.code, 0, result.err)
                self.assertEqual(json.loads(result.out)["probability"], probability)

    def test_the_contract_limits_are_accepted(self):
        subject = {"text{}".format(number): "y" * 4000 for number in range(8)}
        service = self.stand_in()
        result = self.judge(contract_request(subject=subject, extra_field="ignored"), service)
        self.assertEqual(result.code, 0, result.err)
        self.assertEqual(service.requests[0].json["state"], subject)

    def test_it_writes_no_file(self):
        failing = self.stand_in(fixed(500, b'{"detail": "no"}'))
        working = self.stand_in()
        before = listing(self.directory)
        self.assertEqual(self.judge(contract_request(), working).code, 0)
        self.assertEqual(self.judge(contract_request(), failing).code, 4)
        self.assertEqual(self.judge(contract_request(kind="score"), working).code, 2)
        self.assertEqual(listing(self.directory), before)
        self.assertEqual(list(self.work.iterdir()), [])
        self.assertEqual(list(self.home.iterdir()), [])


class KeyFileTest(JudgeTest):
    """B. The key comes from the file, under the documented name or the one given, and only from a private file."""

    def sent_key(self, service):
        self.assertEqual(len(service.requests), 1)
        return service.requests[0].headers["authorization"]

    def test_default_key_name(self):
        self.write_key_file("OTHER_NAME=decoy-{}\nTYPESAFE_API_KEY={}\nTYPESAFE_API_KEY_OLD=old-{}\n".format(
            uuid.uuid4().hex[:8], self.key, uuid.uuid4().hex[:8]))
        service = self.stand_in()
        self.assertEqual(self.judge(contract_request(), service).code, 0)
        self.assertEqual(self.sent_key(service), "Bearer " + self.key)

    def test_key_name_picks_another_line(self):
        self.write_key_file("TYPESAFE_API_KEY=decoy-{}\nJUDGE_KEY={}\n".format(uuid.uuid4().hex[:8], self.key))
        service = self.stand_in()
        result = self.judge(contract_request(), service, options=["--key-name", "JUDGE_KEY"])
        self.assertEqual(result.code, 0, result.err)
        self.assertEqual(self.sent_key(service), "Bearer " + self.key)

    def test_key_line_shapes_are_read(self):
        shapes = (("plain", "TYPESAFE_API_KEY={key}\n"),
                  ("export", "export TYPESAFE_API_KEY={key}\n"),
                  ("double quotes", 'TYPESAFE_API_KEY="{key}"\n'),
                  ("single quotes", "TYPESAFE_API_KEY='{key}'\n"),
                  ("export and quotes", 'export TYPESAFE_API_KEY="{key}"\n'),
                  ("spaces around", "   TYPESAFE_API_KEY={key}   \n"),
                  ("comments and blanks", "# the key\n\nOTHER=1\n   # another\nTYPESAFE_API_KEY={key}\n\n"),
                  ("windows line ends", "OTHER=1\r\nTYPESAFE_API_KEY={key}\r\n"),
                  ("no final newline", "TYPESAFE_API_KEY={key}"),
                  ("the last line wins", "TYPESAFE_API_KEY=decoy-1\nTYPESAFE_API_KEY={key}\n"))
        for label, template in shapes:
            with self.subTest(label):
                self.write_key_file(template.format(key=self.key))
                service = self.stand_in()
                result = self.judge(contract_request(), service)
                self.assertEqual(result.code, 0, result.err)
                self.assertEqual(self.sent_key(service), "Bearer " + self.key)

    def test_readable_key_file_is_refused(self):
        service = self.stand_in()
        for mode in (0o644, 0o640, 0o604, 0o664, 0o666, 0o660, 0o744):
            with self.subTest(oct(mode)):
                self.write_key_file(mode=mode)
                result = self.judge(contract_request(), service)
                self.assert_no_answer(result, 3, oct(mode))
                self.assertIn(format(mode, "o"), result.err, "the line names the mode")
        self.assertEqual(service.requests, [])

    def test_writable_key_file_is_refused(self):
        service = self.stand_in()
        for mode in (0o620, 0o602, 0o622):
            with self.subTest(oct(mode)):
                self.write_key_file(mode=mode)
                self.assert_no_answer(self.judge(contract_request(), service), 3, oct(mode))
        self.assertEqual(service.requests, [])

    def test_a_private_key_file_is_read(self):
        for mode in (0o600, 0o400):
            with self.subTest(oct(mode)):
                self.write_key_file(mode=mode)
                service = self.stand_in()
                self.assertEqual(self.judge(contract_request(), service).code, 0)
                self.assertEqual(self.sent_key(service), "Bearer " + self.key)

    def test_missing_name_is_refused(self):
        service = self.stand_in()
        cases = (("another name only", "OTHER_NAME={}\n".format(self.key), []),
                 ("only in a comment", "# TYPESAFE_API_KEY={}\n".format(self.key), []),
                 ("only a longer name", "TYPESAFE_API_KEY_OLD={}\n".format(self.key), []),
                 ("the given name is absent", "TYPESAFE_API_KEY={}\n".format(self.key), ["--key-name", "NO_SUCH_NAME"]),
                 ("an empty file", "", []))
        for label, text, options in cases:
            with self.subTest(label):
                self.write_key_file(text)
                self.assert_no_answer(self.judge(contract_request(), service, options=options), 3, label)
        self.assertEqual(service.requests, [])

    def test_unusable_key_files_are_refused(self):
        service = self.stand_in()
        self.write_key_file(name="empty-value", text="TYPESAFE_API_KEY=\n")
        self.write_key_file(name="two-words", text="TYPESAFE_API_KEY=two words\n")
        self.write_key_file(name="control", text="TYPESAFE_API_KEY=ab\x01cd\n")
        self.write_key_file(name="not-text", text=b"TYPESAFE_API_KEY=\xff\xfe\n")
        self.write_key_file(name="huge", text="TYPESAFE_API_KEY=" + "k" * 200000 + "\n")
        (self.secrets / "a-directory").mkdir(mode=0o700)
        cases = (("missing file", self.secrets / "absent"), ("a directory", self.secrets / "a-directory"),
                 ("an empty value", self.secrets / "empty-value"), ("a value with a space", self.secrets / "two-words"),
                 ("a control character", self.secrets / "control"), ("not UTF-8", self.secrets / "not-text"),
                 ("a huge file", self.secrets / "huge"))
        for label, path in cases:
            with self.subTest(label):
                self.assert_no_answer(self.judge(contract_request(), service, key_file=path), 3, label)
        self.assertEqual(service.requests, [])

    def test_echoed_key_is_not_repeated(self):
        service = self.stand_in(lambda received, handler: Reply(401, {"Content-Type": "text/plain"},
                                                                 received.headers["authorization"].encode("utf-8")))
        result = self.judge(contract_request(), service)
        self.assert_no_answer(result, 4)
        self.assertNotIn(self.key, result.err)

    def test_a_short_key_is_refused(self):
        """Fix round 2, decision 2: a key of fewer than 16 characters is refused when it is read, with a fixed line and
        never the value. The keys are digits, which no fixed line of the program holds."""
        service = self.stand_in()
        for length in (1, 8, 15):
            with self.subTest(length):
                self.key = str(int(uuid.uuid4().hex, 16)).replace("0", "7")[:length]
                self.write_key_file()
                result = self.judge(contract_request(), service)
                self.assert_no_answer(result, 3, str(length))
                self.assertIn("the key's value is too short to be a key", result.err)
        self.assertEqual(service.requests, [], "a request went out with a key that is too short")

    def test_sixteen_characters_is_a_key(self):
        self.key = "k" + uuid.uuid4().hex[:15]
        self.write_key_file()
        service = self.stand_in()
        result = self.judge(contract_request(), service)
        self.assertEqual((result.code, result.err), (0, ""), result.err)
        self.assertEqual(self.sent_key(service), "Bearer " + self.key)

    def test_a_linked_key_file_is_checked(self):
        private = self.write_key_file(name="target-private")
        permissive = self.write_key_file(name="target-permissive", mode=0o644)
        (self.secrets / "link-private").symlink_to(private)
        (self.secrets / "link-permissive").symlink_to(permissive)
        service = self.stand_in()
        followed = self.judge(contract_request(), service, key_file=self.secrets / "link-private")
        self.assertEqual(followed.code, 0, followed.err)
        self.assertEqual(self.sent_key(service), "Bearer " + self.key)
        refused = self.judge(contract_request(), service, key_file=self.secrets / "link-permissive")
        self.assert_no_answer(refused, 3, "a link to a readable file")
        self.assertEqual(len(service.requests), 1)


class DisclosureTest(JudgeTest):
    """Fix round 1, decisions 1 and 2: nothing that holds the key is ever printed, whatever the service or the command
    line says, and a usage error repeats nothing that was typed."""

    def assert_held(self, result, label=""):
        self.assert_no_answer(result, 4, label)
        self.assertIn(HELD_LINE, result.err, label)

    def holding(self):
        return (("the key itself", self.key), ("the key after a prefix", "req_" + self.key),
                ("the key before a suffix", self.key + ".1"))

    def test_key_in_identifier_on_401(self):
        for label, value in self.holding():
            with self.subTest(label):
                service = self.stand_in(lambda received, handler, value=value: Reply(
                    401, {"Content-Type": "application/json", REQUEST_ID_HEADER: value}, b'{"detail": "no"}'))
                self.assert_held(self.judge(contract_request(), service), label)

    def test_key_in_identifier_on_200(self):
        for label, value in self.holding():
            with self.subTest(label):
                service = self.stand_in(answering(0.9, request_id=value))
                self.assert_held(self.judge(contract_request(), service), label)

    def test_key_in_model_on_200(self):
        for label, value in (("the key itself", self.key), ("a prefix", "jev-" + self.key),
                             ("a suffix", self.key + "-1")):
            with self.subTest(label):
                service = self.stand_in(answering(0.9, model=value))
                self.assert_held(self.judge(contract_request(), service), label)

    def test_16_char_key_in_model_is_held(self):
        """The shortest key that is accepted still cannot be printed: in the model or in the identifier it is withheld."""
        self.key = "k" + uuid.uuid4().hex[:15]
        self.write_key_file()
        self.assert_held(self.judge(contract_request(), self.stand_in(answering(0.9, model=self.key))), "in the model")
        self.assert_held(self.judge(contract_request(), self.stand_in(answering(0.9, request_id=self.key))), "in the id")

    def test_key_outside_the_grammar(self):
        self.key = self.key + "+plus"
        self.key_file = self.write_key_file()
        in_identifier = self.stand_in(answering(0.4, model="jev-1.13.0", request_id=self.key))
        result = self.judge(contract_request(), in_identifier)
        self.assertEqual((result.code, result.err), (0, ""), result.err)
        self.assertEqual(json.loads(result.out), {"probability": 0.4, "model": "jev-1.13.0", "request": None})
        in_model = self.stand_in(answering(0.4, model=self.key, request_id="req_1"))
        self.assert_no_answer(self.judge(contract_request(), in_model), 4)
        on_error = self.stand_in(lambda received, handler: Reply(
            401, {"Content-Type": "application/json", REQUEST_ID_HEADER: self.key}, b"{}"))
        result = self.judge(contract_request(), on_error)
        self.assert_no_answer(result, 4)
        self.assertIn("401", result.err)
        self.assertNotIn("(request", result.err, "an identifier that is not one is left out of the line")

    def test_identifier_grammar(self):
        cases = (("a plain identifier", "req_01ARZ3NDEKTSV4RRFFQ69G5FAV", True), ("128 characters", "a" * 128, True),
                 ("with the allowed marks", "a.b_c:d-e", True), ("129 characters", "a" * 129, False),
                 ("a space inside", "req 01", False), ("a leading hyphen", "-req_01", False),
                 ("a leading dot", ".req_01", False), ("a slash", "req/01", False), ("empty", "", False))
        for label, value, usable in cases:
            with self.subTest(label):
                answered = self.judge(contract_request(), self.stand_in(answering(0.6, request_id=value)))
                self.assertEqual((answered.code, answered.err), (0, ""), answered.err)
                self.assertEqual(json.loads(answered.out)["request"], value if usable else None)
                failed = self.judge(contract_request(), self.stand_in(lambda received, handler, value=value: Reply(
                    500, {"Content-Type": "application/json", REQUEST_ID_HEADER: value}, b"{}")))
                self.assert_no_answer(failed, 4, label)
                self.assertEqual("(request {})".format(value) in failed.err, usable, failed.err)

    def test_model_grammar(self):
        for label, value in (("empty", ""), ("a space", "jev 1.13"), ("129 characters", "a" * 129),
                             ("a leading dot", ".jev"), ("a slash", "jev/1"), ("a trailing newline", "jev-1.13.0\n")):
            with self.subTest(label):
                self.assert_no_answer(self.judge(contract_request(), self.stand_in(answering(0.6, model=value))), 4, label)
        for label, value in (("a version", "jev-1.13.0"), ("128 characters", "a" * 128), ("the other marks", "x:y_z.1-2")):
            with self.subTest(label):
                answered = self.judge(contract_request(), self.stand_in(answering(0.6, model=value)))
                self.assertEqual((answered.code, answered.err), (0, ""), answered.err)
                self.assertEqual(json.loads(answered.out)["model"], value)

    def test_help_goes_to_standard_output(self):
        for flag in ("--help", "-h"):
            with self.subTest(flag):
                result = self.run_program([flag], b"")
                self.assertEqual((result.code, result.err), (0, ""))
                self.assertIn("usage:", result.out)
                self.assertIn("--env-file", result.out)

    def test_usage_errors_repeat_nothing(self):
        key = self.key
        cases = (("--help with a value", ["--help=" + key]), ("-h with a value", ["-h=" + key]),
                 ("an unknown option with a value", ["--frobnicate=" + key]),
                 ("an unknown option and its value", ["--frobnicate", key]), ("a stray argument", [key]),
                 ("a bad --timeout", ["--timeout", key]), ("a bad --base-url", ["--base-url", key]),
                 ("a bad --model", ["--model", key + " x"]), ("a bad --key-name", ["--key-name", key + "-x"]),
                 ("--timeout without a value", ["--timeout"]), ("an abbreviation", ["--env", key]))
        for label, arguments in cases:
            with self.subTest(label):
                result = self.run_program(["--env-file", self.key_file] + arguments, contract_request())
                self.assert_no_answer(result, 2, label)
        with self.subTest("a bad --env-file"):
            self.assert_no_answer(self.run_program(["--env-file", key], contract_request()), 3)
        with self.subTest("no --env-file"):
            self.assert_no_answer(self.run_program([], contract_request()), 2)

    def test_missing_name_line_is_fixed(self):
        service = self.stand_in()
        self.write_key_file("OTHER=1\n")
        result = self.judge(contract_request(), service, options=["--key-name", self.key])
        self.assert_no_answer(result, 3)
        self.assertIn("the key file has no line for the name given with --key-name", result.err)
        self.write_key_file("{}=\n".format(self.key))
        result = self.judge(contract_request(), service, options=["--key-name", self.key])
        self.assert_no_answer(result, 3)
        self.assertEqual(service.requests, [])


class ProxyTest(JudgeTest):
    """Fix round 1, decision 3: a loopback address is never reached through a proxy."""

    def proxied(self, proxy):
        environment = dict(self.environment)
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
            environment[name] = proxy.url
        for name in ("no_proxy", "NO_PROXY"):
            environment.pop(name, None)
        return environment

    def test_loopback_is_never_proxied(self):
        endpoint = self.stand_in(answering(0.77))
        proxy = self.stand_in(fixed(502, b"bad gateway", "text/plain"))
        environment = self.proxied(proxy)
        for base in (endpoint.url, endpoint.url + "/gateway/"):
            with self.subTest(base):
                result = self.run_program(["--env-file", self.key_file, "--base-url", base], contract_request(),
                                          environment=environment)
                self.assertEqual((result.code, result.err), (0, ""), result.err)
                self.assertEqual(json.loads(result.out)["probability"], 0.77)
        self.assertEqual(proxy.requests, [], "the request went to the proxy")
        self.assertEqual(len(endpoint.requests), 2)

    def test_other_https_keeps_the_proxy(self):
        proxy = self.stand_in(fixed(502, b"bad gateway", "text/plain"))
        result = self.run_program(["--env-file", self.key_file, "--base-url", "https://api.example.invalid",
                                   "--timeout", "5"], contract_request(), environment=self.proxied(proxy))
        self.assert_no_answer(result, 4)
        self.assertEqual([(item.method, item.path) for item in proxy.requests], [("CONNECT", "api.example.invalid:443")])
        self.assertNotIn("authorization", proxy.requests[0].headers, "the key stays inside the tunnel")


class ServiceFailureTest(JudgeTest):
    """C. A service that fails, answers wrongly or does not answer gives no answer and never an invented one."""

    def test_http_errors_give_exit_4(self):
        for status in (401, 422, 429, 500, 529):
            with self.subTest(status):
                service = self.stand_in(lambda received, handler, status=status: json_reply(status, ERROR_BODY, "req_01ERROR"))
                result = self.judge(contract_request(), service)
                self.assert_no_answer(result, 4, str(status))
                self.assertIn(str(status), result.err)
                self.assertIn("req_01ERROR", result.err)
                self.assertNotIn("the-service-explains", result.err, "the response body is not repeated")
                self.assertEqual(len(service.requests), 1, "the program retried")

    def test_errors_without_json_give_exit_4(self):
        bodies = (("plain text", fixed(500, b"Internal Server Error", "text/plain")),
                  ("an empty body", fixed(500)), ("an empty 401", fixed(401)),
                  ("html", fixed(429, b"<html><body>slow down</body></html>", "text/html")),
                  ("a status the documentation does not list", fixed(503, b"{}")),
                  ("a bad request", fixed(400, b'{"detail": "no"}')))
        for label, respond in bodies:
            with self.subTest(label):
                service = self.stand_in(respond)
                self.assert_no_answer(self.judge(contract_request(), service), 4, label)
                self.assertEqual(len(service.requests), 1)

    def test_undocumented_shapes_give_exit_4(self):
        def one(**answer):
            return lambda names: {"model": "jev-1.13.0", "answers": {names[0]: answer},
                                  "usage": {"input_tokens": 1, "output_tokens": 1}}
        shapes = (
            ("an empty body", lambda names: b""),
            ("not JSON", lambda names: b"not json at all"),
            ("an HTML page", lambda names: b"<html><body>ok</body></html>"),
            ("truncated JSON", lambda names: b'{"model": "jev-1.13.0", "answers": {'),
            ("a list", lambda names: []),
            ("null", lambda names: None),
            ("an empty object", lambda names: {}),
            ("no answers", lambda names: {"model": "jev-1.13.0"}),
            ("answers is a list", lambda names: {"model": "jev-1.13.0", "answers": [{"type": "noul", "noul": 0.9}]}),
            ("answers is empty", lambda names: {"model": "jev-1.13.0", "answers": {}}),
            ("an answer under another id", lambda names: {"model": "jev-1.13.0", "answers": {
                "other-" + names[0]: {"type": "noul", "noul": 0.9}}}),
            ("the answer is a number", lambda names: {"model": "jev-1.13.0", "answers": {names[0]: 0.9}}),
            ("a choice answer", one(type="choice", choice="yes", probabilities={"yes": 0.9, "no": 0.1}, confidence=0.8)),
            ("a score answer", one(type="score", score=0.9, legend={"0": "a"}, probabilities={"0": 1.0}, confidence=1.0)),
            ("no type", one(noul=0.9)),
            ("no value", one(type="noul")),
            ("the value is text", one(type="noul", noul="0.9")),
            ("the value is null", one(type="noul", noul=None)),
            ("the value is true", one(type="noul", noul=True)),
            ("the value is a list", one(type="noul", noul=[0.9])),
            ("the value is above 1", one(type="noul", noul=1.5)),
            ("the value is below 0", one(type="noul", noul=-0.01)),
            ("the value is NaN", one(type="noul", noul=float("nan"))),
            ("the value is infinite", one(type="noul", noul=float("inf"))),
            ("the model is a number", lambda names: {"model": 5, "answers": {names[0]: {"type": "noul", "noul": 0.9}}}),
        )
        for label, builder in shapes:
            with self.subTest(label):
                service = self.stand_in(shaped(builder))
                self.assert_no_answer(self.judge(contract_request(), service), 4, label)
                self.assertEqual(len(service.requests), 1)

    def test_no_answer_is_a_timeout(self):
        service = self.stand_in(hang)
        result = self.judge(contract_request(), service, options=["--timeout", "2"])
        self.assert_no_answer(result, 5)
        self.assertEqual(len(service.requests), 1, "the program never reached the service")
        self.assertGreaterEqual(result.seconds, 1.5, "the program gave up before its time-out")
        self.assertLessEqual(result.seconds, 4.0, "the program waited longer than --timeout plus 2 seconds")

    def test_default_timeout_is_eight_seconds(self):
        service = self.stand_in(hang)
        result = self.judge(contract_request(), service)
        self.assert_no_answer(result, 5)
        self.assertGreaterEqual(result.seconds, 7.0)
        self.assertLessEqual(result.seconds, 10.0)

    def test_timeout_is_total_not_per_read(self):
        service = self.stand_in(drip)
        result = self.judge(contract_request(), service, options=["--timeout", "1"])
        self.assert_no_answer(result, 5)
        self.assertGreaterEqual(result.seconds, 0.8)
        self.assertLessEqual(result.seconds, 3.0, "a service that sends a byte at a time held the program")

    def test_refused_connection_is_exit_4(self):
        result = self.run_program(["--env-file", self.key_file, "--base-url", "http://127.0.0.1:{}".format(free_port())],
                                  contract_request())
        self.assert_no_answer(result, 4)
        self.assertLess(result.seconds, 5.0)

    def test_redirects_are_not_followed(self):
        elsewhere = self.stand_in()
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status):
                service = self.stand_in(lambda received, handler, status=status: Reply(
                    status, {"Location": elsewhere.url + ENDPOINT}, b""))
                result = self.judge(contract_request(), service)
                self.assert_no_answer(result, 4, str(status))
                self.assertIn(str(status), result.err)
                self.assertEqual(len(service.requests), 1)
        self.assertEqual(elsewhere.requests, [], "the program followed a redirect")

    def test_remote_https_is_accepted(self):
        result = self.run_program(["--env-file", self.key_file, "--base-url", "https://api.example.invalid",
                                   "--timeout", "2"], contract_request())
        self.assertIn(result.code, (4, 5), result.err)
        self.assertEqual(result.out, "")


class ExactAnswerTest(JudgeTest):
    """Fix round 1, decision 4: the provider's number is checked as written and its answer is strict. The bodies are
    literal JSON bytes: building them from Python floats would round the fixtures before the program saw them."""

    HEAD = '{"model": "jev-1.13.0", '
    ANSWER = '{"type": "noul", "noul": 0.5}'
    USAGE = '{"input_tokens": 1, "output_tokens": 1}'
    BODY = HEAD + '"answers": {"QID": {"type": "noul", "noul": NUMBER}}, "usage": ' + USAGE + '}'

    def test_exact_numbers(self):
        outside = ("1.0000000000000001", "1.00000000000000000000000000000001", "-1e-999", "-0.000000000000000000000000001",
                   "1e1", "10", "2", "-1", "1.5e0", "1E+1000000", "-1E-1000000")
        for text in outside:
            with self.subTest("outside: " + text):
                service = self.stand_in(literal(self.BODY.replace("NUMBER", text)))
                self.assert_no_answer(self.judge(contract_request(), service), 4, text)
        inside = ("0", "1", "0.0", "1.0", "1e0", "0.5", "0.93", "9.3E-1", "0e-999", "-0", "-0.0", "0.9999999999999999",
                  "1.000000000000000000000", "0.99999999999999999999")
        for text in inside:
            with self.subTest("inside: " + text):
                service = self.stand_in(literal(self.BODY.replace("NUMBER", text)))
                result = self.judge(contract_request(), service)
                self.assertEqual((result.code, result.err), (0, ""), result.err)
                self.assertEqual(json.loads(result.out)["probability"], float(decimal.Decimal(text)) + 0.0)
                self.assertNotIn("-0", result.out, "zero is printed without a sign")

    def test_repeated_fields(self):
        answer, usage, head = self.ANSWER, self.USAGE, self.HEAD
        bodies = (
            ("model twice", head + '"model": "jev-1.13.0", "answers": {"QID": ' + answer + '}, "usage": ' + usage + '}'),
            ("answers twice", head + '"answers": {"QID": ' + answer + '}, "answers": {"QID": ' + answer + '}, "usage": '
                              + usage + '}'),
            ("the answer's id twice", head + '"answers": {"QID": ' + answer + ', "QID": ' + answer + '}, "usage": '
                                      + usage + '}'),
            ("type twice", head + '"answers": {"QID": {"type": "noul", "type": "noul", "noul": 0.5}}, "usage": '
                           + usage + '}'),
            ("noul twice with one value", head + '"answers": {"QID": {"type": "noul", "noul": 0.5, "noul": 0.5}}, '
                                          '"usage": ' + usage + '}'),
            ("noul twice with two values", head + '"answers": {"QID": {"type": "noul", "noul": 0.5, "noul": 0.6}}, '
                                           '"usage": ' + usage + '}'),
            ("usage twice", head + '"answers": {"QID": ' + answer + '}, "usage": ' + usage + ', "usage": ' + usage + '}'),
            ("a member of usage twice", head + '"answers": {"QID": ' + answer + '}, '
                                        '"usage": {"input_tokens": 1, "input_tokens": 2}}'),
            ("an unknown object with a repeat", head + '"answers": {"QID": ' + answer + '}, "usage": ' + usage
                                                + ', "extra": {"a": 1, "a": 2}}'),
            ("a repeat inside a list", head + '"answers": {"QID": ' + answer + '}, "usage": ' + usage
                                       + ', "extra": [{"a": 1, "a": 2}]}'),
        )
        for label, text in bodies:
            with self.subTest(label):
                service = self.stand_in(literal(text))
                self.assert_no_answer(self.judge(contract_request(), service), 4, label)
        with self.subTest("the same body without a repeat is an answer"):
            service = self.stand_in(literal(head + '"answers": {"QID": ' + answer + '}, "usage": ' + usage + '}'))
            self.assertEqual(self.judge(contract_request(), service).code, 0)


class BadInputTest(JudgeTest):
    """D. A request that breaks the contract and options that cannot be used give exit 2 and send nothing."""

    def test_contract_breaking_requests(self):
        lone_surrogate = json.dumps(contract_request(subject={"result": "a\ud800b"})).encode("ascii")
        requests = (
            ("kind is choice", contract_request(kind="choice")),
            ("kind is score", contract_request(kind="score")),
            ("kind is in capitals", contract_request(kind="NOUL")),
            ("kind is missing", contract_request(kind=MISSING)),
            ("kind is a list", contract_request(kind=["noul"])),
            ("version 2", contract_request(laneboss_judge=2)),
            ("version as text", contract_request(laneboss_judge="1")),
            ("version true", contract_request(laneboss_judge=True)),
            ("version missing", contract_request(laneboss_judge=MISSING)),
            ("question missing", contract_request(question=MISSING)),
            ("question empty", contract_request(question="")),
            ("question a number", contract_request(question=7)),
            ("prompt missing", contract_request(prompt=MISSING)),
            ("prompt empty", contract_request(prompt="")),
            ("prompt a number", contract_request(prompt=7)),
            ("no subject", contract_request(subject=MISSING)),
            ("an empty subject", contract_request(subject={})),
            ("subject is a list", contract_request(subject=["text"])),
            ("subject is text", contract_request(subject="text")),
            ("nine texts", contract_request(subject={"text{}".format(number): "x" for number in range(9)})),
            ("a text is a number", contract_request(subject={"result": 5})),
            ("a text is null", contract_request(subject={"result": None})),
            ("a text is a list", contract_request(subject={"result": ["x"]})),
            ("a text of 4001 characters", contract_request(subject={"result": "x" * 4001})),
            ("a name that is empty", contract_request(subject={"": "text"})),
            ("empty input", b""),
            ("only a newline", b"\n"),
            ("not JSON", b"this is not json\n"),
            ("truncated JSON", b'{"laneboss_judge": 1,'),
            ("a list", b"[]\n"),
            ("a string", b'"noul"\n'),
            ("null", b"null\n"),
            ("two objects", (json.dumps(contract_request()) + "\n" + json.dumps(contract_request()) + "\n").encode("utf-8")),
            ("not UTF-8", b"\xff\xfe\x00"),
            ("a lone surrogate", lone_surrogate),
        )
        service = self.stand_in()
        for label, request in requests:
            with self.subTest(label):
                self.assert_no_answer(self.judge(request, service), 2, label)
        self.assertEqual(service.requests, [], "a request went out for input that breaks the contract")

    def test_unusable_options_are_refused(self):
        """Every case that can, names the stand-in as the address, so that an empty record means the program stopped."""
        service = self.stand_in()
        key = str(self.key_file)
        address = ["--base-url", service.url]
        credentials = "http://" + "user" + ":" + "secret" + "@" + "127.0.0.1:{}".format(service.port)
        cases = (
            ("no --env-file", address),
            ("an unknown option", ["--env-file", key, "--frobnicate"] + address),
            ("a stray argument that is not echoed", ["--env-file", key, self.key] + address),
            ("a key given as the name", ["--env-file", key, "--key-name", self.key + "-x"] + address),
            ("--timeout 0", ["--env-file", key, "--timeout", "0"] + address),
            ("--timeout negative", ["--env-file", key, "--timeout", "-1"] + address),
            ("--timeout text", ["--env-file", key, "--timeout", "soon"] + address),
            ("--timeout NaN", ["--env-file", key, "--timeout", "nan"] + address),
            ("--timeout infinite", ["--env-file", key, "--timeout", "inf"] + address),
            ("--timeout too long", ["--env-file", key, "--timeout", "3601"] + address),
            ("--model not a name", ["--env-file", key, "--model", "jev latest"] + address),
            ("--base-url not https and not local", ["--env-file", key, "--base-url", "http://example.invalid"]),
            ("--base-url ftp at the stand-in", ["--env-file", key, "--base-url", "ftp://127.0.0.1:{}".format(service.port)]),
            ("--base-url a file", ["--env-file", key, "--base-url", "file:///etc/passwd"]),
            ("--base-url a local look-alike", ["--env-file", key, "--base-url",
                                               "http://127.0.0.1.example.invalid:{}".format(service.port)]),
            ("--base-url a localhost look-alike", ["--env-file", key, "--base-url",
                                                   "http://localhost.example.invalid:{}".format(service.port)]),
            ("--base-url with credentials at the stand-in", ["--env-file", key, "--base-url", credentials]),
            ("--base-url with a query at the stand-in", ["--env-file", key, "--base-url", service.url + "/?x=1"]),
            ("--base-url with a fragment at the stand-in", ["--env-file", key, "--base-url", service.url + "/#x"]),
            ("--base-url without a scheme", ["--env-file", key, "--base-url", "127.0.0.1:{}".format(service.port)]),
            ("--base-url empty", ["--env-file", key, "--base-url", ""]),
            ("--base-url without a host", ["--env-file", key, "--base-url", "https://"]),
            ("--base-url an IPv6 address", ["--env-file", key, "--base-url", "http://[::1]:{}".format(service.port)]),
            ("--base-url port 0", ["--env-file", key, "--base-url", "http://127.0.0.1:0"]),
        )
        for label, arguments in cases:
            with self.subTest(label):
                self.assert_no_answer(self.run_program(arguments, contract_request()), 2, label)
        self.assertEqual(service.requests, [], "a request reached the stand-in that the cases name as the address")

    def test_plain_http_only_to_loopback_ip(self):
        """Fix round 2, decision 1: plain HTTP goes only to the literal address 127.0.0.1. A NAME, localhost included,
        could be made to resolve to another machine, so it is refused before anything is resolved or sent. The
        stand-in listens at the very port that each of these names would reach."""
        service = self.stand_in()
        names = ("localhost", "LOCALHOST", "localhost.", "127.1", "2130706433", "[::1]", "127.0.0." + "01",
                 ".".join(["0"] * 4))
        for name in names:
            with self.subTest(name):
                result = self.run_program(["--env-file", self.key_file, "--base-url",
                                           "http://{}:{}".format(name, service.port)], contract_request())
                self.assert_no_answer(result, 2, name)
                self.assertTrue(result.err.endswith("must be https:// unless the host is 127.0.0.1\n"), result.err)
        self.assertEqual(service.requests, [], "a request was sent to a name over plain HTTP")

    def test_https_localhost_is_accepted(self):
        """https stays allowed for any host, localhost included: here the refused connection (exit 4) shows that the
        address was accepted and tried, and that it was not a usage error."""
        result = self.run_program(["--env-file", self.key_file, "--base-url", "https://localhost:{}".format(free_port())],
                                  contract_request())
        self.assert_no_answer(result, 4)


class ProgramTest(JudgeTest):
    """E. One stand-alone file that needs nothing but the standard library of Python 3.9 or newer."""

    def test_imports_only_the_standard_library(self):
        tree = ast.parse(PROGRAM.read_text(encoding="utf-8"))
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "a relative import")
                modules.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Name):
                self.assertNotEqual(node.id, "__import__")
            elif isinstance(node, ast.Attribute):
                self.assertNotEqual(node.attr, "import_module")
        standard = getattr(sys, "stdlib_module_names", None) or KNOWN_STANDARD
        self.assertNotIn("laneboss", modules)
        self.assertEqual(sorted(modules - set(standard)), [])
        self.assertEqual(sorted(modules - KNOWN_STANDARD), [], "a new import: add it to KNOWN_STANDARD on purpose")
        self.assertIn("urllib", modules)

    def test_one_writer_per_stream(self):
        """Decision 1: ONE place writes to standard output and ONE to standard error, and it is the same os.write,
        so that the check for the key stands in front of every byte; nothing else prints, not even argparse."""
        tree = ast.parse(PROGRAM.read_text(encoding="utf-8"))
        writes = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr == "write" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"]
        self.assertEqual(len(writes), 1, "exactly one call of os.write writes to standard output and standard error")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotEqual(node.func.id, "print")
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("stdout", "stderr", "print_help", "print_usage", "_print_message"))
        switches = [keyword for node in ast.walk(tree) if isinstance(node, ast.Call) for keyword in node.keywords
                    if keyword.arg == "add_help"]
        self.assertTrue(switches and all(isinstance(keyword.value, ast.Constant) and keyword.value.value is False
                                         for keyword in switches), "argparse's own help would print by itself")

    def test_runs_under_3_9_and_own_python(self):
        """The suite's own Python, and the Python 3.9 that LANEBOSS_TEST_PYTHON39 names, which must really be a 3.9.
        The variable is required: with no Python 3.9 named this test FAILS, it does not pass and it does not skip,
        because a title claiming a 3.9 run that never happens would otherwise prove nothing. Nothing is searched for
        on PATH."""
        named = os.environ.get("LANEBOSS_TEST_PYTHON39")
        if not named:
            self.fail(NO_PYTHON39)
        interpreters = [("the suite's own Python", sys.executable, "{}.{}".format(*sys.version_info[:2])),
                        ("the Python 3.9 that LANEBOSS_TEST_PYTHON39 names", named, "3.9")]
        copy = self.directory / "copy" / "typesafe_jev.py"
        copy.parent.mkdir()
        shutil.copy2(str(PROGRAM), str(copy))
        for label, python, version in interpreters:
            with self.subTest(label):
                found = subprocess.run([python, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                                       capture_output=True, text=True, timeout=30).stdout.strip()
                self.assertEqual(found, version, "{} reports {!r}, not {}".format(label, found, version))
                service = self.stand_in(answering(0.25, request_id="req_01PYTHON"))
                result = self.judge(contract_request(), service, python=python, program=copy)
                self.assertEqual((result.code, result.err), (0, ""), result.err)
                self.assertEqual(json.loads(result.out), {"probability": 0.25, "model": "jev-1.13.0",
                                                          "request": "req_01PYTHON"})
                self.assert_no_answer(self.judge(contract_request(kind="choice"), service, python=python, program=copy), 2)
                failing = self.stand_in(fixed(500, b'{"detail": "no"}'))
                self.assert_no_answer(self.judge(contract_request(), failing, python=python, program=copy), 4)
                silent = self.stand_in(hang)
                self.assert_no_answer(self.judge(contract_request(), silent, options=["--timeout", "1"], python=python,
                                                 program=copy), 5)
                self.write_key_file(mode=0o644)
                self.assert_no_answer(self.judge(contract_request(), service, python=python, program=copy), 3)
                self.write_key_file(mode=0o600)

    def nested(self, variable):
        """That test alone, in a process of its own, with LANEBOSS_TEST_PYTHON39 set to `variable` or not set."""
        environment = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home), "PYTHONDONTWRITEBYTECODE": "1"}
        if variable is not None:
            environment["LANEBOSS_TEST_PYTHON39"] = str(variable)
        return subprocess.run([sys.executable, "-m", "unittest", "tests.e2e.test_judge_jev.ProgramTest."
                               "test_runs_under_3_9_and_own_python"], cwd=str(ROOT), env=environment,
                              capture_output=True, text=True, timeout=300)

    def test_wrong_python39_fails(self):
        liar = self.directory / "python39"
        liar.write_text("#!/bin/sh\necho 3.8\n", encoding="utf-8")
        liar.chmod(0o755)
        for label, variable in (("an interpreter that reports 3.8", liar), ("a path that is not there", self.directory / "none")):
            with self.subTest(label):
                done = self.nested(variable)
                self.assertNotEqual(done.returncode, 0, "a wrong interpreter did not fail the test:\n" + done.stderr)
                self.assertIn("FAILED", done.stderr)

    def test_missing_interpreter_fails(self):
        """No LANEBOSS_TEST_PYTHON39 at all: the test is red, not green and not skipped, and the one line it fails
        with names the variable and says how to provide a Python 3.9."""
        done = self.nested(None)
        self.assertNotEqual(done.returncode, 0,
                            "the test passed with no Python 3.9 named:\n" + done.stdout + done.stderr)
        self.assertIn("FAILED", done.stderr)
        self.assertIn(NO_PYTHON39, done.stderr)
        self.assertNotIn("skipped", done.stderr)


if __name__ == "__main__":
    unittest.main()

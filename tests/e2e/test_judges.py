"""Judges: a configuration names judges, and the launcher asks one a question, bounded, logged and without a secret.

A judge is an external command: the launcher writes one JSON object to its standard input and reads one JSON object
from its standard output (docs/judges.md). A real judge and its provider cannot reach a test machine, so every test
names the stand-in program below (written by the tests into their temporary directory) as the judge's command. The
stand-in records the request it received and the state of its process; nothing else is replaced. Every outcome is
observed through the installed command, the stand-in's records and the state directory's files. One test imports the
installed package in a separate process, to call the public function with objects that do not belong together.
"""

import fcntl
import hashlib
import json
import os
import random
import re
import shutil
import signal
import string
import subprocess
import sys
import time

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


PROMPT = "Is this tool result a refusal by a guard, a hook or a permission layer?"
RESULT = "SUBJECT-RESULT-7731: the sandbox blocked a write to the build directory."
COMMAND = "SUBJECT-COMMAND-4408: make build"
SENT_KEYS = {"at", "ask", "event", "judge", "question", "lane", "request_sha256", "request_bytes", "withheld", "cut"}
OUTCOME_KEYS = {"at", "ask", "event", "outcome", "probability", "model", "request", "duration_ms"}
PRINTED_KEYS = {"judge", "question", "outcome", "probability", "model", "request", "withheld", "cut", "duration_ms"}
ASK = re.compile(r"[0-9a-f]{32}")
RESERVE = 1024  # docs/judges.md: bytes the log keeps free for the outcome line of every unfinished ask
READER_LIMIT = 64 * 1024 * 1024
ALNUM = string.ascii_letters + string.digits
LOWER = string.ascii_lowercase + string.digits
UPPER = string.ascii_uppercase + string.digits

# The stand-in judge. The first argument picks a behaviour, the second is the directory that gets one record per run:
# run-PID.request (the bytes it was given) and run-PID.json (its process ids, session, arguments, environment names).
# The record is written after the request was read, so a record means that the judge has its request.
STANDIN = r"""
import json
import os
import signal
import subprocess
import sys
import time

mode, directory = sys.argv[1], sys.argv[2]
raw = b"" if mode == "deaf" else sys.stdin.buffer.read()
ANSWER = {"probability": 0.83, "model": "stand-in-1", "request": "req_e2e_001"}
SLEEPER = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(600)\n"
stem = os.path.join(directory, "run-%d" % os.getpid())
record = {"pid": os.getpid(), "pgid": os.getpgrp(), "sid": os.getsid(0), "argv": sys.argv[1:], "cwd": os.getcwd(),
          "environment": sorted(os.environ), "marker": os.environ.get("E2E_JUDGE_MARKER"), "child": None,
          "children": []}


def save():
    with open(stem + ".tmp", "w") as handle:
        json.dump(record, handle)
    os.replace(stem + ".tmp", stem + ".json")


def emit(data):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def answer():
    emit((json.dumps(ANSWER) + "\n").encode())


with open(stem + ".request.tmp", "wb") as handle:
    handle.write(raw)
os.replace(stem + ".request.tmp", stem + ".request")
if mode in ("sleep", "leave"):
    record["child"] = subprocess.Popen([sys.executable, "-I", "-c", SLEEPER]).pid
elif mode in ("flood-group", "flood-session"):
    # yes writes faster than a reader of the pipe reads, and a large pipe keeps it from being empty between two reads;
    # yes ends by SIGPIPE when the reader closes the pipe. Its output is the judge's standard error.
    import fcntl
    try:
        fcntl.fcntl(2, getattr(fcntl, "F_SETPIPE_SZ", 1031), 1 << 20)
    except OSError:
        pass
    flood = subprocess.Popen(["yes", "x"], stdout=sys.stderr, start_new_session=(mode == "flood-session"))
    record["children"] = [flood.pid]
    record["child"] = flood.pid
    time.sleep(0.3)
save()
if mode in ("answer", "deaf", "flood-group", "flood-session"):
    answer()
elif mode == "lock":
    os.chmod(sys.argv[3], 0o500)
    answer()
elif mode == "exit3":
    sys.stderr.write("stand-in: not answering\n")
    answer()
    sys.exit(3)
elif mode == "text":
    emit(b"this is not json\n")
elif mode == "high":
    emit(b'{"probability": 1.7, "model": null, "request": null}\n')
elif mode == "raw":
    with open(os.path.join(directory, "stdout.txt"), "rb") as handle:
        emit(handle.read())
elif mode == "explain":
    with open(os.path.join(directory, "explain.txt"), "rb") as handle:
        sys.stderr.write(handle.read().decode())
    sys.exit(3)
elif mode == "noisy":
    for index in range(64):
        emit(b"x" * 65536)
    answer()
elif mode == "sleep":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(600)
elif mode == "leave":
    answer()
elif mode == "wait":
    while not os.path.exists(os.path.join(directory, "go")):
        time.sleep(0.05)
    answer()
"""


# The installed command with the reader's size limit lowered, so its actual writer and reader face the same bound.
# The Python implementation uses its module constant; the Go implementation uses its operator-configurable lower cap.
# A Python monkeypatch alone cannot cross the launcher's forwarding boundary into the Go process.
LIMITED = r"""
import os
import sys
sys.path.insert(0, sys.argv[1])
from laneboss import cli, judges
judges.MAX_EGRESS_BYTES = int(sys.argv[2])
os.environ["LANEBOSS_JUDGE_MAX_EGRESS_BYTES"] = sys.argv[2]
sys.exit(cli.main(sys.argv[3:]))
"""

# Runs one ask of the judge "guard" through the public function while it records, in order, every fsync (with what the
# descriptor is: the state directory, the judges directory or a file, and what existed at that moment) and the start of
# the judge. In mode "kill" the launcher kills itself at the moment it would start the judge.
PROBE = r"""
import json
import os
import signal
import stat
import subprocess
import sys

sys.path.insert(0, sys.argv[1])
from laneboss import config, judges
from laneboss.statedir import StateDir

mode, name, record = sys.argv[2], sys.argv[3], sys.argv[4]
configuration = config.load(name)
zones = config.Zones(configuration)
state_dir = os.path.realpath(str(configuration.state_dir))
log_path = os.path.join(state_dir, "judges", "egress.jsonl")
events = []


def snapshot():
    return {"marker": os.path.exists(os.path.join(state_dir, ".laneboss-state")),
            "judges": os.path.isdir(os.path.join(state_dir, "judges")), "log": os.path.exists(log_path),
            "log_lines": len(open(log_path).read().splitlines()) if os.path.exists(log_path) else 0}


def target(descriptor):
    info = os.fstat(descriptor)
    for label, path in (("state", state_dir), ("judges", os.path.join(state_dir, "judges"))):
        try:
            other = os.stat(path)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == (other.st_dev, other.st_ino):
            return label
    return "file" if stat.S_ISREG(info.st_mode) else "other"


def save():
    with open(record, "w") as handle:
        json.dump(events, handle)


real_fsync, real_popen = os.fsync, subprocess.Popen


def fsync(descriptor):
    events.append(dict(snapshot(), event="fsync", target=target(descriptor)))
    return real_fsync(descriptor)


class Popen(real_popen):
    def __init__(self, *arguments, **options):
        events.append(dict(snapshot(), event="start"))
        save()
        if mode == "kill":
            os.kill(os.getpid(), signal.SIGKILL)
        super().__init__(*arguments, **options)


os.fsync = fsync
subprocess.Popen = Popen
state = StateDir.open(configuration, zones, create=True)
try:
    judges.ask(configuration, state, "guard", "test.probe", "A question?", {"result": "text"})
finally:
    state.close()
save()
"""


def toml(value):
    return json.dumps(value)


def judge_table(name, command, timeout=None, description=None, extra=""):
    lines = ["", "[judges.{}]".format(name)]
    if description is not None:
        lines.append("description = " + toml(description))
    lines.append("command = " + toml(command))
    if timeout is not None:
        lines.append("timeout_seconds = {}".format(timeout))
    return "\n".join(lines) + "\n" + extra


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def pick(alphabet, count):
    return "".join(random.choice(alphabet) for _ in range(count))


# Credential-shaped values, built at run time and different on every call, so that no file of the repository holds
# one and no assertion can be met by remembering one. Each function is one rule of the credential detector.
def code_host_token():
    return "gh" + "p_" + pick(ALNUM, 36)


def cloud_key_id():
    return "AK" + "IA" + pick(UPPER, 16)


def payment_key():
    return "sk" + "_live_" + pick(ALNUM, 24)


def model_hub_token():
    return "hf" + "_" + pick(ALNUM, 34)


def glpat_token():
    return "glpat" + "-" + pick(LOWER, 20)


def prefixed_key():
    return "sk" + "-" + pick(LOWER, 19) + random.choice(string.digits)


def assignment():
    return "api_key = " + pick(ALNUM, 10) + "7" + pick(ALNUM, 5)


SHAPES = (code_host_token, cloud_key_id, payment_key, model_hub_token, glpat_token, prefixed_key)
LOWERCASE_SHAPES = (glpat_token, prefixed_key)


def credential_token():
    """A different credential-shaped value on every call, drawn from several rules of the detector."""
    return random.choice(SHAPES)()


def secret_of(text):
    """The part of a generated credential whose appearance anywhere is a leak."""
    return text.split(" = ")[-1]


class JudgeTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.records = self.directory / "records"
        self.texts = self.directory / "texts"
        for path in (self.records, self.texts):
            path.mkdir()
        self.standin = self.directory / "judge_standin.py"
        self.standin.write_text(STANDIN, encoding="utf-8")
        self.state = self.state_home / "alpha"
        self.counter = 0

    def installed_library(self):
        found = sorted((support._installation.prefix / "share" / support.PROGRAM / "versions").glob("*/lib"))
        self.assertEqual(len(found), 1)
        return found[0]

    def limited(self, limit, *arguments, code=0):
        """The installed command line with the reader's size limit set to `limit` bytes (see LIMITED)."""
        script = self.directory / "limited.py"
        script.write_text(LIMITED, encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", str(script), str(self.installed_library()), str(limit),
                                 *map(str, arguments)], cwd=str(self.directory), env=self.environment,
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        if code is not None:
            self.assertEqual(result.returncode, code, "limit {}: {}: exit {}; stdout={!r}; stderr={!r}".format(
                limit, " ".join(map(str, arguments[:2])), result.returncode, result.stdout, result.stderr))
        return result

    def probe(self, mode, code=0):
        """Run PROBE; the list of events it recorded, in order."""
        script = self.directory / "probe.py"
        script.write_text(PROBE, encoding="utf-8")
        record = self.directory / "probe-events.json"
        result = subprocess.run([sys.executable, "-I", "-B", str(script), str(self.installed_library()), mode, "alpha",
                                 str(record)], cwd=str(self.directory), env=self.environment, capture_output=True,
                                text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, code, "probe {}: exit {}; stderr={!r}".format(
            mode, result.returncode, result.stderr))
        return json.loads(record.read_text(encoding="utf-8")) if record.exists() else []

    def read_back(self, state=None):
        """`judge egress` through the strict reader: exit 0 and the log's lines printed as they are."""
        result = self.run_laneboss("judge", "egress", "--config", "alpha")
        self.assertEqual(result.stdout, self.log_text(state), "judge egress printed something else than the log")
        return [json.loads(line) for line in result.stdout.splitlines()]

    def program(self, mode, *extra):
        return [sys.executable, "-I", str(self.standin), mode, str(self.records), *extra]

    def configure(self, *tables, name="alpha"):
        return self.write_config(name, tail="".join(tables))

    def one(self, mode="answer", name="guard", config="alpha", timeout=None):
        return self.configure(judge_table(name, self.program(mode), timeout), name=config)

    def text_file(self, label, text):
        self.counter += 1
        path = self.texts / "{}-{}.txt".format(label, self.counter)
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        return path

    def ask_arguments(self, judge="guard", question="refusal.is-refusal", prompt=PROMPT, subject=None, lane=None,
                      config="alpha"):
        subject = {"result": RESULT, "command": COMMAND} if subject is None else subject
        arguments = ["judge", "ask"] + (["--config", config] if config else [])
        arguments += ["--judge", judge, "--question", question, "--prompt-file", self.text_file("prompt", prompt)]
        for name, text in subject.items():
            arguments += ["--subject", "{}={}".format(name, self.text_file("subject-" + name, text))]
        if lane:
            arguments += ["--lane", lane]
        return arguments

    def ask(self, code=0, environment=None, **options):
        return self.run_laneboss(*self.ask_arguments(**options), code=code, environment=environment)

    def printed(self, result):
        value = json.loads(result.stdout)
        self.assertEqual(set(value), PRINTED_KEYS)
        return value

    def start_ask(self, **options):
        return subprocess.Popen([str(self.command), *map(str, self.ask_arguments(**options))], cwd=str(self.directory),
                                env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def runs(self):
        found = sorted(self.records.glob("run-*.json"), key=lambda path: path.stat().st_mtime_ns)
        return [json.loads(path.read_text(encoding="utf-8")) for path in found]

    def request_bytes(self, record):
        return (self.records / "run-{}.request".format(record["pid"])).read_bytes()

    def request(self, record):
        return json.loads(self.request_bytes(record).decode("utf-8"))

    def egress_path(self, state=None):
        return (state or self.state) / "judges" / "egress.jsonl"

    def log_text(self, state=None):
        path = self.egress_path(state)
        self.assertTrue(path.is_file(), "the egress log does not exist")
        text = path.read_text(encoding="utf-8")
        self.assertTrue(text == "" or text.endswith("\n"), "the egress log does not end with a whole line")
        return text

    def log_lines(self, state=None):
        return [json.loads(line) for line in self.log_text(state).splitlines()]

    def egress(self, state=None):
        """One dict per ask: its sent line joined with its outcome line, when there is one (`outcome_at` is the
        outcome line's time)."""
        lines = self.log_lines(state)
        outcomes = {line["ask"]: line for line in lines if line["event"] == "outcome"}
        asks = []
        for line in lines:
            if line["event"] != "sent":
                continue
            merged = {key: value for key, value in line.items() if key != "event"}
            outcome = outcomes.get(line["ask"])
            if outcome is not None:
                merged.update({key: value for key, value in outcome.items() if key not in ("at", "ask", "event")})
                merged["outcome_at"] = outcome["at"]
            asks.append(merged)
        return asks

    def alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
        return status.returncode == 0 and not status.stdout.strip().startswith("Z")

    def assert_gone(self, pids, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            living = [pid for pid in pids if self.alive(pid)]
            if not living:
                return
            if time.monotonic() > deadline:
                self.fail("processes of the judge are still alive: {}".format(living))
            time.sleep(0.1)

    def wait_for_record(self, count=1, timeout=30):
        deadline = time.monotonic() + timeout
        while len(self.runs()) < count:
            if time.monotonic() > deadline:
                self.fail("the stand-in judge left no record")
            time.sleep(0.05)
        return self.runs()

    def everywhere(self, result, state=None):
        """Everything a leak could be found in: both output streams and the egress log, if there is one."""
        path = self.egress_path(state)
        return result.stdout + result.stderr + (path.read_text(encoding="utf-8") if path.is_file() else "")


class AnswerTest(JudgeTest):
    def test_answer_and_exact_request(self):
        """A. The stand-in answers 0.83; the command exits 0; the stand-in received exactly the documented request."""
        marker = self.directory / "shell-marker"
        self.configure(judge_table("guard", self.program("answer", "x; touch " + str(marker))))
        result = self.ask()
        value = self.printed(result)
        self.assertEqual({key: value[key] for key in ("judge", "question", "outcome", "probability", "model", "request",
                                                      "withheld", "cut")},
                         {"judge": "guard", "question": "refusal.is-refusal", "outcome": "answered",
                          "probability": 0.83, "model": "stand-in-1", "request": "req_e2e_001", "withheld": [],
                          "cut": []})
        self.assertIsInstance(value["duration_ms"], int)
        self.assertGreaterEqual(value["duration_ms"], 0)
        (record,) = self.runs()
        raw = self.request_bytes(record)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1, "one object on one line, with a final newline")
        self.assertEqual(json.loads(raw.decode("utf-8")),
                         {"laneboss_judge": 1, "question": "refusal.is-refusal", "kind": "noul", "prompt": PROMPT,
                          "subject": {"result": RESULT, "command": COMMAND}})
        self.assertEqual(list(json.loads(raw.decode("utf-8"))["subject"]), ["result", "command"])
        self.assertEqual(record["argv"][-1], "x; touch " + str(marker))
        self.assertFalse(marker.exists(), "the command was run through a shell")
        self.assertEqual((record["pgid"], record["sid"]), (record["pid"], record["pid"]), "its own session")

    def test_boundary_probabilities(self):
        self.one("raw")
        for text, probability, model in ((b'{"probability": 0, "model": null, "request": null}\n', 0.0, None),
                                         (b'{"probability": 1}\n', 1.0, None),
                                         (b' \n{"probability": 0.25, "model": "m-2", "request": null}\n\n', 0.25,
                                          "m-2")):
            with self.subTest(text=text):
                (self.records / "stdout.txt").write_bytes(text)
                value = self.printed(self.ask())
                self.assertEqual((value["outcome"], value["probability"], value["model"], value["request"]),
                                 ("answered", probability, model, None))

    def test_judge_ignoring_input_answers(self):
        self.one("deaf")
        wide_text = "中" * 4000
        subject = {"s{}".format(index): wide_text for index in range(8)}
        value = self.printed(self.ask(subject=subject))
        self.assertEqual((value["outcome"], value["probability"]), ("answered", 0.83))

    def test_leftover_children_ended(self):
        self.one("leave", timeout=20)
        started = time.monotonic()
        value = self.printed(self.ask())
        self.assertLess(time.monotonic() - started, 10, "the answer waited for a child that holds the pipe")
        self.assertEqual((value["outcome"], value["probability"]), ("answered", 0.83))
        (record,) = self.runs()
        self.assert_gone([record["child"]], timeout=5)

    def test_environment_has_no_launcher_vars(self):
        """G. The judge gets the launcher's environment minus every LANEBOSS_ variable."""
        self.one()
        environment = dict(self.environment, LANEBOSS_CONFIG="alpha", LANEBOSS_LANE="some-lane", LANEBOSS_RUN="3",
                           LANEBOSS_SOMETHING="else", E2E_JUDGE_MARKER="kept")
        self.assertTrue(any(name.startswith(support.ENV_PREFIX) for name in environment))
        self.ask(environment=environment)
        (record,) = self.runs()
        self.assertEqual([name for name in record["environment"] if name.startswith(support.ENV_PREFIX)], [])
        self.assertEqual(record["marker"], "kept")
        self.assertIn("PATH", record["environment"])


class UnavailableTest(JudgeTest):
    def unavailable(self, reason, **options):
        result = self.ask(code=1, **options)
        value = self.printed(result)
        self.assertEqual(value["outcome"], reason)
        self.assertIsNone(value["probability"])
        self.assertIsNone(value["model"])
        self.assertIsNone(value["request"])
        return value

    def test_each_reason_exit_1_no_value(self):
        """B. A non-zero exit, text that is not JSON, a probability of 1.7, a time-out and a missing program."""
        missing = self.directory / "no-such-directory" / "judge"
        plain = self.directory / "not-executable"
        plain.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        plain.chmod(0o644)
        self.configure(judge_table("exits", self.program("exit3")), judge_table("text", self.program("text")),
                       judge_table("high", self.program("high")), judge_table("slow", self.program("sleep"), 1),
                       judge_table("missing", ["laneboss-e2e-absent-judge", "x"]),
                       judge_table("absolute", [str(missing)]), judge_table("plain", [str(plain)]))
        self.unavailable("exit", judge="exits")
        self.unavailable("output", judge="text")
        self.unavailable("output", judge="high")
        self.unavailable("not-found", judge="missing")
        self.unavailable("not-found", judge="absolute")
        self.unavailable("not-found", judge="plain")
        records = self.runs()
        self.assertEqual(len(records), 3, "only the three stand-ins ran")
        started = time.monotonic()
        self.unavailable("timeout", judge="slow")
        self.assertLess(time.monotonic() - started, 4, "the time-out and the end of the process group take under 4 s")
        slow = self.runs()[-1]
        self.assertEqual(slow["argv"][0], "sleep")
        self.assertIsInstance(slow["child"], int)
        self.assert_gone([slow["pid"], slow["child"]], timeout=5)
        log = self.egress()
        self.assertEqual([line["outcome"] for line in log],
                         ["exit", "output", "output", "not-found", "not-found", "not-found", "timeout"])
        self.assertEqual([line["probability"] for line in log], [None] * 7)

    def test_what_counts_as_one_such_object(self):
        """Decisions 3 and 4: identifiers, and numbers read as they were written. The cases are literal bytes."""
        cases = [
            (b'{"probability": 0.5, "model": "m", "request": "r"}', 0.5),
            (b'{"probability": 0.5}\n', 0.5),
            (b'{"probability": 1e-3}\n', 0.001),
            (b'{"probability": 5e-1}\n', 0.5),
            (b'{"probability": 1.0000000000000000}\n', 1.0),
            (b'{"probability": 0.1234567890123456789}\n', 0.1234567890123456789),
            (b'{"probability": 0.99999999999999999999999}\n', 1.0),
            (b'{"probability": -0.0}\n', 0.0), (b'{"probability": -0}\n', 0.0),
            (b'{"probability": 0.5, "model": "a:b.c-d_e", "request": "req_01.x:9"}\n', 0.5),
            (b'{"probability": 0.5, "model": "' + b"m" * 128 + b'"}\n', 0.5),
            (b'{"probability": 0.5, "request": "' + b"r" * 128 + b'"}\n', 0.5),
            (b"", None), (b"\n", None), (b"0.9\n", None), (b"[0.9]\n", None), (b'"0.9"\n', None), (b"null\n", None),
            (b'{"model": "m"}\n', None),
            (b'{"probability": -0.1}\n', None), (b'{"probability": 1.0000001}\n', None),
            (b'{"probability": 1.0000000000000001}\n', None), (b'{"probability": 1.00000000000000000001}\n', None),
            (b'{"probability": -1e-999}\n', None), (b'{"probability": -0.0000000000000000000001}\n', None),
            (b'{"probability": 1e400}\n', None), (b'{"probability": 10e-1000}\n', 0.0),
            (b'{"probability": "0.9"}\n', None), (b'{"probability": true}\n', None),
            (b'{"probability": null}\n', None), (b'{"probability": NaN}\n', None),
            (b'{"probability": Infinity}\n', None), (b'{"probability": 1e999}\n', None),
            (b'{"probability": 1e99999999999999999999999}\n', None),
            (b'{"probability": 0.5, "model": 5}\n', None), (b'{"probability": 0.5, "request": ["r"]}\n', None),
            (b'{"probability": 0.5, "model": "' + b"m" * 129 + b'"}\n', None),
            (b'{"probability": 0.5, "request": "' + b"r" * 129 + b'"}\n', None),
            (b'{"probability": 0.5, "model": "two words"}\n', None), (b'{"probability": 0.5, "model": ""}\n', None),
            (b'{"probability": 0.5, "request": "a/b"}\n', None), (b'{"probability": 0.5, "model": "_x"}\n', None),
            (b'{"probability": 0.5, "model": "x=y"}\n', None),
            (b'{"probability": 0.5, "why": "because"}\n', None),
            (b'{"probability": 0.2, "probability": 0.9}\n', None),
            (b'{"probability": 0.5}\n{"probability": 0.5}\n', None),
            (b'Judge v1\n{"probability": 0.5}\n', None),
            (b'{"probability": 0.5} trailing\n', None),
            (b'{"probability": 0.5}\xff\n', None),
            (b'\xef\xbb\xbf{"probability": 0.5}\n', None),
        ]
        self.one("raw")
        for text, probability in cases:
            with self.subTest(text=text[:70]):
                (self.records / "stdout.txt").write_bytes(text)
                if probability is None:
                    self.unavailable("output")
                else:
                    value = self.printed(self.ask())
                    self.assertEqual((value["outcome"], value["probability"]), ("answered", probability))

    def test_metadata_credential_no_answer(self):
        """Decision 3: a credential-shaped model or request makes the whole answer no answer; nothing of it is shown."""
        self.one("raw")
        for field in ("model", "request"):
            for make in (cloud_key_id, glpat_token, prefixed_key, code_host_token, payment_key):
                secret = make()
                other = "model" if field == "request" else "request"
                answer = {"probability": 0.5, field: secret, other: "stand-in-1"}
                with self.subTest(field=field, rule=make.__name__):
                    (self.records / "stdout.txt").write_bytes((json.dumps(answer) + "\n").encode("utf-8"))
                    result = self.ask(code=1)
                    value = self.printed(result)
                    self.assertEqual((value["outcome"], value["probability"], value["model"], value["request"]),
                                     ("output", None, None, None))
                    self.assertNotIn(secret, self.everywhere(result))

    def test_a_flood_of_output_is_not_an_answer(self):
        self.one("noisy", timeout=30)
        started = time.monotonic()
        self.unavailable("output")
        self.assertLess(time.monotonic() - started, 10)
        (record,) = self.runs()
        self.assert_gone([record["pid"]], timeout=5)

    def test_flood_after_exit_is_bounded(self):
        """A child that writes to standard error without end after the judge exited, in its group and in a session of
        its own: the command returns within the documented bound, and nothing of the child is left running. The bound
        is the time-out (3 s here) plus the two seconds the launcher takes to end the process group, plus a margin of 2 s
        for the launcher's own start and exit on a 2-vCPU machine: 7 s. (The drain does not hang on this machine at the
        head of the previous round either; this pins the bound, it does not reproduce a hang.)"""
        timeout, ending, margin = 3, 2, 2
        for mode in ("flood-group", "flood-session"):
            with self.subTest(mode):
                self.one(mode, timeout=timeout)
                before = len(self.runs())
                process = self.start_ask()
                try:
                    started = time.monotonic()
                    stdout, stderr = process.communicate(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    self.fail("the command did not return: the drain after the judge ended has no bound")
                self.assertLess(time.monotonic() - started, timeout + ending + margin)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(json.loads(stdout)["outcome"], "answered")
                record = self.runs()[before]
                self.assertEqual(len(record["children"]), 1)
                self.assert_gone([record["pid"]] + record["children"], timeout=15)

    def test_explanation_cut_never_secret(self):
        """One line of explanation on standard error is never shown beyond its first 300 characters."""
        self.one("explain")
        line = "EXPLAIN-START" + "y" * 287 + "BEYOND-THE-LIMIT"
        (self.records / "explain.txt").write_text(line + "\nSECOND-LINE-MARKER\n", encoding="utf-8")
        result = self.ask(code=1)
        self.assertIn("EXPLAIN-START", result.stderr)
        self.assertNotIn("BEYOND-THE-LIMIT", result.stderr)
        self.assertNotIn("SECOND-LINE-MARKER", result.stderr)
        self.assertNotIn("EXPLAIN-START", result.stdout)
        for make in SHAPES:
            token = make()
            (self.records / "explain.txt").write_text("401 for the key " + token + "\n", encoding="utf-8")
            result = self.ask(code=1)
            with self.subTest(rule=make.__name__):
                self.assertNotIn(token, self.everywhere(result))
        self.assertNotIn("EXPLAIN-START", self.egress_path().read_text(encoding="utf-8"))

    def test_explanation_secret_after_cut(self):
        """Decision 2: the first 300 characters are screened again; a secret that is a secret only after the cut is not
        shown."""
        self.one("explain")
        key = cloud_key_id()
        line = "note " * 56 + key + random.choice(string.ascii_uppercase)
        self.assertEqual(line[:300].count(key), 1)
        self.assertIsNone(re.search(r"AKIA[A-Z0-9]{16}(?![A-Z0-9])", line), "the whole line must pass the detector")
        (self.records / "explain.txt").write_text(line + "\n", encoding="utf-8")
        result = self.ask(code=1)
        self.assertNotIn(key, self.everywhere(result))
        self.assertIn("[withheld]", result.stderr)

    def test_interrupt_ends_judge_and_logs(self):
        self.one("wait", timeout=30)
        process = self.start_ask()
        (record,) = self.wait_for_record()
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=30)
        self.assertNotEqual(process.returncode, 0)
        self.assert_gone([record["pid"]], timeout=10)
        lines = self.log_lines()
        self.assertEqual([line["event"] for line in lines], ["sent", "outcome"])
        self.assertEqual(lines[0]["ask"], lines[1]["ask"])
        self.assertNotEqual(lines[1]["outcome"], "answered")
        self.assertIsNone(lines[1]["probability"])
        # Decision 4: the strict reader accepts what the interruption wrote, and prints both lines.
        self.assertEqual(self.read_back(), lines)


class WithholdingTest(JudgeTest):
    def test_subject_credential_withheld(self):
        """C. The stand-in's request holds [withheld], the name is in withheld, the string is nowhere else."""
        self.one()
        for make in SHAPES:
            token = make()
            with self.subTest(rule=make.__name__):
                before = len(self.runs())
                result = self.ask(subject={"result": "the deploy said: " + token + " is rejected", "command": COMMAND})
                value = self.printed(result)
                self.assertEqual((value["outcome"], value["withheld"], value["cut"]), ("answered", ["result"], []))
                record = self.runs()[before]
                request = self.request(record)
                self.assertEqual(request["subject"], {"result": "[withheld]", "command": COMMAND})
                self.assertEqual(request["withheld"], ["result"])
                self.assertNotIn("cut", request)
                self.assertEqual(request["prompt"], PROMPT)
                self.assertNotIn(token.encode(), self.request_bytes(record))
                self.assertNotIn(token, self.everywhere(result), "both output streams and the log")
                self.assertEqual(self.egress()[-1]["withheld"], ["result"])

    def test_prompt_credential_withheld(self):
        self.one()
        for make in (assignment, code_host_token, cloud_key_id):
            text = make()
            secret = secret_of(text)
            with self.subTest(rule=make.__name__):
                before = len(self.runs())
                result = self.ask(prompt="Is this a refusal? " + text)
                value = self.printed(result)
                self.assertEqual((value["outcome"], value["withheld"]), ("answered", ["prompt"]))
                record = self.runs()[before]
                request = self.request(record)
                self.assertEqual(request["prompt"], "[withheld]")
                self.assertEqual(request["withheld"], ["prompt"])
                self.assertEqual(request["subject"], {"result": RESULT, "command": COMMAND})
                self.assertNotIn(secret.encode(), self.request_bytes(record))
                self.assertNotIn(secret, self.everywhere(result))

    def test_every_text_is_screened(self):
        self.one()
        token = credential_token()
        secret = assignment()
        subject = {"first": "clean", "second": "has " + token, "third": "also clean", "fourth": secret}
        value = self.printed(self.ask(prompt="a " + credential_token(), subject=subject))
        self.assertEqual(value["withheld"], ["prompt", "second", "fourth"])
        (record,) = self.runs()
        request = self.request(record)
        self.assertEqual(request["subject"], {"first": "clean", "second": "[withheld]", "third": "also clean",
                                              "fourth": "[withheld]"})
        for text in (token, secret_of(secret)):
            self.assertNotIn(text.encode(), self.request_bytes(record))
            self.assertNotIn(text, self.egress_path().read_text(encoding="utf-8"))

    def test_straddling_secret_withheld(self):
        """The whole text is screened before it is cut, so a secret that straddles the cut is never sent in part."""
        self.one()
        token = code_host_token()
        text = "a" * 3989 + " " + token + " " + "b" * 100
        start = text.index(token)
        self.assertTrue(start < 4000 < start + len(token), "the secret must straddle the cut")
        value = self.printed(self.ask(subject={"result": text}))
        self.assertEqual((value["withheld"], value["cut"]), (["result"], []))
        (record,) = self.runs()
        self.assertEqual(self.request(record)["subject"], {"result": "[withheld]"})
        self.assertNotIn(token[:8].encode(), self.request_bytes(record))

    def test_secret_formed_by_the_cut(self):
        """Decision 2: the cut text is screened again. A key with one character too many is no key; the cut makes it
        one, so the text is withheld, whole, and is not listed as cut."""
        self.one()
        key = cloud_key_id()
        text = " " * (4000 - len(key)) + key + random.choice(string.ascii_uppercase)
        self.assertEqual(len(text), 4001)
        self.assertIsNone(re.search(r"AKIA[A-Z0-9]{16}(?![A-Z0-9])", text), "the whole text must pass the detector")
        result = self.ask(subject={"result": text, "command": COMMAND})
        value = self.printed(result)
        self.assertEqual((value["withheld"], value["cut"]), (["result"], []))
        (record,) = self.runs()
        request = self.request(record)
        self.assertEqual(request["subject"], {"result": "[withheld]", "command": COMMAND})
        self.assertNotIn("cut", request)
        self.assertNotIn(key.encode(), self.request_bytes(record))
        self.assertNotIn(key, self.everywhere(result))


class NamesTest(JudgeTest):
    def test_credential_shaped_names_refused(self):
        """Decision 1: a question, lane, subject name or judge name that looks like a credential is refused without
        being repeated; nothing is run and nothing is logged."""
        self.one()
        self.ask()
        control = self.log_text()
        self.assertEqual(len(self.runs()), 1)
        for make in LOWERCASE_SHAPES:
            name = make()
            cases = [("--question", dict(question=name)), ("--lane", dict(lane=name)),
                     ("--subject", dict(subject={name: "text"})), ("--subject", dict(subject={name: name})),
                     ("--subject", dict(subject={"result": "text", name: "text"})),
                     ("--judge", dict(judge=name))]
            for option, options in cases:
                with self.subTest(rule=make.__name__, option=option, shape=sorted(options)):
                    result = self.ask(code=2, **options)
                    self.assertIn(option, result.stderr, "the message says which argument it is")
                    self.assertNotIn(name, self.everywhere(result), "the name is never repeated")
                    self.assertEqual(result.stdout, "")
        self.assertEqual(len(self.runs()), 1, "a refused ask ran a judge")
        self.assertEqual(self.log_text(), control, "a refused ask was logged")

    def test_an_unknown_name_is_named(self):
        """An ordinary unknown judge name is still repeated, with the judges the configuration has."""
        self.one()
        result = self.ask(code=2, judge="absent")
        self.assertIn("absent", result.stderr)
        self.assertIn("guard", result.stderr)


class CutTest(JudgeTest):
    def test_long_subject_is_cut(self):
        """D. The stand-in received the first 4000 characters, and the name is in cut."""
        self.one()
        long_text = "".join(chr(97 + index % 26) for index in range(6000))
        exact = "".join(chr(97 + index % 7) for index in range(4000))
        value = self.printed(self.ask(subject={"result": long_text, "exact": exact, "short": "short"}))
        self.assertEqual((value["cut"], value["withheld"]), (["result"], []))
        (record,) = self.runs()
        request = self.request(record)
        self.assertEqual(request["subject"], {"result": long_text[:4000], "exact": exact, "short": "short"})
        self.assertEqual(request["cut"], ["result"])
        self.assertNotIn("withheld", request)
        self.assertEqual(self.egress()[0]["cut"], ["result"])

    def test_limit_counts_characters(self):
        self.one()
        text = "é" * 4500 + "\U0001f600" * 10
        value = self.printed(self.ask(subject={"result": text}))
        self.assertEqual(value["cut"], ["result"])
        (record,) = self.runs()
        received = self.request(record)["subject"]["result"]
        self.assertEqual(len(received), 4000)
        self.assertEqual(received, "é" * 4000)

    def test_the_text_arrives_as_written(self):
        self.one()
        text = "line one\r\nline two\ttabbed \"quoted\" \\ backslash   ü \U0001f600 \x01 end\n"
        self.ask(subject={"result": text, "empty": ""})
        (record,) = self.runs()
        self.assertEqual(self.request(record)["subject"], {"result": text, "empty": ""})


class EgressTest(JudgeTest):
    def test_two_lines_per_ask(self):
        """E and decision 5. Every ask, answered or not, leaves a sent line and an outcome line that share an ask
        identifier; no subject or prompt text anywhere in the file."""
        self.configure(judge_table("guard", self.program("answer")), judge_table("broken", self.program("exit3")))
        token = credential_token()
        self.ask()
        self.ask(judge="broken", code=1, lane="judge-lane-1", subject={"result": "has " + token, "command": COMMAND})
        self.ask(subject={"result": "x" * 5000, "command": COMMAND}, prompt=PROMPT + " SUBJECT-PROMPT-9921")
        lines = self.log_lines()
        self.assertEqual([line["event"] for line in lines], ["sent", "outcome"] * 3)
        for sent, outcome in zip(lines[0::2], lines[1::2]):
            self.assertEqual(set(sent), SENT_KEYS)
            self.assertEqual(set(outcome), OUTCOME_KEYS)
            self.assertRegex(sent["ask"], ASK)
            self.assertEqual(outcome["ask"], sent["ask"])
            self.assertRegex(sent["at"], support.TIMESTAMP)
            self.assertRegex(outcome["at"], support.TIMESTAMP)
            self.assertLessEqual(sent["at"], outcome["at"])
            self.assertIsInstance(outcome["duration_ms"], int)
        self.assertEqual(len({line["ask"] for line in lines}), 3)
        log = self.egress()
        records = self.runs()
        self.assertEqual(len(records), 3)
        by_judge = [(line["judge"], line["outcome"], line["lane"], line["withheld"], line["cut"]) for line in log]
        self.assertEqual(by_judge, [("guard", "answered", None, [], []), ("broken", "exit", "judge-lane-1", ["result"], []),
                                    ("guard", "answered", None, [], ["result"])])
        self.assertEqual([line["question"] for line in log], ["refusal.is-refusal"] * 3)
        self.assertEqual([line["probability"] for line in log], [0.83, None, 0.83])
        self.assertEqual([(line["model"], line["request"]) for line in log],
                         [("stand-in-1", "req_e2e_001"), (None, None), ("stand-in-1", "req_e2e_001")])
        for line, record in zip(log, records):
            raw = self.request_bytes(record)
            self.assertEqual(line["request_sha256"], sha256(raw))
            self.assertEqual(line["request_bytes"], len(raw))
        text = self.egress_path().read_text(encoding="utf-8")
        for forbidden in (token, "SUBJECT-RESULT-7731", "SUBJECT-COMMAND-4408", "SUBJECT-PROMPT-9921", PROMPT,
                          "x" * 100):
            self.assertNotIn(forbidden, text)
        self.assertEqual(self.egress_path().stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.egress_path().parent.stat().st_mode & 0o777, 0o700)

    def test_sent_line_is_there_before_the_run(self):
        """Decision 5: the log says the ask was sent before the judge ends, and the outcome line comes after."""
        self.one("wait", timeout=30)
        process = self.start_ask()
        (record,) = self.wait_for_record()
        (sent,) = self.log_lines()
        self.assertEqual(set(sent), SENT_KEYS)
        self.assertEqual(sent["event"], "sent")
        self.assertEqual(sent["request_sha256"], sha256(self.request_bytes(record)))
        self.assertEqual(sent["request_bytes"], len(self.request_bytes(record)))
        (self.records / "go").write_text("go", encoding="utf-8")
        process.communicate(timeout=60)
        self.assertEqual(process.returncode, 0)
        lines = self.log_lines()
        self.assertEqual(lines[0], sent, "the sent line is not changed by the outcome")
        self.assertEqual([line["event"] for line in lines], ["sent", "outcome"])
        self.assertEqual(lines[1]["ask"], sent["ask"])
        self.assertEqual(set(lines[1]), OUTCOME_KEYS)

    def test_killed_launcher_leaves_sent_line(self):
        """Decision 5: a launcher killed with SIGKILL after the judge has its request leaves the sent line and no
        outcome line; judge egress prints it."""
        self.one("wait", timeout=30)
        process = self.start_ask()
        (record,) = self.wait_for_record()
        self.addCleanup((self.records / "go").write_text, "go", encoding="utf-8")
        process.kill()
        process.communicate()
        self.assertEqual(process.returncode, -signal.SIGKILL)
        (sent,) = self.log_lines()
        self.assertEqual((sent["event"], sent["judge"], sent["question"]), ("sent", "guard", "refusal.is-refusal"))
        self.assertEqual(sent["request_sha256"], sha256(self.request_bytes(record)))
        printed = self.run_laneboss("judge", "egress", "--config", "alpha").stdout
        self.assertEqual(printed, self.log_text())
        (self.records / "go").write_text("go", encoding="utf-8")
        self.assert_gone([record["pid"]], timeout=15)

    def test_outcome_not_logged_exit_7(self):
        """Decision 5: the egress directory goes read-only from inside the stand-in, after the sent line is written:
        exit 7, a message that says the sending is logged and the outcome is not, no result, the sent line is there."""
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        directory = self.state / "judges"
        self.configure(judge_table("guard", self.program("lock", str(directory))))
        self.addCleanup(lambda: directory.exists() and directory.chmod(0o700))
        result = self.ask(code=7)
        self.assertEqual(result.stdout, "", "no result is printed")
        self.assertTrue(result.stderr.startswith("egress problem:"), result.stderr)
        self.assertIn("its sending is logged", result.stderr)
        self.assertIn("outcome could not be logged", result.stderr)
        self.assertEqual(len(self.runs()), 1)
        directory.chmod(0o700)
        (sent,) = self.log_lines()
        self.assertEqual((sent["event"], sent["judge"]), ("sent", "guard"))

    def test_unwritable_log_exit_7(self):
        """E. The log's directory is read-only: exit 7 and the stand-in was not run."""
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        self.one()
        self.ask()
        directory = self.egress_path().parent
        before = self.egress_path().read_bytes()
        directory.chmod(0o500)
        self.addCleanup(directory.chmod, 0o700)
        result = self.ask(code=7)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("egress problem:"), result.stderr)
        self.assertIn("nothing was asked", result.stderr)
        self.assertEqual(len(self.runs()), 1, "the stand-in was run although the ask could not be logged")
        self.assertEqual(self.egress_path().read_bytes(), before)
        directory.chmod(0o700)
        self.ask()
        self.assertEqual(len(self.runs()), 2)
        self.assertEqual(len(self.egress()), 2)

    def test_unwritable_state_exit_7(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        state = self.directory / "locked-state"
        state.mkdir()
        self.write_config("alpha", state_path=state, tail=judge_table("guard", self.program("answer")))
        state.chmod(0o500)
        self.addCleanup(state.chmod, 0o700)
        result = self.ask(code=7)
        self.assertIn("nothing was asked", result.stderr)
        self.assertEqual(self.runs(), [])
        self.assertEqual(os.listdir(str(state)), [])

    def test_unreadable_log_exit_7(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores file permissions")
        self.one()
        self.ask()
        self.egress_path().chmod(0o000)
        self.addCleanup(self.egress_path().chmod, 0o600)
        self.ask(code=7)
        self.assertEqual(len(self.runs()), 1)

    def test_concurrent_asks_keep_lines(self):
        self.one()
        questions = ["test.concurrent-{}".format(index) for index in range(8)]
        processes = [self.start_ask(question=question) for question in questions]
        for process in processes:
            process.communicate(timeout=60)
            self.assertEqual(process.returncode, 0)
        lines = self.log_lines()
        self.assertEqual(len(lines), 16)
        for ask in {line["ask"] for line in lines}:
            self.assertEqual(sorted(line["event"] for line in lines if line["ask"] == ask), ["outcome", "sent"])
        self.assertEqual(sorted(line["question"] for line in self.egress()), sorted(questions))
        self.assertEqual(len(self.runs()), 8)

    def test_egress_command_and_since(self):
        self.one()
        self.assertEqual(self.run_laneboss("judge", "egress", "--config", "alpha").stdout, "")
        self.assertFalse(self.state.exists(), "reading the egress log created the state directory")
        self.ask(question="test.first")
        time.sleep(1.2)
        mark = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        time.sleep(1.2)
        self.ask(question="test.second")
        everything = self.run_laneboss("judge", "egress", "--config", "alpha").stdout
        self.assertEqual(everything, self.egress_path().read_text(encoding="utf-8"))
        later = self.run_laneboss("judge", "egress", "--config", "alpha", "--since", mark).stdout
        self.assertEqual([(json.loads(line)["event"], json.loads(line)["ask"]) for line in later.splitlines()],
                         [(line["event"], line["ask"]) for line in self.log_lines()[2:]])
        none = self.run_laneboss("judge", "egress", "--config", "alpha", "--since", "2999-01-01T00:00:00Z").stdout
        self.assertEqual(none, "")
        self.run_laneboss("judge", "egress", "--config", "alpha", "--since", "yesterday", code=2)

    def test_since_filters_each_line(self):
        """Decision 5: a line's own time decides; an ask sent before the mark and finished after it shows only its
        outcome line."""
        self.one("wait", timeout=60)
        process = self.start_ask()
        self.wait_for_record()
        time.sleep(1.2)
        mark = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        time.sleep(1.2)
        (self.records / "go").write_text("go", encoding="utf-8")
        process.communicate(timeout=60)
        self.assertEqual(process.returncode, 0)
        shown = self.run_laneboss("judge", "egress", "--config", "alpha", "--since", mark).stdout
        self.assertEqual([json.loads(line)["event"] for line in shown.splitlines()], ["outcome"])
        full = self.run_laneboss("judge", "egress", "--config", "alpha").stdout
        self.assertEqual([json.loads(line)["event"] for line in full.splitlines()], ["sent", "outcome"])

    def test_impossible_times_and_bad_lines(self):
        """Decision 7: an impossible --since is exit 2; a log line with an impossible time, a repeated key or a field of
        the wrong type is exit 3, never an unhandled error, and nothing is printed before the fault is found."""
        self.one()
        self.ask()
        good = self.log_text()
        for since in ("2026-10-09T09:00:00+00:60", "2026-10-09T09:00:00-00:75", "2026-10-09T09:00:00+23:99",
                      "2026-02-30T00:00:00Z", "2026-10-09T25:00:00Z", "2026-10-09T09:60:00Z", "2026-13-01T00:00:00Z",
                      "2026-10-09T09:00:00+24:00", "yesterday"):
            with self.subTest(since=since):
                result = self.run_laneboss("judge", "egress", "--config", "alpha", "--since", since, code=2)
                self.assertEqual(result.stdout, "")
        self.run_laneboss("judge", "egress", "--config", "alpha", "--since", "2026-10-09T09:00:00+08:00")
        self.run_laneboss("judge", "egress", "--config", "alpha", "--since", "2026-10-09T09:00:00-23:59")
        record = json.loads(good.splitlines()[0])
        bad = {"impossible time": dict(record, at="2026-02-30T00:00:00.000000Z"),
               "impossible hour": dict(record, at="2026-10-09T25:00:00.000000Z"),
               "time as a number": dict(record, at=5),
               "bytes as text": dict(record, request_bytes="12"), "bytes negative": dict(record, request_bytes=-1),
               "bytes boolean": dict(record, request_bytes=True),
               "withheld as text": dict(record, withheld="result"), "cut as a number": dict(record, cut=5),
               "withheld item": dict(record, withheld=[5]),
               "lane as a number": dict(record, lane=5), "lane grammar": dict(record, lane="Bad Lane"),
               "judge grammar": dict(record, judge="Bad_Name"), "question grammar": dict(record, question="Not.Good"),
               "digest short": dict(record, request_sha256="abc")}
        for label, changed in bad.items():
            with self.subTest(label):
                self.egress_path().write_text(good + json.dumps(changed) + "\n", encoding="utf-8")
                result = self.run_laneboss("judge", "egress", "--config", "alpha", code=3)
                self.assertEqual(result.stdout, "", "something was printed before the fault was found")
        repeated = good.splitlines()[0][:-1] + ', "at": "2026-10-09T00:00:00.000000Z"}'
        for label, text in (("repeated key", repeated), ("not an object", "[1, 2]"), ("not JSON", "this is not a line"),
                            ("extra key", json.dumps(dict(record, extra=1)))):
            with self.subTest(label):
                self.egress_path().write_text(good + text + "\n", encoding="utf-8")
                result = self.run_laneboss("judge", "egress", "--config", "alpha", code=3)
                self.assertEqual(result.stdout, "")
        self.egress_path().write_text(good, encoding="utf-8")
        self.assertEqual(self.run_laneboss("judge", "egress", "--config", "alpha").stdout, good)

    def test_ask_in_flight_delays_nothing(self):
        """Nothing here may hold the lanes lock or delay a lane command."""
        self.one("wait", timeout=60)
        process = self.start_ask()
        self.wait_for_record()
        for arguments in (("lane", "status", "--config", "alpha"), ("lane", "check", "--config", "alpha"),
                          ("state", "verify", "--config", "alpha")):
            started = time.monotonic()
            self.run_laneboss(*arguments)
            self.assertLess(time.monotonic() - started, 5, " ".join(arguments))
        started = time.monotonic()
        self.append(self.event())
        self.assertLess(time.monotonic() - started, 5)
        (self.records / "go").write_text("go", encoding="utf-8")
        process.communicate(timeout=60)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(len(self.egress()), 1)


class InputTest(JudgeTest):
    def test_invalid_input_runs_nothing(self):
        self.one()
        self.ask()
        self.assertEqual(len(self.runs()), 1)
        control = self.log_text()
        cases = []
        for question in ("Refusal.is", "refusal..is", "refusal.", ".refusal", "-refusal", "has space", "a" * 100, ""):
            cases.append(("question " + question[:12], dict(question=question)))
        cases.append(("empty prompt", dict(prompt="")))
        cases.append(("long prompt", dict(prompt="p" * 4001)))
        cases.append(("bad lane", dict(lane="Bad Lane")))
        cases.append(("unknown judge", dict(judge="absent")))
        cases.append(("bad judge name", dict(judge="Bad_Name")))
        cases.append(("nine subjects", dict(subject={"s{}".format(index): "x" for index in range(9)})))
        for name in ("Bad", "1x", "prompt", "has space", "a" * 40):
            cases.append(("subject name " + name[:12], dict(subject={name: "x"})))
        for label, options in cases:
            with self.subTest(label):
                self.ask(code=2, **options)
        files = {"missing": ["--subject", "result=" + str(self.texts / "absent.txt")],
                 "directory": ["--subject", "result=" + str(self.texts)],
                 "no equals": ["--subject", "result"], "no name": ["--subject", "=" + str(self.texts / "x")],
                 "no file": ["--subject", "result="]}
        (self.texts / "binary.txt").write_bytes(b"\xff\xfe not utf-8")
        files["not utf-8"] = ["--subject", "result=" + str(self.texts / "binary.txt")]
        (self.texts / "big.txt").write_bytes(b"x" * (1024 * 1024 + 1))
        files["larger than 1 MiB"] = ["--subject", "result=" + str(self.texts / "big.txt")]
        for label, subject in files.items():
            with self.subTest(label):
                self.run_laneboss("judge", "ask", "--config", "alpha", "--judge", "guard", "--question", "test.input",
                                  "--prompt-file", self.text_file("prompt", PROMPT), *subject, code=2)
        self.run_laneboss("judge", "ask", "--config", "alpha", "--judge", "guard", "--question", "test.input",
                          "--prompt-file", self.text_file("prompt", PROMPT), code=2)
        self.run_laneboss("judge", "ask", "--config", "alpha", "--judge", "guard", "--question", "test.input",
                          "--subject", "result=" + str(self.texts / "binary.txt"), code=2)
        self.run_laneboss("judge", "ask", "--config", "alpha", "--judge", "guard", "--question", "test.input",
                          "--prompt-file", str(self.texts / "absent.txt"), "--subject",
                          "result=" + str(self.texts / "binary.txt"), code=2)
        self.assertEqual(len(self.runs()), 1, "a refused ask ran a judge")
        self.assertEqual(self.log_text(), control, "a refused ask was logged")

    def test_a_text_may_be_exactly_the_limits(self):
        self.one()
        question = "a" + "b" * 63
        self.assertEqual(len(question), 64)
        subject = {"s{}".format(index): "x" * 4000 for index in range(8)}
        value = self.printed(self.ask(subject=subject, prompt="p" * 4000, question=question))
        self.assertEqual((value["outcome"], value["cut"]), ("answered", []))
        (record,) = self.runs()
        self.assertEqual(len(self.request(record)["subject"]), 8)
        self.assertEqual(self.request(record)["question"], question)
        sent, outcome = self.read_back()
        self.assertEqual((sent["question"], outcome["outcome"]), (question, "answered"))

    def test_subject_names_keep_order(self):
        self.one()
        self.ask(subject={"zeta": "1", "alpha": "2", "mid-dle_1": "3"})
        (record,) = self.runs()
        self.assertEqual(list(self.request(record)["subject"]), ["zeta", "alpha", "mid-dle_1"])


class CapacityTest(JudgeTest):
    """Decision 2: the log never grows past what its own reader accepts. The reader's limit is 64 MiB; these tests set
    a small one through the module's constant in a separate process (LIMITED), the nearest a black-box test can come to
    a log of that size without writing one. Every call that has a limit is the installed command line, unchanged."""

    def lengths(self):
        """(size, sent line length, outcome line length) of a log that holds one ask."""
        raw = self.log_text().encode("utf-8")
        sent, outcome = (len(line) + 1 for line in raw.splitlines())
        return len(raw), sent, outcome

    def test_log_never_outgrows_the_reader(self):
        self.one()
        self.ask()
        size, sent, outcome = self.lengths()
        self.assertLess(outcome, RESERVE)
        before = self.egress_path().read_bytes()
        runs = len(self.runs())
        # One byte short of what a sent line and the reserve for its outcome line need: refused, nothing asked.
        short = size + sent + RESERVE - 1
        result = self.limited(short, *self.ask_arguments(), code=7)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("egress problem:"), result.stderr)
        for text in ("nothing was asked", "full", "aside", str(self.egress_path())):
            self.assertIn(text, result.stderr)
        self.assertEqual(len(self.runs()), runs, "the judge was run although the log had no room")
        self.assertEqual(self.egress_path().read_bytes(), before, "the log was changed")
        # The log stays readable by the command that reads it, under the same limit.
        self.assertEqual(self.limited(short, "judge", "egress", "--config", "alpha").stdout, before.decode("utf-8"))
        # Exactly enough: the ask is made, and its outcome line is written inside the reserve.
        fits = size + sent + RESERVE
        value = json.loads(self.limited(fits, *self.ask_arguments()).stdout)
        self.assertEqual(value["outcome"], "answered")
        self.assertEqual(len(self.runs()), runs + 1)
        grown = self.egress_path().stat().st_size
        self.assertTrue(size + sent < grown <= fits, (size, sent, grown, fits))
        self.assertEqual(len(self.limited(fits, "judge", "egress", "--config", "alpha").stdout.splitlines()), 4)
        # Now it is full for the next ask, which is refused without being run, and the log is still whole.
        self.limited(fits, *self.ask_arguments(), code=7)
        self.assertEqual(len(self.runs()), runs + 1)
        self.assertEqual(self.egress_path().stat().st_size, grown)
        self.assertEqual(len(self.limited(fits, "judge", "egress", "--config", "alpha").stdout.splitlines()), 4)

    def test_unfinished_asks_keep_their_reserve(self):
        """Every unfinished ask holds the reserve for its own outcome line, so asks that overlap cannot spend each
        other's: with one judge still running, an ask that would fit beside its sent line but not beside its reserve is
        refused; when it has ended, the room is back, and the log never passed the limit."""
        self.configure(judge_table("guard", self.program("answer")), judge_table("waiter", self.program("wait"), 60))
        self.ask()
        size, sent, outcome = self.lengths()
        process = self.start_ask(judge="waiter")
        self.addCleanup(process.kill)
        self.wait_for_record(2)
        after = self.egress_path().stat().st_size
        self.assertGreater(after, size, "the running ask's sent line is not in the log")
        limit = after + sent + 2 * RESERVE
        runs = len(self.runs())
        self.limited(limit - 1, *self.ask_arguments(), code=7)
        self.assertEqual((len(self.runs()), self.egress_path().stat().st_size), (runs, after))
        self.limited(limit, *self.ask_arguments())
        self.assertEqual(len(self.runs()), runs + 1)
        (self.records / "go").write_text("go", encoding="utf-8")
        process.communicate(timeout=60)
        self.assertEqual(process.returncode, 0)
        done = self.egress_path().stat().st_size
        self.assertLessEqual(done, limit, "the log passed the limit the ask had been admitted under")
        self.assertEqual(len(self.limited(limit, "judge", "egress", "--config", "alpha").stdout.splitlines()), 6)
        # Nothing is unfinished any more: exactly one sent line and one reserve fit, one byte less does not.
        self.limited(done + sent + RESERVE - 1, *self.ask_arguments(), code=7)
        self.limited(done + sent + RESERVE, *self.ask_arguments())

    def test_killed_ask_holds_its_reserve(self):
        """A sent line without an outcome line stays unfinished: it keeps one reserve for as long as it is in the log."""
        self.one("wait", timeout=30)
        process = self.start_ask()
        self.wait_for_record()
        process.kill()
        process.communicate()
        (self.records / "go").write_text("go", encoding="utf-8")
        self.assert_gone([self.runs()[0]["pid"]], timeout=15)
        size = self.egress_path().stat().st_size
        sent = size
        self.limited(size + sent + 2 * RESERVE - 1, *self.ask_arguments(), code=7)
        self.limited(size + sent + 2 * RESERVE, *self.ask_arguments())


class ForeignLogTest(JudgeTest):
    """Decision 3: a log this version did not write is not appended to."""

    OLD = {"at": "2026-10-09T09:00:00.000000Z", "judge": "guard", "question": "refusal.is-refusal", "lane": None,
           "request_sha256": "0" * 64, "request_bytes": 100, "withheld": [], "cut": [], "outcome": "answered",
           "probability": 0.5, "model": None, "request": None, "duration_ms": 5}

    def old_line(self):
        return (json.dumps(self.OLD, sort_keys=True) + "\n").encode("utf-8")

    def make_log(self, content):
        """The state an earlier unreleased build left: judges/egress.jsonl, and no ownership marker."""
        self.state.mkdir(mode=0o700)
        (self.state / "judges").mkdir(mode=0o700)
        self.egress_path().write_bytes(content)

    def assert_refused(self, content):
        result = self.ask(code=7)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("egress problem:"), result.stderr)
        for text in ("nothing was asked", "aside", str(self.egress_path())):
            self.assertIn(text, result.stderr)
        self.assertEqual(self.runs(), [], "the judge was run")
        self.assertEqual(self.egress_path().read_bytes(), content, "the log was changed")

    def test_old_format_log_is_not_appended(self):
        self.one()
        self.make_log(self.old_line())
        self.assert_refused(self.old_line())
        # The reader refuses such a log too, as before: the person moves it aside.
        self.run_laneboss("judge", "egress", "--config", "alpha", code=3)

    def test_foreign_last_line_refused(self):
        self.one()
        self.ask()
        valid = self.egress_path().read_bytes()
        runs = len(self.runs())
        garbage = {"an old line": self.old_line(), "garbage": b"this is not a line of the log\n",
                   "a half line": b'{"ask": "0123456789abcdef0123456789abcdef", "at": "2026-10-09T09:00:00.000000Z", "ev',
                   "a line of another form": b'{"event": "sent"}\n', "an array": b"[1, 2, 3]\n"}
        for label, extra in garbage.items():
            with self.subTest(label):
                self.egress_path().write_bytes(valid + extra)
                result = self.ask(code=7)
                for text in ("nothing was asked", "aside", str(self.egress_path())):
                    self.assertIn(text, result.stderr)
                self.assertEqual(len(self.runs()), runs, "the judge was run")
                self.assertEqual(self.egress_path().read_bytes(), valid + extra, "the log was changed")

    def test_own_last_line_is_appended_to(self):
        """The controls: a log whose last line is a line of this version, however the file ends, is appended to."""
        self.one()
        self.ask()
        valid = self.egress_path().read_bytes()
        cases = {"without a final newline": valid[:-1], "followed by blank lines": valid + b"\n\n",
                 "empty": b"", "blank lines only": b"\n\n"}
        runs = len(self.runs())
        for label, content in cases.items():
            with self.subTest(label):
                self.egress_path().write_bytes(content)
                self.ask()
                runs += 1
                self.assertEqual(len(self.runs()), runs)
                # The reader skips blank lines, so what it prints is the lines of the log without them.
                printed = self.run_laneboss("judge", "egress", "--config", "alpha").stdout
                lines = [json.loads(line) for line in printed.splitlines()]
                self.assertEqual([line["event"] for line in lines][-2:], ["sent", "outcome"])
                self.assertEqual(printed.splitlines(), [line for line in self.log_text().splitlines() if line.strip()])
                self.assertTrue(self.egress_path().read_bytes().endswith(b"\n"))


class RoundTripTest(JudgeTest):
    """Decision 4: what the writer writes at the edges of its grammars, the strict reader reads."""

    def test_longest_names_read_back(self):
        judge, question, lane = "j" * 32, "q" + "r" * 63, "l" * 64
        withheld_name, cut_name = "w" + "x" * 31, "c" + "y" * 31
        self.assertEqual((len(judge), len(question), len(lane), len(withheld_name), len(cut_name)), (32, 64, 64, 32, 32))
        self.configure(judge_table(judge, self.program("answer")))
        subject = {withheld_name: "has " + credential_token(), cut_name: "z" * 4001, "plain": "text"}
        value = self.printed(self.ask(judge=judge, question=question, lane=lane, subject=subject,
                                      prompt="Is it? " + assignment()))
        self.assertEqual((value["outcome"], value["withheld"], value["cut"]),
                         ("answered", ["prompt", withheld_name], [cut_name]))
        sent, outcome = self.read_back()
        self.assertEqual((sent["judge"], sent["question"], sent["lane"]), (judge, question, lane))
        self.assertEqual((sent["withheld"], sent["cut"]), (["prompt", withheld_name], [cut_name]))
        self.assertEqual(outcome["outcome"], "answered")

    def test_longest_metadata_reads_back(self):
        model, request = "m" * 128, "r" * 128
        self.one("raw")
        (self.records / "stdout.txt").write_bytes(
            (json.dumps({"probability": 0.5, "model": model, "request": request}) + "\n").encode("utf-8"))
        value = self.printed(self.ask())
        self.assertEqual((value["outcome"], value["model"], value["request"]), ("answered", model, request))
        sent, outcome = self.read_back()
        self.assertEqual((outcome["model"], outcome["request"]), (model, request))
        longest = self.log_text().splitlines()[1]
        self.assertLess(len(longest) + 1, RESERVE, "the outcome line must fit the reserve that is kept for it")

    def test_every_outcome_reads_back(self):
        """Each reason an ask can end with, through the strict reader."""
        self.configure(judge_table("exits", self.program("exit3")), judge_table("text", self.program("text")),
                       judge_table("slow", self.program("sleep"), 1), judge_table("missing", ["laneboss-e2e-absent"]),
                       judge_table("guard", self.program("answer")))
        for name, code in (("exits", 1), ("text", 1), ("slow", 1), ("missing", 1), ("guard", 0)):
            self.ask(judge=name, code=code)
        lines = self.read_back()
        self.assertEqual([line["outcome"] for line in lines if line["event"] == "outcome"],
                         ["exit", "output", "timeout", "not-found", "answered"])


class DurabilityTest(JudgeTest):
    def test_state_synced_before_the_start(self):
        """Decision 1: after the ownership marker and the judges directory are made, the state directory is synced once,
        before the sent line is written and before the judge is started. The ask runs in a separate process that records
        every fsync (what it was for, and what existed at that moment) and the start of the judge, in order."""
        self.one()
        events = self.probe("sync")
        kinds = [(event["event"], event.get("target")) for event in events]
        states = [index for index, event in enumerate(events) if event.get("target") == "state"]
        self.assertEqual(len(states), 1, kinds)
        synced = events[states[0]]
        self.assertTrue(synced["marker"], "the marker was not there when the state directory was synced")
        self.assertTrue(synced["judges"], "the judges directory was not there when the state directory was synced")
        self.assertFalse(synced["log"], "the state directory was synced after the log was written")
        starts = [index for index, event in enumerate(events) if event["event"] == "start"]
        self.assertEqual(len(starts), 1, kinds)
        self.assertLess(states[0], starts[0])
        self.assertEqual(events[starts[0]]["log_lines"], 1, "the sent line is in the log when the judge starts")
        before = [(event["event"], event.get("target")) for event in events[:starts[0]]]
        self.assertIn(("fsync", "judges"), before, "the log's own directory was not synced before the start")
        self.assertLess(states[0], before.index(("fsync", "judges")))
        self.assertEqual(len(self.runs()), 1)

    def test_sent_is_an_attempt(self):
        """Decision 5: the sent line records an attempt, written before the command is started: a launcher killed
        between the two leaves a sent line for a judge that never ran, and judge egress prints it as it is."""
        self.one()
        events = self.probe("kill", code=-signal.SIGKILL)
        self.assertEqual(events[-1]["event"], "start")
        (sent,) = self.log_lines()
        self.assertEqual((sent["event"], sent["judge"]), ("sent", "guard"))
        self.assertEqual(self.runs(), [], "the judge ran")
        self.assertEqual(self.read_back(), [sent])


class BindingTest(JudgeTest):
    def test_judge_of_another_config(self):
        """G. judge ask for a judge of another configuration is refused; so is a LANEBOSS_CONFIG that names another."""
        self.one("answer", "guard", "alpha")
        self.one("answer", "other", "beta")
        self.ask(judge="guard", config="alpha")
        result = self.ask(judge="other", config="alpha", code=2)
        self.assertIn("other", result.stderr)
        self.assertEqual(len(self.runs()), 1)
        self.assertFalse((self.state_home / "beta").exists(), "a command bound to alpha touched beta's state")
        bound = dict(self.environment, LANEBOSS_CONFIG="beta")
        result = self.ask(judge="guard", config="alpha", code=2, environment=bound)
        self.assertIn("beta", result.stderr)
        self.assertEqual(len(self.runs()), 1)
        self.ask(judge="guard", config=None, code=2)
        self.ask(judge="other", config=None, environment=bound)
        self.assertEqual(len(self.runs()), 2)
        self.assertEqual([line["judge"] for line in self.egress()], ["guard"], "alpha's log holds only its own ask")
        self.assertEqual([line["judge"] for line in self.egress(self.state_home / "beta")], ["other"])
        listed = self.laneboss_json("judge", "list", environment=bound)
        self.assertEqual([item["name"] for item in listed], ["other"])
        self.run_laneboss("judge", "list", "--config", "alpha", code=2, environment=bound)
        self.run_laneboss("judge", "egress", "--config", "alpha", code=2, environment=bound)
        self.run_laneboss("judge", "list", code=2)

    def test_each_config_logs_alone(self):
        self.one("answer", "guard", "alpha")
        self.one("answer", "guard", "beta")
        self.ask(config="alpha", question="test.alpha")
        self.ask(config="beta", question="test.beta")
        self.assertEqual([line["question"] for line in self.egress()], ["test.alpha"])
        self.assertEqual([line["question"] for line in self.egress(self.state_home / "beta")], ["test.beta"])


class OwnerTest(JudgeTest):
    def test_judge_only_state_has_a_marker(self):
        """Decision 6: a state directory made by judge ask alone records its owner before the first line is written."""
        self.one()
        self.ask()
        marker = json.loads((self.state / ".laneboss-state").read_text(encoding="utf-8"))
        self.assertEqual((marker["config"], marker["store"]), ("alpha", None))
        self.ask()
        self.assertEqual(len(self.egress()), 2)
        self.append(self.event())
        self.assertEqual(self.laneboss_json("state", "verify", "--config", "alpha")["ok"], True)
        self.assertEqual(len(self.egress()), 2)

    def test_copied_judge_state_is_refused(self):
        """Decision 6: state made only by judge ask for alpha, copied whole to beta's place, is refused there."""
        self.one("answer", "guard", "alpha")
        self.one("answer", "guard", "beta")
        self.ask(config="alpha")
        beta = self.state_home / "beta"
        shutil.copytree(str(self.state), str(beta))
        copy = self.egress_path(beta).read_bytes()
        result = self.run_laneboss("judge", "egress", "--config", "beta", code=2)
        self.assertEqual(result.stdout, "", "beta read alpha's records")
        self.assertIn("alpha", result.stderr)
        result = self.ask(config="beta", code=2)
        self.assertIn("alpha", result.stderr)
        self.assertEqual(len(self.runs()), 1, "beta ran a judge over alpha's state")
        self.assertEqual(self.egress_path(beta).read_bytes(), copy, "beta appended to alpha's log")

    def test_function_refuses_foreign_state(self):
        """Decision 6: judges.ask() with a configuration and a state directory that do not belong together is refused
        before anything is run or written. The installed package is imported in a separate process."""
        self.one("answer", "guard", "alpha")
        self.one("answer", "guard", "beta")
        library = self.installed_library()
        code = ("import json, sys\nsys.path.insert(0, sys.argv[1])\n"
                "from laneboss import config, judges\nfrom laneboss.errors import LauncherError\n"
                "from laneboss.statedir import StateDir\n"
                "states, judge = config.load(sys.argv[2]), config.load(sys.argv[3])\n"
                "state = StateDir.open(states, config.Zones(states), create=True)\n"
                "try:\n"
                "    judges.ask(judge, state, 'guard', 'test.api', 'A question?', {'result': 'text'})\n"
                "    print(json.dumps({'refused': False}))\n"
                "except LauncherError as error:\n"
                "    print(json.dumps({'refused': True, 'kind': type(error).__name__}))\n"
                "finally:\n    state.close()\n")
        for states, judge in (("beta", "alpha"), ("alpha", "beta")):
            with self.subTest(state=states, judge=judge):
                result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(library), states, judge],
                                        env=self.environment, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["refused"], True, result.stdout)
                self.assertEqual(self.runs(), [], "a judge ran for a state that is not its configuration's")
                self.assertFalse((self.state_home / states / "judges").exists(), "a log was written")

    def test_first_ask_waits_for_the_state_lock(self):
        """Decision 5: an ask for a state directory that has no ownership marker takes the state directory's lock to
        record its owner and waits for it, without a bound of its own, while another command holds it; an ask for a
        state directory that has a marker does not take it."""
        self.one()
        self.state.mkdir(mode=0o700)
        descriptor = os.open(str(self.state), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            process = self.start_ask()
            self.addCleanup(process.kill)
            time.sleep(3)
            self.assertIsNone(process.poll(), "the first ask did not wait for the state directory's lock")
            self.assertEqual(self.runs(), [], "the judge ran while another command held the lock")
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stderr)
        finally:
            os.close(descriptor)
        descriptor = os.open(str(self.state), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            started = time.monotonic()
            self.ask()
            self.assertLess(time.monotonic() - started, 10, "an ask with a marker waited for the state directory's lock")
        finally:
            os.close(descriptor)
        self.assertEqual(len(self.runs()), 2)


class ConfigurationTest(JudgeTest):
    def refused(self, key_path, table, secret=None, top=""):
        self.write_config("alpha", tail=table, top=top)
        result = self.run_laneboss("config", "validate", "alpha", code=2)
        self.assertIn(key_path, result.stderr)
        if secret is not None:
            self.assertNotIn(secret, result.stdout + result.stderr)
        return result

    def test_invalid_judges_name_key_path(self):
        """F. An unknown key, a time-out of 0 or 61, an empty command and a credential-shaped description."""
        command = ["a-command", "an-argument"]
        cases = [
            ("unknown key", 'config.toml: judges.guard.colour', judge_table("guard", command, extra='colour = "red"\n')),
            ("time-out 0", "config.toml: judges.guard.timeout_seconds", judge_table("guard", command, 0)),
            ("time-out 61", "config.toml: judges.guard.timeout_seconds", judge_table("guard", command, 61)),
            ("time-out negative", "config.toml: judges.guard.timeout_seconds", judge_table("guard", command, -1)),
            ("time-out fraction", "config.toml: judges.guard.timeout_seconds", judge_table("guard", command, "1.5")),
            ("time-out text", "config.toml: judges.guard.timeout_seconds", judge_table("guard", command, '"10"')),
            ("time-out boolean", "config.toml: judges.guard.timeout_seconds", judge_table("guard", command, "true")),
            ("empty command", "config.toml: judges.guard.command", judge_table("guard", [])),
            ("empty program", "config.toml: judges.guard.command[0]", judge_table("guard", [""])),
            ("command text", "config.toml: judges.guard.command", "\n[judges.guard]\ncommand = \"a-command\"\n"),
            ("empty argument", "config.toml: judges.guard.command[1]", judge_table("guard", ["a-command", ""])),
            ("number argument", "config.toml: judges.guard.command[1]",
             "\n[judges.guard]\ncommand = [\"a-command\", 5]\n"),
            ("relative program", "config.toml: judges.guard.command[0]", judge_table("guard", ["./judge.sh"])),
            ("placeholder", "config.toml: judges.guard.command[1]", judge_table("guard", ["a-command", "{lane}"])),
            ("brace", "config.toml: judges.guard.command[2]", judge_table("guard", ["a-command", "ok", "a{b"])),
            ("no command", "config.toml: judges.guard.command", "\n[judges.guard]\ntimeout_seconds = 5\n"),
            ("empty description", "config.toml: judges.guard.description", judge_table("guard", command, description="")),
            ("bad name", "config.toml: judges", judge_table("Bad_Name", command)),
            ("not a table", "config.toml: judges", ""),
            ("entry not a table", "config.toml: judges.guard", "\n[judges]\nguard = 5\n"),
        ]
        for label, key_path, table in cases:
            with self.subTest(label):
                self.refused(key_path, table, top="judges = 5" if label == "not a table" else "")
                self.assertIn(key_path, self.run_laneboss("config", "show", "alpha", code=2).stderr)
                self.run_laneboss("doctor", "--config", "alpha", code=1)

    def test_credential_description(self):
        """This pins what the configuration loader already did before judges existed: its credential check runs over
        the whole file before any schema check, so a credential-shaped description is refused naming the top-level key
        and never the value. The judge code adds nothing to it."""
        for make in SHAPES:
            token = make()
            with self.subTest(rule=make.__name__):
                result = self.refused("config.toml: judges", judge_table("guard", ["a-command"],
                                                                         description=token + " judge"), secret=token)
                self.assertNotIn("config.toml: judges.", result.stderr, "no key below the top level is printed")
                self.assertNotIn("guard", result.stderr)

    def test_valid_judges_are_listed(self):
        """F. judge list shows two judges."""
        self.configure(judge_table("guard", [sys.executable, "-I", "x"], 7, "A stand-in judge."),
                       judge_table("second", ["a-command"], 60), judge_table("third", ["another", "arg"], 1))
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        listed = self.laneboss_json("judge", "list", "--config", "alpha")
        self.assertEqual(listed, [
            {"name": "guard", "description": "A stand-in judge.", "program": sys.executable, "timeout_seconds": 7},
            {"name": "second", "description": None, "program": "a-command", "timeout_seconds": 60},
            {"name": "third", "description": None, "program": "another", "timeout_seconds": 1}])
        self.assertEqual(self.laneboss_json("config", "show", "alpha")["config"]["judges"]["guard"]["timeout_seconds"], 7)
        self.assertFalse(self.state.exists(), "listing the judges created the state directory")

    def test_default_timeout_and_no_judges(self):
        self.configure(judge_table("guard", ["a-command"]))
        self.assertEqual(self.laneboss_json("judge", "list", "--config", "alpha")[0]["timeout_seconds"], 10)
        self.write_config("alpha")
        self.assertEqual(self.laneboss_json("judge", "list", "--config", "alpha"), [])
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})

    def test_doctor_checks_each_judge(self):
        """F. doctor has a judge.NAME line and fails it when the program is missing."""
        self.configure(judge_table("guard", self.program("answer")),
                       judge_table("ghost", ["laneboss-e2e-absent-judge", "x"]))
        result = self.run_laneboss("doctor", "--config", "alpha", code=1)
        checks = {json.loads(line)["check"]: json.loads(line) for line in result.stdout.splitlines()}
        self.assertIs(checks["judge.guard"]["ok"], True, checks["judge.guard"])
        self.assertIs(checks["judge.ghost"]["ok"], False)
        self.assertIn("laneboss-e2e-absent-judge", checks["judge.ghost"]["detail"])
        self.assertIs(checks["config"]["ok"], True)
        self.assertEqual(self.runs(), [], "doctor called a judge")
        self.assertFalse((self.state / "judges").exists(), "doctor wrote an egress log")
        self.one()
        result = self.run_laneboss("doctor", "--config", "alpha", code=0)
        checks = {json.loads(line)["check"]: json.loads(line) for line in result.stdout.splitlines()}
        self.assertIs(checks["judge.guard"]["ok"], True)
        self.assertEqual(self.runs(), [])
        self.assertEqual(sorted(check for check in checks if check.startswith("judge.")), ["judge.guard"])
        self.write_config("alpha")
        result = self.run_laneboss("doctor", "--config", "alpha", code=0)
        self.assertEqual([line for line in result.stdout.splitlines() if '"judge.' in line], [])


class DocumentTest(JudgeTest):
    def test_stand_in_of_the_manual_works(self):
        """The stand-in judge printed in docs/judges.md is read from the page, so the page and the program agree."""
        text = (support.ROOT / "docs" / "judges.md").read_text(encoding="utf-8")
        block = []
        for line in text[text.index("    import json, sys\n"):].splitlines():
            if line.strip() and not line.startswith("    "):
                break
            block.append(line[4:])
        code = "\n".join(block).strip() + "\n"
        self.assertLessEqual(len([line for line in code.splitlines() if line.strip()]), 10, "a stand-in of ten lines")
        program = self.directory / "stand_in.py"
        program.write_text(code, encoding="utf-8")
        self.configure(judge_table("stand-in", [sys.executable, "-I", str(program)]))
        denied = self.printed(self.ask(judge="stand-in", subject={"result": "Permission DENIED by the sandbox"}))
        self.assertEqual((denied["outcome"], denied["probability"], denied["model"], denied["request"]),
                         ("answered", 0.9, "stand-in-1", None))
        calm = self.printed(self.ask(judge="stand-in", subject={"result": "the build finished"}))
        self.assertEqual((calm["outcome"], calm["probability"]), ("answered", 0.1))


if __name__ == "__main__":
    import unittest
    unittest.main()

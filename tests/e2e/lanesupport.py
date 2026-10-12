"""Shared helpers for the lane tests: a configuration whose runners are the stand-in program, a scratch Git
repository per configuration, tmux sockets in a short private directory, and helpers that wait for events, records
and processes.

The runners run tests/e2e/standin.py under the interpreter that runs the suite. That program stands in for a real
agent program, which cannot reach a test machine; nothing else is replaced. Every outcome is observed through the
installed command, the stand-in's records, the file system, Git and tmux.
"""

from datetime import datetime
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

from . import support

STANDIN = support.ROOT / "tests" / "e2e" / "standin.py"
DENY = support.ROOT / "tests" / "e2e" / "denysignals.py"
BASE = ["--lane", "{lane}", "--brief", "{brief}", "--model", "{model}"]
WITH_ACCOUNT = BASE + ["--account", "{account}", "--log", "{log}", "--worktree", "{worktree}"]
RESUME = ["resumed", "--lane", "{lane}", "--brief", "{brief}", "--message", "{message}"]
PATTERNS = ('limit_patterns = ["^standin: usage limit reached"]\n'
            'dropped_patterns = ["^standin: stream disconnected"]\n')
UNTIL = 30


def toml(value):
    return json.dumps(value)


def moment(event):
    """The time an event happened, as seconds since the epoch."""
    value = event["occurred_at"] or event["recorded_at"]
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value).timestamp()


def runner(name, mode, tail, accounts=None, resume=None, extra="", patterns=PATTERNS):
    command = [sys.executable, "-I", str(STANDIN), mode] + tail
    lines = ["[runners.{}]".format(name), "command = " + toml(command)]
    if resume is not None:
        lines.append("resume = " + toml([sys.executable, "-I", str(STANDIN)] + resume))
    if accounts:
        lines.append("accounts = " + toml(accounts))
    return "\n".join(lines) + "\n" + patterns + extra + "\n"


def lane_config(name, quiet_seconds=600):
    """The text of a configuration whose runners are the stand-in program in its different behaviours."""
    resume_ok = ["ok"] + RESUME + ["--account", "{account}"]
    parts = [
        "schema_version = 1\n",
        'name = "{}"\n'.format(name),
        'description = "Invented configuration for the lane tests."\n',
        'rules = ["rules/standing.md"]\n\n',
        "[lanes]\nbudget_minutes = 30\nquiet_seconds = {}\nstop_grace_seconds = 2\n\n".format(quiet_seconds),
        runner("ok", "ok", WITH_ACCOUNT + ["--effort", "{effort}"], ["acc-one", "acc-two", "acc-three"], resume_ok),
        runner("nap", "nap", WITH_ACCOUNT + ["--project", "{project}"], ["acc-two"], resume_ok),
        runner("fail", "fail", BASE, None, ["ok"] + RESUME),
        runner("solo", "ok", WITH_ACCOUNT, ["acc-one"], resume_ok),
        runner("forever", "forever", WITH_ACCOUNT, ["acc-two", "acc-three"], resume_ok),
        runner("stubborn", "stubborn", BASE, None, ["ok"] + RESUME),
        runner("quiet", "quiet", BASE, None, ["ok"] + RESUME, extra="quiet_seconds = 2\n"),
        runner("limit", "limit", WITH_ACCOUNT, ["acc-two", "acc-three"], resume_ok),
        runner("dropped", "dropped", BASE, None, ["ok"] + RESUME),
        runner("writer", "writer", BASE, None, ["ok"] + RESUME),
        runner("secret", "secret", BASE, None, ["ok"] + RESUME),
        runner("plain", "ok", BASE, None, ["ok", "resumed", "--lane", "{lane}"]),
        runner("persist", "forever", WITH_ACCOUNT, ["acc-two"], ["forever"] + RESUME + ["--account", "{account}"]),
        runner("leaver", "leaver", BASE, None, ["ok"] + RESUME),
        runner("waiter", "waiter", BASE, None, ["ok"] + RESUME),
        runner("detacher", "detacher", BASE, None, ["ok"] + RESUME),
        runner("regex", "regex", BASE, None, ["ok"] + RESUME, patterns='limit_patterns = ["(a+)+$"]\n'),
        runner("late", "late", BASE, None, ["ok"] + RESUME),
        runner("reaped", "reaped", BASE, None, ["ok"] + RESUME),
        runner("slowend", "slowend", BASE, None, ["ok"] + RESUME, patterns='limit_patterns = ["(a+)+$"]\n'),
        runner("setsider", "setsider", BASE, None, ["ok"] + RESUME),
        runner("limitdrop", "limitdrop", BASE, None, ["ok"] + RESUME),
        runner("droplimit", "droplimit", BASE, None, ["ok"] + RESUME),
        runner("streamer", "streamer", BASE, None, ["ok"] + RESUME),
        "[[routing.standard]]\nrunner = \"ok\"\nmodel = \"std-model-2\"\neffort = \"high\"\n\n",
        "[[routing.hard]]\nrunner = \"solo\"\nmodel = \"solo-model-1\"\n\n",
        "[[routing.hard]]\nrunner = \"ok\"\nmodel = \"hard-model-4\"\neffort = \"max\"\n\n",
        "[[routing.review]]\nrunner = \"fail\"\nmodel = \"review-model-5\"\n\n",
        "[[routing.review]]\nrunner = \"nap\"\nmodel = \"review-model-6\"\n",
    ]
    return "".join(parts)


def project_text(repository):
    return ('schema_version = 1\nname = "web"\ndescription = "Invented project for the lane tests."\n'
            "repository = {}\nlane_prefix = \"web-\"\n"
            'workers = ["ok", "nap", "solo", "forever", "stubborn", "quiet", "limit", "dropped", "writer", "secret", '
            '"plain", "persist", "leaver", "waiter", "detacher", "regex", "streamer"]\nexcluded_accounts = ["acc-one"]\n').format(
                toml(str(repository)))


class Follower:
    """`laneboss event tail --follow` in the background; every line is kept with the wall-clock time it arrived."""

    def __init__(self, command, config, environment, directory):
        self.process = subprocess.Popen([str(command), "event", "tail", "--config", config, "--follow"],
                                        cwd=str(directory), env=environment, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf-8")
        self.lines = queue.Queue()
        self.seen = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.put((time.time(), json.loads(line)))

    def wait(self, test, kind, lane, run=None, timeout=UNTIL):
        """(arrival time, event) of the first event of this kind, lane and run that arrives."""
        deadline = time.monotonic() + timeout
        while True:
            for arrived, event in self.seen:
                if event["kind"] == kind and event["lane"] == lane and (
                        run is None or event["payload"].get("run") == run):
                    return arrived, event
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                test.fail("event tail --follow did not show {} for {} within {} s".format(kind, lane, timeout))
            try:
                self.seen.append(self.lines.get(timeout=remaining))
            except queue.Empty:
                pass

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process.stdout.close()
        self.process.stderr.close()


class LaneTest(support.LauncherTest):
    """A configuration `alpha` with the stand-in runners and the project `web` on a scratch repository."""

    def setUp(self):
        super().setUp()
        # tmux keeps its sockets below TMUX_TMPDIR; a short private directory keeps the socket paths within the
        # length a Unix socket allows, keeps these servers apart from any other tmux, and lets the test remove them.
        self.tmux_dir = Path(tempfile.mkdtemp(prefix="lbt", dir="/tmp")).resolve()
        self.addCleanup(self.collect)
        for name in ("TMUX", "TMUX_PANE"):
            self.environment.pop(name, None)
        self.environment["TMUX_TMPDIR"] = str(self.tmux_dir)
        self.environment["E2E_MARKER"] = "set-by-the-caller"
        self.records = {}
        self.repos = {}
        self.sentinels = []
        self.add_config("alpha")

    def add_config(self, name):
        records = self.directory / ("records-" + name)
        records.mkdir()
        self.records[name] = records
        self.repos[name] = self.make_repo("repo-" + name)
        directory = self.home / "configs" / name
        (directory / "rules").mkdir(parents=True)
        (directory / "projects").mkdir()
        (directory / "config.toml").write_text(lane_config(name), encoding="utf-8")
        (directory / "rules" / "standing.md").write_text(support.STANDING_RULES.format(name=name), encoding="utf-8")
        (directory / "projects" / "web.toml").write_text(project_text(self.repos[name]), encoding="utf-8")
        return directory

    def env(self, config):
        environment = dict(self.environment)
        environment["E2E_RECORD_DIR"] = str(self.records[config])
        return environment

    def git(self, directory, *arguments, code=0):
        result = subprocess.run(["git", "-C", str(directory), *map(str, arguments)], env=self.environment,
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        if code is not None:
            self.assertEqual(result.returncode, code, "git {}: {}".format(" ".join(map(str, arguments)), result.stderr))
        return result.stdout.strip()

    def make_repo(self, name):
        repo = self.directory / name
        repo.mkdir()
        self.git(repo, "init", "-q", "-b", "trunk")
        self.git(repo, "config", "user.name", "e2e")
        self.git(repo, "config", "user.email", "e2e.invalid")
        self.git(repo, "config", "commit.gpgsign", "false")
        (repo / "README.txt").write_text("An invented repository for the lane tests.\n", encoding="utf-8")
        (repo / "docs").mkdir()
        for index in range(3):
            (repo / "docs" / "note-{}.txt".format(index)).write_text("note {}\n".format(index), encoding="utf-8")
        self.git(repo, "add", "README.txt", "docs")
        self.git(repo, "commit", "-q", "-m", "start")
        return repo

    def paths(self, config="alpha"):
        return self.laneboss_json("config", "path", config, environment=self.env(config))

    def collect(self):
        """Stop every tmux server of the test's configurations (each at the socket its configuration records) and
        below the private socket directory, every recorded stand-in process, and remove the sockets."""
        sockets = sorted(self.tmux_dir.glob("tmux-*/*"))
        for config in self.records:
            try:
                sockets.append(Path(self.paths(config)["socket"]))
            except (AssertionError, KeyError, ValueError):
                pass
        for socket in sockets:
            subprocess.run(["tmux", "-S", str(socket), "kill-server"], env=self.environment, capture_output=True,
                           timeout=30)
            if socket.is_socket():
                socket.unlink()
        for records in self.records.values():
            for path in records.glob("*.helper.json"):
                try:
                    os.kill(json.loads(path.read_text(encoding="utf-8"))["worker"], signal.SIGKILL)
                except (OSError, ValueError, KeyError):
                    pass
        for records in self.records.values():
            for path in records.glob("*.json"):
                try:
                    record = json.loads(path.read_text(encoding="utf-8"))
                    pids = [record["pid"]] + record["children"]
                except (ValueError, KeyError):
                    continue
                for pid in pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
        for pid in self.sentinels:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        # A safety net for a failed test: every process whose command line names this test's private directory (its
        # supervising processes and stand-ins) is stopped, so nothing of it outlives the test.
        listing = subprocess.run(["ps", "-A", "-o", "pid=", "-o", "args="], capture_output=True, text=True)
        for line in listing.stdout.splitlines():
            pid, _, arguments = line.strip().partition(" ")
            if pid.isdigit() and int(pid) != os.getpid() and str(self.directory) in arguments:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except OSError:
                    pass
        shutil.rmtree(str(self.tmux_dir), ignore_errors=True)

    def sentinel(self):
        """An unrelated process the launcher must never signal; the test kills it when it ends."""
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        self.sentinels.append(process.pid)

        def end():
            process.kill()
            process.wait()

        self.addCleanup(end)
        return process

    def hold_store(self, config="alpha"):
        """Hold the store's write lock (BEGIN IMMEDIATE) from this test process; release() ends it."""
        connection = sqlite3.connect(self.paths(config)["store"], timeout=30, isolation_level=None)
        connection.execute("BEGIN IMMEDIATE")
        held = [True]

        def release():
            if held:
                held.clear()
                connection.execute("ROLLBACK")
                connection.close()

        self.addCleanup(release)
        return release

    def run_record_path(self, lane, config="alpha"):
        launch = self.status(lane, config=config)["live"]["launch"]
        return Path(self.paths(config)["state_dir"]) / "lanes" / lane / "runs" / (launch + ".json")

    def go(self, lane, config="alpha"):
        (self.records[config] / (lane + ".go")).write_text("go\n", encoding="utf-8")

    def lane(self, action, *arguments, config="alpha", code=0):
        return self.run_laneboss("lane", action, "--config", config, *arguments, code=code, environment=self.env(config))

    def lane_json(self, action, *arguments, config="alpha"):
        return json.loads(self.lane(action, *arguments, config=config).stdout)

    def brief(self, name, text=None):
        directory = self.directory / "briefs"
        directory.mkdir(exist_ok=True)
        path = directory / (name + ".md")
        path.write_text(text if text is not None else "# Brief {}\n\nAn invented task for the stand-in.\n".format(name),
                        encoding="utf-8")
        return path

    def start(self, lane, *arguments, config="alpha", code=0, text=None):
        result = self.lane("start", "--lane", lane, "--brief", self.brief(config + "-" + lane, text), *arguments,
                           config=config, code=code)
        return json.loads(result.stdout) if code == 0 else result

    def scratch(self, name):
        path = self.directory / "work" / name
        path.mkdir(parents=True)
        return path

    def follow(self, config="alpha"):
        follower = Follower(self.command, config, self.env(config), self.directory)
        self.addCleanup(follower.stop)
        return follower

    def events(self, config="alpha"):
        return self.laneboss_json("state", "events", "--config", config, environment=self.env(config))

    def lane_events(self, lane, kind=None, config="alpha"):
        return [item for item in self.events(config) if item["lane"] == lane and (kind is None or item["kind"] == kind)]

    def wait_event(self, kind, lane, run=None, config="alpha", timeout=UNTIL):
        deadline = time.monotonic() + timeout
        while True:
            for item in self.lane_events(lane, kind, config):
                if run is None or item["payload"].get("run") == run:
                    return item
            if time.monotonic() > deadline:
                self.fail("no {} event for lane {} within {} s; events: {}".format(
                    kind, lane, timeout, [(item["kind"], item["lane"]) for item in self.events(config)]))
            time.sleep(0.2)

    def record(self, lane, run=1, config="alpha", ended=False, timeout=UNTIL):
        path = self.records[config] / "{}.{}.json".format(lane, run)
        deadline = time.monotonic() + timeout
        while True:
            if path.is_file():
                record = json.loads(path.read_text(encoding="utf-8"))
                if record.get("children") is not None and (not ended or record["ended"] is not None):
                    if record["mode"] not in ("forever", "stubborn") or record["children"]:
                        return record
            if time.monotonic() > deadline:
                self.fail("the stand-in left no record {} within {} s".format(path.name, timeout))
            time.sleep(0.1)

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
                self.fail("processes of the run are still alive: {}".format(living))
            time.sleep(0.1)

    def status(self, lane=None, config="alpha"):
        arguments = ["--lane", lane] if lane else []
        return self.lane_json("status", *arguments, config=config)

    def assert_sound(self, config="alpha"):
        """state verify passes and state rebuild reproduces state lanes byte for byte. A supervising process may
        still record an event while this runs (a run's end follows its processes' end); the two outputs are
        compared only when no event was appended between them, which is the comparison the rule is about."""
        environment = self.env(config)
        verified = self.laneboss_json("state", "verify", "--config", config, environment=environment)
        self.assertIs(verified["ok"], True)
        deadline = time.monotonic() + UNTIL
        while True:
            before = len(self.events(config))
            lanes = self.run_laneboss("state", "lanes", "--config", config, environment=environment).stdout
            rebuilt = self.run_laneboss("state", "rebuild", "--config", config, environment=environment).stdout
            if len(self.events(config)) == before:
                self.assertEqual(rebuilt, lanes)
                return verified
            self.assertLess(time.monotonic(), deadline, "the store kept changing while it was checked")
            time.sleep(0.5)

    def tmux(self, socket, *arguments, code=0):
        result = subprocess.run(["tmux", "-S", socket, *arguments], env=self.environment, capture_output=True,
                                text=True, timeout=30)
        if code is not None:
            self.assertEqual(result.returncode, code, result.stderr)
        return result

    def kill_supervisor(self, lane, config="alpha"):
        """SIGKILL the lane's supervising process once it has sampled the run's tree a few times; the run goes on."""
        time.sleep(1.0)
        supervisor = self.status(lane, config=config)["live"]["supervisor"]
        self.assertIs(supervisor["alive"], True)
        os.kill(supervisor["pid"], signal.SIGKILL)
        deadline = time.monotonic() + 10
        while self.status(lane, config=config)["live"]["supervisor"]["alive"]:
            self.assertLess(time.monotonic(), deadline, "the supervising process outlived SIGKILL")
            time.sleep(0.2)

    def fake_program(self, name, text):
        """A directory holding one executable shell script `name`, to put in front of PATH: a stand-in for a system
        program (git, ps) that fails, waits or does something first, as the test says."""
        directory = Path(tempfile.mkdtemp(prefix="bin-" + name + "-", dir=str(self.directory)))
        program = directory / name
        program.write_text("#!/bin/sh\n" + text, encoding="utf-8")
        program.chmod(0o755)
        return directory

    def with_path(self, directory, config="alpha", **extra):
        environment = self.env(config)
        environment["PATH"] = str(directory) + os.pathsep + environment.get("PATH", "")
        environment.update(extra)
        return environment

    def denied(self, mode, *arguments, config="alpha"):
        """`laneboss` with some of its process operations denied (tests/e2e/denysignals.py)."""
        return subprocess.run([sys.executable, str(DENY), mode, str(self.command), *map(str, arguments)],
                              cwd=str(self.directory), env=self.env(config), capture_output=True, text=True,
                              encoding="utf-8", timeout=120)

    def classifiers(self):
        """Process ids of classification processes (the supervising process's pattern matching) now running."""
        listing = subprocess.run(["ps", "-A", "-o", "pid=", "-o", "args="], capture_output=True, text=True).stdout
        found = []
        for line in listing.splitlines():
            pid, _, arguments = line.strip().partition(" ")
            if pid.isdigit() and "import json, re, sys" in arguments:
                found.append(int(pid))
        return found

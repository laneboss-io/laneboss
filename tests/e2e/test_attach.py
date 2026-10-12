"""T4, `lane attach` and the runner key `stream` (docs/architecture.md, "The `lane attach` command and the stream
readers" and "The test plan for T2 to T5").

The tests run `laneboss lane attach` on a pseudo-terminal, as a person's terminal holds it: the program is a session
leader whose controlling terminal is the pseudo-terminal, so the byte 3 typed here reaches it as SIGINT through the line
discipline, and closing the master hangs it up (SIGHUP). The runner is the stand-in program (tests/e2e/standin.py,
behaviour `streamer`), which plays a script of invented stream lines that each test writes; nothing of the launcher is
replaced. Every expectation is worked out from the design, never by asking the code under test what it would print.

A. the view and the idle display; B. the keyboard; C. what is printed from a stream (mode, cost, text, tools, denials);
D. odd lines and control characters; E. a line that is partly typed; F. the stop path and leaving; G. the key `stream`.
"""

import base64
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import sqlite3
import struct
import subprocess
import sys
import termios
import threading
import time
import types
import unittest

from . import lanesupport, support
from .lanesupport import runner
from .mailsupport import STDIN, TURN_START, TurnTest, turn_config, turn_resume


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


UNTIL = lanesupport.UNTIL
PROMPT = "attach> "
WARNING = "WARNING: approvals are bypassed: the agent may run any command and change any file it can reach."
MODE_LINE = "permission mode (as the agent reports it): "
# A credential shape, made here so that no file of the repository holds one.
TOKEN = "gh" + "p_" + "Z9y8X7w6V5u4T3s2R1q0" + "P9o8N7m6L5k4J3i2"
# What a pseudo-terminal shows besides the text: escape sequences of the terminal's line editing and carriage returns.
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>]")
# The program that makes the pseudo-terminal its controlling terminal and becomes the launcher (same process).
WRAPPER = ("import fcntl, os, sys, termios\n"
           "fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n"
           "os.execv(sys.argv[1], sys.argv[1:])\n")
# The idle display: the lane's last run, how it ended, and how many messages wait.
IDLE = re.compile(r"(?m)^idle: run ([0-9]+) ended with reason (\S+), exit code (\S+), .+ ago; "
                  r"messages waiting: ([0-9]+)")
END = r"\[run {} \| exit 0 \| "

# The limit message of a runner that prints JSON is inside a JSON line: its pattern is written for the line as printed.
JSON_PATTERNS = "limit_patterns = ['^\\{.*usage limit reached']\n"
# Runners that play a script in every turn, one that reads its stream as claude-stream-json and one that has no key.
STREAM_RUNNERS = {
    "sjson": runner("sjson", "streamer", TURN_START, None, turn_resume("streamer"),
                    extra=STDIN + 'stream = "claude-stream-json"\n', patterns=JSON_PATTERNS),
    "stext": runner("stext", "streamer", TURN_START, None, turn_resume("streamer"), extra=STDIN),
}


# The invented lines of a stream, in the shapes the design reads (the real trial checks them against a real session).

def line(payload):
    return json.dumps(payload)


def init(mode):
    return line({"type": "system", "subtype": "init", "permissionMode": mode})


def delta(text):
    return line({"type": "stream_event", "event": {"type": "content_block_delta", "index": 0,
                                                    "delta": {"type": "text_delta", "text": text}}})


def whole(text):
    return line({"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}})


def tool(name, command):
    return line({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": name,
                                                               "input": {"command": command}}]}})


def result(cost, denials=(), error=False):
    return line({"type": "result", "subtype": "success", "is_error": error, "total_cost_usd": cost,
                 "permission_denials": list(denials)})


def denial(name, **tool_input):
    return {"tool_name": name, "tool_input": tool_input}


def cost_line(run, turn, session):
    """The end line of a run of a stream that has a cost; `turn` and `session` are the amounts as printed."""
    return re.compile(r"\[run {} \| exit 0 \| this turn {} \| session {} \| [0-9.]+ seconds\]".format(
        run, re.escape(turn), re.escape(session)))


def bookkeeping(subtype, **fields):
    """A `system` line of the shape that a real session prints, with made-up values (the real trial of attach)."""
    return line(dict({"type": "system", "subtype": subtype, "session_id": "sess-made-up", "uuid": "uuid-made-up"},
                     **fields))


def rate_limit(status):
    return line({"type": "rate_limit_event", "rate_limit_info": {"status": status, "rateLimitType": "five_hour"},
                 "uuid": "uuid-made-up", "session_id": "sess-made-up"})


def tool_result(content, error=False):
    return line({"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "content": content, "is_error": error, "tool_use_id": "toolu_made_up"}]},
                 "parent_tool_use_id": None, "session_id": "sess-made-up", "uuid": "uuid-made-up"})


def printed(*lines):
    """Steps of a script that print these lines."""
    return [{"print": item} for item in lines]


def raw_bytes(data):
    """A step of a script that writes these bytes as they are."""
    return {"bytes": base64.b64encode(data).decode("ascii")}


def children_of(pid):
    """Process ids whose parent is this process."""
    listing = subprocess.run(["ps", "-A", "-o", "pid=", "-o", "ppid="], capture_output=True, text=True).stdout
    found = []
    for item in listing.splitlines():
        parts = item.split()
        if len(parts) == 2 and parts[1] == str(pid):
            found.append(int(parts[0]))
    return found


class Terminal:
    """A program on a pseudo-terminal. Everything it writes is kept; text() is that output as a person reads it."""

    def __init__(self, test, arguments, environment, directory, echo=True):
        self.test = test
        self.master, slave = pty.openpty()
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
        if not echo:  # a terminal that does not echo: the line editor then writes nothing for a typed line
            attributes = termios.tcgetattr(slave)
            attributes[3] &= ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, attributes)
        self.slave_name = os.ttyname(slave)
        self.process = subprocess.Popen([sys.executable, "-I", "-c", WRAPPER] + [str(item) for item in arguments],
                                        stdin=slave, stdout=slave, stderr=slave, cwd=str(directory),
                                        env=dict(environment, TERM="xterm"), start_new_session=True, close_fds=True)
        os.close(slave)
        self.buffer = b""
        self.closed = False
        self.paused = threading.Event()
        self.condition = threading.Condition()
        self.stop_pump = threading.Event()
        self.pump = threading.Thread(target=self.pump_output, daemon=True)
        self.pump.start()
        test.addCleanup(self.close)

    def pump_output(self):
        while not self.stop_pump.is_set():
            if self.paused.is_set():
                time.sleep(0.02)
                continue
            try:
                ready = select.select([self.master], [], [], 0.1)[0]
                if not ready:
                    continue
                data = os.read(self.master, 65536)
            except OSError:  # every holder of the other side has gone
                break
            if not data:
                break
            with self.condition:
                self.buffer += data
                self.condition.notify_all()
        with self.condition:
            self.closed = True
            self.condition.notify_all()

    def raw(self):
        return self.buffer

    def mark(self):
        return len(self.buffer)

    def text(self, after=0):
        data = self.buffer[after:].decode("utf-8", "replace")
        return ANSI.sub("", data.replace("\r", "").replace("\x08", ""))

    def state(self):
        code = self.process.poll()
        return "is still running" if code is None else "exited with code {}".format(code)

    def until(self, check, after=0, timeout=UNTIL):
        """The text from `after` on once check(text) holds, or None when the wait runs out. Nothing fails here, so that a
        caller can act (send a key again, for one) and then wait again; the waiting rule is the one of `wait_until`."""
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                found = self.text(after)
                if check(found):
                    return found
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.closed:
                    return None
                self.condition.wait(min(remaining, 0.5))

    def wait_until(self, check, what, after=0, timeout=UNTIL):
        """The text from `after` on, once check(text) holds; the test fails with what it was waiting for."""
        found = self.until(check, after, timeout)
        if found is None:
            self.test.fail("{} did not appear within {} s; the program {}; the terminal shows:\n{}".format(
                what, timeout, self.state(), self.text(after)[-3000:]))
        return found

    def wait_for(self, needle, after=0, timeout=UNTIL):
        """The text from `after` on, once it holds `needle` (a string or a compiled pattern)."""
        if hasattr(needle, "search"):
            return self.wait_until(needle.search, repr(needle.pattern), after, timeout)
        return self.wait_until(lambda found: needle in found, repr(needle), after, timeout)

    def seen(self, needle, after=0, timeout=UNTIL):
        """The text from `after` on once it holds `needle` (a string or a compiled pattern), or None when the wait runs
        out: for a key that may have to be sent a second time, which is what `wait_for` never is."""
        if hasattr(needle, "search"):
            return self.until(needle.search, after, timeout)
        return self.until(lambda found: needle in found, after, timeout)

    def wait_count(self, needle, count, after=0, timeout=UNTIL):
        return self.wait_until(lambda found: found.count(needle) >= count, "{!r} {} times".format(needle, count),
                               after, timeout)

    def wait_prompt(self, after=0, timeout=UNTIL):
        """The text from `after` on, once it ends with the prompt: attach waits for a line."""
        return self.wait_until(lambda found: found.endswith(PROMPT), "the prompt at the end", after, timeout)

    def send(self, data):
        os.write(self.master, data if isinstance(data, bytes) else data.encode("utf-8"))

    def type(self, text):
        """Type a line and press Enter."""
        self.send(text + "\r")

    def ctrl_c(self):
        self.send(b"\x03")

    def pause(self):
        """Read nothing more of what the program writes: its writes fill the terminal's buffer, and then they block."""
        self.paused.set()

    def resume(self):
        self.paused.clear()

    def flow(self, action):
        """Stop (termios.TCOOFF) or start (termios.TCOON) the terminal's output, as a terminal that has sent XOFF or
        XON does: while it is stopped every write of the program blocks at once, and what is in the buffer stays."""
        descriptor = os.open(self.slave_name, os.O_RDWR | os.O_NOCTTY)
        try:
            termios.tcflow(descriptor, action)
        finally:
            os.close(descriptor)

    def hangup(self):
        """Close the terminal: the program gets SIGHUP."""
        self.stop_pump.set()
        self.pump.join(5)
        os.close(self.master)
        self.master = -1

    def wait_exit(self, timeout=UNTIL):
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.test.fail("the program did not leave within {} s; the terminal shows:\n{}".format(
                timeout, self.text()[-3000:]))

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        self.stop_pump.set()
        self.pump.join(5)
        if self.master >= 0:
            os.close(self.master)
            self.master = -1


class AttachTest(TurnTest):
    """The lane tests' configuration `alpha` with the runners that take turns, and runners that play scripts."""

    # The scripted runners of the configuration. `sjson` has the key `stream`: a class lists it only if it needs it.
    runners = ("stext",)

    def add_config(self, name):
        directory = super().add_config(name)
        overrides = {key: STREAM_RUNNERS[key] for key in self.runners}
        (directory / "config.toml").write_text(turn_config(name, overrides=overrides), encoding="utf-8")
        return directory

    def script(self, lane, run, steps):
        """What the stand-in prints in this run of this lane (read when the run starts)."""
        (self.records["alpha"] / "{}.{}.script".format(lane, run)).write_text(json.dumps(steps), encoding="utf-8")

    def trigger(self, lane, name):
        """Let a script go past its {"wait": name} step."""
        (self.records["alpha"] / "{}.{}".format(lane, name)).write_text("go\n", encoding="utf-8")

    def idle_lane(self, lane, runner_name="stext"):
        """A turn-based lane whose first run has ended."""
        started = self.turn_start(lane, runner_name)
        self.settle(lane, 1)
        return started

    def attach(self, lane, config="alpha", echo=True):
        """`laneboss lane attach` on a pseudo-terminal, once it shows its first prompt."""
        terminal = Terminal(self, [self.command, "lane", "attach", "--config", config, "--lane", lane],
                            self.env(config), self.directory, echo=echo)
        terminal.wait_for(PROMPT)
        return terminal

    # A Ctrl-C at the prompt is not always acted on. What was seen on the box: with a line typed and its echo already on
    # the screen, one Ctrl-C printed nothing for 30 s while attach kept running (int23, twice). No run has shown what a
    # later key does; the retry below rests on the reading that follows. CPython's readline runs Python signal handlers
    # only when its `select()` is interrupted, so a SIGINT that lands while the editor is reading the line and drawing its
    # echo does not interrupt `select()`, and attach's handler (`Attach.pressed`, src/laneboss/attach.py) does not run
    # until a later signal interrupts it or the line is entered: nothing is printed and attach stays at its prompt. A
    # later key interrupts `select()` with the prompt armed and is acted on at once. That is the reading that fits what
    # was seen; it is not proven here, and the prompt-draw window the
    # design names (docs/architecture.md, "A key while attach is busy", the bullet "The prompt that is being drawn";
    # `Attach.at_prompt`, whose `finally` arms the prompt again, src/laneboss/attach.py:695-696) may or may not cover this
    # key as well. A test that types a line, presses Ctrl-C once and waits therefore rests on where the key lands, which is
    # what a test must not rest on. So the line is typed once, and the key is pressed again a bounded number of times,
    # without typing again, until the line the key asks for is on the screen: a later key finds the editor waiting and is
    # acted on at once, the line is still there (neither a counted key nor a lost signal touches the editor's buffer), and
    # if it were gone the hint would not claim a discard, so the test would fail, as it should. The line is never retyped
    # between keys: a retry key would then be sent at the same moment as the key that failed, and a key that silently
    # emptied the line would be forgiven by the next one. The last wait is the test's own, so a line that never comes fails
    # with the terminal as it is. Nothing here decides what the line says.
    KEY_TRIES = 3
    KEY_WAIT = 3

    def ctrl_c_at_the_prompt(self, terminal, needle, line, after=0):
        """`line` typed at the prompt once, then Ctrl-C, at most KEY_TRIES times, KEY_WAIT seconds apart, until `needle` is
        on the screen; the text from `after` on. The line is not typed again between keys."""
        self.line_at_the_prompt(terminal, line)
        for _ in range(self.KEY_TRIES - 1):
            terminal.ctrl_c()
            shown = terminal.seen(needle, after=after, timeout=self.KEY_WAIT)
            if shown is not None:
                return shown
        terminal.ctrl_c()
        return terminal.wait_for(needle, after=after)

    @staticmethod
    def line_at_the_prompt(terminal, line):
        """The line typed at the prompt, once the line editor has echoed it: the prompt holds it then."""
        echo = terminal.mark()
        terminal.send(line)
        terminal.wait_until(lambda found: line in found, "the echo of the line at the prompt", after=echo)

    def mail_texts(self, lane):
        """The bytes of the lane's message files, in sequence order."""
        directory = self.mail_directory(lane)
        return [path.read_bytes() for path in sorted(directory.iterdir())] if directory.is_dir() else []

    def ended_runs(self, lane):
        return [item["payload"]["run"] for item in self.lane_events(lane, "lane.ended")]

    def wait_log(self, lane, needle, timeout=UNTIL):
        """Wait until the lane's own log (`output.log`) holds these bytes: what the runner wrote is there to be read."""
        path = Path(self.paths()["state_dir"]) / "lanes" / lane / "output.log"
        deadline = time.monotonic() + timeout
        while needle not in (path.read_bytes() if path.is_file() else b""):
            self.assertLess(time.monotonic(), deadline, "{!r} is not in {} after {} s".format(needle, path, timeout))
            time.sleep(0.1)

    def probe_store(self):
        """Take the store's exclusive lock and give it back at once, without waiting: sqlite3.OperationalError if another
        connection holds any lock of the store (a query of attach that is stopped holds a shared one)."""
        connection = sqlite3.connect(str(Path(self.paths()["state_dir"]) / "events.sqlite"), timeout=0,
                                     isolation_level=None)
        try:
            connection.execute("BEGIN EXCLUSIVE")
            connection.execute("ROLLBACK")
        finally:
            connection.close()

    def freeze(self, process):
        """Stop attach (SIGSTOP) at a moment when it holds no lock of the state directory and none of the store: its
        follower holds the shared lock of the directory for a few milliseconds at each look, and its queries hold a
        shared lock of the store, and a lane command of the test could not write while a stopped attach held either.
        `process.send_signal(signal.SIGCONT)` lets it go on."""
        directory = os.open(str(Path(self.paths()["state_dir"])), os.O_RDONLY)
        try:
            for _ in range(200):
                process.send_signal(signal.SIGSTOP)
                deadline = time.monotonic() + 5
                while not subprocess.run(["ps", "-o", "stat=", "-p", str(process.pid)], capture_output=True,
                                         text=True).stdout.strip().startswith("T"):
                    self.assertLess(time.monotonic(), deadline, "attach did not stop")
                    time.sleep(0.01)
                try:
                    fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    try:
                        self.probe_store()
                    finally:
                        fcntl.flock(directory, fcntl.LOCK_UN)
                except (BlockingIOError, sqlite3.OperationalError):  # inside a look: let it finish, and try again
                    process.send_signal(signal.SIGCONT)
                    time.sleep(0.03)
                    continue
                return
            self.fail("attach could not be stopped at a moment when it held no lock of the state directory or the store")
        finally:
            os.close(directory)

    def hold_flock(self, path, what):
        """Hold the exclusive flock of a directory of the state from this test, as the launcher's own locks of it are
        held. The returned function frees it (it is also freed when the test ends)."""
        descriptor = os.open(str(path), os.O_RDONLY)
        deadline = time.monotonic() + UNTIL
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:  # a look of attach, or an append of a lane command, holds it for a moment
                self.assertLess(time.monotonic(), deadline, "{} was never free".format(what))
                time.sleep(0.01)
        held = [True]

        def release():
            if held:
                held.clear()
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

        self.addCleanup(release)
        return release

    def hold_state_lock(self):
        """Hold the state directory's lock exclusively from this test: every lane command, and every look of attach at
        the store, waits for it, and the test must read nothing of the store while it holds it."""
        return self.hold_flock(Path(self.paths()["state_dir"]), "the state directory's lock")

    def hold_lane_directory(self, lane):
        """Hold the lock of the lane's directory from this test. The first step of every append of a lane event takes it
        (`pending.append_after`: lane send, and the lane.resumed and lane.started of a supervising process), and no step
        that a lane turn takes before its run begins does, so a turn that is asked for starts its supervising process,
        which then waits for the lock, and `lane turn` waits for lane.started."""
        return self.hold_flock(Path(self.paths()["state_dir"]) / "lanes" / lane, "the lane directory's lock")

    def wait_begun(self, lane, runs):
        """Wait until `lane turn` has started the supervising process of a run: `runs` run records exist (the one of the
        run is written once the process is started) and the FIFO that hands the process its description is gone, so
        `lane turn` has let go of the lanes lock and waits for lane.started."""
        directory = Path(self.paths()["state_dir"]) / "lanes" / lane
        deadline = time.monotonic() + UNTIL
        while True:
            if len(list((directory / "runs").glob("*.json"))) >= runs and not list(directory.glob(".launch-*.fifo")):
                return
            self.assertLess(time.monotonic(), deadline, "lane turn never started the supervising process")
            time.sleep(0.01)

    def hold_lanes_lock(self):
        """Hold the configuration's lanes lock (`lanes.lock` in the state directory) from this test, as a lane command
        that is busy holds it: a `lane turn` of attach then waits for it. The returned function frees it (it is also
        freed when the test ends)."""
        descriptor = os.open(str(Path(self.paths()["state_dir"]) / "lanes.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        held = [True]

        def release():
            if held:
                held.clear()
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

        self.addCleanup(release)
        return release

    def played(self, lane, steps, runner_name="sjson", text="go\n"):
        """A lane whose run 1 has ended and whose run 2 has played these steps for one message and ended."""
        self.idle_lane(lane, runner_name)
        self.script(lane, 2, steps)
        self.sent(lane, text)
        self.turn_json(lane)
        self.settle(lane, 2, "lane.delivered")


class ViewTest(AttachTest):
    """A. The view: the header, a live turn, the idle display, a lane that is not turn-based, an unknown lane."""

    def test_header_and_idle_display(self):
        lane = "v-idle"
        started = self.idle_lane(lane)
        self.sent(lane, "A message that waits.\n")
        row = self.status(lane)
        self.assertEqual((row["idle"], row["state"], row["mail"]["waiting"]), (True, "waiting", [1]))
        terminal = self.attach(lane)
        text = terminal.text()
        self.assertIn("lane {}: state waiting, run 1, session {}, runner stext, model stext-model-1".format(
            lane, started["session_id"]), text)
        found = IDLE.search(text)
        self.assertIsNotNone(found, text)
        self.assertEqual(found.groups(), (str(row["run"]), row["reason"], str(row["exit_code"]),
                                         str(len(row["mail"]["waiting"]) + len(row["mail"]["returned"]))))
        self.assertIn("/turn", text)

    def test_idle_display_after_a_failed_turn(self):
        lane = "v-fail"
        self.idle_lane(lane, "tfail")
        self.sent(lane, "This turn fails.\n")
        self.turn_json(lane)
        self.settle(lane, 2, "lane.returned")
        row = self.status(lane)
        self.assertEqual((row["idle"], row["reason"], row["exit_code"], row["mail"]["returned"]),
                         (True, "exit", 3, [1]))
        found = IDLE.search(self.attach(lane).text())
        self.assertIsNotNone(found)
        self.assertEqual(found.groups(), ("2", "exit", "3", "1"))

    def test_live_turn_is_followed_to_its_end(self):
        lane = "v-live"
        self.idle_lane(lane)
        self.script(lane, 2, printed("live-first") + [{"wait": "g1"}] + [raw_bytes(b"live-tail-without-newline")])
        self.sent(lane, "Start a turn.\n")
        self.turn_json(lane)
        self.record(lane, run=2)
        row = self.status(lane)
        self.assertEqual((row["running"], row["idle"]), (True, False))
        terminal = self.attach(lane)
        text = terminal.wait_for("live-first")
        self.assertIn("state running, run 2", text)
        self.assertNotIn("standin: streamer {} run 1".format(lane), text)  # the run's own part of the log only
        self.assertIsNone(IDLE.search(text))  # a lane that runs is not idle
        self.trigger(lane, "g1")
        text = terminal.wait_for(IDLE)
        self.assertLess(text.index("live-tail-without-newline"), text.index("[run 2 | exit 0 | "))
        self.assertLess(text.index("[run 2 | exit 0 | "), text.index("idle: run 2 ended"))
        self.settle(lane, 2, "lane.delivered")
        row = self.status(lane)
        self.assertEqual(IDLE.search(text).groups(), ("2", row["reason"], str(row["exit_code"]), "0"))

    def test_two_short_turns_from_outside(self):
        # N8: two turns that `lane turn` starts from outside while attach is on the lane but cannot look at the store
        # (attach is stopped with SIGSTOP, so both turns begin and end between two of its looks, as no timing could make
        # them): when it goes on, it shows both, each end line in its turn.
        lane = "v-two"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        mark = terminal.mark()
        self.freeze(terminal.process)
        for run, text in ((2, "one\n"), (3, "two\n")):
            self.sent(lane, text)
            self.turn_json(lane)
            self.settle(lane, run, "lane.delivered")
        terminal.process.send_signal(signal.SIGCONT)
        shown = terminal.wait_for(re.compile(r"\[run 3 \| exit 0 \| [0-9.]+ seconds\]"), after=mark)
        first = re.search(r"\[run 2 \| exit 0 \| [0-9.]+ seconds\]", shown)
        second = re.search(r"\[run 3 \| exit 0 \| [0-9.]+ seconds\]", shown)
        self.assertIsNotNone(first, shown)
        self.assertLess(first.start(), second.start())

    def test_lane_that_is_not_turn_based(self):
        lane = "v-plain"
        self.plain_start(lane, "tok")
        self.settle(lane, 1)
        terminal = self.attach(lane)
        text = terminal.text()
        self.assertIn("state verifying", text)
        self.assertIn("not turn-based", text)
        self.assertIn("view only", text)
        self.assertIsNone(IDLE.search(text))
        mark = terminal.mark()
        terminal.type("Is anybody there?")
        text = terminal.wait_for("not sent", after=mark)
        self.assertIn("not turn-based", text)
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])

    def test_unknown_lane_is_refused(self):
        result = self.run_laneboss("lane", "attach", "--config", "alpha", "--lane", "no-such-lane", code=2,
                                   environment=self.env("alpha"), stdin="")
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.strip(), "refused: lane no-such-lane is not known to configuration alpha")


class KeyboardTest(AttachTest):
    """B. A typed line is mail and a turn; commands; queued lines; refusals printed."""

    def test_typed_line_is_mail_and_a_turn(self):
        lane = "k-line"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        self.assertEqual(children_of(terminal.process.pid), [])  # attach starts no agent and keeps no child
        self.assertEqual(len(self.lane_events(lane, "lane.started")), 1)
        typed = "please read the plan"
        terminal.type(typed)
        started = self.wait_event("lane.started", lane, run=2)
        self.assertEqual(started["payload"]["mail"], [1])
        mailed = self.lane_events(lane, "lane.mailed")
        self.assertEqual([(item["payload"]["sequence"], item["payload"]["sender"], item["payload"]["bytes"])
                          for item in mailed], [(1, "attach", len(typed))])
        self.assertEqual(self.mail_texts(lane), [typed.encode("utf-8")])
        terminal.wait_for("standin: streamer {} run 2".format(lane))
        self.settle(lane, 2, "lane.delivered")
        stdin = self.stdin_of(lane, 2)
        self.assertIn(typed, stdin)
        self.assertIn("from attach at", stdin)
        terminal.wait_for(re.compile(END.format(2)))
        self.assertEqual(children_of(terminal.process.pid), [])

    def test_continued_line_and_empty_line(self):
        lane = "k-cont"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("")  # an empty line is ignored
        terminal.wait_for(PROMPT, after=mark)
        self.assertNotIn("not sent", terminal.text(mark))
        terminal.send("first part\\\r")  # a backslash at the end continues on the next line
        terminal.wait_for("... ")
        terminal.type("second part")
        self.wait_event("lane.started", lane, run=2)
        self.assertEqual(self.mail_texts(lane), [b"first part\nsecond part"])
        self.assertEqual([item["payload"]["sequence"] for item in self.lane_events(lane, "lane.mailed")], [1])

    def test_slash_lines_and_help(self):
        lane = "k-slash"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("/help")
        text = terminal.wait_for("/exit", after=mark)
        for command in ("/turn", "/stop", "/help", "/exit"):
            self.assertIn(command, text)
        mark = terminal.mark()
        terminal.type("/bogus")  # a command that does not exist is refused and never sent
        text = terminal.wait_for("not sent", after=mark)
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])
        terminal.type(" /spaced")  # a space first: a message that happens to contain a slash
        self.wait_event("lane.started", lane, run=2)
        self.assertEqual(self.mail_texts(lane), [b" /spaced"])
        self.assertEqual(len(self.lane_events(lane, "lane.mailed")), 1)

    def test_turn_command_takes_waiting_mail(self):
        lane = "k-turn"
        self.idle_lane(lane)
        self.sent(lane, "A message that waits.\n")
        terminal = self.attach(lane)
        self.assertIn("/turn", terminal.text())  # mail waits and no turn is live: attach says so and offers /turn
        self.assertEqual(len(self.lane_events(lane, "lane.started")), 1)
        terminal.type("/turn")
        started = self.wait_event("lane.started", lane, run=2)
        self.assertEqual(started["payload"]["mail"], [1])

    def test_line_during_a_live_turn_is_queued(self):
        lane = "k-queue"
        self.idle_lane(lane, "twait")
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("first")
        self.wait_event("lane.started", lane, run=2)
        terminal.wait_for("standin: waiter {} run 2".format(lane), after=mark)
        terminal.wait_prompt(after=mark)
        mark = terminal.mark()
        terminal.type("second")
        text = terminal.wait_for(re.compile(r"message 2 queued"), after=mark)
        self.assertNotIn("turn started", text)
        self.assertEqual(len(self.lane_events(lane, "lane.started")), 2)  # no second turn
        self.assertEqual([item["payload"]["sequence"] for item in self.lane_events(lane, "lane.mailed")], [1, 2])
        self.go(lane)  # the live turn ends; the second message waits
        text = terminal.wait_for("messages waiting: 1", after=mark)
        self.assertIn("/turn", text)
        self.settle(lane, 2, "lane.delivered")
        terminal.type("/turn")
        self.assertEqual(self.wait_event("lane.started", lane, run=3)["payload"]["mail"], [2])

    def test_refused_line_is_printed_and_held(self):
        lane = "k-held"
        self.idle_lane(lane)
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")  # a lane that cannot take mail
        self.assertTrue(importlib.util.find_spec("readline"), "this interpreter has no readline")
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("hello there")
        text = terminal.wait_for("your line: hello there", after=mark)
        self.assertIn("not sent: lane {} is abandoned".format(lane), text)
        terminal.type("")  # Enter at the next prompt sends the line it holds, which is refused again
        terminal.wait_count("not sent: lane {} is abandoned".format(lane), 2, after=mark)
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])

    def test_credential_line_not_repeated(self):
        lane = "k-secret"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("the key is " + TOKEN + " now")
        text = terminal.wait_for("looks like a credential", after=mark)
        self.assertIn("not sent", text)
        self.assertLessEqual(text.count(TOKEN), 1)  # the terminal's own echo of what was typed, and nothing more
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])
        self.assertEqual(self.mail_texts(lane), [])

    def test_slash_credential_not_repeated(self):
        # F4: a line that starts with a slash is refused as no command, and a credential shape in it is not repeated.
        lane = "k-slashtok"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("/" + TOKEN)
        text = terminal.wait_for("not sent", after=mark)
        self.assertLessEqual(text.count(TOKEN), 1)  # the terminal's own echo of what was typed, and nothing more
        self.assertIn("credential shape", text)  # the refusal says why, without the value
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])
        self.assertEqual(self.mail_texts(lane), [])

    def test_ctrl_c_at_an_empty_prompt(self):
        # Finding 2 of the real trial: with nothing typed and no turn live, Ctrl-C discards nothing, and the hint says only
        # what holds. A line was entered before, so that a line editor that keeps the bytes of the last line would show.
        # (On the box the line editor is GNU readline; on macOS it is libedit, whose decision LineEditorTest tests.)
        lane = "k-empty"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("first line")
        terminal.wait_for(re.compile(END.format(2)), after=mark)  # the turn that it started has ended: none is live
        self.settle(lane, 2, "lane.delivered")
        terminal.wait_prompt(after=mark)
        mark = terminal.mark()
        terminal.ctrl_c()
        text = terminal.wait_for("/exit", after=mark)  # the hint says how to leave
        self.assertIn("nothing was stopped", text)
        self.assertNotIn("discarded", text)
        self.assertIsNone(terminal.process.poll())  # nothing left

    def test_ctrl_c_at_the_prompt_is_a_hint(self):
        lane = "k-hint"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        mark = terminal.mark()
        text = self.ctrl_c_at_the_prompt(terminal, "/exit", "discarded-text", after=mark)  # the hint says how to leave
        self.assertIn("was discarded", text)
        terminal.type("after the hint")
        self.wait_event("lane.started", lane, run=2)
        self.assertEqual(self.mail_texts(lane), [b"after the hint"])  # what was discarded is not sent
        self.assertIsNone(terminal.process.poll())  # nothing left


class ModeTest(AttachTest):
    """C1. The permission mode the agent reports, and the plain warning on bypass."""

    runners = ("stext", "sjson")

    def test_bypass_warns_in_plain_text(self):
        lane = "m-bypass"
        self.played(lane, printed(init("bypassPermissions"), delta("hi")))
        text = self.attach(lane).text()
        self.assertIn(MODE_LINE + "bypassPermissions", text)
        self.assertIn(WARNING, text)

    def test_other_mode_has_no_warning(self):
        lane = "m-edits"
        self.played(lane, printed(init("acceptEdits")))
        text = self.attach(lane).text()
        self.assertIn(MODE_LINE + "acceptEdits", text)
        self.assertNotIn("WARNING", text)
        self.assertNotIn("not reported yet", text)

    def test_no_init_line_is_not_reported_yet(self):
        lane = "m-none"
        self.idle_lane(lane, "sjson")
        text = self.attach(lane).text()
        self.assertIn("permission mode: not reported yet", text)
        self.assertNotIn(MODE_LINE, text)
        self.assertNotIn("WARNING", text)

    def test_a_new_init_line_prints_again(self):
        lane = "m-again"
        self.played(lane, printed(init("acceptEdits")))
        self.script(lane, 3, printed(init("acceptEdits")))  # the same mode: nothing new
        self.script(lane, 4, printed(init("bypassPermissions")))  # another mode: shown again, with the warning
        terminal = self.attach(lane)
        self.assertEqual(terminal.text().count(MODE_LINE + "acceptEdits"), 1)
        terminal.type("again")
        terminal.wait_for(re.compile(END.format(3)))
        self.settle(lane, 3, "lane.delivered")
        self.assertEqual(terminal.text().count(MODE_LINE + "acceptEdits"), 1)
        self.assertNotIn("WARNING", terminal.text())
        mark = terminal.mark()
        terminal.type("third")
        text = terminal.wait_for(WARNING, after=mark)
        self.assertIn(MODE_LINE + "bypassPermissions", text)


class CostTest(AttachTest):
    """C2. The end line and the cost of a turn."""

    runners = ("stext", "sjson")

    def test_turn_cost_is_a_difference(self):
        lane = "c-diff"
        self.idle_lane(lane, "sjson")
        self.script(lane, 2, printed(init("plan"), delta("A"), whole("A"), result(0.25)))
        self.script(lane, 3, printed(init("plan"), delta("B"), whole("B"), result(0.75)))
        terminal = self.attach(lane)
        terminal.type("one")  # the run before it has no result line: the total alone, "this turn" unknown
        terminal.wait_for(cost_line(2, "unknown", "$0.2500"))
        self.settle(lane, 2, "lane.delivered")
        terminal.type("two")
        terminal.wait_for(cost_line(3, "$0.5000", "$0.7500"))

    def test_bad_earlier_total_is_unknown(self):
        lane = "c-bad"
        self.idle_lane(lane, "sjson")
        self.script(lane, 2, printed(init("plan"), result("not a number")))
        self.script(lane, 3, printed(init("plan"), result(1.0)))
        terminal = self.attach(lane)
        terminal.type("one")
        terminal.wait_for(re.compile(END.format(2)))
        self.settle(lane, 2, "lane.delivered")
        terminal.type("two")
        text = terminal.wait_for(cost_line(3, "unknown", "$1.0000"))
        self.assertNotIn("this turn $", text)

    def test_text_stream_has_no_cost(self):
        lane = "c-text"
        self.idle_lane(lane)
        terminal = self.attach(lane)
        terminal.type("go")
        text = terminal.wait_for(re.compile(r"\[run 2 \| exit 0 \| [0-9.]+ seconds\]"))
        self.assertNotIn("this turn", text)
        self.assertNotIn("session $", text)


class StreamTest(AttachTest):
    """C3. Streamed text, tool labels, the answer that is not shown twice, denials, a limit inside a JSON line."""

    runners = ("stext", "sjson")

    def test_streamed_text_and_tools(self):
        lane = "t-text"
        self.idle_lane(lane, "sjson")
        self.script(lane, 2, printed(init("plan"), delta("Hel"), delta("lo wor"), delta("ld"), whole("Hello world"),
                                     tool("Bash", "ls -la"), whole("Second block"), result(0.1)))
        terminal = self.attach(lane)
        terminal.type("go")
        text = terminal.wait_for(re.compile(END.format(2)))
        self.assertEqual(text.count("Hello world"), 1)  # streamed in pieces, and its whole line is not shown again
        self.assertEqual(text.count("Second block"), 1)  # not streamed: shown from its whole line
        self.assertLess(text.index("Hello world"), text.index("[tool Bash] ls -la"))
        self.assertLess(text.index("[tool Bash] ls -la"), text.index("Second block"))

    def test_bookkeeping_lines_are_quiet(self):
        # The real trial of attach: about fifty lines of the agent program's own bookkeeping were shown raw between the
        # person's line and the answer. They give no item now; a notification is shown as `notice: ...`; a rate limit that
        # is not `allowed`, a notification without text and a line of no known shape stay raw; the mode, the answer, the
        # label and the cost are as before. Every line is made up, of the shape of a real one.
        lane = "t-quiet"
        self.idle_lane(lane, "sjson")
        quiet = [bookkeeping("hook_started", hook_id="hook-made-up", hook_name="Made:up", hook_event="MadeUp"),
                 bookkeeping("hook_response", hook_id="hook-made-up", hook_name="Made:up", hook_event="MadeUp",
                             output="made-up hook output", exit_code=0, outcome="success"),
                 bookkeeping("ui_invalidate", event="ui.render"),
                 bookkeeping("status", status="requesting"),
                 bookkeeping("thinking_tokens", estimated_tokens=50, estimated_tokens_delta=50),
                 bookkeeping("task_started", task_id="task-made-up", description="a made-up task",
                             task_type="local_bash", is_backgrounded=False),
                 bookkeeping("task_notification", task_id="task-made-up", status="failed",
                             summary="a made-up summary", output_file=""),
                 rate_limit("allowed"), tool_result("made-up tool output")]  # (an error result is shown since delta 4)
        shown = [bookkeeping("notification", key="made-up-key", text="Made-up message: press x to see",
                             priority="immediate"),
                 rate_limit("rejected"),
                 bookkeeping("notification", key="made-up-other-key"),
                 bookkeeping("made_up_subtype", detail="made-up")]
        self.script(lane, 2, printed(init("acceptEdits"), *quiet[:4], delta("Hel"), delta("lo"), *quiet[4:],
                                     tool("Bash", "ls -la"), *shown, whole("Hello"), result(0.25)))
        terminal = self.attach(lane)
        terminal.type("go")
        text = terminal.wait_for(cost_line(2, "unknown", "$0.2500"))
        for marker in ("hook_started", "hook_response", "ui_invalidate", "thinking_tokens", "task_started",
                       "task_notification", "requesting", "allowed", "tool_result", "made-up tool output",
                       "made-up hook output", "a made-up summary"):
            self.assertNotIn(marker, text, "a line of bookkeeping reached the screen")
        self.assertEqual(text.count("notice: Made-up message: press x to see"), 1)  # the notification, as a notice
        self.assertEqual(text.count("notice: "), 1)  # and nothing else is one
        self.assertIn('"status": "rejected"', text)  # a rate limit that is not `allowed` is raw
        self.assertIn('"key": "made-up-other-key"', text)  # a notification without text is raw
        self.assertIn('"subtype": "made_up_subtype"', text)  # a line of no known shape is raw
        self.assertIn(MODE_LINE + "acceptEdits", text)
        self.assertEqual(text.count("Hello"), 1)  # streamed in pieces, and its whole line is not shown again
        self.assertLess(text.index("Hello"), text.index("[tool Bash] ls -la"))

    def test_failures_are_shown(self):
        # Delta review 4: a hook that fails and a tool that fails reach the person (the bookkeeping around them does not).
        # A hook that succeeds is as quiet as before. Every line is made up, of the shape of a real one.
        lane = "t-fail"
        self.idle_lane(lane, "sjson")
        hook = dict(hook_id="hook-made-up", hook_name="Made:up", hook_event="MadeUp", output="made-up hook output")
        self.script(lane, 2, printed(init("acceptEdits"),
                                     bookkeeping("hook_response", exit_code=0, outcome="success", **hook),
                                     bookkeeping("hook_response", exit_code=1, outcome="error", **hook),
                                     tool("Bash", "ls -la"), tool_result("made-up error output", error=True),
                                     tool_result("made-up fine output"), whole("Done"), result(0.25)))
        terminal = self.attach(lane)
        terminal.type("go")
        text = terminal.wait_for(cost_line(2, "unknown", "$0.2500"))
        self.assertEqual(text.count("notice: hook Made:up: error (exit 1)"), 1)  # the hook that failed
        self.assertEqual(text.count("notice: "), 1)  # and not the one that succeeded
        self.assertEqual(text.count("[tool error] made-up error output"), 1)  # the tool that failed
        for marker in ("hook_response", "made-up hook output", "tool_result", "made-up fine output"):
            self.assertNotIn(marker, text, "a line of bookkeeping reached the screen")
        self.assertLess(text.index("[tool Bash] ls -la"), text.index("[tool error] made-up error output"))
        self.assertLess(text.index("[tool error] made-up error output"), text.index("Done"))

    def test_denials_are_lines_of_their_own(self):
        lane = "t-deny"
        self.idle_lane(lane, "sjson")
        self.script(lane, 2, printed(init("plan"), result(0.1, [denial("Bash", command="rm -rf /tmp/x"),
                                                                 denial("Write", file_path="/etc/hosts")])))
        self.script(lane, 3, printed(init("plan"), result(0.2, [denial("Bash", command="make clean")])))
        terminal = self.attach(lane)
        terminal.type("one")
        text = terminal.wait_for(re.compile(END.format(2)))
        self.assertRegex(text, r"(?m)^\[denied Bash\] rm -rf /tmp/x$")
        self.assertRegex(text, r"(?m)^\[denied Write\] /etc/hosts$")
        self.assertLess(text.index("[denied Write]"), text.index("[run 2 | "))  # before the end line
        self.assertEqual(text.count("ran without approval rights"), 1)
        self.settle(lane, 2, "lane.delivered")
        terminal.type("two")
        text = terminal.wait_for(re.compile(END.format(3)))
        self.assertRegex(text, r"(?m)^\[denied Bash\] make clean$")
        self.assertEqual(text.count("ran without approval rights"), 1)  # only the first denial of an attach

    def test_limit_message_inside_a_json_line(self):
        lane = "t-limit"
        self.idle_lane(lane, "sjson")
        limit = line({"type": "result", "subtype": "success", "is_error": True,
                      "result": "usage limit reached for this account"})
        self.script(lane, 2, printed(init("plan"), limit))
        self.sent(lane, "This turn meets a limit.\n")
        self.turn_json(lane)
        self.settle(lane, 2, "lane.returned")
        ended = self.lane_events(lane, "lane.ended")[-1]["payload"]
        self.assertEqual((ended["reason"], ended["exit_code"], ended["classification"]), ("limit", 0, "matched"))
        self.assertEqual(self.lane_events(lane, "lane.returned")[-1]["payload"]["reason"], "limit")
        self.assertEqual(self.lane_events(lane, "lane.delivered"), [])
        found = IDLE.search(self.attach(lane).text())
        self.assertIsNotNone(found)
        self.assertEqual(found.groups(), ("2", "limit", "0", "1"))

    def test_limit_pattern_misses_the_line(self):
        # A pattern written for another form of the line no longer matches: the turn counts as delivered.
        lane = "t-nolim"
        self.idle_lane(lane, "sjson")
        quiet = line({"type": "result", "subtype": "success", "is_error": True, "result": "Usage Limit"})
        self.script(lane, 2, printed(init("plan"), quiet))
        self.sent(lane, "This turn meets a limit.\n")
        self.turn_json(lane)
        self.settle(lane, 2, "lane.delivered")
        self.assertEqual(self.lane_events(lane, "lane.ended")[-1]["payload"]["reason"], "exit")


class OddLinesTest(AttachTest):
    """D. Lines of any shape never give a traceback, and no control character of the stream reaches the terminal."""

    runners = ("stext", "sjson")

    def test_odd_lines_never_give_a_traceback(self):
        lane = "o-odd"
        self.idle_lane(lane, "sjson")
        odd = [b"not json at all", b"[1, 2, 3]", b'"a string"', b"42", b"null", b"true", b"{}", b"\x00\x01 nul bytes",
               b'{"type": "assistant", "message": "x"}',
               b'{"type": "assistant", "message": {"content": [null, 1, "s"]}}',
               b'{"type": "result", "total_cost_usd": "x", "is_error": "no", "permission_denials": "nope"}',
               b'{"type": "stream_event", "event": {"type": "content_block_delta", '
               b'"delta": {"type": "text_delta", "text": 5}}}',
               b'{"type": "system", "subtype": "init", "permissionMode": 5}',
               b"[" * 1500 + b"]" * 1500, b'{"a":' * 300 + b"1" + b"}" * 300,
               b'{"type": "x", "v": "' + b"x" * 300000 + b'"}', b"\xff\xfe\x80 not utf-8 \xc3\x28",
               # F3: a cost that no float holds, with a denial in the same line (the guard of `_cost` keeps both), and
               # nesting past the interpreter's limit, a list and an object that has a type (the guard of the parse)
               result(10 ** 400, [denial("Bash", command="make clean-big-cost")]).encode("utf-8"),
               b"[" * 100000 + b"]" * 100000,
               b'{"type": "assistant", "message": ' * 100000 + b"1" + b"}" * 100000]
        self.script(lane, 2, [raw_bytes(item + b"\n") for item in odd] + printed("ODD-DONE-MARKER"))
        terminal = self.attach(lane)
        terminal.type("go")
        text = terminal.wait_for("ODD-DONE-MARKER")
        text = terminal.wait_for(re.compile(END.format(2)))
        self.assertNotIn("Traceback", text)
        self.assertNotIn(b"Traceback", terminal.raw())
        self.assertNotIn("stream reader failed", text)  # no line made the reader raise: a note would say so
        self.assertIn("not json at all", text)  # a line of no known shape is shown, cut and made inert
        self.assertIn("[denied Bash] make clean-big-cost", text)  # the huge cost did not take its line's denial along
        self.assertNotIn("x" * 250, text)  # a huge value is cut
        self.assertIsNone(terminal.process.poll())

    def test_controls_never_reach_the_tty(self):
        lane = "o-ctrl"
        self.idle_lane(lane, "sjson")
        denied = [denial("Bash", command="rm\x1b]0;DENIAL-PWN\x07")]
        self.script(lane, 2, printed(init("plan\x1b]0;MODE-PWN\x07"), delta("\x1b]0;TEXT-PWN\x07shown"),
                                     delta("a\u009b31mb\u0085c\n"), tool("Bash", "ls\x1b[2J\x07TOOL-PWN"),
                                     result(0.1, denied)) + [raw_bytes(b"\x1b]0;RAW-PWN\x07raw-visible\n"),
                                                             raw_bytes(b"\xc2\x9b31mC1-RAW\n")])
        terminal = self.attach(lane)
        terminal.type("go")
        text = terminal.wait_for(re.compile(END.format(2)))
        raw = terminal.raw()
        for marker in (b"\x1b]0;MODE-PWN", b"\x1b]0;TEXT-PWN", b"\x1b]0;DENIAL-PWN", b"\x1b]0;RAW-PWN", b"\x1b[2J",
                       b"\xc2\x9b", b"\xc2\x85", b"\x07"):
            self.assertNotIn(marker, raw)
        for visible in ("MODE-PWN", "TEXT-PWNshown", "TOOL-PWN", "DENIAL-PWN", "raw-visible", "C1-RAW", "a31mbc"):
            self.assertIn(visible, text)


class PartlyTypedTest(AttachTest):
    """E. Output is held back while a line is being typed, and goes above the prompt when none is."""

    def setUp(self):
        super().setUp()
        self.assertTrue(importlib.util.find_spec("readline"), "this interpreter has no readline")

    def live(self, lane):
        """A lane whose turn 2, started by attach, prints, waits for g1, prints two lines, waits for g2 and ends."""
        self.idle_lane(lane)
        self.script(lane, 2, printed("hold-first") + [{"wait": "g1"}] + printed("held-A", "held-B") + [{"wait": "g2"}])
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("start")
        terminal.wait_for("hold-first", after=mark)
        terminal.wait_prompt(after=mark)  # the turn is live and attach waits for a line
        return terminal

    def test_output_held_while_typing(self):
        lane = "e-hold"
        terminal = self.live(lane)
        mark = terminal.mark()
        terminal.send("partial-typed")  # no Enter
        terminal.wait_for("partial-typed", after=mark)
        self.trigger(lane, "g1")
        self.wait_log(lane, b"held-B")  # the stand-in has written both lines
        time.sleep(1.5)  # the log is polled every 0.2 s and the store every 0.5 s: a shown line would be here by now
        self.assertNotIn("held-A", terminal.text(mark))
        terminal.send("\r")  # the line is entered
        text = terminal.wait_for(re.compile("held-B.*" + re.escape(PROMPT), re.S), after=mark)  # then the prompt
        self.assertLess(text.index("held-A"), text.index("held-B"))
        terminal.wait_for("message 2 queued", after=mark)  # the entered line was sent, and queued behind the live turn
        self.assertEqual(self.mail_texts(lane), [b"start", b"partial-typed"])  # sent whole
        self.trigger(lane, "g2")

    def test_output_held_until_discarded(self):
        lane = "e-drop"
        terminal = self.live(lane)
        mark = terminal.mark()
        terminal.send("discard-me")
        terminal.wait_for("discard-me", after=mark)
        self.trigger(lane, "g1")
        self.wait_log(lane, b"held-B")  # the stand-in has written both lines
        time.sleep(1.5)
        self.assertNotIn("held-A", terminal.text(mark))
        terminal.send(b"\x15")  # Ctrl-U: the line is discarded
        text = terminal.wait_for("held-B", after=mark)
        self.assertLess(text.index("held-A"), text.index("held-B"))
        self.assertEqual(self.mail_texts(lane), [b"start"])
        self.trigger(lane, "g2")

    def test_output_above_an_empty_prompt(self):
        lane = "e-above"
        terminal = self.live(lane)
        mark = terminal.mark()
        self.trigger(lane, "g1")
        text = terminal.wait_for(re.compile("held-B.*" + re.escape(PROMPT), re.S), after=mark)  # at once, no Enter
        self.assertLess(text.index("held-A"), text.index("held-B"))  # and the prompt is shown again below it
        self.trigger(lane, "g2")


class StopTest(AttachTest):
    """F. The stop path and leaving: Ctrl-C stops only the turn this attach started, and leaving stops nothing."""

    def test_ctrl_c_stops_own_turn_only(self):
        lane, other = "s-own", "s-other"
        self.idle_lane(lane, "tstubborn")
        bystander = self.running_turn(other, ["x"], "tforever")  # a turn of another lane, live all the time
        sentinel = self.sentinel()
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("go")
        self.wait_event("lane.started", lane, run=2)
        record = self.record(lane, run=2)  # the runner, a child, and one that has a session of its own
        terminal.wait_for("standin: stubborn {} run 2".format(lane), after=mark)
        terminal.wait_prompt(after=mark)
        self.assertEqual(children_of(terminal.process.pid), [])
        mark = terminal.mark()
        terminal.ctrl_c()
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["survivors"]), ("stopped", 0))
        self.assert_gone([record["pid"]] + record["children"])
        text = terminal.wait_for("survivors 0", after=mark)
        self.assertIn("stopping run 2", text)
        self.settle(lane, 2, "lane.returned")
        self.assertEqual(self.status(lane)["mail"]["returned"], [1])  # the mail of that turn returns
        self.assertTrue(self.alive(bystander["pid"]))
        self.assertTrue(all(self.alive(pid) for pid in bystander["children"]))
        self.assertEqual(self.ended_runs(other), [1])
        self.assertIsNone(sentinel.poll())

    def test_stop_command_stops_own_turn(self):
        lane = "s-cmd"
        self.idle_lane(lane, "tforever")
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("go")
        self.wait_event("lane.started", lane, run=2)
        record = self.record(lane, run=2)
        terminal.wait_for("standin: forever {} run 2".format(lane), after=mark)
        terminal.wait_prompt(after=mark)
        terminal.type("/stop")
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["survivors"]), ("stopped", 0))
        self.assert_gone([record["pid"]] + record["children"])

    def test_ctrl_c_leaves_a_foreign_turn(self):
        lane = "s-foreign"
        self.idle_lane(lane, "tforever")
        self.sent(lane, "x\n")
        self.turn_json(lane)  # a turn that somebody else started
        record = self.record(lane, run=2)
        terminal = self.attach(lane)
        terminal.wait_for("standin: forever {} run 2".format(lane))
        terminal.ctrl_c()
        self.assertEqual(terminal.wait_exit(), 130)
        self.assertTrue(self.alive(record["pid"]))
        self.assertEqual(self.ended_runs(lane), [1])
        self.assertIs(self.status(lane)["running"], True)

    def test_second_ctrl_c_leaves(self):
        lane = "s-twice"
        self.idle_lane(lane, "tstubborn")
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("go")
        self.wait_event("lane.started", lane, run=2)
        record = self.record(lane, run=2)
        terminal.wait_for("standin: stubborn {} run 2".format(lane), after=mark)
        terminal.wait_prompt(after=mark)
        watch = self.lane_directory(lane) / "watch.log"
        terminal.ctrl_c()
        terminal.wait_for("stopping run 2")
        deadline = time.monotonic() + UNTIL
        while "stop requested" not in watch.read_text(encoding="utf-8", errors="replace"):
            self.assertLess(time.monotonic(), deadline, "the supervising process never saw the stop request")
            time.sleep(0.1)
        terminal.ctrl_c()  # the stubborn runner takes the grace period to end: attach is still waiting for it
        self.assertEqual(terminal.wait_exit(), 130)
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]  # the supervising process finishes the stop
        self.assertEqual((ended["reason"], ended["survivors"]), ("stopped", 0))
        self.assert_gone([record["pid"]] + record["children"])

    def test_ctrl_c_while_the_turn_starts(self):
        # F1: the first Ctrl-C comes while attach is still starting the turn that the line asked for (its `lane turn`
        # waits for the lanes lock, which this test holds, so that the key cannot come too early or too late). There is
        # no prompt to wait for. The turn must be stopped when it has started, and nothing false may be said.
        lane = "s-start"
        self.idle_lane(lane, "tforever")
        terminal = self.attach(lane)
        mark = terminal.mark()
        release = self.hold_lanes_lock()
        terminal.type("go")
        terminal.wait_for("message 1 sent", after=mark)  # the line is stored; lane turn waits for the lock
        terminal.ctrl_c()
        release()  # the turn starts now
        text = terminal.wait_for("survivors 0", after=mark)
        self.assertNotIn("not started by this attach", text)
        self.assertNotIn("the line was discarded", text)
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["survivors"]), ("stopped", 0))
        self.assertIsNone(terminal.process.poll())  # attach is at its prompt again, as after any stop

    def test_second_ctrl_c_before_the_request(self):
        # F2: a second Ctrl-C that comes before the supervising process has been asked to stop must not cancel the
        # request. N-a of the delta review: nothing is left to the timing of the two keys. This test holds the state
        # directory's lock, so that attach waits for it in its first look at the store (which run is live), before it
        # can print `stopping run 2` or ask for anything, and both keys come in that wait.
        lane = "s-before"
        self.idle_lane(lane, "tstubborn")
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("go")
        self.wait_event("lane.started", lane, run=2)
        record = self.record(lane, run=2)
        terminal.wait_for("standin: stubborn {} run 2".format(lane), after=mark)
        terminal.wait_prompt(after=mark)
        release = self.hold_state_lock()  # from here the test reads nothing of the store until it lets go
        terminal.ctrl_c()
        time.sleep(1)  # attach is in that look, and waits for the lock
        terminal.ctrl_c()
        time.sleep(0.5)
        release()
        self.assertEqual(terminal.wait_exit(), 130)
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]  # the supervising process was asked all the same
        self.assertEqual((ended["reason"], ended["survivors"]), ("stopped", 0))
        self.assert_gone([record["pid"]] + record["children"])

    def burst_lane(self, lane):
        """A lane whose turn 2, started by attach, prints a line, waits for g1, prints a burst of about 3 MB, prints
        `burst-end` and waits for g2. The terminal is at its prompt when this returns."""
        self.idle_lane(lane)
        burst = ["burst-{:06d} {}".format(number, "x" * 100) for number in range(30000)]
        self.script(lane, 2, printed("hold-first") + [{"wait": "g1"}] + printed(*burst) + printed("burst-end") +
                    [{"wait": "g2"}])
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("start")
        terminal.wait_for("hold-first", after=mark)
        terminal.wait_prompt(after=mark)
        self.wait_event("lane.started", lane, run=2)
        return terminal

    def test_ctrl_c_before_prompt_is_armed(self):
        # D1: a Ctrl-C that comes while attach writes the output it held back, before it has asked for the next line,
        # must act at that prompt: the turn that this attach started is stopped, without an Enter. The output is held
        # back while a line is typed (here `a\`, a line that goes on), and attach writes all of it, about 3 MB, when
        # Enter has given it the next prompt; the test reads nothing of the terminal, so the write cannot end, and the
        # key comes in it.
        lane = "s-armed"
        terminal = self.burst_lane(lane)
        mark = terminal.mark()
        terminal.send("a\\")
        terminal.wait_for("a\\", after=mark)
        self.trigger(lane, "g1")
        self.wait_log(lane, b"burst-end")
        time.sleep(3)  # attach has read the burst, and holds it
        terminal.pause()
        terminal.send("\r")  # the line goes on: attach writes the held burst before the next prompt
        time.sleep(1.5)  # attach is in that write, which cannot end
        terminal.ctrl_c()
        time.sleep(0.5)
        terminal.resume()
        text = terminal.wait_for("survivors 0", after=mark)
        self.assertNotIn("not started by this attach", text)
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["survivors"]), ("stopped", 0))
        self.assertIsNone(terminal.process.poll())  # attach is at its prompt again, as after any stop

    def test_ctrl_c_while_prompt_is_drawn(self):
        # D1: a Ctrl-C that comes while the line editor draws the prompt must not make Ctrl-C inert at that prompt. The
        # key reaches the process while the line editor runs the hook that attach gives it, and an exception raised
        # there is cleared by the line editor, so a handler that raises there loses the key and its switch. The terminal
        # here does not echo, so that a line that goes on (`a\`) is followed by the next prompt without a write of the
        # line editor, and the terminal's output is stopped before that line, so that the write of the prompt blocks:
        # the key comes in it. Then the output is started again and the next key must stop the turn. The key that came
        # in the draw was counted, so the next one is a second key before the request: attach asks for the stop and
        # leaves with 130, as after a double tap (the request stands, and the supervising process finishes the stop).
        lane = "s-drawn"
        self.idle_lane(lane, "tforever")
        terminal = self.attach(lane, echo=False)
        mark = terminal.mark()
        terminal.type("go")
        self.wait_event("lane.started", lane, run=2)
        record = self.record(lane, run=2)
        terminal.wait_for("standin: forever {} run 2".format(lane), after=mark)
        terminal.wait_prompt(after=mark)
        terminal.flow(termios.TCOOFF)
        terminal.type("a\\")
        time.sleep(1.5)  # attach waits to write the prompt of the line that goes on
        terminal.ctrl_c()
        time.sleep(0.5)
        terminal.flow(termios.TCOON)
        time.sleep(0.5)
        terminal.ctrl_c()
        self.assertEqual(terminal.wait_exit(), 130)
        self.assertNotIn("not started by this attach", terminal.text(mark))
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["survivors"]), ("stopped", 0))
        self.assert_gone([record["pid"]] + record["children"])

    def test_second_ctrl_c_in_a_blocked_command(self):
        # D2 and E1: a Ctrl-C that is counted while a lane command runs says so (once), and a Ctrl-C that comes 2 seconds
        # or more after it leaves attach at once, with the exit code 130 and a line that says what is not known, and
        # how to stop the turn that may be starting. The command is a `lane turn` that waits for the lanes lock, which
        # this test holds; it lets go of it when attach has left. (A second key sooner than that is a double tap, and is
        # tested by test_double_tap_in_lane_turn.)
        lane = "s-blocked"
        self.idle_lane(lane, "tforever")
        terminal = self.attach(lane)
        mark = terminal.mark()
        release = self.hold_lanes_lock()
        terminal.type("go")
        terminal.wait_for("message 1 sent", after=mark)  # the line is stored; lane turn waits for the lock
        time.sleep(0.3)  # attach has gone from that line into lane turn, whose key it counts in the command
        first = time.monotonic()
        terminal.ctrl_c()
        notice = "Ctrl-C noted: attach acts on it when the lane command now running returns; another Ctrl-C at least " \
                 "2 seconds after this one leaves attach now, without waiting"
        terminal.wait_for(notice, after=mark)
        self.assertIsNone(terminal.process.poll())  # the first key does not leave
        time.sleep(max(0.0, 2.5 - (time.monotonic() - first)))  # the second key comes 2.5 seconds after the first
        terminal.ctrl_c()
        self.assertEqual(terminal.wait_exit(), 130)
        release()
        text = terminal.text(mark)
        self.assertEqual(text.count(notice), 1)
        self.assertIn("leaving attach; a turn for message 1 may be starting, and it was not stopped: see lane status, "
                      "and lane stop --lane {} stops it".format(lane), text)
        self.assertNotIn("turn started", text)  # nothing says that the turn began
        self.assertEqual(self.mail_texts(lane), [b"go"])  # the line was stored
        self.assertEqual(self.ended_runs(lane), [1])
        self.assertIs(self.status(lane)["running"], False)

    def test_double_tap_in_lane_turn(self):
        # E1: a person who regrets a line double-taps Ctrl-C just after Enter, and both keys come while `lane turn`,
        # which has started the supervising process, waits for it to record the start of the run. The two keys are one
        # Ctrl-C: attach acts on them when `lane turn` returns, stops the run it started and stays at its prompt; it must
        # not leave with the turn running. The wait is made certain by holding the lane directory's lock, which the
        # supervising process needs for its first append, from before the turn is asked for (the message is sent from
        # outside, because lane send needs the same lock), and the keys are written once `lane turn` has started the
        # process and is waiting for it.
        lane = "s-tap"
        self.idle_lane(lane, "tforever")
        self.sent(lane, "x\n")
        terminal = self.attach(lane)
        mark = terminal.mark()
        release = self.hold_lane_directory(lane)
        terminal.type("/turn")
        self.wait_begun(lane, runs=2)
        terminal.ctrl_c()
        time.sleep(0.15)
        terminal.ctrl_c()
        time.sleep(0.5)  # both keys are handled, and the run cannot have started: the lock is still held
        release()
        text = terminal.wait_for("survivors 0", after=mark)
        self.assertNotIn("may not have its turn yet", text)
        self.assertNotIn("leaving attach", text)
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["survivors"]), ("stopped", 0))
        self.assertIsNone(terminal.process.poll())  # attach is at its prompt again, as after any stop
        terminal.wait_prompt(after=mark)
        terminal.type("/exit")
        self.assertEqual(terminal.wait_exit(), 0)

    def lane_directory(self, lane):
        return self.mail_directory(lane).parent

    def leave(self, lane, how):
        """A turn that attach started is live, and attach is left in one way; returns the exit code of attach."""
        self.idle_lane(lane, "tforever")
        terminal = self.attach(lane)
        mark = terminal.mark()
        terminal.type("go")
        self.wait_event("lane.started", lane, run=2)
        record = self.record(lane, run=2)
        terminal.wait_for("standin: forever {} run 2".format(lane), after=mark)
        terminal.wait_prompt(after=mark)
        if how == "exit":
            terminal.type("/exit")
        elif how == "eof":
            terminal.send(b"\x04")
        elif how == "term":
            terminal.process.send_signal(signal.SIGTERM)
        else:
            terminal.hangup()
        code = terminal.wait_exit()
        self.assertTrue(self.alive(record["pid"]), "the turn was stopped by leaving attach")
        self.assertEqual(self.ended_runs(lane), [1])
        self.assertIs(self.status(lane)["running"], True)
        # A leave that asked for a stop without waiting would show only after the supervising process has had the
        # grace period ([lanes] stop_grace_seconds is 2 here) and a poll to act: look again after 4.5 seconds.
        time.sleep(4.5)
        self.assertTrue(self.alive(record["pid"]), "the turn was stopped, later, by leaving attach")
        self.assertEqual(self.ended_runs(lane), [1])
        self.assertIs(self.status(lane)["running"], True)
        watch = self.lane_directory(lane) / "watch.log"
        self.assertNotIn("stop requested", watch.read_text(encoding="utf-8", errors="replace"))
        return code

    def test_exit_leaves_the_turn_running(self):
        self.assertEqual(self.leave("s-exit", "exit"), 0)

    def test_eof_leaves_the_turn_running(self):
        self.assertEqual(self.leave("s-eof", "eof"), 0)

    def test_sigterm_leaves_the_turn_running(self):
        self.assertEqual(self.leave("s-term", "term"), 128 + signal.SIGTERM)

    def test_hangup_leaves_the_turn_running(self):
        self.assertEqual(self.leave("s-hup", "hup"), 128 + signal.SIGHUP)


class StreamKeyTest(AttachTest):
    """G. The runner key `stream` in `config validate`."""

    runners = ("stext", "sjson")

    def edit(self, old, new):
        path = self.home / "configs" / "alpha" / "config.toml"
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new), encoding="utf-8")

    def validate(self, code):
        return self.run_laneboss("config", "validate", "alpha", code=code, environment=self.env("alpha"))

    def test_the_two_readers_are_accepted(self):
        self.assertEqual(self.laneboss_json("config", "validate", "alpha", environment=self.env("alpha")),
                         {"valid": True, "configs": ["alpha"]})
        shown = self.laneboss_json("config", "show", "alpha", environment=self.env("alpha"))
        self.assertEqual(shown["config"]["runners"]["sjson"]["stream"], "claude-stream-json")
        self.assertNotIn("stream", shown["config"]["runners"]["stext"])
        self.edit('stream = "claude-stream-json"', 'stream = "text"')
        self.validate(0)

    def test_an_unknown_reader_is_refused(self):
        self.edit('stream = "claude-stream-json"', 'stream = "vendor-json"')
        result = self.validate(2)
        self.assertIn("runners.sjson.stream", result.stderr)
        self.assertIn("must be one of: text, claude-stream-json", result.stderr)  # the readers there are
        self.assertNotIn("unknown key", result.stderr)
        self.assertNotIn("vendor-json", result.stderr)  # what was typed is not repeated

    def test_a_reader_must_be_a_string(self):
        self.edit('stream = "claude-stream-json"', "stream = 5")
        result = self.validate(2)
        self.assertIn("runners.sjson.stream", result.stderr)
        self.assertIn("must be one of", result.stderr)


def installed_library():
    """The `lib` directory of the one installed copy that this module built."""
    found = sorted((support._installation.prefix / "share" / support.PROGRAM / "versions").glob("*/lib"))
    assert len(found) == 1, "expected one installed version, found %r" % (found,)
    return found[0]


def line_editor(buffer, backend=None, doc=None, version=None, fails=False):
    """A stand-in for the `readline` module of an interpreter: `get_line_buffer()` says `buffer`, or raises. `backend`,
    `doc` (the module's docstring) and `version` (`_READLINE_LIBRARY_VERSION`) are what the interpreters of macOS and of
    Linux differ in: libedit says `editline`, "libedit" in its docstring, and "EditLine wrapper"."""
    def get_line_buffer():
        if fails:
            raise RuntimeError("the line editor has no buffer to give")
        return buffer

    fields = {"get_line_buffer": get_line_buffer}
    if backend is not None:
        fields["backend"] = backend
    if doc is not None:
        fields["__doc__"] = doc
    if version is not None:
        fields["_READLINE_LIBRARY_VERSION"] = version
    return types.SimpleNamespace(**fields)


GNU = {"backend": "readline", "version": "8.2"}
# The three ways that an interpreter says that its line editor is libedit: the module attribute of Python 3.13 and later,
# the docstring that every version has, and the version of the library.
LIBEDIT = ({"backend": "editline"},
           {"doc": "Importing this module enables command line editing using libedit readline."},
           {"version": "EditLine wrapper"})


class LineEditorTest(unittest.TestCase):
    """Finding 2 of the real trial of attach. On macOS the line editor is libedit (its `readline.backend` is `editline`),
    and with nothing typed and no turn live Ctrl-C said "the line was discarded". Nothing was discarded: the buffer that
    `get_line_buffer()` gives there is libedit's own, which it does not clear between two lines, so the bytes of a line
    that was entered before are "typed" at an empty prompt. What the hint may claim is decided by `Attach.something_typed`
    from what the line editor says; it is tested here with stand-ins for the line editor, on the installed copy, because
    the libedit path itself cannot run on the box (it was seen only in the trial, on a Mac)."""

    @classmethod
    def setUpClass(cls):
        library = str(installed_library())
        for name in [name for name in sys.modules if name == "laneboss" or name.startswith("laneboss.")]:
            del sys.modules[name]  # a copy of an earlier module of this run, whose directory is gone
        sys.path.insert(0, library)
        cls.library = library
        from laneboss import attach
        cls.attach = attach

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(cls.library)
        for name in [name for name in sys.modules if name == "laneboss" or name.startswith("laneboss.")]:
            del sys.modules[name]

    def typed(self, editor, continued=False):
        """What `Attach.something_typed` says for a line editor, as an attach that is in this state would."""
        return self.attach.Attach.something_typed(types.SimpleNamespace(continued=continued, readline=editor))

    def test_gnu_readline_buffer_is_trusted(self):
        self.assertIs(self.typed(line_editor("a line being typed", **GNU)), True)
        self.assertIs(self.typed(line_editor("", **GNU)), False)

    def test_libedit_buffer_is_not_trusted(self):
        # The bytes of the line that was entered before are in the buffer, and nothing is typed: no claim is made, and
        # the answer is "cannot tell" (None, since delta 4: it was False), which is not the answer "empty".
        for fields in LIBEDIT:
            self.assertIs(self.typed(line_editor("the line that was entered before", **fields)), None, str(fields))
            self.assertIs(self.typed(line_editor("", **fields)), None, str(fields))

    def test_no_line_editor_claims_nothing(self):
        self.assertIs(self.typed(None), None)

    def test_a_failing_buffer_claims_nothing(self):
        self.assertIs(self.typed(line_editor("", fails=True, **GNU)), None)

    def test_hint_text_by_what_is_known(self):
        # Delta review 4, N-l: where the line editor cannot tell whether a line was typed, the hint says what is true in
        # both cases; where it can tell, it says what it knows; a key that came while attach was busy discarded no line.
        hint = self.attach.HINT
        self.assertEqual(self.attach.hint_text(True, True), "the line was discarded; " + hint)
        self.assertEqual(self.attach.hint_text(True, False), hint)
        self.assertEqual(self.attach.hint_text(True, None), "anything typed was discarded; " + hint)
        for typed in (True, False, None):
            self.assertEqual(self.attach.hint_text(False, typed), hint, repr(typed))
        self.assertTrue(self.attach.hint_text(True, None).startswith(
            "anything typed was discarded; nothing was stopped; leave with /exit or Ctrl-D"))

    def test_unknown_gives_the_hint_for_unknown(self):
        # Through the decision of Ctrl-C at the prompt: the answer for each line editor, and the words that follow it.
        cases = [(line_editor("typed", **GNU), "the line was discarded; "), (line_editor("", **GNU), ""),
                 (line_editor("stale", **LIBEDIT[0]), "anything typed was discarded; "),
                 (None, "anything typed was discarded; "),
                 (line_editor("", fails=True, **GNU), "anything typed was discarded; ")]
        for editor, words in cases:
            self.assertEqual(self.attach.hint_text(True, self.typed(editor)), words + self.attach.HINT)

    def test_typing_is_three_way(self):
        # Delta review 4, N-m: output is held back only while the line editor says that a line is being typed; where it
        # cannot tell (libedit, no line editor, an error), nothing is typed as far as the console is concerned.
        def typing(editor):
            return self.attach.Console(None, editor).typing()

        self.assertIs(typing(line_editor("a line being typed", **GNU)), True)
        self.assertIs(typing(line_editor("", **GNU)), False)
        for fields in LIBEDIT:
            self.assertIs(typing(line_editor("the line that was entered before", **fields)), False, str(fields))
        self.assertIs(typing(None), False)
        self.assertIs(typing(line_editor("a line", fails=True, **GNU)), False)

    def test_a_continued_message_is_a_discard(self):
        # The lines of a message that goes on have been read, and a Ctrl-C drops them, whatever the line editor says.
        for editor in (None, line_editor("", **GNU), line_editor("stale", **LIBEDIT[0]), line_editor("", fails=True)):
            self.assertIs(self.typed(editor, continued=True), True)


if __name__ == "__main__":
    import unittest

    unittest.main()

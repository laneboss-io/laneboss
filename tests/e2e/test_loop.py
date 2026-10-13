"""T3, `lane loop` (docs/architecture.md, "The `lane loop` command").

A. a message starts a turn and an idle interval starts an idle turn, each as a `loop.turn`; a lane that was not declared
with `--turns` (an abandoned or cleaned one included) is never touched, and a lane with nothing to start gets no event;
B. one loop for a configuration: the lock, `--status` and `--stop`; C. the back-off, and what a person's turn does to
it; D. a turn that cannot start is a skip with reason `refused`; E. a busy store; F. a killed loop, a restarted loop and a
lost turn; G. `--detach`; H. the environment of the loop's turns; I. the form of the `loop.*` events, which `event
append` checks and `state verify` and `state rebuild` do not; J. events in other forms do not steer the loop; K. `lane
check --lane`; L. the keys of the loop in `[turns]`; M. `last_error` of the status and of loop.json; N. `next` in the
entry of each lane of the status.

The runners are tests/e2e/standin.py. The loop runs in the foreground as a child of the test (its standard output is
read as it comes), or detached in its tmux session; every turn it starts is an ordinary run under its own supervising
process. The loop looks every second, and waits 3 seconds after an end that was not good (6 after a limit).
"""

import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from . import support
from .lanesupport import UNTIL, runner
from .mailsupport import (HEADER, IDLE, STDIN, TURN_START, HandTest, TurnTest, plant_event, turn_config,
                          turn_resume)


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


PLAIN = "A line of plain words that only gives the message its size.\n"
LOOP = "0123456789abcdef0123456789abcdef"
OTHER = "fedcba9876543210fedcba9876543210"
SOME = "i-some-lane"
# A credential shape, made here so that no file of the repository holds one.
TOKEN = "gh" + "p_" + "Z9y8X7w6V5u4T3s2R1q0" + "P9o8N7m6L5k4J3i2"
# What a test gets for a key that the status does not have.
MISSING = "(no such key)"
PLANTED_AT = "2026-10-11T00:00:00.000000Z"


def when(value):
    """A timestamp of the launcher as a datetime."""
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


def at(event):
    """The moment an event happened: its occurred_at, else its recorded_at."""
    return when(event["occurred_at"] or event["recorded_at"])


def turns_table(idle_message=True, **values):
    """The table [turns] of these tests: the loop looks every second and waits 3 seconds (6 after a limit)."""
    keys = {"poll_seconds": 1, "backoff_seconds": 3, "limit_backoff_seconds": 6}
    keys.update(values)
    text = "\n[turns]\n" + "".join("{} = {}\n".format(key, value) for key, value in keys.items())
    return text + ('idle_message = "rules/idle.md"\n' if idle_message else "")


def finishing(name):
    """The text of a runner table whose turns end at once, in place of the one in the configuration."""
    return runner(name, "ok", TURN_START, None, turn_resume("ok"), extra=STDIN)


class Loop:
    """`laneboss lane loop` in the foreground, a child of the test. Its standard output (one JSON event for each event
    it appends) and its standard error are read by threads of their own, so that a full pipe never holds it up."""

    def __init__(self, command, config, environment, directory, arguments=()):
        self.process = subprocess.Popen([str(command), "lane", "loop", "--config", config, *arguments],
                                        cwd=str(directory), env=environment, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf-8")
        self.lines = []
        self.errors = []
        self.threads = [threading.Thread(target=self.read, args=(self.process.stdout, self.lines), daemon=True),
                        threading.Thread(target=self.read, args=(self.process.stderr, self.errors), daemon=True)]
        for thread in self.threads:
            thread.start()

    @staticmethod
    def read(stream, kept):
        for line in stream:
            kept.append(line)

    def events(self):
        """The events the loop printed, decoded."""
        return [json.loads(line) for line in list(self.lines)]

    def finish(self):
        """Wait for the end of the process, and for the last of its output."""
        code = self.process.wait(timeout=UNTIL)
        for thread in self.threads:
            thread.join(10)
        return code

    def stop(self):
        """The test's own safety net: a loop that is still there is killed by its process id."""
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)
        for thread in self.threads:
            thread.join(10)
        self.process.stdout.close()
        self.process.stderr.close()


class LoopTest(TurnTest):
    """The lane tests' configuration `alpha` with runners that take turns, an idle message and a loop that looks every
    second."""

    def setUp(self):
        super().setUp()
        (self.home / "configs" / "alpha" / "rules" / "idle.md").write_text(IDLE, encoding="utf-8")
        self.configure()

    def configure(self, turns=None, overrides=None, lanes=""):
        """The configuration `alpha`: the runners that take turns (`overrides` replaces some), the table [turns] and,
        with `lanes`, more keys of [lanes]."""
        text = turn_config("alpha", turns_table() if turns is None else turns, overrides)
        if lanes:
            self.assertIn("stop_grace_seconds = 2\n", text)
            text = text.replace("stop_grace_seconds = 2\n", "stop_grace_seconds = 2\n" + lanes, 1)
        (self.home / "configs" / "alpha" / "config.toml").write_text(text, encoding="utf-8")

    def loop_events(self, kind=None, lane=None):
        """The events of the loop in the store, in order: the lane's when `lane` is given."""
        return [item for item in self.events() if item["kind"].startswith("loop.")
                and (kind is None or item["kind"] == kind) and (lane is None or item["lane"] == lane)]

    def wait_loop(self, kind, lane=None, count=1, timeout=UNTIL, loop=None):
        """The count-th loop event of this kind (and lane) once it is stored. The test fails at once when the loop it
        names has ended."""
        deadline = time.monotonic() + timeout
        while True:
            found = self.loop_events(kind, lane)
            if len(found) >= count:
                return found[count - 1]
            if loop is not None and loop.process.poll() is not None:
                self.fail("the loop ended with exit {} before {} #{}: stdout={!r}; stderr={!r}".format(
                    loop.process.returncode, kind, count, loop.lines, loop.errors))
            if time.monotonic() > deadline:
                self.fail("no {} #{} for lane {} within {} s; loop events: {}".format(
                    kind, count, lane, timeout, [(item["kind"], item["lane"]) for item in self.loop_events()]))
            time.sleep(0.3)

    def start_loop(self, *arguments, environment=None):
        """lane loop in the foreground, as a child of the test, once its loop.started is stored: (handle, that event)."""
        count = len(self.loop_events("loop.started")) + 1
        loop = Loop(self.command, "alpha", self.env("alpha") if environment is None else environment, self.directory,
                    arguments)
        self.addCleanup(loop.stop)
        return loop, self.wait_loop("loop.started", count=count, loop=loop)

    def stop_loop(self, loop):
        """lane loop --stop, the JSON it prints; the foreground loop ends with exit 0."""
        stopped = self.lane_json("loop", "--stop")
        self.assertEqual(loop.finish(), 0, loop.errors)
        return stopped

    def failing_turn(self, lane, runner_name, text, **options):
        """A turn-based lane whose first run has ended, a loop and a message: the turn that the loop starts ends badly
        (the runner fails, reaches its limit or closes its input) and the loop records the wait. Returns the loop, its
        loop.started, the loop.skipped of the wait and the lane.ended of the turn."""
        self.turn_start(lane, runner_name)
        self.settle(lane, 1)
        loop, started = self.start_loop(**options)
        self.sent(lane, text)
        self.wait_loop("loop.turn", lane, loop=loop)
        skip = self.wait_loop("loop.skipped", lane, loop=loop)
        return loop, started, skip, self.wait_event("lane.ended", lane, run=2)

    def stop_quietly(self):
        """lane loop --stop for a detached loop that a failed test left behind."""
        self.run_laneboss("lane", "loop", "--stop", "--config", "alpha", code=None, environment=self.env("alpha"))

    def detach(self, environment=None):
        """lane loop --detach: the process that ran it."""
        result = self.run_laneboss("lane", "loop", "--detach", "--config", "alpha",
                                   environment=self.env("alpha") if environment is None else environment)
        self.addCleanup(self.stop_quietly)
        return result

    def sessions(self):
        """The names of the sessions of the configuration's tmux server."""
        result = self.tmux(self.paths()["socket"], "list-sessions", "-F", "#{session_name}", code=None)
        return result.stdout.split() if result.returncode == 0 else []


class StartTest(LoopTest):
    """A. When a turn starts, and what the loop leaves alone."""

    def test_a_message_starts_a_turn(self):
        lane = "a-mail"
        self.turn_start(lane)
        self.settle(lane, 1)
        loop, started = self.start_loop()
        # The first pass is over before the message comes, so a later one starts the turn, within poll_seconds.
        time.sleep(0.5)
        self.sent(lane, "Please summarise the open review comments.\n")
        mailed = self.wait_event("lane.mailed", lane)
        turn = self.wait_loop("loop.turn", lane, loop=loop)
        self.assertEqual((turn["payload"], turn["actor"], turn["lane"]),
                         ({"loop": started["payload"]["loop"], "kind": "mail", "sequences": [1], "run": 2}, "laneboss",
                          lane))
        self.assertLess((at(turn) - at(mailed)).total_seconds(), 8)
        # The turn is the one that `lane turn` starts: its events, in its order, and the message on standard input.
        self.settle(lane, 2, "lane.delivered")
        self.assertIn("Please summarise the open review comments.", self.stdin_of(lane, 2))
        kinds = [item["kind"] for item in self.lane_events(lane) if not item["kind"].startswith("loop.")]
        self.assertEqual(kinds[kinds.index("lane.mailed"):], ["lane.mailed", "brief.rendered", "lane.resumed",
                                                              "lane.started", "lane.ended", "lane.delivered"])
        began = self.wait_event("lane.started", lane, run=2)
        self.assertEqual(began["payload"]["mail"], [1])
        self.assertLess(began["seq"], turn["seq"])
        self.assertLess(started["seq"], began["seq"])
        # In the foreground the loop printed one line for each event it appended, as `event tail` prints it.
        self.stop_loop(loop)
        stored = self.loop_events()
        self.assertEqual([item["kind"] for item in stored], ["loop.started", "loop.turn", "loop.stopped"])
        self.assertEqual(loop.events(), stored)
        self.assert_sound()

    def test_an_idle_turn_after_idle_seconds(self):
        lane = "a-idle"
        self.turn_start(lane, "tok", "--idle", "3")
        self.settle(lane, 1)
        ended = self.wait_event("lane.ended", lane, run=1)
        loop, started = self.start_loop()
        turn = self.wait_loop("loop.turn", lane, loop=loop)
        self.assertEqual(turn["payload"], {"loop": started["payload"]["loop"], "kind": "idle", "sequences": [],
                                           "run": 2})
        self.stop_loop(loop)
        # Counted from the lane's last state change: its run ended at `ended`, and the idle turn starts 3 seconds later.
        began = self.wait_event("lane.started", lane, run=2)
        self.assertGreaterEqual((at(began) - at(ended)).total_seconds(), 3)
        self.assertEqual(began["payload"]["mail"], [])
        self.settle(lane, 2)
        self.assertTrue(self.stdin_of(lane, 2).startswith(IDLE))

    def test_nothing_to_start_records_nothing(self):
        lane = "a-quiet"
        self.turn_start(lane)
        self.settle(lane, 1)
        before = self.events()
        loop, started = self.start_loop()
        time.sleep(4)
        self.assertEqual([item["kind"] for item in self.events_since(before)], ["loop.started"])
        self.stop_loop(loop)

    def test_undeclared_lanes_are_untouched(self):
        plain, abandoned, cleaned = "a-plain", "a-abandoned", "a-cleaned"
        self.start(plain, "--runner", "forever", "--model", "forever-model-1", "--worktree", self.scratch(plain))
        self.record(plain, run=1)
        self.kill_supervisor(plain)
        for lane in (abandoned, cleaned):
            self.turn_start(lane)
            self.settle(lane, 1)
            self.sent(lane, "A message for a lane that is not declared any more.\n")
            self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        self.lane_json("clean", "--lane", cleaned)
        before = self.events()
        loop, _ = self.start_loop()
        time.sleep(4)
        self.assertEqual([item["kind"] for item in self.events_since(before)], ["loop.started"])
        self.assertIs(self.status(plain)["running"], True)
        self.assertEqual(self.status(abandoned)["mail"]["waiting"], [1])
        self.assertEqual(self.status(cleaned)["mail"]["waiting"], [1])
        self.stop_loop(loop)
        # Run by hand, `lane check` does record the loss of the lane that the loop did not touch.
        self.assertEqual([entry["lane"] for entry in self.lane_json("check")["lost"]], [plain])

    def test_the_defaults(self):
        # No [turns] table: the loop looks every 10 seconds, and waits 300 seconds (1800 after a limit).
        self.configure(turns="")
        failing, limited = "a-fail", "a-limit"
        self.turn_start(failing, "tfail")
        self.settle(failing, 1)
        self.turn_start(limited, "tlimit")
        self.settle(limited, 1)
        self.sent(failing, "A message for a runner that fails.\n")
        self.sent(limited, "A message for a runner that reaches its limit.\n")
        loop, _ = self.start_loop()
        turn = self.wait_loop("loop.turn", failing, loop=loop)
        skip = self.wait_loop("loop.skipped", failing, loop=loop)
        other = self.wait_loop("loop.skipped", limited, loop=loop)
        self.assertEqual(skip["payload"]["after"], {"run": 2, "reason": "exit"})
        self.assertEqual(other["payload"]["after"], {"run": 2, "reason": "limit"})
        self.assertEqual(when(skip["payload"]["until"]),
                         at(self.wait_event("lane.ended", failing, run=2)) + timedelta(seconds=300))
        self.assertEqual(when(other["payload"]["until"]),
                         at(self.wait_event("lane.ended", limited, run=2)) + timedelta(seconds=1800))
        # The turn ended at once, and the loop saw its end only at its second pass, 10 seconds after the first.
        self.assertGreater((at(skip) - at(turn)).total_seconds(), 5)
        self.stop_loop(loop)


class LockTest(LoopTest):
    """B. One loop for a configuration: the lock, the status and the stop."""

    def test_a_second_loop_is_refused(self):
        loop, started = self.start_loop()
        pid = started["payload"]["pid"]
        before = self.events()
        for arguments in ((), ("--detach",)):
            with self.subTest(arguments=arguments):
                result = self.lane("loop", *arguments, code=2)
                self.assertTrue(result.stderr.startswith("refused:"), result.stderr)
                self.assertIn(str(pid), result.stderr)
        self.assertEqual(self.events(), before)
        status = self.lane_json("loop", "--status")
        self.assertEqual((status["running"], status["loop"], status["pid"]), (True, started["payload"]["loop"], pid))
        self.assertIsNone(loop.process.poll())
        self.stop_loop(loop)

    def test_a_probe_does_not_refuse_a_loop(self):
        lane = "b-probe"
        self.turn_start(lane)
        self.settle(lane, 1)
        state = Path(self.paths()["state_dir"])
        self.assertFalse((state / "loop.log").exists())
        # `lane loop --status`, `--stop` and `--detach` look at the lock for an instant, with a shared lock. A loop that
        # asks for its exclusive lock in that instant must not be refused for it: it is not another loop. The test is that
        # probe, held across the moment when the loop asks: the loop creates loop.log a few microseconds before it asks,
        # and the probe lets go 0.2 seconds after that. (A second process that polls `--status` in a tight loop meets the
        # moment about once in ten thousand starts, so a test made of it would pass on the code it is meant to fail on.)
        probe = os.open(str(state / "loop.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(probe, fcntl.LOCK_SH)
            loop = Loop(self.command, "alpha", self.env("alpha"), self.directory)
            self.addCleanup(loop.stop)
            deadline = time.monotonic() + UNTIL
            while not (state / "loop.log").exists():
                self.assertIsNone(loop.process.poll(), "the loop ended before it asked for the lock: {}".format(
                    loop.errors))
                self.assertLess(time.monotonic(), deadline, "the loop did not begin")
                time.sleep(0.005)
            time.sleep(0.2)
        finally:
            os.close(probe)
        started = self.wait_loop("loop.started", loop=loop)
        status = self.lane_json("loop", "--status")
        self.assertEqual((status["running"], status["loop"], status["pid"]),
                         (True, started["payload"]["loop"], started["payload"]["pid"]))
        self.stop_loop(loop)

    def test_the_forms_exclude_each_other(self):
        before = self.events()
        for arguments in (("--detach", "--status"), ("--detach", "--stop"), ("--status", "--stop")):
            with self.subTest(arguments=arguments):
                self.assertIn("not allowed with", self.lane("loop", *arguments, code=2).stderr)
        self.assertEqual(self.events(), before)

    def test_status(self):
        lane, plain = "b-status", "b-plain"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.plain_start(plain)
        self.settle(plain, 1)
        before = self.events()
        status = self.lane_json("loop", "--status")
        self.assertIs(status["running"], False)
        self.assertIsNone(status.get("pid"))
        loop, started = self.start_loop()
        self.assertEqual(self.events(), before + [started])
        status = self.lane_json("loop", "--status")
        self.assertEqual((status["running"], status["loop"], status["pid"], status["detached"], status["session"],
                          status["unrecorded_end"]),
                         (True, started["payload"]["loop"], started["payload"]["pid"], False, None, None))
        self.assertRegex(status["since"], support.TIMESTAMP)
        # One entry for each declared lane: the lane that was not started with --turns is not among them.
        self.assertEqual([entry["lane"] for entry in status["lanes"]], [lane])
        entry = status["lanes"][0]
        self.assertEqual((entry["state"], entry["waiting"], entry["backoff_until"], entry["bad_ends"]),
                         ("waiting", 0, None, 0))
        # Reading the status appended nothing.
        self.assertEqual(self.events(), before + [started])
        self.stop_loop(loop)
        self.assertIs(self.lane_json("loop", "--status")["running"], False)

    def test_stop_leaves_a_running_turn_alone(self):
        lane = "b-stop"
        self.turn_start(lane, "tforever")
        self.settle(lane, 1)
        loop, started = self.start_loop()
        self.sent(lane, "A message for a turn that runs until it is stopped.\n")
        self.wait_loop("loop.turn", lane, loop=loop)
        record = self.record(lane, run=2)
        # The turn goes on, and the loop leaves it alone: a message waits behind it, and no event follows.
        self.sent(lane, "A second message, for the next turn.\n")
        time.sleep(3)
        self.assertEqual([item["kind"] for item in self.loop_events(lane=lane)], ["loop.turn"])
        pid = self.lane_json("loop", "--status")["pid"]
        before = self.events()
        stopped = self.stop_loop(loop)
        [event] = self.events_since(before)
        self.assertEqual((event["kind"], event["lane"], event["actor"], event["payload"]),
                         ("loop.stopped", None, "laneboss",
                          {"loop": started["payload"]["loop"], "reason": "stop", "turns": 1, "skips": 0}))
        self.assertEqual(stopped, {"stopped": True, "pid": pid, "event": {"id": event["id"], "seq": event["seq"]}})
        self.assertIs(self.lane_json("loop", "--status")["running"], False)
        # Nothing of the turn was stopped: its supervising process, its session and its runner are as they were.
        row = self.status(lane)
        self.assertEqual((row["running"], row["live"]["supervisor"]["alive"], row["live"]["session_alive"]),
                         (True, True, True))
        self.assertTrue(self.alive(record["pid"]))
        self.assertEqual([item["payload"]["run"] for item in self.lane_events(lane, "lane.ended")], [1])
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]] + record["children"])

    def test_stop_without_a_loop(self):
        before = self.events()
        result = self.lane("loop", "--stop", code=2)
        self.assertIn("no loop", result.stderr)
        self.assertEqual(self.events(), before)

    def test_stop_is_refused_while_it_stays(self):
        loop, started = self.start_loop()
        pid = started["payload"]["pid"]
        os.kill(pid, signal.SIGSTOP)
        began = time.monotonic()
        result = self.lane("loop", "--stop", code=2)
        self.assertGreaterEqual(time.monotonic() - began, 28)
        self.assertIn(str(pid), result.stderr)
        # It signalled the loop and never killed it: the loop is still there, and ends as soon as it can run.
        self.assertIsNone(loop.process.poll())
        os.kill(pid, signal.SIGCONT)
        self.assertEqual(loop.finish(), 0, loop.errors)
        self.assertEqual(self.loop_events("loop.stopped")[0]["payload"]["reason"], "stop")

    def test_a_record_left_by_a_kill(self):
        loop, started = self.start_loop()
        pid = started["payload"]["pid"]
        os.kill(pid, signal.SIGKILL)
        loop.process.wait(timeout=10)
        status = self.lane_json("loop", "--status")
        self.assertIs(status["running"], False)
        self.assertIsNone(status.get("pid"))
        # The record stays after a kill, and names a process id that another process may be given.
        path = Path(self.paths()["state_dir"]) / "loop.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(pid, data.values())
        sentinel = self.sentinel()
        path.write_text(json.dumps({key: sentinel.pid if value == pid else value for key, value in data.items()}),
                        encoding="utf-8")
        before = self.events()
        self.assertIs(self.lane_json("loop", "--status")["running"], False)
        self.assertIn("no loop", self.lane("loop", "--stop", code=2).stderr)
        self.assertIsNone(sentinel.poll())
        self.assertEqual(self.events(), before)

    def test_a_record_that_does_not_match(self):
        loop, started = self.start_loop()
        pid = started["payload"]["pid"]
        path = Path(self.paths()["state_dir"]) / "loop.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(pid, data.values())
        sentinel = self.sentinel()
        path.write_text(json.dumps({key: sentinel.pid if value == pid else value for key, value in data.items()}),
                        encoding="utf-8")
        # The lock is held by the loop, but the record names another process: it is believed by nothing, and no process
        # is signalled, the loop and the other process alike.
        status = self.lane_json("loop", "--status")
        self.assertIs(status["running"], True)
        self.assertIsNone(status.get("pid"))
        self.lane("loop", "--stop", code=2)
        self.assertIsNone(sentinel.poll())
        self.assertIsNone(loop.process.poll())
        path.write_text(json.dumps(data), encoding="utf-8")
        self.stop_loop(loop)


class BackOffTest(LoopTest):
    """C. After an end that was not good the loop waits, once for each wait; a person's turn ignores the wait."""

    def test_a_failing_turn_waits(self):
        lane = "c-fail"
        loop, started, skip, ended = self.failing_turn(lane, "tfail", "A message for a runner that fails.\n")
        self.assertEqual(self.loop_events("loop.turn", lane)[0]["payload"]["sequences"], [1])
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"]), ("exit", 3))
        payload = dict(skip["payload"])
        until = when(payload.pop("until"))
        self.assertEqual((skip["actor"], skip["lane"], payload),
                         ("laneboss", lane, {"loop": started["payload"]["loop"], "reason": "backoff",
                                             "after": {"run": 2, "reason": "exit"}, "detail": None}))
        # The wait is backoff_seconds after the end, counted from the end's own time.
        self.assertEqual(until, at(ended) + timedelta(seconds=3))
        # The next turn starts when the wait is over, with the message that returned, and is recorded as a turn.
        second = self.wait_loop("loop.turn", lane, count=2, loop=loop)
        self.assertEqual(second["payload"]["sequences"], [1])
        self.assertEqual(second["payload"]["run"], 3)
        self.assertGreaterEqual(at(self.wait_event("lane.started", lane, run=3)), until)
        # One skip for the wait, and none for the passes inside it.
        skips = self.loop_events("loop.skipped", lane)
        self.assertEqual([item["payload"]["after"] for item in skips if when(item["recorded_at"]) < until],
                         [{"run": 2, "reason": "exit"}])
        # The turn of run 3 ends badly too: a new wait, a new skip with another `until`.
        again = self.wait_loop("loop.skipped", lane, count=2, loop=loop)
        self.assertEqual(again["payload"]["after"], {"run": 3, "reason": "exit"})
        self.assertEqual(when(again["payload"]["until"]),
                         at(self.wait_event("lane.ended", lane, run=3)) + timedelta(seconds=3))
        self.assertNotEqual(again["payload"]["until"], skip["payload"]["until"])
        self.stop_loop(loop)
        self.assertEqual(len([item for item in self.loop_events("loop.skipped", lane)
                              if item["payload"]["after"]["run"] == 3]), 1)

    def test_a_limit_waits_longer(self):
        lane = "c-limit"
        loop, _, skip, ended = self.failing_turn(lane, "tlimit", "A message for a runner that reaches its limit.\n")
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"]), ("limit", 0))
        self.assertEqual(skip["payload"]["after"], {"run": 2, "reason": "limit"})
        self.assertEqual(when(skip["payload"]["until"]), at(ended) + timedelta(seconds=6))
        self.stop_loop(loop)

    def test_a_cut_prompt_waits(self):
        # shut closes its input without reading it and exits 0, and the message is far larger than a pipe holds.
        lane = "c-cut"
        loop, _, skip, ended = self.failing_turn(lane, "tshut", (PLAIN * 3000)[:150000])
        done = ended["payload"]
        self.assertEqual((done["reason"], done["exit_code"], done["prompt"]["state"]), ("exit", 0, "cut"))
        self.assertEqual(skip["payload"]["after"], {"run": 2, "reason": "cut"})
        self.assertEqual(when(skip["payload"]["until"]), at(ended) + timedelta(seconds=3))
        self.stop_loop(loop)

    def test_the_status_of_a_lane_in_back_off(self):
        self.configure(turns_table(backoff_seconds=60))
        lane = "c-status"
        loop, _, skip, _ = self.failing_turn(lane, "tfail", "A message that returns.\n")
        status = self.lane_json("loop", "--status")
        [entry] = [item for item in status["lanes"] if item["lane"] == lane]
        self.assertEqual((entry["state"], entry["waiting"], entry["bad_ends"]), ("waiting", 1, 1))
        self.assertEqual(when(entry["backoff_until"]), when(skip["payload"]["until"]))
        self.stop_loop(loop)

    def test_a_person_is_not_held_by_the_wait(self):
        self.configure(turns_table(backoff_seconds=60))
        lane = "c-person"
        loop, _, _, _ = self.failing_turn(lane, "tfail", "A message that returns.\n")
        # The back-off belongs to the loop: a person's `lane turn` starts the turn at once.
        started = self.turn_json(lane)
        self.assertEqual((started["started"], started["run"], started["turn"]["mail"]), (True, 3, [1]))
        self.settle(lane, 3, "lane.returned")
        # `bad_ends` counts the turns in a row that ended badly, whoever started them.
        [entry] = [item for item in self.lane_json("loop", "--status")["lanes"] if item["lane"] == lane]
        self.assertEqual(entry["bad_ends"], 2)
        self.assertEqual(when(entry["backoff_until"]),
                         at(self.wait_event("lane.ended", lane, run=3)) + timedelta(seconds=60))
        # A turn that ends well ends the series, and a person's turn is not refused for the wait that the last one made.
        self.configure(turns_table(backoff_seconds=60), overrides={"tfail": finishing("tfail")})
        self.assertEqual(self.turn_json(lane)["run"], 4)
        self.settle(lane, 4, "lane.delivered")
        [entry] = [item for item in self.lane_json("loop", "--status")["lanes"] if item["lane"] == lane]
        self.assertEqual((entry["bad_ends"], entry["backoff_until"], entry["waiting"]), (0, None, 0))
        self.stop_loop(loop)


class RefusedTest(LoopTest):
    """D. A turn that cannot start is a skip with reason `refused`; the loop goes on, and tries again after the wait."""

    def test_a_runner_edited_since(self):
        lane = "d-edit"
        # The wait after the bad end, and the hold after a refused attempt, are 15 seconds here and not 3: the edit of the
        # runner must land before the wait is over, and it goes through the command line of a test, which takes a second
        # or two on a loaded machine. Every configuration written below keeps the 15.
        turns = turns_table(backoff_seconds=15)
        self.configure(turns=turns)
        loop, started, waiting, _ = self.failing_turn(lane, "tfail", "A message that returns.\n")
        # The loop reads the configuration at every pass: before the wait is over the runner loses its resume template,
        # and the turn that is due then is refused.
        self.configure(turns=turns, overrides={"tfail": runner("tfail", "ok", TURN_START, None, None, extra=STDIN)})
        skip = self.wait_loop("loop.skipped", lane, count=2, loop=loop)
        payload = skip["payload"]
        self.assertEqual((payload["loop"], payload["reason"], payload["after"]),
                         (started["payload"]["loop"], "refused", None))
        self.assertIn("resume template", payload["detail"])
        self.assertNotIn("\n", payload["detail"])
        self.assertLessEqual(len(payload["detail"]), 200)
        self.assertGreaterEqual(at(skip), when(waiting["payload"]["until"]))
        # The lane is not tried again for backoff_seconds, counted from the skip. The runner is mended, and the next
        # attempt starts the turn, which carries the message that returned.
        self.assertEqual(when(payload["until"]), at(skip) + timedelta(seconds=15))
        self.configure(turns=turns, overrides={"tfail": finishing("tfail")})
        turn = self.wait_loop("loop.turn", lane, count=2, loop=loop)
        self.assertEqual((turn["payload"]["sequences"], turn["payload"]["run"]), ([1], 3))
        self.assertGreaterEqual(at(self.wait_event("lane.started", lane, run=3)), when(payload["until"]))
        self.assertEqual([item["kind"] for item in self.loop_events(lane=lane)],
                         ["loop.turn", "loop.skipped", "loop.skipped", "loop.turn"])
        self.stop_loop(loop)

    def test_the_lanes_lock_that_stays_held(self):
        self.configure(lanes="lock_wait_seconds = 2\n")
        lane = "d-lock"
        self.turn_start(lane)
        self.settle(lane, 1)
        descriptor = os.open(str(Path(self.paths()["state_dir"]) / "lanes.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        self.sent(lane, "A message behind a lanes lock that stays held.\n")
        loop, _ = self.start_loop()
        skip = self.wait_loop("loop.skipped", lane, loop=loop)
        self.assertEqual(skip["payload"]["reason"], "refused")
        self.assertIn("lanes lock", skip["payload"]["detail"])
        self.assertIsNone(loop.process.poll())
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        self.wait_loop("loop.turn", lane, loop=loop)
        self.stop_loop(loop)

    def test_a_damaged_mail_file(self):
        lane = "d-damage"
        self.turn_start(lane)
        self.settle(lane, 1)
        path = Path(self.sent(lane, "A message whose file is changed by hand.\n")["file"])
        saved = path.read_bytes()
        path.write_bytes(b"changed by hand")
        loop, _ = self.start_loop()
        skip = self.wait_loop("loop.skipped", lane, loop=loop)
        self.assertEqual(skip["payload"]["reason"], "refused")
        self.assertIn("sequence 1", skip["payload"]["detail"])
        self.assertEqual(self.status(lane)["mail"]["waiting"], [1])
        # The same bytes put back under the same name repair it.
        path.write_bytes(saved)
        self.wait_loop("loop.turn", lane, loop=loop)
        self.stop_loop(loop)

    def test_idle_turn_without_idle_message(self):
        self.configure(turns_table(idle_message=False))
        lane = "d-idle"
        self.turn_start(lane, "tok", "--idle", "2")
        self.settle(lane, 1)
        loop, _ = self.start_loop()
        skip = self.wait_loop("loop.skipped", lane, loop=loop)
        self.assertEqual(skip["payload"]["reason"], "refused")
        self.assertIn("idle_message", skip["payload"]["detail"])
        # The mail turns go on without it.
        self.sent(lane, "A message that needs no idle message.\n")
        turn = self.wait_loop("loop.turn", lane, loop=loop)
        self.assertEqual((turn["payload"]["kind"], turn["payload"]["sequences"]), ("mail", [1]))
        self.stop_loop(loop)


class BusyTest(LoopTest):
    """E. A busy store never ends the loop: it writes a line to loop.log, appends nothing and tries again."""

    def test_a_busy_store_goes_on(self):
        lane = "e-busy"
        self.turn_start(lane, "tok", "--idle", "6")
        self.settle(lane, 1)
        loop, _ = self.start_loop()
        log = Path(self.paths()["state_dir"]) / "loop.log"
        size = log.stat().st_size if log.exists() else 0
        release = self.hold_store()
        # The idle turn is due in a few seconds; its first record waits 10 seconds for the store, and the pass fails.
        deadline = time.monotonic() + 40
        while (log.stat().st_size if log.exists() else 0) <= size:
            self.assertLess(time.monotonic(), deadline, "the loop wrote no line to loop.log while the store was busy")
            self.assertIsNone(loop.process.poll(), loop.errors)
            time.sleep(0.3)
        self.assertEqual(self.loop_events("loop.turn"), [])
        self.assertEqual(self.loop_events("loop.skipped"), [])
        release()
        # Nothing was lost: with the store free the loop starts the turn.
        turn = self.wait_loop("loop.turn", lane, loop=loop)
        self.assertEqual(turn["payload"]["kind"], "idle")
        self.assertEqual(self.loop_events("loop.skipped"), [])
        self.stop_loop(loop)
        self.assertEqual(loop.errors, [])


class RestartTest(LoopTest):
    """F. A killed loop, a restarted loop and a lost turn."""

    def test_a_killed_loop(self):
        lane = "f-kill"
        self.turn_start(lane)
        self.settle(lane, 1)
        first, one = self.start_loop()
        os.kill(one["payload"]["pid"], signal.SIGKILL)
        first.process.wait(timeout=10)
        self.assertEqual(first.process.returncode, -signal.SIGKILL)
        # The kernel freed the lock, and no loop.stopped was written.
        self.assertIs(self.lane_json("loop", "--status")["running"], False)
        self.assertEqual(self.loop_events("loop.stopped"), [])
        second, two = self.start_loop()
        self.assertEqual(two["payload"]["unrecorded_end"], one["payload"]["loop"])
        self.assertNotEqual(two["payload"]["loop"], one["payload"]["loop"])
        status = self.lane_json("loop", "--status")
        self.assertEqual((status["running"], status["loop"], status["pid"], status["unrecorded_end"]),
                         (True, two["payload"]["loop"], two["payload"]["pid"], one["payload"]["loop"]))
        self.stop_loop(second)
        self.assertEqual([item["payload"]["reason"] for item in self.loop_events("loop.stopped")], ["stop"])

    def test_a_turn_survives_its_loop(self):
        lane = "f-survive"
        self.turn_start(lane, "tforever")
        self.settle(lane, 1)
        first, one = self.start_loop()
        self.sent(lane, "A message for a turn that outlives its loop.\n")
        self.wait_loop("loop.turn", lane, loop=first)
        record = self.record(lane, run=2)
        os.kill(one["payload"]["pid"], signal.SIGKILL)
        first.process.wait(timeout=10)
        # The turn goes on under its own supervising process, and mail that arrives meanwhile waits.
        self.sent(lane, "A message that arrives while no loop runs.\n")
        row = self.status(lane)
        self.assertEqual((row["running"], row["live"]["supervisor"]["alive"]), (True, True))
        self.assertEqual(row["mail"]["waiting"], [2])
        self.assertTrue(self.alive(record["pid"]))
        second, two = self.start_loop()
        self.assertEqual(two["payload"]["unrecorded_end"], one["payload"]["loop"])
        # The turn is stopped by hand; the next one carries both messages, and the loop starts it once the wait is over.
        self.configure(overrides={"tforever": finishing("tforever")})
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]] + record["children"])
        skip = self.wait_loop("loop.skipped", lane, loop=second)
        self.assertEqual(skip["payload"]["after"], {"run": 2, "reason": "stopped"})
        turn = self.wait_loop("loop.turn", lane, count=2, loop=second)
        self.assertEqual((turn["payload"]["sequences"], turn["payload"]["run"]), ([1, 2], 3))
        self.settle(lane, 3, "lane.delivered")
        self.assertEqual(self.status(lane)["mail"]["delivered"], 2)
        self.stop_loop(second)

    def test_a_restarted_loop_repeats_no_skip(self):
        self.configure(turns_table(backoff_seconds=60))
        lane = "f-again"
        first, _, skip, _ = self.failing_turn(lane, "tfail", "A message that returns.\n")
        self.stop_loop(first)
        second, _ = self.start_loop()
        time.sleep(4)
        # The restarted loop reads the latest skip of the lane, and neither repeats it nor starts the turn early.
        self.assertEqual(self.loop_events("loop.skipped", lane), [skip])
        self.assertEqual(len(self.loop_events("loop.turn", lane)), 1)
        self.stop_loop(second)

    def test_a_lost_turn_is_recorded(self):
        lane = "f-lost"
        record = self.running_turn(lane, ["A message for a turn whose machine restarts.\n"])
        # The turn that runs goes on as it is; the turns after it end at once.
        self.configure(overrides={"tforever": finishing("tforever")})
        loop, _ = self.start_loop()
        self.lose_supervisor(lane)
        self.remove_processes(record)
        # The loop saw the supervising process gone and ran the check of this lane: the loss and the return of the mail.
        lost = self.wait_event("lane.lost", lane)
        returned = self.wait_event("lane.returned", lane)
        self.assertEqual((lost["actor"], returned["actor"], returned["payload"]),
                         ("laneboss", "laneboss", {"run": 2, "sequences": [1], "reason": "lost"}))
        skip = self.wait_loop("loop.skipped", lane, loop=loop)
        self.assertEqual(skip["payload"]["after"], {"run": 2, "reason": "lost"})
        self.assertEqual(when(skip["payload"]["until"]), at(lost) + timedelta(seconds=3))
        # The next turn is the declared schedule, not a retry by the loop's own judgement: the message goes, marked.
        turn = self.wait_loop("loop.turn", lane, loop=loop)
        self.assertEqual((turn["payload"]["sequences"], turn["payload"]["run"]), ([1], 3))
        self.settle(lane, 3, "lane.delivered")
        self.assertEqual([again for _, _, _, again in HEADER.findall(self.stdin_of(lane, 3))], [" (again)"])
        self.stop_loop(loop)


class DetachTest(LoopTest):
    """G. `--detach`: a loop in the session `laneboss+loop`, which no lane's session can have."""

    def test_a_detached_loop(self):
        lane = "g-detach"
        self.turn_start(lane, "tforever")
        self.settle(lane, 1)
        printed = json.loads(self.detach().stdout)
        started = self.loop_events("loop.started")[-1]
        self.assertEqual(printed, {"loop": started["payload"]["loop"], "pid": started["payload"]["pid"],
                                   "session": "laneboss+loop"})
        self.assertIs(started["payload"]["detached"], True)
        # The tmux of this machine keeps the character `+` in the name of the session.
        self.assertIn("laneboss+loop", self.sessions())
        status = self.lane_json("loop", "--status")
        self.assertEqual((status["running"], status["detached"], status["session"], status["pid"]),
                         (True, True, "laneboss+loop", printed["pid"]))
        # No lane's session can have that name: the lane grammar refuses the character.
        self.start("laneboss+loop", "--runner", "tok", "--model", "tok-model-1", "--worktree", self.scratch("g-name"),
                   code=2)
        # A message starts a real turn: the detached loop does what the foreground loop does.
        self.sent(lane, "A message for a detached loop.\n")
        self.wait_loop("loop.turn", lane)
        record = self.record(lane, run=2)
        stopped = self.lane_json("loop", "--stop")
        self.assertEqual((stopped["stopped"], stopped["pid"]), (True, printed["pid"]))
        self.assertEqual(self.loop_events("loop.stopped")[-1]["payload"]["reason"], "stop")
        # The loop's session ends with its process; no session was killed by its name, and the turn goes on in its own.
        deadline = time.monotonic() + UNTIL
        while "laneboss+loop" in self.sessions():
            self.assertLess(time.monotonic(), deadline, "the session of the loop is still there")
            time.sleep(0.3)
        self.assertIn(lane, self.sessions())
        row = self.status(lane)
        self.assertEqual((row["running"], row["live"]["session_alive"], row["live"]["supervisor"]["alive"]),
                         (True, True, True))
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]] + record["children"])
        self.assertIs(self.lane_json("loop", "--status")["running"], False)

    def pane_command(self, fifo):
        """The command that `lane loop --detach` starts in the pane of the loop, as the installed launcher builds it
        (`loopcmd.loop_argv`). It is asked of the installed package in a process of its own, so that this test imports
        nothing of the package."""
        result = subprocess.run([str(support.faults_binary()), "lane", "__probe"],
                                input=json.dumps({"action": "loop-argv", "fifo": str(fifo)}),
                                env=self.env("alpha"), capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def hand_over(self, fifo, message, process, output):
        """Write the message to the FIFO once the child has it open for reading (as `lane loop --detach` does), then
        close it. The test fails, with what the child wrote, when the child ends first."""
        deadline = time.monotonic() + UNTIL
        while True:
            try:
                descriptor = os.open(str(fifo), os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError as error:
                if error.errno != errno.ENXIO:
                    raise
            if process.poll() is not None:
                self.fail("the loop ended with exit {} before it read its input: {!r}".format(
                    process.returncode, output.read_text(encoding="utf-8", errors="replace")))
            if time.monotonic() > deadline:
                self.fail("the loop did not open its FIFO within {} seconds".format(UNTIL))
            time.sleep(0.02)
        try:
            os.set_blocking(descriptor, True)
            view = memoryview(message)
            while view:
                view = view[os.write(descriptor, view):]
        except BrokenPipeError:
            self.fail("the loop stopped reading its input: {!r}".format(
                output.read_text(encoding="utf-8", errors="replace")))
        finally:
            os.close(descriptor)

    @staticmethod
    def stop_child(process):
        """The test's own safety net: a child that is still there is killed by its process id."""
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)

    def child_loop(self):
        """The detached loop without tmux: the command that `--detach` starts in the pane, run as an ordinary child of
        this test with the caller's environment, and given the same input through a FIFO of the state directory (mode
        0600, the same message: the caller's environment and the configuration and id of the loop). The child's exit
        status is the child's own, which `#{pane_dead_status}` of tmux is not: tmux 3.4 never records the status of some
        panes whose process ended. Returns (process, loop id, the file that holds its output)."""
        state = Path(self.paths()["state_dir"])
        loop_id = uuid.uuid4().hex
        fifo = state / ".loop-{}.fifo".format(loop_id)
        os.mkfifo(str(fifo), 0o600)
        environment = self.env("alpha")
        output = self.directory / "loop-child.out"
        with output.open("wb") as handle:
            process = subprocess.Popen(self.pane_command(fifo), cwd=str(state), env=environment,
                                       stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT)
        self.addCleanup(self.stop_child, process)
        message = json.dumps({"environment": environment, "spec": {"config": "alpha", "loop": loop_id}},
                             ensure_ascii=True).encode("ascii")
        self.hand_over(fifo, message, process, output)
        # The child has the FIFO open and has its input; as `--detach` does, the name goes.
        os.unlink(str(fifo))
        return process, loop_id, output

    def wait_child_started(self, process, loop_id, output):
        """The loop.started of this child, once it is stored; the test fails at once when the child has ended."""
        deadline = time.monotonic() + UNTIL
        while True:
            for item in self.loop_events("loop.started"):
                if item["payload"]["loop"] == loop_id:
                    return item
            if process.poll() is not None:
                self.fail("the loop ended with exit {} before loop.started: {!r}".format(
                    process.returncode, output.read_text(encoding="utf-8", errors="replace")))
            if time.monotonic() > deadline:
                self.fail("no loop.started of the loop within {} seconds".format(UNTIL))
            time.sleep(0.3)

    def test_an_unexpected_error_exits_70(self):
        lane = "g-crash"
        kept = self.running_turn(lane, ["A message for a turn that goes on.\n"])
        process, loop_id, output = self.child_loop()
        self.wait_child_started(process, loop_id, output)
        state = Path(self.paths()["state_dir"])
        runs = state / "lanes" / lane / "runs"
        # An error that nobody expected: the next pass of the loop looks at the run of the lane that goes on, and cannot
        # read the directory of the lane's run records (a permission error, which is not a refusal and not a missing file).
        self.addCleanup(os.chmod, str(runs), 0o700)
        self.assertIsNone(process.poll(), "the loop ended before the error was made")
        os.chmod(str(runs), 0)
        try:
            process.wait(timeout=UNTIL)
        except subprocess.TimeoutExpired:
            self.fail("the loop did not end within {} seconds after its run records were made unreadable".format(UNTIL))
        # The exit status is the one of the child, taken from the operating system: tmux is not asked.
        with self.subTest("the process ends with exit 70"):
            self.assertEqual(process.returncode, 70, "the loop wrote {!r}".format(
                output.read_text(encoding="utf-8", errors="replace")))
        with self.subTest("loop.stopped says error"):
            stopped = [item["payload"]["reason"] for item in self.loop_events("loop.stopped")
                       if item["payload"]["loop"] == loop_id]
            self.assertEqual(stopped, ["error"])
        with self.subTest("loop.log has the error"):
            log = (state / "loop.log").read_text(encoding="utf-8")
            self.assertIn("internal error", log)
            self.assertIn("PermissionError", log)
        with self.subTest("the status says no loop runs"):
            self.assertIs(self.lane_json("loop", "--status")["running"], False)
        os.chmod(str(runs), 0o700)
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([kept["pid"]] + kept["children"])

    def test_an_error_ends_a_detached_loop(self):
        # The same error through the real `--detach`: what is looked at is what tmux and the store can show without the
        # exit status of the pane (which tmux does not always record, so no test reads it): the session of the loop ends,
        # and the store and loop.log say what happened. The exit status itself is `test_an_unexpected_error_exits_70`.
        lane = "g-crash"
        kept = self.running_turn(lane, ["A message for a turn that goes on.\n"])
        printed = json.loads(self.detach().stdout)
        state = Path(self.paths()["state_dir"])
        runs = state / "lanes" / lane / "runs"
        self.addCleanup(os.chmod, str(runs), 0o700)
        os.chmod(str(runs), 0)
        stopped = self.wait_loop("loop.stopped")
        deadline = time.monotonic() + UNTIL
        while "laneboss+loop" in self.sessions():
            self.assertLess(time.monotonic(), deadline, "the session of the loop is still there")
            time.sleep(0.3)
        with self.subTest("loop.stopped says error"):
            self.assertEqual((stopped["payload"]["loop"], stopped["payload"]["reason"]), (printed["loop"], "error"))
        with self.subTest("loop.log has the error"):
            log = (state / "loop.log").read_text(encoding="utf-8")
            self.assertIn("internal error", log)
            self.assertIn("PermissionError", log)
        with self.subTest("the status says no loop runs"):
            self.assertIs(self.lane_json("loop", "--status")["running"], False)
        os.chmod(str(runs), 0o700)
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([kept["pid"]] + kept["children"])


class EnvironmentTest(LoopTest):
    """H. The turns that the loop starts get the environment it captured when it started, and no byte of that
    environment is written anywhere: not to an event, to loop.log, to loop.json, to a file or to any output."""

    NAME = "E2E_LOOP_PROBE"

    def setUp(self):
        super().setUp()
        self.value = "probe-{}-{}".format(time.time_ns(), uuid.uuid4().hex[:8])
        digest = hashlib.sha256(self.value.encode("utf-8")).hexdigest()
        resume = turn_resume("envcheck") + ["--env-name", self.NAME, "--env-sha256", digest]
        self.configure(overrides={"tenv": runner("tenv", "ok", TURN_START, None, resume, extra=STDIN)})

    def probe_environment(self):
        """The environment of the loop: the test's own, and the variable with its value."""
        environment = self.env("alpha")
        environment[self.NAME] = self.value
        return environment

    def assert_nowhere(self, *outputs):
        """The value is in no file of the state directory (the store, loop.log, the lanes' logs, the run records, the
        pending files, loop.json and the mail included), in no event that `event tail` prints and in no output given."""
        needle = self.value.encode("utf-8")
        state = Path(self.paths()["state_dir"])
        found = [str(path.relative_to(state)) for path in sorted(state.rglob("*"))
                 if path.is_file() and not path.is_symlink() and needle in path.read_bytes()]
        self.assertEqual(found, [])
        tail = self.run_laneboss("event", "tail", "--config", "alpha", environment=self.env("alpha")).stdout
        self.assertNotIn(self.value, tail)
        for text in outputs:
            self.assertNotIn(self.value, text)

    def person_turn(self, lane, run):
        """A turn that a person starts has the environment of that person, which has no such variable."""
        self.sent(lane, "A message for a turn that a person starts.\n")
        self.turn_json(lane)
        self.settle(lane, run, "lane.delivered")
        self.assertIs(self.record(lane, run=run, ended=True)["environment_seen"], False)

    def test_the_foreground_loop(self):
        lane = "h-env"
        self.turn_start(lane, "tenv")
        self.settle(lane, 1)
        loop, _ = self.start_loop(environment=self.probe_environment())
        self.sent(lane, "A message for a turn that looks at its environment.\n")
        self.wait_loop("loop.turn", lane, loop=loop)
        self.settle(lane, 2, "lane.delivered")
        # The turn has the variable, with that value; the stand-in says so by a fixed word and never prints the value.
        self.assertIs(self.record(lane, run=2, ended=True)["environment_seen"], True)
        log = (Path(self.paths()["state_dir"]) / "lanes" / lane / "output.log").read_text(encoding="utf-8")
        self.assertIn("standin: environment seen", log)
        self.assertTrue((Path(self.paths()["state_dir"]) / "loop.json").is_file())
        status = self.run_laneboss("lane", "loop", "--status", "--config", "alpha",
                                   environment=self.probe_environment())
        self.stop_loop(loop)
        self.person_turn(lane, 3)
        self.assertIn("standin: environment missing",
                      (Path(self.paths()["state_dir"]) / "lanes" / lane / "output.log").read_text(encoding="utf-8"))
        self.assert_nowhere(status.stdout, status.stderr, "".join(loop.lines), "".join(loop.errors))

    def test_the_detached_loop(self):
        lane, keeper = "h-detach", "h-keep"
        self.turn_start(lane, "tenv")
        self.settle(lane, 1)
        # The environment is the caller's, handed over through a FIFO, not the one the tmux server was started with. The
        # server already runs when `--detach` creates the loop's session, and was started by a command that did not have
        # the variable: a lane of the same configuration, started and given a turn with the plain environment, whose run
        # goes on. (Every tmux command of the launcher runs with a fixed environment of five names, `PATH`, `HOME`,
        # `LANG`, `TMPDIR` and `USER`, so a server that `--detach` starts itself holds none of the variable either: that
        # case is test_detach_starts_the_server.)
        kept = self.running_turn(keeper, ["A message that keeps a turn going.\n"])
        socket = self.paths()["socket"]
        before = self.tmux(socket, "show-environment", "-g").stdout
        self.assertNotIn(self.NAME, before)
        detached = self.detach(environment=self.probe_environment())
        # The server is the same one, and it still has no such variable: only the FIFO can have given it to the loop.
        self.assertIn(keeper, self.sessions())
        self.assertNotIn(self.NAME, self.tmux(socket, "show-environment", "-g").stdout)
        self.sent(lane, "A message for a turn that looks at its environment.\n")
        self.wait_loop("loop.turn", lane)
        self.settle(lane, 2, "lane.delivered")
        self.assertIs(self.record(lane, run=2, ended=True)["environment_seen"], True)
        self.assertTrue((Path(self.paths()["state_dir"]) / "loop.json").is_file())
        self.lane_json("loop", "--stop")
        self.person_turn(lane, 3)
        self.assert_nowhere(detached.stdout, detached.stderr)
        self.lane_json("stop", "--lane", keeper)
        self.assert_gone([kept["pid"]] + kept["children"])

    def test_detach_starts_the_server(self):
        """With no session of the configuration alive, `--detach` starts the tmux server itself, and the server of this
        launcher keeps, of the command that started it, only the fixed set of names it gives every tmux command: no
        other variable of that command, where `show-environment -g` would show it to every process that can reach the
        socket. The command here holds the variable, so the server must hold no other variable of it, and the loop's
        turn must have the variable all the same: only the FIFO can give it."""
        lane = "h-fresh"
        self.turn_start(lane, "tenv")
        self.settle(lane, 1)
        socket = self.paths()["socket"]
        deadline = time.monotonic() + UNTIL
        while self.tmux(socket, "list-sessions", code=None).returncode == 0:
            self.assertLess(time.monotonic(), deadline, "the tmux server of the configuration did not end")
            time.sleep(0.2)
        detached = self.detach(environment=self.probe_environment())
        # The loop's session is the only one, so `--detach` started the server, from an environment that has the
        # variable.
        self.assertEqual(self.sessions(), ["laneboss+loop"])
        output = self.tmux(socket, "show-environment", "-g").stdout
        self.assertTrue(any(line.startswith("PATH=") for line in output.splitlines()),
                        "the answer is not a server's environment: {!r}".format(output))
        self.assertNotIn(self.NAME, output)
        self.assertNotIn(self.value, output)
        self.sent(lane, "A message for a turn that looks at its environment.\n")
        self.wait_loop("loop.turn", lane)
        self.settle(lane, 2, "lane.delivered")
        self.assertIs(self.record(lane, run=2, ended=True)["environment_seen"], True)
        self.lane_json("loop", "--stop")
        self.person_turn(lane, 3)
        self.assert_nowhere(detached.stdout, detached.stderr)


class FormTest(HandTest):
    """I. The `loop.*` events: `event append` checks their form (and only theirs), `state verify` and `state rebuild`
    do not check them, and a store written by 1.1.0 that holds such events by hand still verifies and rebuilds."""

    STARTED = {"loop": LOOP, "pid": 4242, "start": "123456", "detached": False, "unrecorded_end": None}
    STOPPED = {"loop": LOOP, "reason": "stop", "turns": 1, "skips": 0}
    TURNED = {"loop": LOOP, "kind": "mail", "sequences": [1, 2], "run": 2}
    SKIPPED = {"loop": LOOP, "reason": "backoff", "until": "2026-10-11T08:00:00.000000Z",
               "after": {"run": 2, "reason": "exit"}, "detail": None}

    def accepts(self):
        """The forms of the design are accepted, whatever the actor and the protocol version say."""
        accepted = [
            ("loop.started", None, self.STARTED),
            ("loop.started", None, dict(self.STARTED, detached=True, unrecorded_end=OTHER,
                                        start="Sat Oct 10 08:00:00 2026")),
            ("loop.stopped", None, self.STOPPED),
            ("loop.stopped", None, dict(self.STOPPED, reason="error")),
            ("loop.turn", SOME, self.TURNED),
            ("loop.turn", SOME, dict(self.TURNED, kind="idle", sequences=[], run=3)),
            ("loop.skipped", SOME, self.SKIPPED),
            ("loop.skipped", SOME, dict(self.SKIPPED, reason="refused", after=None, until=None,
                                        detail="lane i-some-lane's runner tok cannot take turns")),
            ("loop.skipped", SOME, dict(self.SKIPPED, reason="no-room", after=None)),
        ]
        for kind, lane, payload in accepted:
            with self.subTest(kind=kind, payload=payload):
                self.put(kind, lane, payload, actor="laneboss", protocol_version="1.2.0")
        shown = self.store_events()
        self.assertEqual([(item["kind"], item["lane"], item["payload"]) for item in shown], accepted)
        self.assertEqual(self.laneboss_json("state", "verify", "--config", "alpha",
                                            environment=self.environment)["events"], len(accepted))

    def test_the_forms_are_checked_at_append(self):
        cases = [
            ("loop.started", None, {key: value for key, value in self.STARTED.items() if key != "unrecorded_end"},
             "must be an object with exactly"),
            ("loop.started", None, dict(self.STARTED, extra=1), "must be an object with exactly"),
            ("loop.started", None, dict(self.STARTED, loop="not-a-loop-id"), "payload.loop"),
            ("loop.started", None, dict(self.STARTED, pid=0), "payload.pid"),
            ("loop.started", None, dict(self.STARTED, pid="4242"), "payload.pid"),
            ("loop.started", None, dict(self.STARTED, start=""), "payload.start"),
            ("loop.started", None, dict(self.STARTED, detached="no"), "payload.detached"),
            ("loop.started", None, dict(self.STARTED, unrecorded_end="abc"), "payload.unrecorded_end"),
            ("loop.started", SOME, self.STARTED, "lane:"),
            ("loop.stopped", None, dict(self.STOPPED, reason="crash"), "payload.reason"),
            ("loop.stopped", None, dict(self.STOPPED, turns=-1), "payload.turns"),
            ("loop.stopped", None, {key: value for key, value in self.STOPPED.items() if key != "skips"},
             "must be an object with exactly"),
            ("loop.stopped", SOME, self.STOPPED, "lane:"),
            ("loop.turn", SOME, dict(self.TURNED, kind="retry"), "payload.kind"),
            ("loop.turn", SOME, dict(self.TURNED, sequences=[2, 1]), "payload.sequences"),
            ("loop.turn", SOME, dict(self.TURNED, sequences=[]), "payload.sequences"),
            ("loop.turn", SOME, dict(self.TURNED, kind="idle"), "payload.sequences"),
            ("loop.turn", SOME, dict(self.TURNED, run=1), "payload.run"),
            ("loop.turn", None, self.TURNED, "lane:"),
            ("loop.skipped", SOME, dict(self.SKIPPED, reason="no-room"), "payload.after"),
            ("loop.skipped", SOME, dict(self.SKIPPED, after=None), "payload.after"),
            ("loop.skipped", SOME, dict(self.SKIPPED, reason="refused"), "payload.after"),
            ("loop.skipped", SOME, dict(self.SKIPPED, until="tomorrow"), "payload.until"),
            ("loop.skipped", SOME, dict(self.SKIPPED, detail="x" * 201), "payload.detail"),
            ("loop.skipped", SOME, dict(self.SKIPPED, detail="two\nlines"), "payload.detail"),
            ("loop.skipped", SOME, dict(self.SKIPPED, after={"run": 2, "reason": "sleepy"}), "payload.after.reason"),
            ("loop.skipped", None, self.SKIPPED, "lane:"),
            ("loop.paused", None, {}, "kind: loop events are"),
        ]
        for kind, lane, payload, needle in cases:
            with self.subTest(kind=kind, lane=lane, payload=payload):
                self.refuse(kind, lane, payload, needle)
        self.accepts()

    def test_verify_and_rebuild_do_not_check(self):
        self.append(self.event("note.added", payload={"text": "before"}))
        store = self.where()["store"]
        planted = [
            ("loop.started", None, "somebody", "1.1.0", {"anything": [1, 2, 3], "id": "x"}),
            ("loop.turn", SOME, "e2e", "1.0.0", {"loop": "short", "kind": "retry", "sequences": "all", "run": 0}),
            ("loop.skipped", SOME, "laneboss", "1.2.0", dict(self.SKIPPED, extra=True)),
            ("loop.stopped", None, "laneboss", "1.2.0", {"reason": 7}),
            ("loop.paused", None, "somebody", "1.1.0", {}),
        ]
        for kind, lane, actor, version, payload in planted:
            plant_event(store, kind, lane, actor, version, payload)
        verified = self.laneboss_json("state", "verify", "--config", "alpha", environment=self.environment)
        self.assertEqual((verified["ok"], verified["events"]), (True, 1 + len(planted)))
        rebuilt = self.run_laneboss("state", "rebuild", "--config", "alpha", environment=self.environment).stdout
        self.assertEqual(rebuilt, self.run_laneboss("state", "lanes", "--config", "alpha",
                                                    environment=self.environment).stdout)
        self.assertEqual([item["kind"] for item in self.store_events()], ["note.added"] + [item[0] for item in planted])
        # The launcher refuses to append every one of them now.
        for kind, lane, actor, version, payload in planted:
            with self.subTest(kind=kind, payload=payload):
                self.put(kind, lane, payload, code=2, actor=actor, protocol_version=version)


class PlantedTest(LoopTest):
    """J. A `loop.*` event in another form, with another actor and protocol version, changes neither the loop's
    decisions nor its `unrecorded_end`: the loop trusts only an event in the documented form."""

    def test_other_forms_do_not_steer_it(self):
        lane = "j-planted"
        # A hold of 50 seconds is shorter than backoff_seconds here (60), so a loop that believed the skip below would
        # honour it. (A hold that is longer than backoff_seconds counts as over whatever its form, and could not show that
        # the form is looked at: `test_a_refused_hold_far_ahead_is_over`.)
        self.configure(turns=turns_table(backoff_seconds=60))
        self.turn_start(lane)
        self.settle(lane, 1)
        store = self.paths()["store"]
        held = datetime.now(timezone.utc) + timedelta(seconds=50)
        # A loop that never recorded its end, and two skips that would hold the lane back, all in other forms.
        plant_event(store, "loop.started", None, "somebody", "1.1.0", {"anything": 1})
        plant_event(store, "loop.skipped", lane, "somebody", "1.1.0",
                    {"reason": "backoff", "until": "2999-01-01T00:00:00.000000Z"})
        plant_event(store, "loop.skipped", lane, "laneboss", "1.2.0",
                    {"loop": LOOP, "reason": "refused", "until": held.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "after": None,
                     "detail": "held back", "extra": True})
        self.sent(lane, "A message that must start a turn.\n")
        loop, started = self.start_loop()
        self.assertIsNone(started["payload"]["unrecorded_end"])
        turn = self.wait_loop("loop.turn", lane, loop=loop)
        self.assertEqual((turn["payload"]["sequences"], turn["payload"]["run"]), ([1], 2))
        self.assertLess(at(turn), held)
        self.stop_loop(loop)
        # The loop recorded no skip of its own: the two in the store are the ones that were planted.
        self.assertEqual(len(self.loop_events("loop.skipped", lane)), 2)

    def test_a_refused_hold_far_ahead_is_over(self):
        lane = "j-hold"
        self.turn_start(lane)
        self.settle(lane, 1)
        # A skip in the documented form, which `event append` takes from anyone: reason refused, nothing after it, one line
        # of detail, and an `until` that lies a thousand years ahead. A hold that the loop sets after a refused attempt is
        # `backoff_seconds` long (3 here), so a hold that is longer than that was not set by a loop, or was set while the
        # clock was wrong, and it is over.
        far = "2999-01-01T00:00:00.000000Z"
        self.put("loop.skipped", lane, {"loop": LOOP, "reason": "refused", "until": far, "after": None,
                                        "detail": "held back for good"}, actor="laneboss", protocol_version="1.2.0")
        self.sent(lane, "A message that must start a turn.\n")
        loop, _ = self.start_loop()
        turn = self.wait_loop("loop.turn", lane, loop=loop)
        self.assertEqual((turn["payload"]["sequences"], turn["payload"]["run"]), ([1], 2))
        self.stop_loop(loop)
        # The loop recorded no skip of its own: the one in the store is the one that was appended.
        self.assertEqual(len(self.loop_events("loop.skipped", lane)), 1)


class CheckLaneTest(LoopTest):
    """K. `lane check --lane L` records the loss of that lane only; without `--lane` it checks every lane as before."""

    def test_check_records_one_lane(self):
        one, two = "k-one", "k-two"
        for lane in (one, two):
            self.running_turn(lane, ["A message for a turn that is lost.\n"])
        for lane in (one, two):
            self.lose_supervisor(lane)
        before = self.events()
        result = self.lane_json("check", "--lane", one)
        self.assertEqual((result["checked"], [item["lane"] for item in result["lost"]]), ([one], [one]))
        self.assertEqual([(item["kind"], item["lane"]) for item in self.events_since(before)],
                         [("lane.lost", one), ("lane.returned", one)])
        # The other lane is still taken for running: nothing recorded its loss.
        self.assertIs(self.status(two)["running"], True)
        rest = self.lane_json("check")
        self.assertEqual((rest["checked"], [item["lane"] for item in rest["lost"]]), ([two], [two]))

    def test_check_of_an_idle_lane(self):
        lane = "k-idle"
        self.turn_start(lane)
        self.settle(lane, 1)
        before = self.events()
        self.assertEqual(self.lane_json("check", "--lane", lane),
                         {"checked": [], "alive": [], "lost": [], "recorded": [], "refused": [], "pending": []})
        self.assertEqual(self.events(), before)

    def test_check_refuses_an_unknown_lane(self):
        before = self.events()
        self.assertIn("not known", self.lane("check", "--lane", "k-nobody", code=2).stderr)
        self.assertIn("--lane", self.lane("check", "--lane", "Not A Lane", code=2).stderr)
        self.assertEqual(self.events(), before)


class TurnsKeysTest(support.LauncherTest):
    """L. The keys of the loop in [turns]: poll_seconds, backoff_seconds and limit_backoff_seconds."""

    LIMITS = (("poll_seconds", 3600), ("backoff_seconds", 604800), ("limit_backoff_seconds", 604800))

    def check(self, tail, code):
        self.write_config("alpha", tail=tail)
        return self.run_laneboss("config", "validate", "alpha", code=code)

    def test_accepted(self):
        for key, top in self.LIMITS:
            for value in (1, top):
                with self.subTest(key=key, value=value):
                    self.check("\n[turns]\n{} = {}\n".format(key, value), 0)
                    self.assertEqual(self.laneboss_json("config", "show", "alpha")["config"]["turns"], {key: value})
        self.check("\n[turns]\npoll_seconds = 2\nbackoff_seconds = 30\nlimit_backoff_seconds = 300\n", 0)

    def test_refused(self):
        for key, top in self.LIMITS:
            range_note = "must be from 1 to {}".format(top)
            cases = (("0", range_note), (str(top + 1), range_note), ("-1", range_note), ('"5"', "must be an integer"),
                     ("1.5", "must be an integer"), ("true", "must be an integer"))
            for value, needle in cases:
                with self.subTest(key=key, value=value):
                    result = self.check("\n[turns]\n{} = {}\n".format(key, value), 2)
                    self.assertIn("invalid configuration:", result.stderr)
                    self.assertIn("turns." + key, result.stderr)
                    self.assertIn(needle, result.stderr)


class LastErrorTest(LoopTest):
    """M. `last_error` of `lane loop --status` and of loop.json: the latest failure of a pass, which is the line that the
    loop wrote to loop.log for it (its time and its text), kept until a later failure replaces it, and null when no
    loop that loop.json names lives. What `--status` prints never looks like a credential."""

    def state(self):
        return Path(self.paths()["state_dir"])

    def log(self, state):
        """[(time, text)] of the lines of loop.log, as the loop wrote them."""
        path = state / "loop.log"
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        return [tuple(line.split(" ", 1)) for line in lines]

    def wait_log(self, state, count, loop, timeout=60):
        """The lines of loop.log once there are `count` of them; the loop must still run. The file is read directly, because
        no launcher command runs while a test has broken the configuration."""
        deadline = time.monotonic() + timeout
        while len(self.log(state)) < count:
            self.assertIsNone(loop.process.poll(), loop.errors)
            self.assertLess(time.monotonic(), deadline, "loop.log has {} line(s), not {}".format(
                len(self.log(state)), count))
            time.sleep(0.3)
        return self.log(state)

    def loop_json(self, state):
        return json.loads((state / "loop.json").read_text(encoding="utf-8"))

    def put_loop_json(self, state, data):
        """loop.json replaced whole, as the loop replaces it."""
        temporary = state / "loop.json.test"
        temporary.write_text(json.dumps(data), encoding="utf-8")
        os.replace(str(temporary), str(state / "loop.json"))

    def install(self, turns):
        """The configuration `alpha` with this table [turns], put in place whole, so that a pass of the loop reads the old
        file or the new one and never half of one."""
        path = self.home / "configs" / "alpha" / "config.toml"
        temporary = path.with_name("config.toml.new")
        temporary.write_text(turn_config("alpha", turns), encoding="utf-8")
        os.replace(str(temporary), str(path))

    def last_error(self):
        return self.lane_json("loop", "--status").get("last_error", MISSING)

    def test_a_busy_store(self):
        lane = "m-busy"
        self.turn_start(lane, "tok", "--idle", "12")
        self.settle(lane, 1)
        state = self.state()
        loop, _ = self.start_loop()
        with self.subTest("before any failure"):
            self.assertIsNone(self.last_error())
            self.assertIsNone(self.loop_json(state).get("last_error", MISSING))
        # The idle turn is due after 12 seconds; its first record waits 10 seconds for the store, and the pass fails.
        release = self.hold_store()
        self.wait_log(state, 1, loop)
        release()
        # With the store free the loop goes on and starts the turn; the failure stays as the latest.
        self.wait_loop("loop.turn", lane, loop=loop)
        logged, text = self.log(state)[-1]
        with self.subTest("the status shows the latest line of loop.log"):
            self.assertEqual(self.last_error(), {"at": logged, "message": text})
        with self.subTest("the line says what failed, in SQLite's words"):
            self.assertIn("database is locked", text)
        with self.subTest("loop.json keeps the same object"):
            self.assertEqual(self.loop_json(state).get("last_error", MISSING), {"at": logged, "message": text})
        self.stop_loop(loop)
        with self.subTest("no loop: the status says null, and loop.json keeps the failure"):
            self.assertIsNone(self.last_error())
            self.assertEqual(self.loop_json(state).get("last_error", MISSING), {"at": logged, "message": text})

    def test_a_broken_configuration(self):
        lane = "m-config"
        self.turn_start(lane)
        self.settle(lane, 1)
        state = self.state()
        loop, _ = self.start_loop()
        # A key that [turns] does not have: every pass of the loop fails until the configuration is mended.
        self.install(turns_table() + "no_such_key = 5\n")
        self.wait_log(state, 1, loop)
        self.install(turns_table())
        time.sleep(3)
        lines = self.log(state)
        with self.subTest("every line is the failure, in the configuration's words"):
            for _, text in lines:
                self.assertIn("turns.no_such_key", text)
                self.assertIn("unknown key", text)
        with self.subTest("the status shows the latest line"):
            self.assertEqual(self.last_error(), {"at": lines[-1][0], "message": lines[-1][1]})
        # The passes since the repair succeed, and a good pass does not clear it.
        time.sleep(3)
        with self.subTest("kept after good passes"):
            self.assertEqual(self.log(state), lines)
            self.assertEqual(self.last_error(), {"at": lines[-1][0], "message": lines[-1][1]})
        # A later failure replaces it.
        self.install(turns_table() + "another_key = 5\n")
        self.wait_log(state, len(lines) + 1, loop)
        self.install(turns_table())
        time.sleep(3)
        later = self.log(state)
        with self.subTest("a later failure replaces it"):
            self.assertIn("turns.another_key", later[-1][1])
            self.assertEqual(self.last_error(), {"at": later[-1][0], "message": later[-1][1]})
            self.assertNotEqual(later[-1][0], lines[-1][0])
        self.stop_loop(loop)

    def test_a_line_like_a_credential(self):
        # The text of a failure is made of messages of the launcher, whose values were screened already, so no failure can
        # make it look like a credential; what is left to try is a loop.json that someone edited. What --status prints is
        # withheld the way the detail of a refused turn is.
        loop, _ = self.start_loop()
        state = self.state()
        data = self.loop_json(state)
        self.put_loop_json(state, dict(data, last_error={"at": PLANTED_AT, "message": "failed with " + TOKEN}))
        result = self.run_laneboss("lane", "loop", "--status", "--config", "alpha", environment=self.env("alpha"))
        status = json.loads(result.stdout)
        with self.subTest("the message is withheld, the time is kept"):
            self.assertEqual(status.get("last_error", MISSING), {"at": PLANTED_AT, "message": "(withheld)"})
        with self.subTest("the value is in no output"):
            self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.put_loop_json(state, data)
        self.stop_loop(loop)


class NextTest(LoopTest):
    """N. `next` in the entry of each lane of `--status`: what the loop would start for the lane now. `mail` when a message
    waits or has returned, `idle` when the lane has been idle for its interval, `backoff` when one of the two is due and
    the lane's latest end makes it wait, and null when there is nothing to start or the lane is running."""

    def test_next_of_five_lanes(self):
        self.configure(turns_table(backoff_seconds=600))
        mail, idle, none, backoff, running = "n-mail", "n-idle", "n-none", "n-backoff", "n-running"
        self.turn_start(mail)
        self.settle(mail, 1)
        self.sent(mail, "A message that waits for a turn.\n")
        self.turn_start(idle, "tok", "--idle", "1")
        self.settle(idle, 1)
        self.turn_start(none)
        self.settle(none, 1)
        self.turn_start(backoff, "tfail")
        self.settle(backoff, 1)
        self.sent(backoff, "A message for a runner that fails.\n")
        self.turn_json(backoff)
        self.settle(backoff, 2, "lane.returned")
        record = self.running_turn(running, ["A message for a turn that is still running.\n"])
        # The idle lane has been idle for its second, with no loop to start the turn.
        ended = at(self.wait_event("lane.ended", idle, run=1))
        while datetime.now(timezone.utc) < ended + timedelta(seconds=2):
            time.sleep(0.2)
        before = self.events()
        status = self.lane_json("loop", "--status")
        self.assertEqual(self.events(), before)
        entries = {entry["lane"]: entry for entry in status["lanes"]}
        self.assertEqual(sorted(entries), sorted([mail, idle, none, backoff, running]))
        with self.subTest("next, from five lanes in one status call"):
            self.assertEqual({lane: entry.get("next", MISSING) for lane, entry in entries.items()},
                             {mail: "mail", idle: "idle", none: None, backoff: "backoff", running: None})
        with self.subTest("the rest of the entries agree with it"):
            self.assertEqual({lane: (entry["waiting"], entry["backoff_until"] is not None, entry["bad_ends"])
                              for lane, entry in entries.items()},
                             {mail: (1, False, 0), idle: (0, False, 0), none: (0, False, 0), backoff: (1, True, 1),
                              running: (0, False, 0)})
        # The prediction is true: a loop started now starts the two turns the status named, records the wait of the lane in
        # back-off, and leaves the other two lanes alone.
        loop, _ = self.start_loop()
        turns = {lane: self.wait_loop("loop.turn", lane, loop=loop)["payload"]["kind"] for lane in (mail, idle)}
        skip = self.wait_loop("loop.skipped", backoff, loop=loop)
        time.sleep(3)
        with self.subTest("the loop does what next said"):
            self.assertEqual(turns, {mail: "mail", idle: "idle"})
            self.assertEqual(skip["payload"]["reason"], "backoff")
            self.assertEqual(sorted({item["lane"] for item in self.loop_events() if item["lane"]}),
                             sorted([mail, idle, backoff]))
        self.stop_loop(loop)
        self.lane_json("stop", "--lane", running)
        self.assert_gone([record["pid"]] + record["children"])

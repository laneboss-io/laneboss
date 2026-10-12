"""Helpers shared by the tests of mail and turns (docs/architecture.md, "Turns, mail, the loop and attach").

`Hand` is a mixin with the helpers of the tests that write lane events by hand through `event append`, the launcher's
own interface for hand-written events: the payloads of a turn-based lane's events, and checks of what the store did
with them. `HandTest` is a test with the plain configuration of the launcher tests and no runner at all, `TurnTest` one
with the lane tests' configuration plus runners that take turns. Nothing here imports the package under test: every
assertion goes through the installed command.
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import time
import uuid

from . import lanesupport, support
from .lanesupport import runner

# The lane's session identifier of the hand-made lanes: a UUID in its usual lower-case form.
SESSION = "0f5c9a3e-7b1d-4e6a-9c2f-3a8d1b7e5c40"
LAUNCHER_BLOCK = "<!-- laneboss launcher block: begin (protocol 1.2.0) -->"
# The header line of a message in a turn's prompt: sequence, sender, time and the mark of a returned message.
HEADER = re.compile(r"^## Message ([0-9]+) from (\S+) at (\S+?)( \(again\))?$", re.MULTILINE)
IDLE = "Check in: say in one line what you are doing.\n"


def turn_started(paths, lane, run=1, how="start", mail=(), idle=None, runner_name="local", session_id=SESSION,
                 account="account-two"):
    """A lane.started payload of a turn: the keys `mail` and `idle_seconds` and the lane's session identifier."""
    payload = support.started_payload(paths, lane, run=run, how=how, account=account)
    payload.update(runner=runner_name, mail=list(mail), idle_seconds=idle, session_id=session_id)
    return payload


def ended(run=1, reason="exit", code=0, prompt="written", length=1000):
    """A lane.ended payload. `prompt` is written, cut or None (the key is then absent, as in a store written before the
    prompt was recorded, or by hand)."""
    payload = support.ended_payload(run, reason)
    payload["exit_code"] = code
    if reason in ("limit", "dropped"):
        payload.update(pattern=reason + "_patterns[0]", classification="matched")
    if prompt == "written":
        payload["prompt"] = {"state": "written", "bytes": length, "length": length}
    elif prompt == "cut":
        payload["prompt"] = {"state": "cut", "bytes": length // 2, "length": length}
    return payload


def mailed(sequence, text="a message\n", sender="supervisor"):
    """A lane.mailed payload for a message with this text."""
    data = text.encode("utf-8")
    return {"sequence": sequence, "sender": sender, "sha256": support.digest(data), "bytes": len(data)}


def gone(run):
    """A lane.gone payload for the launch of this run (the launches of the hand-made lanes are numbered by run)."""
    return {"run": run, "launch": "0" * 31 + str(run)}


def mail_state(last=0, waiting=(), returned=(), in_flight=None, delivered=0, settled=None, turn_based=True, idle=None):
    """The row's `mail` field as the design gives it."""
    return {"turn_based": turn_based, "idle_seconds": idle, "last": last, "waiting": list(waiting),
            "returned": list(returned), "in_flight": in_flight, "delivered": delivered, "settled": settled}


def settled(run, outcome, sequences, reason=None, announced=False):
    return {"run": run, "outcome": outcome, "reason": reason, "sequences": list(sequences), "announced": announced}


def message_name(sequence, text):
    """The name of a message's file in lanes/LANE/mail: nine digits of sequence, a hyphen, the SHA-256 of its bytes."""
    return "{:09d}-{}".format(sequence, support.digest(text))


def canonical(value):
    """The canonical JSON the store hashes and keeps (docs/architecture.md, "Hash"): sorted keys, no white space."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def plant_event(store, kind, lane, actor, protocol_version, payload, occurred_at=None):
    """Write one event straight into the store file, as a store written by 1.1.0 could hold it: `event append` refuses a
    `loop.*` event that is not in the documented form since the loop is built, and `state verify` and `state rebuild` do
    not check one. The row is what EventStore.append() writes, and its hash is the one `state verify` recomputes (the
    SHA-256 of the canonical JSON of the envelope fields, seq and recorded_at), so a store that still verifies shows that
    the row is right. Returns the event's id."""
    event = {"id": "ev-" + uuid.uuid4().hex, "kind": kind, "lane": lane, "actor": actor, "occurred_at": occurred_at,
             "payload": payload, "protocol_version": protocol_version}
    connection = sqlite3.connect(str(store), timeout=30, isolation_level=None)
    try:
        connection.execute("BEGIN IMMEDIATE")
        event["seq"] = connection.execute(
            "SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0), "
            "coalesce((SELECT max(seq) FROM events), 0)) + 1").fetchone()[0]
        event["recorded_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        digest = hashlib.sha256(canonical(event).encode("utf-8")).hexdigest()
        connection.execute(
            "INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event["seq"], event["id"], kind, lane, actor, occurred_at, canonical(payload), protocol_version,
             event["recorded_at"], digest))
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return event["id"]


class Hand:
    """Helpers of tests that write the events of turn-based lanes by hand. The class that mixes this in has a
    configuration `alpha`, and gives `where()`."""

    def where(self):
        """`laneboss config path alpha`: the socket and state directory of the configuration."""
        if getattr(self, "_where", None) is None:
            self._where = self.laneboss_json("config", "path", "alpha", environment=self.environment)
        return self._where

    def put(self, kind, lane, payload, code=0, **fields):
        return self.append(self.event(kind, lane=lane, payload=payload, **fields), code=code)

    def store_events(self):
        return self.laneboss_json("state", "events", "--config", "alpha", environment=self.environment)

    def row(self, lane):
        rows = self.laneboss_json("state", "lanes", "--config", "alpha", environment=self.environment)
        return {item["lane"]: item for item in rows}[lane]

    def mail(self, lane):
        return self.row(lane)["mail"]

    def refuse(self, kind, lane, payload, needle, **fields):
        """The event is refused (exit 2) with `needle` in the message, and the store holds what it held before."""
        before = self.store_events()
        result = self.put(kind, lane, payload, code=2, **fields)
        self.assertIn(needle, result.stderr, "{} for {}: {}".format(kind, lane, result.stderr))
        self.assertEqual(self.store_events(), before, "{} for {} left an event behind".format(kind, lane))

    def turn_lane(self, lane, idle=None, prompt="written", runner_name="local"):
        """A lane started by hand as a turn-based lane whose first run has ended: state waiting, no mail."""
        self.put("lane.started", lane, turn_started(self.where(), lane, 1, "start", [], idle, runner_name))
        self.put("lane.ended", lane, ended(1, prompt=prompt))

    def turn(self, lane, run, mail, idle=None, runner_name="local", after="exit"):
        """The events that open a turn: lane.resumed, then lane.started with the mail it carries."""
        self.put("lane.resumed", lane, {"run": run, "after": after, "message": None})
        self.put("lane.started", lane, turn_started(self.where(), lane, run, "resume", mail, idle, runner_name))

    def mail_directory(self, lane):
        return Path(self.where()["state_dir"]) / "lanes" / lane / "mail"

    def write_mail(self, lane, sequence, text, name=None):
        """A message file as `lane send` leaves it, written by hand."""
        directory = self.mail_directory(lane)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / (name or message_name(sequence, text))
        path.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
        return path


class HandTest(Hand, support.LauncherTest):
    """The configuration `alpha` of the launcher tests (its one runner is not a runner that takes turns)."""

    def setUp(self):
        super().setUp()
        self._where = None
        self.write_config("alpha")


# Runners that take turns: {session} in both templates, the prompt on standard input and a resume template. The first
# turn of each is the stand-in's `ok`; the behaviour after the slash is the one the turns after it have.
TURN_START = ["--lane", "{lane}", "--session-id", "{session}"]


def turn_resume(mode):
    return [mode, "resumed", "--lane", "{lane}", "--resume", "{session}"]


STDIN = 'prompt = "stdin"\n'
TURN_MODES = {"tok": "ok", "tfail": "fail", "tlimit": "limit0", "tshut": "shut", "tidle": "idle-open",
              "tdeaf": "deaf", "tstubborn": "stubborn", "tforever": "forever", "twait": "waiter", "tnap": "nap"}


def turn_runners(overrides=None):
    """The lane tests' runners that take turns, and the runners that nearly do, each lacking one part. `overrides` maps
    a runner's name to the text of its table, for a test that edits a runner between two commands."""
    parts = {name: runner(name, "ok", TURN_START, None, turn_resume(mode), extra=STDIN)
             for name, mode in TURN_MODES.items()}
    parts["tbare"] = runner("tbare", "ok", TURN_START, None, turn_resume("ok"), extra=STDIN, patterns="")
    # Lacking {session} in both templates, the prompt on standard input, and a resume template, one at a time.
    parts["tnosess"] = runner("tnosess", "ok", ["--lane", "{lane}"], None, ["ok", "resumed", "--lane", "{lane}"],
                              extra=STDIN)
    parts["targ"] = runner("targ", "ok", TURN_START + ["--brief", "{brief}"], None,
                           turn_resume("ok") + ["--message", "{message}"])
    parts["tnores"] = runner("tnores", "ok", TURN_START, None, None, extra=STDIN)
    parts.update(overrides or {})
    return "".join(parts[name] for name in sorted(parts))


def turn_config(name, tail="", overrides=None):
    """The lane tests' configuration, with the runners that take turns, and `tail` (more tables) at the end."""
    return lanesupport.lane_config(name) + "\n" + turn_runners(overrides) + tail


class TurnTest(Hand, lanesupport.LaneTest):
    """The lane tests' configuration `alpha` with runners that take turns, on stand-in runner programs."""

    def add_config(self, name):
        directory = super().add_config(name)
        (directory / "config.toml").write_text(turn_config(name), encoding="utf-8")
        return directory

    def rewrite(self, tail="", name="alpha", overrides=None):
        (self.home / "configs" / name / "config.toml").write_text(turn_config(name, tail, overrides), encoding="utf-8")

    def turn_start(self, lane, runner_name="tok", *arguments, **options):
        """lane start --turns on a scratch directory with a runner that takes turns."""
        return self.start(lane, "--turns", "--runner", runner_name, "--model", runner_name + "-model-1", "--worktree",
                          self.scratch(lane), *arguments, **options)

    def plain_start(self, lane, runner_name="tok", *arguments, **options):
        """lane start of the same runner without --turns: an ordinary lane."""
        return self.start(lane, "--runner", runner_name, "--model", runner_name + "-model-1", "--worktree",
                          self.scratch(lane), *arguments, **options)

    def settle(self, lane, run, announced=None, config="alpha"):
        """Wait until the run has ended, its announcement (lane.delivered or lane.returned) is stored when the run
        carried mail, and the supervising process and its tmux session are gone, so that the next command on the lane
        is not refused for a run that is still being wrapped up."""
        self.wait_event("lane.ended", lane, run=run, config=config)
        if announced is not None:
            self.wait_event(announced, lane, run=run, config=config)
        deadline = time.monotonic() + lanesupport.UNTIL
        while True:
            live = self.status(lane, config=config)["live"]
            if not (live["supervisor"] and live["supervisor"]["alive"]) and not live["session_alive"]:
                return
            self.assertLess(time.monotonic(), deadline, "the supervising process of run {} did not end".format(run))
            time.sleep(0.2)

    def running_turn(self, lane, texts, runner_name="tforever"):
        """A turn-based lane whose first run has ended, these messages sent and a turn (run 2) going on, whose stand-in
        runs until it is stopped. Returns the stand-in's record of that turn."""
        self.turn_start(lane, runner_name)
        self.settle(lane, 1)
        for text in texts:
            self.sent(lane, text)
        self.turn_json(lane)
        return self.record(lane, run=2)

    def lose_supervisor(self, lane, config="alpha"):
        """SIGKILL the supervising process of the lane's run, once it has sampled the run's tree a few times, and wait
        until its tmux session is gone too (a session ends with its only process); the run's own processes go on."""
        self.kill_supervisor(lane, config=config)
        deadline = time.monotonic() + lanesupport.UNTIL
        while self.status(lane, config=config)["live"]["session_alive"]:
            self.assertLess(time.monotonic(), deadline, "the session of the killed supervising process did not end")
            time.sleep(0.2)

    def remove_processes(self, record):
        """Kill the stand-in's own processes (the runner and its children) by their process ids and wait until they are
        gone: what a test does for the processes of a run that nothing else would remove."""
        pids = [record["pid"]] + record["children"]
        for pid in pids:
            if self.alive(pid):
                os.kill(pid, signal.SIGKILL)
        self.assert_gone(pids)

    def events_since(self, before):
        """The events stored after this list of events (the store only grows, and the list must be its start)."""
        events = self.events()
        self.assertEqual(events[:len(before)], before)
        return events[len(before):]

    def briefing_json(self):
        """laneboss start --format json, bound to the configuration alpha."""
        return json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json",
                                            environment=self.env("alpha")).stdout)

    def message_file(self, text):
        """A file holding this message, in a directory of the test's own."""
        directory = self.directory / "messages"
        directory.mkdir(exist_ok=True)
        path = directory / "message-{}.md".format(len(os.listdir(str(directory))) + 1)
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        return path

    def sent(self, lane, text, sender=None):
        """lane send of this text, from a file; the JSON it prints."""
        extra = ["--from", sender] if sender else []
        return self.lane_json("send", "--lane", lane, "--file", self.message_file(text), *extra)

    def turn_json(self, lane, *arguments):
        """lane turn; the JSON it prints."""
        return self.lane_json("turn", "--lane", lane, *arguments)

    def stdin_of(self, lane, run):
        """What the stand-in read on its standard input in this run (it keeps the bytes in its record), as text."""
        record = self.record(lane, run=run, ended=True)
        return base64.b64decode(record["stdin"]["base64"]).decode("utf-8")

    def mailed_at(self, lane):
        """{sequence: (sender, time)} of the lane.mailed events: the header line of a message names them."""
        return {item["payload"]["sequence"]: (item["payload"]["sender"], item["occurred_at"] or item["recorded_at"])
                for item in self.lane_events(lane, "lane.mailed")}


def header_line(sequence, sender, at, again=False):
    """The header line of a message in a turn's prompt, as the design gives it."""
    return "## Message {} from {} at {}{}".format(sequence, sender, at, " (again)" if again else "")


def joined(messages):
    """The follow-up message a turn builds from these messages, written out from the design: for each message a header
    line, an empty line and its text with a final newline added when it has none; an empty line between two messages.
    `messages` is a list of (sequence, sender, time, text, again)."""
    parts = []
    for sequence, sender, at, text, again in messages:
        parts.append(header_line(sequence, sender, at, again) + "\n\n" + (text if text.endswith("\n") else text + "\n"))
    return "\n".join(parts)

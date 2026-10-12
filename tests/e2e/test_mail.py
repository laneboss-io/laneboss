"""T2, `lane send` and the mail directory (docs/architecture.md, "Mail (built by T2)").

A. a message is stored as an immutable file named by its sequence and digest, announced by an event that holds no text;
B. every refusal leaves no file and no event; C. the mail lock orders two sends and its wait is bounded; D. an orphan is
inert, and the same bytes send it back to life; E. the store being busy leaves a file and no message; F. the numbers
of the design (262,144 bytes, 1,000 messages waiting) are the limits.

The lanes are written by hand, as turn-based lanes whose first run has ended: `lane send` needs no run. The runners are
the stand-in program's, which only the configuration names.
"""

from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

from . import mailsupport, support
from .mailsupport import mailed, message_name


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# A credential shape, made here so that no file of the repository holds one.
TOKEN = "gh" + "p_" + "Z9y8X7w6V5u4T3s2R1q0" + "P9o8N7m6L5k4J3i2"
PLAIN = "A line of plain words that only gives the message its size.\n"


class SendTest(mailsupport.TurnTest):
    def message(self, name, data):
        directory = self.directory / "messages"
        directory.mkdir(exist_ok=True)
        path = directory / (name + ".md")
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def mail_dir(self, lane):
        return Path(self.paths()["state_dir"]) / "lanes" / lane / "mail"

    def mail_files(self, lane):
        directory = self.mail_dir(lane)
        return sorted(os.listdir(str(directory))) if directory.is_dir() else []

    def send(self, lane, data, *options, code=0, name="m"):
        return self.lane("send", "--lane", lane, "--file", self.message(name, data), *options, code=code)

    def refused(self, lane, data, needle, *options):
        """The send is refused (exit 2) with `needle` in the message, and leaves no file and no event."""
        before = (self.events(), self.mail_files(lane))
        result = self.send(lane, data, *options, code=2)
        self.assertIn(needle, result.stderr, result.stderr)
        self.assertEqual((self.events(), self.mail_files(lane)), before)
        return result

    def verified(self):
        return self.laneboss_json("state", "verify", "--config", "alpha", environment=self.env("alpha"))

    def test_files_and_standard_input(self):
        lane = "s-lane"
        self.turn_lane(lane, runner_name="tok")
        texts = ["The first message, from a file.\n", "The second, on standard input, without a final newline",
                 "The third, from a named sender: é 中.\n"]
        first = self.lane_json("send", "--lane", lane, "--file", self.message("one", texts[0]))
        second = json.loads(self.run_laneboss("lane", "send", "--config", "alpha", "--lane", lane, "-",
                                              stdin=texts[1], environment=self.env("alpha")).stdout)
        third = self.lane_json("send", "--lane", lane, "--file", self.message("three", texts[2]), "--from", "alice")
        senders = ["supervisor", "supervisor", "alice"]
        for number, (result, text, sender) in enumerate(zip((first, second, third), texts, senders), 1):
            data = text.encode("utf-8")
            path = self.mail_dir(lane) / message_name(number, text)
            self.assertEqual({key: result[key] for key in ("lane", "sequence", "sender", "sha256", "bytes", "file",
                                                           "waiting")},
                             {"lane": lane, "sequence": number, "sender": sender, "sha256": support.digest(data),
                              "bytes": len(data), "file": str(path), "waiting": number})
            self.assertEqual(sorted(result), ["bytes", "event", "file", "lane", "sender", "sequence", "sha256",
                                              "waiting"])
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(self.mail_files(lane), sorted(message_name(n, t) for n, t in enumerate(texts, 1)))
        # The events carry the sequence, the sender, the hash and the size, and no text, from the supervisor.
        events = self.lane_events(lane, "lane.mailed")
        self.assertEqual([item["payload"]["sequence"] for item in events], [1, 2, 3])
        self.assertEqual([item["payload"]["sender"] for item in events], senders)
        for item, text in zip(events, texts):
            data = text.encode("utf-8")
            self.assertEqual(item["payload"], {"sequence": item["payload"]["sequence"], "sender": item["payload"]["sender"],
                                               "sha256": support.digest(data), "bytes": len(data)})
            self.assertEqual(item["actor"], "supervisor")
        self.assertEqual(first["event"]["seq"], events[0]["seq"])
        everything = json.dumps(self.events(), ensure_ascii=False)
        for text in texts:
            self.assertNotIn(text.strip(), everything)
        row = self.status(lane)
        self.assertEqual((row["mail"]["last"], row["mail"]["waiting"], row["state"]), (3, [1, 2, 3], "waiting"))
        verified = self.verified()
        self.assertEqual((verified["ok"], verified["mail_files"], verified["mail_orphans"]), (True, 3, 0))
        self.assert_sound()

    def test_the_message_is_never_an_argument(self):
        # The text comes from a file or from standard input: a lane send without either is refused, and so is one with
        # both, and an argument that is a message.
        lane = "s-args"
        self.turn_lane(lane, runner_name="tok")
        before = self.events()
        self.assertIn("--file", self.lane("send", "--lane", lane, code=2).stderr)
        self.lane("send", "--lane", lane, "--file", self.message("m", "x\n"), "-", code=2)
        self.lane("send", "--lane", lane, "a message given as an argument", code=2)
        self.assertEqual(self.events(), before)
        self.assertEqual(self.mail_files(lane), [])

    def test_refusals_leave_nothing(self):
        lane = "s-bad"
        self.turn_lane(lane, runner_name="tok")
        self.refused(lane, b"\xff\xfe not UTF-8 \xfa", "UTF-8")
        self.refused(lane, b"", "empty")
        self.refused(lane, " \n\t \n", "empty")
        self.refused(lane, "x" * 262145, "262144")
        self.refused(lane, "A message that holds a block.\n" + mailsupport.LAUNCHER_BLOCK + "\n", "launcher block")
        result = self.refused(lane, "The first line.\nThe key is " + TOKEN + " on the second.\n", "line 2")
        self.assertIn("credential", result.stderr)
        self.assertNotIn(TOKEN, result.stderr)
        self.assertNotIn(TOKEN[8:], result.stderr)
        for sender in ("bad name", "-x", "x" * 65, "", TOKEN, "a/b"):
            with self.subTest(sender=sender[:12]):
                result = self.refused(lane, "A fine message.\n", "--from", "--from", sender)
                self.assertNotIn(TOKEN, result.stderr)
        # None of it left a trace, and a good message is stored as the first.
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])
        self.assertEqual(self.send(lane, "A fine message.\n").stdout.count("\"sequence\": 1"), 1)

    def test_lanes_that_cannot_take_mail(self):
        paths = self.where()
        # An ordinary lane, as main writes it; an abandoned one; an abandoned one that was cleaned; one nobody started.
        self.put("lane.started", "s-plain", support.started_payload(paths, "s-plain"))
        self.put("lane.ended", "s-plain", support.ended_payload(1))
        self.turn_lane("s-abn", runner_name="tok")
        self.put("lane.state", "s-abn", {"state": "abandoned"})
        self.turn_lane("s-cln", runner_name="tok")
        self.put("lane.state", "s-cln", {"state": "abandoned"})
        self.put("lane.cleaned", "s-cln", {"removed": [], "kept": [
            {"item": "lane-directory", "path": "/srv/example/lanes/s-cln", "why": "record"}]})
        for lane, needle in (("s-plain", "not turn-based"), ("s-abn", "abandoned"), ("s-cln", "cleaned"),
                             ("s-nobody", "not known")):
            with self.subTest(lane=lane):
                self.refused(lane, "A message for " + lane + ".\n", needle)

    def test_runners_that_cannot_take_turns(self):
        # The configuration as it is now decides: each part that is missing is named.
        for lane, runner, needles in (("s-nosess", "tnosess", ("{session}",)), ("s-noarg", "targ", ('prompt = "stdin"',)),
                                      ("s-nores", "tnores", ("resume template",)),
                                      ("s-norunner", "tghost", ("tghost", "not defined"))):
            self.turn_lane(lane, runner_name=runner)
            for needle in needles:
                with self.subTest(lane=lane, needle=needle):
                    self.refused(lane, "A message.\n", needle)
        self.assertEqual(self.lane_events("s-nosess", "lane.mailed"), [])

    def test_the_size_limit(self):
        lane = "s-size"
        self.turn_lane(lane, runner_name="tok")
        text = (PLAIN * 5000)[:262144]
        self.assertEqual(len(text.encode("utf-8")), 262144)
        sent = self.send(lane, text)
        self.assertEqual(json.loads(sent.stdout)["bytes"], 262144)
        self.refused(lane, text + "x", "262144")
        verified = self.verified()
        self.assertEqual((verified["mail_files"], verified["mail_orphans"]), (1, 0))


class LockTest(mailsupport.TurnTest):
    """C. The mail lock is `lanes/LANE/mail.lock`: a send waits for it, at most [lanes] lock_wait_seconds."""

    def hold(self, lane):
        directory = Path(self.paths()["state_dir"]) / "lanes" / lane
        directory.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(directory / "mail.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        self.held = descriptor

    def release(self):
        if self.held is not None:
            fcntl.flock(self.held, fcntl.LOCK_UN)
            os.close(self.held)
            self.held = None

    def setUp(self):
        super().setUp()
        self.held = None
        self.addCleanup(self.release)

    def message(self, name, text):
        directory = self.directory / "messages"
        directory.mkdir(exist_ok=True)
        path = directory / (name + ".md")
        path.write_text(text, encoding="utf-8")
        return path

    def test_a_send_waits_for_the_lock(self):
        lane = "c-wait"
        self.turn_lane(lane, runner_name="tok")
        self.hold(lane)
        process = subprocess.Popen([str(self.command), "lane", "send", "--config", "alpha", "--lane", lane, "--file",
                                    str(self.message("held", "Sent while the lock is held.\n"))],
                                   cwd=str(self.directory), env=self.env("alpha"), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, encoding="utf-8")
        self.addCleanup(lambda: process.poll() is None and process.kill())
        time.sleep(2.0)
        # The send can have stored nothing while the lock is held: it is still waiting.
        self.assertIsNone(process.poll(), "the send did not wait for the lock")
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])
        self.assertFalse((Path(self.paths()["state_dir"]) / "lanes" / lane / "mail").exists())
        self.release()
        out, err = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 0, err)
        self.assertEqual(json.loads(out)["sequence"], 1)
        self.assertEqual([item["payload"]["sequence"] for item in self.lane_events(lane, "lane.mailed")], [1])

    def test_the_wait_is_bounded(self):
        path = self.home / "configs" / "alpha" / "config.toml"
        text = path.read_text(encoding="utf-8")
        self.assertIn("stop_grace_seconds = 2\n", text)
        path.write_text(text.replace("stop_grace_seconds = 2\n", "stop_grace_seconds = 2\nlock_wait_seconds = 1\n"),
                        encoding="utf-8")
        lane = "c-bound"
        self.turn_lane(lane, runner_name="tok")
        self.hold(lane)
        events = self.events()
        result = self.lane("send", "--lane", lane, "--file", self.message("late", "Too late.\n"), code=2)
        self.assertIn("mail lock", result.stderr)
        self.assertIn("lock_wait_seconds", result.stderr)
        self.assertEqual(self.events(), events)
        self.assertFalse((Path(self.paths()["state_dir"]) / "lanes" / lane / "mail").exists())
        self.release()
        self.assertEqual(self.lane_json("send", "--lane", lane, "--file", self.message("late", "Too late.\n"))["sequence"], 1)

    def test_two_sends_at_once(self):
        # Sends that overlap are ordered by the lock; sends that do not overlap succeed without it, so this proves the
        # sequence numbers only: two messages, two sequences, no gap.
        lane = "c-two"
        self.turn_lane(lane, runner_name="tok")
        processes = []
        for number in (1, 2):
            path = self.message("two-{}".format(number), "Message {} of two at once.\n".format(number))
            processes.append(subprocess.Popen([str(self.command), "lane", "send", "--config", "alpha", "--lane", lane,
                                               "--file", str(path)], cwd=str(self.directory), env=self.env("alpha"),
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                              encoding="utf-8"))
        results = [process.communicate(timeout=60) for process in processes]
        for process, (out, err) in zip(processes, results):
            self.assertEqual(process.returncode, 0, err)
        self.assertEqual(sorted(json.loads(out)["sequence"] for out, _ in results), [1, 2])
        self.assertEqual([item["payload"]["sequence"] for item in self.lane_events(lane, "lane.mailed")], [1, 2])
        self.assert_sound()


class OrphanTest(mailsupport.TurnTest):
    """D. An orphan is a complete file by the grammar that no event names: inert, counted, and the same bytes give it
    its meaning back. Two sends of the same bytes are two messages."""

    def message(self, name, text):
        directory = self.directory / "messages"
        directory.mkdir(exist_ok=True)
        path = directory / (name + ".md")
        path.write_text(text, encoding="utf-8")
        return path

    def test_the_same_bytes_take_an_orphan(self):
        lane = "o-same"
        self.turn_lane(lane, runner_name="tok")
        text = "A message that has an orphan.\n"
        orphan = self.write_mail(lane, 1, text)
        verified = self.laneboss_json("state", "verify", "--config", "alpha", environment=self.env("alpha"))
        self.assertEqual((verified["ok"], verified["mail_files"], verified["mail_orphans"]), (True, 1, 1))
        self.assertEqual(self.status(lane)["mail"]["waiting"], [])
        sent = self.lane_json("send", "--lane", lane, "--file", self.message("same", text))
        self.assertEqual((sent["sequence"], sent["file"]), (1, str(orphan)))
        verified = self.laneboss_json("state", "verify", "--config", "alpha", environment=self.env("alpha"))
        self.assertEqual((verified["mail_files"], verified["mail_orphans"]), (1, 0))
        self.assertEqual(len(self.lane_events(lane, "lane.mailed")), 1)

    def test_other_bytes_leave_the_orphan(self):
        lane = "o-other"
        self.turn_lane(lane, runner_name="tok")
        orphan = self.write_mail(lane, 1, "The orphan's bytes.\n")
        sent = self.lane_json("send", "--lane", lane, "--file", self.message("other", "Other bytes.\n"))
        self.assertEqual(sent["sequence"], 1)
        self.assertNotEqual(sent["file"], str(orphan))
        self.assertTrue(orphan.is_file())
        verified = self.laneboss_json("state", "verify", "--config", "alpha", environment=self.env("alpha"))
        self.assertEqual((verified["mail_files"], verified["mail_orphans"]), (2, 1))

    def test_a_resend_is_a_second_message(self):
        lane = "o-twice"
        self.turn_lane(lane, runner_name="tok")
        path = self.message("twice", "The same bytes twice.\n")
        first = self.lane_json("send", "--lane", lane, "--file", path)
        second = self.lane_json("send", "--lane", lane, "--file", path)
        self.assertEqual((first["sequence"], second["sequence"], second["waiting"]), (1, 2, 2))
        self.assertNotEqual(first["file"], second["file"])
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(self.status(lane)["mail"]["waiting"], [1, 2])
        verified = self.laneboss_json("state", "verify", "--config", "alpha", environment=self.env("alpha"))
        self.assertEqual((verified["mail_files"], verified["mail_orphans"]), (2, 0))

    def test_a_file_under_a_wrong_name(self):
        # Left by an interrupted send of other bytes under the name of these: the send is an integrity problem.
        lane = "o-wrong"
        self.turn_lane(lane, runner_name="tok")
        text = "The bytes whose name is taken.\n"
        self.write_mail(lane, 1, b"not what its name says", name=message_name(1, text))
        events = self.events()
        result = self.lane("send", "--lane", lane, "--file", self.message("taken", text), code=3)
        self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
        self.assertEqual(self.events(), events)


class BusyTest(mailsupport.TurnTest):
    """E. A busy store: the send waits up to 10 seconds and is refused; its file stays, and the same bytes sent again
    reuse it."""

    def test_the_store_is_busy(self):
        lane = "b-busy"
        self.turn_lane(lane, runner_name="tok")
        text = "A message for a busy store.\n"
        path = self.directory / "busy.md"
        path.write_text(text, encoding="utf-8")
        events = self.events()
        release = self.hold_store()
        began = time.monotonic()
        result = self.lane("send", "--lane", lane, "--file", path, code=2)
        waited = time.monotonic() - began
        release()
        self.assertGreaterEqual(waited, 8.0, "the send did not wait for the store")
        self.assertIn("busy", result.stderr)
        self.assertEqual(self.events(), events)
        name = message_name(1, text)
        self.assertEqual(sorted(os.listdir(str(Path(self.paths()["state_dir"]) / "lanes" / lane / "mail"))), [name])
        sent = self.lane_json("send", "--lane", lane, "--file", path)
        self.assertEqual((sent["sequence"], os.path.basename(sent["file"])), (1, name))
        verified = self.laneboss_json("state", "verify", "--config", "alpha", environment=self.env("alpha"))
        self.assertEqual((verified["mail_files"], verified["mail_orphans"]), (1, 0))


class LimitTest(mailsupport.TurnTest):
    """F. At most 1,000 messages wait or have returned. The events of 999 of them are put into the store behind the
    launcher's back (as the legacy store of the lane checks is), and `state rebuild` makes the row."""

    def put_waiting(self, lane, first, last):
        seq = self.store_events()[-1]["seq"]
        with closing(sqlite3.connect(self.where()["store"])) as connection:
            for sequence in range(first, last + 1):
                seq += 1
                payload = mailed(sequence, "A message put in the store directly: {}\n".format(sequence))
                event = {"id": "ev-direct-{}".format(seq), "kind": "lane.mailed", "lane": lane, "actor": "supervisor",
                         "occurred_at": "2026-10-08T10:00:00Z", "payload": payload, "protocol_version": "1.2.0",
                         "recorded_at": "2026-10-08T10:00:00.000000Z", "seq": seq}
                digest = hashlib.sha256(canonical(event).encode("utf-8")).hexdigest()
                connection.execute("INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, "
                                   "protocol_version, recorded_at, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                   (seq, event["id"], "lane.mailed", lane, "supervisor", event["occurred_at"],
                                    canonical(payload), "1.2.0", event["recorded_at"], digest))
            connection.commit()
        self.run_laneboss("state", "rebuild", "--config", "alpha", environment=self.env("alpha"))

    def test_a_thousand_messages_wait(self):
        lane = "f-full"
        self.turn_lane(lane, runner_name="tok")
        self.put_waiting(lane, 1, 999)
        self.assertEqual(len(self.status(lane)["mail"]["waiting"]), 999)
        path = self.directory / "one-more.md"
        path.write_text("The thousandth message.\n", encoding="utf-8")
        sent = self.lane_json("send", "--lane", lane, "--file", path)
        self.assertEqual((sent["sequence"], sent["waiting"]), (1000, 1000))
        events = self.events()
        result = self.lane("send", "--lane", lane, "--file", path, code=2)
        self.assertIn("1000", result.stderr)
        self.assertEqual(self.events(), events)
        files = os.listdir(str(Path(self.paths()["state_dir"]) / "lanes" / lane / "mail"))
        self.assertEqual(files, [message_name(1000, "The thousandth message.\n")])
        # The rule at append says the same, for a message written by hand.
        self.put("lane.mailed", lane, mailed(1001), code=2)
        self.assertEqual(self.events(), events)

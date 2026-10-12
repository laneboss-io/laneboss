"""T2, the data model of mail and turns (docs/architecture.md, "Mail events, the new lane state and the projection").

A. the protocol version line is 1.2.0; B. the forms of the new events and of the new keys of lane.started; C. the rules
at append, in one table, through `event append`, the launcher's own interface for hand-written events; D. the four
states of a message are derived from the lane's events alone (the table of the design) and the row carries them; E. a
missing prompt counts as cut, a late announcement is accepted, an abandoned row stays abandoned; F. `state verify`
checks the mail directory; G. a store written before this design, in the forms of 1.1.0, verifies and rebuilds as it did,
and a lane that takes turns can be added to it.

Every event is written by hand: nothing here starts a run.
"""

import json
import os

from . import mailsupport, support
from .mailsupport import HandTest, ended, gone, mail_state, mailed, message_name, settled, turn_started


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class ProtocolTest(support.LauncherTest):
    def test_protocol_version_line_is_1_2_0(self):
        self.assertEqual(self.laneboss_json("--version")["protocol_version"], "1.2.0")
        text = support.PROTOCOL_FILE.read_text(encoding="utf-8")
        self.assertEqual(text.count("\nProtocol version: 1.2.0\n"), 1)


class FormTest(HandTest):
    """B. Forms: the new keys of lane.started are there together or not at all, and the new kinds hold exactly their
    payloads. Each refusal names the key it is about, and leaves no event behind."""

    def test_started_keys_come_together(self):
        for lane, idle in (("k-none", None), ("k-one", 1), ("k-week", 604800)):
            self.put("lane.started", lane, turn_started(self.where(), lane, idle=idle))
        base = turn_started(self.where(), "k-bad")
        without = lambda key: {name: value for name, value in base.items() if name != key}
        cases = [("mail without idle_seconds", without("idle_seconds"), "idle_seconds"),
                 ("idle_seconds without mail", without("mail"), "payload.idle_seconds"),
                 ("mail without session_id", without("session_id"), "session_id")]
        for label, value in (("not a list", "1"), ("none", None), ("an object", {"1": 1}), ("zero", [0]),
                             ("too large", [1000000000]), ("text", ["1"]), ("a boolean", [True]),
                             ("unsorted", [2, 1]), ("repeated", [1, 1]), ("65 entries", list(range(1, 66)))):
            cases.append(("mail " + label, dict(base, mail=value), "payload.mail"))
        for label, value in (("zero", 0), ("too large", 604801), ("text", "5"), ("a fraction", 1.5),
                             ("a boolean", True), ("negative", -1)):
            cases.append(("idle_seconds " + label, dict(base, idle_seconds=value), "payload.idle_seconds"))
        for label, payload, needle in cases:
            with self.subTest(label):
                self.refuse("lane.started", "k-bad", payload, needle)
        self.assertEqual(len(self.store_events()), 3)
        self.assertEqual([self.mail(lane)["idle_seconds"] for lane in ("k-none", "k-one", "k-week")], [None, 1, 604800])

    def test_mail_event_forms(self):
        lane = "k-mail"
        self.turn_lane(lane)
        self.put("lane.mailed", lane, mailed(1))
        base = mailed(2)
        cases = [("a missing key", {key: value for key, value in base.items() if key != "bytes"}, "exactly"),
                 ("an extra key", dict(base, text="x"), "exactly")]
        for key, values in (("sequence", [0, 1000000000, "2", True, 1.5, None, -1]),
                            ("sender", ["", "-x", "a b", "a" * 65, "é", 7, None]),
                            ("sha256", ["abc", "A" * 64, "a" * 63, "g" * 64, 5, None]),
                            ("bytes", [0, 262145, "5", True, 1.5, None])):
            for value in values:
                cases.append(("{} {!r}".format(key, value), dict(base, **{key: value}), "payload." + key))
        for label, payload, needle in cases:
            with self.subTest(label):
                self.refuse("lane.mailed", lane, payload, needle)
        self.assertEqual(self.mail(lane)["last"], 1)
        # The limits themselves are accepted.
        text = "x" * 262144
        self.put("lane.mailed", lane, mailed(2, text, sender="a" * 64))
        self.assertEqual(self.mail(lane)["waiting"], [1, 2])

    def test_delivered_and_returned_forms(self):
        lane = "k-ann"
        self.turn_lane(lane)
        cases = []
        for kind, extra in (("lane.delivered", {}), ("lane.returned", {"reason": "exit"})):
            base = dict({"run": 2, "sequences": [1]}, **extra)
            cases.append((kind, {key: value for key, value in base.items() if key != "sequences"}, "exactly"))
            cases.append((kind, dict(base, text="x"), "exactly"))
            for value in (1, 0, "2", True, None, 1000001):
                cases.append((kind, dict(base, run=value), "payload.run"))
            for value in ([], list(range(1, 66)), [2, 1], [1, 1], [0], [1000000000], ["1"], [True], "1", None):
                cases.append((kind, dict(base, sequences=value), "payload.sequences"))
        base = {"run": 2, "sequences": [1]}
        cases.append(("lane.delivered", dict(base, reason="exit"), "exactly"))
        cases.append(("lane.returned", base, "exactly"))
        for value in ("failed", "", None, 5, "EXIT"):
            cases.append(("lane.returned", dict(base, reason=value), "payload.reason"))
        for kind, payload, needle in cases:
            with self.subTest("{} {}".format(kind, json.dumps(payload, sort_keys=True)[:60])):
                self.refuse(kind, lane, payload, needle)


class RulesTest(HandTest):
    """C. The rules at append, one table, each event refused with nothing stored."""

    def test_rules_at_append(self):
        paths = self.where()
        # An ordinary lane, as main writes it, and a lane that nobody wrote an event for.
        self.put("lane.started", "r-ord", support.started_payload(paths, "r-ord"))
        self.put("lane.ended", "r-ord", support.ended_payload(1))
        # Turn-based lanes: waiting with message 1 waiting; running a turn that carries message 1; ended with message 1
        # delivered, and with message 1 returned (a limit); lost, and then run again by hand; abandoned, and abandoned
        # and cleaned.
        self.turn_lane("r-wait")
        self.put("lane.mailed", "r-wait", mailed(1))
        self.turn_lane("r-run")
        self.put("lane.mailed", "r-run", mailed(1))
        self.turn("r-run", 2, [1])
        self.turn_lane("r-dlv")
        self.put("lane.mailed", "r-dlv", mailed(1))
        self.turn("r-dlv", 2, [1])
        self.put("lane.ended", "r-dlv", ended(2))
        self.turn_lane("r-ret")
        self.put("lane.mailed", "r-ret", mailed(1))
        self.turn("r-ret", 2, [1])
        self.put("lane.ended", "r-ret", ended(2, "limit"))
        self.turn_lane("r-old")
        self.put("lane.mailed", "r-old", mailed(1))
        self.turn("r-old", 2, [1])
        self.put("lane.lost", "r-old", {"run": 2, "survivors": 0})
        self.turn("r-old", 3, [])
        self.put("lane.ended", "r-old", ended(3))
        self.turn_lane("r-abn")
        self.put("lane.mailed", "r-abn", mailed(1))
        self.put("lane.state", "r-abn", {"state": "abandoned"})
        self.turn_lane("r-cln")
        self.put("lane.state", "r-cln", {"state": "abandoned"})
        self.put("lane.cleaned", "r-cln", {"removed": [], "kept": [
            {"item": "lane-directory", "path": "/srv/example/lanes/r-cln", "why": "record"}]})
        one = {"run": 2, "sequences": [1]}
        table = [
            # lane.mailed: a gap, a repeat, a lane that is not turn-based, one that nobody started, abandoned, cleaned.
            ("lane.mailed", "r-wait", mailed(3), "payload.sequence must be 2"),
            ("lane.mailed", "r-wait", mailed(1), "payload.sequence must be 2"),
            ("lane.mailed", "r-ord", mailed(1), "not turn-based"),
            ("lane.mailed", "r-nobody", mailed(1), "not turn-based"),
            ("lane.mailed", "r-abn", mailed(2), "abandoned"),
            ("lane.mailed", "r-cln", mailed(1), "cleaned"),
            # lane.delivered and lane.returned.
            ("lane.delivered", "r-run", one, "is running"),
            ("lane.delivered", "r-wait", one, "no settled messages"),
            ("lane.delivered", "r-ord", one, "no settled messages"),
            ("lane.delivered", "r-ret", one, "returned, not delivered"),
            ("lane.returned", "r-dlv", dict(one, reason="exit"), "delivered, not returned"),
            ("lane.delivered", "r-dlv", dict(one, sequences=[2]), "payload.sequences"),
            ("lane.delivered", "r-dlv", dict(one, run=3), "payload.run"),
            ("lane.returned", "r-ret", dict(one, reason="exit"), "payload.reason"),
            ("lane.returned", "r-ret", dict(one, reason="cut"), "payload.reason"),
            ("lane.returned", "r-ret", dict(one, sequences=[1, 2], reason="limit"), "payload.sequences"),
            ("lane.returned", "r-old", dict(one, reason="lost"), "latest run"),
            # lane.started: a list that is not the head of the queue, no list on a turn-based row, a list on a
            # row that is not turn-based, a list for a start, and a new life with a message waiting.
            ("lane.started", "r-wait", turn_started(paths, "r-wait", 2, "resume", [2]), "head of the queue"),
            ("lane.started", "r-wait", turn_started(paths, "r-wait", 2, "resume", [1, 2]), "head of the queue"),
            ("lane.started", "r-wait", dict(support.started_payload(paths, "r-wait", run=2, how="resume"),
                                            session_id=mailsupport.SESSION), "turn-based"),
            ("lane.started", "r-ord", turn_started(paths, "r-ord", 2, "resume", []), "turn-based"),
            ("lane.started", "k-new", turn_started(paths, "k-new", 1, "start", [1]), "must be empty"),
            ("lane.started", "r-abn", turn_started(paths, "r-abn", 2, "reuse", []), "wait or have returned"),
            ("lane.started", "r-abn", support.started_payload(paths, "r-abn", run=2, how="reuse"),
             "wait or have returned"),
            # An abandonment is never undone by a turn that is starting.
            ("lane.resumed", "r-abn", {"run": 2, "after": "exit", "message": None}, "abandoned"),
            ("lane.started", "r-abn", turn_started(paths, "r-abn", 2, "resume", [1]), "abandoned"),
            # lane.state: never waiting, and only abandoned on a turn-based row.
            ("lane.state", "r-wait", {"state": "waiting"}, "never set by lane.state"),
            ("lane.state", "r-ord", {"state": "waiting"}, "never set by lane.state"),
            ("lane.state", "r-wait", {"state": "verifying"}, "only abandoned"),
            ("lane.state", "r-wait", {"state": "accepted"}, "only abandoned"),
            ("lane.state", "r-wait", {"state": "merged"}, "only abandoned"),
        ]
        for kind, lane, payload, needle in table:
            with self.subTest("{} {} {}".format(kind, lane, needle)):
                self.refuse(kind, lane, payload, needle)
        # An announcement is due once.
        self.put("lane.delivered", "r-dlv", one, actor="laneboss")
        self.refuse("lane.delivered", "r-dlv", one, "already announced")
        # What is accepted: an abandonment of a turn-based lane, a state of an ordinary one.
        self.put("lane.state", "r-wait", {"state": "abandoned"})
        self.put("lane.state", "r-ord", {"state": "verifying"})
        self.assertEqual(self.row("r-wait")["state"], "abandoned")


class DerivationTest(HandTest):
    """D. The four states of a message follow from the lane's events, and the row carries them (the table of the
    design, then a lost run, a declared gone run and a turn that carries no mail)."""

    def test_the_table_of_the_design(self):
        lane = "d-lane"
        self.turn_lane(lane, idle=900)
        row = self.row(lane)
        self.assertEqual((row["state"], row["running"], row["run"]), ("waiting", False, 1))
        self.assertEqual(row["mail"], mail_state(idle=900))

        self.put("lane.mailed", lane, mailed(1))
        self.put("lane.mailed", lane, mailed(2))
        self.assertEqual(self.mail(lane), mail_state(last=2, waiting=[1, 2], idle=900))
        self.assertEqual(self.row(lane)["state"], "waiting")

        self.turn(lane, 2, [1, 2], idle=900)
        row = self.row(lane)
        self.assertEqual((row["state"], row["running"], row["run"]), ("running", True, 2))
        flying = {"run": 2, "sequences": [1, 2]}
        self.assertEqual(row["mail"], mail_state(last=2, in_flight=flying, idle=900))

        self.put("lane.mailed", lane, mailed(3))
        self.assertEqual(self.mail(lane), mail_state(last=3, waiting=[3], in_flight=flying, idle=900))

        self.put("lane.ended", lane, ended(2, "limit"))
        row = self.row(lane)
        self.assertEqual((row["state"], row["running"], row["reason"]), ("waiting", False, "limit"))
        self.assertEqual(row["mail"], mail_state(last=3, waiting=[3], returned=[1, 2], idle=900,
                                                 settled=settled(2, "returned", [1, 2], "limit")))
        self.put("lane.returned", lane, {"run": 2, "sequences": [1, 2], "reason": "limit"}, actor="laneboss")
        self.assertEqual(self.mail(lane), mail_state(last=3, waiting=[3], returned=[1, 2], idle=900,
                                                     settled=settled(2, "returned", [1, 2], "limit", True)))

        self.turn(lane, 3, [1, 2, 3], idle=900)
        self.assertEqual(self.mail(lane), mail_state(last=3, in_flight={"run": 3, "sequences": [1, 2, 3]}, idle=900,
                                                     settled=settled(2, "returned", [1, 2], "limit", True)))
        self.put("lane.ended", lane, ended(3))
        row = self.row(lane)
        self.assertEqual((row["state"], row["running"]), ("waiting", False))
        self.assertEqual(row["mail"], mail_state(last=3, delivered=3, idle=900,
                                                 settled=settled(3, "delivered", [1, 2, 3])))
        self.put("lane.delivered", lane, {"run": 3, "sequences": [1, 2, 3]}, actor="laneboss")
        self.assertEqual(self.mail(lane), mail_state(last=3, delivered=3, idle=900,
                                                     settled=settled(3, "delivered", [1, 2, 3], None, True)))

        self.put("lane.mailed", lane, mailed(4))
        self.turn(lane, 4, [4], idle=900)
        self.put("lane.ended", lane, ended(4, prompt="cut"))
        self.assertEqual(self.mail(lane), mail_state(last=4, returned=[4], delivered=3, idle=900,
                                                     settled=settled(4, "returned", [4], "cut")))
        self.put("lane.returned", lane, {"run": 4, "sequences": [4], "reason": "cut"}, actor="laneboss")

        # A lost run returns its messages; a lane.gone after the loss settles nothing, and the loss keeps its reason.
        self.turn(lane, 5, [4], idle=900)
        self.assertEqual(self.mail(lane)["in_flight"], {"run": 5, "sequences": [4]})
        self.put("lane.lost", lane, {"run": 5, "survivors": 0})
        row = self.row(lane)
        self.assertEqual((row["state"], row["running"], row["reason"]), ("waiting", False, "lost"))
        self.assertEqual(row["mail"], mail_state(last=4, returned=[4], delivered=3, idle=900,
                                                 settled=settled(5, "returned", [4], "lost")))
        self.put("lane.gone", lane, gone(5))
        self.assertEqual(self.mail(lane), mail_state(last=4, returned=[4], delivered=3, idle=900,
                                                     settled=settled(5, "returned", [4], "lost")))
        self.assertEqual(self.row(lane)["state"], "waiting")

        # A turn that carries no mail (an idle turn) is accepted while a message has returned, carries nothing, and
        # leaves `settled` as it was.
        self.turn(lane, 6, [], idle=900)
        row = self.row(lane)
        self.assertEqual((row["state"], row["running"]), ("running", True))
        self.assertEqual(row["mail"], mail_state(last=4, returned=[4], delivered=3, idle=900,
                                                 settled=settled(5, "returned", [4], "lost")))
        self.put("lane.ended", lane, ended(6, prompt="cut"))
        row = self.row(lane)
        self.assertEqual(row["state"], "waiting")
        self.assertEqual(row["mail"], mail_state(last=4, returned=[4], delivered=3, idle=900,
                                                 settled=settled(5, "returned", [4], "lost")))
        self.put("lane.mailed", lane, mailed(5))
        self.assertEqual(self.mail(lane)["waiting"], [5])
        self.assertEqual(self.mail(lane)["returned"], [4])

    def test_a_gone_run_returns_its_mail(self):
        lane = "d-gone"
        self.turn_lane(lane)
        self.put("lane.mailed", lane, mailed(1))
        self.turn(lane, 2, [1])
        self.put("lane.gone", lane, gone(2))
        row = self.row(lane)
        self.assertEqual((row["state"], row["running"]), ("waiting", False))
        self.assertEqual(row["mail"], mail_state(last=1, returned=[1], settled=settled(2, "returned", [1], "gone")))
        self.put("lane.returned", lane, {"run": 2, "sequences": [1], "reason": "gone"}, actor="laneboss")
        self.assertIs(self.mail(lane)["settled"]["announced"], True)

    def test_any_other_end_returns_mail(self):
        lane = "d-ends"
        self.turn_lane(lane)
        self.put("lane.mailed", lane, mailed(1))
        run = 1
        for reason, code, prompt, why in (("exit", 3, "written", "exit"), ("timeout", None, "cut", "timeout"),
                                          ("stopped", None, "written", "stopped"), ("dropped", 1, "written", "dropped"),
                                          ("exit", None, "cut", "exit"), ("limit", 0, "written", "limit")):
            run += 1
            with self.subTest(reason=reason, code=code, prompt=prompt):
                self.turn(lane, run, [1])
                self.put("lane.ended", lane, ended(run, reason, code, prompt))
                self.assertEqual(self.mail(lane), mail_state(last=1, returned=[1],
                                                             settled=settled(run, "returned", [1], why)))


class PromptTest(HandTest):
    """E. A missing prompt counts as cut: the messages of an end that does not record its prompt return."""

    def test_a_missing_prompt_counts_as_cut(self):
        lane = "p-lane"
        self.turn_lane(lane)
        self.put("lane.mailed", lane, mailed(1))
        self.turn(lane, 2, [1])
        self.put("lane.ended", lane, ended(2, prompt=None))
        self.assertEqual(self.mail(lane), mail_state(last=1, returned=[1], settled=settled(2, "returned", [1], "cut")))
        self.refuse("lane.returned", lane, {"run": 2, "sequences": [1], "reason": "exit"}, "payload.reason")
        self.put("lane.returned", lane, {"run": 2, "sequences": [1], "reason": "cut"}, actor="laneboss")
        self.assertIs(self.mail(lane)["settled"]["announced"], True)
        self.assertEqual(self.mail(lane)["delivered"], 0)


class LateAnnouncementTest(HandTest):
    """E. A late announcement is accepted while its run is the lane's latest, with the values of `settled`."""

    def test_a_loss_that_was_never_announced(self):
        lane = "l-lane"
        self.turn_lane(lane)
        self.put("lane.mailed", lane, mailed(1))
        self.turn(lane, 2, [1])
        self.put("lane.lost", lane, {"run": 2, "survivors": 0})
        self.put("lane.gone", lane, gone(2))
        want = mail_state(last=1, returned=[1], settled=settled(2, "returned", [1], "lost"))
        self.assertEqual(self.mail(lane), want)
        self.refuse("lane.returned", lane, {"run": 2, "sequences": [1], "reason": "gone"}, "payload.reason")
        self.put("lane.returned", lane, {"run": 2, "sequences": [1], "reason": "lost"}, actor="laneboss")
        want["settled"]["announced"] = True
        self.assertEqual(self.mail(lane), want)
        self.assertEqual(self.row(lane)["state"], "waiting")


class AbandonedTest(HandTest):
    """E. An abandoned row stays abandoned at a closing event when it has `mail`; a row without it is as main has it.
    A new life of a turn-based lane continues its sequence numbers."""

    def test_gone_after_an_abandonment(self):
        paths = self.where()
        self.turn_lane("a-turn")
        self.put("lane.state", "a-turn", {"state": "abandoned"})
        self.put("lane.gone", "a-turn", gone(1))
        self.assertEqual(self.row("a-turn")["state"], "abandoned")
        # A lane that has mail and was started again without --turns: an ordinary run ends in verifying, and a gone
        # after an abandonment keeps the abandonment all the same.
        self.turn_lane("a-again")
        self.put("lane.state", "a-again", {"state": "abandoned"})
        self.put("lane.started", "a-again", support.started_payload(paths, "a-again", run=2, how="reuse"))
        row = self.row("a-again")
        self.assertEqual((row["state"], row["running"], row["mail"]["turn_based"]), ("running", True, False))
        self.put("lane.ended", "a-again", support.ended_payload(2))
        self.assertEqual(self.row("a-again")["state"], "verifying")
        self.put("lane.state", "a-again", {"state": "abandoned"})
        self.put("lane.gone", "a-again", gone(2))
        self.assertEqual(self.row("a-again")["state"], "abandoned")
        self.assertNotIn("waiting", [self.row(lane)["state"] for lane in ("a-turn", "a-again")])
        # A lane without mail is as main has it: a gone after an abandonment is a lane waiting for the supervisor.
        self.put("lane.started", "a-plain", support.started_payload(paths, "a-plain"))
        self.put("lane.ended", "a-plain", support.ended_payload(1))
        self.put("lane.state", "a-plain", {"state": "abandoned"})
        self.put("lane.gone", "a-plain", gone(1))
        row = self.row("a-plain")
        self.assertEqual(row["state"], "verifying")
        self.assertNotIn("mail", row)

    def test_a_new_life_continues_the_sequence(self):
        paths = self.where()
        lane = "a-life"
        self.turn_lane(lane)
        self.put("lane.mailed", lane, mailed(1))
        self.turn(lane, 2, [1])
        self.put("lane.ended", lane, ended(2))
        self.put("lane.state", lane, {"state": "abandoned"})
        self.put("lane.started", lane, turn_started(paths, lane, 3, "reuse", [], 600))
        self.assertEqual(self.mail(lane), mail_state(last=1, delivered=1, idle=600,
                                                     settled=settled(2, "delivered", [1])))
        self.assertIs(self.row(lane)["running"], True)
        self.put("lane.ended", lane, ended(3))
        self.assertEqual(self.row(lane)["state"], "waiting")
        self.refuse("lane.mailed", lane, mailed(1), "payload.sequence must be 2")
        self.put("lane.mailed", lane, mailed(2))
        self.assertEqual(self.mail(lane)["waiting"], [2])
        self.assertEqual(self.mail(lane)["delivered"], 1)


class VerifyTest(HandTest):
    """F. `state verify` checks the mail directory of every lane that has one."""

    def two_messages(self, lane):
        self.turn_lane(lane)
        texts = {1: "The first message.\n", 2: "The second message, with é and 中.\n"}
        for sequence, text in texts.items():
            self.put("lane.mailed", lane, mailed(sequence, text))
            self.write_mail(lane, sequence, text)
        return texts

    def verify(self, code=0):
        return self.run_laneboss("state", "verify", "--config", "alpha", code=code, environment=self.environment)

    def test_files_and_orphans_are_counted(self):
        verified = self.laneboss_json("state", "verify", "--config", "alpha")
        self.assertEqual((verified["mail_files"], verified["mail_orphans"]), (0, 0))
        lane = "v-lane"
        self.two_messages(lane)
        verified = json.loads(self.verify().stdout)
        self.assertEqual((verified["ok"], verified["mail_files"], verified["mail_orphans"]), (True, 2, 0))
        # A complete file that no event names is an orphan: counted, never a problem. A temporary file is skipped.
        self.write_mail(lane, 3, "Never sent.\n")
        (self.mail_directory(lane) / ".tmp-123-abc").write_bytes(b"half a message")
        verified = json.loads(self.verify().stdout)
        self.assertEqual((verified["ok"], verified["mail_files"], verified["mail_orphans"]), (True, 3, 1))
        # state rebuild reads events only.
        before = self.run_laneboss("state", "lanes", "--config", "alpha", environment=self.environment).stdout
        self.assertEqual(self.run_laneboss("state", "rebuild", "--config", "alpha",
                                           environment=self.environment).stdout, before)

    def test_no_store_has_no_mail(self):
        verified = self.laneboss_json("state", "verify", "--config", "alpha")
        self.assertEqual((verified["exists"], verified["mail_files"], verified["mail_orphans"]), (False, 0, 0))

    def test_a_foreign_name_is_refused(self):
        lane = "v-name"
        self.two_messages(lane)
        (self.mail_directory(lane) / "notes.txt").write_bytes(b"not a message")
        result = self.verify(3)
        self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
        self.assertIn("SEQUENCE-DIGEST", result.stderr)
        self.assertNotIn("notes.txt", result.stderr)

    def test_a_changed_file_is_refused(self):
        lane = "v-changed"
        texts = self.two_messages(lane)
        path = self.mail_directory(lane) / message_name(2, texts[2])
        path.write_bytes(b"changed by hand")
        result = self.verify(3)
        self.assertIn("does not match", result.stderr)
        self.assertIn(lane, result.stderr)

    def test_a_missing_file_is_named(self):
        lane = "v-missing"
        texts = self.two_messages(lane)
        os.unlink(str(self.mail_directory(lane) / message_name(1, texts[1])))
        result = self.verify(3)
        events = [item for item in self.store_events() if item["kind"] == "lane.mailed"]
        self.assertIn(lane, result.stderr)
        self.assertIn("sequence 1", result.stderr)
        self.assertIn("event seq {}".format(events[0]["seq"]), result.stderr)
        # state rebuild is not changed by mail files; a message that waits keeps waiting.
        self.run_laneboss("state", "rebuild", "--config", "alpha", environment=self.environment)
        self.assertEqual(self.mail(lane)["waiting"], [1, 2])
        # Putting the same bytes back under the same name repairs it.
        self.write_mail(lane, 1, texts[1])
        self.assertEqual(json.loads(self.verify().stdout)["mail_files"], 2)

    def test_a_wrong_size_is_refused(self):
        lane = "v-size"
        self.turn_lane(lane)
        text = "A message whose event says another size.\n"
        self.put("lane.mailed", lane, dict(mailed(1, text), bytes=len(text) + 1))
        self.write_mail(lane, 1, text)
        result = self.verify(3)
        self.assertIn("bytes", result.stderr)
        self.assertIn("sequence 1", result.stderr)

    def test_a_link_or_directory_is_refused(self):
        lane = "v-link"
        texts = self.two_messages(lane)
        name = message_name(3, "A message that is a link.\n")
        os.symlink(str(self.mail_directory(lane) / message_name(1, texts[1])), str(self.mail_directory(lane) / name))
        result = self.verify(3)
        self.assertIn("regular file", result.stderr)
        os.unlink(str(self.mail_directory(lane) / name))
        os.mkdir(str(self.mail_directory(lane) / name))
        self.assertIn("regular file", self.verify(3).stderr)


class CompatTest(HandTest):
    """G. A store written before this design, in the forms of 1.1.0 (the forms of 0.5.0 and of main, which has
    `session_id` in lane.started and `prompt` in lane.ended, and an event of a kind that is only reserved now, written by
    hand in another form) verifies and rebuilds as it did, and its rows are the literal rows below. A lane that takes
    turns can then be added to the same store without a change to them."""

    def row_of(self, lane, state, state_at, started, ended_at, last_seq, events=2):
        return {"lane": lane, "state": state, "state_at": state_at,
                "times": {"planned": None, "started": started, "ended": ended_at, "timeout": None, "stuck": None,
                          "resumed": None, "lost": None, "cleaned": None},
                "landing": {"merged": None, "deployed": None, "landed": None}, "run": 1, "running": False,
                "runner": "local", "model": "example-model-2", "effort": "max", "account": "account-two",
                "worktree": "/srv/example/lanes/one", "branch": None, "reason": "exit", "exit_code": 0, "resumes": 0,
                "lost": 0, "cleaned": False, "events": events, "last_seq": last_seq}

    def test_a_store_of_1_1_0(self):
        self.assertEqual(self.laneboss_json("--version")["protocol_version"], "1.2.0")
        paths = self.where()
        at = lambda minute: "2026-10-08T09:0{}:00Z".format(minute)
        self.append(self.event("note.added", payload={"text": "before"}))
        # 0.5.0's forms: no session_id in lane.started, no prompt in lane.ended.
        self.put("lane.started", "old-a", support.started_payload(paths, "old-a"), occurred_at=at(1))
        self.put("lane.ended", "old-a", support.ended_payload(1), occurred_at=at(2))
        # main's forms: session_id, and the prompt of a runner that takes it on standard input.
        self.put("lane.started", "old-b", dict(support.started_payload(paths, "old-b"), session_id=mailsupport.SESSION),
                 occurred_at=at(3))
        self.put("lane.ended", "old-b", dict(support.ended_payload(1), prompt={"state": "written", "bytes": 5,
                                                                                "length": 5}), occurred_at=at(4))
        # A kind that is reserved now, written by hand in another form, with another actor and protocol version. Since the
        # loop is built (T3) `event append` refuses it, so it is written into the store file as 1.1.0 would have kept it.
        mailsupport.plant_event(paths["store"], "loop.started", None, "somebody", "1.1.0",
                                {"anything": [1, 2, 3], "id": "x"})
        # A lane that is abandoned and then declared gone: main makes it wait for the supervisor again.
        self.put("lane.started", "old-c", support.started_payload(paths, "old-c"), occurred_at=at(5))
        self.put("lane.ended", "old-c", support.ended_payload(1), occurred_at=at(6))
        self.put("lane.state", "old-c", {"state": "abandoned"}, occurred_at=at(7))
        self.put("lane.gone", "old-c", gone(1), occurred_at=at(8))
        wanted = [self.row_of("old-a", "verifying", at(2), at(1), at(2), 3),
                  self.row_of("old-b", "verifying", at(4), at(3), at(4), 5),
                  self.row_of("old-c", "verifying", at(8), at(5), at(6), 10, events=4)]
        text = self.run_laneboss("state", "lanes", "--config", "alpha", environment=self.environment).stdout
        self.assertEqual(json.loads(text), wanted)
        self.assertEqual(text, json.dumps(wanted, sort_keys=True, ensure_ascii=True) + "\n")
        self.assertIs(self.laneboss_json("state", "verify", "--config", "alpha")["ok"], True)
        self.assertEqual(self.run_laneboss("state", "rebuild", "--config", "alpha",
                                           environment=self.environment).stdout, text)
        # A lane that takes turns is added to the same store: the other rows stay as they were, byte for byte.
        self.turn_lane("new-t")
        self.put("lane.mailed", "new-t", mailed(1))
        self.write_mail("new-t", 1, "a message\n")
        self.turn("new-t", 2, [1])
        self.put("lane.ended", "new-t", ended(2))
        rows = self.laneboss_json("state", "lanes", "--config", "alpha")
        self.assertEqual([row for row in rows if row["lane"].startswith("old-")], wanted)
        self.assertEqual(self.mail("new-t")["delivered"], 1)
        self.assertIs(self.laneboss_json("state", "verify", "--config", "alpha")["ok"], True)
        rebuilt = self.run_laneboss("state", "rebuild", "--config", "alpha", environment=self.environment).stdout
        self.assertEqual(json.loads(rebuilt), rows)

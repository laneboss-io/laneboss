"""T2, `lane start --turns` and `lane turn` (docs/architecture.md, "The `lane turn` command (built by T2)").

A. `lane start --turns` makes run 1 a turn: it records `mail`, `idle_seconds` and `session_id`, hands the brief over on
standard input, and the end of the run leaves the lane waiting; B. a turn carries the waiting messages on the runner's
standard input, and what its end decides (delivered, or returned with the reason of the end) is announced after
`lane.ended`; C. the idle message; D. everything `lane turn` refuses; E. the bounds of a turn; F. the keys of `[turns]`.

The runners are tests/e2e/standin.py, which records what it read on standard input. Nothing of the launcher is replaced:
every message is sent with `lane send` and every turn started with `lane turn`, except where a test says it makes a state
by hand (a mail file written outside the launcher, a pending event, a runner edited in the configuration).
"""

import base64
import json
import os
from pathlib import Path
import re
import time

from . import support
from .lanesupport import runner
from .mailsupport import STDIN, TURN_START, TurnTest, joined, mail_state, mailed, message_name, settled


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


UUID_FORM = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
BLOCK = "<!-- laneboss launcher block: begin (protocol "
HEADER = re.compile(r"^## Message ([0-9]+) from (\S+) at (\S+?)( \(again\))?$", re.MULTILINE)
IDLE = "Check in: say in one line what you are doing.\n"
PLAIN = "A line of plain words that only gives the message its size.\n"
# A credential shape, made here so that no file of the repository holds one.
TOKEN = "gh" + "p_" + "Z9y8X7w6V5u4T3s2R1q0" + "P9o8N7m6L5k4J3i2"
BOUND = 1048576
MESSAGE_BYTES = 262144


class StartTurnsTest(TurnTest):
    """A. lane start --turns, and the lane commands that go with it."""

    def test_first_run_is_a_turn(self):
        lane = "a-first"
        started = self.turn_start(lane, "tok", "--idle", "900")
        self.assertEqual((started["run"], started["how"], started["mail"], started["idle_seconds"]),
                         (1, "start", [], 900))
        self.assertRegex(started["session_id"], UUID_FORM)
        stored = self.wait_event("lane.started", lane, run=1)["payload"]
        self.assertEqual((stored["mail"], stored["idle_seconds"], stored["session_id"]),
                         ([], 900, started["session_id"]))
        self.settle(lane, 1)
        # The brief is the lane's first message: it arrived whole on standard input, and nothing went into the arguments.
        record = self.record(lane, run=1, ended=True)
        self.assertEqual(base64.b64decode(record["stdin"]["base64"]), Path(started["brief"]["path"]).read_bytes())
        self.assertEqual(record["argv"], ["ok", "--lane", lane, "--session-id", started["session_id"]])
        row = self.status(lane)
        self.assertEqual((row["state"], row["running"], row["idle"], row["reason"], row["exit_code"]),
                         ("waiting", False, True, "exit", 0))
        self.assertEqual(row["mail"], mail_state(idle=900))
        self.assertEqual(self.wait_event("lane.ended", lane)["payload"]["prompt"]["state"], "written")
        # A run that carries no mail announces nothing.
        self.assertEqual([item["kind"] for item in self.lane_events(lane)], ["brief.rendered", "lane.started",
                                                                            "lane.ended"])
        self.assert_sound()

    def test_idle_seconds_sources(self):
        none = self.turn_start("a-idle-none")
        self.rewrite("\n[turns]\nidle_seconds = 600\n")
        configured = self.turn_start("a-idle-conf")
        given = self.turn_start("a-idle-given", "tok", "--idle", "30")
        self.assertEqual((none["idle_seconds"], configured["idle_seconds"], given["idle_seconds"]), (None, 600, 30))
        for lane, want in (("a-idle-none", None), ("a-idle-conf", 600), ("a-idle-given", 30)):
            self.assertEqual(self.wait_event("lane.started", lane)["payload"]["idle_seconds"], want, lane)
            self.settle(lane, 1)
            self.assertEqual(self.status(lane)["mail"]["idle_seconds"], want, lane)

    def test_idle_needs_turns_and_a_range(self):
        before = self.events()
        result = self.plain_start("a-idle-plain", "tok", "--idle", "60", code=2)
        self.assertIn("--turns", result.stderr)
        for index, value in enumerate(("0", "604801", "-5", "1.5", "abc", "")):
            with self.subTest(value=value):
                result = self.turn_start("a-idle-bad-{}".format(index), "tok", "--idle", value, code=2)
                self.assertIn("--idle", result.stderr)
        self.assertEqual(self.events(), before)

    def test_without_turns_is_ordinary(self):
        lane = "a-plain"
        started = self.plain_start(lane)
        self.assertNotIn("mail", started)
        self.assertNotIn("idle_seconds", started)
        self.assertRegex(started["session_id"], UUID_FORM)
        self.assertEqual(sorted(self.wait_event("lane.started", lane)["payload"]),
                         sorted(set(started) - {"lane", "event"}))
        self.settle(lane, 1)
        row = self.status(lane)
        self.assertEqual((row["state"], row["idle"]), ("verifying", False))
        self.assertNotIn("mail", row)
        before = self.events()
        self.assertIn("not turn-based", self.lane("send", "--lane", lane, "--file", self.message_file("x\n"),
                                                  code=2).stderr)
        self.assertIn("not turn-based", self.lane("turn", "--lane", lane, code=2).stderr)
        self.assertEqual(self.events(), before)

    def test_runners_that_cannot_take_turns(self):
        # Each part that is missing is named, and only that part; nothing is recorded.
        cases = (("tnosess", ("{session}",), ("no resume template", 'prompt = "stdin"')),
                 ("targ", ('prompt = "stdin"',), ("no resume template", "does not use {session}")),
                 ("tnores", ("no resume template",), ("does not use {session}", 'prompt = "stdin"')))
        for name, needles, unwanted in cases:
            with self.subTest(runner=name):
                lane = "a-no-" + name
                before = self.events()
                result = self.turn_start(lane, name, code=2)
                self.assertIn("--turns", result.stderr)
                for needle in needles:
                    self.assertIn(needle, result.stderr)
                for needle in unwanted:
                    self.assertNotIn(needle, result.stderr)
                self.assertEqual(self.events(), before)
                self.assertIn("not known", self.lane("status", "--lane", lane, code=2).stderr)

    def test_reuse_is_refused_with_mail(self):
        lane = "a-reuse"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.sent(lane, "A message that waits.\n")
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        self.lane_json("clean", "--lane", lane)
        before = self.events()
        for index, turns in enumerate(([], ["--turns"])):
            with self.subTest(turns=turns):
                result = self.start(lane, *turns, "--runner", "tok", "--model", "tok-model-1", "--worktree",
                                    self.scratch("a-reuse-{}".format(index)), "--reuse", code=2)
                self.assertIn("wait or have returned", result.stderr)
        self.assertEqual(self.events(), before)

    def test_reuse_goes_on_with_the_sequence(self):
        lane = "a-life"
        first = self.turn_start(lane)
        self.settle(lane, 1)
        self.sent(lane, "The only message of the first life.\n")
        self.turn_json(lane)
        self.settle(lane, 2, "lane.delivered")
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        self.lane_json("clean", "--lane", lane)
        again = self.start(lane, "--turns", "--runner", "tok", "--model", "tok-model-1", "--worktree",
                           self.scratch("a-life-again"), "--reuse")
        self.assertEqual((again["run"], again["how"], again["mail"]), (3, "reuse", []))
        self.assertRegex(again["session_id"], UUID_FORM)
        self.assertNotEqual(again["session_id"], first["session_id"])
        self.settle(lane, 3)
        # The numbers go on from the first life, and what was delivered stays counted.
        sent = self.sent(lane, "The first message of the second life.\n")
        self.assertEqual(sent["sequence"], 2)
        row = self.status(lane)
        self.assertEqual((row["state"], row["mail"]["last"], row["mail"]["delivered"], row["mail"]["waiting"]),
                         ("waiting", 2, 1, [2]))
        self.assert_sound()

    def test_resume_is_refused(self):
        lane = "a-resume"
        self.turn_start(lane)
        self.settle(lane, 1)
        before = self.events()
        result = self.lane("resume", "--lane", lane, code=2)
        self.assertIn("lane send", result.stderr)
        self.assertIn("lane turn", result.stderr)
        self.assertEqual(self.events(), before)
        self.assertFalse((self.records["alpha"] / (lane + ".2.json")).exists())


class DeliveryTest(TurnTest):
    """B. What a turn carries, and what its end decides."""

    def test_three_messages(self):
        lane = "b-three"
        first = self.turn_start(lane, "tok", "--idle", "120")
        self.settle(lane, 1)
        texts = ["Please summarise the open review comments.\n", "Then list what is blocked, with no final newline",
                 "A third, with é and 中.\n"]
        senders = [None, "alice", None]
        for text, sender in zip(texts, senders):
            self.sent(lane, text, sender)
        mailed_at = self.mailed_at(lane)
        started = self.turn_json(lane)
        self.assertIs(started["started"], True)
        self.assertEqual(started["turn"], {"kind": "mail", "mail": [1, 2, 3]})
        self.assertEqual((started["lane"], started["run"], started["how"], started["mail"]), (lane, 2, "resume",
                                                                                              [1, 2, 3]))
        self.assertEqual((started["idle_seconds"], started["session_id"]), (120, first["session_id"]))
        self.assertEqual((sorted(started["event"]), sorted(started["resumed"])), (["id", "seq"], ["id", "seq"]))
        self.settle(lane, 2, "lane.delivered")
        # The prompt: the three messages under their header lines, in order, and the launcher block once.
        stdin = self.stdin_of(lane, 2)
        want = joined([(number, mailed_at[number][0], mailed_at[number][1], texts[number - 1], False)
                       for number in (1, 2, 3)])
        self.assertTrue(stdin.startswith(want), stdin[:300])
        self.assertTrue(stdin[len(want):].startswith("\n" + BLOCK), stdin[len(want):][:100])
        self.assertEqual(HEADER.findall(stdin), [(str(number), mailed_at[number][0], mailed_at[number][1], "")
                                                 for number in (1, 2, 3)])
        self.assertEqual(stdin.count(BLOCK), 1)
        self.assertEqual(stdin.count("# Shared protocol for supervised lanes"), 1)
        self.assertEqual(stdin.count("## Standing rules: rules/standing.md"), 1)
        # The rendered message is kept, announced by one brief.rendered whose brief input is the join.
        resumed = self.wait_event("lane.resumed", lane, run=2)["payload"]
        rendered = Path(resumed["message"]["path"]).read_bytes()
        self.assertEqual(rendered.decode("utf-8"), stdin)
        self.assertEqual((resumed["after"], resumed["message"]["sha256"]), ("exit", support.digest(rendered)))
        announced = self.lane_events(lane, "brief.rendered")
        self.assertEqual(len(announced), 2)
        brief_input = announced[1]["payload"]["inputs"][0]
        mail_directory = os.path.realpath(str(self.mail_directory(lane)))
        self.assertEqual((brief_input["role"], brief_input["path"], brief_input["sha256"]),
                         ("brief", mail_directory, support.digest(want.encode("utf-8"))))
        self.assertEqual((Path(self.paths()["state_dir"]) / brief_input["copy"]).read_bytes(), want.encode("utf-8"))
        self.assertEqual(announced[1]["payload"]["output"], {"path": resumed["message"]["path"],
                                                             "sha256": resumed["message"]["sha256"]})
        # The events, in order, and what each says.
        kinds = [item["kind"] for item in self.lane_events(lane)]
        self.assertEqual(kinds[kinds.index("lane.mailed"):], ["lane.mailed"] * 3 + [
            "brief.rendered", "lane.resumed", "lane.started", "lane.ended", "lane.delivered"])
        turn = self.wait_event("lane.started", lane, run=2)["payload"]
        self.assertEqual((turn["how"], turn["mail"], turn["idle_seconds"], turn["session_id"]),
                         ("resume", [1, 2, 3], 120, first["session_id"]))
        ended = self.wait_event("lane.ended", lane, run=2)
        delivered = self.wait_event("lane.delivered", lane)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"], ended["payload"]["prompt"]["state"]),
                         ("exit", 0, "written"))
        self.assertEqual((delivered["payload"], delivered["actor"]), ({"run": 2, "sequences": [1, 2, 3]}, "laneboss"))
        self.assertLess(ended["seq"], delivered["seq"])
        row = self.status(lane)
        self.assertEqual((row["state"], row["idle"]), ("waiting", True))
        self.assertEqual(row["mail"], mail_state(last=3, delivered=3, idle=120,
                                                 settled=settled(2, "delivered", [1, 2, 3], None, True)))
        self.assertEqual(sorted(os.listdir(str(self.mail_directory(lane)))),
                         sorted(message_name(number, texts[number - 1]) for number in (1, 2, 3)))
        self.assert_sound()

    def test_cut_prompt_returns_the_mail(self):
        # shut closes its input without reading it and exits 0, and the message is far larger than a pipe holds.
        lane = "b-cut"
        self.turn_start(lane, "tshut")
        self.settle(lane, 1)
        self.sent(lane, (PLAIN * 3000)[:150000])
        self.turn_json(lane)
        self.settle(lane, 2, "lane.returned")
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["exit_code"], ended["prompt"]["state"]), ("exit", 0, "cut"))
        self.assertLess(ended["prompt"]["bytes"], ended["prompt"]["length"])
        returned = self.wait_event("lane.returned", lane)
        self.assertEqual((returned["payload"], returned["actor"]), ({"run": 2, "sequences": [1], "reason": "cut"},
                                                                    "laneboss"))
        self.assertEqual(self.lane_events(lane, "lane.delivered"), [])
        self.assertEqual(self.status(lane)["mail"], mail_state(last=1, returned=[1],
                                                               settled=settled(2, "returned", [1], "cut", True)))
        self.assert_sound()

    def test_written_is_not_read(self):
        # idle-open holds its input open for a second and never reads it: a small prompt is written whole all the same,
        # and the launcher can see no more than that, so the message counts as delivered.
        lane = "b-open"
        self.turn_start(lane, "tidle")
        self.settle(lane, 1)
        self.sent(lane, "A small message that nobody reads.\n")
        self.turn_json(lane)
        self.settle(lane, 2, "lane.delivered")
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["exit_code"], ended["prompt"]["state"]), ("exit", 0, "written"))
        self.assertEqual(ended["prompt"]["bytes"], ended["prompt"]["length"])
        record = self.record(lane, run=2, ended=True)
        self.assertEqual(record["mode"], "idle-open")
        self.assertNotIn("stdin", record)
        self.assertEqual(self.wait_event("lane.delivered", lane)["payload"], {"run": 2, "sequences": [1]})
        self.assertEqual(self.lane_events(lane, "lane.returned"), [])
        self.assertEqual(self.status(lane)["mail"]["delivered"], 1)

    def test_bad_ends_return_the_mail(self):
        for name, reason, code in (("tfail", "exit", 3), ("tlimit", "limit", 0)):
            with self.subTest(runner=name):
                lane = "b-bad-" + name
                self.turn_start(lane, name)
                self.settle(lane, 1)
                self.sent(lane, "First message.\n")
                self.sent(lane, "Second message.\n", "bob")
                self.turn_json(lane)
                self.settle(lane, 2, "lane.returned")
                ended = self.wait_event("lane.ended", lane, run=2)["payload"]
                self.assertEqual((ended["reason"], ended["exit_code"], ended["prompt"]["state"]), (reason, code,
                                                                                                    "written"))
                self.assertEqual(ended["pattern"], "limit_patterns[0]" if reason == "limit" else None)
                returned = self.wait_event("lane.returned", lane, run=2)
                self.assertEqual(returned["payload"], {"run": 2, "sequences": [1, 2], "reason": reason})
                self.assertEqual(self.lane_events(lane, "lane.delivered"), [])
                self.assertEqual(self.status(lane)["mail"], mail_state(
                    last=2, returned=[1, 2], settled=settled(2, "returned", [1, 2], reason, True)))
                # A newer message goes behind them; the next turn carries all three, the returned first, marked.
                self.sent(lane, "Third message.\n")
                mailed_at = self.mailed_at(lane)
                self.assertEqual(self.turn_json(lane)["turn"], {"kind": "mail", "mail": [1, 2, 3]})
                self.settle(lane, 3, "lane.returned")
                stdin = self.stdin_of(lane, 3)
                texts = {1: "First message.\n", 2: "Second message.\n", 3: "Third message.\n"}
                want = joined([(number, mailed_at[number][0], mailed_at[number][1], texts[number], number < 3)
                               for number in (1, 2, 3)])
                self.assertTrue(stdin.startswith(want), stdin[:400])
                self.assertEqual([again for _, _, _, again in HEADER.findall(stdin)], [" (again)", " (again)", ""])
                self.assertEqual(self.status(lane)["mail"]["returned"], [1, 2, 3])
                self.assertEqual(self.status(lane)["mail"]["delivered"], 0)

    def test_budget_returns_the_mail(self):
        lane = "b-slow"
        self.turn_start(lane, "tforever")
        self.settle(lane, 1)
        self.sent(lane, "A message for a turn that takes too long.\n")
        self.turn_json(lane, "--budget", "0.05")
        record = self.record(lane, run=2)
        self.settle(lane, 2, "lane.returned")
        self.assert_gone([record["pid"]] + record["children"])
        ended = self.wait_event("lane.ended", lane, run=2)
        self.assertEqual(ended["payload"]["reason"], "timeout")
        returned = self.wait_event("lane.returned", lane)
        self.assertEqual(returned["payload"], {"run": 2, "sequences": [1], "reason": "timeout"})
        kinds = [item["kind"] for item in self.lane_events(lane)]
        self.assertEqual(kinds[kinds.index("lane.resumed"):], ["lane.resumed", "lane.started", "lane.timeout",
                                                               "lane.ended", "lane.returned"])
        self.assertEqual(self.status(lane)["mail"]["returned"], [1])
        self.assert_sound()

    def test_no_mail_does_nothing(self):
        lane = "b-none"
        self.turn_start(lane)
        self.settle(lane, 1)
        before = self.events()
        result = self.lane("turn", "--lane", lane)
        self.assertEqual(json.loads(result.stdout), {"lane": lane, "started": False, "reason": "no mail",
                                                     "waiting": 0})
        self.assertEqual(self.events(), before)
        self.assertFalse((self.records["alpha"] / (lane + ".2.json")).exists())
        row = self.status(lane)
        self.assertEqual((row["run"], row["state"], row["live"]["session_alive"]), (1, "waiting", False))

    def test_idle_follows_the_turn(self):
        lane = "b-nap"
        self.turn_start(lane, "tnap")
        self.settle(lane, 1)
        self.assertIs(self.status(lane)["idle"], True)
        self.sent(lane, "A message for a slow turn.\n")
        self.assertIs(self.status(lane)["idle"], True)
        self.turn_json(lane)
        row = self.status(lane)
        self.assertEqual((row["state"], row["running"], row["idle"]), ("running", True, False))
        self.assertEqual(row["mail"]["in_flight"], {"run": 2, "sequences": [1]})
        self.settle(lane, 2, "lane.delivered")
        self.assertIs(self.status(lane)["idle"], True)


class IdleTest(TurnTest):
    """C. The idle message of the configuration."""

    def setUp(self):
        super().setUp()
        (self.home / "configs" / "alpha" / "rules" / "idle.md").write_text(IDLE, encoding="utf-8")
        self.rewrite('\n[turns]\nidle_message = "rules/idle.md"\nidle_seconds = 600\n')

    def test_the_idle_message_goes_as_it_is(self):
        lane = "c-idle"
        first = self.turn_start(lane)
        self.assertEqual(first["idle_seconds"], 600)
        self.settle(lane, 1)
        started = self.turn_json(lane, "--idle")
        self.assertEqual(started["turn"], {"kind": "idle", "mail": []})
        self.assertEqual((started["mail"], started["idle_seconds"], started["session_id"]),
                         ([], 600, first["session_id"]))
        self.settle(lane, 2)
        stdin = self.stdin_of(lane, 2)
        self.assertTrue(stdin.startswith(IDLE + "\n" + BLOCK), stdin[:200])
        self.assertEqual((HEADER.findall(stdin), stdin.count(BLOCK)), ([], 1))
        # A turn that carries no mail announces nothing and leaves the mail as it was.
        kinds = [item["kind"] for item in self.lane_events(lane)]
        self.assertEqual(kinds[kinds.index("lane.ended") + 1:], ["brief.rendered", "lane.resumed", "lane.started",
                                                                  "lane.ended"])
        row = self.status(lane)
        self.assertEqual((row["state"], row["mail"]), ("waiting", mail_state(idle=600)))
        self.assert_sound()

    def test_mail_is_sent_instead(self):
        lane = "c-mail"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.sent(lane, "Real mail.\n")
        started = self.turn_json(lane, "--idle")
        self.assertEqual(started["turn"], {"kind": "mail", "mail": [1]})
        self.settle(lane, 2, "lane.delivered")
        stdin = self.stdin_of(lane, 2)
        self.assertEqual(len(HEADER.findall(stdin)), 1)
        self.assertIn("Real mail.", stdin)
        self.assertNotIn(IDLE.strip(), stdin)

    def test_idle_needs_the_key(self):
        lane = "c-nokey"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.rewrite()
        before = self.events()
        result = self.lane("turn", "--lane", lane, "--idle", code=2)
        self.assertIn("idle_message", result.stderr)
        self.assertEqual(self.events(), before)
        # The key is for the idle message only: a turn that has mail to send goes on without it.
        self.sent(lane, "Mail that needs no idle message.\n")
        self.assertEqual(self.turn_json(lane, "--idle")["turn"], {"kind": "mail", "mail": [1]})


class RefusalTest(TurnTest):
    """D. What lane turn refuses: exit 2, nothing appended and nothing started, and exit 3 for a damaged mail file."""

    def refused(self, lane, needle, *arguments):
        before = self.events()
        result = self.lane("turn", "--lane", lane, *arguments, code=2)
        self.assertIn(needle, result.stderr)
        self.assertEqual(self.events(), before)
        return result

    def test_unknown_and_never_run(self):
        self.refused("d-nobody", "not known")
        self.put("lane.planned", "d-planned", {})
        result = self.refused("d-planned", "has not run yet")
        self.assertIn("lane start --turns", result.stderr)

    def test_a_live_run(self):
        lane = "d-live"
        self.turn_start(lane, "tforever")
        self.settle(lane, 1)
        self.sent(lane, "The first message.\n")
        self.turn_json(lane)
        record = self.record(lane, run=2)
        self.sent(lane, "A second one, while the turn runs.\n")
        self.refused(lane, "running")
        row = self.status(lane)
        self.assertEqual((row["state"], row["running"], row["idle"]), ("running", True, False))
        self.assertEqual((row["mail"]["in_flight"], row["mail"]["waiting"]), ({"run": 2, "sequences": [1]}, [2]))
        # Stopping the turn returns its message, and the next one is behind it.
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]] + record["children"])
        self.settle(lane, 2, "lane.returned")
        self.assertEqual(self.wait_event("lane.returned", lane)["payload"]["reason"], "stopped")
        self.assertEqual((self.status(lane)["mail"]["returned"], self.status(lane)["mail"]["waiting"]), ([1], [2]))

    def test_a_runner_edited_since(self):
        lane = "d-edit"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.sent(lane, "A message for a runner that lost its resume template.\n")
        self.rewrite(overrides={"tok": runner("tok", "ok", TURN_START, None, None, extra=STDIN)})
        result = self.refused(lane, "resume template")
        self.assertIn("tok", result.stderr)
        self.rewrite()
        self.assertEqual(self.turn_json(lane)["turn"]["mail"], [1])

    def test_finished_lanes(self):
        lane = "d-done"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.sent(lane, "A message for a lane that is abandoned.\n")
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        self.refused(lane, "abandoned")
        # The mail is kept, and state verify goes on checking its file.
        self.assertEqual(self.status(lane)["mail"]["waiting"], [1])
        self.assertEqual(self.laneboss_json("state", "verify", "--config", "alpha",
                                            environment=self.env("alpha"))["mail_files"], 1)
        self.lane_json("clean", "--lane", lane)
        self.refused(lane, "cleaned")

    def test_a_merged_lane(self):
        lane = "d-merged"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        self.lane_json("clean", "--lane", lane)
        # Started again without --turns, it is an ordinary lane, and an ordinary lane can be merged.
        self.start(lane, "--runner", "tok", "--model", "tok-model-1", "--worktree", self.scratch("d-merged-again"),
                   "--reuse")
        self.settle(lane, 2)
        self.assertEqual((self.status(lane)["state"], self.status(lane)["mail"]["turn_based"]), ("verifying", False))
        self.lane_json("mark", "--lane", lane, "--state", "merged")
        self.refused(lane, "merged")

    def test_the_directory_is_gone(self):
        lane = "d-moved"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.sent(lane, "A message for a lane whose directory moved.\n")
        directory = self.directory / "work" / lane
        os.rename(str(directory), str(directory) + "-moved")
        self.refused(lane, "no longer exists")
        self.assertEqual(self.status(lane)["mail"]["waiting"], [1])

    def test_an_account_the_runner_lacks(self):
        lane = "d-account"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.sent(lane, "A message.\n")
        self.refused(lane, "does not list that account", "--account", "acc-one")

    def test_pending_events_come_first(self):
        lane = "d-pending"
        self.turn_start(lane)
        self.settle(lane, 1)
        self.sent(lane, "A message behind a pending event.\n")
        waiting = Path(self.paths()["state_dir"]) / "lanes" / lane / "pending.jsonl"
        envelope = {"id": "ev-pending-landing", "kind": "lane.landed", "lane": lane, "actor": "supervisor",
                    "payload": {}, "occurred_at": "2026-10-10T08:00:00.000000Z", "protocol_version": "1.2.0"}
        waiting.write_text(json.dumps(envelope, sort_keys=True) + "\n", encoding="utf-8")
        before = self.events()
        release = self.hold_store()
        began = time.monotonic()
        result = self.lane("turn", "--lane", lane, code=2)
        waited = time.monotonic() - began
        release()
        self.assertGreaterEqual(waited, 8.0, "the turn did not wait for the store")
        self.assertIn("1 event(s) waiting to be recorded", result.stderr)
        self.assertEqual(self.events(), before)
        self.assertEqual(self.status(lane)["mail"]["waiting"], [1])
        self.assertFalse((self.records["alpha"] / (lane + ".2.json")).exists())
        # With the store free the waiting event is appended first, and then the turn starts.
        started = self.turn_json(lane)
        landed = self.wait_event("lane.landed", lane)
        self.assertLess(landed["seq"], started["event"]["seq"])
        self.assertEqual(started["turn"]["mail"], [1])

    def test_a_message_the_renderer_refuses(self):
        # A message file made outside the launcher (lane send would have refused it): the turn names its sequence.
        lane = "d-render"
        self.turn_start(lane)
        self.settle(lane, 1)
        text = "The first line.\nThe key is " + TOKEN + " on the second.\n"
        self.write_mail(lane, 1, text)
        self.put("lane.mailed", lane, mailed(1, text), actor="supervisor")
        before = self.events()
        result = self.lane("turn", "--lane", lane, code=2)
        self.assertIn("message 1", result.stderr)
        self.assertIn("credential", result.stderr)
        self.assertNotIn(TOKEN, result.stderr)
        self.assertEqual(self.events(), before)

    def test_a_damaged_mail_file(self):
        lane = "d-damage"
        self.turn_start(lane)
        self.settle(lane, 1)
        one, two = self.sent(lane, "The first message.\n"), self.sent(lane, "The second message.\n")
        saved = {1: Path(one["file"]).read_bytes(), 2: Path(two["file"]).read_bytes()}
        before = self.events()
        for sequence, damage in ((2, "removed"), (1, "changed")):
            with self.subTest(sequence=sequence, damage=damage):
                path = Path((one, two)[sequence - 1]["file"])
                if damage == "removed":
                    os.unlink(str(path))
                else:
                    path.write_bytes(b"changed by hand")
                result = self.lane("turn", "--lane", lane, code=3)
                self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
                self.assertIn("sequence {}".format(sequence), result.stderr)
                self.assertEqual(self.events(), before)
                self.assertEqual(self.status(lane)["mail"]["waiting"], [1, 2])
                # The same bytes put back under the same name repair it.
                path.write_bytes(saved[sequence])
        self.assertEqual(self.turn_json(lane)["turn"]["mail"], [1, 2])
        self.settle(lane, 2, "lane.delivered")


class BoundsTest(TurnTest):
    """E. A turn carries at most 64 messages and 1,048,576 bytes of joined text, header lines and separators included."""

    def test_sixty_five_messages(self):
        lane = "e-count"
        self.turn_start(lane)
        self.settle(lane, 1)
        for number in range(1, 66):
            self.sent(lane, "Message number {}.\n".format(number))
        first = self.turn_json(lane)
        self.assertEqual(first["turn"], {"kind": "mail", "mail": list(range(1, 65))})
        self.settle(lane, 2, "lane.delivered")
        self.assertEqual(len(HEADER.findall(self.stdin_of(lane, 2))), 64)
        self.assertEqual(self.status(lane)["mail"]["waiting"], [65])
        second = self.turn_json(lane)
        self.assertEqual(second["turn"], {"kind": "mail", "mail": [65]})
        self.settle(lane, 3, "lane.delivered")
        self.assertEqual(self.status(lane)["mail"], mail_state(last=65, delivered=65,
                                                               settled=settled(3, "delivered", [65], None, True)))
        self.assert_sound()

    def test_joined_text_bound(self):
        lane = "e-bytes"
        self.turn_start(lane)
        self.settle(lane, 1)
        text = (PLAIN * 5000)[:MESSAGE_BYTES]
        self.assertEqual(len(text.encode("utf-8")), MESSAGE_BYTES)
        for _ in range(5):
            self.sent(lane, text)
        mailed_at = self.mailed_at(lane)
        # Four such messages are exactly the bound in text alone; with their header lines and separators they pass it.
        items = [(number, mailed_at[number][0], mailed_at[number][1], text, False) for number in (1, 2, 3, 4, 5)]
        self.assertLessEqual(len(joined(items[:3]).encode("utf-8")), BOUND)
        self.assertGreater(len(joined(items[:4]).encode("utf-8")), BOUND)
        first = self.turn_json(lane)
        self.assertEqual(first["turn"]["mail"], [1, 2, 3])
        self.settle(lane, 2, "lane.delivered")
        stdin = self.stdin_of(lane, 2)
        self.assertTrue(stdin.startswith(joined(items[:3])))
        self.assertTrue(stdin[len(joined(items[:3])):].startswith("\n" + BLOCK))
        second = self.turn_json(lane)
        self.assertEqual(second["turn"]["mail"], [4, 5])
        self.settle(lane, 3, "lane.delivered")
        self.assertEqual(self.status(lane)["mail"]["delivered"], 5)


class TurnsConfigTest(support.LauncherTest):
    """F. The table [turns]: idle_message and idle_seconds (the keys of the loop are tested in test_loop.py)."""

    def check(self, tail, code, *needles, files=None):
        directory = self.write_config("alpha", tail=tail)
        for name, data in (files or {}).items():
            (directory / "rules" / name).write_bytes(data)
        result = self.run_laneboss("config", "validate", "alpha", code=code)
        for needle in needles:
            self.assertIn(needle, result.stderr)
        self.assertNotIn(TOKEN, result.stderr)
        return result

    def test_accepted(self):
        self.check('\n[turns]\nidle_message = "rules/idle.md"\nidle_seconds = 604800\n', 0,
                   files={"idle.md": IDLE.encode("utf-8")})
        shown = self.laneboss_json("config", "show", "alpha")
        self.assertEqual(shown["config"]["turns"], {"idle_message": "rules/idle.md", "idle_seconds": 604800})
        self.check('\n[turns]\nidle_seconds = 1\n', 0)
        # 64 KiB exactly is accepted.
        self.check('\n[turns]\nidle_message = "rules/idle.md"\n', 0,
                   files={"idle.md": (PLAIN * 1100).encode("utf-8")[:65536]})

    def test_refused(self):
        point = '\n[turns]\nidle_message = "rules/idle.md"\n'
        cases = [
            ("a missing file", '\n[turns]\nidle_message = "rules/missing.md"\n', None, ("turns.idle_message",)),
            ("an absolute path", '\n[turns]\nidle_message = "/rules/idle.md"\n', None, ("turns.idle_message",)),
            ("a path with ..", '\n[turns]\nidle_message = "../idle.md"\n', None, ("turns.idle_message",)),
            ("a file over 64 KiB", point, (PLAIN * 1100).encode("utf-8")[:65537], ("turns.idle_message", "64 KiB")),
            ("a credential", point, ("Check in.\nThe key is " + TOKEN + "\n").encode("utf-8"),
             ("turns.idle_message", "line 2", "credential")),
            ("not UTF-8", point, b"\xff\xfe\xfa", ("turns.idle_message", "UTF-8")),
            ("an unknown key", '\n[turns]\nno_such_key = 5\n', None, ("turns.no_such_key", "unknown key")),
        ]
        for value in ("0", "604801", '"5"', "1.5", "true", "-1"):
            cases.append(("idle_seconds " + value, "\n[turns]\nidle_seconds = {}\n".format(value), None,
                          ("turns.idle_seconds",)))
        for label, tail, data, needles in cases:
            with self.subTest(label):
                self.check(tail, 2, "invalid configuration:", *needles, files={"idle.md": data} if data else None)

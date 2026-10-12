"""T2, how a turn ends when nothing ends it cleanly, and what a person is told about idle lanes and runners
(docs/architecture.md, "Mail events, the new lane state and the projection" and "The `lane turn` command").

A. the supervising process of a turn is killed: `lane check` records the loss and announces the return of its mail
(`lane.returned`, reason `lost`), and `lane turn` is refused while a process of the lost run survives; B. `lane mark
--gone` announces the return of the mail of a run declared gone (reason `gone`), announces nothing that was announced
already, and gives a late announcement the reason of the loss that settled the messages; C. a stopped turn whose agent
has a child in a session of its own leaves nothing alive and returns its mail; D. `laneboss start` lists idle lanes in
a group of their own; E. `laneboss doctor` warns about a runner that can take turns and has no `limit_patterns`.

The runners are tests/e2e/standin.py. Processes are killed by process id, and only the stand-ins' own.
"""

import json
import os

from . import support
from .lanesupport import runner
from .mailsupport import (HEADER, IDLE, STDIN, TURN_START, TurnTest, mail_state, settled, turn_resume)


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


IDLE_GROUP = "Idle, waiting for a turn"


def finishing(name):
    """The text of a runner table whose turns end at once, in place of the one in the configuration: a lane whose runner
    waits for ever is given this between two turns, so that the next turn ends."""
    return runner(name, "ok", TURN_START, None, turn_resume("ok"), extra=STDIN)


class LostTurnTest(TurnTest):
    """A. `lane check` after the supervising process of a turn was killed."""

    def test_check_announces_the_return(self):
        lane = "g-check"
        record = self.running_turn(lane, ["First message.\n", "Second message.\n"])
        pids = [record["pid"]] + record["children"]
        self.lose_supervisor(lane)
        before = self.events()
        [entry] = self.lane_json("check")["lost"]
        new = self.events_since(before)
        self.assertEqual([item["kind"] for item in new], ["lane.lost", "lane.returned"])
        lost, returned = new
        self.assertEqual((entry["lane"], entry["run"]), (lane, 2))
        self.assertGreaterEqual(entry["survivors"], 1)
        self.assertEqual(entry["event"], {"id": lost["id"], "seq": lost["seq"]})
        self.assertEqual(entry["returned"], {"id": returned["id"], "seq": returned["seq"]})
        self.assertNotIn("returned_error", entry)
        self.assertEqual((returned["payload"], returned["actor"], returned["seq"]),
                         ({"run": 2, "sequences": [1, 2], "reason": "lost"}, "laneboss", lost["seq"] + 1))
        row = self.status(lane)
        self.assertEqual((row["state"], row["running"], row["reason"], row["idle"]), ("waiting", False, "lost", True))
        self.assertEqual(row["mail"], mail_state(last=2, returned=[1, 2],
                                                 settled=settled(2, "returned", [1, 2], "lost", True)))
        # A second check records and announces nothing.
        after = self.events()
        self.assertEqual(self.lane_json("check")["lost"], [])
        self.assertEqual(self.events(), after)
        # While a recorded process of the lost run survives, no turn starts; lane stop removes it.
        self.assertIn("survive", self.lane("turn", "--lane", lane, code=2).stderr)
        self.assertEqual(self.events(), after)
        stopped = self.lane_json("stop", "--lane", lane)
        self.assertEqual(stopped["stopped_by"], "lane-stop")
        self.assertGreaterEqual(stopped["removed"], 1)
        self.assert_gone(pids)
        # The next turn carries both messages first, each marked, and delivers them.
        self.rewrite(overrides={"tforever": finishing("tforever")})
        self.assertEqual(self.turn_json(lane)["turn"], {"kind": "mail", "mail": [1, 2]})
        self.settle(lane, 3, "lane.delivered")
        self.assertEqual([again for _, _, _, again in HEADER.findall(self.stdin_of(lane, 3))],
                         [" (again)", " (again)"])
        self.assertEqual(self.status(lane)["mail"]["delivered"], 2)
        self.assert_sound()

    def test_check_for_a_turn_without_mail(self):
        (self.home / "configs" / "alpha" / "rules" / "idle.md").write_text(IDLE, encoding="utf-8")
        self.rewrite('\n[turns]\nidle_message = "rules/idle.md"\n')
        lane = "g-idle"
        self.turn_start(lane, "tforever")
        self.settle(lane, 1)
        self.assertEqual(self.turn_json(lane, "--idle")["turn"], {"kind": "idle", "mail": []})
        self.record(lane, run=2)
        self.lose_supervisor(lane)
        before = self.events()
        [entry] = self.lane_json("check")["lost"]
        [lost] = self.events_since(before)
        self.assertEqual(lost["kind"], "lane.lost")
        self.assertIsNone(entry["returned"])
        self.assertNotIn("returned_error", entry)
        row = self.status(lane)
        self.assertEqual((row["state"], row["reason"], row["mail"]), ("waiting", "lost", mail_state()))
        self.lane_json("stop", "--lane", lane)


class GoneTurnTest(TurnTest):
    """B. `lane mark --gone` for a turn whose supervising process is gone and whose run record cannot be read."""

    def lost_without_a_trace(self, lane, texts):
        """A running turn whose supervising process is killed, whose run record is removed and whose own processes are
        removed too, as a machine that was restarted would leave it. Returns nothing: the lane is left as it is."""
        record = self.running_turn(lane, texts)
        self.lose_supervisor(lane)
        self.run_record_path(lane).unlink()
        self.remove_processes(record)

    def test_gone_announces_the_return(self):
        lane = "j-gone"
        self.lost_without_a_trace(lane, ["A message for a turn that is lost without a trace.\n"])
        before = self.events()
        marked = self.lane_json("mark", "--lane", lane, "--gone")
        new = self.events_since(before)
        self.assertEqual([item["kind"] for item in new], ["lane.gone", "lane.returned"])
        gone, returned = new
        self.assertEqual((gone["actor"], returned["actor"]), ("supervisor", "laneboss"))
        self.assertEqual((marked["kind"], marked["event"]), ("lane.gone", {"id": gone["id"], "seq": gone["seq"]}))
        self.assertEqual(marked["returned"], {"id": returned["id"], "seq": returned["seq"]})
        self.assertNotIn("returned_error", marked)
        self.assertEqual(returned["payload"], {"run": 2, "sequences": [1], "reason": "gone"})
        row = self.status(lane)
        self.assertEqual((row["state"], row["running"], row["idle"]), ("waiting", False, True))
        self.assertEqual(row["mail"], mail_state(last=1, returned=[1],
                                                 settled=settled(2, "returned", [1], "gone", True)))
        self.assert_sound()

    def test_nothing_is_announced_twice(self):
        # The loss was announced by `lane check`; declaring the run gone afterwards stores lane.gone and nothing else.
        lane = "j-twice"
        record = self.running_turn(lane, ["A message whose return is announced once.\n"])
        self.lose_supervisor(lane)
        self.lane_json("check")
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]] + record["children"])
        self.run_record_path(lane).unlink()
        before = self.events()
        marked = self.lane_json("mark", "--lane", lane, "--gone")
        [gone] = self.events_since(before)
        self.assertEqual(gone["kind"], "lane.gone")
        self.assertIsNone(marked["returned"])
        self.assertNotIn("returned_error", marked)
        self.assertEqual(len(self.lane_events(lane, "lane.returned")), 1)
        row = self.status(lane)
        self.assertEqual((row["state"], row["mail"]), ("waiting", mail_state(
            last=1, returned=[1], settled=settled(2, "returned", [1], "lost", True))))

    def test_a_late_announcement(self):
        # The loss is recorded by hand, so no announcement follows it; the run is then declared gone. The announcement
        # that is due is the one of the loss that settled the messages: reason lost, not gone.
        lane = "j-late"
        record = self.running_turn(lane, ["A message whose loss nobody announced.\n"])
        self.lose_supervisor(lane)
        self.put("lane.lost", lane, {"run": 2, "survivors": 0}, actor="laneboss")
        self.assertEqual(self.status(lane)["mail"], mail_state(
            last=1, returned=[1], settled=settled(2, "returned", [1], "lost", False)))
        self.assertEqual(self.lane_events(lane, "lane.returned"), [])
        self.run_record_path(lane).unlink()
        self.remove_processes(record)
        before = self.events()
        marked = self.lane_json("mark", "--lane", lane, "--gone")
        new = self.events_since(before)
        self.assertEqual([item["kind"] for item in new], ["lane.gone", "lane.returned"])
        gone, returned = new
        self.assertEqual(returned["payload"], {"run": 2, "sequences": [1], "reason": "lost"})
        self.assertEqual(marked["returned"], {"id": returned["id"], "seq": returned["seq"]})
        self.assertNotIn("returned_error", marked)
        self.assertEqual(self.status(lane)["mail"], mail_state(
            last=1, returned=[1], settled=settled(2, "returned", [1], "lost", True)))
        self.assert_sound()


class StoppedTurnTest(TurnTest):
    """C. A stopped turn leaves nothing alive, even when the agent's tool runs in a session of its own."""

    def test_a_child_in_its_own_session(self):
        lane = "k-stop"
        record = self.running_turn(lane, ["A message for a turn that is stopped.\n"], "tstubborn")
        runner_pid = record["pid"]
        child, escaped = record["children"]
        self.assertNotEqual(os.getsid(escaped), os.getsid(runner_pid), "the stand-in's child has no session of its own")
        stopped = self.lane_json("stop", "--lane", lane)
        self.assertEqual((stopped["reason"], stopped["survivors"], stopped["stopped_by"]), ("stopped", 0, "supervisor"))
        self.assert_gone([runner_pid, child, escaped])
        self.settle(lane, 2, "lane.returned")
        kinds = [item["kind"] for item in self.lane_events(lane)]
        self.assertEqual(kinds[-2:], ["lane.ended", "lane.returned"])
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((ended["reason"], ended["survivors"], ended["prompt"]["state"]), ("stopped", 0, "written"))
        self.assertEqual(self.wait_event("lane.returned", lane)["payload"],
                         {"run": 2, "sequences": [1], "reason": "stopped"})
        row = self.status(lane)
        self.assertEqual((row["state"], row["idle"]), ("waiting", True))
        self.assertEqual(row["mail"], mail_state(last=1, returned=[1],
                                                 settled=settled(2, "returned", [1], "stopped", True)))
        # The lane is idle with its message waiting for a turn: a supervisor that starts a session sees it.
        [idle] = self.briefing_json()["lanes"]["idle"]
        self.assertEqual((idle["lane"], idle["waiting"]), (lane, 1))
        # The next turn carries the message again, marked, and delivers it.
        self.rewrite(overrides={"tstubborn": finishing("tstubborn")})
        self.assertEqual(self.turn_json(lane)["turn"], {"kind": "mail", "mail": [1]})
        self.settle(lane, 3, "lane.delivered")
        self.assertEqual([again for _, _, _, again in HEADER.findall(self.stdin_of(lane, 3))], [" (again)"])


class IdleGroupTest(TurnTest):
    """D. `laneboss start` lists idle lanes in a group of their own, with the number of messages that wait."""

    def test_idle_lanes_are_listed(self):
        # i-idle: two messages wait. i-empty: none. i-back: one message has returned and another waits.
        for lane in ("i-idle", "i-empty"):
            self.turn_start(lane)
            self.settle(lane, 1)
        self.sent("i-idle", "The first message.\n")
        self.sent("i-idle", "The second message.\n")
        self.turn_start("i-back", "tfail")
        self.settle("i-back", 1)
        self.sent("i-back", "A message that comes back.\n")
        self.turn_json("i-back")
        self.settle("i-back", 2, "lane.returned")
        self.sent("i-back", "A message that waits.\n")
        # Not idle: a lane running a turn, an ordinary lane that ended, and an abandoned lane.
        self.running_turn("i-run", ["A message in flight.\n"])
        self.plain_start("i-plain")
        self.settle("i-plain", 1)
        self.turn_start("i-away")
        self.settle("i-away", 1)
        self.lane_json("mark", "--lane", "i-away", "--state", "abandoned")
        lanes = self.briefing_json()["lanes"]
        self.assertEqual([item["lane"] for item in lanes["idle"]], ["i-back", "i-empty", "i-idle"])
        self.assertEqual({item["lane"]: item["waiting"] for item in lanes["idle"]},
                         {"i-back": 2, "i-empty": 0, "i-idle": 2})
        self.assertEqual({item["state"] for item in lanes["idle"]}, {"waiting"})
        self.assertEqual([item["lane"] for item in lanes["running"]], ["i-run"])
        self.assertEqual([item["lane"] for item in lanes["ended"]], ["i-plain"])
        self.assertEqual(lanes["others"], 1)
        # The text form has the group, with one line for each lane and the number of messages that wait.
        text = self.run_laneboss("start", "--config", "alpha", environment=self.env("alpha")).stdout.splitlines()
        first = text.index("## Lanes")
        body = text[first:next(index for index in range(first + 1, len(text)) if text[index].startswith("## "))]
        self.assertEqual([line for line in body if line.startswith(IDLE_GROUP)], [IDLE_GROUP + " (3):"])
        listed = []
        for line in body[body.index(IDLE_GROUP + " (3):") + 1:]:
            if not line.startswith("- "):
                break
            listed.append(line)
        self.assertEqual([line.split(":")[0] for line in listed], ["- i-back", "- i-empty", "- i-idle"])
        for line, waiting in zip(listed, (2, 0, 2)):
            self.assertTrue(line.endswith("; messages waiting: {}".format(waiting)), line)
        self.lane_json("stop", "--lane", "i-run")


class DoctorTest(TurnTest):
    """E. A runner that can take turns and has no `limit_patterns` makes doctor warn, never fail."""

    def checks(self):
        result = self.run_laneboss("doctor", "--config", "alpha", code=0, environment=self.env("alpha"))
        found = {}
        for line in result.stdout.splitlines():
            item = json.loads(line)
            found[item["check"]] = item
        return found

    def test_the_warning_names_runners(self):
        # The lane tests' configuration has one runner that can take turns and has no limit_patterns: tbare.
        check = self.checks()["turns.limit_patterns"]
        self.assertEqual(sorted(check), ["check", "detail", "ok"])
        self.assertIs(check["ok"], True)
        self.assertTrue(check["detail"].startswith("warning:"), check["detail"])
        self.assertIn("tbare", check["detail"])
        # Now tbare has patterns. tzzz can take turns and has none; tyyy has none and cannot take turns (no {session});
        # tpat can take turns and has patterns. Only tzzz is named.
        self.rewrite(overrides={
            "tbare": finishing("tbare"),
            "tzzz": runner("tzzz", "ok", TURN_START, None, turn_resume("ok"), extra=STDIN, patterns=""),
            "tyyy": runner("tyyy", "ok", ["--lane", "{lane}"], None, ["ok", "resumed", "--lane", "{lane}"], extra=STDIN,
                           patterns=""),
            "tpat": finishing("tpat")})
        detail = self.checks()["turns.limit_patterns"]["detail"]
        self.assertTrue(detail.startswith("warning:"), detail)
        self.assertIn("tzzz", detail)
        for name in ("tyyy", "tpat", "tbare"):
            self.assertNotIn(name, detail)
        # With a pattern on every runner that can take turns there is nothing to warn about, and no line.
        self.rewrite(overrides={"tbare": finishing("tbare")})
        self.assertNotIn("turns.limit_patterns", self.checks())

    def test_the_briefing_shows_it_too(self):
        warned = self.checks()["turns.limit_patterns"]
        read = {item["check"]: item for item in self.briefing_json()["checks"]["read"]}
        self.assertEqual(read["turns.limit_patterns"], warned)
        self.rewrite(overrides={"tbare": finishing("tbare")})
        self.assertNotIn("turns.limit_patterns", {item["check"] for item in self.briefing_json()["checks"]["read"]})

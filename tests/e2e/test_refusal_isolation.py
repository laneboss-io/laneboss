"""Refusals I. Isolation and integrity: another configuration sees and reviews nothing of a lane, and attributes nothing
of it to its own lane of the same name; a hand-written refusal event with a malformed payload is refused; state verify
passes and state rebuild equals state lanes."""

import json

from . import refusalsupport, support
from .refusalsupport import expected_path, refused_steps, shell_steps


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def excerpt(text):
    return {"text": text, "withheld": False, "length": len(text), "sha256": support.digest(text)}


class RefusalIsolationTest(refusalsupport.RefusalTest):
    def setUp(self):
        super().setUp()
        self.add_config("beta")

    def test_configurations_see_only_their_own(self):
        lane = "i-same"
        steps = [{"open": {}}] + refused_steps("claude-code") + shell_steps("c2", "printf 'x\\n' > notes/plan.md")
        alpha = self.start_session(lane, "claude-code", steps + [{"exit": 0}], config="alpha")
        self.wait_event("lane.ended", lane, config="alpha")
        refusal = self.kind_events(lane, "lane.refusal", config="alpha")[0]["payload"]
        plan = expected_path(alpha["worktree"], "notes/plan.md")
        beta_events = self.events("beta")
        # beta does not know alpha's lane: it can neither list, scan nor review it.
        self.refusals(lane, config="beta", code=2)
        self.lane("scan", "--lane", lane, config="beta", code=2)
        self.review(lane, refusal["refusal"], plan, "clean", config="beta", code=2)
        self.assertEqual(self.events("beta"), beta_events)
        # beta's own lane of the same name, in its own working directory, finds only its own records: both sessions
        # are below the same home, and alpha's refusal is not attributed to beta's lane.
        steps = [{"open": {}}] + shell_steps("b1", "ls notes", text="") + [{"exit": 0}]
        self.start_session(lane, "claude-code", steps, config="beta")
        self.wait_event("lane.ended", lane, config="beta")
        self.assertEqual([item for item in self.events("beta") if item["kind"] in refusalsupport.KINDS], [])
        self.assertEqual(self.scan(lane, config="beta")["appended"], {"refusals": 0, "suspicions": 0})
        self.assertEqual(self.refusals(lane, config="beta")["refusals"], [])
        self.assertEqual(len(self.refusals(lane, config="alpha")["unreviewed"]), 1)
        self.review(lane, refusal["refusal"], plan, "clean", config="alpha")
        for config in ("alpha", "beta"):
            self.assert_sound(config)

    def test_malformed_events_are_refused(self):
        steps = [{"open": {}}] + refused_steps("claude-code") + shell_steps("c2", "printf 'x\\n' > notes/plan.md")
        started = self.start_session("i-hand", "claude-code", steps + [{"exit": 0}])
        self.wait_event("lane.ended", "i-hand")
        refusal = self.kind_events("i-hand", "lane.refusal")[0]["payload"]
        suspicion = self.kind_events("i-hand", "lane.workaround_suspected")[0]["payload"]
        plan = expected_path(started["worktree"], "notes/plan.md")
        count = len(self.events())
        good = dict(refusal, refusal="rf-" + "1" * 24, call=dict(refusal["call"], id="hand-1"))
        cases = [
            ("refusal without a payload", "lane.refusal", {}),
            ("refusal with an unknown field", "lane.refusal", dict(good, colour="red")),
            ("refusal without its guard", "lane.refusal", {key: value for key, value in good.items() if key != "guard"}),
            ("refusal with a bad id", "lane.refusal", dict(good, refusal="refusal-1")),
            ("refusal of run zero", "lane.refusal", dict(good, run=0)),
            ("refusal of a run that never was", "lane.refusal", dict(good, run=5)),
            ("refusal of an unknown format", "lane.refusal", dict(good, format="other")),
            ("refusal with a relative target", "lane.refusal", dict(good, targets=["notes/plan.md"])),
            ("refusal with an excerpt that is not one", "lane.refusal", dict(good, message={"text": "x"})),
            ("refusal with withheld text", "lane.refusal", dict(good, command=dict(excerpt("ls"), withheld=True))),
            ("suspicion of an unknown refusal", "lane.workaround_suspected",
             dict(suspicion, suspicion="ws-" + "2" * 24, refusal="rf-" + "3" * 24)),
            ("suspicion with an unknown way", "lane.workaround_suspected",
             dict(suspicion, suspicion="ws-" + "2" * 24, how=["copied"])),
            ("suspicion without paths", "lane.workaround_suspected", dict(suspicion, suspicion="ws-" + "2" * 24, paths=[])),
            ("review of a path no suspicion names", "lane.refusal_reviewed",
             {"refusal": refusal["refusal"], "path": "/elsewhere/x.md", "verdict": "clean",
              "suspicions": [suspicion["suspicion"]], "note": None}),
            ("review with an unknown verdict", "lane.refusal_reviewed",
             {"refusal": refusal["refusal"], "path": plan, "verdict": "fine", "suspicions": [suspicion["suspicion"]],
              "note": None}),
            ("review of an unknown suspicion", "lane.refusal_reviewed",
             {"refusal": refusal["refusal"], "path": plan, "verdict": "clean", "suspicions": ["ws-" + "4" * 24],
              "note": None}),
        ]
        for label, kind, payload in cases:
            with self.subTest(label):
                result = self.append(self.event(kind, lane="i-hand", payload=payload), code=2)
                self.assertTrue(result.stderr.startswith("refused:"), result.stderr)
        self.assertEqual(len(self.events()), count)
        # A well-formed refusal written by hand is accepted once; the same refusal again is a duplicate.
        first = self.laneboss_json("event", "append", "--config", "alpha", "--file", self.event_file(
            self.event("lane.refusal", lane="i-hand", payload=good)))
        again = self.laneboss_json("event", "append", "--config", "alpha", "--file", self.event_file(
            self.event("lane.refusal", lane="i-hand", payload=good)))
        self.assertEqual((first["duplicate"], again["duplicate"], again["seq"]), (False, True, first["seq"]))
        self.assertEqual(len(self.events()), count + 1)
        self.assert_sound()

    def event_file(self, value):
        path = self.directory / "hand-{}.json".format(len(list(self.directory.glob("hand-*.json"))))
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

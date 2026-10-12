"""E. Adoption (T5, the data model half): the event `lane.adopted`, its payload, the rule at append and the
projection (docs/architecture.md, "Accounts and adoption", "Adopting a session that already runs").

The lane takes a session something outside the launcher started and makes it a turn-based lane. These tests drive the
launcher through `event append` and read what the store made of it through `state lanes`, `state verify`, `lane status`
and `lane send`: nothing here imports the package under test. The `lane adopt` command itself and its refusals are a
later lane and are not tested here; the room command is tested in tests/e2e/test_room.py and
tests/e2e/test_room_choice.py.
"""

import hashlib
import json
import os

from . import mailsupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


# The lane's session identifier of a hand-made adoption: a UUID in its usual lower-case form.
SESSION_ID = mailsupport.SESSION
# The projection's `times`, from docs/architecture.md ("The event and state store"): an adoption sets none of them.
TIMES = ("planned", "started", "ended", "timeout", "stuck", "resumed", "lost", "cleaned")


def adopted_payload(paths, lane, session_id=SESSION_ID, idle=None, account="acc-two", runner="tok",
                    model="tok-model-1", effort="high", worktree="/srv/example/lanes/one", branch=None,
                    repository=None, difficulty=None):
    """The payload of a `lane.adopted` event: the payload of a `lane.started` without `run`, `how` and `launch`
    (docs/architecture.md, "Adopting a session that already runs"). `session_id` is required, `idle_seconds` is added,
    `difficulty` is null, and every part of `chosen_by` whose value is given is `supervisor` (a part whose value is
    null stays null). The session, the log and the brief are the ones this configuration binds for this lane."""
    payload = support.started_payload(paths, lane, account=account)
    for key in ("run", "how", "launch"):
        payload.pop(key)
    payload.update(runner=runner, model=model, effort=effort, worktree=worktree, branch=branch,
                   repository=repository, difficulty=difficulty,
                   chosen_by={"runner": "supervisor", "model": "supervisor",
                              "effort": None if effort is None else "supervisor",
                              "account": None if account is None else "supervisor"},
                   session_id=session_id, idle_seconds=idle)
    return payload


class AdoptTest(mailsupport.TurnTest):
    """The launcher's lane configuration `alpha`, whose runners take turns, and an adopted lane built by hand."""

    def adopt(self, lane, payload=None, code=0, **fields):
        return self.put("lane.adopted", lane, payload if payload is not None else adopted_payload(self.where(), lane),
                        code=code, **fields)

    def test_adopted_run_is_already_over(self):
        lane = "adopt-one"
        occurred = "2026-10-08T09:00:00.000000Z"
        branch = "web-adopt-one"
        repository = "/srv/example/web"
        payload = adopted_payload(self.where(), lane, idle=90, account="acc-two", runner="tok", model="tok-model-1",
                                  effort="high", worktree="/srv/example/lanes/adopt-one", branch=branch,
                                  repository=repository)
        result = self.adopt(lane, payload, occurred_at=occurred)
        appended = json.loads(result.stdout)
        self.assertIs(appended["duplicate"], False)
        # state verify passes on a store that holds only the adoption.
        verified = self.laneboss_json("state", "verify", "--config", "alpha", environment=self.env("alpha"))
        self.assertIs(verified["ok"], True)
        self.assertEqual(verified["events"], 1)
        # The projection reads it as run 1, already over, waiting for its first turn, turn-based.
        row = self.row(lane)
        self.assertEqual(row["lane"], lane)
        self.assertEqual(row["run"], 1)
        self.assertIs(row["running"], False)
        self.assertEqual(row["state"], "waiting")
        self.assertEqual(row["state_at"], occurred)
        self.assertEqual(row["events"], 1)
        self.assertEqual(row["last_seq"], appended["seq"])
        # No entry of `times` is set: the launcher started and ended nothing.
        self.assertEqual(row["times"], {name: None for name in TIMES})
        # The runner, model, effort, account, worktree and branch of the payload.
        self.assertEqual(
            {key: row[key] for key in ("runner", "model", "effort", "account", "worktree", "branch")},
            {"runner": "tok", "model": "tok-model-1", "effort": "high", "account": "acc-two",
             "worktree": "/srv/example/lanes/adopt-one", "branch": branch})
        # `mail` with turn_based true, so every later piece treats the lane as turn-based.
        self.assertIs(row["mail"]["turn_based"], True)
        self.assertEqual(row["mail"]["idle_seconds"], 90)
        self.assertEqual((row["mail"]["last"], row["mail"]["waiting"], row["mail"]["returned"]), (0, [], []))
        self.assertIsNone(row["mail"]["in_flight"])
        self.assertIsNone(row["mail"]["settled"])
        # state rebuild reproduces the projection from the events alone.
        self.assert_sound()

    def test_status_and_send_take_the_lane(self):
        lane = "adopt-two"
        self.adopt(lane)
        row = self.status(lane)
        self.assertEqual(row["lane"], lane)
        self.assertEqual(row["state"], "waiting")
        self.assertIs(row["idle"], True)
        self.assertIs(row["mail"]["turn_based"], True)
        # lane send is accepted: the lane is turn-based.
        sent = self.sent(lane, "A first message for the adopted lane.\n")
        self.assertEqual(sent["lane"], lane)
        self.assertEqual(sent["sequence"], 1)
        self.assertEqual(sent["waiting"], 1)

    def test_turn_takes_an_adopted_lane(self):
        lane = "adopt-nine"
        self.adopt(lane)
        # lane turn reads "the previous run" from the adoption (docs/architecture.md, "Adopting a session that already
        # runs"): it is not refused for a lane that "has not run", it reads the runner and the session of the adopted
        # payload, and it reaches the turn itself — which carries no mail and no --idle, so it starts nothing.
        result = self.lane("turn", "--lane", lane, code=0)
        turned = json.loads(result.stdout)
        self.assertEqual((turned["lane"], turned["started"], turned["reason"], turned["waiting"]),
                         (lane, False, "no mail", 0))
        # The previous-run read stops with no error of a missing key: a refusal and an internal error are both absent.
        self.assertNotIn("has not run yet", result.stderr)
        self.assertNotIn("internal error", result.stderr)

    def test_send_reads_the_adoption_runner(self):
        lane = "adopt-ten"
        # The runner the adoption names, tnores, has no resume template, so it cannot take turns; lane send says so,
        # naming that runner: the previous run is the adoption and its runner is the one the turns would use.
        self.adopt(lane, adopted_payload(self.where(), lane, runner="tnores"))
        result = self.lane("send", "--lane", lane, "--file", self.message_file("A message for the adopted lane.\n"),
                           code=2)
        self.assertIn("tnores cannot take turns", result.stderr)

    def test_only_a_lane_with_no_event(self):
        lane = "adopt-three"
        self.adopt(lane)
        # A second adoption of the same lane is refused, and nothing is stored.
        self.refuse("lane.adopted", lane, adopted_payload(self.where(), lane), "lane.adopted")
        # A lane that holds any other lane event is refused too.
        other = "adopt-four"
        self.put("lane.planned", other, {})
        self.refuse("lane.adopted", other, adopted_payload(self.where(), other), "lane.adopted")

    def test_other_configuration_session(self):
        lane = "adopt-five"
        payload = adopted_payload(self.where(), lane)
        payload["session"] = {"socket": "/tmp/elsewhere/tmux-1000/default", "name": lane}
        self.refuse("lane.adopted", lane, payload, "payload.session")

    def test_the_next_start_is_run_two(self):
        lane = "adopt-six"
        self.adopt(lane)
        # A lane.started with run 1 after an adoption is refused: the adopted run was run 1.
        self.refuse("lane.started", lane, support.started_payload(self.where(), lane, run=1, how="start"), "payload.run")
        # The first turn is run 2, resumed, with `after` null.
        self.put("lane.resumed", lane, {"run": 2, "after": None, "message": None})
        started = mailsupport.turn_started(self.where(), lane, run=2, how="resume", mail=[], idle=None,
                                           runner_name="tok", session_id=SESSION_ID, account="acc-two")
        self.put("lane.started", lane, started)
        row = self.row(lane)
        self.assertEqual(row["run"], 2)
        self.assertIs(row["running"], True)
        self.assertEqual(row["resumes"], 1)

    def test_the_payload_is_validated(self):
        lane = "adopt-seven"
        base = adopted_payload(self.where(), lane)
        # A missing session_id: an adoption names the session it takes over.
        without = dict(base)
        without.pop("session_id")
        self.refuse("lane.adopted", lane, without, "session_id")
        # A chosen_by part that contradicts the rule: a person adopted the lane, so every given part is supervisor.
        wrong_runner = dict(base, chosen_by=dict(base["chosen_by"], runner="routing"))
        self.refuse("lane.adopted", lane, wrong_runner, "payload.chosen_by")
        # An account given (so chosen_by.account must be supervisor) named as default instead.
        self.refuse("lane.adopted", lane, dict(base, chosen_by=dict(base["chosen_by"], account="default")),
                    "payload.chosen_by")
        # An adoption states no difficulty.
        self.refuse("lane.adopted", lane, dict(base, difficulty="hard"), "payload.difficulty")
        # The keys of lane.started that an adoption has not: run, how and launch.
        for key, value in (("run", 1), ("how", "resume"), ("launch", "0" * 32)):
            with self.subTest(key):
                self.refuse("lane.adopted", lane, dict(base, **{key: value}), "payload")

    def test_status_takes_the_adoption_id(self):
        lane = "adopt-status"
        # A second identifier, not the shared one of the hand-made lanes: a status that printed a constant, or another
        # lane's identifier, would not pass here.
        session_id = "3f2b1c0d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"
        self.adopt(lane, adopted_payload(self.where(), lane, session_id=session_id))
        # The lane holds no lane.started, so `lane status` takes the adoption's payload where no lane.started exists
        # (docs/architecture.md, "Adopting a session that already runs"): the identifier is the adopted one, not null.
        self.assertEqual(self.status(lane)["session_id"], session_id)

    def test_reuse_checks_the_adopted_registry(self):
        lane = "adopt-reuse"
        payload = adopted_payload(self.where(), lane)
        # The registry the adoption recorded is not the one this command would look in.
        payload["claims"] = "/srv/example/other-claims"
        self.adopt(lane, payload)
        # An abandoned lane whose run the launcher never started is started again with --reuse. The claims check reads
        # the lane's previous run — the adoption, which carries `claims` — and refuses by naming the registry, where a
        # read of the launcher's runs finds none and crashes: exit 2, not the internal error of a TypeError.
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        result = self.start(lane, "--reuse", "--runner", "tok", "--model", "tok-model-1", "--worktree",
                            self.scratch(lane), code=2)
        self.assertIn("registry", result.stderr)

    def test_resume_refuses_an_adopted_lane(self):
        lane = "adopt-resume"
        worktree = str(self.scratch(lane))
        state = self.where()["state_dir"]
        # The scene the later `lane adopt` command will build, and every turn of an adopted lane needs: the working
        # directory carries the lane's claim, and the adoption's brief is rendered on disk. This hand-made adoption
        # stands in for that command, so that every check of `lane resume` before its own turn-based one passes and the
        # refusal the test reads is that one — not the missing claim, the missing rendered brief, the missing worktree
        # or an account the runner does not list.
        info = os.stat(worktree)
        registry = self.directory / "claims"
        registry.mkdir(mode=0o700, exist_ok=True)
        claim = registry / "{}-{}.json".format(info.st_dev, info.st_ino)
        claim.write_text(json.dumps({"config": "alpha", "state": state, "lane": lane}), encoding="utf-8")
        os.chmod(str(claim), 0o600)
        content = b"# The brief of the adopted lane.\n"
        digest = hashlib.sha256(content).hexdigest()
        rendered = os.path.join(state, "lanes", lane, "rendered", digest + ".md")
        os.makedirs(os.path.dirname(rendered), exist_ok=True)
        with open(rendered, "wb") as handle:
            handle.write(content)
        payload = adopted_payload(self.where(), lane, account=None, worktree=worktree)
        payload["brief"] = {"path": rendered, "sha256": digest}
        self.adopt(lane, payload)
        # The projection made the lane turn-based (`mail.turn_based`), so `lane resume`'s own turn-based check refuses
        # it, with the message that names lane send and lane turn (docs/architecture.md, "Adopting a session that
        # already runs") — never the payload.idle_seconds message the adoption's own key would draw, which is what the
        # adoption would be refused with if this check did not read the row.
        result = self.lane("resume", "--lane", lane, code=2)
        self.assertIn("turn-based", result.stderr)
        self.assertIn("lane send", result.stderr)
        self.assertIn("lane turn", result.stderr)

    def test_state_verify_and_rebuild_agree(self):
        lane = "adopt-eight"
        self.adopt(lane, adopted_payload(self.where(), lane, idle=None, effort=None, account=None))
        # An adoption without --effort and --account is accepted: those parts of chosen_by are null.
        row = self.row(lane)
        self.assertIsNone(row["effort"])
        self.assertIsNone(row["account"])
        self.assertIs(row["mail"]["turn_based"], True)
        self.assert_sound()

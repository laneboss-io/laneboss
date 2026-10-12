"""The command `lane adopt`, written before it exists (docs/architecture.md, "Adopting a session that already runs";
the pinned specification of its argv, its output and its twelve refusals).

`lane adopt` is to take a session that something outside the launcher started and make it a turn-based lane, so that
the next `lane turn` resumes it. These tests are the specification that command is built to. Nothing here imports the
package under test: every test drives the installed command (`laneboss lane adopt ...`) and reads what the store made
of it through `state lanes`, `state verify` and `lane status`.

On the launcher as it is the command does not exist (`lane adopt` is an unknown action, the argument parser exits 2
for it), and every test here fails on that absence, not on an error of its own. The success test and every refusal
test share one helper that builds a valid call (tests/e2e/adoptsupport.py): a refusal test changes exactly one thing
in it and asserts, besides the exit code and the pinned phrase, that nothing of the lane was recorded.
"""

import json
import os
from pathlib import Path
import sys

from . import adoptsupport, support
from .adoptsupport import ACCOUNT, EXCLUDED, MODEL, PROJECT, QUIET_SECONDS, RUNNER, TIMES


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class AdoptCommandTest(adoptsupport.AdoptTest):
    """The installed `lane adopt`: its help, one success and the shapes of it, its twelve refusals, and a refused call
    that leaves a good adoption alone."""

    def test_help_names_the_session_option(self):
        # The cheapest test of the command's existence: without `lane adopt` the parser exits 2 and names no option.
        result = self.adopt(["--help"])
        self.assertIn("--session", result.stdout)

    def test_a_valid_call_adopts_the_session(self):
        lane, session = "r2-adopted", "2c4e6a8b-1d3f-4e5a-9b7c-0d2f4a6c8e10"
        printed = json.loads(self.adopt(self.call(lane, session)).stdout)
        stored = self.wait_event("lane.adopted", lane)
        # Standard output is the payload of that event plus `lane` and `event`, exactly as `lane start` prints it, and
        # the lane holds two events and no other: the rendered brief first, then the adoption.
        self.assertEqual(printed["lane"], lane)
        self.assertEqual(printed["event"], {"id": stored["id"], "seq": stored["seq"]})
        self.assertEqual({k: v for k, v in printed.items() if k not in ("lane", "event")}, stored["payload"])
        self.assertEqual([item["kind"] for item in self.lane_events(lane)], ["brief.rendered", "lane.adopted"])
        # The payload: the identifier the command was given, its idle interval, no difficulty, and every part whose
        # value was given chosen by the supervisor.
        self.assertEqual(printed["session_id"], session)
        self.assertEqual(printed["idle_seconds"], 300)
        self.assertIsNone(printed["difficulty"])
        self.assertEqual((printed["runner"], printed["model"]), (RUNNER, MODEL))
        self.assertEqual((printed["effort"], printed["account"]), ("high", ACCOUNT))
        self.assertEqual(printed["chosen_by"], {"runner": "supervisor", "model": "supervisor",
                                                "effort": "supervisor", "account": "supervisor"})
        # The rest of the payload: the project, no touches, the working directory as it was given, the runner's quiet
        # seconds, and the time budget of the configuration the call did not override.
        self.assertEqual(printed["project"], PROJECT)
        self.assertEqual(printed["touches"], [])
        self.assertEqual(os.path.realpath(printed["worktree"]), os.path.realpath(str(self.worktree(lane))))
        self.assertEqual(printed["quiet_seconds"], QUIET_SECONDS)
        # [lanes] budget_minutes of the tests' configuration (tests/e2e/lanesupport.py)
        self.assertEqual(printed["budget_minutes"], 30)
        # The binding of a lane.started: this configuration's session for the lane, the lane's own log and the lane's
        # rendered brief, which is kept on disk under the hash the payload names.
        lane_directory = Path(self.paths()["state_dir"]) / "lanes" / lane
        self.assertEqual(printed["session"], {"socket": self.paths()["socket"], "name": lane})
        self.assertEqual(printed["log"], str(lane_directory / "output.log"))
        rendered = Path(printed["brief"]["path"])
        self.assertTrue(rendered.is_file(), rendered)
        self.assertTrue(str(rendered).startswith(str(lane_directory / "rendered")), rendered)
        self.assertEqual(support.digest(rendered.read_bytes()), printed["brief"]["sha256"])
        # The projection takes the adoption as run 1, already over and waiting for its first turn, turn-based, with no
        # entry of `times` set; the store still verifies.
        row = self.row(lane)
        self.assertEqual(row["run"], 1)
        self.assertIs(row["running"], False)
        self.assertEqual(row["state"], "waiting")
        self.assertIs(row["mail"]["turn_based"], True)
        self.assertEqual(row["times"], {name: None for name in TIMES})
        self.assertIs(self.laneboss_json("state", "verify", "--config", "alpha",
                                         environment=self.env("alpha"))["ok"], True)
        # The working directory's claim is taken: a second lane cannot be started there.
        self.assertEqual(self.claim_lane(self.worktree(lane)), lane)
        second = self.start("r2-second", "--runner", "plain", "--model", "plain-model-1",
                            "--worktree", str(self.worktree(lane)), code=2)
        self.assertIn("lane " + lane, second.stderr)

    def test_without_effort_and_account(self):
        lane, session = "r3-optional", "3d5f7b9c-2e4a-4b6c-8d0e-1f3a5c7b9d21"
        # Only `--effort` and `--account` are dropped: a part not given is null, in the payload and in `chosen_by`.
        # `--budget` is given: the value the call names, not the configuration's.
        printed = json.loads(self.adopt(self.call(lane, session, ("--effort", None), ("--account", None),
                                                    ("--budget", "45"))).stdout)
        stored = self.wait_event("lane.adopted", lane)
        self.assertEqual({k: v for k, v in printed.items() if k not in ("lane", "event")}, stored["payload"])
        self.assertEqual(printed["session_id"], session)
        self.assertEqual(printed["budget_minutes"], 45)
        self.assertIsNone(printed["effort"])
        self.assertIsNone(printed["account"])
        self.assertIsNone(printed["chosen_by"]["effort"])
        self.assertIsNone(printed["chosen_by"]["account"])
        self.assertEqual(printed["chosen_by"]["runner"], "supervisor")
        self.assertEqual(printed["chosen_by"]["model"], "supervisor")

    def test_send_and_the_first_turn(self):
        lane, session = "r4-turn", "4e6a8c0d-3f5b-4c7d-9e1f-2a4b6c8d0e32"
        self.adopt(self.call(lane, session))
        # An adopted lane is turn-based: a message is accepted, and the first turn is run 2, a resume.
        sent = self.sent(lane, "A first message for the adopted lane.\n")
        self.assertEqual((sent["lane"], sent["sequence"], sent["waiting"]), (lane, 1, 1))
        turned = self.turn_json(lane)
        self.assertEqual((turned["run"], turned["how"]), (2, "resume"))
        self.assertEqual(turned["session_id"], session)
        # The turn resumed the session the adoption named: the runner's resume template was filled with it.
        self.assertIn(session, self.record(lane, run=2, ended=True)["argv"])
        self.settle(lane, 2, "lane.delivered")

    # The twelve refusals of the specification: each is exit 2, its phrase on standard error, and nothing recorded.

    def test_refuses_a_known_lane(self):
        lane, session = "r5-known", "5f7b9d1e-4a6c-4d8e-8f0a-3b5c7d9e1f43"
        self.start(lane, "--runner", "plain", "--model", "plain-model-1", "--worktree", str(self.worktree("r5-first")))
        self.settle(lane, 1)
        # The lane name is known to the configuration now, and `lane adopt` has no --reuse.
        self.refused(lane, "is already known", self.call(lane, session))

    def test_refuses_a_session_that_is_no_uuid(self):
        lane = "r6-upper"
        # Only the identifier changes: the same one in its usual upper-case form.
        self.refused(lane, "--session must be a lower-case UUID",
                     self.call(lane, "5F7B9D1E-4A6C-4D8E-8F0A-3B5C7D9E1F43"))

    def test_refuses_another_lanes_session(self):
        owner = "r7-owner"
        started = self.turn_start(owner)
        self.settle(owner, 1)
        # Only the identifier changes: it is the session of a lane of this configuration.
        self.refused("r7-adopted", "already belongs to lane",
                     self.call("r7-adopted", started["session_id"]))

    def test_refuses_a_runner_without_turns(self):
        lane = "r8-noturns"
        # Only the runner changes: tnoturns takes its prompt on standard input and names {session}, but its resume
        # template is missing, so it cannot take turns.
        self.refused(lane, "cannot take turns",
                     self.call(lane, "8b0d2f4a-7c9e-4f1b-8a2c-5d7e9f0a1b64", ("--runner", "tnoturns")))

    def test_refuses_an_unknown_account(self):
        lane = "r9-account"
        # Only the account changes: acc-three is not one the runner lists.
        self.refused(lane, "does not list that account",
                     self.call(lane, "9c1e3f5a-8d0b-4e2c-9a3b-6e8f0a1b2c75", ("--account", "acc-three")))

    def test_refuses_an_excluded_account(self):
        lane = "r10-excluded"
        # Only the account changes: the project adopter excludes acc-one, which the runner does list.
        self.refused(lane, "excludes account",
                     self.call(lane, "0a2b4c6d-9e1f-4a3b-8c4d-7f9a0b1c2d86", ("--account", EXCLUDED)))

    def test_refuses_a_runner_without_records(self):
        lane = "r11-entry"
        # Only the runner changes: tnoentry has a records entry that does not name {session}, so nothing could show
        # the session exists.
        self.refused(lane, "no records entry uses {session}",
                     self.call(lane, "1b3c5d7e-0f2a-4b4c-9d5e-8a0b1c2d3e97", ("--runner", "tnoentry")))

    def test_refuses_a_missing_directory(self):
        lane = "r12-nodir"
        gone = self.directory / "work" / "r12-gone"
        # Only the working directory changes, to one that does not exist.
        self.assertFalse(gone.exists())
        self.refused(lane, "is not an existing directory",
                     self.call(lane, "2c4d6e8f-1a3b-4c5d-8e6f-9b0c1d2e3f08", ("--worktree", str(gone))))
        # The refusal did not create the directory it refused.
        self.assertFalse(gone.exists())

    def test_refuses_a_claimed_directory(self):
        owner, lane = "r13-owner", "r13-adopted"
        shared = self.worktree(owner)
        self.start(owner, "--runner", "plain", "--model", "plain-model-1", "--worktree", str(shared))
        self.wait_event("lane.ended", owner)
        # The control: another lane does hold this directory, and its claim is intact after the refusal.
        self.assertEqual(self.claim_lane(shared), owner)
        # Only the working directory changes, to one another lane's claim holds.
        self.refused(lane, "one lane per working directory", self.call(lane, "3d5e7f90-2b4c-4d6e-9f70-0c1d2e3f4a19",
                                                   ("--worktree", str(shared))), directory=shared)
        self.assertEqual(self.claim_lane(shared), owner)

    def test_refuses_a_taken_session_name(self):
        lane = "r14-held"
        socket = self.paths()["socket"]
        # A tmux session of the lane's own name is open on the configuration's socket (the way tests/e2e/
        # test_lane_ownership.py opens one): only that changes about the call.
        Path(socket).parent.mkdir(mode=0o700, exist_ok=True)
        self.tmux(socket, "-f", os.devnull, "new-session", "-d", "-s", lane,
                  sys.executable, "-c", "import time; time.sleep(600)")
        pane = self.tmux(socket, "list-panes", "-t", "=" + lane, "-F", "#{pane_pid}").stdout.split()
        self.sentinels.append(int(pane[0]))
        self.refused(lane, "is still open", self.call(lane, "4e6f8a01-3c5d-4e7f-8a01-1d2e3f4a5b20"))
        # The refusal did not touch the session it found.
        self.assertIn(lane, self.tmux(socket, "list-sessions", "-F", "#{session_name}").stdout.split())

    def test_refuses_a_session_without_records(self):
        lane = "r15-norec"
        # Another session's record lies in the same directory, older than the quiet seconds: only the record of the
        # session the call names is missing, so a lookup that ignores the identifier would find one and adopt.
        self.session_record(self.worktree(lane), "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e")
        # Only the session's records change: the runner's entry names a file that is not there, so nothing shows the
        # session exists.
        self.refused(lane, "no session record",
                     self.call(lane, "5f7a9b12-4d6e-4f80-9b12-2e3f4a5b6c31", records=False))

    def test_refuses_a_session_still_written(self):
        lane = "r16-fresh"
        # Only the session's records change: the file was written now, within the runner's quiet seconds.
        self.refused(lane, "still being written",
                     self.call(lane, "6a8b0c23-5e7f-4a91-8c23-3f4a5b6c7d42", records="fresh"))

    def test_refuses_a_resume_it_cannot_fill(self):
        lane = "r18-effort"
        # Only the runner and the effort change: teffort's resume template uses {effort} and the call gives none, so
        # no turn of the lane could ever be started.
        self.refused(lane, "which no turn of this lane could fill",
                     self.call(lane, "8c0d2e45-7a9b-4c13-8e45-5b6c7d8e9f64", ("--runner", "teffort"),
                               ("--effort", None)))

    def test_a_refusal_does_not_disturb_one(self):
        # A good adoption first, then a refused call for another lane that tries that adoption's own session, and a
        # refused call with a bad identifier: the good lane keeps its events, its row and its claim, and the refused
        # one holds no event.
        good, bad = "r17-good", "r17-bad"
        session = "7b9c1d34-6f8a-4b02-9d34-4a5b6c7d8e53"
        self.adopt(self.call(good, session))
        events, row = self.lane_events(good), self.row(good)
        self.refused(bad, "already belongs to lane", self.call(bad, session))
        self.refused(bad, "--session must be a lower-case UUID", self.call(bad, "not-a-uuid"))
        self.assertEqual(self.lane_events(good), events)
        self.assertEqual(self.row(good), row)
        self.assertEqual(self.claim_lane(self.worktree(good)), good)
        self.assertEqual(self.lane_events(bad), [])

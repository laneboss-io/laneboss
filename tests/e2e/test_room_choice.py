"""T5, the choice of the account: which account a turn takes, as a function of the installed package.

The design (docs/architecture.md, "Accounts and adoption (T5; built in part)", "Slots and the choice of the
account") gives the order in which a turn takes its account: the one that `--account` names and only that one, else the
previous run's account, else the runner's other accounts in the order they are listed, skipping those the project
excludes; the first whose room command answers `room` true with `slots` of 1 or more is used, and `chosen_by.account`
records that it was the `room` command. The launcher's `lane turn`, `lane resume` and the loop call this choice; this
module still asks it as a function of the *installed* package in a process of its own, the way tests/e2e/test_room.py
asks `accounts.room_of`: this module imports nothing of the package, and the configured `room` command is a program of
the test's own, run for real. That program records every account it is asked about, so a test can show which candidates
were considered, in what order, and that an account the design does not reach was never asked.

A `Choice` also carries an outcome, so a caller can tell the cases apart without reading a reason's text: each test
here pins the outcome it means, so a runner without a room command (no check ran) is never read as one whose command
answered no room.
"""

import json
from pathlib import Path
import subprocess
import sys
import time

from . import support
from .lanesupport import runner
from .mailsupport import STDIN, TURN_START, TurnTest, turn_resume

# The fixture's runner lists two accounts; these tests need three, so an account in the middle of the list can be
# shown to be walked in order (and skipped when the project excludes it) with a further account still to reach.
ACCOUNTS = ["acc-a", "acc-b", "acc-c"]
ACCOUNTS_ANCHOR = 'accounts = ["account-one", "account-two"]'
# The fixture's project excludes one of the fixture's two accounts, which the configuration refuses once the runner
# lists neither: the project's own exclusions are emptied here, and every test passes the exclusions it means to the
# choice itself.
PROJECT_ANCHOR = 'excluded_accounts = ["account-one"]'
# The runner key `room` is added under this anchor, exactly as tests/e2e/test_room.py adds it.
ROOM_ANCHOR = 'secrets = ["E2E_TEST_KEY"]\n\n[supervisors'

# The program the configured `room` command runs. It appends the account it was asked about to a log (so a test can
# show which candidates were asked and in what order), then answers from a table it reads, so one program serves every
# account. A table value that is a string is written as it is (a raw, malformed answer); any other value is the JSON
# object to write. An account the table does not name gets no room, with a reason of its own.
PROGRAM = """\
import json, sys
account, log, answers = sys.argv[1], sys.argv[2], sys.argv[3]
with open(log, "a", encoding="utf-8") as handle:
    handle.write(account + "\\n")
with open(answers, encoding="utf-8") as handle:
    table = json.load(handle)
answer = table.get(account, {"room": False, "slots": 0, "reason": "no room for " + account})
sys.stdout.write(answer if isinstance(answer, str) else json.dumps(answer))
"""

def room(slots=1, reason=""):
    """The documented object of an account that can take a turn."""
    return {"room": True, "slots": slots, "reason": reason}


def no_room(reason):
    """The documented object of an account that cannot take a turn."""
    return {"room": False, "slots": 0, "reason": reason}


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class RoomChoiceTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.programs = self.directory / "programs"
        self.programs.mkdir()
        self.written = 0
        self.asked = self.directory / "asked.log"
        self.answers = self.directory / "answers.json"
        self.answers.write_text("{}", encoding="utf-8")

    # The installed package, the configured command and the check about it.

    def program(self, body):
        self.written += 1
        path = self.programs / "program-{}".format(self.written)
        path.write_text(body, encoding="utf-8")
        return str(path)

    def configure(self, room=None, accounts=ACCOUNTS):
        """The fixture with three accounts, and, when `room` is given, one `room` argument vector in [runners.local]."""
        replace = [(ACCOUNTS_ANCHOR, "accounts = {}".format(json.dumps(accounts)))]
        if room is not None:
            replace.append((ROOM_ANCHOR,
                            'secrets = ["E2E_TEST_KEY"]\nroom = {}\n\n[supervisors'.format(json.dumps(room))))
        directory = self.write_config("alpha", replace=replace)
        project = directory / "projects" / "web.toml"
        text = project.read_text(encoding="utf-8")
        self.assertIn(PROJECT_ANCHOR, text, "the replacement anchor is missing from the project fixture")
        project.write_text(text.replace(PROJECT_ANCHOR, "excluded_accounts = []"), encoding="utf-8")

    def with_room(self, answers, accounts=ACCOUNTS):
        """Configure the runner's `room` command so it answers from `answers` (account -> object or raw string), and
        start a fresh log of the accounts it is asked about. `accounts` is the runner's own list, in its own order."""
        self.answers.write_text(json.dumps(answers), encoding="utf-8")
        if self.asked.exists():
            self.asked.unlink()
        self.configure(room=[sys.executable, self.program(PROGRAM), "{account}", str(self.asked), str(self.answers)],
                       accounts=accounts)

    def ask(self, account=None, previous=None, excluded=None, started=None, timeout=20, grace=1):
        """Ask the installed package for one account choice, in a process of its own."""
        command = [str(support.faults_binary()), "__test", "room-choice"]
        request = {"config": "alpha", "runner": "local", "account": account, "previous": previous,
                   "excluded": [] if excluded is None else excluded, "started": started,
                   "timeout": timeout, "grace": grace}
        return subprocess.run(command, input=json.dumps(request), env=self.environment, capture_output=True, text=True, encoding="utf-8",
                              timeout=120)

    def answer(self, **options):
        """The one line the check printed, read as JSON."""
        result = self.ask(**options)
        self.assertEqual(result.returncode, 0, "the check exited {}: {}".format(result.returncode, result.stderr))
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, "the check printed {} lines, not one".format(len(lines)))
        return json.loads(lines[0])

    def asked_accounts(self):
        """Every account the room command was asked about, in the order it was asked."""
        if not self.asked.exists():
            return []
        return [line for line in self.asked.read_text(encoding="utf-8").splitlines() if line]

    # The account --account names, and only that one.

    def test_named_account_with_room(self):
        self.with_room({"acc-b": room(slots=2)})
        self.assertEqual(self.answer(account="acc-b", previous="acc-a"),
                         {"account": "acc-b", "chosen_by": "supervisor", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-b"],
                         "a command was run for an account other than the one --account named")

    def test_named_account_no_room(self):
        # acc-a and acc-c both have room; --account names acc-b, and only acc-b may be asked or used.
        self.with_room({"acc-b": no_room("the account is at its limit"), "acc-a": room(slots=1), "acc-c": room(slots=1)})
        self.assertEqual(self.answer(account="acc-b", previous="acc-a"),
                         {"account": None, "chosen_by": None, "reason": "the account is at its limit",
                          "outcome": "named-no-room"})
        self.assertEqual(self.asked_accounts(), ["acc-b"],
                         "the choice asked another account although --account named one")

    def test_named_account_malformed(self):
        # room true with slots 0 is not the documented object: the room command's own contract already refuses it.
        self.with_room({"acc-b": {"room": True, "slots": 0, "reason": "DO-NOT-SHOW-6f2a"}})
        self.assertEqual(self.answer(account="acc-b"),
                         {"account": None, "chosen_by": None,
                          "reason": "the room command of account acc-b did not answer in the documented form",
                          "outcome": "named-no-room"})
        self.assertEqual(self.asked_accounts(), ["acc-b"])

    # The previous run's account.

    def test_previous_with_room(self):
        for slots in (1, 3):
            with self.subTest(slots=slots):
                self.with_room({"acc-a": room(slots=slots)})
                self.assertEqual(self.answer(previous="acc-a"),
                                 {"account": "acc-a", "chosen_by": "previous", "reason": None,
                                  "outcome": "chosen"})
                self.assertEqual(self.asked_accounts(), ["acc-a"],
                                 "an account of the list was asked although the previous one had room")

    def test_previous_no_room(self):
        self.with_room({"acc-a": no_room("the account is at its limit"), "acc-b": room(slots=1)})
        self.assertEqual(self.answer(previous="acc-a"),
                         {"account": "acc-b", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-a", "acc-b"])

    def test_previous_not_first_in_the_list(self):
        # The previous run's account is acc-c, the last the runner lists: it is asked first, and when it has no room
        # the walk of the runner's list starts again at the runner's own order (acc-a first), not after acc-c.
        self.with_room({"acc-a": room(slots=1), "acc-c": room(slots=1)})
        self.assertEqual(self.answer(previous="acc-c"),
                         {"account": "acc-c", "chosen_by": "previous", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-c"],
                         "the choice asked an account of the list although the previous one had room")
        self.with_room({"acc-a": room(slots=1)})
        self.assertEqual(self.answer(previous="acc-c"),
                         {"account": "acc-a", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-c", "acc-a"],
                         "the previous run's account was not asked first, before the runner's list")

    def test_previous_excluded_never_asked(self):
        # The design's list skips the project's exclusions, and the previous run's account is one of them: it is not
        # asked at all, and the walk of the runner's list chooses an account the project keeps.
        self.with_room({"acc-a": room(slots=1), "acc-b": room(slots=1)})
        self.assertEqual(self.answer(previous="acc-a", excluded=["acc-a"]),
                         {"account": "acc-b", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-b"],
                         "the choice asked the previous run's account although the project excludes it")

    def test_previous_unlisted_never_asked(self):
        # The previous run's account is one the runner no longer lists: it is not one of the runner's accounts, so it
        # is passed over without being asked, and the runner's own list is walked.
        self.with_room({"acc-x": room(slots=1), "acc-b": room(slots=1)})
        self.assertEqual(self.answer(previous="acc-x"),
                         {"account": "acc-b", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        # acc-a is the first account the runner lists and has no room, so it is asked too; acc-x is asked by no one.
        self.assertEqual(self.asked_accounts(), ["acc-a", "acc-b"],
                         "the choice asked a previous account the runner does not list")

    # The runner's list: its order, its exclusions, and the first account with room.

    def test_list_order(self):
        # acc-b has room and acc-c has room too: the first in the runner's order is taken, and acc-c is never asked.
        self.with_room({"acc-a": no_room("the account is at its limit"), "acc-b": room(slots=1), "acc-c": room(slots=1)})
        self.assertEqual(self.answer(previous="acc-a"),
                         {"account": "acc-b", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-a", "acc-b"],
                         "the choice did not stop at the first account with room")

    def test_excluded_account_never_asked(self):
        # acc-b has room, but the project excludes it: it is skipped, never asked, and acc-c is reached.
        self.with_room({"acc-a": no_room("the account is at its limit"), "acc-b": room(slots=1), "acc-c": room(slots=1)})
        self.assertEqual(self.answer(previous="acc-a", excluded=["acc-b"]),
                         {"account": "acc-c", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-a", "acc-c"],
                         "the choice asked an account the project excludes")

    def test_runner_order_not_sorted(self):
        # The runner lists its accounts acc-c, acc-a, acc-b, and every one has room: the walk follows that order (and
        # stops at acc-c), so an account the runner lists first is taken, not the first one alphabetically.
        self.with_room({"acc-a": room(slots=1), "acc-b": room(slots=1), "acc-c": room(slots=1)},
                       accounts=["acc-c", "acc-a", "acc-b"])
        self.assertEqual(self.answer(),
                         {"account": "acc-c", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-c"],
                         "the walk did not follow the order the runner lists its accounts in")
        # With acc-c having no room, the next account the runner lists is acc-a: still its own order, not a sorted one.
        self.with_room({"acc-a": room(slots=1), "acc-b": room(slots=1)}, accounts=["acc-c", "acc-a", "acc-b"])
        self.assertEqual(self.answer(),
                         {"account": "acc-a", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-c", "acc-a"])

    def test_list_without_previous(self):
        self.with_room({"acc-b": room(slots=1)})
        self.assertEqual(self.answer(),
                         {"account": "acc-b", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-a", "acc-b"])

    def test_no_candidate_has_room(self):
        self.with_room({"acc-a": no_room("a is at its limit"), "acc-b": no_room("b is at its limit"),
                        "acc-c": no_room("c is at its limit")})
        answer = self.answer(previous="acc-a")
        self.assertIsNone(answer["account"])
        self.assertIsNone(answer["chosen_by"])
        self.assertEqual(answer["outcome"], "no-room")
        for reason in ("a is at its limit", "b is at its limit", "c is at its limit"):
            self.assertIn(reason, answer["reason"], "the reason does not say why " + reason.split()[0])
        self.assertEqual(self.asked_accounts(), ACCOUNTS)

    # A malformed answer is no room for that candidate, and the next candidate is asked.

    def test_malformed_then_next(self):
        cases = [
            ("a missing key", '{"room": true, "slots": 1}'),
            ("an extra key", '{"room": true, "slots": 1, "reason": "", "extra": "x"}'),
            ("room as a string", '{"room": "true", "slots": 1, "reason": ""}'),
            ("a repeated key", '{"room": false, "slots": 1, "reason": "x", "room": true}'),
            ("slots out of range", '{"room": true, "slots": 65, "reason": ""}'),
            ("an empty output", ""),
        ]
        for label, text in cases:
            with self.subTest(label):
                self.with_room({"acc-a": text, "acc-b": room(slots=1)})
                self.assertEqual(self.answer(previous="acc-a"),
                                 {"account": "acc-b", "chosen_by": "room", "reason": None, "outcome": "chosen"},
                                 "a malformed answer from acc-a was taken as room")
                self.assertEqual(self.asked_accounts(), ["acc-a", "acc-b"])

    # The turns a pass has already given one account.

    def test_pass_account_full(self):
        # acc-a (the previous run's account) answers room with one slot, but this pass has already started one turn on
        # it: it is passed over, and the choice moves on to the next account with room.
        self.with_room({"acc-a": room(slots=1), "acc-b": room(slots=1)})
        self.assertEqual(self.answer(previous="acc-a", started={"acc-a": 1}),
                         {"account": "acc-b", "chosen_by": "room", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.asked_accounts(), ["acc-a", "acc-b"])

    def test_pass_slots_allow(self):
        self.with_room({"acc-a": room(slots=3)})
        self.assertEqual(self.answer(previous="acc-a", started={"acc-a": 2}),
                         {"account": "acc-a", "chosen_by": "previous", "reason": None, "outcome": "chosen"})
        with self.subTest("the pass has taken every slot"):
            self.with_room({"acc-a": room(slots=3), "acc-b": room(slots=1)})
            self.assertEqual(self.answer(previous="acc-a", started={"acc-a": 3})["account"], "acc-b")

    def test_named_account_full(self):
        self.with_room({"acc-b": room(slots=1)})
        answer = self.answer(account="acc-b", started={"acc-b": 1})
        self.assertIsNone(answer["account"], "an account that filled this pass was chosen again")
        self.assertIsNone(answer["chosen_by"])
        self.assertEqual(answer["outcome"], "named-no-room")
        self.assertIn("acc-b", answer["reason"], "the reason does not name the account that is full")
        self.assertEqual(self.asked_accounts(), ["acc-b"])

    # The account --account names when it is one the runner does not list, or one the project excludes.

    def test_named_account_excluded(self):
        # The caller refuses such an account before the choice is asked (`check_account`); passed anyway, the choice
        # does not ask the room command about it at all and says the named account cannot be used.
        self.with_room({"acc-b": room(slots=1), "acc-a": room(slots=1)})
        answer = self.answer(account="acc-b", previous="acc-a", excluded=["acc-b"])
        self.assertEqual(self.asked_accounts(), [],
                         "the choice asked about an account the project excludes")
        self.assertIsNone(answer["account"])
        self.assertIsNone(answer["chosen_by"])
        self.assertEqual(answer["outcome"], "named-unusable")
        self.assertIn("acc-b", answer["reason"], "the reason does not name the account the project excludes")

    def test_named_account_unlisted(self):
        # The name is not one the runner lists: it is not asked about, it is not used, and the reason does not repeat
        # it (an account a configuration does not list may be anything, a credential too).
        self.with_room({"acc-z": room(slots=1), "acc-b": room(slots=1)})
        answer = self.answer(account="acc-z")
        self.assertEqual(self.asked_accounts(), [],
                         "the choice asked about an account the runner does not list")
        self.assertIsNone(answer["account"])
        self.assertIsNone(answer["chosen_by"])
        self.assertEqual(answer["outcome"], "named-unusable")
        self.assertNotIn("acc-z", answer["reason"], "the reason repeats a name the runner does not list")

    # A runner without a room command: no room check, and no command runs.

    def test_no_room_command(self):
        self.configure()
        self.assertEqual(self.answer(previous="acc-b"),
                         {"account": "acc-b", "chosen_by": "previous", "reason": None, "outcome": "chosen"})
        self.assertEqual(self.answer(account="acc-c"),
                         {"account": "acc-c", "chosen_by": "supervisor", "reason": None, "outcome": "chosen"})

    # The outcome of a "no account" answer: a runner that has no room command is not a runner whose command answered
    # no room, and a named account that has no room is not the walk of the list finding none.

    def test_no_room_command_is_not_no_room(self):
        self.configure()
        self.assertEqual(self.answer(),
                         {"account": None, "chosen_by": None, "outcome": "no-check",
                          "reason": "runner has no room command and the lane has no previous run's account"})
        self.with_room({"acc-a": no_room("a is at its limit"), "acc-b": no_room("b is at its limit"),
                        "acc-c": no_room("c is at its limit")})
        answer = self.answer()
        self.assertIsNone(answer["account"])
        self.assertEqual(answer["outcome"], "no-room",
                         "a runner whose room command answered no room reads as one with no room command")

    # The form of chosen_by.account in the store.

    def test_form_accepts_room(self):
        self.configure()
        # `room` is accepted: the value the room command's answer writes is one of the form's own.
        self.assertEqual(self.append(self.started_chosen_by("room")).returncode, 0,
                         "the store refuses the chosen_by.account value the design adds")
        # And the check is not a rubber stamp: a value that is not one of the form's own is still refused.
        self.append(self.started_chosen_by("somewhere-else"), code=2)

    def started_chosen_by(self, chosen):
        paths = self.laneboss_json("config", "path", "alpha")
        payload = support.started_payload(paths, "alpha-lane-1")
        payload["account"] = ACCOUNTS[0]
        payload["chosen_by"] = dict(payload["chosen_by"], account=chosen)
        return self.event("lane.started", lane="alpha-lane-1", payload=payload)

    # The form of the loop's skip reason in the store.

    def test_form_accepts_no_room(self):
        self.configure()
        # The reason the loop owns for "no account has room" is one of the form's own: `loop.skipped` takes the reasons
        # `backoff` and `refused` and, from T5, `no-room` (docs/architecture.md, "The `lane loop` command"), with no
        # `after` (that is given exactly for `backoff`) and the hold as `until`.
        payload = {"loop": "0123456789abcdef0123456789abcdef", "reason": "no-room",
                   "until": "2026-10-12T08:00:00.000000Z", "after": None,
                   "detail": "no account has room (account-two: the account is at its limit)"}
        self.assertEqual(self.append(self.event("loop.skipped", lane="alpha-lane-1", payload=payload)).returncode, 0,
                         "the store refuses the reason the design gives the loop for no room")
        # And the check is not a rubber stamp: a reason that is not one of the form's own, and `after` with `no-room`,
        # are still refused.
        self.append(self.event("loop.skipped", lane="alpha-lane-1", payload=dict(payload, reason="no-such-reason")),
                    code=2)
        self.append(self.event("loop.skipped", lane="alpha-lane-1",
                               payload=dict(payload, after={"run": 2, "reason": "exit"})), code=2)


# `lane turn` and the loop take their account through the choice (the design's "Slots and the choice of the account").
# These tests drive the installed command: a turn-based lane on a stand-in runner that carries a `room` command of the
# test's own, whose answer is the table they write and whose program records every account it was asked about.

TURN_ACCOUNTS = ["acc-one", "acc-two", "acc-three"]
# A lane of the tests below is started without `--project`, so the design's walk sees no exclusions and asks every
# account of the runner's list. The project's own exclusions at the command level are shown on their own in
# `test_project_excludes_account`, which starts the lane on a project that excludes one of its runner's accounts.


def turn_room_table(name, accounts, room_argv):
    """The table of a turn-based stand-in runner with this account list and this `room` argument vector."""
    extra = STDIN + "room = " + json.dumps(room_argv) + "\n"
    return runner(name, "ok", TURN_START, accounts, turn_resume("ok"), extra=extra)


class TurnChoiceTest(TurnTest):
    """The wiring: a turn a person starts, and a turn the loop starts, take their account through the room command.

    The lane's runner is a turn-based stand-in with the `room` key, so the account is chosen by the design's order and
    `lane.started`'s `chosen_by.account` says who chose it (`previous`, `room` or `supervisor`). A turn that cannot get
    an account is refused with exit 2 and the command's own reason, and appends nothing.
    """

    def setUp(self):
        super().setUp()
        self.programs = self.directory / "programs"
        self.programs.mkdir(exist_ok=True)
        self.written = 0
        self.asked = self.directory / "asked.log"
        self.answers = self.directory / "answers.json"
        self.answers.write_text("{}", encoding="utf-8")

    def program(self, body):
        self.written += 1
        path = self.programs / "program-{}".format(self.written)
        path.write_text(body, encoding="utf-8")
        return str(path)

    def asked_accounts(self):
        if not self.asked.exists():
            return []
        return [line for line in self.asked.read_text(encoding="utf-8").splitlines() if line]

    def turn_runner(self, answers, accounts=TURN_ACCOUNTS, name="tok"):
        """Configure the runner `name` with this account list and a room command answering from `answers`, and start a
        fresh log of the accounts it was asked about."""
        self.answers.write_text(json.dumps(answers), encoding="utf-8")
        if self.asked.exists():
            self.asked.unlink()
        room = [sys.executable, self.program(PROGRAM), "{account}", str(self.asked), str(self.answers)]
        self.rewrite(overrides={name: turn_room_table(name, accounts, room)})

    # The fixture project `web` lists none of the runners these tests use among its workers, so a lane of these tests is
    # started without `--project` and the design's walk sees no exclusions. This makes the project real for the one test
    # that means to use its exclusions: `tok` is added to `web`'s workers, and the project excludes the accounts given.
    PROJECT_WORKERS_ANCHOR = 'workers = ["ok"'

    def project_excluding(self, excluded):
        """Rewrite project `web` so its workers include the runner `tok` and it excludes the accounts given."""
        path = self.home / "configs" / "alpha" / "projects" / "web.toml"
        text = path.read_text(encoding="utf-8")
        self.assertIn(self.PROJECT_WORKERS_ANCHOR, text, "the workers anchor is missing from the project fixture")
        text = text.replace(self.PROJECT_WORKERS_ANCHOR, 'workers = ["tok", "ok"', 1)
        text = text.replace('excluded_accounts = ["acc-one"]',
                            "excluded_accounts = {}".format(json.dumps(excluded)))
        path.write_text(text, encoding="utf-8")

    def turned(self, lane):
        """The payload of the lane's latest lane.started (its turn), read from the store."""
        return self.wait_event("lane.started", lane, run=2)["payload"]

    def test_previous_account_with_room(self):
        # The previous run's account (acc-two) has room: the turn starts on it, and the store says who chose it.
        self.turn_runner({"acc-two": room(slots=1)})
        self.turn_start("b-prev", "tok", "--account", "acc-two")
        self.settle("b-prev", 1)
        self.sent("b-prev", "a message for the turn\n")
        self.turn_json("b-prev")
        started = self.turned("b-prev")
        self.assertEqual((started["account"], started["chosen_by"]["account"]), ("acc-two", "previous"))
        self.assertEqual(self.asked_accounts(), ["acc-two"],
                         "an account of the list was asked although the previous one had room")

    def test_room_command_chooses_other(self):
        # The previous run's account has no room and acc-three does: the turn starts on acc-three, records `room`, and
        # the command was asked about the previous account first and then the runner's own order.
        self.turn_runner({"acc-two": no_room("the account is at its limit"), "acc-three": room(slots=1)})
        self.turn_start("b-other", "tok", "--account", "acc-two")
        self.settle("b-other", 1)
        self.sent("b-other", "a message for the turn\n")
        self.turn_json("b-other")
        started = self.turned("b-other")
        self.assertEqual((started["account"], started["chosen_by"]["account"]), ("acc-three", "room"))
        # The design's order, as this lane has no project: the previous run's account first, then the runner's own
        # list in the order it lists it (acc-one, acc-two, acc-three) with acc-two passed over because it was the
        # previous one — so the walk stops at acc-three, the first account with room.
        self.assertEqual(self.asked_accounts(), ["acc-two", "acc-one", "acc-three"],
                         "the design's order was not followed (previous, then the runner's list)")

    def test_named_account_has_room(self):
        self.turn_runner({"acc-three": room(slots=1), "acc-two": room(slots=1)})
        self.turn_start("b-named", "tok", "--account", "acc-three")
        self.settle("b-named", 1)
        self.sent("b-named", "a message for the turn\n")
        self.turn_json("b-named", "--account", "acc-three")
        started = self.turned("b-named")
        self.assertEqual((started["account"], started["chosen_by"]["account"]), ("acc-three", "supervisor"))
        self.assertEqual(self.asked_accounts(), ["acc-three"])

    def test_nothing_has_room_refused(self):
        # Every account the design would ask has no room: the turn is refused with exit 2, the message says why (the
        # command's own reason), and nothing at all is appended, so the mail still waits.
        self.turn_runner({"acc-two": no_room("acc-two is at its limit"),
                          "acc-three": no_room("acc-three is at its limit")})
        lane = "b-nothing"
        self.turn_start(lane, "tok", "--account", "acc-two")
        self.settle(lane, 1)
        self.sent(lane, "a message that waits\n")
        before = self.events()
        result = self.lane("turn", "--lane", lane, code=2)
        self.assertIn("acc-two is at its limit", result.stderr)
        self.assertEqual(self.events(), before, "a refused turn appended something")
        self.assertEqual(self.status(lane)["mail"]["waiting"], [1], "the message stopped waiting")

    def test_named_no_room_no_fall_through(self):
        # --account names acc-two, which has no room; acc-three has room, and the design does not fall through to it.
        self.turn_runner({"acc-two": no_room("acc-two is at its limit"), "acc-three": room(slots=1)})
        lane = "b-named-none"
        self.turn_start(lane, "tok", "--account", "acc-three")
        self.settle(lane, 1)
        self.sent(lane, "a message that waits\n")
        before = self.events()
        result = self.lane("turn", "--lane", lane, "--account", "acc-two", code=2)
        self.assertIn("acc-two is at its limit", result.stderr)
        self.assertEqual(self.asked_accounts(), ["acc-two"],
                         "a turn whose --account had no room asked another account")
        self.assertEqual(self.events(), before, "a refused turn appended something")

    def test_project_excludes_account(self):
        # The lane's project excludes one of its runner's accounts (acc-one): the design's walk must skip it without
        # asking the room command about it and must never choose it. The room program's own log says which accounts it
        # was asked about, in the order it was asked; the previous run's account acc-two has no room, so the walk
        # reaches acc-three, with acc-one passed over in between.
        self.turn_runner({"acc-two": no_room("the account is at its limit"), "acc-three": room(slots=1)})
        self.project_excluding(["acc-one"])
        lane = "web-excl1"
        self.turn_start(lane, "tok", "--project", "web", "--account", "acc-two")
        self.settle(lane, 1)
        self.sent(lane, "a message for the turn\n")
        self.turn_json(lane)
        started = self.turned(lane)
        self.assertEqual((started["account"], started["chosen_by"]["account"]), ("acc-three", "room"),
                         "the turn did not choose the first account of the walk the project keeps")
        self.assertNotIn("acc-one", self.asked_accounts(),
                         "the room command was asked about the account the project excludes")
        self.assertEqual(self.asked_accounts(), ["acc-two", "acc-three"],
                         "the walk asked the project's excluded account, or did not reach acc-three")

    def test_no_room_command_keeps_it(self):
        # A runner without a room command has no room check: the previous run's account is used as before, and the
        # check_account check still runs for it.
        self.rewrite(overrides={"tok": runner("tok", "ok", TURN_START, TURN_ACCOUNTS, turn_resume("ok"), extra=STDIN)})
        lane = "b-nocheck"
        self.turn_start(lane, "tok", "--account", "acc-two")
        self.settle(lane, 1)
        self.sent(lane, "a message for the turn\n")
        self.turn_json(lane)
        started = self.turned(lane)
        self.assertEqual((started["account"], started["chosen_by"]["account"]), ("acc-two", "previous"))

    def test_no_room_command_still_checks(self):
        # The runner does not list acc-nine: `lane turn` refuses the account it would use, as it does today, and
        # nothing is appended (the check is not dropped for the no-room-command path).
        self.rewrite(overrides={"tok": runner("tok", "ok", TURN_START, TURN_ACCOUNTS, turn_resume("ok"), extra=STDIN)})
        lane = "b-unlisted"
        self.turn_start(lane, "tok", "--account", "acc-two")
        self.settle(lane, 1)
        self.sent(lane, "a message that waits\n")
        before = self.events()
        result = self.lane("turn", "--lane", lane, "--account", "acc-nine", code=2)
        # The name is not repeated (an account a configuration does not list may be anything, a credential too).
        self.assertIn("does not list that account", result.stderr)
        self.assertEqual(self.events(), before, "a refused turn appended something")


# The loop's own decisions with a room command (the design's "No room means no turn" and "Slots and the choice of the
# account"): the skip it records when no account has room, and the turns one pass starts on an account. These run the
# real `lane loop`, in the foreground as a child of the test; the assertions read the store, not the loop's output.
LOOP_TURNS = "\n[turns]\npoll_seconds = 1\nbackoff_seconds = 60\n"


class LoopRoomTest(TurnChoiceTest):
    """`lane loop` with a room command: `loop.skipped` says `no-room` when nothing had room, and one pass starts at most
    `slots` turns on an account, asking the command again on the next pass."""

    def room_loop_runner(self, answers, turns=LOOP_TURNS, accounts=TURN_ACCOUNTS, name="tok"):
        """Configure the runner `name` with this account list and a room command answering from `answers`, write the
        `[turns]` table the loop is to use, and start a fresh log of the accounts the command is asked about."""
        self.answers.write_text(json.dumps(answers), encoding="utf-8")
        if self.asked.exists():
            self.asked.unlink()
        room = [sys.executable, self.program(PROGRAM), "{account}", str(self.asked), str(self.answers)]
        self.rewrite(tail=turns, overrides={name: turn_room_table(name, accounts, room)})

    def start_loop(self):
        """`lane loop` in the foreground, as a child of this test. Its output is not read: the assertions read the store
        (`self.events()`), so a full pipe cannot hold the loop up."""
        process = subprocess.Popen([str(self.command), "lane", "loop", "--config", "alpha"],
                                   cwd=str(self.directory), env=self.env("alpha"),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_loop, process)
        return process

    def stop_loop(self, process):
        """`lane loop --stop`, once the test is done with the loop; a loop that does not end is killed by its process
        id."""
        if process.poll() is None:
            self.run_laneboss("lane", "loop", "--stop", "--config", "alpha", code=None,
                              environment=self.env("alpha"))
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    def loop_events(self, kind=None, lane=None):
        """The loop's events in the store, in order: the lane's when `lane` is given."""
        return [item for item in self.events() if item["kind"].startswith("loop.")
                and (kind is None or item["kind"] == kind) and (lane is None or item["lane"] == lane)]

    def wait_loop(self, kind, lane=None, count=1, timeout=30):
        """The count-th `loop.*` event of this kind (and lane) once it is stored."""
        deadline = time.monotonic() + timeout
        while True:
            found = self.loop_events(kind, lane)
            if len(found) >= count:
                return found[count - 1]
            if time.monotonic() > deadline:
                self.fail("no {} #{} for lane {} within {} s; loop events: {}".format(
                    kind, count, lane, timeout, [(item["kind"], item["lane"]) for item in self.loop_events()]))
            time.sleep(0.3)

    def test_the_loop_records_no_room(self):
        # Every account the design would ask has no room: no turn starts, the mail waits, and the skip says why with the
        # reason the design gives the loop for it, `no-room`, and the command's own reason as `detail` (not the sentence
        # that the refusal of `lane turn` carries it in).
        self.room_loop_runner({"acc-two": no_room("the account is at its limit")})
        lane = "b-noroom"
        self.turn_start(lane, "tok", "--account", "acc-two")
        self.settle(lane, 1)
        self.start_loop()
        self.sent(lane, "a message that waits\n")
        skip = self.wait_loop("loop.skipped", lane)
        self.assertEqual(skip["payload"]["reason"], "no-room",
                         "the loop did not record the reason the design gives a turn that nothing had room for")
        self.assertIn("the account is at its limit", skip["payload"]["detail"],
                      "the skip does not carry the room command's own reason")
        self.assertNotIn("no turn starts", skip["payload"]["detail"],
                         "the skip carries the sentence of the refusal, not the command's own reason")
        self.assertEqual(skip["payload"]["after"], None)
        self.assertIsNotNone(skip["payload"]["until"], "the skip carries no hold")
        self.assertEqual(self.loop_events("loop.turn", lane), [], "a turn started although no account had room")
        self.assertEqual(self.status(lane)["mail"]["waiting"], [1], "the message stopped waiting")

    def test_one_turn_a_pass_for_the_account(self):
        # One account with `slots` 1 and two lanes that both want it: the first pass starts a turn for one lane only —
        # the design's "at most `slots` turns on an account" — and the lane this pass did not start is held as
        # `no-room`, its `detail` naming the count this pass has made on the account. The design holds a `no-room` lane
        # the way it holds a refused one ("for `refused` and `no-room`, `backoff_seconds` after the skip"), so the
        # passes that find the hold neither start the second turn nor ask the command again nor record the wait again.
        # `backoff_seconds` (60) outlasts the wait below, and `poll_seconds` (1) gives many passes inside it, so a hold
        # that is not applied shows up as a second turn, a second skip, or a growing log of the accounts asked about.
        self.room_loop_runner({"acc-two": room(slots=1)})
        for lane in ("b-one", "b-two"):
            self.turn_start(lane, "tok", "--account", "acc-two")
            self.settle(lane, 1)
            self.sent(lane, "a message for the turn\n")
        self.start_loop()
        first = self.wait_loop("loop.turn")
        held_lane = "b-two" if first["lane"] == "b-one" else "b-one"
        skip = self.wait_loop("loop.skipped", held_lane)
        self.assertEqual(skip["payload"]["reason"], "no-room",
                         "the lane the pass did not start was not recorded as the design records it")
        self.assertIn("account acc-two has taken its 1 turn(s) for this pass", skip["payload"]["detail"],
                      "the skip's detail does not name the count this pass has made on the account")
        asked = len(self.asked_accounts())
        time.sleep(8)
        self.assertEqual(len(self.loop_events("loop.turn")), 1,
                         "a second turn started for the held lane while its hold stood")
        self.assertEqual(len(self.loop_events("loop.skipped", held_lane)), 1,
                         "the loop recorded the same wait again on a pass that found the hold")
        self.assertEqual(len(self.asked_accounts()), asked,
                         "the loop asked the room command again while the hold stood")

"""T5, the room command: the runner key `room`, running the configured command, and the check of its answer.

The launcher reaches the room command through the choice of the account (tested in tests/e2e/test_room_choice.py); this
module asks every answer of the *installed* package in a process of its own, the way tests/e2e/test_loop.py asks the
loop's own argv: this module imports nothing of the package, and the command it configures is a program of the test's
own, run for real by the launcher. The configuration checks are the ordinary `config validate` ones.
"""

import json
from pathlib import Path
import subprocess
import sys
import time

from . import support

ACCOUNT = "account-one"
OTHER_ACCOUNT = "account-two"
NOT_DOCUMENTED = "the room command of account {} did not answer in the documented form".format(ACCOUNT)
WITHHELD = "(withheld)"
# A marker the command writes but the check must never show: nothing of a refused answer is printed beyond the
# fixed sentence.
MARKER = "DO-NOT-SHOW-6f2a"
# The fixture's runner keys, where `room` is added.
ROOM_ANCHOR = 'secrets = ["E2E_TEST_KEY"]\n\n[supervisors'
# What is asked of the installed package. It reads one runner of one configuration and asks its room command; its
# standard output is exactly one line holding the checked answer, never anything the room command wrote.
DRIVER = """\
import json, sys
sys.path.insert(0, sys.argv[1])
from laneboss import accounts, config
configuration = config.load("alpha")
runner = configuration.data["runners"]["local"]
answer = accounts.room_of(runner, sys.argv[2], float(sys.argv[3]), float(sys.argv[4]))
print(json.dumps(None if answer is None else
                 {"room": answer.room, "slots": answer.slots, "reason": answer.reason}))
"""

# A command that does not end within the timeout and leaves two children behind: one in its own process group, one in
# a session of its own (so that only the walk of the command's tree finds it). It writes the three ids before it
# hangs, so the test can show that all three are gone afterwards.
TIMEOUT_PROGRAM = """\
import os, subprocess, sys, time

first = subprocess.Popen([sys.executable, sys.argv[3]])
second = subprocess.Popen([sys.executable, sys.argv[4]])
time.sleep(1.0)
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write("{} {} {}\\n".format(os.getpid(), first.pid, second.pid))
time.sleep(300)
"""

# The reviewer's case for the stop's first look. The command starts `middle` in its own process group (standard output
# /dev/null, so `middle` never holds the pipe the answer comes through, and no session of its own, so it stays in the
# command's group). `middle` starts `orphan` in a session of its own and writes both ids; only the command's group
# holds `middle`, and only a parent link from `middle` holds `orphan`. The command waits for those ids before it
# answers, so both are running before the stop's first look.
ORPHAN_PROGRAM = """\
import os, subprocess, sys, time

middle = subprocess.Popen([sys.executable, sys.argv[3], sys.argv[4], sys.argv[2]], stdout=subprocess.DEVNULL)
deadline = time.monotonic() + 20
while not os.path.exists(sys.argv[2]) and time.monotonic() < deadline:
    time.sleep(0.05)
sys.stdout.write('{"room": true, "slots": 1, "reason": ""}')
"""

MIDDLE_PROGRAM = """\
import os, subprocess, sys, time

orphan = subprocess.Popen([sys.executable, sys.argv[1]], stdout=subprocess.DEVNULL, start_new_session=True)
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write("{} {}".format(os.getpid(), orphan.pid))
time.sleep(300)
"""


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def source(text):
    """A program that writes exactly `text` to its standard output. `text` is a str or bytes."""
    if isinstance(text, bytes):
        return "import sys\nsys.stdout.buffer.write({!r})\n".format(text)
    return "import sys\nsys.stdout.write({!r})\n".format(text)


def sized(limit):
    """The documented object `{"room": true, "slots": 1, "reason": ""}` padded with spaces to exactly `limit` bytes:
    JSON allows the whitespace between and after the object, so the answer is the documented object and only its
    length is at the bound the check makes."""
    text = json.dumps({"room": True, "slots": 1, "reason": ""})
    return text + " " * (limit - len(text))


class RoomTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.programs = self.directory / "programs"
        self.programs.mkdir()
        self.written = 0

    def library(self):
        """The installed package's directory, asked of the installed command, so this module imports nothing."""
        library = Path(self.command).resolve().parent.parent / "lib"
        self.assertTrue((library / "laneboss" / "accounts.py").is_file(),
                        "there is no installed package at " + str(library))
        return library

    def program(self, body):
        self.written += 1
        path = self.programs / "program-{}".format(self.written)
        path.write_text(body, encoding="utf-8")
        return str(path)

    def configure(self, room, top="", tail=""):
        """The fixture with one `room` argument vector in its [runners.local] entry."""
        self.write_config("alpha", top=top, tail=tail, replace=[
            (ROOM_ANCHOR, 'secrets = ["E2E_TEST_KEY"]\nroom = {}\n\n[supervisors'.format(json.dumps(room)))])

    def ask(self, account=ACCOUNT, timeout=20, grace=1):
        """Ask the installed package for one account's room answer, in a process of its own."""
        command = [sys.executable, "-I", "-B", "-c", DRIVER, str(self.library()), account, str(timeout), str(grace)]
        return subprocess.run(command, env=self.environment, capture_output=True, text=True, encoding="utf-8",
                              timeout=120)

    def answer(self, **options):
        """The one line the check printed, read as JSON."""
        result = self.ask(**options)
        self.assertEqual(result.returncode, 0, "the check exited {}: {}".format(result.returncode, result.stderr))
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, "the check printed {} lines, not one".format(len(lines)))
        return json.loads(lines[0])

    def assert_no_room(self, program, **options):
        """The command answers, and the check must call the account no room, with the fixed sentence, printing
        nothing of the command's own output."""
        self.configure([sys.executable, program, "{account}"])
        result = self.ask(**options)
        self.assertEqual(result.returncode, 0, "the check exited {}: {}".format(result.returncode, result.stderr))
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, "the check printed {} lines, not one".format(len(lines)))
        self.assertEqual(json.loads(lines[0]), {"room": False, "slots": 0, "reason": NOT_DOCUMENTED})
        self.assertNotIn(MARKER, result.stdout + result.stderr, "the check printed the command's own output")

    def gone(self, pid):
        """True once the process is not alive: no such process, or one that has ended and is not collected yet."""
        deadline = time.monotonic() + 15
        while True:
            result = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True,
                                    encoding="utf-8", timeout=30)
            status = result.stdout.strip()
            if not status or status.startswith("Z"):
                return True
            if time.monotonic() > deadline:
                return False
            time.sleep(0.2)

    # The documented object is the answer.

    def test_the_documented_object(self):
        cases = [
            ("room true with three slots", '{"room": true, "slots": 3, "reason": ""}',
             {"room": True, "slots": 3, "reason": ""}),
            ("room true with one slot and an empty reason", '{"room": true, "slots": 1, "reason": ""}',
             {"room": True, "slots": 1, "reason": ""}),
            ("room false with a reason", '{"room": false, "slots": 0, "reason": "the account is at its limit"}',
             {"room": False, "slots": 0, "reason": "the account is at its limit"}),
            ("the highest slot count", '{"room": true, "slots": 64, "reason": "wide open"}',
             {"room": True, "slots": 64, "reason": "wide open"}),
            ("a reason of exactly 200 characters", json.dumps({"room": False, "slots": 0, "reason": "r" * 200}),
             {"room": False, "slots": 0, "reason": "r" * 200}),
            ("an output of exactly 4 KiB", sized(4096), {"room": True, "slots": 1, "reason": ""}),
        ]
        for label, text, expected in cases:
            with self.subTest(label):
                self.configure([sys.executable, self.program(source(text)), "{account}"])
                self.assertEqual(self.answer(), expected)

    def test_no_room_key_is_no_check(self):
        self.write_config("alpha")
        self.assertIsNone(self.answer(), "a runner with no room command was given a room answer")

    def test_the_account_placeholder(self):
        program = self.program(
            "import json, sys\nprint(json.dumps({'room': True, 'slots': 1, 'reason': 'asked ' + sys.argv[1]}))\n")
        self.configure([sys.executable, program, "{account}"])
        self.assertEqual(self.answer(account=OTHER_ACCOUNT),
                         {"room": True, "slots": 1, "reason": "asked " + OTHER_ACCOUNT})

    def test_a_credential_is_withheld(self):
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
        text = json.dumps({"room": False, "slots": 0, "reason": "the token " + token + " was refused"})
        self.configure([sys.executable, self.program(source(text)), "{account}"])
        result = self.ask()
        self.assertEqual(result.returncode, 0, "the check exited {}: {}".format(result.returncode, result.stderr))
        self.assertEqual(json.loads(result.stdout), {"room": False, "slots": 0, "reason": WITHHELD})
        self.assertNotIn(token, result.stdout + result.stderr, "the check printed the credential")

    # Every answer that is not that object is no room.

    def test_bad_answers_are_no_room(self):
        cases = [
            ("a missing key", '{"room": true, "slots": 1}'),
            ("an extra key", '{"room": true, "slots": 1, "reason": "", "extra": "DO-NOT-SHOW-6f2a"}'),
            ("a repeated key whose last value would be a valid answer",
             '{"room": false, "slots": 1, "reason": "DO-NOT-SHOW-6f2a", "room": true}'),
            ("room as a string", '{"room": "true", "slots": 1, "reason": "DO-NOT-SHOW-6f2a"}'),
            ("room as a number", '{"room": 1, "slots": 1, "reason": "DO-NOT-SHOW-6f2a"}'),
            ("slots as a float", '{"room": true, "slots": 1.5, "reason": "DO-NOT-SHOW-6f2a"}'),
            ("slots as a string", '{"room": true, "slots": "1", "reason": "DO-NOT-SHOW-6f2a"}'),
            ("slots beyond the range", '{"room": true, "slots": 65, "reason": "DO-NOT-SHOW-6f2a"}'),
            ("a negative slot count", '{"room": true, "slots": -1, "reason": "DO-NOT-SHOW-6f2a"}'),
            ("room with no slot", '{"room": true, "slots": 0, "reason": "DO-NOT-SHOW-6f2a"}'),
            ("no room with slots", '{"room": false, "slots": 3, "reason": "DO-NOT-SHOW-6f2a"}'),
            ("a reason that is not a string", '{"room": false, "slots": 0, "reason": 3}'),
            ("a reason over a line", '{"room": false, "slots": 0, "reason": "one\\ntwo DO-NOT-SHOW-6f2a"}'),
            ("a reason of 201 characters",
             json.dumps({"room": False, "slots": 0, "reason": "r" * 185 + MARKER})),
            ("an empty reason with no room", '{"room": false, "slots": 0, "reason": ""}'),
            ("a reason with an unpaired surrogate", '{"room": false, "slots": 0, "reason": "\\ud800"}'),
            ("two objects", '{"room": true, "slots": 1, "reason": "DO-NOT-SHOW-6f2a"}'
                            '{"room": true, "slots": 1, "reason": "DO-NOT-SHOW-6f2a"}'),
            ("an empty output", ""),
        ]
        for label, text in cases:
            with self.subTest(label):
                self.assert_no_room(self.program(source(text)))

    def test_a_non_zero_exit_is_no_room(self):
        body = source('{"room": true, "slots": 1, "reason": "DO-NOT-SHOW-6f2a"}\n') + "sys.exit(3)\n"
        self.assert_no_room(self.program(body))

    def test_output_over_4_kib_is_no_room(self):
        """The object is the documented one; only its length makes it no answer. The bound is exact: the same object
        at exactly 4,096 bytes is accepted (`test_the_documented_object`), one byte more is not."""
        self.assert_no_room(self.program(source(sized(4097))))

    def test_output_that_is_not_utf8_is_no_room(self):
        """The bad byte is inside the reason string, so a decoder that replaces it would still read one whole object:
        only the strict UTF-8 decode refuses this output."""
        self.assert_no_room(self.program(source(b'{"room": true, "slots": 1, "reason": "\xff"}')))

    def test_a_program_that_cannot_start(self):
        self.configure(["/nonexistent/room-command-6f2a", "{account}"])
        result = self.ask()
        self.assertEqual(result.returncode, 0, "the check exited {}: {}".format(result.returncode, result.stderr))
        self.assertEqual(json.loads(result.stdout), {"room": False, "slots": 0, "reason": NOT_DOCUMENTED})

    def test_a_timeout_stops_the_tree(self):
        ids = self.directory / "processes.txt"
        child = self.program("import time\ntime.sleep(300)\n")
        session_child = self.program("import os, time\nos.setsid()\ntime.sleep(300)\n")
        self.configure([sys.executable, self.program(TIMEOUT_PROGRAM), "{account}", str(ids), child, session_child])
        result = self.ask(timeout=3, grace=1)
        self.assertEqual(result.returncode, 0, "the check exited {}: {}".format(result.returncode, result.stderr))
        self.assertEqual(json.loads(result.stdout), {"room": False, "slots": 0, "reason": NOT_DOCUMENTED},
                         "a command that did not end in time was an answer")
        self.assertTrue(ids.is_file(), "the command did not write the ids of its processes")
        root, group_child, session_child = (int(item) for item in ids.read_text(encoding="utf-8").split())
        for label, pid in (("the command", root), ("its group child", group_child),
                           ("its session child", session_child)):
            with self.subTest(label):
                self.assertTrue(self.gone(pid), "{} (process {}) is still alive".format(label, pid))

    def test_a_normal_end_stops_leftovers(self):
        """A command that answers the documented object and ends in time can still leave a member of its own process
        group behind (here a child whose standard output is /dev/null, so it never holds the pipe the answer came
        through). The stop runs after every call, not only at the timeout, so nothing of the command is left and the
        answer is the documented one."""
        ids = self.directory / "leftover.txt"
        child = self.program("import time\ntime.sleep(300)\n")
        body = ("import subprocess, sys\n"
                "child = subprocess.Popen([sys.executable, sys.argv[2]], stdout=subprocess.DEVNULL)\n"
                "with open(sys.argv[3], 'w', encoding='utf-8') as handle:\n"
                "    handle.write(str(child.pid))\n"
                "sys.stdout.write('{\"room\": true, \"slots\": 1, \"reason\": \"\"}')\n")
        self.configure([sys.executable, self.program(body), "{account}", child, str(ids)])
        self.assertEqual(self.answer(), {"room": True, "slots": 1, "reason": ""})
        self.assertTrue(ids.is_file(), "the command did not write the child's id")
        self.assertTrue(self.gone(int(ids.read_text(encoding="utf-8"))),
                        "a process the command left in its own group is still alive")

    def test_a_child_that_left_the_group(self):
        """The child of a process the stop found only through the command's group. The command starts `middle` in its
        own group and `middle` starts `orphan` in a session of its own, so `orphan` is held by no group and by no
        session the stop knows: only a walk that takes the children of every process it finds, inside the first look
        and before any signal, reaches it. A stop that finds `middle` only, signals it and looks again has already
        lost `orphan` (its parent is gone and its group is its own), so it reports nothing living while `orphan`
        runs — and the answer is room. `middle` and `orphan` both sleep, and the command waits for their ids before
        it answers, so both are running when the first look is taken."""
        ids = self.directory / "orphan.txt"
        orphan = self.program("import time\ntime.sleep(300)\n")
        middle = self.program(MIDDLE_PROGRAM)
        self.configure([sys.executable, self.program(ORPHAN_PROGRAM), "{account}", str(ids), middle, orphan])
        self.assertEqual(self.answer(), {"room": True, "slots": 1, "reason": ""})
        self.assertTrue(ids.is_file(), "the command did not write the ids of its processes")
        root, grandchild = (int(item) for item in ids.read_text(encoding="utf-8").split())
        for label, pid in (("the child in the command's group", root),
                           ("the child that left the group", grandchild)):
            with self.subTest(label):
                self.assertTrue(self.gone(pid), "{} (process {}) is still alive".format(label, pid))

    # The configuration.

    def test_room_is_validated(self):
        cases = [
            ("a placeholder other than the account", ["room-command", "{brief}"], "runners.local.room[1]",
             "unknown placeholder"),
            ("the session placeholder", ["room-command", "{session}"], "runners.local.room[1]", "unknown placeholder"),
            ("a placeholder in the program", ["{account}", "x"], "runners.local.room[0]", "absolute path"),
            ("a program that is not a command name or an absolute path", ["tools/room", "{account}"],
             "runners.local.room[0]", "absolute path"),
            ("not an array of arguments", "room-command", "runners.local.room", "must be an array"),
            ("an empty array", [], "runners.local.room", "must not be empty"),
        ]
        for label, room, key_path, said in cases:
            with self.subTest(label):
                self.configure(room)
                message = self.run_laneboss("config", "validate", "alpha", code=2).stderr
                self.assertIn("config.toml: " + key_path, message)
                self.assertIn(said, message, "the refusal does not say what is wrong")

    def test_another_organisations_tools(self):
        own = str(self.home / "orgs" / "alpha-org" / "tools" / "room-command")
        other = str(self.home / "orgs" / "other-org" / "tools" / "room-command")
        self.configure([own, "{account}"], top='organisation = "alpha-org"')
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        self.configure([other, "{account}"], top='organisation = "alpha-org"')
        result = self.run_laneboss("config", "validate", "alpha", code=2)
        self.assertIn("config.toml: runners.local.room[0]", result.stderr)
        self.assertIn("another organisation", result.stderr)
        self.assertNotIn(other, result.stderr, "the refused path is repeated")

    def test_room_timeout_seconds(self):
        key_path = "config.toml: lanes.room_timeout_seconds"
        for value in (1, 60, 20):
            with self.subTest("accepted", value=value):
                self.write_config("alpha", tail="\n[lanes]\nroom_timeout_seconds = {}\n".format(value))
                self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        for value, said in (("0", "must be from 1 to 60"), ("61", "must be from 1 to 60"),
                            ("-1", "must be from 1 to 60"), ("1.5", "must be an integer"),
                            ('"20"', "must be an integer")):
            with self.subTest("refused", value=value):
                self.write_config("alpha", tail="\n[lanes]\nroom_timeout_seconds = {}\n".format(value))
                message = self.run_laneboss("config", "validate", "alpha", code=2).stderr
                self.assertIn(key_path, message)
                self.assertIn(said, message, "the refusal does not say what is wrong")

    def test_the_timeout_key_is_optional(self):
        """`[lanes] room_timeout_seconds` is optional: a configuration without it is valid. The 20-second default is
        applied by `lanecmd.continue_lane`, which reads the key and passes the value to `accounts.choose_account` and
        so to `room_of`; no test under tests/e2e proves that default by behaviour, and no constant is read out of the
        module here."""
        self.write_config("alpha")
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})

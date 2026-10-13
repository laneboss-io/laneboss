"""A lane has an exact session identity, and a runner may take its prompt on standard input.

A. a runner whose templates use {session} gets the lane's own identifier at the start and at every resume; B.
`config validate` refuses {session} in one of `command` and `resume` only, and where it is not allowed; C. a lane whose
runner does not use {session} has the `lane.started` payload that main wrote (its keys are written out below), so a
store written by main and one written now cannot differ in form, and a lane without an identifier is refused a resume
by a runner that now uses {session} and is not covered by a {session} records path (reason no-session); D. `prompt =
"stdin"` hands the rendered brief (at a start) or the rendered message (at a resume) over on standard input, and the
default stays as it was; E. a records path with {session} names exactly the files of that session.

The runners are tests/e2e/standin.py, which records its arguments and its standard input.
"""

import base64
import os
from pathlib import Path
import re
import time
import uuid

from . import lanesupport, refusalsupport, support
from .lanesupport import runner


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


UUID_FORM = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
START = ["--lane", "{lane}", "--brief", "{brief}", "--session-id", "{session}"]
RESUME = ["ok", "resumed", "--lane", "{lane}", "--brief", "{brief}", "--message", "{message}", "--resume", "{session}"]
SHIFT_START = ["--lane", "{lane}", "--brief", "{brief}"]
SHIFT_RESUME = ["ok", "resumed", "--lane", "{lane}"]
BY_SESSION = 'records = [{format = "claude-code", paths = ["~/.claude/projects/*/{session}.jsonl"]}]\n'
BY_GLOB = 'records = [{format = "claude-code", paths = ["~/.claude/projects/*/*.jsonl"]}]\n'
SESSION_PATH = "~/.claude/projects/*/{session}.jsonl"
BRIEF = "# Brief\n\nSay hello from the stand-in. Non-ASCII stays: é中\n"
MESSAGE = "# Follow-up\n\nThe account changed; carry on from where you stopped.\n"
FILLER = "A line of plain words that only gives the brief its size.\n"
CONTINUE = support.ROOT / "internal" / "protocol" / "continue.md"
EMPTY = support.digest(b"")
# The keys of the `lane.started` payload as main's launcher wrote it before this change (lanes.py of 919af68), written
# out here and not computed: `session` is the tmux session, an object of socket and name.
MAIN_STARTED_KEYS = ["account", "base", "branch", "brief", "budget_minutes", "chosen_by", "claims", "difficulty",
                     "effort", "how", "launch", "log", "model", "project", "quiet_seconds", "repository", "run",
                     "runner", "session", "touches", "worktree"]
# A runner that takes its prompt on standard input and whose program is an absolute path that does not exist: `lane
# start` does not look the program up, and the supervising process cannot create the runner.
GONE = ('\n[runners.gone]\ncommand = ["/nonexistent/laneboss-e2e-runner", "--lane", "{lane}"]\nprompt = "stdin"\n')
# The keys of the `lane.ended` payload as main wrote it, which a runner that takes no prompt on standard input keeps.
MAIN_ENDED_KEYS = ["classification", "duration_seconds", "exit_code", "pattern", "reason", "run", "signal",
                   "survivors"]


def session_config(name, shift=None):
    """The lane tests' configuration with guards and the runners of these tests. The runner `shift` is the one a test
    changes between a start and a resume (it starts without {session})."""
    shift = shift or runner("shift", "ok", SHIFT_START, None, SHIFT_RESUME)
    return (lanesupport.lane_config(name) + "\n" + refusalsupport.GUARDS + "\n"
            + runner("ident", "ok", START, None, RESUME)
            + runner("watched", "waiter", START, None, RESUME, extra=BY_SESSION)
            + runner("broad", "waiter", SHIFT_START, None, SHIFT_RESUME, extra=BY_GLOB)
            + runner("bare", "ok", SHIFT_START, None, SHIFT_RESUME, extra=BY_SESSION)
            + runner("fed", "ok", ["--lane", "{lane}"], None, SHIFT_RESUME, extra='prompt = "stdin"\n')
            + runner("deaf", "deaf", ["--lane", "{lane}"], None, SHIFT_RESUME, extra='prompt = "stdin"\n')
            + runner("shut", "shut", ["--lane", "{lane}"], None, SHIFT_RESUME, extra='prompt = "stdin"\n')
            + GONE
            + runner("argued", "ok", SHIFT_START, None, SHIFT_RESUME, extra='prompt = "argument"\n')
            + shift)


class SessionTest(lanesupport.LaneTest):
    """A configuration `alpha` with the lane tests' runners and the runners of these tests."""

    def add_config(self, name):
        directory = super().add_config(name)
        (directory / "config.toml").write_text(session_config(name), encoding="utf-8")
        return directory

    def rewrite(self, config="alpha", shift=None):
        (self.home / "configs" / config / "config.toml").write_text(session_config(config, shift), encoding="utf-8")

    def run_lane(self, lane, runner_name, *arguments, text=None):
        return self.start(lane, "--runner", runner_name, "--model", runner_name + "-model-1", "--worktree",
                          self.scratch(lane), *arguments, text=text)

    def ended_run(self, lane, run=1):
        """The stand-in's record of a run that has ended."""
        self.wait_event("lane.ended", lane, run=run)
        return self.record(lane, run=run, ended=True)

    def standard_input(self, record):
        return base64.b64decode(record["stdin"]["base64"])


class IdentityTest(SessionTest):
    def test_one_identity_per_lane(self):
        first = self.run_lane("a-one", "ident")
        identifier = first["session_id"]
        self.assertRegex(identifier, UUID_FORM)
        self.assertEqual((str(uuid.UUID(identifier)), uuid.UUID(identifier).version), (identifier, 4))
        record = self.ended_run("a-one")
        self.assertEqual(record["argv"], ["ok", "--lane", "a-one", "--brief", first["brief"]["path"], "--session-id",
                                          identifier])
        self.assertEqual(self.wait_event("lane.started", "a-one", run=1)["payload"]["session_id"], identifier)
        self.assertEqual(self.status("a-one")["session_id"], identifier)
        # A resume hands the same identifier to the resume template, and the lane still has it.
        self.assertEqual(self.lane_json("resume", "--lane", "a-one")["session_id"], identifier)
        record = self.ended_run("a-one", 2)
        message = self.wait_event("lane.resumed", "a-one", run=2)["payload"]["message"]["path"]
        self.assertEqual(record["argv"], ["ok", "resumed", "--lane", "a-one", "--brief", first["brief"]["path"],
                                          "--message", message, "--resume", identifier])
        self.assertEqual(self.wait_event("lane.started", "a-one", run=2)["payload"]["session_id"], identifier)
        self.assertEqual(self.status("a-one")["session_id"], identifier)
        # Another lane has an identifier of its own, and the first lane keeps its.
        second = self.run_lane("a-two", "ident")
        self.assertRegex(second["session_id"], UUID_FORM)
        self.assertNotEqual(second["session_id"], identifier)
        self.assertEqual(self.ended_run("a-two")["argv"][-2:], ["--session-id", second["session_id"]])
        self.assertEqual(self.status("a-one")["session_id"], identifier)
        shown = {row["lane"]: row["session_id"] for row in self.lane_json("status")}
        self.assertEqual((shown["a-one"], shown["a-two"]), (identifier, second["session_id"]))
        # The same name started again with --reuse has a new identifier, and a resume of it hands that one over.
        self.lane_json("mark", "--lane", "a-one", "--state", "abandoned")
        self.lane_json("clean", "--lane", "a-one")
        third = self.start("a-one", "--runner", "ident", "--model", "ident-model-1", "--worktree",
                           self.scratch("a-one-again"), "--reuse")
        self.assertEqual((third["run"], third["how"]), (3, "reuse"))
        self.assertRegex(third["session_id"], UUID_FORM)
        self.assertNotIn(third["session_id"], (identifier, second["session_id"]))
        self.assertEqual(self.ended_run("a-one", 3)["argv"][-2:], ["--session-id", third["session_id"]])
        self.assertEqual(self.status("a-one")["session_id"], third["session_id"])
        self.lane_json("resume", "--lane", "a-one")
        self.assertEqual(self.ended_run("a-one", 4)["argv"][-2:], ["--resume", third["session_id"]])
        self.assert_sound()

    def test_no_placeholder_no_identity(self):
        started = self.run_lane("a-bare", "shift")
        self.assertNotIn("session_id", started)
        self.assertNotIn("session_id", self.wait_event("lane.started", "a-bare")["payload"])
        self.assertIsNone(self.status("a-bare")["session_id"])
        self.ended_run("a-bare")
        self.lane_json("resume", "--lane", "a-bare")
        self.ended_run("a-bare", 2)
        self.assertNotIn("session_id", self.wait_event("lane.started", "a-bare", run=2)["payload"])
        self.assertIsNone(self.status("a-bare")["session_id"])
        self.assert_sound()

    def test_resume_refused_without_identity(self):
        self.run_lane("a-late", "shift")
        self.ended_run("a-late")
        events = self.events()
        self.rewrite(shift=runner("shift", "ok", START, None, RESUME))
        result = self.lane("resume", "--lane", "a-late", code=2)
        self.assertIn("no recorded session identity", result.stderr)
        self.assertIn("does not use {session}", result.stderr)
        # Nothing was started or recorded.
        self.assertEqual(self.events(), events)
        status = self.status("a-late")
        self.assertEqual((status["run"], status["running"], status["resumes"]), (1, False, 0))
        self.assertFalse((self.records["alpha"] / "a-late.2.json").exists())
        # The runner as it was resumes the lane.
        self.rewrite()
        self.lane_json("resume", "--lane", "a-late")
        self.ended_run("a-late", 2)
        self.assert_sound()

    def test_resume_refused_if_identity_dropped(self):
        """The other half: a lane that has an identifier is not resumed by a runner whose resume template no longer
        names it (that would continue the newest session of the directory)."""
        self.rewrite(shift=runner("shift", "ok", START, None, RESUME))
        identifier = self.run_lane("a-kept", "shift")["session_id"]
        self.ended_run("a-kept")
        events = self.events()
        self.rewrite()
        result = self.lane("resume", "--lane", "a-kept", code=2)
        self.assertIn("recorded session identity", result.stderr)
        self.assertIn("runners.shift.resume", result.stderr)
        self.assertIn("does not use {session}", result.stderr)
        # Nothing was started or recorded.
        self.assertEqual(self.events(), events)
        status = self.status("a-kept")
        self.assertEqual((status["run"], status["running"], status["resumes"], status["session_id"]),
                         (1, False, 0, identifier))
        self.assertFalse((self.records["alpha"] / "a-kept.2.json").exists())
        # The runner that names it resumes the lane, by the same identifier.
        self.rewrite(shift=runner("shift", "ok", START, None, RESUME))
        self.lane_json("resume", "--lane", "a-kept")
        self.assertEqual(self.ended_run("a-kept", 2)["argv"][-2:], ["--resume", identifier])
        self.assert_sound()


class EventFormTest(support.LauncherTest):
    """The key is optional when an event is read, and an event that has it must hold a valid identifier."""

    def test_key_is_optional_and_checked(self):
        self.write_config("alpha")
        paths = self.laneboss_json("config", "path", "alpha")
        self.append(self.event("lane.started", lane="h-none", payload=support.started_payload(paths, "h-none")))
        good = str(uuid.uuid4())
        self.append(self.event("lane.started", lane="h-good", payload=dict(support.started_payload(paths, "h-good"),
                                                                              session_id=good)))
        refused = [good.upper(), good.replace("-", ""), good + "0", good[:-1], "{" + good + "}", "urn:uuid:" + good,
                   good.replace("-", "_"), "", None, 7, [good], {"id": good}]
        count = len(self.events())
        for index, value in enumerate(refused):
            lane = "h-bad-{}".format(index)
            payload = dict(support.started_payload(paths, lane), session_id=value)
            with self.subTest(value=repr(value)[:30]):
                result = self.append(self.event("lane.started", lane=lane, payload=payload), code=2)
                self.assertIn("session_id", result.stderr)
        self.assertEqual(len(self.events()), count)
        self.assertIs(self.laneboss_json("state", "verify", "--config", "alpha")["ok"], True)
        stored = {item["lane"]: item["payload"] for item in self.events() if item["kind"] == "lane.started"}
        self.assertNotIn("session_id", stored["h-none"])
        self.assertEqual(stored["h-good"]["session_id"], good)


class ConfigurationTest(lanesupport.LaneTest):
    """B and the validation of D: `config validate` names the key path of what it refuses."""

    def validate(self, extra, code, *needles, unwanted=()):
        text = lanesupport.lane_config("alpha") + "\n" + extra
        (self.home / "configs" / "alpha" / "config.toml").write_text(text, encoding="utf-8")
        result = self.run_laneboss("config", "validate", "alpha", code=code)
        for needle in needles:
            self.assertIn(needle, result.stderr)
        for needle in unwanted:
            self.assertNotIn(needle, result.stderr)

    def test_half_an_identity_is_refused(self):
        with_session = ["--lane", "{lane}", "--brief", "{brief}", "--session-id", "{session}"]
        without = ["--lane", "{lane}", "--brief", "{brief}"]
        self.validate(runner("probe", "ok", with_session, None, ["ok", "resumed", "--lane", "{lane}"]), 2,
                      "config.toml: runners.probe.resume", "{session}")
        self.validate(runner("probe", "ok", without, None, ["ok", "resumed", "--lane", "{lane}", "{session}"]), 2,
                      "config.toml: runners.probe.command", "{session}")

    def test_session_only_where_allowed(self):
        # Where it is allowed it is accepted; the placeholder does not leak into any other command or template.
        self.validate(runner("probe", "ok", ["--lane", "{lane}", "--brief", "{brief}", "--session-id", "{session}"],
                             None, ["ok", "resumed", "--lane", "{lane}", "--resume", "{session}"]), 0)
        cases = [
            ("a program name", '[runners.probe]\ncommand = ["{session}", "{brief}"]\n', "runners.probe.command[0]"),
            ("a test machine's command",
             '[test_environments.t2]\nkind = "local"\nlaunch = ["sh", "-c", "exit 0", "{session}"]\n',
             "test_environments.t2.launch[3]"),
            ("a judge's command", '[judges.j]\ncommand = ["sh", "-c", "{session}"]\n', "judges.j.command[2]"),
            ("a format", '[runners.probe]\ncommand = ["sh", "{brief}", "{session!r}"]\n', "runners.probe.command[2]"),
        ]
        for label, extra, key_path in cases:
            with self.subTest(label):
                self.validate(extra, 2, "config.toml: " + key_path)

    def test_session_where_allowed(self):
        both = runner("probe", "ok", ["--lane", "{lane}", "--brief", "{brief}", "--session-id", "{session}"], None,
                      ["ok", "resumed", "--lane", "{lane}", "--resume", "{session}"], extra=BY_SESSION)
        self.validate(both, 0)
        # A runner without a resume template has no resume to get wrong: its command may use the placeholder.
        only = runner("probe", "ok", ["--lane", "{lane}", "--brief", "{brief}", "--session-id", "{session}"])
        self.validate(only, 0)
        # A records path may name the placeholder whatever the templates do; the lanes it cannot name are not covered.
        self.validate(runner("probe", "ok", ["--lane", "{lane}", "--brief", "{brief}"], extra=BY_SESSION), 0)

    def test_prompt_is_validated(self):
        argument = ["--lane", "{lane}"]
        probe = lambda extra="", resume=None: runner("probe", "ok", argument, None, resume, extra=extra)
        # A brief always reaches the runner as a file unless the prompt is on standard input.
        self.validate(probe(), 2, "runners.probe.command", "{brief}")
        self.validate(probe('prompt = "argument"\n'), 2, "runners.probe.command", "{brief}")
        self.validate(probe('prompt = "stdin"\n'), 0)
        self.validate(probe('prompt = "stdin"\n', ["ok", "resumed", "--lane", "{lane}"]), 0)
        self.validate(runner("probe", "ok", ["--lane", "{lane}", "--brief", "{brief}"], extra='prompt = "argument"\n'), 0)
        self.validate(runner("probe", "ok", ["--lane", "{lane}", "--brief", "{brief}"], extra='prompt = "stdin"\n'), 0)
        for label, value in (("another word", '"teletype"'), ("empty", '""'), ("a number", "1"), ("a boolean", "true"),
                             ("a list", '["stdin"]'), ("another case", '"Stdin"')):
            with self.subTest(label):
                self.validate(probe("prompt = {}\n".format(value)), 2, "config.toml: runners.probe.prompt",
                              unwanted=("unknown key",))


class StandardInputTest(SessionTest):
    def test_brief_and_message_on_stdin(self):
        big = BRIEF + FILLER * 4000
        started = self.run_lane("d-fed", "fed", text=big)
        record = self.ended_run("d-fed")
        rendered = Path(started["brief"]["path"]).read_bytes()
        self.assertTrue(rendered.startswith(big.encode("utf-8")))
        self.assertGreater(len(rendered), 200000)
        self.assertEqual(self.standard_input(record), rendered)
        self.assertIs(record["stdin"]["devnull"], False)
        self.assertEqual(record["argv"], ["ok", "--lane", "d-fed"])
        self.assertEqual(self.wait_event("lane.ended", "d-fed")["payload"]["exit_code"], 0)
        # A resume with a message: its rendered file is what arrives, though the template has no {message}.
        message = self.directory / "follow-up.md"
        message.write_text(MESSAGE, encoding="utf-8")
        self.lane_json("resume", "--lane", "d-fed", "--message", message)
        record = self.ended_run("d-fed", 2)
        event = self.wait_event("lane.resumed", "d-fed", run=2)["payload"]["message"]
        sent = Path(event["path"]).read_bytes()
        self.assertEqual(self.standard_input(record), sent)
        self.assertTrue(sent.startswith(MESSAGE.encode("utf-8")))
        self.assertEqual((event["sha256"], record["stdin"]["sha256"]), (support.digest(sent), support.digest(sent)))
        self.assertEqual(record["argv"], ["ok", "resumed", "--lane", "d-fed"])
        # Without a message the launcher's own follow-up is rendered and sent.
        self.lane_json("resume", "--lane", "d-fed")
        record = self.ended_run("d-fed", 3)
        sent = Path(self.wait_event("lane.resumed", "d-fed", run=3)["payload"]["message"]["path"]).read_bytes()
        self.assertEqual(self.standard_input(record), sent)
        self.assertTrue(sent.startswith(CONTINUE.read_bytes()))
        self.assert_sound()

    def test_runner_that_never_reads(self):
        # The brief is larger than a pipe holds, and the runner never reads it: the budget still ends the run.
        self.run_lane("d-deaf", "deaf", "--budget", "0.05", text=BRIEF + FILLER * 4000)
        record = self.record("d-deaf")
        ended = self.wait_event("lane.ended", "d-deaf", timeout=40)["payload"]
        self.assertEqual(ended["reason"], "timeout")
        self.assertEqual(ended["prompt"]["state"], "cut")
        self.assertLess(ended["prompt"]["bytes"], ended["prompt"]["length"])
        self.assert_gone([record["pid"]] + record["children"], timeout=10)
        # The supervising process ends too and says so (a hang at its exit would show here), and its log notes the cut
        # prompt once, with no traceback. This does not detect the removal of the thread's `finally` or of
        # `daemon=True`: the deaf runner's pipe ends are closed when it is killed, so the write ends either way.
        deadline = time.monotonic() + 20
        while self.status("d-deaf")["live"]["supervisor"]["alive"]:
            self.assertLess(time.monotonic(), deadline, "the supervising process did not end")
            time.sleep(0.2)
        text = (Path(self.paths()["state_dir"]) / "lanes" / "d-deaf" / "watch.log").read_text(encoding="utf-8")
        self.assertEqual(text.count("the prompt was not written to the runner's standard input in full"), 1)
        self.assertIn("the supervising process exits with status 0", text)
        self.assertNotIn("Traceback", text)
        self.assert_sound()

    def test_argument_is_the_default(self):
        started = self.run_lane("d-arg", "argued")
        record = self.ended_run("d-arg")
        self.assertEqual(self.standard_input(record), b"")
        self.assertIs(record["stdin"]["devnull"], True)
        self.assertEqual(record["argv"], ["ok", "--lane", "d-arg", "--brief", started["brief"]["path"]])
        self.assertEqual(record["brief"]["text"].encode("utf-8"), Path(started["brief"]["path"]).read_bytes())
        self.lane_json("resume", "--lane", "d-arg")
        record = self.ended_run("d-arg", 2)
        self.assertEqual(self.standard_input(record), b"")
        self.assertIs(record["stdin"]["devnull"], True)
        # A message that would not reach the runner is still refused.
        message = self.directory / "unused.md"
        message.write_text(MESSAGE, encoding="utf-8")
        self.assertIn("message", self.lane("resume", "--lane", "d-arg", "--message", message, code=2).stderr)


class DefaultStandardInputTest(lanesupport.LaneTest):
    """Pins what must not change: a runner without `prompt` is given /dev/null itself (not an empty pipe or a closed
    descriptor, which read as empty too), as on main."""

    def test_nothing_on_stdin_by_default(self):
        self.start("d-plain", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("d-plain"))
        self.wait_event("lane.ended", "d-plain")
        record = self.record("d-plain", ended=True)
        self.assertEqual((record["stdin"]["length"], record["stdin"]["sha256"]), (0, EMPTY))
        self.assertIs(record["stdin"]["devnull"], True)
        self.lane_json("resume", "--lane", "d-plain")
        self.wait_event("lane.ended", "d-plain", run=2)
        record = self.record("d-plain", run=2, ended=True)
        self.assertEqual((record["stdin"]["length"], record["stdin"]["sha256"]), (0, EMPTY))
        self.assertIs(record["stdin"]["devnull"], True)
        self.assert_sound()


class PromptFateTest(SessionTest):
    """What became of a prompt on standard input is recorded in lane.ended (written or cut, and how many bytes) and
    shown by lane status; a runner that takes no prompt there has no such key. Written is not read."""

    def test_written(self):
        started = self.run_lane("f-fed", "fed", text=BRIEF + FILLER * 4000)
        self.ended_run("f-fed")
        length = len(Path(started["brief"]["path"]).read_bytes())
        fate = {"state": "written", "bytes": length, "length": length}
        self.assertEqual(self.wait_event("lane.ended", "f-fed")["payload"]["prompt"], fate)
        self.assertEqual(self.status("f-fed")["prompt"], fate)
        # A resume's message is written the same way.
        self.lane_json("resume", "--lane", "f-fed")
        self.ended_run("f-fed", 2)
        message = Path(self.wait_event("lane.resumed", "f-fed", run=2)["payload"]["message"]["path"]).read_bytes()
        fate = {"state": "written", "bytes": len(message), "length": len(message)}
        self.assertEqual(self.wait_event("lane.ended", "f-fed", run=2)["payload"]["prompt"], fate)
        self.assertEqual(self.status("f-fed")["prompt"], fate)
        # A runner that takes its prompt as an argument has no such key.
        self.run_lane("f-arg", "argued")
        self.ended_run("f-arg")
        self.assertNotIn("prompt", self.wait_event("lane.ended", "f-arg")["payload"])
        self.assertIsNone(self.status("f-arg")["prompt"])
        self.assert_sound()

    def test_runner_never_created(self):
        # The program does not exist, so the supervising process cannot create the runner: the end has no exit status,
        # and the prompt, decoded before the runner was to be created, is recorded as cut with no byte written.
        started = self.run_lane("f-gone", "gone", text=BRIEF + FILLER * 40)
        length = len(Path(started["brief"]["path"]).read_bytes())
        ended = self.wait_event("lane.ended", "f-gone")["payload"]
        self.assertEqual((ended["reason"], ended["exit_code"], ended["signal"]), ("exit", None, None))
        self.assertEqual(ended["prompt"], {"state": "cut", "bytes": 0, "length": length})
        self.assertEqual(self.status("f-gone")["prompt"], ended["prompt"])
        self.assert_sound()

    def test_cut(self):
        # The runner closes its input and exits 0 at once, and the brief is far larger than a pipe holds: the end is
        # a normal end, and the cut is recorded all the same.
        started = self.run_lane("f-shut", "shut", text=BRIEF + FILLER * 4000)
        self.ended_run("f-shut")
        length = len(Path(started["brief"]["path"]).read_bytes())
        ended = self.wait_event("lane.ended", "f-shut")["payload"]
        self.assertEqual((ended["reason"], ended["exit_code"]), ("exit", 0))
        self.assertEqual((ended["prompt"]["state"], ended["prompt"]["length"]), ("cut", length))
        self.assertLess(ended["prompt"]["bytes"], length)
        self.assertEqual(self.status("f-shut")["prompt"], ended["prompt"])
        self.assert_sound()


class RecordsTest(SessionTest):
    def write_pair(self, scratch, own_name, own_id="c-own", other_id="c-other"):
        """Two records in one directory, both of this working directory and each with a refused call: the lane's own,
        named own_name, and another session's. Returns their paths."""
        cwd = os.path.realpath(str(scratch))
        other = refusalsupport.write_session(self.user_home, cwd, other_id)
        made = refusalsupport.write_session(self.user_home, cwd, own_id)
        own = os.path.join(os.path.dirname(made), own_name)
        os.replace(made, own)
        return own, other

    def test_records_by_session(self):
        scratch = self.scratch("e-own")
        started = self.start("e-own", "--runner", "watched", "--model", "watched-model-1", "--worktree", scratch)
        own, other = self.write_pair(scratch, started["session_id"] + ".jsonl")
        self.go("e-own")
        self.wait_event("lane.ended", "e-own")
        # Only the lane's own refusal was recorded while the run lived: the other session's file is not read.
        listing = self.lane_json("refusals", "--lane", "e-own")
        self.assertEqual([item["call"]["id"] for item in listing["refusals"]], ["c-own"])
        self.assertEqual(listing["refusals"][0]["record"]["path"], own)
        self.assertTrue(os.path.exists(other))
        scanned = self.lane_json("scan", "--lane", "e-own")
        self.assertEqual((scanned["appended"], scanned["not_covered"]), ({"refusals": 0, "suspicions": 0}, []))
        coverage = scanned["runs"][0]
        self.assertEqual((coverage["covered"], coverage["not_covered"]), (True, []))
        self.assertEqual([item["path"] for item in coverage["records"]], [own])
        self.assertEqual(self.lane_json("refusals", "--lane", "e-own")["coverage"][0]["records"], coverage["records"])
        # Without the session in the path, the same two files are both read: the identifier is what leaves one out.
        broad = self.scratch("e-broad")
        self.start("e-broad", "--runner", "broad", "--model", "broad-model-1", "--worktree", broad)
        self.write_pair(broad, "mine.jsonl")
        self.go("e-broad")
        self.wait_event("lane.ended", "e-broad")
        both = self.lane_json("refusals", "--lane", "e-broad")
        self.assertEqual(sorted(item["call"]["id"] for item in both["refusals"]), ["c-other", "c-own"])
        self.assert_sound()

    def test_lane_without_identity_not_covered(self):
        scratch = self.scratch("e-bare")
        started = self.start("e-bare", "--runner", "bare", "--model", "bare-model-1", "--worktree", scratch)
        self.assertNotIn("session_id", started)
        self.write_pair(scratch, "any.jsonl")
        self.wait_event("lane.ended", "e-bare")
        # Records of the lane's directory exist, but a path that names a session cannot name one for this lane: the
        # run is not covered, with a reason of its own, and nothing is read.
        scanned = self.lane_json("scan", "--lane", "e-bare")
        self.assertEqual(scanned["not_covered"], [{"run": 1, "reason": "no-session", "path": SESSION_PATH}])
        self.assertEqual((scanned["appended"], scanned["runs"][0]["covered"], scanned["runs"][0]["records"]),
                         ({"refusals": 0, "suspicions": 0}, False, []))
        listing = self.lane_json("refusals", "--lane", "e-bare")
        self.assertEqual(listing["refusals"], [])
        self.assertEqual(listing["not_covered"], [{"run": 1, "reason": "no-session", "path": SESSION_PATH}])
        refused = self.lane("mark", "--lane", "e-bare", "--state", "accepted", code=2)
        self.assertIn("no-session", refused.stderr)
        self.lane_json("mark", "--lane", "e-bare", "--state", "accepted", "--accept-uncovered")


class PayloadFormTest(SessionTest):
    """C, from this launcher's side: a lane whose runner does not use {session} has the `lane.started` payload main
    wrote (the whole store of such a lane is then main's in form). The full read of a store that main's launcher wrote
    is the supervisor's probe, not a test of the suite: nothing here needs a second source tree."""

    def test_payload_form_of_main(self):
        self.run_lane("c-form", "shift")
        self.ended_run("c-form")
        self.lane_json("resume", "--lane", "c-form")
        self.ended_run("c-form", 2)
        for run in (1, 2):
            payload = self.wait_event("lane.started", "c-form", run=run)["payload"]
            self.assertEqual(sorted(payload), MAIN_STARTED_KEYS, "run {}".format(run))
            self.assertEqual(sorted(payload["session"]), ["name", "socket"])
            # So is the end of a run whose runner takes no prompt on standard input.
            self.assertEqual(sorted(self.wait_event("lane.ended", "c-form", run=run)["payload"]), MAIN_ENDED_KEYS)
        # A runner that uses {session} adds one key to it, the lane's identifier, and no other.
        self.run_lane("c-ident", "ident")
        self.ended_run("c-ident")
        payload = self.wait_event("lane.started", "c-ident")["payload"]
        self.assertEqual(sorted(payload), sorted(MAIN_STARTED_KEYS + ["session_id"]))
        self.assert_sound()

    def test_a_new_version(self):
        # A launcher that writes session_id is never mistaken for 0.5.0, which cannot read it (what 0.5.0 can read is
        # the check of the probe outside the suite); the version it writes into brief.rendered is the one it reports,
        # in a form the store accepts.
        version = self.laneboss_json("--version")["version"]
        self.assertNotEqual(version, "0.5.0")
        self.run_lane("c-version", "shift")
        self.ended_run("c-version")
        self.assertEqual(self.lane_events("c-version", "brief.rendered")[0]["payload"]["launcher_version"], version)
        self.assert_sound()

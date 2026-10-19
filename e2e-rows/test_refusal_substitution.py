"""Raw-record CLI rows; run only on the authorized disposable Linux test box.

LANEBOSS_SUBST_BINARY names a supplied release (or pre-fix) CLI by absolute
path. LANEBOSS_SUBST_FAULTS names the tagged CLI for test_mutant_skips_kind.
LANEBOSS_SUBST_EVIDENCE is an absolute directory; every fixture is retained.
Commands under observation are JSONL data only and are never executed.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


KIND = "shell-substitution-in-text"
POINT = "scan-skip-shell-substitution-in-text"
FLAG_ROWS = (
    "test_flag_backticks", "test_flag_dollar", "test_flag_nested",
    "test_flag_inner_quotes", "test_flag_even_escape", "test_flag_after_ansi_quote",
    "test_flag_line_continuation", "test_flag_group_fallback", "test_flag_two_group_fallback",
    "test_flag_positional_backtick", "test_flag_configured_prose", "test_flag_text_option",
    "test_flag_unquoted_heredoc",
)


def executable(variable):
    path = Path(os.environ.get(variable, ""))
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(variable + " must name a supplied executable by absolute path")
    return path.resolve()


def record_line(cwd, kind, content, timestamp=None):
    timestamp = timestamp or datetime.now(timezone.utc).isoformat(timespec="microseconds")
    return (json.dumps({"type": kind, "cwd": str(cwd), "timestamp": timestamp,
                        "message": {"role": kind, "content": content}}) + "\n").encode("utf-8")


def runner_main(worktree, brief, session):
    # This stand-in reads the real prompt and writes records in the supported
    # shape. It never evaluates any of the recorded command strings.
    directory = Path(worktree)
    prompt = sys.stdin.buffer.read()
    if not prompt or prompt != Path(brief).read_bytes():
        raise RuntimeError("the stand-in must receive a real kept prompt")
    (directory / ("prompt-" + uuid.uuid4().hex + ".md")).write_bytes(prompt)
    record = directory / "raw.jsonl"
    if not record.exists():
        record.write_bytes(record_line(directory, "assistant", [
            {"type": "text", "text": "credential-free record fixture"},
        ]))
    plan = directory / "turn-call.json"
    if plan.is_file():
        call = json.loads(plan.read_bytes())
        with record.open("ab") as output:
            output.write(record_line(directory, "assistant", [call]))
            output.write(record_line(directory, "user", [{
                "type": "tool_result", "tool_use_id": call["id"],
                "is_error": False, "content": "recorded result fixture",
            }]))
    print(json.dumps({"type": "system", "subtype": "init", "session_id": session}))
    print("record fixture read", len(prompt), "prompt bytes")


class ShellSubstitutionRows(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, "linux", "these rows require the disposable Linux test box")
        self.binary = getattr(self, "supplied_binary", None) or executable("LANEBOSS_SUBST_BINARY")
        evidence = Path(os.environ.get("LANEBOSS_SUBST_EVIDENCE", ""))
        self.assertTrue(evidence.is_absolute(), "LANEBOSS_SUBST_EVIDENCE must be absolute")
        evidence.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="lb-refusal-subst-", dir=evidence)).resolve()
        (self.root / "row.txt").write_text(self._testMethodName + "\n", encoding="utf-8")
        self.marker = self.root / "mutation-reached"
        self.calls = 0
        self.home = self.root / "home"
        self.home.mkdir()
        self.config_home = self.root / "config-home"
        self.states = self.root / "states"
        self.config = self.config_home / "configs" / "subst"
        self.config.mkdir(parents=True)
        commands = self.root / "bin"
        commands.mkdir()
        for name in ("git", "tmux", "env", "sh"):
            program = shutil.which(name)
            self.assertIsNotNone(program, "test box requires real " + name)
            (commands / name).symlink_to(program)
        self.environment = {
            "HOME": str(self.home), "PATH": str(commands) + os.pathsep + os.defpath,
            "LANG": "C", "LC_ALL": "C", "LANEBOSS_HOME": str(self.config_home),
            "LANEBOSS_STATE_HOME": str(self.states), "LANEBOSS_CONFIG": "subst",
            "LANEBOSS_TEST_CLAIMS_DIR": str(self.root / "claims"),
        }
        self.org = self.config_home / "orgs" / "fixture"
        self.org.parent.mkdir()
        initialized = self.cli("org", "init", self.org, "--name", "fixture")
        self.assertIs(json.loads(initialized)["ok"], True)
        self.assertGreater(json.loads(initialized)["changed"], 0)
        installed = self.cli("org", "roles", "init", self.org)
        self.assertIs(json.loads(installed)["ok"], True)
        self.assertGreater(json.loads(installed)["changed"], 0)
        (self.org / "tools").mkdir(exist_ok=True)
        driver = self.org / ".laneboss/L3/roles/executor.toml"
        driver.write_text("drivers = " + json.dumps([Path(sys.executable).name]) + "\n", encoding="utf-8")
        command = [sys.executable, "-I", str(Path(__file__).resolve()), "--runner",
                   "{worktree}", "{brief}", "{session}"]
        resume = [word.replace("{brief}", "{message}") for word in command]
        config = ('schema_version = 1\nname = "subst"\norganisation = "fixture"\n'
                  '[lanes]\nbudget_minutes = 1\nstop_grace_seconds = 1\n'
                  '[runners.fixture]\nprompt = "stdin"\ncommand = ' + json.dumps(command) +
                  '\nresume = ' + json.dumps(resume) + '\nrecords = [{format = "claude-code", '
                  'paths = ["{worktree}/raw.jsonl"]}]\n'
                  '[supervisors.top]\nlevel = 5\nrunner = "fixture"\n'
                  '[[guards]]\nname = "fixture-guard"\nkind = "hook"\n'
                  "pattern = '^SUBSTITUTION_FIXTURE_REFUSED'\n")
        (self.config / "config.toml").write_text(config, encoding="utf-8")
        self.assertIs(json.loads(self.cli("config", "validate", "subst"))["valid"], True)
        self.cli("start", "--config", "subst", "--role", "top", "--format", "json")
        self.canary = "canary_" + uuid.uuid4().hex
        self.message_tool = "message-" + uuid.uuid4().hex[:12]
        policy = self.org / ".laneboss" / "shared" / "services" / "text-observations.toml"
        policy.write_text('schema_version = 1\n[[tools]]\ncommand = ' +
                          json.dumps([self.message_tool, "send"]) + '\ntext_from = 3\n', encoding="utf-8")
        self.lane = None

    def cli(self, *args, mutation=False):
        self.calls += 1
        path = self.root / ("call-" + str(self.calls))
        argv = [str(self.binary), *map(str, args)]
        path.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n", encoding="utf-8")
        environment = dict(self.environment)
        if mutation:
            environment["LANEBOSS_FAULTS"] = json.dumps({"point": POINT, "marker": str(self.marker)})
            path.with_suffix(".fault.json").write_text(environment["LANEBOSS_FAULTS"] + "\n", encoding="utf-8")
        try:
            result = subprocess.run(argv, cwd=self.root, env=environment, capture_output=True, timeout=90)
        except subprocess.TimeoutExpired as error:
            path.with_suffix(".stdout").write_bytes(error.stdout or b"")
            path.with_suffix(".stderr").write_bytes(error.stderr or b"")
            path.with_suffix(".timeout").write_text("CLI exceeded 90 seconds; no exit was observed.\n", encoding="utf-8")
            raise
        path.with_suffix(".stdout").write_bytes(result.stdout)
        path.with_suffix(".stderr").write_bytes(result.stderr)
        path.with_suffix(".exit").write_text(str(result.returncode) + "\n", encoding="utf-8")
        self.assertEqual(result.returncode, 0, "CLI prerequisite: " + result.stderr.decode("utf-8"))
        return result.stdout

    def wait_end(self, run, since=0):
        data = self.cli("event", "tail", "--config", "subst", "--lane", self.lane,
                        "--since", since, "--follow", "--until", "lane.ended")
        ended = [json.loads(line) for line in data.splitlines() if json.loads(line)["kind"] == "lane.ended"]
        self.assertEqual(len(ended), 1, "the follow must see exactly this run's end")
        self.assertEqual(ended[0]["payload"]["run"], run)
        self.assertEqual(ended[0]["payload"]["reason"], "exit")
        self.assertEqual(ended[0]["payload"]["exit_code"], 0)
        self.assertEqual(ended[0]["payload"]["survivors"], 0)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            status = json.loads(self.cli("lane", "status", "--config", "subst", "--lane", self.lane))
            live = status["live"]
            if live["supervisor"]["alive"] is False and live["session_alive"] is False:
                self.assertIs(status["running"], False)
                self.assertEqual(status["run"], run)
                self.assertEqual((live["survivors"], live["pending_events"], live["refused_events"]), (0, 0, 0))
                return ended[0], status
            time.sleep(0.05)
        self.fail("the real lane did not become quiescent before its deadline")

    def start_lane(self, turns=False):
        self.lane = "lb-refusal-subst-" + uuid.uuid4().hex[:10]
        self.worktree = self.root / self.lane
        self.worktree.mkdir()
        self.brief = self.root / (self.lane + ".md")
        self.brief.write_text("Read the prompt and emit the credential-free record fixture.\n", encoding="utf-8")
        args = ["lane", "start", "--config", "subst", "--lane", self.lane,
                "--worktree", self.worktree, "--brief", self.brief, "--role", "executor",
                "--level", "3", "--runner", "fixture", "--model", "fixture-model-1", "--budget", "1"]
        if turns:
            args.append("--turns")
        started = json.loads(self.cli(*args))
        self.assertEqual(started["run"], 1)
        self.assertEqual(started["worktree"], str(self.worktree))
        self.raw = self.worktree / "raw.jsonl"
        ended, status = self.wait_end(1)
        self.assertTrue(self.raw.is_file(), "the real stand-in must write the raw session seed")
        self.assertIs(json.loads(self.cli("state", "verify", "--config", "subst"))["ok"], True)
        return ended, status

    def interpreter_text(self, text):
        return 'python3 -c "from pathlib import Path; Path(\'note.txt\').write_text(\'' + text + '\')"'

    def append_call(self, command, timestamp, tool="Bash"):
        self.call_id = "call-" + uuid.uuid4().hex
        data = {"command": command} if tool == "Bash" else {
            "file_path": str(self.worktree / "note.txt"), "content": command,
        }
        block = {"type": "tool_use", "id": self.call_id, "name": tool, "input": data}
        self.seed = self.raw.read_bytes()
        with self.raw.open("ab") as output:
            output.write(record_line(self.worktree, "assistant", [block], timestamp))
            output.write(record_line(self.worktree, "user", [{
                "type": "tool_result", "tool_use_id": self.call_id,
                "is_error": False, "content": "recorded result fixture",
            }], timestamp))
        (self.root / "command.txt").write_text(command, encoding="utf-8")
        return block

    def covered(self, scan):
        self.assertEqual(scan["not_covered"], [], "raw-record setup must be fully covered")
        self.assertEqual(scan["refused_events"], 0, "the store must accept the scanner's event")
        self.assertEqual(scan["pending_events"], 0)
        self.assertEqual(len(scan["runs"]), 1)
        self.assertIs(scan["runs"][0]["complete"], True)
        self.assertIs(scan["runs"][0]["covered"], True)

    def listing(self):
        return json.loads(self.cli("lane", "refusals", "--config", "subst", "--lane", self.lane))

    def named_count(self, actual, expected, label, evidence_name="detection-assertion.json", listing=None):
        message = self._testMethodName + ": " + label
        (self.root / evidence_name).write_text(json.dumps({
            "row": self._testMethodName, "assertion": message,
            "actual": actual, "expected": expected, "passed": actual == expected,
            "observations_present": listing is not None and "observations" in listing,
        }, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(actual, expected, message)

    def collect(self):
        self.cli("lane", "mark", "--config", "subst", "--lane", self.lane, "--state", "abandoned")
        cleaned = json.loads(self.cli("lane", "clean", "--config", "subst", "--lane", self.lane))
        self.assertIs(cleaned["pending"], False)
        self.assertTrue(self.raw.is_file(), "collection must retain the fixture and raw evidence")

    def check_start_and_doctor(self):
        dashboard = json.loads(self.cli("start", "--config", "subst", "--role", "top", "--format", "json"))
        checks = dashboard["checks"]["read"]
        self.assertTrue(any(row["check"] == "store.recorded" and row["ok"] is True for row in checks),
                        "start must replay the stored observation")
        self.assertTrue(all(row["ok"] is True for row in checks))
        doctor = [json.loads(line) for line in self.cli("doctor", "--config", "subst").splitlines()]
        self.assertTrue(any(row["check"] == "store.recorded" and row["ok"] is True for row in doctor),
                        "doctor must replay the stored observation")
        self.assertTrue(all(row["ok"] is True for row in doctor))

    def check_command(self, command, expected, tool="Bash"):
        ended, _status = self.start_lane()
        self.append_call(command, ended["occurred_at"] or ended["recorded_at"], tool)
        scan = json.loads(self.cli("lane", "scan", "--config", "subst", "--lane", self.lane,
                                   mutation=getattr(self, "mutate", False)))
        self.covered(scan)
        listing = self.listing()
        self.assertEqual(listing["refusals"], [], "the observation must not invent a guard refusal")
        self.assertEqual(listing["unreviewed"], [], "the observation must not hold the acceptance gate")
        self.assertEqual(listing["not_covered"], [])
        observations = listing.get("observations", [row for row in listing["suspicions"]
                                                    if row["how"] == [KIND] and row["refusal"] is None])
        self.named_count(len(observations), expected, "expected " + KIND, listing=listing)
        self.assertIn("observations", listing, "lane refusals must expose independent observations separately")
        self.assertEqual(listing["observation_count"], expected)
        self.assertEqual(listing["suspicions"], [], "observations must be listed separately from workarounds")
        self.check_start_and_doctor()
        self.assertEqual(scan["appended"], {"refusals": 0, "suspicions": expected})
        for suspicion in listing["observations"]:
            self.assertEqual(suspicion["how"], [KIND])
            self.assertIsNone(suspicion["refusal"])
            self.assertIsNone(suspicion["similarity"])
            self.assertEqual(suspicion["paths"], ["(command)"])
            self.assertEqual(suspicion["tool"], "Bash")
            self.assertEqual(suspicion["run"], 1)
            self.assertEqual(suspicion["call"]["id"], self.call_id)
            self.assertEqual(suspicion["call"]["record"], {
                "path": str(self.raw), "line": 2, "offset": len(self.seed), "item": 0,
            })
            self.assertEqual(suspicion["command"]["sha256"], hashlib.sha256(command.encode()).hexdigest())
            self.assertEqual(suspicion["command"]["length"], len(command))
        repeated = json.loads(self.cli("lane", "scan", "--config", "subst", "--lane", self.lane))
        self.covered(repeated)
        self.assertEqual(repeated["appended"], {"refusals": 0, "suspicions": 0}, "rescan must deduplicate")
        self.assertEqual(self.listing()["observations"], listing["observations"])
        verified = json.loads(self.cli("state", "verify", "--config", "subst"))
        self.assertIs(verified["ok"], True, "the state reader must replay the actual observation")
        accepted = json.loads(self.cli("lane", "mark", "--config", "subst", "--lane", self.lane,
                                       "--state", "accepted"))
        self.assertEqual(accepted["state"], "accepted", "observation alone must leave acceptance open")
        self.assertEqual(accepted["scan"]["not_covered"], [])
        self.collect()

    def test_flag_backticks(self):
        self.check_command(self.interpreter_text("`printf " + self.canary + "`"), 1)

    def test_flag_dollar(self):
        self.check_command(self.interpreter_text("$(printf " + self.canary + ")"), 1)

    def test_start_doctor_after_observation(self):
        ended, _status = self.start_lane()
        self.append_call(self.interpreter_text("$(printf " + self.canary + ")"),
                         ended["occurred_at"] or ended["recorded_at"])
        scan = json.loads(self.cli("lane", "scan", "--config", "subst", "--lane", self.lane))
        self.covered(scan)
        self.named_count(scan["recorded"]["suspicions"], 1, "expected stored observation before replay",
                         "replay-assertion.json")
        self.check_start_and_doctor()
        self.collect()

    def test_flag_nested(self):
        text = "prefix $(printf " + self.canary + ") middle `printf " + self.canary + "` suffix"
        self.check_command(self.interpreter_text(text), 1)

    def test_flag_inner_quotes(self):
        self.check_command('printf "`printf "%s" ' + self.canary + '`"', 1)

    def test_flag_even_escape(self):
        self.check_command(self.interpreter_text("\\" * 2 + "$(printf " + self.canary + ")"), 1)

    def test_flag_after_ansi_quote(self):
        self.check_command("python3 $'it\\'s' -c \"print('$(printf " + self.canary + ")')\"", 1)

    def test_ctrl_ansi_literal(self):
        self.check_command("python3 -c $'it\\'s \"$(printf " + self.canary + ")\"'", 0)

    def test_flag_line_continuation(self):
        self.check_command(self.interpreter_text("$\\\n(printf " + self.canary + ")"), 1)

    def test_flag_group_fallback(self):
        self.check_command(self.interpreter_text("$((printf " + self.canary + ") )"), 1)

    def test_flag_two_group_fallback(self):
        self.check_command(self.interpreter_text("$((printf " + self.canary + ");(printf second))"), 1)

    def test_flag_positional_backtick(self):
        self.check_command('unlisted-message send channel "prose `printf ' + self.canary + '` end"', 1)

    def test_flag_configured_prose(self):
        self.check_command(self.message_tool + ' send channel "prose $(printf ' + self.canary + ') end"', 1)

    def test_flag_text_option(self):
        self.check_command('record-tool --message="prose $(printf ' + self.canary + ') end"', 1)

    def test_ctrl_plain_substitution(self):
        self.check_command('cd "$(printf ' + self.canary + ')"', 0)

    def test_ctrl_echo_idiom(self):
        self.check_command('echo "=== $(date) ' + self.canary + ' ==="', 0)

    def test_ctrl_unconfigured_prose(self):
        self.check_command('unlisted-message send channel "prose $(printf ' + self.canary + ') end"', 0)

    def test_ctrl_file_option(self):
        self.check_command(self.message_tool + ' send channel --file "$(printf ' + self.canary + ')"', 0)

    def test_ctrl_single_quotes(self):
        self.check_command("printf '%s' '`printf " + self.canary + "` $(printf " + self.canary + ")'", 0)

    def test_ctrl_escaped(self):
        text = "\\`printf " + self.canary + "\\` \\$(printf " + self.canary + ")"
        self.check_command(self.interpreter_text(text), 0)

    def test_ctrl_outside_quotes(self):
        self.check_command("printf '%s' `printf " + self.canary + "` $(printf " + self.canary + ")", 0)

    def test_ctrl_quoted_heredoc(self):
        text = 'print("`printf ' + self.canary + '` $(printf ' + self.canary + ')")'
        self.check_command("python3 <<'PY'\n" + text + "\nPY\n", 0)

    def test_flag_unquoted_heredoc(self):
        text = 'print("`printf ' + self.canary + '` $(printf ' + self.canary + ')")'
        self.check_command("python3 - <<PY\n" + text + "\nPY\n", 1)

    def test_ctrl_escaped_heredoc(self):
        text = 'print("\\`printf ' + self.canary + '\\` \\$(printf ' + self.canary + ')")'
        self.check_command("python3 - <<PY\n" + text + "\nPY\n", 0)

    def test_ctrl_arithmetic_pid(self):
        self.check_command('printf "$((1 + 2)) $$(printf ' + self.canary + ')"', 0)

    def test_ctrl_file_tool(self):
        self.check_command(self.interpreter_text("$(printf " + self.canary + ")"), 0, tool="Write")

    def test_turn_live_scan(self):
        _ended, status = self.start_lane(turns=True)
        command = self.interpreter_text("$(printf " + self.canary + ")")
        block = {"type": "tool_use", "id": "call-" + uuid.uuid4().hex,
                 "name": "Bash", "input": {"command": command}}
        (self.worktree / "turn-call.json").write_text(json.dumps(block) + "\n", encoding="utf-8")
        message = self.root / "follow-up.md"
        message.write_text("Emit the next recorded call without executing it.\n", encoding="utf-8")
        self.cli("lane", "send", "--config", "subst", "--lane", self.lane, "--file", message)
        turned = json.loads(self.cli("lane", "turn", "--config", "subst", "--lane", self.lane))
        self.assertIs(turned["started"], True)
        self.wait_end(2, since=status["last_seq"])
        # Inspect before lane scan: this must come from the turn's live reader.
        listing = self.listing()
        self.assertEqual(listing["not_covered"], [])
        self.assertEqual(listing["refusals"], [])
        self.assertEqual(listing["unreviewed"], [])
        self.assertEqual(listing["suspicions"], [])
        self.named_count(len(listing["observations"]), 1, "expected " + KIND, listing=listing)
        observation = listing["observations"][0]
        self.assertEqual(observation["how"], [KIND])
        self.assertEqual(observation["run"], 2)
        self.assertEqual(observation["call"]["id"], block["id"])
        self.assertEqual(observation["command"]["sha256"], hashlib.sha256(command.encode()).hexdigest())
        self.assertIs(json.loads(self.cli("state", "verify", "--config", "subst"))["ok"], True)
        scan = json.loads(self.cli("lane", "scan", "--config", "subst", "--lane", self.lane))
        self.assertEqual(scan["appended"], {"refusals": 0, "suspicions": 0},
                         "the ordinary scanner must use the live turn observation's identity")
        self.assertEqual(self.listing()["observations"], listing["observations"])
        self.collect()

    def test_mutant_skips_kind(self):
        tagged = executable("LANEBOSS_SUBST_FAULTS")
        for name in FLAG_ROWS:
            with self.subTest(row=name):
                case = type(self)(name)
                case.supplied_binary = tagged
                case.mutate = True
                result = unittest.TestResult()
                case.run(result)
                if hasattr(case, "root"):
                    (case.root / "mutant-result.json").write_text(json.dumps({
                        "row": name, "tests_run": result.testsRun,
                        "failures": [failure for _test, failure in result.failures],
                        "errors": [error for _test, error in result.errors],
                    }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.errors, [], "a setup error does not kill the mutant")
                self.assertEqual(len(result.failures), 1, "the unchanged flagged row must fail once")
                failed, detail = result.failures[0]
                self.assertEqual(failed._testMethodName, name)
                self.assertIn(name + ": expected " + KIND, detail,
                              "the mutant must fail the named detection assertion")
                assertion_path = case.root / "detection-assertion.json"
                self.assertTrue(assertion_path.is_file(), "a prerequisite failure is not a named mutant kill")
                assertion = json.loads(assertion_path.read_bytes())
                self.assertEqual(assertion, {
                    "row": name, "assertion": name + ": expected " + KIND,
                    "actual": 0, "expected": 1, "passed": False,
                    "observations_present": True,
                }, "the mutant must reach the row's actual missing-observation assertion")
                self.assertTrue(case.marker.is_file(), "the mutant must reach the real detection point")
                self.assertEqual(case.marker.read_bytes(), b"")
                case.collect()
                print("MUTANT", name, "failed its named detection assertion")


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--runner":
        runner_main(*sys.argv[2:])
    else:
        unittest.main()

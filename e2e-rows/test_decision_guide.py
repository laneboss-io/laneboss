"""Black-box rows for the decision guide (docs/decisions.md, "Guiding agents"); run check-decision-guide.sh on a
disposable Linux test machine, never on a developer's Mac.

What is real: the installed CLI, the org tree it initialises, the SQLite decision store written by
`laneboss decisions`, the launcher configuration, lanes in tmux, the org hook that a runner calls before a tool call,
and the judge machinery with its egress log. What is a stand-in: the vendor program a lane runs (it records the brief it
was given) and the judge. The judge stands in for the TypeSafe service the way the canned answers of rows J4 and J5 of
test_laneboss_jobs.py do, because no secret goes to a test machine: it answers from a rule table that a row writes, by
looking for the row's own random markers inside the texts the product sent, so a score can only come from what the product
put into the request. These rows prove the wiring, the bands and the thresholds, never the accuracy of a model.

G1  a lane brief carries the recorded decisions of its project and level, and nothing else; the section is short
G2  a follow-up message and a new turn carry them too, read when the message is composed
G3  the dial: probability >= warn adds advice; below warn adds nothing with complete coverage; all comparisons share
    one typed request, and partial/legacy-shaped answers cannot clear it
G4  the thresholds are read from the configuration: one score moves between the bands, inclusively at each threshold
G5  no judge answer, an unknown judge or invalid guide.toml: explicit advice and receipts; legacy refusal settings
    cannot deny ordinary work; no judge named: a short notice
G6  a question that is already decided gets the recorded answer back (`lane send --ask`) instead of a new question
G7  controls: nothing applies, a read, the guard switched off, level, project, expiry, supersession and kind; guide.toml
    is protected like the hook policy
G8  mutants, each caught by the row that names it, then the restored row passes
G9  the guard only adds: a call that the org's own rules refuse stays refused, with the rules' own first line, in every
    state of the guard (no guide.toml, one that cannot be used, a judge that answers, fails or talks nonsense, no judge)
G10 the guard's inputs (guide.toml, history.toml, the decision store) cannot be removed, moved or replaced by an agent
    whose write scope covers the whole org folder
G11 a decision that max_decisions leaves out is reported with a warning, however the
    agent words the call
G12 a long call is judged whole, in windows; one longer than the windows is reported as not read
G13 credential-shaped state is withheld before sending and is never reported as scored
G14 what a multiple edit writes reaches the judge
G15 no judge named: the short warn-only notice, and nothing when no guide.toml, no decision or a read
B1-B67, B69-B70 blacklist rows: description/example state, preview egress, deterministic precedence and references, ordinary
observation, compound state and raw fallback paths, protected roots and secret names, bounded judges, instance binding,
reserved bodies, ANSI-C and eval forms, and the variable-redirect R26 control
"""

from datetime import datetime, timedelta, timezone
import json
import fcntl
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
import tomllib
import unittest
import uuid

from orgsupport import assert_hook_deprecation, write_rule_source
from hookfixtures import install_hook_rules


HEADING = "## Recorded decisions that apply to this lane"
CONFLICTS = "decision.conflicts"
ANSWERS = "decision.answers"
PLAIN_ALLOW = "org policy permits this tool call"
PROTECTED_FILES = ("[blacklist:laneboss-files] Refuses: Writes to Laneboss's own hook settings, "
                   "registry, org configuration, refusal catalog, records or state.")
WORKTREE_WRITES = ("refused: lanes may write only inside their recorded worktree; shared message files "
                   "require the checked message path")
INSTANCE = "L3-lane-example"
RUNNERS = ("claude", "codex")
VENDOR = '''#!/usr/bin/python3
import json
import os
from pathlib import Path
import subprocess
import sys
import time

message, calls, record = sys.argv[1:]
text = sys.stdin.read() if message == "stdin" else Path(message).read_text()
with Path(calls).open("a") as stream:
    stream.write(json.dumps({"argv": sys.argv[1:], "brief": text}) + "\\n")
Path(record).write_text("session received its actual brief\\n")
control = Path(calls).with_suffix(".ask.json")
if control.exists():
    request = json.loads(control.read_text())
    if "hook_queue" in request:
        queue = Path(request["hook_queue"])
        (queue / "ready").write_text(str(__import__("os").getpid()))
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline and not (queue / "stop").exists():
            for path in sorted(queue.glob("*.request.json")):
                request = json.loads(path.read_text())
                result = subprocess.run(request["argv"], input=request["stdin"],
                                        capture_output=True, text=True, timeout=65)
                path.with_name(path.name.replace(".request.json", ".result.json")).write_text(json.dumps({
                    "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}))
                path.unlink()
            time.sleep(0.02)
        sys.exit(0)
    environment = dict(os.environ)
    if request.get("faults") is not None:
        environment["LANEBOSS_FAULTS"] = json.dumps(request["faults"])
    result = subprocess.run(request["argv"], input=request.get("stdin"), env=environment,
                            capture_output=True, text=True, timeout=65)
    Path(calls).with_suffix(".ask-result.json").write_text(json.dumps({
        "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}))
    if result.returncode != request.get("expected_exit", 0):
        sys.exit(result.returncode or 1)
print(text, end="")
'''
JUDGE = '''import json
import re
import sys
import time

control = json.load(open(sys.argv[1]))
request = json.loads(sys.stdin.readline())
with open(sys.argv[2], "a") as log:
    log.write(json.dumps(request) + "\\n")
mode = control.get("mode", "answer")
if mode == "slow":
    time.sleep(5)
elif mode == "timeout":
    time.sleep(70)
if mode == "fail":
    sys.stderr.write("the stand-in judge is down\\n")
    sys.exit(1)
if mode == "garbage":
    print("this is not an answer")
    sys.exit(0)

def probability(texts):
    value = control.get("default", 0.0)
    for rule in control.get("rules", []):
        if rule["question"] == request["question"] and all(text in texts.get(name, "") for name, text in rule["contains"].items()):
            return rule["probability"], rule.get("command", "none")
    return value, "none"

if request.get("kind") == "typed":
    answers = {}
    for identifier, question in request["questions"].items():
        instructions = question["instructions"]
        d = re.search(r"decisions\\[(\\d+)\\]", instructions)
        w = re.search(r"texts\\[(\\d+)\\]", instructions)
        if question["type"] != "noul" or not d or not w or set(question["criteria"]) != {"true", "false"}:
            raise RuntimeError("the complete binary comparison must be in instructions and criteria")
        state = request["state"]
        texts = {"decision": state["decisions"][int(d[1])],
                 "action": state["texts"][int(w[1])], "question": state["texts"][int(w[1])]}
        p, _ = probability(texts)
        answers[identifier] = {"type": "noul", "noul": p}
    if mode == "partial":
        answers.pop(next(iter(answers)))
    if mode == "legacy-shape":
        print(json.dumps({"probability": 0.99, "model": "stand-in-1", "request": None}))
        sys.exit(0)
    print(json.dumps({"model": "jev-1.13.0", "answers": answers,
                      "usage": {"input_tokens": len(json.dumps(request)), "output_tokens": 20 * len(answers)}}))
    sys.exit(0)
if request["question"] == "laneboss.jobs":
    if request.get("kind") != "laneboss-jobs" or "shell_command" not in request.get("state", {}):
        raise RuntimeError("the catalog request lost the real shell input")
    criteria = request["questions"]["command"]["criteria"]
    if set(criteria) != {row["path"] for row in request["state"]["laneboss_jobs"]} | {"none"}:
        raise RuntimeError("the choices differ from the generated catalog")
    p, choice = probability({"action": request["state"]["shell_command"]})
    n = len(criteria)
    top = (0.91 * (n - 1) + 1) / n
    distribution = {name: top if name == choice else (1 - top) / (n - 1) for name in criteria}
    print(json.dumps({"model": "jev-1.13.0", "answers": {
        "owned": {"type": "noul", "noul": p},
        "command": {"type": "choice", "choice": choice, "probabilities": distribution, "confidence": 0.91}},
        "usage": {"input_tokens": len(json.dumps(request)), "output_tokens": 40}}))
    sys.exit(0)
p, _ = probability(request["subject"])
print(json.dumps({"probability": p, "model": "stand-in-1", "request": None}))
'''


def setUpModule():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("decision guide rows require the designated disposable Linux machine")
    global RELEASE, FAULTS, EVIDENCE
    names = ("LANEBOSS_GUIDE_BINARY", "LANEBOSS_GUIDE_FAULTS_BINARY", "LANEBOSS_GUIDE_EVIDENCE")
    if any(not os.environ.get(name) for name in names):
        raise RuntimeError("check-decision-guide.sh must supply both builds and an evidence directory")
    RELEASE = Path(os.environ[names[0]]).resolve(strict=True)
    FAULTS = Path(os.environ[names[1]]).resolve(strict=True)
    EVIDENCE = Path(os.environ[names[2]]).resolve(strict=True)
    if not EVIDENCE.is_dir() or not all(os.access(binary, os.X_OK) for binary in (RELEASE, FAULTS)):
        raise RuntimeError("decision guide prerequisites are incomplete")
    for name in ("git", "tmux"):
        if shutil.which(name) is None:
            raise RuntimeError("decision guide rows need " + name)


def token(prefix):
    return prefix + "-" + uuid.uuid4().hex[:10]


class Decision:
    """One recorded decision as a row wrote it: its id, the verbatim answer, the question and a unique marker."""

    def __init__(self, identifier, marker, question, answer, project, level):
        self.id, self.marker, self.question, self.answer = identifier, marker, question, answer
        self.project, self.level = project, level


class GuideBase(unittest.TestCase):
    binary_override = None
    fault_point = None

    def write_rule_source(self, path, text):
        write_rule_source(self, path, text)

    def setUp(self):
        self.directory = EVIDENCE / (self._testMethodName + "-" + uuid.uuid4().hex[:12])
        self.directory.mkdir()
        self.home = self.directory / "home"
        self.home.mkdir()
        self.binary = self.binary_override or RELEASE
        self.marker = self.directory / "mutant-reached"
        self.env = {"HOME": str(self.home), "PATH": os.defpath, "LC_ALL": "C",
                    "LANEBOSS_TEST_CLAIMS_DIR": str(self.directory / "claims")}
        if self.fault_point:
            self.env["LANEBOSS_FAULTS"] = json.dumps({"point": self.fault_point, "marker": str(self.marker)})
        self.counter = 0
        self.clock = 0
        self.lanes = []
        self.org = self.directory / "org"
        self.laneboss = self.org / ".laneboss"
        self.services = self.laneboss / "shared" / "services"
        self.store = self.services / "decisions.sqlite"
        self.guide_file = self.services / "guide.toml"
        self.bin_dir = self.directory / "bin"
        self.bin_dir.mkdir()
        self.records = self.directory / "records"
        self.records.mkdir()
        self.calls_file = self.directory / "vendor-calls.jsonl"
        self.driver = "guide-agent-" + uuid.uuid4().hex[:12]
        (self.bin_dir / self.driver).write_text(VENDOR)
        (self.bin_dir / self.driver).chmod(0o755)
        self.judge_path = self.directory / "stand_in_judge.py"
        self.judge_path.write_text(JUDGE)
        self.control_path = self.directory / "judge-control.json"
        self.requests_path = self.directory / "judge-requests.jsonl"
        self.judge()
        self.cli_json("org", "init", self.org, "--name", "guide-demo")
        # These rows exercise the former policy, now explicitly owner-authored.
        for layer, identifiers in (
            ("shared", ("declared-writes", "secret-files")),
            ("L3", ("worktree-writes", "no-push")),
            ("L4", ("no-push",)),
            ("L5", ("supervisor-writes",)),
            ("L6", ("supervisor-writes",)),
        ):
            install_hook_rules(self, self.org, layer, *identifiers)
        self.cli_json("org", "roles", "init", self.org)  # 1.0.0 b1: org init no longer copies the role library
        self.set_hook_mode("strict")
        for role, level in (("executor", 3), ("supervisor", 4), ("top", 5)):
            source = self.laneboss / ("L" + str(level)) / "roles" / (role + ".toml")
            source.write_text("drivers = " + json.dumps([self.driver]) + "\n")
        self.prepare_instance()
        self.cli_json("decisions", "init", "--db", self.store)
        self.config_dir = self.home / ".config" / "laneboss" / "configs" / "guide-demo"
        (self.config_dir / "projects").mkdir(parents=True)
        for project in ("demo", "other"):
            (self.config_dir / "projects" / (project + ".toml")).write_text('schema_version = 1\nname = "' + project + '"\n')
        self.write_config()
        self.brief_file = self.directory / "brief.md"
        self.task = "# Assigned task\n\nRead canary " + uuid.uuid4().hex[:16] + ".\n"
        self.brief_file.write_text(self.task)
        self.cli_json("org", "render", self.org)
        self.cli_json("start", "--config", "guide-demo", "--role", "top", "--format", "json")

    def tearDown(self):
        # A failed row must still retain its lane state and collect its processes.
        # Stop only a recorded live lane; never kill by a command-line pattern.
        for lane in self.lanes:
            status = self.cli("lane", "status", "--config", "guide-demo", "--lane", lane)
            if status.returncode != 0:
                raise AssertionError("the retained lane status could not be read: " + status.stderr)
            row = json.loads(status.stdout)
            if row["running"] or row["live"]["survivors"]:
                stopped = self.cli_json("lane", "stop", "--config", "guide-demo", "--lane", lane)
                self.assertEqual(stopped.get("survivors"), 0, "cleanup must leave no survivor")

    def cli(self, *args, extra_env=None, stdin=None):
        self.counter += 1
        command = [str(self.binary), *(str(arg) for arg in args)]
        env = dict(self.env)
        if extra_env:
            env.update(extra_env)
        result = subprocess.run(command, cwd=self.directory, env=env, text=True, input=stdin,
                                capture_output=True, timeout=120)
        stem = self.directory / ("command-" + str(self.counter))
        stem.with_suffix(".json").write_text(json.dumps({"argv": command, "exit_code": result.returncode}))
        stem.with_suffix(".stdout").write_text(result.stdout)
        stem.with_suffix(".stderr").write_text(result.stderr)
        if stdin is not None:
            stem.with_suffix(".stdin").write_text(stdin)
        if result.returncode == 0 and len(args) >= 3 and args[:2] in (("org", "render"), ("org", "validate")):
            source = Path(args[2]) / ".laneboss/org.toml"
            if tomllib.loads(source.read_text(encoding="utf-8")).get("hooks", {}).get("mode") == "strict":
                assert_hook_deprecation(self, result)
        return result

    def cli_json(self, *args, **kwargs):
        result = self.cli(*args, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def write_config(self):
        # This receipt carries the session placeholder; text scanning reads only the launcher's run log.
        record = str(self.records / "{session}.log")
        command = [str(self.bin_dir / self.driver), "stdin", str(self.calls_file), record]
        judge = [sys.executable, str(self.judge_path), str(self.control_path), str(self.requests_path)]
        text = (
            'schema_version = 1\nname = "guide-demo"\norg_dir = ' + json.dumps(str(self.org)) + '\n'
            '[lanes]\nbudget_minutes = 1\nquiet_seconds = 1\nstop_grace_seconds = 1\n'
            '[runners.agent]\ncommand = ' + json.dumps(command) + '\nresume = ' + json.dumps(command) + '\n'
            'accounts = []\nquiet_seconds = 1\nprompt = "stdin"\n'
            'records = [{format = "text", paths = ["{log}"]}]\n'
            '[judges.guard]\ndescription = "stand-in for the TypeSafe judge"\ncommand = ' + json.dumps(judge) + '\n'
            'timeout_seconds = 10\n'
            '[supervisors.top]\nlevel = 6\nrunner = "agent"\n'
        )
        (self.config_dir / "config.toml").write_text(text)

    def set_hook_mode(self, mode, entry=None):
        source = self.laneboss / "org.toml"
        text = source.read_text()
        text, count = re.subn(r'(?m)^mode = "(?:blacklist|strict)"$', 'mode = "' + mode + '"', text, count=1)
        self.assertEqual(count, 1, "the active hooks mode source line must be edited")
        if entry is not None:
            text += "\n[[hooks.blacklist]]\n"
            for key, value in entry.items():
                text += key + " = " + json.dumps(value) + "\n"
        source.write_text(text)
        self.cli_json("org", "render", self.org)

    def add_legacy_rule(self, identifier, kind, values, deny_paths=None, level_source=False):
        """Add one instance-local or level legacy rule and its refusal description.

        Hook-only rows may use inline instance rules. A row that renders the
        versioned org uses the legacy level source accepted by the 0.7.0 schema;
        since org init seeds no rule files (R52), an absent level source is
        created with only its schema line.
        """
        directory = self.instance_dir
        if level_source:
            level = tomllib.loads((directory / "instance.toml").read_text())["level"]
            directory = directory.parent.parent / ("L" + str(level))
            source = directory / "hooks" / "rules.toml"
            if not source.exists():
                self.write_rule_source(source, "schema_version = 1\n")
            text = source.read_text()
            if tomllib.loads(text).get("rules") == []:
                text, count = re.subn(r"(?m)^rules\s*=\s*\[\][ \t]*\n?", "", text)
                self.assertEqual(count, 1, "the empty level rule array must be replaced before appending a rule")
            heading = "rules"
        else:
            source = directory / "instance.toml"
            text = source.read_text()
            heading = "hooks.rules"
        text += "\n[[" + heading + "]]\nid = " + json.dumps(identifier) + "\nkind = " + json.dumps(kind) + "\n"
        if kind == "write-scope":
            text += "paths = " + json.dumps(values) + "\n"
            text += "deny_paths = " + json.dumps(deny_paths or []) + "\n"
        else:
            key = "patterns" if kind == "command-pattern" else "tools" if kind == "tool-allowlist" else "names"
            text += key + " = " + json.dumps(values) + "\n"
        if level_source:
            self.write_rule_source(source, text)
        else:
            source.write_text(text)
        refusal_dir = directory / "refusals"
        refusal_dir.mkdir(exist_ok=True)
        refusal = refusal_dir / (identifier + ".toml")
        self.write_rule_source(refusal,
            "id = " + json.dumps(identifier) + "\n"
            "refuses = " + json.dumps("Legacy row " + identifier + " must refuse its matching action.") + "\n"
            "why = " + json.dumps("The compatibility row remains an org boundary in blacklist mode.") + "\n"
            "instead = " + json.dumps("Leave the action undone and report it to the supervisor.") + "\n"
            "examples_allowed = [" + json.dumps("an unrelated action") + "]\n"
            "examples_refused = [" + json.dumps("the matching action") + "]\n\n"
            "[applies_to]\nlevels = [3]\nroles = [\"executor\"]\n"
        )

    def prepare_instance(self):
        """Give the L3 example instance one worktree; tool declarations never grant permission.
        writable_repos entries are paths relative to the org folder, as org validate requires; the hook reads the edited
        instance.toml directly, so nothing is rendered again."""
        self.worktree = self.org / "worktrees" / "guide-work"
        self.worktree.mkdir(parents=True)
        self.instance_dir = self.laneboss / "instances" / INSTANCE
        source = self.instance_dir / "instance.toml"
        text = source.read_text()
        text, repos = re.subn(r"(?m)^writable_repos\s*=.*$", 'writable_repos = ["worktrees/guide-work"]', text)
        self.assertEqual(repos, 1, "the example instance holds one writable_repos line")
        source.write_text(text)

    # The decision store and the dial's configuration

    def decide(self, words="the release process", project="demo", level=None, instance=None, kind="owner-decision",
               valid_until=None, question=None, answer=None, supersedes=None):
        """Record one decision with the CLI; the answer and the question carry one unique marker. An explicit answer
        or question may write {marker} where the marker belongs."""
        identifier, marker = token("D"), token("m")
        if answer is None:
            answer = "Decided {marker}: never skip approval for %s." % words
        if question is None:
            question = "May we skip approval for %s? ({marker})" % words
        answer, question = answer.replace("{marker}", marker), question.replace("{marker}", marker)
        self.clock += 1
        answered = datetime(2026, 10, 8, 9, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=self.clock)
        record = {
            "id": identifier, "kind": kind, "asked_at": "2026-10-08T09:00:00Z",
            "answered_at": answered.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "project": project, "area": "guide", "topics": ["guide"],
            "question": {"text": question, "background": "row"},
            "answer": {"verbatim": answer, "channel": "terminal"},
            "scope": {"applies_to": "row"}, "status": "in_force",
            "provenance": {"recorded_by": "row", "recorded_at": "2026-10-08T09:05:00Z", "sources": []},
        }
        if level is not None:
            record["level"] = level
            record["instance"] = instance or ("L" + str(level) + "-scope")
        if valid_until is not None:
            record["scope"]["valid_until"] = valid_until
        path = self.directory / (identifier + ".json")
        path.write_text(json.dumps(record))
        if supersedes is None:
            self.cli_json("decisions", "add", "--db", self.store, "--file", path)
        else:
            self.cli_json("decisions", "supersede", "--db", self.store, supersedes, "--file", path)
        return Decision(identifier, marker, question, answer, project, level)

    def guide(self, *, defaults=False, **settings):
        """Write the guide settings; a judge is always bound to this row's configuration."""
        # Decision-only rows isolate that dial; job-hook rows exercise the
        # default-on catalog separately with a noul/choice adapter.
        settings.setdefault("jobs", False)

        if not defaults:
            settings.setdefault("refuse_threshold", 0.85)
        if "judge" in settings:
            settings.setdefault("configuration", "guide-demo")
        lines = [key + " = " + json.dumps(value) for key, value in settings.items()]
        self.guide_file.write_text("\n".join(lines) + "\n")

    def judge(self, rules=(), mode="answer", default=0.0):
        self.control_path.write_text(json.dumps({"mode": mode, "default": default, "rules": list(rules)}))

    def rule(self, identifier, probability, **contains):
        return {"question": identifier, "probability": probability, "contains": contains}

    def asked(self):
        if not self.requests_path.exists():
            return []
        return [json.loads(line) for line in self.requests_path.read_text().splitlines()]

    def reset_guide(self):
        """Remove guide.toml whatever it is now: a file, a directory or nothing."""
        if self.guide_file.is_dir() and not self.guide_file.is_symlink():
            shutil.rmtree(self.guide_file)
        else:
            self.guide_file.unlink(missing_ok=True)

    def receipts(self):
        """The callback receipts of the instance: one line for each call that the hook answered."""
        path = self.instance_dir / "hooks" / "callbacks.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def widen_write_scope(self):
        """Let the instance write anywhere in the org folder, so that only the protected paths stand in the way."""
        source = self.instance_dir / "instance.toml"
        text, count = re.subn(r"(?m)^writable_repos\s*=.*$", "writable_repos = [" + json.dumps(str(self.org)) + "]",
                              source.read_text())
        self.assertEqual(count, 1)
        source.write_text(text)

    # The org hook

    def hook(self, runner, tool, tool_input, *, env=None):
        return self.hook_with(runner, tool, tool_input, extra_env=env)

    def hook_with(self, runner, tool, tool_input, pinned=None, extra_env=None, event_cwd=None, env=None):
        if env is not None:
            extra_env = env
        name = ("functions." if runner == "codex" else "") + tool
        event = {"hook_event_name": "PreToolUse", "cwd": str(event_cwd or self.worktree), "tool_name": name, "tool_input": tool_input}
        args = ["org", "hook", "--runner", runner, "--instance", pinned or self.instance_dir]
        result = self.cli(*args, extra_env=extra_env, stdin=json.dumps(event))
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        return output

    def shell(self, runner, command):
        if runner == "codex":
            return self.hook(runner, "exec_command", {"cmd": command})
        return self.hook(runner, "Bash", {"command": command})

    def shell_with_env(self, runner, command, extra_env, event_cwd=None):
        tool = "exec_command" if runner == "codex" else "Bash"
        field = "cmd" if runner == "codex" else "command"
        return self.hook_with(runner, tool, {field: command}, extra_env=extra_env, event_cwd=event_cwd)

    def policy_refusals(self, runner):
        """Retained denials and the ordinary environment-gap allowance (no refusal line)."""
        shell_tool, field = ("Bash", "command") if runner == "claude" else ("exec_command", "cmd")
        return [
            ("push", lambda: self.shell(runner, "git push origin main"),
             "[no-push] Refuses: Pushing repository changes from an executor or mini-supervisor."),
            ("write", lambda: self.hook(runner, "Write", {"file_path": str(self.directory / "outside.txt"), "content": "x"}),
             WORKTREE_WRITES),
            ("closed", lambda: self.hook(runner, shell_tool, {field: "true", "env": {"A": "b"}}),
             None),
            ("lane-write", lambda: self.recorded_hook(runner, "Write", {
                "file_path": str(self.boundary_target), "content": "x"}),
             "refused: lanes may write only inside their recorded worktree; shared message files require the checked message path"),
            ("lane-curl", lambda: self.recorded_hook(runner, shell_tool, {
                field: "curl -s http://127.0.0.1:8765/api/lanes"}),
             "refused: lanes may not request dashboard ports or send outbound messages with a raw network client"),
        ]

    def prepare_boundary_lane(self):
        """A real L3 process calls the hook; target writes pass org scope but
        must still pass its independently recorded worktree boundary."""
        source = self.instance_dir / "instance.toml"
        text, count = re.subn(r"(?m)^writable_repos\s*=.*$", 'writable_repos = ["worktrees"]', source.read_text())
        self.assertEqual(count, 1)
        source.write_text(text)
        rules = self.laneboss / "L3" / "hooks" / "rules.toml"
        text, count = re.subn(r'\n\[\[rules\]\]\n(?:(?!\n\[\[rules\]\]).)*id = "worktree-writes"(?:(?!\n\[\[rules\]\]).)*',
                             "", rules.read_text(), flags=re.S)
        self.assertEqual(count, 1, "the fixture removes only the generic worktree rule")
        self.write_rule_source(rules, text)
        self.cli_json("org", "render", self.org)
        self.boundary_target = self.org / "worktrees" / "outside-recorded-worktree.txt"
        control = self.hook("claude", "Write", {"file_path": str(self.boundary_target), "content": "x"})
        self.assertEqual(control["permissionDecision"], "allow", "the boundary target must be inside writable_repos")
        self.hook_queue = self.directory / "hook-queue"
        self.hook_queue.mkdir()
        self.calls_file.with_suffix(".ask.json").write_text(json.dumps({"hook_queue": str(self.hook_queue)}))
        self.boundary_lane, _ = self.start_lane(turns=False, worktree=self.worktree, budget=4)
        self.addCleanup(self.close_boundary_lane)
        events = self.cli("event", "tail", "--config", "guide-demo", "--lane", self.boundary_lane)
        self.assertEqual(events.returncode, 0, events.stderr)
        started = [json.loads(line) for line in events.stdout.splitlines() if json.loads(line)["kind"] == "lane.started"][-1]
        record = self.home / ".local" / "state" / "laneboss" / "guide-demo" / "lanes" / self.boundary_lane / "runs" / (started["payload"]["launch"] + ".json")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if (self.hook_queue / "ready").is_file() and record.is_file():
                tracked = json.loads(record.read_text())
                if (tracked.get("runner") or {}).get("pid") == int((self.hook_queue / "ready").read_text()):
                    return
            time.sleep(0.05)
        self.fail("the actual boundary lane did not become ready")

    def close_boundary_lane(self):
        (self.hook_queue / "stop").write_text("stop\n")

    def recorded_hook(self, runner, tool, tool_input):
        name = ("functions." if runner == "codex" else "") + tool
        event = {"hook_event_name": "PreToolUse", "cwd": str(self.worktree), "tool_name": name, "tool_input": tool_input}
        identifier = token("hook")
        request = self.hook_queue / (identifier + ".request.json")
        result_path = self.hook_queue / (identifier + ".result.json")
        request.write_text(json.dumps({"argv": [str(self.binary), "org", "hook", "--runner", runner,
                                                 "--instance", str(self.instance_dir)], "stdin": json.dumps(event)}))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if result_path.is_file():
                result = json.loads(result_path.read_text())
                self.assertEqual(result["exit_code"], 0, result["stderr"])
                return json.loads(result["stdout"])["hookSpecificOutput"]
            time.sleep(0.02)
        self.fail("the recorded lane did not return its hook result")

    def band(self, output):
        """The band an output shows: refuse (a denial), warn (an allowance that carries context) or nothing."""
        if output["permissionDecision"] == "deny":
            return "refuse"
        if output.get("additionalContext"):
            return "warn"
        self.assertEqual(output["permissionDecisionReason"], PLAIN_ALLOW)
        return "nothing"

    # Lanes

    def start_lane(self, level=3, role="executor", turns=True, project="demo", worktree=None, budget=1):
        lane = "gd-" + uuid.uuid4().hex[:12]
        work = worktree or self.directory / (lane + "-work")
        if worktree is None:
            work.mkdir()
        args = ["lane", "start", "--config", "guide-demo", "--lane", lane, "--brief", self.brief_file,
                "--worktree", work, "--runner", "agent", "--model", "example-model-medium-1",
                "--budget", budget, "--level", level, "--role", role]
        if project:
            args += ["--project", project]
        if turns:
            args.append("--turns")
        result = self.cli(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.lanes.append(lane)
        return lane, json.loads(result.stdout)

    def calls(self):
        return [json.loads(line) for line in self.calls_file.read_text().splitlines()] if self.calls_file.exists() else []

    def finished(self, lane, run=1, since=0):
        result = self.cli("event", "tail", "--config", "guide-demo", "--lane", lane,
                          "--since", since, "--follow", "--until", "lane.ended")
        self.assertEqual(result.returncode, 0, result.stderr)
        ended = [json.loads(line) for line in result.stdout.splitlines() if json.loads(line)["kind"] == "lane.ended"]
        self.assertEqual(len(ended), 1, "the new run must have one observed end")
        payload = ended[0]["payload"]
        self.assertEqual((payload["run"], payload["reason"], payload["exit_code"], payload["survivors"]),
                         (run, "exit", 0, 0), "the actual vendor run must end successfully")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            row = self.cli_json("lane", "status", "--config", "guide-demo", "--lane", lane)
            live = row["live"]
            if not row["running"] and not live["supervisor"]["alive"] and not live["session_alive"]:
                self.assertEqual((live["survivors"], live["pending_events"], live["refused_events"]), (0, 0, 0))
                return row
            time.sleep(1)
        self.fail("the actual lane worker did not become quiescent")

    def message(self, heading):
        path = self.directory / (token("message") + ".md")
        text = "# " + heading + "\n\n" + uuid.uuid4().hex[:16] + "\n"
        path.write_text(text)
        return path, text


class GuideRows(GuideBase):
    def test_g1_brief_carries_decisions(self):
        """G1: fails if a brief lacks the section or a decision that applies to its project and level, carries one that
        does not (another project or level, superseded, expired, not a decision), puts the section after the task, or
        changes the bytes of the brief it was given."""
        everywhere = self.decide("the shared checklist")
        at_l3 = self.decide("the level three queue", level=3)
        at_l5 = self.decide("the level five budget", level=5)
        elsewhere = self.decide("another project", project="other")
        old = self.decide("the old rule")
        new = self.decide("the new rule", supersedes=old.id)
        expired = self.decide("the lapsed rule", valid_until="2020-01-01T00:00:00Z")
        ledger = self.decide("a ledger line", kind="ledger")
        lane, started = self.start_lane(level=3, role="executor")
        self.finished(lane)
        text = Path(started["brief"]["path"]).read_text()
        self.assertEqual(self.calls()[0]["brief"], text, "G1 the vendor must receive the rendered brief")
        self.assertIn(HEADING, text, "G1 the brief must carry the decision section")
        self.assertLess(text.index("## Your role: executor (L3)"), text.index(HEADING))
        self.assertLess(text.index(HEADING), text.index("## Your task"), "G1 the section must come before the task")
        self.assertIn("## Your task\n\n" + self.task, text, "G1 the brief's own bytes must stay as written")
        section = text[text.index(HEADING):text.index("## Your task")]
        for decision in (everywhere, at_l3, new):
            for part in (decision.id, decision.answer, decision.question):
                self.assertIn(part, section, "G1 a decision that applies must be quoted whole in the section")
        for decision in (at_l5, elsewhere, old, expired, ledger):
            self.assertNotIn(decision.id, text, "G1 a decision that does not apply must not be in the brief")
            self.assertNotIn(decision.marker, text, "G1 a decision that does not apply must not be in the brief")
        top, started_top = self.start_lane(level=5, role="top")
        self.finished(top)
        text_top = Path(started_top["brief"]["path"]).read_text()
        section_top = text_top[text_top.index(HEADING):text_top.index("## Your task")]
        for decision in (everywhere, at_l5, new):
            self.assertIn(decision.id, section_top, "G1 the level five lane must carry what applies at its level")
        for decision in (at_l3, elsewhere, old, expired, ledger):
            self.assertNotIn(decision.id, text_top, "G1 the level five lane must not carry another level's decision")
        self.assertTrue(self.cli_json("state", "verify", "--config", "guide-demo")["ok"])

    def test_g1_a_lane_without_a_project(self):
        """G1: fails if a lane with no project gets no section, gets only one project's decisions when the settings name
        none, or ignores the projects setting."""
        demo = self.decide("the demo rule")
        other = self.decide("the other rule", project="other")
        lane, started = self.start_lane(project=None)
        self.finished(lane)
        text = Path(started["brief"]["path"]).read_text()
        self.assertIn(HEADING, text, "G1 a lane with no project must carry the decision section")
        for decision in (demo, other):
            self.assertIn(decision.id, text, "G1 a lane with no project carries the decisions of every project")
        self.guide(projects=["demo"])
        narrowed, started_narrow = self.start_lane(project=None)
        self.finished(narrowed)
        narrow_text = Path(started_narrow["brief"]["path"]).read_text()
        self.assertIn(demo.id, narrow_text)
        self.assertNotIn(other.id, narrow_text, "G1 the projects setting must narrow a lane with no project")


    def test_g2_follow_up_and_turn(self):
        """G2: fails if a new turn or a follow-up message is composed without the section, or with the decisions that
        were in force when the lane started instead of those in force when the message is composed."""
        self.decide("the first rule")
        lane, _ = self.start_lane(turns=True)
        row = self.finished(lane)
        late_turn = self.decide("the rule recorded between two turns")
        mail, mail_text = self.message("Mail")
        self.cli_json("lane", "send", "--config", "guide-demo", "--lane", lane, "--file", mail)
        turn = self.cli_json("lane", "turn", "--config", "guide-demo", "--lane", lane)
        self.assertTrue(turn["started"])
        self.finished(lane, 2, row["last_seq"])
        turn_brief = self.calls()[1]["brief"]
        self.assertIn(HEADING, turn_brief, "G2 a new turn message must carry the decision section")
        self.assertIn(late_turn.answer, turn_brief, "G2 the turn must carry a decision recorded after the lane started")
        self.assertIn(mail_text, turn_brief)
        self.assertLess(turn_brief.index(HEADING), turn_brief.index("## Your task"))
        second, _ = self.start_lane(turns=False)
        row_second = self.finished(second)
        late_resume = self.decide("the rule recorded before the follow-up")
        follow, follow_text = self.message("Follow-up")
        self.cli_json("lane", "resume", "--config", "guide-demo", "--lane", second, "--message", follow)
        self.finished(second, 2, row_second["last_seq"])
        resume_brief = self.calls()[3]["brief"]
        self.assertIn(HEADING, resume_brief, "G2 a follow-up message must carry the decision section")
        self.assertIn(late_resume.answer, resume_brief, "G2 the follow-up must carry a decision recorded after the start")
        self.assertIn(follow_text, resume_brief)

    def test_g3_dial_bands(self):
        """High and uncertain Nouls warn; low probabilities preserve the baseline.
        One complete typed batch and one egress pair are required per call."""
        self.guide(judge="guard")
        decision = self.decide("the production release")
        high, middle, low = token("act"), token("act"), token("act")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=decision.marker, action=high),
                          self.rule(CONFLICTS, 0.62, decision=decision.marker, action=middle)], default=0.07)
        expected = []
        for runner in RUNNERS:
            for marker, p in ((high, 0.93), (middle, 0.62), (low, 0.07)):
                output = self.shell(runner, "printf '%s' " + marker)
                self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
                context = output.get("additionalContext", "")
                if p >= 0.85:
                    self.assertIn(decision.id, context, "G3 high probability must warn")
                    self.assertIn(decision.answer, context)
                elif p >= 0.5:
                    self.assertIn(decision.id, context, "G3 the warn band must warn")
                    self.assertIn(decision.answer, context)
                else:
                    self.assertEqual(context, "", "G3 below warn must add no context")
                expected.append((marker, p))
        asks = self.asked()
        self.assertEqual(len(asks), len(expected), "G3 one typed batch per call")
        for ask, (marker, _) in zip(asks, expected):
            self.assertEqual((ask["question"], ask["kind"]), (CONFLICTS, "typed"))
            self.assertIn(decision.marker, "\n".join(ask["state"]["decisions"]))
            self.assertIn(marker, "\n".join(ask["state"]["texts"]))
            self.assertEqual(len(ask["questions"]), 1)
            q = next(iter(ask["questions"].values()))
            self.assertIn(chr(96) + "decisions[0]" + chr(96), q["instructions"])
            self.assertIn(chr(96) + "texts[0]" + chr(96), q["instructions"])
            self.assertEqual(set(q["criteria"]), {"true", "false"})
        lines = [json.loads(line) for line in self.cli("judge", "egress", "--config", "guide-demo").stdout.splitlines()]
        sent = [line for line in lines if line["event"] == "sent"]
        done = [line for line in lines if line["event"] == "outcome"]
        self.assertEqual([(line["judge"], line["question"]) for line in sent], [("guard", CONFLICTS)] * len(expected))
        self.assertEqual(sorted(p for line in done for p in line["probabilities"].values()), sorted(p for _, p in expected))

    def test_g3_official_shape_is_required(self):
        """A partial answer or the old scalar shape cannot clear a batch."""
        first, second = self.decide("the first comparison"), self.decide("the second comparison")
        self.guide(judge="guard", max_decisions=2)
        for mode in ("partial", "legacy-shape"):
            self.judge(mode=mode, default=0.01)
            output = self.shell("claude", "printf '%s' " + token("case"))
            self.assertEqual(output["permissionDecision"], "allow")
            context = output.get("additionalContext", "")
            self.assertIn(first.id, context)
            self.assertIn(second.id, context)
            self.assertEqual({entry["outcome"] for entry in self.receipts()[-1]["guard"]["decisions"]}, {"output"})
        self.judge(default=0.01)
        output = self.shell("claude", "printf '%s' " + token("control"))
        self.assertEqual((output["permissionDecision"], output.get("additionalContext", "")), ("allow", ""))

    def test_g3_complete_decision_text(self):
        """The comparison must include a decision's tail or explicitly report a cut."""
        tail, action = token("tail"), token("act")
        decision = self.decide(answer="Decided {marker}: " + "lorem " * 300 + tail, question="Question {marker}?")
        self.guide(judge="guard")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=tail, action=action)])
        output = self.shell("claude", "printf '%s' " + action)
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn(decision.id, output.get("additionalContext", ""), "G3 silently shortened decisions cannot clear a comparison")
        self.assertIn(tail, "\n".join(self.asked()[-1]["state"]["decisions"]))
        self.assertEqual(self.receipts()[-1]["guard"]["decisions"][0]["outcome"], "answered")
        self.requests_path.unlink()
        oversized = self.decide(answer="Decided {marker}: " + "lorem " * 800 + token("tail"), question="Question {marker}?")
        self.guide(judge="guard", max_decisions=2)
        output = self.shell("claude", "printf '%s' " + action)
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn(oversized.id, output.get("additionalContext", ""))
        outcomes = {entry["decision"]: entry for entry in self.receipts()[-1]["guard"]["decisions"]}
        self.assertEqual(outcomes[oversized.id]["outcome"], "cut")
        self.assertEqual(outcomes[decision.id]["outcome"], "answered",
                         "G3 one oversized decision must not blind the ordinary decision")
        self.assertEqual(outcomes[decision.id]["score"], 0.93)
        self.assertEqual(len(self.asked()), 1, "G3 the remaining decision still uses one batch")
        sent = "\n".join(self.asked()[0]["state"]["decisions"])
        self.assertIn(decision.id, sent)
        self.assertIn(tail, sent)
        self.assertNotIn(oversized.id, sent)
        self.assertEqual(len(self.asked()[0]["questions"]), 1)
        self.requests_path.unlink()
        only_long = self.decide(answer="Decided {marker}: " + "lorem " * 800, question="Question {marker}?", project="other")
        self.guide(judge="guard", projects=["other"])
        unscored = self.shell("claude", "printf '%s' " + action)
        self.assertEqual(unscored["permissionDecision"], "allow")
        self.assertIn(only_long.id, unscored.get("additionalContext", ""))
        self.assertEqual(self.receipts()[-1]["guard"]["decisions"][0]["outcome"], "cut")
        self.assertEqual(self.asked(), [], "G3 an entirely unscoreable selection must ask nobody")

    def test_g3_credential_decision_isolated(self):
        """One synthetic credential-shaped decision cannot blind a clean comparison."""
        action = token("act")
        ordinary = self.decide(answer="Decided {marker}: review the requested change.", question="Question {marker}?")
        credential = "gh" + "p_" + "a1B2c3D4e5" * 4
        hidden = self.decide(answer="Decided {marker}: rotate the example " + credential, question="Question {marker}?")
        self.guide(judge="guard", max_decisions=2)
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=ordinary.marker, action=action)])
        for runner in RUNNERS:
            self.requests_path.unlink(missing_ok=True)
            output = self.shell(runner, "printf '%s' " + action)
            self.assertEqual(output["permissionDecision"], "allow")
            outcomes = {entry["decision"]: entry for entry in self.receipts()[-1]["guard"]["decisions"]}
            self.assertEqual(outcomes[hidden.id]["outcome"], "withheld")
            self.assertEqual(outcomes[ordinary.id]["outcome"], "answered",
                             "G3 one credential-shaped decision must not blind the ordinary decision")
            self.assertEqual(outcomes[ordinary.id]["score"], 0.93)
            context = output.get("additionalContext", "")
            self.assertIn(hidden.id, context)
            self.assertIn(ordinary.id, context)
            self.assertNotIn(credential, context)
            self.assertEqual(len(self.asked()), 1)
            sent = json.dumps(self.asked()[0])
            self.assertIn(ordinary.id, sent)
            self.assertNotIn(hidden.id, sent)
            self.assertNotIn(credential, sent)
            self.assertEqual(len(self.asked()[0]["questions"]), 1)

    def test_g3_asks_are_bounded_and_ranked(self):
        """G3: fails if the number of decisions asked about ignores max_decisions, or if the decisions asked about are
        not the ones that share words with the call."""
        marmot = self.decide(answer="Decided {marker}: keep the marmot rotation.")
        quartz = self.decide(answer="Decided {marker}: keep the quartz rotation.")
        velvet = self.decide(answer="Decided {marker}: keep the velvet rotation.")
        lantern = self.decide(answer="Decided {marker}: keep the lantern rotation.")
        related = {quartz.marker, lantern.marker}
        everyone = {marmot.marker, quartz.marker, velvet.marker, lantern.marker}
        command = "printf '%s' 'quartz lantern " + token("note") + "'"

        def asked_markers():
            self.requests_path.unlink(missing_ok=True)
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "allow")
            found = set()
            for ask in self.asked():
                text = "\n".join(ask["state"]["decisions"])
                found |= {marker for marker in everyone if marker in text}
            self.assertEqual(len(self.asked()), 1, "G3 all candidates share one request")
            self.assertEqual(len(self.asked()[0]["questions"]), len(found))
            return found, len(self.asked()), output.get("additionalContext", "")

        self.guide(judge="guard", max_decisions=2)
        found, count, context = asked_markers()
        self.assertEqual((found, count), (related, 1), "G3 two decisions asked, the two that share words with the call")
        for left_out in (marmot, velvet):
            self.assertIn(left_out.id, context, "G3 a decision that max_decisions left out must be reported to the agent")
        for judged in (quartz, lantern):
            self.assertNotIn(judged.id, context, "G3 a decision that was judged and found clear is not reported")
        self.guide(judge="guard", max_decisions=1)
        found, count, context = asked_markers()
        self.assertEqual(count, 1, "G3 max_decisions must bound the asks")
        self.assertTrue(found <= related, "G3 the one decision asked must share words with the call")
        self.assertEqual(sum(decision.id in context for decision in (marmot, quartz, velvet, lantern)), 3,
                         "G3 the three decisions that were left out must be reported")
        self.guide(judge="guard", max_decisions=4)
        found, count, context = asked_markers()
        self.assertEqual((found, count), (everyone, 1), "G3 four decisions asked when four are allowed")
        self.assertEqual(context, "", "G3 with every decision judged and clear the call carries no warning")

    def test_g4_thresholds_move_a_case(self):
        """G4: fails if the bands come from constants instead of the configured thresholds: the same score of 0.7 must
        fall in the band that each pair of thresholds gives, inclusive at both thresholds."""
        decision = self.decide("the production release")
        action = token("act")
        self.judge(rules=[self.rule(CONFLICTS, 0.7, decision=decision.marker, action=action)])
        cases = (
            ({"warn_threshold": 0.5, "refuse_threshold": 0.85}, "warn"),
            ({"warn_threshold": 0.5, "refuse_threshold": 0.65}, "warn"),
            ({"warn_threshold": 0.8, "refuse_threshold": 0.9}, "nothing"),
            ({"warn_threshold": 0.4, "refuse_threshold": 0.7}, "warn"),
            ({"warn_threshold": 0.7, "refuse_threshold": 0.9}, "warn"),
            ({"warn_threshold": 0.71, "refuse_threshold": 0.9}, "nothing"),
            ({}, "warn"),
        )
        for settings, band in cases:
            self.guide(judge="guard", **settings)
            output = self.shell("claude", "printf '%s' " + action)
            self.assertEqual(self.band(output), band, "G4 thresholds %r must put the score 0.7 in band %s" % (settings, band))
        self.assertEqual(len(self.asked()), len(cases))

    def test_g5_no_answer_is_explicit(self):
        """G5: fails if a judge that gives no answer or a judge that the configuration lacks lets a call through silently:
        the default is a warning that names the decision and says the call was not scored, and legacy
        `unavailable = "refuse"` remains warn-only. Invalid guide.toml warns by default with config invalid: FIELD and
        a receipt. With no judge named, valid settings add a warn-only notice."""
        decision = self.decide("the production release")
        action = token("act")
        command = "printf '%s' " + action
        for mode in ("fail", "garbage"):
            self.guide(judge="guard")
            self.judge(mode=mode)
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "allow", "G5 the default is warn-only")
            context = output.get("additionalContext", "")
            self.assertIn(decision.id, context, "G5 an unavailable judge must still put the decision in front of the agent")
            self.assertIn(decision.answer, context)
            self.assertIn("not scored", context.lower(), "G5 the warning must say the call was not scored")
        self.assertEqual(len(self.asked()), 2, "G5 the judge was asked in both cases")
        self.guide(judge="guard", unavailable="refuse")
        self.judge(mode="fail")
        denied = self.shell("claude", command)
        self.assertEqual(denied["permissionDecision"], "allow", "G5 legacy unavailable=refuse must still warn")
        self.assertIn(decision.id, denied.get("additionalContext", ""))
        self.assertIn("not scored", denied.get("additionalContext", "").lower())
        before = len(self.asked())
        self.guide()
        notice = self.shell("claude", command)
        self.assertEqual(notice["permissionDecision"], "allow", "G5 with no judge configured the hook never refuses")
        self.assertIn(decision.id, notice.get("additionalContext", ""),
                      "G5 with no judge configured the notice lists the decisions that apply")
        self.assertEqual(len(self.asked()), before, "G5 with no judge configured nobody is asked")
        self.guide(judge="nobody-is-called-this")
        unknown = self.shell("claude", command)
        self.assertIn(decision.id, unknown.get("additionalContext", ""), "G5 a judge the configuration lacks must still warn")
        for settings in ({"judge": "guard", "warn_threshold": 0.9, "refuse_threshold": 0.5},
                         {"judge": "guard", "refuse_treshold": 0.9},
                         {"judge": "guard", "unavailable": "ignore"},
                         {"judge": "guard", "refuse_threshold": "high"},
                         {"judge": "guard", "jobs_refuse_threshold": "high"},
                         {"judge": "guard", "jobs_refuse_threshold": -0.1},
                         {"judge": "guard", "jobs_refuse_threshold": 1.1},
                         {"judge": "guard", "jobs_refuse_threshold": 0.2}):
            self.guide(**settings)
            before = len(self.asked())
            bad = self.shell("claude", command)
            expected = "allow"
            self.assertEqual(bad["permissionDecision"], expected, "G5 invalid guide settings must honour the unavailable policy")
            self.assertEqual(len(self.asked()), before, "G5 a guide.toml that cannot be used asks nobody")
            guard = self.receipts()[-1].get("guard", {})
            self.assertEqual(guard.get("band"), "settings-error", "G5 the receipt must say that guide.toml could not be used")
            self.assertIn("guide.toml", guard.get("error", ""), "G5 the receipt names the file")
            notice = bad["permissionDecisionReason"] if expected == "deny" else bad.get("additionalContext", "")
            self.assertIn("config invalid: " + guard["field"], notice, "G5 the invalid field must be visible to the agent")
            if expected == "allow":
                self.assertEqual(bad["permissionDecisionReason"], PLAIN_ALLOW)
                self.assertIn("Warning", notice)
            else:
                self.assertNotIn("additionalContext", bad)
        self.guide(judge="guard", refuse_treshold=0.9)
        self.shell("claude", command)
        self.assertIn("refuse_treshold", self.receipts()[-1]["guard"]["error"], "G5 an unknown key must be named in the receipt")

    def turn_target(self):
        lane, _ = self.start_lane(turns=True)
        self.finished(lane)
        return lane

    def send(self, lane, text, *flags, sender=None, env=None):
        path = self.directory / (token("question") + ".md")
        path.write_text(text)
        sender_flags = ["--from", sender] if sender is not None else []
        return self.cli("lane", "send", "--config", "guide-demo", "--lane", lane, *sender_flags, "--file", path, *flags,
                        extra_env=env)

    def runner_question(self, text, *, target=None, project="demo", ask=True, level=3, role="executor", expected_exit=0,
                        fault_marker=None):
        """Ask from an actual lane process, preserving the caller identity gate.
        The driver invokes the supplied binary; the row reads its exact result."""
        question = self.directory / (token("runner-question") + ".md")
        question.write_text(text)
        argv = [str(self.binary)]
        if target is None:
            argv += ["report", "--config", "guide-demo", "--file", str(question)]
        else:
            argv += ["lane", "send", "--config", "guide-demo", "--lane", target, "--file", str(question)]
        if ask:
            argv.append("--ask")
        control = self.calls_file.with_suffix(".ask.json")
        request = {"argv": argv, "expected_exit": expected_exit}
        # Runner launches intentionally filter LANEBOSS_FAULTS. Carry only
        # this test instrumentation through the private request file so the
        # actual answering subprocess reaches the requested mutation.
        if self.fault_point:
            request["faults"] = {"point": self.fault_point, "marker": str(fault_marker or self.marker)}
        control.write_text(json.dumps(request))
        lane, _ = self.start_lane(turns=False, project=project, level=level, role=role)
        self.finished(lane)
        result = json.loads(self.calls_file.with_suffix(".ask-result.json").read_text())
        self.assertEqual(result["exit_code"], expected_exit, result["stderr"])
        control.unlink()
        if expected_exit != 0:
            return lane, result
        return lane, [json.loads(line) for line in result["stdout"].splitlines()]

    def waiting(self, lane):
        return self.cli_json("lane", "status", "--config", "guide-demo", "--lane", lane)["mail"]["waiting"]

    def test_g6_decided_question(self):
        """G6: fails if a question that a recorded decision of the lane's project already answers is stored as new mail
        instead of being answered from the record, if a question that is not decided or is decided for another project is
        held back, if the record is consulted without `--ask`, or if a judge's score is not read the way the thresholds
        say (at or above refuse: answered; between the thresholds: sent with the decision listed; below: sent)."""
        lane = self.turn_target()
        self.guide(judge="guard")
        decided = self.decide("the release notes", question="Should the release notes be written in " + token("lang") + "?")
        other = self.decide("another project", project="other")
        asked = self.send(lane, "  " + decided.question.upper().rstrip("?") + "  \n", "--ask")
        self.assertEqual(asked.returncode, 0, asked.stderr)
        result = json.loads(asked.stdout)
        self.assertIs(result.get("decided"), True, "G6 a question already decided must get the recorded answer back")
        self.assertEqual((result["decision"]["id"], result["decision"]["answer"]), (decided.id, decided.answer))
        self.assertIs(result["sent"], False)
        self.assertEqual((result["match"], result["judge"]), ("exact", "not-asked"))
        self.assertEqual(self.waiting(lane), [], "G6 a decided question must not be stored as mail")
        self.assertEqual(self.asked(), [], "G6 a repeated question needs no judge")
        events = self.cli("event", "tail", "--config", "guide-demo", "--lane", lane).stdout.splitlines()
        self.assertEqual([line for line in events if json.loads(line)["kind"] == "lane.mailed"], [])
        fresh = json.loads(self.send(lane, "Which port should the dashboard bind? " + token("q"), "--ask").stdout)
        self.assertIs(fresh["decided"], False, "G6 a question nobody decided is sent")
        self.assertEqual(fresh["sequence"], 1)
        self.assertEqual((fresh["related"], fresh["judge"]), ([], "answered"))
        elsewhere = json.loads(self.send(lane, other.question, "--ask").stdout)
        self.assertIs(elsewhere["decided"], False, "G6 a decision of another project does not answer this lane's question")
        self.assertEqual(elsewhere["sequence"], 2)
        plain = json.loads(self.send(lane, decided.question).stdout)
        self.assertNotIn("decided", plain, "G6 without --ask the message is plain mail")
        self.assertEqual(plain["sequence"], 3)
        paraphrase_marker = token("para")
        paraphrase = "Do the release notes have to be in that language? " + paraphrase_marker
        self.judge(rules=[self.rule(ANSWERS, 0.93, decision=decided.marker, question=paraphrase_marker)])
        by_judge = json.loads(self.send(lane, paraphrase, "--ask").stdout)
        self.assertIs(by_judge["decided"], True, "G6 a score at or above the refuse threshold answers from the record")
        self.assertEqual((by_judge["match"], by_judge["decision"]["id"]), ("judge", decided.id))
        ask = self.asked()[-1]
        self.assertEqual((ask["question"], ask["kind"]), (ANSWERS, "typed"))
        self.assertIn(decided.answer, "\n".join(ask["state"]["decisions"]), "G6 the decision's text must reach the judge")
        self.assertIn(paraphrase_marker, "\n".join(ask["state"]["texts"]), "G6 the question's text must reach the judge")
        self.judge(rules=[self.rule(ANSWERS, 0.62, decision=decided.marker, question=paraphrase_marker)])
        between = json.loads(self.send(lane, paraphrase, "--ask").stdout)
        self.assertIs(between["decided"], False, "G6 a score between the thresholds does not answer")
        self.assertEqual([item["id"] for item in between["related"]], [decided.id], "G6 it lists the decision as related")
        self.judge(rules=[self.rule(ANSWERS, 0.3, decision=decided.marker, question=paraphrase_marker)])
        below = json.loads(self.send(lane, paraphrase, "--ask").stdout)
        self.assertIs(below["decided"], False)
        self.assertEqual(below["related"], [], "G6 a score below the warn threshold lists nothing")
        self.assertEqual(len(self.waiting(lane)), 5, "G6 only the questions that were not answered are stored")
        asker, answers = self.runner_question(other.question, target=lane, project="other")
        from_lane = answers[0]
        self.assertIs(from_lane["decided"], True, "G6 the project of the asking lane decides which decisions answer")
        self.assertEqual(from_lane["decision"]["id"], other.id)
        spoofed = self.send(lane, other.question, "--ask", sender=asker)
        self.assertEqual(spoofed.returncode, 2, "G6 a sender label cannot impersonate an asking lane")
        self.assertIn("--from must equal the resolved principal ID", spoofed.stderr)
        _, answers = self.runner_question(decided.question, target=lane, project="other")
        refused = answers[0]
        self.assertIs(refused["decided"], False, "G6 a decision of the receiving lane's project does not answer another lane's question")
        self.judge(mode="fail")
        silent = json.loads(self.send(lane, "Which cache size should it use? " + token("q"), "--ask").stdout)
        self.assertEqual((silent["decided"], silent["judge"]), (False, "unavailable"),
                         "G6 a question that a failed judge could not check must say so")
        self.guide()
        unconfigured = json.loads(self.send(lane, "Which log level should it use? " + token("q"), "--ask").stdout)
        self.assertEqual((unconfigured["decided"], unconfigured["judge"]), (False, "unconfigured"))
        self.assertEqual(len(self.waiting(lane)), 8, "G6 only the questions that were not answered are stored")

    def test_g6_question_tool_is_a_question(self):
        """Question tools are judged for already-answered probability and receive advice."""
        self.guide(judge="guard")
        decision = self.decide("the release notes", question="Should the release notes be written in " + token("lang") + "?")
        marker = token("q")
        self.judge(rules=[self.rule(ANSWERS, 0.93, decision=decision.marker, question=marker)])
        output = self.hook("codex", "request_user_input",
                           {"questions": [{"question": "Do the release notes need a language? " + marker}]})
        self.assertEqual(output["permissionDecision"], "allow")
        context = output.get("additionalContext", "")
        self.assertIn(decision.id, context, "G6 an already answered question must receive the recorded advice")
        self.assertIn(decision.answer, context)
        ask = self.asked()[-1]
        self.assertEqual((ask["question"], ask["kind"]), (ANSWERS, "typed"))
        self.assertIn(marker, "\n".join(ask["state"]["texts"]))
        free = self.hook("codex", "request_user_input",
                         {"questions": [{"question": "Which port should it bind? " + token("q")}]})
        self.assertEqual((free["permissionDecision"], free["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        self.assertNotIn("additionalContext", free)

    def test_g6_peer_refusal_precedes_answer(self):
        """Fails if an actual non-peer lane can read a decided answer before
        CheckMessage, while a recorded peer must get that same answer."""
        target = self.turn_target()
        decision = self.decide("the peer scope")
        _, refused = self.runner_question(decision.question, target=target, level=4, role="supervisor", expected_exit=2)
        self.assertIn("lanes talk only to lanes of the same level under the same supervisor", refused["stderr"],
                      "G6 the peer refusal must precede decided-question lookup")
        self.assertNotIn('"decided"', refused["stdout"], "G6 a refused peer must receive no decided result")
        self.assertNotIn(decision.answer, refused["stdout"])
        self.assertEqual(self.waiting(target), [])
        self.assertEqual(self.asked(), [])
        _, allowed = self.runner_question(decision.question, target=target)
        self.assertIs(allowed[0]["decided"], True, "G6 the peer control must get the actual recorded answer")
        self.assertEqual(allowed[0]["decision"]["id"], decision.id)

    def test_g7_controls(self):
        """G7: fails if the guard acts when no decision applies, judges a read that changes nothing, ignores
        enabled = false, applies a decision of another level, instance or project label that the settings exclude, or
        asks about a superseded, expired or non-decision record."""
        self.guide(judge="guard", max_decisions=12)
        self.judge(default=0.99)
        action = token("act")
        command = "printf '%s' " + action
        plain = self.shell("claude", command)
        self.assertEqual((plain["permissionDecision"], plain["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "G7 with no decision recorded the hook must behave as before")
        self.assertNotIn("additionalContext", plain)
        self.assertEqual(self.asked(), [], "G7 nothing to ask about")
        unscoped = self.decide("the unscoped rule")
        at_level = self.decide("the level three rule", level=3)
        by_name = self.decide("the named instance rule", level=5, instance=INSTANCE)
        other_level = self.decide("the level five rule", level=5)
        other_project = self.decide("the other project rule", project="other")
        old = self.decide("the old rule")
        self.decide("the new rule", supersedes=old.id)
        expired = self.decide("the lapsed rule", valid_until="2020-01-01T00:00:00Z")
        ledger = self.decide("a ledger line", kind="ledger")

        def asked_ids():
            self.requests_path.unlink(missing_ok=True)
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "allow", "G7 ordinary high probability only warns")
            self.assertIn(unscoped.id, output.get("additionalContext", ""))
            return {text.split(" ", 1)[0] for ask in self.asked() for text in ask["state"]["decisions"]}

        newer = self.decide("the new rule recorded last")
        everything = asked_ids()
        for decision in (unscoped, at_level, by_name, other_project, newer):
            self.assertIn(decision.id, everything, "G7 a decision that applies to the instance is asked about")
        for decision in (other_level, old, expired, ledger):
            self.assertNotIn(decision.id, everything, "G7 a decision that does not apply is not asked about")
        self.guide(judge="guard", max_decisions=12, projects=["demo"])
        self.assertNotIn(other_project.id, asked_ids(), "G7 the projects setting must exclude other labels")
        self.guide(judge="guard", max_decisions=12)
        self.requests_path.unlink(missing_ok=True)
        read = self.hook("claude", "Read", {"file_path": str(self.worktree / "notes.txt")})
        self.assertEqual((read["permissionDecision"], read["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "G7 a read that cannot change anything is not judged")
        self.assertEqual(self.asked(), [], "G7 a read is not asked about")
        self.guide(judge="guard", max_decisions=12, enabled=False)
        off = self.shell("claude", command)
        self.assertEqual((off["permissionDecision"], off["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "G7 enabled = false must switch the guard off")
        self.assertEqual(self.asked(), [])

    def test_g7_guide_settings_are_protected(self):
        """G7: fails if an agent whose write scope covers the whole org folder can change guide.toml, which holds the dial."""
        self.widen_write_scope()
        for runner in RUNNERS:
            scratch = self.hook(runner, "Write", {"file_path": str(self.org / "scratch.txt"), "content": "x"})
            self.assertEqual(scratch["permissionDecision"], "allow", "G7 the control: the org folder is writable")
            denied = self.hook(runner, "Write", {"file_path": str(self.guide_file), "content": "enabled = false"})
            self.assertEqual(denied["permissionDecision"], "deny",
                             "G7 the guide settings must be protected like the hook policy")

    # The guard only adds to the org policy, and nothing the agent writes makes a call pass as scored (G9 to G15)

    def test_g9_policy_refusals_hold(self):
        """G9: fails if the guard changes a call that the org's own rules refuse. In every state of the guard's inputs (no
        guide.toml; one that is a directory, is not TOML or has an unknown key; a judge that answers, fails or talks
        nonsense; unavailable = refuse; the guard off; no judge) the refusal must stay a refusal with the rules' own text
        and first line, carry no context, and the judge must not be asked about it. The ordinary non-Laneboss environment
        gap remains allowed with an incomplete receipt in every state. The final controls show that the guard is live."""
        self.decide("the production release")

        self.prepare_boundary_lane()

        def make_directory(jobs):
            self.guide_file.mkdir()

        def make_text(jobs):
            self.guide_file.write_text("judge = [\n")

        states = (
            ("no guide.toml", lambda jobs: None, {}),
            ("a judge that answers", lambda jobs: self.guide(judge="guard", jobs=jobs), {}),
            ("a judge that fails", lambda jobs: self.guide(judge="guard", jobs=jobs), {"mode": "fail"}),
            ("a judge that talks nonsense", lambda jobs: self.guide(judge="guard", jobs=jobs), {"mode": "garbage"}),
            ("a failing judge with unavailable = refuse", lambda jobs: self.guide(judge="guard", unavailable="refuse", jobs=jobs),
             {"mode": "fail"}),
            ("guide.toml is a directory", make_directory, {}),
            ("guide.toml is not TOML", make_text, {}),
            ("guide.toml has an unknown key", lambda jobs: self.guide(judge="guard", refuse_treshold=0.9, jobs=jobs), {}),
            ("the guard is off", lambda jobs: self.guide(judge="guard", enabled=False, jobs=jobs), {}),
            ("no judge named", lambda jobs: self.guide(jobs=jobs), {}),
        )
        seen = {}
        for jobs in (False, True):
            for state, setup, judge_settings in states:
                self.reset_guide()
                setup(jobs)
                self.judge(**judge_settings)
                for runner in RUNNERS:
                    for name, call, first_line in self.policy_refusals(runner):
                        where = "%s, jobs=%s, %s, %s" % (state, jobs, runner, name)
                        before = len(self.asked())
                        receipt_count = len(self.receipts())
                        output = call()
                        if first_line is None:
                            self.assertEqual(output["permissionDecision"], "allow",
                                             "G9 ordinary environment gaps must allow (%s)" % where)
                            self.assertTrue(output["permissionDecisionReason"].startswith(PLAIN_ALLOW))
                            receipts = self.receipts()
                            self.assertEqual(len(receipts), receipt_count + 1,
                                             "G9 the ordinary gap must append a fresh callback (%s)" % where)
                            receipt = receipts[-1]
                            self.assertEqual((receipt["runner"], receipt["decision"]), (runner, "allow"))
                            self.assertIs(receipt["inspection_complete"], False,
                                          "G9 an environment override must not claim complete inspection (%s)" % where)
                            self.assertEqual(receipt["inspection_notice"],
                                             "file effects were not fully inspected; blacklist mode allowed the call")
                            continue
                        self.assertEqual(output["permissionDecision"], "deny",
                                         "G9 a refusal of the org policy must hold (%s)" % where)
                        reason = output["permissionDecisionReason"]
                        self.assertEqual(reason.splitlines()[0], first_line,
                                         "G9 a refusal of the org policy must keep its first line (%s)" % where)
                        self.assertEqual(reason, seen.setdefault((runner, name), reason),
                                         "G9 a refusal of the org policy must keep its text (%s)" % where)
                        self.assertNotIn("additionalContext", output,
                                         "G9 a refusal of the org policy must carry no guard context (%s)" % where)
                        self.assertEqual(len(self.asked()), before,
                                         "G9 a call that the org policy refused is never put to the judge (%s)" % where)
        self.reset_guide()
        self.guide(judge="guard")
        self.judge()
        before = len(self.asked())
        live = self.shell("claude", "printf '%s' " + token("act"))
        self.assertEqual((live["permissionDecision"], live["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        self.assertEqual(len(self.asked()), before + 1, "G9 the control: the guard judges a call that the rules allow")
        self.guide(judge="guard", unavailable="refuse")
        self.judge(mode="fail")
        closed = self.shell("claude", "printf '%s' " + token("act"))
        self.assertEqual(closed["permissionDecision"], "allow",
                         "G9 the control: unavailable = refuse remains a warning for a call it cannot score")
        self.assertIn("not scored", closed.get("additionalContext", "").lower())

    def test_g10_guard_inputs_are_protected(self):
        """G10: fails if an agent whose write scope covers the whole org folder can remove, move, replace or create what the
        guard reads: guide.toml, history.toml (it says where the decision store is), the store and its journal files, or
        the folder or a parent folder that holds them. Every such attempt is refused by the rules' own refusal."""
        # Use the fixture's recorded supervisor and an L4 instance: a lane's shared-path boundary would still deny
        # these writes when the services protection is removed, masking the defect this row must detect.
        self.env["LANEBOSS_CONFIG"] = "guide-demo"
        self.instance_dir = self.laneboss / "instances" / "L4-stream"
        self.widen_write_scope()
        self.guide(judge="guard")
        decision = self.decide("the production release")
        history = self.services / "history.toml"
        protected = (self.guide_file, history, self.store, Path(str(self.store) + "-wal"), Path(str(self.store) + "-journal"))
        commands = ["rm " + str(self.store), "mv %s %s.moved" % (self.store, self.store),
                    "truncate -s 0 " + str(self.store), "printf x > " + str(history), "rm " + str(self.guide_file),
                    "rm -rf " + str(self.services), "rm -rf " + str(self.laneboss / "shared")]
        for runner in RUNNERS:
            scratch = self.hook(runner, "Write", {"file_path": str(self.org / "scratch.txt"), "content": "x"})
            self.assertEqual(scratch["permissionDecision"], "allow", "G10 the control: the org folder is writable")
            shared_scratch = self.hook(runner, "Write", {
                "file_path": str(self.laneboss / "shared" / "scratch.txt"), "content": "x"})
            self.assertEqual(shared_scratch["permissionDecision"], "allow",
                             "G10 the control: unprotected shared files are writable")
            for path in protected:
                denied = self.hook(runner, "Write", {"file_path": str(path), "content": "x"})
                self.assertEqual(denied["permissionDecision"], "deny",
                                 "G10 the guard's inputs must be protected like the hook policy (%s, Write %s)" % (runner, path.name))
                self.assertEqual(denied["permissionDecisionReason"].splitlines()[0], PROTECTED_FILES)
            for command in commands:
                denied = self.shell(runner, command)
                self.assertEqual(denied["permissionDecision"], "deny",
                                 "G10 the guard's inputs must be protected like the hook policy (%s, %s)" % (runner, command.split()[0]))
                self.assertEqual(denied["permissionDecisionReason"].splitlines()[0], PROTECTED_FILES)
        action = token("act")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=decision.marker, action=action)])
        refused = self.shell("claude", "printf '%s' " + action)
        self.assertEqual(refused["permissionDecision"], "allow",
                         "G10 the guard's inputs must be protected: the guard still judges after the attempts")
        self.assertIn(decision.id, refused.get("additionalContext", ""))

    def test_g11_left_out_decisions_reported(self):
        """Ranking/caps cannot make uncovered decisions disappear."""
        older = self.decide(answer="Decided {marker}: never publish marmot builds.", question="Question {marker}?")
        newer = self.decide(answer="Decided {marker}: keep the quartz lantern rotation.", question="Question {marker}?")
        action = token("act")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=older.marker, action=action)])
        plain = "printf '%s' marmot publish " + action
        flood = "printf '%s' quartz lantern rotation keep marmot " + action
        self.guide(judge="guard", max_decisions=1)
        output = self.shell("claude", plain)
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn(older.id, output.get("additionalContext", ""))
        self.assertEqual(len(self.asked()), 1)
        self.requests_path.unlink()
        for policy in ("warn", "refuse"):
            self.guide(judge="guard", max_decisions=1, unavailable=policy)
            flooded = self.shell("claude", flood)
            self.assertEqual(flooded["permissionDecision"], "allow")
            context = flooded.get("additionalContext", "")
            self.assertIn(older.id, context, "G11 a decision that max_decisions left out must be reported to the agent")
            self.assertIn("max_decisions", context)
            self.assertNotIn(newer.id, context)
            self.assertEqual(len(self.asked()[-1]["questions"]), 1)
        self.guide(judge="guard", max_decisions=2)
        caught = self.shell("claude", flood)
        self.assertEqual(caught["permissionDecision"], "allow")
        self.assertIn(older.id, caught.get("additionalContext", ""))
        self.assertEqual(len(self.asked()[-1]["questions"]), 2)

    def test_g12_long_calls_are_read_whole(self):
        """Every bounded window shares one request; beyond-limit input warns as partial."""
        decision = self.decide(answer="Decided {marker}: never skip approval.", question="Question {marker}?")
        action = token("act")
        self.guide(judge="guard")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=decision.marker, action=action)])
        filler = "lorem " * 700
        for runner in RUNNERS:
            self.requests_path.unlink(missing_ok=True)
            output = self.shell(runner, "printf '%s' " + filler + action)
            self.assertEqual(output["permissionDecision"], "allow")
            self.assertIn(decision.id, output.get("additionalContext", ""),
                             "G12 a long call must be judged whole: its tail still produces advice")
            self.assertEqual(len(self.asked()), 1, "G12 all windows share one request")
            parts = self.asked()[0]["state"]["texts"]
            self.assertEqual(len(parts), 2)
            self.assertEqual(len(self.asked()[0]["questions"]), 2)
            self.assertTrue(any(part.startswith("[part 1 of 2 of the call]") for part in parts))
            self.assertTrue(any(part.startswith("[part 2 of 2 of the call]") for part in parts))
        written = self.hook("claude", "Write", {"file_path": str(self.worktree / "notes.txt"), "content": "lorem " * 800 + action})
        self.assertEqual(written["permissionDecision"], "allow")
        self.assertIn(decision.id, written.get("additionalContext", ""))
        self.requests_path.unlink(missing_ok=True)
        clean = self.shell("claude", "printf '%s' " + filler + "end")
        self.assertEqual((clean["permissionDecision"], clean["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        self.assertNotIn("additionalContext", clean)
        self.assertEqual(len(self.asked()), 1)
        beyond = "lorem " * 2000
        for policy in ("warn", "refuse"):
            self.guide(judge="guard", unavailable=policy)
            output = self.shell("claude", "printf '%s' " + beyond + action)
            self.assertEqual(output["permissionDecision"], "allow")
            self.assertIn(decision.id, output.get("additionalContext", ""))
            self.assertIn("longer than", output.get("additionalContext", ""))
            self.assertEqual(len(self.asked()[-1]["state"]["texts"]), 3)
            self.assertEqual(self.receipts()[-1]["guard"]["decisions"][0]["outcome"], "partial")

    def test_g13_withheld_text_is_not_a_score(self):
        """Credential-shaped state is never sent and cannot become a clean score."""
        decision = self.decide(answer="Decided {marker}: never skip approval.", question="Question {marker}?")
        action = token("act")
        secret = "gh" + "p_" + "a1B2c3D4e5" * 4
        self.guide(judge="guard")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=decision.marker, action=action)])
        control = self.shell("claude", "printf '%s' " + action)
        self.assertEqual(control["permissionDecision"], "allow")
        self.assertIn(decision.id, control.get("additionalContext", ""))
        self.requests_path.unlink()
        for policy in ("warn", "refuse"):
            self.guide(judge="guard", unavailable=policy)
            hidden = self.shell("claude", "printf '%s' " + action + " " + secret)
            self.assertEqual(hidden["permissionDecision"], "allow")
            context = hidden.get("additionalContext", "")
            self.assertIn(decision.id, context, "G13 a text that the judge was not given must not pass as scored")
            self.assertIn("credential", context)
            self.assertEqual(self.asked(), [], "G13 withheld state must not leave through the judge")
            self.assertEqual(self.receipts()[-1]["guard"]["decisions"][0]["outcome"], "withheld")

    def test_g14_multiedit_is_judged(self):
        """Every edit reaches the typed state; guidance stays in additionalContext."""
        decision = self.decide(answer="Decided {marker}: never skip approval.", question="Question {marker}?")
        action = token("act")
        self.guide(judge="guard")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=decision.marker, action=action)])
        target = str(self.worktree / "notes.txt")
        edit_text = token("single") + " " + action
        edit = self.hook("claude", "Edit", {"file_path": target, "old_string": "a", "new_string": edit_text})
        self.assertEqual((edit["permissionDecision"], edit["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "G14 the control: ordinary edit guidance remains advisory")
        self.assertIn(decision.id, edit.get("additionalContext", ""))
        self.assertIn(edit_text, "\n".join(self.asked()[-1]["state"]["texts"]))
        first, last = token("first"), token("last") + " " + action
        edits = [{"old_string": "a", "new_string": first}, {"old_string": "c", "new_string": last}]
        before = len(self.asked())
        multi = self.hook("claude", "MultiEdit", {"file_path": target, "edits": edits})
        self.assertEqual((multi["permissionDecision"], multi["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        self.assertIn(decision.id, multi.get("additionalContext", ""),
                      "G14 what a multiple edit writes must reach the judge")
        self.assertEqual(len(self.asked()), before + 1, "G14 the actual MultiEdit input must create one typed ask")
        request = self.asked()[-1]
        self.assertEqual(request["kind"], "typed")
        sent = "\n".join(request["state"]["texts"])
        self.assertIn(target, sent)
        for item in edits:
            self.assertIn(item["new_string"], sent, "G14 every real edit text must reach the typed state")
        note = self.receipts()[-1]["guard"]["decisions"][0]
        self.assertEqual((note["decision"], note["outcome"], note["score"]), (decision.id, "answered", 0.93))
        neutral_text = token("neutral")
        plain = self.hook("claude", "MultiEdit", {"file_path": target, "edits": [
            {"old_string": "a", "new_string": neutral_text}]})
        self.assertEqual((plain["permissionDecision"], plain["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        self.assertNotIn("additionalContext", plain, "G14 an unrelated edit must not invent a conflict")
        self.assertIn(neutral_text, "\n".join(self.asked()[-1]["state"]["texts"]))

    def test_g15_no_judge_notice(self):
        """G15: fails if, with a guide.toml that names no judge, the hook asks anybody, refuses, or adds more than the short
        warn-only notice (the newest three decisions and how many more apply); or if it adds anything when there is no
        guide.toml, no decision applies, the guard is off, or the call is a read."""
        decisions = [self.decide(answer="Decided {marker}: rule number %d." % number, question="Question %d {marker}?" % number)
                     for number in range(5)]
        command = "printf '%s' " + token("act")
        before = self.shell("claude", command)
        self.assertEqual((before["permissionDecision"], before["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "G15 with no guide.toml the org has not set the guard up and the hook adds nothing")
        self.assertNotIn("additionalContext", before)
        self.guide()
        for runner in RUNNERS:
            notice = self.shell(runner, command)
            self.assertEqual(notice["permissionDecision"], "allow", "G15 with no judge named the hook never refuses")
            self.assertTrue(notice["permissionDecisionReason"].startswith(PLAIN_ALLOW))
            context = notice.get("additionalContext", "")
            self.assertIn("NOT checked", context, "G15 the notice says that the call was not checked")
            for newest in decisions[:1:-1]:
                self.assertIn(newest.id, context, "G15 the notice lists the newest decisions")
                self.assertIn(newest.answer, context)
            for older in decisions[:2]:
                self.assertNotIn(older.id, context, "G15 the notice is short: only the newest three are listed")
            self.assertIn("2 more", context, "G15 the notice says how many more decisions apply")
            self.assertLess(len(context), 2000, "G15 the notice is short")
        self.assertEqual(self.asked(), [], "G15 with no judge named nobody is asked")
        read = self.hook("claude", "Read", {"file_path": str(self.worktree / "notes.txt")})
        self.assertEqual((read["permissionDecision"], read["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        self.assertNotIn("additionalContext", read, "G15 a read gets no notice")
        self.guide(enabled=False)
        off = self.shell("claude", command)
        self.assertEqual((off["permissionDecision"], off["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "G15 with the guard off the hook adds nothing")
        self.guide(projects=["nobody"])
        none = self.shell("claude", command)
        self.assertEqual((none["permissionDecision"], none["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "G15 with no decision that applies the hook adds nothing")
        self.assertEqual(self.receipts()[-1].get("guard"), None, "G15 nothing was judged, so the receipt has no guard member")

    def test_b1_description_only_blacklist(self):
        """B1: a description without a deterministic pattern is judged, while an unrelated call passes."""
        description = token("do-not-upload")
        action = token("release-upload")
        self.set_hook_mode("blacklist", {
            "id": "no-release-upload", "description": description, "band": "refuse",
            "examples_not_ok": [action], "examples_ok": ["go test ./..."],
        })
        self.guide(judge="guard")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=description, action=action)])
        refused = self.shell("claude", "release upload " + action)
        self.assertEqual(refused["permissionDecision"], "deny")
        self.assertTrue(refused["permissionDecisionReason"].startswith("[no-release-upload] Refuses:"))
        unrelated = self.shell("claude", "go test " + token("unrelated"))
        self.assertEqual((unrelated["permissionDecision"], unrelated["permissionDecisionReason"]),
                         ("allow", PLAIN_ALLOW))

    def test_b2_examples_reach_typesafe(self):
        """B2: examples are part of the judge state, not only local documentation."""
        description, not_ok, ok, action = (token("description"), token("not-ok"), token("ok"), token("action"))
        self.set_hook_mode("blacklist", {
            "id": "example-state", "description": description, "band": "warn",
            "examples_not_ok": [not_ok], "examples_ok": [ok],
        })
        self.guide(judge="guard")
        self.judge(rules=[self.rule(CONFLICTS, 0.70, decision=description, action=action)])
        output = self.shell("claude", "run " + action)
        self.assertEqual(output["permissionDecision"], "allow")
        state = next(
            decision
            for ask in reversed(self.asked())
            for decision in (ask.get("state", {}).get("decisions", []) or [ask.get("subject", {}).get("decision", "")])
            if description in decision
        )
        self.assertIn(description, state)
        self.assertIn(not_ok, state)
        self.assertIn(ok, state)

    def test_b3_preview_scores(self):
        """B3: blacklist try previews per-entry scores without changing decisions or hook receipts."""
        description, action = token("try-description"), token("try-action")
        self.set_hook_mode("blacklist", {
            "id": "try-entry", "description": description, "band": "refuse",
        })
        self.guide(judge="guard")
        self.judge(rules=[self.rule(CONFLICTS, 0.93, decision=description, action=action)])
        before_store = self.store.read_bytes()
        before_receipts = self.receipts()
        before_egress_result = self.cli("judge", "egress", "--config", "guide-demo")
        self.assertEqual(before_egress_result.returncode, 0, before_egress_result.stderr)
        before_egress = before_egress_result.stdout.splitlines()
        result = self.cli("org", "blacklist", "try", "--config", "guide-demo", "--level", "3",
                          "--role", "executor", "--", "run", action)
        self.assertEqual(result.returncode, 0, result.stderr)
        preview = json.loads(result.stdout)
        self.assertEqual(preview["decision"], "refuse")
        row = next(item for item in preview["entries"] if item["id"] == "try-entry")
        self.assertEqual(row["decision"], "refuse")
        self.assertAlmostEqual(row["score"], 0.93)
        self.assertEqual(self.store.read_bytes(), before_store)
        self.assertEqual(self.receipts(), before_receipts)
        after_egress_result = self.cli("judge", "egress", "--config", "guide-demo")
        self.assertEqual(after_egress_result.returncode, 0, after_egress_result.stderr)
        after_egress = after_egress_result.stdout.splitlines()
        self.assertGreater(len(after_egress), len(before_egress),
                           "B3 the preview judge request must leave auditable egress lines")
        new_events = [json.loads(line)["event"] for line in after_egress[len(before_egress):]]
        self.assertEqual(new_events, ["sent", "outcome"],
                         "B3 preview egress must record one sent and one outcome without a decision record")

    def test_b4_refuse_beats_warn(self):
        """B4: a later refuse entry wins when warn and refuse patterns overlap."""
        self.set_hook_mode("blacklist", {
            "id": "broad-warning", "description": token("broad-warning"), "band": "warn",
            "argv_prefix": ["publish"],
        })
        source = self.laneboss / "org.toml"
        text = source.read_text()
        text += "\n[[hooks.blacklist]]\nid = \"specific-refusal\"\ndescription = \"" + token("specific-refusal") + "\"\nband = \"refuse\"\nargv_prefix = [\"publish\", \"now\"]\n"
        source.write_text(text)
        self.cli_json("org", "render", self.org)
        output = self.shell("claude", "publish now")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B4 a refuse entry must beat an overlapping warn entry")
        self.assertTrue(output["permissionDecisionReason"].startswith("[specific-refusal] Refuses:"))

    def test_b5_reference_entry_keeps_pattern(self):
        """B5: a decision reference does not disable its deterministic argv prefix."""
        description = token("reference-description")
        self.set_hook_mode("blacklist", {
            "id": "referenced-pattern", "description": description, "band": "refuse",
            "decision": "D-not-present", "argv_prefix": ["reference", "now"],
        })
        output = self.shell("claude", "reference now")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B5 a decision reference must not disable its deterministic pattern")
        self.assertTrue(output["permissionDecisionReason"].startswith("[referenced-pattern] Refuses:"))

    def test_b6_unknown_receipt(self):
        """B6: strict and unversioned compatibility sources allow gaps and record incomplete inspection."""
        original_instance = self.instance_dir
        self.add_legacy_rule("ignored-tools", "tool-allowlist", ["Read"], level_source=True)
        try:
            for mode in ("strict", "blacklist", "unversioned"):
                if mode == "unversioned":
                    legacy = self.directory / "unversioned-observation"
                    self.cli_json("org", "init", legacy, "--name", "legacy-observation")
                    self.instance_dir = legacy / ".laneboss/instances" / INSTANCE
                    self.add_legacy_rule("ignored-tools", "tool-allowlist", ["Read"], level_source=True)
                    source = legacy / ".laneboss/org.toml"
                    lines, in_hooks = [], False
                    for line in source.read_text().splitlines(keepends=True):
                        heading = line.strip()
                        if heading.startswith("["):
                            in_hooks = heading == "[hooks]" or heading.startswith(("[hooks.", "[[hooks."))
                        if not in_hooks and not line.startswith("schema_version ="):
                            lines.append(line)
                    source.write_text("".join(lines))
                    policy = tomllib.loads(source.read_text())
                    self.assertNotIn("schema_version", policy)
                    self.assertNotIn("hooks", policy)
                    # Keep the configured lane org versioned; only this hook source is legacy.
                    # Rendering would require a schema version, so submit the exact source directly.
                else:
                    self.set_hook_mode(mode)
                    validated = self.cli("org", "validate", self.org, "--format", "json-diagnostics")
                    self.assertEqual(validated.returncode, 0, validated.stderr)
                    self.assertTrue(json.loads(validated.stdout)["valid"])
                    assert_hook_deprecation(self, validated)
                for runner in RUNNERS:
                    calls = (
                        ("shell", lambda: self.shell(runner, "unknown-helper " + token("opaque"))),
                        ("unlisted", lambda: self.hook(runner, token("UnlistedTool"), {"payload": token("input")})),
                    )
                    for shape, call in calls:
                        with self.subTest(mode=mode, runner=runner, shape=shape):
                            output = call()
                            self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]),
                                             ("allow", PLAIN_ALLOW),
                                             "B6 default observation must allow an unknown call without duplicating deterministic notices")
                            self.assertNotIn("additionalContext", output)
                            receipt = self.receipts()[-1]
                            self.assertEqual((receipt["runner"], receipt["decision"]), (runner, "allow"))
                            self.assertIs(receipt["inspection_complete"], False)
                            self.assertEqual(receipt["inspection_notice"],
                                             "file effects were not fully inspected; blacklist mode allowed the call")
        finally:
            self.instance_dir = original_instance

    def test_b7_shared_state_is_built_in(self):
        """B7: the shared state root stays protected even when the instance repository scope is widened."""
        self.set_hook_mode("blacklist")
        self.widen_write_scope()
        target = str(self.laneboss / "shared" / "state" / "canary.txt")
        output = self.hook("claude", "Write", {"file_path": target, "content": "x"})
        self.assertTrue(
            output["permissionDecision"] == "deny" and
            output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"),
            "B7 shared state must remain a built-in refusal")

    def test_b8_cd_preserves_legacy_refusal(self):
        """B8: a literal cd segment must not hide the legacy git-push refusal."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "cd " + str(self.worktree) + " && git push origin main")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B8 cd must preserve the parsed later git push segment")
        self.assertTrue(output["permissionDecisionReason"].startswith("[no-push] Refuses:"),
                        "B8 the legacy no-push row must still refuse after cd")

    def test_b9_cd_read_is_allowed_incomplete(self):
        """B9: the cd control remains allowed while its state-changing inspection is recorded incomplete."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "cd " + str(self.worktree) + " && ls")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B9 cd followed by a read-only listing must remain allowed")
        self.assertFalse(self.receipts()[-1]["inspection_complete"],
                         "B9 a state-changing segment must be recorded as incomplete")

    def test_b10_export_push(self):
        """B10: a state assignment must not hide a later git-push refusal from raw segment matching."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "export A=1; git push origin main")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B10 the raw segment fallback must find git push after export")
        self.assertTrue(output["permissionDecisionReason"].startswith("[no-push] Refuses:"),
                        "B10 the raw segment fallback must find git push after export")

    def test_b11_deny_subtree(self):
        """B11: a legacy deny root refuses a descendant, not only the root itself."""
        self.set_hook_mode("blacklist")
        self.widen_write_scope()
        self.add_legacy_rule("legacy-deny-root", "write-scope", ["{org}"], ["legacy-deny"])
        target = self.org / "legacy-deny" / "nested" / "canary.txt"
        target.parent.mkdir(parents=True)
        output = self.hook("claude", "Write", {"file_path": str(target), "content": "x"})
        self.assertEqual(output["permissionDecision"], "deny",
                         "B11 legacy deny roots must cover descendants; the exact-root mutant would allow this write")
        self.assertTrue(output["permissionDecisionReason"].startswith("[legacy-deny-root] Refuses:"))

    def test_b12_secret_path(self):
        """B12: a legacy secret path name uses strict basename, path and link checks."""
        self.set_hook_mode("blacklist")
        self.add_legacy_rule("legacy-secret-path", "secret-read", ["shared/secrets/api.env"])
        secret = self.org / "shared" / "secrets" / "api.env"
        secret.parent.mkdir(parents=True)
        secret.write_text("redacted\n")
        output = self.hook("claude", "Read", {"file_path": str(secret)})
        self.assertEqual(output["permissionDecision"], "deny",
                         "B12 a legacy secret path must refuse; the secret-glob mutant would allow it")
        self.assertTrue(output["permissionDecisionReason"].startswith("[legacy-secret-path] Refuses:"))

    def test_b13_workdir_env(self):
        """B13: an env observation gap still protects a file named relative to the tool workdir."""
        self.set_hook_mode("blacklist")
        output = self.hook("claude", "Bash", {"command": "printf x > org.toml", "workdir": str(self.laneboss), "env": {"A": "1"}})
        self.assertEqual(output["permissionDecision"], "deny",
                         "B13 the raw protected-path check must use the resolved shell workdir")
        self.assertTrue(output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))

    def test_b14_pin(self):
        """B14: a caller label that disagrees with the pinned instance cannot change the proven scope."""
        self.set_hook_mode("blacklist")
        output = self.hook_with("claude", "Bash", {"command": "printf '%s' pin"}, pinned=self.instance_dir,
                                 extra_env={"LANEBOSS_INSTANCE": "L3-other-instance"})
        self.assertEqual(output["permissionDecision"], "deny",
                         "B14 a LANEBOSS_INSTANCE that disagrees with the pin must be refused")
        self.assertIn("disagrees with the pinned instance", output["permissionDecisionReason"],
                      "B14 the refusal must identify the binding conflict")

    def test_b15_slow(self):
        """B15: a slow blacklist judge produces its notice within the synchronous hook deadline."""
        description = token("slow-entry")
        self.set_hook_mode("blacklist", {"id": "slow-entry", "description": description, "band": "refuse"})
        self.guide(judge="guard")
        self.judge(mode="slow")
        started = time.monotonic()
        output = self.shell("claude", "run " + token("slow-action"))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 3.0, "B15 the blacklist hook must answer before the hook deadline")
        self.assertEqual(output["permissionDecision"], "allow",
                         "B15 an unavailable blacklist judge must leave the deterministic result allowed")
        self.assertIn("before the hook deadline", output.get("additionalContext", ""),
                      "B15 the bounded judge failure must be reported before the hook deadline")
        self.assertTrue(self.asked(), "B15 the blacklist judge must be asked before the bounded timeout")

    def test_b16_gap_push_fallback(self):
        """B16: an env gap leaves the later push to the raw segment fallback."""
        self.set_hook_mode("blacklist")
        output = self.hook("claude", "Bash", {"command": "true; git push origin main", "env": {"A": "1"}})
        self.assertEqual(output["permissionDecision"], "deny",
                         "B16 the gap fallback must refuse a push after the first segment")

    def test_b17_cd_secret_is_refused(self):
        """B17: a cd before a secret read cannot hide the legacy secret-name refusal."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "cd " + str(self.worktree) + " && cat .env")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B17 cd must preserve the secret-name refusal")

    def test_b18_cd_protected_copy_is_refused(self):
        """B18: a protected destination after cd remains a built-in refusal."""
        self.set_hook_mode("blacklist")
        target = str(self.laneboss / "org.toml")
        output = self.shell("claude", "cd . && cp x " + target)
        self.assertEqual(output["permissionDecision"], "deny",
                         "B18 cd must not hide a protected copy destination")
        self.assertTrue(output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))

    def test_b19_var_redirect(self):
        """B19: ordinary variable redirects remain default-allowed when their target is unknown."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", 'echo "$MSG" > "$FILE"')
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B19 an unknown variable redirect must remain ordinary incomplete work")
        self.assertFalse(self.receipts()[-1]["inspection_complete"])

    def test_b20_protected_redirect(self):
        """B20: a literal protected path remains refused even when the command has another variable target."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", 'echo "$MSG" > .laneboss/org.toml')
        self.assertEqual(output["permissionDecision"], "deny",
                         "B20 the raw check must refuse a protected literal redirect")

    def test_b21_reserved_body_push_is_refused(self):
        """B21: reserved shell bodies still expose a listed command to raw matching."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "{ git push origin main; }")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B21 reserved body syntax must not hide git push")

    def test_b22_ansi_push(self):
        """B22: ANSI-C quoting creates an observation gap without hiding a later push."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "git commit -m $'subject\\n\\nbody'; git push origin main")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B22 ANSI-C quoting must preserve the later git push refusal")

    def test_b23_failed_secret(self):
        """B23: a failed earlier segment does not discard a later secret read."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "echo $HOME; cat .env")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B23 later secret reads must survive an earlier inspection failure")

    def test_b24_eval_push_is_refused(self):
        """B24: literal eval text is inspected as a nested shell command."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", 'eval "git push origin main"')
        self.assertEqual(output["permissionDecision"], "deny",
                         "B24 eval must not hide a literal git push")

    def test_b25_guard_fail(self):
        """B25: a failed decision judge warns while blacklist policy remains authoritative."""
        self.set_hook_mode("blacklist")
        decision = self.decide("the release operation")
        self.guide(judge="guard", unavailable="refuse")
        self.judge(mode="fail")
        output = self.shell("claude", "printf '%s' " + decision.marker)
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B25 unavailable decision guidance must remain warn-only")
        self.assertIn(decision.id, output.get("additionalContext", ""))
        self.assertIn("not scored", output.get("additionalContext", "").lower())

    def test_b26_cd_failed_protected(self):
        """B26: a failed cd cannot move a later protected write away from the org."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "cd /nonexistent; printf x > .laneboss/org.toml")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B26 a failed cd must retain the original protected directory candidate")
        self.assertTrue(output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))

    def test_b27_assignment_protected(self):
        """B27: a protected path held in an assignment remains visible to the raw check."""
        self.set_hook_mode("blacklist")
        target = str(self.laneboss / "org.toml")
        output = self.shell("claude", "F=" + target + '; printf x > "$F"')
        self.assertEqual(output["permissionDecision"], "deny",
                         "B27 the raw check must inspect assignment values before stripping them")
        self.assertTrue(output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))

    def test_b28_reserved_bodies(self):
        """B28: loop, case, function and brace bodies expose listed commands while echo remains allowed."""
        self.set_hook_mode("blacklist")
        commands = [
            "{ git push origin main; }",
            "for r in origin; do git push origin main; done",
            "while false; do git push origin main; done",
            "case x in x) git push origin main;; esac",
            "f() { git push origin main; }; f",
        ]
        for command in commands:
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "deny",
                             "B28 reserved shell bodies must not hide git push")
        allowed = self.shell("claude", "echo git push")
        self.assertEqual((allowed["permissionDecision"], allowed["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B28 echoing git push must remain ordinary work")

    def test_b29_alias_and_eval_forms(self):
        """B29: alias values and nested eval text retain the command blacklist."""
        self.set_hook_mode("blacklist")
        alias = self.shell("claude", "alias x='git push origin main'; x")
        self.assertEqual(alias["permissionDecision"], "deny",
                         "B29 an alias value must not hide git push")
        function = self.shell("claude", "f() { git push origin main; }; f")
        self.assertEqual(function["permissionDecision"], "deny",
                         "B29 a function body must not hide git push")

    def test_b30_cd_ordinary_controls(self):
        """B30: ordinary cd work remains a clean allow in both && and list forms."""
        self.set_hook_mode("blacklist")
        for command in ("cd " + str(self.worktree) + " && make", "cd " + str(self.worktree) + "; git status"):
            output = self.shell("claude", command)
            self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                             "B30 ordinary cd work must remain cleanly allowed")

    def test_b31_token_limit_push(self):
        """B31: a token-limit gap still exposes a later push."""
        self.set_hook_mode("blacklist")
        command = " ".join(["echo"] * 10001) + "; git push origin main"
        output = self.shell("claude", command)
        self.assertEqual(output["permissionDecision"], "deny",
                         "B31 token-limit fallback must preserve the later git push refusal")

    def test_b32_cd_expansion_redirect(self):
        """B32: a redirect attached to a variable cd is still a protected write."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "true; cd $D > .laneboss/hooks/settings.json")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B32 a cd expansion redirect must remain a protected write")
        self.assertTrue(output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))

    def test_b33_cdpath_policy_directory(self):
        """B33: CDPATH assignments add their policy directory to protected candidates."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "CDPATH=" + str(self.laneboss) + "; cd shared/services; printf x > guide.toml")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B33 CDPATH must keep the policy directory candidate for guide.toml")
        self.assertTrue(output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))

    def test_b34_cdpath_instance_file(self):
        """B34: an assigned CDPATH cannot hide an instance definition write."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "CDPATH=" + str(self.laneboss / "instances") + "; cd " + INSTANCE + "; : > instance.toml")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B34 assigned CDPATH must preserve the instance definition refusal")

    def test_b35_pushd_cdpath_hooks(self):
        """B35: pushd follows the same uncertain CDPATH protection as cd."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "CDPATH=" + str(self.laneboss / "instances") + "; pushd " + INSTANCE + "; true > hooks/settings.json")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B35 pushd CDPATH must preserve the instance hooks refusal")

    def test_b36_inherited_cdpath_database(self):
        """B36: an inherited CDPATH is treated as uncertain by the hook."""
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("claude", "cd shared/services; printf x > decisions.sqlite", {"CDPATH": str(self.laneboss)})
        self.assertEqual(output["permissionDecision"], "deny",
                         "B36 inherited CDPATH must preserve the decision database refusal")

    def test_b37_launcher_config_is_built_in(self):
        """B37: launcher configuration definitions remain protected from shell redirects."""
        self.set_hook_mode("blacklist")
        config_file = self.home / ".config" / "laneboss" / "configs" / "guide-demo" / "config.toml"
        output = self.shell("claude", "true > " + str(config_file))
        self.assertEqual(output["permissionDecision"], "deny",
                         "B37 the launcher configuration file must remain built in")

    def test_b38_env_short_chdir(self):
        """B38: env -C nested shell writes stay tied to the selected directory."""
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "env -C " + str(self.laneboss) + " sh -c 'printf x > org.toml'")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B38 env -C must preserve the protected directory candidate")

    def test_b39_env_long_chdir(self):
        """B39: both long env --chdir spellings retain protected-path checks."""
        self.set_hook_mode("blacklist")
        commands = (
            "env --chdir=" + str(self.laneboss) + " bash -c 'printf x > org.toml'",
            "env --chdir " + str(self.laneboss) + " sh -c 'printf x > shared/hooks/rules.toml'",
        )
        for command in commands:
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "deny",
                             "B39 env --chdir must preserve the protected directory candidate")

    def test_b40_function_copy(self):
        """B40: a function keyword body exposes embedded copy writes."""
        self.set_hook_mode("blacklist")
        target = str(self.laneboss / "org.toml")
        output = self.shell("claude", "function write_policy { cp payload " + target + "; }; write_policy")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B40 function keyword bodies must preserve protected copy checks")

    def test_b41_variable_protected_suffix(self):
        """B41: a literal protected suffix remains refused through a variable prefix."""
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("claude", 'printf x > "${POLICY}/shared/services/guide.toml"', {"POLICY": str(self.laneboss)})
        self.assertEqual(output["permissionDecision"], "deny",
                         "B41 a protected suffix after expansion must remain refused")

    def test_b42_suffix_control(self):
        """B42: an unresolved variable prefix with an ordinary suffix remains allowed."""
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("claude", 'printf x > "${OUT}/notes.txt"', {"OUT": str(self.worktree)})
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B42 an ordinary unresolved target must remain R26-allowed")

    def test_must_codex_home_config(self):
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("codex", 'printf x >> "$CODEX_HOME/config.toml"',
                                     {"CODEX_HOME": str(self.instance_dir / ".codex")})
        self.assertEqual(output["permissionDecision"], "deny",
                         "must-codex-home-config must refuse a variable-spelled Codex settings write")

    def test_must_policy_one_level(self):
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("claude", 'printf x > "$POLICY/org.toml"',
                                     {"POLICY": str(self.laneboss)}, event_cwd=self.org)
        self.assertEqual(output["permissionDecision"], "deny",
                         "must-policy-one-level must refuse a variable-spelled org configuration write")

    def test_must_cfg_var_judge_defs(self):
        self.set_hook_mode("blacklist")
        self.guide(judge="guard")
        output = self.shell_with_env(
            "claude", 'true; printf x > "$CFG/config.toml"',
            {"CFG": str(self.config_dir)})
        self.assertEqual(output["permissionDecision"], "deny",
                         "must-cfg-variable-judge-definitions must refuse a variable-spelled launcher configuration write")

    def test_must_home_var_judge_defs(self):
        self.set_hook_mode("blacklist")
        self.guide(judge="guard")
        judge_config = "guide" + "-demo"
        output = self.shell("claude", 'true; printf x > "$HOME/.config/laneboss/configs/' + judge_config + '/config.toml"')
        self.assertEqual(output["permissionDecision"], "deny",
                         "must-home-variable-judge-definitions must refuse a HOME-spelled launcher configuration write")

    def test_must_tilde_judge_definitions(self):
        self.set_hook_mode("blacklist")
        self.guide(judge="guard")
        judge_config = "guide" + "-demo"
        output = self.shell("claude", 'true; printf x > ~/.config/laneboss/configs/' + judge_config + '/config.toml')
        self.assertEqual(output["permissionDecision"], "deny",
                         "must-tilde-judge-definitions must refuse a tilde-spelled launcher configuration write")

    def test_must_policy_parent_remove(self):
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("claude", 'rm -rf "$POLICY/shared"', {"POLICY": str(self.laneboss)})
        self.assertEqual(output["permissionDecision"], "deny",
                         "must-policy-parent-remove must refuse removal of a protected policy parent")

    def test_must_quoted_space_dotdot(self):
        self.set_hook_mode("blacklist")
        (self.laneboss / "x y").mkdir()
        output = self.shell_with_env(
            "claude", 'printf x > "$POLICY/x y/../shared/hooks/rules.toml"', {"POLICY": str(self.laneboss)})
        self.assertEqual(output["permissionDecision"], "deny",
                         "must-quoted-space-dotdot must preserve the quoted redirect target")

    def test_control_literal_shared_hooks(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "git mv src/shared/hooks/useA.ts src/shared/hooks/useB.ts")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "control-literal-shared-hooks must remain R26-allowed")

    def test_control_literal_shared_services(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "make lint; cp README.md src/app/shared/services/api.service.ts")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "control-literal-shared-services must remain R26-allowed")

    def test_control_quoted_arrow(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", 'echo "auth -> src/shared/hooks/useAuth.ts"; make test')
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "control-quoted-arrow must remain R26-allowed")

    def test_b43_brace_protected(self):
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("claude", 'printf x > ".laneboss/{shared,org}.toml"', {}, event_cwd=self.org)
        self.assertEqual(output["permissionDecision"], "deny",
                         "B43 brace expansion must refuse a protected alternative")

    def test_b44_brace_control(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", 'printf x > "{result,scratch}.txt"')
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B44 ordinary brace expansion must remain R26-allowed")

    def test_b45_glob_protected(self):
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("claude", 'printf x > ".laneboss/o*.toml"', {}, event_cwd=self.org)
        self.assertEqual(output["permissionDecision"], "deny",
                         "B45 glob expansion must refuse a protected match")

    def test_b46_glob_control(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", 'printf x > "result*.txt"')
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B46 ordinary glob spelling must remain R26-allowed")

    def test_b47_fd_redirect_protected(self):
        self.set_hook_mode("blacklist")
        output = self.shell_with_env("claude", "printf x 3> .laneboss/org.toml", {}, event_cwd=self.org)
        self.assertEqual(output["permissionDecision"], "deny",
                         "B47 file-descriptor redirects must refuse protected targets")

    def test_b48_fd_redirect_control(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "printf x 3> result.txt")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B48 ordinary file-descriptor redirects must remain R26-allowed")

    def test_b49_double_nested_shell(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "env -C " + str(self.laneboss) + " sh -c 'sh -c \"printf x > org.toml\"'")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B49 a second nested shell must retain the protected directory")
        control = self.shell("claude", "env -C " + str(self.worktree) + " sh -c 'sh -c \"printf x > result.txt\"'")
        self.assertEqual((control["permissionDecision"], control["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B49 a second nested shell in the worktree must remain ordinary")

    def test_b50_ansic_protected(self):
        self.set_hook_mode("blacklist")
        target = str(self.laneboss / "org.toml")
        output = self.shell("claude", "sh -c $'printf x > " + target + "'")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B50 an ANSI-C nested body must refuse a protected target")

    def test_b51_eval_ansic_protected(self):
        self.set_hook_mode("blacklist")
        target = str(self.laneboss / "org.toml")
        output = self.shell("claude", "eval $'printf x > " + target + "'")
        self.assertEqual(output["permissionDecision"], "deny",
                         "B51 eval must inspect an ANSI-C body")

    def test_b52_ansic_control(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "sh -c $'echo use > arrow'")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B52 an ordinary ANSI-C body must remain R26-allowed")

    def test_b53_laneboss_org_write(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "laneboss org render " + str(self.org))
        self.assertEqual(output["permissionDecision"], "deny",
                         "B53 declared org writes must still protect policy inputs without an annotation")
        self.assertEqual(output["permissionDecisionReason"].splitlines()[0], PROTECTED_FILES)

    def test_b54_laneboss_db_write(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "laneboss decisions add --db " + str(self.store) + " --file " + str(self.brief_file))
        self.assertEqual(output["permissionDecision"], "deny",
                         "B54 declared database writes must still protect the store without an annotation")
        self.assertEqual(output["permissionDecisionReason"].splitlines()[0], PROTECTED_FILES)

    def test_b55_laneboss_read_control(self):
        self.set_hook_mode("blacklist")
        output = self.shell("claude", "laneboss state events --config guide-demo")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                         "B55 an ordinary parsed Laneboss read must remain allowed")

    def test_b56_blacklist_boundary(self):
        self.prepare_boundary_lane()
        self.set_hook_mode("blacklist")
        outside = self.org / "worktrees" / ("outside-blacklist-" + uuid.uuid4().hex[:12])
        refused = self.recorded_hook("claude", "Write", {"file_path": str(outside), "content": "x"})
        self.assertEqual(refused["permissionDecision"], "deny")
        self.assertIn("lanes may write only inside their recorded worktree", refused["permissionDecisionReason"])
        inside = self.worktree / ("inside-blacklist-" + uuid.uuid4().hex[:12])
        allowed = self.recorded_hook("claude", "Write", {"file_path": str(inside), "content": "x"})
        self.assertEqual((allowed["permissionDecision"], allowed["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))

    def test_b57_boundary_grant(self):
        self.set_hook_mode("blacklist")
        outside = self.org / ("reviewed-repository-" + uuid.uuid4().hex[:12]) / "outside.txt"
        refused = self.hook("claude", "Write", {"file_path": str(outside), "content": "x"})
        self.assertEqual(refused["permissionDecision"], "deny")
        self.assertIn("lanes may write only inside their recorded worktree", refused["permissionDecisionReason"])
        grant = self.laneboss / "shared" / "hooks" / "boundary.toml"
        grant.write_text("allow_worktree_writes = true\n")
        allowed = self.hook("claude", "Write", {"file_path": str(outside), "content": "x"})
        self.assertEqual((allowed["permissionDecision"], allowed["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        edited = self.hook("claude", "Write", {"file_path": str(grant), "content": "allow_worktree_writes = false\n"})
        self.assertEqual(edited["permissionDecision"], "deny")
        self.assertTrue(edited["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))

    def test_b58_penta_nested_shell(self):
        self.set_hook_mode("blacklist")

        def nested(target):
            body = "printf x > " + target
            for _ in range(4):
                body = "sh -c " + shlex.quote(body)
            return "sh -c " + shlex.quote(body)

        protected = self.shell("claude", nested(str(self.laneboss / "org.toml")))
        self.assertEqual(protected["permissionDecision"], "deny")
        self.assertIn("beyond the inspection depth", protected["permissionDecisionReason"])
        control = self.shell("claude", nested(str(self.worktree / "penta.txt")))
        self.assertEqual((control["permissionDecision"], control["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))

    def test_b59_failed_cd_tmux(self):
        """B59: an opaque tmux payload after a failed cd still reaches protected-path checks."""
        self.set_hook_mode("blacklist")
        target = str(self.laneboss / "org.toml")
        for runner in RUNNERS:
            control = self.shell(runner, 'cd "$DIR" && tmux ls')
            self.assertEqual((control["permissionDecision"], control["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
            output = self.shell(runner, "cd \"$DIR\" && tmux new-session -d 'printf x > " + target + "'")
            self.assertEqual(output["permissionDecision"], "deny",
                             "B59 a failed cd must not hide a protected tmux payload")
            self.assertTrue(output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))

    def test_b60_failed_cd_eval_push(self):
        """B60: a failed cd must not hide a literal push inside eval."""
        self.set_hook_mode("blacklist")
        for runner in RUNNERS:
            control = self.shell(runner, 'cd "$DIR" && eval "git status"')
            self.assertEqual((control["permissionDecision"], control["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
            output = self.shell(runner, 'cd "$DIR" && eval "git push origin main"')
            self.assertEqual(output["permissionDecision"], "deny",
                             "B60 a failed cd must not hide an eval push")
            self.assertTrue(output["permissionDecisionReason"].startswith("[no-push] Refuses:"))

    def test_b61_failed_cd_lane_write(self):
        """B61: a lane write after a failed cd still uses the worktree boundary."""
        self.prepare_boundary_lane()
        self.set_hook_mode("blacklist")
        for runner in RUNNERS:
            tool, field = ("Bash", "command") if runner == "claude" else ("exec_command", "cmd")
            control = self.recorded_hook(runner, tool, {field: 'cd "$DIR" && make > ' +
                                                       shlex.quote(str(self.worktree / "make-control.log"))})
            self.assertEqual((control["permissionDecision"], control["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
            output = self.recorded_hook(runner, tool, {field: 'cd "$DIR" && make > /tmp/lb-blacklist-p2.log'})
            self.assertEqual(output["permissionDecision"], "deny",
                             "B61 a failed cd must not hide a lane worktree write")
            self.assertIn("lanes may write only inside their recorded worktree", output["permissionDecisionReason"])


    def test_b62_ansi_secret_reads(self):
        """B62: decoded read operands keep the secret policy without refusing ordinary encoded data."""
        self.set_hook_mode("blacklist")
        secret = token("guarded") + ".fixture"
        self.add_legacy_rule("encoded-secret", "secret-read", [secret])
        encoders = (lambda text: "".join("\\x%02x" % ord(c) for c in text),
                    lambda text: "".join("\\%03o" % ord(c) for c in text),
                    lambda text: "".join("\\u%04x" % ord(c) for c in text))
        for runner in RUNNERS:
            for encode in encoders:
                word = shlex.quote(str(self.worktree) + "/") + "$'" + encode(secret) + "'"
                public = shlex.quote(str(self.worktree) + "/") + "$'" + encode("public.txt") + "'"
                for control in ("cat " + public, "echo " + word):
                    output = self.shell(runner, control)
                    self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
                for command in ("cat " + word, "head -n 1 " + word, "cat < " + word):
                    output = self.shell(runner, command)
                    self.assertEqual(output["permissionDecision"], "deny", "B62 an encoded secret read must refuse")
                    self.assertEqual(output["permissionDecisionReason"].splitlines()[0],
                                     "org hook fails closed: ANSI-C shell quoting cannot be inspected")

    @staticmethod
    def ansi_word(text):
        return "$'" + "".join("\\x%02x" % byte for byte in text.encode()) + "'"

    def ansi_canary(self, name):
        self.set_hook_mode("blacklist")
        secret = self.worktree / (token(name) + ".fixture")
        public = self.worktree / (token("public") + ".txt")
        secret.write_text("harmless secret-policy canary\n")
        public.write_text("harmless public control\n")
        self.add_legacy_rule(name, "secret-read", [secret.name])
        return secret, public

    def check_ansi_pair(self, canary, controls, message):
        for runner in RUNNERS:
            with self.subTest(runner=runner, canary=message):
                for control in controls:
                    output = self.shell(runner, control)
                    self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]),
                                     ("allow", PLAIN_ALLOW), message + " control must stay allowed")
                output = self.shell(runner, canary)
                self.assertEqual(output["permissionDecision"], "deny", message)
                self.assertEqual(output["permissionDecisionReason"].splitlines()[0],
                                 "org hook fails closed: ANSI-C shell quoting cannot be inspected")

    def test_b63_ansi_depth_control(self):
        """B63: the fifth nested body is not allowed to hide an ANSI-C read."""
        secret, public = self.ansi_canary("ansi-depth-secret")

        def nested(command, depth):
            for _ in range(depth):
                command = "sh -c " + shlex.quote(command)
            return command

        self.check_ansi_pair(nested("cat " + self.ansi_word(str(secret)), 5),
                             [nested("echo " + self.ansi_word(str(secret)), 5),
                              nested("cat " + self.ansi_word(str(public)), 2)],
                             "B63 a capped nested encoded read must refuse")

    def test_b64_ansi_body_control(self):
        """B64: body provenance survives decoding, nested eval, and invoked aliases."""
        secret, public = self.ansi_canary("ansi-body-secret")
        body = self.ansi_word('cat "$INPUT" ' + shlex.quote(str(secret)))
        echo = self.ansi_word('echo "$INPUT" ' + shlex.quote(str(secret)))
        public_body = self.ansi_word("cat " + shlex.quote(str(public)))
        for wrapper in ("bash -c ", "eval "):
            self.check_ansi_pair(wrapper + body, [wrapper + echo, wrapper + public_body],
                                 "B64 a decoded body must retain its inspection failure")
        self.check_ansi_pair("alias inspect_read=" + body + "; inspect_read",
                             ["alias inspect_read=" + echo + "; inspect_read"],
                             "B64 an invoked alias must retain ANSI-C provenance")

    def test_b65_ansi_decoder_control(self):
        """B65: empty and adjacent valid fragments preserve decoded secret/public paths."""
        secret, public = self.ansi_canary("ansi-decode-secret")
        prefix = shlex.quote(str(self.worktree) + "/") + "$''"
        word = prefix + self.ansi_word(secret.name)
        self.check_ansi_pair("cat " + word, ["cat " + prefix + self.ansi_word(public.name), "echo " + word],
                             "B65 valid lexer fragments must preserve the protected basename")

    def test_b66_ansi_inspection_control(self):
        """B66: a failed argv inspection must not discard the encoded read operand."""
        secret, public = self.ansi_canary("ansi-inspect-secret")
        word = self.ansi_word(str(secret))
        self.check_ansi_pair('cat "$INPUT" ' + word,
                             ['echo "$INPUT" ' + word, "cat " + self.ansi_word(str(public))],
                             "B66 an argv error must not discard the encoded read")

    def test_b67_ansi_output_controls(self):
        """B67: output arguments stay allowed, but an input redirect beside them remains protected."""
        secret, public = self.ansi_canary("ansi-output-secret")
        for runner in RUNNERS:
            self.assertEqual(self.shell(runner, "echo " + self.ansi_word(secret.name))["permissionDecisionReason"], PLAIN_ALLOW)
            self.assertEqual(self.shell(runner, "printf '%s' " + self.ansi_word(str(public)))["permissionDecisionReason"], PLAIN_ALLOW)
            output = self.shell(runner, "printf '%s' < " + self.ansi_word(str(secret)))
            self.assertEqual(output["permissionDecision"], "deny", "B67 an output command must not hide an input read")
            self.assertEqual(output["permissionDecisionReason"].splitlines()[0],
                             "org hook fails closed: ANSI-C shell quoting cannot be inspected")

    def test_b69_ansi_body_subst(self):
        """B69: decoded body substitutions fail closed for reads and remain safe for echo."""
        secret, public = self.ansi_canary("ansi-body-substitution")
        body = self.ansi_word("cat $INPUT " + shlex.quote(str(secret)))
        echo = self.ansi_word("echo $INPUT " + shlex.quote(str(public)))
        for runner in RUNNERS:
            self.assertEqual(self.shell(runner, "bash -c " + echo)["permissionDecisionReason"], PLAIN_ALLOW)
            output = self.shell(runner, "bash -c " + body)
            self.assertEqual(output["permissionDecision"], "deny", "B69 a substitution in a decoded body must not hide reads")
            self.assertEqual(output["permissionDecisionReason"].splitlines()[0],
                             "org hook fails closed: ANSI-C shell quoting cannot be inspected")

    def test_b70_ansi_adjacent_controls(self):
        """B70: an ordinary command beside ANSI-C output keeps normal public/secret policy."""
        secret, public = self.ansi_canary("ansi-adjacent-secret")
        for runner in RUNNERS:
            allowed = self.shell(runner, "echo " + self.ansi_word(str(public)) + " && cat " + str(public))
            self.assertEqual((allowed["permissionDecision"], allowed["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
            refused = self.shell(runner, "echo " + self.ansi_word(str(public)) + " && cat " + str(secret))
            self.assertEqual(refused["permissionDecision"], "deny", "B70 the non-ANSI reader must retain secret policy")

    def test_g16_report_decided_question(self):
        """G16 fails if report --ask sends a decided question, loses the exact
        recorded answer, uses another lane's scope, or changes ordinary delivery."""
        decision = self.decide(question="Which review format " + token("format") + "?", level=3)
        self.guide(judge="guard")
        _, rows = self.runner_question(decision.question)
        self.assertIs(rows[0].get("decided"), True, "G16 report --ask must echo a recorded answer")
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["sent"], rows[0]["match"], rows[0]["judge"]), (False, "exact", "not-asked"))
        self.assertEqual((rows[0]["decision"]["id"], rows[0]["decision"]["answer"]), (decision.id, decision.answer))
        events = [json.loads(line) for line in self.cli("event", "tail", "--config", "guide-demo").stdout.splitlines()]
        self.assertEqual([event for event in events if event["kind"] == "report.sent"], [],
                         "G16 a decided question must not reach any report channel")
        _, elsewhere = self.runner_question(decision.question, project="other")
        self.assertIs(elsewhere[0]["decided"], False, "G16 scope belongs to the authenticated asking lane")
        self.assertTrue(any(row.get("channel") == "dashboard" and row["status"] == "delivered" for row in elsewhere))
        _, ordinary = self.runner_question(decision.question, ask=False)
        self.assertTrue(all("decided" not in row for row in ordinary))
        self.assertTrue(any(row["channel"] == "dashboard" and row["status"] == "delivered" for row in ordinary),
                        "G16 without --ask the existing report channels still deliver")
        marker = token("paraphrase")
        self.judge(rules=[self.rule(ANSWERS, 0.93, decision=decision.marker, question=marker)])
        _, scored = self.runner_question("Does that review format apply? " + marker)
        self.assertEqual((scored[0]["decided"], scored[0]["match"], scored[0]["decision"]["id"]),
                         (True, "judge", decision.id), "G16 report questions must use the same judge dial")


    def test_g17_missing_unreadable_guide(self):
        """G17 fails if a missing guide changes baseline, or unreadable settings
        refuse by default or lose their field notice; neither state may query a judge."""
        self.decide("the guide source")
        for runner in RUNNERS:
            self.reset_guide()
            count = len(self.asked())
            missing = self.shell(runner, "true")
            self.assertEqual((missing["permissionDecision"], missing["permissionDecisionReason"]),
                             ("allow", PLAIN_ALLOW), "G17 a missing guide must leave baseline unchanged")
            self.assertNotIn("additionalContext", missing)
            self.assertEqual(len(self.asked()), count)
            self.guide_file.mkdir()
            unreadable = self.shell(runner, "true")
            self.assertEqual((unreadable["permissionDecision"], unreadable["permissionDecisionReason"]),
                             ("allow", PLAIN_ALLOW), "G17 unreadable guide must warn by default")
            self.assertIn("config invalid: .laneboss/shared/services/guide.toml.file", unreadable.get("additionalContext", ""))
            self.assertEqual(self.receipts()[-1]["guard"]["band"], "settings-error")
            self.assertEqual(len(self.asked()), count)
        self.reset_guide()


    def test_g18_total_deadline(self):
        """Fails if slow decision asks lose their timeout result, exceed the
        rendered budget, or change the default baseline rather than noticing."""
        decision = self.decide("the deadline")
        path = self.config_dir / "config.toml"
        path.write_text(path.read_text().replace("timeout_seconds = 10", "timeout_seconds = 60"))
        for unavailable, expected in (("warn", "allow"), ("refuse", "allow")):
            self.guide(judge="guard", unavailable=unavailable)
            self.judge(mode="timeout")
            started = time.monotonic()
            output = self.shell("claude", "printf '%s' " + token("slow"))
            elapsed = time.monotonic() - started
            (self.directory / ("deadline-" + unavailable + ".json")).write_text(json.dumps({"elapsed": elapsed}))
            self.assertGreater(elapsed, 24, "G18 the actual slow adapter must hit the shared deadline")
            self.assertLess(elapsed, 35, "G18 decision judging must fit below the rendered hook timeout")
            self.assertEqual(output["permissionDecision"], expected, "G18 an unavailable judge may only warn")
            note = self.receipts()[-1]["guard"]
            self.assertEqual([item["outcome"] for item in note["decisions"]], ["timeout"])
            self.assertIn(decision.id, output["permissionDecisionReason"] + output.get("additionalContext", ""))
            if unavailable == "warn":
                self.assertEqual(output["permissionDecisionReason"], PLAIN_ALLOW)
            for runner in RUNNERS:
                settings = self.instance_dir / (".claude/settings.json" if runner == "claude" else ".codex/hooks.json")
                hook = json.loads(settings.read_text())["hooks"]["PreToolUse"][-1]["hooks"][0]
                self.assertEqual(hook["timeout"], 60, "G18 the rendered timeout must exceed the guard deadline")

    def test_g19_held_judge_lock(self):
        """Fails if a held directory flock blocks beyond the same deadline or
        its failure changes the default baseline without a timeout notice."""
        self.decide("the lock wait")
        self.guide(judge="guard")
        self.shell("claude", "true")
        directory = self.home / ".local" / "state" / "laneboss" / "guide-demo" / "judges"
        fd = os.open(directory, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            output = self.shell("claude", "printf '%s' " + token("locked"))
            elapsed = time.monotonic() - started
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertGreater(elapsed, 27, "G19 a real held lock must consume the guard budget")
        self.assertLess(elapsed, 35, "G19 a held lock must be bounded")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        self.assertEqual(self.receipts()[-1]["guard"]["decisions"][0]["outcome"], "timeout")
        self.assertIn("timeout", output.get("additionalContext", ""))

    def test_g20_missing_store_note(self):
        """Fails if an enabled guide silently loses its store without a receipt."""
        self.guide(judge="guard")
        self.store.unlink()
        output = self.shell("claude", "true")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW))
        self.assertEqual((self.receipts()[-1]["guard"]["band"], self.receipts()[-1]["guard"]["reason"]),
                         ("unavailable", "no-store"))
        self.assertEqual(self.asked(), [])

    def test_g21_scope_before_cap(self):
        """Fails if 1,000 newer records of another scope hide this lane's decision."""
        local = self.decide("the local decision", project="demo", level=3)
        for index in range(1001):
            self.decide("foreign record " + str(index), project="other", level=5)
        self.guide(judge="guard", projects=["demo"])
        self.judge(default=0.99)
        output = self.shell("claude", "true")
        self.assertEqual(output["permissionDecision"], "allow", "G21 other scopes cannot exhaust the local cap")
        self.assertIn(local.id, output.get("additionalContext", ""))
        self.assertEqual(len(self.asked()), 1)
        self.assertIn(local.id, "\n".join(self.asked()[0]["state"]["decisions"]))

    def test_g22_definition_protected(self):
        """Fails if broad write scope permits replacing the judge's definition."""
        self.guide(judge="guard")
        source = self.instance_dir / "instance.toml"
        text, count = re.subn(r"(?m)^writable_repos\s*=.*$", "writable_repos = " + json.dumps([str(self.home)]), source.read_text())
        self.assertEqual(count, 1)
        source.write_text(text)
        control = self.hook("claude", "Write", {"file_path": str(self.home / "ordinary.txt"), "content": "x"})
        self.assertEqual(control["permissionDecision"], "allow")
        for runner in RUNNERS:
            denied = self.hook(runner, "Write", {"file_path": str(self.config_dir / "config.toml"), "content": "x"})
            self.assertEqual(denied["permissionDecision"], "deny", "G22 the judge definition must be protected")
            self.assertTrue(denied["permissionDecisionReason"].startswith(PROTECTED_FILES))


    def test_g23_defaults_only_guide(self):
        """Fails if a default high decision score blocks instead of guiding."""
        decision = self.decide("the default guide")
        self.judge(default=0.99)
        for settings in ({}, {"jobs_refuse_threshold": 0.85}):
            self.guide(defaults=True, judge="guard", **settings)
            output = self.shell("claude", "true")
            self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                             "G23 decision guidance must never refuse with defaults")
            self.assertIn(decision.id, output.get("additionalContext", ""))
            self.assertEqual(self.receipts()[-1]["guard"]["band"], "warn")
        self.guide(judge="guard", refuse_threshold=0.85)
        self.assertEqual(self.shell("claude", "true")["permissionDecision"], "allow",
                         "G23 legacy thresholds cannot grant refusal authority")

    def test_g24_bad_settings_reads(self):
        """Fails if guide/history errors block exempt reads, default Bash errors
        do not warn with their field, or legacy unavailable=refuse stops being warn-only."""
        target = self.worktree / "readable.txt"
        marker = token("read")
        target.write_text(marker + "\n")
        calls = (("Read", {"file_path": str(target)}), ("read_file", {"path": str(target)}),
                 ("Grep", {"pattern": marker, "path": str(target)}),
                 ("Glob", {"pattern": "*.txt", "path": str(self.worktree)}),
                 ("LS", {"path": str(self.worktree)}))

        def reads():
            for runner in RUNNERS:
                for tool, tool_input in calls:
                    output = self.hook(runner, tool, tool_input)
                    self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]),
                                     ("allow", PLAIN_ALLOW), "G24 invalid guide must not block reads")
                    self.assertNotIn("additionalContext", output)

        self.guide_file.write_text("judge = [\n")
        reads()
        for runner in RUNNERS:
            output = self.shell(runner, "true")
            self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", PLAIN_ALLOW),
                             "G24 syntax errors must warn by default")
            self.assertIn("guide.toml.syntax", output.get("additionalContext", ""))
        self.reset_guide()
        self.guide_file.mkdir()
        reads()
        for runner in RUNNERS:
            output = self.shell(runner, "true")
            self.assertEqual(output["permissionDecision"], "allow", "G24 unreadable guide must warn by default")
            self.assertIn("guide.toml.file", output.get("additionalContext", ""))
        self.reset_guide()
        for history_broken in (False, True):
            if history_broken:
                (self.services / "history.toml").write_text("db = [\n")
            for policy, expected in (("warn", "allow"), ("refuse", "allow")):
                self.guide(judge="guard", warn_threshold="invalid", unavailable=policy)
                reads()
                for runner in RUNNERS:
                    output = self.shell(runner, "true")
                    self.assertEqual(output["permissionDecision"], expected, "G24 settings errors must honour the explicit failure policy")
                    note = self.receipts()[-1]["guard"]
                    self.assertEqual((note["band"], note["unavailable"]), ("settings-error", "warn"))
                    self.assertTrue(note["field"].endswith(".warn_threshold"))
                    if expected == "allow":
                        self.assertEqual(output["permissionDecisionReason"], PLAIN_ALLOW)
                        self.assertIn(note["field"], output.get("additionalContext", ""))
                    else:
                        self.assertIn("config invalid: " + note["field"], output["permissionDecisionReason"])
                        self.assertNotIn("additionalContext", output)
        self.guide(judge="guard", unavailable="refuse")
        reads()
        self.assertEqual(self.shell("claude", "true")["permissionDecision"], "allow",
                         "G24 unreadable history follows the explicit failure policy without blocking reads")
        self.assertEqual(self.asked(), [], "G24 invalid guide/history must never query a judge")

    def test_g25_judge_config_scope(self):
        """Fails if the launcher's binding hides the guide/history judge config
        from the protected set while an ordinary broad-scope write is allowed."""
        other = self.config_dir.parent / "judge-other" / "config.toml"
        other.parent.mkdir()
        text, count = re.subn(r'(?m)^name = "guide-demo"$', 'name = "judge-other"',
                             (self.config_dir / "config.toml").read_text())
        self.assertEqual(count, 1)
        other.write_text(text)
        source = self.instance_dir / "instance.toml"
        text, count = re.subn(r"(?m)^writable_repos\s*=.*$", "writable_repos = " + json.dumps([str(self.home)]), source.read_text())
        self.assertEqual(count, 1)
        source.write_text(text)
        for inherited in (False, True):
            if inherited:
                (self.services / "history.toml").write_text('configuration = "judge-other"\n')
                self.guide_file.write_text('judge = "guard"\njobs = false\n')
            else:
                self.guide(judge="guard", configuration="judge-other")
            for runner in RUNNERS:
                control = self.hook(runner, "Write", {"file_path": str(self.home / "ordinary.txt"), "content": token("ordinary")},
                                    env={"LANEBOSS_CONFIG": "guide-demo"})
                self.assertEqual(control["permissionDecision"], "allow", "G25 ordinary broad-scope writes must remain allowed")
                for protected in (other, self.config_dir / "config.toml"):
                    denied = self.hook(runner, "Write", {"file_path": str(protected), "content": token("replacement")},
                                       env={"LANEBOSS_CONFIG": "guide-demo"})
                    self.assertEqual(denied["permissionDecision"], "deny", "G25 both the binding and real judge configuration must be protected")
                    self.assertTrue(denied["permissionDecisionReason"].startswith(PROTECTED_FILES))
                    self.assertNotIn("additionalContext", denied)
        self.assertEqual(self.asked(), [])

    def test_g26_all_judge_sources(self):
        """Fails if an independent source loses protection after overrides or
        parse failures, or a string/comment protects an unrelated configuration."""
        template = (self.config_dir / "config.toml").read_text()
        targets = {}
        for kind in ("org", "raw", "unrelated"):
            name = token(kind)
            path = self.config_dir.parent / name / "config.toml"
            path.parent.mkdir()
            text, count = re.subn(r'(?m)^name = "guide-demo"$', 'name = "' + name + '"', template)
            self.assertEqual(count, 1)
            path.write_text(text)
            targets[kind] = (name, path)
        source = self.instance_dir / "instance.toml"
        text, count = re.subn(r"(?m)^writable_repos\s*=.*$", "writable_repos = " + json.dumps([str(self.home)]), source.read_text())
        self.assertEqual(count, 1)
        source.write_text(text)
        org = self.laneboss / "org.toml"
        text = org.read_text()
        self.assertEqual(text.count("[history]"), 0, "G26 fixture must add one org history source")
        org.write_text(text + '\n[history]\nconfiguration = ' + json.dumps(targets["org"][0]) + '\n')
        # The isolated harness already omits LANEBOSS_CONFIG. An empty service
        # override makes the org source independent of the effective resolver,
        # so dropping that source cannot be masked by a duplicate candidate.
        (self.services / "history.toml").write_text('configuration = ""\n')
        self.reset_guide()

        def protected(kind, assertion):
            for runner in RUNNERS:
                output = self.hook(runner, "Write", {"file_path": str(targets[kind][1]), "content": token("replace")})
                self.assertEqual(output["permissionDecision"], "deny", assertion)
                self.assertTrue(output["permissionDecisionReason"].startswith(PROTECTED_FILES))
                self.assertNotIn("additionalContext", output)

        def unrelated():
            for runner in RUNNERS:
                output = self.hook(runner, "Write", {"file_path": str(targets["unrelated"][1]), "content": token("ordinary")})
                self.assertEqual(output["permissionDecision"], "allow", "G26 unrelated configuration must remain writable")

        protected("org", "G26 org history configuration must be protected")
        unrelated()
        self.guide_file.write_text('judge = [\n')
        protected("org", "G26 malformed guide must not hide the org history source")
        unrelated()
        for raw in (json.dumps(targets["raw"][0]), "'''" + targets["raw"][0] + "'''"):
            self.guide_file.write_text('configuration = ' + raw + '\njudge = [\n')
            protected("org", "G26 every org candidate must stay protected")
            protected("raw", "G26 malformed guide must retain its readable configuration key")
            unrelated()
        self.guide_file.write_text('note = """\nconfiguration = ' + json.dumps(targets["unrelated"][0]) +
                                   '\n"""\njudge = [\nconfiguration = ' + json.dumps(targets["raw"][0]) + '\n')
        protected("raw", "G26 a readable key after an error must stay protected")
        unrelated()
        # Removing only the org fixture source proves that the raw guide key
        # alone still contributes when normal guide parsing fails.
        org.write_text(text)
        protected("raw", "G26 a raw guide configuration must survive without another source")
        unrelated()
        self.assertEqual(self.asked(), [], "G26 protected paths are checked before any judge")

    def test_ask_secret_answer_withheld(self):
        """Fails if either --ask route echoes a secret-bearing recorded answer."""
        lane = self.turn_target()
        decision = self.decide(question="Which review " + token("question") + "?",
                               answer="password = 'harmless-canary'; row " + token("answer"), level=3)
        self.echo_answer = decision.answer
        with sqlite3.connect(self.store) as stored:
            answer_bytes = stored.execute("SELECT verbatim FROM records WHERE id = ?", (decision.id,)).fetchone()[0]
        self.assertEqual(answer_bytes.decode(), decision.answer, "the store must retain the actual echo input bytes")
        sent = self.send(lane, decision.question, "--ask")
        self.assertEqual(sent.returncode, 0, sent.stderr)
        self.echo_report_marker = self.directory / "report-mutant-reached"
        _, report_rows = self.runner_question(decision.question, fault_marker=self.echo_report_marker)
        self.echo_observed = {"send": json.loads(sent.stdout), "report": report_rows[0]}
        for route, output in self.echo_observed.items():
            self.assertIs(output.get("withheld"), True, "secret ask answer must be withheld: " + route)
            self.assertIs(output["decided"], True)
            self.assertIs(output["sent"], False)
            self.assertEqual(output["decision"]["question"], "[withheld: looks like a credential]")
            self.assertEqual(output["decision"]["answer"], "[withheld: looks like a credential]")
            self.assertNotIn("harmless-canary", json.dumps(output))
        clean = self.decide(question="Which clean review " + token("question") + "?",
                            answer="Keep the review requirement " + token("answer") + ".", level=3)
        clean_send = self.send(lane, clean.question, "--ask")
        self.assertEqual(clean_send.returncode, 0, clean_send.stderr)
        _, clean_report = self.runner_question(clean.question)
        for output in (json.loads(clean_send.stdout), clean_report[0]):
            self.assertIs(output["withheld"], False)
            self.assertEqual(output["decision"]["answer"], clean.answer)


class GuidePanicRows(GuideBase):
    def setUp(self):
        self.binary_override = FAULTS
        self.fault_point = self.fault_point or "guide-batch-panic"
        super().setUp()

    def test_g27_batch_panic_is_advisory(self):
        """A reached real batch panic must allow with decision-scoped unscored advice."""
        decision = self.decide("the panic boundary")
        self.guide(judge="guard")
        self.assertFalse(self.marker.exists(), "G27 the panic marker must start absent")
        for runner in RUNNERS:
            output = self.shell(runner, "printf '%s' " + token("act"))
            self.assertTrue(self.marker.is_file(), "G27 the real batch panic must fire")
            self.assertEqual(output["permissionDecision"], "allow", "G27 a batch panic must not refuse ordinary work")
            context = output.get("additionalContext", "")
            self.assertIn(decision.id, context)
            self.assertIn("not scored", context.lower())
            note = self.receipts()[-1]["guard"]
            self.assertEqual(note["band"], "unscored")
            self.assertEqual(note["decisions"][0]["decision"], decision.id)
            self.assertNotEqual(note["decisions"][0]["outcome"], "answered")
            self.assertIsNone(note["decisions"][0]["score"])
            self.assertEqual(self.asked(), [], "G27 the panic boundary precedes adapter execution")

class GuideMutantsTest(unittest.TestCase):
    def test_batch_panic_recover_mutant(self):
        """The same reached panic turns into deny when the recover is removed."""
        mutant = GuidePanicRows("test_g27_batch_panic_is_advisory")
        mutant.fault_point = "guide-batch-no-recover"
        red = unittest.TestResult()
        mutant.run(red)
        self.assertEqual(red.errors, [], "G27 the mutant must fail the assertion, not its fixture")
        self.assertEqual(len(red.failures), 1)
        self.assertIn("G27 a batch panic must not refuse ordinary work", red.failures[0][1])
        self.assertTrue(mutant.marker.is_file(), "G27 the unrecovered panic must actually fire")
        restored = GuidePanicRows("test_g27_batch_panic_is_advisory")
        restored.fault_point = "guide-batch-panic"
        green = unittest.TestResult()
        restored.run(green)
        self.assertEqual((green.errors, green.failures), ([], []))
        self.assertTrue(restored.marker.is_file(), "G27 the recovered control must also fire the panic")
        print("RESTORED GUIDE MUTANT guide-batch-no-recover caught: G27 a batch panic must not refuse ordinary work")

    def test_restored_rows_reject_each_mutant(self):
        """G8: fails unless each of the real faults is reached, an ordinary row catches the intended defect, and the
        restored row passes on the installed release. The first four are the dial's own defects. The next six reintroduce
        what a review of the guard found: the guard's answer overriding a refusal of the org's rules, the guard's inputs
        left unprotected, a decision left out without a word, a long call judged by its head only, an answer about a
        withheld placeholder taken for a score, and the text of a multiple edit kept from the judge. The final seven
        cover blacklist precedence, references, default observation, state protection, segment fallback and the two
        legacy compatibility matchers; the final parser regressions cover candidate directories, swallowed gaps,
        raw assignments, R26 redirects, reserved syntax, lexer gaps, failed segments and eval. Adjacent B rows cover
        instance binding and the bounded judge deadline. The release additions also cover invalid settings, report echo,
        complete typed scoring, read exemptions, and default warnings under invalid settings."""
        cases = (
            ("guide-ignore-thresholds", "test_g3_dial_bands", "G3 high probability must warn"),
            ("guide-no-warning", "test_g3_dial_bands", "G3 the warn band must warn"),
            ("guide-omit-section", "test_g1_brief_carries_decisions",
             "G1 the brief must carry the decision section"),
            ("guide-no-echo", "test_g6_decided_question",
             "G6 a question already decided must get the recorded answer back"),
            ("guide-no-echo", "test_g16_report_decided_question",
             "G16 report --ask must echo a recorded answer"),
            ("guide-guard-overrides-refusal", "test_g9_policy_refusals_hold",
             "G9 a refusal of the org policy must hold"),
            ("guide-services-unprotected", "test_g10_guard_inputs_are_protected",
             "G10 the guard's inputs must be protected like the hook policy"),
            ("guide-skip-left-out", "test_g11_left_out_decisions_reported",
             "G11 a decision that max_decisions left out must be reported to the agent"),
            ("guide-head-only", "test_g12_long_calls_are_read_whole",
             "G12 a long call must be judged whole"),
            ("guide-withheld-scores", "test_g13_withheld_text_is_not_a_score",
             "G13 a text that the judge was not given must not pass as scored"),
            ("guide-multiedit-path-only", "test_g14_multiedit_is_judged",
             "G14 what a multiple edit writes must reach the judge"),
            ("orghook-bl-warn-first", "test_b4_refuse_beats_warn",
             "B4 a refuse entry must beat an overlapping warn entry"),
            ("orghook-bl-skip-ref", "test_b5_reference_entry_keeps_pattern",
             "B5 a decision reference must not disable its deterministic pattern"),
            ("orghook-bl-state-unprotected", "test_b7_shared_state_is_built_in",
             "B7 shared state must remain a built-in refusal"),
            ("orghook-bl-head-only", "test_b16_gap_push_fallback",
             "B16 the gap fallback must refuse a push after the first segment"),
            ("orghook-bl-exact-root", "test_b11_deny_subtree",
             "B11 legacy deny roots must cover descendants"),
            ("orghook-bl-secret-glob", "test_b12_secret_path",
             "B12 a legacy secret path must refuse"),
            ("orghook-bl-cd-unconditional", "test_b26_cd_failed_protected",
             "B26 a failed cd must retain the original protected directory candidate"),
            ("orghook-bl-gap-swallow", "test_b23_failed_secret",
             "B23 later secret reads must survive an earlier inspection failure"),
            ("orghook-bl-raw-narrow", "test_b27_assignment_protected",
             "B27 the raw check must inspect assignment values before stripping them"),
            ("orghook-bl-r26-opaque-refuse", "test_b19_var_redirect",
             "B19 an unknown variable redirect must remain ordinary incomplete work"),
            ("orghook-bl-suffix-limb", "test_b41_variable_protected_suffix",
             "B41 a protected suffix after expansion must remain refused"),
            ("orghook-bl-reserved-head", "test_b21_reserved_body_push_is_refused",
             "B21 reserved body syntax must not hide git push"),
            ("orghook-bl-lexer-head-only", "test_b22_ansi_push",
             "B22 ANSI-C quoting must preserve the later git push refusal"),
            ("orghook-bl-stop-failed", "test_b23_failed_secret",
             "B23 later secret reads must survive an earlier inspection failure"),
            ("orghook-bl-eval-opaque", "test_b24_eval_push_is_refused",
             "B24 eval must not hide a literal git push"),
            ("guide-settings-refuse-all", "test_g24_bad_settings_reads",
             "G24 invalid guide must not block reads"),
            ("judge-drop-org-source", "test_g26_all_judge_sources",
             "G26 org history configuration must be protected"),
        )
        for point, row, reason in cases:
            with self.subTest(mutant=point, row=row):
                mutant = GuideRows(row)
                mutant.binary_override = FAULTS
                mutant.fault_point = point
                red = unittest.TestResult()
                mutant.run(red)
                self.assertEqual(red.errors, [], "the mutant must fail an assertion, not its fixture")
                self.assertEqual(len(red.failures), 1, "an ordinary row must detect the actual mutant")
                self.assertIn(reason, red.failures[0][1])
                self.assertTrue(mutant.marker.is_file(), "the real mutation boundary must be reached")
                restored = GuideRows(row)
                restored.fault_point = point
                green = unittest.TestResult()
                restored.run(green)
                self.assertEqual(green.errors, [])
                self.assertEqual(green.failures, [], "the restored row must pass on the installed release")
                self.assertFalse(restored.marker.exists(), "release builds must ignore the requested mutation")
                print("RESTORED GUIDE MUTANT", point, "caught:", reason)


    def test_unscreened_echo_caught(self):
        """The ordinary --ask row must fail before the same tagged binary and release are restored."""
        point = "guide-echo-unscreened"
        row = GuideRows("test_ask_secret_answer_withheld")
        row.binary_override, row.fault_point = FAULTS, point
        red = unittest.TestResult()
        row.run(red)
        (row.directory / "echo-mutant-result.json").write_text(json.dumps({
            "errors": [trace for _, trace in red.errors],
            "failures": [trace for _, trace in red.failures],
            "observed": getattr(row, "echo_observed", {}),
        }) + "\n")
        self.assertEqual((red.errors, red.skipped), ([], []), "a fixture error is not a caught echo regression")
        self.assertEqual(red.testsRun, 1)
        self.assertEqual(len(red.failures), 1)
        self.assertIn("secret ask answer must be withheld", red.failures[0][1])
        self.assertTrue(row.marker.is_file(), "the real unscreened echo mutation must be reached")
        self.assertTrue(row.echo_report_marker.is_file(), "the report subprocess must reach the echo mutation")
        for output in row.echo_observed.values():
            self.assertIn("harmless-canary", output["decision"]["answer"],
                          "the changed product must actually echo the secret-shaped canary")
            self.assertEqual(output["decision"]["answer"], row.echo_answer,
                             "the mutant must bypass only the screen and echo the exact stored answer")
            self.assertIs(output["withheld"], False)
        for binary, requested in ((FAULTS, None), (RELEASE, point)):
            restored = GuideRows("test_ask_secret_answer_withheld")
            restored.binary_override, restored.fault_point = binary, requested
            green = unittest.TestResult()
            restored.run(green)
            self.assertEqual((green.errors, green.failures, green.skipped), ([], [], []))
            self.assertEqual(green.testsRun, 1)
            self.assertFalse(restored.marker.exists(), "the restored echo screen must be active")
            self.assertFalse(restored.echo_report_marker.exists(), "the restored report echo screen must be active")


if __name__ == "__main__":
    unittest.main()

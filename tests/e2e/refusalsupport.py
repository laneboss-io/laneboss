"""Helpers for the refusal tests: a configuration with guards and with runners whose stand-in program
(tests/e2e/sessionstandin.py) writes session records in each of the two formats while it runs (for text, the run's own
log), scenarios for that program, and helpers that read the refusal events back through the installed command.

Everything here is invented: the guards, their messages and the record lines. The record lines follow the shapes
docs/architecture.md describes under "Refusals".
"""

import datetime
import json
import os
import sys
import time

from . import lanesupport, support

SESSION = support.ROOT / "tests" / "e2e" / "sessionstandin.py"
FORMATS = ("claude-code", "text")
STRUCTURED = ("claude-code",)
RUNNER = {"claude-code": "claude", "text": "texter"}
TEMPLATES = {"claude-code": ["~/.claude/projects/*/*.jsonl"],
             "text": ["{log}"]}
GUARDS = r"""
[[guards]]
name = "doc-guard"
kind = "hook"
pattern = '^PreToolUse:[A-Za-z]+ hook error: \[[^]]*\]: BLOCKED by doc_guard'

[[guards]]
name = "perm"
kind = "permission"
pattern = '^Permission to use [A-Za-z]+ has been denied'

[[guards]]
name = "shell-guard"
pattern = '^shell-guard: refused'
"""
KINDS = ("lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed")

# The refused shell write and the later calls of acceptance test B.
REFUSED = ("cat > notes/plan.md <<'EOF'\n# Plan\n\n1. Stop the service.\n2. Then shutdown the host at midnight.\n"
           "3. Restart it after the backup.\nEOF")
REWORDED = REFUSED.replace("shutdown ", "")
SPLIT = ("cat > notes/plan.md <<'EOF'\n# Plan\n\n1. Stop the service.\nEOF",
         "cat >> notes/plan.md <<'EOF'\n2. Then shut down the host at midnight.\n3. Restart it after the backup.\nEOF")


def hook(what):
    """The text an invented hook guard answers a refused shell call with."""
    return ("PreToolUse:Bash hook error: [/opt/guards/doc-guard.sh]: BLOCKED by doc_guard: {}\n"
            "Reason: documents are written with the file tool, never through the shell.\n"
            "To run it anyway, start the command with the prefix GUARD_SKIP=1.".format(what))


def session_runner(name, fmt, templates=None, extra=""):
    command = [sys.executable, "-I", str(SESSION), fmt, "--lane", "{lane}", "--brief", "{brief}"]
    return ("[runners.{}]\ncommand = {}\nresume = {}\nrecords = [{{format = {}, paths = {}}}]\n{}\n".format(
        name, lanesupport.toml(command), lanesupport.toml(command + ["--message", "{message}"]),
        lanesupport.toml(fmt), lanesupport.toml(templates or TEMPLATES[fmt]), extra))


# Runners of single tests: two templates that reach the same file, a misspelled record directory, a template with a
# model placeholder, a record directory below the home and a recursive template.
EXTRA_RUNNERS = (
    ("twice", "claude-code", ["~/.claude/projects/*/*.jsonl", "~/.claude/./projects/*/*.jsonl"]),
    ("missing", "claude-code", ["~/.claude/projcets/*/*.jsonl"]),
    ("modelled", "claude-code", ["~/records/{model}/*.jsonl"]),
    ("linked", "claude-code", ["~/linked/*.jsonl"]),
    ("deep", "claude-code", ["~/deep/**/*.jsonl"]),
)


def refusal_config(name):
    return (lanesupport.lane_config(name) + "\n" + GUARDS + "\n"
            + "".join(session_runner(RUNNER[fmt], fmt) for fmt in FORMATS)
            + "".join(session_runner(runner, fmt, templates) for runner, fmt, templates in EXTRA_RUNNERS))


class RefusalTest(lanesupport.LaneTest):
    """The lane tests' configuration `alpha` with guards and the session stand-in's runners."""

    def add_config(self, name):
        directory = super().add_config(name)
        (directory / "config.toml").write_text(refusal_config(name), encoding="utf-8")
        return directory

    def scenario(self, lane, steps, run=None, config="alpha"):
        name = "{}.scenario.json".format(lane) if run is None else "{}.{}.scenario.json".format(lane, run)
        (self.records[config] / name).write_text(json.dumps({"steps": steps}), encoding="utf-8")

    def start_session(self, lane, fmt, steps, *arguments, config="alpha", worktree=None, runner=None,
                      model="session-model-1"):
        self.scenario(lane, steps, config=config)
        directory = worktree or self.scratch(config + "-" + lane)
        (directory / "notes").mkdir(exist_ok=True)
        return self.start(lane, "--runner", runner or RUNNER[fmt], "--model", model, "--worktree", directory,
                          *arguments, config=config)

    def coverage(self, lane, run=1, config="alpha"):
        return [item for item in self.refusals(lane, config=config)["coverage"] if item["run"] == run][0]

    def reasons(self, coverage):
        return sorted(item["reason"] for item in coverage["not_covered"])

    def refusals(self, lane=None, config="alpha", code=0):
        arguments = ["--lane", lane] if lane else []
        result = self.lane("refusals", *arguments, config=config, code=code)
        return json.loads(result.stdout) if code == 0 else result

    def scan(self, lane, config="alpha"):
        return self.lane_json("scan", "--lane", lane, config=config)

    def review(self, lane, refusal, path, verdict, *arguments, config="alpha", code=0):
        result = self.lane("review", "--lane", lane, "--refusal", refusal, "--path", path, "--verdict", verdict,
                           *arguments, config=config, code=code)
        return json.loads(result.stdout) if code == 0 else result

    def kind_events(self, lane, kind, config="alpha"):
        return [item for item in self.lane_events(lane, config=config) if item["kind"] == kind]

    def suspicion_of(self, lane, call_id, config="alpha"):
        """The workaround suspicions whose later call has this id."""
        return [item for item in self.kind_events(lane, "lane.workaround_suspected", config)
                if item["payload"]["call"]["id"] == call_id]

    def read_line(self, position):
        """The record line a position names, read at its byte offset."""
        with open(position["path"], "rb") as handle:
            handle.seek(position["offset"])
            return handle.readline().decode("utf-8")

    def marked(self, lane, name, run=1, config="alpha", timeout=lanesupport.UNTIL):
        """The wall-clock moment the stand-in's scenario marked with this name."""
        path = self.records[config] / "{}.{}.json".format(lane, run)
        deadline = time.monotonic() + timeout
        while True:
            if path.is_file():
                try:
                    marks = json.loads(path.read_text(encoding="utf-8")).get("marks", {})
                except ValueError:
                    marks = {}
                if name in marks:
                    return marks[name]
            if time.monotonic() > deadline:
                self.fail("the stand-in did not mark {} within {} s".format(name, timeout))
            time.sleep(0.05)

    def ended_by_itself(self, lane, run=1, config="alpha"):
        """The stand-in's record once it has ended."""
        return self.record(lane, run=run, config=config, ended=True)


def refused_steps(fmt, call_id="c1", command=REFUSED, message=None):
    """A shell call that the doc guard refuses: a call and its refusal (for text, the refusal printed to the log)."""
    message = message or hook("shutdown")
    if fmt == "text":
        return [{"say": line} for line in message.splitlines()]
    return [{"shell": {"id": call_id, "command": command}}, {"result": {"id": call_id, "text": message, "error": True}}]


def shell_steps(call_id, command, text="", error=False):
    return [{"shell": {"id": call_id, "command": command}}, {"result": {"id": call_id, "text": text, "error": error}}]


def hooked_steps(call_id, command=REFUSED, kind="blocking", event="PreToolUse", message=None):
    """A shell call whose result is a success, with a hook's message about it beside: how a hook's refusal is kept."""
    return [{"shell": {"id": call_id, "command": command}}, {"result": {"id": call_id, "text": "", "error": False}},
            {"hook": {"id": call_id, "kind": kind, "text": message or hook("shutdown"), "event": event,
                      "name": event + ":Bash"}}]


def expected_path(worktree, relative):
    return os.path.join(os.path.realpath(str(worktree)), relative)


def stamp():
    moment = datetime.datetime.now(datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "{:03d}Z".format(moment.microsecond // 1000)


def write_session(home, cwd, call_id, command=REFUSED, message=None):
    """A claude-code record written by another session in a directory (not by the lane's runner): a shell call and a
    guard's refusal of it, with the time of now. Returns its path."""
    slug = "".join(character if character.isalnum() else "-" for character in str(cwd))
    path = os.path.join(str(home), ".claude", "projects", slug, "other-{}.jsonl".format(call_id))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = [{"type": "assistant", "timestamp": stamp(), "cwd": str(cwd), "message": {"role": "assistant", "content": [
                 {"type": "tool_use", "id": call_id, "name": "Bash", "input": {"command": command}}]}},
             {"type": "user", "timestamp": stamp(), "cwd": str(cwd), "message": {"role": "user", "content": [
                 {"type": "tool_result", "tool_use_id": call_id, "is_error": True,
                  "content": [{"type": "text", "text": message or hook("newcomer")}]}]}}]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(json.dumps(line) + "\n" for line in lines))
    return path

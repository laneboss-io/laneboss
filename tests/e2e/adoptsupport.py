"""Shared helpers for the tests of the `lane adopt` command (docs/architecture.md, "Adopting a session that already
runs", and the pinned specification of its argv, its output and its twelve refusals).

`lane adopt` is to take a session that something outside the launcher started and make it a turn-based lane, so that
the next `lane turn` resumes it. Nothing here imports the package under test: the tests drive the installed command.

The command needs three things of the world beside its arguments: a runner that takes turns, a `records` entry of that
runner whose path names the session's own file (`{session}`, docs/configuration.md, "Session records"), and that file
itself, which nothing has written to for longer than the runner's quiet seconds. `AdoptTest.setUp` writes the runner
and the project, and `call` builds one valid call whose working directory holds the session's record file, so that a
refusal test changes exactly one thing in it.
"""

import json
import os
from pathlib import Path
import time

from .lanesupport import runner
from .mailsupport import STDIN, TURN_START, TurnTest, turn_resume

# The runner an adoption takes: it takes turns (a resume template, {session} in both templates, its prompt on standard
# input), it lists two accounts, and its `records` entry names the session's own record file below the working
# directory. `tnoentry` takes turns and has a records entry that does not name {session}; `tnoturns` never got a
# resume template. `teffort` takes turns but its resume template needs {effort}.
RUNNER = "tok"
MODEL = "tok-model-1"
ACCOUNTS = ["acc-one", "acc-two"]
ACCOUNT = "acc-two"
# The account the project excludes, and which the runner lists: only the project's exclusion can refuse it.
EXCLUDED = "acc-one"
PROJECT = "adopter"
QUIET_SECONDS = 900
RECORDS = 'records = [{format = "claude-code", paths = ["{worktree}/.sessions/{session}.jsonl"]}]\n'
QUIET = "quiet_seconds = {}\n".format(QUIET_SECONDS)
# How old the session's record file is when nothing is writing to it: an hour, far beyond the runner's quiet seconds.
IDLE_AGE = 3600
# The projection's `times` (docs/architecture.md, "Event and state store"): an adoption sets none of them.
TIMES = ("planned", "started", "ended", "timeout", "stuck", "resumed", "lost", "cleaned")
PROJECT_TEXT = """schema_version = 1
name = "adopter"
description = "Invented project for the tests of the adopt command."
excluded_accounts = ["acc-one"]
"""


class AdoptTest(TurnTest):
    """The lane tests' configuration, with a runner that takes turns and names the session's own record file, and the
    project `adopter`, which excludes one account that runner lists."""

    def setUp(self):
        super().setUp()
        self.rewrite(overrides={
            RUNNER: runner(RUNNER, "ok", TURN_START, ACCOUNTS, turn_resume("ok"), extra=STDIN + RECORDS + QUIET),
            "tnoentry": runner("tnoentry", "ok", TURN_START, ACCOUNTS, turn_resume("ok"),
                               extra=STDIN + QUIET + 'records = [{format = "claude-code", paths = ["{worktree}/.sessions/*.jsonl"]}]\n'),
            "tnoturns": runner("tnoturns", "ok", TURN_START, ACCOUNTS, None, extra=STDIN + RECORDS + QUIET),
            "teffort": runner("teffort", "ok", TURN_START, ACCOUNTS, turn_resume("ok") + ["--effort", "{effort}"],
                              extra=STDIN + RECORDS + QUIET),
        })
        project = self.home / "configs" / "alpha" / "projects" / (PROJECT + ".toml")
        project.write_text(PROJECT_TEXT, encoding="utf-8")

    def worktree(self, lane):
        """One call's working directory: a scratch directory of this test's own."""
        path = self.directory / "work" / lane
        path.mkdir(parents=True, exist_ok=True)
        return path

    def session_record(self, directory, session_id, fresh=False):
        """The session's own record file below this working directory (`{worktree}/.sessions/{session}.jsonl`), its
        modification time an hour old (nothing writes to the session) or, with `fresh`, of now (something still
        writes to it)."""
        where = Path(directory) / ".sessions"
        where.mkdir(parents=True, exist_ok=True)
        path = where / (session_id + ".jsonl")
        path.write_text(json.dumps({"type": "assistant", "timestamp": "2026-10-12T09:00:00.000Z",
                                    "cwd": str(directory), "message": {"content": []}}) + "\n", encoding="utf-8")
        when = time.time() - (0 if fresh else IDLE_AGE)
        os.utime(str(path), (when, when))
        return path

    def call(self, lane, session_id, *changes, records="old"):
        """One valid `lane adopt` call: the lane and the session it names, the runner that takes turns, a model, a
        working directory, a brief, the project, an effort, an account and an idle interval, and the session's own
        record file in that working directory. `changes` are (option, value) pairs that replace one part of the call
        (a value of None drops the option). `records` is `"old"` (the file, an hour old), `"fresh"` (written now) or
        False (no file at all: the call names a session whose records do not exist)."""
        options = [["--lane", lane], ["--session", session_id], ["--runner", RUNNER], ["--model", MODEL],
                   ["--worktree", str(self.worktree(lane))], ["--brief", str(self.brief("adopt-" + lane))],
                   ["--project", PROJECT], ["--effort", "high"], ["--account", ACCOUNT], ["--idle", "300"]]
        for option, value in changes:
            found = [pair for pair in options if pair[0] == option]
            if not found:
                if value is not None:
                    options.append([option, value])
            elif value is None:
                options.remove(found[0])
            else:
                found[0][1] = value
        if records is not False:
            directory = Path(dict(options)["--worktree"])
            if directory.is_dir():
                self.session_record(directory, session_id, fresh=records == "fresh")
        return [str(item) for pair in options for item in pair]

    def adopt(self, arguments, code=0):
        """`laneboss lane adopt` with these arguments, bound to the configuration alpha."""
        return self.lane("adopt", *arguments, code=code)

    def rendered(self, lane):
        """The rendered brief files the store holds for this lane: a refused call renders none."""
        directory = Path(self.paths()["state_dir"]) / "lanes" / lane / "rendered"
        return sorted(path.name for path in directory.glob("*.md")) if directory.is_dir() else []

    def claim_lane(self, directory):
        """The lane whose claim the launcher's claims registry holds for this directory, or None: the file is named
        by the directory's device and inode (src/laneboss/claims.py)."""
        info = os.stat(str(directory))
        path = Path(self.environment["LANEBOSS_TEST_CLAIMS_DIR"]) / "{}-{}.json".format(info.st_dev, info.st_ino)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8")).get("lane")

    def claims(self):
        """Every file of the launcher's claims registry, as (its name, the lane it names): the store of the working
        directories' claims, which a refused call leaves as it was."""
        registry = Path(self.environment["LANEBOSS_TEST_CLAIMS_DIR"])
        found = []
        for path in sorted(registry.glob("*.json")) if registry.is_dir() else []:
            found.append((path.name, json.loads(path.read_text(encoding="utf-8")).get("lane")))
        return found

    def refused(self, lane, phrase, arguments, directory=None):
        """One refused call: exit 2, the pinned phrase, and nothing recorded — no event appended (the store as it
        was, and no `lane.adopted` for the lane), no rendered brief added for it, no claim added to the registry, and,
        for a call about a directory, that directory still not claimed by this lane."""
        before, claims, rendered = self.events(), self.claims(), self.rendered(lane)
        result = self.adopt(arguments, code=2)
        self.assertIn(phrase, result.stderr)
        self.assertEqual(self.events(), before)
        self.assertEqual(self.lane_events(lane, "lane.adopted"), [])
        self.assertEqual(self.rendered(lane), rendered)
        self.assertEqual(self.claims(), claims)
        if directory is not None:
            self.assertNotEqual(self.claim_lane(directory), lane)
        return result

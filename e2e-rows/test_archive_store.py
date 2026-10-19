"""Built-CLI archive rows; run only on an authorized disposable Linux box.

LANEBOSS_BIN names an already built binary (normal or laneboss_faults).
LANEBOSS_ARCHIVE_EVIDENCE must name an absolute evidence directory. Each row
retains its private HOME, supplied binary bytes/hash, fixtures and every CLI
input, stdout, stderr and exit code. No product module is imported or built.

For the destructive-order mutant, use a tagged binary, select
ArchiveRows.test_a6_readback_guard and set LANEBOSS_ARCHIVE_MUTANT to
archive-clean-before-readback. The unchanged row must FAIL, with its reach
marker present. Run the same row without the selector as its control.

P1 regression rows and their baseline failures are described in each row's
docstring. MUTANT_ROWS maps tagged faults to those same unchanged rows.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import uuid

from orgsupport import init_org
from reportsupport import TerminalController


RUNNER = '''from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
data = sys.stdin.buffer.read()
if sys.argv[1] == "recorded":
    observed = hashlib.sha256(data).hexdigest()
    entry = {"type": "assistant", "cwd": os.getcwd(),
             "timestamp": datetime.now(timezone.utc).isoformat(),
             "prompt_bytes": len(data), "prompt_sha256": observed,
             "message": {"content": "Read %d prompt bytes; sha256 %s." % (len(data), observed)}}
    Path(sys.argv[2]).write_text(json.dumps(entry) + "\\n", encoding="utf-8")
elif sys.argv[1] == "space":
    print(" ", flush=True)
elif sys.argv[1] != "silent":
    print("archive stand-in read %d bytes" % len(data), flush=True)
if sys.argv[1] == "hold":
    while True:
        time.sleep(1)
'''

# This uploader copies and reads actual bytes. Its corruption mode models a
# local tar changing after upload; the printed hash still describes the kept
# remote copy, never a supplied expected value.
UPLOADER = '''import hashlib
import json
from pathlib import Path
import shutil
import sys
mode, source, manifest, expected, lane = sys.argv[1:]
source = Path(source)
with (source.parent / "upload-attempts.jsonl").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"lane": lane, "source": str(source)}) + "\\n")
if mode == "fail":
    sys.exit(29)
remote = source.with_suffix(".remote.tar")
shutil.copyfile(source, remote)
observed = hashlib.sha256(remote.read_bytes()).hexdigest()
if mode == "corrupt":
    with source.open("r+b") as stream:
        stream.seek(0)
        stream.write(b"broken tar header")
elif mode == "missing":
    sys.exit(0)
elif mode != "copy":
    raise RuntimeError("unknown uploader fixture mode")
print(observed)
'''




def sha(data):
    return hashlib.sha256(data).hexdigest()


MUTANT_ROWS = {
    "archive-clean-before-readback": "test_a6_readback_guard",
    "archive-daily-stop-on-refusal": "test_p1_daily_continues",
    "archive-report-assignment-refusal": "test_p2_report_commands",
    "archive-list-in-events": "test_p3_large_removal_manifest",
    "archive-drop-raw-logs": "test_p4_raw_records_retained",
    "archive-upload-keeps-batch-going": "test_p5_upload_halts",
    "archive-repeat-verified-attempt": "test_p5_locked_retry",
    "clean-without-archive": "test_clean_archives_first",
    "archive-refuse-child": "test_lane_supervisor_collect",
    "archive-level-only": "test_p6_sibling_child_denied",
    "archive-refuse-missing-worktree": "test_p7_clean_missing_worktree",
    "clean-refuse-unowned-worktree": "test_p7_unowned_worktree_kept",
    "archive-ancestry-any-life": "test_p8_reused_name_denied",
    "archive-readonly-store-fails": "test_clean_readonly_pending",
}


class ArchiveRows(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, "linux", "archive rows require the disposable Linux test box")
        supplied = Path(os.environ["LANEBOSS_BIN"])
        evidence = Path(os.environ["LANEBOSS_ARCHIVE_EVIDENCE"])
        self.assertTrue(supplied.is_absolute() and supplied.is_file() and os.access(supplied, os.X_OK))
        self.assertTrue(evidence.is_absolute(), "evidence must be outside the checkout")
        self.assertFalse(evidence.is_relative_to(Path(__file__).resolve().parents[1]))
        evidence.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix="lb-archive-store-", dir=evidence)).resolve()
        (self.directory / "row.txt").write_text(self._testMethodName + "\n", encoding="utf-8")
        self.binary = self.directory / "tested-laneboss"
        shutil.copy2(supplied, self.binary)
        (self.directory / "binary.sha256").write_text(sha(self.binary.read_bytes()) + "\n")
        for source in (Path(__file__), Path(__file__).with_name("orgsupport.py"),
                       Path(__file__).with_name("reportsupport.py")):
            shutil.copy2(source, self.directory / source.name)
        self.calls = 0
        self.home = self.directory / "home"
        self.home.mkdir()
        self.config_home = self.home / ".config/laneboss"
        self.state = self.home / ".local/state/laneboss/archive"
        self.config = self.config_home / "configs/archive"
        self.config.mkdir(parents=True)
        self.repo = self.directory / "repo"
        self.runner = self.directory / "runner.py"
        self.runner.write_text(RUNNER, encoding="utf-8")
        self.uploader = self.directory / "uploader.py"
        self.uploader.write_text(UPLOADER, encoding="utf-8")
        self.supervisor = self.directory / "supervisor.py"
        self.supervisor.write_bytes(Path(__file__).with_name("archive_supervisor.py").read_bytes())
        self.supervisor_plan = self.directory / "supervisor-plan.json"
        self.brief = self.directory / "brief.md"
        self.brief.write_text("# Archive fixture\n\nRead the stand-in task and exit.\n", encoding="utf-8")
        self.marker = self.directory / "mutation-reached"
        self.mutant = os.environ.get("LANEBOSS_ARCHIVE_MUTANT", "")
        self.assertIn(self.mutant, ("", *MUTANT_ROWS))
        if self.mutant:
            self.assertEqual(self._testMethodName, MUTANT_ROWS[self.mutant],
                             "select the row belonging to this mutant")
        # Start with an empty credential-free HOME and an explicit tool path.
        self.environment = {"HOME": str(self.home), "PATH": os.pathsep.join(
            dict.fromkeys([str(Path(sys.executable).parent), *os.defpath.split(os.pathsep)])),
            "LANG": "C", "LC_ALL": "C", "LANEBOSS_CONFIG": "archive"}
        (self.directory / "tmux").mkdir()
        self.environment["TMUX_TMPDIR"] = str(self.directory / "tmux")
        if self.mutant:
            self.environment["LANEBOSS_FAULTS"] = json.dumps({
                "point": self.mutant, "marker": str(self.marker)})
        self.git("init", "-q", "--initial-branch=main", str(self.repo), directory=self.directory)
        self.git("-c", "user.name=demo", "-c", "user.email=demo", "-c", "commit.gpgsign=false",
                 "commit", "-q", "--allow-empty", "-m", "bootstrap")
        # Ignored fixture bytes test tar preservation without a second commit.
        (self.repo / ".git/info/exclude").write_text("canary.txt\n", encoding="utf-8")
        init_org(self.binary, self.environment, self.directory, self.config_home, "archive-org")
        self.configure()
        (self.config / "projects").mkdir()
        (self.config / "projects/demo.toml").write_text(
            'schema_version = 1\nname = "demo"\nrepository = ' + json.dumps(str(self.repo)) +
            '\nworkers = ["once", "hold", "silent", "space", "recorded", "supervisor"]\nlanding_authority = "top"\n', encoding="utf-8")
        self.human = TerminalController(self, self.binary, self.environment, self.directory)
        self.active = set()
        self.addCleanup(self.collect)
        if self.mutant:
            self.addCleanup(self.require_mutation)
        self.call("config", "validate", "archive")

    def require_mutation(self):
        self.assertTrue(self.marker.is_file(), "the mutation never reached its product call site")

    def configure(self, upload=None, raw=False):
        text = 'schema_version = 1\nname = "archive"\norganisation = "archive-org"\nrules = []\n'
        if upload is not None:
            text += "archive_command = " + json.dumps([sys.executable, str(self.uploader), upload]) + "\n"
        text += ('[lanes]\nbudget_minutes = 2\nstop_grace_seconds = 1\n'
                 '[supervisors.top]\nlevel = 5\nrunner = "once"\nprojects = ["demo"]\n')
        for mode in ("once", "hold", "silent", "space", "recorded", "supervisor"):
            records = ['{format = "text", paths = ["{log}"]}']
            session_path = str(self.directory / "session-{lane}.jsonl")
            if mode == "recorded":
                records = ['{format = "claude-code", paths = [' + json.dumps(session_path) + ']}']
            if raw:
                records.append('{format = "claude-code", paths = ["{log}.raw/**/*.log"]}')
            command = ([sys.executable, str(self.supervisor), str(self.supervisor_plan)] if mode == "supervisor"
                       else [sys.executable, str(self.runner), mode])
            if mode == "recorded":
                command.append(session_path)
            text += ('[runners.' + mode + ']\ncommand = ' + json.dumps(command) +
                     '\nprompt = "stdin"\nrecords = [' + ", ".join(records) + ']\n')
        text += '[[guards]]\nname = "fixture"\nkind = "hook"\npattern = "^fixture-guard: refused "\n'
        (self.config / "config.toml").write_text(text, encoding="utf-8")

    def git(self, *args, directory=None):
        result = subprocess.run(["git", "-C", str(directory or self.repo), *map(str, args)],
                                env=self.environment, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        return result.stdout.decode("utf-8").strip()

    def call(self, *args, code=0):
        self.calls += 1
        prefix = self.directory / ("call-%04d" % self.calls)
        prefix.with_suffix(".input.json").write_text(json.dumps(list(map(str, args))) + "\n")
        result = self.human.request(args)
        prefix.with_suffix(".stdout").write_bytes(result["stdout"].encode("utf-8"))
        prefix.with_suffix(".stderr").write_bytes(result["stderr"].encode("utf-8"))
        prefix.with_suffix(".exit").write_text(str(result["code"]) + "\n")
        self.assertEqual(result["code"], code, result["stderr"])
        return result

    def data(self, *args, **options):
        return json.loads(self.call(*args, **options)["stdout"])

    def status(self, lane):
        return self.data("lane", "status", "--config", "archive", "--lane", lane)

    def quiet(self, lane):
        deadline = time.monotonic() + 45
        while True:
            status = self.status(lane)
            live = status["live"]
            if (not status["running"] and live["supervisor"]["alive"] is False
                    and live["session_alive"] is False and live["survivors"] == 0
                    and live["pending_events"] == 0 and live["refused_events"] == 0):
                return status
            self.assertLess(time.monotonic(), deadline, "the actual lane did not become quiescent")
            time.sleep(0.2)

    def start(self, lane, mode="once"):
        value = self.data("lane", "start", "--config", "archive", "--project", "demo",
                          "--lane", lane, "--brief", self.brief, "--role", "executor",
                          "--runner", mode, "--model", "archive-fixture-model-v1", "--budget", "2")
        self.active.add(lane)
        return Path(value["worktree"])

    def finish(self, lane, state="merged", report=True):
        worktree = self.start(lane)
        status = self.quiet(lane)
        self.assertEqual((status["reason"], status["exit_code"]), ("exit", 0))
        if report:
            source = self.state / "lanes" / lane / "report.md"
            source.write_text("# Lane report\n\nSearchable archive result " + lane + " completed.\n", encoding="utf-8")
        (worktree / "canary.txt").write_bytes(b"kept archive canary\n" + uuid.uuid4().bytes)
        self.data("lane", "mark", "--config", "archive", "--lane", lane, "--state", state)
        return worktree

    def archive(self, lane, *args, code=0):
        return self.call("lane", "archive", "--config", "archive", "--lane", lane, *args, code=code)

    def collector(self, lane, operations, level=4, reuse=False):
        result_file = self.directory / (lane + "-" + uuid.uuid4().hex + "-result.json")
        plan = json.dumps({"binary": str(self.binary), "brief": str(self.brief),
                           "result": str(result_file), "operations": operations}).encode()
        result_file.with_suffix(".plan.json").write_bytes(plan)
        self.supervisor_plan.write_bytes(plan)
        flags = ("--reuse",) if reuse else ()
        started = self.data("lane", "start", "--config", "archive", "--project", "demo", "--lane", lane,
                            "--brief", self.brief, "--role", "executor" if level == 3 else "supervisor",
                            "--level", level, "--runner", "supervisor",
                            "--model", "archive-fixture-model-v1", "--budget", "2", *flags)
        self.active.add(lane)
        status = self.quiet(lane)
        self.assertTrue(result_file.is_file(), "the actual lane runner did not keep its CLI results")
        observed = json.loads(result_file.read_bytes())
        self.assertGreater(len(observed["calls"]), 0)
        self.assertEqual(status["exit_code"], 0, "the lane fixture failed before returning its observations")
        return started, observed

    def denied(self, observed, targets, actions=("archive", "clean")):
        expected = [(lane, action) for lane in targets for action in actions]
        self.assertEqual([(item["lane"], item["action"]) for item in observed["results"]], expected)
        for item in observed["results"]:
            self.assertEqual(item["code"], 2, "a non-descendant or peer acquired collection authority")
            self.assertIn("a lane may collect itself", item["stderr"])
            self.assertEqual(item["stdout"], "")

    def events(self):
        return self.data("state", "events", "--config", "archive")

    def snapshot(self, lane, worktree):
        paths = [worktree, *worktree.rglob("*")] if worktree.exists() else []
        paths += list((self.state / "lanes" / lane).rglob("*.log"))
        return {str(path): (sha(path.read_bytes()) if path.is_file() else "directory") for path in paths}

    def intact(self, lane, worktree, before):
        self.assertEqual(self.snapshot(lane, worktree), before, "refused archival changed its inputs")
        self.assertFalse(self.status(lane)["cleaned"], "refused archival cleaned its lane")
        self.assertEqual(self.git("for-each-ref", "--format=%(refname:short)", "refs/heads/" + lane), lane)
        self.assertFalse(any(e["kind"] in ("lane.cleaned", "archive.completed") and e["lane"] == lane
                             for e in self.events()), "a refusal crossed the cleanup boundary")

    def verify_tar(self, result):
        manifest = json.loads(Path(result["manifest"]).read_bytes())
        self.assertEqual(manifest["format"], 1)
        self.assertEqual(manifest["remove_paths"], result["remove_paths"])
        removal_hash = sha(json.dumps(result["remove_paths"], ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        self.assertEqual(manifest["remove_paths_sha256"], removal_hash)
        entries = manifest["entries"]
        self.assertEqual(sha(Path(result["archive"]).read_bytes()), result["sha256"])
        with tarfile.open(result["archive"], "r:") as archive:
            members = archive.getmembers()
            self.assertEqual([item.name for item in members], [item["path"] for item in entries])
            for member, item in zip(members, entries):
                self.assertEqual(member.mode, item["mode"])
                self.assertEqual(member.size, item["size"])
                if member.isfile():
                    self.assertEqual(sha(archive.extractfile(member).read()), item["sha256"])
                elif member.issym():
                    self.assertEqual(member.linkname, item["link"])
                    self.assertEqual(sha(member.linkname.encode("utf-8")), item["sha256"])
                else:
                    self.assertTrue(member.isdir())
                    self.assertEqual(item["sha256"], sha(b""))
        receipt = json.loads(Path(result["receipt"]).read_bytes())
        self.assertEqual(receipt["sha256"], result["sha256"])
        self.assertEqual(receipt["manifest_sha256"], sha(Path(result["manifest"]).read_bytes()))
        self.assertNotIn("remove_paths", receipt)
        self.assertEqual(receipt["remove_paths_sha256"], removal_hash)
        self.assertEqual(receipt["remove_count"], len(result["remove_paths"]))
        self.assertTrue(receipt["read_back"])
        recorded = [e for e in self.events() if e["lane"] == result["lane"]]
        for event in recorded:
            if event["kind"] in ("archive.verified", "archive.completed") and event["payload"].get("receipt") == result["receipt"]:
                payload = event["payload"]
                self.assertNotIn("remove_paths", payload)
                self.assertEqual(payload["remove_paths_sha256"], removal_hash)
                self.assertEqual(payload["remove_count"], len(result["remove_paths"]))
                self.assertEqual(payload["receipt_sha256"], sha(Path(result["receipt"]).read_bytes()))
                self.assertLessEqual(len(json.dumps(payload, separators=(",", ":")).encode()), 1024 * 1024)
        verified = next(e["seq"] for e in recorded if e["kind"] == "archive.verified" and e["payload"].get("receipt") == result["receipt"])
        stored = [e for e in recorded if e["kind"] == "store.record" and e["seq"] > verified]
        self.assertGreaterEqual(len(stored), 4, "the verified archive did not retain its input records")
        report = next(e["payload"] for e in stored if e["payload"]["kind"] == "lane-report")
        report_hash = sha(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        self.assertEqual(manifest["report_record_sha256"], report_hash, "manifest does not bind the selected report")

    def collect(self):
        recorded = self.data("state", "lanes", "--config", "archive")
        for lane in sorted(self.active | {row["lane"] for row in recorded}):
            status = self.status(lane)
            if status["running"]:
                self.call("lane", "stop", "--config", "archive", "--lane", lane)
            self.quiet(lane)

    def test_a1_dry_real_paths(self):
        lane = "parity"
        worktree = self.finish(lane)
        before = self.snapshot(lane, worktree)
        events = self.events()
        destination = self.directory / "custom-archives"
        dry = json.loads(self.archive(lane, "--dry-run", "--to", destination)["stdout"])
        raw = str(self.state / "lanes" / lane / "output.log")
        self.assertEqual(dry["remove_paths"], sorted(set(before) - {raw}))
        self.assertEqual(dry["keep_paths"], [raw])
        self.assertEqual(self.snapshot(lane, worktree), before)
        self.assertEqual(self.events(), events, "dry-run appended store events")
        self.assertFalse(destination.exists(), "dry-run created its destination")
        real = json.loads(self.archive(lane, "--to", destination)["stdout"])
        self.assertEqual(real["remove_paths"], dry["remove_paths"])
        self.assertEqual(sorted(set(before) - set(self.snapshot(lane, worktree))), dry["remove_paths"])
        self.assertFalse(worktree.exists())
        self.assertEqual(sha(Path(raw).read_bytes()), before[raw])
        self.assertEqual(self.git("branch", "--list", lane), "")
        self.assertTrue((self.state / "lanes" / lane / "report.md").is_file())
        self.verify_tar(real)
        self.assertTrue(self.data("state", "verify", "--config", "archive")["ok"])

    def test_a2_dirty_untouched(self):
        lane = "dirty"
        worktree = self.finish(lane)
        (worktree / "uncommitted.txt").write_text("unfinished work\n", encoding="utf-8")
        before = self.snapshot(lane, worktree)
        for flags in (("--dry-run",), ()):
            result = self.archive(lane, *flags, code=2)
            self.assertIn("uncommitted or untracked", result["stderr"])
            self.intact(lane, worktree, before)
        self.assertFalse((self.state / "archives").exists())

    def test_a3_running_untouched(self):
        """State-guard row; it does not isolate the live-survivor predicate."""
        lane = "running"
        worktree = self.start(lane, "hold")
        self.assertTrue(self.status(lane)["running"])
        result = self.archive(lane, code=2)
        self.assertIn("not running", result["stderr"])
        self.assertTrue(worktree.is_dir())
        self.assertTrue(self.status(lane)["running"])
        self.assertFalse((self.state / "archives").exists())

    def test_a4_search_and_filters(self):
        self.finish("searchable")
        result = json.loads(self.archive("searchable")["stdout"])
        matches = self.data("store", "search", "--config", "archive", "Searchable archive result searchable",
                            "--kind", "lane-report", "--lane", "searchable")
        self.assertTrue(matches, "the archived report was not indexed")
        self.assertTrue(all(row["kind"] == "lane-report" and row["lane"] == "searchable" for row in matches))
        self.assertTrue(all(row["source"] and row["time"] and row["sha256"] == sha(row["text"].encode())
                            for row in matches))
        self.assertEqual(self.data("store", "search", "--config", "archive", "Searchable archive result",
                                   "--kind", "decision"), [])
        self.assertEqual(self.data("store", "search", "--config", "archive", "Searchable archive result",
                                   "--lane", "another"), [])
        self.verify_tar(result)

    def test_a5_secret_refused(self):
        lane = "secret-report"
        worktree = self.finish(lane)
        report = self.state / "lanes" / lane / "report.md"
        canary = "sk-" + "A9" * 14
        report.write_text("# Unsafe report\n" + canary + "\n", encoding="utf-8")
        before = self.snapshot(lane, worktree)
        result = self.archive(lane, code=2)
        self.assertIn("prefixed-secret-key", result["stderr"])
        self.assertIn("line 2", result["stderr"])
        self.assertTrue(canary not in result["stderr"], "refusal echoed a credential-shaped canary")
        self.intact(lane, worktree, before)
        result = self.call("store", "record", "--config", "archive", "--kind", "lane-report",
                           "--lane", lane, "--file", report, code=2)
        self.assertIn("prefixed-secret-key", result["stderr"])
        self.assertTrue(canary not in result["stderr"], "store echoed a credential-shaped canary")
        with sqlite3.connect(self.state / "events.sqlite") as store:
            count = store.execute("SELECT count(*) FROM events WHERE kind='store.record'").fetchone()[0]
        self.assertEqual(count, 0, "a credential report reached the searchable store")

    def test_a6_readback_guard(self):
        lane = "readback"
        worktree = self.finish(lane)
        before = self.snapshot(lane, worktree)
        self.configure("corrupt")
        result = self.archive(lane, code=3)
        if self.mutant:
            self.assertTrue(self.marker.is_file(), "the mutation never reached its product call site")
        self.assertIn("read-back", result["stderr"])
        self.intact(lane, worktree, before)
        self.assertTrue(list((self.state / "archives").glob("*.remote.tar")))
        self.assertFalse(list((self.state / "archives").glob("*.receipt.json")))

    def test_a7_missing_receipt(self):
        lane = "missing-receipt"
        worktree = self.finish(lane)
        before = self.snapshot(lane, worktree)
        self.configure("missing")
        result = self.archive(lane, code=2)
        self.assertIn("read-back hash is missing", result["stderr"])
        self.intact(lane, worktree, before)

    def test_a8_daily_retains_rows(self):
        first = self.finish("daily-a")
        second = self.finish("daily-b", "abandoned")
        events = self.events()
        dry = [json.loads(line) for line in self.call("archive", "daily", "--config", "archive",
                                                    "--dry-run")["stdout"].splitlines()]
        self.assertEqual([row["lane"] for row in dry[:-1]], ["daily-a", "daily-b"])
        real = [json.loads(line) for line in self.call("archive", "daily", "--config", "archive")["stdout"].splitlines()]
        self.assertEqual([row["remove_paths"] for row in dry[:-1]], [row["remove_paths"] for row in real[:-1]])
        self.assertEqual(real[-1]["processed"], 2)
        self.assertFalse(first.exists() or second.exists())
        self.assertEqual(self.git("branch", "--list", "daily-b"), "daily-b")
        current = {row["id"]: row for row in self.events()}
        self.assertTrue(all(current.get(row["id"]) == row for row in events), "archiving deleted or changed ledger history")
        ledger = (self.state / "archive-ledger.md").read_text(encoding="utf-8")
        self.assertIn("## Archive", ledger)
        self.assertIn("daily-a", ledger)
        self.assertIn("daily-b", ledger)
        again = self.call("archive", "daily", "--config", "archive")
        repeated = [json.loads(line) for line in again["stdout"].splitlines()]
        self.assertEqual([row["status"] for row in repeated[:-1]], ["already-archived", "already-archived"])
        self.assertEqual((repeated[-1]["processed"], repeated[-1]["skipped"]), (0, 2))

    def test_a9_private_and_binary(self):
        source = self.directory / "settings.toml"
        source.write_text('retention_days = 14\n', encoding="utf-8")
        self.call("store", "record", "--config", "archive", "--kind", "decision", "--file", source, code=2)
        self.call("store", "record", "--config", "archive", "--kind", "decision", "--file", source, "--private")
        records = self.data("store", "search", "--config", "archive", "settings.toml")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["text"], "")
        self.assertEqual(records[0]["source"], "settings.toml")
        self.assertEqual(records[0]["sha256"], sha(source.read_bytes()))
        source = self.directory / "binary.dat"
        source.write_bytes(b"\x00\xff\x80")
        self.call("store", "record", "--config", "archive", "--kind", "decision", "--file", source, code=2)
        self.assertEqual(self.data("store", "search", "--config", "archive", "binary.dat"), [])

    def test_p1_daily_continues(self):
        """P1-1: the baseline omits zzz-good after aaa-dirty's refusal."""
        dirty = self.finish("aaa-dirty", "abandoned")
        (dirty / "leftover.txt").write_text("unfinished input\n", encoding="utf-8")
        good = self.finish("zzz-good")
        before = self.snapshot("aaa-dirty", dirty)
        for flags in (("--dry-run",), ()):
            reply = self.call("archive", "daily", "--config", "archive", *flags, code=2)
            rows = [json.loads(line) for line in reply["stdout"].splitlines()]
            self.assertEqual([row.get("lane") for row in rows[:-1]], ["aaa-dirty", "zzz-good"],
                             "a refused lane starved a later clean lane")
            self.assertEqual(rows[0]["status"], "refused")
            self.assertIn("uncommitted or untracked", rows[0]["reason"])
            self.assertEqual((rows[-1]["processed"], rows[-1]["refused"], rows[-1]["failed"]), (1, 1, 0))
            self.assertEqual(rows[-1]["status"], "complete-with-refusals")
            self.intact("aaa-dirty", dirty, before)
        self.assertFalse(good.exists(), "daily did not archive the clean lane")
        self.assertTrue(self.status("zzz-good")["cleaned"])

    def test_p2_report_commands(self):
        """P1-2: the baseline refuses the report's GOTOOLCHAIN assignment."""
        lane = "command-report"
        self.finish(lane)
        text = ("# Command-bearing report\n\nGOTOOLCHAIN=local go vet ./...\n"
                "LANEBOSS_BIN=/test/bin/laneboss python3 -m unittest\n"
                "DB_PASS=$VAR\nDB_PASS=<placeholder>\nDB_PASS=none\nDB_PASS=get_value()\nDB_PASS=test pytest\n"
                "```go\n    err = run()\n```\n")
        (self.state / "lanes" / lane / "report.md").write_text(text, encoding="utf-8")
        self.archive(lane, "--dry-run")
        result = json.loads(self.archive(lane)["stdout"])
        self.assertFalse(result["report_private"], "ordinary report lines were withheld as settings")
        matches = self.data("store", "search", "--config", "archive", "Command-bearing report", "--lane", lane)
        self.assertTrue(any(row["text"] == text and row["sha256"] == sha(text.encode()) for row in matches),
                        "the report commands were not stored as their original text")
        self.verify_tar(result)

    def test_p3_large_removal_manifest(self):
        """P1-3: baseline real archive exceeds 1 MiB after partial ingestion."""
        lane = "large-manifest"
        worktree = self.finish(lane)
        payload = worktree / ("ignored-" + "d" * 60)
        payload.mkdir()
        with (self.repo / ".git/info/exclude").open("a", encoding="utf-8") as exclude:
            exclude.write(payload.name + "/\n")
        for number in range(6000):
            name = "%06d-" % number + "entry-" * 14 + ".txt"
            (payload / name).write_text("kept file %d\n" % number, encoding="utf-8")
        dry = json.loads(self.archive(lane, "--dry-run")["stdout"])
        self.assertGreater(len(json.dumps(dry["remove_paths"]).encode()), 1024 * 1024,
                           "the fixture did not reach the old event-payload limit")
        result = json.loads(self.archive(lane)["stdout"])
        self.assertEqual(result["remove_paths"], dry["remove_paths"])
        self.assertFalse(worktree.exists())
        self.verify_tar(result)
        self.assertTrue(self.data("state", "verify", "--config", "archive")["ok"])

    def test_p3_limits_before_ingest(self):
        """Baseline dry-run accepts a report whose escaped payload is too big."""
        lane = "payload-limit"
        worktree = self.finish(lane)
        (self.state / "lanes" / lane / "report.md").write_bytes(b"\t" * (512 * 1024))
        before, events = self.snapshot(lane, worktree), self.events()
        for flags in (("--dry-run",), ()):
            reply = self.archive(lane, *flags, code=2)
            self.assertIn("archive preflight", reply["stderr"])
            self.assertEqual(self.events(), events, "a size refusal partially ingested records")
            self.intact(lane, worktree, before)
        self.assertFalse((self.state / "archives").exists())
        self.assertFalse((self.state / "archive-ledger.md").exists())

    def test_p4_raw_records_retained(self):
        """P1-4: baseline deletes output.log and the configured raw .log."""
        lane = "raw-records"
        self.finish(lane)
        directory = self.state / "lanes" / lane
        output = directory / "output.log"
        original = output.read_bytes()
        raw = directory / "output.log.raw/session/record.log"
        raw.parent.mkdir(parents=True)
        raw.write_text(json.dumps({"type": "assistant", "message": {
            "content": [{"type": "text", "text": "retained raw record fixture"}]}}) + "\n", encoding="utf-8")
        raw_bytes = raw.read_bytes()
        self.configure(raw=True)
        result = json.loads(self.archive(lane)["stdout"])
        self.assertTrue(output.is_file(), "archive removed output.log needed by history ingest")
        self.assertEqual(output.read_bytes(), original)
        self.assertTrue(raw.is_file(), "archive removed a configured raw runner record")
        self.assertEqual(raw.read_bytes(), raw_bytes)
        self.assertNotIn(str(output), result["remove_paths"])
        self.assertNotIn(str(raw), result["remove_paths"])
        self.assertFalse((directory / "watch.log").exists())
        database = self.directory / "history.sqlite"
        self.call("decisions", "init", "--db", database)
        self.call("decisions", "ingest-lane", "--db", database, "--config", "archive", "--lane", lane)
        record = max((json.loads(path.read_bytes()) for path in (directory / "runs").glob("*.json")),
                     key=lambda value: value["run"])
        span = record["log"]
        with sqlite3.connect(database) as store:
            report = store.execute("SELECT text,source_sha256 FROM lane_records WHERE lane=? AND part='report'",
                                   (lane,)).fetchone()
            history = store.execute("SELECT text FROM lane_records WHERE lane=? AND part='events'",
                                    (lane,)).fetchone()[0]
        selected = original[span["start"]:span["end"]]
        self.assertEqual(report, (selected.decode("utf-8"), sha(selected)))
        self.assertTrue(any(e["kind"] == "lane.state" and e["payload"].get("state") == "merged"
                            for e in map(json.loads, history.splitlines())), "history ingest lost the supervisor mark")
        self.verify_tar(result)

    def test_report_from_run_span(self):
        """No report.md or upward report is required when a real run span exists."""
        lane = "run-report"
        self.finish(lane, report=False)
        directory = self.state / "lanes" / lane
        record = max((json.loads(path.read_bytes()) for path in (directory / "runs").glob("*.json")),
                     key=lambda value: value["run"])
        original = (directory / "output.log").read_bytes()
        span = record["log"]
        selected = original[span["start"]:span["end"]]
        self.archive(lane)
        matches = self.data("store", "search", "--config", "archive", "archive stand-in read", "--lane", lane)
        self.assertTrue(any(row["text"].encode() == selected and row["sha256"] == sha(selected) for row in matches))
        self.assertEqual((directory / "output.log").read_bytes(), original)

    def test_report_settings_private(self):
        lane = "quoted-settings"
        self.finish(lane)
        report = self.state / "lanes" / lane / "report.md"
        data = b"# Quoted settings\n\n```toml\nretention_days = 14\n```\n"
        report.write_bytes(data)
        result = json.loads(self.archive(lane)["stdout"])
        self.assertTrue(result["report_private"])
        matches = self.data("store", "search", "--config", "archive", "report.md", "--lane", lane)
        self.assertTrue(any(row["private"] and row["text"] == "" and row["sha256"] == sha(data) for row in matches))
        self.assertEqual(self.data("store", "search", "--config", "archive", "retention_days", "--lane", lane), [])


    def test_ledger_append_growth(self):
        self.finish("ledger-growth")
        board = self.state / "archive-ledger.md"
        original = b"# Lane ledger\n\n## Archive\n\n" + b"- retained historical row\n" * 50000
        self.assertGreater(len(original), 1024 * 1024)
        board.write_bytes(original)
        self.archive("ledger-growth")
        after = board.read_bytes()
        self.assertTrue(after.startswith(original), "the existing ledger bytes changed")
        self.assertIn(b"ledger-growth", after[len(original):])

    def test_daily_integrity_reports_rest(self):
        first = self.finish("aaa-broken-tar")
        second = self.finish("zzz-unattempted")
        before = {"aaa-broken-tar": self.snapshot("aaa-broken-tar", first),
                  "zzz-unattempted": self.snapshot("zzz-unattempted", second)}
        self.configure("corrupt")
        reply = self.call("archive", "daily", "--config", "archive", code=3)
        rows = [json.loads(line) for line in reply["stdout"].splitlines()]
        self.assertEqual([row.get("lane") for row in rows[:-1]], ["aaa-broken-tar", "zzz-unattempted"])
        self.assertEqual([row["status"] for row in rows[:-1]], ["failed", "not-attempted"])
        self.assertEqual((rows[-1]["failed"], rows[-1]["not_attempted"], rows[-1]["processed"]), (1, 1, 0))
        self.intact("aaa-broken-tar", first, before["aaa-broken-tar"])
        self.intact("zzz-unattempted", second, before["zzz-unattempted"])

    def test_supplied_dirty_retained(self):
        lane = "supplied-dirty"
        worktree = self.directory / "repo-supplied-dirty"
        self.git("worktree", "add", "-q", "-b", lane, worktree)
        unfinished = worktree / "unfinished.txt"
        original = b"keep uncommitted supplied work\n"
        unfinished.write_bytes(original)
        self.data("lane", "start", "--config", "archive", "--lane", lane, "--worktree", worktree,
                  "--brief", self.brief, "--role", "executor", "--runner", "once",
                  "--model", "archive-fixture-model-v1", "--budget", "2")
        self.active.add(lane)
        self.quiet(lane)
        (self.state / "lanes" / lane / "report.md").write_text("# Supplied directory report\n", encoding="utf-8")
        self.data("lane", "mark", "--config", "archive", "--lane", lane, "--state", "abandoned")
        result = json.loads(self.archive(lane)["stdout"])
        self.assertTrue(worktree.is_dir(), "a supplied directory was removed")
        self.assertEqual(unfinished.read_bytes(), original)
        self.assertFalse(any(Path(path).is_relative_to(worktree) for path in result["remove_paths"]))
        self.assertEqual(self.git("for-each-ref", "--format=%(refname:short)", "refs/heads/" + lane), lane)
        self.verify_tar(result)

    def test_p5_upload_halts(self):
        """P1-5a: bb47d8a uploads both lanes and keeps two tars per run."""
        first = self.finish("aaa-upload-fail")
        second = self.finish("zzz-upload-unattempted")
        before = {"aaa-upload-fail": self.snapshot("aaa-upload-fail", first),
                  "zzz-upload-unattempted": self.snapshot("zzz-upload-unattempted", second)}
        self.configure("fail")
        for run in (1, 2):
            response = self.call("archive", "daily", "--config", "archive", code=2)
            rows = [json.loads(line) for line in response["stdout"].splitlines()]
            self.assertEqual([row["status"] for row in rows[:-1]], ["failed", "not-attempted"],
                             "an uploader failure did not halt later archive attempts")
            self.assertEqual((rows[-1]["processed"], rows[-1]["failed"], rows[-1]["not_attempted"]), (0, 1, 1))
            attempts = [json.loads(line) for line in (self.state / "archives/upload-attempts.jsonl").read_text().splitlines()]
            self.assertEqual(len(attempts), run, "an uploader outage caused more than one attempt per daily run")
            self.assertTrue(all(attempt["lane"] == "aaa-upload-fail" for attempt in attempts))
            self.assertEqual(len(list((self.state / "archives").glob("*.tar"))), run,
                             "an uploader outage retained more than one tar per daily run")
            self.intact("aaa-upload-fail", first, before["aaa-upload-fail"])
            self.intact("zzz-upload-unattempted", second, before["zzz-upload-unattempted"])

    def test_p5_locked_retry(self):
        """P1-5b: bb47d8a repeats tar/upload/records/ledger after Git refuses."""
        lane = "locked-retry"
        worktree = self.finish(lane)
        before = self.snapshot(lane, worktree)
        self.git("worktree", "lock", worktree)
        self.configure("copy")

        def inventory():
            archives = self.state / "archives"
            tars = {path.name: sha(path.read_bytes()) for path in archives.glob("*.tar")
                    if not path.name.endswith(".remote.tar")}
            records = [event for event in self.events() if event["kind"] in ("store.record", "archive.verified")]
            board = (self.state / "archive-ledger.md").read_bytes()
            uploads = (archives / "upload-attempts.jsonl").read_bytes()
            return tars, records, board, uploads

        first = [json.loads(line) for line in self.call("archive", "daily", "--config", "archive", code=2)["stdout"].splitlines()]
        self.assertEqual(first[0]["status"], "refused")
        self.assertIn("refused to remove", first[0]["reason"])
        previous = inventory()
        self.assertEqual(len(previous[0]), 1)
        self.assertEqual(sum(event["kind"] == "store.record" for event in previous[1]), 4)
        second = [json.loads(line) for line in self.call("archive", "daily", "--config", "archive", code=2)["stdout"].splitlines()]
        self.assertEqual(second[0]["reason"], first[0]["reason"], "the unchanged lock should report the same refusal")
        self.assertEqual(inventory(), previous, "retry duplicated a verified tar, upload, indexed record or board row")
        self.intact(lane, worktree, before)
        self.git("worktree", "unlock", worktree)
        result = json.loads(self.archive(lane)["stdout"])
        self.assertTrue(result["reused"], "unlocking the worktree caused a fresh archive instead of collection")
        self.assertEqual(inventory(), previous)
        self.assertFalse(worktree.exists())
        self.verify_tar(result)

    def test_sensitive_assignments_private(self):
        """P2-A: prefixed password and PASS names are private public-record inputs."""
        value = "hunter2"
        for index, name in enumerate(("PGPASSWORD", "DB_PASS")):
            lane = "private-assignment-%d" % index
            self.finish(lane)
            source = self.state / "lanes" / lane / "report.md"
            data = ("# Reviewed assignment fixture\n" + name + "=" + value + "\n").encode()
            source.write_bytes(data)
            response = self.call("store", "record", "--config", "archive", "--kind", "lane-report",
                                 "--lane", lane, "--file", source, code=2)
            self.assertIn("--private", response["stderr"])
            self.assertTrue(value not in response["stdout"] + response["stderr"], "the backstop echoed a literal value")
            result = json.loads(self.archive(lane)["stdout"])
            self.assertTrue(result["report_private"], "a sensitive-name assignment was indexed as public text")
            matches = self.data("store", "search", "--config", "archive", value)
            self.assertTrue(len(matches) == 0, "a private literal reached keyword search")
            names = self.data("store", "search", "--config", "archive", "report.md", "--lane", lane)
            self.assertTrue(any(row["private"] and row["text"] == "" and row["sha256"] == sha(data) for row in names),
                            "the private source name/hash was not retained")

    def test_clean_archives_first(self):
        """P2-10: baseline clean deletes the worktree without an archive receipt."""
        lane = "clean-verified"
        worktree = self.finish(lane)
        result = self.data("lane", "clean", "--config", "archive", "--lane", lane)
        self.assertTrue("archive" in result and result.get("verified") is True,
                        "plain lane clean removed files without a verified archive")
        self.assertFalse(worktree.exists())
        self.assertFalse(result["pending"])
        self.assertEqual(sorted(item["item"] for item in result["removed"]), ["branch", "worktree"])
        self.verify_tar(result)
        blocked = self.finish("clean-blocked")
        before = self.snapshot("clean-blocked", blocked)
        self.configure("fail")
        self.call("lane", "clean", "--config", "archive", "--lane", "clean-blocked", code=2)
        self.intact("clean-blocked", blocked, before)

    def test_clean_no_run_report(self):
        """6723773 refuses plain clean of a real silent run as an empty report."""
        cases = (("empty", "silent", False, False, "abandoned"),
                 ("space", "space", False, False, "abandoned"),
                 ("missing", "silent", True, False, "abandoned"),
                 ("old", "silent", True, True, "abandoned"),
                 ("merged", "recorded", False, False, "merged"))
        for label, mode, missing, prior, state in cases:
            with self.subTest(case=label):
                lane = "no-report-" + label
                directory = self.state / "lanes" / lane
                old = b""
                if prior:
                    self.finish(lane, report=False)
                    self.archive(lane)
                    old = (directory / "output.log").read_bytes()
                    self.assertTrue(old.strip(), "the older run must have actual report bytes")
                    started = self.data("lane", "start", "--config", "archive", "--project", "demo",
                                        "--lane", lane, "--reuse", "--brief", self.brief,
                                        "--role", "executor", "--runner", mode,
                                        "--model", "archive-fixture-model-v1", "--budget", "2")
                    worktree = Path(started["worktree"])
                else:
                    worktree = self.start(lane, mode)
                status = self.quiet(lane)
                self.assertEqual((status["reason"], status["exit_code"]), ("exit", 0))
                run = status["run"]
                records = list((directory / "runs").glob("*.json"))
                latest = max(records, key=lambda path: json.loads(path.read_bytes())["run"])
                record = json.loads(latest.read_bytes())
                self.assertEqual(record["run"], run)
                span = record["log"]
                output = (directory / "output.log").read_bytes()
                selected = output[span["start"]:span["end"]]
                self.assertEqual(selected.strip(), b"", "the current run must really have no report text")
                if mode in ("silent", "recorded"):
                    self.assertEqual(selected, b"")
                else:
                    self.assertGreater(len(selected), 0)
                if mode == "recorded":
                    # The merge gate scans this runner's real session record;
                    # its stdout and latest-run report remain empty.
                    session_path = self.directory / ("session-" + lane + ".jsonl")
                    session_bytes = session_path.read_bytes()
                    observed = json.loads(session_bytes)
                    event = next(item for item in self.events() if item["lane"] == lane
                                 and item["kind"] == "lane.started" and item["payload"]["run"] == run)
                    prompt = Path(event["payload"]["brief"]["path"]).read_bytes()
                    self.assertGreater(len(prompt), 0)
                    self.assertEqual(observed["prompt_bytes"], len(prompt))
                    self.assertEqual(observed["prompt_sha256"], sha(prompt))
                    self.assertEqual(Path(observed["cwd"]).resolve(), worktree.resolve())
                if prior:
                    self.assertEqual(output, old)
                    self.assertGreater(span["start"], 0)
                if missing:
                    saved_run = self.directory / (lane + "-saved-run.json")
                    latest.rename(saved_run)
                    self.addCleanup(shutil.copyfile, saved_run, latest)
                    self.assertFalse(any(json.loads(path.read_bytes())["run"] == run
                                         for path in (directory / "runs").glob("*.json")))
                marked = self.data("lane", "mark", "--config", "archive", "--lane", lane, "--state", state)
                if mode == "recorded":
                    self.assertEqual(marked["scan"]["not_covered"], [])
                before, events = self.snapshot(lane, worktree), self.events()
                refused = self.archive(lane, code=2)
                self.assertIn("lane report:", refused["stderr"])
                self.assertIn("reviewed", refused["stderr"])
                self.assertEqual(self.snapshot(lane, worktree), before)
                self.assertEqual(self.events(), events, "explicit archive changed state on refusal")

                result = self.data("lane", "clean", "--config", "archive", "--lane", lane)
                self.assertTrue(result["verified"])
                self.assertFalse(result["pending"])
                self.assertFalse(worktree.exists(), "plain clean could not collect the silent lane")
                self.assertTrue(self.status(lane)["cleaned"])
                branch = self.git("branch", "--list", "--format=%(refname:short)", lane)
                if state == "merged":
                    self.assertEqual(branch, "")
                    self.assertIn({"item": "branch", "name": lane}, result["removed"])
                else:
                    self.assertEqual(branch, lane)
                    self.assertIn({"item": "branch", "name": lane, "why": "abandoned"}, result["kept"])
                self.verify_tar(result)
                with tarfile.open(result["archive"], "r:") as archive:
                    note = archive.extractfile("archive/no-report.md").read()
                    self.assertEqual(archive.extractfile("lane/output.log").read(), output)
                    self.assertNotIn("lane/report.md", archive.getnames())
                self.assertIn(("Lane %s. Run %d." % (lane, run)).encode(), note)
                if missing:
                    self.assertIn(b"No latest run record", note)
                    self.assertIn(b"report output is unknown", note)
                    self.assertNotIn(b"Read output.log span", note)
                else:
                    self.assertIn(b"The latest run produced no report", note)
                    bounds = "span %d:%d (%d bytes)" % (span["start"], span["end"], len(selected))
                    self.assertIn(bounds.encode(), note)
                    self.assertIn(sha(selected).encode(), note)
                if prior:
                    self.assertNotIn(old.strip(), note)
                receipt = Path(result["receipt"])
                verified = next(event["seq"] for event in self.events()
                                if event["kind"] == "archive.verified"
                                and event["payload"]["receipt"] == str(receipt))
                reports = [event["payload"] for event in self.events() if event["lane"] == lane
                           and event["kind"] == "store.record" and event["seq"] > verified
                           and event["payload"]["kind"] == "lane-report"]
                self.assertEqual(reports[0]["text"].encode(), note)
                self.assertEqual(reports[0]["sha256"], sha(note))
                matches = self.data("store", "search", "--config", "archive", lane, "--lane", lane)
                self.assertTrue(any(item["text"].encode() == note for item in matches))
                self.assertEqual((directory / "output.log").read_bytes(), output)
                if mode == "recorded":
                    self.assertEqual(session_path.read_bytes(), session_bytes)
                self.assertFalse((directory / "report.md").exists())
                self.assertTrue(self.data("state", "verify", "--config", "archive")["ok"])

        # Absence must not mask damaged evidence: a readable record that
        # promises bytes beyond EOF still refuses both archive and clean.
        lane = "bad-run-span"
        worktree = self.start(lane, "silent")
        self.quiet(lane)
        directory = self.state / "lanes" / lane
        latest = next((directory / "runs").glob("*.json"))
        saved = latest.read_bytes()
        (self.directory / "saved-span.json").write_bytes(saved)
        self.addCleanup(latest.write_bytes, saved)
        record = json.loads(saved)
        self.data("lane", "mark", "--config", "archive", "--lane", lane, "--state", "abandoned")
        before, events = self.snapshot(lane, worktree), self.events()
        past_end = (directory / "output.log").stat().st_size + 1
        for start in (record["log"]["start"], past_end):
            record["log"] = {"start": start, "end": past_end}
            latest.write_text(json.dumps(record), encoding="utf-8")
            for action in ("archive", "clean"):
                result = self.call("lane", action, "--config", "archive", "--lane", lane, code=2)
                self.assertIn("fewer bytes", result["stderr"])
                self.assertEqual(self.snapshot(lane, worktree), before)
                self.assertEqual(self.events(), events)
        record = json.loads(saved)
        record["run"] += 1
        latest.write_text(json.dumps(record), encoding="utf-8")
        for action in ("archive", "clean"):
            result = self.call("lane", action, "--config", "archive", "--lane", lane, code=2)
            self.assertIn("does not match the current run", result["stderr"])
            self.assertEqual(self.snapshot(lane, worktree), before)
            self.assertEqual(self.events(), events)
        latest.write_bytes(saved)

    def test_s0_clean_keeps_lane_records(self):
        """6723773 adds archive documents and removes diagnostic logs on plain clean."""
        lane = "record-inventory"
        worktree = self.finish(lane)
        directory = self.state / "lanes" / lane
        diagnostic = directory / "diagnostics" / "retained.log"
        diagnostic.parent.mkdir()
        diagnostic.write_bytes(b"retained diagnostic canary\n" + uuid.uuid4().bytes)
        before = {str(path.relative_to(directory)): path.read_bytes() if path.is_file() else None
                  for path in directory.rglob("*")}
        result = self.data("lane", "clean", "--config", "archive", "--lane", lane)
        after = {str(path.relative_to(directory)): path.read_bytes() if path.is_file() else None
                 for path in directory.rglob("*")}
        self.assertEqual(after, before, "plain clean changed the retained lane record inventory or bytes")
        self.assertFalse(worktree.exists())
        self.assertEqual(self.git("branch", "--list", "--format=%(refname:short)", lane), "")
        self.assertTrue(result["verified"])
        self.assertFalse(result["pending"])
        self.assertIn(str(diagnostic), result["keep_paths"])
        self.assertNotIn(str(diagnostic), result["remove_paths"])
        self.verify_tar(result)
        receipt = Path(result["receipt"])
        records = receipt.with_name(receipt.name.removesuffix(".receipt.json") + ".records")
        self.assertFalse(records.is_relative_to(directory))
        documents = sorted(records.glob("*.md"))
        self.assertEqual(len(documents), 3, "the archive lost its generated source documents")
        indexed = [event["payload"] for event in self.events()
                   if event["lane"] == lane and event["kind"] == "store.record"]
        matches = self.data("store", "search", "--config", "archive", lane, "--lane", lane)
        for document in documents:
            payload = next(item for item in indexed if item["source"] == str(document))
            self.assertEqual(payload["sha256"], sha(document.read_bytes()))
            self.assertEqual(payload["text"].encode("utf-8"), document.read_bytes())
            self.assertTrue(any(item["source"] == str(document) for item in matches),
                            "the archived source is no longer searchable")
        with tarfile.open(result["archive"], "r:") as archive:
            self.assertEqual(archive.extractfile("lane/diagnostics/retained.log").read(), diagnostic.read_bytes())
        events = self.events()
        repeated = self.call("lane", "clean", "--config", "archive", "--lane", lane, code=2)
        self.assertIn("already cleaned", repeated["stderr"])
        self.assertEqual(self.events(), events)

    def test_s0_clean_refuses_foreign_claim(self):
        """130991c archives and deletes the old branch despite a real foreign live claim."""
        lane = "foreign-live-claim"
        worktree = self.finish(lane)
        self.git("worktree", "remove", worktree)
        self.git("worktree", "add", "-q", "-b", "replacement", worktree)
        other = self.config_home / "configs" / "visitor"
        other.mkdir()
        other.joinpath("config.toml").write_text(
            (self.config / "config.toml").read_text().replace('name = "archive"', 'name = "visitor"', 1),
            encoding="utf-8")
        shutil.copytree(self.config / "projects", other / "projects")
        environment = dict(self.environment, LANEBOSS_CONFIG="visitor")
        visitor = TerminalController(self, self.binary, environment, self.directory)

        def visit(*args):
            self.calls += 1
            prefix = self.directory / ("visitor-call-%04d" % self.calls)
            prefix.with_suffix(".input.json").write_text(json.dumps(list(map(str, args))) + "\n")
            result = visitor.request(args)
            prefix.with_suffix(".stdout").write_text(result["stdout"])
            prefix.with_suffix(".stderr").write_text(result["stderr"])
            prefix.with_suffix(".exit").write_text(str(result["code"]) + "\n")
            self.assertEqual(result["code"], 0, result["stderr"])
            return json.loads(result["stdout"])

        visit("config", "validate", "visitor")
        started = visit("lane", "start", "--config", "visitor", "--lane", "visitor-live", "--worktree", worktree,
                        "--brief", self.brief, "--role", "executor", "--runner", "hold",
                        "--model", "archive-fixture-model-v1", "--budget", "2")

        def stop_visitor():
            stopped = visit("lane", "stop", "--config", "visitor", "--lane", "visitor-live")
            self.assertEqual(stopped["survivors"], 0)

        self.addCleanup(stop_visitor)
        before = {str(path.relative_to(worktree)): path.read_bytes() for path in worktree.rglob("*") if path.is_file()}
        admin = Path(self.git("rev-parse", "--path-format=absolute", "--git-dir", directory=worktree))
        claim = (admin / "laneboss-claim").read_bytes()
        self.assertEqual(json.loads(claim)["config"], "visitor")
        before_events = self.events()
        archives = sorted(path.name for path in (self.state / "archives").glob("*"))
        refused = self.call("lane", "clean", "--config", "archive", "--lane", lane, code=2)
        self.assertIn("visitor", refused["stderr"])
        self.assertEqual(self.events(), before_events, "foreign claim refusal appended archive or cleanup events")
        self.assertEqual(sorted(path.name for path in (self.state / "archives").glob("*")), archives)
        self.assertEqual(self.git("branch", "--list", "--format=%(refname:short)", lane), lane)
        self.assertEqual(self.git("symbolic-ref", "--short", "HEAD", directory=worktree), "replacement")
        self.assertEqual({str(path.relative_to(worktree)): path.read_bytes() for path in worktree.rglob("*") if path.is_file()}, before)
        self.assertEqual((admin / "laneboss-claim").read_bytes(), claim)
        status = visit("lane", "status", "--config", "visitor", "--lane", "visitor-live")
        self.assertTrue(status["running"])
        self.assertEqual(status["live"]["launch"], started["launch"])

    def test_clean_readonly_pending(self):
        """5f50a12 exits 3 instead of queueing clean against a read-only store."""
        lane = "queued-clean"
        worktree = self.finish(lane)
        directory = self.state / "lanes" / lane
        report = (directory / "report.md").read_bytes()
        canary = (worktree / "canary.txt").read_bytes()
        raw = (directory / "output.log").read_bytes()
        self.configure("copy")
        store = self.state / "events.sqlite"
        original_mode = store.stat().st_mode & 0o777
        self.addCleanup(store.chmod, original_mode)
        store.chmod(0o444)
        result = self.data("lane", "clean", "--config", "archive", "--lane", lane)
        self.assertIs(result["pending"], True, "read-only cleanup lost its pending-event contract")
        self.assertIs(result["event"], None, "a queued cleanup claimed a stored event pointer")
        self.assertTrue(result.get("verified"), "pending cleanup skipped archive read-back")
        self.assertFalse(worktree.exists())
        self.assertEqual(self.git("branch", "--list", lane), "")
        self.assertEqual((directory / "output.log").read_bytes(), raw)
        queued_bytes = (directory / "pending.jsonl").read_bytes()
        (self.directory / "pending-before-reuse.jsonl").write_bytes(queued_bytes)
        queued = [json.loads(line) for line in queued_bytes.splitlines()]
        self.assertEqual([event["kind"] for event in queued],
                         ["archive.verified", *(["store.record"] * 4), "lane.cleaned", "archive.completed"])
        self.assertEqual(len({event["id"] for event in queued}), len(queued))
        self.assertFalse(any(event["lane"] == lane and event["id"] in {item["id"] for item in queued}
                             for event in self.events()), "a pending event was already presented as stored")
        receipt = json.loads(Path(result["receipt"]).read_bytes())
        self.assertTrue(receipt["read_back"])
        self.assertEqual(receipt["remote_sha256"], result["sha256"])
        self.assertEqual(sha(Path(result["archive"]).with_suffix(".remote.tar").read_bytes()), result["sha256"])
        with tarfile.open(result["archive"], "r:") as archive:
            self.assertEqual(archive.extractfile("worktree/canary.txt").read(), canary)
            self.assertEqual(archive.extractfile("lane/report.md").read(), report)

        store.chmod(original_mode)
        # No explicit lane check/flush intervenes: start --reuse itself must
        # drain the old cleanup and archive events before storing its start.
        restarted = self.data("lane", "start", "--config", "archive", "--project", "demo", "--lane", lane,
                              "--reuse", "--brief", self.brief, "--role", "executor", "--runner", "once",
                              "--model", "archive-fixture-model-v1", "--budget", "2")
        self.assertEqual(restarted["run"], 2)
        status = self.quiet(lane)
        events = {event["id"]: event for event in self.events()}
        stored_sequences = []
        for queued_event in queued:
            self.assertIn(queued_event["id"], events, "a queued archive/cleanup event never reached the store")
            stored = events[queued_event["id"]]
            self.assertEqual({key: stored[key] for key in queued_event}, queued_event)
            self.assertLess(stored["seq"], restarted["event"]["seq"])
            stored_sequences.append(stored["seq"])
        self.assertEqual(stored_sequences, sorted(set(stored_sequences)))
        self.assertFalse((directory / "pending.jsonl").exists())
        self.assertEqual((status["live"]["pending_events"], status["live"]["refused_events"]), (0, 0))
        self.verify_tar(result)
        matches = self.data("store", "search", "--config", "archive", "Searchable archive result queued-clean",
                            "--kind", "lane-report", "--lane", lane)
        self.assertTrue(any(match["text"].encode() == report for match in matches), "pending report ingest was lost")
        self.assertTrue(self.data("state", "verify", "--config", "archive")["ok"])

    def test_lane_supervisor_collect(self):
        """P2-10: a real L4 lane starts, marks and collects real L3 children."""
        _, observed = self.collector("parent-supervisor", [
            {"lane": "child-archive", "action": "archive"}, {"lane": "child-clean", "action": "clean"}])
        self.assertTrue(all(call["code"] == 0 for call in observed["calls"]),
                        "a child CLI operation by the recorded lane supervisor was refused")
        self.assertEqual([item["action"] for item in observed["results"]], ["archive", "clean"])
        events = self.events()
        for item in observed["results"]:
            lane = item["lane"]
            started = next(event for event in events if event["kind"] == "lane.started" and event["lane"] == lane)
            self.assertEqual((started["payload"]["level"], started["payload"]["starter"]), (3, "lane:parent-supervisor"))
            for kind in ("archive.verified", "lane.cleaned", "archive.completed"):
                event = next(event for event in events if event["kind"] == kind and event["lane"] == lane)
                self.assertEqual(event["actor"], "lane:parent-supervisor")
            self.verify_tar(item["result"])

    def test_p6_sibling_child_denied(self):
        """P1-6: 6723773 returns 0 for B collecting sibling A's L3 child."""
        target = "sibling-child"
        first, _ = self.collector("supervisor-a", [{"lane": target, "action": "prepare"}])
        worktree = Path(self.status(target)["worktree"])
        before = self.snapshot(target, worktree)
        # Include the L4 sibling itself as a preservation check of the strict
        # level test; the regression on 6723773 is the lower-level child.
        targets = (target, "supervisor-a")
        second, observed = self.collector("supervisor-b", [
            {"lane": lane, "action": action, "existing": True, "observe": True}
            for lane in targets for action in ("archive", "clean")])
        events = self.events()
        a = next(e["payload"] for e in events if e["lane"] == first["lane"] and e["kind"] == "lane.started")
        b = next(e["payload"] for e in events if e["lane"] == second["lane"] and e["kind"] == "lane.started")
        child = next(e["payload"] for e in events if e["lane"] == target and e["kind"] == "lane.started")
        self.assertEqual((a["level"], b["level"], a["starter"], b["starter"]), (4, 4, "human", "human"))
        self.assertEqual((child["level"], child["starter"]), (3, "lane:supervisor-a"))
        self.denied(observed, targets)
        self.intact(target, worktree, before)
        self.assertFalse(any(e["lane"] in targets and e["kind"].startswith("archive.") for e in events))

    def test_p6_human_child_denied(self):
        """6723773 grants the L4 collection; the L3 denial already held there."""
        target = "human-child"
        worktree = self.finish(target)
        before = self.snapshot(target, worktree)
        _, observed = self.collector("unrelated-supervisor", [
            {"lane": target, "action": action, "existing": True, "observe": True}
            for action in ("archive", "clean")])
        started = next(e["payload"] for e in self.events() if e["lane"] == target and e["kind"] == "lane.started")
        self.assertEqual((started["level"], started["starter"]), (3, "human"))
        self.denied(observed, (target,))
        _, peer = self.collector("peer-executor", [
            {"lane": target, "action": "clean", "existing": True, "observe": True}], level=3)
        self.denied(peer, (target,), ("clean",))
        self.intact(target, worktree, before)

    def test_p8_reused_name_denied(self):
        """130991c grants B authority over T through A's reused name."""
        parent, target = "reused-starter", "old-life-child"
        self.collector(parent, [{"lane": target, "action": "prepare"}])
        worktree = Path(self.status(target)["worktree"])
        (worktree / "canary.txt").write_bytes(b"old life must retain this file\n" + uuid.uuid4().bytes)
        report = self.state / "lanes" / target / "report.md"
        report_bytes = b"# Old life report\n\nKeep this child's recorded ancestry.\n"
        report.write_bytes(report_bytes)
        before = self.snapshot(target, worktree)
        self.data("lane", "mark", "--config", "archive", "--lane", parent, "--state", "merged")
        # Free the managed path through ordinary verified clean. The child's
        # lane stays finished and uncollected; only the parent's name is reused.
        cleaned = self.data("lane", "clean", "--config", "archive", "--lane", parent)
        self.assertTrue(cleaned["verified"])
        self.intact(target, worktree, before)
        attempts = [{"lane": target, "action": action, "existing": True, "observe": True}
                    for action in ("archive", "clean")]
        reuser, observed = self.collector("reuser-b", [
            {"lane": parent, "action": "prepare", "reuse": True}, *attempts])
        starts = [event for event in self.events() if event["lane"] == parent and event["kind"] == "lane.started"]
        child = next(event for event in self.events() if event["lane"] == target and event["kind"] == "lane.started")
        self.assertEqual(len(starts), 2)
        old, new = starts
        self.assertEqual((old["payload"]["level"], old["payload"]["starter"]), (4, "human"))
        self.assertEqual((child["payload"]["level"], child["payload"]["starter"]), (3, "lane:" + parent))
        self.assertEqual((new["payload"]["level"], new["payload"]["starter"], new["payload"]["run"]),
                         (3, "lane:reuser-b", 2))
        self.assertEqual(new["payload"]["how"], "reuse")
        self.assertNotEqual(old["payload"]["launch"], new["payload"]["launch"])
        self.assertLess(old["seq"], child["seq"])
        self.assertLess(child["seq"], reuser["event"]["seq"])
        self.assertLess(reuser["event"]["seq"], new["seq"])
        self.denied(observed, (target,))
        self.intact(target, worktree, before)
        self.assertEqual(report.read_bytes(), report_bytes)

        # Check the final hop as well: a new L4 life of A itself must not gain
        # collection authority over A's old L3 child just by matching its name.
        self.data("lane", "clean", "--config", "archive", "--lane", parent)
        caller, final_hop = self.collector(parent, attempts, reuse=True)
        current = next(event for event in self.events() if event["seq"] == caller["event"]["seq"])
        self.assertEqual((current["payload"]["level"], current["payload"]["run"]), (4, 3))
        self.assertNotEqual(current["payload"]["launch"], old["payload"]["launch"])
        self.assertGreater(current["seq"], child["seq"])
        self.denied(final_hop, (target,))
        self.assertTrue(all("same recorded lane lives" in item["stderr"] for item in final_hop["results"]))
        self.intact(target, worktree, before)
        self.assertEqual(report.read_bytes(), report_bytes)
        self.assertFalse(any(event["lane"] == target and event["kind"] in
                             ("archive.verified", "store.record", "lane.cleaned", "archive.completed")
                             for event in self.events()))

    def test_p7_clean_missing_worktree(self):
        """P1-7: 6723773 refuses clean after real git worktree remove."""
        lane = "missing-worktree"
        worktree = self.finish(lane)
        directory = self.state / "lanes" / lane
        originals = {"lane/" + str(path.relative_to(directory)): path.read_bytes()
                     for path in directory.rglob("*") if path.is_file()
                     and (path.suffix == ".log" or path.name == "report.md")}
        self.assertIn("lane/report.md", originals)
        self.assertIn("lane/output.log", originals)
        self.git("worktree", "remove", worktree)
        self.assertFalse(worktree.exists())
        result = self.data("lane", "clean", "--config", "archive", "--lane", lane)
        self.assertFalse(result["pending"])
        self.assertTrue(result["verified"] and self.status(lane)["cleaned"])
        self.assertIn({"item": "worktree", "path": str(worktree), "why": "missing"}, result["kept"])
        self.assertFalse(any(item["item"] == "worktree" for item in result["removed"]))
        self.assertFalse(any(Path(path).is_relative_to(worktree) for path in result["remove_paths"]))
        self.assertIn(str(worktree), result["keep_paths"])
        self.verify_tar(result)
        with tarfile.open(result["archive"], "r:") as archive:
            self.assertEqual({member.name: archive.extractfile(member).read() for member in archive.getmembers()}, originals)
        # Absence is collectable; both present and dangling symlinks remain
        # refusals. These are ordinary filesystem inputs, not fake CLI output.
        for name, present in (("linked-worktree", True), ("dangling-worktree", False)):
            linked = self.finish(name)
            self.git("worktree", "remove", linked)
            target = self.directory / (name + "-target")
            if present:
                target.mkdir()
                (target / "canary.txt").write_bytes(b"keep symlink target\n")
            linked.symlink_to(target, target_is_directory=True)
            events = self.events()
            reply = self.call("lane", "clean", "--config", "archive", "--lane", name, code=2)
            self.assertIn("symbolic link", reply["stderr"])
            self.assertEqual(linked.readlink(), target)
            self.assertEqual(self.events(), events)
            self.assertFalse(self.status(name)["cleaned"])
            if present:
                self.assertEqual((target / "canary.txt").read_bytes(), b"keep symlink target\n")

    def test_p7_unowned_worktree_kept(self):
        """6723773 refuses off-branch, absent, malformed or foreign claims."""
        other = self.finish("other-claim-owner")
        other_admin = Path(self.git("rev-parse", "--path-format=absolute", "--git-dir", directory=other))
        foreign = (other_admin / "laneboss-claim").read_bytes()
        for mode in ("branch", "absent", "malformed", "foreign"):
            with self.subTest(mode=mode):
                lane = "unowned-" + mode
                worktree = self.finish(lane)
                admin = Path(self.git("rev-parse", "--path-format=absolute", "--git-dir", directory=worktree))
                claim = admin / "laneboss-claim"
                self.assertTrue(claim.is_file())
                saved_claim = claim.read_bytes()
                (self.directory / (lane + "-original-claim.json")).write_bytes(saved_claim)
                if mode == "branch":
                    self.git("checkout", "-q", "-b", lane + "-review", directory=worktree)
                elif mode == "absent":
                    claim.rename(self.directory / (lane + "-removed-claim.json"))
                else:
                    claim.write_bytes(b"invalid claim JSON\n" if mode == "malformed" else foreign)
                (worktree / "unfinished.txt").write_bytes(b"keep unowned work\n")
                before = {str(path): path.read_bytes() for path in worktree.rglob("*") if path.is_file()}
                action = "archive" if mode == "branch" else "clean"
                result = self.data("lane", action, "--config", "archive", "--lane", lane)
                cleaned = result["clean"] if action == "archive" else result
                self.assertIn({"item": "worktree", "path": str(worktree), "why": "not-this-lane"}, cleaned["kept"])
                self.assertTrue(worktree.is_dir() and self.status(lane)["cleaned"])
                self.assertEqual({str(path): path.read_bytes() for path in worktree.rglob("*") if path.is_file()}, before)
                if mode in ("malformed", "foreign"):
                    self.assertEqual(claim.read_bytes(), b"invalid claim JSON\n" if mode == "malformed" else foreign)
                self.assertFalse(any(Path(path).is_relative_to(worktree) for path in result["remove_paths"]))
                manifest = json.loads(Path(result["manifest"]).read_bytes())
                self.assertTrue(all(entry["path"].startswith("lane/") for entry in manifest["entries"]))
                self.verify_tar(result)

    def test_pg_status_lines_public(self):
        """P2-G: 6723773 refuses public status lines and Go := code."""
        lane = "status-report"
        self.finish(lane)
        report = self.state / "lanes" / lane / "report.md"
        text = ('# Status receipt\nPASS: 26\nPass: 26/26\nAuth: OK\n'
                'Auth: OAuth\npass: 26/26\n    token := os.Getenv("T")\n')
        report.write_text(text, encoding="utf-8")
        self.call("store", "record", "--config", "archive", "--kind", "lane-report",
                  "--lane", lane, "--file", report)
        result = json.loads(self.archive(lane)["stdout"])
        self.assertFalse(result["report_private"], "ordinary status/code became private")
        matches = self.data("store", "search", "--config", "archive", "Status receipt", "--lane", lane)
        self.assertTrue(any(row["text"] == text and row["sha256"] == sha(text.encode()) and not row["private"]
                            for row in matches))
        self.verify_tar(result)
        # Positive controls for the same backstop are deliberately in this
        # row as well as test_sensitive_assignments_private.
        for name in ("PGPASSWORD", "DB_PASS"):
            source = self.directory / (name.lower() + "-assignment.md")
            value = (name + "=hunter2\n").encode()
            source.write_bytes(value)
            refused = self.call("store", "record", "--config", "archive", "--kind", "decision",
                                "--file", source, code=2)
            self.assertIn("--private", refused["stderr"])
            self.call("store", "record", "--config", "archive", "--kind", "decision", "--file", source, "--private")
            records = self.data("store", "search", "--config", "archive", source.name)
            self.assertTrue(any(row["private"] and row["text"] == "" and row["sha256"] == sha(value) for row in records))

    def test_ph_old_attempt_local(self):
        """P2-H: 6723773 halts every daily after an unavailable old attempt."""
        lane = "aaa-old-attempt"
        worktree = self.finish(lane)
        before = self.snapshot(lane, worktree)
        self.git("worktree", "lock", worktree)
        first = self.archive(lane, code=2)
        self.assertIn("refused to remove", first["stderr"])
        archives = self.state / "archives"
        # Every retained file, including an attempt's <base>.records documents, stays byte for byte.
        retained = {str(path.relative_to(archives)): path.read_bytes() for path in archives.rglob("*") if path.is_file()}
        unavailable = self.directory / "unavailable-archives"
        archives.rename(unavailable)
        good = self.finish("zzz-after-old-attempt")
        reply = self.call("archive", "daily", "--config", "archive", code=2)
        rows = [json.loads(line) for line in reply["stdout"].splitlines()]
        self.assertEqual([rows[0].get("status"), rows[1].get("verified")], ["refused", True],
                         "one lane's old artifacts starved a later lane")
        self.assertIn("different --to", rows[0]["reason"])
        self.assertEqual((rows[-1]["processed"], rows[-1]["refused"], rows[-1]["not_attempted"]), (1, 1, 0))
        self.assertFalse(good.exists())
        self.intact(lane, worktree, before)
        self.git("worktree", "unlock", worktree)
        result = json.loads(self.archive(lane, "--to", self.directory / "fresh-archives")["stdout"])
        self.assertFalse(result["reused"], "an explicit new destination failed to start a fresh verified attempt")
        self.assertFalse(worktree.exists())
        self.assertEqual({str(path.relative_to(unavailable)): path.read_bytes()
                          for path in unavailable.rglob("*") if path.is_file()}, retained)
        self.verify_tar(result)

    def test_pj_reuse_requires_upload(self):
        """P2-J: 6723773 collects the old local-only tar without uploading."""
        lane = "upload-policy-change"
        worktree = self.finish(lane)
        self.git("worktree", "lock", worktree)
        self.archive(lane, code=2)
        previous = next(e["payload"] for e in self.events() if e["lane"] == lane and e["kind"] == "archive.verified")
        self.assertIsNone(previous["remote_sha256"])
        self.configure("copy")
        self.git("worktree", "unlock", worktree)
        result = json.loads(self.archive(lane)["stdout"])
        self.assertFalse(result["reused"], "newly required remote verification was skipped")
        receipt = json.loads(Path(result["receipt"]).read_bytes())
        self.assertEqual(receipt["remote_sha256"], result["sha256"])
        attempts = [json.loads(line) for line in (self.state / "archives/upload-attempts.jsonl").read_text().splitlines()]
        self.assertEqual([attempt["lane"] for attempt in attempts], [lane])
        self.verify_tar(result)

    def test_pj_target_actor_not_reused(self):
        """6723773 trusts the target actor, then fails its empty ingest span."""
        lane = "target-verification"
        worktree = self.finish(lane)
        self.git("worktree", "lock", worktree)
        self.archive(lane, code=2)
        verified = next(e for e in self.events() if e["lane"] == lane and e["kind"] == "archive.verified")
        supplied = {key: verified[key] for key in ("kind", "lane", "payload", "protocol_version")}
        supplied["actor"] = "lane:" + lane
        source = self.directory / "target-actor-event.json"
        source.write_text(json.dumps(supplied), encoding="utf-8")
        # Use the public append path to supply this metadata. This isolates
        # reuse's trust rule; it is not a claim of a practical forgery attack.
        self.call("event", "append", "--config", "archive", "--file", source)
        self.git("worktree", "unlock", worktree)
        result = json.loads(self.archive(lane)["stdout"])
        self.assertFalse(result["reused"], "a target-actor event was accepted as a collection receipt")
        fresh = max((e for e in self.events() if e["lane"] == lane and e["kind"] == "archive.verified"), key=lambda e: e["seq"])
        self.assertNotEqual(fresh["actor"], "lane:" + lane)
        self.assertEqual(fresh["payload"]["receipt"], result["receipt"])
        self.verify_tar(result)

    def test_reused_lane_report_current(self):
        lane = "current-report"
        self.finish(lane, report=False)
        self.archive(lane)
        self.brief.write_text("# Second task with different report provenance\n\n" + "Read the next kept task.\n" * 9, encoding="utf-8")
        started = self.data("lane", "start", "--config", "archive", "--project", "demo", "--lane", lane,
                            "--reuse", "--brief", self.brief, "--role", "executor", "--runner", "once",
                            "--model", "archive-fixture-model-v1", "--budget", "2")
        self.quiet(lane)
        self.data("lane", "mark", "--config", "archive", "--lane", lane, "--state", "merged")
        directory = self.state / "lanes" / lane
        record = max((json.loads(path.read_bytes()) for path in (directory / "runs").glob("*.json")), key=lambda row: row["run"])
        span = record["log"]
        text = (directory / "output.log").read_bytes()[span["start"]:span["end"]]
        self.archive(lane)
        fresh = [event["payload"] for event in self.events() if event["kind"] == "store.record"
                 and event["seq"] > started["event"]["seq"] and event["payload"]["kind"] == "lane-report"]
        self.assertTrue(any(row["text"].encode() == text and row["sha256"] == sha(text) for row in fresh),
                        "lane reuse indexed the previous run's stored report")


if __name__ == "__main__":
    unittest.main()

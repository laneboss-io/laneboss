"""R1 and R8, black-box report identity and lifecycle rows.

Run on the disposable test box against the integrated binary in LANEBOSS_BIN.
No product module is imported and no binary is built here. A mutation run uses
this same row and its same assertions, with a laneboss_faults binary and either
LANEBOSS_REPORT_MUTANT or LANEBOSS_FAULTS. The shared helper also honors
LANEBOSS_REPORT_MARKER. The dashboard assertions require part C to be integrated.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

# The stand-in can be invoked with -I; only this fixture's own helper directory
# is added, so its imports never depend on a lane's working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from headless_support import HeadlessController
from orgsupport import ROLES, SUPERVISOR, init_org
from reportsupport import POINT_ROWS, TerminalController, fault_environment, mutation_selection

MUTANTS = {
    name: POINT_ROWS[name] for name in ("starter-level-minus-one", "actor-fixed-laneboss")
}
# The level rule's own refusal (internal/caller belowStarter), as `lane start` prints it: one line, every line prefixed.
LEVEL_RULE = "refused: the lane's level must be below its starter's recorded level"


RUNNER = r'''import json
import os
from pathlib import Path
import subprocess
import sys
import time

mode, lane = sys.argv[1:3]
prompt = sys.stdin.buffer.read()
print("identity fixture read %d bytes" % len(prompt), flush=True)
Path("ready.json").write_text(json.dumps({"pid": os.getpid(), "lane": lane,
                                         "prompt_bytes": len(prompt)}), encoding="utf-8")
if mode == "nested":
    plan = json.loads(Path("nested.json").read_text(encoding="utf-8"))
    result = subprocess.run([plan["binary"], *plan["args"]], capture_output=True, text=True, timeout=60)
    Path("nested-result.json").write_text(json.dumps({"code": result.returncode,
                                                    "stdout": result.stdout,
                                                    "stderr": result.stderr}), encoding="utf-8")
    sys.exit(result.returncode)
if mode == "hold":
    while True:
        time.sleep(1)
elif mode != "once":
    raise RuntimeError("unknown stand-in mode")
'''


class ReportIdentityRows(unittest.TestCase):
    def setUp(self):
        binary = os.environ.get("LANEBOSS_BIN")
        self.assertTrue(binary and Path(binary).is_absolute() and Path(binary).is_file() and os.access(binary, os.X_OK),
                        "LANEBOSS_BIN must name the already built integrated binary")
        self.binary = Path(binary)
        self.temporary = tempfile.TemporaryDirectory(prefix="lb-rl-int-report-identity-")
        self.directory = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)
        self.home = self.directory / "configuration"
        self.states = self.directory / "state"
        self.state = self.states / "identity"
        config = self.home / "configs" / "identity"
        config.mkdir(parents=True)
        self.runner = self.directory / "standin.py"
        self.runner.write_text(RUNNER, encoding="utf-8")
        self.brief = self.directory / "brief.md"
        self.brief.write_text("# Recorded identity fixture\n\nRun the invented lane task.\n", encoding="utf-8")
        runner_tables = []
        for name, mode, session in (("once", "once", False), ("hold", "hold", True),
                                    ("nested", "nested", False), ("turns", "once", True)):
            command = [sys.executable, str(self.runner), mode, "{lane}"]
            if session:
                command.append("{session}")
            extra = ('records = [{format = "claude-code", paths = ["{worktree}/.sessions/{session}.jsonl"]}]\n'
                     if name == "turns" else "")
            runner_tables.append('[runners.{}]\ncommand = {}\nresume = {}\nprompt = "stdin"\n'
                                 'quiet_seconds = 1\n{}\n'.format(name, json.dumps(command),
                                                                  json.dumps(command), extra))
        config_text = ('schema_version = 1\nname = "identity"\ndescription = "Invented report-line fixture."\n'
                       'organisation = "identity-org"\n'
                       'rules = []\nsecrets = []\nowner_channel = "human-file"\ntest_environment = "cloud"\n'
                       '[lanes]\nbudget_minutes = 2\nquiet_seconds = 900\nstop_grace_seconds = 1\n'
                       '[test_environments.cloud]\nkind = "cloud"\nidentity = "invented-test"\n'
                       '[owner_channels.human-file]\nkind = "file"\npath = "owner-report.md"\n'
                       '[supervisors.super-top]\nlevel = 6\nrunner = "once"\nprojects = []\nowner_channel = "human-file"\n'
                       '[supervisors.top]\nlevel = 5\nrunner = "once"\nprojects = []\nowner_channel = "human-file"\n'
                       '[supervisors.mini-a]\nlevel = 4\nrunner = "once"\nprojects = []\nowner_channel = "human-file"\n'
                       + "".join(runner_tables))
        (config / "config.toml").write_text(config_text, encoding="utf-8")
        # Keep only the mutant request from the harness, and bind every product
        # command to this row's private configuration and state directories.
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("LANEBOSS_") or key == "LANEBOSS_FAULTS"}
        for key in ("TMUX", "TMUX_PANE"):
            environment.pop(key, None)
        environment.update(LANEBOSS_HOME=str(self.home), LANEBOSS_STATE_HOME=str(self.states),
                           LANEBOSS_CONFIG="identity", TMUX_TMPDIR=str(self.directory / "tmux"))
        (self.directory / "tmux").mkdir()
        # Lane starts enforce the org's role templates: the configuration names an org with the role library.
        init_org(self.binary, environment, self.directory, self.home, "identity-org")
        self.mutant, self.fault_marker = mutation_selection(self.directory)
        environment.update(fault_environment(self.mutant, self.mutant, self.fault_marker))
        self.environment = environment
        self.repository = self.directory / "repository"
        self.git("init", "-q", str(self.repository))
        # The only fixture commit is empty, in this row's disposable repository.
        self.git("-C", str(self.repository), "-c", "user.name=demo", "-c", "user.email=demo",
                 "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "bootstrap")
        self.human = TerminalController(self, self.binary, environment, self.directory)
        self.started = set()
        self.addCleanup(self.collect_lanes)

    def call(self, *args, **options):
        return self.human.call(*args, **options)

    def mutation_reached(self, point):
        if self.mutant == point:
            self.assertTrue(self.fault_marker.is_file(), "the selected mutation did not reach its product call site")

    def data(self, *args, **options):
        return json.loads(self.call(*args, **options)["stdout"])

    def role(self, name):
        # TerminalController obtains a real service-issued file when configured;
        # the same actual start command remains the registration assertion.
        return self.data("start", "--config", "identity", "--role", name, "--format", "json")

    def git(self, *args):
        fixture = getattr(self, "_ticket_fixture", None)
        demote = None
        if fixture is not None and getattr(self, "_ticket_actor_mode", False):
            fixture.prepare_actor_files()
            demote = fixture.demote(fixture.human_uid)
        result = subprocess.run(["git", *args], cwd=self.directory, env=self.environment,
                                capture_output=True, text=True, timeout=30, preexec_fn=demote)
        self.assertEqual(result.returncode, 0, "prepare the disposable worktrees: " + result.stderr)
        return result

    def worktree(self, lane):
        path = self.directory / "work" / lane
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            # Linked worktrees keep each claim in this row's own Git metadata.
            # Plain temporary directories can reuse inodes from previous rows
            # whose claims remain in the account-wide registry.
            self.git("-C", str(self.repository), "worktree", "add", "-q", "--detach", str(path))
        self.assertTrue((path / ".git").is_file(), "each lane must have its own linked Git worktree")
        return path

    def start_args(self, lane, runner="once", **extra):
        # Every start names an org role template; an L3 lane takes the library's L3 role unless a row names another.
        extra.setdefault("role", ROLES[3])
        args = ["lane", "start", "--config", "identity", "--lane", lane,
                "--brief", str(self.brief), "--worktree", str(self.worktree(lane)),
                "--runner", runner, "--model", runner + "-model-1"]
        for key, value in extra.items():
            args.append("--" + key.replace("_", "-"))
            if value is not True:
                args.append(str(value))
        return args

    def start(self, lane, runner="once", caller_role=None, **extra):
        self.started.add(lane)
        return self.data(*self.start_args(lane, runner, **extra), role=caller_role)

    def events(self):
        return self.data("state", "events", "--config", "identity")

    def event(self, lane, kind, run=None, state=None, timeout=30):
        deadline = time.monotonic() + timeout
        while True:
            found = [event for event in self.events() if event["lane"] == lane and event["kind"] == kind
                     and (run is None or event["payload"].get("run") == run)
                     and (state is None or event["payload"].get("state") == state)]
            if found:
                return found[-1]
            self.assertLess(time.monotonic(), deadline, "missing actual {} event for {}".format(kind, lane))
            time.sleep(0.2)

    def ready(self, lane):
        path = self.worktree(lane) / "ready.json"
        deadline = time.monotonic() + 30
        while not path.is_file():
            self.assertLess(time.monotonic(), deadline, "the actual runner never became ready")
            time.sleep(0.1)
        result = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(result["lane"], lane)
        self.assertGreater(result["prompt_bytes"], 0)
        return result

    def dashboard(self):
        reply = self.call("dashboard", "--config", "identity", "--port", "0", serve=True)
        url = urlsplit(reply["stdout"])
        self.assertEqual(url.hostname, "127.0.0.1")
        self.assertTrue(url.fragment.startswith("t="), "dashboard readiness has no token")
        self.base = "http://" + url.netloc
        self.token = url.fragment[2:]

    def api(self, path):
        request = Request(self.base + path, headers={"X-Laneboss-Token": self.token, "Origin": self.base})
        with urlopen(request, timeout=30) as response:
            self.assertEqual(response.status, 200)
            return json.load(response)

    def assert_line(self, lane, level, source, starter):
        event = self.event(lane, "lane.started", run=1)
        payload = event["payload"]
        self.assertEqual(payload["level"], level, "R1: the lane level must come from its own role or protocol")
        self.assertEqual(payload["level_source"], source)
        self.assertEqual(payload["starter"], starter)
        rendered = Path(payload["brief"]["path"]).read_text(encoding="utf-8")
        self.assertIn("## Report line", rendered)
        self.assertIn("Level: L{} (source: {})".format(level, source), rendered)
        self.assertIn("The human may message you at any time, from the dashboard.", rendered)
        return event

    def collect_lanes(self):
        rows = self.data("state", "lanes", "--config", "identity")
        for row in rows:
            if row["running"]:
                self.data("lane", "stop", "--config", "identity", "--lane", row["lane"])
        # Observe completion by PID and start time, never by command-line pattern.
        identities = []
        for path in self.state.glob("lanes/*/runs/*.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            identities.extend([record.get("supervisor"), record.get("runner"), *record.get("processes", [])])
        deadline = time.monotonic() + 30
        while True:
            alive = [identity["pid"] for identity in identities
                     if identity is not None and self.process_alive(identity)]
            if not alive:
                break
            self.assertLess(time.monotonic(), deadline, "recorded processes still live after collection: {}".format(alive))
            time.sleep(0.1)

    @staticmethod
    def process_alive(identity):
        path = Path("/proc") / str(identity["pid"]) / "stat"
        try:
            data = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        fields = data[data.rindex(")") + 1:].split()
        return fields[0] != "Z" and fields[19] == identity["start"]

    def test_r1_recorded_identity_and_parent(self):
        """R1: terminal, role ticket, nested lane and headless-session starts have real parents."""
        self.start("human-one")
        self.event("human-one", "lane.ended", run=1)
        self.assert_line("human-one", 3, "protocol", "human")
        self.role("super-top")
        self.start("role-one", caller_role="super-top")
        self.mutation_reached("starter-level-minus-one")
        self.event("role-one", "lane.ended", run=1)
        self.assert_line("role-one", 3, "protocol", "supervisor:super-top")
        self.start("mini-one", caller_role="super-top", role=SUPERVISOR, level=4)
        self.event("mini-one", "lane.ended", run=1)
        self.assert_line("mini-one", 4, "org", "supervisor:super-top")
        child = self.start_args("nested-child")
        self.started.add("nested-child")
        controller = self.worktree("controller")
        (controller / "nested.json").write_text(json.dumps({"binary": str(self.binary), "args": child}), encoding="utf-8")
        self.start("controller", runner="nested", role=SUPERVISOR, level=5)
        ended = self.event("controller", "lane.ended", run=1)
        self.assertEqual(ended["payload"]["exit_code"], 0, "inside-lane start failed in the real runner")
        nested = json.loads((controller / "nested-result.json").read_text(encoding="utf-8"))
        self.assertEqual(nested["code"], 0, nested["stderr"])
        self.event("nested-child", "lane.ended", run=1)
        self.assert_line("controller", 5, "org", "human")
        self.assert_line("nested-child", 3, "protocol", "lane:controller")
        # A pipe-only session with no terminal, as a tool shell has, that registered itself with `start --role` is
        # recorded as the starter of the lanes it starts. (A start from a session that registered nothing is refused:
        # row C1 of test_headless.py.)
        self.started.add("detached-one")
        session = HeadlessController(self)
        registered = session.request(["start", "--config", "identity", "--role", "super-top"])
        self.assertEqual(registered["code"], 0, registered["stderr"])
        detached = session.request(self.start_args("detached-one"))
        self.assertEqual(detached["code"], 0, detached["stderr"])
        self.event("detached-one", "lane.ended", run=1)
        self.assert_line("detached-one", 3, "protocol", "supervisor:super-top")
        before = self.events()
        equal = self.call(*self.start_args("equal-level", role=SUPERVISOR, level=6), role="super-top", code=2)
        self.assertEqual(equal["stderr"], LEVEL_RULE + "\n", "an equal-level start must be refused by the level rule")
        self.assertEqual(self.events(), before, "a refused equal-level start wrote an event")
        self.call(*self.start_args("missing-role", role="missing"), code=2)
        self.assertEqual(self.events(), before, "an unreadable role wrote an event")
        self.dashboard()
        graph = self.api("/api/graph")
        nodes = {node["id"]: node for node in graph["nodes"]}
        for lane, level, parent in (("human-one", 3, "human"), ("role-one", 3, "supervisor:super-top"),
                                    ("mini-one", 4, "supervisor:super-top"), ("controller", 5, "human"),
                                    ("nested-child", 3, "lane:controller"),
                                    ("detached-one", 3, "supervisor:super-top")):
            node = nodes["lane:" + lane]
            self.assertEqual((node["level"], node["parent"]), (level, parent))
        self.assertEqual(nodes["lane:detached-one"]["starter"], "supervisor:super-top")

    def test_older_record_keeps_supervisors(self):
        """A tagged real start supplies the historical level source beside a current org-sourced start."""
        self.role("super-top")
        self.start("new-one", caller_role="super-top", role=SUPERVISOR, level=4)
        self.event("new-one", "lane.ended", run=1)
        self.assert_line("new-one", 4, "org", "supervisor:super-top")
        tagged = os.environ.get("LANEBOSS_FAULTS_BIN", "")
        self.assertTrue(tagged and Path(tagged).is_absolute() and Path(tagged).is_file() and os.access(tagged, os.X_OK),
                        "LANEBOSS_FAULTS_BIN must name the built historical fixture binary")
        historical = TerminalController(self, binary=Path(tagged))
        historical.call("start", "--config", "identity", "--role", "super-top", role="super-top")
        marker = self.directory / "historical-source-reached"
        result = historical.request(self.start_args("legacy-one", role=SUPERVISOR, level=4), role="super-top",
                                    environment={"LANEBOSS_FAULTS": json.dumps({"point": "historical-supervisors",
                                                                              "marker": str(marker)})})
        self.assertEqual(result["code"], 0, result["stderr"])
        self.assertTrue(marker.is_file(), "the historical source fixture was not reached")
        self.event("legacy-one", "lane.ended", run=1)
        self.dashboard()
        nodes = {node["id"]: node for node in self.api("/api/graph")["nodes"]}
        legacy, current = nodes["lane:legacy-one"], nodes["lane:new-one"]
        self.assertEqual((legacy["level"], legacy["level_source"], legacy["starter"], legacy["parent"]),
                         (4, "supervisors", "supervisor:super-top", "supervisor:super-top"),
                         "an older record must keep reporting the source it was written with")
        self.assertEqual((current["level"], current["level_source"], current["parent"]),
                         (4, "org", "supervisor:super-top"))

    def test_agreeing_lane_cannot_claim_human(self):
        """A lane whose recorded identity agrees with its LANEBOSS_LANE label still cannot select the human principal.

        The caller's identity is resolved before the role gate. Here it resolves, and agrees with the label, so the
        refusal is the role gate's own, with its exact text, and not the identity refusal that a label no recorded lane
        carries gets. A control lane starts the same child without the claim and succeeds, which shows that the
        identity resolved.
        """
        gate = ("refused: a supervised session cannot select a human principal\n"
                "Instead: select --role from the lane level's roles\n")
        results = {}
        for lane, extra in (("claim-lane", {"principal": "human"}), ("plain-lane", {})):
            work = self.worktree(lane)
            plan = self.start_args(lane + "-child", **extra)
            (work / "nested.json").write_text(json.dumps({"binary": str(self.binary), "args": plan}), encoding="utf-8")
            self.start(lane, runner="nested", role=SUPERVISOR, level=4)
            self.event(lane, "lane.ended", run=1)
            results[lane] = json.loads((work / "nested-result.json").read_text(encoding="utf-8"))
        claim = results["claim-lane"]
        self.assertEqual((claim["code"], claim["stdout"], claim["stderr"]), (2, "", gate),
                         "the role gate must refuse the human claim of a lane whose identity agrees with its label")
        self.assertEqual([event for event in self.events() if event["lane"] == "claim-lane-child"], [],
                         "the refused claim wrote an event")
        self.assertEqual(results["plain-lane"]["code"], 0, results["plain-lane"]["stderr"])
        self.event("plain-lane-child", "lane.ended", run=1)

    def test_r8_lifecycle_records_actual_actor(self):
        """R8: every listed lifecycle step retains its actual principal or detected launcher."""
        self.role("mini-a")
        self.start("lifecycle", runner="hold", caller_role="mini-a")
        self.mutation_reached("actor-fixed-laneboss")
        self.ready("lifecycle")
        self.assertEqual(self.event("lifecycle", "lane.started", run=1)["actor"], "supervisor:mini-a",
                         "R8: a start actor must be the real starter")
        self.data("lane", "stop", "--config", "identity", "--lane", "lifecycle")
        self.assertEqual(self.event("lifecycle", "lane.ended", run=1)["actor"], "human")
        self.data("lane", "resume", "--config", "identity", "--lane", "lifecycle", role="mini-a")
        self.event("lifecycle", "lane.started", run=2)
        self.assertEqual(self.event("lifecycle", "lane.resumed", run=2)["actor"], "supervisor:mini-a")
        self.data("lane", "stop", "--config", "identity", "--lane", "lifecycle", role="mini-a")
        self.assertEqual(self.event("lifecycle", "lane.ended", run=2)["actor"], "supervisor:mini-a")
        self.data("lane", "mark", "--config", "identity", "--lane", "lifecycle", "--state", "accepted")
        self.assertEqual(self.event("lifecycle", "lane.state", state="accepted")["actor"], "human")
        self.data("lane", "mark", "--config", "identity", "--lane", "lifecycle", "--landing", "merged", role="mini-a")
        self.assertEqual(self.event("lifecycle", "lane.merged")["actor"], "supervisor:mini-a")
        self.data("lane", "mark", "--config", "identity", "--lane", "lifecycle", "--state", "merged", role="mini-a")
        self.data("lane", "clean", "--config", "identity", "--lane", "lifecycle")
        self.assertEqual(self.event("lifecycle", "lane.cleaned")["actor"], "human")
        self.start("abandoned-one", caller_role="mini-a")
        self.event("abandoned-one", "lane.ended", run=1)
        self.data("lane", "mark", "--config", "identity", "--lane", "abandoned-one", "--state", "abandoned", role="mini-a")
        self.assertEqual(self.event("abandoned-one", "lane.state", state="abandoned")["actor"], "supervisor:mini-a")
        self.data("lane", "clean", "--config", "identity", "--lane", "abandoned-one", role="mini-a")
        # Adoption uses a real idle session record, not an appended synthetic event.
        adopted = self.worktree("adopted-one")
        session = "cf99c6a8-32ed-4b81-8a1d-f0d84903ae72"
        record = adopted / ".sessions" / (session + ".jsonl")
        record.parent.mkdir()
        record.write_text(json.dumps({"type": "assistant", "timestamp": "2026-10-12T09:00:00.000Z",
                                     "cwd": str(adopted), "message": {"content": []}}) + "\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(record, (old, old))
        self.started.add("adopted-one")
        self.data("lane", "adopt", "--config", "identity", "--lane", "adopted-one", "--session", session,
                  "--runner", "turns", "--model", "turns-model-1", "--worktree", adopted,
                  "--brief", self.brief, "--role", ROLES[3], role="mini-a")
        adoption = self.event("adopted-one", "lane.adopted")
        self.assertEqual((adoption["actor"], adoption["payload"]["level"], adoption["payload"]["starter"]),
                         ("supervisor:mini-a", 3, "supervisor:mini-a"))
        self.data("lane", "send", "--config", "identity", "--lane", "adopted-one", "-",
                  role="mini-a", input_text="Continue the adopted session.\n")
        self.data("lane", "turn", "--config", "identity", "--lane", "adopted-one")
        self.event("adopted-one", "lane.ended", run=2)
        for kind in ("lane.resumed", "lane.started"):
            self.assertEqual(self.event("adopted-one", kind, run=2)["actor"], "supervisor:mini-a",
                             "a turn must record the waking mail's sender")
        self.start("lost-one", runner="hold", caller_role="mini-a")
        self.ready("lost-one")
        start = self.event("lost-one", "lane.started", run=1)
        run_record = self.state / "lanes" / "lost-one" / "runs" / (start["payload"]["launch"] + ".json")
        deadline = time.monotonic() + 30
        while True:
            processes = json.loads(run_record.read_text(encoding="utf-8"))
            if processes["runner"] is not None:
                break
            self.assertLess(time.monotonic(), deadline, "the runner identity was never recorded")
            time.sleep(0.1)
        supervisor = processes["supervisor"]
        os.kill(supervisor["pid"], signal.SIGKILL)
        while self.process_alive(supervisor):
            self.assertLess(time.monotonic(), deadline, "the killed supervisor still lives")
            time.sleep(0.1)
        self.data("lane", "check", "--config", "identity", "--lane", "lost-one")
        self.assertEqual(self.event("lost-one", "lane.lost", run=1)["actor"], "laneboss")
        self.data("lane", "stop", "--config", "identity", "--lane", "lost-one")
        self.dashboard()
        graph = self.api("/api/graph")
        nodes = {node["id"]: node for node in graph["nodes"]}
        for lane in ("lifecycle", "abandoned-one", "adopted-one", "lost-one"):
            self.assertEqual(nodes["lane:" + lane]["parent"], "supervisor:mini-a",
                             "lifecycle changes must preserve the lane's recorded supervisor")
            stored = [event for event in self.events() if event["lane"] == lane]
            shown = {event["id"]: event for event in self.api("/api/events?lane=" + lane)}
            for event in stored:
                if event["kind"] in {"lane.started", "lane.adopted", "lane.resumed", "lane.ended",
                                     "lane.state", "lane.merged", "lane.cleaned", "lane.lost"}:
                    self.assertIn(event["id"], shown, "a lifecycle event was omitted from the dashboard")
                    self.assertEqual(shown[event["id"]]["actor"], event["actor"])
        self.assertTrue(self.data("state", "verify", "--config", "identity")["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

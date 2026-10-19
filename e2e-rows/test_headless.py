"""H1-H11 and C1: headless identity, real processes and the real unified binary.

Run only on the Linux test box with LANEBOSS_BIN already built. All callers
use pipes and setsid, and check /dev/tty and /proc immediately before exec.
The launcher itself still uses its normal tmux transport for lane runners.
LANEBOSS_HEADLESS_MUTANT selects caller-session-no-start, caller-session-env
or caller-unidentified-start on a laneboss_faults binary. The selected row must
fail its refusal assertion; LANEBOSS_HEADLESS_MARKER names the required
call-site evidence file.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from headless_support import HeadlessController
from orgsupport import ROLES, init_org


MUTANTS = {
    "caller-session-no-start": "test_h6_reused_pid",
    "caller-session-env": "test_h7_env_only",
    "caller-unidentified-start": "test_c1_unidentified_start",
}
# The first line of the refusal of a lane start or adoption by a caller that nothing identifies, as `lane` prints it,
# and the two ways out its Instead route names.
UNIDENTIFIED = "refused: the caller has no recorded identity"
UNIDENTIFIED_ROUTES = ("laneboss start --role", "from a terminal as the human")


def runner_main(session):
    prompt = sys.stdin.buffer.read()
    path = Path("prompts")
    path.mkdir(exist_ok=True)
    (path / (uuid.uuid4().hex + ".txt")).write_bytes(prompt)
    print(json.dumps({"type": "system", "subtype": "init", "session_id": session}), flush=True)


class HeadlessRows(unittest.TestCase):
    def setUp(self):
        binary = os.environ.get("LANEBOSS_BIN", "")
        self.binary = Path(binary)
        self.assertTrue(binary and self.binary.is_absolute() and self.binary.is_file()
                        and os.access(self.binary, os.X_OK),
                        "LANEBOSS_BIN must name an already built binary")
        temporary = tempfile.TemporaryDirectory(prefix="lb-rl-headless-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.home = self.directory / "config"
        self.states = self.directory / "state"
        self.state = self.states / "headless"
        config = self.home / "configs" / "headless"
        config.mkdir(parents=True)
        self.brief = self.directory / "brief.md"
        self.brief.write_text("Read the invented fixture task.\n", encoding="utf-8")
        self.message = self.directory / "message.md"
        self.message.write_text("Continue the invented task.\n", encoding="utf-8")
        user_home = self.directory / "home"
        user_home.mkdir()
        command = [sys.executable, "-I", str(Path(__file__).resolve()), "--runner", "{session}"]
        text = ('schema_version = 1\nname = "headless"\norganisation = "headless-org"\n'
                '[lanes]\nbudget_minutes = 2\nquiet_seconds = 900\nstop_grace_seconds = 1\n'
                '[runners.once]\ncommand = ' + json.dumps(command) + '\nresume = ' +
                json.dumps(command) + '\nprompt = "stdin"\nquiet_seconds = 1\n'
                'records = [{format = "claude-code", '
                'paths = ["{worktree}/.sessions/{session}.jsonl"]}]\n'
                '[supervisors.top]\nlevel = 5\nrunner = "once"\nprojects = []\n')
        (config / "config.toml").write_text(text, encoding="utf-8")
        self.environment = {
            "PATH": os.environ.get("PATH", os.defpath), "HOME": str(user_home),
            "LANEBOSS_HOME": str(self.home), "LANEBOSS_STATE_HOME": str(self.states),
            "LANEBOSS_CONFIG": "headless", "TMUX_TMPDIR": str(self.directory),
            "LANEBOSS_TEST_CLAIMS_DIR": str(self.directory / "claims"),
        }
        # Lane starts enforce the org's role templates: the configuration names an org with the role library.
        org = init_org(self.binary, self.environment, self.directory, self.home, "headless-org")
        (org / "tools").mkdir()
        self.mutant = os.environ.get("LANEBOSS_HEADLESS_MUTANT", "")
        self.assertTrue(not self.mutant or self.mutant in MUTANTS, "unknown headless mutant")
        self.marker = Path(os.environ.get("LANEBOSS_HEADLESS_MARKER")
                           or str(self.directory / "mutation-reached"))
        self.assertTrue(self.marker.is_absolute(), "the mutation marker must be absolute")
        self.controller = HeadlessController(self)
        self.addCleanup(self.collect_lanes)

    def call(self, *args, controller=None, code=0, **options):
        result = (controller or self.controller).request(args, **options)
        self.assertEqual(result["code"], code, result["stderr"])
        return result

    def data(self, *args, **options):
        return json.loads(self.call(*args, **options)["stdout"])

    @staticmethod
    def process_start(pid):
        data = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
        fields = data[data.rindex(")") + 1:].split()
        return fields[19]

    def record_path(self, controller=None):
        return self.state / "sessions" / (str((controller or self.controller).process.pid) + ".json")

    def register(self, controller=None, **options):
        controller = controller or self.controller
        self.call("start", "--config", "headless", "--role", "top",
                  controller=controller, **options)
        path = self.record_path(controller)
        if hasattr(self, "_ticket_fixture"):
            self.assertFalse(path.exists(), "service registration wrote a caller-owned session")
            who = self.data("service", "status", "--config", "headless", controller=controller)
            self.assertEqual(who["principal"]["id"], "supervisor:top")
            self.assertEqual(who["identity_root"]["pid"], controller.process.pid)
            return {"config": "headless", "principal": "supervisor:top",
                    "pid": who["identity_root"]["pid"], "start": who["identity_root"]["start"]}
        self.assertTrue(path.is_file(), "headless start did not persist the session identity")
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(record, {"config": "headless", "principal": "supervisor:top",
                                  "pid": controller.process.pid,
                                  "start": self.process_start(controller.process.pid)})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse((self.state / "roles" / "top.json").exists(),
                         "headless start wrote a terminal ticket")
        return record

    def worktree(self, lane):
        path = self.directory / "work" / lane
        path.mkdir(parents=True, exist_ok=True)
        return path

    def start_lane(self, lane, turns=True):
        args = ["lane", "start", "--config", "headless", "--lane", lane,
                "--brief", self.brief, "--worktree", self.worktree(lane),
                "--runner", "once", "--model", "once-model-1", "--role", ROLES[3]]
        if turns:
            args.append("--turns")
        result = self.data(*args)
        self.assertEqual(result["starter"], "supervisor:top")
        self.assertEqual(result["level"], 3)
        self.settled(lane)
        ended = self.events_for(lane, "lane.ended")
        self.assertEqual(len(ended), 1)
        self.assertEqual(ended[0]["payload"]["exit_code"], 0, "the stand-in did not finish its real run")
        prompts = list((self.worktree(lane) / "prompts").glob("*.txt"))
        self.assertEqual(len(prompts), 1)
        self.assertIn(self.brief.read_bytes(), prompts[0].read_bytes())
        return result

    def events(self):
        return self.data("state", "events", "--config", "headless")

    def events_for(self, lane, kind):
        return [event for event in self.events()
                if event["lane"] == lane and event["kind"] == kind]

    def settled(self, lane):
        deadline = time.monotonic() + 30
        while True:
            status = self.data("lane", "status", "--config", "headless", "--lane", lane)
            live = status["live"]
            if not (status["running"] or live["session_alive"]
                    or (live["supervisor"] or {}).get("alive")):
                return status
            self.assertLess(time.monotonic(), deadline, "the real lane did not settle")
            time.sleep(0.1)

    def collect_lanes(self):
        # Claims in the release binary outlive this row's temporary state and
        # are keyed by directory inode. Release them before deleting the row's
        # directories, including after a mutant assertion fails. Enumerating
        # recorded lanes avoids stopping a start attempt that never succeeded.
        rows = self.data("state", "lanes", "--config", "headless")
        for row in rows:
            if row["cleaned"]:
                continue
            lane = row["lane"]
            status = self.data("lane", "status", "--config", "headless", "--lane", lane)
            live = status["live"]
            if (live["supervisor"] or {}).get("alive") or live["survivors"]:
                self.call("lane", "stop", "--config", "headless", "--lane", lane)
            elif status["running"]:
                self.call("lane", "check", "--config", "headless", "--lane", lane)
            status = self.settled(lane)
            if status["state"] not in ("merged", "abandoned"):
                self.call("lane", "mark", "--config", "headless", "--lane", lane,
                          "--state", "abandoned")
            self.call("lane", "clean", "--config", "headless", "--lane", lane)

    def send(self, lane, **options):
        return self.call("lane", "send", "--config", "headless", "--lane", lane,
                         "--file", self.message, **options)

    def faults(self, point):
        if not point or self.mutant != point:
            return {}
        return {"LANEBOSS_FAULTS": json.dumps({"point": point, "marker": str(self.marker)})}

    def assert_refused(self, result):
        self.assertEqual(result["code"], 2, "unproven identity was accepted: " + result["stderr"])
        self.assertIn("refused:", result["stderr"])
        self.assertIn("Instead:", result["stderr"])

    def assert_unidentified(self, result):
        """The refusal of a lane start or adoption by a caller that nothing identifies: its first line and both routes."""
        self.assertEqual(result["code"], 2, "an unidentified caller was admitted: " + result["stderr"])
        self.assertEqual(result["stderr"].splitlines()[:1], [UNIDENTIFIED])
        self.assertIn("Instead:", result["stderr"])
        for route in UNIDENTIFIED_ROUTES:
            self.assertIn(route, result["stderr"])

    def test_h1_headless_start(self):
        self.register()
        self.start_lane("start-one")
        started = self.events_for("start-one", "lane.started")
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0]["actor"], "supervisor:top")
        self.assertEqual(self.events_for("start-one", "lane.ended")[0]["payload"]["exit_code"], 0)
        self.assertTrue(list((self.worktree("start-one") / "prompts").glob("*.txt")))

    def test_h2_headless_send(self):
        self.register()
        self.start_lane("send-one")
        self.send("send-one")
        events = self.events_for("send-one", "lane.mailed")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor"], "supervisor:top")
        self.assertEqual(events[0]["payload"]["sender"], "supervisor:top")
        self.assertEqual(events[0]["payload"]["sha256"],
                         hashlib.sha256(self.message.read_bytes()).hexdigest())

    def test_h3_headless_resume(self):
        self.register()
        self.start_lane("resume-one", turns=False)
        self.call("lane", "resume", "--config", "headless", "--lane", "resume-one",
                  "--message", self.message)
        self.settled("resume-one")
        resumed = self.events_for("resume-one", "lane.resumed")
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0]["actor"], "supervisor:top")
        self.assertEqual(resumed[0]["payload"]["run"], 2)
        self.assertEqual(self.events_for("resume-one", "lane.ended")[-1]["payload"]["exit_code"], 0)
        prompts = list((self.worktree("resume-one") / "prompts").glob("*.txt"))
        self.assertEqual(len(prompts), 2)
        self.assertTrue(any(self.message.read_bytes() in path.read_bytes() for path in prompts))

    def test_h4_headless_turn(self):
        self.register()
        self.start_lane("turn-one")
        self.send("turn-one")
        self.call("lane", "turn", "--config", "headless", "--lane", "turn-one")
        self.settled("turn-one")
        resumed = self.events_for("turn-one", "lane.resumed")
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0]["actor"], "supervisor:top")
        self.assertEqual(resumed[0]["payload"]["run"], 2)
        self.assertEqual(self.events_for("turn-one", "lane.ended")[-1]["payload"]["exit_code"], 0)
        prompts = list((self.worktree("turn-one") / "prompts").glob("*.txt"))
        self.assertEqual(len(prompts), 2)
        self.assertTrue(any(self.message.read_bytes() in path.read_bytes() for path in prompts))

    def changed_start_refusal(self, point=""):
        record = self.register()
        self.start_lane("stale-one")
        self.send("stale-one")
        before = self.events()
        path = self.record_path()
        if hasattr(self, "_ticket_fixture"):
            path.parent.mkdir(parents=True, exist_ok=True)
            forged = {**record, "start": "wrong-generation"}
            path.write_text(json.dumps(forged))
            # Writable local state must neither revoke the genuine service
            # identity nor authorize an unrelated process that selects it.
            self.send("stale-one")
            stranger = HeadlessController(self)
            before = self.events()
            rejected = stranger.request(["lane", "send", "--config", "headless", "--lane", "stale-one",
                                         "--file", self.message], environment={"LANEBOSS_SESSION": str(record["pid"])})
            self.assert_refused(rejected)
            self.assertEqual(self.events(), before)
            self.assertEqual(json.loads(path.read_text()), forged)
            return
        original = path.read_bytes()
        record["start"] = str(int(record["start"]) + 1)
        path.write_text(json.dumps(record), encoding="utf-8")
        try:
            result = self.controller.request(
                ["lane", "send", "--config", "headless", "--lane", "stale-one",
                 "--file", self.message], environment=self.faults(point))
        finally:
            path.write_bytes(original)
        if point and self.mutant == point:
            self.assertTrue(self.marker.is_file(), "the start-time mutant never reached its check")
        self.assert_refused(result)
        self.assertEqual(self.events(), before, "the refused caller wrote to the event store")
        self.send("stale-one")
        self.assertEqual(len(self.events_for("stale-one", "lane.mailed")), 2,
                         "restoring the real process start time did not restore membership")

    def test_h5_spoofed_start(self):
        self.changed_start_refusal()

    def test_h6_reused_pid(self):
        # Model PID recycling by changing only the recorded generation (start
        # time) of a live ancestor. The PID and real ancestry remain identical.
        self.changed_start_refusal("caller-session-no-start")

    def test_h7_env_only(self):
        self.register()
        self.start_lane("env-one")
        stranger = HeadlessController(self)
        args = ["lane", "send", "--config", "headless", "--lane", "env-one",
                "--file", self.message]
        self.assert_refused(stranger.request(args, environment={"LANEBOSS_ROLE": "top"}))
        before = self.events()
        environment = {"LANEBOSS_ROLE": "top",
                       "LANEBOSS_SESSION": str(self.controller.process.pid)}
        environment.update(self.faults("caller-session-env"))
        result = stranger.request(args, environment=environment)
        if self.mutant == "caller-session-env":
            self.assertTrue(self.marker.is_file(), "the env-only mutant never reached its check")
        self.assert_refused(result)
        self.assertEqual(self.events(), before, "an unrelated env-named session delivered mail")
        self.send("env-one", environment={"LANEBOSS_SESSION": str(self.controller.process.pid)})
        self.assertEqual(len(self.events_for("env-one", "lane.mailed")), 1)

    def test_h8_adopt_and_commands(self):
        record = self.register()
        worktree = self.worktree("adopt-one")
        session = str(uuid.uuid4())
        source = worktree / ".sessions" / (session + ".jsonl")
        source.parent.mkdir()
        source.write_text(json.dumps({"type": "assistant", "timestamp": "2026-10-12T09:00:00Z",
                                      "cwd": str(worktree), "message": {"content": []}}) + "\n",
                          encoding="utf-8")
        old = time.time() - 3600
        os.utime(source, (old, old))
        path = self.record_path()
        # An old timestamp proves adoption replaced the record through its
        # actual write path instead of merely relying on the original file.
        if not hasattr(self, "_ticket_fixture"):
            os.utime(path, (old, old))
        self.call("lane", "adopt", "--config", "headless", "--lane", "adopt-one",
                  "--session", session, "--runner", "once", "--model", "once-model-1",
                  "--worktree", worktree, "--brief", self.brief, "--role", ROLES[3])
        if hasattr(self, "_ticket_fixture"):
            self.assertFalse(path.exists(), "service-backed adoption wrote a local identity")
            who = self.data("service", "status", "--config", "headless")
            self.assertEqual(who["identity_root"]["pid"], record["pid"])
        else:
            self.assertGreater(path.stat().st_mtime, old)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), record)
        adopted = self.events_for("adopt-one", "lane.adopted")
        self.assertEqual(len(adopted), 1)
        self.assertEqual(adopted[0]["actor"], "supervisor:top")
        self.assertEqual(adopted[0]["payload"]["starter"], "supervisor:top")
        self.call("report", "--config", "headless", "--file", self.message)
        reports = [event for event in self.events() if event["kind"] == "report.sent"]
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["payload"]["from"], "supervisor:top")
        self.assertEqual(reports[0]["payload"]["text"], self.message.read_text(encoding="utf-8"))
        note = {"kind": "test.note", "actor": "supervisor:top", "protocol_version": "1.3.0",
                "payload": {"text": "Headless event canary."}}
        self.call("event", "append", "--config", "headless", "--file", "-", stdin=json.dumps(note))
        notes = [event for event in self.events() if event["kind"] == "test.note"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["actor"], "supervisor:top")
        self.assertEqual(notes[0]["payload"], note["payload"])
        self.call("lane", "attach", "--config", "headless", "--lane", "adopt-one", stdin="/exit\n")
        # Authentication keeps the dashboard's separate human-only rule.
        refused = self.call("dashboard", "--config", "headless", "--port", "0", code=2)
        self.assertIn("resolved to supervisor:top", refused["stderr"])
        self.assertIn("Instead:", refused["stderr"])
        self.send("adopt-one")
        self.call("lane", "turn", "--config", "headless", "--lane", "adopt-one")
        self.settled("adopt-one")
        self.assertEqual(self.events_for("adopt-one", "lane.started")[-1]["actor"], "supervisor:top")
        self.assertEqual(self.events_for("adopt-one", "lane.ended")[-1]["payload"]["exit_code"], 0)
        prompts = list((worktree / "prompts").glob("*.txt"))
        self.assertEqual(len(prompts), 1)
        self.assertIn(self.message.read_bytes(), prompts[0].read_bytes())

    def test_h9_separate_sessions(self):
        first = self.register()
        self.start_lane("sessions-one")
        other = HeadlessController(self)
        second = self.register(other)
        self.assertNotEqual(first["pid"], second["pid"])
        if hasattr(self, "_ticket_fixture"):
            self.assertFalse(self.record_path().exists())
        else:
            self.assertTrue(self.record_path().is_file())
        self.send("sessions-one")
        self.send("sessions-one", controller=other)
        other.close()
        self.assertFalse((Path("/proc") / str(second["pid"])).exists())
        stranger = HeadlessController(self)
        result = stranger.request(
            ["lane", "send", "--config", "headless", "--lane", "sessions-one",
             "--file", self.message], environment={"LANEBOSS_SESSION": str(second["pid"])})
        self.assert_refused(result)
        self.send("sessions-one")
        self.assertEqual(len(self.events_for("sessions-one", "lane.mailed")), 3)

    def test_h10_unknown_commands(self):
        self.register()
        self.start_lane("unknown-mail")
        self.start_lane("unknown-resume", turns=False)
        stranger = HeadlessController(self)
        note = {"kind": "test.note", "actor": "supervisor:top", "protocol_version": "1.3.0",
                "payload": {"text": "An unproven caller must not append this."}}
        commands = [
            (["lane", "send", "--lane", "unknown-mail", "--file", self.message], ""),
            (["lane", "resume", "--lane", "unknown-resume"], ""),
            (["lane", "turn", "--lane", "unknown-mail"], ""),
            (["report", "--file", self.message], ""),
            (["event", "append", "--file", "-"], json.dumps(note)),
            (["lane", "attach", "--lane", "unknown-mail"], "/exit\n"),
            (["dashboard", "--port", "0"], ""),
        ]
        before = self.events()
        for args, stdin in commands:
            with self.subTest(command=args[:2]):
                result = stranger.request([*args, "--config", "headless"], stdin=stdin)
                self.assert_refused(result)
                self.assertEqual(self.events(), before, "an unknown caller changed stored events")

    def test_h11_portable_setting(self):
        self.register(environment={"LANEBOSS_PROCESSES": "portable"})
        self.start_lane("portable-one")
        self.send("portable-one", environment={"LANEBOSS_PROCESSES": "portable"})
        self.send("portable-one")
        self.assertEqual(len(self.events_for("portable-one", "lane.mailed")), 2)

    def test_unknown_event_keeps_empty(self):
        """An unidentified append must leave the doctor's empty state unchanged."""
        # Bootstrap only after the assertions, so normal cleanup has an
        # authenticated caller even when the regression fails on its base.
        self.addCleanup(self.register)
        evidence_root = os.environ.get("LANEBOSS_ROW_EVIDENCE", "")
        if evidence_root:
            evidence = Path(evidence_root) / ("headless-doctor-" + uuid.uuid4().hex)
            self.assertTrue(evidence.is_absolute(), "doctor evidence must be absolute")
            evidence.mkdir(parents=True)
        else:
            evidence = Path(tempfile.mkdtemp(prefix="lb-rl-headless-doctor-"))
        doctor = self.controller.request(["doctor", "--config", "headless"])
        (evidence / "doctor.jsonl").write_text(doctor["stdout"], encoding="utf-8")
        (evidence / "doctor.stderr").write_text(doctor["stderr"], encoding="utf-8")
        (evidence / "doctor-exit.json").write_text(json.dumps({"exit_code": doctor["code"]}), encoding="utf-8")
        print("Headless doctor evidence: " + str(evidence))
        self.assertEqual(doctor["code"], 0, doctor["stdout"] + doctor["stderr"])
        checks = [json.loads(line) for line in doctor["stdout"].splitlines()]
        self.assertTrue(checks, "doctor must emit its actual checks")
        self.assertTrue(all(item["ok"] is True for item in checks), "doctor reported a failed prerequisite")
        self.assertTrue(any(item["check"] == "organisation.tools" for item in checks),
                        "doctor must check the fixture's org tools directory")
        self.assertTrue(self.state.is_dir(), "doctor must prepare the actual state directory")
        before = sorted(path.name for path in self.state.iterdir())
        self.assertNotIn(".lock", before, "a lockable empty state must need no fallback file")
        result = self.controller.request(
            ["event", "append", "--config", "headless", "--file", "-"],
            stdin=json.dumps({"kind": "brief.rendered"}))
        self.assertEqual(result["code"], 2)
        self.assertEqual(result["stderr"].splitlines()[:1], [UNIDENTIFIED])
        self.assertEqual(result["stdout"], "")
        self.assertEqual(sorted(path.name for path in self.state.iterdir()), before,
                         "an unidentified append must not create a fallback lock or any state entry")

    def test_c1_unidentified_start(self):
        """C1: a headless caller that registered nothing starts no lane and adopts none; H1 and H8 are the controls.

        The stranger is a pipe-only session that never ran `start --role`, so no recorded lane, session or ticket
        proves who it is, and it has no terminal. Its start and its adoption must be refused with the identity
        refusal's first line and its Instead route, and must write nothing: no event, no run of the stand-in. Once
        that same session registers itself, the very same start is admitted, so registration stays the headless
        bootstrap. `caller-unidentified-start` admits the stranger: the marker proves that call site was reached, and
        the row then fails at the refusal assertion.
        """
        # The fixture's own session is registered, as in every other row, so that it collects the lanes at the end.
        self.register()
        stranger = HeadlessController(self)
        environment = self.faults("caller-unidentified-start")
        before = self.events()
        lane = "stranger-one"
        worktree = self.worktree(lane)
        start = ["lane", "start", "--config", "headless", "--lane", lane, "--brief", self.brief,
                 "--worktree", worktree, "--runner", "once", "--model", "once-model-1", "--role", ROLES[3]]
        refused = stranger.request(start, environment=environment)
        if self.mutant == "caller-unidentified-start":
            self.assertTrue(self.marker.is_file(), "the unidentified-start mutant never reached its check")
        self.assert_unidentified(refused)
        self.assertEqual(self.events(), before, "the refused caller wrote to the event store")
        self.assertFalse((worktree / "prompts").exists(), "the stand-in ran for a refused start")
        adopted = self.worktree("stranger-adopt")
        session = str(uuid.uuid4())
        source = adopted / ".sessions" / (session + ".jsonl")
        source.parent.mkdir()
        source.write_text(json.dumps({"type": "assistant", "timestamp": "2026-10-12T09:00:00Z",
                                      "cwd": str(adopted), "message": {"content": []}}) + "\n",
                          encoding="utf-8")
        old = time.time() - 3600
        os.utime(source, (old, old))
        refused = stranger.request(
            ["lane", "adopt", "--config", "headless", "--lane", "stranger-adopt", "--session", session,
             "--runner", "once", "--model", "once-model-1", "--worktree", adopted, "--brief", self.brief,
             "--role", ROLES[3]], environment=environment)
        self.assert_unidentified(refused)
        self.assertEqual(self.events(), before, "the refused caller adopted a session")
        # The control: the same session registers itself with `start --role`, which an unidentified caller may do,
        # and the very same start is then admitted and recorded under that supervisor.
        self.register(stranger)
        started = json.loads(self.call(*start, controller=stranger)["stdout"])
        self.assertEqual(started["starter"], "supervisor:top")
        self.settled(lane)
        self.assertEqual(self.events_for(lane, "lane.started")[0]["actor"], "supervisor:top")
        self.assertEqual(self.events_for(lane, "lane.ended")[0]["payload"]["exit_code"], 0)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--runner":
        runner_main(sys.argv[2])
    else:
        unittest.main(verbosity=2)

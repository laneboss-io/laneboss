"""Built-CLI rows HJ1-HJ15 for generated TypeSafe jobs at the org hook.

Run only on the designated disposable Linux machine. The adapter is a stand-in
that reads the real request and a row's random command markers. It proves the
catalog, transport, thresholds and policy ordering, not model accuracy. Hook
inputs never execute their raw shell command. Adapter-covered printf inputs
carry recorded lane markers for the transport and band rows. Natural-command
controls exercise only supported tmux/curl/kill forms; broader unknown-command
behavior belongs to blacklist integration. Tool declarations never restrict calls; the fixture keeps the
runner-launch rule, secret rule and L3 push refusal.
"""

import importlib.util
import concurrent.futures
import json
import os
import sys
from pathlib import Path
import time
import tomllib
import unittest

import test_decision_guide as guide


ADAPTER = r'''import json
import re
import os
from pathlib import Path
import sys
import time

control = json.loads(Path(sys.argv[1]).read_text())
request = json.loads(sys.stdin.readline())
with Path(sys.argv[2]).open("a") as log:
    log.write(json.dumps(request) + "\n")
Path(sys.argv[2]).with_suffix(".pid").write_text(str(os.getpid()))
if request.get("question") == "decision.conflicts":
    if request.get("kind") != "typed" or not request.get("state"):
        raise RuntimeError("the decision request lost its actual state")
    answers, delay = {}, 0
    for identifier, question in request["questions"].items():
        d = re.search(r"decisions\[(\d+)\]", question["instructions"])
        w = re.search(r"texts\[(\d+)\]", question["instructions"])
        if not d or not w or question["type"] != "noul":
            raise RuntimeError("the decision question lost its explicit state references")
        subject = {"decision": request["state"]["decisions"][int(d[1])],
                   "action": request["state"]["texts"][int(w[1])]}
        matched = [rule for rule in control.get("decision_rules", [])
                   if all(marker in subject.get(name, "") for name, marker in rule["contains"].items())]
        if not matched:
            raise RuntimeError("the decision request did not carry the row's markers")
        rule = matched[0]
        delay = max(delay, rule.get("delay_seconds", 0))
        answers[identifier] = {"type": "noul", "noul": rule["probability"]}
    time.sleep(delay)
    print(json.dumps({"model": "jev-1.13.0", "answers": answers,
                      "usage": {"input_tokens": len(json.dumps(request)), "output_tokens": 20 * len(answers)}}))
    sys.exit(0)
if request.get("question") != "laneboss.jobs" or request.get("kind") != "laneboss-jobs":
    raise RuntimeError("the adapter needs the real catalog question")
shell = request["state"]["shell_command"]
criteria = request["questions"]["command"]["criteria"]
if request["questions"]["owned"]["type"] != "noul" or request["questions"]["command"]["type"] != "choice":
    raise RuntimeError("the request lost a TypeSafe question")
if set(criteria) != {row["path"] for row in request["state"]["laneboss_jobs"]} | {"none"}:
    raise RuntimeError("the choices differ from the generated catalog")
ready = Path(sys.argv[2]).with_suffix(".job.json")
temporary = ready.with_suffix(".tmp")
temporary.write_text(json.dumps({"pid": os.getpid(), "shell_command": shell}))
temporary.replace(ready)
time.sleep(control.get("job_delay_seconds", 0))
mode = control.get("mode", "answer")
if mode == "timeout":
    time.sleep(60)
if mode == "fail":
    sys.exit(1)
if mode == "garbage":
    print("an unreadable job answer")
    sys.exit(0)
choice, owned = "none", 0.0
for rule in control.get("rules", []):
    if rule["contains"] in shell:
        choice, owned = rule["command"], rule["owned"]
        break
confidence = control.get("confidence", 0.91)
n = len(criteria)
top = (confidence * (n - 1) + 1) / n
distribution = {name: top if name == choice else (1 - top) / (n - 1) for name in criteria}
response = {"model": "jev-1.13.0", "answers": {
    "owned": {"type": "noul", "noul": owned},
    "command": {"type": "choice", "choice": choice, "probabilities": distribution, "confidence": confidence}},
    "usage": {"input_tokens": len(json.dumps(request)), "output_tokens": 40}}
if mode == "missing-distribution":
    del response["answers"]["command"]["probabilities"]
if mode == "partial":
    del response["answers"]["owned"]
print(json.dumps(response))
'''


def setUpModule():
    guide.setUpModule()


class JobHookBase(guide.GuideBase):
    def setUp(self):
        super().setUp()
        self.judge_path.write_text(ADAPTER)
        self.catalog_file = self.services / "laneboss-jobs.json"
        self.assertTrue(self.catalog_file.is_file(), "the built CLI must render its job catalog")
        for path in (self.laneboss / "shared" / "hooks" / "rules.toml",
                     self.laneboss / "L3" / "hooks" / "rules.toml"):
            data = tomllib.loads(path.read_text())
            kept = [row for row in data["rules"] if row["kind"] != "write-scope"]
            self.assertLess(len(kept), len(data["rules"]), "the fixture must explicitly remove an opaque-command gate")
            lines = ["schema_version = 1"]
            for row in kept:
                lines.append("\n[[rules]]")
                lines.extend(key + " = " + json.dumps(value) for key, value in sorted(row.items()))
            self.write_rule_source(path, "\n".join(lines) + "\n")
        self.cli_json("org", "render", self.org)
        self.guide(judge="guard", jobs=False)
        command, _ = self.bypass()
        baseline = self.shell("claude", command)
        self.assertEqual((baseline["permissionDecision"], baseline["permissionDecisionReason"]),
                         ("allow", guide.PLAIN_ALLOW), "fixture: the bypass input must pass the baseline")
        self.assertNotIn("additionalContext", baseline)
        self.assertEqual(self.asked(), [], "fixture: jobs off must not query the adapter")
        self.guide(judge="guard", jobs=True, jobs_refuse_threshold=0.85)

    def bypass(self):
        if not hasattr(self, "managed_lane"):
            self.managed_lane, _ = self.start_lane(turns=True)
            self.finished(self.managed_lane)
        marker = self.managed_lane
        return "printf '%s' '" + marker + "'", marker

    def real_tmux_bypass(self):
        # A real flag-first form must still match the deterministic raw-task pack.
        _, marker = self.bypass()
        return "tmux -L " + guide.token("hook-socket") + " new-session -d -s " + marker + " 'printf done'", marker

    def score(self, marker, owned, command="lane start", mode="answer"):
        self.control_path.write_text(json.dumps({"mode": mode, "rules": [
            {"contains": marker, "command": command, "owned": owned}]}))

    def job_receipt(self):
        return self.receipts()[-1]["guard"]["jobs"]

    def check_band(self, owned, band):
        command, marker = self.bypass()
        self.score(marker, owned)
        for runner in guide.RUNNERS:
            output = self.shell(runner, command)
            self.assertEqual(output["permissionDecision"], "allow",
                             "HJ band must follow the configured owned score")
            note = self.job_receipt()
            self.assertEqual((note["band"], note["outcome"], note["owned"], note["confidence"]),
                             (band, "answered", owned, 0.91))
            self.assertEqual(note["flagged"], band != "none")
            self.assertEqual(note["laneboss_command"], "lane start" if band != "none" else None)
            if band == "warn":
                self.assertIn("laneboss lane start", output.get("additionalContext", ""),
                              "HJ2 warning must name the generated command")
            else:
                self.assertEqual(output["permissionDecisionReason"], guide.PLAIN_ALLOW)
                self.assertNotIn("additionalContext", output, "HJ3 below warn must add nothing")
            request = self.asked()[-1]
            self.assertEqual(request["state"]["shell_command"], command, "the whole actual call must reach the judge")
            self.assertEqual(request["questions"]["owned"]["type"], "noul")
            self.assertEqual(request["questions"]["command"]["type"], "choice")
            if band != "none":
                purpose = request["questions"]["command"]["criteria"]["lane start"].rstrip(".")
                self.assertIn(purpose, note["reason"], "the recommendation reason must come from the generated catalog")
        egress = self.cli("judge", "egress", "--config", "guide-demo")
        self.assertEqual(egress.returncode, 0, egress.stderr)
        lines = [json.loads(line) for line in egress.stdout.splitlines()]
        self.assertEqual(len([line for line in lines if line["event"] == "sent" and line["question"] == "laneboss.jobs"]), 2)
        self.assertEqual(len([line for line in lines if line["event"] == "outcome" and line["outcome"] == "answered"]), 2)


class JobHookRows(JobHookBase):
    def test_hj1_refuse(self):
        """Fails if the opted-in inclusive high band allows the covered input or omits its route."""
        self.check_band(0.85, "warn")

    def test_hj16_official_shape(self):
        """Incomplete official answers cannot clear a job; uncertain Choice adds no route."""
        command, marker = self.bypass()
        for mode in ("missing-distribution", "partial"):
            self.score(marker, 0.99, mode=mode)
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "allow")
            self.assertEqual(self.job_receipt()["outcome"], "output")
            self.assertIn("no usable", output.get("additionalContext", ""))
        self.score(marker, 0.99)
        control = json.loads(self.control_path.read_text())
        control["confidence"] = 0.2
        self.control_path.write_text(json.dumps(control))
        output = self.shell("claude", command)
        self.assertEqual(output["permissionDecision"], "allow")
        note = self.job_receipt()
        self.assertEqual(note["band"], "uncertain")
        self.assertFalse(note["flagged"])
        self.assertIsNone(note["laneboss_command"])
        self.assertEqual(set(note["probabilities"]), set(self.asked()[-1]["questions"]["command"]["criteria"]))
        self.assertIn("uncertain", output.get("additionalContext", ""))
        self.score(marker, 0.99)
        output = self.shell("claude", command)
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertEqual(self.job_receipt()["band"], "warn")
        self.assertEqual(self.job_receipt()["laneboss_command"], "lane start")

    def test_hj2_warn(self):
        """Fails if the inclusive warning band denies, stays silent or loses the command."""
        self.check_band(0.5, "warn")

    def test_hj3_nothing(self):
        """Fails if a score below warn changes the baseline or adds context."""
        self.check_band(0.49, "none")

    def test_hj4_unrelated_control(self):
        """Fails if an unrelated shell job is flagged or its real request is missing."""
        marker = guide.token("ordinary")
        command = "printf '%s' '" + marker + "'"
        self.score(guide.token("not-in-call"), 0.99)
        for runner in guide.RUNNERS:
            output = self.shell(runner, command)
            self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", guide.PLAIN_ALLOW))
            self.assertNotIn("additionalContext", output)
            note = self.job_receipt()
            self.assertEqual((note["flagged"], note["laneboss_command"], note["reason"], note["owned"]),
                             (False, None, "", 0.0))
            self.assertEqual(self.asked()[-1]["state"]["shell_command"], command)

        command, marker = self.bypass()
        self.score(marker, 0.99, command="none")
        for runner in guide.RUNNERS:
            output = self.shell(runner, command)
            self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", guide.PLAIN_ALLOW),
                             "HJ4 a high owned score with choice none must stay a plain allow")
            self.assertNotIn("additionalContext", output)
            note = self.job_receipt()
            self.assertEqual((note["band"], note["flagged"], note["laneboss_command"], note["owned"], note["managed"]),
                             ("none", False, None, 0.99, True))

    def test_hj5_stale_catalog(self):
        """Fails if changed org/role sources or a stale syntax hash reach the judge;
        rendering fresh sources must restore the high-band refusal."""
        command, marker = self.bypass()
        self.score(marker, 0.95)
        original = self.catalog_file.read_bytes()
        for path in (self.laneboss / "L3" / "roles" / "executor.md", self.laneboss / "org.toml"):
            before = path.read_text()
            path.write_text(before + "\n# catalog source " + guide.token("change") + "\n")
            count = len(self.asked())
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "allow", "HJ5 stale catalog must leave baseline only")
            self.assertIn("Baseline only", output.get("additionalContext", ""))
            self.assertEqual(self.job_receipt()["outcome"], "stale-catalog")
            self.assertEqual(len(self.asked()), count, "HJ5 a stale catalog must ask nobody")
            self.cli_json("org", "render", self.org)
            self.assertNotEqual(self.catalog_file.read_bytes(), original, "render must incorporate changed source hashes")
            self.assertEqual(self.shell("claude", command)["permissionDecision"], "allow", "HJ5 a fresh catalog must restore advisory scoring")
            path.write_text(before)
            self.cli_json("org", "render", self.org)
        catalog = json.loads(original)
        catalog["source"]["sha256"] = guide.token("stale-syntax")
        self.catalog_file.write_text(json.dumps(catalog))
        count = len(self.asked())
        output = self.shell("codex", command)
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn("stale", output.get("additionalContext", ""))
        self.assertEqual(len(self.asked()), count)
        self.catalog_file.write_bytes(original)

    def test_hj6_timeout_is_bounded(self):
        """Fails if a configured 60-second judge defeats the fixed cap, blocks the
        baseline, leaves a leader alive, or loses the timeout outcome."""
        config = self.config_dir / "config.toml"
        source = config.read_text()
        self.assertEqual(source.count("timeout_seconds = 10"), 1)
        config.write_text(source.replace("timeout_seconds = 10", "timeout_seconds = 60"))
        command, marker = self.bypass()
        self.score(marker, 0.95, mode="timeout")
        started = time.monotonic()
        output = self.shell("claude", command)
        elapsed = time.monotonic() - started
        (self.directory / "timeout.json").write_text(json.dumps({"elapsed_seconds": elapsed, "cap_seconds": 10}))
        self.assertGreaterEqual(elapsed, 6, "HJ6 the real slow adapter must reach the timeout with cleanup reserved")
        self.assertLess(elapsed, 15, "HJ6 the hook must return within the timeout and cleanup bound")
        self.assertEqual(output["permissionDecision"], "allow", "HJ6 timeout must leave baseline only")
        self.assertIn("Baseline only", output.get("additionalContext", ""))
        self.assertEqual(self.job_receipt()["outcome"], "timeout")
        pid = int(self.requests_path.with_suffix(".pid").read_text())
        with self.assertRaises(ProcessLookupError, msg="HJ6 the timed-out judge leader must be reaped"):
            os.kill(pid, 0)
        egress = self.cli("judge", "egress", "--config", "guide-demo")
        self.assertEqual(egress.returncode, 0, egress.stderr)
        outcomes = [json.loads(line) for line in egress.stdout.splitlines() if json.loads(line)["event"] == "outcome"]
        self.assertEqual((outcomes[-1]["outcome"], outcomes[-1]["probability"]), ("timeout", None))
        before = len(self.asked())
        output = self.shell("claude", "git push origin topic")
        self.assertEqual(output["permissionDecision"], "deny", "HJ6 a slow judge cannot relax a baseline refusal")
        self.assertEqual(len(self.asked()), before, "HJ6 baseline refusal must skip the slow judge")

    def test_hj7_baseline_holds(self):
        """The acceptance assertion: a baseline denial is identical with jobs
        enabled, and the judge receives no request for a refused call."""
        self.guide(judge="guard", jobs=False)
        baseline = self.shell("claude", "git push origin topic")
        self.assertEqual(baseline["permissionDecision"], "deny")
        self.guide(judge="guard", jobs=True)
        for runner in guide.RUNNERS:
            count = len(self.asked())
            output = self.shell(runner, "git push origin topic")
            self.assertEqual(output["permissionDecision"], "deny", "HJ7 baseline refusal must remain unchanged")
            self.assertEqual(output["permissionDecisionReason"], baseline["permissionDecisionReason"],
                             "HJ7 the baseline refusal must be preserved verbatim")
            self.assertNotIn("additionalContext", output)
            self.assertEqual(len(self.asked()), count, "HJ7 a refused call must never reach the judge")

    def test_hj8_unavailable_judge(self):
        """Fails if an error, malformed response or unknown command is trusted,
        or unavailable=refuse turns missing job scores into a new denial."""
        command, marker = self.bypass()
        self.guide(judge="guard", jobs=True, unavailable="refuse")
        for mode, choice in (("fail", "lane start"), ("garbage", "lane start"), ("answer", "lane made-up")):
            self.score(marker, 0.95, command=choice, mode=mode)
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "allow", "HJ8 judge failure must leave baseline only")
            self.assertIn("Baseline only", output.get("additionalContext", ""))
            self.assertIn(self.job_receipt()["outcome"], ("exit", "output"))
        self.guide(judge="no-such-judge", jobs=True)
        output = self.shell("codex", command)
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertEqual(self.job_receipt()["outcome"], "unavailable")

    def test_hj9_catalog_matches_generator(self):
        """Fails if the built CLI and standalone generator disagree, if source
        hashes are omitted, or a new syntax job needs a hand-maintained list."""
        root = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location("job_catalog_rows", root / "scripts" / "laneboss_jobs.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        generated = json.loads(self.catalog_file.read_text())
        expected = module.state(org=self.org)
        self.assertEqual(generated, expected, "HJ9 renderer must use the same generated catalog as the script")
        for row in generated["laneboss_jobs"]:
            self.assertTrue(row["purpose"].strip(), "HJ9 every generated job needs its CLI purpose: " + row["path"])
        for key in ("sha256", "org_sha256", "roles_sha256", "rows_sha256", "fingerprint"):
            self.assertEqual(len(generated["source"][key]), 64, "HJ9 freshness needs every source hash")
        syntax = json.loads((root / "internal" / "cli" / "syntax.json").read_text())
        name = guide.token("newjob")
        syntax["commands"].append({"name": name, "help": "new fixture job", "commands": [], "args": []})
        copy = self.directory / "syntax-with-new-job.json"
        copy.write_text(json.dumps(syntax))
        new = module.state(syntax_path=copy, org=self.org)
        self.assertIn(name, module.options(new))
        self.assertNotEqual(new["source"]["fingerprint"], expected["source"]["fingerprint"])

    def test_hj10_thresholds_are_shared(self):
        """Fails if job bands use a hard-coded threshold instead of guide.toml."""
        command, marker = self.bypass()
        self.score(marker, 0.6)
        for warn, refuse, expected in ((0.5, 0.85, "warn"), (0.7, 0.9, "none"), (0.4, 0.6, "warn")):
            self.guide(judge="guard", jobs=True, warn_threshold=warn, refuse_threshold=refuse, jobs_refuse_threshold=refuse)
            output = self.shell("claude", command)
            self.assertEqual(self.job_receipt()["band"], expected, "HJ10 one score must move when its configured dial changes")
            self.assertEqual(output["permissionDecision"], "allow")


    def test_hj11_default_is_warn_only(self):
        """Fails if default catalog thresholds block a recorded managed job."""
        command, marker = self.bypass()
        self.score(marker, 0.99)
        for settings in ({}, {"refuse_threshold": 0.85}):
            self.guide(defaults=True, judge="guard", jobs=True, **settings)
            output = self.shell("claude", command)
            self.assertEqual(output["permissionDecision"], "allow", "HJ11 default catalog policy must be warn-only")
            self.assertEqual(self.job_receipt()["band"], "warn")
            self.assertTrue(self.job_receipt()["managed"])
        self.guide(judge="guard", jobs=True, jobs_refuse_threshold=0.85)
        self.assertEqual(self.shell("claude", command)["permissionDecision"], "allow",
                         "HJ11 legacy thresholds cannot grant refusal authority")

    def test_hj12_natural_controls(self):
        """Fails if default high scores refuse unrelated work or lose the warning;
        low scores must allow the same ordinary tmux/git/curl/kill calls silently."""
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(70)"], env=self.env)
        self.addCleanup(lambda: child.communicate(timeout=5))
        self.addCleanup(lambda: child.terminate() if child.poll() is None else None)
        commands = ("tmux list-sessions",
                    "git status", "curl --head https://example.test/health", "kill " + str(child.pid))
        # Catalog advice is tested on the actual L4 instance's baseline. L3's
        # raw-network boundary is preserved and independently pinned by G9.
        self.instance_dir = self.laneboss / "instances" / "L4-stream"
        self.cli_json("org", "render", self.org)
        self.guide(defaults=True, judge="guard", jobs=False)
        for command in commands:
            baseline = self.shell("claude", command)
            self.assertEqual((baseline["permissionDecision"], baseline["permissionDecisionReason"]), ("allow", guide.PLAIN_ALLOW),
                             "HJ12 fixture: natural controls must pass their supervisor baseline")
            self.assertNotIn("additionalContext", baseline)
            self.assertIs(self.receipts()[-1]["inspection_complete"], True,
                          "HJ12 natural controls must be fully inspected")
        self.guide(defaults=True, judge="guard", jobs=True)
        for owned, band in ((0.9, "warn"), (0.1, "none")):
            for command in commands:
                self.score(command, owned, command="lane start")
                for runner in guide.RUNNERS:
                    output = self.shell(runner, command)
                    self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", guide.PLAIN_ALLOW),
                                     "HJ12 natural unrelated shell work must remain allowed")
                    if band == "warn":
                        self.assertIn("laneboss lane start", output.get("additionalContext", ""), "HJ12 defaults must warn rather than block")
                    else:
                        self.assertNotIn("additionalContext", output, "HJ12 low scores must not warn about ordinary work")
                    self.assertEqual((self.job_receipt()["band"], self.job_receipt()["owned"]), (band, owned))
                    self.assertFalse(self.job_receipt()["managed"])
                    self.assertEqual(self.asked()[-1]["state"]["shell_command"], command)
                    self.assertIs(self.receipts()[-1]["inspection_complete"], True,
                                  "HJ12 a natural control must not become an opaque allowance")
        command = "tmux has-session -t " + guide.token("unmanaged")
        self.guide(judge="guard", jobs=True, jobs_refuse_threshold=0.85)
        self.score(command, 0.99)
        output = self.shell("claude", command)
        self.assertEqual(output["permissionDecision"], "allow", "HJ12 even a high score cannot refuse an unrecorded target")
        self.assertFalse(self.job_receipt()["managed"])

    def test_hj13_held_job_lock(self):
        """Fails if job judging's log lock gets a fresh or unbounded deadline."""
        import fcntl
        command, marker = self.bypass()
        self.score(marker, 0.95)
        self.shell("claude", command)
        directory = self.home / ".local" / "state" / "laneboss" / "guide-demo" / "judges"
        fd = os.open(directory, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            output = self.shell("claude", command)
            elapsed = time.monotonic() - started
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertGreater(elapsed, 8)
        self.assertLess(elapsed, 15, "HJ13 job lock wait must fit in its ten-second share of the deadline")
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertEqual(self.job_receipt()["outcome"], "timeout")

    def test_hj14_combined_deadline_and_lock(self):
        """Fails if slow decisions, slow jobs and an actual held directory lock
        renew the guard budget, lose timeout, or outlast the rendered timeout."""
        import fcntl
        command, marker = self.bypass()
        self.score(marker, 0.0)
        self.shell("claude", command)
        decision = self.decide("the combined deadline")
        config = self.config_dir / "config.toml"
        source = config.read_text()
        self.assertEqual(source.count("timeout_seconds = 10"), 1)
        config.write_text(source.replace("timeout_seconds = 10", "timeout_seconds = 60"))
        self.guide(defaults=True, judge="guard", jobs=True)
        self.control_path.write_text(json.dumps({
            "decision_rules": [{"contains": {"decision": decision.marker, "action": marker},
                                "probability": 0.0, "delay_seconds": 24}],
            "rules": [{"contains": marker, "command": "lane start", "owned": 0.95}],
            "job_delay_seconds": 70}))
        started_file = self.requests_path.with_suffix(".job.json")
        started_file.unlink()
        before = len(self.asked())
        directory = self.home / ".local" / "state" / "laneboss" / "guide-demo" / "judges"
        fd = os.open(directory, os.O_RDONLY)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                started = time.monotonic()
                pending = executor.submit(self.shell, "claude", command)
                ready_deadline = started + 27
                while not started_file.exists() and time.monotonic() < ready_deadline and not pending.done():
                    time.sleep(0.02)
                self.assertTrue(started_file.exists(), "HJ14 both actual slow judges must receive the covered input")
                job = json.loads(started_file.read_text())
                self.assertEqual(job["shell_command"], command)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    output = pending.result(timeout=35 - (time.monotonic() - started))
                    elapsed = time.monotonic() - started
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        hook = json.loads((self.instance_dir / ".claude" / "settings.json").read_text())["hooks"]["PreToolUse"][-1]["hooks"][0]
        (self.directory / "combined-deadline.json").write_text(json.dumps({
            "elapsed_seconds": elapsed, "guard_seconds": 30, "rendered_seconds": hook["timeout"],
            "decision_delay_seconds": 24, "job_delay_seconds": 70}))
        self.assertGreater(elapsed, 28, "HJ14 the real held log lock must consume the remaining shared budget")
        self.assertLess(elapsed, 33, "HJ14 serial asks and log locks must not renew the thirty-second deadline")
        self.assertLess(elapsed, hook["timeout"], "HJ14 the runner must receive the timeout response")
        self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]), ("allow", guide.PLAIN_ALLOW))
        self.assertIn("timeout", output.get("additionalContext", ""))
        receipt = self.receipts()[-1]["guard"]
        self.assertEqual(receipt["decisions"][0]["outcome"], "answered")
        self.assertEqual(receipt["jobs"]["outcome"], "timeout")
        asks = self.asked()[before:]
        self.assertEqual([ask["question"] for ask in asks], [guide.CONFLICTS, "laneboss.jobs"])
        self.assertIn(decision.marker, "\n".join(asks[0]["state"]["decisions"]))
        with self.assertRaises(ProcessLookupError, msg="HJ14 the slow job leader must be reaped"):
            os.kill(job["pid"], 0)

    def test_hj15_real_tmux_blacklist(self):
        """The installed raw-task pack refuses real tmux creation before job scoring."""
        command, marker = self.real_tmux_bypass()
        for jobs in (False, True):
            self.guide(defaults=True, judge="guard", jobs=jobs)
            self.score(marker, 0.9)
            for runner in guide.RUNNERS:
                with self.subTest(jobs=jobs, runner=runner):
                    before = len(self.asked())
                    receipt_count = len(self.receipts())
                    output = self.shell(runner, command)
                    self.assertEqual(output["permissionDecision"], "deny",
                                     "HJ15 the raw-task pack must refuse real tmux creation")
                    reason = output["permissionDecisionReason"].splitlines()
                    self.assertEqual(reason[0],
                                     "[raw-tmux-new-session] Refuses: Creating a raw tmux session bypasses lane start.")
                    self.assertEqual(reason[-1], "Instead: laneboss lane start")
                    self.assertNotIn("additionalContext", output)
                    self.assertEqual(len(self.asked()), before, "HJ15 the pack refusal must precede every judge")
                    receipts = self.receipts()
                    self.assertEqual(len(receipts), receipt_count + 1)
                    self.assertEqual((receipts[-1]["runner"], receipts[-1]["decision"]), (runner, "deny"))
                    self.assertNotIn("jobs", receipts[-1].get("guard", {}),
                                     "HJ15 a pack refusal must never carry a job score")


class JobPanicRows(JobHookBase):
    def setUp(self):
        self.binary_override = guide.FAULTS
        self.fault_point = "jobs-batch-panic"
        super().setUp()

    def test_hj17_job_panic_is_advisory(self):
        """A reached catalog panic keeps the baseline and an unscored receipt."""
        command, marker = self.bypass()
        self.score(marker, 0.99)
        self.assertFalse(self.marker.exists(), "HJ17 the panic marker must start absent")
        for runner in guide.RUNNERS:
            output = self.shell(runner, command)
            self.assertTrue(self.marker.is_file(), "HJ17 the real job batch panic must fire")
            self.assertEqual(output["permissionDecision"], "allow", "HJ17 a job panic must not refuse ordinary work")
            self.assertEqual(output["permissionDecisionReason"], guide.PLAIN_ALLOW)
            self.assertIn("Baseline only", output.get("additionalContext", ""))
            note = self.job_receipt()
            self.assertEqual(note["band"], "notice")
            self.assertNotEqual(note["outcome"], "answered")
            self.assertEqual(self.asked(), [], "HJ17 the panic precedes adapter execution")

class JobHookMutant(unittest.TestCase):
    def test_mutant_rejected_release_passes(self):
        mutant = JobHookRows("test_hj7_baseline_holds")
        mutant.binary_override = guide.FAULTS
        mutant.fault_point = "jobs-relax-baseline"
        red = unittest.TestResult()
        mutant.run(red)
        self.assertEqual(red.errors, [], "the mutant must fail the row, not its setup")
        self.assertEqual(len(red.failures), 1, "the baseline row must catch the real mutation")
        self.assertIn("HJ7 baseline refusal must remain unchanged", red.failures[0][1])
        self.assertTrue(mutant.marker.is_file(), "the compiled mutation must reach its real boundary")
        restored = JobHookRows("test_hj7_baseline_holds")
        restored.binary_override = guide.RELEASE
        restored.fault_point = "jobs-relax-baseline"
        green = unittest.TestResult()
        restored.run(green)
        self.assertEqual((green.errors, green.failures), ([], []), "the release must pass the unchanged acceptance row")
        self.assertFalse(restored.marker.exists(), "the mutation must be absent from a release even when requested")
        print("RESTORED JOB MUTANT jobs-relax-baseline caught: HJ7 baseline refusal must remain unchanged")


if __name__ == "__main__":
    unittest.main()

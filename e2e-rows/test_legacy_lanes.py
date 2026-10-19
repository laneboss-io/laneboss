"""Historical-lane communication rows against supplied built CLIs on Linux.

LANEBOSS_BIN is the release CLI. LANEBOSS_FAULTS_BIN is the tagged CLI used
to create historical records through real launcher starts. No direct SQL,
product imports, model requests or builds are used here. See LEGACY-LANES.md
for the negative-before-positive and mutant commands.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen
import uuid

from headless_support import HeadlessController
from test_report_messages import ReportMessageFixture, executable


class LegacyLaneFixture(ReportMessageFixture):
    requires_fault_binary = True
    extra_supervisors = (("root", 6),)

    def advance_probe(self, lane, payload):
        source = self.directory / ("advance-" + lane + ".json")
        source.write_text(json.dumps({"kind": "lane.started", "lane": lane, "actor": "laneboss",
                                      "protocol_version": "1.3.0", "payload": payload}), encoding="utf-8")
        args = ["event", "append", "--config", "rows", "--file", source]
        before = self.events()
        result = self.role("top-a").request(args)
        record = {"plain": result, "path": "blocked"}
        old = "refused: event append may not append launcher-owned lifecycle events"
        if result["code"] == 2 and result["stderr"].splitlines()[:1] == [old]:
            marker = self.directory / (lane + "-base.hit")
            fault = {"point": "event-allow-started", "marker": str(marker)}
            result = self.role("top-a").request(args, binary=str(executable("LANEBOSS_FAULTS_BIN")),
                                                 environment={"LANEBOSS_FAULTS": json.dumps(fault)})
            record.update(path="base-fault", retry=result)
        (self.directory / "append-path.json").write_text(json.dumps(record), encoding="utf-8")
        self.advance_result = result
        self.setup_path = record["path"]
        if record["path"] == "base-fault":
            self.assert_code(result, 0, "the authorized base append seam must run")
            self.assertTrue(marker.is_file(), "the base append marker is missing")
            receipt = json.loads(result["stdout"])
            stored = [event for event in self.events() if event["id"] == receipt["id"]]
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]["payload"], payload)
            return True
        self.assert_code(result, 2, "run-advancing append was accepted")
        self.assertIn("event append may not advance a launcher-recorded lane's run", result["stderr"])
        self.assertIn("Instead: use lane start, resume or turn", result["stderr"])
        self.assertEqual(self.events(), before, "refused run advance changed the store")
        return False

    def historical_lane(self, lane="historical", level=None, once=True):
        """A real launcher start writes historical authority; event append supplies observations."""
        point = "legacy-start-without-starter" if level is None else "legacy-start-with-level"
        marker = self.directory / (lane + "-start-reached")
        fault = {"LANEBOSS_FAULTS": json.dumps({"point": point, "marker": str(marker)})}
        self.start_lane(lane, "root", environment=fault, legacy=True, level=level or 3, once=once)
        self.assertTrue(marker.is_file(), "the tagged historical start was not reached")
        payload = self.lane_events(lane, "lane.started")[0]["payload"]
        self.assertNotIn("starter", payload)
        if level is None:
            self.assertNotIn("level", payload)
            self.assertNotIn("level_source", payload)
        else:
            self.assertEqual(payload["level"], level)
        if once:
            self.wait_idle(lane)
        result = self.cli("config", "path", "rows")
        self.assert_code(result, 0, "locate the historical lane's state")
        paths = json.loads(result["stdout"])
        return Path(paths["state_dir"]) / "lanes" / lane

    def wait_idle(self, lane):
        status = self.await_value(lambda: self.idle_status(lane), "the actual run did not become quiescent")
        self.assertEqual(status["reason"], "exit")
        self.assertEqual(status["live"]["survivors"], 0)
        self.assertEqual(status["live"]["pending_events"], 0)
        self.assertEqual(status["live"]["refused_events"], 0)
        self.assertEqual(status["exit_code"], 0)
        return status

    def run_turn(self, lane, controller, environment=None, mutant=None):
        ready_file = self.worktrees[lane] / "ready.json"
        previous = json.loads(ready_file.read_text(encoding="utf-8"))
        response = controller.request(["lane", "turn", "--config", "rows", "--lane", lane],
                                      environment=environment or {})
        if mutant is not None:
            self.mutation_reached(mutant)
        self.assert_code(response, 0, "the real turn must start")
        self.assertIs(json.loads(response["stdout"])["started"], True)

        def next_prompt():
            current = json.loads(ready_file.read_text(encoding="utf-8"))
            return current if current["prompt_file"] != previous["prompt_file"] else None

        ready = self.await_value(next_prompt, "the resumed runner never received a prompt")
        self.wait_idle(lane)
        data = Path(ready["prompt_file"]).read_bytes()
        resumed = self.lane_events(lane, "lane.resumed")[-1]["payload"]["message"]
        self.assertEqual(data, Path(resumed["path"]).read_bytes())
        self.assertEqual(hashlib.sha256(data).hexdigest(), resumed["sha256"])
        return data

    def mail_snapshot(self, lane):
        result = self.cli("config", "path", "rows")
        self.assert_code(result, 0, "locate the target's mail directory")
        mail = Path(json.loads(result["stdout"])["state_dir"]) / "lanes" / lane / "mail"
        return mail.exists(), {path.name: path.read_bytes() for path in mail.glob("*")}

    def assert_no_run_mail(self, result, lane):
        self.assert_code(result, 2, "an observation without a launcher-made run must not receive mail")
        self.assertEqual(result["stderr"],
                         "refused: lane {} has not run yet, so it takes no mail\n"
                         "Instead: lane adopt the running session, or lane start --turns\n".format(lane))

    def send(self, controller, lane="historical", **options):
        message = self.directory / ("message-" + uuid.uuid4().hex + ".md")
        message.write_text("Legacy delivery canary " + uuid.uuid4().hex + "\n", encoding="utf-8")
        result = controller.request(["lane", "send", "--config", "rows", "--lane", lane,
                                     "--file", message], **options)
        return result, message.read_bytes()

    def assert_delivery(self, result, data, sender, legacy=True):
        self.assert_code(result, 0, "the intended recipient must receive the actual message")
        receipt = json.loads(result["stdout"])
        self.assertEqual(Path(receipt["file"]).read_bytes(), data)
        event = self.lane_events(receipt["lane"], "lane.mailed")[-1]
        self.assertEqual(event["actor"], sender)
        self.assertEqual(event["payload"]["sender"], sender)
        self.assertEqual(event["payload"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(event["payload"]["bytes"], len(data))
        if legacy:
            self.assertIs(event["payload"]["legacy_relationship"], True)
            self.assertIs(receipt["legacy_relationship"], True)
        else:
            self.assertNotIn("legacy_relationship", event["payload"])
            self.assertNotIn("legacy_relationship", receipt)
        return event

    def dashboard_messages(self):
        ready = self.human.request(["dashboard", "--config", "rows", "--port", "0"], background=True)
        address = urlsplit(ready["ready"].strip())
        base = "{}://{}".format(address.scheme, address.netloc)
        token = parse_qs(address.fragment)["t"][0]
        request = Request(base + "/api/messages", headers={"X-Laneboss-Token": token, "Origin": base})
        with urlopen(request, timeout=15) as response:
            self.assertEqual(response.status, 200)
            return json.load(response)


class LegacyLaneRows(LegacyLaneFixture, unittest.TestCase):
    def test_legacy_supervisor_delivery(self):
        self.historical_lane()
        start = self.lane_events("historical", "lane.started")
        result, data = self.send(self.role("mini-a"),
                                 environment=self.faults("legacy-relationship-disabled"))
        self.mutation_reached("legacy-relationship-disabled")
        event = self.assert_delivery(result, data, "supervisor:mini-a")
        # A first sender does not adopt the lane: another local supervisor can still communicate.
        second, second_data = self.send(self.role("top-a"))
        self.assert_delivery(second, second_data, "supervisor:top-a")
        self.assertEqual(self.lane_events("historical", "lane.started"), start)
        status = self.cli("lane", "status", "--config", "rows", "--lane", "historical")
        self.assert_code(status, 0, "the lifecycle reader must accept marked mail")
        self.assertEqual(json.loads(status["stdout"])["mail"]["waiting"], [1, 2])
        view = self.dashboard_messages()
        rows = [row for row in view["agent_agent"] if row["id"] == event["id"]]
        self.assertEqual(len(rows), 1, "the delivered mail must be visible on the dashboard")
        self.assertIs(rows[0]["legacy_relationship"], True)
        self.assertEqual(rows[0]["text"], data.decode("utf-8"))

    def test_legacy_human_delivery(self):
        self.historical_lane()
        result, data = self.send(self.human)
        self.assert_delivery(result, data, "human")
        rows = self.dashboard_messages()["human_agent"]
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["legacy_relationship"], True)

    def test_foreign_configuration_refused(self):
        directory = self.historical_lane()
        config = self.home / "configs" / "other"
        config.mkdir()
        text = (self.config_dir / "config.toml").read_text(encoding="utf-8")
        (config / "config.toml").write_text(text.replace('name = "rows"', 'name = "other"', 1), encoding="utf-8")
        other = HeadlessController(self)
        registered = other.request(["start", "--config", "other", "--role", "top-a"],
                                   environment={"LANEBOSS_CONFIG": "other"})
        self.assert_code(registered, 0, "identify the foreign supervisor in its own configuration")
        before = self.events()
        before_mail = list((directory / "mail").glob("*"))
        result, _ = self.send(other, unset=["LANEBOSS_CONFIG"])
        self.assert_code(result, 2, "a foreign configuration must not gain the legacy fallback")
        self.assertIn("the caller has no recorded identity", result["stderr"])
        self.assertEqual(self.events(), before)
        self.assertEqual(list((directory / "mail").glob("*")), before_mail)

    def test_legacy_turn_delivery(self):
        self.historical_lane()
        result, supervisor_data = self.send(self.role("mini-a"))
        self.assert_delivery(result, supervisor_data, "supervisor:mini-a")
        result, human_data = self.send(self.human)
        self.assert_delivery(result, human_data, "human")
        prompt = self.run_turn("historical", self.role("mini-a"),
                               environment=self.faults("legacy-turn-strict-only"), mutant="legacy-turn-strict-only")
        self.assertIn(supervisor_data, prompt)
        self.assertIn(human_data, prompt)
        self.assertEqual(prompt.count(b"legacy_relationship: true\n\n"), 2)
        delivered = self.lane_events("historical", "lane.delivered")
        self.assertEqual(delivered[-1]["payload"]["sequences"], [1, 2])
        status = self.wait_idle("historical")
        self.assertEqual(status["mail"]["waiting"], [])
        self.assertEqual(status["mail"]["delivered"], 2)

    def test_changed_sender_not_delivered(self):
        self.historical_lane(level=5)
        response, data = self.send(self.role("root"))
        self.assert_delivery(response, data, "supervisor:root")
        config = self.config_dir / "config.toml"
        original = config.read_text(encoding="utf-8")
        changed = original.replace("[supervisors.root]\nlevel = 6\n", "[supervisors.root]\nlevel = 4\n")
        self.assertNotEqual(changed, original, "the sender's configured level must actually change")
        config.write_text(changed, encoding="utf-8")
        before = self.events()
        prompts = sorted(self.worktrees["historical"].glob("prompt-*.txt"))
        result = self.human.request(["lane", "turn", "--config", "rows", "--lane", "historical"],
                                    environment=self.faults("peers-allow-all"))
        self.mutation_reached("peers-allow-all")
        self.assert_code(result, 2, "a queued legacy marker must not authorize a now-refused sender")
        self.assertIn("may not message", result["stderr"])
        self.assertEqual(self.events(), before)
        self.assertEqual(sorted(self.worktrees["historical"].glob("prompt-*.txt")), prompts)
        status = self.wait_idle("historical")
        self.assertEqual(status["run"], 1)
        self.assertEqual(status["mail"]["waiting"], [1])
        config.write_text(original, encoding="utf-8")
        prompt = self.run_turn("historical", self.role("root"))
        self.assertIn(data, prompt)
        self.assertIn(b"legacy_relationship: true\n\n", prompt)

    def test_legacy_cannot_raise_level(self):
        self.historical_lane(once=False)
        brief = self.worktrees["historical"] / "child.md"
        brief.write_text("# Child level control\n", encoding="utf-8")
        directory = self.directory / "child"
        directory.mkdir()
        before = self.events()
        result = self.lane_request("historical", ["lane", "start", "--config", "rows", "--lane", "child",
                                                   "--worktree", directory, "--brief", brief,
                                                   "--runner", "row-runner", "--model", "row-runner-model-1",
                                                   "--role", "supervisor", "--level", "4"])
        self.assert_code(result, 2, "a historical unnumbered lane must not raise its child's level")
        self.assertIn("the lane's level must be below its starter's recorded level", result["stderr"])
        self.assertEqual(self.events(), before)
        self.start_lane("level-control", "root", level=4, once=True)

    def test_lower_or_equal_level_refused(self):
        directory = self.historical_lane(level=5)
        before = self.events()
        for role in ("mini-a", "top-a"):
            with self.subTest(role=role):
                result, _ = self.send(self.role(role))
                self.assert_code(result, 2, "legacy supervisors must be above the lane's recorded level")
                self.assertIn("may not message", result["stderr"])
                self.assertEqual(self.events(), before)
                self.assertFalse((directory / "mail").exists())

    def test_unidentified_or_forged_refused(self):
        directory = self.historical_lane()
        before = self.events()
        message = self.directory / "unidentified.md"
        message.write_text("An unidentified sender must be refused.\n", encoding="utf-8")
        result = self.cli("lane", "send", "--config", "rows", "--lane", "historical", "--file", message)
        self.assert_code(result, 2, "a pipe without a registered parent is unidentified")
        self.assertIn("the caller has no recorded identity", result["stderr"])
        self.assertEqual(self.events(), before)
        result = self.role("mini-a").request(["lane", "send", "--config", "rows", "--lane", "historical",
                                               "--from", "top-a", "--file", message])
        self.assert_code(result, 2, "--from must not impersonate another supervisor")
        self.assertIn("--from must equal the resolved principal ID", result["stderr"])
        self.assertEqual(self.events(), before)
        self.assertFalse((directory / "mail").exists())


class CurrentLaneRows(LegacyLaneFixture, unittest.TestCase):
    requires_fault_binary = False
    fixture_prefix = "lb-s0-provenance-"

    def test_current_relationship_stays_strict(self):
        self.start_lane("current", "mini-a")
        before = self.events()
        result, _ = self.send(self.role("top-a"), "current")
        self.assert_code(result, 2, "a current lane still requires its recorded report line")
        self.assertIn("may not message", result["stderr"])
        self.assertEqual(self.events(), before)
        result, data = self.send(self.role("mini-a"), "current")
        self.assert_delivery(result, data, "supervisor:mini-a", legacy=False)

    def append_observation(self, kind, lane, payload, mutate=False):
        event = {"kind": kind, "lane": lane, "actor": "laneboss",
                 "protocol_version": "1.3.0", "payload": payload}
        source = self.directory / ("observation-" + uuid.uuid4().hex + ".json")
        source.write_text(json.dumps(event), encoding="utf-8")
        result = self.role("top-a").request(
            ["event", "append", "--config", "rows", "--file", source],
            environment=self.faults("event-allow-started") if mutate else {})
        if mutate:
            self.mutation_reached("event-allow-started")
        self.assert_code(result, 0, "authenticated lifecycle projection input must be accepted")
        receipt = json.loads(result["stdout"])
        matches = [event for event in self.events() if event["id"] == receipt["id"]]
        self.assertEqual(len(matches), 1, "the input must be stored exactly once")
        self.assertEqual(matches[0]["payload"], payload, "provenance must not change payload bytes")
        return matches[0]

    def observed_copy(self, source, **changes):
        payload = deepcopy(source)
        payload.update(changes)
        snapshot = payload.get("settings")
        if snapshot is not None and snapshot.get("delegation") is not None:
            # These are claimed observation fields, never launcher authority.
            # Keep the copied settings consistent with the claimed report line.
            if payload.get("starter") is None:
                snapshot.pop("delegation")
            else:
                snapshot["delegation"]["starter"] = payload["starter"]
        return payload

    def observed_lane(self, starter=None, adopted=False, target="observed", level=3, mutate=False):
        if "control" not in self.started_lanes:
            self.start_lane("control", "mini-a", once=True)
            self.wait_idle("control")
        original = self.lane_events("control", "lane.started")[0]
        payload = self.observed_copy(original["payload"], launch=uuid.uuid4().hex, starter=starter, level=level,
                                     level_source="protocol" if level == 3 else "org")
        paths = self.cli("config", "path", "rows")
        self.assert_code(paths, 0, "locate the observation's bound paths")
        directory = Path(json.loads(paths["stdout"])["state_dir"]) / "lanes" / target
        if starter is None:
            payload.pop("starter")
        payload["session"] = dict(payload["session"], name=target)
        payload["brief"] = dict(payload["brief"], path=str(directory / "rendered" /
                                                         (payload["brief"]["sha256"] + ".md")))
        payload["log"] = str(directory / "output.log")
        if adopted:
            for key in ("run", "how", "launch", "mail"):
                payload.pop(key)
            payload["difficulty"] = None
            payload["chosen_by"] = {key: "supervisor" if payload[key] is not None else None
                                    for key in ("runner", "model", "effort", "account")}
        event = self.append_observation("lane.adopted" if adopted else "lane.started", target, payload, mutate=mutate)
        self.assertEqual(event["actor"], "event.append:supervisor:top-a",
                         "the stored lifecycle origin must be external, regardless of the claimed actor")
        return payload, event

    def test_append_grants_no_legacy(self):
        self.start_lane("current", "mini-a", once=True)
        self.wait_idle("current")
        started = self.lane_events("current", "lane.started")[0]
        # Reuse the existing, ended process record so fixture collection can
        # verify the original real runner without manufacturing a run record.
        payload = self.observed_copy(started["payload"], run=2, how="resume", starter=None)
        payload.pop("starter")
        payload["chosen_by"] = {"runner": "previous", "model": "previous", "effort": None, "account": None}
        accepted = self.advance_probe("current", payload)
        self.assertFalse(accepted, "run-advancing append was accepted")
        before = self.events()
        result, _ = self.send(self.role("top-a"), "current")
        self.assert_code(result, 2, "the original current lane must stay strict")
        self.assertIn("may not message", result["stderr"])
        self.assertEqual(self.events(), before)
        result, data = self.send(self.role("mini-a"), "current")
        self.assert_delivery(result, data, "supervisor:mini-a", legacy=False)

        # Keep the origin mutant reachable on a never-launched name.
        self.observed_lane(mutate=True)

    def test_running_stoppable(self):
        worktree = self.start_lane("running", "mini-a")
        ready = json.loads((worktree / "ready.json").read_text(encoding="utf-8"))
        payload = self.observed_copy(self.lane_events("running", "lane.started")[0]["payload"],
                                     run=2, how="resume")
        ended = {"run": 1, "reason": "exit", "exit_code": 0, "signal": None,
                 "duration_seconds": 0, "pattern": None, "classification": None, "survivors": 0}
        gone = {"run": 1, "launch": payload["launch"]}
        writers = (self.human, self.role("mini-b"), self.role("top-a"), self.role("root"))
        for index, writer in enumerate(writers):
            for kind, body in (("lane.ended", ended), ("lane.lost", {"run": 1, "survivors": 0}),
                               ("lane.gone", gone)):
                source = self.directory / ("close-{}-{}.json".format(index, kind))
                source.write_text(json.dumps({"kind": kind, "lane": "running", "actor": "laneboss",
                                              "protocol_version": "1.3.0", "payload": body}), encoding="utf-8")
                before = self.events()
                result = writer.request(["event", "append", "--config", "rows", "--file", source])
                source.with_suffix(".result").write_text(json.dumps(result), encoding="utf-8")
                self.assert_code(result, 2, "run-closing append was accepted")
                self.assertIn("event append may not end a launcher-recorded lane's run", result["stderr"])
                self.assertIn("Instead: use lane stop, or lane check when its supervising process is gone.",
                              result["stderr"])
                self.assertEqual(self.events(), before, "refused close changed the event store")
        accepted = self.advance_probe("running", payload)
        self.assertFalse(accepted, "run-advancing append was accepted")
        stopped = self.human.request(["lane", "stop", "--config", "rows", "--lane", "running"])
        (self.directory / "stop-after-append.json").write_text(json.dumps(stopped), encoding="utf-8")
        self.assert_code(stopped, 0, "the running lane became unstoppable after appends")
        self.assertEqual(json.loads(stopped["stdout"])["survivors"], 0)
        self.await_value(lambda: not (Path("/proc") / str(ready["pid"])).exists(),
                         "the actual runner survived the stop")

    def test_lane_life_refused(self):
        self.start_lane("sender", "mini-a")
        self.start_lane("victim", "mini-b")
        ended = {"run": 1, "reason": "exit", "exit_code": 0, "signal": None,
                 "duration_seconds": 0, "pattern": None, "classification": None, "survivors": 0}
        for target in ("sender", "victim"):
            started = dict(self.lane_events(target, "lane.started")[0]["payload"], run=2, how="resume")
            # The harmless planned input makes the old permission failure
            # observable without corrupting the base fixture's running life.
            for kind, payload in (("lane.planned", {}), ("lane.ended", ended), ("lane.started", started)):
                source = self.directory / (target + "-" + kind + ".json")
                source.write_text(json.dumps({"kind": kind, "lane": target, "actor": "laneboss",
                                              "protocol_version": "1.3.0", "payload": payload}), encoding="utf-8")
                before = self.events()
                result = self.lane_request("sender", ["event", "append", "--config", "rows", "--file", "-"],
                                           stdin=source.read_text(encoding="utf-8"))
                source.with_suffix(".result").write_text(json.dumps(result), encoding="utf-8")
                self.assert_code(result, 2, "an L3 lane appended lifecycle input")
                self.assertIn("lifecycle append requires", result["stderr"])
                self.assertIn("Instead: report up with laneboss report", result["stderr"])
                self.assertEqual(self.events(), before, "refused lane append changed the event store")
                status = self.human.request(["lane", "status", "--config", "rows", "--lane", target])
                self.assert_code(status, 0, "read the unchanged live lane")
                self.assertIs(json.loads(status["stdout"])["running"], True)
        stopped = self.human.request(["lane", "stop", "--config", "rows", "--lane", "sender"])
        (self.directory / "stop-control.json").write_text(json.dumps(stopped), encoding="utf-8")
        self.assert_code(stopped, 0, "refused lifecycle input must not prevent the human's real stop")
        self.assertEqual(json.loads(stopped["stdout"])["survivors"], 0)

    def test_supervisor_life_append(self):
        worktree = self.start_lane("control", "mini-a", once=True)
        self.wait_idle("control")
        for name in ("mini-a", "top-a", "root"):
            source = self.directory / (name + "-life.json")
            source.write_text(json.dumps({"kind": "lane.state", "lane": "control", "actor": "laneboss",
                                          "protocol_version": "1.3.0", "payload": {"state": "abandoned"}}),
                              encoding="utf-8")
            result = self.role(name).request(["event", "append", "--config", "rows", "--file", source])
            source.with_suffix(".result").write_text(json.dumps(result), encoding="utf-8")
            self.assert_code(result, 0, "a configured supervisor lost lifecycle append")
            receipt = json.loads(result["stdout"])
            stored = [event for event in self.events() if event["id"] == receipt["id"]]
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]["actor"], "event.append:supervisor:" + name)
            self.assertEqual(stored[0]["payload"], {"state": "abandoned"})
        # The appended states are observations: lane clean still sees the launcher's waiting lane.
        before = self.events()
        result = self.human.request(["lane", "clean", "--config", "rows", "--lane", "control"])
        self.assert_code(result, 2, "an appended abandoned state authorized lane clean")
        self.assertIn("lane control is waiting", result["stderr"])
        self.assertEqual(self.events(), before, "a refused clean changed the store")
        self.assertTrue(worktree.is_dir(), "a refused clean removed the worktree")
        result = self.human.request(["lane", "mark", "--config", "rows", "--lane", "control", "--state", "abandoned"])
        self.assert_code(result, 0, "record the actual lane's collection decision")

    def test_append_grants_no_identity(self):
        self.observed_lane()
        controller = HeadlessController(self)
        message = self.directory / "identity-canary.md"
        message.write_text("An observation must not identify this process.\n", encoding="utf-8")
        before = self.events()
        result = controller.request(["lane", "send", "--config", "rows", "--lane", "control", "--file", message],
                                    environment={"LANEBOSS_LANE": "observed"})
        self.assert_code(result, 2, "an appended start must not identify an unrelated process")
        self.assertIn("LANEBOSS_LANE disagrees with the caller's recorded lane identity", result["stderr"])
        self.assertEqual(self.events(), before)
        # The same authenticated sender can still address its real lane.
        result, data = self.send(self.role("mini-a"), "control")
        self.assert_delivery(result, data, "supervisor:mini-a", legacy=False)

    def test_append_grants_no_ancestry(self):
        self.start_lane("parent", "top-a", level=4)
        self.observed_lane(starter="lane:parent")
        before = self.events()
        result = self.lane_request("parent", ["lane", "archive", "--config", "rows",
                                               "--lane", "observed", "--dry-run"])
        self.assert_code(result, 2, "a forged starter must not authorize descendant collection")
        self.assertIn("the target lane has no recorded start or adoption", result["stderr"])
        self.assertEqual(self.events(), before)
        # A live, genuinely recorded L4 parent remains able to start an L3 child.
        worktree = self.directory / "real-child"
        worktree.mkdir()
        (worktree / "once").write_text("Read the prompt and exit.\n", encoding="utf-8")
        brief = self.directory / "real-child.md"
        brief.write_text("Read the real child control.\n", encoding="utf-8")
        result = self.lane_request("parent", ["lane", "start", "--config", "rows", "--lane", "real-child",
                                               "--worktree", worktree, "--brief", brief, "--runner", "row-runner",
                                               "--model", "row-runner-model-1", "--turns", "--role", "executor",
                                               "--level", "3"])
        self.assert_code(result, 0, "the real L4 parent must still launch its actual child")
        self.started_lanes.append("real-child")
        self.worktrees["real-child"] = worktree
        self.wait_idle("real-child")
        child = self.lane_events("real-child", "lane.started")[0]["payload"]
        self.assertEqual(child["starter"], "lane:parent")

    def test_append_grants_no_reuse(self):
        payload, _ = self.observed_lane()
        ended = dict(self.lane_events("control", "lane.ended")[0]["payload"])
        self.append_observation("lane.ended", "observed", ended)
        self.append_observation("lane.state", "observed", {"state": "abandoned"})
        worktree = self.directory / "reuse-target"
        worktree.mkdir()
        brief = self.directory / "reuse-target.md"
        brief.write_text("This runner must not start from an external life.\n", encoding="utf-8")
        before = self.events()
        result = self.human.request(["lane", "start", "--config", "rows", "--lane", "observed", "--reuse",
                                     "--worktree", worktree, "--brief", brief, "--runner", "row-runner",
                                     "--model", "row-runner-model-1", "--role", "executor", "--level", "3"])
        self.assert_code(result, 2, "an external start must not authorize reuse, even for the human")
        self.assertIn("no launcher-recorded life", result["stderr"])
        self.assertEqual(self.events(), before)
        self.assertFalse((worktree / "ready.json").exists())
        self.assertNotEqual(payload["launch"], self.lane_events("control", "lane.started")[0]["payload"]["launch"])

    def test_human_external_target(self):
        self.observed_lane(adopted=True, level=6)
        self.start_lane("sender", "mini-a")
        result = self.human.request(["lane", "turn", "--config", "rows", "--lane", "observed"])
        self.assert_code(result, 0, "the human may inspect an external adoption's empty turn")
        self.assertEqual(json.loads(result["stdout"])["reason"], "no mail")
        message = self.directory / "external-target.md"
        message.write_text("External target legacy-decision canary.\n", encoding="utf-8")
        for controller in (self.role("mini-a"), self.role("top-a")):
            before = self.events()
            before_mail = self.mail_snapshot("observed")
            result = controller.request(["lane", "send", "--config", "rows", "--lane", "observed", "--file", message])
            self.assert_no_run_mail(result, "observed")
            self.assertEqual(self.events(), before)
            self.assertEqual(self.mail_snapshot("observed"), before_mail)
        for target, starter, level in (("observed", None, 6), ("claimed-peer", "supervisor:mini-a", 3),
                                       ("claimed-parent", "lane:sender", 6)):
            if starter is not None:
                self.observed_lane(starter=starter, adopted=True, target=target, level=level)
            before = self.events()
            before_mail = self.mail_snapshot(target)
            result = self.lane_request("sender", ["lane", "send", "--config", "rows", "--lane", target,
                                                   "--file", message])
            self.assert_code(result, 2, "a forged starter or level must not grant L3 delivery")
            self.assertIn("may not message", result["stderr"])
            self.assertEqual(self.events(), before)
            self.assertEqual(self.mail_snapshot(target), before_mail)

        # A launcher-made target keeps the permission boundary observable even
        # when a no-run mail gate would also reject the external targets.
        self.start_lane("unrelated", "mini-b", once=True)
        self.wait_idle("unrelated")
        before = self.events()
        before_mail = self.mail_snapshot("unrelated")
        result = self.lane_request("sender", ["lane", "send", "--config", "rows", "--lane", "unrelated",
                                               "--file", message])
        self.assert_code(result, 2, "the same L3 sender must not message another supervisor's real lane")
        self.assertIn("may not message", result["stderr"])
        self.assertEqual(self.events(), before)
        self.assertEqual(self.mail_snapshot("unrelated"), before_mail)

        before = self.events()
        before_mail = self.mail_snapshot("observed")
        result = self.human.request(["lane", "send", "--config", "rows", "--lane", "observed", "--file", message])
        self.assert_no_run_mail(result, "observed")
        self.assertEqual(self.events(), before)
        self.assertEqual(self.mail_snapshot("observed"), before_mail)

    def dashboard_events(self):
        ready = self.human.request(["dashboard", "--config", "rows", "--port", "0"], background=True)
        address = urlsplit(ready["ready"].strip())
        base = "{}://{}".format(address.scheme, address.netloc)
        token = parse_qs(address.fragment)["t"][0]
        request = Request(base + "/api/events?lane=control&limit=1000",
                          headers={"X-Laneboss-Token": token, "Origin": base})
        with urlopen(request, timeout=15) as response:
            self.assertEqual(response.status, 200)
            return json.load(response)

    def test_dashboard_marks_external(self):
        self.start_lane("control", "mini-a", once=True)
        self.wait_idle("control")
        # lane.state was already appendable on the release head. The named
        # regression is its missing origin mark, independent of the start gate.
        event = self.append_observation("lane.state", "control", {"state": "abandoned"})
        events = self.dashboard_events()
        rows = [row for row in events if row["id"] == event["id"]]
        self.assertEqual(len(rows), 1, "the dashboard must retain the observation")
        self.assertIs(rows[0].get("externally_appended"), True,
                      "dashboard is missing the external lifecycle mark on an appendable lane.state")
        self.assertIn("Externally appended lifecycle event", rows[0]["summary"])
        genuine = [row for row in events if row["id"] == self.lane_events("control", "lane.started")[0]["id"]]
        self.assertEqual(len(genuine), 1)
        self.assertFalse(genuine[0].get("externally_appended", False))
        result = self.human.request(["lane", "mark", "--config", "rows", "--lane", "control", "--state", "abandoned"])
        self.assert_code(result, 0, "record the actual lane's collection decision")

    def test_ledger_marks_external(self):
        self.start_lane("control", "mini-a", once=True)
        self.wait_idle("control")
        event = self.append_observation("lane.state", "control", {"state": "abandoned"})
        result = self.human.request(["ledger", "--config", "rows", "--lane", "control", "--format", "json"])
        self.assert_code(result, 0, "read the actual employee ledger")
        ledger = json.loads(result["stdout"])
        marked = [row for row in ledger["rows"] if row.get("event") == event["seq"]]
        self.assertEqual(len(marked), 1,
                         "ledger is missing the external lifecycle mark on an appendable lane.state")
        self.assertIs(marked[0].get("externally_appended"), True)
        self.assertEqual(marked[0]["kind"], "external_lifecycle")
        self.assertEqual(marked[0]["action"], "lane.state")
        self.assertEqual(ledger["summary"]["tasks_done"], 1)
        result = self.human.request(["ledger", "--config", "rows", "--lane", "control", "--format", "text"])
        self.assert_code(result, 0, "read the human ledger view")
        self.assertIn("Externally appended lifecycle event", result["stdout"])
        self.assertIn("externally_appended=true", result["stdout"])
        result = self.human.request(["lane", "mark", "--config", "rows", "--lane", "control", "--state", "abandoned"])
        self.assert_code(result, 0, "record the actual lane's collection decision")


class LifeRows(LegacyLaneFixture, unittest.TestCase):
    requires_fault_binary = False
    fixture_prefix = "lb-s0-provenance-life-"

    def git(self, *arguments, cwd=None, code=0):
        result = subprocess.run(["git", "-C", str(cwd or self.repo), *map(str, arguments)],
                                env=self.environment, capture_output=True, text=True, timeout=30)
        if code is not None:
            self.assertEqual(result.returncode, code, "Git setup/read failed: " + result.stderr)
        return result

    def save_result(self, name, value):
        (self.directory / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")

    def make_life(self):
        self.repo = self.directory / "life-repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("-c", "user.name=fixture", "-c", "user.email=fixture", "-c", "commit.gpgsign=false",
                 "commit", "-q", "--allow-empty", "-m", "bootstrap")
        self.capture = self.directory / "runner.json"
        helper = self.directory / "life-runner.py"
        helper.write_text("import json, pathlib, sys\n"
                          "data = sys.stdin.buffer.read()\n"
                          "target = pathlib.Path(sys.argv[1])\n"
                          "target.with_suffix('.bin').write_bytes(data)\n"
                          "seen = dict(worktree=str(pathlib.Path.cwd()), session=sys.argv[2], size=len(data))\n"
                          "target.write_text(json.dumps(seen))\n"
                          "print('run', sys.argv[2], flush=True)\n"
                          "print('read', len(data), 'bytes', flush=True)\n", encoding="utf-8")
        command = [sys.executable, "-I", str(helper), str(self.capture), "{session}", "{brief}"]
        configuration = self.config_dir / "config.toml"
        configuration.write_text(configuration.read_text(encoding="utf-8") +
                                 "\n[runners.life-runner]\ncommand = " + json.dumps(command) +
                                 "\nresume = " + json.dumps(command) + '\nprompt = "stdin"\n'
                                 'records = [{format = "text", paths = ["{log}"]}]\n', encoding="utf-8")
        projects = self.config_dir / "projects"
        projects.mkdir(exist_ok=True)
        (projects / "life.toml").write_text(
            'schema_version = 1\nname = "life"\nrepository = ' + json.dumps(str(self.repo)) +
            '\nworkers = ["life-runner"]\nlanding_authority = "top-a"\n', encoding="utf-8")
        self.brief = self.directory / "proof.md"
        self.brief.write_text("Read the recorded-life probe.\n", encoding="utf-8")
        result = self.human.request(["lane", "start", "--config", "rows", "--project", "life", "--lane", "proof",
                                     "--brief", self.brief, "--runner", "life-runner", "--model", "life-model-1",
                                     "--role", "executor", "--level", "3"])
        self.save_result("real-start", result)
        self.assert_code(result, 0, "start the genuine first life")
        self.actual = json.loads(result["stdout"])
        self.original = Path(self.actual["worktree"])
        self.wait_idle("proof")
        self.assertIn(b"Read the recorded-life probe.", self.capture.with_suffix(".bin").read_bytes())
        self.initial = self.capture.read_bytes()
        self.started = self.lane_events("proof", "lane.started")[0]
        self.assertEqual(json.loads(self.initial)["worktree"], str(self.original))

    def claim_path(self, worktree):
        registry = self.started["payload"]["claims"]
        if registry is None:
            result = self.git("rev-parse", "--absolute-git-dir", cwd=worktree)
            return Path(result.stdout.strip()) / "laneboss-claim"
        info = worktree.stat()
        return Path(registry) / ("{}-{}.json".format(info.st_dev, info.st_ino))

    def append_run(self, payload):
        return self.advance_probe("proof", payload)

    def forged_life(self):
        self.make_life()
        self.spare = self.directory / "proof-spare"
        self.git("worktree", "add", "-b", "proof-spare", self.spare, "HEAD")
        self.spare_head = self.git("rev-parse", "refs/heads/proof-spare").stdout.strip()
        # Both worktrees belong to the fixture. A matching historical claim
        # ensures the foreign-claim gate cannot mask a life-selection error.
        claim = json.loads(self.claim_path(self.original).read_text(encoding="utf-8"))
        self.assertEqual((claim["config"], claim["lane"]), ("rows", "proof"))
        path = self.claim_path(self.spare)
        path.write_text(json.dumps(dict(claim, path=str(self.spare))), encoding="utf-8")
        path.chmod(0o600)
        self.forged = dict(self.started["payload"], run=2, how="resume", worktree=str(self.spare),
                           branch="proof-spare", session_id=str(uuid.uuid4()))
        if not self.append_run(self.forged):
            self.before = self.events()
            return False
        # The base also refuses hand-appended ends. Reconcile the actual dead
        # recorded supervisor through the real CLI, then append the decision.
        result = self.human.request(["lane", "check", "--config", "rows", "--lane", "proof"])
        self.save_result("reconciled", result)
        self.assert_code(result, 0, "settle the observed run through lane check")
        source = self.directory / "abandoned.json"
        source.write_text(json.dumps({"kind": "lane.state", "lane": "proof", "actor": "laneboss",
                                      "protocol_version": self.started["protocol_version"],
                                      "payload": {"state": "abandoned"}}), encoding="utf-8")
        result = self.role("top-a").request(["event", "append", "--config", "rows", "--file", source])
        self.save_result("appended-state", result)
        self.assert_code(result, 0, "append the same abandoned decision on both trees")
        result = self.human.request(["lane", "status", "--config", "rows", "--lane", "proof"])
        self.assert_code(result, 0, "read the actual reconciled observation")
        row = json.loads(result["stdout"])
        self.assertEqual((row["run"], row["worktree"], row["state"], row["running"]),
                         (2, str(self.spare), "abandoned", False))
        self.before = self.events()
        return True

    def snapshot(self, result):
        branch = self.git("rev-parse", "--verify", "refs/heads/proof-spare", code=None)
        state = {"result": result, "setup_path": self.setup_path,
                 "worktree_exists": self.spare.is_dir(), "branch_code": branch.returncode,
                 "branch_head": branch.stdout.strip(), "branch_error": branch.stderr,
                 "runner": json.loads(self.capture.read_text(encoding="utf-8"))}
        self.save_result("after-operation", state)
        return state

    def preserved(self, name, result):
        state = self.snapshot(result)
        self.assertTrue(state["worktree_exists"], name + " removed the appended worktree")
        self.assertEqual(state["branch_code"], 0, name + " removed the appended branch")
        self.assertEqual(state["branch_head"], self.spare_head, name + " changed the appended branch")
        self.assertEqual(self.capture.read_bytes(), self.initial, name + " used the appended session or worktree")
        self.assert_code(result, 2, name + " granted authority from appended events")
        self.assertTrue(result["stderr"].strip(), name + " refused without a clear diagnostic")
        self.assertEqual(self.events(), self.before, name + " changed state despite the authority refusal")

    def test_clean_blocks_forgery(self):
        if not self.forged_life():
            self.preserved("append", self.advance_result)
            return
        result = self.human.request(["lane", "clean", "--config", "rows", "--lane", "proof"])
        self.preserved("clean", result)

    def test_archive_blocks_forgery(self):
        if not self.forged_life():
            self.preserved("append", self.advance_result)
            return
        result = self.human.request(["lane", "archive", "--config", "rows", "--lane", "proof"])
        self.preserved("archive", result)

    def test_reuse_blocks_forgery(self):
        if not self.forged_life():
            self.preserved("append", self.advance_result)
            return
        result = self.human.request(["lane", "start", "--config", "rows", "--lane", "proof", "--reuse",
                                     "--worktree", self.spare, "--brief", self.brief, "--runner", "life-runner",
                                     "--model", "life-model-1", "--role", "executor", "--level", "3"])
        self.save_result("operation", result)
        if result["code"] == 0:
            self.wait_idle("proof")
        self.preserved("reuse", result)

    def test_resume_blocks_forgery(self):
        if not self.forged_life():
            self.preserved("append", self.advance_result)
            return
        result = self.human.request(["lane", "resume", "--config", "rows", "--lane", "proof"])
        self.save_result("operation", result)
        if result["code"] == 0:
            self.wait_idle("proof")
        self.preserved("resume", result)

    def test_clean_launcher_control(self):
        self.make_life()
        paths = self.cli("config", "path", "rows")
        self.assert_code(paths, 0, "locate the retained lane records")
        lane_dir = Path(json.loads(paths["stdout"])["state_dir"]) / "lanes" / "proof"
        saved_log = (lane_dir / "output.log").read_bytes()
        result = self.human.request(["lane", "mark", "--config", "rows", "--lane", "proof", "--state", "merged"])
        self.assert_code(result, 0, "the launcher must record the actual collection decision")
        result = self.human.request(["lane", "clean", "--config", "rows", "--lane", "proof"])
        self.save_result("clean-control", result)
        self.assert_code(result, 0, "launcher-made events must authorize normal clean")
        receipt = json.loads(result["stdout"])
        self.assertIs(receipt["verified"], True)
        self.assertFalse(self.original.exists(), "authorized clean kept its own worktree")
        branch = self.git("show-ref", "--verify", "--quiet", "refs/heads/proof", code=None)
        self.assertEqual(branch.returncode, 1, "authorized clean kept its own branch")
        for field in ("archive", "manifest", "receipt"):
            self.assertTrue(Path(receipt[field]).is_file(), "authorized clean lost its " + field)
        with tarfile.open(receipt["archive"], "r") as archive:
            member = archive.extractfile("lane/output.log")
            self.assertIsNotNone(member, "authorized clean did not archive its recorded output")
            with member:
                self.assertEqual(member.read(), saved_log, "archival changed the real runner's output bytes")
        self.assertTrue(lane_dir.is_dir(), "authorized clean lost the lane record")
        verified = self.human.request(["state", "verify", "--config", "rows"])
        self.assert_code(verified, 0, "verify the real cleaned store")
        self.assertIs(json.loads(verified["stdout"])["ok"], True)

    def test_diverged_recovery(self):
        if self.forged_life():
            result = self.human.request(["lane", "resume", "--config", "rows", "--lane", "proof"])
            if result["code"] == 0:
                self.wait_idle("proof")
            self.preserved("resume", result)
        else:
            self.preserved("append", self.advance_result)
        result = self.human.request(["lane", "mark", "--config", "rows", "--lane", "proof", "--state", "abandoned"])
        self.save_result("recovery-mark", result)
        self.assert_code(result, 0, "the human must be able to abandon the divergent lane")
        decision = json.loads(result["stdout"])
        self.assertEqual((decision["kind"], decision["state"]), ("lane.state", "abandoned"))
        result = self.human.request(["lane", "start", "--config", "rows", "--project", "life", "--lane", "proof-next",
                                     "--brief", self.brief, "--runner", "life-runner", "--model", "life-model-1",
                                     "--role", "executor", "--level", "3"])
        self.save_result("recovery-start", result)
        self.assert_code(result, 0, "the human's recovery must start work under a new name")
        self.wait_idle("proof-next")
        actual = self.lane_events("proof-next", "lane.started")[0]["payload"]
        captured = json.loads(self.capture.read_text(encoding="utf-8"))
        self.assertEqual(actual["run"], 1)
        self.assertEqual((captured["worktree"], captured["session"]), (actual["worktree"], actual["session_id"]))
        self.assertNotEqual(captured["worktree"], str(self.spare))
        self.assertNotEqual(captured["session"], self.forged["session_id"])
        self.assertTrue(self.spare.is_dir(), "recovery removed the appended worktree")
        self.assertEqual(self.git("rev-parse", "refs/heads/proof-spare").stdout.strip(), self.spare_head)
        result = self.human.request(["lane", "mark", "--config", "rows", "--lane", "proof-next", "--state", "abandoned"])
        self.assert_code(result, 0, "abandon the real recovery control")
        result = self.human.request(["lane", "clean", "--config", "rows", "--lane", "proof-next"])
        self.save_result("recovery-clean", result)
        self.assert_code(result, 0, "collect the real recovery control")
        verified = self.human.request(["state", "verify", "--config", "rows"])
        self.assert_code(verified, 0, "verify the actual recovered store")
        self.assertIs(json.loads(verified["stdout"])["ok"], True)


class LegacyReportRows(LegacyLaneFixture, unittest.TestCase):
    requires_fault_binary = True

    def test_legacy_reports_reach_supervisors(self):
        self.write_config(file_channel=True)
        marker = self.directory / "historical-start-reached"
        fault = {"LANEBOSS_FAULTS": json.dumps({"point": "legacy-start-without-starter", "marker": str(marker)})}
        self.start_lane("reporter", "mini-a", environment=fault, legacy=True)
        self.assertTrue(marker.is_file(), "the historical start must reach its tagged fixture point")
        report = self.worktrees["reporter"] / "report.md"
        text = "Historical report canary " + uuid.uuid4().hex
        report.write_text(text, encoding="utf-8")
        result = self.lane_request("reporter", ["report", "--config", "rows", "--file", report])
        self.assert_code(result, 0, "legacy reports must reach every configuration supervisor")
        outcomes = [json.loads(line) for line in result["stdout"].splitlines()]
        expected = {"supervisor:mini-a", "supervisor:mini-b", "supervisor:top-a", "supervisor:root"}
        self.assertEqual({outcome["to"] for outcome in outcomes}, expected)
        self.assertEqual(len(outcomes), 4 * len(expected))
        for outcome in outcomes:
            self.assertIs(outcome["legacy_relationship"], True)
            self.assertEqual(outcome["status"], "delivered" if outcome["channel"] in ("dashboard", "file") else "skipped")
        sent = [event for event in self.events() if event["kind"] == "report.sent"]
        self.assertEqual(len(sent), len(expected))
        self.assertEqual({event["payload"]["to"] for event in sent}, expected)
        for event in sent:
            self.assertEqual(event["actor"], "lane:reporter")
            self.assertEqual(event["payload"]["text"], text)
            self.assertIs(event["payload"]["legacy_relationship"], True)
        delivered = [event["payload"] for event in self.events() if event["kind"] == "report.delivered"]
        self.assertEqual(delivered, outcomes, "stored channel outcomes must match the actual CLI output")
        kept = [json.loads(line) for line in (self.config_dir / "owner" / "queue.jsonl").read_text().splitlines()]
        self.assertEqual(kept, [event["payload"] for event in sent])
        self.assertEqual({item["to"] for item in kept}, expected)
        self.assertTrue(all(item["text"] == text and item["legacy_relationship"] is True for item in kept))
        rows = self.dashboard_messages()["agent_agent"]
        reports = [row for row in rows if row["kind"] == "report.sent"]
        self.assertEqual({row["to"] for row in reports}, expected)
        self.assertTrue(all(row["text"] == text and row["legacy_relationship"] is True for row in reports))


if __name__ == "__main__":
    unittest.main()

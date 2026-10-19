#!/usr/bin/env python3
"""Linux-only unit controls for the case consumer, never live acceptance."""

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

import run as case_module
import probe as probe_module


def stream_fixture():
    request = {"life_id": "life-a", "run": 2, "since": 2, "until": "lane.ended"}
    first = {"schema": 2, "config": "demo", "life_id": "life-a", "run": 2,
             "seq": 3, "kind": "lane.resumed", "origin": "service"}
    end = dict(first, seq=4, kind="lane.ended")
    page = {"events": [first], "cursor": "snapshot", "complete": True}
    frames = [{"request_id": "request-a", "index": 1, "cursor": "event", "event": end, "end": False},
              {"request_id": "request-a", "index": 2, "cursor": "end", "end": True}]
    return request, page, frames


def stream_bytes(page, frames):
    # The initial result can be multiline; StreamFrames are separate JSON values.
    return (json.dumps(page, indent=2) + "\n" + "\n".join(json.dumps(frame) for frame in frames)).encode()


class CaseContractTests(unittest.TestCase):
    def case_fixture(self, directory, phase="candidate", mutation=""):
        root = Path(directory)
        os.chmod(root, 0o700)
        context = {"test_root": str(root), "evidence_root": str(root / "evidence"), "config": "demo",
                   "binary": "/test/artifacts/laneboss", "binding_file": "/test/bindings/demo.json",
                   "phase": phase, "mutation_id": mutation}
        return case_module.Case(context, root / "result.json")

    def test_quota_terminal_shapes(self):
        for subtype in [None, "success", "error_during_execution"]:
            record = {"type": "result", "is_error": True, "session_id": "session-a",
                      "result": "You've hit your session limit · resets 9pm (UTC)"}
            if subtype is not None:
                record["subtype"] = subtype
            self.assertTrue(case_module.quota_record(record, "session-a"), "documented result quota was ignored")
            record["is_error"] = False
            self.assertFalse(case_module.quota_record(record, "session-a"))
        for message in ["guard refused", '"Usage limit reached"', "OAuth token has expired"]:
            self.assertFalse(case_module.quota_record({"type": "result", "is_error": True,
                             "session_id": "session-a", "result": message}, "session-a"))

    def test_follow_waits_next_run(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-claudock-") as directory:
            case = self.case_fixture(directory)
            case.invoke = mock.Mock(side_effect=[{"run": 1, "state": "profile_wait", "cleaned": False},
                                                {"run": 1, "state": "profile_wait", "cleaned": False}, {"run": 2}])
            with mock.patch.object(case_module.time, "sleep"):
                selected = case.wait_run("life-a", 1)
            self.assertEqual(selected["run"], 2, "follow reused an ended run")

    def test_cursor_clears_since(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-claudock-") as directory:
            case = self.case_fixture(directory)
            event = {"schema": 2, "config": "demo", "life_id": "life-a", "run": 1, "seq": 6}
            case.invoke = mock.Mock(side_effect=[{"events": [event], "cursor": "next"},
                                                {"events": [dict(event, seq=7)], "cursor": ""}])
            self.assertEqual(len(case.tail("life-a", 5)), 2)
            second = case.invoke.call_args_list[1].args[1]
            self.assertEqual(second["since"], 0, "cursor retained nonzero since")

    def test_candidate_reach_completion(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-claudock-") as directory:
            case = self.case_fixture(directory)
            case.reach("start")
            self.assertFalse(case.reached, "partial candidate claimed the assertion")
            with self.assertRaises(case_module.Failure):
                case.complete()
            case.quiescent = case.collected = True
            case.complete()
            self.assertTrue(case.reached)

    def test_red_reach_mapping(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-claudock-") as directory:
            case = self.case_fixture(directory, "red", "new-conversation")
            case.reach("resume")
            self.assertFalse(case.reached, "unrelated resume marked lost control")
            case.reach("lost-conversation")
            self.assertTrue(case.reached, "lost conversation control was not reached")

    def test_negative_control_shapes(self):
        before = {"run": 1, "launch_id": "launch-a"}
        after = {"run": 2, "launch_id": "launch-b"}
        observation = {"state": "exited", "survivors": 0}
        failed = {"kind": "launch.failed", "origin": "service", "run": 2, "payload": {"agent_executed": False}}
        try:
            case_module.verify_negative(False, before, before, [], observation)
        except case_module.Failure:
            self.fail("synchronous refusal wrongly required an end event")
        try:
            case_module.verify_negative(True, before, after, [failed], dict(observation, state="prepared"))
        except case_module.Failure:
            self.fail("aborted prepared gate was rejected")
        with self.assertRaises(case_module.Failure, msg="async abort accepted without no-execution evidence"):
            case_module.verify_negative(True, before, after, [], observation)
        with self.assertRaises(case_module.Failure):
            case_module.verify_negative(True, before, after, [failed], dict(observation, survivors=None))
        with self.assertRaises(case_module.Failure):
            case_module.verify_negative(False, before, after, [], observation)
        with self.assertRaises(case_module.Failure, msg="synchronous refusal accepted launch events"):
            case_module.verify_negative(False, before, before, [failed], observation)

    def test_helper_abort_collection(self):
        target = {"life_id": "life-a", "run": 2}
        lease = {"id": "lease-a", "containment_id": "containment-a"}
        observed = {"state": "prepared", "survivors": 0, "handle": {"target": target, "containment_id": "containment-a"}}
        allocation = {"kind": "helper.allocated", "payload": lease}
        failed = {"kind": "launch.failed", "run": 2, "origin": "service", "payload": {"agent_executed": False}}
        self.assertTrue(case_module.collected_helpers([allocation, failed], observed, "life-a"), "aborted gate demanded release receipt")
        self.assertFalse(case_module.collected_helpers([allocation], observed, "life-a"))
        self.assertFalse(case_module.collected_helpers([allocation, failed], dict(observed, survivors=None), "life-a"))

    def test_lease_level_release(self):
        target = {"life_id": "life-a", "run": 2}
        lease = {"id": "lease-a", "containment_id": "containment-a"}
        observed = {"state": "exited", "survivors": 0, "observed_at": "2026-10-16T00:00:00Z",
                    "handle": {"target": target, "containment_id": "containment-a"}}
        receipt = {"id": "release-a", "lease_id": "lease-a", "containment_id": "containment-a",
                   "operation_id": "operation-a", "effect_id": "effect-a", "backend": "linux-bwrap-landlock",
                   "quiescence": observed, "observed_at": "2026-10-16T00:00:01Z",
                   "live_connections": 0, "queued_jobs": 0, "writable_exports": 0}
        events = [{"kind": "helper.allocated", "payload": lease},
                  {"kind": "helper.released", "origin": "service", "payload": receipt}]
        try:
            complete = case_module.collected_helpers(events, observed, "life-a")
        except KeyError:
            self.fail("lease-level release required an event run")
        self.assertTrue(complete)

    def test_stream_keeps_snapshot(self):
        request, page, frames = stream_fixture()
        events = case_module.tail_output(stream_bytes(page, frames), request, "request-a", "demo")
        self.assertEqual([event["seq"] for event in events], [3, 4], "snapshot events were dropped")

    def test_stream_requires_end(self):
        request, page, frames = stream_fixture()
        with self.assertRaises(case_module.Failure, msg="stream missing an end was accepted"):
            case_module.tail_output(stream_bytes(page, frames[:-1]), request, "request-a", "demo")

    def test_stream_attribution(self):
        for kind in ["request", "index", "run", "config", "sequence", "origin", "after-end"]:
            request, page, frames = stream_fixture()
            if kind == "request":
                frames[0]["request_id"] = "other-request"
            elif kind == "index":
                frames[0]["index"] = 2
            elif kind == "run":
                page["events"][0]["run"] = 1
            elif kind == "config":
                page["events"][0]["config"] = "other"
            elif kind == "sequence":
                frames[0]["event"]["seq"] = 3
            elif kind == "origin":
                frames[0]["event"]["origin"] = "observation"
            else:
                frames.append(deepcopy(frames[0]))
            with self.subTest(kind=kind), self.assertRaises(case_module.Failure, msg="foreign stream attribution was accepted"):
                case_module.tail_output(stream_bytes(page, frames), request, "request-a", "demo")

    def test_release_measurements(self):
        target = {"life_id": "life-a", "run": 2}
        lease = {"id": "lease-a", "containment_id": "containment-a"}
        observed = {"state": "exited", "survivors": 0, "observed_at": "2026-10-16T00:00:00Z",
                    "handle": {"target": target, "containment_id": lease["containment_id"]}}
        receipt = {"id": "release-a", "lease_id": lease["id"], "containment_id": lease["containment_id"],
                   "operation_id": "operation-a", "effect_id": "effect-a", "backend": "linux-bwrap-landlock",
                   "quiescence": observed, "observed_at": "2026-10-16T00:00:01Z",
                   "live_connections": 0, "queued_jobs": 0, "writable_exports": 0}
        case_module.validate_release(receipt, lease, target)
        for field in ["live_connections", "queued_jobs", "writable_exports"]:
            for value in [None, 1, False, "missing"]:
                changed = deepcopy(receipt)
                if value == "missing":
                    del changed[field]
                else:
                    changed[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(case_module.Failure, msg="unknown helper count was accepted"):
                    case_module.validate_release(changed, lease, target)
        with self.assertRaises(case_module.Failure):
            case_module.validate_release(lease, lease, target)

    def test_cli_retains_keys(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-claudock-") as directory:
            os.chmod(directory, 0o700)
            root = Path(directory)
            context = {"test_root": str(root), "evidence_root": str(root / "evidence"), "config": "demo",
                       "binary": "/test/artifacts/laneboss", "binding_file": "/test/bindings/demo.json"}
            case = case_module.Case(context, root / "result.json")
            process = mock.Mock(returncode=0)
            process.communicate.return_value = (case_module.encoded({"object_id": "upload-a"}), b"")

            def launch(argv, **options):
                retained = json.loads((case.evidence / "cli-0001.argv.json").read_bytes())
                self.assertEqual(retained, argv, "invocation identities were not retained before execution")
                return process

            with mock.patch.object(case_module.subprocess, "Popen", side_effect=launch) as invoked:
                case.invoke("blob begin", {"class": "artifact", "bytes": 1, "sha256": case_module.sha(b"x")})
            argv = invoked.call_args.args[0]
            self.assertIn("--binding", argv, "installed binding was omitted")
            self.assertEqual(argv[argv.index("--binding") + 1], context["binding_file"])
            self.assertIn("--idempotency-key", argv, "mutation key was omitted")
            for flag in ["--idempotency-key", "--request-id"]:
                self.assertRegex(argv[argv.index(flag) + 1], r"^[a-f0-9]{32}$")

    def test_health_result_body(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-claudock-") as directory:
            os.chmod(directory, 0o700)
            root = Path(directory)
            context = {"test_root": str(root), "evidence_root": str(root / "evidence"), "config": "demo",
                       "binary": "/test/artifacts/laneboss", "binding_file": "/test/bindings/demo.json"}
            case = case_module.Case(context, root / "result.json")
            health = {"protocol": "laneboss.rpc.v2", "schema": 2, "ready": True}
            process = mock.Mock(returncode=0)
            process.communicate.return_value = (case_module.encoded(health), b"")
            with mock.patch.object(case_module.subprocess, "Popen", return_value=process):
                try:
                    result = case.invoke("health", {})
                except (KeyError, case_module.Failure):
                    self.fail("typed health body was unwrapped")
            self.assertEqual(result, health)

    def test_continuation_state(self):
        swap = {"eligibility_id": "eligibility-a", "profile_grant_id": "grant-b", "expected_generation": 3,
                "cancellation_epoch": 0, "causing_run": 1, "continuation_run": 2}
        prior = {"task": {"id": "task-a"}, "counters": {"failures": 0, "retries": 0},
                 "session": {"history_id": "history-a"}, "cancellation_epoch": 0}
        continued = dict(deepcopy(prior), run=2, generation=4, profile_grant_id="grant-b")
        launch = {"profile_swap": deepcopy(swap)}
        case_module.validate_continuation(swap, prior, continued, launch, ["grant-b"])
        for field in ["counters", "task", "cancellation_epoch", "generation", "profile_grant_id"]:
            changed = deepcopy(continued)
            changed[field] = {"counters": {"failures": 1, "retries": 0}, "task": {"id": "other-task"},
                              "cancellation_epoch": 1, "generation": 3, "profile_grant_id": "other-grant"}[field]
            with self.subTest(field=field), self.assertRaises(case_module.Failure, msg="changed continuation state was accepted"):
                case_module.validate_continuation(swap, prior, changed, launch, ["grant-b"])

    def test_workspace_write_bytes(self):
        expected = ("write-" + uuid.uuid4().hex + "\n").encode()
        row = {"errno": 0, "bytes": len(expected), "sha256": case_module.sha(expected)}
        case_module.validate_workspace_write(row, expected)
        for field, value in [("errno", 13), ("bytes", len(expected) - 1), ("sha256", case_module.sha(b"other"))]:
            with self.subTest(field=field), self.assertRaises(case_module.Failure, msg="workspace bytes were not independently checked"):
                case_module.validate_workspace_write(dict(row, **{field: value}), expected)

    def test_transcript_mode(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-claudock-") as directory:
            root = Path(directory)
            session = str(uuid.uuid4())
            transcript = root / (session + ".jsonl")
            transcript.write_bytes(b"private synthetic transcript\n")
            os.chmod(transcript, 0o600)
            actual = probe_module.transcript_path(str(root), session)
            self.assertEqual(Path(actual), transcript)
            row = probe_module.observe(actual, metadata_only=True)
            self.assertEqual(row["bytes"], 0, "mode probe copied transcript content")
            case_module.validate_transcript_mode(row)
            for field, value in [("errno", 13), ("mode", 0o644), ("nlink", 2), ("regular", False)]:
                with self.subTest(field=field), self.assertRaises(case_module.Failure, msg="unsafe first transcript mode was accepted"):
                    case_module.validate_transcript_mode(dict(row, **{field: value}))

    def test_sibling_requires_permission_denial(self):
        for number in [1, 13]:
            case_module.validate_sibling_denial({"errno": number, "bytes": 0})
        for number in [0, 2, None, True]:
            with self.subTest(errno=number), self.assertRaises(case_module.Failure, msg="missing sibling path was mistaken for a denied read"):
                case_module.validate_sibling_denial({"errno": number, "bytes": 0})
        with self.assertRaises(case_module.Failure):
            case_module.validate_sibling_denial({"errno": 13, "bytes": 1})

    def test_workspace_snapshot_identity(self):
        before = {"id": "workspace-a", "project_id": "project-a", "base": "base-a", "branch": "lane/life-a",
                  "logical_cwd": "/work/main", "snapshot": {"id": "snapshot-one"}}
        after = dict(before, snapshot={"id": "snapshot-two"})
        self.assertTrue(case_module.same_workspace(before, after), "fresh workspace snapshot lost retained identity")
        for field in ["id", "project_id", "base", "branch", "logical_cwd"]:
            self.assertFalse(case_module.same_workspace(before, dict(after, **{field: "other"})),
                             "changed workspace identity was accepted")

    def test_repeated_probe_inputs(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-claudock-") as directory:
            case = self.case_fixture(directory)
            path = Path(directory) / "probe-plan.json"
            path.write_bytes(case_module.encoded({"id": "probe-a"}))
            first = case.inputs("probe-plan.json")
            first["id"] = "local-edit"
            self.assertEqual(case.inputs("probe-plan.json"), {"id": "probe-a"})
            path.write_bytes(case_module.encoded({"id": "changed-plan"}))
            with self.assertRaises(case_module.Failure, msg="changed installed probe input was accepted"):
                case.inputs("probe-plan.json")


if __name__ == "__main__":
    if sys.platform != "linux":
        raise RuntimeError("case unit execution requires the authorized Linux test box")
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))

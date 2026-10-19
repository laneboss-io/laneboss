"""Linux-only regressions for the case reader; these certify no live service."""

import copy
import json
import shlex
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import uuid

from run import Case, digest, one_json, serialized_leases, stream_json, supervisor_request, workspace_bytes


if sys.platform != "linux":
    raise RuntimeError("case regression execution requires Linux")


def encoded(*values):
    return b"\n".join(json.dumps(value, indent=2).encode() for value in values)


def event(sequence, life="life_one", run=2):
    return {"config": "case-codex", "life_id": life, "run": run,
            "origin": "service", "seq": sequence, "kind": "lane.ended"}


def stream_parts():
    request_id = uuid.uuid4().hex
    page = {"events": [event(4)], "cursor": "", "complete": True}
    frame = {"request_id": request_id, "index": 1, "cursor": "next",
             "event": event(5), "end": False}
    end = {"request_id": request_id, "index": 2, "cursor": "last", "end": True}
    return request_id, page, frame, end


class ProtocolTests(unittest.TestCase):
    def case(self):
        temporary = tempfile.TemporaryDirectory(prefix="lb-v2-codex-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve(strict=True)
        evidence = root / "evidence"
        evidence.mkdir(mode=0o700)
        context = {"test_root": str(root), "evidence_root": str(evidence),
                   "config": "case-codex", "phase": "candidate", "mutation_id": ""}
        return Case(context, root / "result.json")

    def test_vendor_stream(self):
        record = {"type": "thread.started", "thread_id": uuid.uuid4().hex}
        data = json.dumps(record).encode() + b"\n"
        reference = {"id": "capture_blob", "sha256": digest(data),
                     "bytes": len(data), "class": "capture"}
        retained = {reference["id"]: data}
        for stream in ("stdout", "vendor"):
            with self.subTest(stream=stream):
                case = self.case()

                def read(ref):
                    self.assertEqual(ref, reference)
                    return retained[ref["id"]]

                case.blob = read
                capture = {"kind": "capture.appended", "life_id": "life_one", "run": 1,
                           "payload": {"primary": True, "coverage": "partial",
                                       "target": {"life_id": "life_one", "run": 1},
                                       "stream": stream, "offset": 0, "data": reference}}
                self.assertEqual(case.capture([capture]), [record],
                                 "registered vendor stream was not read")
                if stream == "vendor":
                    capture["payload"]["stream"] = "structured"
                    with self.assertRaises(AssertionError,
                                           msg="unknown structured stream became primary capture"):
                        case.capture([capture])

    # Dropping the initial snapshot must fail even with a valid live end frame.
    def test_stream_snapshot(self):
        request_id, page, frame, end = stream_parts()
        actual, live = stream_json(encoded(page, frame, end), request_id)
        self.assertEqual(actual, page, "initial snapshot was dropped")
        self.assertEqual(live, [frame["event"]], "live event was dropped")

    # A disconnected stream is not a completed wait.
    def test_stream_end(self):
        request_id, page, frame, end = stream_parts()
        self.assertEqual(stream_json(encoded(page, frame, end), request_id),
                         (page, [frame["event"]]))
        with self.assertRaises(AssertionError, msg="stream EOF became completion"):
            stream_json(encoded(page, frame), request_id)

    # A matching-looking event from another request cannot complete this stream.
    def test_stream_correlation(self):
        request_id, page, frame, end = stream_parts()
        self.assertEqual(stream_json(encoded(page, frame, end), request_id)[1],
                         [frame["event"]])
        for shape in ("request", "index", "payload", "trailing"):
            with self.subTest(shape=shape):
                changed = copy.deepcopy(frame)
                frames = [page, changed, end]
                if shape == "request":
                    changed["request_id"] = uuid.uuid4().hex
                elif shape == "index":
                    changed["index"] += 1
                elif shape == "payload":
                    changed["chunk"] = {}
                else:
                    frames.append(copy.deepcopy(end))
                with self.assertRaises(AssertionError,
                                       msg="foreign frame was accepted"):
                    stream_json(encoded(*frames), request_id)

    # Pagination retains the filter and initial page before any live events.
    # Wrong life/run/origin/order must fail after the actual reader consumes it.
    def test_event_scope(self):
        case = self.case()
        calls = []
        first, second, live = event(4), event(5), event(6)

        def invoke(command, request):
            calls.append(copy.deepcopy(request))
            if request["follow"]:
                return ({"events": [first], "cursor": "page_two", "complete": False},
                        [live])
            return {"events": [second], "cursor": "", "complete": True}

        case.call = invoke
        self.assertEqual(case.events("life_one", 2, follow=True, since=3),
                         [first, second, live])
        self.assertEqual(calls[1]["since"], 3)
        self.assertEqual(calls[1]["run"], 2)
        self.assertEqual(calls[1]["cursor"], "page_two")
        for shape in ("life", "run", "origin", "order"):
            changed = copy.deepcopy(live)
            if shape == "life":
                changed["life_id"] = "another_life"
            elif shape == "run":
                changed["run"] += 1
            elif shape == "origin":
                changed["origin"] = "legacy"
            else:
                changed["seq"] = second["seq"]
            live = changed
            with self.assertRaises(AssertionError, msg="foreign life was accepted"):
                case.events("life_one", 2, follow=True, since=3)
            live = event(6)

    def test_turn_id(self):
        case = self.case()
        value = {**event(4), "kind": "lane.turn", "logical_turn_id": uuid.uuid4().hex}
        case.call = lambda *args: {"events": [value], "cursor": "", "complete": True}
        self.assertEqual(case.events("life_one", 2), [value])
        for invalid in ("", "bad turn", None, 7):
            value["logical_turn_id"] = invalid
            with self.assertRaises(AssertionError, msg="turn without identity became evidence"):
                case.events("life_one", 2)

    def test_red_snapshot(self):
        from check_red import PACKAGE, snapshot

        case = self.case()
        source, target = case.root / "source", case.root / "snapshot"
        source.mkdir(mode=0o700)
        (source / "go.mod").write_bytes(b"module laneboss.io/laneboss\n\ngo 1.26.0\n")
        (source / "go.sum").write_bytes(b"")
        identity = Path("internal") / "identity" / "identity.go"
        identity_bytes = ("package identity\nconst Version = " + json.dumps(uuid.uuid4().hex) + "\n").encode()
        for relative in (Path("internal") / "identity",
                         Path("internal") / "v2" / "api",
                         Path("internal") / "v2" / "admin",
                         Path("internal") / "v2" / "store",
                         Path("internal") / "v2" / "secrets", PACKAGE):
            directory = source / relative
            directory.mkdir(parents=True, mode=0o700)
            (directory / "source.go").write_bytes(("package " + relative.name + "\n").encode())
        (source / identity).write_bytes(identity_bytes)
        snapshot(source, target)
        self.assertTrue((target / identity).is_file(),
                        "red snapshot omitted required identity source")
        self.assertEqual((target / identity).read_bytes(), identity_bytes,
                         "red snapshot changed required identity source")
        for relative in ("go.mod", "go.sum", str(PACKAGE / "source.go")):
            self.assertEqual((target / relative).read_bytes(),
                             (source / relative).read_bytes())

    # The supplied file is synthetic parser data, never an issued authority.
    # Reads request human.session, and the same proof cannot cross connections.
    def test_read_proof(self):
        case = self.case()
        case.proof_directory = case.root / "proof-inputs"
        case.proof_directory.mkdir(mode=0o700)
        invocation = {"request_id": uuid.uuid4().hex}
        proof = {"id": "synthetic_proof", "request_sha256": digest(b"fixture"),
                 "expires_at": "2026-01-01T00:02:00Z"}
        (case.proof_directory / (invocation["request_id"] + ".json")).write_bytes(
            encoded(proof))
        params = {"object_id": "blob_one", "offset": 0, "limit": 4}
        path = case.proof("001", "blob read", params, invocation)
        self.assertEqual(one_json(path.read_bytes()), proof)
        request = one_json((case.evidence / "001-authorization-request.json").read_bytes())
        self.assertEqual(request["proof_method"], "human.session",
                         "read proof did not open a connection session")
        self.assertEqual(request["proof_params"], {})
        with self.assertRaises(AssertionError, msg="read proof crossed connections"):
            case.proof("002", "blob read", params, invocation)

    # Unknown/nonzero resource counts cannot be mistaken for helper quiescence.
    def test_release_counts(self):
        case = self.case()
        receipt = {"id": "release_one", "lease_id": "lease_one",
                   "containment_id": "containment_one", "backend": "linux-bwrap-landlock",
                   "operation_id": "operation_one", "effect_id": "effect_one",
                   "quiescence": {"state": "exited", "survivors": 0, "exit_code": 0,
                                  "handle": {"containment_id": "containment_one",
                                             "target": {"life_id": "life_one", "run": 2}}},
                   "live_connections": 0, "queued_jobs": 0, "writable_exports": 0,
                   "observed_at": "2026-01-01T00:00:01Z"}
        value = {**event(8), "operation_id": "operation_one", "payload": receipt}
        case.release_receipt(value)
        for field in ("live_connections", "queued_jobs", "writable_exports"):
            for count in (1, None, False):
                changed = copy.deepcopy(value)
                changed["payload"][field] = count
                with self.assertRaises(AssertionError,
                                       msg="unmeasured release became success"):
                    case.release_receipt(changed)

    # Duplicate/nonfinite/lossy JSON must fail while exact UTF-8 stays intact.
    def test_json_shape(self):
        original = {"text": "kept café", "items": [1, 2]}
        self.assertEqual(one_json(encoded(original)), original)
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}',
                     b'{"x":9007199254740992}', b'{"x":"\\ud800"}',
                     b'{"x":"\xff"}', b'{} {}', b'null', b'{} trailing'):
            with self.assertRaises((AssertionError, ValueError),
                                   msg="invalid JSON became evidence"):
                one_json(data)

    # A relative evidence ref cannot write into another directory.
    def test_evidence_path(self):
        case = self.case()
        data = uuid.uuid4().hex.encode()
        row = case.keep("input.bin", data)
        self.assertEqual((case.evidence / row["path"]).read_bytes(), data)
        self.assertEqual(row["sha256"], digest(data))
        with self.assertRaises(AssertionError, msg="evidence escaped its root"):
            case.keep("../escaped.bin", data)
        with self.assertRaises(AssertionError, msg="result escaped its root"):
            Case(case.context, case.root.parent / "another-result.json")

    # Uploads use the same exact-connection human.session ceremony as reads.
    def test_session_staging(self):
        case = self.case()
        case.proof_directory = case.root / "proofs"
        case.proof_directory.mkdir(mode=0o700)
        for number, command in enumerate(("blob begin", "blob chunk", "blob commit")):
            invocation = {"request_id": uuid.uuid4().hex}
            proof = {"id": "synthetic_" + uuid.uuid4().hex,
                     "request_sha256": digest(command.encode()),
                     "expires_at": "2026-01-01T00:02:00Z"}
            (case.proof_directory / (invocation["request_id"] + ".json")).write_bytes(encoded(proof))
            stem = "stage-" + str(number)
            case.proof(stem, command, {"fixture": command}, invocation)
            request = one_json((case.evidence / (stem + "-authorization-request.json")).read_bytes())
            self.assertEqual(request["proof_method"], "human.session",
                             "blob staging requested an operation proof")
            self.assertEqual(request["proof_params"], {})

    # A valid ReviewReceipt has no life_id, but pass-through still reaches the
    # negative coverage assertion. The subprocess is a case-reader fixture only.
    def test_review_reached(self):
        case = self.case()
        case.context.update({"binary": "/fixture/laneboss", "binding_file": "/fixture/binding"})
        case.active = "CODEX-COVERAGE"
        case.proof = lambda *args: case.root / "fixture-proof.json"
        ref = {"id": "blob_one", "sha256": digest(b"fixture"), "bytes": 7, "class": "record"}
        request = {"target": {"life_id": "life_one", "run": 1}, "diff": ref,
                   "checks": [ref], "record_inventory": ref, "refusal_resolution": []}
        receipt = {"id": "review_one", "reviewer": {"kind": "human", "id": "reviewer_one"},
                   "diff": ref, "checks": [ref], "record_inventory": ref,
                   "refusal_resolution": [], "coverage": "complete"}
        completed = subprocess.CompletedProcess([], 0, encoded(receipt), b"")
        with patch("run.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(AssertionError, "negative control succeeded"):
                case.call("lane review", request, error="integrity")
        self.assertTrue(case.failure_reached(), "review pass-through did not reach assertion")

    # A committed launch returns an Operation; its measured error is a later
    # effect with the same operation/life/run, never a synchronous error/write.
    def test_launch_effect(self):
        case = self.case()
        control = {"owner": "fixture_owner", "message": "fixture missing helper",
                   "code": "prerequisite_missing", "stage": "runner"}
        operation = {"id": "operation_one", "life_id": "life_one", "run": 1, "status": "pending"}
        error = {**{key: control[key] for key in ("owner", "message", "code")},
                 "instead": "repair fixture", "retryable": False}

        def invoke(command, request, error=None):
            if error is not None:
                raise AssertionError("synchronous error demanded for a committed launch")
            if command == "operation get":
                return {**operation, "status": "failed", "error": dict(error_record)}
            self.assertEqual(command, "lane start")
            return dict(operation)

        error_record = error
        case.call = invoke
        failure = {**event(9, run=1), "kind": "launch.failed", "operation_id": operation["id"],
                   "payload": {"stage": "runner", "agent_executed": False, "error": error}}
        case.events = lambda *args, **kwargs: [copy.deepcopy(failure)]
        result = case.failed_launch("lane start", {"lane": "fixture"}, control)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(case.reached)
        case.reached = False
        failure["payload"]["stage"] = "another_stage"
        with self.assertRaises(AssertionError):
            case.failed_launch("lane start", {"lane": "fixture"}, control)
        self.assertFalse(case.reached)

    # Nanosecond intervals, rather than cross-life sequence labels, establish
    # the claimed serialization. An overlap under clean-looking seqs must fail.
    def test_lease_intervals(self):
        def lease(kind, life, fraction, seq):
            return {"kind": kind, "life_id": life, "run": 1, "seq": seq,
                    "origin": "service", "recorded_at": "2026-01-01T00:00:00." + fraction + "Z",
                    "payload": {"slot": {"id": "slot_" + life}}}

        events = [lease("credential.leased", "one", "000000100", 1),
                  lease("credential.released", "one", "000000200", 2),
                  lease("credential.leased", "two", "000000200", 3),
                  lease("credential.released", "two", "000000400", 4)]
        serialized_leases(list(reversed(events)))
        events[2]["recorded_at"] = "2026-01-01T00:00:00.000000150Z"
        with self.assertRaises(AssertionError, msg="timestamp overlap was accepted"):
            serialized_leases(events)

    # A failure of an earlier/different cell cannot kill the selected mutation.
    def test_red_target(self):
        case = self.case()
        case.context.update({"phase": "red", "mutation_id": "omit-helper"})
        case.reached = True
        case.active = "CODEX-COVERAGE"
        self.assertFalse(case.failure_reached(), "unrelated red assertion counted as reached")
        case.active = "CODEX-HELPER"
        self.assertTrue(case.failure_reached())

    # Empty planted answers and another driver cannot pass a supervisor cell.
    def test_supervisor_inputs(self):
        source = {"driver": "codex", "level": 5, "expected_child_level": 3,
                  "expected_answer": uuid.uuid4().hex}
        request, word, child = supervisor_request(source)
        self.assertEqual((word, child), (source["expected_answer"], 3))
        self.assertNotIn("expected_answer", request)
        with self.assertRaises(AssertionError, msg="empty supervisor word became a passing plant"):
            supervisor_request({**source, "expected_answer": ""})
        with self.assertRaises(AssertionError):
            supervisor_request({**source, "driver": "claudock-cli"})

    # Exercise the real collection control flow with asynchronous state fixtures:
    # all stops precede review; accepted is intermediate; clean waits for its end.
    def test_collection_waits(self):
        case = self.case()
        lanes = {life: {"life_id": life, "name": life, "run": 1, "generation": 1,
                        "last_seq": 4, "state": "verifying", "cleaned": False,
                        "starter_chain": []} for life in ("life_one", "life_two")}
        case.lives = dict.fromkeys(lanes)
        case.roots = set(lanes)
        case.lanes = lambda: [copy.deepcopy(value) for value in lanes.values()]
        case.status = lambda life: copy.deepcopy(lanes[life])
        alive = {"life_one": 1, "life_two": 0}
        calls = []
        case.upload = lambda data: {"id": "reason", "sha256": digest(data), "bytes": len(data), "class": "prompt"}

        def invoke(command, request):
            calls.append(command)
            if command == "lane check":
                return {"survivors": alive[request["life_id"]]}
            if command == "lane stop":
                alive[request["target"]["life_id"]] = 0
                return {"id": "stop_one", "status": "pending"}
            if command == "operation get":
                return {"id": request["operation_id"], "status": "succeeded"}
            if command == "lane archive":
                return {"id": "archive_one", "archive_sha256": digest(b"archive"),
                        "read_back_sha256": digest(b"archive")}
            self.assertEqual(command, "lane clean")
            return {"id": "clean_one", "status": "pending"}

        def events(life, run, follow=False, until="lane.ended", since=0, **kwargs):
            calls.append(until)
            self.assertTrue(follow)
            self.assertEqual(since, lanes[life]["last_seq"])
            if until == "lane.state":
                lanes[life]["state"] = "accepted" if lanes[life]["state"] == "verifying" else "merged"
            else:
                self.assertEqual(until, "lane.cleaned")
                lanes[life]["cleaned"] = True
            lanes[life]["last_seq"] += 1
            return []

        original_keep = case.keep

        def keep(name, data):
            if name == "collection-request.json":
                self.assertEqual(sum(alive.values()), 0, "collection reviewer raced quiescence")
                calls.append("review-request")
            return original_keep(name, data)

        case.call, case.events, case.keep = invoke, events, keep
        case.collect()
        self.assertTrue(case.quiescent and case.collected)
        self.assertEqual(calls.count("lane.state"), 4)
        self.assertEqual(calls.count("lane.cleaned"), 2)
        self.assertLess(calls.index("lane stop"), calls.index("review-request"))

    # A failed observation is retained and fails collection, while the remaining
    # owned lane still receives its stop. No failure is converted to success.
    def test_collection_stops_all(self):
        case = self.case()
        lanes = {life: {"life_id": life, "name": life, "run": 1, "generation": 1,
                        "last_seq": 1, "state": "running", "starter_chain": []}
                 for life in ("life_two", "life_one")}
        case.lives = dict.fromkeys(lanes)
        case.roots = set(lanes)
        case.lanes = lambda: [copy.deepcopy(value) for value in lanes.values()]
        case.status = lambda life: copy.deepcopy(lanes[life])
        case.upload = lambda data: {"id": "reason", "sha256": digest(data), "bytes": len(data), "class": "prompt"}
        stopped = []

        def invoke(command, request):
            if command == "lane check":
                if request["life_id"] == "life_one":
                    raise AssertionError("synthetic observation unavailable")
                return {"survivors": 0 if stopped else 1}
            self.assertEqual(command, "lane stop")
            stopped.append(request["target"]["life_id"])
            return {"id": "stop_one", "status": "succeeded"}

        case.call = invoke
        with self.assertRaises(AssertionError):
            case.collect()
        self.assertEqual(stopped, ["life_two"], "sibling stop was not attempted")
        self.assertFalse(case.quiescent or case.collected)
        self.assertTrue((case.evidence / "collection-stop-failures.json").is_file())

    # Exact unpredictable bytes must come from the actual file-read command;
    # a model's answer, a printf lookalike, another exit or changed bytes fail.
    def test_workspace_probe(self):
        path = "/work/probe " + uuid.uuid4().hex + ".txt"
        expected = ("workspace probe " + uuid.uuid4().hex + "\n").encode()
        command = "/usr/bin/cat -- " + shlex.quote(path)
        item = {"type": "command_execution", "command": command,
                "exit_code": 0, "aggregated_output": expected.decode()}
        records = [{"type": "item.completed", "item": item}]
        workspace_bytes(records, path, expected)
        wrapped = copy.deepcopy(records)
        wrapped[0]["item"]["command"] = "/bin/bash -lc " + shlex.quote(command)
        workspace_bytes(wrapped, path, expected)
        model = [{"type": "item.completed", "item": {"type": "agent_message", "text": expected.decode()}}]
        with self.assertRaises(AssertionError):
            workspace_bytes(model, path, expected)
        fake = copy.deepcopy(records)
        fake[0]["item"]["command"] = "printf simulated_read"
        with self.assertRaises(AssertionError, msg="model text became a workspace read"):
            workspace_bytes(fake, path, expected)
        changed = copy.deepcopy(records)
        changed[0]["item"]["aggregated_output"] = expected.decode() + "changed"
        with self.assertRaises(AssertionError, msg="write probe trusted different bytes"):
            workspace_bytes(changed, path, expected)
        failed = copy.deepcopy(records)
        failed[0]["item"]["exit_code"] = 1
        with self.assertRaises(AssertionError):
            workspace_bytes(failed, path, expected)


if __name__ == "__main__":
    unittest.main()

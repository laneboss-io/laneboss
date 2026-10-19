#!/usr/bin/env python3
"""CLI-only LIFECYCLE-TREE acceptance; Ubuntu test boxes only."""

import argparse
import base64
import concurrent.futures
import functools
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time


CONTROL_RULES = {
    "archive_failure": ("lane.archive", {"integrity", "unavailable"}),
    "dirty_clean": ("lane.clean", {"conflict", "integrity"}),
    "unowned_clean": ("lane.clean", {"forbidden", "integrity"}),
    "unknown_resume": ("lane.resume", {"containment_unknown"}),
    "gate_failure": ("lane.start", {"prerequisite_missing", "unavailable"}),
    "hidden_tail": ("event.tail", {"forbidden", "not_found"}),
    "observed_tail": ("event.tail", {"deadline_exceeded"}),
}


def named_test(name):
    def decorate(method):
        @functools.wraps(method)
        def checked(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except Exception as error:
                if not hasattr(error, "case_test"):
                    error.case_test = "LIFECYCLE-TREE/" + name
                raise
        return checked
    return decorate


class Case:
    def __init__(self, plan, evidence):
        if not __debug__:
            raise RuntimeError("acceptance assertions must not be optimized away")
        if sys.platform != "linux":
            raise RuntimeError("acceptance execution requires the disposable Linux box")
        self.plan = plan
        self.evidence = evidence
        self.serial = 0
        self.lock = threading.Lock()
        self.executor_target = None
        self.current_test = "LIFECYCLE-TREE/preconditions"
        evidence.mkdir(parents=True, exist_ok=False, mode=0o700)

    def reserve(self, label):
        with self.lock:
            self.serial += 1
            return self.evidence / f"{self.serial:03d}-{label}"

    def command(self, argv, label, timeout=60, stem=None):
        if stem is None:
            stem = self.reserve(label)
        try:
            completed = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as error:
            stem.with_suffix(".stdout").write_bytes(error.stdout or b"")
            stem.with_suffix(".stderr").write_bytes(error.stderr or b"")
            stem.with_suffix(".exit").write_text("deadline_exceeded\n")
            raise
        received = time.monotonic_ns()
        stem.with_suffix(".stdout").write_bytes(completed.stdout)
        stem.with_suffix(".stderr").write_bytes(completed.stderr)
        stem.with_suffix(".exit").write_text(str(completed.returncode) + "\n")
        return completed, received

    def call(self, actor, method, params, codes=None, ergonomic=False):
        stem = self.reserve(method.replace(".", "-"))
        request = stem.with_suffix(".request.json")
        request.write_text(json.dumps(params, ensure_ascii=False) + "\n")
        request_id, key = secrets.token_hex(16), secrets.token_hex(16)
        stem.with_suffix(".correlation.json").write_text(json.dumps({
            "method": method, "request_id": request_id, "idempotency_key": key}) + "\n")
        prefix = self.plan["actors"][actor]
        if actor == "executor":
            assert self.executor_target, "executor must be the actual live test life"
            prefix = [*prefix, "--life", self.executor_target["life_id"],
                      "--run", str(self.executor_target["run"]), "--"]
        flags = ["--request", str(request)]
        if ergonomic:
            assert method in {"lane.status", "event.tail"}, "unsupported ergonomic probe"
            flags = ["--life", params["life_id"], "--run", str(params["run"])]
            if method == "event.tail":
                flags.extend(["--since", str(params["since"]), "--cursor", params["cursor"],
                              "--until", params["until"], "--deadline-ms", str(params["deadline_ms"])])
                if params["follow"]:
                    flags.extend(["--follow", "--format", "jsonl"])
        stem.with_suffix(".form.json").write_text(json.dumps({
            "method": method, "form": "flags" if ergonomic else "request"}) + "\n")
        argv = [*prefix, *method.split("."), "--config", self.plan["config"],
                *flags, "--request-id", request_id, "--idempotency-key", key]
        result, received = self.command(argv, method.replace(".", "-"), stem=stem)
        if codes is not None:
            if result.returncode == 0:
                raise AssertionError(f"{method}: forbidden success")
            error = json.loads(result.stderr)
            assert error["code"] in codes, (method, error["code"])
            return error, received
        assert result.returncode == 0, (method, result.returncode)
        if method == "event.tail" and params.get("follow"):
            documents = [json.loads(line) for line in result.stdout.splitlines()]
            assert documents and isinstance(documents[0].get("events"), list), "initial snapshot missing"
            value = {**documents[0], "events": list(documents[0]["events"]), "complete": False}
            ended = False
            previous = params["since"]
            selected_end = False

            def selected(event):
                nonlocal previous, selected_end
                assert not selected_end, "data followed the selected end"
                assert event["config"] == self.plan["config"], "configuration leaked"
                assert event["life_id"] == params["life_id"] and event["run"] == params["run"], "life or run leaked"
                assert event["origin"] == "service" and event["seq"] > previous, "uncommitted or repeated event"
                previous = event["seq"]
                selected_end = bool(params["until"]) and event["kind"] == params["until"]

            for event in value["events"]:
                selected(event)
            for index, frame in enumerate(documents[1:], 1):
                assert not ended and frame["index"] == index, "stream order changed"
                assert frame["request_id"] == request_id and not frame.get("error"), "stream correlation failed"
                if frame["end"]:
                    assert not frame.get("event") and not frame.get("chunk"), "invalid stream end"
                    assert not params["until"] or selected_end, "end preceded the selected committed event"
                    value["cursor"], value["complete"], ended = frame["cursor"], True, True
                else:
                    assert frame.get("event") and not frame.get("chunk"), "invalid event data frame"
                    selected(frame["event"])
                    value["events"].append(frame["event"])
            assert ended, "EOF cannot replace a stream end"
        else:
            value = json.loads(result.stdout)
        assert not value.get("error"), method
        return value, received

    def blob(self, ref):
        content = bytearray()
        while len(content) < ref["bytes"]:
            chunk, _ = self.call("parent", "blob.read", {
                "object_id": ref["id"], "offset": len(content),
                "limit": min(262144, ref["bytes"] - len(content))})
            data = base64.b64decode(chunk["data"], validate=True)
            assert chunk["object_id"] == ref["id"] and chunk["offset"] == len(content)
            assert data and hashlib.sha256(data).hexdigest() == chunk["sha256"]
            content.extend(data)
        assert len(content) == ref["bytes"]
        assert hashlib.sha256(content).hexdigest() == ref["sha256"]
        end, _ = self.call("parent", "blob.read", {
            "object_id": ref["id"], "offset": len(content), "limit": 1})
        assert end["object_id"] == ref["id"] and end["offset"] == len(content)
        assert base64.b64decode(end["data"], validate=True) == b"", "reference truncated the object"
        assert end["sha256"] == hashlib.sha256(b"").hexdigest(), "invalid EOF digest"
        return bytes(content)

    def settle(self, operation):
        deadline = time.monotonic() + 45
        while operation["status"] in ("pending", "running"):
            assert time.monotonic() < deadline, "operation deadline"
            time.sleep(0.05)
            operation, _ = self.call(
                "parent", "operation.get", {"operation_id": operation["id"]})
        assert operation["status"] == "succeeded", operation["status"]
        assert not operation.get("error"), "failed receipt"
        return operation

    def status(self, target):
        value, _ = self.call("parent", "lane.status", target, ergonomic=True)
        assert value["life_id"] == target["life_id"]
        assert value["run"] == target["run"]
        return value

    @named_test("two-ladder-latency")
    def follow(self, target, since):
        request = {**target, "since": since, "cursor": "", "follow": True,
                   "until": "lane.ended", "deadline_ms": 45000}
        value, received = self.call("parent", "event.tail", request, ergonomic=True)
        events = value["events"]
        selected = [event for event in events
                    if event["kind"] == "lane.ended"
                    and event["life_id"] == target["life_id"]
                    and event["run"] == target["run"]
                    and event["origin"] == "service"
                    and event["seq"] > since]
        assert value["complete"] and len(selected) == 1, "selected end missing"
        end = selected[0]
        observation = end["payload"]["observation"]
        assert observation["state"] == "exited"
        assert observation["survivors"] == 0
        assert "exit_code" in observation or "signal" in observation
        timing, _ = self.command(
            [*self.plan["timing"], "--life", target["life_id"],
             "--run", str(target["run"]), "--seq", str(end["seq"])], "timing")
        assert timing.returncode == 0, "commit observer failed"
        committed = json.loads(timing.stdout)["commit_monotonic_ns"]
        latency = received - committed
        assert 0 <= latency <= 2_000_000_000, "follow exceeded two seconds"
        (self.evidence / f"latency-run-{target['run']}.json").write_text(
            json.dumps({"seq": end["seq"], "commit_ns": committed,
                        "receive_ns": received, "latency_ns": latency}) + "\n")
        return end

    def observe(self, phase, target):
        result, _ = self.command(
            [*self.plan["observe"], "--phase", phase,
             "--life", target["life_id"], "--run", str(target["run"])], phase)
        assert result.returncode == 0, "outside observer failed"
        value = json.loads(result.stdout)
        if phase != "after-clean":
            assert value["containment_known"], "unknown containment"
        if phase == "before-stop":
            assert value["child_seen"], "detached child not exercised"
        elif phase == "after-stop":
            assert value["survivors"] == 0, "detached child survived"
        elif phase == "after-clean":
            assert not value["workspace_present"] and not value["branch_present"]
            assert value["records_present"] and value["archive_readback_ok"]

    def control_probe(self, name, phase):
        result, _ = self.command(
            [*self.plan["verify_control"], "--name", name, "--phase", phase],
            name + "-" + phase)
        assert result.returncode == 0, "outside control observer failed"
        facts = json.loads(result.stdout)
        assert facts["ready"] and facts["objects"], "physical control canaries missing"
        assert isinstance(facts["launch_count"], int), "scoped launch observation missing"
        return facts

    def controls(self, names):
        for name in names:
            self.current_test = "LIFECYCLE-TREE/" + name
            method, codes = CONTROL_RULES[name]
            control = self.plan["controls"][name]
            assert control["method"] == method and control["codes"]
            assert set(control["codes"]) <= codes, "dependency errors cannot pass a red control"
            physical_before = self.control_probe(name, "before")
            control_target = control["params"].get("target")
            before = self.status(control_target) if control_target else None
            self.call(control["actor"], control["method"], control["params"], control["codes"])
            if before:
                after = self.status(control_target)
                assert before["workspace"] == after["workspace"] and not after["cleaned"]
            physical_after = self.control_probe(name, "after")
            assert physical_before["objects"] == physical_after["objects"], "refusal removed or changed work"
            assert physical_before["launch_count"] == physical_after["launch_count"], "refusal launched an agent"

    def run(self):
        assert sys.platform == "linux", "Ubuntu test box required"
        assert len(self.plan["load"]) >= 20, "twenty loaded lives required"
        identities = {}
        for actor in self.plan["actors"]:
            if actor == "executor":
                continue
            identities[actor], _ = self.call(actor, "identity.self", {})
        assert identities["parent"]["actor"]["life_id"] != (
            identities["sender"]["actor"]["life_id"])
        loaded, roots = set(), set()
        for life in self.plan["load"]:
            value, _ = self.call("observer", "lane.status", life)
            assert value["state"] == "running", "load must be actual runs"
            identity = (value["life_id"], value["run"])
            assert identity not in loaded, "load repeated the same life"
            loaded.add(identity)
            roots.add(value["root_life_id"])
        assert len(loaded) >= 20 and len(roots) >= 2, "load needs two authentic starter trees"
        assert self.blob(self.plan["start"]["task"]), "real task input required"
        assert self.blob(self.plan["message"]), "real resume input required"
        self.current_test = "LIFECYCLE-TREE/full-flow"
        (self.evidence / "reached.json").write_text(json.dumps({"assertion": "LIFECYCLE-TREE"}) + "\n")
        operation, _ = self.call("parent", "lane.start", self.plan["start"])
        (self.evidence / "subject.json").write_text(json.dumps({"life_id": operation["life_id"], "run": operation["run"]}) + "\n")
        self.settle(operation)
        target = {"life_id": operation["life_id"], "run": 1}
        end = self.follow(target, 0)
        assert end["payload"]["reason"] == "exit"
        assert end["payload"]["observation"]["exit_code"] == 0
        first = self.status(target)
        assert first["state"] == "verifying" and not first["cleaned"]
        file_first, _ = self.call("parent", "lane.status", target)
        assert first == file_first, "status flag and request-file forms disagree"
        assert first["task"] == self.plan["start"]["task"] and first["launch_id"]
        assert first["session"]["history_id"], "private history identity missing"
        assert isinstance(first["cancellation_epoch"], int) and first["cancellation_epoch"] >= 0
        assert all(isinstance(first["counters"][key], int) and first["counters"][key] >= 0
                   for key in ("failures", "retries")), "task counters missing"
        resume = {"target": target, "expected_generation": first["generation"],
                  "message": self.plan["message"], "budget": first["budget_remaining"]}
        operation, _ = self.call("parent", "lane.resume", resume)
        self.settle(operation)
        target = {**target, "run": 2}
        end = self.follow(target, first["last_seq"])
        assert end["payload"]["observation"]["exit_code"] == 0
        second = self.status(target)
        assert second["workspace"] == first["workspace"], "workspace changed"
        assert second["session"] == first["session"], "session changed"
        self.current_test = "LIFECYCLE-TREE/manual-turn-actor"
        mail, _ = self.call("sender", "mail.send", {
            **self.plan["mail"], "recipient_life_id": target["life_id"]})
        turn = {"target": target, "expected_generation": second["generation"],
                "mail_ids": [mail["id"]], "idle_message": self.plan["idle_message"],
                "budget": second["budget_remaining"]}
        operation, _ = self.call("parent", "lane.turn", turn)
        self.settle(operation)
        target = {**target, "run": 3}
        third = self.status(target)
        events, _ = self.call("parent", "event.tail", {
            **target, "since": second["last_seq"], "cursor": "", "follow": False,
            "until": "", "deadline_ms": 0})
        turns = [event for event in events["events"] if event["kind"] == "lane.turn"]
        assert len(turns) == 1 and turns[0]["actor"] == identities["parent"]["actor"]
        assert turns[0]["actor"] != mail["sender"], "sender became requester"
        self.executor_target = target
        executor, _ = self.call("executor", "identity.self", {})
        assert executor["actor"]["life_id"] == target["life_id"], "executor transport impersonation"
        self_review = self.plan["self_review"]
        self.call("executor", "lane.review", {**self_review, "target": target}, ["forbidden"])
        self.call("executor", "lane.mark", {
            "target": target, "expected_generation": third["generation"], "state": "accepted",
            "review": {"id": "untrusted-self-attempt", "reviewer": executor["actor"],
                       "diff": self_review["diff"], "checks": self_review["checks"],
                       "record_inventory": self_review["record_inventory"],
                       "refusal_resolution": [], "coverage": "complete"}}, ["forbidden"])
        self.current_test = "LIFECYCLE-TREE/detached-stop"
        self.observe("before-stop", target)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            following = pool.submit(self.follow, target, second["last_seq"])
            stop, _ = self.call("parent", "lane.stop", {
                "target": target, "expected_generation": third["generation"],
                "reason": self.plan["reason"]})
            self.settle(stop)
            following.result(timeout=50)
        self.observe("after-stop", target)
        self.current_test = "LIFECYCLE-TREE/independent-review"
        prepared, _ = self.command(
            [*self.plan["prepare_review"], "--life", target["life_id"],
             "--run", str(target["run"])], "prepare-review")
        assert prepared.returncode == 0, "trusted review evidence worker failed"
        review = {**json.loads(prepared.stdout), "target": target}
        receipt, _ = self.call("reviewer", "lane.review", review)
        assert receipt["reviewer"] == identities["reviewer"]["actor"]
        assert receipt["coverage"] == "complete", "coverage is incomplete"
        for state in ("accepted", "merged"):
            lane = self.status(target)
            operation, _ = self.call("reviewer", "lane.mark", {
                "target": target, "expected_generation": lane["generation"],
                "state": state, "review": receipt})
            self.settle(operation)
            assert self.status(target)["state"] == state
        self.controls(CONTROL_RULES)
        self.current_test = "LIFECYCLE-TREE/archive-clean"
        lane = self.status(target)
        archive, _ = self.call("parent", "lane.archive", {
            "target": target, "expected_generation": lane["generation"]})
        assert archive["archive_sha256"] == archive["read_back_sha256"]
        assert archive["life_id"] == target["life_id"] and archive["verified_at"]
        assert self.blob(archive["manifest"]), "archive manifest read-back missing"
        lane = self.status(target)
        self.current_test = "LIFECYCLE-TREE/receipt-before-delete"
        clean, _ = self.call("parent", "lane.clean", {
            "target": target, "expected_generation": lane["generation"],
            "archive_receipt_id": archive["id"]})
        self.settle(clean)
        cleaned = self.status(target)
        assert cleaned["cleaned"] and cleaned["state"] == "merged"
        self.observe("after-clean", target)
        resume.update(target=target, expected_generation=cleaned["generation"])
        self.call("parent", "lane.resume", resume, ["conflict"])
        print("PASS: LIFECYCLE-TREE")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--control", action="append", choices=tuple(CONTROL_RULES), default=[])
    args = parser.parse_args()
    raw = args.plan.read_bytes()
    plan = json.loads(raw)
    case = Case(plan, args.evidence)
    (args.evidence / "plan.json").write_bytes(raw)
    try:
        if args.control:
            case.controls(args.control)
            print("PASS: focused lifecycle controls; full acceptance was not run")
        else:
            case.run()
    except Exception as error:
        name = getattr(error, "case_test", case.current_test)
        (args.evidence / "failure.json").write_text(json.dumps({
            "test": name, "error_type": type(error).__name__}) + "\n")
        print("FAIL: " + name, file=sys.stderr)
        raise


if __name__ == "__main__":
    main()

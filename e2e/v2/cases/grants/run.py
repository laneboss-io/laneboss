#!/usr/bin/env python3
"""External CLI acceptance. Dependency/setup failures remain failures."""

import argparse
import base64
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import stat
import subprocess
import time


_handoff_spec = importlib.util.spec_from_file_location(
    "laneboss_lane_handoff", Path(__file__).resolve().parents[2] / "lane_handoff.py")
HANDOFF = importlib.util.module_from_spec(_handoff_spec)
_handoff_spec.loader.exec_module(HANDOFF)
_observer_spec = importlib.util.spec_from_file_location(
    "grants_observer", Path(__file__).with_name("observer.py"))
OBSERVER = importlib.util.module_from_spec(_observer_spec)
_observer_spec.loader.exec_module(OBSERVER)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(Path(path).read_bytes())


class Case:
    def __init__(self, context):
        self.context = context
        self.root = Path(context["evidence_root"])
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
        self.root.chmod(0o700)
        self.counter = 0
        self.evidence = []
        self.reached = False
        self.last_exit = 1
        self.operations = []

    def retain(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        item = {"path": name, "sha256": digest(data), "bytes": len(data)}
        self.evidence.append(item)
        return item

    def call(self, command, request, denied=False):
        self.counter += 1
        stem = f"rpc-{self.counter:03d}"
        raw = json.dumps(request, sort_keys=True).encode()
        self.retain(stem + "-input.json", raw)

        request_id, mutation_key = secrets.token_hex(16), secrets.token_hex(16)
        self.retain(stem + "-keys.json", json.dumps({
            "request_id": request_id, "idempotency_key": mutation_key}).encode())
        args = [self.context["binary"], *command.split(), "--config",
                self.context["config"], "--binding",
                self.context["binding_file"], "--request",
                str(self.root / (stem + "-input.json")),
                "--request-id", request_id, "--idempotency-key", mutation_key]
        if OBSERVER.available():
            result = OBSERVER.exchange({"action": "rpc", "command": command,
                "request": request, "denied": denied, "request_id": request_id,
                "idempotency_key": mutation_key})
            completed = subprocess.CompletedProcess(args, result["exit_code"],
                base64.b64decode(result["stdout"], validate=True),
                base64.b64decode(result["stderr"], validate=True))
        else:
            completed = subprocess.run(args, capture_output=True, timeout=120,
                close_fds=True, pass_fds=HANDOFF.lane_descriptors(
                    self.context["config"], self.context["binding_file"]))
        self.last_exit = completed.returncode
        self.retain(stem + "-stdout.json", completed.stdout)
        self.retain(stem + "-stderr.json", completed.stderr)
        self.retain(stem + "-exit.json",
                    json.dumps({"exit": completed.returncode}).encode())
        if denied:
            assert completed.returncode == 2, "request was not refused"
            error = json.loads(completed.stderr)
            assert error["code"] in {"forbidden", "invalid_request",
                                     "conflict"}, "unexpected refusal"
            return error
        assert completed.returncode == 0, "dependency or operation failed"
        return json.loads(completed.stdout)

    def outside_control(self, canary):
        source = Path(__file__).with_name("child_probe.c")
        binary = self.root / "observer-probe"
        compiler = shutil.which("cc") or shutil.which("gcc")
        assert compiler is not None, "missing: cc or gcc; prep package: gcc and libc6-dev"
        built = subprocess.run([compiler, "-Wall", "-Werror", str(source),
                                "-o", str(binary)], capture_output=True, timeout=60)
        self.retain("observer-build.stdout", built.stdout)
        self.retain("observer-build.stderr", built.stderr)
        self.retain("observer-build.json", json.dumps({"exit": built.returncode}).encode())
        assert built.returncode == 0, "observer probe did not compile"
        self.retain("observer-probe.c", source.read_bytes())
        data = binary.read_bytes()
        self.evidence.append({"path": binary.name, "sha256": digest(data),
                              "bytes": len(data)})
        control = subprocess.run([str(binary), str(canary)],
                                 capture_output=True, timeout=15)
        self.retain("observer-control.stdout", control.stdout)
        self.retain("observer-control.stderr", control.stderr)
        self.retain("observer-control.json", json.dumps({"exit": control.returncode}).encode())
        assert control.returncode == 41, "outside read control did not execute"

    def complete(self, operation):
        self.operations.append(operation["id"])
        deadline = time.monotonic() + 120
        while operation["status"] in {"pending", "running"}:
            assert time.monotonic() < deadline, "worker completion timed out"
            time.sleep(1)
            operation = self.call("operation get", {
                "operation_id": operation["id"]})
        return operation

    def blob(self, ref):
        assert 0 <= ref["bytes"] <= 67108864, "object reference exceeds the bounded size"
        data = bytearray()
        while len(data) < ref["bytes"]:
            chunk = self.call("blob read", {
                "object_id": ref["id"], "offset": len(data),
                "limit": min(262144, ref["bytes"] - len(data))})
            part = base64.b64decode(chunk["data"], validate=True)
            assert part and chunk["offset"] == len(data)
            assert chunk["object_id"] == ref["id"]
            assert digest(part) == chunk["sha256"]
            data.extend(part)
        assert len(data) == ref["bytes"]
        assert digest(data) == ref["sha256"]
        end = self.call("blob read", {"object_id": ref["id"],
                                      "offset": len(data), "limit": 1})
        assert end["object_id"] == ref["id"] and end["offset"] == len(data)
        assert base64.b64decode(end["data"], validate=True) == b""
        assert end["sha256"] == digest(b""), "object has no authentic exact-end chunk"
        return bytes(data)

    def grants(self, grant_id):
        return self.call("grants get", {"grant_set_id": grant_id})

    def source(self, grant):
        data = bytearray()
        while len(data) <= 67108864:
            chunk = self.call("blob read", {
                "object_id": grant["source_object_id"], "offset": len(data),
                "limit": 262144})
            part = base64.b64decode(chunk["data"], validate=True)
            assert chunk["offset"] == len(data)
            assert chunk["object_id"] == grant["source_object_id"]
            assert digest(part) == chunk["sha256"]
            if not part:
                break
            data.extend(part)
        assert len(data) <= 67108864
        assert digest(data) == grant["source_sha256"]
        return json.loads(data)

    def bound(self, fixture):
        binding_bytes = Path(self.context["binding_file"]).read_bytes()
        binding = json.loads(binding_bytes)
        compatible = (binding["schema"] == "laneboss.binding.v2" and
                      binding["contract_revision"] == "v2.0-draft.4" and
                      binding["protocol"] == "laneboss.rpc.v2" and
                      binding["api_schema"] == 2 and
                      binding["config"] == self.context["config"] and
                      binding["class"] == "lane" and
                      binding["artifact_sha256"] == self.context["binary_sha256"])
        self.retain("binding-check.json", json.dumps({
            "sha256": digest(binding_bytes), "bytes": len(binding_bytes),
            "contract_revision": "v2.0-draft.4", "compatible": compatible}).encode())
        assert compatible, "installed binding differs from the draft.4 candidate"
        scope = self.call("identity self", {})
        assert scope["actor"]["kind"] == "lane" and scope["actor"]["level"] == 5
        assert scope["actor"]["life_id"] == fixture["parent_life_id"]
        assert binding["target"]["life_id"] == scope["actor"]["life_id"]
        assert binding["launch_id"] == scope["launch_id"]
        assert binding["endpoint_generation"] == scope["endpoint_generation"]
        parent = self.grants(fixture["parent_grant_set_id"])
        source = next(item for item in parent["data"]
                      if item["id"] == fixture["data_grant_id"])
        assert source["relative_path"] == "." and source["access"] == "ro"
        assert source["delegate"] and not parent["revoked"]
        tree = self.source(source)
        entries = {item["path"]: item for item in tree["entries"]}
        assert entries["alias"]["kind"] == "symlink"
        assert entries["alias"]["link_target"] == "private/canary"
        self.input_ref = entries["child/input.txt"]["content"]
        self.canary_ref = entries["private/canary"]["content"]
        assert fixture["canary_path"] == source["destination"] + "/private/canary"
        data = {"parent_grant_id": source["id"], "relative_path": "child",
                "access": "ro", "delivery": "copy",
                "destination": "/work/main", "delegate": False,
                "expires_at": source["expires_at"]}
        requested = {"resources": [], "data": [data], "secrets": [],
                     "profiles": [], "network": [], "channels": []}
        request = {"parent_life_id": fixture["parent_life_id"],
                   "child_level": 3, "requested": requested,
                   "expected_policy_generation": fixture["policy_generation"]}
        result = self.call("grants validate", request)["effective"]
        actual = result["data"][0]
        for field in ("relative_path", "access", "delivery", "destination",
                      "delegate", "expires_at", "parent_grant_id"):
            assert actual[field] == data[field], "narrow grant changed"
        assert actual["source_object_id"] == source["source_object_id"]
        assert actual["source_sha256"] == source["source_sha256"]
        self.reached = True
        variants = []
        for field, value in [("relative_path", "../private"),
                             ("relative_path", "/private"),
                             ("relative_path", "child/../private"),
                             ("relative_path", "alias"),
                             ("relative_path", "child/.git"),
                             ("access", "rw"),
                             ("delivery", "mount"),
                             ("expires_at", "9999-01-01T00:00:00Z"),
                             ("destination", "/run/control"),
                             ("parent_grant_id", "ungranted")]:
            bad = copy.deepcopy(request)
            bad["requested"]["data"][0][field] = value
            variants.append(bad)
        for level in (2, 5, 6):
            bad = copy.deepcopy(request)
            bad["child_level"] = level
            variants.append(bad)
        bad = copy.deepcopy(request)
        bad["requested"]["data"].append(copy.deepcopy(data))
        variants.append(bad)
        nondelegable = next(item for item in parent["data"]
                            if item["id"] == fixture["nondelegable_grant_id"])
        assert not nondelegable["delegate"]
        for delegate in (False, True):
            bad = copy.deepcopy(request)
            selection = bad["requested"]["data"][0]
            selection.update({"parent_grant_id": nondelegable["id"],
                              "relative_path": ".", "delegate": delegate,
                              "expires_at": nondelegable["expires_at"]})
            variants.append(bad)
        for family, value in [("secrets", {
                "parent_grant_id": "ungranted", "name": "UNGRANTED",
                "version": "1", "delivery": "env", "target": "TASK_KEY",
                "delegate": False, "expires_at": source["expires_at"]}),
                ("resources", {"parent_grant_id": "ungranted",
                 "regions": ["region-a"], "image_ids": ["image-a"],
                 "machine_types": ["small"], "max_active": 1,
                 "max_hourly_micros": 1, "total_budget_micros": 1,
                 "delegate": False, "expires_at": source["expires_at"]})]:
            bad = copy.deepcopy(request)
            bad["requested"][family] = [value]
            variants.append(bad)
        resource = parent["resources"][0]
        for field in ("max_active", "max_hourly_micros", "total_budget_micros"):
            bad = copy.deepcopy(request)
            value = {key: copy.deepcopy(resource[key]) for key in (
                "regions", "image_ids", "machine_types", "max_active",
                "max_hourly_micros", "total_budget_micros", "expires_at")}
            value.update({"parent_grant_id": resource["id"], "delegate": False})
            value[field] += 1
            bad["requested"]["resources"] = [value]
            variants.append(bad)
        for bad in variants:
            self.call("grants validate", bad, denied=True)
            assert self.grants(parent["id"]) == parent, "refusal mutated grants"

    def child(self, fixture):
        # This assertion has its own setup and executes after a bound failure.
        parent = self.grants(fixture["parent_grant_set_id"])
        source = next(item for item in parent["data"]
                      if item["id"] == fixture["data_grant_id"])
        entries = {item["path"]: item for item in self.source(source)["entries"]}
        self.input_ref = entries["child/input.txt"]["content"]
        self.canary_ref = entries["private/canary"]["content"]
        canary = Path(fixture["canary_observer"])
        before = canary.read_bytes()
        assert before, "missing observer canary"
        assert digest(before) == self.canary_ref["sha256"]
        assert len(before) == self.canary_ref["bytes"]
        self.outside_control(canary)
        candidate = self.blob(fixture["candidate"])
        self.retain("candidate.json", candidate)
        entries = json.loads(candidate)["entries"]
        files = {item["path"]: item for item in entries}
        names = {"child_probe.c", "child_task.sh", "pre-commit.sh", "input.txt"}
        assert len(files) == len(entries) and set(files) == names
        for name in sorted(names - {"input.txt"}):
            source = Path(__file__).with_name(name).read_bytes()
            assert files[name]["kind"] == "file"
            assert self.blob(files[name]["content"]) == source, "candidate substituted the canary program"
        input_ref = files["input.txt"]["content"]
        assert input_ref == self.input_ref, "candidate replaced the narrow source bytes"
        plan = json.loads(self.blob(fixture["test_plan"]))
        assert plan["kind"] == "test"
        assert plan["input"] == fixture["candidate"]
        assert plan["argv"] == ["sh", "child_task.sh", fixture["canary_path"]]
        child_lane = self.call("lane status", fixture["child"])
        assert child_lane["level"] == 3 and child_lane["parent_life_id"] == fixture["parent_life_id"]
        child_grants = self.grants(child_lane["grant_set_id"])
        assert plan["grant_set_id"] == child_grants["id"]
        assert child_grants["parent_life_id"] == fixture["parent_life_id"]
        assert len(child_grants["data"]) == 1
        assert child_grants["data"][0]["relative_path"] == "child"
        assert child_grants["data"][0]["destination"] == "/work/main"
        operation = self.call("grants test-child", {
            "child": fixture["child"], "candidate": fixture["candidate"],
            "test_plan": fixture["test_plan"], "budget": plan["budget"]})
        operation = self.complete(operation)
        page = self.call("event tail", {
            "life_id": fixture["child"]["life_id"],
            "run": fixture["child"]["run"], "since": operation["first_seq"],
            "cursor": "", "follow": False, "until": "worker.completed",
            "deadline_ms": 10000})
        output = bytearray()
        while True:
            for event in page["events"]:
                if event["operation_id"] != operation["id"] or event["kind"] != "capture.appended":
                    continue
                capture = event["payload"]
                if capture["stream"] != "stdout":
                    continue
                assert capture["primary"] and capture["coverage"] == "complete"
                assert capture["target"] == fixture["child"]
                assert capture["offset"] == len(output), "capture has a gap or overlap"
                output.extend(self.blob(capture["data"]))
            if page["complete"]:
                break
            page = self.call("event tail", {
                "life_id": fixture["child"]["life_id"],
                "run": fixture["child"]["run"], "since": 0,
                "cursor": page["cursor"], "follow": False,
                "until": "worker.completed", "deadline_ms": 10000})
        self.retain("worker-output.jsonl", output)
        records = [json.loads(line) for line in output.splitlines()]
        probes = [row for row in records if "read_errno" in row]
        self.reached = bool(probes)
        assert len(probes) == 2, "test and Git hook were not both executed"
        for row in probes:
            for key in ("read_errno", "write_errno"):
                assert row[key] in {errno.EACCES, errno.EPERM, errno.EROFS,
                                    errno.ENOENT}, "parent authority leaked"
        assert any(row.get("build_exit") == 0 and row.get("git_exit") == 0
                   for row in records), "ordinary child work failed"
        assert any(row.get("input_sha256") == input_ref["sha256"]
                   for row in records), "inside source bytes differ from the narrow grant"
        assert operation["status"] == "succeeded", "worker did not succeed"
        assert canary.read_bytes() == before, "parent canary changed"
        revoked = self.complete(self.call("grants revoke", fixture["revocation_request"]))
        assert revoked["status"] == "succeeded", "revocation was not completed"
        latest = self.call("lane status", fixture["child"])
        current_grants = self.grants(latest["grant_set_id"])
        assert current_grants["revoked"] is True, "revocation did not change the child's retained grants"
        resume = copy.deepcopy(fixture["resume_request"])
        resume["expected_generation"] = latest["generation"]
        for key, ceiling in latest["budget_remaining"].items():
            if key != "currency":
                resume["budget"][key] = min(resume["budget"][key], ceiling)
        error = self.call("lane resume", resume, denied=True)
        assert error["code"] == "forbidden" and "revoked" in error["message"], \
            "resume refused before reaching revoked-grant enforcement"
        observed = self.call("lane check", fixture["child"])
        assert observed["survivors"] == 0 and observed["state"] == "exited"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    assert platform.system() == "Linux", "acceptance runs only on the authorized Linux box"
    context = load(args.context)
    assert context["schema"] == "laneboss.e2e-context.v2"
    assert context["case_id"] == "grants"
    assert digest(Path(context["binary"]).read_bytes()) == context["binary_sha256"]
    case = Case(context)
    result = {"schema": "laneboss.e2e-result.v2", "case_id": "grants",
              "phase": context["phase"], "mutation_id": context["mutation_id"],
              "binary_sha256": context["binary_sha256"],
              "source_sha256": context["source_sha256"], "assertions": [],
              "collection": {"processes_quiescent": False,
                             "temporary_resources_collected": False,
                             "evidence": []}}
    failed = False
    fixture = None
    for assertion, method in [("GRANT-BOUND", case.bound),
                              ("CHILD-CODE", case.child)]:
        case.reached = False
        case.evidence = []
        try:
            fixture = load(Path(context["test_root"]) / "grants-fixture.json")
            method(fixture)
        except (AssertionError, OSError, ValueError, KeyError, RuntimeError, AttributeError,
                subprocess.SubprocessError, StopIteration) as error:
            failed = True
            case.retain(assertion.lower() + "-failure.json", json.dumps({
                "error_type": type(error).__name__,
                "reason": str(error) if isinstance(error, AssertionError)
                else "setup, transport, or dependency failure"}).encode())
            verdict = "fail"
        else:
            verdict = "pass"
        result["assertions"].append({"id": assertion, "reached": case.reached,
                                     "verdict": verdict,
                                     "observed_exit": case.last_exit,
                                     "evidence": list(case.evidence)})
    # The shared harness owns process/resource collection. Its independently
    # verified receipt is required; absence can never become a clean result.
    try:
        receipt = OBSERVER.exchange({"action": "collect", "operation_ids": case.operations})
        assert receipt["processes_quiescent"]
        assert receipt["temporary_resources_collected"]
        assert set(case.operations) <= set(receipt["operation_ids"])
        assert receipt["evidence"], "outside collection has no measured evidence"
        for ref in receipt["evidence"]:
            relative = Path(ref["path"])
            assert not relative.is_absolute() and ".." not in relative.parts
            path = case.root / relative
            assert path.resolve(strict=True) == path and path.is_file()
            raw = path.read_bytes()
            assert len(raw) == ref["bytes"] and digest(raw) == ref["sha256"]
        item = case.retain("collection.json", json.dumps(receipt).encode())
        result["collection"] = {"processes_quiescent": True,
                                "temporary_resources_collected": True,
                                "evidence": [item, *receipt["evidence"]]}
    except (OSError, ValueError, KeyError, AssertionError):
        failed = True
    destination = Path(args.result)
    temporary = destination.with_suffix(".pending")
    temporary.write_text(json.dumps(result, indent=2) + "\n")
    temporary.replace(destination)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

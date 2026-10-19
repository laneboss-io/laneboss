"""Reached red/green controls for the shared exporter and grants harness.

Only disposable Linux executes this file. Mutants are private copies of
case-owned code; none is installed or credited as product acceptance.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CORE = ROOT / "scripts" / "v2-serve"
RESULT_CALL = '''value = reader.result_file(result_path, manifest, context, observed_exit,
        red_assertion=prepared.get("red_assertion"), red_check=prepared.get("red_check"))'''
CONTROLS = (
    ("context-artifact", "item_context.py", ('"binary_sha256": sha(binary)',
      '"binary_sha256": sha(archive)'), ("test_context",), "binary pin changed"),
    ("retained-artifact", "item_context.py", (
      'sha(binary) == case.installed["artifact_sha256"] == sha(retained)',
      'sha(binary) == case.installed["artifact_sha256"]'), ("test_binary_change",), "ValueError not raised"),
    ("consumed-source", "item_context.py", (
      ' and\n                    (case.stage / member.name).read_bytes() == raw', ''),
      ("test_source_change",), "ValueError not raised"),
    ("input-evidence", "item_context.py", (
      '"sha256": sha(path), "bytes": len(raw)',
      '"sha256": sha(path) + ":changed", "bytes": len(raw)'), ("test_inputs",), "input evidence pin changed"),
    ("declared-interpreter", "item_dispatch.py", (
      'return [*interpreter, str(entry)]', 'return ["/bin/sh", str(entry)]'),
      ("test_interpreter",), "declared bash interpreter was changed"),
    ("entry-scope", "item_dispatch.py", (
      '"unit": self.unit, "cgroup_present": present', '"unit": self.unit + ":foreign", "cgroup_present": present'),
      ("test_entry_scope",), "entry scope identity changed"),
    ("entry-removed-enodev", "item_dispatch.py", (
      'error.errno not in (errno.ENODEV, errno.ENOENT)',
      'error.errno != errno.ENOENT'),
      ("test_entry_removed",), "removed cgroup was not collected"),
    ("entry-removed-enoent", "item_dispatch.py", (
      'error.errno not in (errno.ENODEV, errno.ENOENT)',
      'error.errno != errno.ENODEV'),
      ("test_entry_removed",), "removed cgroup was not collected"),
    ("entry-removed-exit", "item_dispatch.py", (
      '"entry_exit_code": entry_exit', '"entry_exit_code": 0'),
      ("test_entry_removed",), "removed cgroup lost the observed exit"),
    ("entry-exit-required", "item_dispatch.py", (
      'context_io.require(type(entry_exit) is int, "item entry exit status is unknown")',
      ''), ("test_entry_removed_unknown",), "ValueError not raised"),
    ("entry-other-error", "item_dispatch.py", (
      'error.errno not in (errno.ENODEV, errno.ENOENT)',
      'error.errno not in (errno.ENODEV, errno.ENOENT, errno.EACCES, errno.EIO)'),
      ("test_entry_read_error",), "OSError not raised"),
    ("peer-token", "item_dispatch.py", (
      'request.pop("token", None) == self.token', 'request.pop("token", None) is not None'),
      ("test_peer_token",), "ValueError not raised"),
    ("frozen-result", "item_dispatch.py", (RESULT_CALL, 'value = json.loads(result_path.read_bytes())'),
      ("test_missing_assertion", "test_exit_gate"), "RuntimeError not raised"),
    ("collection-once", "item_dispatch.py", (
      'if self.collection_error is not None:',
      'if self.collection_error is not None and self.receipt is not None:'),
      ("test_collection_failure",), "failed collection was retried"),
    ("owner-preserved", "item_dispatch.py", (
      'copy.deepcopy(row.get("observed", {}))', 'dict(row.get("observed", {}), refusal={})'),
      ("test_first_refusal",), "first owner refusal was changed"),
    ("collection-flag", "item_context.py", (
      'receipt.get("temporary_resources_collected") is True',
      'receipt.get("temporary_resources_collected") is not None'),
      ("test_collection_guard",), "ValueError not raised"),
    ("release-operation", "case_grants.py", (
      'receipt.get("operation_id") == operation', 'receipt.get("operation_id") is not None'),
      ("test_release",), "ValueError not raised"),
    ("release-known-zero", "case_grants.py", (
      'type(receipt.get(key)) is int and receipt[key] == 0', 'receipt.get(key) == 0'),
      ("test_release",), "ValueError not raised"),
    ("abort-refusal", "case_grants.py", (
      'failed.get("refusal") or (failed.get("operation") or {}).get("error") or',
      '(failed.get("operation") or {}).get("error") or'),
      ("test_abort_boundary",), "alternate collection was attempted"),
    ("source-alias", "case_grants.py", (
      '"link_target": "private/canary"', '"link_target": "child/input.txt"'),
      ("test_boot",), "canary alias differs"),
    ("runtime-pin", "case_grants.py", (
      '"sha256": io.sha(path)', '"sha256": sha(version)'),
      ("test_boot",), "runtime tool bytes differ"),
    ("boot-resource-id", "case_grants.py", (
      'resource_enrollment = {"provider": "gcp",',
      'resource_enrollment = {"id": "", "provider": "gcp",'),
      ("test_boot",), "resource proposal included an issued grant ID"),
    ("boot-resource-handle", "case_grants.py", (
      'resource_enrollment = {"provider": "gcp",',
      'resource_enrollment = {"source_handle": "", "provider": "gcp",'),
      ("test_boot",), "resource proposal chose a service handle"),
    ("upload-stage-proof", "grants_upload.py", (
      '"method": "secret.stage", "request": str(directory / "stage.json")}',
      '"method": "secret.stage", "request": str(directory / "stage.json"), "proof": "extra.proof.json"}'),
      ("test_upload_plan",), "stage replaced the live session"),
    ("upload-import-proof", "grants_upload.py", (
      '         "proof": str(directory / "import.proof.json")},', '        },'),
      ("test_upload_plan",), "import lost its independent operation proof"),
    ("runtime-mode", "provision.py", (
      '"relative_path": name, "mode": asset["mode"]', '"relative_path": name, "mode": 0o444'),
      ("test_runtime_asset",), "runtime asset mode changed"),
    ("caller-evidence", "run.py", (
      '"launch-" + self.human_prefix + "-" + launch["driver"]', '"launch-" + launch["driver"]'),
      ("test_root_binding",), "root evidence omitted its caller scope"),
    ("capture-operation", "case_grants.py", (
      'event["operation_id"] == record["operation"]["id"]', 'event["operation_id"] is not None'),
      ("test_capture",), "ValueError not raised"),
    ("capture-line-error", "case_grants.py", (
      'raise self.fail("relay primary capture contains a malformed JSON line") from None',
      'raise'), ("test_capture",), "does not match"),
    ("capture-bytes", "case_grants.py", (
      'len(raw) == ref["bytes"] and sha(raw) == ref["sha256"]', 'len(raw) == ref["bytes"]'),
      ("test_capture",), "ValueError not raised"),
    ("summary-inventory", "summary.py", (
      'len(assertions) == len(declared) and\n        {row.get("id") for row in assertions} == set(declared) and',
      'bool(assertions) and'), ("test_summary",), "missing declared item was credited"),
    ("summary-collection", "summary.py", (
      'entry.get("processes_quiescent") is True', 'entry.get("processes_quiescent") is not None'),
      ("test_summary",), "incomplete collection was credited"),
    ("git-hook", "child_task.sh", (
      "-m 'Boundary probe'", ""), ("test_child_task",), "child build or Git hook failed"),
    ("outside-positive", "consumer.py", (
      'assert control.returncode == 41,', 'assert control.returncode in (0, 41),'),
      ("test_outside_probe",), "AssertionError not raised"),
)
BUNDLE_CONTROLS = (
    ("boot-context-level", '"contexts": [{"level": 3, "role": "executor"}]',
     '"contexts": [{"role": "executor"}]', "boot bundle decoder:",
     "field=$.contexts[].level; reason=missing"),
    ("boot-data-id", '{"id": "", "source_object_id": ref["id"]',
     '{"source_object_id": ref["id"]', "boot bundle decoder:",
     "field=$.root_grants.data[].id; reason=missing"),
    ("boot-profile-id", '{"id": "", "profile_id": "serve-profile-" + driver',
     '{"profile_id": "serve-profile-" + driver', "boot bundle decoder:",
     "field=$.root_grants.profiles[].id; reason=missing"),
    ("boot-unselected-child-task", '    sources = []\n',
     '    document("grants-child-task", "task", CHILD_TASK)\n    sources = []\n',
     "admin initial validation:", "initial publication contains an unselected object"),
)
ENROLLMENT_CONTROLS = (
    ("enrollment-resource-id", "resource", 'resource_enrollment = {"provider": "gcp",',
     'resource_enrollment = {"id": "", "provider": "gcp",',
     "enrollment CLI decoder:", "unknown JSON field"),
    ("enrollment-resource-empty-handle", "resource", 'resource_enrollment = {"provider": "gcp",',
     'resource_enrollment = {"source_handle": "", "provider": "gcp",',
     "enrollment CLI decoder:", "invalid object ID"),
    ("enrollment-resource-chosen-handle", "resource", 'resource_enrollment = {"provider": "gcp",',
     'resource_enrollment = {"source_handle": "caller-chosen", "provider": "gcp",',
     "enrollment semantic validator:", "resource enrollment cannot choose a service handle"),
    ("enrollment-secret-id", "secret", 'return {"secret": {"source_handle": imported["source_handle"],',
     'return {"secret": {"id": "", "source_handle": imported["source_handle"],',
     "enrollment CLI decoder:", "unknown JSON field"),
    ("enrollment-secret-empty-handle", "secret", 'return {"secret": {"source_handle": imported["source_handle"],',
     'return {"secret": {"source_handle": "",',
     "enrollment CLI decoder:", "invalid object ID"),
    ("enrollment-secret-invalid-handle", "secret", 'return {"secret": {"source_handle": imported["source_handle"],',
     'return {"secret": {"source_handle": imported["source_handle"] + ".",',
     "enrollment CLI decoder:", "invalid object ID"),
    ("enrollment-secret-substituted-handle", "secret", 'return {"secret": {"source_handle": imported["source_handle"],',
     'return {"secret": {"source_handle": "substituted-source",',
     "secret enrollment changed the imported source selection", "secret enrollment changed the imported source selection"),
    ("enrollment-secret-delivery", "secret", '"version": imported["version"], "delivery": "file",',
     '"version": imported["version"], "delivery": "other",',
     "enrollment CLI decoder:", "unknown schema enum"),
)
UPLOAD_CONTROLS = (
    ("upload-session-reset", "grants_upload.py",
     '        {"name": "task-secret-stage", "method": "secret.stage",',
     '        {"name": "replacement-session", "method": "human.session", "request": str(directory / "replacement.json"), '
     '"proof": str(directory / "replacement.proof.json")},\n'
     '        {"name": "task-secret-stage", "method": "secret.stage",',
     "upload key is absent for this live human read session"),
    ("upload-other-key", "case_grants.py",
     '"config": case.config, "key": key, "name": name, "version": version}',
     '"config": case.config, "key": dict(key, id=uuid.uuid4().hex), "name": name, "version": version}',
     "upload key is absent for this human principal"),
    ("upload-invalid-nonce", "case_grants.py",
     'return json.loads(case.command("grants-seal-canary", [str(tool), "--input", str(sealing)], clean=True))',
     'return dict(json.loads(case.command("grants-seal-canary", [str(tool), "--input", str(sealing)], clean=True)), nonce="")',
     "invalid encrypted secret staging request"),
)


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def prove_producer_inputs(root, modules):
    binary = root / "bundle.test"
    built = subprocess.run(["go", "test", "-c", "-o", str(binary), "./scripts/v2-serve/bundle"],
                           cwd=ROOT, capture_output=True, timeout=180)
    require(built.returncode == 0,
            "bundle regression build failed\n" + (built.stdout + built.stderr).decode())
    binary_sha = sha(binary.read_bytes())
    for test, controls in (("TestGrantsBootBundle", tuple((row[0], "", *row[1:]) for row in BUNDLE_CONTROLS)),
                           ("TestGrantsEnrollmentInputs", ENROLLMENT_CONTROLS)):
        command = [str(binary), "-test.run=^" + test + "$", "-test.v"]
        families = {row[1] for row in controls if row[1]}
        for identifier, family, before, after, assertion, diagnostic in controls:
            require(modules["case_grants.py"].count(before.encode()) == 1,
                    "missing/ambiguous control anchor: " + identifier)
            overlay = root / identifier
            overlay.mkdir()
            for name, raw in modules.items():
                if name not in ("consumer.py", "child_task.sh"):
                    (overlay / name).write_bytes(raw.replace(before.encode(), after.encode(), 1)
                        if name == "case_grants.py" else raw)
            result = subprocess.run(command, cwd=CORE / "bundle", capture_output=True, timeout=120,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                     "LB_GRANTS_CORE": str(overlay)})
            combined = result.stdout + result.stderr
            deciding_test = test + ("/" + family if family else "")
            require(result.returncode == 1 and ("--- FAIL: " + deciding_test + " ").encode() in combined and
                    combined.count(b"--- FAIL:") == 1 + bool(family) and
                    all(("--- PASS: " + test + "/" + other + " ").encode() in combined
                        for other in families - {family}) and
                    assertion.encode() in combined and diagnostic.encode() in combined,
                    "control missed its deciding assertion: " + identifier + "\n" + combined.decode())
            print(json.dumps({"phase": "red", "id": identifier, "test": deciding_test,
                "source": "case_grants.py", "input_sha256": sha(modules["case_grants.py"]),
                "mutated_sha256": sha(modules["case_grants.py"].replace(before.encode(), after.encode(), 1)),
                "before": before, "after": after,
                "test_binary_sha256": binary_sha, "exit_code": result.returncode,
                "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr),
                "assertion": assertion, "diagnostic": diagnostic}, sort_keys=True), flush=True)
            sys.stdout.buffer.write(result.stdout)
            sys.stderr.buffer.write(result.stderr)
        result = subprocess.run(command, cwd=CORE / "bundle", capture_output=True, timeout=120,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        require(result.returncode == 0 and ("--- PASS: " + test + " ").encode() in result.stdout and
                all(("--- PASS: " + test + "/" + family + " ").encode() in result.stdout for family in families),
                "unchanged producer candidate failed: " + test + "\n" + (result.stdout + result.stderr).decode())
        print(json.dumps({"phase": "green", "test": test, "source": "case_grants.py",
            "input_sha256": sha(modules["case_grants.py"]), "test_binary_sha256": binary_sha,
            "exit_code": result.returncode, "stdout_sha256": sha(result.stdout),
            "stderr_sha256": sha(result.stderr)}, sort_keys=True), flush=True)


def prove_native_upload(modules):
    root = Path(tempfile.mkdtemp(prefix="lb-v2-case-grants-upload-")).resolve()
    print("retained native upload controls: " + str(root), flush=True)
    binary = root / "cli.test"
    built = subprocess.run(["go", "test", "-tags", "laneboss_root_canary,laneboss_gate_integration",
        "-c", "-o", str(binary), "./internal/v2/cli"], cwd=ROOT, capture_output=True, timeout=240)
    (root / "build.stdout").write_bytes(built.stdout)
    (root / "build.stderr").write_bytes(built.stderr)
    (root / "build.exit.json").write_text(json.dumps({"exit_code": built.returncode}) + "\n")
    require(built.returncode == 0, "native upload regression build failed\n" + (built.stdout + built.stderr).decode())
    source = root / "source"
    source.mkdir()
    for name, raw in modules.items():
        (source / name).write_bytes(raw)
    for relative in ("internal/v2/cli/session_wire_linux_test.go", "scripts/v2-serve/grants_seal/main.go",
                     "e2e/v2/cases/grants/upload_probe.py", "e2e/v2/cases/grants/boot_bundle_input.py"):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    command = [str(binary), "-test.run=^TestSessionWire/grants$", "-test.v"]
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
    for name in ("HOME", "GOCACHE", "GOMODCACHE", "GOTOOLCHAIN", "GOFLAGS"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    for identifier, name, before, after, diagnostic in UPLOAD_CONTROLS:
        require(modules[name].count(before.encode()) == 1, "missing/ambiguous upload anchor: " + identifier)
        overlay = root / identifier
        overlay.mkdir()
        for key, raw in modules.items():
            if key not in ("consumer.py", "child_task.sh"):
                (overlay / key).write_bytes(raw.replace(before.encode(), after.encode(), 1) if key == name else raw)
        result = subprocess.run(command, cwd=ROOT / "internal/v2/cli", capture_output=True, timeout=300,
            env=dict(environment, LB_GRANTS_CORE=str(overlay), LB_GRANTS_UPLOAD_EVIDENCE=str(overlay)))
        (root / (identifier + ".stdout")).write_bytes(result.stdout)
        (root / (identifier + ".stderr")).write_bytes(result.stderr)
        combined = result.stdout + result.stderr
        record = {"phase": "red", "id": identifier, "test": "TestSessionWire/grants",
            "source": name, "before": before, "after": after, "input_sha256": sha(modules[name]),
            "mutated_sha256": sha(modules[name].replace(before.encode(), after.encode(), 1)),
            "test_binary_sha256": sha(binary.read_bytes()), "exit_code": result.returncode,
            "sealer_sha256": sha((overlay / "grants-seal.input").read_bytes())
                if (overlay / "grants-seal.input").exists() else None,
            "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr),
            "assertion": "actual grants staging failed", "diagnostic": diagnostic}
        (root / (identifier + ".json")).write_text(json.dumps(record, sort_keys=True) + "\n")
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        require(result.returncode == 1 and b"--- FAIL: TestSessionWire/grants " in combined and
                combined.count(b"--- FAIL:") == 2 and b"actual grants staging failed" in combined and
                diagnostic.encode() in combined, "native upload control missed its deciding assertion: " + identifier)
        print(json.dumps(record, sort_keys=True), flush=True)
    retained = root / "candidate"
    retained.mkdir()
    result = subprocess.run(command, cwd=ROOT / "internal/v2/cli", capture_output=True, timeout=300,
        env=dict(environment, LB_GRANTS_UPLOAD_EVIDENCE=str(retained)))
    (root / "candidate.stdout").write_bytes(result.stdout)
    (root / "candidate.stderr").write_bytes(result.stderr)
    (root / "candidate.exit.json").write_text(json.dumps({"exit_code": result.returncode,
        "sealer_sha256": sha((retained / "grants-seal.input").read_bytes())
            if (retained / "grants-seal.input").exists() else None}) + "\n")
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    require(result.returncode == 0 and b"--- PASS: TestSessionWire/grants " in result.stdout,
            "unchanged native upload candidate failed")


def main():
    require(sys.platform == "linux" and os.geteuid() == 0,
            "controls require the authorized disposable Linux root observer")
    modules = {path.name: path.read_bytes() for path in CORE.glob("*.py")
               if not path.name.endswith("_test.py")}
    modules["consumer.py"] = (HERE / "run.py").read_bytes()
    modules["child_task.sh"] = (HERE / "child_task.sh").read_bytes()
    print(json.dumps({"scope": "harness controls only", "source_inputs": {
        key: {"sha256": sha(raw), "bytes": len(raw)} for key, raw in modules.items()}}, sort_keys=True), flush=True)
    with tempfile.TemporaryDirectory(prefix="lb-grants-proof-") as temporary:
        root = Path(temporary).resolve()
        for identifier, name, patch, tests, diagnostic in CONTROLS:
            before, after = (value.encode() for value in patch)
            require(modules[name].count(before) == 1, "missing/ambiguous control anchor: " + identifier)
            overlay = root / identifier
            core = overlay / "scripts" / "v2-serve"
            core.mkdir(parents=True)
            for key, raw in modules.items():
                if key not in ("consumer.py", "child_task.sh"):
                    (core / key).write_bytes(raw.replace(before, after, 1) if key == name else raw)
            cases = overlay / "e2e" / "v2" / "cases" / "grants"
            cases.mkdir(parents=True)
            for key in ("case.json", "observer.py", "child_probe.c"):
                shutil.copyfile(HERE / key, cases / key)
            (cases / "run.py").write_bytes(modules["consumer.py"].replace(before, after, 1)
                if name == "consumer.py" else modules["consumer.py"])
            (cases / "child_task.sh").write_bytes(modules["child_task.sh"].replace(before, after, 1)
                if name == "child_task.sh" else modules["child_task.sh"])
            for key in ("manifests.py", "support.py", "lane_handoff.py"):
                shutil.copyfile(ROOT / "e2e" / "v2" / key, overlay / "e2e" / "v2" / key)
            admin = overlay / "scripts" / "v2-admin"
            admin.mkdir()
            shutil.copyfile(ROOT / "scripts" / "v2-admin" / "boot.py", admin / "boot.py")
            environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                "LB_GRANTS_CORE": str(core), "LB_GRANTS_CONSUMER": str(cases / "run.py"),
                "LB_GRANTS_TASK": str(cases / "child_task.sh")}
            command = [sys.executable, "-B", str(HERE / "wiring_test.py"),
                       *["Wiring." + test for test in tests], "-v"]
            result = subprocess.run(command, capture_output=True, timeout=120, env=environment)
            combined = result.stdout + result.stderr
            require(result.returncode == 1 and b"ERROR:" not in combined and
                    diagnostic.encode() in combined and
                    all(("FAIL: " + test).encode() in combined for test in tests) and
                    ("Ran %d test" % len(tests)).encode() in combined,
                    "control missed its deciding assertion: " + identifier + "\n" + combined.decode())
            print(json.dumps({"phase": "red", "id": identifier, "tests": tests,
                "source": name, "input_sha256": sha(modules[name]),
                "mutated_sha256": sha(modules[name].replace(before, after, 1)),
                "before": patch[0], "after": patch[1], "exit_code": result.returncode,
                "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr),
                "diagnostic": diagnostic}, sort_keys=True), flush=True)
        prove_producer_inputs(root, modules)
        prove_native_upload(modules)
        command = [sys.executable, "-B", str(HERE / "wiring_test.py"), "-v"]
        result = subprocess.run(command, capture_output=True, timeout=180,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        require(result.returncode == 0 and b"\nOK\n" in result.stderr and b"skipped" not in result.stderr,
                "unchanged wiring candidate failed")
        require(all((CORE / key).read_bytes() == raw for key, raw in modules.items()
                    if key not in ("consumer.py", "child_task.sh")) and
                (HERE / "run.py").read_bytes() == modules["consumer.py"] and
                (HERE / "child_task.sh").read_bytes() == modules["child_task.sh"], "original source changed during controls")
    print("PASS: grants wiring red/candidate controls", flush=True)


if __name__ == "__main__":
    main()

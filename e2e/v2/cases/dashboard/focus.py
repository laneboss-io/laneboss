"""Run targeted Python RED before GREEN, only on disposable Linux.

Mutants contain deliberately broken acceptance checks. They are never used by
the candidate or installed service. Only case-owned source files are copied;
there is no source archive, catalog-wide scan, Go build or model request.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


CASE_DIR = Path("e2e/v2/cases/dashboard")
PRODUCER = Path("scripts/v2-serve/case_dashboard.py")
DATA = Path("scripts/v2-serve/dash_data.py")
CHILD = Path("scripts/v2-serve/item_test_child.py")
CASE = CASE_DIR / "case.py"
IO = CASE_DIR / "fixture_io.py"
VIEWS = CASE_DIR / "view_checks.py"


def controls():
    rows = []
    def add(test, path, before, after, diagnostic):
        rows.append((test, path, before, after, diagnostic))
    for test, diagnostic in (
            ("empty", "empty dashboard view passed"), ("malformed", "malformed dashboard view passed"),
            ("pins", "unbound resource bytes passed"), ("plugin", "unverified plugin passed"),
            ("approvals", "unrelated approval/application passed"), ("raw", "duplicate raw records passed")):
        add("test_views.ViewTests.test_" + test, VIEWS, "def populated(aid, value):",
            "def populated(aid, value):\n    return True", diagnostic)
    add("test_views.ViewTests.test_eight", VIEWS, "def populated(aid, value):",
        "def populated(aid, value):\n    return False", "real populated shape was rejected")
    add("test_views.ViewTests.test_cli", VIEWS, "def cli_passed(probe):",
        "def cli_passed(probe):\n    return True", "failed or unauthorized CLI probe passed")
    add("test_views.ViewTests.test_denials", VIEWS, "def denied(status, raw, allowed, stale=False):",
        "def denied(status, raw, allowed, stale=False):\n    return True", "status-only refusal passed")
    add("test_views.ViewTests.test_denials", VIEWS, "def denied(status, raw, allowed, stale=False):",
        "def denied(status, raw, allowed, stale=True):", "non-stale missing receipt passed as an authentication refusal")
    add("test_inputs.InputTests.test_private_bytes", IO, "    return raw\n\n\ndef private_dir",
        '    return b""\n\n\ndef private_dir', "private input bytes were reserialized")
    add("test_inputs.InputTests.test_immutable", IO, "if path.exists() or path.is_symlink():", "if False:", "ValueError not raised")
    add("test_inputs.InputTests.test_cli_handoff", IO,
        'raise ValueError("CLI proof does not authorize the empty human.session prelude")',
        'return value["proof_file"]', "ValueError not raised")
    add("test_inputs.InputTests.test_action_bytes", IO, "return self.wires[aid]",
        "return json.dumps(self.cache[aid]).encode()", "exact action wire bytes changed")
    add("test_inputs.InputTests.test_exchange", IO, 'return result["result"]',
        'return {"unrelated": True}', "handoff returned a different actual response")
    add("test_inputs.InputTests.test_exact_error", IO, 'raise FixtureError(result["error"])',
        'return result["error"]', "FixtureError not raised")
    add("test_inputs.InputTests.test_timeout", IO, '"code": "deadline_exceeded"',
        '"code": "invalid_request"', "deadline_exceeded")
    add("test_inputs.InputTests.test_failed_collection", IO, 'return self.exchange("collect", "external", failure)',
        'return self.exchange("collect", "external")', "expected call not found")
    add("test_inputs.InputTests.test_collection", IO, "def _external_collected(report, required):",
        "def _external_collected(report, required):\n    return False", "measured complete collection was rejected")
    for test, diagnostic in (("targets", "unmeasured external collection passed"),
                              ("history", "resume history was not collected"), ("https", "uncollected HTTPS/session passed")):
        add("test_inputs.InputTests.test_collection_" + test, IO, "def _external_collected(report, required):",
            "def _external_collected(report, required):\n    return True", diagnostic)
    add("test_actions.ActionTests.test_same_operation", CASE,
        'or polled.get("result", {}).get("id") != operation_id', 'or False', "foreign operation completion passed")
    add("test_actions.ActionTests.test_resume_run", CASE, 'read_params["run"] += 1',
        'read_params["run"] += 0', "resume read-back requested the previous run")
    add("test_actions.ActionTests.test_owner_refusal", CASE,
        'if response.get("error"):\n        raise FixtureError(response["error"])',
        'if response.get("error"):\n        response = dict(response)', "FixtureError not raised")
    add("test_actions.ActionTests.test_mail_readback", CASE,
        'and mail.get("source") == result.get("source")', 'and True', "changed immutable mail read-back passed")
    add("test_actions.ActionTests.test_cli_failure_stops_http", CASE,
        'if not all(cli_passed(probes.get(aid, {})) for aid, _ in VIEW_ASSERTIONS):',
        'if False:', "unauthorized CLI read allowed dependent HTTP actions")
    add("test_producer.ProducerTests.test_native_gate", PRODUCER, "def check_handoff(handoff):",
        "def check_handoff(handoff):\n    return None", "FixtureError not raised")
    add("test_producer.ProducerTests.test_cookie", PRODUCER, 'cookie.value == result.get("id")',
        "False", "ValueError not raised")
    add("test_producer.ProducerTests.test_bootstrap_owner_error", PRODUCER,
        'raise FixtureError(reply["error"])', 'raise FixtureError({"code": "rewritten"})',
        "native bootstrap refusal was reworded")
    add("test_producer.ProducerTests.test_https_origin", CASE, 'parsed.scheme != "https"',
        "False", "ValueError not raised")
    add("test_producer.ProducerTests.test_collection_processes", PRODUCER, "listener_errno = error.errno",
        "listener_errno = 0", "listener closure evidence did not use actual errno")
    add("test_producer.ProducerTests.test_bookkeeping", PRODUCER,
        "case.rows, case.current, case.human_prefix = shared_rows, shared_current, shared_prefix",
        "case.current, case.human_prefix = shared_current, shared_prefix", "producer changed shared check registry")
    add("test_producer.ProducerTests.test_result", PRODUCER, "def validate_result(result, context, assertion_ids):",
        "def validate_result(result, context, assertion_ids):\n    return None", "ValueError not raised")
    add("test_data.DataTests.test_mail_target", DATA, "proof_target = self.case.config",
        'proof_target = lane["life_id"]', "mail proof used recipient instead of authorization target")
    add("test_data.DataTests.test_stop_live", DATA, 'self.observe(record, running=True)\n            params["reason"]',
        'self.observe(record, running=False)\n            params["reason"]', "expected call not found")
    add("test_data.DataTests.test_resume_generation", DATA,
        'params["expected_generation"], generation = lane["generation"], lane["generation"]',
        'params["expected_generation"], generation = params["expected_generation"], generation',
        "resume proof used generation before terminal observation")
    add("test_data.DataTests.test_review", DATA, 'self.browser.rpc("lane.review", review, proof)',
        'self.browser.rpc("lane.status", review, proof)', "merged did not invoke genuine service review")
    add("test_data.DataTests.test_partial_review", DATA, 'receipt.get("coverage") == "complete"',
        "True", "ValueError not raised")
    add("test_data.DataTests.test_abandon", DATA, 'params.update({"state": "abandoned", "review": empty_review()})',
        'params.update({"state": "abandoned", "review": {}})', "abandonment request lost the typed zero review")
    add("test_case.CaseTests.test_poll_headers", CASE, "response_headers = poll_headers",
        "response_headers = response_headers", "operation poll reused initial presence headers")
    add("test_case.CaseTests.test_service_event", CASE, "def service_state_seen(frames, target, readback, since=0):",
        "def service_state_seen(frames, target, readback, since=0):\n    return True", "terminal SSE frame passed")
    add("test_case.CaseTests.test_no_positive", CASE, "return bool(red_denied and positive_ok)",
        "return bool(red_denied)", "refusal-only evidence passed an action")
    for test, diagnostic in (("pending", "pending operation passed"), ("readback", "stale lane projection passed"),
                              ("presence", "simulated action passed without presence reporting")):
        add("test_case.CaseTests.test_" + test, CASE,
            "def positive_observed(method, request, status, response, readback, headers):",
            "def positive_observed(method, request, status, response, readback, headers):\n    return True", diagnostic)
    add("test_g0.G0Tests.test_g0_import", PRODUCER, "def boot(case):", "def boot_absent(case):",
        "G0 dashboard producer entry is missing")
    add("test_g0.G0Tests.test_boot", PRODUCER, 'raw = path.read_bytes()',
        'raw = path.read_bytes() + b"changed"', "G0 boot source bytes differ from measured templates")
    add("test_g0.G0Tests.test_prepare_gate", PRODUCER,
        'case.human_prefix = "itemdashboard"\n    case.current = "item.dashboard.prepare"',
        'case.human_prefix = "dashboard"\n    case.current = "item.dashboard.prepare"',
        "G0 preparation used the baseline human proof catalog")
    add("test_g0.G0Tests.test_transport", PRODUCER,
        'self.case.human_prefix = "itemdashboard"\n        self.case.current = "item.dashboard.run"',
        'self.case.human_prefix = "dashboard"\n        self.case.current = "item.dashboard.run"',
        "fresh CLI proof used another scope")
    add("test_g0.G0Tests.test_transport_failure", PRODUCER, 'if self.failure:\n                raise FixtureError(self.failure)',
        'if False:\n                raise FixtureError(self.failure)', "G0 repeated a mutation after its refused gate")
    add("test_g0.G0Tests.test_observer_reply", IO, 'return response["result"]',
        'return {"different": True}', "G0 input response was substituted")
    add("test_g0.G0Tests.test_observer_collection", IO,
        'len(raw) != ref["bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]',
        'len(raw) != ref["bytes"]', "ValueError not raised")
    add("test_g0.G0Tests.test_cached_collection", PRODUCER,
        'self.require(set(operation_ids) <= set(self.receipt["operation_ids"]),',
        'self.require(True,', "ValueError not raised")
    add("test_g0.G0Tests.test_prefix", DATA,
        'self.prefix = self.initial_prefix if self.initial_prefix.startswith("item") else "dashboard"',
        'self.prefix = "dashboard"', "producer replaced the G0 human prefix")
    add("test_g0.G0Tests.test_prefix", DATA,
        'self.case.current = "item.dashboard." + self.phase',
        'self.case.current = "item.dashboard.prepare"', "G0 action overwrote the preparation row")
    add("test_binding.BindingTests.test_factory", DATA, 'request["budget"] = case.dashboard_boot["budget"]',
        'request["budget"] = {}', "fixture factory lost the installed budget")
    add("test_binding.BindingTests.test_review_missing", DATA,
        '"owner": "lb-v2-grants", "code": "prerequisite_missing",\n            "message": "native review preparation',
        '"owner": "lb-v2-dashboard", "code": "prerequisite_missing",\n            "message": "native review preparation', "lb-v2-grants")
    add("test_binding.BindingTests.test_native_proof", PRODUCER,
        'proof.get("simulated_presence") is True,\n        "native confirmation lacks',
        'True,\n        "native confirmation lacks', "ValueError not raised")
    add("test_binding.BindingTests.test_https_read", CASE, 'ssl.create_default_context(cafile=ca_file)',
        'ssl._create_unverified_context()', "TLS accepted a certificate for another hostname")
    add("test_binding.BindingTests.test_startup_tracking", PRODUCER, 'case.dashboard_native.append(self)',
        'case.dashboard_native.extend([])', "native startup lost its owned child before readiness")
    add("test_binding.BindingTests.test_populate_refusal", PRODUCER,
        'self.failure = getattr(error, "error", None) or row.get("refusal") or {\n                "owner": "lb-v2-dashboard", "code": "fixture_incomplete"',
        'self.failure = None or row.get("refusal") or {\n                "owner": "lb-v2-dashboard", "code": "fixture_incomplete"', "preparation lost the exact owning refusal")
    add("test_pipeline.PipelineTests.test_partial_relay", DATA,
        'frame.get("subtype") == "dashboard-fixture"', 'frame.get("subtype") == "unrelated"',
        "partial capture was not reassembled into its actual relay value")
    add("test_pipeline.PipelineTests.test_relay_scope", DATA,
        'event.get("operation_id") == relay.record["operation"]["id"]', 'True',
        "foreign capture became relay authority")
    add("test_pipeline.PipelineTests.test_gap_binding", DATA,
        'gap.get("target") == record.get("target")', 'True',
        "unrelated gap passed as partial capture evidence")
    add("test_pipeline.PipelineTests.test_review_producer", DATA,
        'request = result["request"]', 'request = dict(result["request"], refusal_resolution=["different"])',
        "native producer candidate references were replaced")
    add("test_pipeline.PipelineTests.test_review_gate", DATA,
        'if result.get("missing_checks"):', 'if False:',
        "missing measured test job passed review preparation")
    add("test_pipeline.PipelineTests.test_review_subject", DATA,
        'result.get("subject", {}).get("target") == target and result.get("required_checks")', 'result.get("required_checks")',
        "foreign frozen subject passed review preparation")
    add("test_pipeline.PipelineTests.test_requirements", DATA,
        '"policy_generation": generation', '"policy_generation": generation + 1',
        "protected requirement generation was replaced")
    add("test_binding.BindingTests.test_factory", DATA,
        'proposals["claudock-cli"] if aid == "DASH-MERGED" else proposals["codex"]', 'proposals["codex"]',
        "review fixture lacks actual Claudock tool coverage")
    add("test_pipeline.PipelineTests.test_fake_asset", PRODUCER,
        '"role": "dashboard-fake-judge"', '"role": "unmarked"',
        "scored source was not explicitly enrolled as a fake")
    add("test_pipeline.PipelineTests.test_accounting", DATA,
        'data.browser.rpc("policy.evaluate", request)', 'data.browser.rpc("policy.get", request)',
        "fixture did not dispatch the actual policy evaluator")
    add("test_pipeline.PipelineTests.test_accounting_source", DATA,
        'replies and all(reply.get("reported_model") == "dashboard-fake-sha256-question-v1" for reply in replies)', 'True',
        "scored accounting accepted an unmarked source")
    add("test_pipeline.PipelineTests.test_accounting_input", DATA,
        'observation.get("request") == request', 'True',
        "accounting accepted unrelated retained request bytes")
    add("test_pipeline.PipelineTests.test_accounting_audit", DATA,
        'decision.get("audit_complete") is True', 'True',
        "accounting accepted a missing policy audit")
    add("test_data.DataTests.test_accept_readback", DATA,
        'lane.get("state") == "accepted"', 'True',
        "merged request passed without accepted read-back")
    add("test_pipeline.PipelineTests.test_test_child", DATA,
        'data.browser.rpc("grants.test-child", request, proof)', 'data.browser.rpc("lane.check", request, proof)',
        "TestChild was not dispatched through the actual public service")
    add("test_pipeline.PipelineTests.test_test_child_subject", DATA,
        'result.get("subject", {}).get("target") == target and not result.get("missing_checks")', 'not result.get("missing_checks")',
        "completed test selected another frozen subject")
    add("test_pipeline.PipelineTests.test_fake_asset", PRODUCER,
        '"role": "tool"', '"role": "unmarked"',
        "candidate check executable is not enrolled from the measured actor")
    add("test_data.DataTests.test_capture_ready", DATA,
        'self.read("event.tail", params)', 'self.read("lane.status", params)',
        "capture readiness did not read actual run events")
    add("test_data.DataTests.test_capture_eof", DATA,
        'streams and streams <= closed', 'streams and bool(closed)',
        "one committed EOF passed as the entire primary capture")
    add("test_pipeline.PipelineTests.test_fake_asset", PRODUCER,
        'baseline_root = dict(root, data=[])', 'baseline_root = dict(root)',
        "dashboard fixture widened baseline materialization")
    add("test_pipeline.PipelineTests.test_root_binding", DATA,
        '"parent_grant_id": member["id"]', '"parent_grant_id": grants["id"]',
        "case root selected a data grant other than the actual issued member")
    add("test_pipeline.PipelineTests.test_root_source", DATA,
        'row.get("source_sha256") == tree["sha256"]', 'True',
        "case root accepted another project source digest")
    add("test_pipeline.PipelineTests.test_root_policy", DATA,
        'grants.get("policy_generation") == request["expected_policy_generation"]', 'True',
        "case root accepted another policy generation")
    for test, before, after, diagnostic in (
        ("result", '"capture": capture', '"capture": {name: "" for name in capture}',
         "TestChild discarded its actual primary output"),
        ("operation", 'selected.get("id") == submitted["id"]', 'True', "foreign TestChild operation passed"),
        ("pending", 'selected is not submitted and selected["status"] == "succeeded"', 'selected is not submitted',
         "pending TestChild response received completion credit"),
        ("event_scope", 'event.get("run") == target["run"]', 'True', "foreign worker event passed TestChild"),
        ("plan", 'plan.get("input") == request["candidate"]', 'True', "TestChild accepted another candidate in the sealed plan"),
        ("output_hash", 'hashlib.sha256(raw).hexdigest() == ref.get("sha256")', 'True', "TestChild accepted changed worker output bytes"),
        ("worker", 'worker.get("kind") == "test"', 'True', "another worker kind passed TestChild"),
        ("capture_range", 'value.get("offset") == len(output[name])', 'True', "discontinuous TestChild primary output passed"),
        ("capture_origin", 'value.get("primary") is True', 'True', "nonprimary TestChild output passed"),
        ("eof", 'closed == set(streams)', 'True', "one EOF passed as drained TestChild output"),
        ("release", 'release.get("quiescence", {}).get("handle", {}).get("id") == binding["launch_id"]', 'True',
         "another native worker release passed TestChild"),
        ("native", 'outside = native_release(self.case, release, target, operation["id"])', 'outside = {}',
         "Expected 'native_release' to be called once"),
        ("native_journal", 'worker.get("Collected") is True', 'True', "uncollected nested TestChild helper worker passed"),
        ("check_subject", 'check.get("snapshot_sha256") == subject.get("snapshot", {}).get("sha256")', 'True',
         "TestChild accepted a check for another frozen subject"),
        ("check_worker", 'check.get("worker_lease_id") == binding["worker_lease_id"]', 'True',
         "TestChild accepted a check from another worker"),
        ("required", 'set(required) <= set(names)', 'True', "TestChild omitted a required measured check"),
        ("refusal", 'self.failure = error\n            raise\n\n    def complete', 'self.failure = None\n            raise\n\n    def complete',
         "TestChild retried after its native refusal"),
        ("transport", 'runner.complete(message["request"], operation)', 'operation = operation',
         "TestChild transport did not await and measure its worker"),
        ("transport_refusal", 'NativeFailure(json.loads(base64.b64decode(response["stderr"], validate=True)))',
         'NativeFailure({"code": "rewritten"})', "TestChild transport lost the exact native refusal"),
        ("collection", 'receipt = dict(receipt, evidence=[*receipt["evidence"], ref])',
         'receipt = dict(receipt, evidence=[*receipt["evidence"], ref], operation_ids=list(operations))',
         "nested TestChild operation was omitted from collection")):
        add("test_test_child.TestChildTests.test_" + test, CHILD, before, after, diagnostic)
    add("test_test_child.TestChildTests.test_dispatch", Path("scripts/v2-serve/item_dispatch.py"),
        'prepared = sibling("item_test_child").bind(case, prepared, context_io)', 'prepared = prepared',
        "dispatcher did not bind TestChild before populate")
    add("test_test_child.TestChildTests.test_grants_native_observer", Path("scripts/v2-serve/case_grants.py"),
        'return sibling("item_test_child").nested_native_zero(case, receipt, sibling("provision").read_protected)',
        'return {"not_measured": True}', "grants collector ignored native TestChild journal observer")
    return rows


def run(command, directory, evidence):
    result = subprocess.run(command, cwd=directory, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.with_suffix(".stdout").write_bytes(result.stdout)
    evidence.with_suffix(".stderr").write_bytes(result.stderr)
    value = {"argv": command, "exit": result.returncode, "stdout": result.stdout.decode(),
             "stderr": result.stderr.decode(), "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
             "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
    evidence.with_suffix(".json").write_text(json.dumps(value) + "\n")
    # The queue independently collects its full verify.log. Exact output is
    # serialized here too, so deleting the test box loses no control evidence.
    print(json.dumps({"control_output": value}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run only on the authorized disposable Linux test machine")
    source, evidence = args.source.resolve(strict=True), args.evidence.resolve()
    if evidence.is_relative_to(source) or source.is_relative_to(evidence) or evidence.exists():
        parser.error("use a fresh evidence directory disjoint from source")
    evidence.mkdir(mode=0o700, parents=True)
    files = sorted([*source.joinpath(CASE_DIR).glob("*.py"), source / CASE_DIR / "scored-judge.json", source / PRODUCER, source / DATA, source / CHILD,
        source / "scripts/v2-serve/item_context.py", source / "scripts/v2-serve/item_dispatch.py",
        source / "scripts/v2-serve/case_grants.py", source / "scripts/v2-serve/lifecycle.py",
        source / "scripts/v2-serve/fixtures/README.md",
        *source.joinpath("templates/v2/roles/L3").glob("reviewer.*"),
        *source.joinpath("templates/v2/roles/L6").glob("supervisor.*")])
    hashes = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    print(json.dumps({"scope": "dashboard Python unit and acceptance-classifier controls", "source_files": hashes}), flush=True)
    results = []
    for index, (test, relative, before, after, diagnostic) in enumerate(controls(), 1):
        mutant = evidence / ("red-%02d" % index) / "source"
        for path in files:
            target = mutant / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        path = mutant / relative
        original = path.read_text()
        if original.count(before) != 1:
            raise RuntimeError("red mutation anchor is missing or ambiguous: " + test)
        changed = original.replace(before, after, 1)
        path.write_text(changed)
        mutation = {"test": test, "file": str(relative), "before": before, "after": after,
                    "source_sha256": hashlib.sha256(original.encode()).hexdigest(),
                    "mutant_sha256": hashlib.sha256(changed.encode()).hexdigest()}
        print(json.dumps({"mutation": mutation}), flush=True)
        command = [sys.executable, "-B", "-m", "unittest", "-f", "-q", test]
        red = run(command, mutant / CASE_DIR, mutant.parent / "red")
        stderr = red.stderr.decode()
        if (red.returncode != 1 or "Ran 1 test" not in stderr or "ERROR" in stderr
                or "FAIL:" not in stderr or diagnostic not in stderr):
            raise RuntimeError("red control missed its intended assertion: " + test)
        green = run(command, source / CASE_DIR, mutant.parent / "green")
        if green.returncode != 0 or "Ran 1 test" not in green.stderr.decode() or "\nOK\n" not in green.stderr.decode():
            raise RuntimeError("candidate focused test failed: " + test)
        results.append({"test": test, "red_exit": red.returncode, "green_exit": green.returncode})
        print("PASS RED/GREEN " + test, flush=True)
    candidate = run([sys.executable, "-B", "-m", "unittest", "discover", "-q", "-s", str(source / CASE_DIR),
                     "-p", "test_*.py"], source, evidence / "candidate")
    if candidate.returncode != 0:
        raise RuntimeError("candidate unit suite failed")
    summary = {"controls": len(results), "results": results, "unit_exit": candidate.returncode,
               "scope": "Linux unit controls; installed E2E not measured", "source_files": hashes}
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"summary": summary}), flush=True)
    print("PASS: dashboard focused controls", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Print the reached failing step/owner without hiding unreached FAIL rows."""

import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("serve_steps", Path(__file__).with_name("lifecycle.py"))
steps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(steps)

INITIAL_STAGES = {"initial_publish." + stage for stage in (
    "native_context", "protected_read", "load_validate", "bundle_validate", "object_hashes", "policy_validate", "template_validate",
    "revalidate", "plan", "seal", "commit", "read_object", "read_back", "total")}


def expected_checks(scope, reply=False, fake=False):
    if scope == "installed-lifecycle":
        return list(steps.checks(reply=reply, fake=fake))
    if scope == "serve-state":
        return list(steps.STATE_CHECKS)
    return []


def with_item(checks, case_id):
    human = "human.item" + case_id + "."
    proof_rows = [human + operation + "." + stage for operation in
                  ("session", "grants", "ticket", "read", "control")
                  for stage in ("challenge", "confirm")]
    proof_rows += [human + operation for operation in ("session", "grants", "ticket")]
    stages = ("boot", "prepare", "reuse", "run", "collection") if case_id == "grants" else (
        "boot", "prepare", "run", "collection")
    rows = ["item." + case_id + "." + stage for stage in stages]
    if case_id == "dashboard":
        proof_rows += [human + operation + "." + stage for operation in ("invite", "approve")
                       for stage in ("challenge", "confirm")]
        proof_rows += ["human.other.read." + stage for stage in ("challenge", "confirm")]
        rows += ["capture.other.enroll", "capture.other.read"]
    return tuple([name for name in checks if name != "cleanup"] + proof_rows + rows + ["cleanup"])


def item_passed(item, case_id):
    if not isinstance(item, dict):
        return False
    assertions = (item.get("result") or {}).get("assertions", [])
    manifest = Path(__file__).resolve().parents[2] / "e2e" / "v2" / "cases" / case_id / "case.json"
    declared = json.loads(manifest.read_bytes())["assertion_ids"]
    receipt, entry = item.get("collection") or {}, item.get("entry_collection") or {}
    return (item.get("exit_code") == 0 and len(assertions) == len(declared) and
        {row.get("id") for row in assertions} == set(declared) and
        all(row.get("reached") is True and row.get("verdict") == "pass" for row in assertions) and
        receipt.get("processes_quiescent") is True and
        receipt.get("temporary_resources_collected") is True and bool(receipt.get("evidence")) and
        entry.get("processes_quiescent") is True and bool(entry.get("evidence")))


def owners(check):
    if check.startswith("item."):
        return ["lb-v2-" + check.split(".")[1], "lb-v2-serve"]
    if check in ("admin.publish", "admin.publish.retry", "admin.publication"):
        return ["lb-v2-admin", "lb-v2-service", "lb-v2-serve"]
    if check == "human.enroll.attestation":
        return ["lb-v2-serve"]
    if check.startswith("human.enroll"):
        return ["lb-v2-admin", "lb-v2-identity", "lb-v2-service"]
    if check.startswith("human."):
        return ["lb-v2-grants"] if check.endswith(".grants") else ["lb-v2-identity"]
    if check.startswith("lane.") and check.endswith(".inputs"):
        return ["lb-v2-admin", "lb-v2-grants"]
    if check.startswith("lane.") and check.endswith(".reason"):
        return ["lb-v2-service"]
    if check.startswith(("lane.", "state.")):
        return ["lb-v2-lifecycle"]
    if check.startswith(("admin.", "namespace.")) or check in ("boot.inputs", "installation", "root.stage"):
        return ["lb-v2-admin"]
    if check in ("serve", "health"):
        return ["lb-v2-service", "lb-v2-serve"]
    return ["lb-v2-serve"]


def errors(observed, *, journals=True):
    result = []
    if observed.get("code") == "not_implemented":
        result.append(observed)
    if observed.get("refusal"):
        result.append(observed["refusal"])
    if isinstance(observed.get("error"), dict) and observed["error"] not in result:
        result.append(observed["error"])
    operation = observed.get("operation")
    if isinstance(operation, dict) and operation.get("error") and operation["error"] not in result:
        result.append(operation["error"])
    if journals:
        for journal in observed.get("journal_refusals", []):
            result.extend(row["error"] for row in journal["refusals"])
    return result


def row_passed(row, mode=None):
    observed = row.get("observed", {})
    return (row.get("result") == "pass" and observed.get("executed") is True and
            row.get("presence") in ("simulated", "not_applicable") and
            not errors(observed) and not observed.get("error") and
            (mode != "fake-key" or steps.fake_row_passed(row["check"], observed)) and
            (not row["check"].startswith(("human.", "lane.", "state.")) or row.get("presence") == "simulated"))


def reply_diagnostics(observed):
    """Allow-list the probe's value-free facts for untruncated box logs."""
    data = observed.get("diagnostics", {})
    process = data.get("process", {})
    result = {field: data.get(field) for field in (
        "capture_records", "snapshot_complete", "deadline_hit", "elapsed_ms", "lane_state", "end_reason",
        "phase", "wait_elapsed_ms", "read_elapsed_ms", "read_window_ms")}
    result["process"] = {field: process.get(field) for field in (
        "state", "exited", "exit_code", "signal", "survivors")}
    result["streams"] = [{field: stream.get(field) for field in (
        "stream", "records", "bytes", "read_records", "read_bytes", "read_pages", "max_read_page_bytes", "closed", "closed_bytes",
        "result_events", "non_json_lines", "pending_line_bytes")}
        for stream in data.get("streams", [])]
    result["event_kinds"] = data.get("event_kinds", [])
    return result


def describe(report):
    if not isinstance(report, dict):
        return False, "FAIL: report\nstep=report reason=report is absent or not an object"
    checks = report.get("checks") or []
    names = [row["check"] for row in checks]
    mode = report.get("reply_mode")
    required = expected_checks(report.get("scope"), reply=mode is not None, fake=mode == "fake-key")
    item_case = report.get("item_case")
    if item_case:
        required = list(with_item(required, item_case))
    marked = report.get("presence") == "simulated" and report.get("human_approval") == "not_proven"
    complete = (mode in (None, "real-key", "fake-key") and bool(required) and names == required and report.get("required_checks") == required and
                len(set(names)) == len(names))
    passed = complete and marked and not report.get("failure") and all(row_passed(row, mode) for row in checks)
    if mode is not None:
        reply = next((row for row in checks if row["check"] == "lane.claudock.reply"), {})
        passed = passed and steps.reply_passed(reply.get("observed", {}), mode)
    if item_case:
        passed = passed and item_passed(report.get("item_result"), item_case)
    status = "PASS" if passed else "FAIL"
    lines = ["%s: %s; presence=%s; human_approval=%s" % (status, report.get("scope", "unreported"),
             report.get("presence", "unreported"), report.get("human_approval", "unreported"))]
    reply_row = next((row for row in checks if row["check"] == "lane.claudock.reply"), {})
    if reply_row.get("observed", {}).get("diagnostics") is not None:
        lines.append("reply diagnostics " + json.dumps(reply_diagnostics(reply_row["observed"]), sort_keys=True))
        reply_observed = reply_row["observed"]
        if reply_observed.get("spend") is not None:
            lines.append("public spend " + json.dumps(reply_observed["spend"], sort_keys=True))
        if reply_observed.get("public_result_fields"):
            lines.append(reply_observed["public_result_fields"])
        if reply_observed.get("capture_read", {}).get("reason"):
            lines.append(reply_observed["capture_read"]["reason"])
        if mode == "real-key" and row_passed(reply_row, mode) and steps.reply_passed(reply_observed, mode):
            lines.append(steps.REAL_TURN_PROOF)
        if mode == "fake-key" and row_passed(reply_row, mode):
            lines.append(steps.FAKE_TURN_PROOF)
    if mode == "fake-key":
        for row in checks:
            observed = row.get("observed", {})
            if observed.get("purpose") == steps.LIFECYCLE_ONLY:
                lines.append("step=%s %s" % (row["check"], steps.LIFECYCLE_ONLY))
            if observed.get("canary_spend"):
                lines.append("canary balance is credential setup only; does not prove the agent ran")
    failure = report.get("failure")
    if not passed and not failure:
        selected = next((row for row in checks if not row_passed(row, mode)), None)
        missing = next((name for name in required if name not in names), None)
        if selected:
            reason = "required observation failed or did not execute"
            if mode == "fake-key" and not steps.fake_row_passed(selected["check"], selected.get("observed", {})):
                reason = steps.AGENT_NOT_STARTED
            failure = {"check": selected["check"], "observed": selected.get("observed", {}), "reason": reason}
        elif missing:
            failure = {"check": missing, "reason": "required row is absent"}
        else:
            failure = {"check": "report", "reason": "scope, required rows or simulated provenance is invalid"}
    if failure:
        selected = next((row for row in checks if row["check"] == failure["check"]), None)
        observed = failure.get("observed") or (selected["observed"] if selected else {})
        actual = errors(observed, journals=False)
        if not actual and selected:
            actual = errors(selected["observed"], journals=False)
        if actual:
            for error in actual:
                lines.append("step=%s owner=%s code=%s message=%s" % (
                    failure["check"], error.get("owner") or "unreported", error.get("code") or "unreported", error.get("message", "")))
        else:
            requested = observed.get("owner_request", owners(failure["check"]))
            lines.append("step=%s owner=%s reason=%s" % (failure["check"],
                "requested:" + ",".join(requested) if requested else "unreported", failure.get("reason", "")))
        context = selected["observed"] if selected else observed
        for journal in context.get("unit_journals", []):
            lines.append("journal step=%s role=%s result=%s exit=%s lines=%s stdout=%s stderr=%s" % (
                failure["check"], journal["role"], journal["result"], journal["exit_code"], journal["lines"],
                journal["stdout"], journal["stderr"]))
        for journal in context.get("journal_refusals", []):
            for row in journal["refusals"]:
                verdict = row["error"]
                lines.append("journal_verdict step=%s role=%s line=%s owner=%s code=%s field=%s" % (
                    failure["check"], journal.get("role", "unreported"), row["line"],
                    verdict.get("owner", "unreported"), verdict.get("code", "unreported"),
                    verdict.get("field", verdict.get("stage", "unreported"))))
    for row in checks:
        for journal in row.get("observed", {}).get("initial_publish_timings", []):
            for timing in journal["records"]:
                lines.append("initial_timing step=%s role=%s line=%s stage=%s elapsed_ms=%s stdout=%s" % (
                    row["check"], journal["role"], timing["line"], timing["stage"],
                    timing["elapsed_ms"], journal["stdout"]))
    credited = sum(row_passed(row, mode) for row in checks)
    unrun = sum(not row["observed"].get("executed") for row in checks)
    lines.append("checks=%d passed=%d failed=%d unrun=%d" % (len(checks), credited, len(checks) - credited, unrun))
    if item_case:
        item_result = (report.get("item_result") or {}).get("result") or {}
        for row in item_result.get("assertions", []):
            lines.append("item=%s assertion=%s reached=%s verdict=%s" % (
                item_case, row["id"], row["reached"], row["verdict"]))
    return passed, "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    passed, text = describe(json.loads(args.report.read_bytes()))
    print(text)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

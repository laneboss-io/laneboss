"""Public CLI observation round trip; run only in the Linux E2E harness."""

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lane_handoff import HandoffRefusal, lane_descriptors


class CaseFailure(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture_inference_limit(path, config, policy, lane):
    # This file is a checked fixture claim. The installed service separately
    # enforces protected enrollment, the positive ceiling and remaining spend.
    value = json.loads(path.read_bytes())
    cap = value["max_cost_micros"]
    if (value["schema"] != "laneboss.e2e-judge-budget.v1"
            or value["config"] != config
            or value["policy_generation"] != policy["generation"]
            or value["deployment_sha256"] != policy["judge"]["deployment_sha256"]
            or value["tokenizer_sha256"] != policy["judge"]["tokenizer_sha256"]
            or type(cap) is not int or not 0 < cap <= 2**53 - 1
            or cap > lane["budget_remaining"]["spend_micros"]):
        raise CaseFailure("judge fixture requires its current positive enrolled inference limit")
    return cap


def preview_request(config, target, policy, lane, grants_sha256, cap, command):
    if (policy["context"]["level"] != lane["level"]
            or policy["context"]["role"] != lane["role"]):
        raise CaseFailure("judge fixture policy differs from its authentic role")
    return {
        "id": uuid.uuid4().hex, "purpose": "preview", "rules": [], "decisions": [],
        "task": "",  # Resolve the actual turn task; observation text is no task assignment.
        "command": {"tool": "shell", "command": base64.b64encode(command).decode(),
                    "argv": [], "declared_paths": [], "cwd": lane["workspace"]["logical_cwd"],
                    "raw_sha256": digest(command)},
        "context": {"config": config, "target": target, "role": policy["context"],
                    "logical_turn_id": lane["logical_turn_id"], "grant_set_id": lane["grant_set_id"],
                    "grants_sha256": grants_sha256, "policy_generation": policy["generation"],
                    "cwd": lane["workspace"]["logical_cwd"]},
        "config": policy["judge"], "deadline_ms": 2000, "max_cost_micros": cap,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    context = json.loads(args.context.read_bytes())
    if context["schema"] != "laneboss.e2e-context.v2":
        raise CaseFailure("invalid context schema")
    if context["case_id"] != "integrate":
        raise CaseFailure("wrong case context")
    evidence = Path(context["evidence_root"]).resolve(strict=True)
    test_root = Path(context["test_root"]).resolve(strict=True)
    result_path = args.result.absolute()
    if not result_path.parent.resolve(strict=True).is_relative_to(test_root):
        raise CaseFailure("result escapes disposable test scope")
    binary = Path(context["binary"]).resolve(strict=True)
    if digest(binary.read_bytes()) != context["binary_sha256"]:
        raise CaseFailure("installed artifact digest mismatch")
    phase = context["phase"]
    mutation = context["mutation_id"]
    if phase not in {"red", "candidate"} or bool(mutation) != (phase == "red"):
        raise CaseFailure("invalid phase or mutation")
    supported = {
        "drop-record-write", "constant-record-read", "trust-record-collection",
        "promote-lane-decision", "jev-default",
    }
    if phase == "red" and mutation not in supported:
        raise CaseFailure("unknown integration mutation")
    refs = []
    calls = 0
    reached = False
    observed_exit = 1
    failed_at = "setup"
    process_observations = []
    open_uploads = set()

    def keep(name, data):
        path = evidence / name
        with path.open("xb") as stream:
            stream.write(data)
        refs.append({"path": name, "sha256": digest(data), "bytes": len(data)})
        return path

    def invoke(words, request, expect_error=None, idempotency_key=None):
        nonlocal calls, observed_exit
        calls += 1
        stem = f"call-{calls:03d}"
        source = json.dumps(request, ensure_ascii=False).encode()
        input_path = keep(stem + "-input.json", source)
        argv = [str(binary), *words, "--config", context["config"],
                "--binding", context["binding_file"], "--request", str(input_path),
                "--idempotency-key", idempotency_key or uuid.uuid4().hex]
        keep(stem + "-argv.json", json.dumps(argv).encode())
        call = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True,
                                pass_fds=lane_descriptors(context["config"], context["binding_file"]))
        timed_out = False
        try:
            stdout, stderr = call.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            call.kill()  # The exact owned process ID, never a command pattern.
            stdout, stderr = call.communicate(timeout=5)
        observed_exit = call.returncode
        try:
            os.killpg(call.pid, 0)
            group_absent = False
        except ProcessLookupError:
            group_absent = True
        except PermissionError:
            group_absent = False
        process_observations.append({"pid": call.pid, "exit": call.returncode,
                                     "group_absent": group_absent})
        keep(stem + "-out", stdout)
        keep(stem + "-err", stderr)
        keep(stem + "-exit.json", json.dumps(call.returncode).encode())
        if timed_out or not group_absent:
            raise CaseFailure("CLI deadline or process collection failed")
        if expect_error is not None:
            if call.returncode == 0:
                raise CaseFailure("forbidden operation succeeded")
            error = json.loads(stderr)
            if error.get("code") != expect_error:
                raise CaseFailure("operation failed for the wrong reason")
            return error
        if call.returncode != 0:
            raise CaseFailure("required CLI operation failed")
        return json.loads(stdout)

    try:
        failed_at = "health"
        health = invoke(["health"], {"client_version": "", "artifact_sha256":
                                    context["binary_sha256"]})
        if not health["ready"] or health["protocol"] != "laneboss.rpc.v2":
            raise CaseFailure("service not ready")
        identity = invoke(["identity", "self"], {})
        if identity["actor"]["kind"] != "lane":
            raise CaseFailure("case requires an authenticated lane")
        data = ("Integration observation " + uuid.uuid4().hex + "\n").encode()
        keep("observation.txt", data)
        upload = invoke(["blob", "begin"], {
            "class": "record", "bytes": len(data), "sha256": digest(data),
        })
        open_uploads.add(upload["object_id"])
        invoke(["blob", "chunk"], {
            "object_id": upload["object_id"], "offset": 0,
            "data": base64.b64encode(data).decode(), "sha256": digest(data),
        })
        blob = invoke(["blob", "commit"], {
            "object_id": upload["object_id"], "sha256": digest(data),
        })
        open_uploads.remove(upload["object_id"])
        if blob["sha256"] != digest(data) or blob["bytes"] != len(data):
            raise CaseFailure("upload receipt mismatch")
        append_body = {
            "collection": "observations", "content": blob, "related_ids": [],
        }
        append_key = uuid.uuid4().hex
        record = invoke(["records", "append"], append_body, idempotency_key=append_key)
        reached = True
        failed_at = "record-read"
        got = invoke(["records", "get"], {"record_id": record["id"]})
        if got != record or got["origin"] != "observation":
            raise CaseFailure("record/provenance mismatch")
        replayed = invoke(["records", "append"], append_body, idempotency_key=append_key)
        if replayed != record:
            raise CaseFailure("same-key retry changed the durable record receipt")
        chunk = invoke(["blob", "read"], {
            "object_id": got["content"]["id"], "offset": 0, "limit": len(data),
        })
        decoded = base64.b64decode(chunk["data"], validate=True)
        if decoded != data or chunk["sha256"] != digest(decoded):
            raise CaseFailure("record bytes changed")
        page = invoke(["records", "query"], {
            "collection": "observations", "query": data.decode().strip(),
            "search_mode": "keyword", "cursor": "", "limit": 20,
        })
        if record["id"] not in {row["id"] for row in page["records"]}:
            raise CaseFailure("random keyword record missing")
        failed_at = "ledger-authority"
        invoke(["records", "append"], {
            "collection": "ledger", "content": blob, "related_ids": [],
        }, "forbidden")
        failed_at = "decision-authority"
        invoke(["decisions", "mutate"], {
            "action": "add", "content": blob, "expected_generation": 0,
        }, "forbidden")
        failed_at = "unknown-field"
        invoke(["records", "get"], {"record_id": record["id"], "actor": {}},
               "invalid_request")
        failed_at = "judge-default"
        policy = invoke(["policy", "get"], {"life_id": identity["actor"]["life_id"]})
        if (policy["judge"]["provider"] != "clef-sglang" or
                policy["judge"]["model"] != "Cloudflare/clef-flash"):
            raise CaseFailure("self-hosted Clef default not selected")
        binding = json.loads(Path(context["binding_file"]).read_bytes())
        if binding["class"] != "lane" or binding["target"]["life_id"] != identity["actor"]["life_id"]:
            raise CaseFailure("judge preview has no authentic current target")
        lane = invoke(["lane", "status"], binding["target"])
        rule = policy["rules"][0]  # Harness installs one scoped calibration rule.
        limit_path = test_root / "inference-budget.json"
        cap = fixture_inference_limit(limit_path, context["config"], policy, lane)
        keep("inference-budget.json", limit_path.read_bytes())
        judgment = invoke(["judge", "ask"], preview_request(
            context["config"], binding["target"], policy, lane,
            invoke(["grants", "get"], {"grant_set_id": lane["grant_set_id"]})["sha256"], cap, data))
        answers = judgment["results"]
        if (judgment["status"] != "scored" or judgment["selected_model"] != "Cloudflare/clef-flash" or
                judgment["deployment_sha256"] != policy["judge"]["deployment_sha256"] or
                not judgment.get("request") or len(answers) != 1 or answers[0]["question_id"] != rule["id"] or
                answers[0]["status"] != "scored" or type(answers[0].get("probability")) not in {int, float} or
                not math.isfinite(answers[0]["probability"]) or not 0 <= answers[0]["probability"] <= 1):
            raise CaseFailure("judge.ask did not use and audit the approved default deployment")
        failed_at = "complete"
        passed = True
    except (HandoffRefusal, CaseFailure, KeyError, IndexError, ValueError, OSError) as error:
        failure = {"stage": failed_at, "kind": type(error).__name__}
        if isinstance(error, HandoffRefusal):
            failure.update(error.projection())
        keep("failure.json", json.dumps(failure).encode())
        passed = False
    target_stages = {
        "drop-record-write": "record-read", "constant-record-read": "record-read",
        "trust-record-collection": "ledger-authority",
        "promote-lane-decision": "decision-authority", "jev-default": "judge-default",
    }
    if phase == "red" and not passed and failed_at != target_stages[mutation]:
        reached = False
    quiescent = all(row["exit"] is not None and row["group_absent"]
                    for row in process_observations)
    collection_path = keep("collection.json", json.dumps({
        "cli_processes": process_observations,
        "open_upload_ids": sorted(open_uploads),
    }).encode())
    collection_ref = next(row for row in refs if row["path"] == collection_path.name)
    result = {
        "schema": "laneboss.e2e-result.v2", "case_id": "integrate", "phase": phase,
        "mutation_id": mutation, "binary_sha256": context["binary_sha256"],
        "source_sha256": context["source_sha256"],
        "assertions": [{"id": "INTEGRATE-RECORDS", "reached": reached,
                        "verdict": "pass" if passed else "fail",
                        "observed_exit": observed_exit, "evidence": refs}],
        "collection": {"processes_quiescent": quiescent,
                       "temporary_resources_collected": not open_uploads,
                       "evidence": [collection_ref]},
    }
    # The shared harness additionally observes the enclosing test scope, catching
    # detached descendants. This entry never provisions a service or cloud box.
    temporary = result_path.with_name(result_path.name + ".tmp")
    with temporary.open("x") as stream:
        json.dump(result, stream)
        stream.write("\n")
    temporary.replace(result_path)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

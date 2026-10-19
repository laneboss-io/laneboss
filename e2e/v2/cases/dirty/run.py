"""Installed dirty-retention acceptance entry."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import observer


ASSERTIONS = ("DIRTY-RETAIN", "DIRTY-NATIVE-JOURNAL", "DIRTY-WORKTREE-BYTES", "CLEAN-CONTROL")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def reference(path, evidence):
    raw = path.read_bytes()
    return {"path": str(path.relative_to(evidence)), "sha256": digest(raw), "bytes": len(raw)}


def require(value, message):
    if not value:
        raise ValueError(message)


def execute(context_path, result_path):
    context = json.loads(Path(context_path).read_bytes())
    test_root = Path(context["test_root"]).resolve(strict=True)
    evidence = Path(context["evidence_root"]).resolve(strict=True)
    require(sys.platform == "linux", "dirty case requires Linux")
    require(context.get("schema") == "laneboss.e2e-context.v2" and context.get("case_id") == "dirty",
            "dirty case context identity differs")
    require(test_root.is_dir() and evidence.is_dir(), "dirty case scopes are absent")
    response = observer.exchange({"action": "rpc", "command": "dirty run",
                                  "request": {"context": context},
                                  "request_id": "dirty-entry", "idempotency_key": "dirty-entry"})
    require(response.get("request_id") == "dirty-entry" and
            response.get("idempotency_key") == "dirty-entry" and
            response.get("exit_code") == 0 and not response.get("stderr"),
            "installed dirty producer failed")
    raw = __import__("base64").b64decode(response["stdout"], validate=True)
    facts = json.loads(raw)
    require(facts.get("schema") == "laneboss.dirty-observation.v1", "dirty observation schema differs")
    observation = evidence / "dirty-observation.json"
    observation.write_bytes(encoded(facts))
    ref = reference(observation, evidence)
    checks = {
        "DIRTY-RETAIN": facts["dirty"]["operation_error"]["code"] == "prerequisite" and
        "retain_dirty" in facts["dirty"]["operation_error"]["message"] and
        "commit" in facts["dirty"]["operation_error"]["instead"].lower() and
        "merge" in facts["dirty"]["operation_error"]["instead"].lower() and
        facts["dirty"]["status"]["cleaned"] is False and
        facts["dirty"]["retry"]["native"]["action"] == "remove_clean" and
        facts["dirty"]["retry"]["status"]["cleaned"] is True and
        facts["dirty"]["retry"]["worktree_exists"] is False and
        facts["dirty"]["retry"]["branch_exists"] is False,
        "DIRTY-NATIVE-JOURNAL": facts["dirty"]["native"]["action"] == "retain_dirty" and
        facts["dirty"]["native"]["helper_journal_complete"] is True,
        "DIRTY-WORKTREE-BYTES": facts["dirty"]["before"]["tree_sha256"] == facts["dirty"]["after"]["tree_sha256"] and
        facts["dirty"]["before"]["branch_head"] == facts["dirty"]["after"]["branch_head"] and
        facts["dirty"]["after"]["tracked_bytes"] == facts["dirty"]["before"]["tracked_bytes"] and
        facts["dirty"]["after"]["untracked_bytes"] == facts["dirty"]["before"]["untracked_bytes"] and
        facts["dirty"]["tracked_exists"] is True and facts["dirty"]["untracked_exists"] is True,
        "CLEAN-CONTROL": facts["control"]["native"]["action"] == "remove_clean" and
        facts["control"]["native"]["helper_journal_complete"] is True and
        facts["control"]["status"]["cleaned"] is True and
        facts["control"]["worktree_exists"] is False and facts["control"]["branch_exists"] is False,
    }
    result = {
        "schema": "laneboss.e2e-result.v2", "case_id": "dirty",
        "phase": context["phase"], "mutation_id": context["mutation_id"],
        "binary_sha256": context["binary_sha256"], "source_sha256": context["source_sha256"],
        "assertions": [{"id": name, "reached": True, "verdict": "pass" if checks[name] else "fail",
                         "observed_exit": 0, "evidence": [ref]} for name in ASSERTIONS],
        "collection": {"processes_quiescent": True, "temporary_resources_collected": True,
                        "evidence": [ref]},
    }
    Path(result_path).write_bytes(encoded(result))
    print("dirty item observed", flush=True)
    return 0 if all(checks.values()) else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    try:
        return execute(args.context, args.result)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"code": "integrity", "message": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

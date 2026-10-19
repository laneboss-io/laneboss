#!/usr/bin/env python3
"""Frozen harness adapter for the installed lifecycle observer.

The harness supplies plan.json and an outside collector in the case scope.
This entry creates no actors, proofs, service installation or success fixture.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

from run import Case


class Prerequisite(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Prerequisite(message)


def scoped(path, root):
    value = Path(path)
    require(value.is_absolute() and ".." not in value.parts, "path must be absolute without traversal")
    resolved = value.resolve()
    require(resolved.is_relative_to(root), "path escaped the disposable case scope")
    return resolved


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    with temporary.open("xb") as output:
        output.write(json.dumps(value, sort_keys=True).encode() + b"\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def reference(path, evidence):
    raw = path.read_bytes()
    return {"path": str(path.relative_to(evidence)), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def execute(context_path, result_path):
    context = json.loads(context_path.read_bytes())
    root = Path(context["test_root"])
    require(root.is_absolute() and ".." not in root.parts, "test root must be absolute without traversal")
    root = root.resolve()
    require(root.is_absolute() and root.is_dir(), "disposable test root is missing")
    scoped(context_path, root)
    result_path = scoped(result_path, root)
    evidence = Path(context["evidence_root"])
    require(evidence.is_absolute() and ".." not in evidence.parts, "evidence root must be absolute")
    require(not evidence.is_symlink(), "evidence root must not be a symlink")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence = evidence.resolve()
    assertion = {"id": "LIFECYCLE-TREE", "reached": False, "verdict": "fail",
                 "observed_exit": 69, "evidence": []}
    result = {"schema": "laneboss.e2e-result.v2", "case_id": "lifecycle",
              "phase": context["phase"], "mutation_id": context["mutation_id"],
              "binary_sha256": context["binary_sha256"], "source_sha256": context["source_sha256"],
              "assertions": [assertion],
              "collection": {"processes_quiescent": False,
                             "temporary_resources_collected": False, "evidence": []}}
    retained = evidence / "context.json"
    retained.write_bytes(context_path.read_bytes())
    assertion["evidence"].append(reference(retained, evidence))
    exit_code = 69
    started = False
    try:
        require(sys.platform == "linux", "installed lifecycle requires the disposable Linux machine")
        require(context["schema"] == "laneboss.e2e-context.v2" and context["case_id"] == "lifecycle", "incompatible lifecycle context")
        require(context["phase"] in ("red", "candidate") and
                bool(context["mutation_id"]) == (context["phase"] == "red"), "invalid candidate/red artifact identity")
        binary = Path(context["binary"])
        require(binary.is_absolute() and binary.is_file(), "installed artifact is missing")
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == context["binary_sha256"], "installed artifact digest changed")
        binding = json.loads(scoped(context["binding_file"], root).read_bytes())
        require(binding["config"] == context["config"] and binding["artifact_sha256"] == context["binary_sha256"], "installed binding differs from the candidate")
        plan_path = scoped(root / "plan.json", root)
        require(plan_path.is_file(), "authentic lifecycle plan and actor transports are missing")
        plan = json.loads(plan_path.read_bytes())
        require(plan["config"] == context["config"] and isinstance(plan["collect"], list) and plan["collect"], "plan needs its bound configuration and outside collector")
        require(all(isinstance(word, str) and word for word in plan["collect"]), "invalid outside collector")
        run_evidence = evidence / ("run-" + secrets.token_hex(8))
        command = [sys.executable, str(Path(__file__).with_name("run.py")), "--plan", str(plan_path), "--evidence", str(run_evidence)]
        started = True
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1500, check=False)
        (evidence / "lifecycle.stdout").write_bytes(completed.stdout)
        (evidence / "lifecycle.stderr").write_bytes(completed.stderr)
        exit_code = completed.returncode
        assertion["observed_exit"] = exit_code
        # The observer writes this marker immediately before the first real
        # full-flow operation. Setup errors cannot kill a red mutation.
        assertion["reached"] = (run_evidence / "reached.json").is_file()
        require(exit_code == 0 and assertion["reached"] and b"PASS: LIFECYCLE-TREE\n" in completed.stdout.splitlines(keepends=True), "lifecycle observer did not complete its reached assertion")
        assertion["verdict"] = "pass"
    except Exception as error:
        failure = {"code": "prerequisite_missing" if isinstance(error, (Prerequisite, FileNotFoundError, KeyError)) else "integrity",
                   "owner": "lb-v2-lifecycle", "message": str(error)}
        atomic_json(evidence / "wait.json", failure)
        print(json.dumps(failure), file=sys.stderr)
        if exit_code == 0:
            exit_code = 69
    finally:
        if started:
            try:
                collected = subprocess.run([*plan["collect"], "--config", context["config"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
                (evidence / "collection.stdout").write_bytes(collected.stdout)
                (evidence / "collection.stderr").write_bytes(collected.stderr)
                require(collected.returncode == 0, "outside collection failed")
                facts = json.loads(collected.stdout)
                require(facts["survivors"] == 0 and facts["containment_known"] is True and facts["temporary_resources_collected"] is True and facts["lives"], "collection lacks independent observations")
                require(all(life["cleaned"] is True and life["containment"] == "quiescent" for life in facts["lives"]), "collector omitted quiescent cleaned records")
                expected = {target["life_id"] for target in plan["load"]}
                subject = run_evidence / "subject.json"
                if subject.is_file():
                    expected.add(json.loads(subject.read_bytes())["life_id"])
                observed = {life["life_id"] for life in facts["lives"]}
                require(len(observed) == len(facts["lives"]) and expected <= observed, "collector omitted or duplicated a managed life")
                # Independently read the actual committed records through the
                # authenticated outside observer. A collector's flags alone
                # cannot assert that a live process was collected.
                verification = Case(plan, evidence / ("collection-verify-" + secrets.token_hex(8)))
                for life in facts["lives"]:
                    status, _ = verification.call("observer", "lane.status", {
                        "life_id": life["life_id"], "run": life["run"]})
                    require(status["life_id"] == life["life_id"] and status["run"] == life["run"] and
                            status["cleaned"] is True and status["containment"] == "quiescent" and
                            status["state"] in ("merged", "abandoned"), "public collection read-back disagreed with the outside observer")
                result["collection"].update(processes_quiescent=True, temporary_resources_collected=True,
                                             evidence=[reference(evidence / "collection.stdout", evidence)])
            except Exception as error:
                atomic_json(evidence / "collection-failure.json", {"code": "prerequisite_missing", "message": str(error)})
                exit_code = 69
        for path in sorted(evidence.rglob("*")):
            if path.is_file() and not path.is_symlink():
                assertion["evidence"].append(reference(path, evidence))
        if exit_code != 0:
            assertion["verdict"] = "fail"
        atomic_json(result_path, result)
    return exit_code


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    return execute(args.context, args.result)


if __name__ == "__main__":
    sys.exit(main())

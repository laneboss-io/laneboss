"""Validate sealed, independently observed supporting acceptance on one artifact."""

from pathlib import Path

from manifests import case_file, context_file, result_file
from run import observation_result
from support import Failure, ROOT, beneath, exact_keys, immutable, integer, load, require, sha256


REQUIRED = {"service": ("SERVE-STATE", "lb-v2-service"),
            "migration": ("MIGRATE-ROLLBACK", "lb-v2-migration"),
            "integrate": ("INTEGRATED-RELEASE", "lb-v2-integrate")}


def verify_supporting(context):
    path = Path(context["test_root"]) / "supporting.json"
    if not path.is_file():
        raise Failure("8F: sealed supporting acceptance is absent", "prerequisite_missing", "lb-v2-e2e")
    value = load(immutable(path))
    exact_keys(value, ("schema", "binary_sha256", "source_sha256", "cases"))
    require(value["schema"] == "laneboss.ladder-supporting.v1", "8F: unsupported supporting envelope")
    require(all(value[key] == context[key] for key in ("binary_sha256", "source_sha256")),
            "8F: supporting acceptance belongs to another candidate")
    cases = value["cases"]
    require(isinstance(cases, list) and len(cases) == len(REQUIRED) and
            {item["id"] for item in cases} == set(REQUIRED), "8F: supporting case inventory differs")
    seen_paths, retained = set(), []
    for item in cases:
        exact_keys(item, ("id", "context", "context_sha256", "result", "result_sha256",
                          "observer", "observer_sha256", "execution", "execution_sha256"))
        required, owner = REQUIRED[item["id"]]
        manifest, _ = case_file(ROOT / "e2e/v2/cases" / item["id"] / "case.json")
        if required not in manifest["assertion_ids"]:
            raise Failure("8F: " + item["id"] + " does not implement " + required,
                          "not_implemented", owner)
        for name in ("context", "result", "observer", "execution"):
            target = immutable(item[name])
            require(str(target) not in seen_paths,
                    "8F: supporting evidence path is repeated, linked or absent")
            require(sha256(target) == item[name + "_sha256"], "8F: supporting evidence bytes changed")
            seen_paths.add(str(target))
        source = context_file(item["context"])
        require(source["case_id"] == item["id"] and source["phase"] == "candidate" and
                source["mutation_id"] == "" and
                all(source[key] == context[key] for key in ("binary_sha256", "source_sha256")) and
                sha256(source["binary"]) == context["binary_sha256"],
                "8F: supporting context is foreign, red or stale")
        execution = load(item["execution"])
        require(integer(execution["exit_code"], 0, 255) and execution["exit_code"] == 0 and
                execution["timed_out"] is False and
                integer(execution["started_ns"], 1) and integer(execution["ended_ns"], execution["started_ns"]),
                "8F: supporting entry failed or has no measured execution bracket")
        result = result_file(item["result"], manifest, source, execution["exit_code"])
        independent = observation_result(item["observer"], source, manifest)
        require(independent and all(verdict == "pass" for verdict in independent.values()),
                "8F: independent observer did not pass every supporting assertion")
        references = [ref for row in result["assertions"] for ref in row["evidence"]]
        references += result["collection"]["evidence"] + load(item["observer"])["evidence"]
        for reference in references:
            immutable(beneath(source["evidence_root"], reference["path"]))
        retained.append({"id": item["id"], "assertion": required,
                         "result_sha256": item["result_sha256"], "observer_sha256": item["observer_sha256"]})
    return retained

"""The frozen case/context/result interface, with strict evidence validation."""

from pathlib import Path

from support import (DIGEST, NAME, beneath, exact_keys, immutable, integer, load, require,
                     verify_evidence)


CASE_KEYS = ("schema", "id", "owner", "platforms", "requires", "entry",
             "timeout_seconds", "live_auth", "assertion_ids")
CONTEXT_KEYS = ("schema", "case_id", "phase", "mutation_id", "binary",
                "binary_sha256", "source_sha256", "config", "binding_file",
                "test_root", "evidence_root", "profile_grant_ids")
RESULT_KEYS = ("schema", "case_id", "phase", "mutation_id", "binary_sha256",
               "source_sha256", "assertions", "collection")


def strings(value, *, nonempty=False):
    return (isinstance(value, list) and (bool(value) or not nonempty)
            and all(isinstance(word, str) and word for word in value)
            and len(set(value)) == len(value))


def case_file(path):
    path = Path(path)
    case = load(path)
    exact_keys(case, CASE_KEYS)
    require(case["schema"] == "laneboss.e2e-case.v2", "unsupported case schema")
    require(isinstance(case["id"], str) and NAME.fullmatch(case["id"]),
            "invalid case ID")
    require(case["owner"].startswith("lb-v2-") and NAME.fullmatch(case["owner"]),
            "invalid case owner")
    require(strings(case["platforms"], nonempty=True) and
            set(case["platforms"]) <= {"linux", "darwin"}, "invalid case platforms")
    require(strings(case["requires"]), "invalid dependency names")
    require(strings(case["assertion_ids"], nonempty=True), "empty/duplicate assertions")
    require(all(NAME.fullmatch(word) for word in
                case["requires"] + case["assertion_ids"]), "invalid assertion/dependency ID")
    require(integer(case["timeout_seconds"], 1, 86400), "invalid case timeout")
    require(type(case["live_auth"]) is bool, "invalid live-auth flag")
    entry = beneath(path.parent, case["entry"])
    require(entry.is_file() and entry.suffix in (".py", ".sh"),
            "case entry must be a regular Python or shell file")
    return case, entry


def discover(root):
    root = Path(root).resolve(strict=True)
    found = {}
    for path in sorted(root.rglob("case.json")):
        beneath(root, str(path.relative_to(root)))
        case, entry = case_file(path)
        require(case["id"] not in found, "duplicate discovered case ID")
        found[case["id"]] = (case, entry, path)
    require(bool(found), "no case manifests discovered")
    return found


def context_file(path):
    value = load(path)
    exact_keys(value, CONTEXT_KEYS, ("controls",))
    if "controls" in value:
        immutable(value["controls"])
    require(value["schema"] == "laneboss.e2e-context.v2", "unsupported context schema")
    require(value["phase"] in ("red", "candidate"), "unknown test phase")
    require(isinstance(value["mutation_id"], str) and
            bool(value["mutation_id"]) == (value["phase"] == "red"),
            "phase and mutation disagree")
    for key in ("binary_sha256", "source_sha256"):
        require(isinstance(value[key], str) and DIGEST.fullmatch(value[key]),
                "invalid artifact digest")
    require(isinstance(value["case_id"], str) and NAME.fullmatch(value["case_id"]),
            "invalid context case ID")
    require(isinstance(value["config"], str) and NAME.fullmatch(value["config"]),
            "invalid context configuration")
    require(strings(value["profile_grant_ids"]), "invalid profile grant IDs")
    for key in ("binary", "binding_file", "test_root", "evidence_root"):
        path_value = Path(value[key])
        require(path_value.is_absolute() and
                path_value.resolve(strict=True) == path_value, "noncanonical context path")
    test = Path(value["test_root"])
    output = Path(value["evidence_root"])
    require(test != output and not test.is_relative_to(output) and
            not output.is_relative_to(test), "input and evidence scopes overlap")
    return value


def result_file(path, case, context, observed_exit, *, red_assertion=None, red_check=None):
    value = load(path)
    exact_keys(value, RESULT_KEYS)
    require(value["schema"] == "laneboss.e2e-result.v2", "unsupported result schema")
    for key in ("case_id", "phase", "mutation_id", "binary_sha256", "source_sha256"):
        expected = context[key]
        require(value[key] == expected, "result identity/artifact mismatch: " + key)
    assertions = value["assertions"]
    require(isinstance(assertions, list), "assertions must be an array")
    seen = {}
    for assertion in assertions:
        exact_keys(assertion, ("id", "reached", "verdict", "observed_exit", "evidence"))
        name = assertion["id"]
        require(name in case["assertion_ids"] and name not in seen,
                "undeclared or duplicate assertion")
        require(type(assertion["reached"]) is bool, "invalid reached flag")
        require(assertion["verdict"] in ("pass", "fail"), "invalid verdict")
        require(integer(assertion["observed_exit"], -(2**31), 2**31 - 1),
                "invalid observed command exit")
        require(isinstance(assertion["evidence"], list) and assertion["evidence"],
                "assertion has no operation evidence")
        for item in assertion["evidence"]:
            verify_evidence(context["evidence_root"], item)
            if item["path"] == "presence-summary.json":
                presence_file(beneath(context["evidence_root"], item["path"]))
        seen[name] = assertion
    require(set(seen) == set(case["assertion_ids"]), "missing declared assertions")
    collection = value["collection"]
    exact_keys(collection, ("processes_quiescent", "temporary_resources_collected",
                            "evidence"))
    require(collection["processes_quiescent"] is True and
            collection["temporary_resources_collected"] is True,
            "case did not collect owned resources")
    require(isinstance(collection["evidence"], list) and collection["evidence"],
            "collection has no observation evidence")
    for item in collection["evidence"]:
        verify_evidence(context["evidence_root"], item)
    if context["phase"] == "candidate":
        require(observed_exit == 0, "candidate entry exited nonzero")
        require(all(item["reached"] and item["verdict"] == "pass"
                    for item in seen.values()), "candidate assertions failed/not reached")
    else:
        require(red_assertion in seen, "red assertion is undeclared")
        require(integer(observed_exit, 1, 255) and observed_exit != 69,
                "red entry did not fail normally or lacks a prerequisite")
        target = seen[red_assertion]
        require(target["reached"] and target["verdict"] == "fail",
                "red failed before reaching its operation")
        if red_assertion == "E2E-LADDER" or red_check is not None:
            require(isinstance(red_check, str) and NAME.fullmatch(red_check),
                    "red run needs its expected named check")
            failures = [item for item in target["evidence"]
                        if item["path"] == "failure.json"]
            require(len(failures) == 1, "red lacks a unique failure receipt")
            failure = load(beneath(context["evidence_root"], failures[0]["path"]))
            require(failure.get("check_id") == red_check and failure.get("code") == "integrity",
                    "red failed at an unrelated check or infrastructure error")
        require(all(item["reached"] and item["verdict"] == "pass"
                    for name, item in seen.items() if name != red_assertion),
                "red had an unrelated failure")
    return value


def presence_file(path):
    mark = load(path)
    return presence_value(mark)


def presence_value(mark):
    exact_keys(mark, ("simulated_presence", "presence", "human_approval"), ("trees",))
    require(type(mark["simulated_presence"]) is bool and mark["presence"] ==
            ("simulated" if mark["simulated_presence"] else "not_measured") and
            mark["human_approval"] == ("not_proven" if mark["simulated_presence"] else "not_measured"),
            "result promoted unproven presence to human approval")
    if "trees" in mark:
        require(isinstance(mark["trees"], list) and mark["trees"], "presence aggregate has no tree evidence")
        trees = [presence_value(tree) for tree in mark["trees"]]
        require(any(tree["simulated_presence"] for tree in trees) == mark["simulated_presence"],
                "presence aggregate dropped a simulated tree")
    return mark

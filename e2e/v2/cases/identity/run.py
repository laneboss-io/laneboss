"""Run public identity canaries; fail closed on absent integration setup."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


GROUPS = {
    "HUMAN-IDENTITY": (
        "human-no-proof", "human-wrong-origin", "human-replay",
        "human-wrong-intent", "human-expired", "human-confirmed",
        "human-lost-reply", "human-key-conflict", "human-effect",
        "human-read-session", "human-self-no-session",
        "human-read-new-connection", "human-read-revoked", "human-read-idle",
        "human-stage-session", "human-stage-no-session",
    ),
    "PEER": (
        "peer-child", "peer-detached", "peer-forged-label",
        "peer-uid-drift", "peer-generation", "peer-stale-launch",
        "peer-passed-fd", "peer-foreign-containment", "peer-effect",
        "peer-brief-own", "peer-brief-other-life", "peer-brief-level",
        "peer-template-other-grants", "peer-grant-other-parent",
    ),
    "TICKET-ONCE": (
        "ticket-issue", "ticket-first", "ticket-second",
        "ticket-wrong-level", "ticket-wrong-role", "ticket-lost-reply", "ticket-effect",
        "ticket-wrong-principal", "ticket-wrong-config",
        "ticket-wrong-endpoint", "ticket-lane-endpoint",
    ),
}
NEGATIVE = {
    "human-no-proof", "human-wrong-origin", "human-replay",
    "human-wrong-intent", "human-expired", "peer-uid-drift",
    "human-key-conflict",
    "peer-generation", "peer-stale-launch", "peer-passed-fd",
    "peer-foreign-containment",
    "ticket-second", "ticket-wrong-level", "ticket-wrong-role",
    "human-self-no-session", "human-read-new-connection",
    "human-read-revoked", "human-read-idle",
    "human-stage-no-session",
    "peer-brief-other-life", "peer-brief-level", "peer-template-other-grants",
    "peer-grant-other-parent", "ticket-wrong-principal", "ticket-wrong-config",
    "ticket-wrong-endpoint", "ticket-lane-endpoint",
}
DENIALS = {"unauthenticated", "forbidden", "conflict",
           "idempotency_conflict", "containment_unknown"}
CONTRACT_REVISION = "v2.0-draft.4"
RED_TARGETS = {
    "omit-containment": ("peer-foreign-containment", "peer-effect"),
    "omit-generation": ("peer-generation", "peer-effect"),
    "omit-proof": ("human-no-proof", "human-effect"),
    "omit-nonce": ("human-replay", "human-effect"),
}


def load(path):
    return json.loads(Path(path).read_bytes())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reference(root, path):
    data = path.read_bytes()
    return {"path": str(path.relative_to(root)),
            "sha256": digest(data), "bytes": len(data)}


def lookup(value, path):
    for part in path.split("."):
        value = value[part]
    return value


def qualified_red(mutation, observations):
    """Only the named reached canary and its effect may contradict the plan."""
    if mutation not in RED_TARGETS:
        return False
    target, effect = RED_TARGETS[mutation]
    names = {name for group in GROUPS.values() for name in group}
    by_id = {row["id"]: row for row in observations}
    if len(by_id) != len(observations) or set(by_id) != names:
        return False
    if not all(row["reached"] for row in observations):
        return False
    if by_id[target]["verdict"]:
        return False
    return all(row["verdict"] or row["id"] in {target, effect}
               for row in observations)


def scenario_expectation(scenario):
    expected, checks = scenario["expected_exit"], scenario["expect"]
    if type(expected) is not int or not isinstance(checks, dict) or not checks:
        raise ValueError("scenario needs an exit code and nonempty assertions")
    if scenario["id"] in NEGATIVE:
        code = checks.get("code")
        if code not in DENIALS or expected != (75 if code == "containment_unknown" else 2):
            raise ValueError("negative scenario needs a typed refusal and its exact CLI exit")
    elif expected != 0:
        raise ValueError("control scenario must succeed")
    return expected, checks


def option_value(argv, names):
    values = []
    index = 0
    while index < len(argv):
        option, separator, inline = argv[index].partition("=")
        if option in names:
            if separator:
                value = inline
            else:
                index += 1
                if index == len(argv):
                    raise ValueError("scenario option has no value")
                value = argv[index]
            if not value:
                raise ValueError("scenario option has an empty value")
            values.append(value)
        index += 1
    if len(values) != 1:
        raise ValueError("scenario needs one unambiguous option")
    return values[0]


def execute(context, scenario, evidence):
    argv = scenario["argv"]
    if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or not arg for arg in argv):
        raise ValueError("scenario command missing")
    name = scenario["id"]
    if not name or any(c not in "abcdefghijklmnopqrstuvwxyz-" for c in name):
        raise ValueError("invalid scenario ID")
    if name != "collection":
        binary = context["binary"]
        if argv.count(binary) != 1:
            raise ValueError("scenario must invoke the installed artifact once")
        # Namespace wrappers precede the actual installed client. Their own
        # options cannot stand in for that client's config or binding flags.
        client_args = argv[argv.index(binary) + 1:]
        config = option_value(client_args, {"--config"})
        if name == "ticket-wrong-config":
            if config == context["config"]:
                raise ValueError("cross-config canary needs its other configuration")
        elif config != context["config"]:
            raise ValueError("scenario has a conflicting configuration")
        binding = option_value(client_args, {"--binding", "--binding-file"})
        # An inside-namespace path may not exist on the host. The installed
        # client must verify its actual protected binding in that namespace.
        if not Path(binding).is_absolute() or ".." in Path(binding).parts or "\x00" in binding:
            raise ValueError("scenario binding must be an absolute projection path")
    expected, checks = scenario_expectation(scenario)
    completed = subprocess.run(argv, capture_output=True, timeout=90, check=False)
    command_file = evidence / (name + ".command.json")
    command_file.write_text(json.dumps(argv) + "\n")
    out = evidence / (name + ".stdout")
    err = evidence / (name + ".stderr")
    out.write_bytes(completed.stdout)
    err.write_bytes(completed.stderr)
    exit_file = evidence / (name + ".exit.json")
    exit_file.write_text(json.dumps(completed.returncode) + "\n")
    refs = [reference(evidence, out), reference(evidence, err),
            reference(evidence, command_file), reference(evidence, exit_file)]
    raw = completed.stdout if completed.returncode == 0 else completed.stderr
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, TypeError):
        return False, False, completed.returncode, refs
    error_code = value.get("code") if isinstance(value, dict) else None
    reached = isinstance(value, dict) and bool(value) and (
        completed.returncode == 0 or
        completed.returncode == 2 and isinstance(error_code, str) and error_code in DENIALS or
        completed.returncode == 75 and error_code == "containment_unknown")
    if completed.returncode != expected:
        return False, reached, completed.returncode, refs
    def equal(actual, expected):
        return type(actual) is type(expected) and actual == expected

    try:
        verdict = all(equal(lookup(value, key), want) for key, want in checks.items())
    except (ValueError, KeyError, IndexError, TypeError):
        verdict = False
    return verdict, reached, completed.returncode, refs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run only on the authorized disposable Linux test box")
    context = load(args.context)
    if context["schema"] != "laneboss.e2e-context.v2":
        raise ValueError("unsupported context schema")
    if context["case_id"] != "identity" or context["phase"] not in {"red", "candidate"}:
        raise ValueError("wrong case or phase")
    if context["phase"] == "red" and context["mutation_id"] not in RED_TARGETS or \
            context["phase"] == "candidate" and context["mutation_id"]:
        raise ValueError("wrong identity mutation or candidate phase")
    test_root = Path(context["test_root"]).resolve(strict=True)
    evidence = Path(context["evidence_root"]).resolve(strict=True)
    result_input = Path(args.result).absolute()
    result_parent = result_input.parent.resolve(strict=True)
    if not evidence.is_relative_to(test_root) or not result_parent.is_relative_to(test_root) or result_input.name in {"", ".", ".."}:
        raise ValueError("result and evidence must remain under test_root")
    result_path = result_parent / result_input.name
    if result_path.exists() or result_path.is_symlink():
        raise ValueError("preserve an existing result path")
    if digest(Path(context["binary"]).read_bytes()) != context["binary_sha256"]:
        raise ValueError("artifact digest mismatch")
    assertions = []
    observations = []
    collection_ok = False
    try:
        version = subprocess.run([context["binary"], "--version"], capture_output=True,
                                 timeout=30, check=False)
        (evidence / "identity-version.stdout").write_bytes(version.stdout)
        (evidence / "identity-version.stderr").write_bytes(version.stderr)
        (evidence / "identity-version.exit.json").write_text(json.dumps(version.returncode) + "\n")
        metadata = json.loads(version.stdout)
        if version.returncode != 0 or not isinstance(metadata, dict) or \
                metadata.get("program") != "laneboss" or \
                metadata.get("api_protocol") != "laneboss.rpc.v2" or \
                metadata.get("contract_revision") != CONTRACT_REVISION:
            raise ValueError("installed artifact differs from the identity case contract")
        plan_path = test_root / "identity-scenarios.json"
        plan_bytes = plan_path.read_bytes()
        (evidence / "identity-scenarios.json").write_bytes(plan_bytes)
        plan = json.loads(plan_bytes)
        if plan.get("contract_revision") != CONTRACT_REVISION:
            raise ValueError("identity scenario plan differs from the frozen contract")
        rows = plan["scenarios"]
        by_id = {row["id"]: row for row in rows}
        if len(by_id) != len(rows):
            raise ValueError("duplicate scenario")
        for assertion, names in GROUPS.items():
            ok, reached, observed, refs = True, True, 0, []
            for name in names:
                if name not in by_id:
                    reached, ok = False, False
                    continue
                row = by_id[name]
                if row["assertion"] != assertion:
                    raise ValueError("wrong assertion group")
                verdict, operation_reached, exit_code, outputs = execute(context, row, evidence)
                observations.append({"id": name, "assertion": assertion, "verdict": verdict,
                                     "reached": operation_reached, "exit": exit_code})
                refs.extend(outputs)
                if not verdict and ok:
                    observed = exit_code
                reached = reached and operation_reached
                ok = ok and verdict
            assertions.append({"id": assertion, "reached": reached,
                               "verdict": "pass" if ok else "fail",
                               "observed_exit": observed, "evidence": refs})
        red_ok = qualified_red(context["mutation_id"], observations) if context["phase"] == "red" else None
        observed_file = evidence / "identity-observations.json"
        observed_file.write_text(json.dumps({"scenarios": observations, "qualified_red": red_ok}) + "\n")
        for assertion in assertions:
            assertion["evidence"].append(reference(evidence, observed_file))
            if red_ok is False:
                assertion["reached"] = False
        if "collection" in by_id:
            row = by_id["collection"]
            if row["expect"] != {"processes_quiescent": True,
                                 "temporary_resources_collected": True}:
                raise ValueError("collection needs independent observations")
            collection_ok, _, _, collection_refs = execute(context, row, evidence)
        else:
            collection_refs = []
    except (OSError, ValueError, KeyError, IndexError,
            subprocess.SubprocessError) as error:
        path = evidence / "dependency.txt"
        path.write_text(type(error).__name__ + ": identity setup or operation failed\n")
        present = {item["id"] for item in assertions}
        for assertion in GROUPS:
            if assertion not in present:
                assertions.append({"id": assertion, "reached": False,
                                   "verdict": "fail", "observed_exit": 1,
                                   "evidence": [reference(evidence, path)]})
        collection_refs = []
    result = {"schema": "laneboss.e2e-result.v2", "case_id": "identity",
              "phase": context["phase"], "mutation_id": context["mutation_id"],
              "binary_sha256": context["binary_sha256"],
              "source_sha256": context["source_sha256"],
              "assertions": assertions,
              "collection": {"processes_quiescent": collection_ok,
                             "temporary_resources_collected": collection_ok,
                             "evidence": collection_refs}}
    fd, temporary = tempfile.mkstemp(dir=result_path.parent, prefix="identity-")
    with os.fdopen(fd, "w") as output:
        json.dump(result, output, sort_keys=True)
        output.write("\n")
    os.replace(temporary, result_path)
    return 0 if collection_ok and all(
        item["reached"] and item["verdict"] == "pass" for item in assertions
    ) else 1


if __name__ == "__main__":
    sys.exit(main())

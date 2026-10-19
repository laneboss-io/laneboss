"""Prepare the watchdog consumer from the frozen installed case context.

G0 supplies the real L6 binding and protected worker/reader/controller inputs.
This adapter creates no identity, ticket, profile, lease, normalized usage,
review receipt or native result. It checks the actual parent and delegated
inventory through the installed shared CLI before preparing L3 child inputs.
"""

import argparse
import copy
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wd_usage import Gate, closed, digest, need, parse, private, save, wire


KEYS = {"schema", "case_id", "phase", "mutation_id", "binary", "binary_sha256", "source_sha256", "config",
        "binding_file", "test_root", "evidence_root", "profile_grant_ids"}


def consumer():
    directory = Path(__file__).resolve().parents[2] / "e2e/v2/cases/watchdog"
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location("watchdog_consumer", directory / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def context_input(value):
    need(isinstance(value, dict) and KEYS <= set(value) <= KEYS | {"controls"}, "watchdog context differs from the frozen field map")
    need(value["schema"] == "laneboss.e2e-context.v2" and value["case_id"] == "watchdog"
         and value["phase"] in {"candidate", "red"}
         and bool(value["mutation_id"]) == (value["phase"] == "red"), "watchdog context identity differs")
    need(digest(Path(value["binary"]).read_bytes()) == value["binary_sha256"], "watchdog installed artifact differs")
    need(len(value["profile_grant_ids"]) >= 2 and len(set(value["profile_grant_ids"])) == len(value["profile_grant_ids"]),
         "watchdog context needs two distinct issued profile grants")
    for key in ("binary", "binding_file", "test_root", "evidence_root"):
        path = Path(value[key])
        need(path.is_absolute(), "watchdog context has a relative installed path")
    need(Path(value["test_root"]).resolve() != Path(value["evidence_root"]).resolve(), "watchdog scopes overlap")
    return value


def selected_profiles(grants, ids):
    profiles = [p for p in grants["profiles"] if p["id"] in ids]
    need(len(profiles) == len(ids) and len({p["profile_id"] for p in profiles}) == len(profiles)
         and all(p["driver"] == "claudock-cli" and p["delegate"] is True and p["paid"] is False for p in profiles)
         and len({p["provider"] for p in profiles}) == 1, "issued watchdog profiles are not distinct delegated same-provider Claudock selectors")
    now = datetime.now(timezone.utc)
    for profile in profiles:
        need(datetime.fromisoformat(profile["expires_at"].replace("Z", "+00:00")) > now,
             "watchdog profile delegation has expired")
    return profiles


def prepare_context(context, inputs, *, human_reader=None):
    """Called in the authentic installed L6 process, after G0 enrollment.

    The inputs are checkpoint outputs, not a setup-authority request. Missing
    native transport remains a gate; this function supplies no fake callback.
    """
    context_input(context)
    closed(inputs, "schema start review reader_binding canary_id restart")
    need(inputs["schema"] == "laneboss.wd-checkpoint.v1", "watchdog checkpoint schema differs")
    module = consumer()
    case = module.Case(context, human_reader=human_reader)
    caller = case.call("identity.self", {})
    need(caller["config"] == context["config"] and caller["actor"]["kind"] == "lane"
         and caller["actor"]["level"] == 6 and caller["actor"]["life_id"], "watchdog producer lacks an authentic L6 caller")
    binding = parse(Path(context["binding_file"]).read_bytes())
    need(binding["config"] == context["config"] and binding["artifact_sha256"] == context["binary_sha256"]
         and binding["contract_revision"] == module.REVISION and binding["target"]["life_id"] == caller["actor"]["life_id"],
         "watchdog producer binding crossed its installed life or artifact")
    parent = case.call("lane.status", binding["target"])
    need(parent["level"] == 6 and parent["life_id"] == caller["actor"]["life_id"], "watchdog parent projection is foreign")
    grants = case.call("grants.get", {"grant_set_id": parent["grant_set_id"]})
    need(grants["life_id"] == parent["life_id"] and not grants["revoked"], "watchdog parent grant inventory is foreign or revoked")
    profiles = selected_profiles(grants, context["profile_grant_ids"])
    start = copy.deepcopy(inputs["start"])
    need(start["level"] == 3 and start["role"] == "executor" and start["driver"] == "claudock-cli"
         and start["profile_grant_id"] in context["profile_grant_ids"] and not start.get("root_ticket_id"),
         "watchdog child proposal is not scoped L6 to L3 execution")
    requested = {p["parent_grant_id"]: p for p in start["grants"]["profiles"]}
    need(set(requested) == set(context["profile_grant_ids"]) and len(requested) == len(start["grants"]["profiles"]),
         "watchdog child proposal omits or adds a delegated profile")
    for profile in profiles:
        proposal = requested[profile["id"]]
        need(proposal["profile_id"] == profile["profile_id"] and proposal["delegate"] is False
             and datetime.fromisoformat(proposal["expires_at"].replace("Z", "+00:00"))
             <= datetime.fromisoformat(profile["expires_at"].replace("Z", "+00:00")), "watchdog child widens its issued profile")
    need(context.get("controls") and inputs["reader_binding"] and inputs["canary_id"]
         and inputs["restart"]["expected_generation"] > 0, "watchdog external reader/controller checkpoint is missing")
    from reader import SocketReader
    reader = human_reader or SocketReader(context, inputs["reader_binding"], case.keep)
    reader.preflight()
    case.human_reader, case.owns_reader = reader, human_reader is None
    task = b"# Watchdog quota fixture\nRetain the supplied first-run history in the private vendor home.\n"
    mail = b"Continue the existing logical turn from its retained history.\n"
    root = Path(context["test_root"])
    save(root / "wd-task.md", task)
    save(root / "wd-mail.md", mail)
    setup = {"schema": "laneboss.watchdog-case.v2", "start": start, "review": inputs["review"],
             "task_file": "wd-task.md", "mail_file": "wd-mail.md", "control": "wd-phase.json",
             "reader_binding": inputs["reader_binding"], "canary_id": inputs["canary_id"], "restart": inputs["restart"]}
    save(root / "setup.json", wire(setup))
    case.keep("producer-parent.json", wire({"caller": caller, "parent": parent, "grants": grants}))
    return case


def run(context, inputs, *, human_reader=None):
    case = prepare_context(context, inputs, human_reader=human_reader)
    result, code = case.run()
    # Case.run measures normal child collection and closes an owned reader.
    # G0 additionally waits for/collects the outside provider and bridge PIDs.
    return result, code


AGENT_PACKAGE = "./e2e/v2/cases/watchdog/native"


def boot(case):
    from wd_item import boot as installed_boot
    return installed_boot(case)


def prepare(case, require, fail, blocked):
    from wd_item import prepare as installed_prepare
    return installed_prepare(case, require, fail, blocked)


def abort(case, require, fail):
    from wd_item import abort as installed_abort
    return installed_abort(case, require, fail)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    need(sys.platform == "linux", "watchdog producer requires the authorized installed Linux host")
    context = context_input(parse(private(args.context, {0, os.getuid()})))
    result_path = args.result.resolve()
    need(any(result_path.is_relative_to(Path(context[k]).resolve()) for k in ("test_root", "evidence_root")),
         "watchdog result escaped the frozen scopes")
    inputs = parse(private(args.inputs, {0, os.getuid()}))
    result, code = run(context, inputs)
    save(args.result, wire(result))
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Gate, OSError, ValueError, KeyError, RuntimeError) as failure:
        sys.stderr.buffer.write(wire({"schema": "laneboss.e2e-wait.v2", "passed": False,
            "owner": getattr(failure, "owner", "lb-v2-serve"), "code": getattr(failure, "code", "prerequisite_missing"),
            "message": str(failure)}))
        sys.exit(69)

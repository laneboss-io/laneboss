"""Installed public health, followed by an authenticated startup snapshot."""

from pathlib import Path
import sys

from caseutil import Case
from ladder_live import CLI, missing
from support import (Failure, clean_environment, exact_keys, load,
                     require, require_linux, save)


def main():
    require_linux()
    case = Case(["E2E-SERVICE"])
    reached, cli = False, None
    error = None
    simulated = False
    try:
        case.check_artifact()
        home, temporary = case.inputs / "home", case.inputs / "tmp"
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        cli = CLI(case.context["binary"], case.context["config"],
                  case.context["binding_file"], case.root / "cli",
                  clean_environment(home, temporary, case.context["config"]))
        cli.health(case.context["binary_sha256"])
        descriptor = case.inputs / "service-read-proof.json"
        if not descriptor.is_file():
            missing("startup human.session proof", "lb-v2-identity")
        authentication = load(descriptor)
        exact_keys(authentication, ("config", "proof_file"))
        require(authentication["config"] == case.context["config"],
                "startup proof descriptor crossed configurations")
        page = cli.call(["event", "tail"], {
            "life_id": "", "run": 0, "since": 0, "cursor": "", "follow": False,
            "until": "service.started", "deadline_ms": 1000},
            proof=authentication["proof_file"])
        from draft4 import presence
        simulated = any(presence(event["payload"]) for event in page["events"] if event["kind"] in
                        ("human.session", "human.proof.used", "ticket.issued", "ticket.redeemed"))
        reached = True
        starts = [event for event in page["events"]
                  if event["kind"] == "service.started" and event["origin"] == "service"
                  and event["schema"] == 2 and event["config"] == case.context["config"]
                  and event["seq"] > 0 and event["payload"]["artifact_sha256"] ==
                  case.context["binary_sha256"]]
        require(len(starts) == 1, "authentic startup event is missing")
        case.check_artifact()
    except (Failure, OSError, KeyError, TypeError, ValueError) as caught:
        error = caught
        case.observed_exit = cli.last_exit if cli is not None else 0
        if isinstance(error, Failure):
            save(case.root / "failure-owner.json", {"code": error.code, "owner": error.owner})
            if error.code in ("not_implemented", "prerequisite_missing", "unsupported", "unavailable"):
                reached = False
    finally:
        # Recorder returns only after reaping each CLI. This case starts no
        # service/lane/resource; the outer runner also collects its cgroup.
        path = case.root / "command-collection.json"
        save(path, {"cli_intents": cli.invocations if cli is not None else [],
                    "owned_services": [], "owned_resources": [], "commands_reaped": True})
    return case.finish(error, reached=reached, collection={
        "processes_quiescent": True, "temporary_resources_collected": True,
        "evidence": [case.reference(path)]}, presence={
            "simulated_presence": simulated, "presence": "simulated" if simulated else "not_measured",
            "human_approval": "not_proven" if simulated else "not_measured"})


if __name__ == "__main__":
    sys.exit(main())

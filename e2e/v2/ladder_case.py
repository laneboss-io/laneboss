"""E2E-LADDER: installed CLI and protected outside-observer acceptance."""

from pathlib import Path
import sys

from caseutil import Case
from ladder import LadderFailure, structure
from draft4 import REVISION
from ladder_live import CLI, missing, run_pair
from ladder_observer import Observer
from ladder_ready import PLAN, ready_plan, require_ports
from ladder_supporting import verify_supporting
from support import (Failure, beneath, clean_environment, exact_keys, immutable,
                     integer, load, require, require_linux, save, sha256)


def installation_inventory(trees):
    """Reject overlapping claims before launch; public receipts still verify them."""
    for tree in trees:
        binding = tree["binding"]
        exact_keys(binding, ("store_id", "socket", "service_uid", "workspace_ids", "lane_uids"))
        require(isinstance(binding["store_id"], str) and binding["store_id"] and
                isinstance(binding["socket"], str) and Path(binding["socket"]).is_absolute() and
                integer(binding["service_uid"], 1, 2**32 - 1), "invalid installation inventory")
        workspaces, uids = binding["workspace_ids"], binding["lane_uids"]
        require(isinstance(workspaces, list) and len(workspaces) == 10 and
                all(isinstance(item, str) and item for item in workspaces) and len(set(workspaces)) == 10 and
                isinstance(uids, list) and len(uids) == 10 and
                all(integer(item, 1, 2**32 - 1) for item in uids) and len(set(uids)) == 10 and
                binding["service_uid"] not in uids, "invalid or overlapping installation identities")
    left, right = (tree["binding"] for tree in trees)
    for key in ("store_id", "socket", "service_uid", "workspace_ids", "lane_uids"):
        require(not set(left[key]) & set(right[key]) if isinstance(left[key], list) else left[key] != right[key],
                "installation resources overlap: " + key)
    require(not ({left["service_uid"], *left["lane_uids"]} &
                 {right["service_uid"], *right["lane_uids"]}), "installation OS identities overlap")


def fixture(case):
    path = case.inputs / "ladder.json"
    if not path.is_file():
        missing("ladder dual installation", "lb-v2-admin")
    value = load(path)
    exact_keys(value, ("schema", "contract_revision", "plan_directory", "observer_binding",
                       "trees", "artifacts"), ("read_sessions",))
    require(value["schema"] == "laneboss.ladder-live.v2" and value["contract_revision"] == REVISION,
            "wrong ladder fixture schema")
    trees = value["trees"]
    require([item["config"] for item in trees] == ["tree-a", "tree-b"],
            "two separately bound trees are required")
    installation_inventory(trees)
    require(case.context["config"] == trees[0]["config"] and
            case.context["binding_file"] == trees[0]["binding_file"],
            "context differs from primary tree binding")
    for tree in trees:
        exact_keys(tree, ("config", "binding_file", "start_file", "ticket_file",
                          "request_id", "idempotency_key", "binding"))
        binding = load(immutable(tree["binding_file"]))
        require(binding["config"] == tree["config"] and
                binding["artifact_sha256"] == case.context["binary_sha256"] and
                binding["contract_revision"] == REVISION and
                binding["service_uid"] == tree["binding"]["service_uid"] and
                binding["socket"] == tree["binding"]["socket"],
                "tree differs from installed endpoint binding")
    require(value["artifacts"]["binary"] == case.context["binary"],
            "live binary differs from candidate")
    if "read_sessions" in value:
        require(set(value["read_sessions"]) == {tree["config"] for tree in trees},
                "public reader configuration inventory differs")
        for session in value["read_sessions"].values():
            exact_keys(session, ("binary", "proof_file"))
            require(session["binary"] == value["artifacts"].get("reader"),
                    "public reader differs from retained executable inventory")
    root = Path(value["plan_directory"])
    plan = load(root / "observer-plan.json")
    require(plan["row_plan_sha256"] == sha256(root / "row-plan.json") == sha256(PLAN) and
            load(root / "row-plan.json") == ready_plan(), "installed row plan changed from prepared inputs")
    draw = load(root / "draw.json")
    digest = sha256(root / "draw.json")
    require(load(root / "draw.sha256.json") == {
                "file": "draw.json", "sha256": digest} and
            digest == plan["draw_sha256"] and draw["seed"] == plan["seed"] and
            draw["nodes"] == structure(plan["seed"]), "runner draw hash/seed differs")
    for tree in trees:
        expected = plan["answers"][tree["config"]]
        require(set(expected) == {node["name"] for node in draw["nodes"]},
                "planted input inventory is incomplete")
        for node, answer in expected.items():
            target = beneath(root / tree["config"] / node, answer["path"])
            require(target.read_bytes() == (answer["token"] + "\n").encode("ascii"),
                    "planted input bytes differ from retained expected answers")
    return value, plan


def main():
    require_linux()
    case = Case(["E2E-LADDER"])
    reached, observer, error = False, None, None
    collection = None
    clis = []
    simulated_seen = False

    def verifying():
        nonlocal reached
        reached = True

    try:
        case.check_artifact()
        require_ports(ready_plan())
        verify_supporting(case.context)
        home = case.inputs / "home"
        temporary = case.inputs / "tmp"
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        health = CLI(case.context["binary"], case.context["config"],
                     case.context["binding_file"], case.root / "health",
                     clean_environment(home, temporary, case.context["config"]))
        clis.append(health)
        health.health(case.context["binary_sha256"])
        value, plan = fixture(case)
        observer = Observer(value["observer_binding"], case.root / "observer",
                            case.context["binary_sha256"], plan["draw_sha256"])
        trees = value["trees"]
        clis = []
        for tree in trees:
            config = tree["config"]
            cli_home, cli_tmp = home / config, temporary / config
            cli_home.mkdir(mode=0o700)
            cli_tmp.mkdir(mode=0o700)
            clis.append(CLI(
                case.context["binary"], config, tree["binding_file"],
                case.root / config, clean_environment(cli_home, cli_tmp, config),
                read_session=value.get("read_sessions", {}).get(config)))
        runs = run_pair(clis, trees, observer, plan, case.root, value["artifacts"], on_verify=verifying)
        simulated_seen = any(run["presence"]["simulated_presence"] for run in runs)
        case.check_artifact()
    except (Failure, OSError, KeyError, TypeError, ValueError) as caught:
        error, reached = verification_failure(caught, reached)
        if isinstance(error, Failure):
            save(case.root / "failure-owner.json", {"code": error.code, "owner": error.owner})
    finally:
        reader_error = None
        for cli in clis:
            reader = getattr(cli, "reader", None)
            if reader is not None:
                try:
                    reader.close()
                except (Failure, OSError, ValueError) as caught:
                    save(case.root / (cli.config + "-reader-failure.json"),
                         caught.wire() if isinstance(caught, Failure) else Failure("reader collection failed").wire())
                    reader_error = caught
                    if error is None:
                        error = caught
        save(case.root / "read-session-counts.json", {
            cli.config: {"proof_count": len(cli.reader.used_proofs), "sessions": len(cli.reader.starts)}
            for cli in clis if getattr(cli, "reader", None) is not None})
        case.observed_exit = next(
            (cli.last_exit for cli in clis if cli.last_exit), 0)
        if observer is not None:
            try:
                result = observer.call("collect", {"configs": ["tree-a", "tree-b"]})
                exact_keys(result, ("processes_quiescent",
                                    "temporary_resources_collected", "receipt"))
                require(result["processes_quiescent"] is True and
                        result["temporary_resources_collected"] is True and
                        bool(result["receipt"]), "outside collection is incomplete")
                path = case.root / "collection.json"
                save(path, result)
                collection = {
                    "processes_quiescent": True, "temporary_resources_collected": True,
                    "evidence": [case.reference(path)]}
            except (Failure, OSError, KeyError, TypeError, ValueError) as caught:
                # A cleanup failure cannot erase the original operation error.
                save(case.root / "collection-failure.json",
                     caught.wire() if isinstance(caught, Failure)
                     else Failure("collection infrastructure failed").wire())
                if error is None:
                    error = caught
        else:
            # Health/preflight created no service, lane, or external resource.
            path = case.root / "preflight-collection.json"
            save(path, {"owned_services": [], "owned_lanes": [],
                        "commands_reaped": True})
            collection = {
                "processes_quiescent": True, "temporary_resources_collected": True,
                "evidence": [case.reference(path)]}
        if reader_error is not None and collection is not None:
            collection["processes_quiescent"] = False
    simulated = simulated_seen or any(cli.reader.session and cli.reader.session.get("simulated_presence", False)
                                      for cli in clis if getattr(cli, "reader", None) is not None)
    return case.finish(error, reached=reached, collection=collection, presence={
        "simulated_presence": bool(simulated), "presence": "simulated" if simulated else "not_measured",
        "human_approval": "not_proven" if simulated else "not_measured"})


def verification_failure(error, reached):
    if isinstance(error, (KeyError, TypeError)) and reached:
        error = LadderFailure("shape", "verification input has missing or invalid fields")
    if isinstance(error, Failure) and error.code in (
            "not_implemented", "prerequisite_missing", "unsupported", "unavailable"):
        return error, False
    return error, reached or isinstance(error, LadderFailure)


if __name__ == "__main__":
    sys.exit(main())

"""Pinned credential-free judge enrollment and original native job evidence."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import uuid


def sibling(name):
    spec = importlib.util.spec_from_file_location(
        "judge_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


io = sibling("item_context")
flow = sibling("lifecycle")
fixtures = sibling("case_grants")


def boot(case):
    program = case.stage / "judge-fit.input"
    case.command("judge-fit-build", ["go", "build", "-trimpath", "-mod=vendor",
        "-o", str(program), "./e2e/v2/cases/judge/fit"], seconds=600)
    program.chmod(0o555)
    specification = io.encoded({"schema": "laneboss.fixture-fit.v1",
        "formatter": "complete UTF-8 HTTP body", "input_tokens": "2 * bytes + 32",
        "context_tokens": 32768, "safety_tokens": 32})
    deployment = io.encoded({"schema": "laneboss.fixture-provider.v1",
        "provider": "clef-sglang", "model": "Cloudflare/clef-flash",
        "route": "/v1/systemone", "fixture": True,
        "implementation": io.sha(case.stage / "e2e/v2/cases/judge/run.py")})
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    judge = {"provider": "clef-sglang", "model": "Cloudflare/clef-flash",
        "deployment_sha256": sha(deployment), "tokenizer_sha256": sha(specification),
        "context_tokens": 32768, "max_bytes": 32768, "max_questions": 12,
        "command_deadline_ms": 2000, "guidance_deadline_ms": 5000,
        "cache_ttl_ms": 0, "outage_policy": "critical-only"}
    price = io.encoded({"schema": "laneboss.judge-price.v1",
        "provider": judge["provider"], "model": judge["model"],
        "input_micros_per_million": 1000000,
        "output_micros_per_million": 1000000})
    price_file = case.stage / "judge-price.input"
    io.keep(price_file, price)
    price_file.chmod(0o444)
    for name, raw in (("judge-fit.spec", specification),
                      ("judge-stack.input", deployment),
                      ("judge-price.input", price),
                      ("judge-fit.input", program.read_bytes())):
        case.keep(name, raw)
    worker = {"tokenizer_path": str(program), "tokenizer_args": [
        judge["tokenizer_sha256"], str(judge["context_tokens"])],
        "tokenizer_executable_sha256": io.sha(program),
        "price_file": str(price_file), "price_sha256": sha(price),
        "safety_tokens": 32, "reserve_micros": 1000000}
    budget = {"wall_ms": 300000, "cpu_seconds": 120,
        "memory_bytes": 536870912, "processes": 32,
        "disk_bytes": 67108864, "spend_micros": 50000000, "currency": "USD"}
    case.judge_boot = {"judge": judge, "worker": worker,
        "price_sha256": sha(price), "endpoint": "http://127.0.0.1:18081"}
    case.keep_json("judge-enrollment.input.json", case.judge_boot)
    return {"bundle": {"budget": budget}, "assets": [{"id": "judge-fit",
        "role": "case-tokenizer", "file": str(program), "mode": 0o555}],
        "enrollment": {"judge": judge, "judge_worker": worker,
            "judge_endpoint": case.judge_boot["endpoint"],
            "policy_max_cost_micros": 1000000}}


def prepare(case, require, fail, blocked):
    case.human_prefix = "itemjudge"
    case.current = "item.judge.prepare"
    proposal = case.decode_document(case.root_launch_input(case.lane_inputs))["codex"]
    proposal["lane"] = "judge-parent-" + uuid.uuid4().hex[:8]
    ticket = case.human.ticket(proposal, case.root_grants)
    proposal["root_ticket_id"] = ticket["id"]
    proof = case.human.proof("read", "human.session", {},
                             case.human.public["principal_id"], 0)
    case.current = "item.judge.prepare"
    operation = case.checked_cli("judge-parent-start", ["lane", "start"], proposal,
        idempotency_key=uuid.uuid4().hex, session_proof=str(proof))
    record = {"name": "judge-parent", "target": {"life_id": operation["life_id"],
        "run": operation["run"]}, "operation": operation, "collected": False}
    case.item_lives.append(record)
    flow.await_operation(case, operation, require, fail, record["target"])
    lane, observed = fixtures.checked(case, record["target"], require)
    require(lane["level"] == 5 and observed["state"] == "running",
            "judge target is not the actual running L5 fixture")
    require(case.installed.get("judge") == case.judge_boot["judge"] and
        case.installed.get("judge_worker") == case.judge_boot["worker"] and
        case.installed.get("judge_endpoint") == case.judge_boot["endpoint"],
        "installed judge enrollment differs from retained bytes")

    def transport(request):
        case.current = "item.judge.run"
        command = request["command"].split()
        if command == ["fixture", "restart"]:
            unit = "laneboss-service@" + case.config + ".service"
            before = case.command("judge-pid-before", ["systemctl", "show", "--value", "-p", "MainPID", unit], clean=True)
            case.command("judge-restart", ["systemctl", "restart", unit], clean=True)
            after = case.command("judge-pid-after", ["systemctl", "show", "--value", "-p", "MainPID", unit], clean=True)
            require(int(before.strip()) > 1 and int(after.strip()) > 1 and before != after,
                    "judge restart did not replace the actual installed service process")
            result = {"before": int(before.strip()), "after": int(after.strip())}
            return {"exit_code": 0, "stdout": base64.b64encode(io.encoded(result)).decode(), "stderr": ""}
        require(command[:2] in (["judge", "ask"], ["judge", "egress"],
            ["judge", "list"], ["blob", "read"], ["event", "tail"],
            ["store", "verify"]), "unknown judge fixture transport operation")
        body = request["request"]
        if command[:2] == ["judge", "ask"] and isinstance(body, dict) and body:
            require(body["context"]["target"] == record["target"], "judge input selected another fixture target")
        proof = case.human.proof("read", "human.session", {},
                                 case.human.public["principal_id"], 0)
        case.current = "item.judge.run"
        options = {"proof": str(proof), "request_id": request["request_id"]}
        if command[:2] == ["judge", "ask"]:
            options["idempotency_key"] = request["idempotency_key"]
        case.cli("judge-item-rpc", command, body, expected=None, **options)
        response = {"exit_code": case.last["exit_code"]}
        for name in ("stdout", "stderr"):
            response[name] = base64.b64encode(
                (case.root / case.last[name]).read_bytes()).decode()
        if response["exit_code"] and not request.get("denied"):
            record["refused"] = True
            raw = base64.b64decode(response["stderr"], validate=True)
            case.rows[case.current]["observed"].update({
                "executed": True, "refusal": json.loads(raw)})
            raise fail("installed judge RPC refused; retain exact response")
        return response

    def collect(context, operations):
        case.current = "item.judge.collection"
        require(not record.get("refused"), "judge stopped at its native refusal")
        observations = fixtures.collect_fixtures(case, require, fail)
        ref = io.keep(Path(context["evidence_root"]) / "native-collection.json",
            io.encoded({"observations": observations, "operation_ids": operations}))
        return {"processes_quiescent": all(r.get("collected") for r in case.item_lives),
            "temporary_resources_collected": all(r.get("collected") for r in case.item_lives),
            "operation_ids": operations, "evidence": [ref]}

    return {"binding_file": Path(case.installed["binding_file"]),
        "profile_grant_ids": [], "transport": transport, "collect": collect,
        "inputs": {"judge-input.json": io.encoded({"target": record["target"],
            "judge": case.judge_boot["judge"], "price_sha256": case.judge_boot["price_sha256"],
            "fixture": True, "presence": "simulated", "human_approval": "not_proven"})}}


def abort(case, require, fail):
    pending = [record for record in case.item_lives if not record.get("collected")]
    if pending and not any(record.get("refused") or record.get("collection_started") for record in pending):
        case.current = "item.judge.collection"
        fixtures.collect_fixtures(case, require, fail)
    return [{"target": record["target"], "reason": "judge fixture collection is incomplete"}
            for record in case.item_lives if not record.get("collected")]

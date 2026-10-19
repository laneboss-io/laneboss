"""Black-box policy checks; no imports from the implementation or state DB."""

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import stat
import sys
import time

import observer


class OwnerWait(AssertionError):
    """A missing fresh confirmation is a wait, never a passed D6 step."""

    def __init__(self, stage, generation):
        super().__init__("fresh owner confirmation is required at the current D6 base")
        self.stage = stage
        self.generation = generation

    def projection(self):
        return {"code": "prerequisite_missing", "owner": "owner-in-person",
                "gate": "D6", "stage": self.stage,
                "expected_generation": self.generation,
                "instead": "Confirm this exact pending change at its current base, then continue through the approval coordinator."}


def atomic(path, value):
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        if path.name.endswith(".job.json") and os.geteuid() == 0:
            # Only the outside coordinator can populate another UID's private
            # queue. Keep the job readable by that exact worker, at mode 0600.
            os.fchown(stream.fileno(), path.parent.stat().st_uid, -1)
        stream.write(json.dumps(value, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def require_fresh_skip(warm):
    require(warm["result"] == "allow" and not warm.get("skip_id") and not warm.get("cache_of")
            and warm["rules"] and all(
                isinstance(rule.get("probability"), (int, float)) and not isinstance(rule["probability"], bool)
                and math.isfinite(rule["probability"]) and 0 <= rule["probability"] <= 1
                and rule.get("judgment_id") for rule in warm["rules"]),
            "fresh skip proof was not a judged allow")


def require_policy_rollover(before, after_read, after_evaluation, policy, events):
    require(before["policy_generation"] < policy["generation"],
            "mid-run D6 did not change the effective policy")
    require(after_read == before, "policy listing refreshed the lane projection")
    for field in ("life_id", "run", "logical_turn_id", "task", "launch_id", "grant_set_id",
                  "cancellation_epoch", "level", "role", "session", "workspace", "containment"):
        require(after_evaluation[field] == before[field], "policy rollover changed live identity: " + field)
    require(after_evaluation["policy_generation"] == policy["generation"],
            "fresh evaluation did not advance its live policy projection")
    refreshes = [event for event in events if event["kind"] == "lane.policy"
                 and event["life_id"] == before["life_id"] and event["run"] == before["run"]]
    require(len(refreshes) == 1, "mid-run policy refresh event missing or duplicated")
    event = refreshes[0]
    expected = {"from_generation": before["policy_generation"], "to_generation": policy["generation"],
                "lane_generation": before["generation"] + 1, "policy_sha256": policy["sha256"],
                "grant_set_id": before["grant_set_id"]}
    require(event["origin"] == "service" and event["actor"]["kind"] == "service"
            and event["payload"] == expected and after_evaluation["generation"] >= expected["lane_generation"],
            "mid-run policy refresh event changed its approved fence or snapshot")


def private_directory(path):
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.geteuid(), "test directory must be private and owned by this test identity")


class Case:
    def __init__(self, context):
        self.context = context
        self.root = Path(context["test_root"]).resolve(strict=True)
        self.evidence = Path(context["evidence_root"]).resolve(strict=True)
        private_directory(self.root)
        private_directory(self.evidence)
        self.setup = json.loads((self.root / "setup.json").read_text())
        require(self.setup["schema"] == "laneboss.policy-case.v2", "setup schema")
        require(self.setup["contract_revision"] == "v2.0-draft.4", "setup contract mismatch")
        require(
            set(self.setup["actors"]) == {"executor", "tester", "reviewer", "fallback", "l6"},
            "the five authentic role workers are required",
        )
        self.indices = dict.fromkeys(self.setup["actors"], 0)
        self.refs = []
        self.last_exit = 1
        self.sequences = dict.fromkeys(self.setup["actors"], 0)
        self.reached = {"BL-RESP": False, "SKIP": False}
        self.nonce = secrets.token_hex(16)
        self.generation = None
        self.policy_generation = None
        self.last_events = []
        self.retain("setup.json", (self.root / "setup.json").read_bytes())

    def retain(self, name, data):
        path = self.evidence / name
        path.write_bytes(data)
        ref = {
            "path": name, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        self.refs.append(ref)
        return ref

    def call(self, actor, kind, request):
        index = self.indices[actor]
        self.indices[actor] += 1
        queue = self.root / "queues" / actor
        name = f"{index:04d}"
        key = secrets.token_urlsafe(24) if kind in ("hook", "apply") else ""
        job_path = queue / (name + ".job.json")
        require(not job_path.exists(), "new operation would overwrite a retained job/key")
        atomic(job_path, {"kind": kind, "request": request, "idempotency_key": key})
        self.retain(actor + "-" + name + ".job.json", job_path.read_bytes())
        reply_path = queue / (name + ".reply.json")
        deadline = time.monotonic() + 40
        while not reply_path.is_file() and time.monotonic() < deadline:
            time.sleep(0.1)
        require(reply_path.is_file(), "authenticated worker reply missing: " + actor)
        raw = reply_path.read_bytes()
        self.retain(actor + "-" + name + ".json", raw)
        reply = json.loads(raw)
        self.last_exit = reply["exit"]
        require(reply["binary_sha256"] == self.context["binary_sha256"], "worker binary mismatch")
        require(reply["config"] == self.context["config"], "worker configuration mismatch")
        require(reply["contract_revision"] == self.setup["contract_revision"], "worker contract mismatch")
        require(reply["request"] == request, "worker input mismatch")
        require(reply["idempotency_key"] == key, "worker changed the retained operation key")
        input_bytes = base64.b64decode(reply["request_bytes"], validate=True)
        require(hashlib.sha256(input_bytes).hexdigest() == reply["request_sha256"], "request bytes mismatch")
        require(json.loads(input_bytes) == request, "CLI input differs from coordinator request")
        require(not reply["timed_out"], "CLI timed out; actual exit retained")
        stdout = base64.b64decode(reply["stdout_bytes"], validate=True).decode("utf-8")
        stderr = base64.b64decode(reply["stderr_bytes"], validate=True).decode("utf-8")
        if kind == "hook":
            require("--request" not in reply["command"] and "--command-file" in reply["command"],
                    "installed hook used the raw non-enforcing file form")
            command_bytes = base64.b64decode(reply["command_file_bytes"], validate=True)
            require(command_bytes == base64.b64decode(request["command"]["command"], validate=True),
                    "installed hook changed exact command bytes")
            require(hashlib.sha256(command_bytes).hexdigest() == reply["command_file_sha256"]
                    == request["command"]["raw_sha256"], "hook command file digest differs")
            require(reply["exit"] in (0, 2), "hook failed; inspect retained typed error")
            result = json.loads(stdout)
            expected_exit = 2 if result["result"] == "refuse" else 0
            require(reply["exit"] == expected_exit, "hook exit did not enforce its decision")
            if expected_exit == 2:
                refusal = json.loads(stderr)
                require(refusal["code"] == "forbidden" and refusal["instead"], "hook refusal route missing")
            return result
        require(reply["exit"] == 0, "CLI failed; inspect retained typed error")
        return json.loads(stdout)

    def apply(self, name):
        # Request files are populated by the approval harness just in time.
        path = self.root / self.setup["changes"][name]
        require(path.resolve().is_relative_to(self.root), "change path escaped")
        notice = {
            "stage": name, "expected_generation": self.generation,
            "nonce": self.nonce, "config": self.context["config"],
        }
        atomic(self.root / ("approval-" + name + ".json"), notice)
        if observer.available():
            # G0 invokes the outside producer synchronously; the role still
            # applies the exact file through its original authenticated CLI.
            staged = observer.exchange({"action": "rpc", "command": "policy stage",
                "request": notice, "denied": False,
                "request_id": secrets.token_urlsafe(24), "idempotency_key": secrets.token_urlsafe(24)})
            require(staged["exit_code"] == 0 and not base64.b64decode(staged["stderr"], validate=True),
                    "outside D6 producer refused; retain its exact failure")
            self.retain("stage-" + name + ".json", base64.b64decode(staged["stdout"], validate=True))
        deadline = time.monotonic() + 120
        while not path.is_file() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not path.is_file():
            raise OwnerWait(name, self.generation)
        raw = path.read_bytes()
        self.retain("change-" + name + ".json", raw)
        request = json.loads(raw)
        if self.generation is not None:
            require(request["expected_generation"] == self.generation, "stale D6 setup")
        receipt = self.call("l6", "apply", request)
        require(receipt["change_id"] == request["change_id"], "wrong D6 change")
        require(receipt["approval_id"] == request["approval_id"], "wrong approval")
        require(
            receipt["new_generation"] > receipt["old_generation"],
            "D6 did not advance policy",
        )
        require(receipt["old_generation"] == request["expected_generation"], "D6 base mismatch")
        self.generation = receipt["new_generation"]
        policy = self.call("executor", "list", {"life_id": self.setup["actors"]["executor"]["life_id"]})
        require(policy["generation"] > 0, "policy generation missing")
        if self.policy_generation is not None:
            require(policy["generation"] > self.policy_generation, "changed policy generation did not advance")
        self.policy_generation = policy["generation"]
        require(policy["sources"] and all(source["generation"] == self.generation for source in policy["sources"]),
                "policy sources do not reference the approved org generation")

    def listing(self, actor):
        target = self.setup["actors"][actor]
        result = self.call(actor, "list", {"life_id": target["life_id"]})
        require(result["generation"] == self.policy_generation, "list used a stale policy generation")
        require(all(source["generation"] == self.generation for source in result["sources"]), "list used stale approved sources")
        return result

    def blob(self, actor, reference):
        require(0 < reference["bytes"] <= 67108864, "retained object size missing or unbounded")
        data = bytearray()
        while len(data) < reference["bytes"]:
            chunk = self.call(actor, "blob", {
                "object_id": reference["id"], "offset": len(data),
                "limit": min(262144, reference["bytes"] - len(data)),
            })
            raw = base64.b64decode(chunk["data"], validate=True)
            require(chunk["object_id"] == reference["id"] and chunk["offset"] == len(data), "object read changed identity/offset")
            require(0 < len(raw) <= reference["bytes"] - len(data), "object read was empty or oversized")
            require(hashlib.sha256(raw).hexdigest() == chunk["sha256"], "object chunk hash mismatch")
            data.extend(raw)
        require(hashlib.sha256(data).hexdigest() == reference["sha256"], "object read-back hash mismatch")
        return bytes(data)

    def evaluate(self, actor, command, cwd="/work/main"):
        target = self.setup["actors"][actor]
        raw = command.encode()
        request = {
            "target": {"life_id": target["life_id"], "run": target["run"]},
            "logical_turn_id": target["logical_turn_id"],
            "command": {
                "tool": "shell", "command": base64.b64encode(raw).decode(),
                "argv": [], "declared_paths": [], "cwd": cwd,
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            },
        }
        result = self.call(actor, "hook", request)
        require(result["policy_generation"] == self.policy_generation, "hook used a stale policy generation")
        require(result["audit_complete"], "decision audit incomplete")
        require(result["input"]["bytes"] > 0, "exact input object missing")
        retained = json.loads(self.blob(actor, result["input"]))
        require(retained["request"] == request, "retained hook request differs from exact input")
        wire = base64.b64decode(retained["wire_params"], validate=True)
        require(json.loads(wire) == request, "retained CLI wire params differ from exact input")
        records = []
        cursor = ""
        for _ in range(100):
            events = self.call(actor, "events", {
                "life_id": target["life_id"], "run": target["run"],
                "since": self.sequences[actor], "cursor": cursor,
                "follow": False, "until": "", "deadline_ms": 1000,
            })
            records.extend(events["events"])
            if events["complete"]:
                break
            require(events["cursor"] and events["cursor"] != cursor, "event cursor stalled")
            cursor = events["cursor"]
        else:
            raise AssertionError("event observation exceeded page bound")
        matches = [
            event for event in records
            if event["kind"] == "policy.evaluated"
            and event["origin"] == "service"
            and event["life_id"] == target["life_id"]
            and event["run"] == target["run"]
            and event["logical_turn_id"] == target["logical_turn_id"]
            and event["actor"]["life_id"] == target["life_id"]
            and event["payload"]["id"] == result["id"]
        ]
        require(len(matches) == 1, "durable policy event missing or duplicated")
        require(matches[0]["payload"] == result, "decision differs from event")
        self.sequences[actor] = max([self.sequences[actor], *[e["seq"] for e in records]])
        self.last_events = records
        return result

    def responsibility(self):
        self.apply("baseline")
        rules = self.setup["rules"]
        executor = self.listing("executor")
        self.reached["BL-RESP"] = True
        present = {rule["id"]: rule for rule in executor["rules"]}
        require(executor["context"]["level"] == 3 and executor["context"]["role"] == "executor", "executor identity mismatch")
        for name in ("org", "own", "higher"):
            require(rules[name] in present, "missing inherited rule: " + name)
        require(rules["lower"] not in present, "same-level peer role inherited")
        require(
            present[rules["org"]]["thresholds"]["match"] == 0.80,
            "org threshold was replaced",
        )
        require(present[rules["own"]]["thresholds"]["match"] == 0.95, "own threshold missing")
        require(present[rules["higher"]]["thresholds"]["match"] == 0.85, "higher threshold replaced")
        brief = self.call("executor", "brief", {
            "role": "executor", "level": 3,
            "life_id": self.setup["actors"]["executor"]["life_id"],
        })
        require(brief["policy_generation"] == self.policy_generation, "brief policy is stale")
        markdown = self.blob("executor", brief["markdown"]).decode("utf-8")
        require("org blacklist list" in markdown, "brief omits rule-list discovery")
        for source in executor["sources"]:
            require(source["path"] in markdown, "brief omits effective source provenance")
        reviewer = {rule["id"] for rule in self.listing("reviewer")["rules"]}
        require(rules["own"] not in reviewer, "lower-level rule inherited")
        fallback = {rule["id"] for rule in self.listing("fallback")["rules"]}
        require(rules["org"] in fallback, "missing org fallback")
        for name, text in (
            ("cloud", "aws ec2 run-instances --dry-run"),
            ("pr", "gh pr create --draft"),
            ("plugin", "use the restricted org publishing plugin"),
        ):
            result = self.evaluate("executor", text)
            require(result["result"] == "refuse", "matching action allowed: " + name)
            reasons = [r for r in result["rules"] if r["rule_id"] == rules[name]]
            require(len(reasons) == 1 and reasons[0]["instead"], "Instead missing")
        for actor, text in (
            ("tester", "laneboss box list"),
            ("executor", "unfamiliar-public-reader --version"),
            ("executor", "tmux -L private-build new-session -d make"),
        ):
            require(self.evaluate(actor, text)["result"] == "allow", "ordinary work refused")

    def skips(self):
        command = "cat public-readme.txt"
        first = self.evaluate("executor", command)
        self.reached["SKIP"] = True
        again = self.evaluate("executor", command)
        require(again.get("cache_of") == first["id"], "cache lacks original receipt")
        changed = self.evaluate("executor", command, "/work/main/docs")
        require(not changed.get("cache_of"), "cwd cache invalidation failed")
        role = self.evaluate("tester", command)
        require(not role.get("cache_of"), "role cache invalidation failed")
        self.apply("skip")
        warm = self.evaluate("executor", command)
        require_fresh_skip(warm)
        skipped = self.evaluate("executor", command)
        require(skipped.get("skip_id") and skipped["result"] == "allow", "approved skip not used")
        require(skipped.get("cache_of") == warm["id"], "skip lacks its positive receipt")
        miss = self.evaluate("executor", "cat a-different-public-file.txt")
        require(not miss.get("skip_id") and miss["result"] == "allow", "skip miss refused")
        target = self.setup["actors"]["executor"]
        selector = {"life_id": target["life_id"], "run": target["run"]}
        before = self.call("executor", "status", selector)
        require(before["policy_generation"] == self.policy_generation,
                "pre-change evaluation did not establish the current live projection")
        self.apply("rules")
        policy = self.listing("executor")
        after_read = self.call("executor", "status", selector)
        invalidated = self.evaluate("executor", command)
        require(not invalidated.get("cache_of"), "stale rules cache reused")
        require(not invalidated.get("skip_id"), "stale skip reused")
        require(invalidated["result"] == "refuse", "new semantic deny ignored")
        after_evaluation = self.call("executor", "status", selector)
        require_policy_rollover(before, after_read, after_evaluation, policy, self.last_events)

    def outages(self):
        for name in ("timeout", "partial", "cost"):
            self.apply(name)
            result = self.evaluate("executor", "read the public outage canary")
            decisions = {r["rule_id"]: r for r in result["rules"]}
            critical = decisions[self.setup["rules"]["critical"]]
            notice = decisions[self.setup["rules"]["notice"]]
            require(result["result"] == "refuse", "critical outage allowed")
            require(critical["result"] == "refuse", "critical entry did not close")
            require("probability" not in critical, "unscored became probability zero")
            require(notice["result"] != "refuse", "warn entry closed")
            require("probability" not in notice and notice["reason"], "outage notice missing")
            other = self.evaluate("tester", "read the public outage canary")
            require(other["result"] != "refuse", "noncritical outage closed")

    def stop(self):
        for actor, index in self.indices.items():
            queue = self.root / "queues" / actor
            atomic(queue / f"{index:04d}.job.json", {"kind": "stop"})
        atomic(self.evidence / "collection-request.json", {
            "nonce": self.nonce, "config": self.context["config"],
            "binary_sha256": self.context["binary_sha256"],
            "actors": self.setup["actors"],
        })


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    context = json.loads(args.context.read_text())
    require(context["schema"] == "laneboss.e2e-context.v2", "context schema")
    result = {
        key: context[key] for key in (
            "case_id", "phase", "mutation_id", "binary_sha256", "source_sha256"
        )
    }
    result["schema"] = "laneboss.e2e-result.v2"
    result["assertions"] = [
        {"id": name, "reached": False, "verdict": "fail",
         "observed_exit": 1, "evidence": []}
        for name in ("BL-RESP", "SKIP")
    ]
    result["collection"] = {
        "processes_quiescent": False, "temporary_resources_collected": False,
        "evidence": [],
    }
    case = None
    failure = False
    try:
        case = Case(context)
        require(
            hashlib.sha256(Path(context["binary"]).read_bytes()).hexdigest()
            == context["binary_sha256"], "binary identity mismatch",
        )
        for assertion, check in zip(
            result["assertions"], (case.responsibility, case.skips)
        ):
            before = len(case.refs)
            try:
                check()
                if assertion["id"] == "SKIP":
                    assertion["verdict"] = "pass"
            finally:
                assertion["reached"] = case.reached[assertion["id"]]
                assertion["observed_exit"] = case.last_exit
                assertion["evidence"] = case.refs[before:]
        result["assertions"][0]["verdict"] = "fail"
        before = len(case.refs)
        try:
            case.outages()
            result["assertions"][0]["verdict"] = "pass"
        finally:
            result["assertions"][0]["evidence"].extend(case.refs[before:])
            result["assertions"][0]["observed_exit"] = case.last_exit
    except OwnerWait as error:
        failure = True
        atomic(Path(context["evidence_root"]) / "owner-wait.json", error.projection())
        print("WAIT: prerequisite_missing; fresh owner D6 confirmation is required", file=sys.stderr)
    except (AssertionError, OSError, ValueError, KeyError, TypeError) as error:
        failure = True
        evidence = Path(context["evidence_root"])
        diagnostic = (str(error) + "\n").encode()
        (evidence / "failure.txt").write_bytes(diagnostic)
        print("FAIL: policy; inspect retained evidence", file=sys.stderr)
    finally:
        if case is not None:
            case.stop()
            if observer.available():
                # This callback's measured receipt is also retained separately
                # by G0 after entry exit. The entry never supplies its flags.
                try:
                    observer.exchange({"action": "collect", "operation_ids": []})
                except (AssertionError, OSError, ValueError, KeyError, TypeError) as error:
                    failure = True
                    case.retain("observer-failure.json", json.dumps({"message": str(error)}).encode())
                    print("FAIL: independent policy collection; retain observer failure", file=sys.stderr)
            collection = case.evidence / "collection.json"
            deadline = time.monotonic() + (0 if failure and observer.available() else 180)
            while not collection.is_file() and time.monotonic() < deadline:
                time.sleep(0.1)
            if collection.is_file():
                observed = json.loads(collection.read_text())
                if (
                    observed.get("observations") and observed.get("nonce") == case.nonce
                    and observed.get("binary_sha256") == context["binary_sha256"]
                    and observed.get("config") == context["config"]
                ):
                    result["collection"].update({
                        "processes_quiescent": observed.get("processes_quiescent") is True,
                        "temporary_resources_collected":
                            observed.get("temporary_resources_collected") is True,
                        "evidence": [case.retain("collected.json", collection.read_bytes())],
                    })
        atomic(args.result, result)
    complete = all(a["verdict"] == "pass" for a in result["assertions"])
    collected = result["collection"]
    return 0 if (
        not failure and complete and collected["processes_quiescent"]
        and collected["temporary_resources_collected"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())

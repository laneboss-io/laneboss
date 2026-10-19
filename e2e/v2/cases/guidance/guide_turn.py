#!/usr/bin/env python3
"""Public CLI oracle; execute only on the disposable Linux acceptance box."""

import argparse
import base64
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lane_handoff import HandoffRefusal, lane_descriptors


class CheckFailure(ValueError):
    """Only authored diagnostic text may be disclosed from a failed check."""


class OwnerWait(CheckFailure):
    def __init__(self, gate):
        super().__init__("fresh owner confirmation is required before this workload step")
        self.gate = gate

    def projection(self):
        return {"code": "prerequisite_missing", "owner": "owner-in-person",
                "gate": self.gate,
                "instead": "Supply the real current operation confirmation through the coordinator; do not synthesize a decision or D6 approval."}


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


def load(path):
    return json.loads(path.read_bytes())


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()


def atomic(path, data):
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def beneath(root, name):
    path = (root / name).resolve()
    require(path.is_relative_to(root), "input path escapes the test scope")
    return path


def seconds(value):
    require(isinstance(value, str) and value.endswith("Z"), "non-UTC time")
    return datetime.datetime.fromisoformat(value[:-1] + "+00:00").timestamp()


def near(actual, expected):
    return (
        isinstance(actual, (int, float))
        and not isinstance(actual, bool)
        and math.isfinite(actual)
        and math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-12)
    )


def minimum_relevance(value):
    require(near(value, value) and 0 <= value <= 1,
            "invalid approved relevance cutoff")
    return 0.5 if value == 0 else value


def resolved_judge(value):
    config = dict(value)
    config["provider"] = config["provider"] or "clef-sglang"
    if config["provider"] == "clef-sglang":
        config["model"] = config["model"] or "Cloudflare/clef-flash"
        require(config["model"] == "Cloudflare/clef-flash"
                and config["context_tokens"] > 0,
                "invalid approved Clef model or context")
        for field in ("deployment_sha256", "tokenizer_sha256"):
            require(isinstance(config[field], str)
                    and re.fullmatch(r"[a-f0-9]{64}", config[field]),
                    "approved Clef pins are missing")
    else:
        require(config["provider"] == "typesafe" and config["model"],
                "unapproved judge provider or missing full model")
    return config


def result_body(value):
    if isinstance(value, dict) and "protocol" in value:
        require("error" not in value, "CLI returned an error envelope")
        return value["result"]
    return value


def chunk_bytes(value):
    require(value["offset"] == 0, "fixture blob must start at offset zero")
    data = base64.b64decode(value["data"], validate=True)
    require(
        hashlib.sha256(data).hexdigest() == value["sha256"],
        "downloaded chunk digest differs",
    )
    return data


def resolve(value, responses):
    if isinstance(value, dict):
        if set(value) == {"$step", "$path"}:
            selected = responses[value["$step"]]
            for key in value["$path"]:
                selected = selected[key]
            return selected
        return {key: resolve(item, responses) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve(item, responses) for item in value]
    return value


def check_candidate_origin(candidate, commands, responses):
    authority = candidate["authority"]
    require(authority["kind"] in {"human", "d6"}
            and authority["receipt_id"] and authority["source_seq"] > 0,
            "candidate authority is not canonical human or D6 history")
    if authority["kind"] == "human":
        require("seed_step" in candidate and "approval_step" not in candidate,
                "human candidate lacks its canonical seed step")
        step = candidate["seed_step"]
        receipt = responses[step]
        require(commands[step] in (["decisions", "mutate"], ["decisions", "add"],
                                   ["decisions", "supersede"])
                and receipt["id"] == candidate["id"],
                "candidate lacks a real decision mutation receipt")
        require(receipt["actor"]["kind"] == "human"
                and authority["org_generation"] == 0
                and candidate["source"]["id"] == candidate["id"]
                and not candidate["source"]["path"],
                "lane proposal was treated as authoritative history")
    else:
        require("approval_step" in candidate, "D6 candidate lacks its approval step")
        step = candidate["approval_step"]
        receipt = responses[step]
        require(commands[step] == ["org", "change", "apply"]
                and receipt["approval_id"] and receipt["applied_at"]
                and receipt["new_generation"] > receipt["old_generation"]
                and candidate["source"]["generation"] == receipt["new_generation"]
                and authority["org_generation"] == receipt["new_generation"]
                and candidate["source"]["path"],
                "D6 input lacks its applied approval receipt")


def check_variations(observations):
    """Compare controlled pairs, using observed probabilities and reminders."""
    require(any(row["below_cutoff"] for row in observations),
            "workload did not observe an excluded below-cutoff candidate")
    task_changed = False
    clock_changed = False
    for index, first in enumerate(observations):
        for second in observations[index + 1:]:
            if any(first[field] != second[field] for field in
                   ("history", "half_life", "cutoff", "judge")):
                continue
            if (first["as_of"] == second["as_of"]
                    and first["task"] != second["task"]
                    and first["probabilities"] != second["probabilities"]
                    and set(first["selected"]) != set(second["selected"])):
                task_changed = True
            if (first["task"] != second["task"]
                    or first["as_of"] == second["as_of"]
                    or first["probabilities"] != second["probabilities"]):
                continue
            common = set(first["selected"]).intersection(second["selected"])
            for left in common:
                for right in common - {left}:
                    if first["history"][left]["effective_at"] == first["history"][right]["effective_at"]:
                        continue
                    before = first["selected"].index(left) - first["selected"].index(right)
                    after = second["selected"].index(left) - second["selected"].index(right)
                    clock_changed |= before * after < 0
    require(task_changed,
            "controlled task change did not change relevance and selected decision IDs")
    require(clock_changed,
            "controlled clock change did not reverse recent and older reminder order")
    recency_matters = any(row["selected"] != sorted(
        (key for key, probability in row["probabilities"].items()
         if probability >= row["cutoff"]),
        key=lambda key: (-row["probabilities"][key], key))[:5]
        for row in observations)
    require(recency_matters, "recency did not change reminder order versus pure relevance")


class Case:
    def __init__(self, context):
        self.context = context
        self.root = Path(context["test_root"]).resolve()
        self.evidence = Path(context["evidence_root"]).resolve()
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.responses = {}
        self.commands = {}
        self.requests = {}
        self.evidence_refs = []
        self.reached = False
        self.observed_exit = 1
        self.quiescent = False
        self.collected = False
        self.deadline = time.monotonic() + 1700

    def retain(self, name, data):
        path = beneath(self.evidence, name)
        require(not path.exists(), "evidence destination already exists")
        atomic(path, data)
        self.evidence_refs.append({
            "path": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })

    def execute(self, step, index):
        name = step["name"]
        require(name not in self.responses, "duplicate workload step")
        command = step["command"]
        require(
            isinstance(command, list) and command
            and all(isinstance(word, str) and word
                    and not word.startswith("-") for word in command),
            "workload command must contain command words only",
        )
        source = beneath(self.root, step["request"])
        original = source.read_bytes()
        self.retain(f"{index:03d}-input.json", original)
        request = resolve(json.loads(original), self.responses)
        request_name = f"{index:03d}-request.json"
        self.retain(request_name, encoded(request))
        key = step["idempotency_key"]
        require(isinstance(key, str)
                and re.fullmatch(r"[A-Za-z0-9_-]{22,128}", key),
                "workload requires a retained request key")
        argv = [self.context["binary"], *command, "--config",
                self.context["config"], "--binding", self.context["binding_file"],
                "--idempotency-key", key, "--request",
                str(beneath(self.evidence, request_name))]
        if "proof" in step:
            proof_path = beneath(self.root, step["proof"])
            if not proof_path.is_file():
                raise OwnerWait("D6" if command == ["org", "change", "apply"] else "operation_confirmation")
            proof_bytes = proof_path.read_bytes()
            self.retain(f"{index:03d}-proof-input.json", proof_bytes)
            proof = resolve(json.loads(proof_bytes), self.responses)
            proof_name = f"{index:03d}-proof.json"
            self.retain(proof_name, encoded(proof))
            argv += ["--proof", str(beneath(self.evidence, proof_name))]
        self.retain(f"{index:03d}-argv.json", encoded(argv))
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "workload deadline exhausted")
        completed = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=remaining,
            close_fds=True,
            pass_fds=lane_descriptors(self.context["config"], self.context["binding_file"]),
        )
        self.observed_exit = completed.returncode
        self.retain(f"{index:03d}-stdout.json", completed.stdout)
        self.retain(f"{index:03d}-stderr.json", completed.stderr)
        self.retain(f"{index:03d}-exit.json", encoded({
            "command": command, "exit": completed.returncode,
        }))
        require(completed.returncode == 0, "CLI workload step failed")
        self.responses[name] = result_body(json.loads(completed.stdout))
        self.commands[name] = command
        self.requests[name] = request

    def events(self, turn):
        step = turn["events_step"]
        require(self.commands[step] == ["event", "tail"], "not an event read")
        page = self.responses[step]
        require(page["complete"] and not page["cursor"], "incomplete event page")
        request = self.requests[step]
        # A complete explicit run read from sequence zero includes pre-launch
        # selection/judgment. A cursor or late since can conceal a duplicate.
        require(request["life_id"] == turn["life_id"]
                and request["run"] == turn["run"] and turn["run"] > 0
                and request["since"] == 0 and not request["cursor"]
                and not request["follow"] and not request["until"],
                "event request does not cover the complete authentic run")
        events = [event for event in page["events"]
                  if event.get("origin") == "service"
                  and event.get("config") == self.context["config"]
                  and event.get("life_id") == turn["life_id"]
                  and event.get("run") == turn["run"]]
        sequences = [event["seq"] for event in events]
        require(all(isinstance(seq, int) and not isinstance(seq, bool) and seq > 0
                    for seq in sequences)
                and sequences == sorted(set(sequences)),
                "service run events have invalid sequence provenance")
        return [event for event in events
                if event.get("logical_turn_id") == turn["logical_turn_id"]]

    def delivery(self, turn):
        action = turn["action_step"]
        operation = self.responses[action]
        require(operation["life_id"] == turn["life_id"]
                and operation["run"] == turn["run"],
                "delivery operation belongs to another life or run")
        events = self.events(turn)
        delivery = [event for event in events if event["kind"] in
                    {"lane.started", "lane.resumed", "lane.turn"}]
        require(delivery and delivery[-1]["operation_id"] == operation["id"],
                "no authentic prompt delivery event for the operation")
        command = self.commands[action]
        expected = {"initial": ["lane", "start"], "resume": ["lane", "resume"],
                    "mail": ["lane", "turn"], "idle": ["lane", "turn"]}
        kind = turn["kind"]
        if kind in expected:
            require(command == expected[kind], "delivery case used the wrong command")
        elif kind in {"empty", "unavailable"}:
            require(command in (["lane", "start"], ["lane", "resume"], ["lane", "turn"]),
                    "empty or unavailable case has no lane delivery")
        elif kind == "continuation":
            require(command == ["operation", "get"],
                    "continuation must observe the actual watchdog operation")
        else:
            raise CheckFailure("unknown delivery kind")
        if kind != "continuation":
            event_kind = {"start": "lane.started", "resume": "lane.resumed", "turn": "lane.turn"}[command[-1]]
            require(delivery[-1]["kind"] == event_kind, "command and delivery event differ")
        return events, delivery

    def preflight(self, workload):
        """Load every required input and validate every delivery before reach."""
        self.input_bytes = {}
        candidates = resolve(workload["candidates"], self.responses)
        turns = resolve(workload["turns"], self.responses)
        require(candidates and turns, "missing candidate or turn inputs")
        for candidate in candidates:
            for field in ("id", "text", "source", "effective_at", "binding", "authority", "applies_to"):
                candidate[field]
            name = candidate["input_file"]
            self.input_bytes[name] = beneath(self.root, name).read_bytes()
            require(self.input_bytes[name].decode() == candidate["text"], "seed text differs")
            self.responses[candidate["view_step"]]["decisions"]
            require("seed_step" in candidate or "approval_step" in candidate,
                    "candidate lacks a retained seed or D6 approval step")
            for field in ("seed_step", "approval_step"):
                if field in candidate:
                    self.responses[candidate[field]]
                    self.commands[candidate[field]]
        for turn in turns:
            for field in ("candidate_ids", "as_of", "policy_generation", "half_life_seconds"):
                turn[field]
            name = turn["task_file"]
            self.input_bytes[name] = beneath(self.root, name).read_bytes()
            seconds(turn["as_of"])
            self.responses[turn["policy_step"]]
            chunk_bytes(self.responses[turn["prompt_step"]])
            if turn["kind"] not in {"continuation", "empty", "unavailable"}:
                steps = turn.get("judge_input_steps")
                if steps is None:
                    steps = [turn["judge_input_step"]]
                for step in steps:
                    json.loads(chunk_bytes(self.responses[step]))
            self.delivery(turn)

    def check(self, workload):
        self.reached = False
        try:
            self.preflight(workload)
            self.reached = True
            self.oracle(workload)
        except CheckFailure:
            raise
        except (OSError, ValueError, KeyError, TypeError, OverflowError,
                subprocess.SubprocessError):
            self.reached = False
            raise

    def oracle(self, workload):
        candidates = {}
        for candidate in resolve(workload["candidates"], self.responses):
            identifier = candidate["id"]
            require(identifier not in candidates, "duplicate candidate input")
            text = self.input_bytes[candidate["input_file"]]
            self.retain(f"candidate-{len(candidates):03d}.txt", text)
            require(text.decode() == candidate["text"], "seed text differs")
            view = candidate["view_step"]
            require(self.commands[view] == ["dashboard", "decisions"],
                    "candidate provenance is not from the public decision view")
            observed = [item for item in self.responses[view]["decisions"]
                        if item["id"] == identifier]
            fields = {key: candidate[key] for key in
                      ("id", "text", "source", "effective_at", "binding",
                       "authority", "applies_to")}
            require(observed == [fields], "seeded decision projection differs")
            check_candidate_origin(candidate, self.commands, self.responses)
            candidates[identifier] = candidate

        turns = resolve(workload["turns"], self.responses)
        kinds = {turn["kind"] for turn in turns}
        require(kinds == {"initial", "resume", "mail", "idle",
                          "continuation", "empty", "unavailable"},
                "workload does not exercise every required delivery")
        require(len({turn["as_of"] for turn in turns}) > 1,
                "service clock was not varied")
        task_digests = set()
        seen = {}
        over_five = False
        multi_batch = False
        old_binding = False
        observations = []
        for turn in turns:
            action = turn["action_step"]
            events, delivery = self.delivery(turn)
            payload = delivery[-1]["payload"]
            kind = turn["kind"]
            if kind == "initial":
                require(self.commands[action] == ["lane", "start"]
                        and delivery[-1]["kind"] == "lane.started",
                        "initial case did not actually start a lane")
            elif kind == "resume":
                require(self.commands[action] == ["lane", "resume"]
                        and delivery[-1]["kind"] == "lane.resumed",
                        "resume case did not actually resume a lane")
            elif kind in {"mail", "idle"}:
                require(self.commands[action] == ["lane", "turn"]
                        and delivery[-1]["kind"] == "lane.turn",
                        "turn case did not actually deliver a turn")
                if kind == "mail":
                    mail = turn["mail_step"]
                    require(self.commands[mail] == ["mail", "send"]
                            and self.responses[mail]["id"]
                            in self.requests[action]["mail_ids"]
                            and payload["mail_ids"]
                            == self.requests[action]["mail_ids"],
                            "mail case did not deliver the queued message")
                elif kind == "idle":
                    require(not self.requests[action]["mail_ids"]
                            and self.requests[action]["idle_message"]
                            and not payload["mail_ids"],
                            "idle case delivered mail instead")
            selection = [event["payload"] for event in events
                         if event["kind"] == "guidance.selected"]
            judgments = [event["payload"] for event in events
                         if event["kind"] == "judge.completed"]
            turn_id = turn["logical_turn_id"]
            if turn["kind"] == "continuation":
                previous = turn["continuation_of"]
                require(previous in seen and previous == turn_id,
                        "continuation changed logical turn")
                prior = seen[previous]
                require(turn["life_id"] == prior["life_id"]
                        and payload["profile_continuation_of"] == prior["run"]
                        and delivery[-1]["run"] > prior["run"]
                        and payload["profile_swap"]["logical_turn_id"] == turn_id
                        and payload["prompt"] == prior["prompt"],
                        "continuation did not retain its original run/turn/prompt")
                require(not selection and not judgments,
                        "continuation duplicated selection or judgment")
                require(not any(event["kind"] == "mail.delivered"
                                for event in events),
                        "continuation acknowledged mail again")
                continue
            require(turn_id not in seen, "distinct delivery reused logical turn")
            require(len(selection) == 1, "turn lacks exactly one selection")
            guidance = selection[0]
            seen[turn_id] = {"guidance": guidance,
                             "life_id": turn["life_id"],
                             "run": delivery[-1]["run"],
                             "prompt": payload["prompt"]}
            require(guidance["logical_turn_id"] == turn_id, "wrong receipt turn")
            require(guidance["target"]["life_id"] == turn["life_id"]
                    and guidance["task"] == payload["task"]
                    and guidance["policy_generation"] == turn["policy_generation"]
                    and guidance["candidate_snapshot_id"]
                    and guidance["reservation_id"],
                    "guidance lost its draft.3 task, policy or reservation binding")
            require(guidance["as_of"] == turn["as_of"], "clock input ignored")
            policy_step = turn["policy_step"]
            require(self.commands[policy_step] == ["policy", "get"],
                    "guidance policy is not from an authorized policy read")
            policy = self.responses[policy_step]
            require(policy["generation"] == guidance["policy_generation"],
                    "guidance used a different policy generation")
            approved_judge = resolved_judge(policy["judge"])
            cutoff = minimum_relevance(policy["guidance_min_relevance"])
            task = self.input_bytes[turn["task_file"]]
            self.retain(f"task-{len(seen):03d}.txt", task)
            task_digests.add(hashlib.sha256(task).digest())
            prompt_step = turn["prompt_step"]
            require(self.commands[prompt_step] == ["blob", "read"],
                    "prompt is not from a public blob read")
            prompt = chunk_bytes(self.responses[prompt_step])
            prompt_ref = delivery[-1]["payload"]["prompt"]
            require(len(prompt) == prompt_ref["bytes"]
                    and self.responses[prompt_step]["object_id"] == prompt_ref["id"]
                    and hashlib.sha256(prompt).hexdigest() == prompt_ref["sha256"],
                    "prompt bytes differ from the delivered object")
            require(task and task in prompt, "delivered prompt lost task bytes")
            applicable = [candidates[key] for key in turn["candidate_ids"]]
            bindings = {item["id"] for item in applicable if item["binding"]}
            history = {item["id"]: item for item in applicable
                       if not item["binding"]}
            items = guidance["items"]
            item_ids = [item["decision_id"] for item in items]
            require(len(item_ids) == len(set(item_ids)), "duplicate guidance item")
            require({item["decision_id"] for item in items if item["binding"]}
                    == bindings, "current binding policy was lost")
            for item in items:
                candidate = candidates[item["decision_id"]]
                require(item["source"] == candidate["source"], "source changed")
                require(candidate["text"].encode() in prompt,
                        "selected source text is absent from prompt")
                if item["binding"]:
                    require(near(item["weight"], 1), "binding context decayed")
                    expected_age = max(0, seconds(turn["as_of"])
                                       - seconds(candidate["effective_at"]))
                    require(item["age_seconds"] == math.floor(expected_age),
                            "binding source age differs from the input")
                    require("score" not in item and "probability" not in item,
                            "binding context was relevance scored")
                    old_binding |= item["age_seconds"] > 4 * 14 * 86400
            for key, candidate in candidates.items():
                if not candidate["binding"] and key not in item_ids:
                    require(candidate["text"].encode() not in prompt,
                            "prompt included an unselected historical reminder")
            if turn["kind"] == "unavailable":
                require(guidance["status"] == "unavailable"
                        and "weighted_score" not in guidance
                        and guidance["notice"], "outage became a scored zero")
                require(set(item_ids) == bindings, "outage offered fake reminders")
                continue
            if turn["kind"] == "empty":
                require(not history and guidance["status"] == "empty"
                        and guidance["weighted_score"] == 0 and not judgments,
                        "empty history is not distinct from unavailable")
                continue
            require(guidance["status"] == "scored" and judgments,
                    "turn did not obtain complete judgments")
            input_steps = turn.get("judge_input_steps")
            if input_steps is None:
                input_steps = [turn["judge_input_step"]]
            require(isinstance(input_steps, list)
                    and len(input_steps) == len(judgments),
                    "every judge batch requires its actual retained input")
            audit_inputs = {}
            for step in input_steps:
                require(self.commands[step] == ["blob", "read"],
                        "judge input is not from a public audit blob read")
                chunk = self.responses[step]
                require(chunk["object_id"] not in audit_inputs,
                        "judge input reference was repeated")
                audit_inputs[chunk["object_id"]] = chunk_bytes(chunk)
            receipt_ids = []
            reply_ids = set()
            covered = set()
            probabilities = {}
            remaining_cost = None
            for reply in judgments:
                require(reply["status"] == "scored"
                        and reply["id"] not in reply_ids,
                        "reused or unscored judge batch")
                reply_ids.add(reply["id"])
                batch_ids = reply.get("batch_ids") or [reply["id"]]
                require(len(batch_ids) == len(set(batch_ids))
                        and not set(batch_ids).intersection(receipt_ids),
                        "duplicate batch receipt provenance")
                receipt_ids.extend(batch_ids)
                request_ref = reply["request"]
                judge_bytes = audit_inputs.pop(request_ref["id"])
                require(len(judge_bytes) == request_ref["bytes"]
                        and hashlib.sha256(judge_bytes).hexdigest()
                        == request_ref["sha256"],
                        "judge audit input differs from its retained request reference")
                judge_input = json.loads(judge_bytes)
                cap = judge_input["max_cost_micros"]
                cost = reply["cost_micros"]
                latency = reply["latency_ms"]
                require(isinstance(cap, int) and not isinstance(cap, bool)
                        and 0 < cap <= 2**53 - 1
                        and isinstance(cost, int) and not isinstance(cost, bool)
                        and 0 <= cost <= cap
                        and isinstance(latency, int) and not isinstance(latency, bool)
                        and 0 <= latency <= 2**53 - 1,
                        "judge reply exceeds its explicit measured cost or latency bounds")
                if remaining_cost is None:
                    remaining_cost = cap
                require(cap <= remaining_cost, "judge batch renewed the total cost budget")
                remaining_cost -= cost
                require(resolved_judge(judge_input["config"]) == approved_judge
                        and reply["selected_model"] == approved_judge["model"]
                        and reply["deployment_sha256"]
                        == approved_judge["deployment_sha256"],
                        "judge batch differs from approved provider pins")
                require(base64.b64decode(judge_input["task"], validate=True) == task,
                        "judge did not receive this turn's exact task")
                require(judge_input["context"]["logical_turn_id"] == turn_id
                        and judge_input["context"]["target"] == guidance["target"]
                        and judge_input["context"]["policy_generation"]
                        == guidance["policy_generation"],
                        "judge input changed turn, target or policy")
                batch = {item["id"]: item for item in judge_input["decisions"]}
                require(judge_input["purpose"] == "guidance"
                        and 0 < len(batch) <= 12
                        and len(batch) == len(judge_input["decisions"])
                        and set(batch).issubset(history)
                        and not covered.intersection(batch)
                        and batch == {key: {field: history[key][field] for field in
                                          ("id", "text", "source", "effective_at",
                                           "binding", "authority", "applies_to")}
                                      for key in batch},
                        "judge input dropped candidate text or judged binding policy")
                covered.update(batch)
                answered = set()
                for answer in reply["results"]:
                    probability = answer.get("probability")
                    key = answer["question_id"]
                    require(answer["status"] == "scored" and key in batch
                            and key not in probabilities
                            and near(probability, probability)
                            and 0 <= probability <= 1, "invalid judge probability")
                    answered.add(key)
                    probabilities[key] = probability
                require(answered == set(batch), "partial judge batch coverage")
            require(not audit_inputs and covered == set(history),
                    "partial judge input coverage")
            require(guidance["judgment_ids"] == receipt_ids
                    and (not guidance.get("judgment_id")
                         or guidance["judgment_id"] in reply_ids.union(receipt_ids)),
                    "wrong judge receipt")
            multi_batch |= len(history) > 12 and len(judgments) > 1
            require(set(probabilities) == set(history), "partial judge coverage")
            eligible = []
            now = seconds(turn["as_of"])
            half_life = policy["guidance_half_life_seconds"] or 14 * 86400
            require(half_life == turn["half_life_seconds"],
                    "fixture half-life differs from the approved policy")
            require(half_life > 0, "invalid half-life fixture")
            for key, candidate in history.items():
                age = max(0, now - seconds(candidate["effective_at"]))
                probability = probabilities[key]
                require((probability >= cutoff) or key not in item_ids,
                        "unrelated candidate filled a reminder slot")
                if probability >= cutoff:
                    eligible.append((key, age, probability))
            eligible.sort(key=lambda row: (
                row[1] / half_life - math.log2(row[2])
                if row[2] > 0 else math.inf, row[0]))
            reminders = [item for item in items if not item["binding"]]
            require([item["decision_id"] for item in reminders]
                    == [row[0] for row in eligible[:5]],
                    "reminder order, relevance cutoff, or five-item cap differs")
            over_five |= len(eligible) > 5
            for item, (_, age, probability) in zip(reminders, eligible):
                weight = math.exp2(-age / half_life)
                require(item["age_seconds"] == math.floor(age)
                        and near(item["weight"], weight)
                        and near(item["probability"], probability)
                        and near(item["score"], weight * probability),
                        "reminder metadata does not match the inputs")
            score = 0
            if eligible:
                youngest = min(row[1] for row in eligible)
                weights = [math.exp2(-(row[1] - youngest) / half_life)
                           for row in eligible]
                score = sum(weight * row[2] for weight, row in
                            zip(weights, eligible)) / sum(weights)
            require(near(guidance["weighted_score"], score),
                    "weighted mean differs from the complete eligible set")
            observations.append({
                "task": hashlib.sha256(task).hexdigest(), "as_of": turn["as_of"],
                "history": history, "half_life": half_life, "cutoff": cutoff,
                "judge": approved_judge, "probabilities": probabilities,
                "selected": [item["decision_id"] for item in reminders],
                "below_cutoff": any(value < cutoff for value in probabilities.values()),
            })
        require(len(task_digests) > 1, "task input was not varied")
        check_variations(observations)
        require(over_five and old_binding, "missing cap or old-binding control")
        require(multi_batch, "workload did not exercise complete multi-batch history")

    def collection(self, workload):
        checks = workload["collection"]["observation_steps"]
        statuses = workload["collection"]["status_steps"]
        require(checks and statuses, "missing collection observations")
        self.quiescent = all(
            self.commands[name] == ["lane", "check"]
            and self.responses[name]["state"] == "exited"
            and self.responses[name].get("survivors") == 0 for name in checks)
        self.collected = all(
            self.commands[name] == ["lane", "status"]
            and self.responses[name]["cleaned"] for name in statuses)
        require(self.quiescent and self.collected, "collection incomplete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    context = load(args.context)
    case = Case(context)
    verdict = "fail"
    try:
        require(sys.platform == "linux", "Linux test box required")
        require(args.context.is_absolute() and args.result.is_absolute()
                and args.context.resolve().is_relative_to(case.root)
                and args.result.resolve().is_relative_to(case.root),
                "context and result must be absolute paths in the test scope")
        require(context["schema"] == "laneboss.e2e-context.v2"
                and context["case_id"] == "guidance", "wrong case context")
        binding = load(Path(context["binding_file"]))
        require(binding["contract_revision"] == "v2.0-draft.4"
                and binding["config"] == context["config"],
                "case requires the matched draft.4 installed binding")
        binary = Path(context["binary"])
        require(hashlib.sha256(binary.read_bytes()).hexdigest()
                == context["binary_sha256"], "artifact digest differs")
        source = beneath(case.root, "workload.json")
        case.retain("workload.json", source.read_bytes())
        workload = load(source)
        require(workload["steps"], "empty workload")
        for index, step in enumerate(workload["steps"]):
            case.execute(step, index)
        case.collection(workload)
        case.check(workload)
        verdict = "pass"
    except (HandoffRefusal, OSError, ValueError, KeyError, TypeError, OverflowError,
            subprocess.SubprocessError) as error:
        # The reason is screened: input values and provider output stay in evidence.
        reason = type(error).__name__
        failure = {"category": reason}
        if isinstance(error, HandoffRefusal):
            failure.update(error.projection())
        if isinstance(error, OwnerWait):
            failure.update(error.projection())
            case.reached = False
        if isinstance(error, CheckFailure):
            failure["reason"] = str(error)
        else:
            case.reached = False
        case.retain("failure.json", encoded(failure))
        print("GUIDE-TURN failed; inspect retained inputs and CLI outputs",
              file=sys.stderr)
    result = {
        "schema": "laneboss.e2e-result.v2", "case_id": "guidance",
        "phase": context["phase"], "mutation_id": context["mutation_id"],
        "binary_sha256": context["binary_sha256"],
        "source_sha256": context["source_sha256"],
        "assertions": [{
            "id": "GUIDE-TURN", "reached": case.reached, "verdict": verdict,
            "observed_exit": case.observed_exit, "evidence": case.evidence_refs,
        }],
        "collection": {
            "processes_quiescent": case.quiescent,
            "temporary_resources_collected": case.collected,
            "evidence": case.evidence_refs,
        },
    }
    atomic(args.result, encoded(result))
    return 0 if verdict == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())

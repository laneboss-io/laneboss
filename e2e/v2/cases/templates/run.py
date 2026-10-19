#!/usr/bin/env python3
"""Outside-in template assertions; execute only on the disposable Linux box."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys


class CaseFailure(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def beneath(root, relative):
    candidate = root / relative
    if Path(relative).is_absolute() or not candidate.resolve().is_relative_to(root):
        raise CaseFailure("fixture or evidence path escapes its scope")
    return candidate


def load_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise CaseFailure("duplicate JSON field")
            result[key] = value
        return result

    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def require(condition, reason):
    if not condition:
        raise CaseFailure(reason)


class Case:
    def __init__(self, context):
        self.context = context
        self.root = Path(context["test_root"]).resolve(strict=True)
        self.evidence_root = Path(context["evidence_root"]).resolve(strict=True)
        for directory in (self.root, self.evidence_root):
            metadata = directory.stat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid()
                    and stat.S_IMODE(metadata.st_mode) & 0o077 == 0,
                    "test and evidence roots must be private and owned by the test identity")
        self.current = "TPL-SCOPE"
        self.counter = 0
        self.last_exit = 1
        self.children = set()
        self.reader_kind = None
        self.used_proofs = set()
        self.callers = {}
        self.default_caller = None
        self.assertions = {
            name: {
                "id": name, "reached": False, "verdict": "fail",
                "observed_exit": 1, "evidence": [],
            }
            for name in ("TPL-SCOPE", "LB-FIRST")
        }

    def keep(self, name, data):
        target = beneath(self.evidence_root, name)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(data)
        ref = {"path": name, "sha256": digest(data), "bytes": len(data)}
        self.assertions[self.current]["evidence"].append(ref)
        return ref

    def json_file(self, name, value):
        data = json.dumps(value, ensure_ascii=False, indent=2).encode() + b"\n"
        self.keep(name, data)
        return beneath(self.evidence_root, name)

    def setup_callers(self, fixture):
        self.reader_kind = fixture["reader_kind"]
        require(self.reader_kind in ("lane", "worker", "human"), "invalid fixture reader kind")
        primary = str(Path(self.context["binding_file"]).resolve(strict=True))
        self.default_caller = {
            "binding_file": primary, "reader_kind": self.reader_kind,
            "session_proofs": list(fixture.get("session_proofs", [])),
            "mutation_inputs": fixture.get("mutation_inputs", []), "identity": None,
        }
        self.callers[primary] = self.default_caller

    def input_guard(self, condition, reason):
        if not condition:
            self.assertions[self.current]["reached"] = False
            raise CaseFailure(reason)

    def caller(self, row):
        if "binding_file" not in row:
            self.input_guard("reader_kind" not in row or row["reader_kind"] == self.reader_kind,
                    "reader kind cannot change without a separate binding")
            return self.default_caller
        try:
            binding = beneath(self.root, row["binding_file"]).resolve(strict=True)
        except CaseFailure:
            self.assertions[self.current]["reached"] = False
            raise
        kind = row["reader_kind"]
        self.input_guard(kind in ("lane", "worker", "human"), "invalid alternate reader kind")
        key = str(binding)
        if key not in self.callers:
            self.callers[key] = {
                "binding_file": key, "reader_kind": kind,
                "session_proofs": list(row.get("session_proofs", [])),
                "mutation_inputs": row.get("mutation_inputs", []), "identity": None,
            }
        selected = self.callers[key]
        self.input_guard(selected["reader_kind"] == kind, "one binding has conflicting reader kinds")
        if selected["identity"] is None:
            identity = self.command(["identity", "self"], {}, caller=selected)
            if identity["config"] != self.context["config"] or identity["actor"]["kind"] != kind:
                self.assertions[self.current]["reached"] = False
                raise CaseFailure("alternate binding identity differs from its enrolled reader")
            selected["identity"] = identity
        return selected

    def proof_args(self, words, request, stem, selected):
        # policy.evaluate and blob staging use human.session, despite being
        # mutations. Only a non-session operation consumes an operation proof.
        operation_proof = words == ["org", "change", "propose"]
        key = secrets.token_urlsafe(32)
        proof_file = None
        if selected["reader_kind"] == "human":
            if operation_proof:
                matches = [row for row in selected["mutation_inputs"]
                           if row["command"] == words and row["request"] == request]
                if len(matches) != 1:
                    self.assertions[self.current]["reached"] = False
                    raise CaseFailure("human mutation lacks one exact retained key and operation proof")
                key, proof_file = matches[0]["idempotency_key"], matches[0]["proof_file"]
            else:
                if not selected["session_proofs"]:
                    self.assertions[self.current]["reached"] = False
                    raise CaseFailure("human read lacks a fresh connection-session proof")
                proof_file = selected["session_proofs"].pop(0)
        self.input_guard(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_-]{22,128}", key),
                "command lacks a valid retained idempotency key")
        argv = ["--idempotency-key", key]
        if proof_file is not None:
            proof_path = beneath(self.root, proof_file)
            proof_bytes, proof = proof_path.read_bytes(), load_json(proof_path)
            if not isinstance(proof, dict) or not proof.get("id") or proof["id"] in self.used_proofs:
                self.assertions[self.current]["reached"] = False
                raise CaseFailure("human proof is absent or reused across CLI connections")
            self.used_proofs.add(proof["id"])
            self.keep(stem + "-proof.json", proof_bytes)
            argv += ["--proof", str(beneath(self.evidence_root, stem + "-proof.json"))]
        return argv

    def command(self, words, request, success=True, raw=False, ergonomic=None, caller=None):
        self.input_guard(bool(words) and all(isinstance(w, str) for w in words),
                         "invalid fixture command")
        self.counter += 1
        stem = "commands/{:03d}".format(self.counter)
        path = self.json_file(stem + "-request.json", request)
        selected = self.default_caller if caller is None else caller
        self.input_guard(isinstance(selected, dict), "command has no enrolled reader")
        argv = [self.context["binary"], *words,
                "--config", self.context["config"],
                "--binding-file", selected["binding_file"]]
        argv += self.proof_args(words, request, stem, selected)
        template_view = words in (["brief", "render"], ["brief", "start"], ["start"])
        # The common --request path prints raw typed JSON. The feature path
        # verifies retained prompt/task bytes and supports Markdown output.
        if ergonomic is None:
            argv += ["--request-file" if template_view else "--request", str(path)]
        else:
            require(template_view and isinstance(ergonomic, list)
                    and all(isinstance(word, str) for word in ergonomic),
                    "ergonomic input is outside template views")
            argv += ergonomic
        if template_view:
            argv += ["--format", "markdown" if raw else "json"]
        self.json_file(stem + "-argv.json", argv)
        out_path = beneath(self.evidence_root, stem + "-stdout")
        err_path = beneath(self.evidence_root, stem + "-stderr")
        timed_out = False
        with out_path.open("wb") as out_file, err_path.open("wb") as err_file:
            process = subprocess.Popen(argv, stdout=out_file, stderr=err_file,
                                       start_new_session=True)
            self.children.add(process.pid)
            try:
                process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait(timeout=10)
        self.last_exit = process.returncode
        out, err = out_path.read_bytes(), err_path.read_bytes()
        self.keep(stem + "-stdout", out)
        self.keep(stem + "-stderr", err)
        self.json_file(stem + "-exit.json", {"exit": process.returncode})
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            self.children.discard(process.pid)
        if timed_out:
            self.assertions[self.current]["reached"] = False
            raise CaseFailure("CLI command exceeded its deadline")
        require(process.pid not in self.children,
                "CLI command left a surviving process group")
        if success:
            if process.returncode != 0:
                try:
                    failure = json.loads(err)
                except ValueError:
                    failure = None
                dependencies = ("not_implemented", "unavailable", "unsupported",
                                "prerequisite_missing", "unauthenticated",
                                "version_mismatch")
                if not isinstance(failure, dict) or failure.get("code") in dependencies:
                    self.assertions[self.current]["reached"] = False
                raise CaseFailure("CLI operation failed")
        else:
            require(process.returncode != 0, "negative request was accepted")
            try:
                failure = json.loads(err)
            except ValueError as error:
                self.assertions[self.current]["reached"] = False
                raise CaseFailure("negative failure is untyped") from error
            if not (isinstance(failure, dict) and failure.get("code")
                    and failure.get("instead") and failure.get("message")):
                self.assertions[self.current]["reached"] = False
                raise CaseFailure("negative failure is untyped")
            return failure
        if raw:
            return out
        value = json.loads(out)
        require(isinstance(value, dict), "CLI returned a non-object")
        return value

    def blob(self, ref, caller=None):
        data = bytearray()
        require(0 <= ref["bytes"] <= 67108864, "invalid blob size")
        while len(data) < ref["bytes"]:
            request = {"object_id": ref["id"], "offset": len(data),
                       "limit": min(262144, ref["bytes"] - len(data))}
            row = self.command(["blob", "read"], request, caller=caller)
            chunk = base64.b64decode(row["data"], validate=True)
            require(row["object_id"] == ref["id"]
                    and row["offset"] == len(data), "blob identity mismatch")
            require(0 < len(chunk) <= request["limit"], "invalid blob chunk size")
            require(digest(chunk) == row["sha256"], "blob chunk digest mismatch")
            data.extend(chunk)
        end = self.command(["blob", "read"], {"object_id": ref["id"],
                           "offset": ref["bytes"], "limit": 1}, caller=caller)
        require(end["object_id"] == ref["id"] and end["offset"] == ref["bytes"]
                and base64.b64decode(end["data"], validate=True) == b""
                and end["sha256"] == digest(b""),
                "blob has undeclared bytes or an invalid exact-end receipt")
        require(digest(data) == ref["sha256"], "blob digest mismatch")
        return bytes(data)

    def negative(self, rows, name):
        matches = [row for row in rows if row["name"] == name]
        require(len(matches) == 1, "missing or duplicated negative request")
        row = matches[0]
        selected = self.caller(row)
        require(row["command"] in (["brief", "render"], ["org", "validate"],
                                   ["org", "change", "propose"]),
                "negative request is outside template validation")
        if not isinstance(row["request"], dict):
            self.assertions[self.current]["reached"] = False
            raise CaseFailure("negative request body is not an object")
        if row["command"] == ["org", "change", "propose"]:
            identity = selected["identity"]
            if not (identity is not None and identity["actor"]["kind"] == "lane"
                    and identity["actor"]["level"] == 6):
                self.assertions[self.current]["reached"] = False
                raise CaseFailure("D6 source negatives need an authenticated L6 lane binding")
        isolated = True
        if row["command"] == ["brief", "render"] and name in ("wrong-hash", "wrong-role"):
            request, baseline = row["request"], self.render_request
            isolated = (set(request) == set(baseline)
                        and request.get("grant_set_id") == baseline["grant_set_id"])
            if name == "wrong-hash":
                task = request.get("task", {})
                if not isinstance(task, dict):
                    self.assertions[self.current]["reached"] = False
                    raise CaseFailure("negative task claim is not an object")
                claimed_hash = task.get("sha256", "")
                isolated = (isolated and request.get("context") == baseline["context"]
                            and all(task.get(key) == baseline["task"][key]
                                    for key in ("id", "bytes", "class"))
                            and isinstance(claimed_hash, str) and len(claimed_hash) == 64
                            and all(char in "0123456789abcdef" for char in claimed_hash)
                            and claimed_hash != baseline["task"]["sha256"])
            else:
                context = request.get("context", {})
                if not isinstance(context, dict):
                    self.assertions[self.current]["reached"] = False
                    raise CaseFailure("negative role context is not an object")
                original = baseline["context"]
                isolated = (isolated and request.get("task") == baseline["task"]
                            and set(context) == set(original)
                            and context.get("instance_id") == original.get("instance_id")
                            and (context.get("level") != original["level"]
                                 or context.get("role") != original["role"]))
        if row["command"] == ["org", "validate"] and name == "wrong-generation":
            generation = row["request"].get("generation")
            isolated = (isinstance(generation, int) and not isinstance(generation, bool)
                        and generation > 0 and generation != self.template_generation)
        if not isolated:
            self.assertions[self.current]["reached"] = False
            raise CaseFailure("negative request does not isolate its named boundary")
        failure = self.command(row["command"], row["request"], success=False, caller=selected)
        if failure["code"] in ("not_implemented", "unavailable", "unsupported",
                               "prerequisite_missing", "unauthenticated"):
            self.assertions[self.current]["reached"] = False
            raise CaseFailure("negative request did not reach validation")
        if failure["code"] not in row["error_codes"]:
            self.assertions[self.current]["reached"] = False
            raise CaseFailure("negative request failed for the wrong reason")
        messages = {
            "wrong-hash": (
                "template source bytes differ from their retained digest",
                "blob claim differs from its committed metadata or configuration",
                "approved source inventory has invalid kind, mode, digest or revision generation",
                "approved source identity differs from its committed content",
                "retained blob differs from its committed digest",
                "render task differs from the life’s retained task"),
            "wrong-generation": (
                "template source generation differs from the approved snapshot",
                "template snapshot is stale or belongs to another role",
                "approved source inventory has invalid kind, mode, digest or revision generation",
                "org validation generation is stale"),
            "wrong-role": (
                "template source does not belong to the selected layer and role",
                "requested briefing context differs from the authenticated lane",
                "render role and grants differ from the authentic lane",
                "briefing role or grant claim differs from the authenticated life",
                "briefing template belongs to another level or role"),
            "malformed-source": ("template source is missing a required role section",),
            "bare-claude": (
                "driver source contains an unsupported primary agent driver",),
        }
        if failure["message"] not in messages[name]:
            self.assertions[self.current]["reached"] = False
            raise CaseFailure("negative request failed outside its intended validation boundary")

    def config_view(self):
        view = self.command(["config", "read"], {"view": "roles"})
        projection = self.blob(view["projection"])
        self.keep("config/{:03d}-projection.json".format(self.counter), projection)
        value = json.loads(projection)
        require(isinstance(value, dict)
                and value["schema"] == "laneboss.config-view.v2"
                and value["config"] == self.context["config"]
                and value["view"] == "roles"
                and value["generation"] == view["generation"],
                "config projection differs from its typed scope or generation")
        # A new immutable output object ID is not an org change. Compare the
        # actual verified projection bytes and source/generation metadata.
        return {"generation": view["generation"], "sources": view["sources"],
                "warnings": view["warnings"], "projection": projection}

    def check_fallback(self, fixture):
        selected = self.caller(fixture)
        expected = fixture["expected"]
        if selected["reader_kind"] in ("lane", "worker"):
            identity = selected["identity"]
            if identity is None or identity["actor"]["life_id"] != expected["life_id"]:
                self.assertions[self.current]["reached"] = False
                raise CaseFailure("fallback binding does not belong to its fixture life")
            if selected["reader_kind"] == "lane":
                role = fixture["render_request"]["context"]
                self.input_guard(identity["actor"]["level"] == role["level"]
                                 and identity["actor"]["role"] == role["role"],
                                 "fallback binding has a different authentic role")
        task = beneath(self.root, expected["task_file"]).read_bytes()
        self.keep("fallback/task", task)
        source = beneath(self.root, expected["org_template_file"]).read_bytes()
        self.keep("fallback/org-template.md", source)
        result = self.command(["brief", "render"], fixture["render_request"], caller=selected)
        rendered = self.blob(result["markdown"], caller=selected)
        self.keep("fallback/prompt.md", rendered)
        require(result["template"]["source_sha256"] == digest(source)
                and result["template"]["generation"] == expected["template_generation"],
                "missing local pair did not inherit its approved org default")
        require(rendered.endswith(task) and source in rendered,
                "org fallback lost the source or exact assigned task")

    def lanes(self):
        page = self.command(["lane", "list"], {"cursor": "", "limit": 200})
        require(not page["cursor"], "fixture needs a single isolated lane page")
        require(all(row["state"] in ("preparing", "running", "stopping",
                                      "profile_wait", "verifying", "idle",
                                      "accepted", "merged", "abandoned", "lost")
                    for row in page["lanes"]), "fixture has an unknown lane state")
        # Internal immutable-object retention may advance an event cursor.
        # Every lifecycle field, including run/generation/launch ID, stays in
        # the comparison, so even a transient launch changes this snapshot.
        return {"cursor": page["cursor"],
                "lanes": [{key: value for key, value in row.items() if key != "last_seq"}
                          for row in page["lanes"]]}

    def run(self):
        source = self.root / "templates-inputs.json"
        fixture_bytes = source.read_bytes()
        self.keep("inputs/fixture.json", fixture_bytes)
        fixture = load_json(source)
        self.setup_callers(fixture)
        self.json_file("inputs/coverage.json", {
            "public_hash_control": "retained task claim; does not prove template source digest validation",
            "public_generation_control": "org generation claim; does not prove template source generation validation",
            "source_digest_generation": "separate component controls and D6 acceptance are required",
        })
        expected = fixture["expected"]
        self.render_request = fixture["render_request"]
        self.template_generation = expected["template_generation"]
        task = beneath(self.root, expected["task_file"]).read_bytes()
        require(bool(task), "fixture task must contain exact nonempty bytes")
        self.keep("inputs/task", task)
        sources = {}
        for name, relative in expected["source_files"].items():
            data = beneath(self.root, relative).read_bytes()
            self.keep("inputs/sources/" + name, data)
            sources[name] = data
        require(any(digest(data) == expected["template_sha256"]
                    for data in sources.values()), "expected template is not retained")
        identity = self.command(["identity", "self"], {})
        self.default_caller["identity"] = identity
        actor = identity["actor"]
        require(identity["config"] == self.context["config"]
                and actor["kind"] == self.reader_kind,
                "fixture client has no authentic template reader identity")
        if actor["kind"] in ("lane", "worker"):
            require(actor["life_id"] == expected["life_id"],
                    "fixture lane identity differs from the public self-render scope")
        if actor["kind"] == "lane":
            require(actor["level"] == expected["level"] and actor["role"] == expected["role"],
                    "fixture lane role differs from the public self-render scope")
        before = self.lanes()
        org_before = self.config_view()
        self.assertions[self.current]["reached"] = True
        briefing = self.command(["brief", "render"], fixture["render_request"])
        markdown = self.blob(briefing["markdown"])
        self.keep("render/prompt.md", markdown)
        template = briefing["template"]
        require(template["id"] == expected["template_id"],
                "selected template identity differs from the approved receipt")
        require(template["generation"] == expected["template_generation"],
                "template generation differs from applied receipt")
        require(template["source_sha256"] == expected["template_sha256"],
                "template hash differs from applied receipt")
        require(template["rendered_sha256"] == digest(markdown),
                "rendered digest differs from actual bytes")
        require(briefing["policy_generation"] == expected["policy_generation"],
                "wrong policy generation")
        require(markdown.endswith(task) and
                b"## Assigned task\n\n" in markdown[:-len(task)],
                "exact assigned task bytes were dropped or rewritten")
        require(("Level: L{}\n".format(expected["level"])).encode() in markdown
                and ("Role: {}\n".format(expected["role"])).encode() in markdown,
                "selected role or level missing")
        require(expected["grant_set_id"].encode() in markdown,
                "grant set absent from prompt")
        report_line = "Report line: {} → {}".format(
            expected["life_id"], expected["parent_life_id"]).encode()
        require(report_line in markdown,
                "authentic parent missing from report line")
        require(all(row["available"] for row in briefing["checks"])
                and briefing["checks"], "briefing has incomplete checks")
        for ref in briefing["sources"]:
            require(ref["path"] in sources, "source provenance is not retained")
            require(digest(sources[ref["path"]]) == ref["sha256"],
                    "source provenance digest differs from retained bytes")
        human = self.command(["brief", "render"], fixture["render_request"], raw=True)
        require(human == markdown, "human CLI output changes rendered bytes")
        flags = ["--level", str(expected["level"]), "--role", expected["role"],
                 "--grant-set-id", expected["grant_set_id"], "--brief",
                 str(beneath(self.root, expected["task_file"]))]
        instance = fixture["render_request"]["context"].get("instance_id")
        if instance:
            flags += ["--instance-id", instance]
        ergonomic = self.command(["brief", "render"], fixture["render_request"],
                                 raw=True, ergonomic=flags)
        require(ergonomic == markdown,
                "ergonomic render changed the retained task or prompt bytes")
        start = self.command(["start"], fixture["start_request"])
        start_markdown = self.blob(start["markdown"])
        self.keep("start/prompt.md", start_markdown)
        start_expected = fixture["start_expected"]
        start_task = beneath(self.root, start_expected["task_file"]).read_bytes()
        self.keep("start/original-task", start_task)
        start_lane = self.command(["lane", "status"], {
            "life_id": start_expected["life_id"], "run": 0})
        require(start_lane["life_id"] == start_expected["life_id"]
                and start_lane["level"] == fixture["start_request"]["level"]
                and start_lane["role"] == fixture["start_request"]["role"]
                and start_lane["task"]["class"] == "task"
                and self.blob(start_lane["task"]) == start_task,
                "start original-task association differs from setup and life")
        require(start_markdown.endswith(b"## Assigned task\n\n" + start_task),
                "start did not print the exact retained original task")
        start_human = self.command(["start"], fixture["start_request"], raw=True)
        require(start_human == start_markdown,
                "human start output changes retained briefing bytes")
        self.check_fallback(fixture["fallback"])
        for name in ("wrong-hash", "wrong-generation", "wrong-role",
                     "malformed-source"):
            self.negative(fixture["negative_requests"], name)
        events = self.command(["event", "tail"], fixture["event_request"])
        require(events["complete"], "launch evidence is incomplete")
        starts = [row for row in events["events"]
                  if row["kind"] == "lane.started"
                  and row["origin"] == "service"
                  and row["life_id"] == expected["life_id"]]
        require(len(starts) == 1, "actual lane launch receipt is absent or ambiguous")
        launch = starts[0]["payload"]
        require(launch["lane"]["level"] == expected["level"]
                and launch["lane"]["role"] == expected["role"]
                and launch["lane"]["parent_life_id"] == expected["parent_life_id"],
                "actual launch used a different authentic role or parent")
        require(launch["prompt_template"] == template, "launch used another template")
        require(launch["task_sha256"] == digest(task), "launch used another task")
        require(launch["task"] == fixture["render_request"]["task"]
                and launch["lane"]["task"] == launch["task"]
                and launch["lane"]["launch_id"] == launch["launch_id"],
                "launch omitted its retained task and launch association")
        require(self.blob(launch["prompt"]) == markdown,
                "actual lane prompt differs from render")
        observed = [row for row in events["events"]
                    if row["kind"] == "prompt.observed"
                    and row["origin"] == "service"
                    and row["life_id"] == expected["life_id"]
                    and row["run"] == starts[0]["run"]]
        require(any(row["payload"]["status"] in ("written", "completed")
                    and row["logical_turn_id"] == launch["lane"]["logical_turn_id"]
                    and row["payload"]["task"] == launch["task"]
                    and row["payload"]["prompt"] == launch["prompt"]
                    for row in observed), "prompt delivery lacks a real receipt")
        require(self.lanes() == before, "briefing or invalid input launched a lane")
        require(self.config_view() == org_before,
                "briefing or invalid source changed the approved org snapshot")
        self.assertions[self.current].update(verdict="pass", observed_exit=0)

        self.current = "LB-FIRST"
        self.assertions[self.current]["reached"] = True
        require(b"laneboss org blacklist list" in markdown
                and b"laneboss org blacklist list" in start_markdown,
                "blacklist discovery route is missing")
        policy = self.command(["org", "blacklist", "list"],
                              {"life_id": expected["life_id"]})
        sessions = "laneboss lane start / laneboss lane resume / laneboss lane turn"
        routes = {
            "raw-codex-exec": sessions,
            "raw-claude-p": sessions,
            "raw-claude-print": sessions,
            "raw-claudock-run": sessions,
            "raw-tmux-new-session": "laneboss lane start",
            "raw-tmux-new": "laneboss lane start",
            "raw-tmux-kill-session": "laneboss lane stop",
            "raw-tmux-send-keys": "laneboss lane attach",
            "raw-tmux-attach": "laneboss lane attach",
            "raw-tmux-attach-session": "laneboss lane attach",
            "raw-aws-run-instances": "laneboss box",
            "raw-gcloud-instances-create": "laneboss box",
        }
        rules = policy["rules"]
        require(len(rules) == 12 and {r["id"] for r in rules} == set(routes),
                "seeded workflow inventory differs from twelve entries")
        for row in rules:
            require(routes[row["id"]] == row["instead"], "Instead route was lost")
            if row["id"].startswith("raw-tmux-"):
                require("agent" in row["text"].lower(),
                        "tmux entry also forbids ordinary build sessions")
        self.negative(fixture["negative_requests"], "bare-claude")
        decision = self.command(["policy", "evaluate"], fixture["ordinary_request"])
        require(decision["result"] == "allow" and decision["audit_complete"],
                "unfamiliar ordinary work failed or lacks audit evidence")
        require(self.lanes() == before, "read-only case changed lane state")
        require(self.config_view() == org_before,
                "workflow checks changed the approved org snapshot")
        self.assertions[self.current].update(verdict="pass", observed_exit=0)

    def result(self):
        return {
            "schema": "laneboss.e2e-result.v2", "case_id": "templates",
            "phase": self.context["phase"],
            "mutation_id": self.context["mutation_id"],
            "binary_sha256": self.context["binary_sha256"],
            "source_sha256": self.context["source_sha256"],
            "assertions": list(self.assertions.values()),
            "collection": {
                "processes_quiescent": not self.children,
                "temporary_resources_collected": not self.children,
                "evidence": [],
            },
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    context = load_json(args.context)
    require(context["schema"] == "laneboss.e2e-context.v2"
            and context["case_id"] == "templates", "wrong harness context")
    case = Case(context)
    status = 1
    try:
        require(sys.platform == "linux", "this case requires the Linux test box")
        binary = Path(context["binary"])
        require(digest(binary.read_bytes()) == context["binary_sha256"],
                "installed artifact digest mismatch")
        case.run()
        status = 0
    except (CaseFailure, OSError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired) as error:
        # Keep only the exception class and our screened assertion messages.
        reason = str(error) if isinstance(error, CaseFailure) else type(error).__name__
        if not isinstance(error, CaseFailure):
            case.assertions[case.current]["reached"] = False
        case.keep("failure.txt", (reason + "\n").encode())
        case.assertions[case.current]["observed_exit"] = case.last_exit
    finally:
        args.result.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = args.result.with_suffix(args.result.suffix + ".tmp")
        temporary.write_text(json.dumps(case.result(), indent=2) + "\n")
        os.replace(temporary, args.result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())

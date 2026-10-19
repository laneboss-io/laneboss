"""G0 callbacks using the original installed human and Linux producer."""

import base64
import copy
import json
import os
from pathlib import Path
import uuid


class Session:
    def __init__(self, case, plan, require, fail, factory, io):
        self.case, self.plan = case, plan
        self.require, self.fail, self.factory, self.io = require, fail, factory, io
        self.context = self.producer = self.proxy = None
        self.operations = {}
        self.target = self.record = self.clean = None
        self.stopped = self.receipt = self.collection_error = None
        self.index = 0

    def populate(self, context):
        self.case.human_prefix = "itemlinux"
        self.case.current = "item.linux.prepare"
        self.require(self.producer is None, "Linux populate was already attempted")
        self.context = context
        self.producer = self.factory(self.case, context)
        try:
            self.producer.prepare(self.plan, publish=False)
        except Exception:
            for name, raw in self.producer.inputs.items():
                self.case.keep("linux-prep-" + name + ".input", raw)
            raise
        consumer = self.producer.consumer
        session = self

        class Outside(consumer.Case):
            def keep(self, name, raw):
                super().keep("outside/" + name, raw)

            def call(self, words, body):
                reply = session.invoke(" ".join(words), body,
                                       uuid.uuid4().hex, uuid.uuid4().hex)
                session.require(reply["exit_code"] == 0, "outside CLI failed")
                return json.loads(base64.b64decode(reply["stdout"], validate=True))

        self.proxy = Outside(context)
        return dict(self.producer.inputs)

    def validate(self, command, body):
        self.require(self.stopped is None, "Linux transport stopped at its first refusal")
        allowed = {"lane start", "lane status", "lane check", "lane stop", "lane archive",
                   "lane review", "lane mark", "lane clean", "operation get", "event tail"}
        self.require(command in allowed, "unsupported Linux transport operation")
        if command == "lane start":
            self.require(not self.operations and body == self.producer.start,
                         "Linux start differs from exact authorized input")
            return
        if command == "operation get":
            self.require(body["operation_id"] in self.operations,
                         "Linux operation is outside its actual managed set")
            return
        target = body if command in {"lane status", "lane check"} else body.get("target")
        if command == "event tail":
            target = {"life_id": body["life_id"], "run": body["run"]}
        self.require(self.target is not None and target == self.target,
                     "Linux transport target belongs to another life")
        if command == "lane stop":
            self.require(body["reason"] == self.producer.native["cell"]["stop_reason"],
                         "Linux stop reason differs from its committed input")
        if command == "lane mark":
            self.require(body["state"] == "abandoned", "Linux case cannot accept or merge work")

    def invoke(self, command, body, request_id, key):
        self.validate(command, body)
        case = self.case
        case.human_prefix = "itemlinux"
        phase = "collection" if case.current == "item.linux.collection" else "run"
        case.current = "item.linux." + phase
        self.index += 1
        words = command.split()
        try:
            if command in {"lane check", "lane review"}:
                target = body if command == "lane check" else body["target"]
                lane = case.human.read("linux-proof-status", ["lane", "status"], target)
                self.producer.after_call(["lane", "status"], target, lane)
                case.current = "item.linux." + phase
            self.producer.before_call(self.index, words, body)
            case.current = "item.linux." + phase
            canary = getattr(case, "api_key_canary", None)
            if command == "lane clean" and canary is not None:
                self.require(self.record is not None and self.record["quiescent"],
                             "Linux key scan requires an observed stopped lane")
                if not self.record.get("api_key_scanned"):
                    canary.scan_lane(case, self.record)
            proof = self.producer.root / "authority" / ("%06d.proof.json" % self.index)
            options = {"request_id": request_id, "idempotency_key": key,
                       "session_proof" if command == "lane start" else "proof": str(proof)}
            case.checked_cli("linux-rpc", words, body, **options)
        except Exception as error:
            self.stopped = error
            if self.proxy is not None:
                self.proxy.refused = True
            raise
        raw_out = (case.root / case.last["stdout"]).read_bytes()
        raw_err = (case.root / case.last["stderr"]).read_bytes()
        code = case.last["exit_code"]
        self.require(code == 0, "Linux CLI returned a nonzero exit")
        value = json.loads(raw_out)
        self.producer.after_call(words, body, value)
        if self.proxy is not None:
            stem = "rpc/" + str(self.index)
            for suffix, raw in (("request", self.io.encoded(body)), ("stdout", raw_out),
                                ("stderr", raw_err), ("exit", (str(code) + "\n").encode())):
                self.proxy.keep(stem + "." + suffix, raw)
        if value.get("error") is not None:
            case.rows[case.current]["observed"].update({
                "refusal": value["error"], "operation": value, "exit_code": code})
            self.stopped = self.fail("installed Linux operation refused; retained actual response")
            if self.proxy is not None:
                self.proxy.refused = True
            raise self.stopped
        if command in {"lane start", "lane stop", "lane mark", "lane clean"}:
            self.require(value.get("id") and value.get("status"), "actual operation identity is missing")
            self.operations[value["id"]] = value
            if command == "lane clean":
                self.clean = value
            if command == "lane start" and value.get("life_id") and value.get("run"):
                self.target = {"life_id": value["life_id"], "run": value["run"]}
        if command == "operation get":
            self.operations[value["id"]] = value
            if self.target is None and value.get("life_id") and value.get("run"):
                self.target = {"life_id": value["life_id"], "run": value["run"]}
            if self.clean is not None and self.clean["id"] == value["id"]:
                self.clean = value
        if self.record is not None:
            if command == "lane check":
                handle = value.get("handle")
                self.require(isinstance(handle, dict) and handle.get("target") == self.target,
                             "Linux process observation has a foreign handle")
                if "handle" in self.record:
                    self.require(handle == self.record["handle"], "Linux original process handle changed")
                else:
                    self.record["handle"] = handle
            if command == "lane check" and value.get("state") == "exited" and value.get("survivors") == 0:
                self.record["quiescent"] = True
            if command == "lane archive":
                self.record["collecting"] = True
        return {"exit_code": code, "stdout": base64.b64encode(raw_out).decode(),
                "stderr": base64.b64encode(raw_err).decode()}

    def hook(self, action, body):
        p = self.producer
        self.require(p is not None and self.proxy is not None and self.stopped is None,
                     "Linux private observer is unavailable")
        if action == "before-start":
            self.require(not self.operations and body["cell"] == p.native["cell"],
                         "Linux pre-start cell differs")
            p.before_start(self.proxy, body["cell"])
            value = {}
        elif action == "network-positive":
            self.require(not self.operations, "network baseline cannot change after start")
            payload = bytes.fromhex(body["payload_hex"])
            actual = json.loads(p.inputs["canary-input.json"])["payload_hex"]
            self.require(body["payload_hex"] == actual, "network control bytes differ")
            value = p.network.positive_control(payload)
        elif action in {"network-finish", "network-close"}:
            value = p.network.finish() if action == "network-finish" else p.network.close()
        elif action == "after-start":
            operation = body["operation"]
            self.require(self.operations.get(operation["id"]) == operation and
                         body["target"] == self.target and body["cell"] == p.native["cell"],
                         "Linux native join differs from its actual start")
            self.require(self.record is None, "Linux native join was already attempted")
            self.record = {"cell": copy.deepcopy(body["cell"]), "target": self.target,
                "uid": None, "observer": p.network, "started": True,
                "quiescent": False, "collected": False, "collecting": False,
                "operation": operation}
            self.proxy.records.append(self.record)
            self.proxy.owned.append(self.record)
            p.after_start(self.proxy, self.record, operation)
            original = self.proxy.evidence / "outside/native/helper-lease.json"
            self.record["lease"] = json.loads(original.read_bytes())["lease"]
            value = {"cell": self.record["cell"], "uid": self.record["uid"]}
        elif action == "release-input":
            self.require(self.record is not None and body["cell"] == self.record["cell"],
                         "Linux release mapping differs from native observations")
            raw = base64.b64decode(body["input"], validate=True)
            self.require(raw == p.inputs["canary-input.json"], "Linux released input bytes differ")
            p.release_input(self.proxy, self.record, raw)
            value = {}
        elif action == "foreign":
            self.require(body["phase"] in {"after-canary", "after-stop"}, "unknown foreign observation phase")
            p.check_foreign(self.proxy, body["phase"])
            value = {}
        elif action == "review":
            self.require(body["target"] == self.target and self.record is not None,
                         "Linux review target differs")
            value = p.review(self.proxy, self.target, self.record["cell"])
            self.record["cell"]["review"] = value
        else:
            raise self.fail("unknown Linux private observer action")
        return {"data": value, "evidence": list(self.proxy.references)}

    def transport(self, request):
        self.case.human_prefix = "itemlinux"
        self.case.current = "item.linux.run"
        self.require(request.get("action") == "rpc" and request.get("denied") is False and
                     request.get("request_id") and request.get("idempotency_key"),
                     "invalid Linux observer envelope")
        command = request["command"]
        if command.startswith("linux "):
            value = self.hook(command[6:], request["request"])
            return {"exit_code": 0, "stdout": base64.b64encode(self.io.encoded(value)).decode(),
                    "stderr": base64.b64encode(b"").decode()}
        return self.invoke(command, request["request"], request["request_id"], request["idempotency_key"])

    def collect(self, context, operations):
        if self.collection_error is not None:
            raise self.collection_error
        self.require(context == self.context, "Linux collector context differs")
        if self.receipt is not None:
            self.require(set(operations) <= set(self.receipt["operation_ids"]),
                         "Linux cached collection omitted an operation")
            return self.receipt
        try:
            self.require(context == self.context and self.stopped is None,
                         "Linux collection stopped at its original refusal")
            self.require(set(operations) <= set(self.operations), "unknown Linux managed operation")
            self.case.human_prefix = "itemlinux"
            self.case.current = "item.linux.collection"
            self.require(self.record is not None and self.clean is not None and
                         self.operations[self.clean["id"]].get("status") == "succeeded",
                         "Linux actual clean operation has not completed")
            lane = self.proxy.call(["lane", "status"], self.target)
            self.require(lane.get("cleaned") is True, "Linux cleaned status was not observed")
            cell = self.record["cell"]
            worktree = Path(cell["observer_paths"]["worktree"])
            self.require(not os.path.lexists(worktree), "Linux actual worktree still exists")
            native = self.case.native_cleanup_evidence(
                {"name": "itemlinux", "target": self.target}, lane, self.operations[self.clean["id"]])
            self.require(native.get("action") == "remove_clean", "Linux native cleanup retained its workspace or branch")
            uid_after = self.producer.consumer.uid_processes(self.record["uid"])
            self.require(not uid_after, "Linux owned UID has live processes")
            page = self.proxy.call(["event", "tail"], {
                "life_id": self.target["life_id"], "run": self.target["run"], "since": 0,
                "cursor": "", "follow": False, "until": "", "deadline_ms": 1000})
            self.require(page.get("complete") is True, "Linux release snapshot is incomplete")
            releases = [event["payload"] for event in page["events"]
                if event.get("kind") == "helper.released" and
                event.get("operation_id") == self.clean["id"] and
                event.get("life_id") == self.target["life_id"] and event.get("run") == self.target["run"]]
            self.require(len(releases) == 1, "Linux actual helper release is missing or ambiguous")
            release = releases[0]
            self.require(isinstance(release.get("lease_id"), str) and
                         release["lease_id"].replace("-", "").replace("_", "").isalnum(),
                         "Linux release has an invalid lease selector")
            counts = [release.get("live_connections"), release.get("queued_jobs"),
                      release.get("writable_exports"), release.get("quiescence", {}).get("survivors")]
            self.require(all(type(value) is int and value == 0 for value in counts) and
                release.get("id") and release.get("observed_at") and release.get("effect_id") and
                release.get("backend") == "linux-bwrap-landlock" and
                release.get("operation_id") == self.clean["id"] and
                release.get("lease_id") == self.record["lease"]["id"] and
                release.get("quiescence", {}).get("state") == "exited" and
                release.get("containment_id") == Path(cell["cgroup_relative"]).name and
                release.get("containment_id") == self.record["lease"]["containment_id"] and
                release.get("quiescence", {}).get("handle") == self.record["handle"],
                "Linux release has unknown counts or foreign containment")
            path = Path("/var/lib/laneboss-v2/helper") / self.case.config / (release["lease_id"] + ".json")
            raw = self.producer.consumer.read_fenced(path.parent, path.name)[0]
            journal = json.loads(raw)
            self.require(journal.get("schema") == "laneboss.helper-lease.v2" and
                         journal.get("phase") == "released" and journal.get("receipt") == release and
                         journal.get("lease") == self.record["lease"] and
                         journal["lease"]["uid"] == self.record["uid"],
                         "Linux helper journal does not attest the actual released UID")
            group = Path("/sys/fs/cgroup") / cell["cgroup_relative"].lstrip("/")
            self.require(not group.is_symlink(), "Linux released cgroup is linked")
            containment = self.proxy.cgroup_observation(cell) if group.exists() else None
            self.require(containment is None or (not containment["pids"] and
                containment["events"].get("populated") == 0), "Linux actual cgroup remains populated")
            self.proxy.keep("collection.json", self.io.encoded({"status": lane, "release": release,
                "native_cleanup": native,
                "journal_sha256": self.producer.consumer.digest(raw), "uid_after": uid_after,
                "cgroup": containment, "cgroup_present": group.exists(), "worktree_exists": worktree.exists()}))
            self.producer.close()
            fixtures = json.loads((Path(context["test_root"]) / "outside-collection.json").read_bytes())
            self.require(not fixtures["errors"] and not fixtures["public"]["retained"] and
                         fixtures["signal"]["collected"] and not fixtures["permitted"]["thread_alive"],
                         "Linux independent fixture collection is incomplete")
            self.proxy.keep("fixtures.json", self.io.encoded(fixtures))
            self.record["collected"] = True
            self.record["quiescent"] = not uid_after
            self.receipt = {"processes_quiescent": not uid_after,
                "temporary_resources_collected": not worktree.exists() and not fixtures["public"]["retained"],
                "operation_ids": list(self.operations), "evidence": list(self.proxy.references)}
            return self.receipt
        except Exception as error:
            self.collection_error = error
            raise

    def abort(self):
        if self.receipt is not None:
            return []
        if self.stopped is not None:
            if self.producer is not None and not self.producer.closed:
                self.producer.close(Path(self.context["test_root"]) / "no-entry-result")
            return [{"reason": "Linux stopped at its original refusal; collection is incomplete"}]
        if self.producer is None:
            return []
        if self.record is None and not self.operations:
            if not self.producer.closed:
                self.producer.close()
            path = Path(self.context["test_root"]) / "outside-collection.json"
            if not path.is_file():
                return [{"reason": "Linux fixture close has no observed receipt"}]
            observed = json.loads(path.read_bytes())
            if observed.get("errors") or observed.get("public", {}).get("retained"):
                return [{"reason": "Linux fixture close is incomplete", "observed": observed}]
            return []
        if self.proxy is not None:
            if self.record is None and self.target is not None:
                self.record = {"cell": copy.deepcopy(self.producer.native["cell"]),
                    "target": self.target, "uid": None, "observer": self.producer.network,
                    "started": True, "quiescent": False, "collected": False,
                    "collecting": False}
                self.proxy.records.append(self.record)
                self.proxy.owned.append(self.record)
            if self.record is not None and not self.record["collecting"]:
                self.proxy.cleanup()
                self.case.keep_json("linux-abort.input.json", {
                    "target": self.target, "quiescent": self.proxy.quiescent,
                    "collected": self.proxy.collected, "errors": self.proxy.cleanup_errors})
        if not self.producer.closed:
            self.producer.close(Path(self.context["test_root"]) / "no-entry-result")
        # A failed installed collector is never retried under a different form.
        return [{"target": self.target, "reason": "Linux native collection remains incomplete"}]

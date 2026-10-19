"""Linux-only black-box case. Run by the supervisor, never on the authoring Mac."""

import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import subprocess
import stat
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Lock

from controls import Controller, ControlError, parse, protected


ASSERTIONS = [
    "WATCHDOG-LIMIT", "WATCHDOG-NO-ROOM", "WATCHDOG-TAMPER",
    "WATCHDOG-STOP-RACE", "WATCHDOG-RESUME-RACE",
    "WATCHDOG-RESTART",
]
REVISION = "v2.0-draft.4"
LANE_BINDING = "/run/laneboss/binding.json"
LANE_SOCKET = "/run/laneboss/service.sock"


class Failure(Exception):
    def __init__(self, reason, reached=True, observed_exit=1):
        super().__init__(reason)
        self.reached = reached
        self.observed_exit = observed_exit


class SetupFailure(Failure):
    """A named missing fixture, including the separate human-reader port."""

    def __init__(self, reason, owner_in_person=()):
        super().__init__(reason, reached=False, observed_exit=69)
        self.owner_in_person = list(owner_in_person)


def require(condition, reason):
    if not condition:
        raise Failure(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def atomic(path, data):
    temporary = path.with_name(path.name + "." + secrets.token_hex(8))
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def beneath(root, name):
    path = (root / name).resolve()
    require(path.is_relative_to(root), "case input escaped its disposable scope")
    return path


def utc(value):
    require(isinstance(value, str) and value.endswith("Z"), "missing UTC observation time")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def inherited_lane_descriptors(binding_file, config):
    """Preserve exactly the two fixed projections at their original numbers.

    This is a cooperative subprocess handoff, not authentication. The common
    CLI still checks the complete binding and actual native service peer.
    """
    if binding_file != LANE_BINDING:
        return ()
    try:
        if not stat.S_ISLNK(os.lstat(LANE_BINDING).st_mode):
            return ()  # An outside human binding uses the ordinary file path.
        descriptors = []
        for path in (LANE_BINDING, LANE_SOCKET):
            link = os.readlink(path)
            match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]*)", link)
            require(match is not None, "lane projection has another descriptor-link grammar")
            descriptor = int(match.group(1))
            require(6 <= descriptor <= 4096, "lane projection descriptor is outside its fixed handoff bound")
            descriptors.append(descriptor)
        require(descriptors[0] != descriptors[1], "binding and socket projections alias one descriptor")
        binding_fd, socket_fd = descriptors
        info = os.fstat(binding_fd)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o444
                and 0 < info.st_size <= 1024 * 1024
                and fcntl.fcntl(binding_fd, fcntl.F_GET_SEALS) & seals == seals,
                "lane binding is not its exact sealed immutable input")
        data = os.pread(binding_fd, info.st_size + 1, 0)
        require(len(data) == info.st_size, "lane binding changed length during handoff")
        binding = parse(data)
        require(binding.get("schema") == "laneboss.binding.v2" and binding.get("class") == "lane"
                and binding.get("config") == config and binding.get("socket") == LANE_SOCKET,
                "lane binding handoff differs from its configuration or fixed endpoint")
        endpoint = os.fstat(socket_fd)
        require(stat.S_ISSOCK(endpoint.st_mode) and stat.S_IMODE(endpoint.st_mode) == 0o666
                and endpoint.st_nlink == 1 and endpoint.st_uid == binding.get("mapped_service_uid")
                and endpoint.st_gid == binding.get("mapped_service_gid")
                and fcntl.fcntl(socket_fd, fcntl.F_GETFL) & os.O_PATH,
                "lane socket handoff is not its pinned O_PATH endpoint")
        return tuple(descriptors)
    except (OSError, ControlError, ValueError) as error:
        raise Failure("lane descriptor handoff failed its installed projection checks") from error


class Case:
    def __init__(self, context, human_reader=None):
        self.context = context
        # A trusted outside harness may install its independently enrolled
        # human process/transport. JSON labels, bindings and proof files are
        # never a substitute for that separate kernel principal.
        self.human_reader = human_reader
        self.owns_reader = False
        self.transport = None
        if os.environ.get("LANEBOSS_ITEM_SOCKET"):
            from item_bridge import Bridge, Reader
            self.transport = Bridge()
            if self.human_reader is None:
                self.human_reader = Reader(self.transport)
                self.owns_reader = True
                self.human_reader.preflight()
        self.root = Path(context["test_root"]).resolve()
        self.evidence = Path(context["evidence_root"]).resolve()
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in (self.root, self.evidence):
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o700, "case directories must be ordinary, owned and private")
        self.serial = 0
        self.read_proof_serial = 0
        self.lock = Lock()
        self.cells = {}
        self.references = []
        self.owned = []
        self.results = {
            name: {"id": name, "reached": False, "verdict": "fail",
                   "observed_exit": 69, "evidence": []}
            for name in ASSERTIONS
        }
        self.collection = {
            "processes_quiescent": False,
            "temporary_resources_collected": False,
            "evidence": [],
        }

    def keep(self, suffix, data):
        with self.lock:
            self.serial += 1
            name = f"{self.serial:05d}-{suffix}"
        path = self.evidence / name
        atomic(path, data)
        reference = {"path": name, "sha256": sha(data), "bytes": len(data)}
        with self.lock:
            self.references.append(reference)
        return path

    def call(self, method, params, allowed=()):
        request = self.keep(method.replace(".", "-") + ".request.json", encoded(params))
        request_id, key = secrets.token_hex(16), secrets.token_hex(16)
        if method.startswith("dashboard."):
            if self.human_reader is None:
                raise SetupFailure("independent human dashboard-reader process is not installed", ("human.session",))
            binding, proof = None, None
        else:
            binding, proof = self.read_options(method)
        argv = [self.context["binary"], *method.split("."),
                "--config", self.context["config"], "--binding", binding,
                "--request", str(request), "--request-id", request_id, "--idempotency-key", key]
        if proof is not None:
            argv.extend(["--proof", str(proof)])
        self.keep("request-correlation.json", encoded({"method": method, "request_id": request_id,
                                                       "idempotency_key": key, "body_sha256": sha(request.read_bytes())}))
        try:
            if method.startswith("dashboard."):
                completed = self.human_reader.read(method, request.read_bytes(), request_id, key)
            elif getattr(self, "transport", None) is not None:
                completed = self.transport.call(method.replace(".", " "), params, request_id, key, denied=bool(allowed))
            else:
                inherited = inherited_lane_descriptors(binding, self.context["config"])
                completed = subprocess.run(argv, capture_output=True, timeout=45, check=False, pass_fds=inherited)
        except subprocess.TimeoutExpired as error:
            self.keep("timeout.json", encoded({"method": method, "deadline_seconds": 45}))
            if error.stdout:
                self.keep("timeout.stdout", error.stdout)
            if error.stderr:
                self.keep("timeout.stderr", error.stderr)
            raise Failure("CLI command exceeded its deadline", observed_exit=75) from error
        except (RuntimeError, ControlError) as error:
            self.keep("reader-failure.json", encoded({"method": method, "message": str(error),
                                                       "code": getattr(error, "code", "integrity")}))
            if method.startswith("dashboard.") and getattr(error, "code", "") == "prerequisite_missing":
                raise SetupFailure("fresh human.session reader handoff is unavailable", ("human.session",)) from error
            raise Failure("reader bridge failed; retain its process and input receipts") from error
        self.keep(method.replace(".", "-") + ".stdout", completed.stdout)
        self.keep(method.replace(".", "-") + ".stderr", completed.stderr)
        self.keep("exit.json", encoded({"method": method, "exit": completed.returncode}))
        if completed.returncode:
            try:
                error = json.loads(completed.stderr)
                error = error.get("error", error)
            except (ValueError, AttributeError) as error:
                raise Failure("failed CLI returned no typed error", observed_exit=completed.returncode) from error
            if error.get("code") in allowed:
                return {"refused": error}
            if method.startswith("dashboard.") and error.get("code") in {"forbidden", "unauthenticated"} \
                    and self.context.get("human_reader_handoff_available") is False:
                raise SetupFailure("independent human dashboard-reader handoff is unavailable; retain the service refusal")
            raise Failure("CLI failed; retain the typed stderr receipt",
                          observed_exit=completed.returncode)
        try:
            value = json.loads(completed.stdout)
        except ValueError as error:
            raise Failure("successful CLI returned malformed JSON", observed_exit=0) from error
        require(isinstance(value, dict) and "error" not in value,
                "successful CLI returned an error or non-object")
        if value.get("protocol") == "laneboss.rpc.v2":
            require(value.get("schema") == 2 and "result" in value,
                    "CLI response envelope has the wrong schema or no result")
            return value["result"]
        return value

    def read_options(self, method):
        if not method.startswith("dashboard."):
            return self.context["binding_file"], None
        # Dashboard is human-read even when the tested children have an L6
        # starter. Each CLI invocation establishes its own human.session on
        # the same connection as this read; no session ID is a bearer token.
        options = getattr(self, "setup", {}).get("human_reads")
        if not options:
            raise SetupFailure("enrolled human dashboard read fixture is missing")
        binding = Path(options["binding_file"])
        require(binding.is_absolute(), "human read binding must be an installed absolute path")
        with self.lock:
            self.read_proof_serial += 1
            index = self.read_proof_serial
        source = beneath(self.root, options["proofs_dir"]) / f"{index:08d}.json"
        try:
            data, _ = protected(source, {0, os.getuid()}, 1024 * 1024)
        except (FileNotFoundError, ControlError) as error:
            raise SetupFailure("fresh private human.session proof is unavailable") from error
        # Retain and send the exact verified bytes. The common CLI performs
        # proof shape, digest and session setup through its shared client.
        proof = self.keep("human-session-proof.json", data)
        return str(binding), proof

    def upload(self, data, kind="task"):
        digest = sha(data)
        upload = self.call("blob.begin", {"class": kind, "bytes": len(data), "sha256": digest})
        object_id = upload["object_id"]
        for offset in range(0, len(data), 128 * 1024):
            part = data[offset:offset + 128 * 1024]
            self.call("blob.chunk", {"object_id": object_id, "offset": offset,
                                    "data": base64.b64encode(part).decode(), "sha256": sha(part)})
        result = self.call("blob.commit", {"object_id": object_id, "sha256": digest})
        require(result["sha256"] == digest and result["bytes"] == len(data),
                "committed input differs from actual source bytes")
        return result

    def blob(self, reference):
        require(0 < reference["bytes"] <= 16 * 1024 * 1024,
                "capture/room blob is absent or exceeds case bound")
        result = bytearray()
        while len(result) < reference["bytes"]:
            part = self.call("blob.read", {"object_id": reference["id"], "offset": len(result),
                                           "limit": min(128 * 1024, reference["bytes"] - len(result))})
            data = base64.b64decode(part["data"], validate=True)
            require(part["object_id"] == reference["id"] and part["offset"] == len(result)
                    and 0 < len(data) <= reference["bytes"] - len(result)
                    and sha(data) == part["sha256"], "capture/room chunk range or hash failed")
            result.extend(data)
        require(len(result) == reference["bytes"] and sha(result) == reference["sha256"],
                "capture/room bytes failed independent hash verification")
        self.keep("verified-object.bin", bytes(result))
        return bytes(result)

    def operation(self, operation):
        def done():
            current = self.call("operation.get", {"operation_id": operation["id"]})
            require(current["status"] not in {"failed", "cancelled"},
                    "operation ended without success")
            return current if current["status"] == "succeeded" else None
        return self.wait(done)

    def wait(self, observe, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = observe()
            if result is not None and result is not False:
                return result
            time.sleep(1)
        raise Failure("bounded observation did not reach its required state", observed_exit=75)

    def control(self, cell, phase, nonce):
        data = encoded({"cell": cell, "phase": phase, "nonce": nonce})
        self.keep("fixture-input.json", data)
        atomic(self.control_path, data)
        if getattr(self, "transport", None) is not None:
            receipt = self.transport.call("fixture phase", {"cell": cell, "phase": phase, "nonce": nonce})
            self.keep("phase-relay.stdout", receipt.stdout)
            self.keep("phase-relay.stderr", receipt.stderr)
            require(receipt.returncode == 0, "outside phase control failed")

    def harness_action(self, action, params):
        if not self.context.get("controls"):
            raise SetupFailure("enrolled harness controller binding is missing")
        try:
            controller = Controller(self.context, self.keep)
        except FileNotFoundError as error:
            raise SetupFailure("enrolled harness controller binding file is missing") from error
        except ControlError as error:
            raise Failure(str(error)) from error
        try:
            return controller.invoke(action, params)
        except ControlError as error:
            raise Failure(str(error)) from error

    def independent_canary(self, life, baseline):
        if not self.setup.get("canary_id"):
            raise SetupFailure("enrolled watchdog canary is missing")
        nonce = secrets.token_hex(16)
        target = {"life_id": life, "run": baseline["run"]}
        source = encoded({"schema": "laneboss.watchdog-probe.v2", "target": target, "nonce": nonce})
        reference = self.upload(source, "task")
        _, evidence = self.harness_action("run_confined_canary", {
            "target": target, "canary_id": self.setup["canary_id"], "input": reference,
        })
        self.verify_canary_evidence(evidence, target, nonce)

    def verify_canary_evidence(self, evidence, target, nonce):
        reports = []
        for data in evidence:
            try:
                value = parse(data)
            except ControlError:
                continue  # Other hashed OS evidence need not be a JSON report.
            if isinstance(value, dict) and value.get("schema") == "laneboss.watchdog-canary.v2":
                reports.append(value)
        require(len(reports) == 1, "independent watchdog canary report is absent or ambiguous")
        report, = reports
        require(report["target"] == target and report["nonce"] == nonce,
                "independent canary evidence belongs to another input or life")
        checks = report["checks"]
        require(len(checks) == 3 and {check["probe"] for check in checks} == {"forge", "file", "signal"}
                and all(check["attempted"] is True and check["confined"] is True
                        and check["target_present"] is True and check["denied"] is True
                        and check["unchanged"] is True for check in checks),
                "independent canary did not prove a confined denied probe against a real unchanged target")

    def restart_wait(self, life, baseline):
        if not self.setup.get("restart"):
            raise SetupFailure("enrolled service restart selector is missing")
        result, _ = self.harness_action("restart_service", copy.deepcopy(self.setup["restart"]))
        self.setup["restart"]["expected_generation"] = result["current_generation"]
        recovered = self.status(life)
        require(recovered["run"] == baseline["run"] and recovered["state"] == "profile_wait"
                and recovered["session"] == baseline["session"] and recovered["workspace"] == baseline["workspace"]
                and recovered["task"] == baseline["task"] and recovered["counters"] == baseline["counters"]
                and recovered["cancellation_epoch"] == baseline["cancellation_epoch"]
                and recovered["logical_turn_id"] == baseline["logical_turn_id"],
                "service restart lost the durable wait, history, task, counters or cancellation epoch")
        self.no_early_mail_receipt(life, baseline)

    def status(self, life):
        # Use the documented life filter; do not invent a latest-run sentinel
        # for LifeRef, whose actual immutable run must remain explicit.
        page = self.call("lane.list", {"life_id": life, "cursor": "", "limit": 200})
        require(not page["cursor"] and len(page["lanes"]) == 1
                and page["lanes"][0]["life_id"] == life, "life projection is missing or ambiguous")
        return page["lanes"][0]

    def events(self, life):
        result, cursor, seen = [], "", set()
        for _ in range(512):
            page = self.call("event.tail", {"life_id": life, "run": 0, "since": 0,
                                            "cursor": cursor, "follow": False,
                                            "until": "", "deadline_ms": 5000})
            for event in page["events"]:
                require(event["config"] == self.context["config"] and event["life_id"] == life
                        and (not result or event["seq"] > result[-1]["seq"]),
                        "event observer crossed scope or repeated a sequence")
                result.append(event)
            if page["complete"]:
                return result
            cursor = page["cursor"]
            require(cursor and cursor not in seen, "incomplete or repeating event cursor")
            seen.add(cursor)
        raise Failure("event observer exceeded its bound")

    def query(self, life, run=0):
        result = {"life_id": life, "cursor": "", "limit": 200}
        if run:
            result["run"] = run
        return result

    def raw(self, life, run, live=False):
        # event.tail and blob.read authorize a supervisor's tree/content
        # reads. They do not require a human session or a new proof per poll.
        records = []
        observed = self.events(life)
        framed = any(e["kind"] == "capture.framed" and e.get("run") == run for e in observed)
        for event in observed:
            actor = event.get("actor", {})
            if (event.get("run") != run or event.get("origin") != "service"
                    or actor.get("kind") not in {"service", "worker"} or not actor.get("id")
                    or actor.get("life_id") or actor.get("level", 0) != 0 or actor.get("role")):
                continue
            require(event.get("kind") != "capture.gap", "primary capture contains a gap")
            if event.get("kind") == ("capture.framed" if framed else "capture.appended"):
                require(isinstance(event.get("payload"), dict), "capture event has no typed payload")
                records.append(event["payload"])
        data = bytearray()
        primary = [r for r in records if r["primary"] and r["stream"] in {"stdout", "structured"}]
        binding_ids = {r.get("binding_id") for r in primary}
        require(not primary or (len(binding_ids) == 1 and all(binding_ids)), "live capture lacks one registered binding identity")
        selected_stream = "stdout" if any(r["stream"] == "stdout" for r in primary) else "structured"
        for record in sorted((r for r in primary if r["stream"] == selected_stream), key=lambda item: item["offset"]):
            require(record["target"] == {"life_id": life, "run": run}
                    and (record["coverage"] == "complete" or live and record["coverage"] == "partial") and not record.get("replacement_of")
                    and record["offset"] == len(data) and record["data"].get("class") == "capture",
                    "raw capture does not cover the actual original run")
            data.extend(self.blob(record["data"]))
        return bytes(data), records

    def check_quiet(self, life, run):
        observation = self.call("lane.check", {"life_id": life, "run": run})
        return observation["state"] == "exited" and observation.get("survivors") == 0

    def start_cell(self, cell):
        nonce = secrets.token_hex(16)
        self.control(cell, "seed", nonce)
        body = copy.deepcopy(self.setup["start"])
        body["lane"] = "wd-" + cell + "-" + secrets.token_hex(6)
        task = self.task_bytes + f"\nCell: {cell}\nHistory nonce: {nonce}\n".encode()
        self.keep("task.md", task)
        body["task"] = self.upload(task)
        operation = self.call("lane.start", body)
        life = operation.get("life_id")
        require(bool(life) and operation["run"] == 1, "start returned no new life/run 1")
        self.owned.append(life)
        self.operation(operation)
        self.wait(lambda: self.check_quiet(life, 1))
        initial = self.status(life)
        self.control(cell, "ready", nonce)
        mail_bytes = self.mail_bytes + f"\nRecall the existing history nonce; cell {cell}.\n".encode()
        # The continuation answer is not in this message. It was introduced
        # only in run 1's task and must come from this life/session's history.
        message = self.call("mail.send", {"recipient_life_id": life,
                                           "content": self.upload(mail_bytes, "report"), "ask": False})
        self.operation(self.call("lane.turn", {"target": {"life_id": life, "run": initial["run"]},
                                "expected_generation": initial["generation"],
                                "mail_ids": [message["id"]], "budget": initial["budget_remaining"]}))
        baseline = self.wait(lambda: self.running_after(life, initial["run"]))
        self.cells[life] = {"cell": cell, "nonce": nonce, "mail_id": message["id"], "baseline": baseline}
        return life, nonce, baseline

    def running_after(self, life, run):
        current = self.status(life)
        return current if current["run"] == run + 1 and current["state"] == "running" else None

    def no_early_mail_receipt(self, life, baseline):
        mail_id = self.cells[life]["mail_id"]
        for event in self.events(life):
            if event["kind"] in {"mail.delivered", "mail.returned"} and event["payload"]["mail_id"] == mail_id:
                require(event["payload"]["status"] not in {"delivered", "returned"},
                        "quota exit acknowledged or returned logical-turn mail")
        current = self.status(life)
        require(bool(current.get("logical_turn_id")) and current.get("logical_turn_id") == baseline.get("logical_turn_id"),
                "waiting lost the logical turn")

    def continuation(self, life, baseline, nonce):
        current = self.wait(lambda: self.after_swap(life, baseline["run"]))
        self.wait(lambda: self.check_quiet(life, current["run"]))
        def mail_completed():
            receipts = [e for e in self.events(life) if e["kind"] in {"mail.delivered", "mail.returned"}
                        and e["payload"]["mail_id"] == self.cells[life]["mail_id"]]
            return receipts if receipts else None
        self.wait(mail_completed)
        current = self.status(life)
        events = self.events(life)
        swaps = [e for e in events if e["kind"] == "watchdog.swapped"
                 and e["payload"].get("swap", {}).get("causing_run") == baseline["run"]]
        require(len(swaps) == 1, "limit did not cause exactly one recorded swap")
        event, = swaps
        swap = event["payload"]["swap"]
        require(event["origin"] == "service" and event["actor"]["kind"] == "watchdog"
                and not event["actor"].get("life_id"), "swap borrowed a lane/mail actor")
        require(swap["causing_run"] == baseline["run"] and swap["continuation_run"] == baseline["run"] + 1
                and swap["logical_turn_id"] == baseline["logical_turn_id"]
                and swap["from_profile_id"] != swap["to_profile_id"]
                and swap["operation_id"] == event["operation_id"], "swap provenance is incomplete")
        require(bool(swap["eligibility_id"]) and swap["profile_grant_id"] == current["profile_grant_id"]
                and swap["expected_generation"] >= baseline["generation"]
                and swap["cancellation_epoch"] == baseline["cancellation_epoch"] == current["cancellation_epoch"],
                "swap lost typed eligibility, selected grant, generation or cancellation epoch")
        usage = swap["limit"].get("usage_evidence", {})
        require(usage.get("class") == "usage_window" and bool(usage.get("id"))
                and isinstance(usage.get("sha256"), str) and len(usage["sha256"]) == 64
                and type(usage.get("bytes")) is int and usage["bytes"] > 0,
                "swap lost its retained normalized outside usage evidence")
        require(current["run"] == baseline["run"] + 1 and current["session"] == baseline["session"]
                and current["workspace"] == baseline["workspace"]
                and bool(current.get("logical_turn_id")) and current.get("logical_turn_id") == baseline.get("logical_turn_id"),
                "continuation duplicated a run or changed session/home/workspace/turn")
        require(bool(baseline["session"]["history_id"])
                and current["session"]["history_id"] == baseline["session"]["history_id"],
                "continuation lost the retained private history identity")
        require(current["task"] == baseline["task"], "continuation changed the original retained task")
        require(current["counters"] == baseline["counters"], "quota continuation changed failure/retry counters")
        before, after = baseline["budget_remaining"], current["budget_remaining"]
        require(before["currency"] == after["currency"], "continuation changed budget currency")
        for field in ("wall_ms", "cpu_seconds", "memory_bytes", "processes", "disk_bytes", "spend_micros"):
            require(0 <= after[field] <= before[field], "continuation reset a remaining budget")
        ends = [e for e in events if e["kind"] == "lane.ended" and e["run"] == baseline["run"]]
        require(len(ends) == 1 and ends[0]["payload"]["reason"] == "limit"
                and ends[0]["payload"].get("profile_continuation") is True
                and type(ends[0]["payload"]["observation"].get("exit_code")) is int
                and type(swap["limit"].get("exit_code")) is int
                and ends[0]["payload"]["observation"].get("exit_code") == swap["limit"].get("exit_code")
                and ends[0]["payload"]["observation"].get("survivors") == 0,
                "quota end lost real exit/zero survivors or became a task failure")
        launches = [e for e in events if e["kind"] == "lane.resumed" and e["run"] == current["run"]]
        require(len(launches) == 1 and launches[0]["payload"]["trigger"]["kind"] == "profile_limit"
                and launches[0]["payload"].get("profile_continuation_of") == baseline["run"],
                "continuation became an ordinary retry/manual turn")
        require(launches[0]["payload"].get("profile_swap") == swap
                and launches[0]["operation_id"] == swap["operation_id"]
                and launches[0]["payload"]["task"] == baseline["task"],
                "continued launch lost its exact typed swap or original task")
        _, records = self.raw(life, baseline["run"])
        capture = [r for r in records if r["id"] == swap["limit"]["capture_id"]]
        require(len(capture) == 1 and capture[0]["primary"] and bool(capture[0].get("binding_id")) and capture[0]["coverage"] == "complete"
                and capture[0]["data"]["sha256"] == swap["limit"]["capture_sha256"],
                "swap lacks exact original outside limit capture")
        room = swap["room"]
        require(room["available"] and room["profile_id"] == swap["to_profile_id"]
                and utc(room["checked_at"]) <= utc(event["observed_at"]) < utc(room["expires_at"]),
                "swap used forged, stale or unavailable room")
        self.blob(room["evidence"])
        data, _ = self.raw(life, current["run"])
        require(nonce.encode() in data, "continued history did not recall the unpredictable first-run token")
        receipts = [e for e in events if e["kind"] in {"mail.delivered", "mail.returned"}
                    and e["payload"]["mail_id"] == self.cells[life]["mail_id"]]
        delivered = [e for e in receipts if e["payload"]["status"] == "delivered"]
        require(len(delivered) == 1 and len(receipts) == 1
                and delivered[0]["payload"]["logical_turn_id"] == baseline["logical_turn_id"]
                and delivered[0]["payload"]["target"]["run"] == current["run"]
                and delivered[0]["payload"]["prompt_status"] == "completed",
                "logical-turn mail was duplicated, returned, or acknowledged without completion")
        view = self.call("dashboard.lifecycle", self.query(life))
        require(any(lane["life_id"] == life and lane["run"] == current["run"] for lane in view["lanes"]),
                "dashboard did not show the actual continued run")

    def after_swap(self, life, run):
        current = self.status(life)
        require(current["run"] <= run + 1, "multiple continuations launched")
        return current if current["run"] == run + 1 else None

    def waiting(self, life, baseline):
        current = self.status(life)
        require(current["run"] == baseline["run"], "exhausted room launched a fallback")
        return current if current["state"] == "profile_wait" else None

    @staticmethod
    def denied_probe(report):
        kind = report.get("probe")
        if kind == "forge":
            return report.get("code") in {"forbidden", "invalid_request", "unauthenticated"}
        if kind == "file":
            return report.get("errno") in {1, 13, 30}
        if kind == "signal":
            return report.get("errno") in {1, 3, 13}
        return kind == "quote"

    def run_cell(self, cell, assertion):
        self.results[assertion]["reached"] = True
        life, nonce, baseline = self.start_cell(cell)
        if cell == "tamper":
            self.control(cell, "attacks", nonce)
            def attacked():
                data, _ = self.raw(life, baseline["run"], live=True)
                reports = []
                for line in data.splitlines():
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue  # Ordinary capture text is not a canary receipt.
                    if isinstance(item, dict) and item.get("type") == "watchdog_canary":
                        reports.append(item)
                return reports if len(reports) >= 4 else None
            reports = self.wait(attacked)
            require({r["probe"] for r in reports} == {"quote", "forge", "file", "signal"}
                    and all(r["attempted"] for r in reports), "not every real tamper probe ran")
            require(all(self.denied_probe(r) for r in reports), "tamper/control operation was allowed or missed its target")
            require(self.status(life)["run"] == baseline["run"]
                    and not any(e["kind"] == "watchdog.swapped" for e in self.events(life)),
                    "quoted/forged output triggered a swap")
            self.independent_canary(life, baseline)
        if cell in {"no-room", "stop-race", "resume-race", "restart"}:
            self.control(cell, "exhausted", nonce)
            current = self.wait(lambda: self.waiting(life, baseline))
            self.no_early_mail_receipt(life, baseline)
            first = self.events(life)
            waits = [e for e in first if e["kind"] == "watchdog.waiting"]
            require(bool(waits) and all(5000 <= e["payload"]["retry_after_ms"] <= 300000 for e in waits),
                    "no-room has no bounded service backoff")
            if cell == "restart":
                self.restart_wait(life, baseline)
                self.control(cell, "restored", nonce)
            elif cell == "no-room":
                def another_wait():
                    events = [e for e in self.events(life) if e["kind"] == "watchdog.waiting"]
                    return events if len(events) > len(waits) else None
                later = self.wait(another_wait, seconds=360)
                for prior, following in zip(later, later[1:]):
                    delay = prior["payload"]["retry_after_ms"]
                    require(following["payload"]["retry_after_ms"] >= delay
                            and (utc(following["recorded_at"]) - utc(prior["recorded_at"])).total_seconds() * 1000 >= delay,
                            "service spun or reset exhausted-room backoff")
                require(self.status(life)["run"] == baseline["run"], "exhausted room advanced before restoration")
                self.control(cell, "restored", nonce)
            else:
                self.race(cell, life, nonce, current, baseline)
                return
        else:
            self.control(cell, "limit", nonce)
        self.continuation(life, baseline, nonce)

    def race(self, cell, life, nonce, current, baseline):
        if cell == "stop-race":
            method = "lane.stop"
            body = {"target": {"life_id": life, "run": current["run"]},
                    "expected_generation": current["generation"], "reason": self.reason}
        else:
            method = "lane.resume"
            body = {"target": {"life_id": life, "run": current["run"]},
                    "expected_generation": current["generation"], "message": self.manual_message,
                    "budget": current["budget_remaining"]}
        with ThreadPoolExecutor(max_workers=2) as pool:
            restore = pool.submit(self.control, cell, "restored", nonce)
            control = pool.submit(self.call, method, body, ("conflict",))
            restore.result()
            receipt = control.result()
        initial_succeeded = "refused" not in receipt
        if initial_succeeded:
            self.operation(receipt)
        if cell == "resume-race":
            self.wait(lambda: self.after_swap(life, baseline["run"]))
            self.wait(lambda: self.check_quiet(life, baseline["run"] + 1))
        else:
            if not initial_succeeded:
                # Swap won the CAS. Stop the actual new run explicitly; the
                # old stop refusal is retained and does not count as success.
                def stop_current():
                    actual = self.status(life)
                    require(actual["run"] <= baseline["run"] + 1, "swap duplicated before stop recovery")
                    stopped = self.call("lane.stop", {"target": {"life_id": life, "run": actual["run"]},
                                                      "expected_generation": actual["generation"], "reason": self.reason},
                                        allowed=("conflict",))
                    if "refused" in stopped:
                        return None
                    self.operation(stopped)
                    return actual
                actual = self.wait(stop_current)
            else:
                actual = self.status(life)
                require(actual["run"] == baseline["run"], "successful stop allowed a new run")
            self.wait(lambda: self.check_quiet(life, actual["run"]))
        waits = [e for e in self.events(life) if e["kind"] == "watchdog.waiting"]
        require(bool(waits), "race did not encounter an actual pending watchdog wait")
        interval = max(e["payload"]["retry_after_ms"] for e in waits) / 1000 + 2
        require(7 <= interval <= 302, "race observation backoff is invalid")
        deadline = time.monotonic() + interval
        while time.monotonic() < deadline:
            observed = self.status(life)
            require(observed["run"] <= baseline["run"] + 1, "stale watchdog duplicated manual continuation")
            if cell == "stop-race":
                require(observed["run"] == actual["run"], "watchdog advanced the stopped run")
            time.sleep(1)
        events = self.events(life)
        if cell == "stop-race":
            stops = [e for e in events if e["kind"] == "lane.stopping"]
            require(bool(stops) and not any(e["kind"] == "lane.resumed" and e["seq"] > stops[0]["seq"] for e in events),
                    "watchdog launched after the authorized stop committed")
        else:
            launches = [e for e in events if e["kind"] == "lane.resumed" and e["run"] > baseline["run"]]
            require(len(launches) == 1 and self.status(life)["run"] == baseline["run"] + 1,
                    "manual resume and profile restore did not produce exactly one new run")

    def collect(self, successful):
        for life in self.owned:
            current = self.status(life)
            if not self.check_quiet(life, current["run"]):
                self.operation(self.call("lane.stop", {"target": {"life_id": life, "run": current["run"]},
                                                       "expected_generation": current["generation"], "reason": self.reason}))
                self.wait(lambda: self.check_quiet(life, self.status(life)["run"]))
            if not successful:
                continue  # Preserve the failed workspace and its records for supervision.
            current = self.status(life)
            review = copy.deepcopy(self.setup["review"])
            if getattr(self, "transport", None) is not None:
                response = self.transport.call("fixture review-input", {"life_id": life, "run": current["run"]})
                self.keep("review-input.stdout", response.stdout)
                self.keep("review-input.stderr", response.stderr)
                require(response.returncode == 0, "measured review inputs are unavailable")
                review = parse(response.stdout)
            review["target"] = {"life_id": life, "run": current["run"]}
            receipt = self.call("lane.review", review)
            current = self.status(life)
            self.operation(self.call("lane.mark", {"target": review["target"], "expected_generation": current["generation"],
                                                   "state": "abandoned", "review": receipt}))
            current = self.status(life)
            archive = self.call("lane.archive", {"target": review["target"], "expected_generation": current["generation"]})
            require(archive["archive_sha256"] == archive["read_back_sha256"], "collection archive read-back failed")
            current = self.status(life)
            self.operation(self.call("lane.clean", {"target": review["target"], "expected_generation": current["generation"],
                                                    "archive_receipt_id": archive["id"]}))
            require(self.status(life)["cleaned"] and self.check_quiet(life, current["run"]),
                    "collection left a process or uncollected temporary lane")
        self.collection["processes_quiescent"] = True
        self.collection["temporary_resources_collected"] = successful
        self.collection["evidence"] = list(self.references)

    def run(self):
        active = ASSERTIONS[0]
        exit_code = 0
        try:
            if sys.platform != "linux":
                raise SetupFailure("watchdog E2E requires the authorized Linux test box")
            require(self.context["schema"] == "laneboss.e2e-context.v2" and self.context["case_id"] == "watchdog",
                    "case context does not match watchdog")
            require(sha(Path(self.context["binary"]).read_bytes()) == self.context["binary_sha256"], "installed binary hash differs")
            binding = Path(self.context["binding_file"]).read_bytes()
            self.keep("binding-identity.json", encoded({"sha256": sha(binding), "bytes": len(binding)}))
            installed = json.loads(binding)
            require(installed["schema"] == "laneboss.binding.v2"
                    and installed["contract_revision"] == REVISION
                    and installed["protocol"] == "laneboss.rpc.v2" and installed["api_schema"] == 2
                    and installed["config"] == self.context["config"]
                    and installed["artifact_sha256"] == self.context["binary_sha256"],
                    "case binding and installed binary are not one draft.4 generation")
            setup_path = self.root / "setup.json"
            if not setup_path.is_file():
                raise SetupFailure("outside runner/usage fixture setup is missing")
            setup_bytes = setup_path.read_bytes()
            self.keep("setup.json", setup_bytes)
            self.setup = json.loads(setup_bytes)
            require(self.setup["schema"] == "laneboss.watchdog-case.v2", "fixture setup schema mismatch")
            require(self.setup["start"]["driver"] == "claudock-cli"
                    and self.setup["start"]["profile_grant_id"] in self.context["profile_grant_ids"]
                    and len(set(self.context["profile_grant_ids"])) >= 2, "two explicit Claudock profile grants are required")
            if self.human_reader is None and self.setup.get("reader_binding"):
                from reader import SocketReader
                try:
                    self.human_reader = SocketReader(self.context, self.setup["reader_binding"], self.keep)
                    self.owns_reader = True
                    self.human_reader.preflight()
                except (OSError, ControlError, RuntimeError) as error:
                    if isinstance(error, OSError) or getattr(error, "code", "") == "prerequisite_missing":
                        raise SetupFailure(str(error), ("human.session",)) from error
                    raise Failure("outside reader preflight failed: " + str(error)) from error
            if self.human_reader is None or not callable(getattr(self.human_reader, "read", None)):
                raise SetupFailure("independent human dashboard-reader process is not installed", ("human.session",))
            self.control_path = beneath(self.root, self.setup["control"])
            self.task_bytes = beneath(self.root, self.setup["task_file"]).read_bytes()
            self.mail_bytes = beneath(self.root, self.setup["mail_file"]).read_bytes()
            self.reason = self.upload(b"Watchdog acceptance collection.\n", "report")
            self.manual_message = self.upload(b"Continue the existing task with its history.\n", "task")
            caller = self.call("identity.self", {})
            require(caller["config"] == self.context["config"] and caller["actor"]["kind"] == "lane"
                    and caller["actor"]["level"] == 6, "case is not bound to its authentic L6 test caller")
            for cell, active in zip(("limit", "no-room", "tamper", "stop-race", "resume-race", "restart"), ASSERTIONS):
                begin = len(self.references)
                self.run_cell(cell, active)
                self.results[active].update(reached=True, verdict="pass", observed_exit=0,
                                            evidence=self.references[begin:])
        except Failure as error:
            exit_code = self.failed(active, error)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            exit_code = self.failed(active, error)
        try:
            if self.owned:
                self.collect(exit_code == 0)
            else:
                self.collection.update(processes_quiescent=True, temporary_resources_collected=True,
                                       evidence=list(self.references))
            if self.owns_reader:
                require(self.human_reader.close() == 0, "outside reader did not close cleanly")
                self.collection["evidence"] = list(self.references)
        except (Failure, OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, ControlError) as error:
            self.keep("collection-failure.json", encoded({"category": type(error).__name__}))
            self.collection.update(processes_quiescent=False, temporary_resources_collected=False)
            exit_code = exit_code or 1
        result = {"schema": "laneboss.e2e-result.v2", "case_id": "watchdog",
                  "phase": self.context["phase"], "mutation_id": self.context["mutation_id"],
                  "binary_sha256": self.context["binary_sha256"], "source_sha256": self.context["source_sha256"],
                  "assertions": list(self.results.values()), "collection": self.collection}
        return result, exit_code

    def failed(self, active, error):
        # Once a cell has reached its assertions, malformed/missing fields and
        # runtime unsupported/unavailable replies remain failed assertions.
        # Only an explicitly named missing fixture can make it unreached.
        reached = self.results[active]["reached"] and not isinstance(error, SetupFailure)
        observed_exit = 1 if reached else 69
        if isinstance(error, SetupFailure):
            self.keep("wait.json", encoded({"schema": "laneboss.e2e-wait.v2", "code": "prerequisite_missing",
                                            "assertion": active, "message": str(error), "passed": False,
                                            "owner_in_person": error.owner_in_person}))
        self.keep("failure.json", encoded({"assertion": active, "reason": str(error),
                                           "category": type(error).__name__,
                                           "cli_exit": getattr(error, "observed_exit", None)}))
        self.results[active].update(reached=reached, verdict="fail", observed_exit=observed_exit,
                                    evidence=list(self.references))
        return observed_exit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    context_bytes = args.context.read_bytes()
    context = json.loads(context_bytes)
    require(args.context.is_absolute() and args.result.is_absolute(), "case paths must be absolute")
    result_path = args.result.resolve()
    require(result_path.is_relative_to(Path(context["test_root"]).resolve())
            or result_path.is_relative_to(Path(context["evidence_root"]).resolve()),
            "result escaped the disposable case scope")
    case = Case(context)
    case.keep("context.json", context_bytes)
    result, exit_code = case.run()
    atomic(args.result, encoded(result))
    print("watchdog case: " + ("pass" if exit_code == 0 else "fail; inspect retained evidence"))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

"""TestChild dispatch and result collection through installed native actors.

The adapter submits once, waits for that operation, and reads its real worker
output, primary capture and helper release. It never runs candidate code as
the observer or writes a check, lease, event or worker receipt into the store.
The installed grants/dataworker must provide those native execution ports.
"""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import time


def need(value, message):
    if not value:
        raise ValueError(message)


class NativeFailure(Exception):
    def __init__(self, error):
        self.error = copy.deepcopy(error)
        super().__init__(json.dumps(error, sort_keys=True))


def native_release(case, receipt, target, operation):
    """Read the protected helper journal, cgroup and leased UID outside it."""
    spec = importlib.util.spec_from_file_location(
        "test_child_grants", Path(__file__).with_name("case_grants.py"))
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    owner.release(receipt, target, operation, need)
    return nested_native_zero(case, receipt, owner.sibling("provision").read_protected)


def released_worker(document, receipt):
    """Select an actual collected post-run worker in its canonical journal."""
    if document.get("schema") != "laneboss.helper-lease.v2":
        return None
    journals = [document.get("archive"), *document.get("reviews", [])]
    matches = []
    for journal in journals:
        if journal is None:
            continue
        worker = journal.get("Worker") or {}
        if worker.get("Lease", {}).get("id") != receipt["lease_id"]:
            continue
        proof = (journal.get("Retirement") or {}).get("Proof") or {}
        need(worker.get("Collected") is True and proof.get("release") == receipt
             and worker["Lease"].get("containment_id") == receipt["containment_id"],
             "TestChild native journal changed its actual collected worker release")
        matches.append(worker["Lease"])
    need(len(matches) <= 1, "TestChild helper journal duplicated its native worker")
    return matches[0] if matches else None


def nested_native_zero(case, receipt, read_protected):
    helper = Path("/var/lib/laneboss-v2/helper") / case.config
    found = []
    for path in sorted(helper.glob("*.json")):
        raw = read_protected(path, mode=0o600)
        lease = released_worker(json.loads(raw), receipt)
        if lease is not None:
            found.append((lease, raw))
    need(len(found) == 1, "TestChild has no unique canonical helper release journal")
    lease, raw = found[0]
    uid = lease["uid"]
    need(type(uid) is int and uid > 0 and uid != case.admin["service"]["uid"],
         "TestChild outside measurement lacks its distinct native UID")
    group = Path("/sys/fs/cgroup/system.slice") / ("laneboss-helper@" + case.config + ".service") / "lanes" / receipt["containment_id"]
    need(not group.is_symlink(), "TestChild outside cgroup is redirected")
    present = group.exists()
    processes, events = b"", b""
    if present:
        processes, events = (group / "cgroup.procs").read_bytes(), (group / "cgroup.events").read_bytes()
        facts = dict(row.split() for row in events.decode().splitlines())
        need(not processes.strip() and facts.get("populated") == "0", "TestChild outside cgroup retained live processes")
    survivors = []
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            status = (process / "status").read_bytes()
            stat = (process / "stat").read_bytes().rsplit(b")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        uids = next(row.split()[1:] for row in status.splitlines() if row.startswith(b"Uid:"))
        if uid not in [int(value) for value in uids]:
            continue
        live = stat[0] not in (b"Z", b"X")
        if not live:
            for thread in (process / "task").glob("*/stat"):
                try:
                    state = thread.read_bytes().rsplit(b")", 1)[1].split()[0]
                except (FileNotFoundError, ProcessLookupError):
                    continue
                live = live or state not in (b"Z", b"X")
        if live:
            survivors.append({"pid": int(process.name), "start": stat[19].decode()})
    need(not survivors, "TestChild outside leased UID retained live processes")
    digest = hashlib.sha256(raw).hexdigest()
    name = "test-native-" + digest[:20] + ".json"
    path = case.root / name
    if path.exists():
        need(path.read_bytes() == raw, "retained TestChild helper journal changed")
    else:
        case.keep(name, raw)
    return {"journal_input": name, "journal_sha256": digest, "uid": uid, "survivors": survivors,
        "cgroup_present": present, "cgroup_procs_sha256": hashlib.sha256(processes).hexdigest(),
        "cgroup_events_sha256": hashlib.sha256(events).hexdigest()}


class ChildTests:
    def __init__(self, case):
        self.case = case
        self.results = {}
        self.failure = None

    def read(self, method, params):
        return self.case.human.read("item-test-" + method.replace(".", "-"), method.split("."), params)

    def blob(self, ref):
        need(isinstance(ref, dict) and ref.get("id") and ref.get("class")
             and type(ref.get("bytes")) is int and 0 <= ref["bytes"] <= 64 << 20,
             "test worker object lacks its retained reference or bound")
        raw = bytearray()
        while True:
            limit = min(262144, ref["bytes"] - len(raw)) or 1
            chunk = self.read("blob.read", {"object_id": ref["id"], "offset": len(raw), "limit": limit})
            part = base64.b64decode(chunk["data"], validate=True)
            need(chunk.get("object_id") == ref["id"] and chunk.get("offset") == len(raw)
                 and len(part) <= limit and hashlib.sha256(part).hexdigest() == chunk.get("sha256")
                 and len(raw) + len(part) <= ref["bytes"], "test worker object chunk differs")
            if not part:
                break
            raw.extend(part)
        need(len(raw) == ref["bytes"] and hashlib.sha256(raw).hexdigest() == ref.get("sha256"),
             "test worker object bytes differ from their retained reference")
        return bytes(raw)

    def await_operation(self, submitted, target):
        need(submitted.get("id"), "TestChild did not reserve an actual operation")
        selected, deadline = submitted, time.monotonic() + 120
        while True:
            if selected.get("error"):
                raise NativeFailure(selected["error"])
            need(selected.get("id") == submitted["id"] and selected.get("life_id") == target["life_id"]
                 and selected.get("run") == target["run"] and type(selected.get("first_seq")) is int
                 and selected["first_seq"] > 0 and type(selected.get("last_seq")) is int
                 and selected["last_seq"] >= selected["first_seq"], "TestChild operation changed its reserved child or sequence")
            need(selected.get("status") in ("pending", "running", "succeeded"),
                 "TestChild operation has no successful terminal result")
            # Even an immediately successful submit must have an independent
            # operation.get read-back. A pending response confers no credit.
            if selected is not submitted and selected["status"] == "succeeded":
                return selected
            need(time.monotonic() < deadline, "TestChild operation deadline")
            if selected["status"] != "succeeded":
                time.sleep(0.25)
            selected = self.read("operation.get", {"operation_id": submitted["id"]})

    def events(self, operation, target):
        rows, cursor, seen = [], "", set()
        through, deadline = operation["first_seq"] - 1, time.monotonic() + 120
        while True:
            need(time.monotonic() < deadline, "TestChild event pagination deadline")
            page = self.read("event.tail", dict(target, since=operation["first_seq"] - 1,
                cursor=cursor, follow=False, until="", deadline_ms=1000))
            need(isinstance(page.get("events"), list), "TestChild event page is absent")
            for event in page["events"]:
                need(type(event.get("seq")) is int and event["seq"] > through,
                     "TestChild event history is duplicated or out of order")
                through = event["seq"]
                if event.get("operation_id") == operation["id"]:
                    need(event.get("config") == self.case.config and event.get("life_id") == target["life_id"]
                         and event.get("run") == target["run"] and event.get("origin") == "service",
                         "TestChild event belongs to another native operation or run")
                    rows.append(event)
            if page.get("complete") is True:
                return rows
            cursor = page.get("cursor")
            need(cursor and cursor not in seen, "TestChild event cursor did not advance")
            seen.add(cursor)

    def capture(self, events, binding):
        need(binding.get("id") and binding.get("status") == "registered" and binding.get("launch_id")
             and binding.get("worker_lease_id"), "TestChild has no registered native worker capture")
        streams = {row["stream"]: row["id"] for row in binding["streams"]}
        need(set(streams) == {"stdout", "stderr"} and len(set(streams.values())) == 2,
             "TestChild capture omitted a primary output stream")
        output, closed = {name: bytearray() for name in streams}, set()
        for event in events:
            value = event["payload"]
            need(event["kind"] != "capture.gap", "TestChild primary capture has a gap")
            if event["kind"] == "capture.appended":
                name = value.get("stream")
                need(name in streams and name not in closed and value.get("binding_id") == binding["id"]
                     and value.get("target") == binding["target"] and value.get("primary") is True
                     and value.get("coverage") in ("partial", "complete")
                     and value.get("offset") == len(output[name]), "TestChild primary capture changed its binding or range")
                need(value.get("data", {}).get("class") == "capture", "TestChild output is not a capture object")
                output[name].extend(self.blob(value["data"]))
            elif event["kind"] == "capture.closed":
                names = [name for name, stream in streams.items() if stream == value.get("stream_id")]
                need(len(names) == 1 and names[0] not in closed and value.get("binding_id") == binding["id"]
                     and value.get("eof") is True and value.get("offset") == len(output[names[0]])
                     and value.get("next_offset") == len(output[names[0]]), "TestChild EOF changed its exact primary range")
                closed.add(names[0])
        need(closed == set(streams), "TestChild primary capture is not drained through both EOFs")
        return {name: base64.b64encode(raw).decode() for name, raw in output.items()}

    def execute(self, request, submit, *, subject=None, required=()):
        """Submit through the original actor; return only its measured result."""
        if self.failure is not None:
            raise self.failure
        try:
            self.case.keep_json("test-input-" + str(len(self.results)) + ".json", request)
            operation = submit(request)
            return self.complete(request, operation, subject=subject, required=required)
        except Exception as error:
            self.failure = error
            raise

    def complete(self, request, operation, *, subject=None, required=()):
        if self.failure is not None:
            raise self.failure
        target = request["child"]
        operation = self.await_operation(operation, target)
        need(operation["id"] not in self.results, "TestChild operation was executed twice")
        events = self.events(operation, target)
        select = lambda kind: [row["payload"] for row in events if row["kind"] == kind]
        completed, bindings, releases = select("worker.completed"), select("capture.bound"), select("helper.released")
        need(len(completed) == len(bindings) == len(releases) == 1 and not select("worker.failed"),
             "TestChild lacks its unique completed worker, capture and release")
        worker, binding, release = completed[0], bindings[0], releases[0]
        need(worker.get("kind") == "test" and worker.get("status") == "succeeded" and not worker.get("error")
             and worker.get("worker_id") and binding.get("target") == target
             and binding.get("operation_id") == operation["id"] and binding.get("config") == self.case.config,
             "TestChild completion changed its native test job")
        # The sealed plan must contain the exact child-produced candidate.
        plan = json.loads(self.blob(request["test_plan"]))
        lane = self.read("lane.status", target)
        need(plan.get("schema") == "laneboss.worker-plan.v2" and plan.get("kind") == "test"
             and plan.get("input") == request["candidate"] and plan.get("budget") == request["budget"]
             and plan.get("grant_set_id") == lane.get("grant_set_id")
             and lane.get("life_id") == target["life_id"] and lane.get("run") == target["run"],
             "TestChild result no longer names its exact candidate, plan or child grants")
        output = self.blob(worker["output"])
        capture = self.capture(events, binding)
        need(release.get("lease_id") == binding.get("helper_lease_id")
             and release.get("quiescence", {}).get("handle", {}).get("id") == binding["launch_id"]
             and release["quiescence"].get("exit_code") == 0 and not release["quiescence"].get("signal"),
             "TestChild release differs from its successful native worker")
        outside = native_release(self.case, release, target, operation["id"])
        checks = []
        for ref in select("blob.committed"):
            if ref.get("class") != "check":
                continue
            check = json.loads(self.blob(ref))
            need(check.get("schema") == "laneboss.check.v2" and check.get("target") == target
                 and check.get("operation_id") == operation["id"] and check.get("worker_lease_id") == binding["worker_lease_id"]
                 and check.get("exit_code") == 0, "TestChild check differs from its actual completed worker")
            if subject is not None:
                need(subject.get("target") == target and check.get("end_seq") == subject.get("end_seq")
                     and check.get("snapshot_sha256") == subject.get("snapshot", {}).get("sha256"),
                     "TestChild check selected another frozen subject")
            checks.append({"ref": ref, "check": check})
        names = [row["check"].get("name") for row in checks]
        need(len(names) == len(set(names)) and set(required) <= set(names),
             "TestChild did not retain each required measured check")
        result = {"operation": operation, "request": copy.deepcopy(request), "events": events,
            "output": base64.b64encode(output).decode(), "capture": capture, "checks": checks,
            "worker_release": release, "outside": outside}
        self.case.keep_json("test-result-" + str(len(self.results)) + ".json", result)
        self.results[operation["id"]] = result
        return result


def bind(case, prepared, io):
    """One dispatcher hook; original transports retain all RPC authority."""
    runner = ChildTests(case)
    case.item_test_child = runner
    result = dict(prepared)
    original, collect = prepared.get("transport"), prepared["collect"]

    def transport(message):
        if runner.failure is not None:
            raise runner.failure
        response = original(message)
        if message.get("command") != "grants test-child" or message.get("denied") is True:
            return response
        if response["exit_code"] != 0:
            runner.failure = NativeFailure(json.loads(base64.b64decode(response["stderr"], validate=True)))
            return response
        try:
            operation = json.loads(base64.b64decode(response["stdout"], validate=True))
            runner.complete(message["request"], operation)
        except Exception as error:
            runner.failure = error
            raise
        return response

    def collected(context, operations):
        if runner.failure is not None:
            raise runner.failure
        # Dashboard prepares TestChild within its input callback, so its real
        # operation also belongs in outside collection, beyond observer RPCs.
        managed = list(dict.fromkeys([*operations, *runner.results]))
        receipt = collect(context, managed)
        if runner.results:
            need(set(runner.results) <= set(receipt["operation_ids"]), "outside collection omitted a TestChild worker")
            ref = io.keep(Path(context["evidence_root"]) / "test-child-results.json", io.encoded(list(runner.results.values())))
            receipt = dict(receipt, evidence=[*receipt["evidence"], ref])
        return receipt

    if original is not None:
        result["transport"] = transport
    result["collect"] = collected
    return result

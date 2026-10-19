"""Drive two real installed CLIs; retain public results and outside receipts."""

import base64
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import secrets
import threading
import time

from ladder import blob, check, verify_pair
from draft4 import (ID, MUTATIONS, READS, REVISION, SESSION_MUTATIONS, blob_ref, intent_digest,
                    operation_proof, retained_key, session_proof, ticket, typed_reply)
from ladder_observer import RemoteFailure
from readsession import SessionReader
from support import (Failure, OwnerWait, Recorder, atomic_bytes, beneath, bytes_hash, decode,
                     evidence, exact_keys, immutable, integer, load, require, save, sha256)


def missing(symbol, owner):
    raise Failure(symbol + " is not implemented", "not_implemented", owner)


class CLI:
    def __init__(self, binary, config, binding, root, environment, read_session=None):
        self.binary = str(immutable(binary))
        self.config, self.binding = config, str(immutable(binding))
        self.bound = load(self.binding)
        require(self.bound["config"] == config and self.bound["contract_revision"] == REVISION,
                "CLI binding differs from draft.4", "version_mismatch")
        self.used_read_proofs, self.used_operation_proofs = set(), set()
        self.invocations = []
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.recorder = Recorder(self.root / "commands", environment)
        self.index = 0
        self.last_exit = 0
        self.events, self.blobs = [], {}
        self.event_positions, self.authority_events = {}, {}
        self.cursor, self.seq = "", 0
        self.reader = None
        if read_session is not None:
            exact_keys(read_session, ("binary", "proof_file"))
            self.reader = SessionReader(read_session["binary"], config, self.binding,
                                        read_session["proof_file"], self.root / "session", environment)

    def call(self, words, body, *, proof=None, request_id=None, key=None, content_ref=None):
        method = ".".join(words)
        require(method in MUTATIONS | READS, "unmapped ladder CLI method", "invalid_request")
        if method in MUTATIONS:
            retained_key(key)
        request_id = request_id or secrets.token_hex(16)
        proof_id = ""
        reader = getattr(self, "reader", None)
        shared = self.bound["class"] == "human" and method in (READS - {"health"}) | SESSION_MUTATIONS and reader is not None
        if self.bound["class"] != "human":
            require(proof is None, "lane endpoint cannot carry a human proof", "forbidden")
        elif method in (READS - {"health"}) | SESSION_MUTATIONS:
            if shared:
                require(proof is None, "shared session cannot take an ambient proof", "invalid_request")
                reader.ensure_open()
                proof_id = reader.proof_id
            elif proof is None:
                raise OwnerWait("fresh human read session", "lb-v2-identity",
                                "The owner must confirm human.session on the enrolled endpoint and supply its protected proof file.")
            else:
                proof_id = session_proof(proof, self.config, self.used_read_proofs)["id"]
        elif method in MUTATIONS and method not in ("lane.start", "lane.adopt"):
            if proof is None:
                missing("exact human operation proof", "lb-v2-identity")
            operation_proof(proof, self.config, method, body, self.used_operation_proofs)
        elif method in ("lane.start", "lane.adopt"):
            require(proof is None, "root start uses a ticket, not a proof", "invalid_request")
        self.index += 1
        label = "rpc-" + str(self.index)
        request = self.root / (label + ".request.json")
        save(request, body, mode=0o400)
        argv = [self.binary, *words, "--config", self.config,
                "--binding", self.binding, "--request", str(request)]
        if content_ref is not None:
            exact_keys(body, ("collection", "content", "related_ids"))
            require(method == "records.append" and body["related_ids"] == [],
                    "content-ref is for the exact record append", "invalid_request")
            committed = load(immutable(content_ref))
            blob_ref(committed)
            require(body["content"] == committed and body["collection"] == "reports",
                    "content-ref differs from confirmed record intent", "invalid_request")
            argv = [self.binary, *words, "--collection", "reports", "--content-ref", str(content_ref),
                    "--config", self.config, "--binding", self.binding]
        for flag, value in (("--proof", proof), ("--request-id", request_id),
                            ("--idempotency-key", key)):
            if value is not None:
                argv.extend((flag, str(value)))
        metadata = {"config": self.config, "method": method, "request_id": request_id,
                    "idempotency_key": key or "", "request_sha256":
                    intent_digest(self.config, method, body), "request_file": str(request),
                    "session_proof_id": proof_id}
        save(self.root / (label + ".intent.json"), metadata, mode=0o400)
        self.invocations.append(metadata)
        if shared:
            response = reader.call({"protocol": "laneboss.rpc.v2", "schema": 2,
                **{name: metadata[name] for name in ("config", "method", "request_id",
                   "idempotency_key", "request_sha256")}, "params": body})
            self.last_exit = 0
            return typed_reply(method, response["result"])
        result = self.recorder.run(argv, label, cwd=self.root, timeout=60)
        self.last_exit = result.exit_code
        if result.exit_code != 0:
            try:
                value = load(result.stderr)
                if "error" in value:
                    value = value["error"]
                failure = RemoteFailure(value, "lb-v2-service")
            except (Failure, ValueError, TypeError) as error:
                raise Failure("CLI exited " + str(result.exit_code) +
                              "; invalid error reply; command receipt " + str(result.receipt),
                              "integrity", "lb-v2-service") from error
            raise failure
        return typed_reply(method, result.json())

    def health(self, digest):
        value = self.call(["health"], {"client_version": "",
                                      "artifact_sha256": digest})
        if not (value["protocol"] == "laneboss.rpc.v2" and value["schema"] == 2 and
                value["ready"] is True and value["artifact_sha256"] == digest):
            raise Failure("serve not running with the tested artifact",
                          "unavailable", "lb-v2-service")
        return value

    def events_page(self):
        # The public route selects one exact life/run. Configuration-wide
        # human/ticket events require the protected observer's separate source.
        lanes = self.lanes()
        require(len(lanes) <= 10 and len({lane["life_id"] for lane in lanes}) == len(lanes),
                "ladder life selection is duplicated or exceeds ten instances")
        complete, selections = True, 0
        for lane in lanes:
            life, runs = lane["life_id"], lane["run"]
            require(isinstance(life, str) and ID.fullmatch(life) and integer(runs, 1, 4096),
                    "invalid ladder life/run selection")
            selections += runs
            require(selections <= 4096, "ladder run selection exceeds the bounded poll budget")
            for run in range(1, runs + 1):
                key = (life, run)
                position = self.event_positions.get(key, {"cursor": "", "seq": 0})
                page = self.call(["event", "tail"], {
                    "life_id": life, "run": run, "since": 0 if position["cursor"] else position["seq"],
                    "cursor": position["cursor"], "follow": False, "until": "", "deadline_ms": 1000})
                exact_keys(page, ("events", "cursor", "complete"))
                require(type(page["complete"]) is bool and isinstance(page["events"], list) and
                        len(page["events"]) <= 200 and isinstance(page["cursor"], str) and
                        len(page["cursor"]) <= 4096, "event page has no bounded complete snapshot")
                require(page["complete"] or page["cursor"] and page["cursor"] != position["cursor"],
                        "incomplete event cursor did not advance")
                previous = position["seq"]
                seen_sequences = {event["seq"] for event in self.events}
                seen_ids = {event["id"] for event in self.events}
                for event in page["events"]:
                    check(event["config"] == self.config and event["schema"] == 2 and
                          event.get("life_id") == life and event.get("run") == run and
                          integer(event["seq"], previous + 1) and event["seq"] not in seen_sequences and
                          isinstance(event["id"], str) and ID.fullmatch(event["id"]) and
                          event["id"] not in seen_ids,
                          "events", "event cursor regressed or crossed its exact selection")
                    previous = event["seq"]
                    seen_sequences.add(previous)
                    seen_ids.add(event["id"])
                self.events.extend(page["events"])
                self.event_positions[key] = {"cursor": page["cursor"], "seq": previous}
                complete = complete and page["complete"]
        self.events.sort(key=lambda event: event["seq"])
        self.seq = max((event["seq"] for event in self.events), default=0)
        return complete

    def configuration_events(self, events):
        """Supplement only service events unavailable through selected tails."""
        require(isinstance(events, list), "protected configuration events are absent")
        incoming, previous = {}, 0
        known = {event["seq"]: event for event in self.events}
        ids = {event["id"]: event for event in self.events}
        for event in events:
            require(event["config"] == self.config and event["schema"] == 2 and
                    event["origin"] == "service" and not event.get("life_id") and not event.get("run") and
                    integer(event["seq"], previous + 1) and isinstance(event["id"], str) and ID.fullmatch(event["id"]),
                    "protected configuration event crossed its scope or commit order")
            previous = event["seq"]
            require(event["seq"] not in known or known[event["seq"]] == event,
                    "protected event changed a public commit")
            require(event["id"] not in ids or ids[event["id"]] == event, "protected event reused an event ID")
            incoming[previous] = event
            known[previous], ids[event["id"]] = event, event
        require(all(incoming.get(seq) == event for seq, event in self.authority_events.items()),
                "protected configuration event snapshot is stale")
        self.authority_events = incoming
        self.events = sorted(known.values(), key=lambda event: event["seq"])

    def retain_blob(self, reference, evidence_root):
        identifier = reference["id"]
        if identifier in self.blobs:
            item = self.blobs[identifier]
            require(item["sha256"] == reference["sha256"] and
                    item["bytes"] == reference["bytes"], "blob ID changed bytes")
            return
        require(0 <= reference["bytes"] <= 67108864, "blob exceeds object bound")
        offset, parts = 0, []
        while offset < reference["bytes"]:
            chunk = self.call(["blob", "read"], {
                "object_id": identifier, "offset": offset, "limit": 262144})
            data = base64.b64decode(chunk["data"], validate=True)
            require(chunk["object_id"] == identifier and chunk["offset"] == offset and
                    0 < len(data) <= min(262144, reference["bytes"] - offset) and
                    bytes_hash(data) == chunk["sha256"], "public blob chunk differs")
            parts.append(data)
            offset += len(data)
        data = b"".join(parts)
        check(bytes_hash(data) == reference["sha256"], "transcript", "public blob digest differs")
        # Local ordinals keep untrusted object IDs out of host file paths.
        target = self.root / ("blob-" + str(len(self.blobs)))
        atomic_bytes(target, data, 0o400)
        self.blobs[identifier] = evidence(evidence_root, target)

    def retain_references(self, value, evidence_root):
        if isinstance(value, dict):
            if set(value) == {"id", "sha256", "bytes", "class"}:
                self.retain_blob(value, evidence_root)
            else:
                for item in value.values():
                    self.retain_references(item, evidence_root)
        elif isinstance(value, list):
            for item in value:
                self.retain_references(item, evidence_root)

    def lanes(self):
        lanes, cursor, seen = [], "", set()
        while True:
            page = self.call(["lane", "list"], {"cursor": cursor, "limit": 128})
            lanes.extend(page["lanes"])
            if not page["cursor"]:
                break
            require(page["cursor"] not in seen, "lane page cursor repeated")
            cursor = page["cursor"]
            seen.add(cursor)
        return lanes


def completed(events):
    created = [item for item in events if item["kind"] == "lane.created"]
    roots = [item for item in created if not item.get("parent_life_id")]
    if len(created) != 10 or len(roots) != 1:
        return False
    root = roots[0]["life_id"]
    root_turns = {item["logical_turn_id"] for item in events
                  if item["kind"] in ("lane.started", "lane.resumed") and
                  item["life_id"] == root}
    cleaned = {item["life_id"] for item in events if item["kind"] == "lane.cleaned"}
    final = [item for item in events if item["kind"] == "lane.ended" and
             item["life_id"] == root]
    return (len(root_turns) >= 2 and len(cleaned) == 9 and bool(final) and
            not final[-1]["payload"]["profile_continuation"] and
            final[-1]["seq"] > max(item["seq"] for item in events
                                  if item["kind"] == "lane.cleaned"))


def root_result(cli, evidence_root):
    roots = {item["life_id"] for item in cli.events if item["kind"] == "lane.created"
             and not item.get("parent_life_id")}
    results = []
    for event in cli.events:
        if event["kind"] != "blob.committed" or event["actor"].get("life_id") not in roots:
            continue
        ref = event["payload"]
        data = blob(evidence_root, ref, cli.blobs)
        # Only JSON result blobs are candidates; no parsing a vendor's prose.
        if ref["class"] != "report":
            continue
        body = decode(data)
        if body.get("kind") == "RESULT":
            results.append(body["answers"])
    check(len(results) == 1, "answers", "L6 did not publish one retained RESULT blob")
    return results[0]


def keep_artifacts(files, root):
    hashes, kept = {}, {}
    require({"binary", "helper", "claudock-cli", "claude", "codex"} <= set(files) <=
            {"binary", "helper", "claudock-cli", "claude", "codex", "reader"},
            "incomplete immutable executable inventory")
    for index, (name, source) in enumerate(sorted(files.items())):
        source = immutable(source)
        target = Path(root) / ("executable-" + str(index))
        shutil.copyfile(source, target)
        target.chmod(0o400)
        require(sha256(source) == sha256(target), "executable read-back differs")
        hashes[name] = sha256(target)
        kept[name] = {"source": str(source), "kept": target.name}
    return hashes, kept


def run_pair(clis, trees, observer, plan, evidence_root, artifacts, deadline=6900,
             on_verify=None):
    persistent_read_gate(clis, evidence_root)
    require(len(clis) == len(trees) == 2 and
            [cli.config for cli in clis] == [tree["config"] for tree in trees] == ["tree-a", "tree-b"],
            "two separately bound root controllers are required")
    coverage = observer.call("preflight", {"configs": [cli.config for cli in clis]})
    required = {"durable-waits", "privacy", "kernel", "overlap", "source", "actor",
                "collection", "read-auth", "root-turn", "barrier", "archives",
                "draft4-mutations", "draft4-releases", "draft4-reads", "draft4-launch-pins",
                "draft4-policy", "draft4-presence", "draft4-review", "configuration-events"}
    if coverage.get("ready") is not True or not required <= set(coverage.get("coverage", [])):
        missing("ladder independent observations", "lb-v2-integrate")
    # Prove both public read sessions work before any chargeable root start.
    scopes = []
    for cli in clis:
        scopes.append(cli.call(["identity", "self"], {}))
        cli.events_page()
        require(not any(item["kind"] == "lane.created" for item in cli.events),
                "ladder configuration is not fresh")
    # Finish both local preflights before either launch thread can reach its
    # barrier. A missing second ticket must retain its owner wait, rather than
    # leave the first thread to replace it with BrokenBarrierError.
    prepared = []
    for cli, tree, scope in zip(clis, trees, scopes):
        try:
            body = load(immutable(tree["start_file"]))
        except FileNotFoundError:
            raise Failure("8C: protected root start request is absent for " + cli.config,
                          "prerequisite_missing", "lb-v2-admin") from None
        try:
            root_ticket = load(immutable(tree["ticket_file"]))
        except FileNotFoundError:
            raise OwnerWait("fresh L6 root ticket for " + cli.config, "lb-v2-identity",
                            "The owner must issue an unspent L6 ticket at this installation's enrolled human endpoint.") from None
        ticket(root_ticket, scope, body)
        require(body["lane"] == "l6" and body["level"] == 6 and
                body["driver"] == "claudock-cli", "root start differs from scenario")
        require(isinstance(tree["request_id"], str) and ID.fullmatch(tree["request_id"]),
                "root start has no valid correlation ID")
        retained_key(tree["idempotency_key"])
        prepared.append((cli, tree, body))
    hashes, kept = keep_artifacts(artifacts, evidence_root)
    barrier = threading.Barrier(2, timeout=15)

    def start(prepared_root):
        cli, tree, body = prepared_root
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            raise Failure("two-root launch barrier did not open", "deadline_exceeded") from None
        return cli.call(["lane", "start"], body,
                        request_id=tree["request_id"], key=tree["idempotency_key"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(start, root) for root in prepared]
        outcomes = []
        for future in futures:
            try:
                outcomes.append((future.result(), None))
            except Exception as error:
                outcomes.append((None, error))
        errors = [error for _, error in outcomes if error is not None]
        if errors:
            raise errors[0]
        operations = [value for value, _ in outcomes]
    require(all(item["status"] in ("pending", "running", "succeeded") and
                not item.get("error") for item in operations), "root start failed")
    if on_verify is not None:
        on_verify()
    # The exact retained key must replay the original typed reply, not launch
    # another life or consume a new root ticket.
    for cli, tree, original in zip(clis, trees, operations):
        repeated = cli.call(["lane", "start"], load(immutable(tree["start_file"])),
                            key=tree["idempotency_key"])
        check(repeated == original, "mutation-replay", "root start replay changed its exact reply")
    end = time.monotonic() + deadline
    samples = []
    while True:
        require(time.monotonic() < end, "ladder deadline exceeded", "deadline_exceeded")
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(cli.events_page) for cli in clis]
            complete = [future.result() for future in futures]
        sample = observer.call("sample", {"configs": [cli.config for cli in clis]})
        samples.append(sample)
        save(Path(evidence_root) / "load-samples.json", samples)
        for cli in clis:
            # Persist every phase before collecting the next one.
            save(cli.root / "events.json", cli.events)
            cli.retain_references(cli.events, evidence_root)
        if all(complete) and all(completed(cli.events) for cli in clis):
            break
        threading.Event().wait(0.25)
    final = observer.call("finalize", {"configs": [cli.config for cli in clis]})
    exact_keys(final, ("runs",))
    require(set(final["runs"]) == {cli.config for cli in clis}, "observer tree set differs")
    runs = []
    for index, (cli, tree) in enumerate(zip(clis, trees)):
        measurements = final["runs"][cli.config]
        fields = {"waits", "privacy", "manual_requests", "kernel_final",
                  "sources_before", "sources_after", "unresolved", "archive_readbacks", "mutations", "reads",
                  "launch_audits", "presence", "review_requirements", "authority_events"}
        if set(measurements) != fields:
            missing("complete ladder observer coverage", "lb-v2-integrate")
        cli.configuration_events(measurements["authority_events"])
        cli.retain_references(cli.events, evidence_root)
        cli.retain_references(measurements["archive_readbacks"], evidence_root)
        cli.retain_references(measurements["launch_audits"], evidence_root)
        lanes = cli.lanes()
        cli.health(hashes["binary"])
        # Public reads create session events. Drain their real snapshots after
        # the final blob/list calls; each last tail includes its own session.
        while True:
            require(time.monotonic() < end, "final event drain exceeded deadline", "deadline_exceeded")
            complete = cli.events_page()
            before = len(cli.blobs)
            cli.retain_references(cli.events, evidence_root)
            if complete and before == len(cli.blobs):
                break
        run = {"config": cli.config, "events": cli.events, "blobs": cli.blobs,
               "lanes": lanes, "binding": tree["binding"],
               "root_answers": root_result(cli, evidence_root),
               "artifact_hashes": hashes, "artifact_files": kept,
               "caller_scope": scopes[index], "root_ticket": load(immutable(tree["ticket_file"])),
               "client_intents": cli.invocations,
               **measurements}
        runs.append(run)
    # Refresh observer protocol records after the last authenticated CLI read.
    refreshed = observer.call("finalize", {"configs": [cli.config for cli in clis]})
    exact_keys(refreshed, ("runs",))
    require(set(refreshed["runs"]) == {cli.config for cli in clis}, "final observer tree set differs")
    for cli, run in zip(clis, runs):
        measured = refreshed["runs"][cli.config]
        require(set(measured) == fields and measured["archive_readbacks"] == run["archive_readbacks"],
                "final observer changed archive references or coverage")
        cli.configuration_events(measured["authority_events"])
        run["events"] = cli.events
        run.update(measured)
        save(cli.root / "observations.json", run)
    from ladder_pins import presence_report
    reports = [presence_report(run) for run in runs]
    simulated = any(report["simulated_presence"] for report in reports)
    save(Path(evidence_root) / "presence-summary.json", {
        "simulated_presence": simulated, "presence": "simulated" if simulated else "not_measured",
        "human_approval": "not_proven" if simulated else "not_measured", "trees": reports})
    plan = {**plan, "load_samples": samples}
    verify_pair(runs, plan, evidence_root)
    return runs


def persistent_read_gate(clis, evidence_root):
    readers = [getattr(cli, "reader", None) for cli in clis]
    if len(readers) == 2 and all(isinstance(reader, SessionReader) for reader in readers):
        for reader in readers:
            reader.ensure_open()
        save(Path(evidence_root) / "read-workflow.json", {
            "configs": [cli.config for cli in clis], "session_proofs_used":
            sum(len(reader.used_proofs) for reader in readers), "root_starts": 0,
            "workflow": "installed public client connections"})
        return
    save(Path(evidence_root) / "read-workflow.json", {
        "configs": [cli.config for cli in clis], "session_proofs_used": 0,
        "root_starts": 0, "workflow": "persistent installed CLI required"})
    raise OwnerWait("persistent CLI event/blob read workflow for both trees", "lb-v2-identity",
                    "The owner must confirm fresh human.session windows and supply both protected reader/proof bindings.")

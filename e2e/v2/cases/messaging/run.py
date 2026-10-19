#!/usr/bin/env python3
"""Public CLI/dashboard messaging acceptance; no direct service-state reads."""

import argparse
import base64
import json
from pathlib import Path
import secrets
import socket
import struct
import sys

from observations import (
    CaseFailure, digest, require, verify_channel, verify_delivery,
    verify_human_mail, verify_human_raw, verify_mail_copy,
    verify_manual_actor, verify_partial_retry, verify_scheduler_actor,
)

ASSERTIONS = ("MSG-REL", "HUMAN-SEND", "MSG-RECHECK", "MSG-RETRY", "MSG-ACTOR")
TOPOLOGY = {
    "root": (6, ""), "a5": (5, "root"), "b5": (5, "root"),
    "a4": (4, "a5"), "peer4": (4, "a5"), "b4": (4, "b5"),
    "a3": (3, "a4"), "peer3": (3, "a4"), "cousin3": (3, "peer4"),
    "direct3": (3, "a5"), "b3": (3, "b4"), "other": (6, ""),
}
MAX_FRAME = 4 * 1024 * 1024


def wire_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    with temporary.open("xb") as output:
        output.write(wire_bytes(value) + b"\n")
        output.flush()
    temporary.replace(path)


def receive_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        require(bool(part), "fixture connection ended without its actual result")
        result.extend(part)
    return bytes(result)


class Case:
    def __init__(self, context, result_path):
        self.context = context
        self.result_path = result_path
        require(Path(context["test_root"]).is_absolute() and
                Path(context["evidence_root"]).is_absolute() and
                ".." not in Path(context["test_root"]).parts and
                ".." not in Path(context["evidence_root"]).parts,
                "case roots must be absolute without traversal")
        self.root = Path(context["test_root"]).resolve()
        self.evidence = Path(context["evidence_root"]).resolve()
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.transcript = self.evidence / "operations.jsonl"
        self.results = {
            name: {"id": name, "reached": False, "verdict": "fail",
                   "observed_exit": 1, "evidence": []}
            for name in ASSERTIONS
        }
        self.active = None
        self.last_exit = 1
        self.fixture = {}
        self.identities = {}
        self.lanes = {}
        self.all_lives = set()
        self.collected = False
        self.operation_index = 0
        self.owner_waiting = False

    def record(self, value):
        with self.transcript.open("ab") as output:
            output.write(wire_bytes(value) + b"\n")

    def bridge(self, endpoint, request):
        if self.active:
            self.results[self.active]["reached"] = True
        require(Path(endpoint).is_absolute() and ".." not in Path(endpoint).parts,
                "fixture socket must be absolute without traversal")
        path = Path(endpoint).resolve()
        require(path.is_absolute() and path.is_relative_to(self.root),
                "fixture socket escaped the case scope")
        data = wire_bytes(request)
        require(0 < len(data) <= MAX_FRAME, "fixture request exceeds bound")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(180)
            connection.connect(str(path))
            connection.sendall(struct.pack(">I", len(data)) + data)
            size = struct.unpack(">I", receive_exact(connection, 4))[0]
            require(0 < size <= MAX_FRAME, "fixture result exceeds bound")
            return json.loads(receive_exact(connection, size))

    def cli(self, actor, command, params=None, content=None, flags=None, refused=False):
        retained_flags = list(flags or [])
        if not any(flag == "--idempotency-key" or flag.startswith("--idempotency-key=")
                   for flag in retained_flags):
            retained_flags += ["--idempotency-key", secrets.token_hex(16)]
        request = {"command": command, "flags": retained_flags}
        if content is None:
            request["params"] = params
        else:
            request["file_bytes"] = base64.b64encode(content).decode()
        self.operation_index += 1
        response = self.bridge(self.fixture["actors"][actor], request)
        self.record({"index": self.operation_index, "actor": actor,
                     "request": request, "response": response})
        require(response["binary_sha256"] == self.context["binary_sha256"],
                "inside CLI used a different artifact")
        self.last_exit = response["exit"]
        if self.active:
            self.results[self.active]["reached"] = True
        stdout = base64.b64decode(response["stdout"], validate=True)
        stderr = base64.b64decode(response["stderr"], validate=True)
        if refused:
            require(response["exit"] == 2 and not stdout,
                    "negative operation did not refuse with a public error")
            failure = json.loads(stderr)
            require(failure["code"] in ("forbidden", "not_found"),
                    "negative operation failed setup instead of its intended boundary")
            return failure
        if response["exit"] != 0:
            failure = json.loads(stderr)
            raise CaseFailure("required public operation failed: " + failure["code"])
        require(not stderr, "successful CLI emitted unexplained stderr")
        return json.loads(stdout)

    def control(self, action, **fields):
        if self.active:
            self.results[self.active]["reached"] = True
        require("control" in self.fixture,
                "prerequisite_missing: real lifecycle/human scenario bridge")
        response = self.bridge(self.fixture["control"], {"action": action, **fields})
        self.record({"scenario_action": action, "input": fields, "response": response})
        require(response.get("exit") == 0 and response.get("public_operations"),
                "scenario action lacks successful real public-operation evidence")
        for operation in response["public_operations"]:
            require(operation["request"]["config"] == self.context["config"] and
                    operation["request"]["request_id"] == operation["response"]["request_id"] and
                    operation["response"]["protocol"] == "laneboss.rpc.v2" and
                    operation["response"]["schema"] == 2,
                    "scenario trace is not a matching configuration-bound public RPC")
            self.last_exit = operation["exit"]
        return response

    def setup(self):
        context = self.context
        require(sys.platform == "linux", "this case runs only on the authorized Linux box")
        require(context["schema"] == "laneboss.e2e-context.v2" and context["case_id"] == "messaging",
                "case context is incompatible")
        require(context["phase"] in ("red", "candidate"), "case phase is invalid")
        require(all(Path(context[name]).is_absolute() and ".." not in Path(context[name]).parts
                    for name in ("binary", "binding_file")),
                "artifact and binding paths must be absolute without traversal")
        require(digest(Path(context["binary"]).read_bytes()) == context["binary_sha256"],
                "installed artifact hash mismatch")
        require(Path(context["binding_file"]).is_file(), "installed binding is missing")
        binding = json.loads(Path(context["binding_file"]).read_bytes())
        require(binding["schema"] == "laneboss.binding.v2" and
                binding["contract_revision"] == "v2.0-draft.4" and
                binding["protocol"] == "laneboss.rpc.v2" and binding["api_schema"] == 2 and
                binding["config"] == context["config"] and
                binding["artifact_sha256"] == context["binary_sha256"],
                "case binding differs from the matched draft.4 artifact")
        fixture_path = self.root / "fixture.json"
        require(fixture_path.is_file(),
                "prerequisite_missing: installed authentic topology and human/channel fixtures")
        fixture_bytes = fixture_path.read_bytes()
        self.fixture = json.loads(fixture_bytes)
        (self.evidence / "fixture.json").write_bytes(fixture_bytes)
        used = set()
        for name, (level, parent) in TOPOLOGY.items():
            identity = self.cli(name, ["identity", "self"], {})
            require(identity["config"] == context["config"] and identity["actor"]["kind"] == "lane",
                    "fixture actor is not an authentic lane in this configuration")
            life = identity["actor"]["life_id"]
            require(life not in used, "different fixture actors share a life")
            used.add(life)
            lane = self.cli(name, ["lane", "status"], {"life_id": life, "run": 0})
            require(lane["life_id"] == life and lane["level"] == level and not lane["cleaned"],
                    "fixture level/life differs from actual status")
            expected_parent = self.lanes[parent]["life_id"] if parent else ""
            require(lane.get("parent_life_id", "") == expected_parent,
                    "fixture does not have the actual required starter edge")
            expected_chain = self.lanes[parent]["starter_chain"] + [expected_parent] if parent else []
            require(lane["starter_chain"] == expected_chain,
                    "fixture starter chain is inconsistent")
            require(lane["root_life_id"] == (self.lanes[parent]["root_life_id"] if parent else life),
                    "fixture root identity is inconsistent")
            self.identities[name], self.lanes[name] = identity, lane
            self.all_lives.add(life)

    def mailbox(self, actor):
        rows, cursor = [], ""
        seen = set()
        while True:
            page = self.cli(actor, ["mail", "list"], {"cursor": cursor, "limit": 200})
            rows.extend(page["messages"])
            cursor = page["cursor"]
            if not cursor:
                return rows
            require(cursor not in seen, "mailbox pagination repeated a cursor")
            seen.add(cursor)

    def observe_mail(self, actor, mail, content):
        rows = [item for item in self.mailbox(actor) if item["id"] == mail["id"]]
        require(len(rows) == 1, "recipient lacks exactly one immutable mail object")
        kept = rows[0]
        verify_mail_copy(kept, mail, content, self.lanes[actor]["life_id"])
        chunk = self.cli(actor, ["blob", "read"],
                         {"object_id": kept["content"]["id"], "offset": 0, "limit": 262144})
        data = base64.b64decode(chunk["data"], validate=True)
        require(data == content and digest(data) == chunk["sha256"],
                "recipient immutable bytes differ from actual file input")
        return kept

    def send_mail(self, sender, recipient, content, key=None, refused=False):
        flags = ["--life-id", self.lanes[recipient]["life_id"]]
        if key:
            flags += ["--idempotency-key", key]
        if refused:
            # Complete upload separately, so a denied upload/auth setup can
            # never masquerade as a reached mail relationship refusal.
            ref = self.upload(sender, content)
            body = {"recipient_life_id": self.lanes[recipient]["life_id"],
                    "content": ref, "ask": False}
            retry_flags = ["--idempotency-key", key] if key else None
            result = self.cli(sender, ["mail", "send"], body, flags=retry_flags, refused=True)
        else:
            result = self.cli(sender, ["mail", "send"], content=content, flags=flags)
        if not refused:
            require(result["sender"] == self.identities[sender]["actor"] and result["source"] == "cli",
                    "mail sender/source was not derived from the actual inside caller")
            self.observe_mail(recipient, result, content)
        return result

    def upload(self, actor, content):
        declared = {"class": "report", "bytes": len(content), "sha256": digest(content)}
        upload = self.cli(actor, ["blob", "begin"], declared)
        maximum = upload["max_chunk_bytes"]
        require(0 < maximum <= 262144, "upload chunk bound is invalid")
        for offset in range(0, len(content), maximum):
            part = content[offset:offset + maximum]
            self.cli(actor, ["blob", "chunk"], {
                "object_id": upload["object_id"], "offset": offset,
                "data": base64.b64encode(part).decode(), "sha256": digest(part),
            })
        ref = self.cli(actor, ["blob", "commit"],
                       {"object_id": upload["object_id"], "sha256": declared["sha256"]})
        require(ref == {"id": upload["object_id"], **declared},
                "uploaded object differs from the original file bytes")
        return ref

    def sink(self):
        require("sink_log" in self.fixture, "prerequisite_missing: independent disposable delivery sink")
        require(Path(self.fixture["sink_log"]).is_absolute() and
                ".." not in Path(self.fixture["sink_log"]).parts,
                "delivery sink must be absolute without traversal")
        path = Path(self.fixture["sink_log"]).resolve()
        require(path.is_relative_to(self.root), "delivery sink escaped the case scope")
        raw = path.read_bytes()
        (self.evidence / ("sink-" + str(self.operation_index) + ".jsonl")).write_bytes(raw)
        return [json.loads(line) for line in raw.splitlines()]

    def relations(self):
        for sender, recipient in (("a3", "peer3"), ("a4", "peer4"), ("a5", "b5"),
                                  ("a5", "a3"), ("a4", "a3"), ("a5", "direct3")):
            mail = self.send_mail(sender, recipient, ("File input " + secrets.token_hex(16) + "\n").encode())
            self.control("drain-turn", life_id=self.lanes[recipient]["life_id"], mail_ids=[mail["id"]])
            verify_delivery(self.mail_events(recipient, mail), mail, self.lanes[recipient]["life_id"])
        for sender, recipient in (("a3", "a4"), ("direct3", "a5")):
            data = ("Report input " + secrets.token_hex(16) + "\n").encode()
            mail = self.cli(sender, ["report", "submit"], content=data)
            require(mail["recipient_life_id"] == self.lanes[recipient]["life_id"],
                    "report skipped its authentic direct starter")
            self.observe_mail(recipient, mail, data)
            self.control("drain-turn", life_id=self.lanes[recipient]["life_id"], mail_ids=[mail["id"]])
            verify_delivery(self.mail_events(recipient, mail), mail, self.lanes[recipient]["life_id"])
        for sender, recipient in (("a3", "cousin3"), ("a3", "b3"), ("a3", "a5"),
                                  ("a4", "b3"), ("other", "a3"), ("a5", "other")):
            data = ("Refused input " + secrets.token_hex(16) + "\n").encode()
            self.send_mail(sender, recipient, data, refused=True)
            require(not any(item["content"]["sha256"] == digest(data) for item in self.mailbox(recipient)),
                    "refused mail appeared in the recipient mailbox")
        grants = self.channel_selectors()
        for sender in ("a3", "a4"):
            ref = self.upload(sender, b"No human fallback\n")
            self.cli(sender, ["mail", "send"], {
                "recipient_life_id": "", "channel_grant_id": grants["a5"],
                "content": ref, "ask": False,
            }, refused=True)
        for sender in ("a5", "root"):
            data = ("Channel input " + secrets.token_hex(16) + "\n").encode()
            mail = self.cli(sender, ["mail", "send"], content=data,
                            flags=["--channel-grant-id", grants[sender]])
            self.control("drain-channel", mail_id=mail["id"])
            destinations = self.fixture["channel_destinations"][grants[sender]]
            verify_channel(self.sink(), mail["id"], data, destinations)

    def events(self, actor):
        life_id = self.lanes[actor]["life_id"]
        current = self.cli(actor, ["lane", "status"], {"life_id": life_id, "run": 0})
        require(current["life_id"] == life_id and type(current["run"]) is int and
                0 < current["run"] <= 10000, "event observation has no bounded actual run inventory")
        result, identities = [], set()
        for run in range(1, current["run"] + 1):
            cursor, seen, previous = "", set(), 0
            while True:
                page = self.cli(actor, ["event", "tail"], {
                    "life_id": life_id, "run": run, "since": 0,
                    "cursor": cursor, "follow": False, "until": "", "deadline_ms": 0,
                })
                for event in page["events"]:
                    require(event["life_id"] == life_id and event["run"] == run and
                            type(event["seq"]) is int and event["seq"] > previous and
                            event["id"] not in identities, "public event page changed its selected run or order")
                    previous = event["seq"]
                    identities.add(event["id"])
                    result.append(event)
                if page["complete"]:
                    break
                cursor = page["cursor"]
                require(cursor and cursor not in seen, "event observation is incomplete or cyclic")
                seen.add(cursor)
        # An asynchronous receipt for an older run can commit after the next
        # run has started. Merge exact-run pages by their actual commit order.
        return sorted(result, key=lambda event: event["seq"])

    def owner_wait(self, owner, message, instead):
        failure = {"code": "prerequisite_missing", "owner": owner,
                   "message": message, "instead": instead}
        self.last_exit = 69
        self.owner_waiting = True
        atomic_json(self.evidence / "owner-wait.json", failure)
        self.record({"owner_wait": failure, "assertion": self.active})
        raise CaseFailure(json.dumps(failure, sort_keys=True))

    def channel_selectors(self):
        grants = self.fixture.get("channel_grants")
        if not isinstance(grants, dict) or any(not isinstance(grants.get(name), str) or not grants[name] for name in ("a5", "root")):
            self.owner_wait("lb-v2-approval", "waiting for D6-approved disposable channel grant selectors",
                            "Have the owner approve the exact disposable sink through D6; retain the actual current grant IDs.")
        # Selectors alone confer no approval. The real mail.send operation
        # still resolves protected D6 enrollment and current channel grants.
        return grants

    def mail_events(self, actor, mail):
        rows = self.events(actor)
        if mail["sender"]["kind"] == "lane":
            senders = [name for name, identity in self.identities.items()
                       if identity["actor"].get("life_id") == mail["sender"]["life_id"]]
            require(len(senders) == 1, "queue provenance has no authentic sending actor")
            if senders[0] != actor:
                rows += self.events(senders[0])
        unique = {}
        for event in rows:
            require(event["id"] not in unique or unique[event["id"]] == event,
                    "public event copies disagree on immutable bytes")
            unique[event["id"]] = event
        return sorted(unique.values(), key=lambda item: item["seq"])

    def human_send(self):
        endpoint = self.fixture.get("human")
        if not isinstance(endpoint, str) or not endpoint:
            self.owner_wait("lb-v2-identity", "waiting for actual operation-bound human dashboard confirmation",
                            "Connect the real human confirmation bridge; do not synthesize a proof or owner send.")
        path = Path(endpoint)
        require(path.is_absolute() and ".." not in path.parts and path.resolve().is_relative_to(self.root),
                "human confirmation bridge escaped the disposable scope")
        if not path.is_socket():
            self.owner_wait("lb-v2-identity", "waiting for the real human confirmation transport",
                            "Start the authorized human bridge and let the owner confirm the actual operation.")
        data = ("Human input " + secrets.token_hex(16) + "\n").encode()
        intent = {"action": "dashboard-mail", "recipient_life_id": self.lanes["a3"]["life_id"],
                  "file_bytes": base64.b64encode(data).decode(), "idempotency_key": secrets.token_hex(16)}
        response = self.bridge(self.fixture["human"], {**intent, "confirm": True})
        self.record({"human_dashboard": "confirmed", "intent": intent, "public_response": response})
        require(response["http_status"] == 200 and "error" not in response["response"],
                "verified human dashboard request failed")
        mail = response["response"]["result"]
        verify_human_mail(mail, self.lanes["a3"]["life_id"], data)
        self.observe_mail("a3", mail, data)
        unsigned = self.bridge(self.fixture["human"], {**intent, "confirm": False})
        self.record({"human_dashboard": "unsigned", "intent": intent, "public_response": unsigned})
        require(unsigned["http_status"] in (401, 403) and unsigned["response"]["error"]["code"] in ("unauthenticated", "forbidden"),
                "identical unsigned human request gained mutation or replay rights")
        self.control("drain-turn", life_id=self.lanes["a3"]["life_id"], mail_ids=[mail["id"]])
        verify_delivery(self.events("a3"), mail, self.lanes["a3"]["life_id"])
        raw = self.bridge(self.fixture["human"], {
            "action": "dashboard-raw", "life_id": self.lanes["a3"]["life_id"],
        })
        self.record({"human_dashboard": "raw", "public_response": raw})
        require(raw["http_status"] == 200 and "error" not in raw["response"],
                "human raw history request failed")
        verify_human_raw(raw["response"]["result"], mail)

    def recheck(self):
        first = self.send_mail("a5", "peer3", b"First valid carried input\n")
        second = self.send_mail("a3", "peer3", ("Later input " + secrets.token_hex(16) + "\n").encode())
        self.control("revoke-sender", life_id=self.lanes["a3"]["life_id"])
        attempt = self.control("attempt-turn", life_id=self.lanes["peer3"]["life_id"], mail_ids=[first["id"], second["id"]])
        attempted = [operation for operation in attempt["public_operations"]
                     if operation["request"]["method"] == "lane.turn"]
        require(len(attempted) == 1 and attempted[0]["exit"] == 2 and
                attempted[0]["response"].get("error", {}).get("code") == "forbidden",
                "later sender control did not reach an actual turn relation refusal")
        events = self.events("peer3")
        require(not any(event["kind"] == "mail.delivered" and event["payload"]["mail_id"] == second["id"] for event in events),
                "delivery omitted the later sender's current-rights check")
        old = self.lanes["peer3"]
        self.control("retire-reuse", life_id=old["life_id"], name=old["name"], parent_life_id=self.lanes["b4"]["life_id"])
        identity = self.cli("peer3", ["identity", "self"], {})
        replacement = self.cli("peer3", ["lane", "status"], {"life_id": identity["actor"]["life_id"], "run": 0})
        require(replacement["life_id"] != old["life_id"] and replacement["name"] == old["name"] and replacement["parent_life_id"] == self.lanes["b4"]["life_id"],
                "reused display name retained the old life or parent")
        require(not any(item["id"] in (first["id"], second["id"]) for item in self.mailbox("peer3")),
                "a replacement life inherited old private mail")
        self.lanes["peer3"], self.identities["peer3"] = replacement, identity
        self.all_lives.add(replacement["life_id"])
        self.send_mail("a5", "peer3", b"Old name gives no subtree rights\n", refused=True)

    def retry(self):
        self.control("fail-one-destination")
        data = ("Partial delivery " + secrets.token_hex(16) + "\n").encode()
        key = secrets.token_hex(16)
        grant = self.fixture["partial_channel_grant"]
        flags = ["--channel-grant-id", grant, "--idempotency-key", key]
        first = self.cli("root", ["mail", "send"], content=data, flags=flags)
        self.control("drain-partial", mail_id=first["id"])
        before = [item for item in self.sink() if item["mail_id"] == first["id"]]
        require(bool(before), "partial-delivery control did not reach a confirmed send")
        failures = [event for event in self.events("root") if event["kind"] == "channel.failed" and event["payload"]["mail_id"] == first["id"]]
        require(bool(failures), "partial delivery hid its failed outcome")
        self.control("recover-channel-worker", mail_id=first["id"])
        second = self.cli("root", ["mail", "send"], content=data, flags=flags)
        require(second == first, "channel retry changed its original durable receipt")
        self.control("drain-channel", mail_id=first["id"])
        after = [item for item in self.sink() if item["mail_id"] == first["id"]]
        destinations = self.fixture["channel_destinations"][grant]
        verify_partial_retry(before, after, first["id"], data, destinations)

    def actors(self):
        # The carried sender a4 differs from the actual requester a5.
        mail = self.send_mail("a4", "peer4", b"Actor correlation input\n")
        self.control("manual-turn", requester_life_id=self.lanes["a5"]["life_id"],
                     life_id=self.lanes["peer4"]["life_id"], mail_ids=[mail["id"]])
        events = self.mail_events("peer4", mail)
        verify_manual_actor(events, mail, self.identities["a5"]["actor"], self.lanes["peer4"]["life_id"])
        verify_delivery(events, mail, self.lanes["peer4"]["life_id"])
        automatic = self.send_mail("a5", "direct3", b"Automatic actor input\n")
        self.control("limit-then-continue", life_id=self.lanes["direct3"]["life_id"], mail_ids=[automatic["id"]])
        events = self.mail_events("direct3", automatic)
        turns = verify_scheduler_actor(events, automatic, self.lanes["direct3"]["life_id"])
        verify_delivery(events, automatic, self.lanes["direct3"]["life_id"])
        ends = [event for event in events if event["kind"] == "lane.ended" and event["logical_turn_id"] == turns[-1]["logical_turn_id"]]
        limits = [event for event in ends if event["payload"]["reason"] == "limit"]
        completed = [event for event in ends if event["payload"]["reason"] == "exit" and event["payload"]["observation"]["prompt_status"] == "completed"]
        receipts = [event for event in events if event["kind"] in ("mail.delivered", "mail.returned") and event["payload"]["mail_id"] == automatic["id"]]
        require(limits and completed and len(receipts) == 1 and receipts[0]["seq"] > completed[-1]["seq"] > limits[-1]["seq"],
                "profile-limit exit prematurely acknowledged or returned logical-turn mail")

    def collect(self):
        require("control" in self.fixture, "collection needs the real lifecycle scenario bridge")
        response = self.control("collect")
        operations = response["public_operations"]
        observations = [operation["response"]["result"] for operation in operations
                        if operation["request"]["method"] == "lane.check" and operation["exit"] == 0]
        statuses = [operation["response"]["result"] for operation in operations
                    if operation["request"]["method"] == "lane.status" and operation["exit"] == 0]
        require(self.all_lives <= {item["handle"]["target"]["life_id"] for item in observations},
                "collection omitted a managed life")
        require(all(item["state"] == "exited" and item.get("survivors") == 0 for item in observations),
                "managed processes survived or containment is unknown")
        require(self.all_lives <= {item["life_id"] for item in statuses if item["cleaned"]},
                "collection lacks actual cleaned status for a managed life")
        for name in self.fixture["temporary_paths"]:
            path = Path(name)
            require(path.is_absolute() and ".." not in path.parts and path.resolve().is_relative_to(self.root) and not path.exists(),
                    "an owned fixture resource remains after collection")
        require(set(self.fixture["actors"].values()) <= set(self.fixture["temporary_paths"]),
                "collection inventory omitted a known actor socket")
        self.collected = True

    def finish(self):
        references = []
        for path in sorted(self.evidence.iterdir()):
            require(not path.is_symlink(), "case evidence must not follow a symlink")
            if path.is_file():
                raw = path.read_bytes()
                references.append({"path": path.name, "sha256": digest(raw), "bytes": len(raw)})
        for item in self.results.values():
            item["evidence"] = references
        result = {
            "schema": "laneboss.e2e-result.v2", "case_id": "messaging",
            "phase": self.context["phase"], "mutation_id": self.context["mutation_id"],
            "binary_sha256": self.context["binary_sha256"], "source_sha256": self.context["source_sha256"],
            "assertions": list(self.results.values()),
            "collection": {"processes_quiescent": self.collected,
                           "temporary_resources_collected": self.collected,
                           "evidence": references},
        }
        atomic_json(self.result_path, result)

    def fail_active(self):
        if self.active:
            self.results[self.active]["observed_exit"] = self.last_exit or 1

    def run(self):
        success = False
        try:
            self.setup()
            for name, operation in zip(ASSERTIONS, (self.relations, self.human_send, self.recheck, self.retry, self.actors)):
                self.active = name
                operation()
                self.results[name].update(verdict="pass", observed_exit=self.last_exit)
            success = True
        except (CaseFailure, OSError, ValueError, KeyError, TypeError) as error:
            self.record({"failure_class": type(error).__name__, "assertion": self.active,
                         "reason": str(error) if isinstance(error, CaseFailure) else "missing or invalid fixture/public output"})
            if self.active:
                self.fail_active()
        finally:
            self.active = None
            try:
                self.collect()
            except (CaseFailure, OSError, ValueError, KeyError, TypeError) as error:
                self.record({"collection_failure": type(error).__name__})
                success = False
            self.finish()
        if self.owner_waiting:
            return 69
        return 0 if success and self.collected else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    options = parser.parse_args()
    require(options.context.is_absolute() and options.result.is_absolute(), "context/result paths must be absolute")
    require(".." not in options.context.parts and ".." not in options.result.parts,
            "context/result paths must not contain traversal")
    context = json.loads(options.context.read_bytes())
    case = Case(context, options.result)
    (case.evidence / "context.json").write_bytes(options.context.read_bytes())
    return case.run()


if __name__ == "__main__":
    raise SystemExit(main())

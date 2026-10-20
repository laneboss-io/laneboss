"""Declared software-device ceremony through the installed CLI, never a store."""

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import uuid


class HumanRoot:
    def __init__(self, case, private, public, require, blocked):
        self.case = case
        self.private = private
        self.public = public
        self.require = require
        self.blocked = blocked
        self.proof_index = 0
        self.grant_index = 0

    def check(self, name, suffix=None):
        parts = ["human"]
        if self.case.human_prefix:
            parts.append(self.case.human_prefix)
        parts.append(name)
        if suffix:
            parts.append(suffix)
        return ".".join(parts)

    def enroll(self):
        """The installed fixed helper is the only initial enrollment writer."""
        request = {"config": self.case.config, "ceremony_id": uuid.uuid4().hex,
                   "principal_id": self.public["principal_id"], "expected_generation": 0}
        self.case.current = "human.enroll.begin"
        challenge = self.case.admin_call("enroll-begin", request)
        self.require(challenge.get("ID") and challenge.get("Ceremony") == request and
                     challenge.get("Origin") == self.public["origin"] and challenge.get("RPID") == self.public["rp_id"] and
                     challenge.get("Consumed") is False and type(challenge.get("EndpointGeneration")) is int and
                     challenge["EndpointGeneration"] > 0 and type(challenge.get("InstallationGeneration")) is int and
                     challenge["InstallationGeneration"] > 0, "installed create challenge differs from empty-baseline ceremony")
        challenge_file = self.case.root / self.case.last["stdout"]
        self.case.passed({"challenge_id": challenge["ID"], "ceremony": request})
        self.case.current = "human.enroll.attestation"
        registration = self.case.decode_document(self.case.command("auth-register", [str(self.case.authenticator), "register",
            "--config", self.case.config, "--private", str(self.private), "--challenge", str(challenge_file)], clean=True))
        self.require(registration.get("ceremony") == request and registration.get("challenge_id") == challenge["ID"] and
                     registration.get("attestation_marker") == self.public["attestation_marker"] and
                     registration.get("attestation_object") and registration.get("client_data_json"),
                     "software registration differs from installed challenge")
        self.case.passed({"challenge_id": challenge["ID"], "attestation_marker": registration["attestation_marker"],
                          "registration_sha256": hashlib.sha256(base64.b64decode(registration["attestation_object"], validate=True)).hexdigest()})
        self.case.current = "human.enroll.complete"
        completed = self.case.admin_call("enroll-complete", registration)
        self.require(set(completed) == {"receipt", "presence", "human_approval"} and
                     completed["presence"] == "simulated" and completed["human_approval"] == "not_proven",
                     "software ceremony did not retain explicit simulated presence and unproven approval")
        receipt = completed["receipt"]
        self.require(receipt.get("CeremonyID") == request["ceremony_id"] and receipt.get("ChallengeID") == challenge["ID"] and
                     receipt.get("PrincipalID") == request["principal_id"] and receipt.get("Config") == self.case.config and
                     type(receipt.get("Generation")) is int and receipt["Generation"] == 1 and receipt.get("SimulatedPresence") is True and
                     receipt.get("Evidence", {}).get("class") == "artifact" and receipt["Evidence"].get("id") and
                     receipt.get("OperationID") and receipt.get("EventID") and type(receipt.get("CommittedSeq")) is int and receipt["CommittedSeq"] > 0,
                     "installed enrollment receipt lacks actual commit or simulated provenance")
        self.case.passed(receipt)
        self.case.current = "human.enrollment"
        self.case.passed({"receipt": receipt, "writer": "installed admin_enroll"})

    def rpc(self, label, words, request, proof=None):
        options = {"idempotency_key": "serve-human-" + uuid.uuid4().hex}
        if proof is not None:
            options["proof"] = str(proof)
        return self.case.checked_cli(label, words, request, **options)

    def proof(self, name, method, request, target, generation):
        """Only human.confirm may return the ProofRef used by the operation."""
        self.proof_index += 1
        self.case.current = self.check(name, "challenge")
        self.case.rows[self.case.current]["result"] = "fail"
        self.case.rows[self.case.current]["observed"] = {"executed": False, "rpc_executed": False,
                                                       "phase": "intent preparation"}
        prefix = "%02d-%s" % (self.proof_index, name)
        operation_file = self.case.keep_json(prefix + ".operation.json", request)
        arguments = ["--config", self.case.config, "--operation", str(operation_file),
                     "--method", method, "--target", target, "--generation", str(generation)]
        intent = json.loads(self.case.command("auth-intent", [str(self.case.authenticator), "intent", *arguments], clean=True))
        self.case.current = self.check(name, "challenge")
        challenge = self.rpc("human-challenge", ["human", "challenge"], intent)
        self.require(all(challenge.get(field) == intent[field] for field in
                         ("method", "target_id", "request_sha256", "base_generation")) and
                     challenge.get("config") == self.case.config and challenge.get("id") and
                     challenge.get("origin") == self.public["origin"] and challenge.get("rp_id") == self.public["rp_id"],
                     "installed challenge differs from exact operation or enrollment")
        challenge_file = self.case.root / self.case.last["stdout"]
        self.case.passed({"id": challenge["id"], "method": method, "request_sha256": intent["request_sha256"]})
        self.case.current = self.check(name, "confirm")
        self.case.rows[self.case.current]["result"] = "fail"
        self.case.rows[self.case.current]["observed"] = {"executed": False, "rpc_executed": False,
                                                       "phase": "assertion preparation"}
        assertion = json.loads(self.case.command("auth-sign", [str(self.case.authenticator), "sign", *arguments,
            "--private", str(self.private), "--challenge", str(challenge_file)], clean=True))
        self.require(assertion.get("challenge_id") == challenge["id"] and
                     assertion.get("credential_id") == self.public["credential_id"], "signer used another credential")
        proof = self.rpc("human-confirm", ["human", "confirm"], assertion)
        self.require(proof.get("id") and proof.get("request_sha256") == intent["request_sha256"] and
                     proof.get("expires_at") == challenge["expires_at"] and proof.get("simulated_presence") is True,
                     "installed proof differs from signed operation or simulated provenance")
        proof_file = self.case.root / self.case.last["stdout"]
        self.case.passed({"proof": proof, "credential_id": assertion["credential_id"], "signature_verified_by": "installed identity"})
        return proof_file

    def session(self, name="session"):
        proof = self.proof(name, "human.session", {}, self.public["principal_id"], 0)
        self.case.current = self.check("session")
        result = self.rpc("human-session", ["human", "session"], {}, proof)
        self.require(result.get("id") and result.get("config") == self.case.config and
                     result.get("expires_at") and result.get("idle_expires_at") and result.get("simulated_presence") is True,
                     "installed human session or simulated provenance missing")
        # This CLI process closes its socket. Its session ID is never reused
        # as a credential; every later read gets a fresh human.session proof.
        # A committed session receipt alone cannot prove the connection bind.
        # Exercise a new real CLI's session prelude and protected read on that
        # same socket, using a separate fresh proof rather than reusing the ID.
        live = self.read("human-session-read-back", ["identity", "self"], {})
        self.require(live.get("config") == self.case.config and
                     live.get("actor", {}).get("kind") == "human" and
                     live["actor"].get("id") == self.public["principal_id"] and not live.get("launch_id") and
                     type(live.get("endpoint_generation")) is int and live["endpoint_generation"] > 0 and
                     type(live.get("policy_generation")) is int and live["policy_generation"] > 0,
                     "human session did not authorize its actual same-socket read")
        self.case.passed(dict(result, connection_closed=True, same_socket_read=live))

    def read(self, label, words, request, mutation=False):
        saved_check = self.case.current
        proof = self.proof("read", "human.session", {}, self.public["principal_id"], 0)
        self.case.current = saved_check
        options = {"proof": str(proof)}
        if mutation:
            options["idempotency_key"] = "serve-stage-" + uuid.uuid4().hex
        return self.case.checked_cli(label, words, request, **options)

    def upload(self, label, kind, content):
        parent = self.case.current
        digest = hashlib.sha256(content).hexdigest()
        begun = self.read(label + "-begin", ["blob", "begin"],
                          {"class": kind, "bytes": len(content), "sha256": digest}, mutation=True)
        self.require(begun.get("object_id") and begun.get("max_chunk_bytes", 0) >= len(content), "upload allocation differs")
        self.case.current = parent
        self.read(label + "-chunk", ["blob", "chunk"], {"object_id": begun["object_id"], "offset": 0,
            "data": base64.b64encode(content).decode(), "sha256": digest}, mutation=True)
        self.case.current = parent
        ref = self.read(label + "-commit", ["blob", "commit"], {"object_id": begun["object_id"], "sha256": digest}, mutation=True)
        self.require(ref == {"id": begun["object_id"], "class": kind, "bytes": len(content), "sha256": digest},
                     "installed upload commit differs from actual bytes")
        self.case.current = parent
        return ref

    def ticket(self, launch, root_input):
        self.grant_index += 1
        grant_round = self.grant_index
        self.session()
        self.case.current = self.check("grants")
        if root_input is None:
            raise self.blocked("lb-v2-admin/grants: real committed root grant manifest input absent")
        raw = self.case.root_grant_input(root_input)
        suffix = "." + self.case.human_prefix if self.case.human_prefix else ""
        # An item can launch multiple lanes under the same reporting prefix.
        # Keep each round's exact input, even when its source bytes repeat.
        self.case.keep("root-grants" + suffix + ".%02d.input.json" % grant_round, raw)
        request = self.case.decode_document(raw)
        proof = self.proof("grants", "grants.root", request, self.case.config, 0)
        self.case.current = self.check("grants")
        grants = self.rpc("root-grants", ["grants", "root"], request, proof)
        self.require(grants.get("id") and type(grants.get("generation")) is int and grants["generation"] > 0 and
                     not grants.get("parent_life_id") and not grants.get("revoked"), "CLI did not issue current root grants")
        self.case.passed(grants)
        self.case.bind_root_launch(launch, grants, evidence_round=grant_round)
        expiry = datetime.fromisoformat(grants["expires_at"].replace("Z", "+00:00"))
        expiry = min(expiry, datetime.now(timezone.utc) + timedelta(seconds=90))
        request = {"level": launch["level"], "role": launch["role"], "grant_set_id": grants["id"],
                   "expires_at": expiry.isoformat(timespec="microseconds").removesuffix("+00:00").rstrip("0").rstrip(".") + "Z"}
        proof = self.proof("ticket", "ticket.issue", request, grants["id"], grants["generation"])
        self.case.current = self.check("ticket")
        ticket = self.rpc("root-ticket", ["ticket", "issue"], request, proof)
        self.require(ticket.get("id") and ticket.get("principal_id") == self.public["principal_id"] and
                     ticket.get("config") == self.case.config and ticket.get("redeemed") is False and ticket.get("simulated_presence") is True and
                     all(ticket.get(field) == request[field] for field in ("level", "role", "grant_set_id", "expires_at")),
                     "installed ticket differs from confirmed root authority")
        self.case.passed(ticket)
        return ticket

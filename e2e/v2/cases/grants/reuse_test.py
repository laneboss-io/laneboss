"""Value-free controls for the installed seat-reuse acceptance gate."""

import copy
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("prep", HERE / "prep_probe.py")
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
GRANTS = PREP.GRANTS
SUMMARY = GRANTS.sibling("summary")


def proof_fixture(root, fault=""):
    target = {"life_id": "contained-life", "run": 1}
    handle = {"target": target, "containment_id": "contained-group"}
    record = {"State": "withdrawn", "Authority": {"ID": "projection", "Request": {
        "Handoff": {"config": "reuse-case", "spec": {"target": target,
            "runner": {"slot": {"profile_id": "serve-profile-codex"}}}}}},
        "Fence": {"Reason": "cancelled"}, "Withdrawal": {"ProjectionID": "projection",
            "HelperLeaseID": "contained-lease", "Prepared": {"target": target,
                "containment_id": "contained-group"}, "RotationRequired": True,
            "AgentExecuted": True, "Observation": {"handle": copy.deepcopy(handle), "state": "exited", "survivors": 0}}}
    journal = {"schema": "laneboss.helper-lease.v2", "lease": {"id": "contained-lease"},
        "credential_projection": {"State": "withdrawn", "local_stop": {"Reason": "cancelled"}, "Record": record}}
    observation = {"handle": copy.deepcopy(handle), "state": "running", "survivors": 1}
    withdrawal = record["Withdrawal"]
    if fault == "natural-exit":
        journal["credential_projection"]["local_stop"]["Reason"] = "release"
    elif fault == "not-running":
        observation["state"] = "exited"
    elif fault == "no-rotation":
        withdrawal["RotationRequired"] = False
    elif fault == "not-executed":
        withdrawal["AgentExecuted"] = False
    elif fault == "wrong-target":
        withdrawal["Prepared"]["target"] = {"life_id": "other", "run": 1}
    elif fault == "wrong-seat":
        record["Authority"]["Request"]["Handoff"]["spec"]["runner"]["slot"]["profile_id"] = "other-seat"
    elif fault == "survivors":
        withdrawal["Observation"]["survivors"] = 1
    raw = GRANTS.io.encoded(journal)
    (root / "codex-cleanup-helper.input.json").write_bytes(raw)
    rows = {"lane.codex.running": {"result": "pass", "observed": {"executed": True,
        "lane": dict(target), "observation": observation}},
        "lane.codex.clean": {"result": "pass", "observed": {"executed": True,
            "native_helper": {"journal_sha256": GRANTS.sha(raw)}}}, "item.grants.reuse": {"observed": {}}}
    if fault == "changed-bytes":
        rows["lane.codex.clean"]["observed"]["native_helper"]["journal_sha256"] = "changed"
    return SimpleNamespace(root=root, config="reuse-case", rows=rows)


class Reuse(unittest.TestCase):
    def test_required(self):
        self.assertIn("item.grants.reuse", SUMMARY.with_item(SUMMARY.expected_checks(
            "installed-lifecycle"), "grants"), "installed suite has no required seat-reuse item")

    def test_refusal(self):
        target = {"life_id": "reuse-life", "run": 1}
        operation = dict(target, id="reuse-operation", status="failed", error={
            "owner": "lb-v2-secrets", "code": "forbidden",
            "message": "canonical credential is quarantined pending protected rotation"})
        self.assertEqual(GRANTS.reuse_refusal(operation, target, GRANTS.io.require), operation["error"])
        for field, value in (("status", "succeeded"), ("status", "pending"),
                             ("life_id", "another-life"), ("run", 2), ("error", None)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                GRANTS.reuse_refusal(dict(operation, **{field: value}), target, GRANTS.io.require)
        for field, value in (("owner", "lb-v2-grants"), ("code", "conflict"),
                             ("message", "profile has no room")):
            bad = copy.deepcopy(operation)
            bad["error"][field] = value
            with self.subTest(error=field), self.assertRaises(ValueError):
                GRANTS.reuse_refusal(bad, target, GRANTS.io.require)

    def test_dispatch(self):
        with tempfile.TemporaryDirectory(prefix="reuse-dispatch-") as area:
            root = Path(area)
            prepared = PREP.prefix(root)
            inputs = prepared["issued"]
            requests, passed = [], []
            target = {"life_id": "reuse-child", "run": 1}
            reserved = dict(target, id="reuse-operation", status="pending")
            rejected = dict(reserved, status="failed", error={"owner": "lb-v2-secrets", "code": "forbidden",
                "message": "canonical credential is quarantined pending protected rotation"})

            class Actor:
                def upload(self, kind, raw):
                    self_kind = {"id": "reuse-task", "class": kind, "bytes": len(raw), "sha256": GRANTS.sha(raw)}
                    return self_kind

                def call(self, command, request):
                    if command != "lane start":
                        raise ValueError("reuse control selected another endpoint")
                    requests.append(copy.deepcopy(request))
                    return copy.deepcopy(reserved)

            def read(label, words, request):
                self.assertEqual(words, ["operation", "get"])
                self.assertEqual(request, {"operation_id": reserved["id"]})
                return copy.deepcopy(rejected)

            case = proof_fixture(root)
            case.agent = {"version": "fixture-version"}
            case.grants_boot = {"profiles": prepared["profile_ids"], "budget": {"wall_ms": 60000}}
            case.human = SimpleNamespace(read=read)
            case.keep_json = PREP.BOOT.BootFixture(root).keep_json

            def note(value):
                PREP.SERVER.Case.passed(case, value)
                passed.append(value)

            case.passed = note
            # Native metadata and transport are component inputs. Real
            # producer, retained files, refusal gate and report checks execute.
            GRANTS.quarantined_reuse(case, Actor(), {"policy_generation": 1}, inputs, inputs["data"][0], GRANTS.io.require)
            self.assertEqual(len(requests), 1)
            selected = next(row for row in inputs["profiles"] if row["profile_id"] == "serve-profile-codex")
            self.assertEqual(requests[0]["profile_grant_id"], selected["id"])
            self.assertEqual(requests[0]["grants"]["profiles"], [{"parent_grant_id": selected["id"],
                "profile_id": selected["profile_id"], "delegate": False, "expires_at": selected["expires_at"]}])
            self.assertEqual(requests[0]["level"], 3)
            self.assertEqual(requests[0]["grants"]["data"][0]["relative_path"], "child")
            self.assertEqual(len(passed), 1)
            self.assertEqual(passed[0]["expected_refusal"], rejected["error"])
            self.assertEqual(case.grants_reuse["target"], target)
            self.assertFalse(case.grants_reuse["collected"])
            self.assertTrue(SUMMARY.row_passed(case.rows["item.grants.reuse"]))
            retained = GRANTS.io.encoded(rejected)
            self.assertEqual((root / "reuse-refusal.input.json").read_bytes(), retained)

    def test_containment(self):
        for fault in ("", "natural-exit", "not-running", "no-rotation", "not-executed",
                      "wrong-target", "wrong-seat", "changed-bytes", "survivors"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="reuse-proof-") as area:
                case = proof_fixture(Path(area), fault)
                if fault:
                    with self.assertRaises(ValueError):
                        GRANTS.containment_proof(case, GRANTS.io.require)
                else:
                    proof = GRANTS.containment_proof(case, GRANTS.io.require)
                    self.assertEqual(proof["target"], {"life_id": "contained-life", "run": 1})
                    self.assertEqual(proof["profile_id"], "serve-profile-codex")

    def test_abort(self):
        target = {"life_id": "reuse-child", "run": 1}
        source_sibling = GRANTS.sibling
        for fault in ("", "executed", "wrong-target", "survivors", "started", "live-uid",
                      "runtime", "cgroup", "linked"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="reuse-abort-") as area:
                case = PREP.BOOT.BootFixture(Path(area))
                case.config, case.admin = "reuse-case", {"service": {"uid": 0}}
                case.grants_reuse = {"target": target, "operation": {"id": "reuse-operation"}, "collected": False}
                lease = {"id": "reuse-lease", "containment_id": "reuse-group", "uid": 1000000000}
                if fault == "live-uid":
                    lease["uid"] = os.getuid()
                receipt = {"lease_id": lease["id"], "agent_executed": fault == "executed",
                    "quiescence": {"state": "not_started", "survivors": 1 if fault == "survivors" else 0,
                        "handle": {"target": {"life_id": "other", "run": 1} if fault == "wrong-target" else target,
                            "containment_id": lease["containment_id"]}}}
                journal = {"schema": "laneboss.helper-lease.v2", "phase": "aborted", "lease": lease,
                    "abort": {"operation_id": "reuse-operation", "cause": {"target": target}}, "abort_receipt": receipt}
                events = [{"kind": "helper.allocated", "operation_id": "reuse-operation", "payload": lease}]
                if fault == "started":
                    events.append({"kind": "lane.started"})
                runtime = Path("/var/lib") / "laneboss-v2" / "lanes" / case.config / lease["id"]
                group = (Path("/sys/fs/cgroup/system.slice") / ("laneboss-helper@" + case.config + ".service") /
                         "lanes" / lease["containment_id"])
                roots = {runtime: case.root / "runtime", group: case.root / "cgroup"}
                if fault in ("runtime", "cgroup"):
                    (case.root / fault).mkdir()
                elif fault == "linked":
                    roots[runtime].symlink_to("missing")
                path_exists, path_linked = Path.exists, Path.is_symlink

                def exists(path):
                    return path_exists(roots.get(path, path))

                def linked(path):
                    return path_linked(roots.get(path, path))

                def read(path, *, mode):
                    self.assertEqual(path, Path("/var/lib") / "laneboss-v2" / "helper" /
                                     "reuse-case" / "reuse-lease.json")
                    self.assertEqual(mode, 0o600)
                    return GRANTS.io.encoded(journal)

                def sibling(name):
                    return SimpleNamespace(read_protected=read) if name == "provision" else source_sibling(name)

                # Helper metadata and filesystem roots are component ports.
                # The filesystem twins are real directories/links in this
                # test's scratch root; UID survivors are measured in /proc.
                with patch.object(GRANTS.flow, "events", return_value=events), patch.object(GRANTS, "sibling", side_effect=sibling), \
                        patch.object(Path, "exists", exists), patch.object(Path, "is_symlink", linked):
                    if fault:
                        with self.assertRaises(ValueError):
                            GRANTS.collect_reuse(case, GRANTS.io.require)
                        self.assertFalse(case.grants_reuse["collected"])
                    else:
                        result = GRANTS.collect_reuse(case, GRANTS.io.require)
                        self.assertEqual(result["abort"], receipt)
                        self.assertEqual(result["survivors"], [])
                        self.assertTrue(case.grants_reuse["collected"])
                        self.assertEqual((case.root / "reuse-abort.input.json").read_bytes(), GRANTS.io.encoded(journal))


if __name__ == "__main__":
    unittest.main()

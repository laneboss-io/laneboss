"""Producer boundary controls; synthetic inputs are not installed evidence."""

import base64
import copy
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import tempfile
import re
import socket
import struct
import subprocess
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest import mock


source = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location(
    "case_policy", source / "scripts/v2-serve/case_policy.py")
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class ProducerControls(unittest.TestCase):
    def boot_fixture(self):
        directory = tempfile.TemporaryDirectory(prefix="lb-policy-boot-")
        self.addCleanup(directory.cleanup)
        retained = {}
        def keep(name, raw):
            self.assertNotIn(name, retained)
            retained[name] = raw
            return Path(name)
        def command(name, argv, **options):
            result = subprocess.run(argv, cwd=source, capture_output=True,
                                    timeout=options.get("seconds", 240))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            return result.stdout
        case = SimpleNamespace(stage=source, root=Path(directory.name), config="policy-case", keep=keep,
                               command=command,
                               keep_json=lambda name, value: keep(name, producer.encoded(value)))
        result = producer.boot(case)
        if hasattr(case, "policy_judge"):
            self.addCleanup(case.policy_judge.close)
        return case, result

    def test_g0_boot_contract(self):
        case, result = self.boot_fixture()
        self.assertEqual(set(result), {"bundle", "assets", "enrollment"})
        enrollment = result["enrollment"]
        self.assertGreater(enrollment["judge"]["cache_ttl_ms"], 0)
        self.assertGreater(enrollment["policy_max_cost_micros"], 0)
        worker = enrollment["judge_worker"]
        self.assertEqual(hashlib.sha256(Path(worker["tokenizer_path"]).read_bytes()).hexdigest(),
                         worker["tokenizer_executable_sha256"])
        self.assertEqual(hashlib.sha256(Path(worker["price_file"]).read_bytes()).hexdigest(),
                         worker["price_sha256"])
        handoff = producer.document(producer.read_private(case.root / "policy-judge.input.json"))
        self.assertEqual(handoff["judge"], enrollment["judge"])
        controller = Path(handoff["controller"])
        self.assertEqual(hashlib.sha256(controller.read_bytes()).hexdigest(), handoff["controller_sha256"])
        self.assertTrue(controller.stat().st_mode & 0o111)
        self.assertEqual({asset["role"] for asset in result["assets"]}, {"case-tokenizer"})
        # A control notice is not a readiness boolean. The executable must
        # reject reordering and foreign/stale authority before changing HTTP.
        bad = case.root / "bad-control.json"
        producer.publish(bad, {"stage": "partial", "config": case.config,
                              "nonce": os.urandom(16).hex(), "org_generation": 5})
        rejected = subprocess.run([str(controller), "--request", str(bad)],
                                  capture_output=True, timeout=10)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(b"stale, reordered or foreign judge control", rejected.stderr)
        self.assertEqual(case.policy_judge.phase, "normal")
        collected = case.policy_judge.close()
        self.assertTrue(collected["closed"])
        self.assertEqual(collected["errors"], [])
        self.assertTrue(all(not row["alive"] for row in collected["threads"]))
        self.assertFalse(case.policy_judge.socket_root.exists())
        self.assertEqual(producer.AGENT_PACKAGE, "./scripts/v2-serve/policy_agent")
        bundle = result["bundle"]
        self.assertEqual(base64.b64decode(case.policy_boot["task_bytes"], validate=True),
                         (source / "e2e/v2/cases/policy/role.md").read_bytes())
        self.assertFalse(any(row["ref"]["class"] == "task" for row in bundle["documents"]))
        self.assertEqual({(c["level"], c["role"]) for c in bundle["contexts"]},
                         set(producer.ROLES.values()))
        self.assertGreater(bundle["budget"]["spend_micros"], 0)
        objects = {}
        for row in bundle["documents"]:
            raw = base64.b64decode(row["data"], validate=True)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["ref"]["sha256"])
            self.assertEqual(len(raw), row["ref"]["bytes"])
            objects[row["ref"]["id"]] = raw
        root = bundle["root_grants"]
        self.assertTrue(root["data"] and root["profiles"])
        for grant in root["data"]:
            self.assertTrue(grant["delegate"])
            raw = objects[grant["source_object_id"]]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), grant["source_sha256"])
        self.assertTrue(all(p["delegate"] and not p["paid"] for p in root["profiles"]))
        self.assertEqual(root["resources"], [])
        for row in bundle["sources"]:
            self.assertIn(base64.b64decode(row["data"]), (
                (source / "e2e/v2/cases/policy/role.md").read_bytes(),
                (source / "templates/v2/org/drivers.toml").read_bytes()))

    def test_actual_boot_assembler(self):
        case, result = self.boot_fixture()
        # Feed the unchanged boot bundle AND its actual judge enrollment to
        # the real typed assembler. A replacement test judge masks invalid
        # installed settings, including the cache TTL used by SKIP.
        self.assemble_boot(result, case.config)

    def assemble_boot(self, boot, config):
        bundle = boot["bundle"]
        program = Path(sys.executable).read_bytes()
        digest = hashlib.sha256(program).hexdigest()
        executable = {"id": "policy-unit-client", "sha256": digest, "version": "0.7.0"}
        runtime = {"schema": "laneboss.runtime.v2", "generation": 1,
            "artifact": executable, "bootstrap": executable, "bindings": [],
            "objects": [{"id": name, "role": role, "root_id": "assets", "relative_path": name,
                "mode": 0o555, "content": {"id": name, "class": "artifact", "sha256": digest, "bytes": len(program)}}
                for name, role in (("policy-unit-client", "bootstrap"), ("policy-unit-agent", "serve-fixture-agent"))]}
        runtime_contents = {row["content"]["id"]: program for row in runtime["objects"]}
        for asset in boot["assets"]:
            data = Path(asset["file"]).read_bytes()
            runtime_contents[asset["id"]] = data
            runtime["objects"].append({"id": asset["id"], "role": asset["role"], "root_id": "assets",
                "relative_path": asset["id"], "mode": asset["mode"], "content": {"id": asset["id"],
                    "class": "artifact", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}})
        raw = producer.encoded(runtime)
        sources = []
        for index, (relative, logical, kind) in enumerate((
                ("org/default.md", ".laneboss/shared/templates/default.md", "prompt"),
                ("org/drivers.toml", ".laneboss/shared/templates/drivers.toml", "drivers"),
                ("org/workflow.toml", ".laneboss/shared/workflow.toml", "policy"),
                ("roles/L5/supervisor.md", ".laneboss/L5/roles/supervisor.md", "prompt"),
                ("roles/L5/supervisor.toml", ".laneboss/L5/roles/supervisor.toml", "drivers"))):
            sources.append({"id": "unit-source-" + str(index), "path": logical, "kind": kind,
                "data": base64.b64encode((source / "templates/v2" / relative).read_bytes()).decode()})
        request = {"config": config, "runtime_ref": {"id": "runtime", "class": "manifest",
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)},
            "runtime": base64.b64encode(raw).decode(), "sources": sources + bundle["sources"],
            "project": base64.b64encode(b"unit workspace\n").decode(),
            "task": base64.b64encode(b"unit task\n").decode(), "model": "1.0.0",
            "expires_at": bundle["root_grants"]["profiles"][0]["expires_at"],
            "judge": copy.deepcopy(boot["enrollment"]["judge"]),
            **{key: value for key, value in bundle.items() if key != "sources"}}
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "bundle"
            build = subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "./scripts/v2-serve/bundle"],
                                   cwd=source, capture_output=True, timeout=240)
            self.assertEqual(build.returncode, 0, build.stderr.decode())
            input_file = Path(directory) / "input.json"
            input_file.write_bytes(producer.encoded(request))
            result = subprocess.run([str(binary), "--input", str(input_file)],
                                    cwd=source, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            assembled = json.loads(result.stdout)
            # Reintroduce only the original invalid setting. The unchanged
            # validator must still reject it with its specific typed error.
            invalid = copy.deepcopy(request)
            invalid["judge"]["cache_ttl_ms"] = 300000
            invalid_file = Path(directory) / "invalid-ttl.json"
            invalid_file.write_bytes(producer.encoded(invalid))
            rejected = subprocess.run([str(binary), "--input", str(invalid_file)],
                                      cwd=source, capture_output=True, timeout=30)
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(rejected.stdout, b"")
            error = producer.document(rejected.stderr)
            self.assertEqual(error["code"], "invalid_request")
            self.assertEqual(error["message"], "invalid effective policy")
        self.assertEqual(assembled["schema"], "laneboss.serve-initial-bundle.v1")
        objects = {row["ref"]["id"]: base64.b64decode(row["data"])
                   for row in assembled["documents"]}
        initial = assembled["initial"]
        policy = json.loads(objects[initial["policy"]["id"]])
        self.assertEqual(policy["judge"], boot["enrollment"]["judge"])
        for row in bundle["documents"]:
            self.assertEqual(objects[row["ref"]["id"]], base64.b64decode(row["data"], validate=True))
        for asset in runtime["objects"][2:]:
            self.assertIn(asset["content"], initial["objects"])
        snapshot = json.loads(objects[initial["sources"]["id"]])
        paths = {row["Source"]["path"] for row in snapshot["Sources"]}
        self.assertTrue({row["path"] for row in bundle["sources"]} <= paths)
        canonical = next(row for row in snapshot["Sources"]
                         if row["Source"]["path"] == producer.ORG)
        self.assertEqual(json.loads(objects[canonical["Content"]["id"]])["judge"],
                         boot["enrollment"]["judge"])
        approved = json.loads(objects[initial["profiles"]["id"]])
        self.assertEqual(approved["data"][-len(bundle["root_grants"]["data"]):],
                         bundle["root_grants"]["data"])
        return assembled, runtime_contents

    def test_g0_entry_contract(self):
        self.assertEqual(tuple(inspect.signature(producer.prepare).parameters),
                         ("case", "require", "fail", "blocked"))
        self.assertEqual(tuple(inspect.signature(producer.abort).parameters),
                         ("case", "require", "fail"))
        run = producer.sibling("run")
        case = run.Case.__new__(run.Case)
        def abort(*_):
            raise RuntimeError("boot resource abort reached")
        case.item_module = SimpleNamespace(abort=abort)
        case.item_lives = []
        with self.assertRaisesRegex(RuntimeError, "boot resource abort reached"):
            case.cleanup()

    def test_serve_discovers_policy(self):
        reply = subprocess.run(["python3", "-B", "-E", str(source / "scripts/v2-serve/run.py"), "--help"],
                               capture_output=True, check=True, timeout=20)
        option = re.search(rb"--item-case \{([^}]+)\}", reply.stdout)
        self.assertIsNotNone(option)
        self.assertIn(b"policy", option[1].split(b","))

    def test_observer_uses_real_private_ipc(self):
        spec = importlib.util.spec_from_file_location("policy_observer", Path(__file__).with_name("observer.py"))
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        request = {"action": "rpc", "command": "policy stage", "request": {"nonce": os.urandom(16).hex()}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observer.sock"
            token = os.urandom(16).hex()
            observed = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                path.chmod(0o600)
                listener.listen(1)
                listener.settimeout(5)
                def serve():
                    with listener.accept()[0] as peer:
                        peer.settimeout(5)
                        prefix = peer.recv(4, socket.MSG_WAITALL)
                        raw = peer.recv(struct.unpack("!I", prefix)[0], socket.MSG_WAITALL)
                        observed.append(json.loads(raw))
                        reply = json.dumps({"nonce": observed[0]["request"]["nonce"]}).encode()
                        peer.sendall(struct.pack("!I", len(reply)) + reply)
                thread = threading.Thread(target=serve)
                thread.start()
                with mock.patch.dict(os.environ, {"LANEBOSS_ITEM_SOCKET": str(path), "LANEBOSS_ITEM_TOKEN": token}):
                    result = observer.exchange(request)
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(observed, [{**request, "token": token}])
            self.assertEqual(result, request["request"])

    def test_stage_fences(self):
        cursor = producer.Stages("policy-case", 7, "fresh-nonce")
        notice = {"config": "policy-case", "nonce": "fresh-nonce",
                  "stage": "baseline", "expected_generation": None}
        for edit in ({"nonce": "stale"}, {"config": "other"},
                     {"stage": "skip"}, {"expected_generation": 6}):
            with self.subTest(edit=edit):
                with self.assertRaisesRegex(ValueError, "stage"):
                    cursor.check({**notice, **edit})
        self.assertEqual(cursor.check(notice), 7)
        request = {"change_id": "change-a", "approval_id": "approval-a",
                   "expected_generation": 7}
        receipt = {"change_id": "change-a", "approval_id": "approval-a",
                   "old_generation": 7, "new_generation": 8}
        for edit in ({"change_id": "other"}, {"approval_id": "other"},
                     {"old_generation": 6}, {"new_generation": 7},
                     {"new_generation": True}):
            with self.assertRaisesRegex(ValueError, "receipt"):
                cursor.commit(request, {**receipt, **edit})
        cursor.commit(request, receipt)
        with self.assertRaisesRegex(ValueError, "stage"):
            cursor.check(notice)
        self.assertEqual(cursor.check({**notice, "stage": "skip",
                                      "expected_generation": 8}), 8)

    def test_sources_are_role_scoped(self):
        judge = {"provider": "typesafe", "model": "declared-fixture"}
        first = producer.policy_sources(judge)
        second = producer.policy_sources(judge)
        self.assertNotEqual(first["rules"], second["rules"])
        docs = first["documents"]
        org = docs[".laneboss/policy.json"]
        self.assertEqual(org["thresholds"]["match"], 0.8)
        self.assertEqual(org["judge"], judge)
        own = docs[".laneboss/L3/policy/executor.json"]
        higher = docs[".laneboss/L4/policy/reviewer.json"]
        lower = docs[".laneboss/L3/policy/tester.json"]
        self.assertEqual(own["thresholds"]["match"], 0.95)
        self.assertEqual(higher["thresholds"]["match"], 0.85)
        for name in ("cloud", "pr", "plugin"):
            rule = next(r for r in higher["rules"]
                        if r["id"] == first["rules"][name])
            self.assertEqual(rule["scope"], {"levels": [3], "roles": ["executor"]})
            self.assertTrue(rule["instead"])
            self.assertEqual(rule["band"], "refuse")
        self.assertEqual(lower["rules"][0]["id"], first["rules"]["lower"])
        for doc in docs.values():
            self.assertEqual(doc["schema"], "laneboss.policy-source.v2")
            self.assertEqual(doc["skip"], [])
            self.assertEqual(doc["settings"], [])
        self.assertEqual(own["rules"][0]["id"], first["rules"]["own"])

    def test_reply_binds_exact_job(self):
        job = {"kind": "identity", "request": {}, "idempotency_key": ""}
        raw = b"{}\n"
        reply = {"binary_sha256": "binary-pin", "config": "policy-case",
                 "contract_revision": "v2.0-draft.4", "request": {},
                 "request_bytes": base64.b64encode(raw).decode(),
                 "request_sha256": hashlib.sha256(raw).hexdigest(),
                 "idempotency_key": "", "exit": 0, "timed_out": False,
                 "stdout_bytes": base64.b64encode(b'{"native":42}').decode(),
                 "stderr_bytes": ""}
        self.assertEqual(producer.decode_reply(reply, job, "policy-case", "binary-pin"),
                         {"native": 42})
        for edit in ({"binary_sha256": "foreign"}, {"config": "foreign"},
                     {"request": {"forged": True}}, {"request_sha256": "bad"},
                     {"idempotency_key": "new-key"}, {"exit": 69},
                     {"timed_out": True}, {"contract_revision": "old"},
                     {"stderr_bytes": base64.b64encode(b"failed").decode()}):
            with self.subTest(edit=edit):
                with self.assertRaises(ValueError):
                    producer.decode_reply({**reply, **edit}, job,
                                          "policy-case", "binary-pin")

    def test_collection_needs_native_release(self):
        request = {"nonce": "unpredictable", "config": "policy-case",
                   "binary_sha256": "artifact", "actors": {
                       "executor": {"life_id": "life-a", "run": 1,
                                    "logical_turn_id": "turn-a"}}}
        row = {"target": {"life_id": "life-a", "run": 1},
               "observation": {"state": "exited", "survivors": 0,
                               "exit_code": 0, "observed_at": "observed"},
               "cleaned": True, "native_helper": {
                   "helper_journal_complete": True,
                   "worktree_measured": True, "branch_measured": True,
                   "action": "remove_clean"}}
        result = producer.collection_result(request, [row])
        self.assertTrue(result["processes_quiescent"])
        self.assertTrue(result["temporary_resources_collected"])
        self.assertEqual(result["nonce"], request["nonce"])
        bad = []
        for path, value in ((["target", "run"], 2),
                            (["observation", "survivors"], 1),
                            (["observation", "state"], "unknown"),
                            (["cleaned"], False),
                            (["native_helper", "action"], "retain_dirty"),
                            (["native_helper", "worktree_measured"], False)):
            changed = copy.deepcopy(row)
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            bad.append(changed)
        for changed in bad:
            with self.subTest(row=changed):
                with self.assertRaisesRegex(ValueError, "collection"):
                    producer.collection_result(request, [changed])
        for rows in ([], [row, row]):
            with self.assertRaisesRegex(ValueError, "collection"):
                producer.collection_result(request, rows)

        # Synthetic read-port data tests matching only; these rows never
        # supply the installed producer with authority or collection receipts.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            measured, records = {"requests": []}, []
            def ref(name, value):
                raw = producer.encoded(value)
                path = producer.publish(root / name, raw)
                return {"path": str(path), "sha256": producer.sha(raw), "bytes": len(raw)}
            for index, stage in enumerate(("normal", "timeout", "partial", "cost")):
                body = {"model": "Cloudflare/clef-flash", "state": {"task": stage},
                        "questions": {"rule-" + str(index): {"type": "noul"}}}
                raw = producer.encoded(body)
                response = {"request": "provider-" + str(index),
                    "answers": {"rule-" + str(index): {"type": "noul", "noul": .9}},
                    "usage": {"input_tokens": 2 * len(raw) + 32,
                              "output_tokens": 1000001 if stage == "cost" else 0}}
                if stage == "partial":
                    response["input_truncated"] = True
                measured["requests"].append({"stage": stage, "elapsed_ms": 2400,
                    "request": ref(stage + ".request", body),
                    "response": ref(stage + ".response", response)})
                sent = {"event": "sent", "ask": "ask-" + str(index), "claim_id": "claim-" + str(index),
                    "attempt_id": "attempt-" + str(index), "request_sha256": producer.sha(raw),
                    "request_bytes": len(raw), "reserved_micros": 2000000,
                    "outcome_reserve": 2000000, "cut": False, "withheld": False}
                records.append(sent)
                if stage != "timeout":
                    records.append({**sent, "event": "outcome", "usage_known": True,
                        "outcome": "answered" if stage == "normal" else "unscored",
                        "cost_micros": sum(response["usage"].values()), "request": response["request"],
                        "probabilities": {"rule-" + str(index): .9} if stage == "normal" else {}})
            judge = {"command_deadline_ms": 2000}
            self.assertEqual(len(producer.judge_observations(measured, records, judge, 1000000, 2000000)), 4)
            for field, value in (("request_sha256", "foreign"), ("claim_id", ""),
                                 ("reserved_micros", 0), ("request_bytes", 1)):
                changed = copy.deepcopy(records)
                changed[0][field] = value
                with self.assertRaises(ValueError):
                    producer.judge_observations(measured, changed, judge, 1000000, 2000000)
            with self.assertRaises(ValueError):
                producer.judge_observations(measured, records[:-1], judge, 1000000, 2000000)
            changed = copy.deepcopy(records)
            changed[-1]["cost_micros"] = 0
            with self.assertRaises(ValueError):
                producer.judge_observations(measured, changed, judge, 1000000, 2000000)
            # Separate legitimate calls may send identical body bytes (for
            # example, after cache expiry). Record order is not HTTP order.
            repeated = copy.deepcopy(measured)
            again = copy.deepcopy(measured["requests"][0])
            response = producer.document(producer.read_private(again["response"]["path"]))
            response["request"] = "provider-again"
            again["response"] = ref("normal-again.response", response)
            repeated["requests"].append(again)
            duplicate = copy.deepcopy(records[:2])
            for row in duplicate:
                row.update(ask="ask-again", claim_id="claim-again", attempt_id="attempt-again")
            duplicate[1]["request"] = response["request"]
            reordered = list(reversed(records + duplicate))
            self.assertEqual(len(producer.judge_observations(repeated, reordered, judge, 1000000, 2000000)), 5)

    def test_queue_preserves_existing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue = root / "queue"
            queue.mkdir(mode=0o700)
            path = queue / "0000.job.json"
            path.write_bytes(b"retained-key")
            channel = producer.Queue(queue, "policy-case", "artifact")
            with self.assertRaisesRegex(ValueError, "overwrite"):
                channel.submit("propose", {"unpredictable": os.urandom(8).hex()})
            self.assertEqual(path.read_bytes(), b"retained-key")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                producer.read_private(path)
            alias = root / "queue-alias"
            alias.symlink_to(queue, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "private"):
                producer.Queue(alias, "policy-case", "artifact")


if __name__ == "__main__":
    unittest.main()

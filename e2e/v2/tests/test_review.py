"""Review regressions: exact failures and fresh conforming controls.

These run only through the supervisor's Linux unit job. Synthetic observations
exercise acceptance logic; they never satisfy installed service acceptance.
"""

import copy
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e" / "v2"))

import box
import box_support
import draft4
import ladder
import ladder_box
import ladder_case
import ladder_live
import ladder_transactions as transactions
import manifests
import smoke_case
import support
import test_draft4
import toolchain
from caseutil import Case
from ladder_fixtures import make_run, observation


class SessionShapeRegressions(unittest.TestCase):
    def test_session_row_guards(self):
        actor = {"kind": "human", "id": "unit-human"}
        catalog = support.load(ladder.SCENARIO / "draft4-writes.json")["rows"]
        methods = ("blob.begin", "blob.chunk", "blob.commit", "secret.stage",
                   "policy.evaluate", "guidance.select", "judge.ask")
        for method in methods:
            with self.subTest(method=method):
                row = catalog[method]
                shape = {key: row[key].split() for key in ("fields", "events", "effects")}
                shape.update(guards=[], reply=True)
                self.assertIsNone(transactions.write_shape(method, actor, shape))
                for guard in ("Proof", "Ticket", "Approval"):
                    with self.assertRaises(ladder.LadderFailure) as caught:
                        transactions.write_shape(method, actor, {**shape, "guards": [guard]})
                    self.assertEqual(caught.exception.check_id, "write-matrix")

    def test_exclusive_authority(self):
        actor = {"kind": "human", "id": "unit-human"}
        for method, good, extra in (("lane.start", ["Ticket", "Cancellation"], "Proof"),
                                    ("ticket.issue", ["Proof"], "Ticket"),
                                    ("human.session", ["Proof"], "Approval")):
            with self.subTest(method=method):
                shape = {"fields": [], "events": [], "effects": [], "reply": True, "guards": good}
                with self.assertRaises(ladder.LadderFailure) as caught:
                    transactions.write_shape(method, actor, {**shape, "guards": good + [extra]})
                self.assertEqual(caught.exception.check_id, "write-matrix")
                self.assertIsNone(transactions.write_shape(method, actor, shape))


class TicketRegressions(unittest.TestCase):
    def facts(self):
        actor = {"kind": "human", "id": "unit-human"}
        ticket = {"principal_id": actor["id"], "config": "tree-a", "endpoint_generation": 1,
                  "id": "ticket", "level": 6, "role": "supervisor", "grant_set_id": "root-grants",
                  "expires_at": "2099-01-01T00:00:00Z", "redeemed": False}
        scope = {"actor": actor, "config": "tree-a", "endpoint_generation": 1}
        root = {"kind": "lane.created", "seq": 12, "operation_id": "start-op", "actor": actor,
                "payload": {"lane": {"level": 6, "role": "supervisor", "grant_set_id": "root-grants"}}}
        issued = {"kind": "ticket.issued", "seq": 3, "operation_id": "issue-op", "origin": "service",
                  "actor": actor, "payload": copy.deepcopy(ticket)}
        redeemed = {"kind": "ticket.redeemed", "seq": 11, "operation_id": "start-op", "origin": "service",
                    "actor": actor, "payload": {**ticket, "redeemed": True}}
        mutation = {"request": {"method": "lane.start", "params": {"root_ticket_id": ticket["id"]}},
                    "receipt": {"first_seq": 10, "last_seq": 11, "operation_id": "start-op"},
                    "replayed": False}
        return {"root_ticket": ticket, "caller_scope": scope, "config": "tree-a",
                "events": [issued, root, redeemed], "mutations": [mutation]}, {"l6": root}

    def test_reservation_then_creation(self):
        run, names = self.facts()
        self.assertLess(run["events"][-1]["seq"], names["l6"]["seq"])
        self.assertIsNone(draft4.ticket_events(run, names))

    def test_redemption_provenance(self):
        for field, value in (("operation_id", "another-operation"), ("seq", 15)):
            run, names = self.facts()
            run["events"][-1][field] = value
            with self.assertRaises(ladder.LadderFailure) as caught:
                draft4.ticket_events(run, names)
            self.assertEqual(caught.exception.check_id, "ticket")
        run, names = self.facts()
        names["l6"]["payload"]["lane"]["grant_set_id"] = "foreign-grants"
        with self.assertRaises(ladder.LadderFailure) as caught:
            draft4.ticket_events(run, names)
        self.assertEqual(caught.exception.check_id, "ticket")


class LiveReadRegressions(unittest.TestCase):
    def test_refuses_before_root_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clis = [Mock(config="tree-a"), Mock(config="tree-b")]
            observer = Mock()
            with self.assertRaises(support.Failure) as caught:
                ladder_live.run_pair(clis, [], observer, {}, root, {})
            self.assertEqual((caught.exception.code, caught.exception.owner),
                             ("prerequisite_missing", "lb-v2-identity"))
            self.assertIn("persistent", str(caught.exception))
            observer.call.assert_not_called()
            for cli in clis:
                cli.call.assert_not_called()
            receipt = support.load(root / "read-workflow.json")
            self.assertEqual(receipt["session_proofs_used"], 0)
            self.assertEqual(receipt["root_starts"], 0)

    def test_session_mutation_proof(self):
        fixture = test_draft4.Draft4CLIControls()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reply = {"object_id": "upload", "max_chunk_bytes": 262144, "expires_at": "2099-01-01T00:00:00Z"}
            cli = fixture.cli(root, reply)
            proof = root / "proof.json"
            fixture.proof(proof, "blob.begin", {"class": "task"})
            with patch("draft4.immutable", side_effect=support.regular):
                with self.assertRaises(support.Failure) as caught:
                    cli.call(["blob", "begin"], {"class": "task"}, proof=proof, key=os.urandom(16).hex())
                self.assertEqual(caught.exception.code, "unauthenticated")
                cli.recorder.run.assert_not_called()
                fixture.proof(proof)
                self.assertEqual(cli.call(["blob", "begin"], {"class": "task"},
                                          proof=proof, key=os.urandom(16).hex()), reply)

    def test_operation_proof(self):
        fixture = test_draft4.Draft4CLIControls()
        body = {"level": 6, "role": "supervisor", "grant_set_id": "root-grants"}
        reply = TicketRegressions().facts()[0]["root_ticket"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cli, proof = fixture.cli(root, reply), root / "proof.json"
            fixture.proof(proof, "ticket.issue", {**body, "level": 5})
            with patch("draft4.immutable", side_effect=support.regular):
                with self.assertRaises(support.Failure) as caught:
                    cli.call(["ticket", "issue"], body, proof=proof, key=os.urandom(16).hex())
                self.assertEqual(caught.exception.code, "unauthenticated")
                value = support.load(proof)
                value.update(request_sha256=draft4.intent_digest("tree-a", "ticket.issue", body),
                             expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
                support.save(proof, value)
                with self.assertRaises(support.Failure) as caught:
                    cli.call(["ticket", "issue"], body, proof=proof, key=os.urandom(16).hex())
                self.assertEqual(caught.exception.code, "unauthenticated")
                cli.recorder.run.assert_not_called()
                fixture.proof(proof, "ticket.issue", body)
                self.assertEqual(cli.call(["ticket", "issue"], body, proof=proof,
                                          key=os.urandom(16).hex()), reply)
                with self.assertRaises(support.Failure) as caught:
                    cli.call(["ticket", "issue"], body, proof=proof, key=os.urandom(16).hex())
                self.assertEqual(caught.exception.code, "unauthenticated")
                self.assertEqual(cli.recorder.run.call_count, 1)

    def test_plain_stderr_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cli = test_draft4.Draft4CLIControls().cli(root, {})
            result = cli.recorder.run.return_value
            result.stderr.write_bytes(b"usage: unexpected flag\n")
            cli.recorder.run.return_value = support.Command(2, result.stdout, result.stderr, result.receipt)
            with self.assertRaises(support.Failure) as caught:
                cli.call(["health"], {})
            self.assertEqual((caught.exception.code, caught.exception.owner), ("integrity", "lb-v2-service"))
            self.assertIn("exited 2", str(caught.exception))
            self.assertIn(str(result.receipt), str(caught.exception))
            self.assertEqual(result.stderr.read_bytes(), b"usage: unexpected flag\n")


class NamedRedRegressions(unittest.TestCase):
    def result(self, root, failure):
        target = root / "failure.json"
        support.save(target, failure)
        reference = support.evidence(root, target)
        context = {"case_id": "e2e-ladder", "phase": "red", "mutation_id": "release-survivor",
                   "binary_sha256": "a"*64, "source_sha256": "b"*64, "evidence_root": str(root)}
        value = {"schema": "laneboss.e2e-result.v2", **{key: context[key] for key in
                  ("case_id", "phase", "mutation_id", "binary_sha256", "source_sha256")},
                 "assertions": [{"id": "E2E-LADDER", "reached": True, "verdict": "fail",
                                 "observed_exit": 0, "evidence": [reference]}],
                 "collection": {"processes_quiescent": True, "temporary_resources_collected": True,
                                "evidence": [reference]}}
        path = root / "result.json"
        support.save(path, value)
        return path, {"assertion_ids": ["E2E-LADDER"]}, context

    def test_named_red_identity(self):
        failures = (ladder.LadderFailure("shape", "missing profile_swap").wire(),
                    support.Failure("entry infrastructure failed").wire(),
                    ladder.LadderFailure("answers", "another check").wire())
        for failure in failures:
            with self.subTest(failure=failure.get("check_id", "generic")):
                with tempfile.TemporaryDirectory() as temporary:
                    args = self.result(Path(temporary), failure)
                    with self.assertRaisesRegex(support.Failure, "unrelated"):
                        manifests.result_file(*args, 1, red_assertion="E2E-LADDER", red_check="release")
        with tempfile.TemporaryDirectory() as temporary:
            args = self.result(Path(temporary), ladder.LadderFailure("release", "survivors").wire())
            self.assertEqual(manifests.result_file(*args, 1, red_assertion="E2E-LADDER",
                                                  red_check="release")["phase"], "red")

    def test_missing_check_and_exit_69(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.result(Path(temporary), ladder.LadderFailure("release", "survivors").wire())
            with self.assertRaisesRegex(support.Failure, "named check"):
                manifests.result_file(*args, 1, red_assertion="E2E-LADDER")
            with self.assertRaisesRegex(support.Failure, "prerequisite"):
                manifests.result_file(*args, 69, red_assertion="E2E-LADDER", red_check="release")

    def test_reached_identity(self):
        error, reached = ladder_case.verification_failure(ladder.LadderFailure("events", "regressed"), False)
        self.assertTrue(reached)
        self.assertEqual(error.check_id, "events")
        error, reached = ladder_case.verification_failure(KeyError("profile_swap"), True)
        self.assertTrue(reached)
        self.assertEqual(error.check_id, "shape")
        error, reached = ladder_case.verification_failure(
            support.Failure("transport absent", "not_implemented", "lb-v2-identity"), True)
        self.assertFalse(reached)
        self.assertEqual(error.owner, "lb-v2-identity")


class WholeReviewRegressions(unittest.TestCase):
    def red(self, check_id, mutate):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, reports = make_run(root)
            mutate(root, run, reports)
            with self.assertRaises(ladder.LadderFailure) as caught:
                ladder.verify_run(run, plan, root)
            self.assertEqual(caught.exception.check_id, check_id)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            self.assertEqual(len(ladder.verify_run(run, plan, root)), 10)

    def test_all_retained_blobs_are_rehashed(self):
        def corrupt(root, run, _reports):
            task = run["lanes"][0]["task"]
            (root / run["blobs"][task["id"]]["path"]).write_bytes(os.urandom(task["bytes"]))
        self.red("transcript", corrupt)

    def test_root_result_must_be_retained(self):
        self.red("answers", lambda _root, run, _reports: run["events"].__setitem__(slice(None), [
            event for event in run["events"] if event["kind"] != "blob.committed"]))

    def test_public_mutation_coverage(self):
        for kind in ("human.session", "ticket.issued", "lane.turn", "blob.committed", "lane.loop"):
            with self.subTest(kind=kind):
                def mutate(_root, run, _reports):
                    event = next(event for event in run["events"] if event["kind"] == kind)
                    run["mutations"][:] = [item for item in run["mutations"] if event["id"] not in item["event_ids"]]
                self.red("mutation-key", mutate)

    def test_required_cli_intents(self):
        self.red("mutation-key", lambda _root, run, _reports: run["client_intents"].clear())

    def test_replay_cannot_consume_guard(self):
        self.red("mutation-replay", lambda _root, run, _reports:
                 run["mutations"][-1]["transaction"]["guards"].append("Ticket"))

    def test_read_before_session_is_rejected(self):
        self.red("read-auth", lambda _root, run, _reports: run["reads"][0]["response"].update(last_seq=0))

    def test_session_cannot_change_its_proof(self):
        def mutate(_root, run, _reports):
            extra = copy.deepcopy(run["reads"][0])
            extra["request"]["request_id"] = os.urandom(16).hex()
            extra["response"]["request_id"] = extra["request"]["request_id"]
            extra["session"]["proof_id"] = "another-proof"
            run["reads"].append(extra)
        self.red("read-auth", mutate)

    def test_session_requires_proof_consumption(self):
        def remove(_root, run, _reports):
            identifiers = {event["id"] for event in run["events"] if event["kind"] == "human.proof.used"}
            run["events"][:] = [event for event in run["events"] if event["id"] not in identifiers]
            for item in run["mutations"]:
                item["event_ids"][:] = [identifier for identifier in item["event_ids"] if identifier not in identifiers]
        self.red("read-auth", remove)

    def test_clean_quiescence_has_no_prompt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            for event in run["events"]:
                if event["kind"] == "lane.cleaned":
                    event["payload"]["quiescence"]["prompt_status"] = ""
            self.assertEqual(len(ladder.verify_run(run, plan, root)), 10)
        self.red("survivors", lambda _root, run, _reports: next(event for event in run["events"]
                 if event["kind"] == "lane.ended")["payload"]["observation"].update(prompt_status=""))

    def test_resume_requires_vendor_identity(self):
        self.red("runtime", lambda _root, run, _reports: next(event for event in run["events"]
                 if event["kind"] == "lane.resumed")["payload"]["lane"]["session"].update(vendor_id=""))

    def test_unrequested_swap_after_normal_exit(self):
        self.red("runtime", lambda _root, run, _reports: next(event for event in run["events"]
                 if event["kind"] == "lane.resumed")["payload"].update(profile_continuation_of=1))

    def test_release_run_binding(self):
        def mutate(_root, run, _reports):
            release = next(event for event in run["events"] if event["kind"] == "helper.released")
            release["payload"]["quiescence"]["handle"]["target"]["run"] = 1
        self.red("release", mutate)

    def test_each_terminal_action_cancels(self):
        self.red("cancellation", lambda _root, run, _reports: run["lanes"][1].update(cancellation_epoch=2))
        def remove(_root, run, _reports):
            event = next(event for event in run["events"] if event["kind"] == "watchdog.cancelled")
            run["events"].remove(event)
            for item in run["mutations"]:
                if event["id"] in item["event_ids"]:
                    item["event_ids"].remove(event["id"])
        self.red("cancellation", remove)

    def test_native_containment_is_bound(self):
        self.red("survivors", lambda _root, run, _reports: run["kernel_final"][0].update(containment_id="foreign"))
        self.red("privacy", lambda _root, run, _reports: run["privacy"][0].update(containment_id="foreign"))

    def test_failed_event_and_source_hash(self):
        def fail(_root, run, _reports):
            event = copy.deepcopy(run["events"][-1])
            event.update(id="failed-event", seq=event["seq"] + 1, kind="operation.failed")
            run["events"].append(event)
        self.red("events", fail)
        def hashes(_root, run, _reports):
            run["sources_before"] = {"source": "z"*64}
            run["sources_after"] = {"source": "z"*64}
        self.red("source-tree", hashes)


class EvidenceRegressions(unittest.TestCase):
    def case(self, root):
        case = Case.__new__(Case)
        case.root, case.result_path = root, root / "result.json"
        case.context = {"case_id": "e2e-ladder", "phase": "red", "mutation_id": "unit-red",
                        "binary_sha256": "a"*64, "source_sha256": "b"*64}
        case.assertion_ids, case.assertions, case.observed_exit = ["E2E-LADDER"], [], 0
        return case

    def test_links_and_stale_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            support.save(root / "failure.json", {"old": "failure"})
            case = self.case(root)
            self.assertEqual(case.finish(ladder.LadderFailure("release", "survivor")), 1)
            refs = support.load(case.result_path)["assertions"][0]["evidence"]
            self.assertEqual(len([item for item in refs if item["path"] == "failure.json"]), 1)
            for reference in refs:
                support.verify_evidence(root, reference)
            (root / "linked").symlink_to(root / "failure.json")
            with self.assertRaisesRegex(support.Failure, "linked evidence"):
                case.finish(ladder.LadderFailure("release", "survivor"))

    def test_source_archive_is_read_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence").mkdir()
            source = root / "source"
            source.mkdir()
            (source / "input").write_bytes(os.urandom(16))
            with patch.object(box, "ROOT", source):
                with patch.object(box, "verify_tar_inventory", side_effect=support.Failure("archive red")):
                    with self.assertRaisesRegex(support.Failure, "archive red"):
                        box.keep_source(root)
                control = root / "control"
                (control / "evidence").mkdir(parents=True)
                archive = box.keep_source(control)
                with tarfile.open(archive, "r:gz") as retained:
                    self.assertEqual(retained.extractfile("input").read(), (source / "input").read_bytes())

    def test_retained_archive_member_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, data = root / "input.tar", os.urandom(16)
            with tarfile.open(path, "w:") as archive:
                member = tarfile.TarInfo("input")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            row = {"path": "input", "bytes": len(data), "sha256": support.bytes_hash(data)}
            with self.assertRaisesRegex(support.Failure, "read-back"):
                support.verify_tar_inventory(path, [{**row, "sha256": support.bytes_hash(os.urandom(16))}])
            self.assertIsNone(support.verify_tar_inventory(path, [row]))

    def test_full_typed_projections(self):
        for method in ("lane.status", "grants.get"):
            with self.subTest(method=method):
                with self.assertRaises(ladder.LadderFailure) as caught:
                    draft4.typed_reply(method, {"life_id": "unit-life"})
                self.assertEqual(caught.exception.check_id, "typed-reply")
        with tempfile.TemporaryDirectory() as temporary:
            run, _, _ = make_run(Path(temporary))
            self.assertEqual(draft4.typed_reply("lane.status", run["lanes"][0]), run["lanes"][0])

    def test_named_go_selector(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "go"
            binary.write_bytes(os.urandom(16))
            binary.chmod(0o500)
            with patch.object(toolchain.os.environ, "get", return_value=str(binary)) as getter:
                with patch.object(toolchain.shutil, "which", side_effect=AssertionError("ambient lookup")):
                    selected = toolchain.resolve_go()
            getter.assert_called_once_with("LANEBOSS_GO")
            self.assertEqual(selected.path, binary)
            self.assertEqual(selected.sha256, support.sha256(binary))

    def test_optional_protected_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("inputs", "evidence"):
                (root / name).mkdir()
            for name in ("binary", "binding", "controls"):
                (root / name).write_bytes(os.urandom(16))
            value = {"schema": "laneboss.e2e-context.v2", "case_id": "unit-case", "phase": "candidate",
                     "mutation_id": "", "binary_sha256": "a"*64, "source_sha256": "b"*64,
                     "config": "tree-a", "profile_grant_ids": [], "binary": str(root / "binary"),
                     "binding_file": str(root / "binding"), "test_root": str(root / "inputs"),
                     "evidence_root": str(root / "evidence"), "controls": str(root / "controls")}
            path = root / "context.json"
            support.save(path, value)
            with patch.object(manifests, "immutable", side_effect=support.regular) as checked:
                self.assertEqual(manifests.context_file(path), value)
                checked.assert_called_once_with(value["controls"])
            with self.assertRaises(support.Failure):
                manifests.context_file(path)

    def test_copy_readback_checks_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "source", root / "target"
            source.write_bytes(os.urandom(16))
            original = support.shutil.copyfile
            def corrupt(source_path, target_path):
                original(source_path, target_path)
                Path(target_path).write_bytes(os.urandom(16))
            with patch.object(support.shutil, "copyfile", side_effect=corrupt):
                with self.assertRaisesRegex(support.Failure, "read-back"):
                    support.copy_verified(source, target)
            support.copy_verified(source, target)
            self.assertEqual(source.read_bytes(), target.read_bytes())

    def test_installed_boot_prerequisite(self):
        with self.assertRaises(support.Failure) as caught:
            box.installed_fixture_required()
        self.assertEqual((caught.exception.code, caught.exception.owner), ("not_implemented", "lb-v2-admin"))


class SmokeCollectionRegressions(unittest.TestCase):
    def test_failed_smoke_collects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, evidence = root / "inputs", root / "evidence"
            inputs.mkdir()
            evidence.mkdir()
            support.save(inputs / "service-read-proof.json", {"config": "tree-a", "proof_file": "proof"})
            case = Mock(inputs=inputs, root=evidence, context={"binary": "binary", "config": "tree-a",
                        "binding_file": "binding", "binary_sha256": "a"*64})
            case.finish.return_value = 1
            cli = Mock(invocations=[{"method": "health"}], last_exit=0)
            cli.call.return_value = {"events": []}
            with patch.object(smoke_case, "require_linux"), patch.object(smoke_case, "Case", return_value=case):
                with patch.object(smoke_case, "CLI", return_value=cli):
                    self.assertEqual(smoke_case.main(), 1)
            call = case.finish.call_args
            self.assertTrue(call.kwargs["reached"])
            self.assertIsInstance(call.args[0], support.Failure)
            self.assertTrue(call.kwargs["collection"]["processes_quiescent"])
            self.assertTrue(support.load(evidence / "command-collection.json")["commands_reaped"])


class BoxOrderRegressions(unittest.TestCase):
    def test_install_precedes_observer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, bundle, harvest = root / "run", root / "bundle", root / "harvest"
            bundle.mkdir()
            for name in ("evidence", "controller-home", "controller-tmp", "requests"):
                (directory / name).mkdir(parents=True)
            binary, compiler_path = root / "binary", root / "go"
            binary.write_bytes(os.urandom(16))
            compiler_path.write_bytes(os.urandom(16))
            revision = root / "revision"
            revision.write_text("abcdef0\n")
            result = support.Command(0, revision, root / "stderr", root / "receipt")
            compiler = SimpleNamespace(path=compiler_path)
            seen, environments = [], []
            recorder = Mock()
            recorder.run.return_value = result
            def record(_path, environment):
                environments.append(environment)
                return recorder
            binding = root / "observer.json"
            fake_observer = Mock()
            fake_observer.call.return_value = {"processes_quiescent": True,
                                               "temporary_resources_collected": True}
            def install(*_args):
                seen.append("install")
                support.save(binding, {"artifact_sha256": support.sha256(binary)})
                context = root / "context.json"
                support.save(context, {"binary_sha256": support.sha256(binary),
                                      "evidence_root": str(directory / "evidence")})
                return {"observer_binding": str(binding), "context_file": str(context)}
            def observe(path, _root, artifact, _draw):
                self.assertTrue(binding.exists())
                self.assertEqual(str(path), str(binding))
                self.assertEqual(support.load(binding)["artifact_sha256"], artifact)
                seen.append("observer")
                return fake_observer
            # Stop at the missing fixture_file after the ordering under test.
            # No service, model, unit subprocess or machine is started.
            with ExitStack() as stack:
                stack.enter_context(patch.object(ladder_box.os, "umask"))
                replacements = {"require_linux": Mock(), "bundle_file": Mock(return_value=(bundle, {})),
                                "run_directory": Mock(return_value=directory), "keep_source": Mock(),
                                "capacity": Mock(), "prep": Mock(return_value=(binary, compiler)),
                                "snapshot": Mock(), "Recorder": record, "install_trees": install,
                                "Observer": observe, "immutable": support.regular,
                                "finish": Mock()}
                for name, replacement in replacements.items():
                    stack.enter_context(patch.object(ladder_box, name, replacement))
                stack.enter_context(patch.object(sys, "argv", ["ladder-box", "--source-revision", "abcdef0",
                                                               "--out", str(harvest), "--seed", "7"]))
                with patch("sys.stderr", new=io.StringIO()):
                    self.assertEqual(ladder_box.main(), 2)
            self.assertEqual(seen, ["install", "observer"])
            units = recorder.run.call_args_list[-1]
            self.assertEqual(units.args[1], "harness-units")
            self.assertEqual(environments[-1]["LANEBOSS_GO"], str(compiler_path))
            fake_observer.call.assert_called_once_with("collect", {"configs": ["tree-a", "tree-b"]})

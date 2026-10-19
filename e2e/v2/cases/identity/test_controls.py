"""Reporter-only tests with synthetic events, never identity acceptance evidence."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import run as case_runner

from controls import CLI_SOURCE, COMMON_CLI_SOURCE, ControlError, DESCRIPTOR_HELPER, apply_mutation, assess_test, test_observation
from run import GROUPS, qualified_red, scenario_expectation


TARGET = ["TestFixture", "rule"]
NAME = "/".join(TARGET)
DIAGNOSTIC = "fixture check: wrong input was accepted"


def stream(action="fail", diagnostic=DIAGNOSTIC):
    events = [{"Action": "run", "Test": "TestFixture"},
              {"Action": "run", "Test": NAME},
              {"Action": "output", "Test": NAME, "Output": diagnostic + "\n"},
              {"Action": action, "Test": NAME},
              {"Action": action, "Test": "TestFixture"},
              {"Action": action}]
    return b"\n".join(json.dumps(event).encode() for event in events)


def result(exit_code):
    # Synthetic reporter input only; actual runs obtain this from waitpid and
    # independent child collection, with retained stdout/stderr references.
    return {"exit": exit_code, "timed_out": False,
            "collection": {"quiescent": True, "observed": []}}


class ReporterTests(unittest.TestCase):
    def test_catalog_controls_are_distinct(self):
        rows = json.loads(Path(__file__).with_name("mutations.json").read_bytes())["mutations"]
        seen = {}
        for row in rows:
            signature = json.dumps({key: row.get(key) for key in ("package", "test", "edits")}, sort_keys=True)
            self.assertNotIn(signature, seen, "acceptance: duplicate identity package/test/edit control")
            seen[signature] = row["id"]

    def test_expected_red_and_green(self):
        observed = test_observation(stream(), NAME)
        assess_test(result(1), observed, TARGET, red=True, diagnostic=DIAGNOSTIC)
        self.assertEqual(observed["failed_tests"], ["TestFixture", NAME])
        green = test_observation(stream(action="pass", diagnostic="valid control"), NAME)
        assess_test(result(0), green, TARGET)
        self.assertIn("pass", green["actions"])

    def test_survivor_cannot_be_killed(self):
        observed = test_observation(stream(action="pass"), NAME)
        with self.assertRaisesRegex(ControlError, "survived"):
            assess_test(result(0), observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_build_failure_is_not_red(self):
        observed = test_observation(b'{"Action":"fail"}\n', NAME)
        with self.assertRaisesRegex(ControlError, "did not run"):
            assess_test(result(1), observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_setup_and_cleanup_rejected(self):
        for prefix in ["fixture setup:", "fixture cleanup:", "panic:"]:
            with self.subTest(prefix=prefix):
                with self.assertRaisesRegex(ControlError, "setup, panic or collection"):
                    test_observation(stream(diagnostic=prefix + DIAGNOSTIC), NAME)

    def test_wrong_failure_rejected(self):
        observed = test_observation(stream(diagnostic="different assertion failed"), NAME)
        with self.assertRaisesRegex(ControlError, "unexpected reason"):
            assess_test(result(1), observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_wrong_target_rejected(self):
        raw = stream() + b'\n{"Action":"fail","Test":"TestOther"}\n'
        observed = test_observation(raw, NAME)
        with self.assertRaisesRegex(ControlError, "unexpected test"):
            assess_test(result(1), observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_skip_and_missing_rejected(self):
        for raw in [stream(action="skip"), b'{"Action":"pass"}\n']:
            with self.subTest(raw=raw):
                observed = test_observation(raw, NAME)
                with self.assertRaisesRegex(ControlError, "did not run"):
                    assess_test(result(1), observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_green_failure_is_fatal(self):
        observed = test_observation(stream(), NAME)
        with self.assertRaisesRegex(ControlError, "candidate failed"):
            assess_test(result(1), observed, TARGET)

    def test_timeout_cannot_be_killed(self):
        actual = result(1)
        actual["timed_out"] = True
        observed = test_observation(stream(), NAME)
        with self.assertRaisesRegex(ControlError, "timeout or leftover"):
            assess_test(actual, observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_descendant_cannot_be_killed(self):
        actual = result(1)
        actual["collection"]["observed"] = [123]
        observed = test_observation(stream(), NAME)
        with self.assertRaisesRegex(ControlError, "timeout or leftover"):
            assess_test(actual, observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_package_skip_rejected(self):
        raw = stream() + b'\n{"Action":"skip"}\n'
        observed = test_observation(raw, NAME)
        with self.assertRaisesRegex(ControlError, "did not run"):
            assess_test(result(1), observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_conflicting_status_rejected(self):
        raw = stream() + b"\n" + json.dumps({"Action": "pass", "Test": NAME}).encode()
        observed = test_observation(raw, NAME)
        with self.assertRaisesRegex(ControlError, "survived"):
            assess_test(result(1), observed, TARGET, red=True, diagnostic=DIAGNOSTIC)

    def test_non_json_is_not_red(self):
        with self.assertRaisesRegex(ControlError, "malformed event"):
            test_observation(b"compiler error\n", NAME)

    def test_anchor_is_exact_and_unique(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            path = root / "internal" / "v2" / "identity" / "input.go"
            path.parent.mkdir(parents=True)
            original = b"package identity\nfunc check() bool { return 2 > 1 }\n"
            path.write_bytes(original)
            files = {"input": ["internal", "v2", "identity", "input.go"]}
            spec = {"edits": [{"file": "input", "before": "2 > 1", "after": "2 < 1"}]}
            edits = apply_mutation(root, spec, files)
            self.assertEqual(len(edits), 1)
            self.assertEqual(path.read_bytes(), original.replace(b"2 > 1", b"2 < 1"))
            with self.assertRaisesRegex(ControlError, "absent or ambiguous"):
                apply_mutation(root, spec, files)
            path.write_bytes(original + original)
            with self.assertRaisesRegex(ControlError, "absent or ambiguous"):
                apply_mutation(root, spec, files)

    def test_test_file_cannot_be_mutated(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            files = {"input": ["internal", "v2", "identity", "input_test.go"]}
            spec = {"edits": [{"file": "input", "before": "x", "after": "y"}]}
            with self.assertRaisesRegex(ControlError, "production Go source"):
                apply_mutation(Path(directory), spec, files)

    def test_helper_exception_is_narrow(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            target = root / DESCRIPTOR_HELPER
            target.parent.mkdir(parents=True)
            target.write_bytes(b"package linux\nfunc helper() bool { return 2 > 1 }\n")
            files = {"helper": list(DESCRIPTOR_HELPER.parts)}
            spec = {"kind": "fixture-helper", "edits": [
                {"file": "helper", "before": "2 > 1", "after": "2 < 1"}]}
            changed = apply_mutation(root, spec, files)
            self.assertEqual(len(changed), 1)
            self.assertIn(b"2 < 1", target.read_bytes())
            before = target.read_bytes()
            injection = {"kind": "fixture-helper", "edits": [{
                "file": "helper", "before": "2 < 1",
                "after": "2 < 1\n}\nfunc TestInjected() {"}]}
            with self.assertRaisesRegex(ControlError, "cannot change test assertions"):
                apply_mutation(root, injection, files)
            self.assertEqual(target.read_bytes(), before)
            target.write_bytes(b"package linux\nfunc TestProtected() {}\n2 > 1\n")
            before = target.read_bytes()
            with self.assertRaisesRegex(ControlError, "cannot change test assertions"):
                apply_mutation(root, spec, files)
            self.assertEqual(target.read_bytes(), before)
            files["helper"] = ["internal", "v2", "identity", "input_test.go"]
            with self.assertRaisesRegex(ControlError, "production Go source"):
                apply_mutation(root, spec, files)

    def test_cli_exception_owned_explicit(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            target = root / CLI_SOURCE
            target.parent.mkdir(parents=True)
            original = b"package cli\nfunc helper() bool { return 2 > 1 }\n"
            target.write_bytes(original)
            files = {"cli": list(CLI_SOURCE.parts)}
            spec = {"package": "cli", "kind": "client", "edits": [
                {"file": "cli", "before": "2 > 1", "after": "2 < 1"}]}
            changed = apply_mutation(root, spec, files)
            self.assertEqual(len(changed), 1)
            self.assertEqual(target.read_bytes(), original.replace(b"2 > 1", b"2 < 1"))
            for field, wrong in [("package", "identity"), ("kind", "projection")]:
                target.write_bytes(original)
                invalid = dict(spec)
                invalid[field] = wrong
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ControlError, "outside identity ownership"):
                        apply_mutation(root, invalid, files)
                self.assertEqual(target.read_bytes(), original)
            files["cli"] = [*CLI_SOURCE.parts[:-1], "commands_other.go"]
            (target.parent / "commands_other.go").write_bytes(original)
            with self.assertRaisesRegex(ControlError, "outside identity ownership"):
                apply_mutation(root, spec, files)

    def test_common_cli_exception(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            target = root / COMMON_CLI_SOURCE
            target.parent.mkdir(parents=True)
            original = b"package cli\nfunc helper() bool { return 2 > 1 }\n"
            target.write_bytes(original)
            files = {"common": list(COMMON_CLI_SOURCE.parts)}
            spec = {"package": "cli", "kind": "client", "edits": [
                {"file": "common", "before": "2 > 1", "after": "2 < 1"}]}
            changed = apply_mutation(root, spec, files)
            self.assertEqual(len(changed), 1)
            self.assertEqual(target.read_bytes(), original.replace(b"2 > 1", b"2 < 1"))
            target.write_bytes(original)
            invalid = dict(spec, kind="projection")
            with self.assertRaisesRegex(ControlError, "outside identity ownership"):
                apply_mutation(root, invalid, files)
            self.assertEqual(target.read_bytes(), original)


class CaseReporterTests(unittest.TestCase):
    def observations(self, failed):
        return [{"id": name, "reached": True, "verdict": name not in failed}
                for group in GROUPS.values() for name in group]

    def test_named_canary_required(self):
        rows = self.observations({"human-no-proof", "human-effect"})
        self.assertTrue(qualified_red("omit-proof", rows))
        self.assertFalse(qualified_red("omit-generation", rows))

    def test_survivor_and_effect_only_rejected(self):
        self.assertFalse(qualified_red("omit-proof", self.observations(set())))
        self.assertFalse(qualified_red("omit-proof", self.observations({"human-effect"})))

    def test_unrelated_failure_rejected(self):
        rows = self.observations({"human-no-proof", "peer-child"})
        self.assertFalse(qualified_red("omit-proof", rows))

    def test_unreached_and_missing_rejected(self):
        rows = self.observations({"human-no-proof"})
        rows[0]["reached"] = False
        self.assertFalse(qualified_red("omit-proof", rows))
        rows = self.observations({"human-no-proof"})
        self.assertFalse(qualified_red("omit-proof", rows[:-1]))
        self.assertFalse(qualified_red("omit-proof", rows + [rows[0]]))

    def test_unknown_mutation_rejected(self):
        self.assertFalse(qualified_red("unknown", self.observations({"human-no-proof"})))

    def test_plan_checked_before_execution(self):
        for scenario in [
            {"id": "human-no-proof", "expected_exit": 0, "expect": {"id": "unexpected"}},
            {"id": "human-no-proof", "expected_exit": 75, "expect": {"code": "forbidden"}},
            {"id": "peer-child", "expected_exit": 2, "expect": {"code": "forbidden"}},
            {"id": "peer-child", "expected_exit": False, "expect": {"id": "unexpected"}},
        ]:
            with self.subTest(scenario=scenario):
                with self.assertRaises(ValueError):
                    scenario_expectation(scenario)
        scenario = {"id": "peer-foreign-containment", "expected_exit": 75,
                    "expect": {"code": "containment_unknown"}}
        self.assertEqual(scenario_expectation(scenario), (75, scenario["expect"]))


class RunnerTests(unittest.TestCase):
    # All process outputs below are synthetic reporter inputs. These tests
    # establish runner behavior only, never installed identity acceptance.
    def context(self, root):
        test_root = root / "test"
        test_root.mkdir()
        evidence = test_root / "evidence"
        evidence.mkdir()
        binary = root / "reporter-input"
        binary.write_bytes(b"reporter-only input; never executed")
        context = {"schema": "laneboss.e2e-context.v2", "case_id": "identity",
                   "phase": "candidate", "mutation_id": "", "config": "fixture",
                   "binary": str(binary), "binary_sha256": case_runner.digest(binary.read_bytes()),
                   "source_sha256": "reporter-only-source", "test_root": str(test_root),
                   "evidence_root": str(evidence), "binding_file": str(test_root / "host-binding.json")}
        return context

    def scenario(self, context, name="peer-child"):
        return {"id": name, "assertion": "PEER", "argv": [context["binary"], "identity", "self",
                "--config", context["config"], "--binding", context["binding_file"]],
                "expected_exit": 0, "expect": {"observed.id": "observed-id"}}

    def version(self):
        value = {"program": "laneboss", "api_protocol": "laneboss.rpc.v2",
                 "contract_revision": case_runner.CONTRACT_REVISION}
        return subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b"")

    def test_scenario_binding_and_config(self):
        for kind in ["namespace", "endpoint", "cross-config", "collection"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
                context = self.context(Path(directory))
                row = self.scenario(context)
                response = subprocess.CompletedProcess([], 0, b'{"observed":{"id":"observed-id"}}', b"")
                if kind == "namespace":
                    row["argv"] = ["namespace-enter", "--", context["binary"], "identity", "self",
                                   "--config=fixture", "--binding-file=/run/laneboss/binding.json"]
                if kind == "endpoint":
                    row["argv"][-1] = "/run/fixture/another-endpoint.json"
                if kind == "cross-config":
                    row.update(id="ticket-wrong-config", expected_exit=2, expect={"code": "forbidden"})
                    row["argv"][row["argv"].index("--config") + 1] = "other"
                    row["argv"][-1] = "/run/other/binding.json"
                    response = subprocess.CompletedProcess([], 2, b"", b'{"code":"forbidden"}')
                if kind == "collection":
                    row.update(id="collection", argv=["observe-owned-resources"], expect={"quiescent": True})
                    response = subprocess.CompletedProcess([], 0, b'{"quiescent":true}', b"")
                with patch.object(case_runner.subprocess, "run", return_value=response):
                    try:
                        actual = case_runner.execute(context, row, Path(context["evidence_root"]))
                    except (ValueError, KeyError, IndexError, TypeError) as error:
                        self.fail("runner rejected a permitted scenario: " + type(error).__name__)
                self.assertTrue(actual[0], "permitted scenario did not meet its assertions")
                self.assertTrue(actual[1], "permitted scenario was not reached")

    def test_binding_options_stay_explicit(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            context = self.context(Path(directory))
            variants = [
                ["--binding", "/run/first.json", "--binding-file", "/run/second.json"],
                ["--binding", "relative.json"],
                ["--binding", "/run/../other.json"],
                ["--binding="],
            ]
            for flags in variants:
                row = self.scenario(context)
                row["argv"] = row["argv"][:-2] + flags
                with self.subTest(flags=flags), self.assertRaises(ValueError):
                    case_runner.execute(context, row, Path(context["evidence_root"]))
            row = self.scenario(context)
            row["argv"][row["argv"].index("--config") + 1] = "other"
            with self.assertRaisesRegex(ValueError, "conflicting configuration"):
                case_runner.execute(context, row, Path(context["evidence_root"]))

    def test_bad_refusal_type_is_unreached(self):
        for error_code in [{}, []]:
            with self.subTest(error_code=error_code), tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
                context = self.context(Path(directory))
                row = self.scenario(context, "human-no-proof")
                row.update(expected_exit=2, expect={"code": "forbidden"})
                response = subprocess.CompletedProcess([], 2, b"", json.dumps({"code": error_code}).encode())
                with patch.object(case_runner.subprocess, "run", return_value=response):
                    try:
                        actual = case_runner.execute(context, row, Path(context["evidence_root"]))
                    except (ValueError, KeyError, IndexError, TypeError) as error:
                        self.fail("malformed refusal aborted observation: " + type(error).__name__)
                self.assertFalse(actual[0])
                self.assertFalse(actual[1])

    def test_bad_output_keeps_later_checks(self):
        for first in [b'{"observed":{}}', b"not JSON", b'{"observed":null}']:
            with self.subTest(first=first), tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
                context = self.context(Path(directory))
                root, evidence = Path(context["test_root"]), Path(context["evidence_root"])
                context_path, result_path = root / "context.json", root / "result.json"
                context_path.write_text(json.dumps(context))
                rows = [self.scenario(context), self.scenario(context, "peer-detached")]
                rows.append({"id": "collection", "argv": ["observe-owned-resources"], "expected_exit": 0,
                             "expect": {"processes_quiescent": True, "temporary_resources_collected": True}})
                (root / "identity-scenarios.json").write_text(json.dumps({
                    "contract_revision": case_runner.CONTRACT_REVISION, "scenarios": rows}))
                responses = [self.version(), subprocess.CompletedProcess([], 0, first, b""),
                             subprocess.CompletedProcess([], 0, b'{"observed":{"id":"observed-id"}}', b""),
                             subprocess.CompletedProcess([], 0, b'{"processes_quiescent":true,"temporary_resources_collected":true}', b"")]
                with patch.object(case_runner.sys, "argv", ["run.py", "--context", str(context_path), "--result", str(result_path)]), \
                        patch.object(case_runner, "GROUPS", {"PEER": ("peer-child", "peer-detached")}), \
                        patch.object(case_runner.subprocess, "run", side_effect=responses) as invoked:
                    try:
                        exit_code = case_runner.main()
                    except (ValueError, KeyError, IndexError, TypeError) as error:
                        self.fail("malformed output aborted later checks: " + type(error).__name__)
                    self.assertEqual(exit_code, 1)
                observed = evidence / "identity-observations.json"
                self.assertTrue(observed.exists(), "malformed output aborted observation collection")
                actual = json.loads(observed.read_bytes())["scenarios"]
                self.assertEqual([row["id"] for row in actual], ["peer-child", "peer-detached"])
                self.assertFalse(actual[0]["verdict"])
                self.assertTrue(actual[1]["verdict"])
                self.assertEqual(invoked.call_count, 4, "a later check or collection did not run")
                report = json.loads(result_path.read_bytes())
                self.assertTrue(report["collection"]["processes_quiescent"])
                self.assertEqual(report["assertions"][0]["verdict"], "fail")

    def test_outputs_stay_beneath_test_root(self):
        for kind in ["result", "evidence", "result-link", "evidence-link"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
                outer = Path(directory)
                context = self.context(outer)
                root = Path(context["test_root"])
                outside = outer / "outside"
                outside.mkdir()
                result_path = root / "result.json"
                if kind == "result":
                    result_path = outside / "result.json"
                if kind == "evidence":
                    context["evidence_root"] = str(outside)
                if kind.endswith("-link"):
                    link = root / "link"
                    link.symlink_to(outside, target_is_directory=True)
                    if kind == "result-link":
                        result_path = link / "result.json"
                    else:
                        context["evidence_root"] = str(link)
                context_path = root / "context.json"
                context_path.write_text(json.dumps(context))
                (root / "identity-scenarios.json").write_text(json.dumps({
                    "contract_revision": case_runner.CONTRACT_REVISION, "scenarios": []}))
                with patch.object(case_runner.sys, "argv", ["run.py", "--context", str(context_path), "--result", str(result_path)]), \
                        patch.object(case_runner.subprocess, "run", return_value=self.version()):
                    with self.assertRaisesRegex(ValueError, "under test_root"):
                        case_runner.main()
                self.assertFalse(result_path.exists(), "an escaping result path was written")


if __name__ == "__main__":
    unittest.main()

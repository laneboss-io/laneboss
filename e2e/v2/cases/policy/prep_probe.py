"""Unprivileged policy boot, assembly and profile-selection controls."""

import base64
import copy
import importlib.util
import os
from pathlib import Path
import secrets
import sys
import unittest


here = Path(__file__).resolve().parent
source = here.parents[3]
spec = importlib.util.spec_from_file_location("controls", here / "test_producer.py")
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
policy = controls.producer


def check_profiles(output=None):
    if os.geteuid() == 0:
        raise AssertionError("profile controls require the unprivileged box phase")
    test = controls.ProducerControls()
    try:
        case, boot = test.boot_fixture()
        ids = case.policy_boot.get("profiles", {})
        test.assertEqual(set(ids), set(policy.ROLES),
                         "policy roles lack independently enrolled profiles")
        test.assertEqual(len(set(ids.values())), len(policy.ROLES))
        baseline = {driver: "serve-profile-" + driver for driver in ("codex", "claudock-cli")}
        test.assertTrue(set(ids.values()).isdisjoint(baseline.values()))
        test.assertEqual(case.fixture_profile_selectors, baseline)
        assembled, _ = test.assemble_boot(boot, case.config)
        documents = {row["ref"]["id"]: base64.b64decode(row["data"], validate=True)
                     for row in assembled["documents"]}
        approved = policy.document(documents[assembled["initial"]["profiles"]["id"]])
        test.assertEqual({p["profile_id"] for p in approved["profiles"]},
                         set(ids.values()) | set(baseline.values()))
        # Only opaque issued identities are component fixture inputs. All
        # profile scope comes unchanged from the real boot/typed assembler.
        grants = copy.deepcopy(approved)
        grants.update(id=secrets.token_hex(16), generation=1, revoked=False,
                      policy_generation=assembled["initial"]["generation"],
                      life_id=secrets.token_hex(16),
                      expires_at=max(p["expires_at"] for p in approved["profiles"]))
        for family in policy.FAMILIES:
            for member in grants[family]:
                member["id"] = secrets.token_hex(16)
        run = policy.sibling("run")
        binder = run.Case.__new__(run.Case)
        binder.root = case.root
        binder.initial = assembled["initial"]
        binder.initial_receipt = {"generation": assembled["initial"]["generation"]}
        binder.generated_launches = True
        binder.egress_anthropic = False
        binder.human_prefix = "prep"
        binder.keep_json = case.keep_json
        binder.fixture_profile_selectors = case.fixture_profile_selectors
        inputs = case.root / "initial-inputs"
        inputs.mkdir(mode=0o700)
        policy.publish(inputs / binder.initial["profiles"]["id"],
                       documents[binder.initial["profiles"]["id"]])
        for driver in baseline:
            request = copy.deepcopy(assembled["lanes"][driver])
            binder.bind_root_launch(request, grants)
            chosen = next(p for p in grants["profiles"] if p["id"] == request["profile_grant_id"])
            test.assertEqual(chosen["profile_id"], baseline[driver])

        reads = []
        class Human:
            def ticket(self, request, root_input):
                test.assertEqual(root_input, "fixture-root")
                binder.bind_root_launch(request, grants)
                return {"id": secrets.token_hex(16), "grant_set_id": grants["id"]}

            def read(self, label, words, request):
                test.assertEqual(words, ["grants", "get"])
                test.assertEqual(request, {"grant_set_id": grants["id"]})
                reads.append({"words": list(words), "request": copy.deepcopy(request)})
                return copy.deepcopy(grants)

        binder.human = Human()
        binder.human_prefix = "prep-policy"
        producer = policy.Producer.__new__(policy.Producer)
        producer.serve = binder
        producer.inputs = {"profile_ids": ids, "root_grants_file": "fixture-root"}
        producer.read_index = 0
        retained = {}
        def keep(name, value):
            test.assertNotIn(name, retained)
            retained[name] = copy.deepcopy(value)
        producer.keep = keep
        root = copy.deepcopy(assembled["lanes"]["codex"])
        root.update(level=6, role="supervisor")
        ticket = producer.ticket(root)
        test.assertEqual(ticket["grant_set_id"], grants["id"])
        selected = next(p for p in grants["profiles"] if p["id"] == root["profile_grant_id"])
        test.assertEqual(selected["profile_id"], ids["l6"])
        test.assertEqual({p["profile_id"] for p in root["grants"]["profiles"]}, set(ids.values()))
        test.assertTrue(all(p["delegate"] for p in root["grants"]["profiles"]))
        test.assertEqual(binder.fixture_profile_selectors, baseline)
        test.assertEqual(retained["l6-profiles.input.json"], grants)
        # Missing issuance cannot fall back to the baseline seat.
        missing = copy.deepcopy(grants)
        missing["profiles"] = [p for p in missing["profiles"] if p["profile_id"] != ids["tester"]]
        with test.assertRaisesRegex(ValueError, "policy profile"):
            policy.profile_grants(missing, ids, "codex")
        duplicate = dict(ids)
        duplicate["tester"] = ids["executor"]
        with test.assertRaisesRegex(ValueError, "policy profile"):
            policy.profile_grants(grants, duplicate, "codex")
        if output is not None:
            # The real ticket method supplies the request. Issued IDs remain
            # the declared component inputs used above, never live authority.
            exported = {name: grants[name] for name in policy.FAMILIES}
            exported.update({name: grants[name] for name in
                             ("id", "life_id", "generation", "revoked", "policy_generation", "expires_at")})
            test.assertEqual(len(reads), 1)
            policy.publish(output, {"reads": reads, "grants": exported})
        print("GREEN: publication, baseline binding, L6 delegation and missing-profile twins")
    finally:
        if not test.doCleanups():
            raise AssertionError("policy boot cleanup failed")


def serve_units():
    path = source / "scripts/v2-serve"
    sys.path.insert(0, str(path))
    suite = unittest.TestSuite()
    # Unprivileged controls; protected staging and installs are separate.
    for name in ("summary_test", "agent_evidence_test", "helper_policy_test",
                 "launch_evidence_test", "api_key_canary_test", "reuse_gate_test", "wd_review_test"):
        spec = importlib.util.spec_from_file_location(name, path / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun == 0:
        raise AssertionError("unprivileged serve harness controls failed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--units"]:
        serve_units()
    elif len(sys.argv) == 3 and sys.argv[1] == "--row":
        check_profiles(Path(sys.argv[2]))
    elif not sys.argv[1:]:
        check_profiles()
    else:
        raise SystemExit("unknown probe option")

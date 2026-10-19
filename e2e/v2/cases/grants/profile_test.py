"""Producer selector regressions. Native acceptance is measured separately."""

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("prep", Path(__file__).with_name("prep_probe.py"))
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
GRANTS = PREP.GRANTS


class Profiles(unittest.TestCase):
    def setUp(self):
        area = tempfile.TemporaryDirectory(prefix="grants-profiles-")
        self.addCleanup(area.cleanup)
        self.input = PREP.prefix(Path(area.name))

    def test_baseline(self):
        root = self.input["approved"]
        ids = self.input["profile_ids"]
        self.assertEqual(set(ids), {"parent", "child"})
        self.assertEqual(len(set(ids.values())), 2)
        self.assertEqual(len(root["profiles"]), 4)
        self.assertEqual([row["profile_id"] for row in root["profiles"][:2]],
                         ["serve-profile-claudock-cli", "serve-profile-codex"])
        for row in root["profiles"]:
            self.assertEqual(row["id"], "")
            self.assertEqual(row["provider"], "serve-fixture")
            self.assertIs(row["paid"], False)
            self.assertIs(row["delegate"], True)
        request = self.input["parent_request"]
        self.assertEqual(request["profile_grant_id"], self.input["parent"]["id"])
        self.assertEqual(self.input["parent"]["profile_id"], ids["parent"])
        self.assertEqual(self.input["child"]["profile_id"], ids["child"])
        self.assertNotEqual(self.input["parent"]["id"], self.input["child"]["id"])
        self.assertEqual(len(request["grants"]["profiles"]), 3)
        self.assertEqual(self.input["delegated"][-1]["profile_id"], "serve-profile-codex")
        self.assertEqual([row["delegate"] for row in request["grants"]["data"]], [True, False])
        for name in ("resources", "secrets", "network", "channels"):
            self.assertEqual(request["grants"][name], [])

    def test_issued_scope(self):
        ids = self.input["profile_ids"]
        original = self.input["issued"]
        retained = copy.deepcopy(original)
        good = GRANTS.profile_members(original, ids, GRANTS.io.require)
        self.assertEqual(set(good), set(ids))
        for actor in ids:
            for field, value in (("id", "bad/id"), ("driver", "claudock-cli"),
                    ("provider", "other-provider"), ("paid", True), ("paid", 0),
                    ("delegate", False), ("delegate", 1), ("expires_at", ""),
                    ("expires_at", "bad-date"), ("expires_at", "2000-01-01T00:00:00Z"),
                    ("expires_at", "2099-01-01T00:00:00"), ("parent_grant_id", "foreign")):
                with self.subTest(actor=actor, field=field, value=value):
                    bad = copy.deepcopy(original)
                    row = next(row for row in bad["profiles"] if row["profile_id"] == ids[actor])
                    row[field] = value
                    with self.assertRaises(ValueError):
                        GRANTS.profile_members(bad, ids, GRANTS.io.require)
            for mode in ("missing", "duplicate", "shared-id"):
                with self.subTest(actor=actor, mode=mode):
                    bad = copy.deepcopy(original)
                    row = next(row for row in bad["profiles"] if row["profile_id"] == ids[actor])
                    if mode == "missing":
                        bad["profiles"].remove(row)
                    elif mode == "duplicate":
                        bad["profiles"].append(copy.deepcopy(row))
                    else:
                        row["id"] = good["child" if actor == "parent" else "parent"]["id"]
                    with self.assertRaises(ValueError):
                        GRANTS.profile_members(bad, ids, GRANTS.io.require)
        for bad in ({}, {"parent": ids["parent"], "child": ids["parent"]},
                    {"parent": ids["parent"], "child": ""}):
            with self.subTest(selectors=bad), self.assertRaises(ValueError):
                GRANTS.profile_members(original, bad, GRANTS.io.require)
        self.assertEqual(original, retained, "selection mutated original grants")


if __name__ == "__main__":
    unittest.main()

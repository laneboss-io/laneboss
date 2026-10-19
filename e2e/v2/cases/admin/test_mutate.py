"""Mutation reporter/fixture classification tests, with no product execution."""
import json
from pathlib import Path
import unittest

import mutate


class MutationClassification(unittest.TestCase):
    def test_test_target_requires_fixture_class(self):
        edit = {"path": "internal/v2/admin/private_dir_test.go"}
        with self.assertRaisesRegex(mutate.InvalidRun, "evidence class"):
            mutate.edit_path(edit)
        self.assertEqual(mutate.edit_path(edit, "fixture-check"), edit["path"])

    def test_product_cannot_claim_fixture(self):
        edit = {"path": "internal/v2/admin/gate_args_linux.go"}
        self.assertEqual(mutate.edit_path(edit), edit["path"])
        with self.assertRaisesRegex(mutate.InvalidRun, "evidence class"):
            mutate.edit_path(edit, "fixture-check")

    def test_catalog_is_classified_and_mapped(self):
        catalog = json.loads(Path(__file__).with_name("mutations.json").read_bytes())
        ids = {row["id"] for row in catalog["mutations"]}
        mapped = {identifier for rule in catalog["acceptance_rules"] for identifier in rule["mutations"]}
        self.assertEqual(ids, mapped, "acceptance: mutation acceptance-rule mappings are incomplete")
        for row in catalog["mutations"]:
            for edit in row["edits"]:
                mutate.edit_path(edit, row.get("evidence_class", "product"))


if __name__ == "__main__":
    unittest.main()

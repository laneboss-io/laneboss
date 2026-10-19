"""Linux-only unit checks for the red proof catalog's deciding boundaries."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("grants_red", HERE / "prove-red.py")
RED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RED)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads((HERE / "mutations.json").read_bytes())
        self.ready = next(row for row in self.catalog["mutations"] if row["status"] == "ready")

    def parse(self, value):
        with tempfile.TemporaryDirectory(prefix="lb-v2-grants-catalog-") as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / "mutations.json"
            path.write_text(json.dumps(value))
            return RED.catalog(path)

    def test_real_catalog_and_aliases(self):
        _, rows = self.parse(self.catalog)
        names = [name for row in rows for name in [row["id"], *row.get("aliases", [])]]
        self.assertEqual(len(names), len(set(names)))
        for name in ["f11-data-input", "f11-data-readback"]:
            row = next(row for row in rows if name in row.get("aliases", []))
            self.assertGreater(len(row["required_failures"]), 1)

    def test_duplicate_assertion(self):
        duplicate = copy.deepcopy(self.ready)
        duplicate["id"] = "catalog-assertion-duplicate"
        duplicate["patches"][0]["after"] += " "
        self.catalog["mutations"].append(duplicate)
        with self.assertRaisesRegex(RED.ProofFailure, "^ready mutations share a deciding test and assertion$"):
            self.parse(self.catalog)

    def test_duplicate_patches(self):
        duplicate = copy.deepcopy(self.ready)
        duplicate["id"] = "catalog-source-duplicate"
        duplicate["test"] = ["TestDifferentDecidingAssertion"]
        duplicate.pop("required_failures", None)
        duplicate["failure"] = "different diagnostic"
        self.catalog["mutations"].append(duplicate)
        with self.assertRaisesRegex(RED.ProofFailure, "^ready mutations share the same source patches$"):
            self.parse(self.catalog)

    def test_duplicate_alias(self):
        self.ready["aliases"] = [self.catalog["mutations"][1]["id"]]
        with self.assertRaisesRegex(RED.ProofFailure, "^invalid or duplicate mutation name or alias$"):
            self.parse(self.catalog)


if __name__ == "__main__":
    unittest.main()

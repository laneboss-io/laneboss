"""Source-overlay reporter tests only; no product or launch evidence."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import before as before_runner
from controls import CASE, INPUTS, ControlError, inventory


class OverlayTests(unittest.TestCase):
    def source(self, root, production, tests):
        for item in INPUTS:
            path = root / item
            if item in {Path("go.mod"), Path("go.sum")}:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"source inventory fixture\n")
            else:
                path.mkdir(parents=True, exist_ok=True)
        package = root / "internal" / "v2" / "identity"
        package.mkdir()
        (package / "service.go").write_bytes(production)
        for name, data in tests.items():
            (package / name).write_bytes(data)
        (root / CASE / "input.json").write_bytes(b"{}\n")
        return inventory(root)

    def test_only_tests_change(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            base, candidate = root / "base", root / "candidate"
            old = self.source(base, b"base production\n", {"prior_test.go": b"prior test\n"})
            new = self.source(candidate, b"candidate production\n",
                              {"prior_test.go": b"updated test\n", "new_test.go": b"new test\n"})
            changed, paths = before_runner.overlay_tests(base, candidate, old, new)
            production = "internal/v2/identity/service.go"
            self.assertEqual(changed[production], old[production])
            self.assertEqual((base / production).read_bytes(), b"base production\n")
            self.assertEqual(len(paths), 2)
            for name in paths:
                self.assertEqual((base / name).read_bytes(), (candidate / name).read_bytes())
                self.assertEqual(changed[name], new[name])
            self.assertEqual(inventory(candidate), new)

    def test_no_removed_base_test(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            base, candidate = root / "base", root / "candidate"
            old = self.source(base, b"base production\n", {"prior_test.go": b"prior test\n"})
            new = self.source(candidate, b"candidate production\n", {"new_test.go": b"new test\n"})
            with self.assertRaisesRegex(ControlError, "base test removal"):
                before_runner.overlay_tests(base, candidate, old, new)
            self.assertEqual(inventory(base), old)
            self.assertEqual(inventory(candidate), new)

    def test_production_drift_refuses(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            base, candidate = root / "base", root / "candidate"
            old = self.source(base, b"base production\n", {"prior_test.go": b"prior test\n"})
            new = self.source(candidate, b"candidate production\n", {"prior_test.go": b"updated test\n"})
            (base / "internal/v2/identity/service.go").write_bytes(b"unexpected production\n")
            with self.assertRaisesRegex(ControlError, "changed production"):
                before_runner.overlay_tests(base, candidate, old, new)
            self.assertEqual(inventory(candidate), new)

    def test_test_drift_refuses(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            base, candidate = root / "base", root / "candidate"
            old = self.source(base, b"base production\n", {"prior_test.go": b"prior test\n"})
            new = self.source(candidate, b"candidate production\n", {"prior_test.go": b"updated test\n"})
            observed = dict(old)
            for name, details in new.items():
                if name.endswith("_test.go"):
                    observed[name] = details
            name = "internal/v2/identity/prior_test.go"
            observed[name] = dict(observed[name], sha256="different-test")
            with patch.object(before_runner, "inventory", return_value=observed):
                with self.assertRaisesRegex(ControlError, "tests are not identical"):
                    before_runner.overlay_tests(base, candidate, old, new)


if __name__ == "__main__":
    unittest.main()

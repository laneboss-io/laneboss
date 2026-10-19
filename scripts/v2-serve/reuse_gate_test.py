"""Release-place controls using the shipped fake-key canary, on Linux only."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "api_key_canary", Path(__file__).with_name("api_key_canary.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReuseControls(unittest.TestCase):
    def test_release_places_reject_both_plants(self):
        places = ("lane-home", "claude-config", "claudock-registry",
                  "credential-store", "helper-state", "evidence",
                  "service-journal", "helper-journal", "credential-journal")
        canary = module.Canary()
        with tempfile.TemporaryDirectory(prefix="lb-reuse-") as directory:
            root = Path(directory)
            path = root / "retained"
            for place in places:
                for index, needle in enumerate(canary.needles):
                    with self.subTest(place=place, kind=index):
                        path.write_bytes(b"prefix\n" + needle + b"\nsuffix")
                        hit = canary.scan(place, root)
                        self.assertTrue(hit["last8"])
                        self.assertEqual(hit["key"], index == 0)
                        self.assertFalse(hit["unreadable"])
                        path.write_bytes(b"ordinary retained bytes\n")
                        clean = canary.scan(place, root)
                        self.assertFalse(clean["key"] or clean["last8"] or clean["unreadable"])
            encoded = json.dumps(canary.rows).encode()
            self.assertFalse(any(canary.matches(encoded).values()))
            missing = canary.scan("helper-state", root / "absent")
            self.assertTrue(missing["unreadable"])


if __name__ == "__main__":
    unittest.main()

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("item4_boot", Path(__file__).resolve().parents[2] / "scripts/v2-admin/boot.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class InferenceBootTests(unittest.TestCase):
    def test_ceiling_is_forwarded_without_879b(self):
        self.assertEqual(boot.inference_enrollment({}), {})
        for ceiling in (0, 37, 9101):
            source = {"policy_max_cost_micros": ceiling}
            self.assertEqual(boot.inference_enrollment(source), source)
        for ceiling in (-1, True, 1 << 53):
            with self.assertRaises(boot.Stopped):
                boot.inference_enrollment({"policy_max_cost_micros": ceiling})


if __name__ == "__main__":
    unittest.main()

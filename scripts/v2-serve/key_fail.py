"""Force the actual key-shape assertion to fail without disclosing its input."""

import importlib.util
from pathlib import Path
import sys
import unittest


def main():
    material = sys.stdin.buffer.read(4097)
    if not 16 < len(material) <= 4096 or len(sys.argv) != 2:
        raise ValueError("private assertion control needs one bounded input")
    spec = importlib.util.spec_from_file_location(
        "key_failure_controls", Path(__file__).with_name("api_key_canary_test.py"))
    controls = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controls)
    controls.canary_module.Canary.fake_material = staticmethod(lambda: b"invalid-" + material)

    class Tee:
        def __init__(self, result):
            self.result = result

        def write(self, value):
            sys.stderr.write(value)
            return self.result.write(value)

        def flush(self):
            sys.stderr.flush()
            self.result.flush()

    with Path(sys.argv[1]).open("x", encoding="utf-8") as result:
        suite = unittest.TestSuite([controls.CanaryControls("test_fake_vendor_key_shape")])
        observed = unittest.TextTestRunner(stream=Tee(result)).run(suite)
    # Failure is the required trigger. The parent independently checks its
    # identity, count and all three captured output surfaces before passing.
    return 1 if not observed.wasSuccessful() else 0


if __name__ == "__main__":
    sys.exit(main())

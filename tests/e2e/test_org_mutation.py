"""A boundary mutation must fail the actual canary assertion, rather than an unrelated setup or import check."""

from pathlib import Path
import subprocess
import sys
import unittest


class MutationTest(unittest.TestCase):
    def test_store_id_mutant(self):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("orgmutant.py"))],
                                capture_output=True, text=True, timeout=120)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AssertionError: 'FOREIGN_CANARY' unexpectedly found", result.stdout + result.stderr)

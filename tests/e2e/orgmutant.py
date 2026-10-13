"""Run the resident-boundary assertion with just its store-id comparison removed in an isolated checkout."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-case", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.run_case:
        import unittest
        sys.path.insert(0, str(ROOT))
        result = unittest.main(module=None, argv=[sys.argv[0], arguments.run_case], exit=False)
        return 0 if result.result.wasSuccessful() else 1
    with tempfile.TemporaryDirectory(prefix="lb172-org-b2-mutant-") as temporary:
        checkout = Path(temporary) / "checkout"
        shutil.copytree(ROOT, checkout, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.pyc", ".venv", "build", "dist", "*.egg-info"))
        go = "decisions" in os.environ.get("LANEBOSS_TEST_GO_GROUPS", "").split(",")
        path = checkout / ("internal/decisionsrv/history.go" if go else "src/laneboss/decisions/history.py")
        original = path.read_text(encoding="utf-8")
        anchor = ('useServer = obj(status) != nil && obj(status)["store_id"] == digest(o.db)' if go else
                  'use_server = status.get("store_id") == sha256(str(org.db))')
        if original.count(anchor) != 1:
            raise RuntimeError("resident comparison mutation has no unique anchor")
        replacement = 'useServer = obj(status) != nil' if go else "use_server = True"
        path.write_text(original.replace(anchor, replacement), encoding="utf-8")
        module = "tests.e2e.test_org_history"
        case = module + ".HistoryTest.test_foreign_resident"
        # Isolation ensures no Python path from the supervising test process selects the original checkout.
        return subprocess.run([sys.executable, "-I", "-B", str(checkout / "tests/e2e/orgmutant.py"),
                               "--run-case", case], cwd=checkout).returncode


if __name__ == "__main__":
    raise SystemExit(main())

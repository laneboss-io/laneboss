"""Execute product tests in a child. Only the parent can accept the result."""

import argparse
from pathlib import Path
import sys
import unittest

import box_support
from box_support import Context
from suite import StrictResult, leaves, load_suite
from support import ROOT, require_linux, save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("modules", nargs="*")
    args = parser.parse_args()
    require_linux()
    output = args.directory / "evidence"
    box_support.CONTEXT = Context(args.directory, args.kit)
    suite = load_suite(ROOT / "e2e" / "v2" / "product", args.modules)
    selected = [test.id() for test in leaves(suite)]
    count = suite.countTestCases()
    save(output / "selected-tests.json", selected)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, failfast=True,
                                    resultclass=StrictResult).run(suite)
    successful = (result.wasSuccessful() and result.testsRun == count and
                  result.completed_ids == selected and
                  all(result.cli_calls.get(name, 0) > 0 for name in selected))
    save(output / "child-result.json", {
        "selected_ids": selected, "started_ids": result.started_ids,
        "completed_ids": result.completed_ids, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "cli_calls": result.cli_calls, "successful": successful})
    return 0 if successful else 1


if __name__ == "__main__":
    sys.exit(main())

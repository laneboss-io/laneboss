"""Run harness-only tests on the authorized Ubuntu box, retaining exact IDs."""

import argparse
from pathlib import Path
import sys
import unittest

from support import ROOT, require, require_linux, save


class Result(unittest.TextTestResult):
    def addSkip(self, test, reason):
        error = AssertionError("harness-unit skip: " + reason)
        self.addFailure(test, (AssertionError, error, None))

    def addExpectedFailure(self, test, error):
        self.addFailure(test, error)

    def addUnexpectedSuccess(self, test):
        error = AssertionError("unexpected success")
        self.addFailure(test, (AssertionError, error, None))


def leaves(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from leaves(test)
        else:
            yield test


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pattern", default="test_*.py")
    args = parser.parse_args()
    require_linux()
    require(args.out.is_absolute() and not args.out.resolve().is_relative_to(ROOT),
            "keep unit evidence outside the checkout")
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    loader = unittest.TestLoader()
    suites = []
    root = ROOT / "e2e" / "v2" / "tests"
    require(args.pattern == "test_*.py" or
            args.pattern.startswith("test_") and args.pattern.endswith(".py") and
            Path(args.pattern).name == args.pattern and "*" not in args.pattern and "?" not in args.pattern,
            "invalid unit module selection")
    for source in sorted(root.glob(args.pattern)):
        suite = loader.discover(str(root), pattern=source.name)
        require(not loader.errors and suite.countTestCases() > 0, "empty/unloadable unit module")
        suites.append(suite)
    suite = unittest.TestSuite(suites)
    ids = [test.id() for test in leaves(suite)]
    require(ids and len(set(ids)) == len(ids), "invalid unit selection")
    count = suite.countTestCases()
    with (args.out / "unittest.log").open("w") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, failfast=True,
                                        resultclass=Result).run(suite)
    passed = result.wasSuccessful() and result.testsRun == count
    save(args.out / "summary.json", {"scope": "harness units, not product acceptance",
                                    "selected_test_ids": ids, "tests_run": result.testsRun,
                                    "failures": len(result.failures), "errors": len(result.errors),
                                    "exit_code": 0 if passed else 1})
    print("harness-unit tests={} exit={}".format(result.testsRun, 0 if passed else 1))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

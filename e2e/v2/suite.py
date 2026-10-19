"""Uniform product-test discovery and parent validation of child completion."""

import importlib.util
from pathlib import Path
import re
import sys
import unittest

from box_support import BlackBoxCase
from support import exact_keys, integer, load, require


def module_paths(root, names):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "missing product-test directory")
    for path in root.rglob("*"):
        require(not path.is_symlink(), "linked product-test input")
        require(not (path.name.startswith("test_") and path.suffix == ".py"
                     and path.parent != root), "nested product-test module refused")
    available = sorted(root.glob("test_*.py"))
    require(bool(available), "no product-test modules")
    for path in available:
        require(re.fullmatch(r"test_[A-Za-z0-9_]+", path.stem) is not None,
                "invalid product-test module name")
    if names:
        selected = []
        for value in names:
            name = value.removesuffix(".py")
            require(re.fullmatch(r"test_[A-Za-z0-9_]+", name) is not None,
                    "invalid named product-test module")
            path = root / (name + ".py")
            require(path in available, "named module is absent")
            selected.append(path)
    else:
        selected = available
    gate = root / "test_smoke.py"
    require(gate in available, "mandatory product smoke is absent")
    return [gate, *[path for path in selected if path != gate]]


def leaves(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from leaves(test)
        else:
            yield test


def load_suite(root, names):
    selected = []
    seen = set()
    for path in module_paths(root, names):
        name = "_lb_case_" + path.stem
        spec = importlib.util.spec_from_file_location(name, path)
        require(spec is not None and spec.loader is not None, "unloadable test module")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(module)
        require(not loader.errors and suite.countTestCases() > 0,
                "product-test module collected zero tests or failed loading")
        for test in leaves(suite):
            require(isinstance(test, BlackBoxCase), "test does not use the black-box base")
            require(test.id() not in seen, "duplicate selected test ID")
            selected.append(test)
            seen.add(test.id())
    require(bool(selected), "empty product test selection")
    return unittest.TestSuite(selected)


class StrictResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.completed_ids = []
        self.cli_calls = {}

    def startTest(self, test):
        import box_support
        self.started_ids.append(test.id())
        self._before = box_support.CONTEXT.recorder.cli_count
        super().startTest(test)

    def stopTest(self, test):
        import box_support
        self.cli_calls[test.id()] = box_support.CONTEXT.recorder.cli_count - self._before
        self.completed_ids.append(test.id())
        super().stopTest(test)

    def addSkip(self, test, reason):
        error = AssertionError("product-test skip is a failure: " + reason)
        self.addFailure(test, (AssertionError, error, None))

    def addExpectedFailure(self, test, error):
        self.addFailure(test, error)

    def addUnexpectedSuccess(self, test):
        error = AssertionError("unexpected success is not acceptance")
        self.addFailure(test, (AssertionError, error, None))


def validate_child(selected_path, result_path, child_exit):
    selected = load(selected_path)
    result = load(result_path)
    exact_keys(result, ("selected_ids", "started_ids", "completed_ids", "tests_run",
                        "failures", "errors", "cli_calls", "successful"))
    require(isinstance(selected, list) and selected and
            all(isinstance(name, str) and name for name in selected) and
            len(set(selected)) == len(selected),
            "child selected-ID record is invalid")
    require(type(result["successful"]) is bool and
            all(integer(result[key]) for key in ("tests_run", "failures", "errors")),
            "child count/success types are invalid")
    require(isinstance(result["started_ids"], list) and
            isinstance(result["completed_ids"], list) and
            isinstance(result["cli_calls"], dict), "child completion inventory is invalid")
    require(result["selected_ids"] == selected, "child changed selected IDs")
    require(result["started_ids"] == result["completed_ids"] and
            result["started_ids"] == selected[:len(result["started_ids"])],
            "child exited before test completion")
    require(result["tests_run"] == len(result["completed_ids"]),
            "child count contradicts completed IDs")
    expected_exit = 0 if result["successful"] else 1
    require(child_exit == expected_exit, "child exit contradicts its result record")
    if result["successful"]:
        require(result["tests_run"] == len(selected) == len(result["completed_ids"]),
                "successful child omitted selected tests")
        require(all(result["cli_calls"].get(name, 0) > 0 for name in selected),
                "successful test made no product CLI call")
        require(result["failures"] == 0 and result["errors"] == 0,
                "child success contradicts failures")
    return result

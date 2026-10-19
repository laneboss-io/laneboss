"""Rows for the Codex hook-trust bypass and its plugin gate, through the installed launcher.

Run with the private suite on the designated disposable test machine. Only the Codex
provider is doubled: the stand-in records its argument vector and runs nothing, so every
row decides on the launcher's own behaviour. The rule is that a bypass run never reaches
its vendor unless `--disable plugins` is a real flag in the argument vector. Prepare adds
the flag when the lane is planned; Revet checks it again at the moment of execution, in
the supervised start route (internal/lane/supervise.go) and in the turn route
(internal/laneturns/worker.go). Only a defect in Prepare shows Revet's gate from outside,
so the mutants first drop the flag from Prepare and then also remove Revet's gate.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.e2e import support, test_codex_hooks as hooks

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orgsupport import ROLES


setUpModule = hooks.setUpModule
tearDownModule = hooks.tearDownModule

TRUST = "--dangerously-bypass-hook-trust"
PREPARE_DROPS_FLAG = (
    "internal/hookconfig/codex.go",
    '[]string{CodexTrustBypass, "--disable", "plugins"}',
    "[]string{CodexTrustBypass}",
)
REVET_GATE_OFF = (
    "internal/hookconfig/launch.go",
    "if !pluginsOff {",
    "if false && !pluginsOff {",
)
ROWS = {"start": "test_start_route_plugin_flag", "turns": "test_turn_route_plugin_flag"}


class PluginGateTest(hooks.CodexHookLoadTest):
    def configure(self, models_map=None, stdin=False):
        super().configure(models_map, stdin=stdin)
        # The inherited fixture initializes this org, including the built-in
        # role library and the Codex hook home. Bind lane roles to that same org.
        org = self.directory / "model-org"
        text = self.config_file.read_text(encoding="utf-8")
        text = "org_dir = " + json.dumps(str(org)) + "\n" + text
        text += ('\n[supervisors.plugin-gate]\nlevel = 5\nrunner = "deepseek"\n'
                 'projects = ["web"]\n')
        self.config_file.write_text(text, encoding="utf-8")

    def setUp(self):
        super().setUp()
        # Grant the inherited, vetted vendor home in this custom org. Later
        # configure(stdin=True) calls retain this source for the turn route.
        (self.directory / "model-org/.laneboss/settings.toml").write_text(
            'env_allow = ["CODEX_HOME"]\n', encoding="utf-8")
        self.run_laneboss("config", "validate", "alpha")
        # Record the persistent test process before its headless commands start
        # lanes; a role label alone is not an authenticated caller.
        self.run_laneboss("start", "--config", "alpha", "--role", "plugin-gate")
        self.environment["LANEBOSS_ROLE"] = "plugin-gate"

    def begin(self, lane, *extra):
        return super().begin(lane, "--role", ROLES[3], *extra)

    def run_lane(self, route):
        lane = "web-plugin-gate-" + route
        if route == "turns":
            self.configure(stdin=True)
            self.begin(lane, "--turns")
        else:
            self.begin(lane)
        self.finished(lane, 1)
        row = self.status(lane)
        path = self.directory / "codex-calls.jsonl"
        calls = [json.loads(line)["argv"] for line in path.read_text().splitlines()] if path.exists() else []
        # Recorded before any assertion so the mutant driver can read what really happened.
        self.observed = {"reason": row["reason"], "exit_code": row["exit_code"], "calls": calls}
        return row, calls

    def check_route(self, route):
        row, calls = self.run_lane(route)
        self.assertEqual((row["reason"], row["exit_code"], len(calls)), ("exit", 0, 1),
                         "a prepared bypass lane must run its vendor once")
        argv = calls[0]
        self.assertEqual(argv.count(TRUST), 1, "the trust flag must be supplied once")
        index = argv.index(TRUST)
        self.assertEqual(argv[index + 1:index + 3], ["--disable", "plugins"],
                         "the trust flag must be followed by the real plugin-disabling flag")
        stop = argv.index("--") if "--" in argv else len(argv)
        self.assertLess(index + 2, stop, "the plugin-disabling flag must come before any operand marker")

    def test_start_route_plugin_flag(self):
        """Fails when the supervised start route runs a bypass without a real plugin-disabling flag."""
        self.check_route("start")

    def test_turn_route_plugin_flag(self):
        """Fails when the turn route runs a bypass without a real plugin-disabling flag."""
        self.check_route("turns")

    def build_mutant(self, temporary, name, edits):
        tree = support.copy_go_tree(Path(temporary) / name)
        for path, before, after in edits:
            source = tree / path
            text = source.read_text()
            self.assertEqual(text.count(before), 1, path)
            source.write_text(text.replace(before, after, 1))
        prefix = Path(temporary) / (name + "-installed")
        installed = subprocess.run(["sh", str(tree / "scripts/install.sh"), "--prefix", str(prefix)], cwd=tree,
                                   env=support.install_environment(self.user_home), capture_output=True,
                                   text=True, timeout=600)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        return prefix / "bin/laneboss"

    def test_restoring_mutants(self):
        """Fails unless Revet's gate alone keeps a flagless bypass from its vendor, in both routes."""
        for route, row in ROWS.items():
            green = unittest.TestResult()
            type(self)(row).run(green)
            self.assertEqual(green.errors, [])
            self.assertEqual(green.failures, [], "the rows must pass on the unmodified launcher")
        with tempfile.TemporaryDirectory(prefix="lb-hookconfig-fix-") as temporary:
            held = self.build_mutant(temporary, "gate-held", (PREPARE_DROPS_FLAG,))
            open_gate = self.build_mutant(temporary, "gate-open", (PREPARE_DROPS_FLAG, REVET_GATE_OFF))
            for route, row in ROWS.items():
                with self.subTest(mutant="gate-held", route=route):
                    case = type(self)(row)
                    case.model_binary = held
                    red = unittest.TestResult()
                    case.run(red)
                    self.assertEqual(red.errors, [])
                    self.assertEqual(len(red.failures), 1)
                    self.assertIn("a prepared bypass lane must run its vendor once", red.failures[0][1])
                    # Decision only: the re-check refused before exec and the vendor never started.
                    self.assertEqual((case.observed["reason"], case.observed["exit_code"], case.observed["calls"]),
                                     ("hook-config", 125, []))
                with self.subTest(mutant="gate-open", route=route):
                    case = type(self)(row)
                    case.model_binary = open_gate
                    red = unittest.TestResult()
                    case.run(red)
                    self.assertEqual(red.errors, [])
                    self.assertEqual(len(red.failures), 1)
                    self.assertIn("followed by the real plugin-disabling flag", red.failures[0][1])
                    # With the gate removed the vendor really ran, and without the flag.
                    self.assertEqual(len(case.observed["calls"]), 1)
                    argv = case.observed["calls"][0]
                    self.assertIn(TRUST, argv)
                    self.assertNotIn("--disable", argv)
                    print("RESTORING MUTANT", route, "ran its vendor without the plugin-disabling flag")


    def test_unit_mutants(self):
        """Fails unless TestPluginFlag catches both a removed plugin gate and a scan that ignores the operand marker."""
        cases = (
            ("gate-off", "internal/hookconfig/launch.go", "if !pluginsOff {", "if false && !pluginsOff {"),
            ("scan-past-marker", "internal/hookconfig/launch.go",
             'i < len(argv) && argv[i] != "--"', "i < len(argv)"),
        )
        args = [support.go_executable(), "test", "-count=1", "-run", "^TestPluginFlag$", "./internal/hookconfig"]
        green = subprocess.run(args, cwd=support.ROOT, env=support.go_environment(), capture_output=True,
                               text=True, timeout=300)
        self.assertEqual(green.returncode, 0, green.stderr + green.stdout)
        with tempfile.TemporaryDirectory(prefix="lb-hookconfig-fix-unit-") as temporary:
            for name, path, before, after in cases:
                with self.subTest(name=name):
                    tree = support.copy_go_tree(Path(temporary) / name)
                    source = tree / path
                    text = source.read_text()
                    self.assertEqual(text.count(before), 1, path)
                    source.write_text(text.replace(before, after, 1))
                    red = subprocess.run(args, cwd=tree, env=support.go_environment(), capture_output=True,
                                         text=True, timeout=300)
                    self.assertEqual(red.returncode, 1, red.stderr + red.stdout)
                    self.assertIn("FAIL: TestPluginFlag", red.stdout)
                    self.assertIn("must be refused by the plugin gate", red.stdout)


def load_tests(loader, standard_tests, pattern):
    # This module contributes its own rows; the fixture's rows stay in test_codex_hooks.
    return unittest.TestSuite(
        PluginGateTest(name) for name in sorted(PluginGateTest.__dict__) if name.startswith("test_")
    )

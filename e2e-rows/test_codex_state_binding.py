"""Codex state-binding compatibility rows; run only on disposable Linux.

Use the pinned private harness with its installed launcher. The provider double
records real probes and invocations; the configuration, trust gates and lane
lifecycle are the product. No authenticated model service is used.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

from tests.e2e import support, test_codex_hooks as hooks


setUpModule = hooks.setUpModule
tearDownModule = hooks.tearDownModule


VENDOR_INPUT_OBSERVER = r'''import hashlib
import json
import os
from pathlib import Path
import sys

provider = Path(__file__).resolve()
config_path = Path(os.environ["CODEX_HOME"]) / "config.toml"
data = config_path.read_bytes()
record = {"pid": os.getpid(), "argv": sys.argv[1:], "cwd": str(Path.cwd()),
          "config_path": str(config_path), "config_toml": data.decode("utf-8"),
          "config_sha256": hashlib.sha256(data).hexdigest()}
with (provider.parent.parent / "codex-vendor-inputs.jsonl").open("a") as output:
    output.write(json.dumps(record) + "\n")
original = provider.with_name("codex-unobserved.py")
exec(compile(original.read_bytes(), str(original), "exec"),
     {"__name__": "__main__", "__file__": str(original)})
'''

STATE_BINDING_MATCH = "if actual != filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(home)))) {"
STATE_BINDING_GRANT = "if false && actual != filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(home)))) {"
NO_STATE_GRANT = "mismatched org must reach the vendor without any writable state root"


class CodexStateBindingRows(hooks.CodexHookLoadTest):
    def setUp(self):
        super().setUp()
        self.write_user_config(self.config_file, self.config_file.read_text())
        self.bound_org = self.read_bound_org()
        self.assertNotEqual(self.bound_org.resolve(), self.model_org.resolve(),
                            "the regression fixture must keep the two orgs distinct")
        sandbox = tomllib.loads((self.codex_home / "config.toml").read_text())["sandbox_workspace_write"]
        self.assertNotIn("writable_roots", sandbox, "the vetted unrelated home must request no state grant")

    def read_bound_org(self):
        shown = self.run_laneboss("config", "show", "alpha", code=None)
        self.assertEqual(shown.returncode, 0, "the product must read the fixture config: " + shown.stderr)
        configuration = json.loads(shown.stdout)["config"]
        org = configuration.get("org_dir")
        self.assertIsInstance(org, str, "the effective config must name the fixture org")
        return Path(org)

    def begin_any(self, lane):
        """The private begin() with its own arguments, keeping any exit status (begin takes no code)."""
        start = self.start
        self.start = lambda *arguments, **options: start(*arguments, **dict(options, code=None))
        try:
            return self.begin(lane)
        finally:
            del self.start

    def test_unrelated_home_without_state_grant(self):
        path = self.codex_home / "config.toml"
        before = path.read_bytes()
        lane = "web-unrelated-state"
        started = self.begin_any(lane)
        self.assertEqual(started.returncode, 0,
                         "a fully vetted unrelated hook home without extra roots must launch: " + started.stderr)
        self.finished(lane, 1)
        row = self.status(lane)
        self.assertEqual((row["reason"], row["exit_code"]), ("exit", 0),
                         "a fully vetted unrelated hook home without extra roots must launch")
        probes = [json.loads(line)["argv"] for line in
                  (self.directory / "codex-probes.jsonl").read_text().splitlines()]
        self.assertTrue(any("--version" in argv for argv in probes), "the real version probe must run")
        self.assertTrue(any("features" in argv and "list" in argv for argv in probes),
                        "the real feature probe must run")
        calls = (self.directory / "codex-calls.jsonl").read_text().splitlines()
        self.assertEqual(len(calls), 1, "the unrelated home must reach the provider exactly once")
        self.assertEqual(path.read_bytes(), before,
                         "automatic preparation must preserve the unrelated home's exact bytes without a grant")

    def test_supplied_grant_needs_matching_org(self):
        state = Path(self.paths("alpha")["state_dir"]).resolve()
        state.mkdir(parents=True, exist_ok=True)
        path = self.codex_home / "config.toml"
        text = path.read_text()
        table = "[sandbox_workspace_write]\n"
        self.assertEqual(text.count(table), 1, "the state grant must be placed in the real sandbox table")
        text = text.replace(table, table + "writable_roots = " + json.dumps([str(state)]) + "\n", 1)
        mode = path.stat().st_mode & 0o777
        path.chmod(0o600)
        path.write_text(text)
        path.chmod(mode)
        before = path.read_bytes()
        refused = self.begin_any("web-mismatched-state")
        self.assertEqual(refused.returncode, 2, "a supplied state grant must require its matching bound org")
        self.assertIn('"writable_roots"', refused.stderr)
        self.assertFalse((self.directory / "codex-probes.jsonl").exists(),
                         "a mismatched supplied state grant must refuse before any probe")
        self.assertFalse((self.directory / "codex-calls.jsonl").exists(),
                         "a mismatched supplied state grant must refuse before the provider")
        self.assertEqual(path.read_bytes(), before, "a refused grant must not be repaired or discarded")


class CodexStateBindingVendorRows(CodexStateBindingRows):
    """Observe vendor inputs, without adding a sandbox to the provider double."""

    def setUp(self):
        super().setUp()
        provider = self.provider_bin / "codex"
        provider.with_name("codex-unobserved.py").write_bytes(provider.read_bytes())
        provider.write_text("#!" + sys.executable + "\n" + VENDOR_INPUT_OBSERVER)
        provider.chmod(0o755)
        evidence = os.environ.get("LANEBOSS_ROW_EVIDENCE")
        if evidence:
            root = Path(evidence)
            self.assertTrue(root.is_absolute(), "the vendor-input evidence directory must be absolute")
            self.addCleanup(self.retain_vendor_inputs, root)

    def retain_vendor_inputs(self, root):
        destination = root / "lb-s0-codexstate" / self._testMethodName / self.directory.name
        destination.mkdir(parents=True)
        paths = {"vendor-inputs.jsonl": self.directory / "codex-vendor-inputs.jsonl",
                 "provider-calls.jsonl": self.directory / "codex-calls.jsonl",
                 "probe-calls.jsonl": self.directory / "codex-probes.jsonl",
                 "config.toml": self.codex_home / "config.toml",
                 "provider.py": self.provider_bin / "codex",
                 "provider-original.py": self.provider_bin / "codex-unobserved.py",
                 "configuration.toml": self.config_file,
                 "row.py": Path(__file__)}
        for name, path in paths.items():
            if path.is_file():
                shutil.copyfile(path, destination / name)

    def check_vendor_roots(self, matching):
        configuration = tomllib.loads(self.config_file.read_text())
        text = self.config_file.read_text()
        if matching:
            before = "org_dir = " + json.dumps(str(self.bound_org)) + "\n"
            self.assertEqual(text.count(before), 1, "the control must replace exactly the bound org")
            text = text.replace(before, "org_dir = " + json.dumps(str(self.model_org)) + "\n", 1)
        # The default fixture org permits inherited CODEX_HOME; model-org does
        # not. Declare the same vetted home in each runner's literal env prefix,
        # as the existing matching-org state rows do. Both bindings use this prefix.
        safe_path = os.pathsep.join([str(self.provider_bin), "/usr/bin", "/bin"])
        prefix = ["env", "CODEX_HOME=" + str(self.codex_home), "PATH=" + safe_path,
                  str(self.provider_bin / "codex"), "--sandbox", "workspace-write"]
        for key in ("command", "resume"):
            original = configuration["runners"]["codex"][key]
            before = key + " = " + json.dumps(original)
            self.assertEqual(text.count(before), 1, "the control must replace exactly one Codex template")
            selected = [*prefix, *original[1:]]
            text = text.replace(before, key + " = " + json.dumps(selected), 1)
        self.config_file.write_text(text)
        bound_org = self.read_bound_org().resolve()
        self.assertTrue((bound_org == self.model_org.resolve()) == matching,
                        "the control must use the requested org binding")
        state = str(Path(self.paths("alpha")["state_dir"]).resolve())
        path = self.codex_home / "config.toml"
        before = path.read_bytes()
        lane = "web-vendor-state-" + ("matching" if matching else "mismatched")
        result = self.begin_any(lane)
        self.assertEqual(result.returncode, 0, "vendor-input controls must start a real lane: " + result.stderr)
        started = json.loads(result.stdout)
        self.finished(lane, 1)
        row = self.status(lane)
        self.assertEqual((row["reason"], row["exit_code"]), ("exit", 0),
                         "vendor-input controls must complete the actual provider process")
        observations = [json.loads(line) for line in
                        (self.directory / "codex-vendor-inputs.jsonl").read_text().splitlines()]
        calls = [json.loads(line) for line in
                 (self.directory / "codex-calls.jsonl").read_text().splitlines()]
        launches = [entry for entry in observations if "exec" in entry["argv"]]
        self.assertEqual(len(launches), 1, "exactly one lane provider must record its effective inputs")
        self.assertEqual(len(calls), 1, "the original provider must execute exactly once")
        launch = launches[0]
        self.assertTrue(launch["pid"] == calls[0]["pid"] and launch["argv"] == calls[0]["argv"],
                        "input observations must come from the lane provider's own process")
        expected = ["-c", "features.hooks=true", "--sandbox", "workspace-write",
                    "--model", "gpt-6.1-sol", "exec", "--dangerously-bypass-hook-trust",
                    "--disable", "plugins", "Read the brief file " + started["brief"]["path"]]
        self.assertTrue(launch["argv"] == expected,
                        "the vendor must receive workspace-write without extra roots, profiles or permission overrides")
        flags = ["-c", "features.hooks=true", "--sandbox", "workspace-write", "--disable", "plugins"]
        probes = [entry["argv"] for entry in observations if "exec" not in entry["argv"]]
        self.assertTrue(probes == [flags + ["--version"], flags + ["features", "list"]],
                        "both probes must receive the same explicit workspace-write configuration flags")
        for entry in observations:
            self.assertTrue(entry["config_path"] == str(path) and entry["cwd"] == started["worktree"],
                            "the actual provider and probes must use the selected hook home and lane worktree")
            document = tomllib.loads(entry["config_toml"])
            sandbox = document["sandbox_workspace_write"]
            if matching:
                self.assertTrue(sandbox.get("writable_roots") == [state],
                                "matching org must reach the vendor with exactly its configuration state root")
            else:
                self.assertTrue("writable_roots" not in sandbox, NO_STATE_GRANT)
            self.assertTrue(sandbox["exclude_slash_tmp"] is True and sandbox["exclude_tmpdir_env_var"] is True,
                            "the vendor must receive both implicit temporary-write exclusions")
        if not matching:
            self.assertTrue(path.read_bytes() == before, "the no-grant launch must preserve its configuration bytes")

    def test_mismatched_org_vendor_roots(self):
        self.check_vendor_roots(matching=False)

    def test_matching_org_vendor_roots(self):
        self.check_vendor_roots(matching=True)


class CodexStateBindingMutationRows(unittest.TestCase):
    def test_repository_vetting_mutant(self):
        row = "test_repo_hooks_refused_early"
        green = unittest.TestResult()
        CodexStateBindingRows(row).run(green)
        self.assertEqual(green.testsRun, 1)
        self.assertEqual(green.errors, [])
        self.assertEqual(green.skipped, [])
        self.assertEqual(green.failures, [], "the unmodified repository-injection control must pass")
        with tempfile.TemporaryDirectory(prefix="lb-codex-state-binding-") as temporary:
            tree = support.copy_go_tree(Path(temporary) / "repo-skipped")
            source = tree / "internal/hookconfig/trust.go"
            text = source.read_text()
            before = "if err := vetRepository(actual, home); err != nil {"
            self.assertEqual(text.count(before), 1)
            source.write_text(text.replace(before, "if err := error(nil); err != nil {", 1))
            prefix = Path(temporary) / "installed"
            installed = subprocess.run(["sh", str(tree / "scripts/install.sh"), "--prefix", str(prefix)],
                                       cwd=tree, env=support.install_environment(Path(temporary) / "user"),
                                       capture_output=True, text=True, timeout=600)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            case = CodexStateBindingRows(row)
            case.model_binary = prefix / "bin/laneboss"
            red = unittest.TestResult()
            case.run(red)
            self.assertEqual(red.testsRun, 1)
            self.assertEqual(red.errors, [])
            self.assertEqual(red.skipped, [])
            self.assertEqual(len(red.failures), 1)
            self.assertIn("repository hook injection must be refused before any Codex invocation", red.failures[0][1])

    def test_mismatched_state_grant_mutant(self):
        rows = ("test_mismatched_org_vendor_roots", "test_matching_org_vendor_roots")
        for row in rows:
            green = unittest.TestResult()
            CodexStateBindingVendorRows(row).run(green)
            self.assertEqual(green.testsRun, 1)
            self.assertEqual(green.errors, [])
            self.assertEqual(green.skipped, [])
            self.assertEqual(green.failures, [], "the fixed vendor-input controls must pass")
        with tempfile.TemporaryDirectory(prefix="lb-codex-state-grant-") as temporary:
            tree = support.copy_go_tree(Path(temporary) / "mismatched-state-grant")
            source = tree / "internal/hookconfig/state_root.go"
            text = source.read_text()
            self.assertEqual(text.count(STATE_BINDING_MATCH), 1)
            source.write_text(text.replace(STATE_BINDING_MATCH, STATE_BINDING_GRANT, 1))
            prefix = Path(temporary) / "installed"
            installed = subprocess.run(["sh", str(tree / "scripts/install.sh"), "--prefix", str(prefix)],
                                       cwd=tree, env=support.install_environment(Path(temporary) / "user"),
                                       capture_output=True, text=True, timeout=600)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            for row in reversed(rows):
                case = CodexStateBindingVendorRows(row)
                case.model_binary = prefix / "bin/laneboss"
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.skipped, [])
                if row == "test_matching_org_vendor_roots":
                    self.assertEqual(result.failures, [], "the mutant must preserve the matching-org control")
                else:
                    self.assertEqual(len(result.failures), 1)
                    self.assertIn(NO_STATE_GRANT, result.failures[0][1])


def load_tests(loader, standard_tests, pattern):
    rows = ("test_unrelated_home_without_state_grant", "test_repo_hooks_refused_early",
            "test_tampered_home_refused_early", "test_supplied_grant_needs_matching_org")
    return unittest.TestSuite([*(CodexStateBindingRows(row) for row in rows),
                               CodexStateBindingVendorRows("test_mismatched_org_vendor_roots"),
                               CodexStateBindingVendorRows("test_matching_org_vendor_roots"),
                               CodexStateBindingMutationRows("test_repository_vetting_mutant"),
                               CodexStateBindingMutationRows("test_mismatched_state_grant_mutant")])


if __name__ == "__main__":
    unittest.main(verbosity=2)

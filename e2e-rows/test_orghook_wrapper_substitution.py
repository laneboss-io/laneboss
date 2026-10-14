"""CLI org-hook rows for words discarded by wrapper normalisation.

Run with the private suite on the designated disposable test machine. Commands
are submitted as hook events only; no canary command is executed. Each refusal
must come from the real installed CLI and keep its existing fails-closed text.
"""

import json
import shlex
import unittest
import uuid

from tests.e2e import support, test_org_hooks


setUpModule = test_org_hooks.setUpModule
tearDownModule = test_org_hooks.tearDownModule

FAILS_CLOSED = (
    "org hook fails closed: command substitutions and variables cannot be inspected"
)
FAULT_POINT = "orghook-substitution-after-strip"

# All twelve entries of internal/orghook/argv.go's wrappers map. The values
# enumerate every separate value option that normalise can discard. Context and
# output-changing options keep their original plain-value refusal as controls.
WRAPPER_OPTIONS = {
    "sudo": ("-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-T", "-U"),
    "doas": ("-u", "-C"),
    "env": ("-u", "-C", "-S", "--unset", "--chdir", "--split-string"),
    "nohup": (),
    "time": ("-f", "-o"),
    "command": (),
    "builtin": (),
    "exec": ("-a",),
    "nice": ("-n", "--adjustment"),
    "timeout": ("-s", "-k", "--signal", "--kill-after"),
    "stdbuf": ("-i", "-o", "-e"),
    "noglob": (),
}


class WrapperSubstitutionTest(test_org_hooks.OrgHookTest):
    def forms(self):
        # Vary each canary so implementations keyed on a test literal fail.
        marker = "wrapper_canary_" + uuid.uuid4().hex
        return {
            "backtick": "`printf " + marker + "`",
            "dollar": "$(printf " + marker + ")",
            "variable": "$" + marker.upper(),
        }

    def check_words(self, runner, words, decision, detail=None, environment=None):
        # Double quoting keeps each substitution in a single shell word while
        # retaining the expansion semantics of the original canary shapes.
        command = " ".join(
            '"' + word.replace("\\", "\\\\").replace('"', '\\"') + '"'
            if "$" in word or "`" in word else shlex.quote(word)
            for word in words
        )
        event = self.shell("alpha", runner, command)
        reason = self.check_decision(
            event, runner, decision, environment=environment,
            message="wrapper words must retain their inspection result",
        )
        if detail is not None:
            self.assertIn(detail, reason)
        return reason

    def test_probed_wrapper_values(self):
        """Fails when any of the three probed values disappears before inspection."""
        self.plain_values_and_argument_controls()
        for runner in ("claude", "codex"):
            for form, value in self.forms().items():
                rows = {
                    "nice-option-value": ["nice", "-n", value, "git", "status"],
                    "timeout-duration": ["timeout", value, "git", "status"],
                    "env-unset-value": ["env", "-u", value, "git", "status"],
                }
                for shape, words in rows.items():
                    with self.subTest(runner=runner, form=form, shape=shape):
                        self.check_words(runner, words, "deny", FAILS_CLOSED)

    def plain_values_and_argument_controls(self):
        """Controls fail on blanket denial or loss of normal-argument inspection."""
        plain = (
            ["git", "status"],
            ["nice", "-n", "5", "git", "status"],
            ["timeout", "5s", "git", "status"],
            ["env", "-u", "WRAPPER_CANARY_UNUSED", "git", "status"],
        )
        for runner in ("claude", "codex"):
            for words in plain:
                with self.subTest(runner=runner, control=words[0]):
                    self.check_words(runner, words, "allow")
            for form, value in self.forms().items():
                with self.subTest(runner=runner, argument=form):
                    self.check_words(runner, ["git", "status", value], "deny", FAILS_CLOSED)

    def test_every_stripped_wrapper_option(self):
        """Fails when any wrapper option word bypasses the original-word check."""
        for runner in ("claude", "codex"):
            for wrapper in WRAPPER_OPTIONS:
                for form, value in self.forms().items():
                    words = [wrapper, "--canary=" + value]
                    if wrapper == "timeout":
                        words.append("5s")
                    words.extend(("git", "status"))
                    with self.subTest(runner=runner, wrapper=wrapper, form=form):
                        self.check_words(runner, words, "deny", FAILS_CLOSED)
                with self.subTest(runner=runner, wrapper=wrapper, control="plain"):
                    if wrapper == "nohup":
                        self.check_words(
                            runner, [wrapper, "git", "status"], "deny",
                            "a command wrapper's output files cannot be inspected",
                        )
                    else:
                        words = [wrapper]
                        if wrapper == "timeout":
                            words.append("5s")
                        self.check_words(runner, words + ["git", "status"], "allow")

    def test_wrapper_option_values(self):
        """Fails when any value-taking wrapper option or joined value is omitted."""
        for runner in ("claude", "codex"):
            for wrapper, options in WRAPPER_OPTIONS.items():
                for option in options:
                    plain_detail = None
                    if wrapper in ("sudo", "doas", "env") and option in (
                        "-C", "-D", "-S", "--chdir", "--split-string",
                    ):
                        plain_detail = "a command wrapper changes execution context"
                    elif wrapper == "time" and option == "-o":
                        plain_detail = "a command wrapper's output files cannot be inspected"
                    suffix = (["5s"] if wrapper == "timeout" else []) + ["git", "status"]
                    with self.subTest(runner=runner, wrapper=wrapper, option=option, control="plain"):
                        self.check_words(
                            runner, [wrapper, option, "5", *suffix],
                            "deny" if plain_detail else "allow", plain_detail,
                        )
                    for form, value in self.forms().items():
                        for spelling, words in (
                            ("separate", [wrapper, option, value, *suffix]),
                            ("joined", [wrapper, option + "=" + value, *suffix]),
                        ):
                            with self.subTest(
                                runner=runner, wrapper=wrapper, option=option,
                                form=form, spelling=spelling,
                            ):
                                self.check_words(runner, words, "deny", FAILS_CLOSED)

    def test_nested_wrappers_and_literal_argv(self):
        """Fails if a later wrapper or the argv event adapter loses a word."""
        for runner in ("claude", "codex"):
            for form, value in self.forms().items():
                words = ["command", "nice", "-n", "5", "env", "-u", value, "git", "status"]
                with self.subTest(runner=runner, form=form, shape="nested"):
                    self.check_words(runner, words, "deny", FAILS_CLOSED)
                with self.subTest(runner=runner, form=form, shape="argv"):
                    event = self.event(tool="shell", data={"command": words})
                    reason = self.check_decision(event, runner, "deny")
                    self.assertIn(FAILS_CLOSED, reason)

    def test_original_word_refusal(self):
        """Fails if a wrapper or assignment diagnostic hides an original unsafe word."""
        for runner in ("claude", "codex"):
            self.check_words(runner, ["command", "nice", "-n", "5", "git", "status"], "allow")
            for form, value in self.forms().items():
                rows = {
                    "effective-command": ["nice", "-n", value, "/fixture/unknown-helper"],
                    "missing-value": ["nice", "-n", value, "sudo", "-u"],
                    "unresolved-option": ["command", "--canary=" + value, "git", "status"],
                    "missing-duration": ["nice", "-n", value, "timeout"],
                    "wrapper-limit": [*(["command"] * 9), "nice", "-n", value, "git", "status"],
                    "assignment": ["WRAPPER_CANARY=" + value, "git", "status"],
                    "context": ["sudo", "-D", value, "git", "status"],
                    "output": ["nohup", "git", "status", value],
                    "policy": ["nice", "-n", value, "git", "push"],
                }
                for shape, words in rows.items():
                    with self.subTest(runner=runner, form=form, shape=shape):
                        self.check_words(runner, words, "deny", FAILS_CLOSED)

    def test_restoring_mutant(self):
        """Fails unless the real after-stripping mutant is detected by every new denial row."""
        binary = support.faults_binary()
        for method in (
            "test_probed_wrapper_values",
            "test_every_stripped_wrapper_option",
            "test_wrapper_option_values",
            "test_nested_wrappers_and_literal_argv",
            "test_original_word_refusal",
        ):
            mutant = type(self)(method)
            mutant.hook_binary = binary
            original_setup = mutant.setUp

            def setup_with_fault(case=mutant, setup=original_setup):
                setup()
                case.environment["LANEBOSS_FAULTS"] = json.dumps({"point": FAULT_POINT})

            mutant.setUp = setup_with_fault
            red = unittest.TestResult()
            mutant.run(red)
            self.assertEqual(red.testsRun, 1)
            self.assertEqual(red.errors, [], "setup errors do not kill the restoring mutant")
            self.assertGreater(len(red.failures), 0, "restoring the old ordering must fail the rows")
            for _, failure in red.failures:
                self.assertTrue(
                    "'allow' != 'deny'" in failure or FAILS_CLOSED in failure,
                    "the mutant must fail on a real decision or its refusal text: " + failure,
                )
            print("RESTORING MUTANT", method, "detected by", len(red.failures), "assertions")


def load_tests(loader, standard_tests, pattern):
    # This module contributes its own rows; the fixture's existing rows remain
    # in test_org_hooks and are exercised there by the private suite.
    return unittest.TestSuite(
        WrapperSubstitutionTest(name)
        for name in sorted(WrapperSubstitutionTest.__dict__)
        if name.startswith("test_")
    )

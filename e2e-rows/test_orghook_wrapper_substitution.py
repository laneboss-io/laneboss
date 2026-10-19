"""CLI org-hook rows for words discarded by wrapper normalisation.

Run with the private suite on the designated disposable test machine. Commands
are submitted as hook events only; no canary command is executed. Ordinary
inspection gaps allow with a fresh incomplete receipt. Laneboss calls and
deterministic blacklist matches retain their refusals.
"""

import json
import shlex
import tomllib
import unittest
import uuid

from tests.e2e import test_org_hooks
from orgsupport import assert_hook_deprecation, set_hook_mode
from orgsupport import DETACH_REASON, check_incomplete_hook, write_rule_source
from hookfixtures import install_hook_refusals


setUpModule = test_org_hooks.setUpModule
tearDownModule = test_org_hooks.tearDownModule

FAILS_CLOSED = (
    "org hook fails closed: command substitutions and variables cannot be inspected"
)

# All twelve entries of internal/orghook/argv.go's wrappers map. The values
# enumerate every separate value option that normalise can discard. Context and
# output-changing options must retain incomplete receipts even with plain values.
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
    def write_rule_source(self, path, text):
        write_rule_source(self, path, text)

    def setUp(self):
        super().setUp()
        # The private hook-only fixture is intentionally too small for render.
        # Use the public initializer for complete protocol and instance sources.
        self.org = self.directory / "wrapper-org"
        self.org.mkdir()
        initialized = self.cli("init", self.org, "--levels", "3", "--name", "wrapper-org")
        self.assertTrue(json.loads(initialized.stdout)["ok"])
        self.org_home = self.org / ".laneboss"
        install_hook_refusals(self, self.org, "L3", "no-push")
        self.instances = {"alpha": self.org_home / "instances" / "L3-lane-example"}
        self.workspaces = {"alpha": self.org / "worktrees" / "alpha"}
        self.workspaces["alpha"].mkdir()
        identity = self.instances["alpha"] / "instance.toml"
        values = tomllib.loads(identity.read_text(encoding="utf-8"))
        values["writable_repos"] = ["worktrees/alpha"]
        self.write_rule_source(identity, "".join(key + " = " + json.dumps(value) + "\n"
                                                for key, value in values.items()))
        self.write_rule_source(self.org_home / "L3/hooks/rules.toml",
                               'schema_version = 1\n[[rules]]\nid = "no-push"\n'
                               'kind = "command-pattern"\npatterns = [["git", "push"]]\n')
        self.strict_mode()

    def strict_mode(self):
        source = self.org / ".laneboss" / "org.toml"
        set_hook_mode(self, source, "strict")
        rendered = self.cli("render", self.org)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        assert_hook_deprecation(self, rendered)

    def forms(self):
        # Vary each canary so implementations keyed on a test literal fail.
        marker = "wrapper_canary_" + uuid.uuid4().hex
        return {
            "backtick": "`printf " + marker + "`",
            "dollar": "$(printf " + marker + ")",
            "variable": "$" + marker.upper(),
        }

    def check_words(self, runner, words, decision, detail=None, environment=None, incomplete=False):
        # Double quoting keeps each substitution in a single shell word while
        # retaining the expansion semantics of the original canary shapes.
        command = " ".join(
            '"' + word.replace("\\", "\\\\").replace('"', '\\"') + '"'
            if "$" in word or "`" in word else shlex.quote(word)
            for word in words
        )
        event = self.shell("alpha", runner, command)
        event["tool_input"]["workdir"] = str(self.workspaces["alpha"])
        if incomplete:
            self.assertEqual(decision, "allow")
            reason = check_incomplete_hook(self, event, runner, environment=environment)
        else:
            reason = self.check_decision(
                event, runner, decision, environment=environment,
                message="wrapper words must retain their inspection result",
            )
        if detail is not None:
            self.assertIn(detail, reason)
        return reason

    def test_probed_wrapper_values(self):
        """Ordinary wrapper values allow while recording incomplete inspection."""
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
                        self.check_words(runner, words, "allow", incomplete=True)

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
                    self.check_words(runner, ["git", "status", value], "allow", incomplete=True)

    def test_every_stripped_wrapper_option(self):
        """An unresolved option must never claim complete inspection."""
        for runner in ("claude", "codex"):
            for wrapper in WRAPPER_OPTIONS:
                for form, value in self.forms().items():
                    words = [wrapper, "--canary=" + value]
                    if wrapper == "timeout":
                        words.append("5s")
                    words.extend(("git", "status"))
                    with self.subTest(runner=runner, wrapper=wrapper, form=form):
                        if wrapper == "nohup":
                            self.assertEqual(self.check_words(runner, words, "deny"), DETACH_REASON)
                        else:
                            self.check_words(runner, words, "allow", incomplete=True)
                with self.subTest(runner=runner, wrapper=wrapper, control="plain"):
                    if wrapper == "nohup":
                        self.assertEqual(self.check_words(runner, [wrapper, "git", "status"], "deny"), DETACH_REASON)
                    else:
                        words = [wrapper]
                        if wrapper == "timeout":
                            words.append("5s")
                        self.check_words(runner, words + ["git", "status"], "allow")

    def test_wrapper_option_values(self):
        """Every unresolved option value allows with an incomplete receipt."""
        self.strict_mode()
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
                            "allow", incomplete=plain_detail is not None,
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
                                self.check_words(runner, words, "allow", incomplete=True)

    def test_nested_wrappers_and_literal_argv(self):
        """Nested and argv forms retain an incomplete receipt for every gap."""
        for runner in ("claude", "codex"):
            for form, value in self.forms().items():
                words = ["command", "nice", "-n", "5", "env", "-u", value, "git", "status"]
                with self.subTest(runner=runner, form=form, shape="nested"):
                    self.check_words(runner, words, "allow", incomplete=True)
                with self.subTest(runner=runner, form=form, shape="argv"):
                    event = self.event(tool="shell", data={"command": words,
                                                          "workdir": str(self.workspaces["alpha"])})
                    check_incomplete_hook(self, event, runner)

    def test_original_word_inspection(self):
        """Ordinary gaps allow; an installed blacklist match still refuses."""
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
                        if shape == "policy":
                            reason = self.check_words(runner, words, "deny")
                            self.assertTrue(reason.startswith("[no-push] Refuses:"), reason)
                        elif shape == "output":
                            self.assertEqual(self.check_words(runner, words, "deny"), DETACH_REASON)
                        else:
                            self.check_words(runner, words, "allow", incomplete=True)

    def test_laneboss_substitution_refused(self):
        """The same wrapper values must still refuse when they obscure Laneboss."""
        for runner in ("claude", "codex"):
            for form, value in self.forms().items():
                for prefix in (["nice", "-n", value], ["timeout", value], ["env", "-u", value]):
                    with self.subTest(runner=runner, form=form, wrapper=prefix[0]):
                        self.check_words(runner, [*prefix, "laneboss", "--help"], "deny", FAILS_CLOSED)

    def test_shell_code_laneboss(self):
        """Nested Laneboss commands refuse; message text and heredoc data keep incomplete receipts."""
        marker = "ARG_" + uuid.uuid4().hex.upper()
        variable = "$" + marker
        refused = [
            "sh -c 'laneboss status " + variable + "'",
            'eval "laneboss lane start ' + variable + '"',
            'bash -c "cd d && laneboss report ' + variable + '"',
            "sh -c './bin/laneboss status " + variable + "'",
            'echo "$(command laneboss status ' + variable + ')"',
            "echo `env FIXTURE=1 /opt/tools/laneboss status " + variable + "`",
        ]
        allowed = [
            'git commit -m "fix laneboss ' + variable + '"',
            'echo "laneboss ' + variable + '" > notes.txt',
            "git commit -F - <<EOF\nlaneboss " + variable + "\nEOF\n",
            "sh -c 'echo laneboss " + variable + "'",
            'git commit -m "fix; laneboss ' + variable + '"',
            'git commit -m "first line\nlaneboss ' + variable + '\nlast line"',
            "sh -c 'git commit -F - <<EOF\nlaneboss " + variable + "\nEOF\n'",
        ]
        for runner in ("claude", "codex"):
            for decision, rows in (("deny", refused), ("allow", allowed)):
                for index, command in enumerate(rows):
                    with self.subTest(runner=runner, decision=decision, row=index):
                        event = self.shell("alpha", runner, command)
                        event["tool_input"]["workdir"] = str(self.workspaces["alpha"])
                        if decision == "allow":
                            check_incomplete_hook(self, event, runner)
                        else:
                            reason = self.check_decision(event, runner, "deny")
                            self.assertEqual(reason.splitlines()[0], FAILS_CLOSED)


def load_tests(loader, standard_tests, pattern):
    # This module contributes its own rows; the fixture's existing rows remain
    # in test_org_hooks and are exercised there by the private suite.
    return unittest.TestSuite(
        WrapperSubstitutionTest(name)
        for name in sorted(WrapperSubstitutionTest.__dict__)
        if name.startswith("test_")
    )

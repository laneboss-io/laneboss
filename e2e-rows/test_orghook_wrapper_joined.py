"""CLI org-hook rows for wrapper options that are not exactly a table entry.

Run with the private suite on the designated disposable test machine. Commands
are submitted as hook events only; no canary command is executed. The wrappers
map in internal/orghook/argv.go lists option words that stand alone. A letter
joined to its value, several short options in one word and a long option joined
with an equals sign are not entries of that map. The hook must refuse them with
its existing diagnostic and must never strip them as flags and then inspect a
command the wrapper would not run. Each inner command writes a relative file,
which is allowed from the allowed worktree, so a word stripped as a flag turns
the decision into allow. Each refusal must come from the real installed CLI and
its first line is compared whole.
"""

import json
import re
import shlex
import unittest
import uuid

from tests.e2e import support, test_org_hooks


setUpModule = test_org_hooks.setUpModule
tearDownModule = test_org_hooks.tearDownModule

FAILS_CLOSED = (
    "org hook fails closed: command substitutions and variables cannot be inspected"
)
UNRESOLVED = "org hook fails closed: a command wrapper option cannot be resolved"
CONTEXT = "org hook fails closed: a command wrapper changes execution context"
OUTPUT = "org hook fails closed: a command wrapper's output files cannot be inspected"
FAULT_POINT = "orghook-substitution-after-strip"
RUNNERS = ("claude", "codex")

# All twelve entries of internal/orghook/argv.go's wrappers map, verbatim. The
# inventory row compares this table with the Go source.
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

# The short value options of the table, each with the long spelling the vendor
# documents (None: the wrapper has no long spelling). A long name that is also a
# table entry (env, nice, timeout) is an exact word; the others are not entries.
SHORT_OPTIONS = {
    "sudo": {
        "-u": "--user", "-g": "--group", "-h": "--host", "-p": "--prompt",
        "-C": "--close-from", "-D": "--chdir", "-r": "--role", "-t": "--type",
        "-T": "--command-timeout", "-U": "--other-user",
    },
    "doas": {"-u": None, "-C": None},
    "env": {"-u": "--unset", "-C": "--chdir", "-S": "--split-string"},
    "time": {"-f": "--format", "-o": "--output"},
    "exec": {"-a": None},
    "nice": {"-n": "--adjustment"},
    "timeout": {"-s": "--signal", "-k": "--kill-after"},
    "stdbuf": {"-i": "--input", "-o": "--output", "-e": "--error"},
}

# One real short flag of the vendor's command that a command line may bundle
# with an option letter. nice and stdbuf have no second short flag.
BUNDLE_FLAG = {
    "sudo": "-n", "doas": "-n", "env": "-i", "time": "-p", "exec": "-c", "timeout": "-v",
}

# Exact option words the hook refuses by name, with the refusal each one gets.
EXACT_REFUSALS = {
    ("sudo", "-C"): CONTEXT, ("sudo", "-D"): CONTEXT, ("doas", "-C"): CONTEXT,
    ("env", "-C"): CONTEXT, ("env", "-S"): CONTEXT, ("env", "--chdir"): CONTEXT,
    ("env", "--split-string"): CONTEXT, ("time", "-o"): OUTPUT,
}


def option_letter(wrapper, option):
    for letter, name in SHORT_OPTIONS[wrapper].items():
        if option in (letter, name):
            return letter
    raise AssertionError("no short spelling for " + wrapper + " " + option)


class WrapperJoinedTest(test_org_hooks.OrgHookTest):
    def setUp(self):
        super().setUp()
        # Vary the names so an implementation keyed on a test literal fails.
        self.target = "wrapper_joined_" + uuid.uuid4().hex[:12] + ".txt"
        self.outside = str(self.org / "outside")

    def quote(self, word):
        # Double quoting keeps a substitution in a single shell word while
        # retaining the expansion semantics of the canary; other words are
        # single quoted, so a word with spaces stays one word.
        if "$" in word or "`" in word:
            return '"' + word.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return shlex.quote(word)

    def submit(self, runner, words):
        command = " ".join(self.quote(word) for word in words)
        event = self.shell("alpha", runner, command)
        # The relative inner file is inside the worktree only when the hook sees
        # the working directory this event names.
        event["tool_input"]["workdir"] = str(self.workspaces["alpha"])
        return event

    def check(self, runner, words, decision, detail=None):
        reason = self.check_decision(
            self.submit(runner, words), runner, decision,
            message="wrapper words must keep their inspection result",
        )
        if detail is not None:
            first = reason.splitlines()[0]
            self.assertEqual(first, detail, "refusal text was " + repr(first))
        return reason

    def inner(self, wrapper):
        # timeout takes its duration as the first word after its options.
        return (["5s"] if wrapper == "timeout" else []) + ["touch", self.target]

    def value(self, wrapper, option):
        """A plain value for the option; context options carry a path or a command line."""
        outside = self.outside
        values = {
            ("sudo", "-u"): "operator", ("sudo", "-g"): "operator", ("sudo", "-U"): "operator",
            ("sudo", "-h"): "localhost", ("sudo", "-p"): "prompt", ("sudo", "-D"): outside,
            ("sudo", "-r"): "canary_role", ("sudo", "-t"): "canary_type",
            ("doas", "-u"): "operator", ("doas", "-C"): outside + "/doas.conf",
            ("env", "-u"): "WRAPPER_JOINED_UNUSED", ("env", "-C"): outside,
            ("env", "-S"): "touch " + outside + "/" + self.target,
            ("time", "-f"): "%e", ("time", "-o"): outside + "/time.out",
            ("exec", "-a"): "canary_name", ("timeout", "-s"): "KILL",
            ("stdbuf", "-i"): "L", ("stdbuf", "-o"): "L", ("stdbuf", "-e"): "L",
        }
        return values.get((wrapper, option_letter(wrapper, option)), "5")

    def substitutions(self):
        marker = "wrapper_joined_" + uuid.uuid4().hex
        return {
            "backtick": "`printf " + marker + "`",
            "dollar": "$(printf " + marker + ")",
            "variable": "$" + marker.upper(),
        }

    def test_plain_controls_and_exact_options(self):
        """Fails on a blanket refusal, a stripped context option or a changed refusal text."""
        for runner in RUNNERS:
            for wrapper, options in WRAPPER_OPTIONS.items():
                with self.subTest(runner=runner, wrapper=wrapper, control="plain"):
                    if wrapper == "nohup":
                        self.check(runner, [wrapper, *self.inner(wrapper)], "deny", OUTPUT)
                    else:
                        self.check(runner, [wrapper, *self.inner(wrapper)], "allow")
                for option in options:
                    refusal = EXACT_REFUSALS.get((wrapper, option))
                    words = [wrapper, option, self.value(wrapper, option), *self.inner(wrapper)]
                    with self.subTest(runner=runner, wrapper=wrapper, option=option, shape="exact"):
                        self.check(runner, words, "deny" if refusal else "allow", refusal)

    def test_joined_short_options(self):
        """Fails when a letter joined to its value is stripped as a flag or refused for another reason."""
        for runner in RUNNERS:
            for wrapper, spellings in SHORT_OPTIONS.items():
                for option in spellings:
                    words = [wrapper, option + self.value(wrapper, option), *self.inner(wrapper)]
                    with self.subTest(runner=runner, wrapper=wrapper, option=option, shape="joined"):
                        self.check(runner, words, "deny", UNRESOLVED)
            with self.subTest(runner=runner, wrapper="nice", option="-5", shape="legacy"):
                self.check(runner, ["nice", "-5", *self.inner("nice")], "deny", UNRESOLVED)

    def test_bundled_short_options(self):
        """Fails when several short options in one word are stripped as a flag or refused for another reason."""
        for runner in RUNNERS:
            for wrapper, flag in BUNDLE_FLAG.items():
                for option in SHORT_OPTIONS[wrapper]:
                    bundle = flag + option[1:]
                    value = self.value(wrapper, option)
                    for spelling, words in (
                        ("separate", [wrapper, bundle, value, *self.inner(wrapper)]),
                        ("joined", [wrapper, bundle + value, *self.inner(wrapper)]),
                    ):
                        with self.subTest(
                            runner=runner, wrapper=wrapper, option=option, shape="bundled", value=spelling,
                        ):
                            self.check(runner, words, "deny", UNRESOLVED)

    def test_long_options_with_equals(self):
        """Fails when a long option joined with = or a long name outside the table is stripped as a flag."""
        for runner in RUNNERS:
            for wrapper, spellings in SHORT_OPTIONS.items():
                for option, name in spellings.items():
                    if name is None:
                        continue
                    value = self.value(wrapper, option)
                    with self.subTest(runner=runner, wrapper=wrapper, option=name, shape="long-equals"):
                        words = [wrapper, name + "=" + value, *self.inner(wrapper)]
                        self.check(runner, words, "deny", UNRESOLVED)
                    if name not in WRAPPER_OPTIONS[wrapper]:
                        with self.subTest(runner=runner, wrapper=wrapper, option=name, shape="long-separate"):
                            words = [wrapper, name, value, *self.inner(wrapper)]
                            self.check(runner, words, "deny", UNRESOLVED)

    def test_joined_substitution_first(self):
        """Fails when the unresolvable-option text answers before a substitution inside a joined word."""
        for runner in RUNNERS:
            for form, substitution in self.substitutions().items():
                for wrapper, spellings in SHORT_OPTIONS.items():
                    for option in spellings:
                        words = [wrapper, option + substitution, *self.inner(wrapper)]
                        with self.subTest(runner=runner, form=form, wrapper=wrapper, option=option):
                            self.check(runner, words, "deny", FAILS_CLOSED)

    def test_nested_chains_and_argv(self):
        """Fails when a wrapper later in a chain, or an argv array, lets a joined or context word through."""
        outside = self.outside
        split = "touch " + outside + "/" + self.target
        chains = {
            "nested-joined": (["command", "nice", "-n", "5", "env", "-C" + outside], UNRESOLVED),
            "nested-bundled": (["command", "nice", "-n", "5", "env", "-iC" + outside], UNRESOLVED),
            "nested-long": (["sudo", "-u", "operator", "env", "--chdir=" + outside], UNRESOLVED),
            "nested-split": (["timeout", "-s", "KILL", "5s", "env", "-S" + split], UNRESOLVED),
            "nested-exact": (["command", "nice", "-n", "5", "env", "-C", outside], CONTEXT),
            "nested-exact-split": (["sudo", "-u", "operator", "env", "-S", split], CONTEXT),
            "nested-control": (["command", "nice", "-n", "5", "env", "-u", "WRAPPER_JOINED_UNUSED"], None),
        }
        for runner in RUNNERS:
            for shape, (prefix, refusal) in chains.items():
                words = [*prefix, "touch", self.target]
                decision = "deny" if refusal else "allow"
                with self.subTest(runner=runner, shape=shape, adapter="string"):
                    self.check(runner, words, decision, refusal)
                with self.subTest(runner=runner, shape=shape, adapter="argv"):
                    event = self.event(
                        tool="shell",
                        data={"command": words, "workdir": str(self.workspaces["alpha"])},
                    )
                    reason = self.check_decision(event, runner, decision)
                    if refusal:
                        self.assertEqual(reason.splitlines()[0], refusal, "refusal text was " + repr(reason))

    def test_inventory_matches_source(self):
        """Fails when the wrappers map of the product and this file's option spellings disagree."""
        source = support.repository_path("internal/orghook/argv.go").read_text(encoding="utf-8")
        text = source.split("var wrappers = map[string][]string{", 1)[1].split("var copiers", 1)[0]
        table = {
            name: tuple(re.findall(r'"([^"]+)"', values))
            for name, values in re.findall(r'"([^"]+)":\s*\{([^}]*)\}', text)
        }
        self.assertEqual(table, WRAPPER_OPTIONS)
        for wrapper, options in WRAPPER_OPTIONS.items():
            spellings = SHORT_OPTIONS.get(wrapper, {})
            listed = set(spellings) | {name for name in spellings.values() if name in options}
            self.assertEqual(listed, set(options), wrapper)

    def test_restoring_mutant(self):
        """Fails unless the real after-stripping mutant turns the joined-substitution rows red."""
        binary = support.faults_binary()
        mutant = type(self)("test_joined_substitution_first")
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
                UNRESOLVED in failure and FAILS_CLOSED in failure,
                "the mutant must answer with the old wrapper text, not the substitution text: " + failure,
            )
        print("RESTORING MUTANT detected by", len(red.failures), "assertions")


def load_tests(loader, standard_tests, pattern):
    # This module contributes its own rows; the fixture's existing rows remain
    # in test_org_hooks and are exercised there by the private suite.
    return unittest.TestSuite(
        WrapperJoinedTest(name)
        for name in sorted(WrapperJoinedTest.__dict__)
        if name.startswith("test_")
    )

"""CLI org-hook rows for wrapper options that are not exactly a table entry.

Run with the private suite on the designated disposable test machine. Commands
are submitted as hook events only; no canary command is executed. The wrappers
map in internal/orghook/argv.go lists option words that stand alone. A letter
joined to its value, several short options in one word and a long option joined
with an equals sign are not entries of that map. Ordinary calls allow with an
incomplete-inspection receipt; they must never claim that a stripped option was
fully inspected. Obscured Laneboss calls retain their refusal. Each decision
and receipt comes from the real installed CLI.
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
UNRESOLVED = "org hook fails closed: a command wrapper option cannot be resolved"
CONTEXT = "org hook fails closed: a command wrapper changes execution context"
OUTPUT = "org hook fails closed: a command wrapper's output files cannot be inspected"
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

# Exact option words that leave an inspection gap for an ordinary command.
EXACT_GAPS = {
    ("sudo", "-C"), ("sudo", "-D"), ("doas", "-C"),
    ("env", "-C"), ("env", "-S"), ("env", "--chdir"),
    ("env", "--split-string"), ("time", "-o"),
}


def option_letter(wrapper, option):
    for letter, name in SHORT_OPTIONS[wrapper].items():
        if option in (letter, name):
            return letter
    raise AssertionError("no short spelling for " + wrapper + " " + option)


class WrapperJoinedTest(test_org_hooks.OrgHookTest):
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
        source = self.org / ".laneboss" / "org.toml"
        set_hook_mode(self, source, "strict")
        rendered = self.cli("render", self.org)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        assert_hook_deprecation(self, rendered)
        # Vary the names so an implementation keyed on a test literal fails.
        self.target = "wrapper_joined_" + uuid.uuid4().hex[:12] + ".txt"
        self.outside = str(self.org / "outside")

    def test_substitution_allowed_receipt(self):
        """The blacklist default permits ordinary substitutions with an incomplete receipt."""
        source = self.org / ".laneboss" / "org.toml"
        set_hook_mode(self, source, "blacklist")
        rendered = self.cli("render", self.org)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        for runner in RUNNERS:
            self.check(runner, ["nice", "-n", "$UNRESOLVED", "touch", self.target], "allow", incomplete=True)

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

    def check(self, runner, words, decision, detail=None, incomplete=False):
        event = self.submit(runner, words)
        if incomplete:
            self.assertEqual(decision, "allow")
            reason = check_incomplete_hook(self, event, runner)
        else:
            reason = self.check_decision(event, runner, decision,
                                        message="wrapper words must keep their inspection result")
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
        """Ordinary context/output gaps allow but never claim complete inspection."""
        for runner in RUNNERS:
            for wrapper, options in WRAPPER_OPTIONS.items():
                with self.subTest(runner=runner, wrapper=wrapper, control="plain"):
                    if wrapper == "nohup":
                        self.assertEqual(self.check(runner, [wrapper, *self.inner(wrapper)], "deny"), DETACH_REASON)
                    else:
                        self.check(runner, [wrapper, *self.inner(wrapper)], "allow")
                for option in options:
                    incomplete = (wrapper, option) in EXACT_GAPS
                    words = [wrapper, option, self.value(wrapper, option), *self.inner(wrapper)]
                    with self.subTest(runner=runner, wrapper=wrapper, option=option, shape="exact"):
                        self.check(runner, words, "allow", incomplete=incomplete)

    def test_joined_short_options(self):
        """Joined values must allow with an incomplete receipt."""
        for runner in RUNNERS:
            for wrapper, spellings in SHORT_OPTIONS.items():
                for option in spellings:
                    words = [wrapper, option + self.value(wrapper, option), *self.inner(wrapper)]
                    with self.subTest(runner=runner, wrapper=wrapper, option=option, shape="joined"):
                        self.check(runner, words, "allow", incomplete=True)
            with self.subTest(runner=runner, wrapper="nice", option="-5", shape="legacy"):
                self.check(runner, ["nice", "-5", *self.inner("nice")], "allow", incomplete=True)

    def test_bundled_short_options(self):
        """Bundled options must allow with an incomplete receipt."""
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
                            self.check(runner, words, "allow", incomplete=True)

    def test_long_options_with_equals(self):
        """Unresolved long options must allow with an incomplete receipt."""
        for runner in RUNNERS:
            for wrapper, spellings in SHORT_OPTIONS.items():
                for option, name in spellings.items():
                    if name is None:
                        continue
                    value = self.value(wrapper, option)
                    with self.subTest(runner=runner, wrapper=wrapper, option=name, shape="long-equals"):
                        words = [wrapper, name + "=" + value, *self.inner(wrapper)]
                        self.check(runner, words, "allow", incomplete=True)
                    if name not in WRAPPER_OPTIONS[wrapper]:
                        with self.subTest(runner=runner, wrapper=wrapper, option=name, shape="long-separate"):
                            words = [wrapper, name, value, *self.inner(wrapper)]
                            self.check(runner, words, "allow", incomplete=True)

    def test_joined_substitution_receipt(self):
        """Substitutions in ordinary joined options must retain the incomplete receipt."""
        for runner in RUNNERS:
            for form, substitution in self.substitutions().items():
                for wrapper, spellings in SHORT_OPTIONS.items():
                    for option in spellings:
                        words = [wrapper, option + substitution, *self.inner(wrapper)]
                        with self.subTest(runner=runner, form=form, wrapper=wrapper, option=option):
                            self.check(runner, words, "allow", incomplete=True)

    def test_nested_chains_and_argv(self):
        """Nested gaps allow with receipts through string and argv adapters."""
        outside = self.outside
        split = "touch " + outside + "/" + self.target
        chains = {
            "nested-joined": (["command", "nice", "-n", "5", "env", "-C" + outside], True),
            "nested-bundled": (["command", "nice", "-n", "5", "env", "-iC" + outside], True),
            "nested-long": (["sudo", "-u", "operator", "env", "--chdir=" + outside], True),
            "nested-split": (["timeout", "-s", "KILL", "5s", "env", "-S" + split], True),
            "nested-exact": (["command", "nice", "-n", "5", "env", "-C", outside], True),
            "nested-exact-split": (["sudo", "-u", "operator", "env", "-S", split], True),
            "nested-control": (["command", "nice", "-n", "5", "env", "-u", "WRAPPER_JOINED_UNUSED"], False),
        }
        for runner in RUNNERS:
            for shape, (prefix, incomplete) in chains.items():
                words = [*prefix, "touch", self.target]
                with self.subTest(runner=runner, shape=shape, adapter="string"):
                    self.check(runner, words, "allow", incomplete=incomplete)
                with self.subTest(runner=runner, shape=shape, adapter="argv"):
                    event = self.event(
                        tool="shell",
                        data={"command": words, "workdir": str(self.workspaces["alpha"])},
                    )
                    if incomplete:
                        check_incomplete_hook(self, event, runner)
                    else:
                        self.check_decision(event, runner, "allow")

    def test_laneboss_wrapper_gaps_refused(self):
        """The ordinary-call allowance must never admit an obscured Laneboss call."""
        for runner in RUNNERS:
            for prefix, detail in ((["nice", "-n5"], UNRESOLVED),
                                   (["env", "-C", self.outside], CONTEXT),
                                   (["nohup"], OUTPUT)):
                with self.subTest(runner=runner, wrapper=prefix[0]):
                    self.check(runner, [*prefix, "laneboss", "--help"], "deny", detail)
            for form, value in self.substitutions().items():
                with self.subTest(runner=runner, form=form):
                    self.check(runner, ["nice", "-n", value, "laneboss", "--help"],
                               "deny", FAILS_CLOSED)


def load_tests(loader, standard_tests, pattern):
    # This module contributes its own rows; the fixture's existing rows remain
    # in test_org_hooks and are exercised there by the private suite.
    return unittest.TestSuite(
        WrapperJoinedTest(name)
        for name in sorted(WrapperJoinedTest.__dict__)
        if name.startswith("test_")
    )

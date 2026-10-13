"""LB-96 P1: the two generic rules files ship inside the launcher and carry no company's name.

`internal/protocol/executor.md` (G1) reaches every lane brief; `internal/protocol/supervisor.md` (G2)
reaches a supervisor's briefing and no lane brief. Both travel inside the package, so a second company installs
them as they are written here, and this test is what keeps them the files the design describes.

This repository writes no private company, host, person or tool, here or anywhere, and never in pieces: the
word list that rules them out lives in the file `LANEBOSS_SCAN_DENYLIST` names, the same denylist
`scripts/scan.sh` reads, and this test reads that file with the same matcher when the variable is set. When it
is unset, the test falls back to the small list of non-private words below and says so in one line of its
output. The files' labels are checked elsewhere, by the deployed rule-id check, so no leg here compares one of
this module's constants against another.
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / "internal" / "protocol"

# One top-level item of a generic file: "- `id`: its text." The deployed rule-id check reads the same shape.
ITEM = re.compile(r"^- `(?P<id>[a-z][a-z0-9-]+)`: (?P<text>\S.*)$")

# The two files and the ids each must carry, written out as literals: the 16 generic executor rows and the 16
# generic supervisor rows, each in its file's order. This tuple is the id contract the repository publishes, so
# a missing, a renamed or a reordered id fails.
GENERIC = {
    "executor.md": (
        "brief-decides-role", "one-lane-one-worktree", "e2e-proof", "red-first", "green-with-output",
        "no-test-weakening", "no-faked-pass", "black-box-tests", "isolated-test-data", "secrets-from-env",
        "tests-off-workstation", "test-a-commit", "collect-test-machines", "stop-by-id", "stay-in-bounds",
        "report-assumptions"),
    "supervisor.md": (
        "supervisor-role", "dispatch-through-launcher", "brief-sections", "reject-out-of-bounds", "rerun-e2e",
        "revert-check", "retry-once", "resume-dropped-stream", "limit-not-failure", "three-resumes-fail",
        "heartbeat", "tick-steps", "cleanup", "keep-records", "own-lanes-only", "gate-repeat-offences"),
}

# The non-private words a generic rules file may never carry: the brand and home-directory markers a company
# that is not this launcher's own would read as its own. A company, a host, a person or a private tool is named
# by the denylist file named by LANEBOSS_SCAN_DENYLIST, never here; this list is what the check falls back to.
IN_REPO_WORDS = ("claude", "codex", "anthropic", "openai", "deepseek", "typesafe", "discord", "aws", "ec2",
                 "/Users/", "~/")
DENYLIST_VARIABLE = "LANEBOSS_SCAN_DENYLIST"

# The same words written a second time as the control's own literals. The control iterates these, not
# IN_REPO_WORDS, so that a word dropped from the check's list is still demanded by the control: a control that
# read the check's own list would go blind with it and pass by itself.
CONTROL_WORDS = ("claude", "codex", "anthropic", "openai", "deepseek", "typesafe", "discord", "aws", "ec2",
                 "/Users/", "~/")

# A small rules-file body for the negative control. It is written here rather than read from the tree, because
# the control checks the checker, not the files: it must pass on a red tree, where the two files are missing.
CONTROL_BODY = "# Generic rules\n\n- `an-id`: A rule whose sentence carries {word} inside it.\n"


def denylist_patterns(path):
    """The patterns of a denylist file, as scripts/scan.sh reads it: one regular expression per line, a blank
    line or a line whose first non-space character is '#' being a comment, each compiled case-insensitively."""
    patterns = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        patterns.append((number, re.compile(rule, re.IGNORECASE)))
    return patterns


def forbidden_in(text, denylist):
    """The forbidden words a text carries, case-insensitively: every in-repo word it holds, and, for each
    pattern of the denylist it is given, the pattern's own line number. An empty list means the text is clean."""
    found = [word for word in IN_REPO_WORDS if re.search(re.escape(word), text, re.IGNORECASE)]
    for number, pattern in denylist:
        if pattern.search(text) is not None:
            found.append("denylist-line-{}".format(number))
    return found


class GenericRulesTest(unittest.TestCase):
    """G1 and G2 read as the files they are: the deployed check reads the byte copy a configuration receives,
    and this reads the master that copy is made from."""

    def read(self, name):
        path = PROTOCOL / name
        self.assertTrue(path.is_file(), "the generic rules file is missing: {}".format(path))
        return path.read_text(encoding="utf-8")

    def ids_of(self, name, text):
        """The ids of one file's top-level items, in order. A top-level item whose line carries no id fails."""
        identifiers = []
        for line in text.split("\n"):
            if not line.startswith("- "):
                continue
            match = ITEM.match(line)
            self.assertIsNotNone(match, "{}: this top-level item carries no id: {!r}".format(name, line[:70]))
            identifiers.append(match.group("id"))
        self.assertTrue(identifiers, "{} carries no top-level rule item".format(name))
        return identifiers

    def test_every_top_level_item_carries_an_id(self):
        """Every rule is one top-level item, `- `id`: its text.`, so every one of them carries an id."""
        for name in GENERIC:
            with self.subTest(file=name):
                self.ids_of(name, self.read(name))

    def test_ids_are_unique_in_both_files(self):
        """One id, one rule: no id is in both files, and none is twice in one file."""
        seen = {}
        for name in GENERIC:
            for identifier in self.ids_of(name, self.read(name)):
                self.assertNotIn(identifier, seen, "the id {} is in {} and in {}".format(
                    identifier, seen.get(identifier), name))
                seen[identifier] = name

    def test_ids_are_the_carried_list(self):
        """The id contract this repository publishes: each file carries exactly the ids carried here, in the
        order carried here, so a missing id and a renamed id both fail."""
        for name, expected in GENERIC.items():
            with self.subTest(file=name):
                self.assertEqual(self.ids_of(name, self.read(name)), list(expected),
                                 "{} does not carry the carried ids, in order".format(name))

    def test_no_private_word_in_a_generic_file(self):
        """Rule (h): a file a second company installs carries none of the forbidden words this repository
        names, nor, when LANEBOSS_SCAN_DENYLIST names a denylist, any pattern of that file, in either case."""
        named = os.environ.get(DENYLIST_VARIABLE)
        if named:
            denylist = denylist_patterns(Path(named))
        else:
            denylist = []
            print("{} is unset: checking only the non-private words this repository names".format(
                DENYLIST_VARIABLE))
        for name in GENERIC:
            with self.subTest(file=name):
                found = forbidden_in(self.read(name), denylist)
                self.assertEqual(found, [], "{} carries {}".format(name, found))

    def test_the_forbidden_check_rejects_a_word(self):
        """The negative control for the forbidden-word check: a rules file that carries a word must be
        rejected, so the check cannot pass by ignoring one. The bodies are written here, not read from the
        tree, so this control passes on a red tree, where the two files are still missing."""
        with tempfile.TemporaryDirectory() as directory:
            for name in GENERIC:
                for word in CONTROL_WORDS:
                    for text in (word, word.upper()):
                        with self.subTest(file=name, word=text):
                            path = Path(directory) / name
                            path.write_text(CONTROL_BODY.format(word=text), encoding="utf-8")
                            self.assertTrue(forbidden_in(path.read_text(encoding="utf-8"), []),
                                            "{} carrying {} is not rejected".format(name, text))

    def test_the_publication_scan_passes(self):
        """scripts/scan.sh over this repository, with whatever denylist the caller's environment names (the
        commit-time command names one): a private-key header, a long secret-like token, an email address, a
        non-loopback IPv4 address and every denylist rule are what it fails on."""
        result = subprocess.run(["sh", str(ROOT / "scripts" / "scan.sh"), str(ROOT)],
                                capture_output=True, text=True, encoding="utf-8", timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SCAN PASS", result.stdout)

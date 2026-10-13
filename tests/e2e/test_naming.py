"""K. The project's name: the installed command, the environment prefix, the default directories and the tree.

Every expectation is written out here as a literal and does not read support.PROGRAM, so a helper constant that
drifts from the product cannot hide a wrong name. The old working name is assembled from pieces so that this file
does not contain it.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import unittest

from . import support

OLD = "su" + "p"
OLD_WORD = re.compile(r"(?<![A-Za-z0-9])" + OLD + r"(?![A-Za-z0-9])", re.IGNORECASE)
NOT_WALKED = {".git", "__pycache__", ".venv", "venv", "build", "dist"}

# The one role in which the old name remains in the tree: the `format` value that earlier code wrote into every export
# manifest. Those files are rebuild points that must stay importable, so the importer reads the value and the decision
# store's manual explains it. It is the identifier of a data format, not a name to rename. The exception is as narrow
# as it can be made: TWO EXACT LINES, one in each of two files, compared whole. No pattern decides what counts as the
# identifier; any other line that carries the old name fails, whatever it looks like. Whoever rewraps the manual's
# sentence updates the line here on purpose.
EXPORT_IDENTIFIER = OLD + "-decisions-jsonl"
ALLOWED_LINES = {
    "internal/decisions/portable.go": 'const earlierExportFormat = "{}"'.format(EXPORT_IDENTIFIER),
    "docs/decisions.md": "project had its name, say `{}`. They are rebuild points and stay".format(EXPORT_IDENTIFIER),
}
IDENTIFIER_FILES = tuple(ALLOWED_LINES)


def offences(relative_path, text):
    """The numbers of the lines of a file (named by its path from the repository root, with slashes) that carry the old
    name. The one line of ALLOWED_LINES for that file does not count when it is that line exactly; every other line
    that carries the old name or the export identifier does, in every file."""
    allowed = ALLOWED_LINES.get(relative_path)
    numbers = []
    for number, line in enumerate(text.splitlines(), 1):
        if line == allowed:
            continue
        if OLD_WORD.search(line) or EXPORT_IDENTIFIER in line:
            numbers.append(number)
    return numbers


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class NamingTest(support.LauncherTest):
    def install_into(self, name):
        prefix = self.directory / name
        result = support.run_install(support.ROOT, prefix, self.user_home)
        self.assertEqual(result.returncode, 0, "install: stdout={!r}; stderr={!r}".format(result.stdout, result.stderr))
        return prefix, json.loads(result.stdout)

    def clean_environment(self):
        """The test's own environment without any variable of the new or the old prefix."""
        prefixes = ("LANEBOSS_", OLD.upper() + "_")
        environment = {key: value for key, value in os.environ.items() if not key.startswith(prefixes)}
        environment["HOME"] = str(self.user_home)
        return environment

    def test_the_installed_command_is_laneboss(self):
        prefix, installed = self.install_into("prefix")
        version = installed["installed"]
        link = prefix / "bin" / "laneboss"
        self.assertEqual(Path(installed["link"]), link)
        self.assertTrue(link.is_symlink(), "bin/laneboss must be a link into the version directory")
        self.assertEqual(os.readlink(str(link)),
                         os.path.join("..", "share", "laneboss", "versions", version, "bin", "laneboss"))
        self.assertEqual(sorted(os.listdir(str(prefix / "bin"))), ["laneboss"])
        self.assertEqual(sorted(os.listdir(str(prefix / "share"))), ["laneboss"])
        directory = prefix / "share" / "laneboss" / "versions" / version
        self.assertEqual(sorted(os.listdir(directory)), ["MANIFEST", "bin", "plugins"])
        self.assertEqual(sorted(os.listdir(directory / "bin")), ["laneboss"])
        self.assertFalse((directory / "lib").exists())
        result = subprocess.run([str(link), "--version"], env=self.clean_environment(), capture_output=True,
                                text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["program"], "laneboss")
        usage = subprocess.run([str(link), "--help"], env=self.clean_environment(), capture_output=True,
                               text=True, encoding="utf-8", timeout=60)
        self.assertEqual(usage.returncode, 0, usage.stderr)
        self.assertTrue(usage.stdout.startswith("usage: laneboss "), usage.stdout[:80])

    def test_no_old_command_is_installed(self):
        prefix, _ = self.install_into("prefix")
        self.assertFalse(os.path.lexists(str(prefix / "bin" / OLD)))
        self.assertFalse(os.path.lexists(str(prefix / "share" / OLD)))
        for path in prefix.rglob("*"):
            for part in path.relative_to(prefix).parts:
                self.assertIsNone(OLD_WORD.search(part), "{} carries the old name".format(path))

    def test_decision_store_program_name(self):
        result = self.run_laneboss("decisions", "--help")
        self.assertTrue(result.stdout.startswith("usage: laneboss-decisions "), result.stdout[:80])

    def test_distribution_and_console_scripts(self):
        module = (support.ROOT / "go.mod").read_text(encoding="utf-8")
        self.assertRegex(module, r"(?m)^module laneboss\.io/laneboss$")
        source = support.ROOT / "cmd" / "laneboss" / "main.go"
        self.assertRegex(source.read_text(encoding="utf-8"), r"(?m)^func main\(")
        self.assertIn("internal/cli", source.read_text(encoding="utf-8"))
        self.assertFalse((support.ROOT / "src" / "laneboss").exists())
        self.assertFalse((support.ROOT / "pyproject.toml").exists())
        self.assertIn("//go:embed", (support.ROOT / "internal" / "protocol" / "embed.go").read_text(encoding="utf-8"))

    def test_default_directories(self):
        self.home = self.user_home / ".config" / "laneboss"
        self.home.mkdir(parents=True)
        self.write_config("alpha")
        paths = self.laneboss_json("config", "path", "alpha", environment=self.clean_environment())
        self.assertEqual(paths["config_dir"], str(self.user_home / ".config" / "laneboss" / "configs" / "alpha"))
        self.assertEqual(paths["state_dir"], str(self.user_home / ".local" / "state" / "laneboss" / "alpha"))

    def test_environment_prefix_is_laneboss(self):
        self.write_config("alpha")
        decoy = self.directory / "decoy-home"
        (decoy / "configs").mkdir(parents=True)
        environment = self.clean_environment()
        environment["LANEBOSS_HOME"] = str(self.home)
        environment["LANEBOSS_STATE_HOME"] = str(self.state_home)
        environment[OLD.upper() + "_HOME"] = str(decoy)
        self.assertEqual(self.laneboss_json("config", "list", environment=environment), ["alpha"])
        event = self.directory / "event.json"
        event.write_text(json.dumps(self.event()), encoding="utf-8")
        environment["LANEBOSS_CONFIG"] = "alpha"
        appended = self.laneboss_json("event", "append", "--file", event, environment=environment)
        self.assertEqual(appended["seq"], 1)
        self.assertTrue((self.state_home / "alpha" / ".laneboss-state").is_file())

    def test_no_old_name_in_the_tree(self):
        offenders = []
        for directory, names, files in os.walk(str(support.ROOT)):
            names[:] = sorted(name for name in names if name not in NOT_WALKED and not name.endswith(".egg-info"))
            here = Path(directory).relative_to(support.ROOT)
            for name in names + sorted(files):
                if OLD_WORD.search(name):
                    offenders.append(str(here / name))
            for name in sorted(files):
                if name.endswith((".pyc", ".pyo", ".sqlite")):
                    continue
                try:
                    text = (Path(directory) / name).read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                relative = (here / name).as_posix()
                offenders.extend("{}:{}".format(relative, number) for number in offences(relative, text))
        self.assertEqual(offenders, [], "the old working name is still in {} place(s)".format(len(offenders)))

    def test_identifier_is_used_where_allowed(self):
        for path in IDENTIFIER_FILES:
            with self.subTest(path=path):
                text = (support.ROOT / path).read_text(encoding="utf-8")
                self.assertEqual(text.splitlines().count(ALLOWED_LINES[path]), 1,
                                 "{} is named as an exception but does not hold its one allowed line".format(path))


class ExceptionRuleTest(unittest.TestCase):
    """The exception is narrow: the complete identifier, in the two named files, and nothing attached to it."""

    others = ("README.md", "CHANGELOG.md", "CONTRIBUTING.md", "docs/architecture.md", "docs/configuration.md",
              "scripts/scan.sh", "scripts/install.sh", "internal/brief/brief.go", "internal/decisions/load.go",
              "tests/decisions/support.py", "tests/e2e/test_naming.py", "docs/decisions.md.txt")

    def test_complete_identifier_allowed(self):
        for path, line in ALLOWED_LINES.items():
            with self.subTest(path=path):
                self.assertEqual(offences(path, "first\n" + line + "\n"), [])
            for other in tuple(set(IDENTIFIER_FILES) - {path}) + self.others:
                with self.subTest(path=path, other=other):
                    self.assertEqual(offences(other, "first\n" + line + "\n"), [2])

    def test_unquoted_or_extended_values_fail(self):
        for path in IDENTIFIER_FILES:
            for line in ("says {}.".format(EXPORT_IDENTIFIER), "({})".format(EXPORT_IDENTIFIER), EXPORT_IDENTIFIER,
                         'FORMAT = "{}"'.format(EXPORT_IDENTIFIER), "the value `{}` is read.".format(EXPORT_IDENTIFIER),
                         'FORMAT = "{}/v2"'.format(EXPORT_IDENTIFIER), 'FORMAT = "{}."'.format(EXPORT_IDENTIFIER),
                         'FORMAT = "v2 {}"'.format(EXPORT_IDENTIFIER), "`{} `".format(EXPORT_IDENTIFIER),
                         "\"{}'".format(EXPORT_IDENTIFIER), "VALUE = \"prefix '{}' suffix\"".format(EXPORT_IDENTIFIER),
                         "TEXT = \"{}'{}'x\"".format(OLD, EXPORT_IDENTIFIER),
                         ALLOWED_LINES[path] + " ", " " + ALLOWED_LINES[path], ALLOWED_LINES[path] + "  # and more"):
                with self.subTest(path=path, line=line):
                    self.assertEqual(offences(path, line + "\n"), [1])

    def test_identifier_in_any_other_file_fails(self):
        for path in self.others:
            with self.subTest(path=path):
                self.assertEqual(offences(path, "first\n`{}`\n".format(EXPORT_IDENTIFIER)), [2])

    def test_attachments_fail_in_every_file(self):
        prefixes = ("x", "my-", "my_", "laneboss-", "2", ".")
        suffixes = ("-extra", "_extra", "2", ".jsonl", "x", "-")
        for path in IDENTIFIER_FILES + self.others:
            for prefix in prefixes:
                with self.subTest(path=path, prefix=prefix):
                    self.assertEqual(offences(path, prefix + EXPORT_IDENTIFIER + "\n"), [1])
            for suffix in suffixes:
                with self.subTest(path=path, suffix=suffix):
                    self.assertEqual(offences(path, EXPORT_IDENTIFIER + suffix + "\n"), [1])

    def test_other_uses_fail_in_the_named_files(self):
        for path in IDENTIFIER_FILES:
            for line in ("the " + OLD + " command", OLD.upper() + "_HOME", OLD + "-decisions", OLD + ".decisions",
                         "run_" + OLD, EXPORT_IDENTIFIER + " and " + OLD, "." + OLD + "-state"):
                with self.subTest(path=path, line=line):
                    self.assertEqual(offences(path, line + "\n"), [1])

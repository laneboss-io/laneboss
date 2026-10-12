"""I. Commit scan: denylist rules, no echo of matched text, and a pre-commit hook that blocks."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from . import support


class ScanTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="laneboss-e2e-scan-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.environment = support.base_environment(self.directory)

    def scan(self, target, denylist=None, staged=False):
        environment = dict(self.environment)
        if denylist is not None:
            environment[support.ENV_PREFIX + "SCAN_DENYLIST"] = str(denylist)
        command = ["sh", str(support.ROOT / "scripts" / "scan.sh")] + (["--staged"] if staged else []) + [str(target)]
        return subprocess.run(command, env=environment, capture_output=True, text=True, timeout=120)

    def counted_files(self, root):
        """The files scripts/scan.sh counts when it scans `root`, computed by the rule the script uses.

        Outside `--staged` the script first runs `git -C root rev-parse --show-toplevel`. When that
        succeeds it lists `git ls-files -z` at the repository top and keeps each entry that lies under
        the scanned root and satisfies `Path.is_file()` (a submodule entry is a directory, and a
        tracked path removed from the working copy is not a file). When it fails it walks the root
        with `rglob("*")` and keeps each path that is a regular file and whose parts relative to the
        root hold neither `.git` nor `__pycache__` and whose suffix is not `.pyc`. It reads the files
        it kept and counts each one, so the printed count is the length of this list. A developer's
        checkout takes the first branch; the suite's own source tree on a test box, which is a tar
        extract, takes the second.
        """
        try:
            top = Path(subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
            ).decode("utf-8").strip()).resolve()
            listing = subprocess.check_output(["git", "-C", str(top), "ls-files", "-z"],
                                              stderr=subprocess.DEVNULL).split(b"\0")
        except (OSError, subprocess.CalledProcessError):
            return [path for path in root.rglob("*")
                    if not {"__pycache__", ".git"} & set(path.relative_to(root).parts)
                    and path.suffix != ".pyc" and path.is_file()]
        kept = []
        for name in listing:
            if not name:
                continue
            path = top / name.decode("utf-8")
            try:
                path.relative_to(root)
            except ValueError:
                continue
            if path.is_file():
                kept.append(path)
        return kept

    def test_tree_passes(self):
        result = self.scan(support.ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SCAN PASS", result.stdout)
        match = re.search(r"SCAN PASS: (\d+) file\(s\)", result.stdout)
        self.assertIsNotNone(match, "the summary line must carry the file count: " + result.stdout)
        expected = self.counted_files(support.ROOT)
        self.assertGreater(len(expected), 0, "the checkout must hold files to scan")
        self.assertEqual(int(match.group(1)), len(expected),
                         "the scan must count every file it read, and nothing else")

    def test_summary_counts_the_tree_it_scanned(self):
        """The count is computed from the scanned tree, not printed as a constant.

        The checkout's own file count is fixed for a given commit, so `test_tree_passes` alone is passed
        by a scan.sh whose SCAN PASS line holds that fixed number. This tree is built at run time, with a
        file count derived from the checkout's so the two can never agree; the scan must report this
        tree's own count.
        """
        tree = self.directory / "counted"
        tree.mkdir()
        checkout_count = len(self.counted_files(support.ROOT))
        count = checkout_count % 5 + 2
        self.assertNotEqual(count, checkout_count,
                            "the run-time count must differ from the checkout's")
        for index in range(count):
            (tree / "file-{}.txt".format(index)).write_text("a neutral sentence\n", encoding="utf-8")
        self.assertEqual(len(self.counted_files(tree)), count, "the fixture must hold exactly the files it wrote")
        result = self.scan(tree)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        match = re.search(r"SCAN PASS: (\d+) file\(s\)", result.stdout)
        self.assertIsNotNone(match, "the summary line must carry the file count: " + result.stdout)
        self.assertEqual(int(match.group(1)), count,
                         "the scan must count the files of the tree it scanned, not a constant")

    def test_denylist_match_fails(self):
        word = "zq" + "xv-invented-name"
        tree = self.directory / "tree"
        tree.mkdir()
        (tree / "clean.txt").write_text("nothing to report\n", encoding="utf-8")
        (tree / "notes.md").write_text("line one\nline two mentions ZQ" + "XV-Invented-Name here\n", encoding="utf-8")
        denylist = self.directory / "denylist.txt"
        denylist.write_text("# invented denylist\n\n" + word + "\n" + r"\bunused-" + "rule\\b\n", encoding="utf-8")
        result = self.scan(tree, denylist)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("SCAN FAIL notes.md:2 denylist-line-3", result.stdout)
        self.assertNotIn(word, (result.stdout + result.stderr).lower())
        self.assertNotIn("clean.txt", result.stdout)
        (tree / "notes.md").write_text("line one\n", encoding="utf-8")
        result = self.scan(tree, denylist)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.scan(support.ROOT, denylist).returncode, 0)

    def test_bad_denylist_is_an_error(self):
        tree = self.directory / "tree"
        tree.mkdir()
        (tree / "clean.txt").write_text("nothing to report\n", encoding="utf-8")
        result = self.scan(tree, self.directory / "absent.txt")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(),
                         "SCAN ERROR: cannot read the denylist file named by LANEBOSS_SCAN_DENYLIST")
        self.assertNotIn("SCAN PASS", result.stdout)
        invalid = self.directory / "invalid.txt"
        invalid.write_text("# comment\n(unclosed\n", encoding="utf-8")
        result = self.scan(tree, invalid)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(), "SCAN ERROR: denylist line 2: invalid regular expression")
        self.assertNotIn("(unclosed", result.stdout + result.stderr)

    def test_empty_denylist_is_an_error(self):
        """A named denylist that holds no rule must be refused, not silently applied.

        Before this check a named file of only comments and blank lines passed with `no match for 0
        denylist rule(s)`, so an emptied denylist stopped guarding anything while every commit still
        read as clean.
        """
        tree = self.directory / "tree"
        tree.mkdir()
        (tree / "clean.txt").write_text("nothing to report\n", encoding="utf-8")
        empty = self.directory / "rules.txt"
        empty.write_text("# comments and blank lines only\n\n", encoding="utf-8")
        result = self.scan(tree, empty)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(),
                         "SCAN ERROR: the denylist file named by LANEBOSS_SCAN_DENYLIST holds no rule")
        self.assertNotIn("SCAN PASS", result.stdout)

    def test_missing_root_is_an_error(self):
        result = self.scan(self.directory / "absent")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(), "SCAN ERROR: the scan root is missing or is not a directory")
        self.assertNotIn("SCAN PASS", result.stdout + result.stderr)

    def test_root_that_is_a_file_is_an_error(self):
        target = self.directory / "a-file.txt"
        target.write_text("nothing to report\n", encoding="utf-8")
        result = self.scan(target)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(), "SCAN ERROR: the scan root is missing or is not a directory")
        self.assertNotIn("SCAN PASS", result.stdout + result.stderr)

    def test_empty_directory_is_an_error(self):
        target = self.directory / "empty"
        target.mkdir()
        result = self.scan(target)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(), "SCAN ERROR: the scan checked no file")
        self.assertNotIn("SCAN PASS", result.stdout + result.stderr)

    def test_all_skipped_root_is_an_error(self):
        target = self.directory / "skipped"
        (target / "__pycache__").mkdir(parents=True)
        (target / "__pycache__" / "noise.pyc").write_bytes(b"a neutral sentence\n")
        result = self.scan(target)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(), "SCAN ERROR: the scan checked no file")
        self.assertNotIn("SCAN PASS", result.stdout + result.stderr)

    def test_unreadable_denylist_is_an_error(self):
        tree = self.directory / "tree"
        tree.mkdir()
        (tree / "clean.txt").write_text("nothing to report\n", encoding="utf-8")
        denylist_as_directory = self.directory / "denylist-directory"
        denylist_as_directory.mkdir()
        result = self.scan(tree, denylist_as_directory)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(),
                         "SCAN ERROR: cannot read the denylist file named by LANEBOSS_SCAN_DENYLIST")
        self.assertNotIn("SCAN PASS", result.stdout + result.stderr)

    def git(self, repository, *arguments):
        environment = dict(self.environment)
        environment.update({
            "GIT_AUTHOR_NAME": "e2e", "GIT_COMMITTER_NAME": "e2e", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_EMAIL": "e2e" + "@" + "example.invalid", "GIT_COMMITTER_EMAIL": "e2e" + "@" + "example.invalid",
        })
        return subprocess.run(["git", "-C", str(repository), *arguments], env=environment,
                              capture_output=True, text=True, timeout=120)

    def test_hook_blocks_private_key(self):
        repository = self.directory / "repository"
        repository.mkdir()
        self.assertEqual(self.git(repository, "init", "-q").returncode, 0)
        shutil.copytree(str(support.ROOT / "scripts"), str(repository / "scripts"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        (repository / "README.txt").write_text("An invented repository.\n", encoding="utf-8")
        denylist = self.directory / "denylist.txt"
        denylist.write_text("zq" + "xv-invented-name\n", encoding="utf-8")
        installed = subprocess.run(["sh", "scripts/install-hooks.sh", "--denylist", str(denylist)], cwd=str(repository),
                                   env=self.environment, capture_output=True, text=True, timeout=120)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertEqual(self.git(repository, "add", ".").returncode, 0)
        first = self.git(repository, "commit", "-q", "-m", "Start the repository")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        head = self.git(repository, "rev-parse", "HEAD").stdout.strip()
        key = repository / "deploy.key"
        key.write_text("-----" + "BEGIN " + "PRIVATE KEY" + "-----\ninvented\n", encoding="utf-8")
        self.assertEqual(self.git(repository, "add", "deploy.key").returncode, 0)
        blocked = self.git(repository, "commit", "-q", "-m", "Add a key")
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("private-key-header", blocked.stdout + blocked.stderr)
        self.assertEqual(self.git(repository, "rev-parse", "HEAD").stdout.strip(), head)
        os.remove(str(key))
        blocked = self.git(repository, "commit", "-q", "-m", "Add a key that is only staged")
        self.assertNotEqual(blocked.returncode, 0, "the hook must scan the staged content")
        self.assertEqual(self.git(repository, "rev-parse", "HEAD").stdout.strip(), head)
        self.assertEqual(self.git(repository, "rm", "-q", "--cached", "deploy.key").returncode, 0)
        (repository / "notes.md").write_text("mentions zq" + "xv-invented-name\n", encoding="utf-8")
        self.assertEqual(self.git(repository, "add", "notes.md").returncode, 0)
        blocked = self.git(repository, "commit", "-q", "-m", "Add notes")
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("denylist-line-1", blocked.stdout + blocked.stderr)
        (repository / "notes.md").write_text("neutral notes\n", encoding="utf-8")
        self.assertEqual(self.git(repository, "add", "notes.md").returncode, 0)
        allowed = self.git(repository, "commit", "-q", "-m", "Add neutral notes")
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
        self.assertNotEqual(self.git(repository, "rev-parse", "HEAD").stdout.strip(), head)

    def large_tree(self):
        tree = self.directory / "large"
        tree.mkdir()
        line = "a neutral sentence about apples and pears that repeats\n"
        (tree / "big.txt").write_text(line * (1024 * 1024 // len(line) + 1), encoding="utf-8")
        return tree

    def timed_scan(self, target, denylist):
        environment = dict(self.environment)
        environment[support.ENV_PREFIX + "SCAN_DENYLIST"] = str(denylist)
        try:
            return subprocess.run(["sh", str(support.ROOT / "scripts" / "scan.sh"), str(target)], env=environment,
                                  capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            self.fail("the scan did not finish within 30 seconds")

    def test_empty_matching_rule_refused(self):
        tree = self.large_tree()
        for rule in ("a*", "(?:)", "x?"):
            with self.subTest(rule):
                denylist = self.directory / "denylist.txt"
                denylist.write_text("# invented\n" + rule + "\n", encoding="utf-8")
                result = self.timed_scan(tree, denylist)
                self.assertEqual(result.returncode, 2, result.stdout[-500:] + result.stderr[-500:])
                self.assertIn("line 2", result.stderr)
                self.assertNotIn("SCAN PASS", result.stdout)

    def test_output_is_bounded(self):
        tree = self.large_tree()
        denylist = self.directory / "denylist.txt"
        denylist.write_text("pears\n", encoding="utf-8")
        result = self.timed_scan(tree, denylist)
        self.assertEqual(result.returncode, 1)
        self.assertLessEqual(len(result.stdout.splitlines()), 202)
        self.assertIn("SCAN FAIL big.txt:1 denylist-line-1", result.stdout)
        self.assertNotIn("pears", result.stdout + result.stderr)

    def test_zero_width_match_is_an_error(self):
        word = "zq" + "lookahead-word"
        tree = self.directory / "lookahead"
        tree.mkdir()
        (tree / "notes.md").write_text("first line\nmentions " + word + " here\n", encoding="utf-8")
        denylist = self.directory / "denylist.txt"
        denylist.write_text("# invented\n(?=" + word + ")\n", encoding="utf-8")
        result = self.timed_scan(tree, denylist)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("line 2", result.stderr)
        self.assertNotIn("SCAN PASS", result.stdout)
        self.assertNotIn(word, result.stdout + result.stderr)

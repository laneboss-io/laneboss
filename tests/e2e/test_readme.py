"""L. The README's quick start runs as written, from a fresh copy of the repository.

The commands are read from README.md itself, so the test fails when the text and the program drift apart.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from . import support

README = support.ROOT / "README.md"
CONTROL_FLOW = re.compile(r"^\s*(if|then|else|fi|case|esac|for|while|until|do|done)\b|&&|\|\||\||;")


def quick_start():
    """The first shell block under the README's "Quick start" heading, exactly as written."""
    text = README.read_text(encoding="utf-8")
    heading = re.search(r"(?m)^## Quick start[ \t]*$", text)
    if heading is None:
        raise AssertionError('README.md has no "## Quick start" section')
    block = re.search(r"(?ms)^```sh\n(.*?)^```$", text[heading.end():])
    if block is None:
        raise AssertionError('the "Quick start" section of README.md has no ```sh block')
    return block.group(1)


LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"(?m)^#{1,6}[ \t]+(.+?)[ \t]*$")
DOCUMENTS = ("docs/architecture.md", "docs/configuration.md", "docs/decisions.md", "src/laneboss/protocol/protocol.md",
             "examples/minimal/", "CONTRIBUTING.md", "CHANGELOG.md")


def anchors(path):
    """The anchors of a Markdown file's headings, the way GitHub forms them."""
    text = re.sub(r"(?ms)^```.*?^```$", "", path.read_text(encoding="utf-8"))
    return {re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-") for heading in HEADING.findall(text)}


class DocumentLinkTest(unittest.TestCase):
    """The documents are reachable by real relative links, and every link of the front page resolves."""

    def links(self, name):
        text = re.sub(r"(?ms)^```.*?^```$", "", (support.ROOT / name).read_text(encoding="utf-8"))
        return [target for target in LINK.findall(text) if "://" not in target]

    def test_readme_links_to_every_document(self):
        targets = {target.split("#")[0] for target in self.links("README.md")}
        self.assertEqual(sorted(set(DOCUMENTS) - targets), [], "README.md does not link to these documents")

    def test_links_resolve(self):
        for name in ("README.md", "CONTRIBUTING.md", "CHANGELOG.md"):
            for target in self.links(name):
                with self.subTest(document=name, target=target):
                    path, _, anchor = target.partition("#")
                    destination = (support.ROOT / name).parent / path if path else support.ROOT / name
                    self.assertTrue(destination.exists(), "{} links to {}, which does not exist".format(name, target))
                    if anchor:
                        self.assertIn(anchor, anchors(destination), "{} has no heading for #{}".format(path, anchor))


class QuickStartTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="laneboss-e2e-readme-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.checkout = self.directory / "checkout"
        shutil.copytree(str(support.ROOT), str(self.checkout),
                        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        self.home = self.directory / "home"
        self.scratch = self.directory / "tmp"
        for path in (self.home, self.scratch):
            path.mkdir()
        # The quick start's lane runs on a tmux server; its socket goes to a short private directory (a Unix socket
        # path is short) that is removed afterwards, instead of staying behind in the user's tmux directory.
        self.tmux_dir = Path(tempfile.mkdtemp(prefix="lbr", dir="/tmp")).resolve()
        self.addCleanup(self.collect_tmux)

    def collect_tmux(self):
        sockets = sorted(self.tmux_dir.glob("tmux-*/*"))
        command = self.home / ".local" / "bin" / "laneboss"
        if command.exists():
            # The example configuration's lanes run on a server at the socket its configuration records.
            result = subprocess.run([str(command), "config", "path", "example"], env=self.environment(),
                                    capture_output=True, text=True, timeout=60)
            try:
                sockets.append(Path(json.loads(result.stdout)["socket"]))
            except (ValueError, KeyError):
                pass
        for socket in sockets:
            subprocess.run(["tmux", "-S", str(socket), "kill-server"], capture_output=True, timeout=30)
            if socket.is_socket():
                socket.unlink()
        shutil.rmtree(str(self.tmux_dir), ignore_errors=True)

    def environment(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("LANEBOSS_", "PYTHON"))}
        environment["HOME"] = str(self.home)
        environment["TMPDIR"] = str(self.scratch)
        environment["TMUX_TMPDIR"] = str(self.tmux_dir)
        # The claims registry is the account's own, whatever HOME says; the test keeps it in its scratch directory.
        environment["LANEBOSS_TEST_CLAIMS_DIR"] = str(self.scratch / "claims")
        # The suite installs with the interpreter that runs it, so every platform tests one Python.
        environment["LANEBOSS_PYTHON"] = sys.executable
        return environment

    def test_quick_start_is_straight_line(self):
        script = quick_start()
        self.assertTrue(script.strip(), "the quick start is empty")
        for number, line in enumerate(script.splitlines(), 1):
            if line.lstrip().startswith("#") or not line.strip():
                continue
            self.assertIsNone(CONTROL_FLOW.search(line), "quick start line {} branches or chains: {!r}".format(
                number, line))

    def listing(self):
        return sorted(str(path.relative_to(self.checkout)) for path in self.checkout.rglob("*"))

    def test_quick_start_runs_as_written(self):
        before = self.listing()
        result = subprocess.run(["sh", "-e", "-c", quick_start()], cwd=str(self.checkout), env=self.environment(),
                                capture_output=True, text=True, encoding="utf-8", timeout=300)
        self.assertEqual(result.returncode, 0, "quick start: exit {}; stdout={!r}; stderr={!r}".format(
            result.returncode, result.stdout, result.stderr))
        objects = []
        for line in result.stdout.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                objects.append(value)
        installed = [item for item in objects if "installed" in item]
        self.assertEqual(len(installed), 1, objects)
        self.assertEqual(Path(installed[0]["link"]), self.home / ".local" / "bin" / "laneboss")
        versions = [item for item in objects if item.get("program") == "laneboss"]
        self.assertEqual(len(versions), 1, objects)
        self.assertRegex(versions[0]["protocol_version"], r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertIn({"valid": True, "configs": ["example"]}, objects)
        checks = [item for item in objects if set(item) == {"check", "ok", "detail"}]
        self.assertEqual(sorted(item["check"] for item in checks),
                         sorted(["config", "state.isolated", "store.recorded", "state.writable", "store.round_trip",
                                 "tool.git", "tool.tmux", "runner.agent", "organisation.tools"]))
        self.assertEqual([item for item in checks if item["ok"] is not True], [])
        appended = [item for item in objects if "duplicate" in item]
        self.assertEqual(len(appended), 1, objects)
        self.assertEqual((appended[0]["seq"], appended[0]["duplicate"]), (1, False))
        tailed = [item for item in objects if item.get("kind") == "note.added"]
        self.assertEqual(len(tailed), 1, objects)
        self.assertEqual((tailed[0]["seq"], tailed[0]["actor"], tailed[0]["id"]), (1, "me", appended[0]["id"]))
        rendered = [item for item in objects if "out" in item and "event" in item]
        self.assertEqual(len(rendered), 1, objects)
        self.assertEqual(rendered[0]["event"]["seq"], 2)
        self.assertIn("<!-- laneboss launcher block: begin (protocol ", result.stdout)
        self.assertIn("Print a greeting.", result.stdout)
        # The lane: started at once, followed through its events until it ended, marked and cleaned up.
        started = [item for item in objects if item.get("how") == "start"]
        self.assertEqual(len(started), 1, objects)
        self.assertEqual((started[0]["lane"], started[0]["run"], started[0]["runner"], started[0]["branch"]),
                         ("demo-1", 1, "agent", "demo-1"))
        worktree = Path(started[0]["worktree"])
        followed = [item for item in objects if item.get("lane") == "demo-1" and "kind" in item and "seq" in item]
        self.assertEqual([item["kind"] for item in followed], ["brief.rendered", "lane.started", "lane.ended"])
        self.assertEqual((followed[2]["payload"]["reason"], followed[2]["payload"]["exit_code"]), ("exit", 0))
        log = Path(started[0]["log"]).read_text(encoding="utf-8")
        self.assertIn("example-agent", log)
        self.assertIn("# Say hello", log)
        status = [item for item in objects if item.get("lane") == "demo-1" and "live" in item]
        self.assertEqual(len(status), 1, objects)
        self.assertEqual((status[0]["state"], status[0]["running"], status[0]["reason"]), ("verifying", False, "exit"))
        cleaned = [item for item in objects if "removed" in item]
        self.assertEqual(len(cleaned), 1, objects)
        self.assertIn({"item": "worktree", "path": str(worktree)}, cleaned[0]["removed"])
        self.assertIn({"item": "branch", "name": "demo-1"}, cleaned[0]["removed"])
        self.assertFalse(worktree.exists())
        # What the quick start created lives under the home and the scratch directory, not in the checkout.
        self.assertTrue((self.home / ".local" / "state" / "laneboss" / "example" / "events.sqlite").is_file())
        self.assertEqual(self.listing(), before)

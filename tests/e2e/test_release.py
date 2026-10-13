"""Release boundaries and the two scanner regressions raised by the Go-only review."""

import json
import subprocess

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class ReleaseProbeTest(support.LauncherTest):

    def test_untagged_decisions_probe(self):
        """Fails if the release probe can create a directory and append caller-chosen data."""
        self.command = support.helper_binary(support.ROOT / "cmd" / "laneboss" / "main.go")
        destination = self.directory / "probe-created" / "record.jsonl"
        payload = json.dumps({"action": "log", "path": str(destination), "value": {"entry": "release canary"}}) + "\n"
        unknown = self.run_laneboss("decisions", "unknown-action", code=2, stdin=payload)
        refused = self.run_laneboss("decisions", "probe", code=2, stdin=payload)
        self.assertEqual(refused.stdout, "")
        self.assertIn("invalid choice", unknown.stderr)
        self.assertIn("invalid choice", refused.stderr)
        self.assertFalse(destination.parent.exists(), "the release probe created the log directory")
        tagged = subprocess.run([str(support.faults_binary()), "decisions", "probe"], input=payload,
                                env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(tagged.returncode, 0, tagged.stderr)
        self.assertEqual(tagged.stdout.splitlines()[0], "ready")
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), {"entry": "release canary"})

    def test_untagged_discord_adapter(self):
        """Fails if the test-only Discord dispatcher is reachable in the release."""
        self.command = support.helper_binary(support.ROOT / "cmd" / "laneboss" / "main.go")
        unknown = self.run_laneboss("org", "channel", "unknown-action", code=2)
        refused = self.run_laneboss("org", "channel", "_probe", "read", str(self.directory), code=2)
        self.assertEqual(refused.stdout, "")
        self.assertEqual(refused.stderr, unknown.stderr)

    def test_untagged_lane_probe(self):
        """Fails when the release dispatcher still admits the private lane probe."""
        self.command = support.helper_binary(support.ROOT / "cmd" / "laneboss" / "main.go")
        payload = json.dumps({"action": "stream", "name": "text", "line": "release control"})
        unknown = self.run_laneboss("lane", "__unknown_action", code=2, stdin=payload)
        refused = self.run_laneboss("lane", "__probe", code=2, stdin=payload)
        self.assertEqual(refused.stdout, "")
        self.assertEqual(refused.stderr, unknown.stderr)
        tagged = subprocess.run([str(support.faults_binary()), "lane", "__probe"], input=payload,
                                env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(tagged.returncode, 0, tagged.stderr)
        self.assertEqual(json.loads(tagged.stdout), [{"kind": "answer", "text": "release control"}])


class TurnScannerRegressionTest(support.LauncherTest):
    def analyse(self, command):
        result = subprocess.run([str(support.faults_binary()), "lane", "__probe"],
                                input=json.dumps({"action": "shell-analysis", "command": command,
                                                  "directory": str(self.directory)}),
                                env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_unicode_heredoc_write(self):
        """Fails if a UTF-8 continuation byte ends the delimiter and hides the later rm."""
        target = str(self.directory / "protected.txt")
        for delimiter in ("你", "à", "\u0185"):
            with self.subTest(delimiter=delimiter):
                answer = self.analyse("cat <<" + delimiter + "\nx\n" + delimiter + "\nrm protected.txt")
                self.assertEqual(answer["writes"], [target])
                self.assertIn(target, answer["named"])
        self.assertEqual(self.analyse("cat protected.txt")["writes"], [])

    def test_del_c1_traversals(self):
        """Fails if the scanner screens control characters before resolving a quoted path."""
        target = str(self.directory / "protected.txt")
        for control in ("\u007f", "\u0080", "\u0085", "\u009f"):
            word = "d" + control
            with self.subTest(character=hex(ord(control))):
                answer = self.analyse('mkdir -p "' + word + '" && rm "' + word + '/../protected.txt"')
                self.assertEqual(answer["writes"], [target])
                self.assertIn(target, answer["named"])

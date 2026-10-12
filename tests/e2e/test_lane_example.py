"""J. The shipped example: examples/minimal passes doctor as shipped, with its stand-in runner program on PATH, and runs
a lane end to end without any agent program installed. (test_readme.py runs the README's quick start as written.)"""

import json
import os
from pathlib import Path
import shutil

from . import lanesupport, support

EXAMPLE = support.ROOT / "examples" / "minimal"


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class ExampleTest(lanesupport.LaneTest):
    def setUp(self):
        super().setUp()
        shutil.copytree(str(EXAMPLE), str(self.home / "configs" / "example"))
        self.records["example"] = self.records["alpha"]
        self.environment["PATH"] = str(EXAMPLE / "bin") + os.pathsep + self.environment.get("PATH", "")

    def test_example_passes_doctor_as_shipped(self):
        self.assertTrue(os.access(str(EXAMPLE / "bin" / "example-agent"), os.X_OK))
        result = self.run_laneboss("doctor", "--config", "example", code=0, environment=self.env("example"))
        checks = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([item for item in checks if item["ok"] is not True], [])
        self.assertIn("runner.agent", [item["check"] for item in checks])

    def test_example_runs_a_lane(self):
        brief = self.brief("example-demo", "# Say hello\n\nPrint a greeting.\n")
        started = json.loads(self.lane("start", "--lane", "demo-1", "--brief", brief, "--difficulty", "standard",
                                       "--worktree", self.scratch("demo"), config="example").stdout)
        self.assertEqual((started["runner"], started["model"], started["account"]),
                         ("agent", "example-model-medium-1", "example-main"))
        ended = self.wait_event("lane.ended", "demo-1", config="example")
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"]), ("exit", 0))
        log = Path(started["log"]).read_text(encoding="utf-8")
        self.assertIn("example-agent", log)
        self.assertIn("# Say hello", log)
        self.assert_sound("example")

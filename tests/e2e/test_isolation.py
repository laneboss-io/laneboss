"""C. Isolation: every state command is bound to exactly one configuration and stays inside it."""

import json
import os
from pathlib import Path
import shutil

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class IsolationTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")
        self.write_config("beta")
        self.brief = self.directory / "brief.md"
        self.brief.write_text("# Brief\n\nAn invented task.\n", encoding="utf-8")
        self.event_file = self.directory / "event.json"
        self.event_file.write_text(json.dumps(self.event()), encoding="utf-8")

    def render(self, source, target, config="alpha", code=0, environment=None):
        arguments = ["brief", "render", "--lane", "alpha-lane-1", "--in", source, "--out", target]
        if config:
            arguments[2:2] = ["--config", config]
        return self.run_laneboss(*arguments, code=code, environment=environment)

    def test_event_stays_in_its_configuration(self):
        appended = json.loads(self.append(self.event(id="iso-1", payload={"n": 1}), config="alpha").stdout)
        self.assertEqual(appended["seq"], 1)
        self.assertEqual([item["id"] for item in self.events("alpha")], ["iso-1"])
        self.assertEqual(self.events("beta"), [])
        self.assertEqual(self.run_laneboss("event", "tail", "--config", "beta").stdout, "")
        self.append(self.event(id="iso-2"), config="beta")
        self.assertEqual([item["id"] for item in self.events("beta")], ["iso-2"])
        self.assertEqual([item["id"] for item in self.events("alpha")], ["iso-1"])
        lines = self.run_laneboss("event", "tail", "--config", "beta").stdout.splitlines()
        self.assertEqual([json.loads(line)["id"] for line in lines], ["iso-2"])
        alpha = Path(self.laneboss_json("config", "path", "alpha")["store"])
        beta = Path(self.laneboss_json("config", "path", "beta")["store"])
        self.assertTrue(alpha.is_file())
        self.assertTrue(beta.is_file())
        self.assertNotEqual(alpha, beta)
        self.assertNotEqual(alpha.parent, beta.parent)
        self.assertFalse(alpha.parent in beta.parents or beta.parent in alpha.parents)

    def test_conflicting_binding_refused(self):
        environment = dict(self.environment)
        environment[support.ENV_PREFIX + "CONFIG"] = "alpha"
        commands = [
            ["state", "events", "--config", "beta"],
            ["state", "lanes", "--config", "beta"],
            ["state", "verify", "--config", "beta"],
            ["event", "tail", "--config", "beta"],
            ["event", "append", "--config", "beta", "--file", self.event_file],
            ["doctor", "--config", "beta"],
            ["config", "show", "beta"],
            ["config", "path", "beta"],
        ]
        for arguments in commands:
            with self.subTest(arguments[:2]):
                result = self.run_laneboss(*arguments, code=2, environment=environment)
                self.assertIn("alpha", result.stderr)
                self.assertIn("beta", result.stderr)
        result = self.render(self.brief, self.directory / "out.md", config="beta", code=2, environment=environment)
        self.assertIn("beta", result.stderr)
        self.assertEqual(self.events("beta"), [])
        self.run_laneboss("event", "append", "--file", self.event_file, environment=environment)
        self.assertEqual(len(self.laneboss_json("state", "events", "--config", "alpha", environment=environment)), 1)
        self.assertEqual(len(self.laneboss_json("state", "events", environment=environment)), 1)
        self.assertEqual(self.events("beta"), [])

    def test_missing_binding_lists_names(self):
        commands = [
            ["state", "events"], ["state", "lanes"], ["state", "rebuild"], ["state", "verify"],
            ["event", "tail"], ["event", "append", "--file", self.event_file], ["doctor"],
        ]
        for arguments in commands:
            with self.subTest(arguments):
                result = self.run_laneboss(*arguments, code=2)
                self.assertIn("alpha", result.stderr)
                self.assertIn("beta", result.stderr)
        result = self.render(self.brief, self.directory / "out.md", config=None, code=2)
        self.assertIn("alpha", result.stderr)
        self.assertFalse((self.directory / "out.md").exists())
        shutil.rmtree(str(self.home / "configs" / "beta"))
        result = self.run_laneboss("state", "events", code=2)
        self.assertIn("alpha", result.stderr)
        self.assertEqual(self.events("alpha"), [])

    def test_paths_in_other_config_refused(self):
        beta = self.laneboss_json("config", "path", "beta")
        inside_config = Path(beta["config_dir"]) / "event.json"
        inside_config.write_text(json.dumps(self.event(id="planted-1")), encoding="utf-8")
        result = self.run_laneboss("event", "append", "--config", "alpha", "--file", inside_config, code=2)
        self.assertIn("beta", result.stderr)
        link = self.directory / "link.json"
        os.symlink(str(inside_config), str(link))
        self.run_laneboss("event", "append", "--config", "alpha", "--file", link, code=2)
        self.append(self.event(id="beta-1"), config="beta")
        inside_state = Path(beta["state_dir"]) / "brief.md"
        inside_state.write_text("# Brief\n", encoding="utf-8")
        self.render(inside_state, self.directory / "out.md", code=2)
        self.assertFalse((self.directory / "out.md").exists())
        target = Path(beta["state_dir"]) / "out.md"
        self.render(self.brief, target, code=2)
        self.assertFalse(target.exists())
        own = Path(self.laneboss_json("config", "path", "alpha")["state_dir"])
        self.render(self.brief, own / "out.md", code=2)
        self.assertFalse((own / "out.md").exists())
        custom = self.directory / "custom-beta-state"
        self.write_config("beta", state_path=custom)
        self.append(self.event(id="beta-2"), config="beta")
        planted = custom / "planted.json"
        planted.write_text(json.dumps(self.event(id="planted-2")), encoding="utf-8")
        result = self.run_laneboss("event", "append", "--config", "alpha", "--file", planted, code=2)
        self.assertIn("beta", result.stderr)
        self.assertEqual(self.events("alpha"), [])
        self.assertEqual([item["id"] for item in self.events("beta")], ["beta-2"])

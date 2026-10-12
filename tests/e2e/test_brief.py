"""G. Brief rendering: the input bytes stay a prefix, the protocol block follows, inputs are hashed and kept."""

import json
from pathlib import Path

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


BRIEF = "# Brief: an invented task\n\nRender me exactly. Non-ASCII stays: é中 \U0001f642\n\n## Steps\n\n1. Do it.\n"
COST = """
## Cost

- Unit price: 0.01 USD per call
- Per-run cap: 50 calls
- Daily cap: 2 USD
- Worst case: 2 USD in one day
"""
PREFLIGHT = """
## Preflight

| Call | Permission | Where granted | Read-back |
|---|---|---|---|
| update the service | deploy role | project settings | describe the service |
"""


class BriefTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")
        self.paths = self.laneboss_json("config", "path", "alpha")

    def render(self, content, *extra, code=0, name="brief", lane="alpha-lane-1"):
        source = self.directory / (name + ".md")
        source.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        target = self.directory / (name + "-rendered.md")
        result = self.run_laneboss("brief", "render", "--config", "alpha", "--lane", lane, "--in", source,
                              "--out", target, *extra, code=code)
        return target, result

    def rendered_events(self):
        return [item for item in self.events() if item["kind"] == "brief.rendered"]

    def test_render_keeps_input_and_appends(self):
        brief = BRIEF.encode("utf-8") + b"The last line has no newline."
        target, result = self.render(brief, "--project", "web")
        output = target.read_bytes()
        self.assertEqual(output[:len(brief)], brief)
        block = output[len(brief):].decode("utf-8")
        protocol_version = self.laneboss_json("--version")["protocol_version"]
        self.assertIn("Protocol version: " + protocol_version, block)
        self.assertIn("Refusal rule", block)
        self.assertIn("Never use an override prefix.", block)
        protocol = support.PROTOCOL_FILE.read_bytes()
        self.assertIn(protocol.decode("utf-8"), block)
        rules_directory = self.home / "configs" / "alpha" / "rules"
        standing = (rules_directory / "standing.md").read_bytes()
        web = (rules_directory / "web.md").read_bytes()
        self.assertIn(standing.decode("utf-8"), block)
        self.assertIn(web.decode("utf-8"), block)
        events = self.rendered_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["lane"], "alpha-lane-1")
        payload = events[0]["payload"]
        self.assertEqual(payload["output"]["sha256"], support.digest(output))
        self.assertEqual(Path(payload["output"]["path"]), target)
        self.assertEqual(json.loads(result.stdout)["event"]["seq"], events[0]["seq"])
        inputs = payload["inputs"]
        self.assertEqual([item["role"] for item in inputs], ["brief", "protocol", "rules", "rules"])
        self.assertEqual(inputs[0]["sha256"], support.digest(brief))
        self.assertEqual(inputs[1]["sha256"], support.digest(protocol))
        self.assertEqual(inputs[1]["version"], protocol_version)
        self.assertEqual([item["path"] for item in inputs[2:]], ["rules/standing.md", "rules/web.md"])
        self.assertEqual([item["sha256"] for item in inputs[2:]], [support.digest(standing), support.digest(web)])
        state = Path(self.paths["state_dir"])
        for item in inputs:
            copy = state / item["copy"]
            self.assertTrue(copy.is_file(), item["copy"])
            self.assertEqual(copy.name, item["sha256"])
            self.assertEqual(support.digest(copy.read_bytes()), item["sha256"])
            self.assertIn("alpha-lane-1", Path(item["copy"]).parts)
        self.laneboss_json("state", "verify", "--config", "alpha")
        again, result = self.render(output, name="again", code=2)
        self.assertIn("launcher block", result.stderr)
        self.assertFalse(again.exists())
        kept = state / inputs[2]["copy"]
        kept.write_bytes(b"changed rules\n")
        self.assertIn("kept input", self.run_laneboss("state", "verify", "--config", "alpha", code=3).stderr)

    def test_billing_needs_cost_section(self):
        target, result = self.render(BRIEF, "--touches", "billing", code=2)
        self.assertIn("cost", result.stderr.lower())
        self.assertFalse(target.exists())
        target, result = self.render(BRIEF + COST.replace("- Daily cap: 2 USD\n", ""), "--touches", "billing",
                                     code=2, name="partial")
        self.assertIn("daily cap", result.stderr.lower())
        self.assertFalse(target.exists())
        self.assertEqual(self.rendered_events(), [])
        target, _ = self.render(BRIEF + COST, "--touches", "billing", name="complete")
        self.assertTrue(target.is_file())
        self.assertEqual(self.rendered_events()[0]["payload"]["touches"], ["billing"])

    def test_deploy_needs_preflight_section(self):
        target, result = self.render(BRIEF + COST, "--touches", "deploy", code=2)
        self.assertIn("preflight", result.stderr.lower())
        self.assertFalse(target.exists())
        target, result = self.render(BRIEF + PREFLIGHT.replace(" Read-back |", " |"), "--touches", "deploy",
                                     code=2, name="partial")
        self.assertIn("read-back", result.stderr.lower())
        target, result = self.render(BRIEF + PREFLIGHT, "--touches", "deploy", "--touches", "billing",
                                     code=2, name="both")
        self.assertIn("cost", result.stderr.lower())
        self.assertEqual(self.rendered_events(), [])
        self.render(BRIEF + PREFLIGHT + COST, "--touches", "deploy", "--touches", "billing", name="complete")
        self.assertEqual(self.rendered_events()[0]["payload"]["touches"], ["billing", "deploy"])

    def test_credential_brief_is_refused(self):
        bearer = "abc123def456" + "ghi789jkl012"
        target, result = self.render(BRIEF + "Call it with Authorization: Bearer " + bearer + "\n", code=2)
        self.assertNotIn(bearer, result.stdout + result.stderr)
        self.assertIn("line 8", result.stderr)
        self.assertFalse(target.exists())
        self.assertEqual(self.events(), [])

    def test_bad_requests_are_refused(self):
        existing = self.directory / "taken-rendered.md"
        existing.write_text("keep me\n", encoding="utf-8")
        self.render(BRIEF, code=2, name="taken")
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep me\n")
        self.render(BRIEF, "--project", "absent", code=2, name="project")
        self.render(BRIEF, code=2, name="lane", lane="Bad Lane")
        self.render(b"\xff\xfe not text", code=2, name="binary")
        self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in",
                     self.directory / "absent.md", "--out", self.directory / "out.md", code=2)
        self.render(BRIEF, "--touches", "marketing", code=2, name="touch")
        self.assertEqual(self.events(), [])

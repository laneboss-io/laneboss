"""Mandatory sections need labelled values in the body, and a failed render leaves nothing behind."""

from contextlib import closing
import json
from pathlib import Path
import resource
import sqlite3
import subprocess

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


BRIEF = "# Brief: an invented task\n\nRender me.\n"
COST_LINES = "\n## Cost\n\n- Unit price: 0.01 USD per call\n- Per-run cap: 50 calls\n- Daily cap: 2 USD\n- Worst case: 2 USD\n"
COST_TABLE = ("\n## Cost\n\n| Unit price | Per-run cap | Daily cap | Worst case |\n|---|---|---|---|\n"
              "| 0.01 USD | 50 calls | 2 USD | 2 USD |\n")
PREFLIGHT_TABLE = ("\n## Preflight\n\n| Call | Permission | Where granted | Read-back |\n|---|---|---|---|\n"
                   "| update the service | deploy role | project settings | describe the service |\n")
PREFLIGHT_LINES = ("\n## Preflight\n\n- Call: update the service\n- Permission: deploy role\n"
                   "- Where granted: project settings\n- Read-back: describe the service\n")
FENCE = "`" * 3

REJECTED = [
    ("cost heading only", "billing", "\n## Cost: unit price / per-run cap / daily cap / worst case\n"),
    ("preflight heading only", "deploy", "\n## Preflight: calls, permission, where granted, read-back\n"),
    ("table header only", "deploy",
     "\n## Preflight\n\n| Call | Permission | Where granted | Read-back |\n|---|---|---|---|\n"),
    ("table without values", "deploy",
     "\n## Preflight\n\n| Call | Permission | Where granted | Read-back |\n|---|---|---|---|\n|  |  |  |  |\n"),
    ("labels without values", "billing", "\n## Cost\n\n- Unit price:\n- Per-run cap:\n- Daily cap:\n- Worst case:\n"),
    ("cost labels in a fence", "billing",
     "\n## Cost\n\n" + FENCE + "\nUnit price: 1 USD\nPer-run cap: 2 USD\nDaily cap: 3 USD\nWorst case: 4 USD\n"
     + FENCE + "\n"),
    ("preflight table in a fence", "deploy",
     "\n## Preflight\n\n" + FENCE + "\n| Call | Permission | Where granted | Read-back |\n|---|---|---|---|\n"
     "| update the service | deploy role | project settings | describe the service |\n" + FENCE + "\n"),
]
ACCEPTED = [
    ("cost lines", "billing", COST_LINES),
    ("cost table", "billing", COST_TABLE),
    ("preflight table", "deploy", PREFLIGHT_TABLE),
    ("preflight lines", "deploy", PREFLIGHT_LINES),
]


class RenderTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")
        self.paths = self.laneboss_json("config", "path", "alpha")
        self.state = Path(self.paths["state_dir"])
        self.counter = 0

    def render(self, content, *extra, code=0, preexec=None):
        self.counter += 1
        source = self.directory / "brief-{}.md".format(self.counter)
        source.write_text(content, encoding="utf-8")
        target = self.directory / "out" / "rendered-{}.md".format(self.counter)
        target.parent.mkdir(exist_ok=True)
        command = [str(self.command), "brief", "render", "--config", "alpha", "--lane", "alpha-lane-1",
                   "--in", str(source), "--out", str(target), *extra]
        result = subprocess.run(command, cwd=str(self.directory), env=self.environment, capture_output=True,
                                text=True, encoding="utf-8", timeout=60, preexec_fn=preexec)
        if code is not None:
            self.assertEqual(result.returncode, code, result.stderr)
        return target, result

    def copies(self):
        root = self.state / "lanes"
        return sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()) if root.exists() else []

    def rendered(self):
        return [item for item in self.events() if item["kind"] == "brief.rendered"]

    def test_sections_need_values(self):
        for label, touch, section in REJECTED:
            with self.subTest(label):
                target, result = self.render(BRIEF + section, "--touches", touch, code=2)
                self.assertFalse(target.exists())
        self.assertEqual(self.rendered(), [])
        for label, touch, section in ACCEPTED:
            with self.subTest(label):
                target, _ = self.render(BRIEF + section, "--touches", touch)
                self.assertTrue(target.is_file())

    def test_failed_write_leaves_nothing(self):
        self.render(BRIEF)
        before = self.copies()
        big = BRIEF + "A neutral sentence that only adds size to the brief.\n" * 300
        limit = len(big.encode("utf-8")) + 1024

        def small_files():
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

        target, result = self.render(big, code=None, preexec=small_files)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())
        self.assertEqual(sorted(path.name for path in target.parent.iterdir()), ["rendered-1.md"])
        self.assertEqual(self.copies(), before)
        self.assertEqual(len(self.rendered()), 1)
        self.laneboss_json("state", "verify", "--config", "alpha")

    def test_failed_append_leaves_nothing(self):
        self.render(BRIEF)
        before = self.copies()
        store = Path(self.paths["store"])
        with closing(sqlite3.connect(str(store))) as connection:
            connection.execute("CREATE TRIGGER block_append BEFORE INSERT ON events "
                               "BEGIN SELECT RAISE(ABORT, 'blocked by the test'); END")
            connection.commit()
        target, result = self.render(BRIEF + "\nA second, different brief.\n", code=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())
        self.assertEqual(self.copies(), before)
        with closing(sqlite3.connect(str(store))) as connection:
            connection.execute("DROP TRIGGER block_append")
            connection.commit()
        self.assertEqual(len(self.rendered()), 1)
        self.laneboss_json("state", "verify", "--config", "alpha")
        self.render(BRIEF + "\nA second, different brief.\n")
        self.assertEqual(len(self.rendered()), 2)

    def test_fences_follow_markdown(self):
        values = "- Unit price: 1 USD\n- Per-run cap: 2 USD\n- Daily cap: 3 USD\n- Worst case: 4 USD\n"
        rejected = [
            ("shorter closing line", "\n## Cost\n\n" + "`" * 4 + "\nexample\n" + FENCE + "\n" + values),
            ("closing line with text", "\n## Cost\n\n" + FENCE + "\nexample\n" + FENCE + "text\n" + values),
            ("other fence character", "\n## Cost\n\n~~~\nexample\n" + FENCE + "\n" + values),
            ("unclosed fence", "\n## Cost\n\n" + FENCE + "\nexample\n" + values),
        ]
        for label, section in rejected:
            with self.subTest(label):
                target, _ = self.render(BRIEF + section, "--touches", "billing", code=2)
                self.assertFalse(target.exists())
        for label, section in (("longer closing line", "\n## Cost\n\n" + FENCE + "\nexample\n" + "`" * 5 + "\n"
                                + values),
                               ("tilde fence", "\n## Cost\n\n~~~~\nexample\n~~~~\n" + values)):
            with self.subTest(label):
                target, _ = self.render(BRIEF + section, "--touches", "billing")
                self.assertTrue(target.is_file())

    def test_crlf_fence_then_cost(self):
        values = "- Unit price: 1 USD\n- Per-run cap: 2 USD\n- Daily cap: 3 USD\n- Worst case: 4 USD\n"
        text = BRIEF + "\n## Example\n\n" + FENCE + "\nexample\n" + FENCE + "\n\n## Cost\n\n" + values
        data = text.replace("\n", "\r\n").encode("utf-8")
        source = self.directory / "crlf.md"
        source.write_bytes(data)
        target = self.directory / "out" / "crlf-rendered.md"
        target.parent.mkdir(exist_ok=True)
        self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in", source,
                     "--out", target, "--touches", "billing")
        self.assertTrue(target.read_bytes().startswith(data), "the output begins with the exact input bytes")

    def render_in(self, lane, content, code=0):
        self.counter += 1
        source = self.directory / "lane-brief-{}.md".format(self.counter)
        source.write_text(content, encoding="utf-8")
        target = self.directory / "out" / "lane-rendered-{}.md".format(self.counter)
        target.parent.mkdir(exist_ok=True)
        return target, self.run_laneboss("brief", "render", "--config", "alpha", "--lane", lane, "--in", source,
                                    "--out", target, code=code)

    def test_cleanup_is_per_lane(self):
        self.render_in("alpha-lane-a", BRIEF)
        lane_a = sorted(str(path) for path in (self.state / "lanes" / "alpha-lane-a").rglob("*") if path.is_file())
        self.assertEqual(len(lane_a), 3)
        before = {path: Path(path).read_bytes() for path in lane_a}
        store = Path(self.paths["store"])
        with closing(sqlite3.connect(str(store))) as connection:
            connection.execute("CREATE TRIGGER block_append BEFORE INSERT ON events "
                               "BEGIN SELECT RAISE(ABORT, 'blocked by the test'); END")
            connection.commit()
        target, result = self.render_in("alpha-lane-b", BRIEF, code=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())
        lane_b = self.state / "lanes" / "alpha-lane-b"
        self.assertEqual([path for path in lane_b.rglob("*") if path.is_file()] if lane_b.exists() else [], [])
        self.assertEqual({path: Path(path).read_bytes() for path in lane_a}, before)
        with closing(sqlite3.connect(str(store))) as connection:
            connection.execute("DROP TRIGGER block_append")
            connection.commit()
        self.laneboss_json("state", "verify", "--config", "alpha")

"""Rows J1-J5 for the laneboss job catalog and the TypeSafe judge's state and output (scripts/laneboss_jobs.py).

J1 checks the generated catalog against the installed command line itself (the top-level commands of --help, the
dashboard that the program adds in code included, are exactly the catalog's; the commands the jobs name answer --help;
every row has its purpose). J3 checks the org part of the state. J4 runs every representative job through the output
plumbing and J5 is its
stale-catalog mutant.

In J4 and J5 the TypeSafe service is a STAND-IN: no secret goes to a test machine, so the answers are canned. Those rows
prove the state, the options, the validation of the answer and the output; they do not measure the model's accuracy.
"""

import importlib.util
import json
import re

from tests.e2e import support


# The raw shell command of a job that a laneboss command already does, and the command that should have been used.
JOBS = (
    ("tmux new-session -d -s lb-worker 'claude -p brief.md'", "lane start"),
    ("git worktree add ../laneboss-lb-worker -b lb-worker", "lane start"),
    ("tmux new-session -d -s lb-worker 'claude --continue'", "lane resume"),
    ("tmux send-keys -t lb-worker 'please rebase' Enter", "lane send"),
    ("tmux kill-session -t lb-worker", "lane stop"),
    ("kill $(cat ~/.local/state/laneboss/lb-worker.pid)", "lane stop"),
    ("git worktree remove ../laneboss-lb-worker", "lane clean"),
    ("sqlite3 ~/.local/state/laneboss/events.db 'select * from events'", "state events"),
    ("curl -s http://127.0.0.1:8765/api/lanes", "state lanes"),
    ("curl -s -X POST -d '{\"content\":\"done\"}' https://discord.example/api/webhooks/1", "report"),
)
# Ordinary shell commands with no laneboss job.
CONTROLS = ("ls -la docs", "go test ./...", "git status")


def load():
    spec = importlib.util.spec_from_file_location("laneboss_jobs", support.ROOT / "scripts" / "laneboss_jobs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stand_in(expected, st, owned=0.95):
    """A canned TypeSafe answer set for the Noul and the Choice of one question."""
    return {"owned": {"type": "noul", "noul": owned},
            "command": {"type": "choice", "choice": expected, "probabilities": {name: 1.0 if name == expected else 0.0 for name in [row["path"] for row in st["laneboss_jobs"]] + ["none"]}, "confidence": 1.0}}


def check_jobs(module, st):
    """The jobs whose output is wrong for this state, as (shell command, why)."""
    failing = []
    for command, expected in JOBS:
        try:
            out = module.flag(command, st, stand_in(expected, st))
        except ValueError as error:
            failing.append((command, str(error)))
            continue
        if not (out["flagged"] and out["laneboss_command"] == expected and "laneboss " + expected + " " in out["reason"]):
            failing.append((command, "wrong output: %r" % (out,)))
    for command in CONTROLS:
        out = module.flag(command, st, stand_in("none", st, owned=0.02))
        if out["flagged"] or out["laneboss_command"] is not None or out["reason"]:
            failing.append((command, "a control was flagged: %r" % (out,)))
    return failing


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LanebossJobsTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.jobs = load()
        self.syntax = support.ROOT / "internal" / "cli" / "syntax.json"

    def syntax_copy(self, remove=()):
        """A copy of syntax.json with the named commands removed."""
        data = json.loads(self.syntax.read_text(encoding="utf-8"))

        def find(parent):
            node = data
            for name in parent.split():
                node = next(child for child in node["commands"] if child["name"] == name)
            return node

        for path in remove:
            *parent, name = path.split()
            node = find(" ".join(parent))
            self.assertIn(name, [child["name"] for child in node["commands"]], "the mutant removes a command that exists")
            node["commands"] = [child for child in node["commands"] if child["name"] != name]
        copy = self.directory / "syntax-copy.json"
        copy.write_text(json.dumps(data), encoding="utf-8")
        return copy

    def test_j1_catalog_is_the_command_line(self):
        """The catalog names exactly the commands the installed program lists, and the commands the jobs name answer --help.

        The program's own top-level --help is the reference: its commands are exactly the catalog's top-level commands, so a
        command the program adds in code (the dashboard) must be in the catalog too. Every row has its one-line purpose.
        --help is not asked of every path, because the commands print their own formats: decisions its own usage, org hook
        rejects everything but its own arguments, org check-hooks runs its check; the paths that the representative jobs name
        must answer it with exit 0.
        """
        st = self.jobs.state()
        rows = st["laneboss_jobs"] + st["laneboss_groups"]
        self.assertGreater(len(rows), 40, "J1 the generated catalog must hold the whole command line")
        for row in rows:
            self.assertTrue(row["purpose"], "J1 every command path needs its one-line purpose: " + row["path"])
        listed = set(re.findall(r"^    ([a-z][a-z0-9-]*)\s{2,}\S", self.run_laneboss("--help").stdout, re.MULTILINE))
        tops = {row["path"].split()[0] for row in rows}
        self.assertEqual(listed, tops, "J1 the catalog must name every top-level command of the program and nothing else")
        self.assertIn("dashboard", st["source"]["added_in_code"], "J1 the dashboard is added in code, and the catalog must read it there")
        for path in sorted({expected for _, expected in JOBS}):
            self.assertIn(path, [row["path"] for row in rows], "J1 a job names a command that the catalog does not hold: " + path)
            self.run_laneboss(*path.split(), "--help")
        stale = self.jobs.state(self.syntax_copy(remove=["disk"]))
        stale_tops = {row["path"].split()[0] for row in stale["laneboss_jobs"] + stale["laneboss_groups"]}
        self.assertNotEqual(listed, stale_tops, "J1 the control: a catalog that lost a command must differ from the program's list")
        self.assertEqual(st["source"]["jobs"], len(st["laneboss_jobs"]))


    def test_j3_org_levels_and_roles(self):
        home = self.directory / "example-org" / ".laneboss"
        home.mkdir(parents=True)
        (home / "org.toml").write_text('schema_version = 1\nname = "example-org"\nlevels = [3, 4, 5]\n'
                                       '[roles]\nworker = ["lane start", "report"]\nreviewer = ["report"]\n', encoding="utf-8")
        org = self.jobs.state(org=self.directory / "example-org")["org"]
        self.assertEqual(org, {"name": "example-org", "levels": [3, 4, 5],
                               "roles": {"worker": ["lane start", "report"], "reviewer": ["report"]}})
        self.assertEqual(self.jobs.state()["org"], {"levels": [], "roles": {}}, "J3 the control: no org, no levels or roles")

    def test_j4_every_job_names_its_command(self):
        """Stand-in answers: the state, the options, the answer check and the output (not the model's accuracy)."""
        st = self.jobs.state()
        self.assertEqual(check_jobs(self.jobs, st), [], "J4 every job must name its command and no control may be flagged")
        purposes = {}
        data = json.loads(self.syntax.read_text(encoding="utf-8"))
        for node in data["commands"]:
            for child in node.get("commands", []):
                purposes[node["name"] + " " + child["name"]] = (child.get("description") or child.get("help") or "").rstrip(".")
        out = self.jobs.flag(JOBS[4][0], st, stand_in("lane stop", st))
        self.assertIn(purposes["lane stop"], out["reason"], "J4 the reason comes from the catalog's own purpose text")
        with self.assertRaises(ValueError, msg="J4 an answer outside the generated options must be refused"):
            self.jobs.flag("tmux kill-session -t x", st, stand_in("lane obliterate", st))
        low = self.jobs.flag("tmux kill-session -t x", st, stand_in("lane stop", st, owned=0.1))
        self.assertFalse(low["flagged"], "J4 a low Noul keeps a named command from being flagged")

    def test_j5_a_stale_catalog_fails_its_row(self):
        """The mutant: one command removed from the catalog. The jobs that need it fail; the others and the real catalog pass."""
        self.assertEqual(check_jobs(self.jobs, self.jobs.state()), [], "J5 the control: the real catalog passes")
        stale = self.jobs.state(self.syntax_copy(remove=["lane stop"]))
        self.assertNotIn("lane stop", [row["path"] for row in stale["laneboss_jobs"]])
        failing = check_jobs(self.jobs, stale)
        self.assertEqual({command for command, _ in failing}, {command for command, expected in JOBS if expected == "lane stop"},
                         "J5 exactly the jobs that need the removed command must fail")
        self.assertGreater(len(failing), 1)

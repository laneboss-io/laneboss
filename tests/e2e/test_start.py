"""laneboss start: the briefing a supervisor reads when its session begins.

A. Without a configuration the command lists them, an unreadable one included, and touches nothing.
B. With lanes in every state the briefing puts each lane in its group, in text and in json, and changes nothing.
C. The protocol and the rules files carry the hashes that a rendered brief records.
D. Binding: LANEBOSS_CONFIG, a conflicting --config, an undefined role, a configuration that was never used.
E. A description that looks like a credential is withheld.
F. The headings of the text form and the top-level keys of the json form are exactly the documented ones.
G. The whole suite passes (a run on the test machine, not a test of this file).

The last tests cover the rest of the contract: the last twenty events, the counts of waiting and refused events, and
the read-only checks agreeing with doctor. Every assertion goes through the installed command.

Follow-up 1, the briefing carries the text of the standing rules:
H. Each rules file's exact text is in the json form, and every line of it, indented by four spaces, follows its line in
   the text form.
I. A rules file with lines that start with `#` adds no heading to the briefing.
J. A rules file that holds a credential: the configuration loader refuses it before a briefing is built (exit 2), and
   the string is nowhere in the output.
K. The tree comparisons, with rules files present and with a store, show that nothing was created or changed.

Levels:
L. The Role section names the level of the chosen entry (`- Level: L5 (top supervisor)`, no `- Kind:` line; in json
   `level` and `level_name` and no `role` key in `role.entry`), also for an entry written with the old `role` key.
"""

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import subprocess
import time

from . import lanesupport, support

TITLE = "# Laneboss session briefing"
SECTIONS = ["Configuration", "Protocol", "Standing rules", "Role", "Checks", "Lanes", "Recent events",
            "Not known to the launcher"]
KEYS = ["checks", "configuration", "events", "lanes", "protocol", "role", "rules", "unknown"]
UNKNOWN = "Open questions to the owner and due dates are not in the store yet."
GROUPS = {"running": "Running", "ended": "Ended, waiting for the supervisor",
          "accepted": "Accepted or merged, not yet cleaned", "lost": "Lost or declared gone"}
DESCRIPTION_LINE = 'description = "Invented configuration for the launcher\'s black-box tests."'
# The fixture's one [supervisors] entry: the two lines that the level tests replace.
ENTRY = 'level = 5\nrunner = "local"'
GONE = "declared gone, no end recorded"
NOT_ACCEPTED = "not accepted; a typed value is never repeated here, see the usage line above or run with --help"
LANE_LINE = re.compile(
    r"- (?P<lane>\S+): run (?P<run>\d+), runner (?P<runner>\S+), model (?P<model>\S+), account (?P<account>\S+); "
    r"last end: (?:reason (?P<reason>\S+), exit code (?P<exit_code>\S+), survivors (?P<survivors>\S+)"
    r"|(?P<gone>" + GONE + r")); "
    r"state (?P<state>\S+) since (?P<since>\S+); times: (?P<times>.+?)(?:; landing: (?P<landing>.+))?")
# Follow-up 2. The installed program runs unchanged under an interpreter whose sqlite3 connections stop once, after
# the first read of the lane rows or of the events that is made outside a transaction (the reader's own reads, not
# the checks' transactions), until the test lets them go. Between that read and the next the test appends an event
# with the real writer.
PAUSE_AFTER_FIRST_READ = '''import os, runpy, sqlite3, sys, time
reached, go = os.environ["E2E_PAUSE_REACHED"], os.environ["E2E_PAUSE_GO"]
real_connect = sqlite3.connect
paused = []


class Cursor(sqlite3.Cursor):
    def fetchall(self):
        rows = super().fetchall()
        sql = getattr(self, "e2e_sql", "")
        if not paused and not self.connection.in_transaction and ("FROM lanes" in sql or "FROM events" in sql):
            paused.append(True)
            open(reached, "w").close()
            deadline = time.monotonic() + 40
            while not os.path.exists(go) and time.monotonic() < deadline:
                time.sleep(0.05)
        return rows


class Connection(sqlite3.Connection):
    def cursor(self, factory=Cursor):
        return super().cursor(factory)

    def execute(self, sql, parameters=()):
        cursor = self.cursor()
        cursor.e2e_sql = sql
        return cursor.execute(sql, parameters)


def connect(*arguments, **options):
    options["factory"] = Connection
    return real_connect(*arguments, **options)


sqlite3.connect = connect
launch = sys.argv[1]
sys.argv = [launch] + sys.argv[2:]
runpy.run_path(launch, run_name="__main__")
'''
EVENT_LINE = re.compile(r"- seq (\d+), (\S+), lane (\S+), (\S+)")
RULE_LINE = re.compile(r"- (\S+): sha256 ([0-9a-f]{64})")
# Rules files with blank lines, an indented line, non-ASCII text and lines that start with `#`; the second has no
# line end at its end.
STANDING_TEXT = ("# Standing rules for the test\n"
                 "\n"
                 "## A second-level heading in a rules file\n"
                 "\n"
                 "- Name every branch after its lane.\n"
                 "  An indented continuation line.\n"
                 "\n"
                 "### Non-ASCII stays: é中\n"
                 "Last line.\n")
WEB_TEXT = "# Project rules: web\n\n1. Keep the release list current.\n2. A last line without a line end."


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def tree(root):
    """Every path below root with its kind, size and, for a file, its SHA-256."""
    found = {}
    for directory, names, files in os.walk(str(root)):
        for name in names + files:
            path = Path(directory) / name
            info = path.lstat()
            relative = str(path.relative_to(root))
            if stat.S_ISREG(info.st_mode):
                found[relative] = ("file", info.st_size, hashlib.sha256(path.read_bytes()).hexdigest())
            elif stat.S_ISDIR(info.st_mode):
                found[relative] = ("directory",)
            else:
                found[relative] = ("other", stat.S_IFMT(info.st_mode))
    return found


def names(root):
    """The paths below root, without the temporary names other processes use while they write a file whole."""
    return sorted(path for path in tree(root) if not Path(path).name.startswith(".tmp-"))


def headings(text):
    return [line for line in text.splitlines() if line.startswith("#")]


def indented(content):
    """The lines of a text as the briefing shows them: indented by four spaces, blank lines blank."""
    lines = content.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [("    " + line) if line.strip() else "" for line in lines]


def section(text, title):
    """The lines of the `## title` section of a briefing, up to the next heading."""
    lines = text.splitlines()
    body = []
    for line in lines[lines.index("## " + title) + 1:]:
        if line.startswith("#"):
            break
        body.append(line)
    return body


def value(word):
    return None if word == "none" else int(word) if word.isdigit() else word


def text_lanes(text):
    """The lanes of the text form: {group: [fields of each lane]}, each group's count checked against its lines."""
    found = {group: [] for group in GROUPS}
    current = None
    counts = {}
    for line in section(text, "Lanes"):
        label = re.fullmatch(r"(.+) \(([0-9]+)\):", line)
        if label:
            current = next(group for group, words in GROUPS.items() if words == label.group(1))
            counts[current] = int(label.group(2))
        elif line.startswith("- "):
            match = LANE_LINE.fullmatch(line)
            if match is None:
                raise AssertionError("a lane line is not in the documented form: " + line)
            fields = {key: value(word) for key, word in match.groupdict().items()
                      if key not in ("times", "landing", "gone") and word is not None}
            fields["gone"] = match.group("gone") is not None
            fields["landing"] = match.group("landing")
            fields["times"] = {} if match.group("times") == "none" else dict(
                pair.split(" ") for pair in match.group("times").split(", "))
            found[current].append(fields)
    for group, number in counts.items():
        if number != len(found[group]):
            raise AssertionError("group {} says {} lanes and lists {}".format(group, number, len(found[group])))
    if sorted(counts) != sorted(GROUPS):
        raise AssertionError("the four groups are not all there: " + str(sorted(counts)))
    return found


class StartTest(support.LauncherTest):
    def briefing(self, *arguments, config="alpha", code=0, environment=None):
        return self.run_laneboss("start", "--config", config, *arguments, code=code, environment=environment)

    def briefing_json(self, *arguments, config="alpha"):
        return json.loads(self.briefing("--format", "json", *arguments, config=config).stdout)

    def described(self, name, description):
        return self.write_config(name, replace=((DESCRIPTION_LINE, 'description = "{}"'.format(description)),))

    # A. No configuration given.

    def test_listing_without_a_configuration(self):
        self.described("alpha", "The first invented company.")
        self.described("beta", "The second invented company.")
        broken = self.home / "configs" / "gamma"
        broken.mkdir()
        (broken / "config.toml").write_text('name = = "gamma\n', encoding="utf-8")
        before = tree(self.directory)
        result = self.run_laneboss("start")
        self.assertEqual(tree(self.directory), before, "the listing changed the file tree")
        self.assertEqual(result.stderr, "")
        lines = result.stdout.splitlines()
        by_name = {name: next(line for line in lines if line.startswith("- " + name)) for name in
                   ("alpha", "beta", "gamma")}
        self.assertIn("The first invented company.", by_name["alpha"])
        self.assertIn("The second invented company.", by_name["beta"])
        self.assertIn("unreadable", by_name["gamma"])
        self.assertNotIn("unreadable", by_name["alpha"] + by_name["beta"])
        self.assertTrue(any("--config" in line and "LANEBOSS_CONFIG" in line for line in lines),
                        "no line says how to choose a configuration")
        self.assertEqual(len([line for line in lines if line.startswith("#")]), 1, "the listing is not a briefing")
        self.assertFalse(any(line.startswith("## ") for line in lines))

    def test_listing_reads_no_state(self):
        self.write_config("alpha")
        state = self.state_home / "alpha"
        state.mkdir()
        (state / ".laneboss-state").write_text("this is not a marker\n", encoding="utf-8")
        (state / "events.sqlite").write_bytes(b"this is not a store")
        before = tree(self.directory)
        result = self.run_laneboss("start")
        self.assertIn("alpha", result.stdout)
        self.assertEqual(tree(self.directory), before)

    def test_listing_shows_one_clean_line(self):
        # TOML escapes: a line separator, a C1 control character and an escape inside one description.
        self.described("alpha", "first\\u2028second\\u009bthird\\u001bfourth\\nfifth")
        result = self.run_laneboss("start")
        self.assertIn("- alpha: first second third fourth fifth", result.stdout.splitlines())
        for character in (" ", "\u009b", "\x1b"):
            self.assertNotIn(character, result.stdout)
        found = json.loads(self.run_laneboss("start", "--format", "json").stdout)["configurations"]
        self.assertEqual(found[0]["description"], "first second third fourth fifth")

    def test_listing_in_json(self):
        self.described("alpha", "The first invented company.")
        broken = self.home / "configs" / "gamma"
        broken.mkdir()
        (broken / "config.toml").write_text("not = [valid\n", encoding="utf-8")
        before = tree(self.directory)
        listing = json.loads(self.run_laneboss("start", "--format", "json").stdout)
        self.assertEqual(tree(self.directory), before)
        found = {item["name"]: item for item in listing["configurations"]}
        self.assertEqual(sorted(found), ["alpha", "gamma"])
        self.assertEqual((found["alpha"]["readable"], found["alpha"]["description"]),
                         (True, "The first invented company."))
        self.assertIs(found["gamma"]["readable"], False)
        self.assertIsNone(found["gamma"]["description"])
        self.assertIn("--config", listing["choose"])

    def test_empty_environment_counts_as_unset(self):
        self.write_config("alpha")
        environment = dict(self.environment, LANEBOSS_CONFIG="")
        result = self.run_laneboss("start", environment=environment)
        self.assertNotIn(TITLE, result.stdout)
        self.assertIn("alpha", result.stdout)

    # B. Lanes in every state.

    # C. The hashes a rendered brief records.

    def test_hashes_match_a_rendered_brief(self):
        self.write_config("alpha")
        brief = self.directory / "brief.md"
        brief.write_text("# Brief\n\nSay hello.\n", encoding="utf-8")
        self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "c-lane", "--in", brief, "--out",
                          self.directory / "rendered.md", "--project", "web")
        rendered = [item for item in self.events() if item["kind"] == "brief.rendered"]
        self.assertEqual(len(rendered), 1)
        inputs = rendered[0]["payload"]["inputs"]
        protocol = next(item for item in inputs if item["role"] == "protocol")
        rules = [(item["path"], item["sha256"]) for item in inputs if item["role"] == "rules"]
        configuration = self.home / "configs" / "alpha"
        self.assertEqual(rules, [("rules/standing.md", support.digest((configuration / "rules" / "standing.md")
                                                                      .read_bytes())),
                                 ("rules/web.md", support.digest((configuration / "rules" / "web.md").read_bytes()))])
        self.assertEqual(protocol["sha256"], support.digest(support.PROTOCOL_FILE.read_bytes()))

        briefing = self.briefing_json("--role", "top")
        self.assertEqual(briefing["protocol"]["version"], protocol["version"])
        self.assertEqual(briefing["protocol"]["sha256"], protocol["sha256"])
        self.assertEqual(briefing["protocol"]["text"], support.PROTOCOL_FILE.read_text(encoding="utf-8"))
        self.assertEqual([(item["path"], item["sha256"]) for item in briefing["rules"]], rules)

        text = self.briefing("--role", "top").stdout
        body = section(text, "Protocol")
        self.assertIn("- Version: " + protocol["version"], body)
        self.assertIn("- SHA-256: " + protocol["sha256"], body)
        for line in support.PROTOCOL_FILE.read_text(encoding="utf-8").splitlines():
            if line.strip():
                self.assertIn("    " + line, body, "the protocol text is not in the briefing")
        self.assertEqual(RULE_LINE.findall("\n".join(section(text, "Standing rules"))), rules)

        # Without a role only the configuration's own rules files are listed.
        alone = self.briefing_json()
        self.assertEqual([(item["path"], item["sha256"]) for item in alone["rules"]], rules[:1])

    def test_role_entry(self):
        self.write_config("alpha", tail='\n[supervisors.second]\nlevel = 4\nrunner = "local"\n')
        briefing = self.briefing_json("--role", "top")
        self.assertEqual(briefing["role"]["selected"], "top")
        self.assertEqual(briefing["role"]["defined"], ["second", "top"])
        self.assertEqual(briefing["role"]["entry"], {"level": 5, "level_name": "top supervisor", "runner": "local",
                                                     "projects": ["web"], "owner_channel": "chat",
                                                     "description": None})
        lines = section(self.briefing("--role", "top").stdout, "Role")
        body = "\n".join(lines)
        for words in ("Role: top", "Runner: local", "Projects: web", "Owner channel: chat"):
            self.assertIn(words, body)
        self.assertIn("- Level: L5 (top supervisor)", lines)
        self.assertEqual([line for line in lines if line.startswith("- Kind")], [])
        chosen = self.briefing_json("--role", "second")["role"]["entry"]
        self.assertEqual((chosen["level"], chosen["level_name"], chosen["projects"], chosen["owner_channel"]),
                         (4, "mini-supervisor", [], None))
        free = self.briefing_json()
        self.assertEqual((free["role"]["selected"], free["role"]["entry"], free["role"]["defined"]),
                         (None, None, ["second", "top"]))
        body = "\n".join(section(self.briefing().stdout, "Role"))
        self.assertIn("second", body)
        self.assertIn("top", body)

    # L. The levels in the Role section.

    def test_role_section_names_the_level(self):
        # `top` stays at level 5, which the project's landing_authority needs; the entry under test is `second`.
        for level, name in ((4, "mini-supervisor"), (5, "top supervisor"), (6, "super top")):
            with self.subTest(level=level):
                self.write_config("alpha", tail='\n[supervisors.second]\nlevel = {}\nrunner = "local"\n'.format(level))
                lines = section(self.briefing("--role", "second").stdout, "Role")
                self.assertIn("- Level: L{} ({})".format(level, name), lines)
                self.assertEqual([line for line in lines if line.startswith("- Kind")], [])
                entry = self.briefing_json("--role", "second")["role"]["entry"]
                self.assertEqual((entry["level"], entry["level_name"]), (level, name))
                self.assertNotIn("role", entry)

    def test_old_spelling_shows_its_level(self):
        """An entry with `role = "top"` or `role = "mini"` is read as level 5 or 4, and the briefing says so."""
        self.write_config("alpha", replace=((ENTRY, ENTRY.replace("level = 5", 'role = "top"')),),
                          tail='\n[supervisors.second]\nrole = "mini"\nrunner = "local"\n')
        for role, level, name in (("top", 5, "top supervisor"), ("second", 4, "mini-supervisor")):
            with self.subTest(role=role):
                lines = section(self.briefing("--role", role).stdout, "Role")
                self.assertIn("- Level: L{} ({})".format(level, name), lines)
                self.assertEqual([line for line in lines if line.startswith("- Kind")], [])
                entry = self.briefing_json("--role", role)["role"]["entry"]
                self.assertEqual((entry["level"], entry["level_name"]), (level, name))
                self.assertNotIn("role", entry)

    # H to K. The text of the standing rules.

    def write_rules(self, standing, web):
        directory = self.home / "configs" / "alpha" / "rules"
        for name, data in (("standing.md", standing), ("web.md", web)):
            (directory / name).write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))

    def test_rules_text_in_json(self):
        self.write_config("alpha")
        self.write_rules(STANDING_TEXT, WEB_TEXT)
        for stored in (False, True):
            if stored:
                self.append(self.event("note.added", payload={"text": "one"}))
            before = tree(self.directory)
            briefing = self.briefing_json("--role", "top")
            alone = self.briefing_json()
            self.briefing("--role", "top")
            self.assertEqual(tree(self.directory), before, "the briefing created or changed something")
            self.assertEqual([item["path"] for item in briefing["rules"]], ["rules/standing.md", "rules/web.md"])
            for item, content in zip(briefing["rules"], (STANDING_TEXT, WEB_TEXT)):
                self.assertIn("text", item)
                self.assertEqual(item["text"], content)
                self.assertEqual(item["sha256"], support.digest(content.encode("utf-8")))
                self.assertEqual(sorted(item), ["path", "sha256", "text"])
            # Without a role only the configuration's own file is there.
            self.assertEqual([(item["path"], item["text"]) for item in alone["rules"]],
                             [("rules/standing.md", STANDING_TEXT)])

    def test_rules_text_in_text_form(self):
        self.write_config("alpha")
        self.write_rules(STANDING_TEXT, WEB_TEXT)
        for stored in (False, True):
            if stored:
                self.append(self.event("note.added", payload={"text": "one"}))
            before = tree(self.directory)
            text = self.briefing("--role", "top").stdout
            self.assertEqual(tree(self.directory), before, "the briefing created or changed something")
            body = section(text, "Standing rules")
            standing = "- rules/standing.md: sha256 " + support.digest(STANDING_TEXT.encode("utf-8"))
            web = "- rules/web.md: sha256 " + support.digest(WEB_TEXT.encode("utf-8"))
            first, second = body.index(standing), body.index(web)
            # One sentence above the first file says that the texts follow indented.
            sentence = [line for line in body[:first] if line.strip()]
            self.assertEqual(len(sentence), 1, body[:first])
            self.assertIn("indented", sentence[0])
            # Each file's line is followed by its lines, then one blank line, then the next file's line (or the
            # blank line that ends the section).
            self.assertEqual(body[first + 1:second], indented(STANDING_TEXT) + [""])
            self.assertEqual(body[second + 1:], indented(WEB_TEXT) + [""])
            # The role's project file is listed only with the role.
            alone = section(self.briefing().stdout, "Standing rules")
            self.assertNotIn(web, alone)
            self.assertEqual(alone[alone.index(standing) + 1:], indented(STANDING_TEXT) + [""])

    def test_rules_headings_stay_out(self):
        self.write_config("alpha")
        self.write_rules(STANDING_TEXT, WEB_TEXT)
        wanted = [TITLE] + ["## " + title for title in SECTIONS]
        for arguments in ((), ("--role", "top")):
            with self.subTest(arguments=arguments):
                text = self.briefing(*arguments).stdout
                self.assertEqual(headings(text), wanted)
                lines = text.splitlines()
                for heading in ("# Standing rules for the test", "## A second-level heading in a rules file",
                                "### Non-ASCII stays: é中"):
                    self.assertNotIn(heading, lines)
                    self.assertIn("    " + heading, lines)

    def test_credential_in_rules_is_refused(self):
        token = "gh" + "p_" + "Q1w2E3r4T5y6U7i8O9p0" + "A1s2D3f4G5"
        self.write_config("alpha")
        for name, standing, web in (
                ("rules/standing.md", "# Rules\n\n- Deploy with {} today.\n".format(token), WEB_TEXT),
                ("rules/web.md", STANDING_TEXT, "# Web\n\n- Use {} here.\n".format(token))):
            self.write_rules(standing, web)
            for arguments in ((), ("--role", "top"), ("--format", "json")):
                with self.subTest(file=name, arguments=arguments):
                    result = self.briefing(*arguments, code=2)
                    self.assertEqual(result.stdout, "")
                    self.assertTrue(result.stderr.startswith("invalid configuration:"), result.stderr)
                    self.assertIn(name, result.stderr)
                    self.assertIn("credential", result.stderr)
                    self.assertNotIn(token, result.stdout + result.stderr)
        # The listing reads no rules file, so the string is not printed there either.
        listing = self.run_laneboss("start")
        self.assertNotIn(token, listing.stdout + listing.stderr)
        self.assertFalse((self.state_home / "alpha").exists())

    # Follow-up 2. The briefing states only what the store supports.

    def lane_event(self, kind, lane, payload=None):
        self.append(self.event(kind, lane=lane, payload={} if payload is None else payload))

    def started(self, lane, run=1, how="start"):
        if getattr(self, "paths_of_alpha", None) is None:
            self.paths_of_alpha = self.laneboss_json("config", "path", "alpha")
        self.lane_event("lane.started", lane, support.started_payload(self.paths_of_alpha, lane, run=run, how=how))

    def ended(self, lane, run=1, **changes):
        self.lane_event("lane.ended", lane, dict(support.ended_payload(run=run), **changes))

    def mark(self, lane, *flags):
        self.run_laneboss("lane", "mark", "--config", "alpha", "--lane", lane, *flags)

    def test_unsound_store_is_refused(self):
        self.write_config("alpha")
        self.started("a-lane")
        self.ended("a-lane")
        with closing(sqlite3.connect(str(self.state_home / "alpha" / "events.sqlite"))) as connection:
            [(stored,)] = connection.execute("SELECT projection FROM lanes WHERE lane = 'a-lane'").fetchall()
            projection = json.loads(stored)
            projection["state"] = "accepted"
            connection.execute("UPDATE lanes SET projection = ? WHERE lane = 'a-lane'",
                               (json.dumps(projection, sort_keys=True, separators=(",", ":")),))
            connection.commit()
        self.run_laneboss("state", "verify", "--config", "alpha", code=3)
        for arguments in ((), ("--format", "json"), ("--role", "top")):
            with self.subTest(arguments=arguments):
                result = self.briefing(*arguments, code=3)
                self.assertEqual(result.stdout, "", "a briefing was printed from a store that does not verify")
                self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
                self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)
                self.assertIn("store.recorded", result.stderr)
                self.assertIn("laneboss state verify --config alpha", result.stderr)

    def test_one_snapshot_of_the_store(self):
        self.write_config("alpha")
        self.started("b-one")
        python, launch = self.python_and_launch()
        wrapper = self.directory / "pause-after-first-read.py"
        wrapper.write_text(PAUSE_AFTER_FIRST_READ, encoding="utf-8")
        reached, go = self.directory / "reader-reached", self.directory / "reader-go"
        environment = dict(self.environment, E2E_PAUSE_REACHED=str(reached), E2E_PAUSE_GO=str(go))
        reader = subprocess.Popen([python, "-I", "-B", str(wrapper), launch, "start", "--config", "alpha", "--format",
                                   "json"], cwd=str(self.directory), env=environment, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 60
            while not reached.exists() and reader.poll() is None:
                self.assertLess(time.monotonic(), deadline, "the reader never reached its first read")
                time.sleep(0.05)
            # A real writer appends the end of the running lane while the reader waits between its reads.
            self.ended("b-one", exit_code=7, survivors=2)
        finally:
            go.write_text("go\n", encoding="utf-8")
        stdout, stderr = reader.communicate(timeout=60)
        self.assertEqual(reader.returncode, 0, stderr)
        self.assertTrue(reached.exists(), "the test never stopped the reader between its reads")
        briefing = json.loads(stdout)
        recent = briefing["events"]["recent"]
        shown = [item for item in recent if item["kind"] == "lane.ended" and item["lane"] == "b-one"]
        groups = {group: [item["lane"] for item in briefing["lanes"][group]] for group in GROUPS}
        self.assertEqual(sum(lanes.count("b-one") for lanes in groups.values()), 1, groups)
        self.assertEqual(briefing["events"]["total"], len(recent))
        if shown:
            self.assertEqual(groups["ended"], ["b-one"], "the end is among the events but the lane is not ended")
            [item] = briefing["lanes"]["ended"]
            self.assertEqual((item["run"], item["reason"], item["exit_code"], item["survivors"]), (1, "exit", 7, 2))
            self.assertEqual(briefing["events"]["total"], 2)
        else:
            self.assertEqual(groups["running"], ["b-one"], "the lane is not running but its end is not among the events")
            [item] = briefing["lanes"]["running"]
            self.assertEqual((item["reason"], item["exit_code"], item["survivors"]), (None, None, None))
            self.assertEqual(briefing["events"]["total"], 1)
        self.assertEqual([item["kind"] for item in self.events()], ["lane.started", "lane.ended"])

    def python_and_launch(self):
        exec_line = [line for line in self.command.read_text(encoding="utf-8").splitlines()
                     if line.startswith("exec ")][0]
        words = shlex.split(exec_line)
        return words[1], words[4]

    def test_latest_run_end_is_shown(self):
        self.write_config("alpha")
        self.started("b-two")
        self.ended("b-two", exit_code=0, survivors=0)
        self.lane_event("lane.resumed", "b-two", {"run": 2, "after": "exit", "message": None})
        self.started("b-two", run=2, how="resume")
        self.ended("b-two", run=2, exit_code=5, survivors=3)
        briefing = self.briefing_json()
        [item] = briefing["lanes"]["ended"]
        self.assertEqual((item["lane"], item["run"], item["reason"], item["exit_code"], item["survivors"]),
                         ("b-two", 2, "exit", 5, 3))
        [line] = text_lanes(self.briefing().stdout)["ended"]
        self.assertEqual((line["run"], line["reason"], line["exit_code"], line["survivors"]), (2, "exit", 5, 3))

    def test_groups_are_truthful(self):
        self.write_config("alpha")
        for lane in ("c-run", "c-end", "c-acc", "c-mrg", "c-cln", "c-lost", "c-gone", "c-abn"):
            self.started(lane)
        self.lane_event("lane.planned", "c-plan")
        for lane in ("c-end", "c-acc", "c-mrg", "c-cln", "c-abn"):
            self.ended(lane)
        self.lane_event("lane.lost", "c-lost", {"run": 1, "survivors": 2})
        self.lane_event("lane.gone", "c-gone", {"run": 1, "launch": "0" * 31 + "1"})
        self.mark("c-acc", "--state", "accepted")
        self.mark("c-acc", "--landing", "merged")
        self.mark("c-mrg", "--state", "accepted")
        self.mark("c-mrg", "--state", "merged")
        self.mark("c-cln", "--state", "merged")
        self.lane_event("lane.cleaned", "c-cln", {"removed": [], "kept": [
            {"item": "lane-directory", "path": "/srv/example/lanes/c-cln", "why": "record"}]})
        self.mark("c-abn", "--state", "abandoned")
        rows = {row["lane"]: row for row in self.laneboss_json("state", "lanes", "--config", "alpha")}
        self.assertEqual({lane: row["state"] for lane, row in rows.items()},
                         {"c-run": "running", "c-end": "verifying", "c-acc": "accepted", "c-mrg": "merged",
                          "c-cln": "merged", "c-lost": "verifying", "c-gone": "verifying", "c-abn": "abandoned",
                          "c-plan": "queued"})
        before = tree(self.directory)
        briefing = self.briefing_json()
        text = self.briefing().stdout
        self.assertEqual(tree(self.directory), before)
        groups = {group: [item["lane"] for item in briefing["lanes"][group]] for group in GROUPS}
        self.assertEqual(groups, {"running": ["c-run"], "ended": ["c-end"], "accepted": ["c-acc", "c-mrg"],
                                  "lost": ["c-gone", "c-lost"]})
        # Every lane of the store is in exactly one group or counted in `others`.
        listed = [lane for lanes in groups.values() for lane in lanes]
        self.assertEqual(len(listed), len(set(listed)))
        self.assertEqual(len(listed) + briefing["lanes"]["others"], len(rows))
        self.assertEqual(briefing["lanes"]["others"], 3)
        items = {item["lane"]: item for group in GROUPS for item in briefing["lanes"][group]}
        self.assertEqual({lane: item["gone"] for lane, item in items.items() if item["gone"]}, {"c-gone": True})
        self.assertEqual((items["c-gone"]["reason"], items["c-gone"]["survivors"]), (None, None))
        self.assertEqual((items["c-lost"]["reason"], items["c-lost"]["survivors"]), ("lost", 2))
        self.assertEqual((items["c-acc"]["state"], items["c-acc"]["landing"]["merged"] is not None), ("accepted", True))
        self.assertEqual((items["c-mrg"]["state"], items["c-mrg"]["landing"]["merged"]), ("merged", None))
        parsed = text_lanes(text)
        self.assertEqual({group: [line["lane"] for line in lines] for group, lines in parsed.items()}, groups)
        body = section(text, "Lanes")
        for label, number in (("Running", 1), ("Ended, waiting for the supervisor", 1),
                              ("Accepted or merged, not yet cleaned", 2), ("Lost or declared gone", 2)):
            self.assertIn("{} ({}):".format(label, number), body)
        accepted = {line["lane"]: line for line in parsed["accepted"]}
        self.assertEqual((accepted["c-acc"]["state"], accepted["c-mrg"]["state"]), ("accepted", "merged"))
        self.assertTrue(accepted["c-acc"]["landing"].startswith("merged "), accepted["c-acc"])
        self.assertEqual(accepted["c-mrg"]["landing"], "none")
        lost = {line["lane"]: line for line in parsed["lost"]}
        self.assertIs(lost["c-gone"]["gone"], True)
        self.assertIs(lost["c-lost"]["gone"], False)
        self.assertEqual((lost["c-lost"]["reason"], lost["c-lost"]["survivors"]), ("lost", 2))
        [gone_line] = [line for line in body if line.startswith("- c-gone:")]
        self.assertIn(GONE, gone_line)
        self.assertNotIn("reason none", gone_line)
        self.assertIn("Lanes in none of these groups (queued, merged or abandoned): 3", body)

    def test_credential_name_withheld(self):
        secret = "glpat-" + "abcdefghijklmnopqrst"
        self.write_config("alpha")
        self.write_config(secret)
        before = tree(self.directory)
        for arguments in ((), ("--format", "json")):
            with self.subTest(arguments=arguments):
                result = self.run_laneboss("start", *arguments)
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertIn("[withheld]", result.stdout)
                self.assertIn("alpha", result.stdout)
        text = self.run_laneboss("start").stdout
        [line] = [line for line in text.splitlines() if line.startswith("- [withheld]")]
        self.assertIn("looks like a credential", line)
        found = {item["name"]: item for item in json.loads(self.run_laneboss("start", "--format", "json").stdout)
                 ["configurations"]}
        self.assertEqual(sorted(found), ["[withheld]", "alpha"])
        self.assertEqual((found["[withheld]"]["name_withheld"], found["alpha"]["name_withheld"]), (True, False))
        self.assertEqual(tree(self.directory), before)
        # A neighbour that cannot be read is a warning of the briefing, which names it only as [withheld].
        (self.home / "configs" / secret / "config.toml").write_text("not = [valid\n", encoding="utf-8")
        for arguments in ((), ("--format", "json")):
            with self.subTest(neighbour=arguments):
                result = self.briefing(*arguments)
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertIn("[withheld]", result.stdout)

    def test_credential_role_withheld(self):
        secret = "glpat-" + "abcdefghijklmnopqrst"
        self.write_config("alpha")
        before = tree(self.directory)
        for arguments in (("--role", secret), ("--format", "json", "--role", secret)):
            with self.subTest(arguments=arguments):
                result = self.run_laneboss("start", *arguments)
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertIn("--role [withheld]", result.stdout)
        self.assertEqual(tree(self.directory), before)
        for arguments in (("--role", secret), ("--format", "json", "--role", secret)):
            with self.subTest(config=arguments):
                result = self.briefing(*arguments, code=2)
                self.assertEqual(result.stdout, "")
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertIn("[withheld]", result.stderr)
                self.assertIn("top", result.stderr)

    def test_binding_error_withholds_name(self):
        # The binding is every command's: a name that passes the grammar but looks like a credential is not repeated.
        secret = "glpat-" + "abcdefghijklmnopqrst"
        self.write_config("alpha")
        with_secret = dict(self.environment, LANEBOSS_CONFIG=secret)
        with_alpha = dict(self.environment, LANEBOSS_CONFIG="alpha")

        def refused(*arguments, environment=None):
            result = self.run_laneboss(*arguments, code=2, environment=environment)
            self.assertEqual(result.stdout, "")
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertIn("[withheld]", result.stderr)
            return result

        for arguments in (("start", "--config", secret), ("start", "--config", secret, "--format", "json"),
                          ("state", "events", "--config", secret)):
            with self.subTest(arguments=arguments):
                refused(*arguments)
        # LANEBOSS_CONFIG alone, and in conflict with --config in both directions.
        for arguments, environment in ((("start",), with_secret), (("start", "--format", "json"), with_secret),
                                       (("start", "--config", "alpha"), with_secret),
                                       (("start", "--config", secret), with_alpha),
                                       (("state", "events", "--config", "alpha"), with_secret)):
            with self.subTest(arguments=arguments, environment=environment["LANEBOSS_CONFIG"]):
                refused(*arguments, environment=environment)
        # An ordinary unknown name, and an ordinary conflict, are repeated as before.
        for arguments in (("start", "--config", "no-such-config"), ("state", "events", "--config", "no-such-config")):
            with self.subTest(ordinary=arguments):
                result = self.run_laneboss(*arguments, code=2)
                self.assertIn("no-such-config", result.stderr)
                self.assertNotIn("[withheld]", result.stderr)
        conflict = self.run_laneboss("start", "--config", "alpha", code=2,
                                     environment=dict(self.environment, LANEBOSS_CONFIG="beta-two"))
        self.assertIn("--config alpha conflicts with LANEBOSS_CONFIG=beta-two", conflict.stderr)
        self.assertNotIn("[withheld]", conflict.stderr)

    def test_guard_message_withholds_name(self):
        secret = "glpat-" + "abcdefghijklmnopqrst"
        self.write_config("alpha")
        with_secret = dict(self.environment, LANEBOSS_CONFIG=secret)
        with_alpha = dict(self.environment, LANEBOSS_CONFIG="alpha")
        for arguments, environment in ((("config", "show", "alpha"), with_secret),
                                       (("config", "validate", "alpha"), with_secret),
                                       (("config", "show", secret), with_alpha),
                                       (("config", "path", secret), with_alpha)):
            with self.subTest(arguments=arguments, environment=environment["LANEBOSS_CONFIG"]):
                result = self.run_laneboss(*arguments, code=2, environment=environment)
                self.assertEqual(result.stdout, "")
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertIn("[withheld]", result.stderr)
        # Ordinary names are repeated as before.
        result = self.run_laneboss("config", "show", "alpha", code=2,
                                   environment=dict(self.environment, LANEBOSS_CONFIG="beta-two"))
        self.assertIn("this session is bound to LANEBOSS_CONFIG=beta-two; reading configuration alpha is refused",
                      result.stderr)

    def test_validation_label_withholds_name(self):
        # An existing configuration whose own name looks like a credential, and whose content is invalid: the label of
        # its validation errors, and the directory name an error quotes, do not repeat the name.
        secret = "glpat-" + "abcdefghijklmnopqrst"
        self.write_config("alpha")
        mismatch = (('name = "{}"'.format(secret), 'name = "other"'),)
        variants = (("credential-shaped name inside", {}),
                    ("name differs from the directory", {"replace": mismatch}),
                    ("unknown key", {"replace": mismatch, "top": 'colour = "red"'}))
        for label, options in variants:
            self.fresh_config(secret, **options)
            for arguments in (("start", "--config", secret), ("config", "validate", secret), ("config", "show", secret)):
                with self.subTest(variant=label, arguments=arguments):
                    result = self.run_laneboss(*arguments, code=2)
                    self.assertEqual(result.stdout, "")
                    self.assertTrue(result.stderr.startswith("invalid configuration:"), result.stderr)
                    self.assertNotIn(secret, result.stdout + result.stderr)
                    self.assertIn("[withheld]", result.stderr)
        # An ordinary name is repeated as before.
        self.fresh_config("beta-two", replace=(('name = "beta-two"', 'name = "other"'),))
        result = self.run_laneboss("config", "validate", "beta-two", code=2)
        self.assertIn('configuration beta-two: config.toml: name: must equal the directory name "beta-two"',
                      result.stderr)

    def test_available_list_withholds_name(self):
        secret = "glpat-" + "abcdefghijklmnopqrst"
        self.write_config("alpha")
        self.write_config(secret)
        for arguments in (("start", "--config", "no-such-config"), ("config", "show", "no-such-config"),
                          ("state", "events", "--config", "no-such-config"), ("state", "events")):
            with self.subTest(arguments=arguments):
                result = self.run_laneboss(*arguments, code=2)
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertIn("configurations: alpha, [withheld]", result.stderr)
        # The ordinary unknown name is repeated as before.
        result = self.run_laneboss("start", "--config", "no-such-config", code=2)
        self.assertIn("no configuration named no-such-config (", result.stderr)

    def test_every_line_end_is_split(self):
        self.write_config("alpha")
        standing = (b"# Standing\r\n\r\n## After a CRLF\r\nline two\r## After a lone CR\rlast line\n## After an LF\n"
                    b"\r\n### Mixed\r## end")
        web = b"# Web\r## Second\r\n- item\r\r## Third\n- last without an end"
        self.write_rules(standing, web)
        wanted = [TITLE] + ["## " + title for title in SECTIONS]
        standing_lines = ("## After a CRLF", "## After a lone CR", "## After an LF", "### Mixed", "## end")
        web_lines = ("## Second", "## Third")
        command = [str(self.command), "start", "--config", "alpha"]
        for arguments, expected in (((), standing_lines), (("--role", "top"), standing_lines + web_lines)):
            with self.subTest(arguments=arguments):
                raw = subprocess.run(command + list(arguments), cwd=str(self.directory), env=self.environment,
                                     capture_output=True, timeout=60)
                self.assertEqual(raw.returncode, 0, raw.stderr)
                self.assertNotIn(b"\r", raw.stdout, "a carriage return reached the briefing")
                text = raw.stdout.decode("utf-8")
                self.assertEqual(headings(text), wanted)
                lines = text.split("\n")
                for line in expected:
                    self.assertNotIn(line, lines)
                    self.assertIn("    " + line, lines)
        briefing = self.briefing_json("--role", "top")
        self.assertEqual([(item["text"].encode("utf-8"), item["sha256"]) for item in briefing["rules"]],
                         [(standing, support.digest(standing)), (web, support.digest(web))])

    # D. Binding and refusals.

    def test_environment_binds_the_session(self):
        self.write_config("alpha")
        self.write_config("beta")
        environment = dict(self.environment, LANEBOSS_CONFIG="beta")
        bound = self.run_laneboss("start", "--format", "json", environment=environment)
        self.assertEqual(json.loads(bound.stdout)["configuration"]["name"], "beta")
        self.assertEqual(bound.stdout, self.briefing("--format", "json", config="beta").stdout)
        agreeing = self.run_laneboss("start", "--config", "beta", environment=environment)
        self.assertEqual(agreeing.stdout.splitlines()[0], TITLE)

    def test_conflicting_binding_is_refused(self):
        self.write_config("alpha")
        self.write_config("beta")
        environment = dict(self.environment, LANEBOSS_CONFIG="beta")
        result = self.run_laneboss("start", "--config", "alpha", code=2, environment=environment)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("refused:"), result.stderr)
        self.assertFalse((self.state_home / "alpha").exists())
        self.assertFalse((self.state_home / "beta").exists())
        self.briefing(config="no-such-config", code=2)

    def test_undefined_role_is_refused(self):
        self.write_config("alpha", tail='\n[supervisors.second]\nlevel = 4\nrunner = "local"\n')
        result = self.briefing("--role", "nobody", code=2)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("refused:"), result.stderr)
        self.assertIn("top", result.stderr)
        self.assertIn("second", result.stderr)
        # A configuration with no [supervisors] at all has no role to name.
        directory = self.home / "configs" / "beta"
        (directory / "rules").mkdir(parents=True)
        (directory / "config.toml").write_text(lanesupport.lane_config("beta"), encoding="utf-8")
        (directory / "rules" / "standing.md").write_text("# Rules\n\n- Be careful.\n", encoding="utf-8")
        result = self.briefing("--role", "top", config="beta", code=2)
        self.assertEqual(result.stdout, "")
        self.assertIn("no role", result.stderr.lower())
        self.assertFalse((self.state_home / "alpha").exists())
        self.assertFalse((self.state_home / "beta").exists())

    def test_role_without_a_configuration(self):
        self.write_config("alpha")
        before = tree(self.directory)
        result = self.run_laneboss("start", "--role", "top")
        self.assertEqual(tree(self.directory), before)
        self.assertEqual(result.stderr, "")
        self.assertIn("- alpha", result.stdout)
        choose = [line for line in result.stdout.splitlines() if "--config" in line and "LANEBOSS_CONFIG" in line]
        self.assertEqual(len(choose), 1)
        self.assertIn("--role top", choose[0])
        listing = json.loads(self.run_laneboss("start", "--role", "top", "--format", "json").stdout)
        self.assertIn("--role top", listing["choose"])
        # Only a role name is ever repeated.
        refused = self.run_laneboss("start", "--role", "Not A Role", code=2)
        self.assertTrue(refused.stderr.startswith("refused:"), refused.stderr)
        self.assertNotIn("Not A Role", refused.stdout + refused.stderr)

    def test_bad_format_is_refused(self):
        self.write_config("alpha")
        result = self.briefing("--format", "yaml", code=2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--format", result.stderr)
        self.assertIn(NOT_ACCEPTED, result.stderr)

    def test_usage_error_withholds_secret(self):
        """argparse's own usage errors repeat what was typed, in forms that no list of shapes can cover. A usage error
        fails closed: only the parser's own forms made of its own words and labels are printed unchanged, and any
        other becomes a fixed sentence. No typed value, of a known shape or of none, comes back on either stream."""
        self.write_config("alpha")
        generic = "the command line was not accepted; a typed value is never repeated here, see the usage line " \
                  "above or run with --help"
        for kind, value in (("shaped", "glpat-" + "q" * 20), ("plain", "hunter" + "2x7")):
            lane = ("lane", "start", "--config", "alpha", "--lane", "x", "--brief", "/dev/null")
            forms = (
                # (the command line, the sentence that must be in the error)
                (("start", "--config", "alpha", "--format", value), "argument --format: " + NOT_ACCEPTED),
                # The value holds argparse's own words: the first "(choose from" must not end the screening.
                (("start", "--config", "alpha", "--format", "{0} (choose from {0}".format(value)),
                 "argument --format: " + NOT_ACCEPTED),
                (("start", "--config", "alpha", "--password", value), generic),
                (("start", "--config", "alpha", "--role", "top", "extra", value), generic),
                # An abbreviation of an option (or an ambiguous one, whichever argparse makes of it).
                (("start", "--config", "alpha", "--fo=" + value), NOT_ACCEPTED),
                # A value attached to a flag that takes none: "ignored explicit argument".
                (lane + ("--reuse=" + value,), "argument --reuse: " + NOT_ACCEPTED),
                # An invalid number: a refusal of the command, not of the parser.
                (lane + ("--runner", "local", "--model", "example-model-2", "--budget", value), "--budget"),
                ((value,), "argument COMMAND: " + NOT_ACCEPTED),
                (("lane", value), "argument ACTION: " + NOT_ACCEPTED),
                (("plugin", "path", "--agent", "claude-code", value), generic),
            )
            for number, (arguments, wanted) in enumerate(forms):
                with self.subTest(kind=kind, form=number):
                    result = self.run_laneboss(*arguments, code=2)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual((result.stdout + result.stderr).count(value), 0, result.stderr)
                    self.assertIn(wanted, result.stderr)
        # The safe forms still help: they name the options, which are the parser's own words.
        result = self.run_laneboss("lane", "start", "--config", "alpha", code=2)
        self.assertEqual(result.stdout, "")
        self.assertIn("the following arguments are required: --lane", result.stderr)
        result = self.run_laneboss("start", "--config", code=2)
        self.assertEqual(result.stdout, "")
        self.assertIn("argument --config: expected one argument", result.stderr)

    def test_unused_configuration(self):
        self.write_config("alpha")
        before = tree(self.directory)
        text = self.briefing("--role", "top").stdout
        briefing = self.briefing_json("--role", "top")
        self.assertEqual(tree(self.directory), before, "the briefing created something")
        self.assertFalse((self.state_home / "alpha").exists(), "the state directory exists afterwards")
        self.assertFalse((self.directory / "claims").exists())
        for title in ("Lanes", "Recent events"):
            self.assertIn("no store exists yet", " ".join(section(text, title)).lower(), title)
        self.assertEqual(text.splitlines()[0], TITLE)
        self.assertEqual(briefing["configuration"]["warnings"], [])
        self.assertIs(briefing["lanes"]["store"], False)
        self.assertIs(briefing["events"]["store"], False)
        self.assertIn("no store exists yet", briefing["lanes"]["note"])
        self.assertIn("no store exists yet", briefing["events"]["note"])
        self.assertEqual(briefing["events"]["recent"], [])
        for group in GROUPS:
            self.assertEqual(briefing["lanes"][group], [])
        checks = {item["check"]: item for item in briefing["checks"]["read"]}
        self.assertIn("no store has been created yet", checks["store.recorded"]["detail"])
        self.assertTrue(all(item["ok"] for item in checks.values()), checks)

    # E. A description that looks like a credential.

    def test_listing_withholds_credentials(self):
        token = "gh" + "p_" + "Q1w2E3r4T5y6U7i8O9p0" + "A1s2D3f4G5"
        password = "Hunter2" + "Passw0rd"
        self.described("alpha", "The first invented company.")
        self.described("delta", "Invented company. Token {}".format(token))
        self.described("epsilon", "Invented company, password: {}".format(password))
        before = tree(self.directory)
        for arguments in ((), ("--format", "json")):
            with self.subTest(arguments=arguments):
                result = self.run_laneboss("start", *arguments)
                for secret in (token, password, "Hunter2"):
                    self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertEqual(result.stdout.count("[withheld]"), 2, result.stdout)
                for name in ("alpha", "delta", "epsilon"):
                    self.assertIn(name, result.stdout)
                self.assertIn("The first invented company.", result.stdout)
        found = {item["name"]: item for item in json.loads(self.run_laneboss("start", "--format", "json").stdout)
                 ["configurations"]}
        self.assertEqual((found["delta"]["description"], found["epsilon"]["description"]),
                         ("[withheld]", "[withheld]"))
        self.assertEqual(tree(self.directory), before)

    def test_bound_credential_is_refused(self):
        token = "gh" + "p_" + "Q1w2E3r4T5y6U7i8O9p0" + "A1s2D3f4G5"
        self.described("delta", "Invented company. Token {}".format(token))
        for arguments in ((), ("--format", "json")):
            result = self.briefing(*arguments, config="delta", code=2)
            self.assertEqual(result.stdout, "")
            self.assertTrue(result.stderr.startswith("invalid configuration:"), result.stderr)
            self.assertIn("description", result.stderr)
            self.assertNotIn(token, result.stdout + result.stderr)
        self.assertFalse((self.state_home / "delta").exists())

    # F. The headings and the keys.

    def test_headings_and_keys_are_exact(self):
        self.write_config("alpha")
        wanted = [TITLE] + ["## " + title for title in SECTIONS]
        for used in (False, True):
            if used:
                self.append(self.event("note.added", payload={"text": "# not a heading"}))
                self.append(self.event("lane.planned", lane="f-lane", payload={}))
            for arguments in ((), ("--role", "top")):
                with self.subTest(used=used, arguments=arguments):
                    text = self.briefing(*arguments).stdout
                    self.assertEqual(headings(text), wanted)
                    self.assertEqual(text.splitlines()[0], TITLE)
                    self.assertEqual(section(text, "Not known to the launcher"), ["", UNKNOWN])
                    briefing = self.briefing_json(*arguments)
                    self.assertEqual(sorted(briefing), KEYS)
                    self.assertEqual(briefing["unknown"], UNKNOWN)
        # The json form is one value, followed by a line end, and it is the same on every run.
        first = self.briefing("--format", "json").stdout
        self.assertTrue(first.endswith("\n"))
        self.assertEqual(len(first.splitlines()), 1)
        self.assertEqual(self.briefing("--format", "json").stdout, first)

    # The rest of the contract.

    def test_last_twenty_events(self):
        self.write_config("alpha")
        for number in range(24):
            self.append(self.event("note.added", payload={"text": "payload-marker-{}".format(number)}))
        self.append(self.event("lane.planned", lane="e-lane", payload={}))
        stored = self.events()
        self.assertEqual(len(stored), 25)
        wanted = [{"seq": item["seq"], "time": item["occurred_at"] or item["recorded_at"], "lane": item["lane"],
                   "kind": item["kind"]} for item in stored[-20:]]
        self.assertEqual([item["seq"] for item in wanted], list(range(6, 26)))
        briefing = self.briefing_json()
        self.assertEqual(briefing["events"]["total"], 25)
        self.assertEqual(briefing["events"]["recent"], wanted)
        self.assertIs(briefing["events"]["store"], True)
        text = self.briefing().stdout
        shown = [match.groups() for match in map(EVENT_LINE.fullmatch, section(text, "Recent events")) if match]
        self.assertEqual(shown, [(str(item["seq"]), item["time"], item["lane"] or "none", item["kind"])
                                 for item in wanted])
        self.assertNotIn("payload-marker", text + json.dumps(briefing))

    def test_waiting_and_refused_counts(self):
        self.write_config("alpha")
        self.append(self.event("lane.planned", lane="w-lane", payload={}))
        directory = self.state_home / "alpha" / "lanes" / "w-lane"
        directory.mkdir(parents=True)
        (directory / "pending.jsonl").write_text('{"first": 1}\n{"second": 2}\n', encoding="utf-8")
        (directory / "pending-0123abcd.jsonl").write_text('{"third": 3}\n', encoding="utf-8")
        (directory / "refused.jsonl").write_text('{"envelope": null, "reason": "x", "line": "y"}\n', encoding="utf-8")
        before = tree(self.state_home)
        briefing = self.briefing_json()
        text = self.briefing().stdout
        self.assertEqual(tree(self.state_home), before, "the briefing changed the pending or refused files")
        self.assertEqual((briefing["lanes"]["pending_events"], briefing["lanes"]["refused_events"]), (3, 1))
        self.assertEqual(briefing["lanes"]["pending_lanes"], [{"lane": "w-lane", "waiting": 3, "refused": 1}])
        body = "\n".join(section(text, "Lanes"))
        self.assertIn("as the store records them", body)
        self.assertIn("w-lane (waiting 3, refused 1)", body)
        self.assertIn("Events waiting to be recorded: 3", body)
        self.assertIn("Events the store refused for good: 1", body)
        # A lane that only was planned is in none of the four groups; it is counted.
        self.assertEqual(briefing["lanes"]["others"], 1)
        for group in GROUPS:
            self.assertEqual(briefing["lanes"][group], [])
        self.assertIn("Lanes in none of these groups (queued, merged or abandoned): 1", body)

    def test_checks_agree_with_doctor(self):
        self.write_config("alpha")
        doctor = [json.loads(line) for line in self.run_laneboss("doctor", "--config", "alpha").stdout.splitlines()]
        briefing = self.briefing_json()
        mine = {item["check"]: (item["ok"], item["detail"]) for item in briefing["checks"]["read"]}
        theirs = {item["check"]: (item["ok"], item["detail"]) for item in doctor}
        # Doctor also checks the organisation's tools directory; the briefing shows it in its configuration section.
        self.assertEqual(sorted(theirs), sorted(set(mine) | {"state.writable", "store.round_trip",
                                                             "organisation.tools"}))
        self.assertEqual(sorted(mine), ["config", "runner.local", "state.isolated", "store.recorded", "tool.git",
                                        "tool.tmux"])
        for name, answer in mine.items():
            self.assertEqual(answer, theirs[name], name)
        self.assertEqual(briefing["checks"]["not_run"]["checks"], ["state.writable", "store.round_trip"])
        text = self.briefing().stdout
        body = section(text, "Checks")
        self.assertEqual(len([line for line in body if re.fullmatch(r"- \S+ \[(ok|FAILED)\] .+", line)]), 6)
        sentence = next(line for line in body if line.startswith("Not run:"))
        for words in ("state.writable", "store.round_trip", "laneboss doctor"):
            self.assertIn(words, sentence)

    # Ruling R37. A configuration that cannot be read is a warning of the briefing of the others; a problem of the bound
    # configuration's own state directory is a refusal.

    def break_neighbour(self, name="beta"):
        """The fixture of the isolation tests (test_links): another configuration whose config.toml cannot be read, so
        its state directory cannot be compared with this one."""
        self.write_config(name)
        (self.home / "configs" / name / "config.toml").write_text("this is [not toml", encoding="utf-8")

    def test_unreadable_neighbour_warns(self):
        self.write_config("alpha")
        self.started("j-lane")
        self.ended("j-lane")
        self.break_neighbour()
        doctor = {item["check"]: item for item in map(json.loads, self.run_laneboss(
            "doctor", "--config", "alpha", code=1).stdout.splitlines())}
        self.assertIs(doctor["state.isolated"]["ok"], False)
        before = tree(self.directory)
        wanted = [TITLE] + ["## " + title for title in SECTIONS]
        for arguments in ((), ("--role", "top")):
            with self.subTest(arguments=arguments):
                text = self.briefing(*arguments).stdout
                lines = text.splitlines()
                self.assertEqual(headings(text), wanted)
                warning = lines[lines.index("## Configuration") + 1]
                self.assertTrue(warning.startswith("Warning:"), warning)
                self.assertIn("beta", warning)
                self.assertIn("isolation from it cannot be shown", warning)
                self.assertIn("laneboss doctor --config alpha", warning)
                self.assertLess(lines.index(warning), lines.index("- config [ok] configuration alpha is valid"))
                self.assertIn("- state.isolated [FAILED] ", text)
                self.assertIn("- store.recorded [ok] ", text)
                self.assertEqual([line["lane"] for line in text_lanes(text)["ended"]], ["j-lane"])
                data = self.briefing_json(*arguments)
                self.assertEqual(sorted(data), KEYS)
                self.assertEqual(data["configuration"]["warnings"], [warning])
                checks = {item["check"]: item for item in data["checks"]["read"]}
                self.assertIs(checks["state.isolated"]["ok"], False)
                self.assertIs(checks["store.recorded"]["ok"], True)
                self.assertEqual([item["lane"] for item in data["lanes"]["ended"]], ["j-lane"])
        self.assertEqual(tree(self.directory), before, "the briefing created or changed something")

    def test_neighbour_and_unsound_store(self):
        self.write_config("alpha")
        self.started("k-lane")
        self.ended("k-lane")
        self.break_neighbour()
        with closing(sqlite3.connect(str(self.state_home / "alpha" / "events.sqlite"))) as connection:
            [(stored,)] = connection.execute("SELECT projection FROM lanes WHERE lane = 'k-lane'").fetchall()
            projection = json.loads(stored)
            projection["state"] = "accepted"
            connection.execute("UPDATE lanes SET projection = ? WHERE lane = 'k-lane'",
                               (json.dumps(projection, sort_keys=True, separators=(",", ":")),))
            connection.commit()
        for arguments in ((), ("--format", "json"), ("--role", "top")):
            with self.subTest(arguments=arguments):
                result = self.briefing(*arguments, code=3)
                self.assertEqual(result.stdout, "", "a briefing was printed from a store that does not verify")
                self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
                self.assertIn("store.recorded", result.stderr)
                self.assertIn("laneboss state verify --config alpha", result.stderr)

    def test_own_state_inside_another_refused(self):
        # The bound configuration's own state directory lies inside a directory that another configuration's ownership
        # marker claims: its own problem, not a neighbour that cannot be read.
        shared = self.directory / "shared"
        shared.mkdir()
        (shared / ".laneboss-state").write_text(json.dumps({"config": "beta", "format": 2, "store": None}),
                                                encoding="utf-8")
        self.write_config("beta")
        self.write_config("alpha", state_path=shared / "inner")
        before = tree(self.directory)
        for arguments in ((), ("--format", "json"), ("--role", "top")):
            with self.subTest(arguments=arguments):
                result = self.briefing(*arguments, code=3)
                self.assertEqual(result.stdout, "", "a briefing was printed from a state directory that is not isolated")
                self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
                self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)
                self.assertIn("state.isolated", result.stderr)
                self.assertIn("beta", result.stderr)
        self.assertEqual(tree(self.directory), before)
        self.assertFalse((shared / "inner").exists())

    def test_unreadable_secret_neighbour(self):
        secret = "glpat-" + "abcdefghijklmnopqrst"
        self.write_config("alpha")
        self.break_neighbour(secret)
        for arguments in ((), ("--format", "json")):
            with self.subTest(arguments=arguments):
                result = self.briefing(*arguments)
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                if arguments:
                    warnings = json.loads(result.stdout)["configuration"]["warnings"]
                else:
                    lines = result.stdout.splitlines()
                    warnings = [lines[lines.index("## Configuration") + 1]]
                self.assertEqual(len(warnings), 1, warnings)
                self.assertIn("[withheld]", warnings[0])
                self.assertIn("laneboss doctor --config alpha", warnings[0])

    def test_statedir_message_withholds(self):
        # The messages of the state directory's own check that name another configuration: the state directory lies
        # inside a directory that the other's marker claims, and the state directory holds the other's marker. A name
        # that looks like a credential is not repeated; an ordinary one is, as before.
        secret = "glpat-" + "abcdefghijklmnopqrst"
        for other in ("beta-two", secret):
            for variant, phrase in (("above", "lies inside the state directory of configuration"),
                                    ("own", "belongs to configuration")):
                with self.subTest(other=other, variant=variant):
                    base = self.directory / "{}-{}".format(variant, other[:6])
                    inner = base / "inner"
                    inner.mkdir(parents=True)
                    marker = (base if variant == "above" else inner) / ".laneboss-state"
                    marker.write_text(json.dumps({"config": other, "format": 2, "store": None}), encoding="utf-8")
                    self.fresh_config(other)
                    self.fresh_config("alpha", state_path=inner)
                    result = self.run_laneboss("state", "events", "--config", "alpha", code=2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(phrase, result.stderr)
                    if other == secret:
                        self.assertNotIn(secret, result.stdout + result.stderr)
                        self.assertIn(phrase + " [withheld]", result.stderr)
                    else:
                        self.assertIn(phrase + " " + other, result.stderr)

    def test_damaged_store_exits_3(self):
        self.write_config("alpha")
        self.append(self.event("note.added", payload={"text": "one"}))
        (self.state_home / "alpha" / "events.sqlite").write_bytes(b"")
        result = self.briefing(code=3)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
        self.run_laneboss("state", "events", "--config", "alpha", code=3)

    def test_failed_check_is_reported(self):
        self.write_config("alpha", replace=(('command = ["sh", "-c", "exit 0", "{brief}"]',
                                             'command = ["no-such-program-anywhere", "{brief}"]'),))
        briefing = self.briefing_json()
        checks = {item["check"]: item for item in briefing["checks"]["read"]}
        self.assertIs(checks["runner.local"]["ok"], False)
        self.assertIn("no-such-program-anywhere", checks["runner.local"]["detail"])
        self.assertIs(checks["config"]["ok"], True)
        text = self.briefing().stdout
        self.assertIn("- runner.local [FAILED] ", text)


class LaneBriefingTest(lanesupport.LaneTest):
    """B. Real stand-in lanes: two ended (one marked accepted), one running and one whose run was lost."""

    def start_json(self, *arguments):
        return json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json", *arguments,
                                            environment=self.env("alpha")).stdout)

    def start_text(self, *arguments):
        return self.run_laneboss("start", "--config", "alpha", *arguments, environment=self.env("alpha")).stdout

    def test_lanes_in_every_state(self):
        scratch = self.scratch
        self.start("s-done", "--runner", "ok", "--model", "ok-model-1", "--effort", "high", "--account", "acc-three",
                   "--worktree", scratch("s-done"))
        self.start("s-fail", "--runner", "fail", "--model", "fail-model-1", "--worktree", scratch("s-fail"))
        for lane in ("s-done", "s-fail"):
            self.wait_event("lane.ended", lane)
        self.lane_json("mark", "--lane", "s-fail", "--state", "accepted")
        for lane in ("s-run", "s-lost"):
            self.start(lane, "--runner", "forever", "--model", "ever-model-1", "--worktree", scratch(lane))
            self.record(lane)
        socket = self.status("s-lost")["live"]["session"]["socket"]
        self.tmux(socket, "kill-session", "-t", "=s-lost")
        deadline = time.monotonic() + 30
        while self.status("s-lost")["live"]["supervisor"]["alive"]:
            self.assertLess(time.monotonic(), deadline, "the supervising process outlived its session")
            time.sleep(0.2)
        checked = self.lane_json("check")
        self.assertEqual([item["lane"] for item in checked["lost"]], ["s-lost"])
        self.assertEqual(checked["alive"], ["s-run"])
        time.sleep(1.0)

        state = Path(self.paths()["state_dir"])
        store = state / "events.sqlite"
        names_before = names(state)
        store_before = hashlib.sha256(store.read_bytes()).hexdigest()
        count_before = len(self.events())
        briefing = self.start_json()
        text = self.start_text()
        self.assertEqual(self.start_json(), briefing, "two briefings of one store differ")
        self.assertEqual(names(state), names_before, "the briefing created or removed a file")
        self.assertEqual(hashlib.sha256(store.read_bytes()).hexdigest(), store_before, "the store changed")
        self.assertEqual(len(self.events()), count_before, "the briefing appended an event")

        survivors = {}
        for lane, kind in (("s-done", "lane.ended"), ("s-fail", "lane.ended"), ("s-lost", "lane.lost")):
            survivors[lane] = self.lane_events(lane, kind)[-1]["payload"]["survivors"]
        expected = {  # lane: (group, run, runner, model, account, reason, exit code, survivors)
            "s-run": ("running", 1, "forever", "ever-model-1", "acc-two", None, None, None),
            "s-done": ("ended", 1, "ok", "ok-model-1", "acc-three", "exit", 0, survivors["s-done"]),
            "s-fail": ("accepted", 1, "fail", "fail-model-1", None, "exit", 3, survivors["s-fail"]),
            "s-lost": ("lost", 1, "forever", "ever-model-1", "acc-two", "lost", None, survivors["s-lost"]),
        }
        self.assertEqual((survivors["s-done"], survivors["s-fail"]), (0, 0))
        rows = {row["lane"]: row for row in self.laneboss_json("state", "lanes", "--config", "alpha",
                                                                environment=self.env("alpha"))}
        self.assertEqual(sorted(rows), sorted(expected))
        self.assertEqual({lane: row["state"] for lane, row in rows.items()},
                         {"s-run": "running", "s-done": "verifying", "s-fail": "accepted", "s-lost": "verifying"})

        self.assertIs(briefing["lanes"]["store"], True)
        self.assertIsNone(briefing["lanes"]["note"])
        parsed = text_lanes(text)
        for group in GROUPS:
            self.assertEqual([item["lane"] for item in briefing["lanes"][group]],
                             [lane for lane, facts in sorted(expected.items()) if facts[0] == group], group)
            self.assertEqual([item["lane"] for item in parsed[group]],
                             [lane for lane, facts in sorted(expected.items()) if facts[0] == group], group)
        self.assertEqual(briefing["lanes"]["others"], 0)
        for lane, (group, run, runner, model, account, reason, code, left) in expected.items():
            row = rows[lane]
            fields = ("run", "runner", "model", "account", "reason", "exit_code", "survivors")
            wanted = dict(zip(fields, (run, runner, model, account, reason, code, left)))
            [item] = [item for item in briefing["lanes"][group] if item["lane"] == lane]
            self.assertEqual({key: item[key] for key in fields}, wanted, lane)
            self.assertEqual((item["state"], item["state_at"]), (row["state"], row["state_at"]), lane)
            self.assertEqual(item["times"], row["times"], lane)
            self.assertEqual(item["landing"], row["landing"], lane)
            [line] = [line for line in parsed[group] if line["lane"] == lane]
            self.assertEqual({key: line[key] for key in fields}, wanted, lane)
            self.assertEqual((line["state"], line["since"]), (row["state"], row["state_at"]), lane)
            self.assertEqual(line["times"], {name: time_ for name, time_ in row["times"].items() if time_}, lane)
        self.assertEqual(briefing["lanes"]["pending_events"], 0)
        self.assertEqual(briefing["lanes"]["refused_events"], 0)
        body = "\n".join(section(text, "Lanes"))
        self.assertIn("Events waiting to be recorded: 0", body)
        self.assertIn("Events the store refused for good: 0", body)

        recent = briefing["events"]["recent"]
        stored = self.events()
        self.assertEqual(briefing["events"]["total"], len(stored))
        self.assertEqual([item["seq"] for item in recent], [item["seq"] for item in stored[-20:]])
        self.assertTrue(all(sorted(item) == ["kind", "lane", "seq", "time"] for item in recent), recent)
        self.assertEqual(headings(text), [TITLE] + ["## " + title for title in SECTIONS])
        self.assert_sound()

    def test_lost_then_declared_gone(self):
        self.start("g-lost", "--runner", "persist", "--model", "persist-model-1", "--worktree", self.scratch("g-lost"))
        self.record("g-lost")
        socket = self.status("g-lost")["live"]["session"]["socket"]
        self.tmux(socket, "kill-session", "-t", "=g-lost")
        deadline = time.monotonic() + 30
        while self.status("g-lost")["live"]["supervisor"]["alive"]:
            self.assertLess(time.monotonic(), deadline, "the supervising process outlived its session")
            time.sleep(0.2)
        self.assertEqual([item["lane"] for item in self.lane_json("check")["lost"]], ["g-lost"])
        [item] = self.start_json()["lanes"]["lost"]
        self.assertEqual((item["lane"], item["reason"], item["gone"]), ("g-lost", "lost", False))
        # The run record is removed by hand; the supervisor declares the launch gone. A recorded loss does not matter:
        # the latest run has a declaration and no end.
        self.run_record_path("g-lost").unlink()
        self.lane_json("mark", "--lane", "g-lost", "--gone")
        briefing, text = self.start_json(), self.start_text()
        groups = {group: [item["lane"] for item in briefing["lanes"][group]] for group in GROUPS}
        self.assertEqual(groups, {"running": [], "ended": [], "accepted": [], "lost": ["g-lost"]})
        [item] = briefing["lanes"]["lost"]
        self.assertIs(item["gone"], True)
        self.assertEqual(item["run"], 1)
        lines = [line for line in section(text, "Lanes") if line.startswith("- g-lost:")]
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(GONE, lines[0])
        self.assertNotIn("reason lost", lines[0])
        self.assertIs(text_lanes(text)["lost"][0]["gone"], True)
        # The same lane resumed: the new run is not gone.
        self.lane_json("resume", "--lane", "g-lost")
        self.wait_event("lane.started", "g-lost", run=2)
        briefing, text = self.start_json(), self.start_text()
        groups = {group: [item["lane"] for item in briefing["lanes"][group]] for group in GROUPS}
        self.assertEqual(groups, {"running": ["g-lost"], "ended": [], "accepted": [], "lost": []})
        [item] = briefing["lanes"]["running"]
        self.assertEqual((item["run"], item["gone"]), (2, False))
        self.assertNotIn(GONE, text)

    def test_waiting_end_is_named(self):
        self.start("p-wait", "--runner", "waiter", "--model", "wait-model-1", "--worktree", self.scratch("p-wait"))
        self.record("p-wait")
        store = Path(self.paths()["store"])
        store.chmod(0o444)
        self.addCleanup(store.chmod, 0o644)
        self.go("p-wait")
        # The run ends while the store cannot be written: its end waits in the pending file, and the supervising
        # process, after its last tries, is gone. Nothing records the end until `lane check` does.
        deadline = time.monotonic() + 90
        while True:
            live = self.status("p-wait")["live"]
            if live["pending_events"] == 1 and live["supervisor"] and not live["supervisor"]["alive"]:
                break
            self.assertLess(time.monotonic(), deadline, "the end did not wait in the pending file: {}".format(live))
            time.sleep(0.5)
        store.chmod(0o644)
        state = Path(self.paths()["state_dir"])
        before = tree(state)
        briefing = self.start_json()
        text = self.start_text()
        self.assertEqual(tree(state), before, "the briefing changed a file")
        self.assertEqual([item["lane"] for item in briefing["lanes"]["running"]], ["p-wait"])
        self.assertEqual(briefing["lanes"]["pending_lanes"], [{"lane": "p-wait", "waiting": 1, "refused": 0}])
        self.assertEqual((briefing["lanes"]["pending_events"], briefing["lanes"]["refused_events"]), (1, 0))
        body = "\n".join(section(text, "Lanes"))
        self.assertIn("as the store records them", body)
        self.assertIn("p-wait (waiting 1, refused 0)", body)
        # Once the end is recorded the sentence is gone.
        self.lane_json("check")
        recorded = self.start_json()
        self.assertEqual(recorded["lanes"]["pending_lanes"], [])
        self.assertEqual([item["lane"] for item in recorded["lanes"]["ended"]], ["p-wait"])
        self.assertNotIn("as the store records them", "\n".join(section(self.start_text(), "Lanes")))

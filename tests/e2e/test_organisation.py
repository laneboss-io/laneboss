"""Organisations: a configuration names the organisation it belongs to; the organisation has rules files and tools
of its own, under `$LANEBOSS_HOME/orgs/NAME/`.

A. `organisation` is optional and takes the grammar of configuration names.
B. `organisation_rules` lists rules files read inside the organisation's directory; they come first, in a rendered
   brief, in the event that records the rendering, and in the briefing. Each refusal names the key path.
C. A command element that is an absolute path into another organisation's directory is refused, and one into the
   configuration's own organisation is accepted. The known limits stay limits.
D. `laneboss start` names the organisation and its tools directory, and creates nothing.
E. `laneboss doctor` has the check `organisation.tools`.
F. A configuration without the two keys renders the brief it always did, byte for byte.
G. The whole suite passes (a run on the test machine, not a test of this file).

Every assertion goes through the installed command.
"""

import json
import os
from pathlib import Path
import shutil
import stat

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


ORG_COMMON = "# Organisation rules: acme\n\n- The organisation asks for a written plan first.\n"
ORG_EXTRA = "# Organisation rules, second file\n\n- The organisation asks for a written summary last."
TOKEN = "gh" + "p_" + "Q1w2E3r4T5y6U7i8O9p0" + "A1s2D3f4G5"
TOOLS_ARE_NOT_SHARED = "tools are not shared between organisations"
LABEL = "orgs/acme/{}"


def tree(root):
    """Every path below root with its kind, size and modification time: a listing that shows a created, written or
    removed entry (a directory's own time moves when an entry is added or removed)."""
    found = {}
    for directory, names, files in os.walk(str(root)):
        for name in names + files:
            path = Path(directory) / name
            info = path.lstat()
            found[str(path.relative_to(root))] = (stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns)
    return found


def section(text, title):
    """The lines of the `## title` section of a briefing, up to the next heading."""
    lines = text.splitlines()
    body = []
    for line in lines[lines.index("## " + title) + 1:]:
        if line.startswith("#"):
            break
        body.append(line)
    return body


def ended(data):
    return data if data.endswith(b"\n") else data + b"\n"


def quoted(value):
    """A TOML string for an ordinary value."""
    return json.dumps(value)


class OrganisationCase(support.LauncherTest):
    def write_org(self, relative, content, name="acme"):
        path = self.home / "orgs" / name / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def reset_orgs(self):
        shutil.rmtree(str(self.home / "orgs"), ignore_errors=True)

    def named(self, extra="", organisation="acme", **options):
        top = ('organisation = "{}"'.format(organisation) if organisation else "") + ("\n" + extra if extra else "")
        return self.write_config("alpha", top=top, **options)

    def with_rules(self, *relatives, **options):
        listed = "organisation_rules = [{}]".format(", ".join(quoted(relative) for relative in relatives))
        return self.named(listed, **options)

    def validate(self, name="alpha", code=0):
        return self.run_laneboss("config", "validate", name, code=code)

    def refusal(self, key_path, *forbidden):
        """`config validate alpha` is refused with the key path in the message, and not as an unknown key."""
        result = self.validate(code=2)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("invalid configuration:"), result.stderr)
        self.assertIn("config.toml: " + key_path, result.stderr)
        self.assertNotIn("unknown key", result.stderr)
        for text in forbidden:
            self.assertNotIn(text, result.stdout + result.stderr)
        return result

    def render(self, lane="b-lane", project="web", brief="# Brief: an invented task\n\nRender me.\n"):
        source = self.directory / "brief-{}.md".format(lane)
        source.write_bytes(brief.encode("utf-8") if isinstance(brief, str) else brief)
        target = self.directory / "rendered-{}.md".format(lane)
        arguments = ["brief", "render", "--config", "alpha", "--lane", lane, "--in", source, "--out", target]
        if project:
            arguments += ["--project", project]
        self.run_laneboss(*arguments)
        return target.read_bytes()

    def rule_inputs(self):
        """(path, hash) of every rules input of the last brief.rendered event."""
        rendered = [item for item in self.events() if item["kind"] == "brief.rendered"]
        return [(item["path"], item["sha256"]) for item in rendered[-1]["payload"]["inputs"] if item["role"] == "rules"]


class NameTest(OrganisationCase):
    """A. The key `organisation`."""

    def test_a_name_is_optional_dir_may_miss(self):
        self.write_config("alpha")
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        self.assertNotIn("organisation", self.laneboss_json("config", "show", "alpha")["config"])
        self.named()
        before = tree(self.home)
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        self.assertEqual(self.laneboss_json("config", "show", "alpha")["config"]["organisation"], "acme")
        self.assertEqual(self.laneboss_json("config", "path", "alpha")["name"], "alpha")
        self.assertEqual(tree(self.home), before, "reading the configuration changed the configuration home")
        self.assertFalse((self.home / "orgs").exists(), "reading the configuration created orgs/")

    def test_a_several_share_one_organisation(self):
        self.named()
        self.write_config("beta", top='organisation = "acme"')
        self.write_config("gamma")
        self.assertEqual(self.laneboss_json("config", "validate", "--all"),
                         {"valid": True, "configs": ["alpha", "beta", "gamma"]})

    def test_a_bad_names_are_refused(self):
        cases = [("an upper-case letter", '"Acme"'), ("a slash", '"ac/me"'), ("an empty string", '""'),
                 ("a number", "5"), ("a leading hyphen", '"-acme"'), ("a dot", '"ac.me"'),
                 ("more than 32 characters", '"{}"'.format("a" * 33)), ("a path", '"../acme"')]
        for label, value in cases:
            with self.subTest(label):
                self.write_config("alpha", top="organisation = " + value)
                self.refusal("organisation: ")
                self.assertIn("config.toml: organisation", self.run_laneboss("config", "show", "alpha", code=2).stderr)
        self.write_config("alpha", top='organisation = "a"\norganisation = "b"')
        self.validate(code=2)
        self.named(organisation="a" * 32)
        self.validate()


class RulesTest(OrganisationCase):
    """B. The organisation's rules files."""

    def organisation_files(self):
        self.write_org("protocol/common.md", ORG_COMMON)
        self.write_org("protocol/extra.md", ORG_EXTRA)

    def test_b_files_are_accepted_and_shown(self):
        self.organisation_files()
        self.with_rules("protocol/common.md", "protocol/extra.md")
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        shown = self.laneboss_json("config", "show", "alpha")["config"]
        self.assertEqual((shown["organisation"], shown["organisation_rules"]),
                         ("acme", ["protocol/common.md", "protocol/extra.md"]))
        before = tree(self.home)
        self.validate()
        self.assertEqual(tree(self.home), before, "validating changed the configuration home")

    def test_b_a_link_inside_the_org_is_fine(self):
        self.write_org("shared/common.md", ORG_COMMON)
        (self.home / "orgs" / "acme" / "protocol").mkdir()
        os.symlink("../shared/common.md", str(self.home / "orgs" / "acme" / "protocol" / "common.md"))
        self.with_rules("protocol/common.md")
        self.validate()
        briefing = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json").stdout)
        standing = support.STANDING_RULES.format(name="alpha")
        self.assertEqual([(item["path"], item["text"]) for item in briefing["rules"]],
                         [(LABEL.format("protocol/common.md"), ORG_COMMON), ("rules/standing.md", standing)])

    def test_b_the_org_directory_may_be_a_link(self):
        real = self.directory / "dotfiles" / "acme"
        (real / "protocol").mkdir(parents=True)
        (real / "protocol" / "common.md").write_text(ORG_COMMON, encoding="utf-8")
        (self.home / "orgs").mkdir()
        os.symlink(str(real), str(self.home / "orgs" / "acme"))
        self.with_rules("protocol/common.md")
        self.validate()
        briefing = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json").stdout)
        self.assertEqual((briefing["rules"][0]["path"], briefing["rules"][0]["text"]),
                         (LABEL.format("protocol/common.md"), ORG_COMMON))
        # A file that leads out of the real directory is still refused.
        outside = self.directory / "outside.md"
        outside.write_text(ORG_COMMON, encoding="utf-8")
        os.symlink(str(outside), str(real / "protocol" / "leaving.md"))
        self.with_rules("protocol/leaving.md")
        self.refusal("organisation_rules[0]")

    def test_b_a_link_between_orgs_is_followed(self):
        # A known limit: an organisation's directory that is itself a link is followed, so a link from one
        # organisation's directory to another's makes the first read the second's files.
        self.write_org("protocol/common.md", "# The other organisation's rules\n", name="other")
        os.symlink("other", str(self.home / "orgs" / "acme"))
        self.with_rules("protocol/common.md")
        self.validate()
        briefing = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json").stdout)
        self.assertEqual((briefing["rules"][0]["path"], briefing["rules"][0]["text"]),
                         (LABEL.format("protocol/common.md"), "# The other organisation's rules\n"))

    def test_r_orgs_is_reserved_in_rules(self):
        # The spelling orgs/NAME/<path> is the label of an organisation's file in briefs, events and the briefing, so
        # a configuration's or a project's own `rules` entry may not start with `orgs`.
        directory = self.home / "configs" / "alpha"
        for label, value in (("a file below orgs/NAME/", "orgs/acme/protocol/common.md"),
                             ("a file in orgs/", "orgs/x.md"), ("a file named orgs", "orgs")):
            with self.subTest(label):
                self.fresh_config("alpha", replace=[('rules = ["rules/standing.md"]',
                                                     'rules = ["rules/standing.md", {}]'.format(quoted(value)))])
                (directory / value).parent.mkdir(parents=True, exist_ok=True)
                (directory / value).write_text("# Rules that start with orgs\n", encoding="utf-8")
                result = self.run_laneboss("config", "validate", "alpha", code=2)
                self.assertTrue(result.stderr.startswith("invalid configuration:"), result.stderr)
                self.assertIn("config.toml: rules[1]", result.stderr)
                self.assertIn("orgs", result.stderr.split("config.toml: rules[1]", 1)[1])
        for label, value in (("a project's file below orgs/NAME/", "orgs/acme/web.md"),
                             ("a project's file in orgs/", "orgs/web.md")):
            with self.subTest(label):
                self.fresh_config("alpha")
                (directory / value).parent.mkdir(parents=True, exist_ok=True)
                (directory / value).write_text("# Project rules that start with orgs\n", encoding="utf-8")
                project = directory / "projects" / "web.toml"
                project.write_text(project.read_text(encoding="utf-8").replace(
                    'rules = ["rules/web.md"]', 'rules = ["rules/web.md", {}]'.format(quoted(value))), encoding="utf-8")
                result = self.run_laneboss("config", "validate", "alpha", code=2)
                self.assertTrue(result.stderr.startswith("invalid configuration:"), result.stderr)
                self.assertIn("projects/web.toml: rules[1]", result.stderr)
        # Only the first part counts: these are fine, and so is an organisation's own file below an orgs/ of its own.
        self.fresh_config("alpha", replace=[('rules = ["rules/standing.md"]',
                                             'rules = ["rules/standing.md", "rules/orgs/x.md", "orgs-notes.md"]')])
        (directory / "rules" / "orgs").mkdir()
        (directory / "rules" / "orgs" / "x.md").write_text("# Rules\n", encoding="utf-8")
        (directory / "orgs-notes.md").write_text("# Rules\n", encoding="utf-8")
        self.validate()
        self.write_org("orgs/common.md", ORG_COMMON)
        self.with_rules("orgs/common.md")
        self.validate()
        briefing = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json").stdout)
        self.assertEqual(briefing["rules"][0]["path"], "orgs/acme/orgs/common.md")

    def test_b_start_prints_them_first(self):
        self.organisation_files()
        self.with_rules("protocol/common.md", "protocol/extra.md")
        wanted = [(LABEL.format("protocol/common.md"), ORG_COMMON), (LABEL.format("protocol/extra.md"), ORG_EXTRA),
                  ("rules/standing.md", support.STANDING_RULES.format(name="alpha"))]
        before = tree(self.home)
        briefing = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json").stdout)
        self.assertEqual([(item["path"], item["text"]) for item in briefing["rules"]], wanted)
        for item, (_, content) in zip(briefing["rules"], wanted):
            self.assertEqual(item["sha256"], support.digest(content))
        # With a role, the project's file comes last.
        role = json.loads(self.run_laneboss("start", "--config", "alpha", "--role", "top", "--format", "json").stdout)
        self.assertEqual([item["path"] for item in role["rules"]], [path for path, _ in wanted] + ["rules/web.md"])
        text = self.run_laneboss("start", "--config", "alpha", "--role", "top").stdout
        body = section(text, "Standing rules")
        lines = [line for line in body if line.startswith("- ")]
        self.assertEqual([line.split(":")[0] for line in lines],
                         ["- " + path for path, _ in wanted] + ["- rules/web.md"])
        for path, content in wanted:
            header = "- {}: sha256 {}".format(path, support.digest(content))
            self.assertIn(header, body)
            following = body[body.index(header) + 1:]
            for line in content.splitlines():
                if line.strip():
                    self.assertIn("    " + line, following)
        self.assertLess(body.index("- {}: sha256 {}".format(wanted[0][0], support.digest(ORG_COMMON))),
                        body.index("- rules/standing.md: sha256 " + support.digest(wanted[2][1])))
        self.assertEqual(tree(self.home), before, "the briefing changed the configuration home")

    def test_b_a_brief_carries_them_first(self):
        self.organisation_files()
        self.with_rules("protocol/common.md", "protocol/extra.md")
        standing = (self.home / "configs" / "alpha" / "rules" / "standing.md").read_bytes()
        project = (self.home / "configs" / "alpha" / "rules" / "web.md").read_bytes()
        rendered = self.render()
        common, extra = ORG_COMMON.encode("utf-8"), ORG_EXTRA.encode("utf-8")
        positions = [rendered.index(data) for data in (common, extra, standing, project)]
        self.assertEqual(positions, sorted(positions), "the rules are not in the order organisation, configuration, "
                                                       "project")
        for label, data in ((LABEL.format("protocol/common.md"), common), (LABEL.format("protocol/extra.md"), extra),
                            ("rules/standing.md", standing), ("rules/web.md", project)):
            heading = "\n## Standing rules: {} (sha256 {})\n\n".format(label, support.digest(data)).encode("utf-8")
            self.assertIn(heading + ended(data), rendered)
        self.assertEqual(self.rule_inputs(), [
            (LABEL.format("protocol/common.md"), support.digest(common)),
            (LABEL.format("protocol/extra.md"), support.digest(extra)),
            ("rules/standing.md", support.digest(standing)), ("rules/web.md", support.digest(project))])
        self.laneboss_json("state", "verify", "--config", "alpha")
        # Without a project, the organisation's files and the configuration's come in that order.
        self.render(lane="b-lane-two", project=None)
        self.assertEqual([path for path, _ in self.rule_inputs()],
                         [LABEL.format("protocol/common.md"), LABEL.format("protocol/extra.md"), "rules/standing.md"])
        self.laneboss_json("state", "verify", "--config", "alpha")

    def test_b_each_reads_its_own_files(self):
        # Two organisations hold a file of the same relative path.
        self.write_org("protocol/common.md", ORG_COMMON)
        self.write_org("protocol/common.md", "# The other organisation's rules\n", name="other")
        self.with_rules("protocol/common.md")
        self.write_config("beta", top='organisation = "other"\norganisation_rules = ["protocol/common.md"]')
        alpha = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json").stdout)["rules"][0]
        beta = json.loads(self.run_laneboss("start", "--config", "beta", "--format", "json").stdout)["rules"][0]
        self.assertEqual((alpha["path"], alpha["text"]), (LABEL.format("protocol/common.md"), ORG_COMMON))
        self.assertEqual((beta["path"], beta["text"]), ("orgs/other/protocol/common.md",
                                                       "# The other organisation's rules\n"))

    def test_b_rules_without_an_organisation(self):
        self.write_org("protocol/common.md", ORG_COMMON)
        for label, value in (("one file", '["protocol/common.md"]'), ("no file", "[]")):
            with self.subTest(label):
                self.write_config("alpha", top="organisation_rules = " + value)
                self.refusal("organisation_rules")
                self.assertIn("organisation", self.validate(code=2).stderr.split("organisation_rules", 1)[1])

    def test_b_a_missing_file_is_refused(self):
        self.write_org("protocol/common.md", ORG_COMMON)
        self.with_rules("protocol/common.md", "protocol/absent.md")
        self.refusal("organisation_rules[1]")
        self.reset_orgs()
        self.with_rules("protocol/common.md")
        self.refusal("organisation_rules[0]")
        (self.home / "orgs" / "acme").mkdir(parents=True)
        self.refusal("organisation_rules[0]")
        (self.home / "orgs" / "acme" / "protocol").mkdir()
        self.refusal("organisation_rules[0]")

    def test_b_a_path_not_relative_is_refused(self):
        self.write_org("protocol/common.md", ORG_COMMON)
        self.write_org("../other/protocol/common.md", ORG_COMMON)
        for label, value in (("a parent part", "../other/protocol/common.md"), ("a parent part inside", "protocol/../x.md"),
                             ("a current part", "./protocol/common.md"), ("an empty part", "protocol//common.md"),
                             ("an absolute path", str(self.home / "orgs" / "acme" / "protocol" / "common.md")),
                             ("a backslash", "protocol\\common.md")):
            with self.subTest(label):
                self.with_rules(value)
                self.refusal("organisation_rules[0]")
        self.with_rules("protocol/common.md", "protocol/common.md")
        self.refusal("organisation_rules")

    def test_b_link_to_another_org_refused(self):
        self.write_org("protocol/common.md", "# The other organisation's rules\n", name="other")
        directory = self.home / "orgs" / "acme" / "protocol"
        directory.mkdir(parents=True)
        for label, target in (("absolute", str(self.home / "orgs" / "other" / "protocol" / "common.md")),
                              ("relative", "../../other/protocol/common.md")):
            with self.subTest(label):
                link = directory / "common.md"
                if link.is_symlink():
                    link.unlink()
                os.symlink(target, str(link))
                self.with_rules("protocol/common.md")
                self.refusal("organisation_rules[0]", "other organisation's rules")
        link.unlink()
        # A directory of the organisation that is a link into the other one.
        shutil.rmtree(str(directory))
        os.symlink("../other/protocol", str(directory))
        self.with_rules("protocol/common.md")
        self.refusal("organisation_rules[0]")

    def test_b_link_outside_orgs_refused(self):
        outside = self.directory / "outside"
        outside.mkdir()
        (outside / "common.md").write_text(ORG_COMMON, encoding="utf-8")
        directory = self.home / "orgs" / "acme" / "protocol"
        directory.mkdir(parents=True)
        os.symlink(str(outside / "common.md"), str(directory / "common.md"))
        self.with_rules("protocol/common.md")
        self.refusal("organisation_rules[0]")
        (directory / "common.md").unlink()
        os.symlink("../../../../outside/common.md", str(directory / "common.md"))
        self.refusal("organisation_rules[0]")

    def test_b_credential_refused_not_printed(self):
        line = "- Deploy with {} today.".format(TOKEN)
        self.write_org("protocol/common.md", "# Organisation rules\n\n" + line + "\n")
        self.with_rules("protocol/common.md")
        result = self.refusal("organisation_rules[0]", TOKEN, line, "Deploy with")
        self.assertIn("line 3", result.stderr)
        self.assertIn("credential", result.stderr)
        for arguments in (("start", "--config", "alpha"), ("doctor", "--config", "alpha")):
            result = self.run_laneboss(*arguments, code=None)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_b_not_utf8_is_refused(self):
        self.write_org("protocol/common.md", b"# Organisation rules\n\xff\xfe not text\n")
        self.with_rules("protocol/common.md")
        result = self.refusal("organisation_rules[0]")
        self.assertIn("UTF-8", result.stderr)

    def test_b_over_one_mebibyte_is_refused(self):
        self.write_org("protocol/common.md", b"x" * (1024 * 1024 + 1) + b"\n")
        self.with_rules("protocol/common.md")
        self.refusal("organisation_rules[0]")
        self.write_org("protocol/common.md", b"x" * (1024 * 1024 + 1))
        self.refusal("organisation_rules[0]")
        self.write_org("protocol/common.md", (b"y" * 63 + b"\n") * 16384)
        self.validate()

    def test_b_a_directory_is_refused(self):
        (self.home / "orgs" / "acme" / "protocol" / "common.md").mkdir(parents=True)
        self.with_rules("protocol/common.md")
        self.refusal("organisation_rules[0]")


class DirectoryTest(OrganisationCase):
    """C. Tools are not shared between organisations."""

    KINDS = (("command", "runners.local.command[0]"), ("an argument of command", "runners.local.command[1]"),
             ("resume", "runners.local.resume[0]"), ("a judge's command", "judges.guard.command[0]"))

    def setUp(self):
        super().setUp()
        self.own = str(self.home / "orgs" / "acme" / "tools" / "tool.sh")
        self.other = str(self.home / "orgs" / "other" / "tools" / "tool.sh")
        for name in ("acme", "other"):
            self.write_org("tools/tool.sh", "#!/bin/sh\nexit 0\n", name=name).chmod(0o755)

    def doctor(self, code):
        result = self.run_laneboss("doctor", "--config", "alpha", code=code)
        return {item["check"]: item for item in map(json.loads, result.stdout.splitlines())}

    def configure(self, kind, element, organisation="acme"):
        text = quoted(element)
        top = 'organisation = "{}"'.format(organisation) if organisation else ""
        if kind == "command":
            options = {"replace": [('command = ["sh", "-c", "exit 0", "{brief}"]',
                                    'command = [' + text + ', "{brief}"]')]}
        elif kind == "an argument of command":
            options = {"replace": [('command = ["sh", "-c", "exit 0", "{brief}"]',
                                    'command = ["sh", ' + text + ', "{brief}"]')]}
        elif kind == "resume":
            options = {"replace": [('accounts = ["account-one", "account-two"]',
                                    'accounts = ["account-one", "account-two"]\nresume = [' + text + ', "{message}"]')]}
        else:
            options = {"tail": '\n[judges.guard]\ncommand = [' + text + ', "x"]\n'}
        return self.write_config("alpha", top=top, **options)

    def not_shared(self, element, key_path):
        result = self.validate(code=2)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("invalid configuration:"), result.stderr)
        self.assertIn("config.toml: " + key_path, result.stderr)
        self.assertIn(TOOLS_ARE_NOT_SHARED, result.stderr)
        self.assertNotIn("unknown key", result.stderr)
        self.assertNotIn(element, result.stdout + result.stderr, "the message repeats the path")
        self.assertNotIn(str(self.home / "orgs"), result.stdout + result.stderr, "the message holds a path")

    def test_c_other_organisation_is_refused(self):
        for kind, key_path in self.KINDS:
            with self.subTest(kind):
                self.configure(kind, self.other)
                self.not_shared(self.other, key_path)
                self.assertIn(key_path, self.run_laneboss("config", "show", "alpha", code=2).stderr)
                self.assertIn(key_path, self.run_laneboss("doctor", "--config", "alpha", code=1).stdout)

    def test_c_the_directory_and_deep_paths(self):
        for element in (str(self.home / "orgs" / "other"), str(self.home / "orgs" / "other") + "/",
                        str(self.home / "orgs" / "other" / "tools" / "a" / "b" / "c.sh"),
                        str(self.home / "orgs" / "other" / "not-yet-made.sh")):
            with self.subTest(element):
                self.configure("command", element)
                self.not_shared(element, "runners.local.command[0]")

    def test_c_own_organisation_is_accepted(self):
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                self.configure(kind, self.own)
                self.assertEqual(self.laneboss_json("config", "validate", "alpha"),
                                 {"valid": True, "configs": ["alpha"]})
        self.configure("command", str(self.home / "orgs" / "acme"))
        self.validate()

    def test_c_without_an_org_is_accepted(self):
        # A configuration written before organisations may point a command into an organisation's tools and name
        # none: it validates, and it renders a brief and is briefed as before.
        for kind, _ in self.KINDS:
            for element in (self.own, self.other):
                with self.subTest(kind=kind, element=element):
                    self.configure(kind, element, organisation=None)
                    self.assertEqual(self.laneboss_json("config", "validate", "alpha"),
                                     {"valid": True, "configs": ["alpha"]})
        self.configure("command", self.other, organisation=None)
        self.assertIn(b"## Standing rules: rules/standing.md", self.render())
        briefing = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json").stdout)
        self.assertIsNone(briefing["configuration"]["organisation"])

    def test_c_doctor_fails_the_one_check(self):
        for kind, key_path in self.KINDS:
            for element in (self.own, self.other):
                with self.subTest(kind=kind, element=element):
                    self.configure(kind, element, organisation=None)
                    checks = self.doctor(1)
                    self.assertEqual([name for name, item in checks.items() if not item["ok"]],
                                     ["organisation.tools"])
                    detail = checks["organisation.tools"]["detail"]
                    self.assertIn(key_path, detail)
                    self.assertIn("names no organisation", detail)
                    self.assertIn('organisation = "NAME"', detail)
                    self.assertNotIn(element, detail, "the detail repeats the path")
                    self.assertNotIn(str(self.home / "orgs"), detail, "the detail holds a path")
        # A path outside every organisation's directory is no reason to fail.
        for element in (str(self.home / "configs" / "alpha" / "tool.sh"), str(self.home / "orgs")):
            with self.subTest(outside=element):
                self.configure("an argument of command", element, organisation=None)
                check = self.doctor(0)["organisation.tools"]
                self.assertEqual((check["ok"], check["detail"]), (True, "no organisation is named"))

    def test_c_doctor_names_the_first_element(self):
        self.write_config("alpha", replace=[
            ('command = ["sh", "-c", "exit 0", "{brief}"]', 'command = ["sh", ' + quoted(self.other) + ', "{brief}"]'),
            ('accounts = ["account-one", "account-two"]',
             'accounts = ["account-one", "account-two"]\nresume = [' + quoted(self.own) + ', "{message}"]')])
        detail = self.doctor(1)["organisation.tools"]["detail"]
        self.assertIn("runners.local.command[1]", detail)
        self.assertNotIn("resume", detail)

    def test_c_naming_the_org_fixes_doctor(self):
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                self.configure(kind, self.own, organisation=None)
                self.assertIs(self.doctor(1)["organisation.tools"]["ok"], False)
                self.configure(kind, self.own, organisation="acme")
                checks = self.doctor(0)
                self.assertIs(checks["organisation.tools"]["ok"], True)
                self.assertTrue(all(item["ok"] for item in checks.values()), checks)
        # Naming another organisation is not a fix: the configuration is refused.
        self.configure("command", self.own, organisation="other")
        self.not_shared(self.own, "runners.local.command[0]")

    def test_c_dots_reaching_the_other_org(self):
        orgs = str(self.home / "orgs")
        for label, element in (("up and down", orgs + "/acme/tools/../../other/tools/tool.sh"),
                               ("up from the organisation", orgs + "/acme/../other/tools/tool.sh"),
                               ("a current part", orgs + "/./other/./tools/tool.sh"),
                               ("a doubled slash", orgs + "//other//tools/tool.sh"),
                               ("a leading doubled slash", "/" + orgs + "/other/tools/tool.sh"),
                               ("far up", orgs + "/acme/tools/../../../orgs/other/tools/tool.sh")):
            with self.subTest(label):
                self.configure("command", element)
                self.not_shared(element, "runners.local.command[0]")

    def test_c_paths_are_compared_folded(self):
        orgs = str(self.home / "orgs")
        for label, element in (("back into the own organisation", orgs + "/other/../acme/tools/tool.sh"),
                               ("a current part in the own organisation", orgs + "/acme/./tools/tool.sh"),
                               ("out of orgs", orgs + "/other/../../configs/alpha/tool.sh")):
            with self.subTest(label):
                self.configure("command", element)
                self.validate()
        # A name that only starts like the own one is another organisation.
        element = str(self.home / "orgs" / "acme-more" / "tools" / "tool.sh")
        self.configure("command", element)
        self.not_shared(element, "runners.local.command[0]")

    def test_c_the_known_limits_are_limits(self):
        link = self.directory / "link-to-the-other-tool.sh"
        os.symlink(self.other, str(link))
        for label, element in (("a path inside an option", "--tools=" + self.other),
                               ("a relative path", "orgs/other/tools/tool.sh"),
                               ("a command found on PATH", "tool.sh"),
                               ("a link that leads there", str(link))):
            with self.subTest(label):
                self.configure("an argument of command", element)
                self.assertEqual(self.laneboss_json("config", "validate", "alpha"),
                                 {"valid": True, "configs": ["alpha"]})
        # The commands of a test environment are not looked at either.
        self.write_config("alpha", top='organisation = "acme"', replace=[
            ('attest = ["sh", "-c", "exit 0"]', 'attest = [' + quoted(self.other) + ', "-c", "exit 0"]')])
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})

    def test_c_every_configuration_is_checked(self):
        self.configure("command", self.other)
        self.write_config("beta", top='organisation = "other"')
        result = self.run_laneboss("config", "validate", "--all", code=2)
        self.assertIn("config.toml: runners.local.command[0]", result.stderr)
        self.assertIn("alpha", result.stderr)
        self.assertNotIn("beta", result.stderr)
        self.laneboss_json("config", "validate", "beta")


class StartTest(OrganisationCase):
    """D. The briefing names the organisation and its tools directory."""

    def briefing(self, *arguments):
        before = tree(self.home)
        text = self.run_laneboss("start", "--config", "alpha", *arguments).stdout
        data = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json", *arguments).stdout)
        self.assertEqual(tree(self.home), before, "the briefing changed the configuration home")
        return section(text, "Configuration"), data["configuration"]

    def test_d_the_tools_directory_is_present(self):
        tools = self.home / "orgs" / "acme" / "tools"
        tools.mkdir(parents=True)
        (tools / "tool.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        self.named()
        lines, configuration = self.briefing()
        self.assertIn("- Organisation: acme", lines)
        self.assertIn("- Organisation tools: {} (present)".format(tools), lines)
        self.assertEqual(configuration["organisation"], {"name": "acme", "tools": str(tools), "tools_present": True})
        self.assertEqual(sorted(configuration), ["binding", "description", "name", "organisation", "warnings"])

    def test_d_the_tools_directory_is_missing(self):
        tools = self.home / "orgs" / "acme" / "tools"
        self.named()
        for made in ("no orgs/", "organisation directory only"):
            with self.subTest(made):
                if made != "no orgs/":
                    (self.home / "orgs" / "acme").mkdir(parents=True)
                lines, configuration = self.briefing()
                self.assertIn("- Organisation: acme", lines)
                self.assertIn("- Organisation tools: {} (missing)".format(tools), lines)
                self.assertEqual(configuration["organisation"],
                                 {"name": "acme", "tools": str(tools), "tools_present": False})
        self.assertFalse(tools.exists())

    def test_d_without_an_organisation(self):
        self.write_config("alpha")
        lines, configuration = self.briefing()
        self.assertIn("- Organisation: none", lines)
        self.assertEqual([line for line in lines if line.startswith("- Organisation")], ["- Organisation: none"])
        self.assertIn("organisation", configuration)
        self.assertIsNone(configuration["organisation"])
        self.assertFalse((self.home / "orgs").exists())

    def test_d_lines_are_in_the_section(self):
        (self.home / "orgs" / "acme" / "tools").mkdir(parents=True)
        self.named()
        text = self.run_laneboss("start", "--config", "alpha").stdout
        lines = [line for line in text.splitlines() if line.startswith("- Organisation")]
        self.assertEqual(len(lines), 2)
        body = section(text, "Configuration")
        for line in lines:
            self.assertIn(line, body)
        self.assertEqual([line for line in body if line.strip()][0], "- Name: alpha")
        self.assertEqual(text.splitlines()[0], "# Laneboss session briefing")

    def test_d_nothing_is_created_under_orgs(self):
        tools = self.home / "orgs" / "acme" / "tools"
        tools.mkdir(parents=True)
        (tools / "tool.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        self.write_org("protocol/common.md", ORG_COMMON)
        self.with_rules("protocol/common.md")
        before = tree(self.home / "orgs")
        for number, arguments in enumerate(((), ("--role", "top"), ("--format", "json"))):
            source = self.directory / "d-brief-{}.md".format(number)
            source.write_text("# Brief\n\nSay hello.\n", encoding="utf-8")
            self.run_laneboss("start", "--config", "alpha", *arguments)
            self.run_laneboss("doctor", "--config", "alpha")
            self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "d-lane-{}".format(number), "--in",
                              source, "--out", self.directory / "d-rendered-{}.md".format(number))
        self.assertEqual(tree(self.home / "orgs"), before)


class DoctorTest(OrganisationCase):
    """E. The check organisation.tools."""

    def checks(self, code):
        before = tree(self.home)
        result = self.run_laneboss("doctor", "--config", "alpha", code=code)
        checks = {}
        for line in result.stdout.splitlines():
            item = json.loads(line)
            self.assertEqual(set(item), {"check", "ok", "detail"})
            checks[item["check"]] = item
        self.assertEqual(tree(self.home), before, "doctor changed the configuration home")
        return checks

    def test_e_no_organisation_is_named(self):
        self.write_config("alpha")
        check = self.checks(0)["organisation.tools"]
        self.assertEqual((check["ok"], check["detail"]), (True, "no organisation is named"))

    def test_e_the_tools_directory_exists(self):
        self.named()
        (self.home / "orgs" / "acme" / "tools").mkdir(parents=True)
        checks = self.checks(0)
        self.assertIs(checks["organisation.tools"]["ok"], True, checks["organisation.tools"])
        self.assertTrue(all(item["ok"] for item in checks.values()), checks)

    def test_e_tools_may_be_a_link(self):
        self.named()
        elsewhere = self.directory / "dotfiles-tools"
        elsewhere.mkdir()
        (self.home / "orgs" / "acme").mkdir(parents=True)
        os.symlink(str(elsewhere), str(self.home / "orgs" / "acme" / "tools"))
        self.assertIs(self.checks(0)["organisation.tools"]["ok"], True)

    def test_e_the_tools_directory_is_missing(self):
        tools = self.home / "orgs" / "acme" / "tools"
        self.named()
        for made in ("no orgs/", "organisation directory only"):
            with self.subTest(made):
                if made != "no orgs/":
                    (self.home / "orgs" / "acme").mkdir(parents=True)
                checks = self.checks(1)
                self.assertIs(checks["organisation.tools"]["ok"], False)
                self.assertIn(str(tools), checks["organisation.tools"]["detail"])
                self.assertIs(checks["config"]["ok"], True)
                self.assertIs(checks["runner.local"]["ok"], True)
        self.assertFalse(tools.exists())

    def test_e_the_tools_path_is_a_regular_file(self):
        tools = self.write_org("tools", "not a directory\n")
        self.named()
        checks = self.checks(1)
        self.assertIs(checks["organisation.tools"]["ok"], False)
        self.assertIn(str(tools), checks["organisation.tools"]["detail"])
        self.assertTrue(tools.is_file())


class UnchangedTest(OrganisationCase):
    """F. A configuration without the two keys behaves as before."""

    def test_f_rendered_brief_is_unchanged(self):
        self.write_config("alpha")
        version = self.laneboss_json("--version")
        protocol = support.PROTOCOL_FILE.read_bytes()
        standing = (self.home / "configs" / "alpha" / "rules" / "standing.md").read_bytes()
        project = (self.home / "configs" / "alpha" / "rules" / "web.md").read_bytes()
        brief = "# Brief: an invented task\n\nRender me.\n"
        for lane, project_name, files in (("f-lane-one", "web", (("rules/standing.md", standing),
                                                                  ("rules/web.md", project))),
                                          ("f-lane-two", None, (("rules/standing.md", standing),))):
            with self.subTest(project=project_name):
                header = "\n".join([
                    "", "<!-- laneboss launcher block: begin (protocol {}) -->".format(version["protocol_version"]), "",
                    "---", "", "# Launcher block", "",
                    "Everything above this block is the brief exactly as written. laneboss {} appended this "
                    "block.".format(version["version"]), "", "- Configuration: alpha",
                    "- Project: " + (project_name or "none"), "- Lane: " + lane,
                    "- Protocol version: " + version["protocol_version"],
                    "- Brief sha256: " + support.digest(brief), "", ""]).encode("utf-8")
                expected = ended(brief.encode("utf-8")) + header + ended(protocol)
                for path, data in files:
                    expected += "\n## Standing rules: {} (sha256 {})\n\n".format(path, support.digest(data)).encode(
                        "utf-8") + ended(data)
                expected += b"\n<!-- laneboss launcher block: end -->\n"
                self.assertEqual(self.render(lane=lane, project=project_name, brief=brief), expected)
                self.assertEqual([path for path, _ in self.rule_inputs()], [path for path, _ in files])
        self.laneboss_json("state", "verify", "--config", "alpha")

    def test_f_briefing_rules_unchanged(self):
        self.write_config("alpha")
        briefing = json.loads(self.run_laneboss("start", "--config", "alpha", "--role", "top", "--format", "json").stdout)
        self.assertEqual([item["path"] for item in briefing["rules"]], ["rules/standing.md", "rules/web.md"])
        alone = json.loads(self.run_laneboss("start", "--config", "alpha", "--format", "json").stdout)
        self.assertEqual([item["path"] for item in alone["rules"]], ["rules/standing.md"])

    def test_f_example_has_no_organisation(self):
        shutil.copytree(str(support.ROOT / "examples" / "minimal"), str(self.home / "configs" / "example"))
        shown = self.laneboss_json("config", "show", "example")["config"]
        self.assertNotIn("organisation", shown)
        self.assertNotIn("organisation_rules", shown)
        self.assertEqual(self.laneboss_json("config", "validate", "example"), {"valid": True, "configs": ["example"]})


class LaneOrganisationTest(lanesupport.LaneTest):
    """B, for a lane started with the stand-in runner."""

    def test_b_a_lane_brief_has_the_org_first(self):
        directory = self.home / "configs" / "alpha"
        text = (directory / "config.toml").read_text(encoding="utf-8")
        anchor = 'rules = ["rules/standing.md"]\n'
        self.assertIn(anchor, text)
        (directory / "config.toml").write_text(
            text.replace(anchor, anchor + 'organisation = "acme"\norganisation_rules = ["protocol/common.md"]\n', 1),
            encoding="utf-8")
        (directory / "rules" / "web.md").write_text(support.WEB_RULES, encoding="utf-8")
        project = directory / "projects" / "web.toml"
        project.write_text(project.read_text(encoding="utf-8") + 'rules = ["rules/web.md"]\n', encoding="utf-8")
        common = self.home / "orgs" / "acme" / "protocol" / "common.md"
        common.parent.mkdir(parents=True)
        common.write_text(ORG_COMMON, encoding="utf-8")
        standing = (directory / "rules" / "standing.md").read_text(encoding="utf-8")
        self.laneboss_json("config", "validate", "alpha")

        started = self.start("web-o1", "--project", "web", "--difficulty", "standard")
        self.wait_event("lane.ended", "web-o1")
        rendered = self.record("web-o1", ended=True)["brief"]["text"]
        positions = [rendered.index(item) for item in (ORG_COMMON, standing, support.WEB_RULES)]
        self.assertEqual(positions, sorted(positions), "the lane's brief is not in the order organisation, "
                                                       "configuration, project")
        heading = "## Standing rules: orgs/acme/protocol/common.md (sha256 {})".format(support.digest(ORG_COMMON))
        self.assertIn(heading, rendered)
        self.assertEqual(support.digest(rendered), started["brief"]["sha256"])
        events = self.lane_events("web-o1", "brief.rendered")
        self.assertEqual(len(events), 1)
        rules = [(item["path"], item["sha256"]) for item in events[0]["payload"]["inputs"] if item["role"] == "rules"]
        self.assertEqual(rules, [("orgs/acme/protocol/common.md", support.digest(ORG_COMMON)),
                                 ("rules/standing.md", support.digest(standing)),
                                 ("rules/web.md", support.digest(support.WEB_RULES))])
        self.assert_sound()

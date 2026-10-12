"""Black-box tests for integrations/gcp/with_identity.py, written from its specification alone.

Every test runs the program as its own process ([sys.executable, "-I", SCRIPT] + arguments), with an environment the
test supplies (never the test runner's own), in a temporary directory of its own, and compares what came back with
values derived from the identity the test itself wrote into the identities file. The commands are system programs
only (/usr/bin/env, /bin/echo, /bin/cat, /bin/sh) and a script named gcloud written by the test into its own bin/
directory; nothing here is a real cloud command, and nothing reads the machine: PATH, HOME, TMPDIR, LANG and TERM
are values of the test's own making, under the test's own temporary directory.
"""
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "integrations" / "gcp" / "with_identity.py"

# The only variables the program may copy from the caller (specification, "What it does", point 2).
COPIED = ("PATH", "HOME", "TMPDIR", "LANG", "TERM")
# Variables of an ambient identity: none of them may reach the command, whatever the caller has set.
AMBIENT = ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CONFIG", "CLOUDSDK_CORE_PROJECT",
           "GCLOUD_PROJECT", "AWS_PROFILE", "AZURE_CLIENT_ID")
# The four an identity does not provide: the other three of AMBIENT are set by the identity itself, not the caller.
NOT_PROVIDED_BY_AN_IDENTITY = ("GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "AWS_PROFILE", "AZURE_CLIENT_ID")
AMBIENT_VALUE = "ambient-value"
LIMIT = 65536  # the identities file is at most 64 KiB
NAME_32 = "a" * 32  # the longest NAME the grammar allows: [a-z0-9][a-z0-9-]{0,31}
NAME_33 = "a" * 33  # one character too many
GOOD_TAIL = ("gcloud", "projects", "list")  # a command that is allowed to run, used to prove a refusal did not run


def table(name, config_dir=None, project=None, key_file=None, extra=()):
    """The TOML of one [identities.NAME] table, from the values this test chose (absent means the key is absent)."""
    lines = ["[identities.%s]" % name]
    if config_dir is not None:
        lines.append('config_dir = "%s"' % config_dir)
    if project is not None:
        lines.append('project = "%s"' % project)
    if key_file is not None:
        lines.append('key_file = "%s"' % key_file)
    lines.extend(extra)
    return "\n".join(lines) + "\n"


def document(tables, schema="schema_version = 1\n", top=()):
    """A whole identities file: the schema_version line, then any extra top-level keys, then the tables."""
    return schema + "".join(top) + "".join(tables)


def pad_to(text, size):
    """TEXT grown to exactly SIZE bytes with TOML comment lines, and blank lines for the remainder."""
    have = len(text.encode("utf-8"))
    filler = size - have
    if filler < 0:
        raise AssertionError("the identities text is %d bytes, more than the %d asked for" % (have, size))
    return text + ("#" * 72 + "\n") * (filler // 73) + "\n" * (filler % 73)


class WithIdentityTest(unittest.TestCase):
    """One temporary directory per test: bin/ for marker commands, home/, a TMPDIR for the child, identity dirs."""

    def setUp(self):
        held = tempfile.TemporaryDirectory(prefix="with-identity-")
        self.addCleanup(held.cleanup)
        self.dir = held.name
        self.bin = self.make_dir("bin")
        self.home = self.make_dir("home")
        self.child_tmp = self.make_dir("child-tmp")
        self.marker = os.path.join(self.dir, "marker")

    def make_dir(self, name):
        path = os.path.join(self.dir, name)
        os.mkdir(path)
        return path

    def config_dir(self, name):
        """An existing directory that an identity's config_dir can point at."""
        return self.make_dir(name)

    def key_file(self, name):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"type": "service_account"}\n')
        return path

    def identities_file(self, text, name="ids.toml"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def marker_commands(self, *names):
        """An executable shell script of each name in bin/, each appending a line to the marker file when run."""
        for name in names:
            path = os.path.join(self.bin, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('#!/bin/sh\nprintf "ran %s\\n" >> "%s"\n' % (name, self.marker))
            os.chmod(path, 0o755)

    def ident_env(self, copied=True, extra=()):
        """The caller's environment: the five copyable ones, the seven ambient ones, and one unrelated variable."""
        env = {}
        if copied:
            env.update({"PATH": self.bin, "HOME": self.home, "TMPDIR": self.child_tmp, "LANG": "C",
                        "TERM": "dumb"})
        for name in AMBIENT:
            env[name] = AMBIENT_VALUE
        env["FOO"] = "bar"
        env.update(dict(extra))
        return env

    def call(self, arguments, env=None, stdin=""):
        """Run the program as its own process, with the environment given, in this test's directory."""
        if not os.path.isfile(SCRIPT):
            self.fail("the program under test is not there: %s" % SCRIPT)
        if env is None:
            env = self.ident_env()
        return subprocess.run([sys.executable, "-I", str(SCRIPT)] + list(arguments), env=env, cwd=self.dir,
                              input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
                              errors="replace", timeout=120)

    def expect_refused(self, proc):
        """A refusal: exit status 2, nothing on stdout, a first stderr line starting refused:, command not run."""
        self.assertEqual(proc.returncode, 2, "stdout=%r stderr=%r" % (proc.stdout, proc.stderr))
        self.assertEqual(proc.stdout, "", "a refusal prints nothing on stdout, it printed %r" % proc.stdout)
        lines = proc.stderr.splitlines()
        self.assertTrue(lines and lines[0].startswith("refused:"),
                        "the first line of stderr must start with refused:, stderr is %r" % proc.stderr)
        self.assertFalse(os.path.exists(self.marker),
                         "the command was run, although the call was refused: stderr=%r" % proc.stderr)
        self.assertEqual(len(lines), 1, "a refusal is one line, stderr is %r" % proc.stderr)
        self.assertNotIn(AMBIENT_VALUE, proc.stderr)

    def refused_run(self, identities_path, name, command=("gcloud", "projects", "list")):
        """Run COMMAND under NAME against IDENTITIES_PATH and assert the whole refusal of it."""
        self.marker_commands("gcloud", "other")
        proc = self.call(["--identities", identities_path, name, "--"] + list(command))
        self.expect_refused(proc)
        return proc

    def refused_argv(self, argv):
        """Run the whole command line ARGV and assert it is refused and that the marker command was not run."""
        self.marker_commands("gcloud", "other")
        proc = self.call(argv)
        self.expect_refused(proc)
        return proc

    def child_env(self, proc):
        """The environment the command received, as a dict parsed out of the output of /usr/bin/env."""
        got = {}
        for line in proc.stdout.splitlines():
            self.assertIn("=", line, "not a NAME=value line in the environment: %r" % line)
            key, _, value = line.partition("=")
            got[key] = value
        return got

    def expected_env(self, outer, name, config_dir, project=None, key_file=None):
        """The command's whole environment: the copied variables the caller had, plus this identity's own values."""
        want = dict((key, value) for key, value in outer.items() if key in COPIED)
        want["CLOUDSDK_CONFIG"] = config_dir
        want["WITH_IDENTITY_NAME"] = name
        if project is not None:
            want["CLOUDSDK_CORE_PROJECT"] = project
        if key_file is not None:
            want["GOOGLE_APPLICATION_CREDENTIALS"] = key_file
        return want

    def assert_environment(self, identities_path, outer, name, config_dir, project=None, key_file=None,
                           command=("/usr/bin/env",)):
        """Run the program and compare the command's WHOLE environment with what this identity requires."""
        proc = self.assert_ran(identities_path, name, command=command, outer=outer)
        got = self.child_env(proc)
        want = self.expected_env(outer, name, config_dir, project=project, key_file=key_file)
        self.assertEqual(got, want, "variables that must not reach the command: %s" % sorted(set(got) - set(want)))
        return proc

    def assert_ran(self, identities_path, name, command=("/bin/echo", "ran"), outer=None):
        """Run the program under NAME and assert the command ran: it is found and its own exit status is 0."""
        if outer is None:
            outer = self.ident_env()
        proc = self.call(["--identities", identities_path, name, "--"] + list(command), env=outer)
        self.assertEqual(proc.returncode, 0, "the command did not run: stdout=%r stderr=%r"
                         % (proc.stdout, proc.stderr))
        return proc


class HelpTest(WithIdentityTest):  # case A
    def test_dash_h_prints_usage_and_exits_0(self):
        """fails when: -h is treated as a refusal, or the usage text does not name the --identities option."""
        proc = self.call(["-h"])
        self.assertEqual(proc.returncode, 0, "stderr=%r" % proc.stderr)
        self.assertIn("--identities", proc.stdout + proc.stderr)

    def test_double_dash_help_exits_0(self):
        """fails when: --help is refused, or it prints no usage text at all."""
        proc = self.call(["--help"])
        self.assertEqual(proc.returncode, 0, "stderr=%r" % proc.stderr)
        self.assertNotEqual((proc.stdout + proc.stderr).strip(), "", "--help printed nothing")
        self.assertIn("--identities", proc.stdout + proc.stderr)


class EnvironmentTest(WithIdentityTest):  # case B: the heart of the work
    def test_environment_is_built_from_scratch(self):
        """fails when: any variable of the caller survives, or a value is the ambient one and not the identity's."""
        self.assertEqual(len(COPIED), 5)
        self.assertEqual(len(AMBIENT), 7)
        config = self.config_dir("dir-alpha")
        key = self.key_file("key-alpha.json")
        identities = self.identities_file(document([table("alpha", config, project="proj-alpha-1", key_file=key)]))
        outer = self.ident_env()
        proc = self.assert_environment(identities, outer, "alpha", config, project="proj-alpha-1", key_file=key)
        got = self.child_env(proc)
        for name in COPIED:
            self.assertIn(name, got, "%s was set by the caller and must be copied" % name)
        for name in NOT_PROVIDED_BY_AN_IDENTITY:
            self.assertNotIn(name, got, "an ambient variable reached the command")
        self.assertNotIn("FOO", got, "an unrelated variable of the caller reached the command")
        self.assertEqual(got["CLOUDSDK_CONFIG"], config, "CLOUDSDK_CONFIG is not the identity's directory")
        self.assertEqual(got["GOOGLE_APPLICATION_CREDENTIALS"], key, "the credentials are not the identity's file")

    def test_nothing_invented_bare_name(self):
        """fails when: the program invents PATH/HOME/TMPDIR/LANG/TERM the caller had not set, or cannot search."""
        config = self.config_dir("dir-beta")
        identities = self.identities_file(document([table("beta", config, project="proj-beta-22")]),
                                          name="other-identities.toml")
        outer = self.ident_env(copied=False)
        proc = self.assert_environment(identities, outer, "beta", config, project="proj-beta-22",
                                       command=("env",))  # a bare name, with no PATH anywhere
        got = self.child_env(proc)
        for name in COPIED:
            self.assertNotIn(name, got, "%s was not set by the caller and must not be invented" % name)


class OptionalKeysTest(WithIdentityTest):  # case C
    def test_identity_without_optional_keys(self):
        """fails when: the caller's own project or credentials are passed on to an identity that has none."""
        config = self.config_dir("dir-plain")
        identities = self.identities_file(document([table("plain", config)]))
        outer = self.ident_env()
        proc = self.assert_environment(identities, outer, "plain", config)
        got = self.child_env(proc)
        self.assertNotIn("CLOUDSDK_CORE_PROJECT", got, "the caller's project reached a projectless identity")
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", got, "the caller's credentials reached a keyless identity")


class SeveralNamesTest(WithIdentityTest):  # case D
    def test_two_identities_in_one_file(self):
        """fails when: the wrong table is picked, or the values of the other identity appear in the environment."""
        config_one = self.config_dir("dir-one")
        config_two = self.config_dir("dir-two")
        key_one = self.key_file("key-one.json")
        identities = self.identities_file(document([table("one", config_one, project="proj-one-11", key_file=key_one),
                                                    table("two", config_two, project="proj-two-22")]))
        outer = self.ident_env()
        first = self.assert_environment(identities, outer, "one", config_one, project="proj-one-11", key_file=key_one)
        second = self.assert_environment(identities, outer, "two", config_two, project="proj-two-22")
        self.assertIn("WITH_IDENTITY_NAME=one\n", first.stdout)
        self.assertIn("WITH_IDENTITY_NAME=two\n", second.stdout)
        for absent in (config_two, "proj-two-22"):
            self.assertNotIn(absent, first.stdout, "identity two is leaking into the run of identity one")
        for absent in (config_one, "proj-one-11", key_one):
            self.assertNotIn(absent, second.stdout, "identity one is leaking into the run of identity two")


class CommandLineShapeTest(WithIdentityTest):  # case E: the command line has exactly one shape
    def setUp(self):
        super().setUp()
        self.config = self.config_dir("dir-shape")
        self.identities = self.identities_file(document([table("id1", self.config)]))

    def test_without_identities_option(self):
        """fails when: a command line with no --identities is accepted and some identity is used."""
        self.refused_argv(["id1", "--"] + list(GOOD_TAIL))

    def test_identities_option_without_a_file(self):
        """fails when: --identities is accepted with nothing after it to name the file."""
        self.refused_argv(["--identities"])

    def test_without_a_name(self):
        """fails when: the identity NAME is optional and the program falls back to a default identity."""
        self.refused_argv(["--identities", self.identities, "--"] + list(GOOD_TAIL))

    def test_without_the_double_dash(self):
        """fails when: the -- separator is optional and the command is taken from the wrong place."""
        self.refused_argv(["--identities", self.identities, "id1", "other", "gcloud", "projects", "list"])

    def test_nothing_after_the_double_dash(self):
        """fails when: a command line with no COMMAND after -- is accepted."""
        self.refused_argv(["--identities", self.identities, "id1", "--"])

    def test_extra_word_before_dash_refused(self):
        """fails when: a second word before -- is silently ignored instead of refused."""
        self.refused_argv(["--identities", self.identities, "id1", "extra", "--"] + list(GOOD_TAIL))

    def test_options_after_name_refused(self):
        """fails when: --identities is accepted after the NAME, where the shape says it must come first."""
        self.refused_argv(["id1", "--identities", self.identities, "--"] + list(GOOD_TAIL))


class NameGrammarTest(WithIdentityTest):  # case F: NAME matches [a-z0-9][a-z0-9-]{0,31}
    def setUp(self):
        super().setUp()
        self.config = self.config_dir("dir-names")
        self.identities = self.identities_file(document([table("id1", self.config), table(NAME_32, self.config)]))
        # Every refused name is a defined table here, so that only the grammar can refuse it.
        self.bad_names = self.identities_file(
            document([table(n, self.config) for n in ("Bad", "bad", "a_b", '"../x"', '""', NAME_32, NAME_33,
                                                      '"id1;touch MARK"')]),
            name="bad-names.toml")

    def test_upper_case_name_refused(self):
        """fails when: the NAME is matched case-insensitively, so Bad is taken for bad."""
        self.refused_argv(["--identities", self.bad_names, "Bad", "--"] + list(GOOD_TAIL))

    def test_name_with_a_path_refused(self):
        """fails when: ../ in a NAME is accepted and the identity is read from another directory."""
        self.refused_argv(["--identities", self.bad_names, "../x", "--"] + list(GOOD_TAIL))

    def test_name_with_an_underscore_refused(self):
        """fails when: the NAME grammar allows a character that is not a lower-case letter, digit or dash."""
        self.refused_argv(["--identities", self.bad_names, "a_b", "--"] + list(GOOD_TAIL))

    def test_empty_name_refused(self):
        """fails when: an empty NAME is accepted, for instance as a default identity."""
        self.refused_argv(["--identities", self.bad_names, "", "--"] + list(GOOD_TAIL))

    def test_name_of_33_characters_refused(self):
        """fails when: the length of a NAME is not bounded by 32 characters."""
        self.refused_argv(["--identities", self.bad_names, NAME_33, "--"] + list(GOOD_TAIL))

    def test_name_32_chars_accepted(self):
        """fails when: the NAME grammar is tighter than 32 characters and refuses a legal name."""
        self.assertEqual(len(NAME_32), 32)
        proc = self.assert_ran(self.identities, NAME_32, command=("/usr/bin/env",))
        self.assertIn("WITH_IDENTITY_NAME=" + NAME_32 + "\n", proc.stdout)
        self.assertIn("CLOUDSDK_CONFIG=" + self.config + "\n", proc.stdout)


class IdentitiesFileTest(WithIdentityTest):  # case G: the file and the table are checked, in order
    def setUp(self):
        super().setUp()
        self.config = self.config_dir("dir-checked")

    def test_file_that_does_not_exist_refused(self):
        """fails when: a missing identities file is accepted and an ambient or default identity is used."""
        self.refused_run(os.path.join(self.dir, "absent.toml"), "id1")

    def test_directory_not_a_file_refused(self):
        """fails when: anything readable is taken for an identities file, a directory included."""
        self.refused_run(self.config_dir("not-a-file"), "id1")

    def test_file_bigger_than_64_kib_refused(self):
        """fails when: the 64 KiB bound on the identities file is missing or bigger than 64 KiB."""
        path = self.identities_file(pad_to(document([table("id1", self.config)]), LIMIT + 1), name="big.toml")
        with open(path, "rb") as handle:
            self.assertEqual(len(handle.read()), LIMIT + 1, "the test did not build a file of 65537 bytes")
        self.refused_run(path, "id1")

    def test_file_of_exactly_64_kib_accepted(self):
        """fails when: the bound is read as smaller than 64 KiB and refuses a file of exactly 65536 bytes."""
        path = self.identities_file(pad_to(document([table("id1", self.config, project="proj-pad-01")]), LIMIT),
                                    name="exact.toml")
        with open(path, "rb") as handle:
            raw = handle.read()
        self.assertEqual(len(raw), LIMIT, "the test did not build a file of exactly 65536 bytes")
        self.assertIn(b"[identities.id1]", raw, "the test built a file whose table is not there")
        self.assert_environment(path, self.ident_env(), "id1", self.config, project="proj-pad-01")

    def test_invalid_toml_refused(self):
        """fails when: an unparsable file is accepted, or a parse error is reported as something else than 2."""
        path = self.identities_file("schema_version = 1\n[identities.id1\nconfig_dir = \n", name="broken.toml")
        self.refused_run(path, "id1")

    def test_no_schema_version_refused(self):
        """fails when: a file with no schema_version is taken for version 1."""
        path = self.identities_file(document([table("id1", self.config)], schema=""), name="no-version.toml")
        self.refused_run(path, "id1")

    def test_schema_version_2_refused(self):
        """fails when: a schema version the program does not implement is accepted anyway."""
        path = self.identities_file(document([table("id1", self.config)], schema="schema_version = 2\n"),
                                    name="v2.toml")
        self.refused_run(path, "id1")

    def test_schema_version_as_a_string_refused(self):
        """fails when: schema_version is compared loosely, so the string "1" passes for the integer 1."""
        path = self.identities_file(document([table("id1", self.config)], schema='schema_version = "1"\n'),
                                    name="string-version.toml")
        self.refused_run(path, "id1")

    def test_unknown_top_level_key_refused(self):
        """fails when: a top-level key other than schema_version and identities is ignored."""
        path = self.identities_file(document([table("id1", self.config)], top=["unknown_top = 1\n"]),
                                    name="extra-top.toml")
        self.refused_run(path, "id1")

    def test_undefined_name_refused(self):
        """fails when: a NAME that is not a table falls back to another identity in the same file."""
        path = self.identities_file(document([table("some-other-name", self.config)]), name="other.toml")
        self.refused_run(path, "id1")

    def test_unknown_table_key_refused(self):
        """fails when: a key the table must not hold (a service account, a token) is ignored."""
        path = self.identities_file(document([table("id1", self.config, extra=['note = "x"'])]), name="extra-key.toml")
        self.refused_run(path, "id1")

    def test_config_dir_missing_refused(self):
        """fails when: an identity without config_dir runs with the machine's own gcloud configuration."""
        path = self.identities_file(document([table("id1", project="proj-nocfg-1")]), name="no-config.toml")
        self.refused_run(path, "id1")

    def test_config_dir_relative_refused(self):
        """fails when: a relative config_dir is made absolute against the current directory."""
        path = self.identities_file(document([table("id1", "dir-checked")]), name="rel-config.toml")
        self.refused_run(path, "id1")

    def test_config_dir_absent_path_refused(self):
        """fails when: config_dir is only checked for being a string, not for being an existing directory."""
        path = self.identities_file(document([table("id1", os.path.join(self.dir, "never-created"))]),
                                    name="gone-config.toml")
        self.refused_run(path, "id1")

    def test_config_dir_is_file_refused(self):
        """fails when: config_dir need only exist, whatever it points at."""
        path = self.identities_file(document([table("id1", self.key_file("file-as-config"))]),
                                    name="file-config.toml")
        self.refused_run(path, "id1")

    def test_project_upper_case_refused(self):
        """fails when: the project pattern is applied case-insensitively."""
        path = self.identities_file(document([table("id1", self.config, project="Proj-abc1")]), name="upper.toml")
        self.refused_run(path, "id1")

    def test_project_of_5_characters_refused(self):
        """fails when: the project pattern allows fewer than 6 characters."""
        path = self.identities_file(document([table("id1", self.config, project="abcde")]), name="short.toml")
        self.refused_run(path, "id1")

    def test_project_of_6_characters_accepted(self):
        """fails when: the project pattern is tighter than the specification and refuses its shortest legal value."""
        path = self.identities_file(document([table("id1", self.config, project="abcdef")]), name="min.toml")
        self.assert_environment(path, self.ident_env(), "id1", self.config, project="abcdef")

    def test_project_of_31_characters_refused(self):
        """fails when: the project pattern allows more than 30 characters."""
        path = self.identities_file(document([table("id1", self.config, project="a" * 31)]), name="long.toml")
        self.refused_run(path, "id1")

    def test_project_of_30_characters_accepted(self):
        """fails when: the project pattern is tighter than 30 characters and refuses its longest legal value."""
        path = self.identities_file(document([table("id1", self.config, project="a" * 30)]), name="max.toml")
        self.assert_environment(path, self.ident_env(), "id1", self.config, project="a" * 30)

    def test_key_file_relative_refused(self):
        """fails when: a relative key_file is made absolute against the current directory."""
        self.key_file("relative-key.json")
        path = self.identities_file(document([table("id1", self.config, key_file="relative-key.json")]),
                                    name="rel-key.toml")
        self.refused_run(path, "id1")

    def test_key_file_missing_refused(self):
        """fails when: key_file is not checked for existing, so the command gets a path to nothing."""
        path = self.identities_file(document([table("id1", self.config, key_file=os.path.join(self.dir, "no.json"))]),
                                    name="gone-key.toml")
        self.refused_run(path, "id1")

    def test_key_file_directory_refused(self):
        """fails when: key_file need only exist, whatever it points at."""
        path = self.identities_file(document([table("id1", self.config, key_file=self.config_dir("dir-as-key"))]),
                                    name="dir-key.toml")
        self.refused_run(path, "id1")

    def test_key_file_of_mode_000_accepted(self):
        """fails when: the program opens or tests the key file, instead of using only its path."""
        key = self.key_file("unreadable-key.json")
        os.chmod(key, 0o000)
        # a suite run as root can read it, and then the test would prove nothing: fail loudly
        with self.assertRaises(PermissionError):
            open(key, "rb").close()
        path = self.identities_file(document([table("id1", self.config, key_file=key)]), name="mode000.toml")
        self.assert_environment(path, self.ident_env(), "id1", self.config, key_file=key)

    def test_schema_version_true_refused(self):
        """fails when: the TOML boolean true is taken for the integer 1 of schema_version."""
        path = self.identities_file(document([table("id1", self.config)], schema="schema_version = true\n"),
                                    name="bool-version.toml")
        self.refused_run(path, "id1")

    def test_schema_version_float_refused(self):
        """fails when: the TOML float 1.0 is taken for the integer 1 of schema_version."""
        path = self.identities_file(document([table("id1", self.config)], schema="schema_version = 1.0\n"),
                                    name="float-version.toml")
        self.refused_run(path, "id1")

    def test_identities_not_a_table_refused(self):
        """fails when: a top-level identities that is not a table is taken for the table of names."""
        path = self.identities_file("schema_version = 1\nidentities = []\n", name="identities-list.toml")
        self.refused_run(path, "id1")

    def test_identity_not_a_table_refused(self):
        """fails when: an entry of identities that is not a table is taken for the identity itself."""
        path = self.identities_file('schema_version = 1\n[identities]\nid1 = ["config_dir"]\n',
                                    name="identity-string.toml")
        self.refused_run(path, "id1")

    def test_config_dir_number_refused(self):
        """fails when: a config_dir that is not a string is accepted for the directory it should name."""
        path = self.identities_file('schema_version = 1\n[identities.id1]\nconfig_dir = 5\n',
                                    name="config-number.toml")
        self.refused_run(path, "id1")

    def test_project_number_refused(self):
        """fails when: a project that is not a string is accepted, since only its text can match the pattern."""
        path = self.identities_file(document([table("id1", self.config, extra=["project = 5"])]),
                                    name="project-number.toml")
        self.refused_run(path, "id1")

    def test_key_file_number_refused(self):
        """fails when: a key_file that is not a string is accepted, since only its text can name a file."""
        path = self.identities_file(document([table("id1", self.config, extra=["key_file = 5"])]),
                                    name="key-number.toml")
        self.refused_run(path, "id1")

    def test_project_digit_first_refused(self):
        """fails when: the project pattern allows a first character that is a digit."""
        path = self.identities_file(document([table("id1", self.config, project="1abcde")]),
                                    name="project-digit-first.toml")
        self.refused_run(path, "id1")

    def test_project_dash_last_refused(self):
        """fails when: the project pattern allows a last character that is a dash."""
        path = self.identities_file(document([table("id1", self.config, project="abcde-")]),
                                    name="project-dash-last.toml")
        self.refused_run(path, "id1")

    def test_config_dir_nul_refused(self):
        """fails when: a NUL character in config_dir is an internal error instead of a refusal."""
        path = self.identities_file("schema_version = 1\n[identities.id1]\nconfig_dir = \"/tmp\\u0000x\"\n",
                                    name="nul-config.toml")
        self.refused_run(path, "id1")

    def test_key_with_a_line_break_refused(self):
        """fails when: a refusal quotes a key of the file and so spans several lines."""
        path = self.identities_file(document([table("id1", self.config)], top=['"two\\nlines" = 1\n']),
                                    name="two-lines.toml")
        self.refused_run(path, "id1")

    def test_table_key_line_break_refused(self):
        """fails when: a key of an identity's table that is not allowed is echoed in the refusal, so the refusal
        is more than one line."""
        path = self.identities_file(document([table("id1", self.config, extra=['"two\\nlines" = 1'])]),
                                    name="table-two-lines.toml")
        self.refused_run(path, "id1")


class CommandLookupTest(WithIdentityTest):  # case H: the command is found, or the call is refused
    def setUp(self):
        super().setUp()
        self.config = self.config_dir("dir-lookup")
        self.identities = self.identities_file(document([table("id1", self.config)]))

    def test_command_not_on_path_refused(self):
        """fails when: a name is execed outside the PATH the caller passed, or not found is not a refusal."""
        self.refused_run(self.identities, "id1", command=("no-such-command-zq9",))

    def test_slash_path_missing_refused(self):
        """fails when: a COMMAND containing / is execed without checking that it exists."""
        self.refused_run(self.identities, "id1", command=(os.path.join(self.dir, "no-such-file-zq9"),))

    def test_slash_path_not_executable_refused(self):
        """fails when: the executable bit is not checked for a COMMAND that contains /."""
        path = os.path.join(self.dir, "not-executable")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('#!/bin/sh\necho ran\n')
        os.chmod(path, 0o644)
        self.refused_run(self.identities, "id1", command=(path,))
        os.chmod(path, 0o755)  # the same file does run once it is executable: the refusal was about that bit
        proc = self.assert_ran(self.identities, "id1", command=(path,))
        self.assertEqual(proc.stdout, "ran\n")

    def test_directory_as_command_refused(self):
        """fails when: a directory is taken for a command."""
        self.refused_run(self.identities, "id1", command=(self.bin,))


class DeniedGcloudTest(WithIdentityTest):  # case I: the plain log-in and configuration-changing forms are refused
    def setUp(self):
        super().setUp()
        self.config = self.config_dir("dir-denied")
        self.identities = self.identities_file(document([table("id1", self.config)]))

    def denied(self, *arguments, name="gcloud"):
        """Run NAME with these arguments and assert the refusal: exit 2, refused:, nothing on stdout, not run."""
        self.marker_commands("gcloud", "other")
        proc = self.call(["--identities", self.identities, "id1", "--", name] + list(arguments))
        self.expect_refused(proc)
        return proc

    def ran_marker(self, expected_lines, *arguments, name="gcloud"):
        """Run NAME with these arguments and assert the marker script ran and wrote these lines."""
        self.marker_commands("gcloud", "other")
        proc = self.call(["--identities", self.identities, "id1", "--", name] + list(arguments))
        self.assertEqual(proc.returncode, 0, "the allowed form was refused: stderr=%r" % proc.stderr)
        self.assertEqual(proc.stdout, "")
        with open(self.marker, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), expected_lines)

    def test_auth_login_refused(self):
        """fails when: gcloud auth login runs and puts the machine's ambient identity into the identity's home."""
        self.denied("auth", "login")

    def test_auth_activate_refused(self):
        """fails when: gcloud auth activate-service-account runs and swaps credentials in."""
        self.denied("auth", "activate-service-account")

    def test_auth_appdefault_login_refused(self):
        """fails when: the application-default log-in is not one of the denied prefixes."""
        self.denied("auth", "application-default", "login")

    def test_auth_appdefault_token_refused(self):
        """fails when: printing an access token is allowed, whatever follows application-default."""
        self.denied("auth", "application-default", "print-access-token")

    def test_config_set_refused(self):
        """fails when: gcloud config set runs and changes the configuration of this identity."""
        self.denied("config", "set", "project", "x")

    def test_config_configurations_refused(self):
        """fails when: gcloud config configurations runs and creates or lists configurations."""
        self.denied("config", "configurations", "list")

    def test_allowed_gcloud_forms_run(self):
        """fails when: the denial is too wide and a read-only gcloud form no longer runs."""
        self.ran_marker("ran gcloud\n", "projects", "list")
        self.ran_marker("ran gcloud\nran gcloud\n", "auth", "list")
        self.ran_marker("ran gcloud\nran gcloud\nran gcloud\n", "config", "get-value", "project")

    def test_other_command_name_runs(self):
        """fails when: the denial looks at the arguments only, and refuses a program that is not gcloud."""
        self.ran_marker("ran other\n", "auth", "login", name="other")

    def test_auth_login_refused_by_path(self):
        """fails when: the denial compares the typed command instead of the base name of the command."""
        self.denied("auth", "login", name=os.path.join(self.bin, "gcloud"))


class ValuesAreNotPrintedTest(WithIdentityTest):  # case J: a refusal names the key, never the value
    def setUp(self):
        super().setUp()
        self.config = self.config_dir("dir-quiet")

    def test_bad_project_not_printed(self):
        """fails when: a refusal quotes the value it did not like, leaking a secret into the log."""
        secret = "Secret_Value_Zq9"  # invalid: upper-case letters and an underscore
        path = self.identities_file(document([table("id1", self.config, project=secret)]), name="secret-a.toml")
        proc = self.refused_run(path, "id1", command=("/bin/echo", "run"))
        combined = proc.stdout + proc.stderr
        self.assertNotIn(secret, combined)
        self.assertIn("project", combined, "the refusal does not name the key project")

    def test_bad_config_dir_not_printed(self):
        """fails when: a refusal quotes the path it did not like, leaking where the identity lives."""
        secret = "/nonexistent/secret-dir-zq9"
        path = self.identities_file(document([table("id1", secret)]), name="secret-b.toml")
        proc = self.refused_run(path, "id1", command=("/bin/echo", "run"))
        combined = proc.stdout + proc.stderr
        self.assertNotIn(secret, combined)
        self.assertIn("config_dir", combined, "the refusal does not name the key config_dir")


class ExitStatusAndStreamsTest(WithIdentityTest):  # case K: the command is replaced, the streams passed on
    def setUp(self):
        super().setUp()
        self.config = self.config_dir("dir-status")
        self.identities = self.identities_file(document([table("id1", self.config)]))

    def test_command_exit_status_kept(self):
        """fails when: the wrapper stays alive and reports its own status instead of becoming the command."""
        proc = self.call(["--identities", self.identities, "id1", "--", "/bin/sh", "-c", "exit 7"])
        self.assertEqual(proc.returncode, 7, "stderr=%r stdout=%r" % (proc.stderr, proc.stdout))
        self.assertNotIn("refused:", proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_command_stdout_arrives(self):
        """fails when: the command output is swallowed, buffered twice, or wrapped in other text."""
        proc = self.call(["--identities", self.identities, "id1", "--", "/bin/echo", "hello", "world"])
        self.assertEqual(proc.returncode, 0, "stderr=%r" % proc.stderr)
        self.assertEqual(proc.stdout, "hello world\n")

    def test_stdin_reaches_command(self):
        """fails when: the command is given no standard input, or something else than the caller's."""
        given = "alpha line\nbeta line\n"
        proc = self.call(["--identities", self.identities, "id1", "--", "/bin/cat"], stdin=given)
        self.assertEqual(proc.returncode, 0, "stderr=%r" % proc.stderr)
        self.assertEqual(proc.stdout, given)

    def test_arguments_with_spaces_kept(self):
        """fails when: the arguments are joined with a space, so one argument becomes two."""
        proc = self.call(["--identities", self.identities, "id1", "--", "/bin/echo", "a b", '"c"', ""])
        self.assertEqual(proc.returncode, 0, "stderr=%r" % proc.stderr)
        self.assertEqual(proc.stdout, 'a b "c" \n')

    def test_the_wrapper_becomes_the_command(self):
        """fails when: the wrapper runs the command as a child process, so the command has another process id."""
        proc = subprocess.Popen([sys.executable, "-I", str(SCRIPT), "--identities", self.identities, "id1", "--",
                                 "/bin/sh", "-c", "echo $$"], env=self.ident_env(), cwd=self.dir,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        out, err = proc.communicate(timeout=120)
        self.assertEqual(proc.returncode, 0, "stderr=%r" % err)
        self.assertEqual(out.strip(), str(proc.pid))

    def test_pipe_signal_reaches_the_command(self):
        """fails when: the command inherits SIGPIPE as ignored, so a broken pipe becomes a write error (exit 1)
        instead of the signal."""
        proc = self.call(["--identities", self.identities, "id1", "--", "/bin/sh", "-c",
                          "kill -s PIPE $$; echo survived"])
        self.assertEqual(proc.returncode, -signal.SIGPIPE, "stderr=%r stdout=%r" % (proc.stderr, proc.stdout))
        self.assertEqual(proc.stdout, "")

    def test_xfsz_signal_reaches_the_command(self):
        """fails when: the command inherits SIGXFSZ as ignored, so a write past the file-size limit becomes a write
        error instead of the signal."""
        proc = self.call(["--identities", self.identities, "id1", "--", "/bin/sh", "-c",
                          "ulimit -c 0; kill -s XFSZ $$; echo survived"])
        self.assertEqual(proc.returncode, -signal.SIGXFSZ, "stderr=%r stdout=%r" % (proc.stderr, proc.stdout))
        self.assertEqual(proc.stdout, "")


class NoSideEffectsTest(WithIdentityTest):  # case L: the program writes nothing, anywhere
    def listing(self, root):
        """Every name under ROOT, recursively, each with its size: what a run has to leave exactly as it was."""
        entries = []
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                is_dir = os.path.isdir(full)
                entries.append((os.path.relpath(full, root), is_dir, 0 if is_dir else os.path.getsize(full)))
        if len(entries) < 4:
            self.fail("the listing of %s has only %d entries, so comparing it proves nothing" % (root, len(entries)))
        return sorted(entries)

    def test_a_successful_run_writes_nothing(self):
        """fails when: the program writes a cache, a lock, a token file or a log of the run."""
        path = self.identities_file(document([table("id1", self.config_dir("dir-clean"))]))
        self.marker_commands("gcloud", "other")
        before = self.listing(self.dir)
        proc = self.call(["--identities", path, "id1", "--", "/bin/echo", "hello"])
        self.assertEqual(proc.returncode, 0, "stderr=%r" % proc.stderr)
        self.assertEqual(proc.stdout, "hello\n")
        self.assertEqual(self.listing(self.dir), before)

    def test_a_refused_run_writes_nothing(self):
        """fails when: a refusal still writes something: a partial environment, a log, a marker."""
        path = self.identities_file(document([table("id1", "relative-dir")]), name="refused.toml")
        self.marker_commands("gcloud", "other")
        before = self.listing(self.dir)
        proc = self.call(["--identities", path, "id1", "--", "gcloud", "projects", "list"])
        self.expect_refused(proc)
        self.assertEqual(self.listing(self.dir), before)


class NotRunThroughAShellTest(WithIdentityTest):  # case M: nothing is ever given to a shell
    def setUp(self):
        super().setUp()
        self.config = self.config_dir("dir-shell")
        self.identities = self.identities_file(document([table("id1", self.config)]))

    def test_name_semicolon_refused_no_file(self):
        """fails when: the NAME is put into a shell command line, which then runs what follows the ;."""
        self.marker_commands("gcloud", "other")
        path = self.identities_file(document([table('"id1;touch MARK"', self.config), table("id1", self.config)]),
                                    name="semi.toml")
        proc = self.call(["--identities", path, "id1;touch MARK", "--", "gcloud", "projects", "list"])
        self.expect_refused(proc)
        self.assertNotIn("MARK", os.listdir(self.dir))

    def test_semicolon_argument_is_text(self):
        """fails when: the arguments are joined into a shell command line, which then runs what follows the ;."""
        argument = "note;touch MARK"
        proc = self.call(["--identities", self.identities, "id1", "--", "/bin/echo", argument])
        self.assertEqual(proc.returncode, 0, "stderr=%r" % proc.stderr)
        self.assertEqual(proc.stdout, argument + "\n")
        self.assertNotIn("MARK", os.listdir(self.dir))


if __name__ == "__main__":
    unittest.main()

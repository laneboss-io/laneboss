"""M. One-command installation: the root install.sh gets the source of one version and runs that version's own
scripts/install.sh.

Every test drives `sh install.sh` from outside, the way a person does: with a scratch HOME and TMPDIR, a PATH that
holds only the tools the test names (a directory of links, so a test can leave one out or put a stub in its place) and
a source on this machine, LANEBOSS_SOURCE or a repository or tarball reached through a file:// address. Nothing
touches the network and nothing is set from outside. The stand-ins are stubs that provoke a condition or record that
they were run: an `id` that says root or says nothing, a `uname` of another system, interpreters that are too old or
that note their use, a `tar` that never finishes, a `mktemp` that records what it made, a `git` and a `curl` that fail
or record their arguments, and programs named like the first words of the script that must never run.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

from . import support

SCRIPT = support.ROOT / "install.sh"
SH = "/bin/sh"
PROGRAM = support.PROGRAM
VERSION_LINE = re.compile(r'^\s*Version\s*= "([^"]+)"$', re.M)
SYNTAX_ERROR = re.compile(r"(?i)syntax error|unexpected|unterminated|end of file")
INTERPRETERS = ("python3", "python3.14", "python3.13", "python3.12", "python3.11")
# What install.sh and the installer it runs may call. Each is linked into a private directory that is the whole PATH of
# a run. python3 there is the interpreter that runs this suite, so every platform tests one Python.
TOOLS = ("awk", "basename", "cat", "chmod", "cp", "cut", "date", "dirname", "env", "expr", "find", "grep", "gzip", "head",
         "id", "ln", "ls", "mkdir", "mktemp", "mv", "printf", "readlink", "rm", "sed", "sh", "sleep", "sort", "tail",
         "tar", "touch", "tr", "uname", "wc")


def tree_version(root):
    return VERSION_LINE.search((root / "internal" / "identity" / "identity.go").read_text(encoding="utf-8")).group(1)


def copy_tree(destination):
    """The parts of the checkout that the installer reads, copied without caches."""
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    destination.mkdir()
    for name in ("cmd", "internal", "scripts", "plugins", "go.mod", "go.sum"):
        (shutil.copytree(str(support.ROOT / name), str(destination / name), ignore=ignore)
         if (support.ROOT / name).is_dir() else shutil.copy2(support.ROOT / name, destination / name))
    return destination


def change_version(root, suffix):
    """Give the copy at `root` another version number, the old one with `suffix` after it; returns the new one."""
    identity = root / "internal" / "identity" / "identity.go"
    text = identity.read_text(encoding="utf-8")
    current = VERSION_LINE.search(text).group(1)
    identity.write_text(text.replace('Version   = "{}"'.format(current), 'Version   = "{}{}"'.format(current, suffix)),
                        encoding="utf-8")
    return current + suffix


def make_archive(root, target, top=None):
    """A tar of the installable parts of `root`, gzip-compressed when the name ends in .gz, below one top directory
    named `top` (the way a hosting service packs a version) or with no top directory."""

    def clean(member):
        return None if "__pycache__" in member.name or member.name.endswith(".pyc") else member

    with tarfile.open(str(target), "w:gz" if str(target).endswith(".gz") else "w") as archive:
        for name in ("cmd", "internal", "scripts", "plugins", "go.mod", "go.sum"):
            archive.add(str(root / name), arcname=(top + "/" + name) if top else name, filter=clean)
    return target


def snapshot(root):
    """Every entry under `root` with what makes it what it is: a link's target, a file's hash and mode."""
    state = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            state[relative] = ("link", os.readlink(str(path)))
        elif path.is_dir():
            state[relative] = ("directory",)
        else:
            state[relative] = ("file", hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode))
    return state


def outside_lines(data):
    """(start, line) of every line of the script that is neither blank, nor a comment, nor inside the body of its one
    function (from the line `laneboss_bootstrap() {` to the next line that is only `}`)."""
    found, inside, offset = [], False, 0
    for line in data.splitlines(keepends=True):
        if inside:
            inside = line.rstrip(b"\r\n") != b"}"
            if not inside:
                found.append((offset, line))
        elif line.strip() and not line.lstrip().startswith(b"#"):
            found.append((offset, line))
            inside = line.startswith(b"laneboss_bootstrap() {")
        offset += len(line)
    return found


def cut_positions(data):
    """Every length at which the script can be cut inside a line of outside_lines, except the cuts that keep the whole
    last line, which are the whole script."""
    last = len(data) - len(data.splitlines(keepends=True)[-1])
    positions = []
    for start, line in outside_lines(data):
        positions.extend(range(start, start + (len(line.rstrip()) if start == last else len(line))))
    return positions


def has_code(prefix):
    return any(line.strip() and not line.lstrip().startswith(b"#") for line in prefix.splitlines())


class Run:
    def __init__(self, completed):
        self.returncode = completed.returncode
        self.stdout = completed.stdout.decode("utf-8", "replace")
        self.stderr = completed.stderr.decode("utf-8", "replace")

    def __str__(self):
        return "exit {}; stdout={!r}; stderr={!r}".format(self.returncode, self.stdout, self.stderr)


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "install.sh does not exist at the repository root")
        temporary = tempfile.TemporaryDirectory(prefix="laneboss-e2e-bootstrap-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.home = self.directory / "home"
        self.scratch = self.directory / "tmp"
        for path in (self.home, self.scratch):
            path.mkdir()
        self.prefix = self.home / ".local"
        self.tools = self.toolbox("tools")

    def toolbox(self, name, without=(), extra=(), python=True):
        directory = self.directory / name
        directory.mkdir()
        for tool in TOOLS + tuple(extra):
            found = shutil.which(tool)
            if found is not None and tool not in without:
                os.symlink(found, str(directory / tool))
        if python:
            os.symlink(sys.executable, str(directory / "python3"))
        return directory

    def stub(self, directory, name, text):
        path = directory / name
        if path.is_symlink() or path.exists():
            path.unlink()
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)
        return path

    def recorder(self, directory, name, status=0):
        """A program named `name` that notes each call, with its arguments one to a line, in a log; returns the log."""
        log = self.directory / (name + ".log")
        self.stub(directory, name, '#!/bin/sh\nfor argument in "$@"; do echo "$argument"; done >> {}\nexit {}\n'.format(
            shlex.quote(str(log)), status))
        return log

    def environment(self, path=None, **variables):
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("LANEBOSS_", "PYTHON"))}
        environment.update(HOME=str(self.home), TMPDIR=str(self.scratch), PATH=str(path or self.tools))
        build = support.install_environment(self.home)
        for key in ("LANEBOSS_GO", "GOCACHE", "GOPATH", "GOMODCACHE", "XDG_CONFIG_HOME"):
            if key in build:
                environment[key] = build[key]
        environment.update(variables)
        return environment

    def run_script(self, *arguments, environment=None, piped=False, script=None, data=None):
        """`sh install.sh ARGS`, or with piped=True the script on standard input as `curl ... | sh` gives it."""
        script = Path(script or SCRIPT)
        environment = self.environment() if environment is None else environment
        if piped:
            completed = subprocess.run([SH, "-s", "--", *arguments], input=script.read_bytes() if data is None else data,
                                       env=environment, cwd=str(self.directory), capture_output=True, timeout=120)
        else:
            completed = subprocess.run([SH, str(script), *arguments], stdin=subprocess.DEVNULL, env=environment,
                                       cwd=str(self.directory), capture_output=True, timeout=120)
        return Run(completed)

    def install_ok(self, *arguments, path=None, **variables):
        run = self.run_script(*arguments, environment=self.environment(path=path, **variables))
        self.assertEqual(run.returncode, 0, str(run))
        return run

    def installed_version(self, prefix=None):
        command = (prefix or self.prefix) / "bin" / PROGRAM
        result = subprocess.run([str(command), "--version"], env=self.environment(), stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)["version"]

    def printed_versions(self, stdout):
        found = []
        for line in stdout.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and value.get("program") == PROGRAM:
                found.append(value["version"])
        return found

    def assert_refused(self, run, *words):
        """One plain line on standard error naming `words`, a non-zero exit, and nothing written anywhere."""
        self.assertNotEqual(run.returncode, 0, str(run))
        lines = run.stderr.strip().splitlines()
        self.assertEqual(len(lines), 1, "one line expected: " + str(run))
        for word in words:
            self.assertIn(word, lines[0], str(run))
        self.assertEqual(run.stdout, "", str(run))
        self.assertFalse(self.prefix.exists(), "nothing may be written under the prefix: " + str(run))
        self.assertEqual(list(self.home.iterdir()), [], "nothing may be written under HOME: " + str(run))
        self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind: " + str(run))

    def script_with_placeholder(self):
        """The script with a REPO line that holds no address, whatever address the real file holds now. Any word that is
        not an address does, so this does not name the placeholder that stands in the script and the documents."""
        text, count = re.subn(r"(?m)^REPO=.*$", "REPO=NOT_AN_ADDRESS", SCRIPT.read_text(encoding="utf-8"))
        self.assertEqual(count, 1, "install.sh must hold exactly one line that sets REPO")
        copy = self.directory / "install-placeholder.sh"
        copy.write_text(text, encoding="utf-8")
        return copy

    def git(self, repository, *arguments):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment["HOME"] = str(self.directory)
        subprocess.run(["git", "-C", str(repository), "-c", "user.name=e2e", "-c", "user.email=e2e", *arguments],
                       check=True, env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)

    def make_repository(self):
        """A Git repository on this machine whose branch main and tag e2e-tag hold this tree."""
        repository = copy_tree(self.directory / "repository")
        self.assertIsNotNone(shutil.which("git"), "git must be on PATH to test the clone")
        self.git(repository, "init", "-q")
        self.git(repository, "symbolic-ref", "HEAD", "refs/heads/main")
        self.git(repository, "add", "-A")
        self.git(repository, "commit", "-q", "-m", "e2e")
        self.git(repository, "tag", "e2e-tag")
        return repository

    def logged_mktemp(self, tools):
        """Replace mktemp in `tools` by one that records every directory it makes; returns the log's path."""
        log = self.directory / "mktemp.log"
        log.write_text("", encoding="utf-8")
        self.stub(tools, "mktemp", '#!/bin/sh\nmade=$({} "$@") || exit $?\necho "$made" >> {}\necho "$made"\n'.format(
            shlex.quote(shutil.which("mktemp")), shlex.quote(str(log))))
        return log

    # A directory and a tarball of this tree: the installed command answers, a second run says so, a new version upgrades.

    def test_installs_from_a_directory(self):
        run = self.install_ok(LANEBOSS_SOURCE=str(support.ROOT))
        version = tree_version(support.ROOT)
        self.assertEqual(self.installed_version(), version)
        self.assertEqual(self.printed_versions(run.stdout), [version], str(run))
        self.assertNotIn("already installed", run.stdout)
        self.assertIn("laneboss doctor", run.stdout)
        self.assertEqual([line for line in run.stderr.splitlines() if "tmux" not in line], [], str(run))
        self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")

    def test_second_run_is_already_installed(self):
        first = self.install_ok(LANEBOSS_SOURCE=str(support.ROOT))
        before = snapshot(self.prefix)
        second = self.install_ok(LANEBOSS_SOURCE=str(support.ROOT))
        self.assertNotIn("already installed", first.stdout)
        self.assertIn("already installed", second.stdout)
        self.assertEqual(snapshot(self.prefix), before)
        self.assertEqual(self.installed_version(), tree_version(support.ROOT))

    def test_a_new_version_upgrades(self):
        self.install_ok(LANEBOSS_SOURCE=str(support.ROOT))
        old = tree_version(support.ROOT)
        newer = copy_tree(self.directory / "newer")
        new = change_version(newer, "-e2e.1")
        run = self.install_ok(LANEBOSS_SOURCE=str(newer))
        self.assertNotIn("already installed", run.stdout)
        self.assertEqual(self.printed_versions(run.stdout), [new], str(run))
        self.assertEqual(self.installed_version(), new)
        link = os.readlink(str(self.prefix / "bin" / PROGRAM))
        self.assertTrue(link.endswith(os.path.join("versions", new, "bin", PROGRAM)), link)
        self.assertTrue((self.prefix / "share" / PROGRAM / "versions" / old / "bin" / PROGRAM).is_file())

    def test_installs_from_a_gzip_tarball(self):
        archive = make_archive(support.ROOT, self.directory / "laneboss-main.tar.gz", top="laneboss-main")
        run = self.install_ok(LANEBOSS_SOURCE=str(archive))
        version = tree_version(support.ROOT)
        self.assertEqual(self.installed_version(), version)
        self.assertEqual(self.printed_versions(run.stdout), [version], str(run))
        self.assertNotIn("already installed", run.stdout)
        self.assertIn("already installed", self.install_ok(LANEBOSS_SOURCE=str(archive)).stdout)
        self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")

    def test_installs_from_a_plain_tar(self):
        archive = make_archive(support.ROOT, self.directory / "laneboss.tar")
        tools = self.toolbox("tools-no-gzip", without=("gzip",))
        self.install_ok(path=tools, LANEBOSS_SOURCE=str(archive))
        self.assertEqual(self.installed_version(), tree_version(support.ROOT))
        self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")

    def test_a_directory_needs_no_tools(self):
        tools = self.toolbox("tools-bare", without=("tar", "gzip"))
        self.install_ok(path=tools, LANEBOSS_SOURCE=str(support.ROOT))
        self.assertEqual(self.installed_version(), tree_version(support.ROOT))

    def test_prefix_chooses_the_place(self):
        elsewhere = self.directory / "elsewhere"
        self.install_ok("--prefix", str(elsewhere), LANEBOSS_SOURCE=str(support.ROOT))
        self.assertEqual(self.installed_version(elsewhere), tree_version(support.ROOT))
        joined = self.directory / "joined"
        self.install_ok("--prefix=" + str(joined), LANEBOSS_SOURCE=str(support.ROOT))
        self.assertEqual(self.installed_version(joined), tree_version(support.ROOT))
        self.assertFalse(self.prefix.exists())

    def test_source_wins_over_repo(self):
        self.install_ok(LANEBOSS_SOURCE=str(support.ROOT), LANEBOSS_REPO="file://" + str(self.directory / "none"))
        self.assertEqual(self.installed_version(), tree_version(support.ROOT))

    # What it checks, each with one plain line and a non-zero exit when it is missing.

    def go_refusal(self, tools, go):
        """A missing Go executable is refused before fetching or creating temporary files."""
        archive = make_archive(support.ROOT, self.directory / "laneboss.tar.gz", top="laneboss-main")
        log = self.logged_mktemp(tools)
        run = self.run_script(environment=self.environment(path=tools, LANEBOSS_SOURCE=str(archive), LANEBOSS_GO=str(go)))
        self.assert_refused(run, "Go is required")
        self.assertEqual(log.read_text(encoding="utf-8"), "", "a temporary directory was made before the Go check")

    def test_nonexecutable_go_is_refused(self):
        tools = self.toolbox("tools-nonexecutable-go", python=False)
        go = self.directory / "not-executable-go"
        go.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        go.chmod(0o644)
        self.go_refusal(tools, go)

    def test_no_go_is_refused(self):
        self.go_refusal(self.toolbox("tools-no-go", python=False), self.directory / "missing-go")

    def test_one_go_is_used(self):
        tools = self.toolbox("tools-two-go-commands", python=False)
        log = self.directory / "go.log"
        chosen = self.stub(tools, "chosen-go", '#!/bin/sh\necho chosen >> {}\nexec {} "$@"\n'.format(
            shlex.quote(str(log)), shlex.quote(support.go_executable())))
        self.stub(tools, "go", '#!/bin/sh\necho wrong >> {}\nexit 19\n'.format(shlex.quote(str(log))))
        self.install_ok(path=tools, LANEBOSS_GO=str(chosen), LANEBOSS_SOURCE=str(support.ROOT))
        self.assertEqual(log.read_text(encoding="utf-8").split(), ["chosen", "chosen"],
                         "the source installer must use the chosen Go for both builds")

    def test_run_as_root_is_refused(self):
        tools = self.toolbox("tools-root")
        self.stub(tools, "id", "#!/bin/sh\necho 0\n")
        run = self.run_script(environment=self.environment(path=tools, LANEBOSS_SOURCE=str(support.ROOT)))
        self.assert_refused(run, "root")

    def test_an_unknown_user_is_refused(self):
        for label, text in (("silent", "#!/bin/sh\n"), ("failing", "#!/bin/sh\nexit 1\n"),
                            ("not a number", "#!/bin/sh\necho abc\n"), ("missing", None)):
            with self.subTest(label):
                tools = self.toolbox("tools-" + label.replace(" ", "-"), without=("id",) if text is None else ())
                if text is not None:
                    self.stub(tools, "id", text)
                run = self.run_script(environment=self.environment(path=tools, LANEBOSS_SOURCE=str(support.ROOT)))
                self.assert_refused(run, "id")

    def test_another_system_is_refused(self):
        tools = self.toolbox("tools-other-system")
        self.stub(tools, "uname", "#!/bin/sh\necho FreeBSD\n")
        run = self.run_script(environment=self.environment(path=tools, LANEBOSS_SOURCE=str(support.ROOT)))
        self.assert_refused(run, "FreeBSD", "macOS", "Linux")

    def test_an_unknown_system_is_refused(self):
        for label, text in (("silent", "#!/bin/sh\n"), ("failing", "#!/bin/sh\nexit 1\n"), ("missing", None)):
            with self.subTest(label):
                tools = self.toolbox("tools-" + label, without=("uname",) if text is None else ())
                if text is not None:
                    self.stub(tools, "uname", text)
                run = self.run_script(environment=self.environment(path=tools, LANEBOSS_SOURCE=str(support.ROOT)))
                self.assert_refused(run, "macOS", "Linux")

    def test_the_placeholder_stops_the_run(self):
        tools = self.toolbox("tools-fetchers")
        git = self.recorder(tools, "git")
        curl = self.recorder(tools, "curl")
        run = self.run_script(script=self.script_with_placeholder(), environment=self.environment(path=tools))
        self.assert_refused(run, "LANEBOSS_SOURCE", "LANEBOSS_REPO")
        self.assertFalse(git.exists() or curl.exists(), "the placeholder was handed to git or curl")

    def test_an_archive_needs_tar(self):
        archive = make_archive(support.ROOT, self.directory / "laneboss.tar.gz", top="laneboss-main")
        tools = self.toolbox("tools-no-tar", without=("tar",))
        run = self.run_script(environment=self.environment(path=tools, LANEBOSS_SOURCE=str(archive)))
        self.assert_refused(run, "tar")

    def test_a_gzip_archive_needs_gzip(self):
        archive = make_archive(support.ROOT, self.directory / "laneboss.tar.gz", top="laneboss-main")
        tools = self.toolbox("tools-no-gzip", without=("gzip",))
        run = self.run_script(environment=self.environment(path=tools, LANEBOSS_SOURCE=str(archive)))
        self.assert_refused(run, "gzip")

    def test_fetching_needs_git_or_curl(self):
        run = self.run_script(environment=self.environment(LANEBOSS_REPO="file://" + str(self.directory / "none")))
        self.assert_refused(run, "git", "curl")

    def test_a_bad_source_is_refused(self):
        empty = self.directory / "empty"
        empty.mkdir()
        archive = self.directory / "empty.tar.gz"
        with tarfile.open(str(archive), "w:gz") as handle:
            handle.add(str(empty), arcname="laneboss-main")
        for source, word in ((self.directory / "none", "LANEBOSS_SOURCE"), (empty, "scripts/install.sh"),
                             (archive, "scripts/install.sh")):
            with self.subTest(source=source.name):
                run = self.run_script(environment=self.environment(LANEBOSS_SOURCE=str(source)))
                self.assert_refused(run, word)

    def test_a_bad_version_is_refused(self):
        for version in ("--upload-pack=true", "../escape", "has space", "semi;colon"):
            with self.subTest(version=version):
                run = self.run_script(environment=self.environment(
                    LANEBOSS_REPO="file://" + str(self.directory / "none"), LANEBOSS_VERSION=version))
                self.assert_refused(run, "LANEBOSS_VERSION")

    def test_a_helper_address_is_refused(self):
        tools = self.toolbox("tools-fetchers")
        git = self.recorder(tools, "git")
        for address in ("ext::sh -c true", "foo::bar", "https://host.invalid/a::b"):
            with self.subTest(address=address):
                run = self.run_script(environment=self.environment(path=tools, LANEBOSS_REPO=address))
                self.assert_refused(run, "::")
        self.assertFalse(git.exists(), "git was run for an address with a helper")

    def test_a_plain_transport_is_refused(self):
        """Only https, ssh, file, the scp form and an absolute path are allowed; every other address is refused."""
        tools = self.toolbox("tools-fetchers")
        git = self.recorder(tools, "git")
        for address in ("http://host.invalid/laneboss", "HTTP://host.invalid/laneboss", "git://host.invalid/laneboss",
                        "ftp://host.invalid/laneboss", "laneboss", "host.invalid:laneboss"):
            with self.subTest(address=address):
                run = self.run_script(environment=self.environment(path=tools, LANEBOSS_REPO=address))
                self.assert_refused(run, "https")
        self.assertFalse(git.exists(), "git was run for a transport that is not allowed")

    def test_git_may_only_use_three_transports(self):
        """The clone is told which protocols it may use, whatever the environment says, so that git itself refuses a
        redirect from https to http and every name::address helper."""
        tools = self.toolbox("tools-git-env")
        log = self.directory / "git-env.log"
        self.stub(tools, "git", '#!/bin/sh\necho "${{GIT_ALLOW_PROTOCOL-unset}}" >> {}\nexit 128\n'.format(
            shlex.quote(str(log))))
        run = self.run_script(environment=self.environment(
            path=tools, LANEBOSS_REPO="https://host.invalid/laneboss", GIT_ALLOW_PROTOCOL="http:git:ext"))
        self.assertNotEqual(run.returncode, 0, str(run))
        self.assertEqual(log.read_text(encoding="utf-8").split(), ["file:https:ssh"])

    def test_curl_cannot_fetch_over_ssh(self):
        tools = self.toolbox("tools-curl-only")
        curl = self.recorder(tools, "curl")
        for address in ("ssh://host.invalid/laneboss", "user" + "@" + "host.invalid:laneboss", "/srv/laneboss"):
            with self.subTest(address=address):
                run = self.run_script(environment=self.environment(path=tools, LANEBOSS_REPO=address))
                self.assert_refused(run, "https")
        self.assertFalse(curl.exists(), "curl was run for an address it cannot fetch a tarball from")

    def test_help_and_unknown_arguments(self):
        run = self.run_script("--help")
        self.assertEqual(run.returncode, 0, str(run))
        self.assertIn("usage", run.stdout)
        self.assertFalse(self.prefix.exists())
        self.assert_refused(self.run_script("--bogus"), "usage")

    # What it says when it is done.

    def test_the_path_line(self):
        off = self.directory / "off-path"
        run = self.install_ok("--prefix", str(off), LANEBOSS_SOURCE=str(support.ROOT))
        lines = [line for line in run.stdout.splitlines() if line.startswith("export PATH=")]
        self.assertEqual(lines, ['export PATH="{}:$PATH"'.format(off / "bin")], str(run))
        on = self.directory / "on-path"
        run = self.install_ok("--prefix", str(on), path=str(self.tools) + os.pathsep + str(on / "bin"),
                              LANEBOSS_SOURCE=str(support.ROOT))
        self.assertEqual([line for line in run.stdout.splitlines() if line.startswith("export PATH=")], [], str(run))

    def test_a_missing_tmux_is_a_warning(self):
        without = self.install_ok(LANEBOSS_SOURCE=str(support.ROOT))
        warnings = [line for line in without.stderr.splitlines() if "tmux" in line]
        self.assertEqual(len(warnings), 1, str(without))
        self.assertIn("warning", warnings[0])
        self.assertIsNotNone(shutil.which("tmux"), "tmux must be on PATH for the suite")
        tools = self.toolbox("tools-tmux", extra=("tmux",))
        with_tmux = self.install_ok("--prefix", str(self.directory / "with-tmux"), path=tools,
                                    LANEBOSS_SOURCE=str(support.ROOT))
        self.assertEqual(with_tmux.stderr, "", str(with_tmux))

    def test_the_old_command_is_not_run(self):
        """What PREFIX/bin/laneboss points at is read, never started: the person who can write there is not the one
        who asked for the install."""
        planted = self.directory / "planted"
        ran = self.directory / "planted.log"
        planted.write_text("#!/bin/sh\necho ran >> {}\n".format(shlex.quote(str(ran))), encoding="utf-8")
        planted.chmod(0o755)
        (self.prefix / "bin").mkdir(parents=True)
        os.symlink(str(planted), str(self.prefix / "bin" / PROGRAM))
        self.install_ok(LANEBOSS_SOURCE=str(support.ROOT))
        self.assertFalse(ran.exists(), "the program at PREFIX/bin/laneboss was run before the install")
        self.assertEqual(self.installed_version(), tree_version(support.ROOT))

    # Where the source comes from when it is not on this machine.

    def test_clones_with_git(self):
        repository = self.make_repository()
        old = tree_version(repository)
        new = change_version(repository, "-e2e.1")
        self.git(repository, "commit", "-q", "-a", "-m", "newer")
        tools = self.toolbox("tools-git", extra=("git",))
        address = "file://" + str(repository)
        self.install_ok(path=tools, LANEBOSS_REPO=address)
        self.assertEqual(self.installed_version(), new, "the default version is the branch main")
        tagged = self.directory / "tagged"
        self.install_ok("--prefix", str(tagged), path=tools, LANEBOSS_REPO=address, LANEBOSS_VERSION="e2e-tag")
        self.assertEqual(self.installed_version(tagged), old)
        self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")

    def hosted(self):
        """A directory that serves tarballs as `ADDRESS/archive/VERSION.tar.gz` through a file:// address: main holds
        this tree, e2e-tag a copy with another version number, which is returned."""
        hosted = self.directory / "hosted"
        (hosted / "archive").mkdir(parents=True)
        make_archive(support.ROOT, hosted / "archive" / "main.tar.gz", top="laneboss-main")
        newer = copy_tree(self.directory / "newer")
        new = change_version(newer, "-e2e.1")
        make_archive(newer, hosted / "archive" / "e2e-tag.tar.gz", top="laneboss-e2e-tag")
        return hosted, new

    def test_fetches_a_tarball_with_curl(self):
        self.assertIsNotNone(shutil.which("curl"), "curl must be on PATH to test the tarball")
        hosted, new = self.hosted()
        tools = self.toolbox("tools-curl", extra=("curl",))
        address = "file://" + str(hosted)
        self.install_ok(path=tools, LANEBOSS_REPO=address)
        self.assertEqual(self.installed_version(), tree_version(support.ROOT), "the default version is main")
        tagged = self.directory / "tagged"
        self.install_ok("--prefix", str(tagged), path=tools, LANEBOSS_REPO=address, LANEBOSS_VERSION="e2e-tag")
        self.assertEqual(self.installed_version(tagged), new)
        self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")

    def test_a_relative_tmpdir_with_a_colon(self):
        """GNU tar takes a name with a colon before its first slash for a file on another machine."""
        self.assertIsNotNone(shutil.which("curl"), "curl must be on PATH to test the tarball")
        hosted, _ = self.hosted()
        (self.directory / "rel:dir").mkdir()
        tools = self.toolbox("tools-curl", extra=("curl",))
        self.install_ok(path=tools, LANEBOSS_REPO="file://" + str(hosted), TMPDIR="rel:dir")
        self.assertEqual(self.installed_version(), tree_version(support.ROOT))
        self.assertEqual(list((self.directory / "rel:dir").iterdir()), [], "the temporary directory is left behind")

    def test_curl_gets_its_safety_flags(self):
        tools = self.toolbox("tools-curl")
        log = self.recorder(tools, "curl", status=22)
        run = self.run_script(environment=self.environment(path=tools, LANEBOSS_REPO="https://host.invalid/laneboss"))
        self.assertNotEqual(run.returncode, 0, str(run))
        arguments = log.read_text(encoding="utf-8").split("\n")
        self.assertIn("-g", arguments, "curl was not told to treat [] and {} as plain characters")
        redirects = arguments.index("--proto-redir") if "--proto-redir" in arguments else -1
        self.assertGreaterEqual(redirects, 0, "curl was not told which protocols a redirect may use")
        self.assertEqual(arguments[redirects + 1], "=https")
        protocols = arguments.index("--proto") if "--proto" in arguments else -1
        self.assertGreaterEqual(protocols, 0, "curl was not told which protocols it may use")
        self.assertEqual(arguments[protocols + 1], "=https,file")
        self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")

    def test_no_password_is_printed(self):
        """Only what follows the last @ of an address is shown, whatever the address holds before it; the stand-ins
        fail at once and say nothing, so that what is checked is only what the script itself prints."""
        secret = "s3" + "cret"
        forms = (("https://user:" + secret + "@" + "127.0.0.1:9/laneboss.git", "a password"),
                 ("https://user:p" + "@" + secret + "@" + "127.0.0.1:9/laneboss.git", "a password with an at sign"),
                 ("https://user:p/" + secret + "@" + "127.0.0.1:9/laneboss.git", "a password with a slash"),
                 ("ssh://" + secret + "@" + "127.0.0.1/laneboss.git", "a user name"),
                 (secret + "@" + "127.0.0.1:laneboss.git", "an scp-style user name"))
        for route, fetcher in (("git", "git"), ("curl", "curl")):
            tools = self.toolbox("tools-" + route)
            log = self.recorder(tools, fetcher, status=22)
            for address, label in forms:
                if route == "curl" and not address.startswith("https://"):
                    continue
                with self.subTest(route=route, form=label):
                    if log.exists():
                        log.unlink()
                    run = self.run_script(environment=self.environment(path=tools, LANEBOSS_REPO=address))
                    self.assertNotEqual(run.returncode, 0, str(run))
                    self.assertTrue(log.exists(), "the script did not get as far as the fetch: " + str(run))
                    self.assertNotIn(secret, run.stdout + run.stderr)
                    self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")

    # Piped, cut, and cleaned up.

    def test_the_script_piped_on_stdin(self):
        results = {}
        for label, piped in (("file", False), ("pipe", True)):
            prefix = self.directory / ("prefix-" + label)
            run = self.run_script("--prefix", str(prefix), environment=self.environment(
                LANEBOSS_SOURCE=str(support.ROOT)), piped=piped)
            self.assertEqual(run.returncode, 0, str(run))
            results[label] = (run.returncode, run.stdout.replace(str(prefix), "PREFIX"),
                              run.stderr.replace(str(prefix), "PREFIX"),
                              sorted(snapshot(prefix / "share")), self.installed_version(prefix))
        self.assertEqual(results["pipe"], results["file"])

    def test_every_command_is_in_one_group(self):
        data = SCRIPT.read_bytes()
        commands = [line.rstrip(b"\r\n") for _, line in outside_lines(data)]
        self.assertEqual(commands[0], b"{", "the first command of the file must open the one group")
        self.assertEqual(data.splitlines()[-1], b"}", "the last line of the file must close the one group")
        self.assertTrue(data.endswith(b"\n}\n"))
        self.assertEqual(len([line for line in data.splitlines() if line.startswith(b"REPO=")]), 1)

    def test_a_cut_script_runs_nothing(self):
        """Cut at every byte of every command that is not in the function: no cut script may print anything but a
        syntax error, write anything, or start a program that is named like the first word of a command."""
        data = SCRIPT.read_bytes()
        control = self.directory / "control"
        run = self.run_script("--prefix", str(control),
                              environment=self.environment(LANEBOSS_SOURCE=str(support.ROOT)))
        self.assertEqual(run.returncode, 0, str(run))
        self.assertTrue((control / "bin" / PROGRAM).is_symlink(),
                        "the whole script must install, or no cut proves anything")
        positions = cut_positions(data)
        self.assertGreater(len(positions), 60, "too few places to cut at")
        stubs = self.directory / "stubs"
        stubs.mkdir()
        ran = self.directory / "ran.log"
        words = {"laneboss", "R", "repo", "REPO", "set"}
        for _, line in outside_lines(data):
            word = re.match(rb"[A-Za-z_][A-Za-z0-9_]*", line)
            if word:
                name = word.group().decode("ascii")
                words.update(name[:length] for length in range(1, len(name) + 1))
        for name in sorted(words | {word.lower() for word in words}):
            self.stub(stubs, name, "#!/bin/sh\necho {} >> {}\n".format(name, shlex.quote(str(ran))))
        marker = "marker-{}".format(os.getpid())
        environment = self.environment(path=str(stubs) + os.pathsep + str(self.tools), LANEBOSS_SOURCE=str(support.ROOT),
                                       LANEBOSS_REPO="https://user:" + marker + "@" + "host.invalid/laneboss",
                                       SECRET_E2E_TOKEN=marker)
        for position in positions:
            for piped in (True, False):
                with self.subTest(position=position, piped=piped):
                    prefix = self.directory / "cut-prefix"
                    cut = self.directory / "cut.sh"
                    cut.write_bytes(data[:position])
                    run = self.run_script("--prefix", str(prefix), piped=piped, script=cut, data=data[:position],
                                          environment=environment)
                    self.assertEqual(run.stdout, "", "a cut script printed: " + str(run))
                    self.assertNotIn(marker, run.stderr)
                    if has_code(data[:position]):
                        self.assertNotEqual(run.returncode, 0, str(run))
                        lines = run.stderr.strip().splitlines()
                        self.assertTrue(lines and all(SYNTAX_ERROR.search(line) for line in lines),
                                        "a cut script said more than a syntax error: " + str(run))
                    self.assertFalse(ran.exists(), "a cut script ran a program named like one of its words")
                    self.assertFalse(prefix.exists(), "a cut script wrote under the prefix: " + str(run))
                    self.assertEqual(list(self.home.iterdir()), [], str(run))
                    self.assertEqual(list(self.scratch.iterdir()), [], str(run))

    def test_temporary_directory_is_removed(self):
        tools = self.toolbox("tools-logged")
        log = self.logged_mktemp(tools)
        good = make_archive(support.ROOT, self.directory / "good.tar.gz", top="laneboss-main")
        run = self.install_ok(path=tools, LANEBOSS_SOURCE=str(good))
        made = log.read_text(encoding="utf-8").split()
        self.assertTrue(made, "the script made no temporary directory, so the check below proves nothing")
        self.assertEqual([name for name in made if os.path.exists(name)], [], str(run))
        self.assertEqual(list(self.scratch.iterdir()), [])
        # The same version with other content: the installer it runs refuses, and the script fails with it.
        changed = copy_tree(self.directory / "changed")
        protocol = changed / "internal" / "protocol" / "protocol.md"
        protocol.write_text(protocol.read_text(encoding="utf-8") + "\nAn unreleased change.\n", encoding="utf-8")
        bad = make_archive(changed, self.directory / "bad.tar.gz", top="laneboss-main")
        log.write_text("", encoding="utf-8")
        run = self.run_script(environment=self.environment(path=tools, LANEBOSS_SOURCE=str(bad)))
        self.assertNotEqual(run.returncode, 0, str(run))
        self.assertIn(tree_version(support.ROOT), run.stderr)
        made = log.read_text(encoding="utf-8").split()
        self.assertTrue(made, "the failing run made no temporary directory")
        self.assertEqual([name for name in made if os.path.exists(name)], [], str(run))
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertEqual(self.installed_version(), tree_version(support.ROOT))

    def test_a_read_only_tree_is_removed(self):
        """An archive can hold directories that nobody may write to; they must not keep the temporary directory."""
        tree = copy_tree(self.directory / "locked")
        locked = (tree / "internal" / "protocol", tree / "internal")
        for directory in locked:
            directory.chmod(0o555)
        self.addCleanup(lambda: [directory.chmod(0o755) for directory in locked])
        archive = make_archive(tree, self.directory / "locked.tar.gz", top="laneboss-main")
        self.install_ok(LANEBOSS_SOURCE=str(archive))
        self.assertEqual(self.installed_version(), tree_version(support.ROOT))
        self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")

    def test_interrupted_run_cleans_up(self):
        tools = self.toolbox("tools-slow")
        archive = make_archive(support.ROOT, self.directory / "laneboss.tar.gz", top="laneboss-main")
        for name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT", "SIGPIPE"):
            with self.subTest(name):
                started = self.directory / ("tar-started-" + name)
                self.stub(tools, "tar", "#!/bin/sh\n: > {}\nexec sleep 60\n".format(shlex.quote(str(started))))
                process = subprocess.Popen([SH, str(SCRIPT)], env=self.environment(path=tools, LANEBOSS_SOURCE=str(archive)),
                                           cwd=str(self.directory), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, start_new_session=True)
                try:
                    deadline = time.monotonic() + 30
                    while not started.exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertTrue(started.exists(), "the script never reached tar")
                    os.killpg(process.pid, getattr(signal, name))
                    process.communicate(timeout=30)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.communicate()
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(list(self.scratch.iterdir()), [], "the temporary directory is left behind")
                self.assertFalse(self.prefix.exists())


if __name__ == "__main__":
    unittest.main()

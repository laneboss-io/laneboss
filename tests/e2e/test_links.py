"""Isolation by identity: links at internal paths, linked directories, every marker, unreadable configurations,
letter-case aliases, and inputs that are not regular files.

Links and planted files are deliberate tampering; every outcome is asserted through the installed command
and by comparing the other configuration's files before and after.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def snapshot(root):
    """Every regular file below root with its bytes (links are not followed)."""
    root = Path(root)
    if not root.exists():
        return None
    return {str(path.relative_to(root)): path.read_bytes() for path in sorted(root.rglob("*"))
            if path.is_file() and not path.is_symlink()}


def folds_case(directory):
    """True when the file system under `directory` resolves a name written in another letter case to the same
    file. The probe file is the only thing this writes, and it removes it again."""
    directory = Path(directory)
    if not directory.is_dir():
        return False
    name = "CaseProbe" + uuid.uuid4().hex
    probe = directory / name
    try:
        probe.write_text("probe\n", encoding="utf-8")
    except OSError:
        return False
    try:
        other = directory / name.upper()
        return other.exists() and os.path.samefile(str(probe), str(other))
    finally:
        probe.unlink()


class LinkTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")
        self.write_config("beta")
        project = self.home / "configs" / "beta" / "projects" / "web.toml"
        project.write_text(project.read_text(encoding="utf-8").replace(
            "Invented project for", "Beta private project for"), encoding="utf-8")
        self.brief = self.directory / "brief.md"
        self.brief.write_text("# Brief\n\nAn invented task.\n", encoding="utf-8")
        self.outside = self.directory / "outside"
        self.outside.mkdir()

    def state(self, name):
        return Path(self.laneboss_json("config", "path", name)["state_dir"])

    def render(self, config="alpha", lane="alpha-lane-1", name="rendered", code=0):
        return self.run_laneboss("brief", "render", "--config", config, "--lane", lane, "--in", self.brief,
                            "--out", self.directory / (name + ".md"), code=code)

    def replace_with_link(self, path, target):
        path = Path(path)
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(str(path))
        os.symlink(str(target), str(path))

    def test_config_links_refused(self):
        beta = self.home / "configs" / "beta"
        (self.outside / "web.toml").write_text(support.PROJECT_TEXT, encoding="utf-8")
        (self.outside / "standing.md").write_text("# Outside rules\n", encoding="utf-8")
        alpha_text = (self.home / "configs" / "alpha" / "config.toml").read_text(encoding="utf-8")
        (self.outside / "config.toml").write_text(alpha_text, encoding="utf-8")
        cases = [
            ("projects into beta", "projects", beta / "projects"),
            ("projects outside", "projects", self.outside),
            ("project file into beta", "projects/web.toml", beta / "projects" / "web.toml"),
            ("project file outside", "projects/web.toml", self.outside / "web.toml"),
            ("config file outside", "config.toml", self.outside / "config.toml"),
            ("rules into beta", "rules", beta / "rules"),
            ("rules file outside", "rules/standing.md", self.outside / "standing.md"),
        ]
        for label, relative, target in cases:
            with self.subTest(label):
                alpha = self.fresh_config("alpha")
                self.replace_with_link(alpha / relative, target)
                for arguments in (["config", "validate", "alpha"], ["config", "show", "alpha"]):
                    result = self.run_laneboss(*arguments, code=2)
                    self.assertNotIn("Beta private project", result.stdout + result.stderr)
                self.run_laneboss("event", "append", "--config", "alpha", "--file", self.write_event(), code=2)

    def write_event(self, identifier="planted-0", where=None):
        path = Path(where or self.directory) / "event-{}.json".format(identifier)
        path.write_text(json.dumps(self.event(id=identifier)), encoding="utf-8")
        return path

    def test_state_links_refused(self):
        self.render(config="beta", lane="beta-lane-1", name="beta-rendered")
        beta_state = self.state("beta")
        cases = [
            ("lanes into beta", "lanes", beta_state / "lanes"),
            ("lanes outside", "lanes", self.outside),
            ("inputs into beta", "lanes/alpha-lane-1/inputs", beta_state / "lanes" / "beta-lane-1" / "inputs"),
            ("store into beta", "events.sqlite", beta_state / "events.sqlite"),
            ("store outside", "events.sqlite", self.outside / "events.sqlite"),
        ]
        for label, relative, target in cases:
            with self.subTest(label):
                alpha_state = self.directory / ("alpha-state-" + label.replace(" ", "-"))
                self.fresh_config("alpha", state_path=alpha_state)
                self.append(self.event(id="alpha-first"))
                before = snapshot(beta_state)
                outside_before = snapshot(self.outside)
                link = alpha_state / relative
                link.parent.mkdir(parents=True, exist_ok=True)
                self.replace_with_link(link, target)
                self.render(name="r-" + label.replace(" ", "-"), code=2)
                if relative == "events.sqlite":
                    self.append(self.event(id="alpha-second"), code=2)
                self.assertEqual(snapshot(beta_state), before)
                self.assertEqual(snapshot(self.outside), outside_before)
        alpha_state = self.directory / "alpha-state-marker"
        self.fresh_config("alpha", state_path=alpha_state)
        self.append(self.event(id="alpha-first"))
        (self.outside / "marker").write_text(json.dumps({"config": "alpha", "format": 1}), encoding="utf-8")
        self.replace_with_link(alpha_state / ".laneboss-state", self.outside / "marker")
        self.append(self.event(id="alpha-second"), code=2)

    def test_linked_configuration_directory(self):
        dotfiles = self.directory / "dotfiles"
        dotfiles.mkdir()
        shutil.move(str(self.home / "configs" / "alpha"), str(dotfiles / "alpha"))
        os.symlink(str(dotfiles / "alpha"), str(self.home / "configs" / "alpha"))
        self.assertEqual(self.laneboss_json("config", "validate", "alpha")["configs"], ["alpha"])
        self.append(self.event(id="linked-1"), config="alpha")
        self.render(config="alpha")
        self.assertEqual([item["id"] for item in self.events("alpha")][0], "linked-1")
        planted = self.write_event("planted-1", dotfiles / "alpha")
        result = self.run_laneboss("event", "append", "--config", "beta", "--file", planted, code=2)
        self.assertIn("alpha", result.stderr)
        external = self.directory / "external-beta"
        shutil.move(str(self.home / "configs" / "beta"), str(external))
        os.symlink(str(external), str(self.home / "configs" / "beta"))
        planted = self.write_event("planted-2", external)
        through_link = self.home / "configs" / "beta" / planted.name
        for path in (through_link, planted):
            result = self.run_laneboss("event", "append", "--config", "alpha", "--file", path, code=2)
            self.assertIn("beta", result.stderr)
        self.assertEqual(self.events("beta"), [])

    def test_default_state_link_refused(self):
        beta_state = self.directory / "beta-custom-state"
        beta_state.mkdir()
        self.write_config("beta", state_path=beta_state)
        os.symlink(str(beta_state), str(self.state_home / "alpha"))
        result = self.append(self.event(), config="alpha", code=2)
        self.assertIn("beta", result.stderr)
        self.assertEqual(sorted(os.listdir(str(beta_state))), [])
        self.run_laneboss("doctor", "--config", "alpha", code=1)

    def test_shared_state_both_refused(self):
        for label, alpha_path, beta_path in (("same", "shared", "shared"), ("nested", "shared", "shared/inner"),
                                             ("nested other way", "outer/inner", "outer")):
            with self.subTest(label):
                self.fresh_config("alpha", state_path=self.directory / label.replace(" ", "-") / alpha_path)
                self.fresh_config("beta", state_path=self.directory / label.replace(" ", "-") / beta_path)
                for name, other in (("alpha", "beta"), ("beta", "alpha")):
                    result = self.append(self.event(), config=name, code=2)
                    self.assertIn(other, result.stderr)
                    self.run_laneboss("state", "events", "--config", name, code=2)
                    self.run_laneboss("event", "tail", "--config", name, code=2)
                    self.run_laneboss("doctor", "--config", name, code=1)
                self.assertFalse((self.directory / label.replace(" ", "-")).exists())

    def test_forged_marker_does_not_hide(self):
        old = self.directory / "old-beta-state"
        self.write_config("beta", state_path=old)
        self.append(self.event(id="beta-old"), config="beta")
        self.write_config("beta", state_path=self.directory / "new-beta-state")
        sub = old / "sub"
        sub.mkdir()
        (sub / ".laneboss-state").write_text(json.dumps({"config": "alpha", "format": 1}), encoding="utf-8")
        planted = self.write_event("planted-3", sub)
        result = self.run_laneboss("event", "append", "--config", "alpha", "--file", planted, code=2)
        self.assertIn("beta", result.stderr)
        self.write_config("alpha", state_path=sub)
        result = self.append(self.event(id="alpha-under-forged"), config="alpha", code=2)
        self.assertIn("beta", result.stderr)

    def doctor_isolation(self, name="alpha"):
        result = self.run_laneboss("doctor", "--config", name, code=1)
        checks = {json.loads(line)["check"]: json.loads(line) for line in result.stdout.splitlines()}
        return checks["state.isolated"]

    def test_foreign_config_link_unreadable(self):
        alpha_state = self.state("alpha")
        planted = self.outside / "beta-config.toml"
        text = (self.home / "configs" / "beta" / "config.toml").read_text(encoding="utf-8")
        planted.write_text(text + "\n[state]\npath = {}\n".format(json.dumps(str(alpha_state))), encoding="utf-8")
        self.replace_with_link(self.home / "configs" / "beta" / "config.toml", planted)
        self.append(self.event(id="alpha-runs"), config="alpha")
        isolated = self.doctor_isolation()
        self.assertIs(isolated["ok"], False)
        self.assertIn("beta", isolated["detail"])

    def test_explicit_path_leaving_own_dir(self):
        outside_event = self.write_event("outside-1", self.outside)
        outside_brief = self.outside / "brief.md"
        outside_brief.write_text("# Brief\n\nAn invented task kept outside.\n", encoding="utf-8")
        notes = self.home / "configs" / "alpha" / "notes"
        notes.mkdir()
        os.symlink(str(outside_event), str(notes / "event.json"))
        os.symlink(str(outside_brief), str(notes / "brief.md"))
        self.run_laneboss("event", "append", "--config", "alpha", "--file", notes / "event.json", code=2)
        self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in", notes / "brief.md",
                     "--out", self.directory / "leaving-rendered.md", code=2)
        self.append(self.event(id="alpha-state-made"), config="alpha")
        state_notes = self.state("alpha") / "notes-link"
        os.symlink(str(self.outside), str(state_notes))
        self.run_laneboss("event", "append", "--config", "alpha", "--file", state_notes / outside_event.name, code=2)
        self.assertEqual([item["id"] for item in self.events("alpha")], ["alpha-state-made"])

    def test_unsearchable_config_entry(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        locked = self.directory / "locked"
        (locked / "beta").mkdir(parents=True)
        shutil.move(str(self.home / "configs" / "beta" / "config.toml"), str(locked / "beta" / "config.toml"))
        shutil.rmtree(str(self.home / "configs" / "beta"))
        os.symlink(str(locked / "beta"), str(self.home / "configs" / "beta"))
        locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o700)
        self.append(self.event(id="alpha-runs"), config="alpha")
        isolated = self.doctor_isolation()
        self.assertIs(isolated["ok"], False)
        self.assertIn("beta", isolated["detail"])

    def test_unreadable_other_configuration(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root reads a file whose mode says unreadable, so the "
                      "unreadable variant of this test would pass without ever being exercised")
        beta_file = self.home / "configs" / "beta" / "config.toml"
        variants = [("invalid", lambda: beta_file.write_text("this is [not toml", encoding="utf-8")),
                    ("unreadable", lambda: beta_file.chmod(0o000))]
        for label, damage in variants:
            with self.subTest(label):
                self.fresh_config("beta")
                damage()
                self.addCleanup(lambda: beta_file.chmod(0o600) if beta_file.exists() else None)
                self.append(self.event(id="alpha-" + label), config="alpha")
                result = self.run_laneboss("doctor", "--config", "alpha", code=1)
                checks = {json.loads(line)["check"]: json.loads(line) for line in result.stdout.splitlines()}
                self.assertIs(checks["state.isolated"]["ok"], False)
                self.assertIn("beta", checks["state.isolated"]["detail"])
                beta_file.chmod(0o600)

    def root(self, *command):
        """A command that needs root: run it as it is when the suite is root, through sudo -n otherwise."""
        prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
        return subprocess.run(prefix + [str(part) for part in command], capture_output=True, text=True,
                              encoding="utf-8", timeout=120)

    def unmount(self, mount_point):
        self.root("umount", mount_point)

    def mount_case_insensitive_image(self):
        """Mount a small image under this test's own directory with a loop device, and return the directory on
        it whose file system folds letter case; None when no image could be made and mounted."""
        area = self.directory / "case-filesystem"
        area.mkdir()
        own = "loop,uid={},gid={},umask=0077".format(os.getuid(), os.getgid())
        makers = (("vfat", ["mkfs.vfat"], own, False),
                  ("fat", ["mkfs.fat"], own, False),
                  ("exfat", ["mkfs.exfat"], own, False),
                  ("ext4-casefold", ["mkfs.ext4", "-q", "-F", "-O", "casefold", "-E", "encoding=utf8"],
                   "loop", True))
        for label, maker, options, inner in makers:
            if shutil.which(maker[0]) is None:
                continue
            image = area / (label + ".img")
            with open(str(image), "wb") as handle:
                handle.truncate(16 * 1024 * 1024)
            if self.root(*maker, image).returncode != 0:
                continue
            mount_point = area / (label + "-mount")
            mount_point.mkdir()
            if self.root("mount", "-o", options, image, mount_point).returncode != 0:
                continue
            self.addCleanup(self.unmount, mount_point)
            directory = mount_point
            if inner:
                # ext4 folds case only in a directory given the casefold attribute, inherited by its children.
                directory = mount_point / "case"
                if self.root("mkdir", directory).returncode != 0:
                    continue
                if self.root("chattr", "+F", directory).returncode != 0:
                    continue
                self.root("chown", "{}:{}".format(os.getuid(), os.getgid()), directory)
            if folds_case(directory):
                return directory
        return None

    def case_insensitive_directory(self):
        """A directory whose file system folds letter case. A directory named by LANEBOSS_CASE_INSENSITIVE_DIR
        is used when it really folds case, and so is this test's own temporary directory where its file system
        already does (macOS). Otherwise an image is made and mounted here. When none of that works the test
        FAILS: the alias leg cannot be run, and a case-sensitive file system is never a pass."""
        declared = os.environ.get("LANEBOSS_CASE_INSENSITIVE_DIR")
        if declared and folds_case(declared):
            return Path(declared)
        if folds_case(self.directory):
            return self.directory
        made = self.mount_case_insensitive_image()
        if made is not None:
            return made
        self.fail("no case-insensitive file system could be made for the case alias leg: {} does not fold letter "
                  "case, LANEBOSS_CASE_INSENSITIVE_DIR is {}, and no image (vfat, exfat, or ext4 with casefold) "
                  "could be mounted there".format(self.directory, declared or "unset"))

    def test_case_alias_refused(self):
        """An alias that differs from a configuration's directory only in letter case resolves, by file identity,
        to that other configuration, and a command bound to one configuration refuses it."""
        scratch = self.case_insensitive_directory()
        self.assertTrue(folds_case(scratch), "{} must fold letter case".format(scratch))
        home = scratch / "config-home"
        user_home = scratch / "user-home"
        for path in (home, user_home):
            path.mkdir()
        # The store stays on the suite's own file system: only the configuration home must fold case here.
        state_home = self.directory / "state-home-alias"
        state_home.mkdir()
        self.home = home
        self.state_home = state_home
        environment = dict(self.environment)
        environment["HOME"] = str(user_home)
        environment["LANEBOSS_HOME"] = str(home)
        environment["LANEBOSS_STATE_HOME"] = str(state_home)
        self.environment = environment
        self.write_config("alpha")
        self.write_config("beta")
        target = self.write_event("case-1", home / "configs" / "beta")
        aliases = [home / "configs" / "BETA" / target.name,
                   home.parent / home.name.upper() / "configs" / "beta" / target.name]
        for alias in aliases:
            with self.subTest(alias=alias):
                self.assertTrue(os.path.samefile(str(alias), str(target)),
                                "the alias {} must be the other configuration's file on this file system".format(
                                    alias))
                result = self.run_laneboss("event", "append", "--config", "alpha", "--file", alias, code=2)
                self.assertIn("beta", result.stderr)
        self.assertEqual(self.events("alpha"), [])

    def blocked(self, process, seconds=2.0):
        try:
            process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            return True
        return False

    def release(self, fifo, data):
        try:
            descriptor = os.open(str(fifo), os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            return
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)

    def finish(self, process):
        try:
            output, error = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.fail("the command did not finish")
        return output.decode("utf-8", "replace"), error.decode("utf-8", "replace")

    def start(self, *arguments):
        return subprocess.Popen([str(self.command), *map(str, arguments)], cwd=str(self.directory),
                                env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_fifo_inputs_and_swaps(self):
        self.append(self.event(id="beta-1"), config="beta")
        beta_state = self.state("beta")
        fifo = self.directory / "brief.fifo"
        os.mkfifo(str(fifo))
        output_dir = self.directory / "out"
        output_dir.mkdir()
        before = snapshot(beta_state)
        process = self.start("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in", fifo,
                             "--out", output_dir / "rendered.md")
        # Inputs are opened with O_NONBLOCK and a name that is not a regular file is refused at once
        # (fsguard.open_child), so a FIFO input never holds the command open. The swap this test used to make
        # here, under a command waiting on the FIFO, was therefore never made: the assertion below requires the
        # refusal to be immediate, and test_swapped_output_directory_refused makes the swap for real, before the
        # command opens the output directory.
        self.assertFalse(self.blocked(process), "the render waited on a FIFO input instead of refusing it at once")
        output, error = self.finish(process)
        self.assertEqual(process.returncode, 2, "stdout={!r}; stderr={!r}".format(output, error))
        self.assertIn("regular file", error)
        self.assertEqual(snapshot(beta_state), before)
        self.assertFalse((output_dir / "rendered.md").exists())
        self.assertEqual(self.events("alpha"), [])
        event_fifo = self.directory / "event.fifo"
        os.mkfifo(str(event_fifo))
        process = self.start("event", "append", "--config", "alpha", "--file", event_fifo)
        if self.blocked(process, seconds=5.0):
            self.release(event_fifo, json.dumps(self.event(id="fifo-1")).encode())
            self.finish(process)
            self.fail("event append waited on a FIFO instead of refusing it")
        self.finish(process)
        self.assertEqual(process.returncode, 2)
        directory_input = self.directory / "a-directory"
        directory_input.mkdir()
        self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in", directory_input,
                     "--out", self.directory / "dir-rendered.md", code=2)

    def test_swapped_output_directory_refused(self):
        """The output directory is moved away and another configuration's state directory is left in its place
        before the command opens it: the render must refuse by identity, the other configuration's state must be
        byte for byte what it was, and the brief must not be written through the path that was left there."""
        self.append(self.event(id="beta-1"), config="beta")
        beta_state = self.state("beta")
        # Control: the same render into an output directory of its own succeeds and writes the brief, so the
        # refusal below is the swap and not the fixture.
        control = self.directory / "out-control"
        control.mkdir()
        self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in", self.brief,
                          "--out", control / "rendered.md")
        self.assertTrue((control / "rendered.md").is_file())
        before = snapshot(beta_state)
        output_dir = self.directory / "out-swapped"
        output_dir.mkdir()
        output_dir.rename(self.directory / "out-swapped-moved")
        os.symlink(str(beta_state), str(output_dir))
        result = self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1",
                                   "--in", self.brief, "--out", output_dir / "rendered.md", code=2)
        self.assertIn("beta", result.stderr)
        self.assertEqual(snapshot(beta_state), before)
        self.assertFalse((self.directory / "out-swapped-moved" / "rendered.md").exists())

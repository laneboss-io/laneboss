"""A. Installation: version output, versioned directories, switching and rolling back the link."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class InstallTest(support.LauncherTest):

    def test_saved_go_env_no_faults(self):
        """Fails if the installer imports laneboss_faults from the user's saved GOFLAGS."""
        settings = self.directory / "go-settings"
        settings.write_text("GOFLAGS=-tags=laneboss_faults\n", encoding="utf-8")
        environment = dict(support.install_environment(self.user_home), GOENV=str(settings), GOFLAGS="")
        payload = json.dumps({"action": "stream", "name": "text", "line": "settings control"})
        control = self.directory / "settings-control"
        build = subprocess.run([support.go_executable(), "build", "-trimpath", "-o", str(control), "./cmd/laneboss"],
                               cwd=support.ROOT, env=dict(support.go_environment(), GOENV=str(settings), GOFLAGS=""),
                               capture_output=True, text=True, timeout=600)
        self.assertEqual(build.returncode, 0, build.stderr)
        run = subprocess.run([str(control), "lane", "__probe"], input=payload, env=environment,
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, "the saved-settings control did not enable instrumentation: " + run.stderr)
        self.assertEqual(json.loads(run.stdout), [{"kind": "answer", "text": "settings control"}])
        prefix = self.directory / "saved-settings-install"
        installed = support.run_install(support.ROOT, prefix, self.user_home, environment=environment)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        release = subprocess.run([str(prefix / "bin" / support.PROGRAM), "lane", "__probe"],
                                 input=payload, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(release.returncode, 2, "the installer included private instrumentation")
        self.assertEqual(release.stdout, "")

    def version_of(self, prefix):
        result = subprocess.run([str(prefix / "bin" / support.PROGRAM), "--version"], env=self.environment,
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)["version"]

    def install_from(self, source, prefix, code=0):
        result = support.run_install(source, prefix, self.user_home)
        self.assertEqual(result.returncode, code, "install: stdout={!r}; stderr={!r}".format(
            result.stdout, result.stderr))
        return result

    def copy_checkout(self):
        return support.copy_go_tree(self.directory / "checkout-copy")

    def version_directory(self, prefix, version):
        return prefix / "share" / support.PROGRAM / "versions" / version

    def test_version_output(self):
        version = self.laneboss_json("--version")
        self.assertEqual(version["program"], support.PROGRAM)
        self.assertRegex(version["version"], r"^[0-9]+\.[0-9]+\.[0-9]+")
        protocol = support.PROTOCOL_FILE.read_text(encoding="utf-8")
        self.assertRegex(version["protocol_version"], r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertIn("Protocol version: " + version["protocol_version"] + "\n", protocol)
        link = os.readlink(str(self.command))
        self.assertTrue(link.endswith(os.path.join("versions", version["version"], "bin", support.PROGRAM)), link)

    def test_second_version_switches_link(self):
        prefix = self.directory / "prefix"
        self.install_from(support.ROOT, prefix)
        first = self.version_of(prefix)
        copy = self.copy_checkout()
        identity = copy / "internal" / "identity" / "identity.go"
        second = first + "-e2e.1"
        text, count = re.subn(r'(?m)^(\s*Version\s*= )"[^"]+"$', r'\g<1>"{}"'.format(second),
                              identity.read_text(encoding="utf-8"), flags=re.M)
        self.assertEqual(count, 1, "identity.go must hold exactly one Version constant")
        identity.write_text(text, encoding="utf-8")
        self.install_from(copy, prefix)
        self.assertEqual(self.version_of(prefix), second)
        link = prefix / "bin" / support.PROGRAM
        self.assertTrue(os.readlink(str(link)).endswith(os.path.join("versions", second, "bin", support.PROGRAM)))
        first_directory = self.version_directory(prefix, first)
        self.assertTrue((first_directory / "bin" / support.PROGRAM).is_file())
        self.assertTrue((self.version_directory(prefix, second) / "bin" / support.PROGRAM).is_file())
        # Rollback is a relink to the first version's directory, which installing left in place.
        replacement = prefix / "bin" / ".rollback-link"
        os.symlink(os.path.relpath(str(first_directory / "bin" / support.PROGRAM), str(prefix / "bin")),
                   str(replacement))
        os.replace(str(replacement), str(link))
        self.assertEqual(self.version_of(prefix), first)

    def test_installed_versions_are_immutable(self):
        prefix = self.directory / "prefix"
        self.install_from(support.ROOT, prefix)
        version = self.version_of(prefix)
        self.install_from(support.ROOT, prefix)
        self.assertEqual(self.version_of(prefix), version)
        copy = self.copy_checkout()
        protocol = copy / "internal" / "protocol" / "protocol.md"
        protocol.write_text(protocol.read_text(encoding="utf-8") + "\nAn unreleased change.\n", encoding="utf-8")
        result = self.install_from(copy, prefix, code=2)
        self.assertIn(version, result.stderr)
        self.assertEqual(self.version_of(prefix), version)

    def test_failing_go_build_is_refused(self):
        fake = self.directory / "failing-go"
        fake.write_text("#!/bin/sh\necho 'toolchain unavailable' >&2\nexit 1\n", encoding="utf-8")
        fake.chmod(0o755)
        environment = support.base_environment(self.user_home)
        environment[support.ENV_PREFIX + "GO"] = str(fake)
        prefix = self.directory / "prefix"
        result = support.run_install(support.ROOT, prefix, self.user_home, environment=environment)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("toolchain unavailable", result.stderr)
        self.assertFalse((prefix / "bin" / support.PROGRAM).exists())
        self.assertFalse(Path(prefix / "share").exists())

    def make_second_version(self):
        copy = self.copy_checkout()
        identity = copy / "internal" / "identity" / "identity.go"
        text = identity.read_text(encoding="utf-8")
        current = re.search(r'^\s*Version\s*= "([^"]+)"$', text, flags=re.M).group(1)
        identity.write_text(text.replace('Version   = "{}"'.format(current), 'Version   = "{}-e2e.2"'.format(current)),
                            encoding="utf-8")
        return copy, current, current + "-e2e.2"

    def test_reinstall_verifies_files(self):
        copy, first, second = self.make_second_version()
        damages = [
            ("changed plugin", lambda directory: (directory / "plugins" / "claude-code" / "skills" / "laneboss" / "SKILL.md").write_text(
                "# changed after installation\n", encoding="utf-8")),
            ("missing plugin", lambda directory: os.remove(str(directory / "plugins" / "claude-code" / "skills" / "laneboss" / "start.sh"))),
            ("changed launcher", lambda directory: (directory / "bin" / support.PROGRAM).write_text(
                "#!/bin/sh\nexit 0\n", encoding="utf-8")),
            ("extra asset", lambda directory: (directory / "plugins" / "extra.txt").write_text(
                "raise SystemExit(9)\n", encoding="utf-8")),
        ]
        for index, (label, damage) in enumerate(damages):
            with self.subTest(label):
                prefix = self.directory / "prefix-{}".format(index)
                self.install_from(support.ROOT, prefix)
                self.install_from(copy, prefix)
                self.assertEqual(self.version_of(prefix), second)
                damage(self.version_directory(prefix, first))
                result = self.install_from(support.ROOT, prefix, code=2)
                self.assertIn(first, result.stderr)
                link = os.readlink(str(prefix / "bin" / support.PROGRAM))
                self.assertTrue(link.endswith(os.path.join("versions", second, "bin", support.PROGRAM)), link)

    def test_install_uses_explicit_go(self):
        prefix = self.directory / "prefix"
        result = support.run_install(support.ROOT, prefix, self.user_home,
                                     environment=support.install_environment(self.user_home))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(json.loads(result.stdout)["link"]), prefix / "bin" / support.PROGRAM)
        self.assertFalse((Path(json.loads(result.stdout)["directory"]) / "lib").exists())
        self.assertEqual(self.version_of(prefix), self.laneboss_json("--version")["version"])

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
        copy = self.directory / "checkout-copy"
        ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
        shutil.copytree(str(support.ROOT / "src"), str(copy / "src"), ignore=ignore)
        shutil.copytree(str(support.ROOT / "scripts"), str(copy / "scripts"), ignore=ignore)
        return copy

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
        identity = copy / "src" / "laneboss" / "identity.py"
        second = first + "-e2e.1"
        text, count = re.subn(r'^VERSION = "[^"]+"$', 'VERSION = "{}"'.format(second),
                              identity.read_text(encoding="utf-8"), flags=re.M)
        self.assertEqual(count, 1, "identity.py must hold exactly one VERSION constant")
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
        protocol = copy / "src" / "laneboss" / "protocol" / "protocol.md"
        protocol.write_text(protocol.read_text(encoding="utf-8") + "\nAn unreleased change.\n", encoding="utf-8")
        result = self.install_from(copy, prefix, code=2)
        self.assertIn(version, result.stderr)
        self.assertEqual(self.version_of(prefix), version)

    def test_unsuitable_python_is_refused(self):
        fake = self.directory / "old-python"
        fake.write_text("#!/bin/sh\necho 'Python 3.8.10'\nexit 1\n", encoding="utf-8")
        fake.chmod(0o755)
        environment = support.base_environment(self.user_home)
        environment[support.ENV_PREFIX + "PYTHON"] = str(fake)
        prefix = self.directory / "prefix"
        result = support.run_install(support.ROOT, prefix, self.user_home, environment=environment)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("3.11", result.stderr)
        self.assertFalse((prefix / "bin" / support.PROGRAM).exists())
        self.assertFalse(Path(prefix / "share").exists())

    def make_second_version(self):
        copy = self.copy_checkout()
        identity = copy / "src" / "laneboss" / "identity.py"
        text = identity.read_text(encoding="utf-8")
        current = re.search(r'^VERSION = "([^"]+)"$', text, flags=re.M).group(1)
        identity.write_text(text.replace('VERSION = "{}"'.format(current), 'VERSION = "{}-e2e.2"'.format(current)),
                            encoding="utf-8")
        return copy, current, current + "-e2e.2"

    def test_reinstall_verifies_files(self):
        copy, first, second = self.make_second_version()
        damages = [
            ("changed module", lambda directory: (directory / "lib" / "laneboss" / "lanes.py").write_text(
                "# changed after installation\n", encoding="utf-8")),
            ("missing module", lambda directory: os.remove(str(directory / "lib" / "laneboss" / "brief.py"))),
            ("changed launcher", lambda directory: (directory / "bin" / support.PROGRAM).write_text(
                "#!/bin/sh\nexit 0\n", encoding="utf-8")),
            ("extra module", lambda directory: (directory / "lib" / "json.py").write_text(
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

    def test_install_searches_path(self):
        prefix = self.directory / "prefix"
        result = support.run_install(support.ROOT, prefix, self.user_home,
                                     environment=support.base_environment(self.user_home))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(json.loads(result.stdout)["python"], r"python3")
        self.assertEqual(self.version_of(prefix), self.laneboss_json("--version")["version"])

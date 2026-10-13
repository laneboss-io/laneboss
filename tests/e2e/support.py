"""Shared helpers for the launcher's black-box tests.

Each test module installs the launcher with scripts/install.sh into a temporary
prefix in setUpModule and removes it in tearDownModule. Each test owns temporary
configuration, state and home directories and removes them. Nothing here imports
the package under test: every assertion goes through the installed command.
"""

import hashlib
import importlib.abc
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
PROGRAM = "laneboss"
ENV_PREFIX = "LANEBOSS_"
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"

PYTHON_FIXTURE_ERROR = ("LANEBOSS_PY_SRC must name the absolute src/ directory of the pinned "
                        "python-final tree for fixture construction")


def python_source(required=True):
    source = os.environ.get("LANEBOSS_PY_SRC")
    if source is None and not required:
        return None
    if not source or not Path(source).is_absolute() or not (Path(source) / "laneboss" / "__init__.py").is_file():
        raise RuntimeError(PYTHON_FIXTURE_ERROR)
    return source


class _FixtureImportGuard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "laneboss" or fullname.startswith("laneboss."):
            python_source()
        return None


_fixture_source = python_source(required=False)
if _fixture_source is not None:
    sys.path.insert(0, _fixture_source)
sys.meta_path.insert(0, _FixtureImportGuard())

_helper_builds = {}
_helper_directories = []


def go_executable():
    command = os.environ.get("LANEBOSS_GO", "go")
    found = shutil.which(command)
    if found is None:
        raise AssertionError("Go is required for the Go-only test harness")
    return str(Path(found).absolute())


def go_environment():
    """Keep build caches and toolchain settings outside the test's product HOME."""
    environment = dict(os.environ, GOTOOLCHAIN="go1.26.0", GOWORK="off", CGO_ENABLED="0", GOENV="off", GOFLAGS="")
    environment.setdefault("GOCACHE", str(Path.home() / ".cache" / "go-build"))
    environment.setdefault("GOPATH", str(Path.home() / "go"))
    environment.setdefault("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    return environment


def copy_go_tree(destination, plugins=True):
    """Copy the complete Go installer input, including embedded protocol files."""
    destination = Path(destination)
    destination.mkdir(parents=True)
    for name in ("cmd", "internal", "scripts") + (("plugins",) if plugins else ()):
        shutil.copytree(ROOT / name, destination / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("go.mod", "go.sum"):
        shutil.copy2(ROOT / name, destination / name)
    return destination


def helper_binary(source, *, standalone=False):
    """Build a Go package, or an explicitly isolated mutant file; fail on build errors."""
    source = Path(source).resolve()
    key = (str(source), standalone)
    if key not in _helper_builds:
        directory = tempfile.TemporaryDirectory(prefix="lb-go-only-helper-")
        _helper_directories.append(directory)
        output = Path(directory.name) / source.parent.name
        environment = go_environment()
        target = str(source) if standalone else "./" + str(source.parent.relative_to(ROOT))
        result = subprocess.run([go_executable(), "build", "-tags=", "-trimpath", "-o", str(output), target],
                                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=600)
        if result.returncode:
            raise AssertionError("Go helper build failed: " + result.stderr)
        _helper_builds[key] = output
    return _helper_builds[key]


def faults_binary():
    """Build instrumentation only into the binary used by private probes."""
    key = "laneboss_faults"
    if key not in _helper_builds:
        directory = tempfile.TemporaryDirectory(prefix="lb-go-only-faults-")
        _helper_directories.append(directory)
        output = Path(directory.name) / PROGRAM
        result = subprocess.run([go_executable(), "build", "-tags=laneboss_faults", "-trimpath", "-o", str(output),
                                 "./cmd/laneboss"], cwd=ROOT, env=go_environment(),
                                capture_output=True, text=True, timeout=600)
        if result.returncode:
            raise AssertionError("Go fault binary build failed: " + result.stderr)
        _helper_builds[key] = output
    return _helper_builds[key]

PROTOCOL_FILE = ROOT / "internal" / "protocol" / "protocol.md"
TIMESTAMP = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"

CONFIG_TEMPLATE = """\
schema_version = 1
name = "{name}"
description = "Invented configuration for the launcher's black-box tests."
rules = ["rules/standing.md"]
secrets = ["E2E_TEST_KEY", "E2E_CHAT_TOKEN"]
owner_channel = "main"
test_environment = "cloud"
{top}
[runners.local]
command = ["sh", "-c", "exit 0", "{{brief}}"]
accounts = ["account-one", "account-two"]
secrets = ["E2E_TEST_KEY"]

[supervisors.top]
level = 5
runner = "local"
projects = ["web"]
owner_channel = "chat"

[[routing.standard]]
runner = "local"
model = "example-model-2"
effort = "max"

[[routing.hard]]
runner = "local"
model = "example-model-3"
effort = "max"

[test_environments.cloud]
kind = "cloud"
identity = "example-test-identity"
region = "region-one"
max_machines = 1
secrets = ["E2E_TEST_KEY"]
attest = ["sh", "-c", "exit 0"]

[owner_channels.main]
kind = "file"
path = "owner/queue.md"

[owner_channels.chat]
kind = "chat"
service = "example-chat"
target = "lane-reports"
token_secret = "E2E_CHAT_TOKEN"

[cost]
currency = "USD"
daily_cap = 2.0
per_run_cap = 0.5
report_threshold = 2
{tail}"""

PROJECT_TEXT = """\
schema_version = 1
name = "web"
description = "Invented project for the launcher's black-box tests."
repository = "/srv/example/web"
lane_prefix = "web-"
workers = ["local"]
gates = ["fixtures", "hosted-ci", "review", "merge", "deploy", "e2e"]
excluded_accounts = ["account-one"]
test_environment = "cloud"
reserved_paths = ["docs/release-notes.md"]
owner_channel = "main"
landing_authority = "top"
rules = ["rules/web.md"]
"""

STANDING_RULES = """\
# Standing rules for {name}

- Name every branch after its lane.
- Copy evidence back after every phase.
"""

WEB_RULES = """\
# Project rules: web

- Keep the release list current.
"""

_installation = None


def started_payload(paths, lane="alpha-lane-1", run=1, how="start", account="account-two"):
    """A lane.started payload of the form the launcher writes, for tests that append lane events by hand. `paths` is
    the output of `config path` for the receiving configuration: the session, the rendered brief and the log must be
    that configuration's and that lane's."""
    lane_directory = paths["state_dir"] + "/lanes/" + lane
    return {"run": run, "how": how, "launch": "0" * 31 + str(run), "runner": "local", "model": "example-model-2",
            "effort": "max", "account": account,
            "chosen_by": {"runner": "routing", "model": "routing", "effort": "routing", "account": "default"},
            "difficulty": "standard", "project": None, "worktree": "/srv/example/lanes/one", "branch": None,
            "base": None, "repository": None, "budget_minutes": 30, "quiet_seconds": 600,
            "brief": {"path": lane_directory + "/rendered/" + "a" * 64 + ".md", "sha256": "a" * 64},
            "log": lane_directory + "/output.log", "session": {"socket": paths["socket"], "name": lane},
            "touches": [], "claims": None}


def ended_payload(run=1, reason="exit"):
    """A lane.ended payload of the form the launcher writes."""
    return {"run": run, "reason": reason, "exit_code": 0, "signal": None, "duration_seconds": 1.5, "pattern": None,
            "classification": None, "survivors": 0}


def digest(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# LANEBOSS_TEST_GO_GROUPS=org,config,... runs those command groups of the suite on their Go ports: each binary
# (cmd/laneboss-<group>) is built once from this checkout and named to the installed launcher, which forwards to
# it with no Python fallback. LANEBOSS_TEST_ORG_ENGINE=go is the older spelling of the group org.
GO_GROUPS = [group for group in os.environ.get(ENV_PREFIX + "TEST_GO_GROUPS", "").split(",") if group]
if os.environ.get(ENV_PREFIX + "TEST_ORG_ENGINE", "python") == "go" and "org" not in GO_GROUPS:
    GO_GROUPS.append("org")
_go_binaries = {}


def go_binary(group):
    """Build cmd/laneboss-<group> once per test process; a failed build fails every test that needs it."""
    if group not in _go_binaries:
        if not re.fullmatch(r"[a-z]+", group) or not (ROOT / "cmd" / ("laneboss-" + group)).is_dir():
            raise AssertionError("no Go port for the command group " + repr(group))
        output = Path(tempfile.mkdtemp(prefix="laneboss-e2e-go-")) / ("laneboss-" + group)
        result = subprocess.run(["go", "build", "-o", str(output), "./cmd/laneboss-" + group], cwd=str(ROOT),
                                capture_output=True, text=True, encoding="utf-8", timeout=600)
        if result.returncode != 0:
            raise AssertionError("go build ./cmd/laneboss-" + group + " failed: " + result.stderr.strip())
        _go_binaries[group] = output
    return _go_binaries[group]


def base_environment(user_home):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(ENV_PREFIX) and not key.startswith("PYTHON")}
    environment["HOME"] = str(user_home)
    for key in ("LANEBOSS_BIN", "LANEBOSS_PY_SRC"):
        if key in os.environ:
            environment[key] = os.environ[key]
    for group in GO_GROUPS:
        environment[ENV_PREFIX + group.upper() + "_GO_BIN"] = str(go_binary(group))
    return environment


def install_environment(user_home):
    """Pass the Go executable explicitly, including when a test restricts PATH."""
    environment = base_environment(user_home)
    environment[ENV_PREFIX + "GO"] = go_executable()
    build = go_environment()
    for key in ("GOCACHE", "GOPATH", "GOMODCACHE", "XDG_CONFIG_HOME"):
        if key in build:
            environment[key] = build[key]
    return environment


def group_command(group):
    binary = os.environ.get("LANEBOSS_BIN")
    if binary is not None:
        if not Path(binary).is_absolute() or not Path(binary).is_file() or not os.access(binary, os.X_OK):
            raise AssertionError("LANEBOSS_BIN must name an executable file by absolute path")
        return [binary, group]
    if group in GO_GROUPS:
        return [str(go_binary(group))]
    if _installation is not None:
        if _installation.problem:
            raise AssertionError(_installation.problem)
        return [str(_installation.command), group]
    return [str(helper_binary(ROOT / "cmd" / "laneboss" / "main.go")), group]


def run_install(source_root, prefix, user_home, environment=None):
    return subprocess.run(
        ["sh", str(Path(source_root) / "scripts" / "install.sh"), "--prefix", str(prefix)],
        env=environment or install_environment(user_home), capture_output=True, text=True,
        encoding="utf-8", timeout=120,
    )


class Installation:
    """One installed copy of the launcher, shared by the tests of one module."""

    def __init__(self):
        self.directory = Path(tempfile.mkdtemp(prefix="laneboss-e2e-install-")).resolve()
        self.prefix = self.directory / "prefix"
        self.command = self.prefix / "bin" / PROGRAM
        self.problem = None
        binary = os.environ.get(ENV_PREFIX + "BIN")
        if binary is not None:
            supplied = Path(binary)
            if not supplied.is_absolute() or not supplied.is_file() or not os.access(binary, os.X_OK):
                self.problem = "LANEBOSS_BIN must name an executable file by absolute path"
                return
            # Install the exact supplied bytes with the real Go install helper.
            # This exercises the manifest, link and plugin layout without rebuilding
            # the product for every module of a sharded suite.
            installer = helper_binary(ROOT / "scripts" / "install" / "main.go")
            user_home = self.directory / "user-home"
            user_home.mkdir()
            result = subprocess.run([str(installer), str(ROOT), str(self.prefix), str(supplied)],
                                    env=install_environment(user_home), capture_output=True, text=True, timeout=120)
            if result.returncode:
                self.problem = "Go install helper failed: " + result.stderr
            return
        if not INSTALL_SCRIPT.is_file():
            self.problem = "scripts/install.sh does not exist, so the launcher cannot be installed"
            return
        user_home = self.directory / "user-home"
        user_home.mkdir()
        result = run_install(ROOT, self.prefix, user_home)
        if result.returncode != 0:
            self.problem = "scripts/install.sh exited {}: {}".format(result.returncode, result.stderr.strip())
        elif not os.access(str(self.command), os.X_OK):
            self.problem = "scripts/install.sh did not create an executable " + str(self.command)

    def remove(self):
        shutil.rmtree(str(self.directory))


def install():
    global _installation
    _installation = Installation()


def uninstall():
    global _installation
    if _installation is not None:
        _installation.remove()
        _installation = None


class LauncherTest(unittest.TestCase):
    """Base class: temporary homes per test and helpers that drive the installed command."""

    def setUp(self):
        if _installation is None:
            self.fail("the test module did not install the launcher")
        if _installation.problem:
            self.fail(PROGRAM + " is not installed: " + _installation.problem)
        self.command = _installation.command
        temporary = tempfile.TemporaryDirectory(prefix="laneboss-e2e-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.home = self.directory / "config-home"
        self.state_home = self.directory / "state-home"
        self.user_home = self.directory / "user-home"
        for path in (self.home, self.state_home, self.user_home):
            path.mkdir()
        self.environment = base_environment(self.user_home)
        self.environment[ENV_PREFIX + "HOME"] = str(self.home)
        self.environment[ENV_PREFIX + "STATE_HOME"] = str(self.state_home)
        # The claims registry is the account's own; tests move it into their temporary directory.
        self.environment[ENV_PREFIX + "TEST_CLAIMS_DIR"] = str(self.directory / "claims")

    def run_laneboss(self, *arguments, code=0, environment=None, stdin=None):
        result = subprocess.run(
            [str(self.command), *map(str, arguments)], cwd=str(self.directory),
            env=self.environment if environment is None else environment, input=stdin,
            capture_output=True, text=True, encoding="utf-8", timeout=60,
        )
        if code is not None:
            self.assertEqual(result.returncode, code, "{}: exit {}; stdout={!r}; stderr={!r}".format(
                " ".join(map(str, arguments)), result.returncode, result.stdout, result.stderr))
        return result

    def laneboss_json(self, *arguments, **options):
        return json.loads(self.run_laneboss(*arguments, **options).stdout)

    def write_config(self, name, top="", tail="", replace=(), directory_name=None, state_path=None):
        directory = self.home / "configs" / (directory_name or name)
        (directory / "rules").mkdir(parents=True, exist_ok=True)
        (directory / "projects").mkdir(exist_ok=True)
        text = CONFIG_TEMPLATE.format(name=name, top=top, tail=tail)
        if state_path is not None:
            text += "\n[state]\npath = {}\n".format(json.dumps(str(state_path)))
        for old, new in replace:
            self.assertIn(old, text, "the replacement anchor is missing from the fixture")
            text = text.replace(old, new)
        (directory / "config.toml").write_text(text, encoding="utf-8")
        (directory / "rules" / "standing.md").write_text(STANDING_RULES.format(name=name), encoding="utf-8")
        (directory / "rules" / "web.md").write_text(WEB_RULES, encoding="utf-8")
        (directory / "projects" / "web.toml").write_text(PROJECT_TEXT, encoding="utf-8")
        return directory

    def remove_config(self, name):
        directory = self.home / "configs" / name
        if directory.is_symlink():
            directory.unlink()
        elif directory.exists():
            shutil.rmtree(str(directory))

    def fresh_config(self, name, **options):
        self.remove_config(name)
        return self.write_config(name, **options)

    def event(self, kind="test.note", **fields):
        value = {"kind": kind, "actor": "e2e", "payload": {}, "protocol_version": "1.0.0"}
        for key, item in fields.items():
            if item is None:
                value.pop(key, None)
            else:
                value[key] = item
        return value

    def append(self, value, config="alpha", code=0):
        path = self.directory / "event-{}.json".format(uuid.uuid4().hex)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return self.run_laneboss("event", "append", "--config", config, "--file", path, code=code)

    def events(self, config="alpha"):
        return self.laneboss_json("state", "events", "--config", config)

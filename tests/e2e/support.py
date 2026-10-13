"""Shared helpers for the launcher's black-box tests.

Each test module installs the launcher with scripts/install.sh into a temporary
prefix in setUpModule and removes it in tearDownModule. Each test owns temporary
configuration, state and home directories and removes them. Nothing here imports
the package under test: every assertion goes through the installed command.
"""

import hashlib
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
PROTOCOL_FILE = ROOT / "src" / "laneboss" / "protocol" / "protocol.md"
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
    for group in GO_GROUPS:
        environment[ENV_PREFIX + group.upper() + "_GO_BIN"] = str(go_binary(group))
    return environment


def install_environment(user_home):
    """Install with the interpreter that runs the suite, so every platform tests one Python."""
    environment = base_environment(user_home)
    environment[ENV_PREFIX + "PYTHON"] = sys.executable
    return environment


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

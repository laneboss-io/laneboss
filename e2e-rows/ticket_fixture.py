"""Actual service/owner PTY fixture, used only on the disposable Linux box.

No raw ticket is placed in a fixture log. Issuance always executes the real CLI
under the separately attested owner terminal, never a seeded ticket or verifier.
"""

import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid


def safe_diagnostic(result):
    """Expose a CLI refusal without ever printing an issued bearer/stdout."""
    text = result.get("stderr", result.get("output", ""))
    return re.sub(r"lbt[12]\.[A-Za-z0-9_.-]+", "[ticket withheld]", text).strip()


def diagnostic_tail(path):
    """Bound diagnostics without publishing a bearer suffix cut mid-line."""
    with path.open("rb") as source:
        source.seek(0, os.SEEK_END)
        start = max(0, source.tell() - 16384)
        source.seek(start)
        data = source.read(16384)
    if start:
        _, separator, data = data.partition(b"\n")
        if not separator:
            return "[overlong partial log line omitted]"
    return data.decode("utf-8", errors="replace")


def client_environment(environment):
    selected = dict(environment)
    home = Path(selected["HOME"])
    selected.setdefault("LANEBOSS_HOME", str(home / ".config" / "laneboss"))
    selected.setdefault("LANEBOSS_STATE_HOME", str(home / ".local" / "state" / "laneboss"))
    return selected


def read_line(stream):
    readable, _, _ = select.select([stream], [], [], 60)
    if not readable:
        raise RuntimeError("the ticket fixture missed its response deadline")
    line = stream.readline()
    if not line:
        raise RuntimeError("the ticket fixture exited before responding")
    return json.loads(line)


def kernel_peer(pid):
    base = Path("/proc") / str(pid)
    fields = (base / "stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] in ("Z", "X"):
        raise RuntimeError("the fixture peer exited")
    ids = {}
    for line in (base / "status").read_text().splitlines():
        values = line.split()
        if values and values[0] in ("Uid:", "Gid:"):
            ids[values[0]] = int(values[2])
    return {"pid": pid, "uid": ids["Uid:"], "gid": ids["Gid:"],
            "start": Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + fields[19]}


class ServiceFixture:
    def __init__(self, test):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("service fixtures require the disposable Linux box's root test driver")
        self.test = test
        # Caller evidence/TMPDIR may belong to the unprivileged suite driver;
        # the service's protected roots require root-owned ancestry instead.
        self.directory = Path(tempfile.mkdtemp(prefix="lb-svc-ticket-fixture-", dir="/tmp"))
        self.directory.chmod(0o755)
        self.binary = self.directory / "laneboss"
        shutil.copyfile(getattr(test, "binary", getattr(test, "launcher", "")), self.binary)
        self.binary.chmod(0o755)
        # A release-suite venv may sit below its private evidence directory.
        # Controller children need only the system interpreter and stdlib.
        # Preserve the configured driver's basename (e.g. python3). Resolving
        # it to python3.12 in command arrays violates the real org allowlist.
        self.python = self.directory / Path(sys.executable).name
        self.python.symlink_to(Path(sys.executable).resolve(strict=True))
        token = uuid.uuid4().hex[:8]
        group = "lb-ticket-g-" + token
        subprocess.run(["groupadd", "--system", group], check=True, capture_output=True)
        self.gid = grp.getgrnam(group).gr_gid
        accounts = ["lb-ticket-s-" + token, "lb-ticket-h-" + token]
        account_homes = [self.directory / "service-home", self.directory / "human-home"]
        for account, account_home in zip(accounts, account_homes):
            subprocess.run(["useradd", "--system", "--no-create-home", "--gid", group,
                            "--home-dir", str(account_home),
                            "--shell", "/usr/sbin/nologin", account], check=True, capture_output=True)
        self.service_uid, self.human_uid = [pwd.getpwnam(name).pw_uid for name in accounts]
        for account_home, uid in zip(account_homes, (self.service_uid, self.human_uid)):
            account_home.mkdir(mode=0o700)
            os.chown(account_home, uid, self.gid)
        self.client_home = account_homes[1]
        self.runtime = self.directory / "runtime"
        self.state = self.directory / "state"
        self.policy = self.directory / "policy"
        self.runner_sources = self.directory / "runner-sources"
        self.runner_sources.mkdir(mode=0o755)
        self.runner_sources.chmod(0o755)
        for source in Path(__file__).parent.glob("*.py"):
            shutil.copyfile(source, self.runner_sources / source.name)
            (self.runner_sources / source.name).chmod(0o644)
        for path in (self.runtime, self.state, self.policy):
            path.mkdir(mode=0o755)
            path.chmod(0o755)
        os.chown(self.runtime, self.service_uid, self.gid)
        os.chown(self.state, self.service_uid, self.gid)
        self.services = {}
        self.service_errors = {}
        self.launches = {}
        self.level_supported = {}
        self.trusted_orgs = {}
        self.owners = {}
        self.environments = {}
        self.marker = self.directory / "ticket-mutant"
        self.marker.mkdir(mode=0o755)
        os.chown(self.marker, self.service_uid, self.gid)
        self.mutation_marker = self.marker / "reached"
        # Run after lane/controller cleanup, including callbacks registered later.
        test._cleanups.insert(0, (self.close, (), {}))

    def demote(self, uid):
        def apply():
            os.setgroups([])
            os.setgid(self.gid)
            os.setuid(uid)
            os.umask(0o077)
        return apply

    def policy_home(self, name):
        return self.policy / name

    def policy_config(self, name):
        return self.policy_home(name) / "configs" / name / "config.toml"

    def public_config(self, text):
        text = text.replace(str(Path(__file__).parent) + "/", str(self.runner_sources) + "/")
        text = text.replace(json.dumps(sys.executable), json.dumps(str(self.python)))
        original_binary = str(getattr(self.test, "binary", getattr(self.test, "launcher", "")))
        return text.replace(json.dumps(original_binary), json.dumps(str(self.binary)))

    def bind(self, name, environment, policy_drivers=()):
        if name in self.services:
            return
        environment = client_environment(environment)
        home = Path(environment["LANEBOSS_HOME"])
        original = home / "configs" / name
        source_text = (original / "config.toml").read_text()
        public_text = self.public_config(source_text)
        if public_text != source_text:
            (original / "config.toml").write_text(public_text)
        config = tomllib.loads((original / "config.toml").read_text())
        binding_home = self.policy_home(name)
        binding_home.mkdir(mode=0o755)
        binding_home.chmod(0o755)
        (binding_home / "configs").mkdir(mode=0o755)
        (binding_home / "configs").chmod(0o755)
        target = binding_home / "configs" / name
        shutil.copytree(original, target)
        for path in [target, *target.rglob("*")]:
            if path.is_symlink():
                raise RuntimeError("the trusted ticket fixture does not copy linked policy")
            path.chmod(0o755 if path.is_dir() else 0o644)
        org = None
        if "org_dir" in config:
            org = Path(config["org_dir"])
        elif "organisation" in config:
            org = home / "orgs" / config["organisation"]
        if org is not None:
            # Each service binding owns its policy copy, even when two
            # configurations select the same source org. Never overlay copies.
            # A separate ConfigHome preserves the canonical named-org layout
            # for historical binaries which predate explicit org_dir support.
            trusted_org = binding_home / "orgs" / config.get("organisation", name)
            self.trusted_orgs[name] = trusted_org
            trusted_org.parent.mkdir(mode=0o755)
            trusted_org.parent.chmod(0o755)
            shutil.copytree(org, trusted_org)
            for path in [trusted_org, *trusted_org.rglob("*")]:
                if path.is_symlink():
                    raise RuntimeError("the service role fixture contains a link")
                path.chmod(0o755 if path.is_dir() else 0o644)
            if policy_drivers:
                # Explicit root-driver approval in the separate service policy;
                # client role files remain the inputs exercised by the rows.
                drivers = trusted_org / ".laneboss" / "L3" / "roles" / "tester.toml"
                names = tomllib.loads(drivers.read_text())["drivers"]
                drivers.write_text("drivers = " + json.dumps(sorted(set(names) | set(policy_drivers))) + "\n")
            # org_dir is authoritative; both roots contain the same real role library.
            text = (target / "config.toml").read_text()
            if "org_dir" in config:
                text = text.replace(json.dumps(str(org)), json.dumps(str(trusted_org)), 1)
            else:
                text = "org_dir = " + json.dumps(str(trusted_org)) + "\n" + text
            (target / "config.toml").write_text(text)
        child_environment = {"PATH": environment.get("PATH", os.defpath),
                             "HOME": str(self.directory), "LANEBOSS_CONFIG": name,
                             "LANEBOSS_HOME": str(binding_home),
                             "LANEBOSS_STATE_HOME": str(self.directory / "owner-state")}
        helper = self.directory / "ticket_support.py"
        if not helper.exists():
            for filename in ("ticket_support.py", "headless_support.py", "reportsupport.py"):
                shutil.copyfile(Path(__file__).with_name(filename), self.directory / filename)
                (self.directory / filename).chmod(0o644)
        owner = subprocess.Popen([str(self.python), "-I", str(helper), "--login", str(self.binary)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, env=child_environment, preexec_fn=self.demote(self.human_uid))
        self.owners[name] = owner
        ready = read_line(owner.stdout)
        actual = kernel_peer(ready["pid"])
        if actual["uid"] != self.human_uid or actual["pid"] != ready["pid"]:
            raise RuntimeError("the attested owner terminal disagrees with the kernel")
        arguments = [str(self.binary), "service", "run", "--config", name,
                     "--state-root", str(self.state), "--runtime-root", str(self.runtime),
                     "--config-home", str(binding_home), "--human-uid", str(self.human_uid),
                     "--human-session", str(actual["pid"]) + ":" + actual["start"]]
        daemon_environment = {"PATH": environment.get("PATH", os.defpath), "HOME": str(self.directory),
                              "LANEBOSS_CONFIG": name}
        mutation = os.environ.get("LANEBOSS_TICKET_MUTANT", "")
        if mutation:
            if mutation not in ("ticket-reuse", "ticket-human-pty", "ticket-level-unchecked"):
                raise RuntimeError("unsupported ticket mutation")
            daemon_environment["LANEBOSS_FAULTS"] = json.dumps(
                {"point": mutation, "marker": str(self.mutation_marker)})
        self.launches[name] = (arguments, daemon_environment)
        self.start_daemon(name)
        self.environments[name] = child_environment
        text = (original / "config.toml").read_text()
        if "identity_service" not in config:
            (original / "config.toml").write_text(
                text + "\n[identity_service]\nruntime_root = " + json.dumps(str(self.runtime)) + "\n")
            policy_text = (target / "config.toml").read_text()
            (target / "config.toml").write_text(
                policy_text + "\n[identity_service]\nruntime_root = " + json.dumps(str(self.runtime)) + "\n")
        help_result = self.owner_call(name, ["ticket", "issue", "--help"])
        if help_result["code"] != 0 or help_result["stderr"]:
            raise RuntimeError("the real ticket issue help was unavailable")
        self.level_supported[name] = "--level" in help_result["stdout"]

    def start_daemon(self, name):
        arguments, daemon_environment = self.launches[name]
        error_path = self.directory / ("service-stderr-" + name + "-" + uuid.uuid4().hex + ".log")
        descriptor = os.open(error_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as error_output:
            daemon = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=error_output, text=True,
                                      env=daemon_environment, preexec_fn=self.demote(self.service_uid))
        self.services[name] = daemon
        self.service_errors[daemon.pid] = error_path
        try:
            answer = read_line(daemon.stdout)
        except (RuntimeError, json.JSONDecodeError) as problem:
            # EOF means stdout is closed; give the exited child a bounded reap
            # so the diagnostic includes its actual return code, not a guess.
            try:
                code = daemon.wait(timeout=1)
            except subprocess.TimeoutExpired:
                code = "still running"
            raise RuntimeError("the actual ticket service failed before readiness (exit " + str(code) +
                               "): " + str(problem) + "\ndaemon stderr tail:\n" +
                               safe_diagnostic({"stderr": self.daemon_stderr(name)})) from problem
        if not answer.get("ok") or answer["service"]["process"] != kernel_peer(daemon.pid):
            raise RuntimeError("the actual ticket service did not become ready")

    def daemon_stderr(self, name):
        path = self.service_errors[self.services[name].pid]
        return diagnostic_tail(path)

    def level_args(self, name, level):
        # Discover syntax before issuance, never retry a refused registration.
        # This lets R39 rows reach their semantic assertions on the pre-R39
        # binary too. Assertions are identical for both token versions.
        return ["--level", str(level)] if self.level_supported[name] else []

    def change_role_level(self, name, role, level, restart=True):
        """Reload real protected policy without editing tickets or identities."""
        if restart:
            daemon = self.services[name]
            os.kill(daemon.pid, signal.SIGTERM)
            daemon.communicate(timeout=20)
            if daemon.returncode != 0:
                raise RuntimeError("the policy reload could not stop its service: " +
                                   safe_diagnostic({"stderr": self.daemon_stderr(name)}))
        path = self.policy_config(name)
        text = path.read_text()
        old_level = tomllib.loads(text)["supervisors"][role]["level"]
        old = "[supervisors." + role + "]\nlevel = " + str(old_level) + "\n"
        if text.count(old) != 1:
            raise RuntimeError("the fixture role level source is ambiguous")
        path.write_text(text.replace(old, "[supervisors." + role + "]\nlevel = " + str(level) + "\n", 1))
        if restart:
            self.start_daemon(name)

    def remove_role(self, name, role):
        path = self.policy_config(name)
        text, count = re.subn(r"(?ms)^\[supervisors\." + re.escape(role) + r"\]\n.*?(?=^\[|\Z)", "", path.read_text())
        if count != 1:
            raise RuntimeError("the protected role removal source is ambiguous")
        path.write_text(text)

    def issue(self, name, level, role, ttl="10m"):
        owner = self.owners[name]
        owner.stdin.write(json.dumps({"args": ["ticket", "issue", "--config", name,
                                                *self.level_args(name, level),
                                                "--role", role, "--ttl", ttl]}) + "\n")
        owner.stdin.flush()
        result = read_line(owner.stdout)
        if result["code"] != 0:
            raise RuntimeError("the actual owner terminal could not issue through the service (exit " +
                               str(result["code"]) + "): " + safe_diagnostic(result))
        lines = result["stdout"].splitlines()
        prefix = "lbt2." if self.level_supported[name] else "lbt1."
        if len(lines) != 1 or not lines[0].startswith(prefix) or result["stderr"]:
            raise RuntimeError("issuance did not print exactly one canonical ticket")
        return lines[0]

    def owner_call(self, name, arguments):
        return self.owner_request(name, {"args": list(map(str, arguments))})

    def owner_request(self, name, request):
        owner = self.owners[name]
        owner.stdin.write(json.dumps(request) + "\n")
        owner.stdin.flush()
        return read_line(owner.stdout)

    def prepare_actor_files(self):
        """Root prepares fixture files for the shared unprivileged client UID.

        Service policy/state live in a different tree and retain their original
        protected ownership. Do not follow links out of the disposable row.
        """
        self.test._ticket_actor_mode = True
        root = Path(getattr(self.test, "directory", getattr(self.test, "root", "")))
        if not root.is_absolute() or root == self.directory or self.directory.is_relative_to(root):
            raise RuntimeError("the client actor root overlaps the service fixture")
        for directory, dirs, files in os.walk(root, followlinks=False):
            for path in [Path(directory), *(Path(directory) / name for name in dirs + files)]:
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    # Product atomic replacements may remove a temporary name
                    # after walk enumerated it; there is no file to prepare.
                    continue
                if stat.S_ISLNK(info.st_mode):
                    continue
                if (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1) and info.st_uid != self.human_uid:
                    os.chown(path, self.human_uid, self.gid)

    def actor_environment(self, name, environment):
        self.bind(name, environment)
        self.prepare_actor_files()
        selected = client_environment(environment)
        root = Path(getattr(self.test, "directory", getattr(self.test, "root", "")))
        if not Path(selected["HOME"]).is_relative_to(root):
            selected["HOME"] = str(self.client_home)
        return {**selected, "LANEBOSS_CONFIG": name}

    def actor_binary(self, binary):
        source = Path(binary)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        target = self.directory / ("actor-binary-" + digest)
        if not target.exists():
            shutil.copyfile(source, target)
            target.chmod(0o755)
        return target

    def publish_instance(self, name, source_org, instance):
        """Mirror an explicit root-driver org-instance add into trusted policy."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", instance):
            raise RuntimeError("the admin instance name is invalid")
        policy = tomllib.loads(self.policy_config(name).read_text())
        target = Path(policy["org_dir"]) / ".laneboss" / "instances" / instance
        source = Path(source_org) / ".laneboss" / "instances" / instance
        shutil.copytree(source, target)
        for path in [target, *target.rglob("*")]:
            if path.is_symlink():
                raise RuntimeError("the approved instance source contains a link")
            path.chmod(0o755 if path.is_dir() else 0o644)

    def owner_write(self, name, path, text):
        owner = self.owners[name]
        owner.stdin.write(json.dumps({"write_file": str(path), "text": text}) + "\n")
        owner.stdin.flush()
        result = read_line(owner.stdout)
        if result.get("written") != len(text) or path.read_text() != text:
            raise RuntimeError("the unprivileged policy-write canary did not change its real file")

    def close(self):
        for name, process in self.services.items():
            if process.poll() is None:
                os.kill(process.pid, signal.SIGTERM)
            process.communicate(timeout=20)
            if process.returncode != 0:
                raise RuntimeError("ticket service collection failed: " +
                                   safe_diagnostic({"stderr": self.daemon_stderr(name)}))
        for owner in self.owners.values():
            if owner.poll() is None:
                owner.stdin.write('{"quit":true}\n')
                owner.stdin.flush()
            owner.communicate(timeout=20)
            if owner.returncode != 0:
                raise RuntimeError("the attested owner terminal was not collected")


def fixture_for(test):
    fixture = getattr(test, "_ticket_fixture", None)
    if fixture is None:
        fixture = ServiceFixture(test)
        test._ticket_fixture = fixture
    return fixture


def registration_args(test, name, role, environment):
    """Keep no-service rows unchanged; opt-in matrices exercise actual issuance."""
    environment = client_environment(environment)
    config_file = Path(environment["LANEBOSS_HOME"]) / "configs" / name / "config.toml"
    data = tomllib.loads(config_file.read_text())
    enabled = os.environ.get("LANEBOSS_TICKET_SERVICE_ROWS", "") == "1" or "identity_service" in data
    if not enabled:
        return []
    fixture = fixture_for(test)
    fixture.bind(name, environment)
    entry = data.get("supervisors", {}).get(role)
    if entry is None:
        policy = tomllib.loads(fixture.policy_config(name).read_text())
        source = Path(policy["org_dir"]) / ".laneboss" / "instances" / role / "instance.toml"
        entry = tomllib.loads(source.read_text())
    level = entry.get("level")
    if level is None:
        level = {"mini": 4, "top": 5}[entry["role"]]
    raw = fixture.issue(name, level, role)
    path = fixture.directory / ("handoff-" + uuid.uuid4().hex)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(raw + "\n")
    if getattr(test, "_ticket_actor_mode", False) or service_rows(test, environment):
        os.chown(path, fixture.human_uid, fixture.gid)
    return [*fixture.level_args(name, level), "--ticket-file", str(path)]


def with_registration(test, arguments, environment):
    environment = client_environment(environment)
    args = list(map(str, arguments))
    if (getattr(test, "ticket_rows_explicit", False) or not args or args[0] != "start"
            or "--role" not in args or "--config" not in args or "--ticket-file" in args):
        return args
    name = args[args.index("--config") + 1]
    role = args[args.index("--role") + 1]
    path = Path(environment["LANEBOSS_HOME"]) / "configs" / name / "config.toml"
    if not path.is_file():
        return args
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError:
        # Preserve the real launcher's malformed-configuration rejection.
        return args
    supervisors = data.get("supervisors", {})
    if not isinstance(supervisors, dict):
        return args
    entry = supervisors.get(role)
    minimum = 4
    if entry is None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", role):
            return args
        org = data.get("org_dir")
        if not org and data.get("organisation"):
            org = str(Path(environment["LANEBOSS_HOME"]) / "orgs" / data["organisation"])
        if not org:
            return args
        source = Path(org) / ".laneboss" / "instances" / role / "instance.toml"
        if not source.is_file():
            return args
        entry = tomllib.loads(source.read_text())
        minimum = 3
    if not isinstance(entry, dict):
        return args
    level = entry.get("level", {"mini": 4, "top": 5}.get(entry.get("role")))
    if type(level) is not int or not minimum <= level <= 6:
        # The actual CLI reports malformed client config before registration.
        return args
    return [*args, *registration_args(test, name, role, environment)]


def service_text(test, text):
    fixture = getattr(test, "_ticket_fixture", None)
    if fixture is not None:
        text = fixture.public_config(text)
    if fixture is not None and "[identity_service]" not in text:
        return text + "\n[identity_service]\nruntime_root = " + json.dumps(str(fixture.runtime)) + "\n"
    return text


def service_rows(test, environment):
    environment = client_environment(environment)
    if getattr(test, "ticket_rows_explicit", False):
        return False
    if os.environ.get("LANEBOSS_TICKET_SERVICE_ROWS", "") == "1":
        return True
    name = environment.get("LANEBOSS_CONFIG", "")
    home = environment.get("LANEBOSS_HOME", "")
    path = Path(home) / "configs" / name / "config.toml"
    if not name or not home or not path.is_file():
        return False
    try:
        return "identity_service" in tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError:
        return False

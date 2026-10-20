"""Root-owned inputs for the installed serve case; no service substitutes."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import tarfile
import tempfile
import uuid


_admin_boot_spec = importlib.util.spec_from_file_location(
    "laneboss_admin_boot", Path(__file__).parents[1] / "v2-admin" / "boot.py")
if _admin_boot_spec is None or _admin_boot_spec.loader is None:
    raise RuntimeError("administrator installer source is unavailable")
_admin_boot = importlib.util.module_from_spec(_admin_boot_spec)
_admin_boot_spec.loader.exec_module(_admin_boot)

_runtime_spec = importlib.util.spec_from_file_location(
    "runtime_deps", Path(__file__).parents[1] / "v2-admin" / "runtime_deps.py")
_runtime_deps = importlib.util.module_from_spec(_runtime_spec)
_runtime_spec.loader.exec_module(_runtime_deps)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def key_source(source_type, fake=False, source_file=None):
    """Select bytes once; both flags use the identical source/enrollment path.

    The real flag changes only byte acquisition and its explicit smoke budget;
    no profile, home, store format, destination or native projection is selected
    from that flag. The existing private-file checks apply before construction.
    """
    require(not (fake and source_file is not None), "fake and real API key sources are mutually exclusive")
    if not fake and source_file is None:
        return None
    material = source_type.fake_material() if source_file is None else source_type.read_file(source_file)
    return source_type(material, real=source_file is not None)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture_accounts(config):
    """Return the disposable non-root identities used by installed canaries."""
    require(isinstance(config, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", config),
            "fixture account configuration is invalid")
    run = sha(config.encode("utf-8"))[:8]
    return {
        "run": run,
        "group": {"name": "lbrpc" + run},
        "users": [{"name": prefix + run} for prefix in ("lbsvc", "lbop", "lblane")],
    }


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def installed_socket_path(config):
    """Resolve the installed endpoint through the administrator source of truth."""
    return _admin_boot.socket_root(config) / "control.sock"


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def protected(path):
    while True:
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022, f"unprotected root staging path: {path}")
        if path == Path("/"):
            return
        path = path.parent


def read_protected(path, limit=1048576, mode=None, allow_empty=False):
    """Read supplied administrator bytes; never repair a rejected input."""
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)),
            "administrator input needs a canonical absolute path")
    protected(path.parent)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
            not before.st_mode & 0o7022 and 0 <= before.st_size <= limit and
            (before.st_size > 0 or allow_empty), "unsafe administrator input metadata")
    require(mode is None or stat.S_IMODE(before.st_mode) == mode, "administrator input mode differs")
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_uid, info.st_gid,
                             info.st_mode, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before), "administrator input changed on open")
        data = stream.read(limit + 1)
        require(len(data) == before.st_size and identity(os.fstat(stream.fileno())) == identity(before),
                "administrator input changed while reading")
    require(identity(path.lstat()) == identity(before), "administrator input path changed while reading")
    return data


def document(data):
    def members(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate administrator JSON member")
            result[key] = value
        return result
    def invalid_number(_):
        raise ValueError("invalid JSON number")
    value = json.loads(data, object_pairs_hook=members, parse_constant=invalid_number)
    require(isinstance(value, dict), "administrator input must be a JSON object")
    return value


def fields(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= set(value) <= set(required) | set(optional),
            "administrator input field map differs")


HELPER_PROPERTIES = ("CapabilityBoundingSet", "AmbientCapabilities", "SecureBits", "User", "Group",
                     "PrivateUsers", "NoNewPrivileges", "RestrictSUIDSGID", "DropInPaths", "FragmentPath",
                     "SystemCallFilter", "RestrictNamespaces")


def helper_capability_record(value):
    require(isinstance(value, dict) and set(value) == {"stage", "observation"} and
            value["stage"] in ("helper.before_accounts", "helper.after_accounts") and isinstance(value["observation"], str),
            "helper capability record has an invalid shape")
    observation = value["observation"]
    match = re.fullmatch(r"process CAP_SETUID CapEff=(present|absent), CapPrm=(present|absent), CapBnd=(present|absent)", observation)
    if match:
        return {"stage": value["stage"], "CapEff": match[1], "CapPrm": match[2], "CapBnd": match[3]}
    match = re.fullmatch(r"process CAP_SETUID=unavailable\(([A-Z]+|other)\)", observation)
    require(match and match[1] in {"EPERM", "EACCES", "ENOSYS", "EINVAL", "EBADF", "EBUSY", "EOPNOTSUPP",
                                  "EAGAIN", "ENOMEM", "ENOENT", "ENOEXEC", "ENOTDIR", "ELOOP", "EFAULT", "EMFILE", "ENFILE", "other"},
            "helper capability record has an invalid verdict")
    return {"stage": value["stage"], "unavailable": match[1]}


def helper_policy_facts(expected, installed, shown):
    """Compare real selected manager fields in memory; publish names/verdicts only."""
    try:
        declared = [line.split("=", 1)[1] for line in expected.decode("utf-8").splitlines()
                    if line.startswith("CapabilityBoundingSet=")]
        values = {}
        for line in shown.decode("utf-8").splitlines():
            name, separator, value = line.partition("=")
            require(separator and name in HELPER_PROPERTIES and name not in values,
                    "helper policy has an unknown or duplicate selected field")
            values[name] = value.strip()
    except UnicodeDecodeError:
        raise ValueError("helper policy is not UTF-8") from None
    require(len(declared) == 1 and set(values) == set(HELPER_PROPERTIES),
            "helper policy lacks complete declared and effective fields")
    actual_caps = set(values["CapabilityBoundingSet"].upper().split())
    declared_caps = set(declared[0].upper().split())
    verdicts = {
        "fragment.template": "match" if installed == expected else "different",
        "CapabilityBoundingSet.declared": "match" if actual_caps == declared_caps else "different",
        "CapabilityBoundingSet.CAP_SETUID": "present" if "CAP_SETUID" in actual_caps else "absent",
        "CapabilityBoundingSet.CAP_SETGID": "present" if "CAP_SETGID" in actual_caps else "absent",
        "AmbientCapabilities": "empty" if not values["AmbientCapabilities"] else "reported",
        "SecureBits": "clear" if values["SecureBits"] == "0" else "reported",
        # An empty User is the system manager's default, root (the helper unit sets none on purpose).
        "User.root": "default" if not values["User"] else ("yes" if values["User"] in ("root", "0") else "no"),
        "Group.root": "yes" if values["Group"] in ("root", "0") else "no",
        "DropInPaths": "empty" if not values["DropInPaths"] else "reported",
        "FragmentPath": "reported" if values["FragmentPath"] else "empty",
        "SystemCallFilter": "empty" if not values["SystemCallFilter"] else "reported",
        "RestrictNamespaces": "empty" if not values["RestrictNamespaces"] else "reported",
    }
    for name in ("PrivateUsers", "NoNewPrivileges", "RestrictSUIDSGID"):
        value = values[name].lower()
        verdicts[name] = "enabled" if value in ("yes", "true", "1") else "disabled" if value in ("no", "false", "0") else "unrecognized"
    return [{"name": name, "verdict": verdict} for name, verdict in sorted(verdicts.items())]


def pinned(ref, data):
    fields(ref, ("id", "class", "sha256", "bytes"))
    require(isinstance(ref["id"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", ref["id"]) and
            ref["class"] in ("manifest", "artifact", "task") and
            type(ref["bytes"]) is int and 0 <= ref["bytes"] <= 64 << 20 and
            (ref["bytes"] > 0 or ref["class"] == "artifact") and
            ref["bytes"] == len(data) and ref["sha256"] == sha(data), "administrator object pin differs")


def release(binary, version, architecture, output):
    return {"version": version["version"], "protocol": version["api_protocol"],
            "schema": 2, "source_sha256": digest(output / "source.tar"),
            "artifacts": [{"os": "linux", "arch": architecture,
                           "sha256": digest(binary), "bytes": binary.stat().st_size}],
            "vendor_manifest": {"id": "go_vendor", "class": "manifest",
                                "sha256": digest(output / "vendor-manifest.input"),
                                "bytes": (output / "vendor-manifest.input").stat().st_size}}


def supplied_boot(path, binary, version, architecture, output, agent, config, suite, egress_anthropic=False):
    """Pass the complete explicit boot bundle to the real installer unchanged."""
    raw = read_protected(path)
    boot_input = document(raw)
    fields(boot_input, ("schema", "runtime_manifest", "runtime_file", "runtime_roots", "secret_key_file",
                        "judge", "judge_endpoint", "admin_enrollment", "launch_enrollment",
                        "launch_enrollment_file", "initial_publication", "initial_publication_file", "initial_objects"),
           ("judge_credential_handle", "judge_alternative", "fixture_accounts"))
    require(boot_input["schema"] == "laneboss.boot-input.v2", "supplied boot schema differs")
    runtime_raw = read_protected(boot_input["runtime_file"])
    launch_raw = read_protected(boot_input["launch_enrollment_file"])
    initial_raw = read_protected(boot_input["initial_publication_file"], mode=0o444)
    for name, data in (("runtime_manifest", runtime_raw), ("launch_enrollment", launch_raw),
                       ("initial_publication", initial_raw)):
        pinned(boot_input[name], data)
        require(boot_input[name]["class"] == "manifest", "boot descriptor is not a manifest")
    initial, runtime, launch = map(document, (initial_raw, runtime_raw, launch_raw))
    fields(initial, ("schema", "config", "id", "generation", "runtime", "launch_enrollment", "policy",
                     "sources", "source_manifest", "profiles", "task", "l5", "l5_sources", "objects"))
    require(initial["schema"] == "laneboss.initial.v2" and initial["config"] == config and
            type(initial["generation"]) is int and initial["generation"] == 1 and
            initial["runtime"] == boot_input["runtime_manifest"] and
            initial["launch_enrollment"] == boot_input["launch_enrollment"] and
            isinstance(initial["id"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", initial["id"]),
            "publication differs from the supplied configuration or boot pins")
    require(launch.get("config") == config and runtime.get("schema") == "laneboss.runtime.v2" and
            runtime.get("artifact", {}).get("sha256") == digest(binary) and
            runtime["artifact"].get("version") == version["version"], "supplied runtime differs from the actual built artifact")
    require(isinstance(initial["objects"], list) and 0 < len(initial["objects"]) <= 512 and
            isinstance(boot_input["initial_objects"], list) and
            len(boot_input["initial_objects"]) == len(initial["objects"]), "initial inventory is absent or unbounded")
    declared = {}
    for ref in initial["objects"]:
        require(isinstance(ref, dict) and isinstance(ref.get("id"), str) and ref["id"] not in declared,
                "duplicate initial object identity")
        declared[ref["id"]] = ref
    retained = output / "initial-inputs"
    retained.mkdir(mode=0o700)
    (retained / "initial.json").write_bytes(initial_raw)
    objects, inventory, total = {}, [], 0
    for row in boot_input["initial_objects"]:
        fields(row, ("ref", "file"))
        ref = row["ref"]
        fields(ref, ("id", "class", "sha256", "bytes"))
        require(type(ref["bytes"]) is int and 0 <= ref["bytes"] <= 64 << 20,
                "initial object size is unbounded")
        data = read_protected(row["file"], ref["bytes"], mode=0o444, allow_empty=ref["class"] == "artifact")
        pinned(ref, data)
        require(declared.get(ref["id"]) == ref and ref["id"] not in objects and
                ref["id"] not in (boot_input["initial_publication"]["id"], "initial-receipt-" + config),
                "initial inventory is undeclared, duplicated or reserved")
        total += len(data)
        require(total <= 64 << 20, "initial inventory exceeds its byte bound")
        objects[ref["id"]] = data
        (retained / ref["id"]).write_bytes(data)
        inventory.append({"ref": ref, "paths": path_metadata(Path(row["file"]))})
    for name in ("runtime", "launch_enrollment", "policy", "sources", "source_manifest", "profiles", "task"):
        require(declared.get(initial[name]["id"]) == initial[name], "selected publication document is absent")
    require(objects[initial["runtime"]["id"]] == runtime_raw and
            objects[initial["launch_enrollment"]["id"]] == launch_raw, "publication and installed runtime/launch bytes differ")
    if egress_anthropic:
        endpoints = launch.get("network", [])
        network = document(objects[initial["profiles"]["id"]]).get("network", [])
        require(len(endpoints) == 1 and all(endpoints[0].get(name) == expected for name, expected in
                (("id", "anthropic-api"), ("host", "api.anthropic.com"), ("protocol", "tcp"), ("port", 443))) and
                len(network) == 1 and network[0].get("endpoint_id") == "anthropic-api" and
                network[0].get("mode") == "internet",
                "supplied egress bundle must already enroll and approve the Anthropic API endpoint")
    roots = {}
    require(isinstance(boot_input["runtime_roots"], list), "supplied runtime roots are absent")
    for root in boot_input["runtime_roots"]:
        fields(root, ("id", "path"))
        require(root["id"] not in roots, "duplicate runtime root")
        selected = Path(root["path"])
        require(selected.is_absolute() and str(selected) == os.path.normpath(str(selected)) and selected.is_dir(),
                "runtime root is not a canonical directory")
        protected(selected)
        roots[root["id"]] = selected
    configurations = []
    for obj in runtime["objects"]:
        relative = Path(obj["relative_path"])
        require(not relative.is_absolute() and relative.parts and str(relative) == obj["relative_path"] and
                all(part not in (".", "..") for part in relative.parts), "runtime object escapes its supplied root")
        data = read_protected(roots[obj["root_id"]] / relative, 64 << 20, mode=obj["mode"])
        pinned(obj["content"], data)
        require(declared.get(obj["content"]["id"]) == obj["content"] and
                objects[obj["content"]["id"]] == data, "runtime object differs from the published inventory")
        if obj["role"] == "serve-fixture-config":
            configurations.append(data)
        if obj["role"] == "serve-fixture-agent":
            require(sha(data) == agent["sha256"], "supplied fixture differs from the actual built executable")
    require(len(configurations) == 1, "one explicitly supplied fixture descriptor is required")
    descriptor = document(configurations[0])
    require(descriptor.get("config") == config and descriptor.get("mode") == suite and
            descriptor.get("challenge") and descriptor.get("vendor_stood_in") is True and
            descriptor.get("executable", {}).get("sha256") == agent["sha256"] and
            descriptor.get("client", {}).get("sha256") == digest(binary), "supplied fixture descriptor differs from this case")
    inputs = evidence_root("lb-v2-serve-boot-", "/opt")
    boot_file = administrator_input(inputs, "boot.json", raw)
    manifest_raw = encoded(release(binary, version, architecture, output))
    manifest_file = administrator_input(inputs, "release.json", manifest_raw)
    for name, data in (("boot.json.input", raw), ("release.json.input", manifest_raw),
                       ("runtime.json.input", runtime_raw), ("launch-enrollment.json.input", launch_raw),
                       ("fixture-enrollment.input.json", configurations[0]),
                       ("fixture-task.input.json", objects[initial["task"]["id"]])):
        (output / name).write_bytes(data)
    (output / "initial-inputs.paths.json").write_bytes(encoded({"objects": inventory,
        "boot": path_metadata(Path(path)), "descriptor": path_metadata(Path(boot_input["initial_publication_file"]))}))
    # The native key remains at the supplied protected path. Its bytes are
    # consumed by the real installer and never copied into this evidence set.
    return boot_file, manifest_file, None


def evidence_root(prefix, parent="/var/tmp"):
    root = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    info = root.lstat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            "root evidence identity differs")
    return root


def path_metadata(path):
    """Retain native metadata for a leaf and every ancestor, without contents."""
    require(path.is_absolute() and Path(os.path.normpath(path)) == path, "noncanonical metadata path")
    rows = []
    while True:
        info = path.lstat()
        kind = "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else (
            "regular" if stat.S_ISREG(info.st_mode) else "socket" if stat.S_ISSOCK(info.st_mode) else "other")
        rows.append({"path": str(path), "uid": info.st_uid, "gid": info.st_gid,
                     "mode": format(stat.S_IMODE(info.st_mode), "04o"), "links": info.st_nlink,
                     "kind": kind, "device": info.st_dev, "inode": info.st_ino})
        if path == Path("/"):
            return list(reversed(rows))
        path = path.parent


def administrator_input(root, name, data):
    """Publish the exact helper input inside a private protected root."""
    protected(root)
    require(stat.S_IMODE(root.lstat().st_mode) == 0o700 and root.is_dir(),
            "administrator input directory is not private")
    require(name not in ("", ".", "..") and Path(name).name == name,
            "administrator input name is not a leaf")
    path = root / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        require(stream.write(data) == len(data), "short administrator input write")
        stream.flush()
        os.fsync(stream.fileno())
        before = os.fstat(stream.fileno())
    protected(path)
    after = path.lstat()
    require(stat.S_ISREG(after.st_mode) and after.st_uid == 0 and after.st_nlink == 1 and
            stat.S_IMODE(after.st_mode) == 0o600 and
            (before.st_dev, before.st_ino, before.st_size) == (after.st_dev, after.st_ino, after.st_size) and
            path.read_bytes() == data, "administrator input identity or exact read-back differs")
    return path


def immutable_input(root, name, data):
    path = administrator_input(root, name, data)
    path.chmod(0o444)
    require(read_protected(path, max(len(data), 1), mode=0o444, allow_empty=not data) == data,
            "immutable fixture input read-back differs")
    return path


def runtime_asset(root, asset):
    """Stage one measured case asset in the protected runtime directory."""
    fields(asset, ("id", "role", "file", "mode"))
    name = asset["id"]
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,39}", name) and
            asset["mode"] in (0o444, 0o555) and isinstance(asset["role"], str) and
            asset["role"] and not asset["role"].startswith("serve-fixture"),
            "case runtime asset is invalid or aliases a fixture role")
    protected(root)
    raw = read_protected(Path(asset["file"]), 64 << 20)
    target = root / name
    with target.open("xb") as stream:
        require(stream.write(raw) == len(raw), "short runtime asset write")
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), asset["mode"])
    require(read_protected(target, 64 << 20, mode=asset["mode"]) == raw,
            "case runtime bytes differ after staging")
    return {"id": name, "role": asset["role"], "root_id": "serve_assets",
            "relative_path": name, "mode": asset["mode"], "content": {
                "id": name, "class": "artifact", "sha256": sha(raw), "bytes": len(raw)}}


def canary_balance(inputs, output, profile_id):
    """Declare fake pool data for this canary, using the operator tool format.

    This executable is input to the installed administrator CLI. Only the
    service may enroll its output; this harness never opens the state store.
    """
    require(isinstance(profile_id, str) and
            re.fullmatch(r"[A-Za-z0-9_-]{1,128}", profile_id),
            "canary balance needs its published profile selector")
    data = (b"#!/bin/sh\n"
            b"# Fixed fake API-key canary reading; no vendor balance queried.\n"
            b"printf 'CANARY  10.00 USD\\n'\n")
    tool = administrator_input(inputs, "canary-balance", data)
    tool.chmod(0o700)
    require(read_protected(tool, mode=0o700) == data,
            "canary balance executable read-back differs")
    (output / "canary-balance.input.sh").write_bytes(data)
    return {"command": str(tool), "selector": "CANARY",
            "credential_id": "canary-api-pool", "profile_ids": [profile_id],
            "floor_micros": 5000000}


def fixture_initial(inputs, objects_root, boot_input, output, agent, source, tool, command,
                    egress_anthropic=False, real_vendor=None, item_inputs=None, real_api_key=False):
    """Assemble explicit test-org documents outside the installed product."""
    require(tool is not None and command is not None and source is not None,
            "the installed fixture requires the real bundle assembler")
    sources = []
    for identifier, relative, logical, kind in (
            ("serve-org-prompt", "org/default.md", ".laneboss/shared/templates/default.md", "prompt"),
            ("serve-org-drivers", "org/drivers.toml", ".laneboss/shared/templates/drivers.toml", "drivers"),
            ("serve-workflow", "org/workflow.toml", ".laneboss/shared/workflow.toml", "policy"),
            ("serve-l5-prompt", "roles/L5/supervisor.md", ".laneboss/L5/roles/supervisor.md", "prompt"),
            ("serve-l5-drivers", "roles/L5/supervisor.toml", ".laneboss/L5/roles/supervisor.toml", "drivers")):
        data = read_protected(source / "templates/v2" / relative)
        sources.append({"id": identifier, "path": logical, "kind": kind,
                        "data": base64.b64encode(data).decode("ascii")})
    runtime_raw = read_protected(boot_input["runtime_file"])
    runtime = document(runtime_raw)
    fixture = source / "scripts/v2-serve/fixtures/README.md"
    data = {"config": document(read_protected(objects_root / "serve-agent.json"))["config"],
            "runtime_ref": boot_input["runtime_manifest"], "runtime": base64.b64encode(runtime_raw).decode("ascii"),
            "sources": sources, "project": base64.b64encode(read_protected(fixture)).decode("ascii"),
            "task": base64.b64encode(read_protected(objects_root / "serve-task.json")).decode("ascii"),
            "judge": boot_input["judge"], "model": agent["version"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if egress_anthropic:
        data["egress_anthropic"] = True
    if real_vendor is not None:
        data["real_claudock"] = real_vendor["claudock"]["executable"]
        data["real_claude"] = real_vendor["claude"]["executable"]
    bundle = (item_inputs or {}).get("bundle", {})
    require(isinstance(bundle, dict) and set(bundle) <= {
        "documents", "sources", "contexts", "projects", "root_grants", "budget", "task"},
        "case bundle contains an unsupported assembler field")
    data["sources"].extend(bundle.get("sources", []))
    data.update({key: value for key, value in bundle.items() if key != "sources"})
    if real_api_key:
        require(real_vendor is not None and egress_anthropic,
                "real API key task requires the real runtime and enrolled endpoint")
        # Bound the actual published task/budget before the assembler hashes
        # them. The Codex stand-in's separate runtime task remains unchanged.
        data["task"] = base64.b64encode(
            b"# Installed real-key smoke task\n\n"
            b"Reply with exactly: installed real-key smoke complete.\n"
            b"Use one short reply. Do not use tools or modify files.\n").decode("ascii")
        data["budget"] = {"wall_ms": 60000, "cpu_seconds": 30,
                          "memory_bytes": 1073741824, "processes": 64,
                          "disk_bytes": 67108864, "spend_micros": 100000,
                          "currency": "USD"}
    input_file = administrator_input(inputs, "bundle-input.json", encoded(data))
    (output / "bundle-input.json.input").write_bytes(read_protected(input_file, mode=0o600))
    assembled = document(command("bundle-assemble", [str(tool), "--input", str(input_file)], clean=True))
    fields(assembled, ("schema", "initial", "ref", "raw", "documents", "root_request", "lanes"))
    require(assembled["schema"] == "laneboss.serve-initial-bundle.v1", "bundle assembler returned another schema")
    raw = base64.b64decode(assembled["raw"], validate=True)
    pinned(assembled["ref"], raw)
    initial = document(raw)
    require(initial == assembled["initial"] and initial["config"] == data["config"] and
            initial["runtime"] == boot_input["runtime_manifest"], "bundle descriptor differs from its input")
    object_root = inputs / "initial-objects"
    object_root.mkdir(mode=0o700)
    inventory, objects = [], {}

    def retain(ref, content):
        pinned(ref, content)
        require(ref["id"] not in objects, "bundle object repeats")
        path = immutable_input(object_root, ref["id"], content)
        objects[ref["id"]] = ref
        inventory.append({"ref": ref, "file": str(path)})

    for obj in runtime["objects"]:
        require(obj["root_id"] == "serve_assets", "fixture runtime root differs")
        if obj["role"] in ("claudock", "claude"):
            continue  # Installation files are absent from the publication/frame inventory.
        retain(obj["content"], read_protected(objects_root / obj["relative_path"], 64 << 20))
    for doc in assembled["documents"]:
        fields(doc, ("ref", "data"))
        retain(doc["ref"], base64.b64decode(doc["data"], validate=True))
    require(len(objects) == len(initial["objects"]) and
            all(objects.get(ref["id"]) == ref for ref in initial["objects"]),
            "assembled object closure differs from protected input files")
    initial_file = immutable_input(inputs, "initial.json", raw)
    launch_ref = initial["launch_enrollment"]
    launch_file = object_root / launch_ref["id"]
    boot_input.update({"initial_publication": assembled["ref"], "initial_publication_file": str(initial_file),
        "initial_objects": inventory, "launch_enrollment": launch_ref, "launch_enrollment_file": str(launch_file)})
    require(assembled["root_request"]["manifest"] == initial["profiles"], "root request changed the profile manifest")
    requests = []
    for name, value in (("root-grants.json", assembled["root_request"]),
                        ("lane-inputs.json", assembled["lanes"]),
                        ("state-launch.json", assembled["lanes"]["codex"])):
        path = immutable_input(inputs, name, encoded(value))
        (output / (name + ".input")).write_bytes(read_protected(path, mode=0o444))
        requests.append({"name": name, "paths": path_metadata(path), "sha256": digest(path)})
    retained = output / "initial-inputs"
    retained.mkdir(mode=0o700)
    (retained / "initial.json").write_bytes(raw)
    for row in inventory:
        ref = row["ref"]
        (retained / ref["id"]).write_bytes(read_protected(row["file"], ref["bytes"], mode=0o444))
    (output / "launch-enrollment.json.input").write_bytes(read_protected(launch_file, mode=0o444))
    (output / "initial-inputs.paths.json").write_bytes(encoded({"objects": [
        {"ref": row["ref"], "paths": path_metadata(Path(row["file"]))} for row in inventory],
        "descriptor": path_metadata(initial_file), "requests": requests,
        "assembler_input": path_metadata(input_file), "origin": "owned harness fixture sources"}))


def stage(source, output):
    destination = Path(tempfile.mkdtemp(prefix="lb-v2-serve-src-", dir="/opt"))
    destination.chmod(0o755)
    protected(destination)
    inventory = []
    roots = ("go.mod", "go.sum", "cmd", "internal", "packaging", "scripts/v2-admin",
             "templates/v2", "scripts/v2-serve", "e2e/v2")
    # module packages outside internal/ (migration/v2, web/v2); a base tree may predate them
    optional = ("migration", "web")
    with tarfile.open(output / "source.tar", "w") as archive:
        for name in roots + optional:
            root = source / name
            if name in optional and not root.exists() and not root.is_symlink():
                continue
            require(root.exists() and not root.is_symlink(), "invalid source root")
            paths = [root] if root.is_file() else sorted(root.rglob("*"))
            for path in paths:
                require(not path.is_symlink(), "linked source input")
                if not path.is_file():
                    continue
                if "__pycache__" in path.parts or path.suffix == ".pyc":
                    continue
                data = path.read_bytes()
                relative = path.relative_to(source)
                target = destination / relative
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    stream.write(data)
                target.chmod(0o644)
                protected(target)
                require(digest(target) == sha(data), "root copy read-back differs")
                inventory.append({"path": str(relative), "sha256": sha(data),
                                  "bytes": len(data)})
                archive.add(target, arcname=str(relative), recursive=False)
    (output / "source-files.json").write_bytes(encoded(inventory))
    harness = Path(__file__).resolve().parent
    archive_harness(harness, output)
    (output / "entry.input.sh").write_bytes((harness.parents[1] /
                                           "e2e/v2/cases/serve/run.sh").read_bytes())
    return destination


def archive_harness(harness, output):
    with tarfile.open(output / "harness.tar", "w") as archive:
        names = ("README", "authenticator.mod") + tuple(sorted(path.name for path in harness.glob("*.py")))
        for name in names:
            archive.add(harness / name, arcname=name, recursive=False)
        fixture = harness.parents[1] / "cmd/laneboss/serve-fixture"
        for path in sorted(fixture.glob("*.go")):
            archive.add(path, arcname="serve-fixture/" + path.name, recursive=False)


def fixture_source(source, output, package_bytes, entry=None):
    """Retain the actual in-module build inputs, selected by Go's dependency list."""
    source_manifest = (output / "source-files.json").read_bytes()
    rows = json.loads(source_manifest)
    require(isinstance(rows, list) and rows, "fixture build source inventory is absent")
    inventory = {row["path"]: row for row in rows}
    require(len(inventory) == len(rows), "fixture build source inventory repeats a path")
    decoder, text, position, packages = json.JSONDecoder(), package_bytes.decode("utf-8"), 0, []
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        package, position = decoder.raw_decode(text, position)
        require(isinstance(package, dict) and not package.get("Error") and not package.get("Incomplete"),
                "fixture build package selection is incomplete")
        packages.append(package)
    require(packages, "fixture build package selection is absent")
    names = {"go.mod", "go.sum"}
    file_fields = ("GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles", "FFiles", "SFiles",
                   "SwigFiles", "SwigCXXFiles", "SysoFiles", "EmbedFiles")
    for package in packages:
        if package.get("Standard"):
            continue
        directory = Path(package["Dir"])
        require(directory.is_absolute() and directory.is_relative_to(source) and directory.resolve() == directory,
                "fixture build package is outside the staged module")
        for field in file_fields:
            for name in package.get(field, []):
                require(isinstance(name, str) and name and not Path(name).is_absolute() and
                        ".." not in Path(name).parts, "fixture build file selector is invalid")
                names.add(str((directory / name).relative_to(source)))
    entry = entry or "cmd/laneboss/serve-fixture/main.go"
    require(entry in names, "fixture build selection lost its main package")
    vendor = (output / "vendor-manifest.input").read_bytes()
    require(vendor and (source / "vendor/modules.txt").read_bytes() == vendor,
            "fixture build vendor manifest differs from retained input")
    selected = []
    with tarfile.open(output / "dependencies.tar", "r") as dependencies:
        member = dependencies.getmember("vendor/modules.txt")
        require(member.isfile() and dependencies.extractfile(member).read() == vendor,
                "fixture build vendor archive differs from retained manifest")
        for name in sorted(names):
            path = source / name
            require(path.is_file() and not path.is_symlink() and path.resolve() == path,
                    "fixture build input is absent or linked")
            data = path.read_bytes()
            row = {"path": name, "sha256": sha(data), "bytes": len(data)}
            if name.startswith("vendor/"):
                member = dependencies.getmember(name)
                require(member.isfile() and dependencies.extractfile(member).read() == data,
                        "fixture build dependency differs from retained archive")
            else:
                require(inventory.get(name) == row, "fixture build source differs from retained inventory")
            selected.append(row)
    (output / "fixture-source-files.json").write_bytes(encoded(selected))
    (output / "fixture-build-inputs.json").write_bytes(encoded({
        "schema": "laneboss.fixture-build-inputs.v1", "source_archive": "source.tar",
        "source_manifest_sha256": sha(source_manifest), "dependencies_archive": "dependencies.tar",
        "dependencies_sha256": digest(output / "dependencies.tar"),
        "vendor_manifest_sha256": sha(vendor), "package_selection_sha256": sha(package_bytes),
        "scope": "actual module and vendor files selected by go list; standard library belongs to recorded toolchain"}))


def authenticator_source(output):
    checkout = Path(__file__).resolve().parents[2]
    root = Path(tempfile.mkdtemp(prefix="lb-v2-serve-auth-src-", dir="/opt"))
    protected(root)
    paths = []
    for name in ("cmd/laneboss/serve-authenticator", "internal/v2/api"):
        for path in sorted((checkout / name).glob("*.go")):
            if not path.name.endswith("_test.go"):
                paths.append((path, path.relative_to(checkout)))
    paths.append((Path(__file__).with_name("authenticator.mod"), Path("go.mod")))
    require(any(path.name == "main.go" for path, _ in paths), "authenticator source absent")
    inventory = []
    with tarfile.open(output / "authenticator-source.tar", "w") as archive:
        for path, relative in paths:
            require(not path.is_symlink(), "linked authenticator source")
            data = path.read_bytes()
            target = root / relative
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o644)
            protected(target)
            require(digest(target) == sha(data), "authenticator source read-back differs")
            inventory.append({"path": str(relative), "sha256": sha(data), "bytes": len(data)})
            archive.add(target, arcname=str(relative), recursive=False)
    (output / "authenticator-source-files.json").write_bytes(encoded(inventory))
    return root


def authenticator_private():
    # The private key and counter never enter a source/runtime/evidence archive.
    root = Path(tempfile.mkdtemp(prefix="lb-v2-serve-auth-private-", dir="/opt"))
    protected(root)
    require(stat.S_IMODE(root.stat().st_mode) == 0o700, "authenticator directory not private")
    return root


def real_claudock(output, command):
    """Install exact public vendor versions on the box, without authentication."""
    require(os.geteuid() == 0 and os.uname().sysname == "Linux", "real vendor setup requires Linux root")
    root = evidence_root("lb-v2-realrun-", "/opt")
    home = root / "home"
    home.mkdir(mode=0o700)
    # The same toolchain the laneboss build uses (box real112: /usr/local/go/bin held no go, so the build never started).
    go = shutil.which("go")
    require(go is not None, "real vendor setup requires the recorded Go toolchain on PATH")
    environment = {"HOME": str(home), "PATH": os.path.dirname(os.path.realpath(go)) + ":/usr/bin:/bin",
                   "LANG": "C", "GOCACHE": str(root / "cache"), "CGO_ENABLED": "0"}
    source = root / "claudock-src"
    command("real-clone", ["git", "clone", "--depth=1", "--branch=v0.1.0",
            "https://github.com/laneboss-io/claudock-cli.git", str(source)],
            seconds=300, environment=environment)
    revision = command("real-revision", ["git", "rev-parse", "HEAD"], cwd=source, environment=environment)
    wrapper = root / "claudock"
    command("real-build", ["go", "build", "-trimpath", "-o", str(wrapper), "./cmd/claudock"],
            seconds=600, cwd=source, environment=environment)
    version = command("real-version", [str(wrapper), "version"], environment=environment)
    require(re.search(rb"\b0\.1\.0\b", version) is not None, "Claudock version differs from 0.1.0")
    script = root / "claude-install.sh"
    command("claude-installer", ["curl", "--fail", "--silent", "--show-error", "--location",
            "--output", str(script), "https://claude.ai/install.sh"],
            seconds=120, environment=environment)
    protected(script)
    command("claude-install", ["bash", str(script), "2.1.296"], seconds=600, environment=environment)
    vendor = (home / ".local/bin/claude").resolve(strict=True)
    require(vendor.is_relative_to(home), "Claude installer escaped the isolated home")
    version = command("claude-version", [str(vendor), "--version"], environment=environment)
    require(re.match(rb"^2\.1\.296(?:\s|$)", version) is not None, "Claude version differs from 2.1.296")
    result = {}
    for name, path, pin in (("claudock", wrapper, "0.1.0"), ("claude", vendor, "2.1.296")):
        protected(path)
        # 512 MiB leaves headroom for the current roughly 256 MB native CLI;
        # this file allowance never changes the 64 MiB store-object limit.
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= _admin_boot.MAX_VENDOR,
                name + " exceeds the vendor executable file bound")
        path.chmod(0o555)
        size, content = _admin_boot.stream_file(path, _admin_boot.MAX_VENDOR, mode=0o555)
        retained = output / (name + ".input")
        with retained.open("xb") as stream:
            copied = _admin_boot.stream_file(path, _admin_boot.MAX_VENDOR, mode=0o555, target=stream)
        require(copied == (size, content) and digest(retained) == content, "retained vendor pin differs")
        result[name] = {"path": str(path), "bytes": size,
                        "executable": {"id": name, "version": pin, "sha256": content}}
    (output / "real-runtime.input.json").write_bytes(encoded({
        "schema": "laneboss.real-runtime.v1", "vendor_stood_in": False,
        "source_tag": "v0.1.0", "source_revision": revision.decode("ascii").strip(),
        "installer_sha256": digest(script), "binaries": result, "credential_enrolled": False}))
    return result


def boot(binary, version, architecture, output, agent, config, challenge, mode="state", supplied=None,
         source=None, tool=None, command=None, egress_anthropic=False, real_vendor=None,
         item_inputs=None, canary_api_key=False, real_api_key=False):
    require(real_vendor is None or (mode == "lifecycle" and supplied is None),
            "real Claudock requires generated lifecycle inputs")
    require(not real_api_key or canary_api_key,
            "real API key requires the measured key source")
    if supplied is not None:
        return supplied_boot(supplied, binary, version, architecture, output, agent, config, mode, egress_anthropic)
    inputs = Path(tempfile.mkdtemp(prefix="lb-v2-serve-boot-", dir="/opt"))
    protected(inputs)
    objects_root = inputs / "objects"
    objects_root.mkdir(mode=0o755)
    shutil.copyfile(binary, objects_root / "laneboss")
    (objects_root / "laneboss").chmod(0o555)
    require(digest(objects_root / "laneboss") == digest(binary), "runtime binary pin differs")
    agent_path = objects_root / "serve-agent"
    shutil.copyfile(agent["path"], agent_path)
    agent_path.chmod(0o555)
    require(digest(agent_path) == agent["sha256"], "fixture runtime pin differs")
    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reservation.bind(("127.0.0.1", 0))
    endpoint = "http://127.0.0.1:" + str(reservation.getsockname()[1])
    # Explicit inert fixture enrollment: no Clef compatibility or model result
    # is asserted. The bound, non-listening endpoint cannot serve a model call.
    tokenizer = encoded({"fixture": "byte-alphabet", "tokens": list(range(256))})
    deployment = encoded({"fixture": "unavailable-judge", "nonce": uuid.uuid4().hex,
                          "context_tokens": 256, "endpoint": endpoint})
    (objects_root / "tokenizer.json").write_bytes(tokenizer)
    (objects_root / "deployment.json").write_bytes(deployment)
    task = encoded({"schema": "laneboss.serve-task.v1", "config": config,
                    "challenge": challenge, "purpose": "installed L5 lifecycle" if mode == "lifecycle" else "SERVE-STATE via installed CLI",
                    "output": "/home/lane/serve-state", "vendor_stood_in": True})
    (objects_root / "serve-task.json").write_bytes(task)
    descriptor = {"schema": "laneboss.serve-agent.v1", "program": agent["program"],
                  "version": agent["version"], "vendor_stood_in": True,
                  "driver": "codex", "drivers": ["claudock-cli", "codex"], "mode": mode,
                  "config": config, "challenge": challenge,
                  "executable": {"id": "serve-agent", "sha256": agent["sha256"],
                                 "version": agent["version"]},
                  "client": {"id": "laneboss", "sha256": digest(binary),
                             "version": version["version"]},
                  "client_path": "/run/laneboss/client",
                  "binding_path": "/run/laneboss/binding.json",
                  "task_object": "serve-task_json", "output": "/home/lane/serve-state"}
    require(not canary_api_key or (real_vendor is not None and egress_anthropic),
            "fake API key requires real vendor pins and the enrolled API endpoint")
    if canary_api_key:
        descriptor["canary_api_key"] = True
    (objects_root / "serve-agent.json").write_bytes(encoded(descriptor))
    objects = []
    for name, role, mode in (("laneboss", "bootstrap", 0o555),
                              ("tokenizer.json", "fixture", 0o444),
                              ("deployment.json", "fixture", 0o444),
                              ("serve-agent", "serve-fixture-agent", 0o555),
                              ("serve-agent.json", "serve-fixture-config", 0o444),
                              ("serve-task.json", "serve-fixture-task", 0o444)):
        path = objects_root / name
        path.chmod(mode)
        identifier = name.replace(".", "_")
        objects.append({"id": identifier, "role": role, "root_id": "serve_assets",
                        "relative_path": name, "mode": mode, "content": {
                            "id": identifier, "class": "artifact",
                            "sha256": digest(path), "bytes": path.stat().st_size}})
    if real_vendor is not None:
        for name in ("claudock", "claude"):
            entry = real_vendor[name]
            path = objects_root / name
            shutil.copyfile(entry["path"], path)
            path.chmod(0o555)
            require(digest(path) == entry["executable"]["sha256"], "real runtime pin differs")
            objects.append({"id": name, "role": name, "root_id": "serve_assets",
                            "relative_path": name, "mode": 0o555, "content": {
                                "id": name, "class": "artifact", "sha256": digest(path),
                                "bytes": path.stat().st_size}})
        objects.extend(_runtime_deps.enroll(objects_root, "serve_assets",
                       {name: objects_root / name for name in ("claudock", "claude")}, measured=True))
    for asset in (item_inputs or {}).get("assets", []):
        require(asset.get("id") not in {row["id"] for row in objects}, "case runtime object repeats")
        objects.append(runtime_asset(objects_root, asset))
    executable = {"id": "laneboss", "sha256": digest(binary), "version": version["version"]}
    runtime = encoded({"schema": "laneboss.runtime.v2", "generation": 1,
                       "artifact": executable, "bootstrap": executable,
                       "objects": objects, "bindings": []})
    runtime_file = inputs / "runtime.json"
    runtime_file.write_bytes(runtime)
    reference = {"id": "serve_runtime", "class": "manifest",
                 "sha256": sha(runtime), "bytes": len(runtime)}
    key_file = inputs / "native.key"
    with key_file.open("xb") as stream:
        stream.write(os.urandom(32))
    key_file.chmod(0o600)
    protected(key_file)
    require(key_file.stat().st_size == 32, "native key input is incomplete")
    boot_input = {"schema": "laneboss.boot-input.v2", "runtime_manifest": reference,
                  "runtime_file": str(runtime_file), "secret_key_file": str(key_file),
                  "runtime_roots": [{"id": "serve_assets", "path": str(objects_root)}],
                  "judge_endpoint": endpoint, "judge": {
                      "provider": "clef-sglang", "model": "Cloudflare/clef-flash",
                      "deployment_sha256": sha(deployment), "tokenizer_sha256": sha(tokenizer),
                      "context_tokens": 256, "max_bytes": 256, "max_questions": 1,
                      "command_deadline_ms": 1000, "guidance_deadline_ms": 1000,
                      "cache_ttl_ms": 0, "outage_policy": "critical-only"}}
    boot_input["fixture_accounts"] = fixture_accounts(config)
    # Case-owned judge capabilities are installed before the initial policy
    # and runtime closure are hashed. Normal administrator validation remains
    # authoritative for every endpoint, executable/price pin and budget.
    enrollment = (item_inputs or {}).get("enrollment", {})
    require(isinstance(enrollment, dict) and set(enrollment) <= {
        "judge", "judge_endpoint", "judge_worker", "policy_max_cost_micros"},
        "case enrollment contains an unsupported protected field")
    boot_input.update(enrollment)
    # This isolated case supplies its own explicit RP policy as retained boot
    # data. The production installer has no test-domain or origin default.
    relying_party = config + ".example.invalid"
    boot_input["admin_enrollment"] = {"origin": "https://" + relying_party, "rp_id": relying_party}
    fixture_initial(inputs, objects_root, boot_input, output, agent, source, tool, command,
                    egress_anthropic=egress_anthropic, real_vendor=real_vendor,
                    item_inputs=item_inputs, real_api_key=real_api_key)
    manifest = release(binary, version, architecture, output)
    for name, value in (("boot.json", boot_input), ("release.json", manifest)):
        (inputs / name).write_bytes(encoded(value))
    for path in (inputs / "boot.json", inputs / "release.json", runtime_file):
        path.chmod(0o600)
        protected(path)
        (output / (path.name + ".input")).write_bytes(path.read_bytes())
    (output / "tokenizer.input").write_bytes(tokenizer)
    (output / "deployment.input").write_bytes(deployment)
    (output / "fixture-enrollment.input.json").write_bytes(encoded(descriptor))
    (output / "fixture-task.input.json").write_bytes(task)
    # Key bytes stay only in the private admin provisioning inputs and installed
    # private key store. They are excluded from source, archives and reports.
    return inputs / "boot.json", inputs / "release.json", reservation

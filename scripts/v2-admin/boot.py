"""Protected Linux boot provisioning. Execute only as the authorized admin."""

import argparse
import errno
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import pwd
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit


REVISION = "v2.0-draft.4"
PROTOCOL = "laneboss.rpc.v2"
MAX_OBJECT = 67108864
# Native vendor executables are about 256 MB today; allow bounded headroom
# only for installation files, never for store objects or wire payloads.
MAX_VENDOR = 512 << 20
CONFIG = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
SOCKET_RUNTIME_ROOT = Path("/run/lb-v2")
EGRESS_TOOLS = (("/usr/sbin/nft", "nftables"), ("/usr/sbin/ip", "iproute2"))


class Stopped(Exception):
    """No automatic overwrite, authority downgrade or readiness substitute."""


def require(value, reason):
    if not value:
        raise Stopped(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def socket_root(config):
    """Use a bounded socket directory while retaining the full config elsewhere."""
    require(isinstance(config, str) and CONFIG.fullmatch(config), "invalid socket configuration name")
    return SOCKET_RUNTIME_ROOT / sha(config.encode("utf-8"))[:32]


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def members(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def document(data):
    value = json.loads(data.decode("utf-8"), object_pairs_hook=members)
    require(isinstance(value, dict), "an exact JSON object is required")
    # Python preserves unpaired escapes; they cannot enter retained metadata.
    encoded(value).decode("utf-8").encode("utf-8")
    def scalars(item):
        if isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, dict):
            for key, val in item.items():
                scalars(key)
                scalars(val)
        elif isinstance(item, list):
            for val in item:
                scalars(val)
        elif type(item) is int:
            require(0 <= item < 1 << 53, "installation integer exceeds the exact unsigned JSON range")
        else:
            require(type(item) is bool, "null, floating or unknown installation scalar")
    scalars(value)
    return value


def fields(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= set(value) <= set(required) | set(optional),
            "JSON field map differs from the installation contract")


def identifier(value):
    require(isinstance(value, str) and IDENTIFIER.fullmatch(value), "invalid enrolled identifier")
    return value


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), "canonical absolute path required")
    return path


def parents(path, owner=0):
    path = canonical(path)
    while True:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, owner) and not info.st_mode & 0o022,
                "protected parent is linked, untrusted or shared writable")
        if path == Path("/"):
            return
        path = path.parent


def read(path, limit=MAX_OBJECT, owner=0, mode=None, allow_empty=False):
    path = canonical(path)
    parents(path.parent, owner)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1 and
            not before.st_mode & 0o7022 and 0 <= before.st_size <= limit and
            (before.st_size > 0 or allow_empty),
            "unsafe protected input ownership, links, mode or size")
    if mode is not None:
        require(stat.S_IMODE(before.st_mode) == mode, "installed file mode differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "input changed while opening")
        data = stream.read(limit + 1)
        require(len(data) == before.st_size and len(data) <= limit, "input changed size while reading")
        require(os.fstat(stream.fileno()).st_mtime_ns == before.st_mtime_ns, "input changed while reading")
        return data


def stream_file(path, limit=MAX_OBJECT, owner=0, mode=None, allow_empty=False, target=None):
    """Measure/copy a protected inode with a fixed-size buffer and stable metadata."""
    path = canonical(path)
    parents(path.parent, owner)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1 and
            not before.st_mode & 0o7022 and 0 <= before.st_size <= limit and
            (before.st_size > 0 or allow_empty), "unsafe protected input ownership, links, mode or size")
    require(mode is None or stat.S_IMODE(before.st_mode) == mode, "installed file mode differs")
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    digest, size = hashlib.sha256(), 0
    with os.fdopen(descriptor, "rb") as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before), "input changed while opening")
        while True:
            chunk = stream.read(min(1 << 20, limit + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= limit, "input exceeded its streaming bound")
            digest.update(chunk)
            if target is not None:
                require(target.write(chunk) == len(chunk), "short installed file write")
        require(size == before.st_size and identity(os.fstat(stream.fileno())) == identity(before),
                "input changed while streaming")
    require(identity(path.lstat()) == identity(before), "input path changed while streaming")
    return size, digest.hexdigest()


def vendor_file(item, source):
    """Vendor descriptors select protected basename files, outside the store."""
    ref = item["content"]
    fields(ref, ("id", "sha256", "bytes", "class"))
    identifier(ref["id"])
    require(item["role"] in ("claudock", "claude") and item["id"] == item["role"] and
            item["relative_path"] == item["role"] and item["mode"] == 0o555 and
            ref["class"] == "artifact" and type(ref["bytes"]) is int and 0 < ref["bytes"] <= MAX_VENDOR and
            DIGEST.fullmatch(ref["sha256"]), "invalid vendor executable pin")
    unprivileged_file(source)
    require(stream_file(source, MAX_VENDOR, mode=0o555) == (ref["bytes"], ref["sha256"]),
            "vendor executable bytes differ from their pin")
    return source


def publish_vendor(path, source, ref):
    path = canonical(path)
    parents(path.parent)
    expected = (ref["bytes"], ref["sha256"])
    if path.exists() or path.is_symlink():
        require(stream_file(path, MAX_VENDOR, mode=0o555) == expected and path.stat().st_gid == 0,
                "existing installed vendor differs; no overwrite is permitted")
        return
    temporary = path.with_name(path.name + ".pending-" + os.urandom(12).hex())
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        require(stream_file(source, MAX_VENDOR, mode=0o555, target=stream) == expected,
                "vendor executable changed during installation")
        stream.flush()
        os.fchown(stream.fileno(), 0, 0)
        os.fchmod(stream.fileno(), 0o555)
        os.fsync(stream.fileno())
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(stream_file(path, MAX_VENDOR, mode=0o555) == expected, "installed vendor read-back differs")


def unprivileged_file(path):
    try:
        os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError as failure:
        require(failure.errno in (errno.ENODATA, errno.ENOTSUP), "cannot verify file capabilities")
        return
    raise Stopped("file-capability executable refused")


def egress_tools():
    found = {}
    for spelling, package in EGRESS_TOOLS:
        name = Path(spelling).name
        try:
            path = Path(spelling).resolve(strict=True)
            info = path.lstat()
        except FileNotFoundError:
            raise Stopped(f"controlled egress prerequisite missing: {name}; install package {package}") from None
        parents(path.parent)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                not info.st_mode & 0o7022 and info.st_mode & 0o111,
                f"unsafe controlled egress prerequisite: {name}")
        unprivileged_file(path)
        found[name] = path
    return found


def directory(path, uid=0, gid=0, mode=0o755):
    path = canonical(path)
    if not path.parent.exists():
        directory(path.parent)
    parents(path.parent, uid)
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        path.chmod(mode)
        info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
            (uid, gid, mode), "existing directory differs; preserve its owner and mode")


def publish(path, data, mode=0o644, uid=0, gid=0):
    path = canonical(path)
    parents(path.parent, uid)
    if path.exists() or path.is_symlink():
        require(read(path, max(len(data), 1), uid, mode, allow_empty=not data) == data and path.stat().st_gid == gid,
                "existing installed file differs; no overwrite is permitted")
        return False
    temporary = path.with_name(path.name + ".pending-" + os.urandom(12).hex())
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchown(stream.fileno(), uid, gid)
        os.fchmod(stream.fileno(), mode)
        require(stream.write(data) == len(data), "short installed file write")
        stream.flush()
        os.fsync(stream.fileno())
    # A hard-link publishes without replacing any concurrent or differing file.
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(read(path, max(len(data), 1), uid, mode, allow_empty=not data) == data, "installed file read-back differs")
    return True


def command(argv, evidence, label):
    done = subprocess.run(argv, env=ENVIRONMENT, cwd="/", stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    for suffix, data in (("argv.json", encoded(argv)), ("stdout", done.stdout), ("stderr", done.stderr),
                         ("exit.json", encoded({"exit_code": done.returncode}))):
        descriptor = os.open(evidence / (label + "." + suffix), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            require(stream.write(data) == len(data), "short administrator command evidence write")
            stream.flush()
            os.fsync(stream.fileno())
    require(done.returncode == 0, "required administrator command failed; installation remains stopped")
    return done.stdout


def blob(ref, data):
    fields(ref, ("id", "sha256", "bytes", "class"))
    identifier(ref["id"])
    require(ref["class"] in ("manifest", "artifact") and type(ref["bytes"]) is int and
            0 < ref["bytes"] <= MAX_OBJECT and DIGEST.fullmatch(ref["sha256"]) and
            ref["bytes"] == len(data) and ref["sha256"] == sha(data), "retained object bytes differ from their pin")


def source_cache_inputs(enrollment_bytes, initial):
    """Resolve only immutable tree objects from the protected initial bundle."""
    if enrollment_bytes is None or initial is None:
        return []
    enrollment = document(enrollment_bytes)
    objects = initial[2]
    caches, seen, total = [], set(), 0

    def relative(name):
        require(isinstance(name, str) and 0 < len(name) <= 4096 and "\\" not in name and "\x00" not in name and
                not name.startswith("/") and str(PurePosixPath(name)) == name and
                all(part not in ("", "..") and part.lower() != ".git" for part in name.split("/")) and
                len(name.split("/")) <= 64, "source tree path escapes its protected root")
        return name

    def content(ref):
        require(isinstance(ref, dict) and objects.get(ref.get("id"), (None,))[0] == ref,
                "source content is absent from the protected initial inventory")
        data = objects[ref["id"]][1]
        require(ref["bytes"] == len(data) and ref["sha256"] == sha(data), "source content pin differs")
        return data

    references = []
    for project in enrollment["projects"]:
        if project["history_scope"] != "tree":
            continue
        ref = project["object"]
        require(project["base"] == ref["sha256"], "immutable source base differs from its manifest")
        references.append(ref)
    # Extra copy grants are explicit authority in the protected root-grants
    # document. Never populate the cache from unrelated inventory manifests.
    if "profiles" in initial[1]:
        root_ref = initial[1]["profiles"]
        root_raw = content(root_ref)
        blob(root_ref, root_raw)
        grants = document(root_raw)
        fields(grants, ("schema", "resources", "data", "secrets", "profiles", "network", "channels"))
        require(grants["schema"] == "laneboss.root-grants.v2" and isinstance(grants["data"], list),
                "invalid protected root-grants source inventory")
        for grant in grants["data"]:
            if grant["delivery"] != "copy" or grant["history_scope"] not in ("tree", "snapshot"):
                continue
            ref = objects.get(grant["source_object_id"], (None,))[0]
            require(ref is not None and ref["class"] == "manifest" and ref["sha256"] == grant["source_sha256"],
                    "copy source differs from the protected root grant")
            references.append(ref)
    for ref in references:
        raw = content(ref)
        blob(ref, raw)
        require(len(raw) <= 1048576, "source manifest exceeds the helper frame bound")
        if ref["sha256"] in seen:
            continue
        seen.add(ref["sha256"])
        manifest = document(raw)
        fields(manifest, ("schema", "entries"))
        require(manifest["schema"] == "laneboss.objects.v2" and isinstance(manifest["entries"], list) and
                len(manifest["entries"]) <= 65536, "invalid source tree manifest")
        entries, payloads = {}, {}
        for entry in manifest["entries"]:
            fields(entry, ("path", "kind", "mode"), ("content", "assembly", "link_target"))
            name, kind, mode = relative(entry["path"]), entry["kind"], entry["mode"]
            require(name not in entries and type(mode) is int and 0 <= mode <= 0o777,
                    "source tree path repeats or has unsupported permissions")
            entries[name] = entry
            if kind == "directory":
                require(mode & 0o500 == 0o500 and not mode & 0o022 and
                        not any(key in entry for key in ("content", "assembly", "link_target")) and
                        (name != "." or mode == 0o700), "invalid source directory")
            elif kind == "file":
                require(name != "." and mode & 0o400 and not mode & 0o022 and "link_target" not in entry and
                        (("content" in entry) != ("assembly" in entry)), "invalid source file")
                if "content" in entry:
                    data = content(entry["content"])
                else:
                    assembly = entry["assembly"]
                    fields(assembly, ("parts", "bytes", "sha256"))
                    require(isinstance(assembly["parts"], list) and 0 < len(assembly["parts"]) <= 65536 and
                            type(assembly["bytes"]) is int and 0 <= assembly["bytes"] <= MAX_OBJECT,
                            "source assembly exceeds its bound")
                    parts = [content(part) for part in assembly["parts"]]
                    require(sum(map(len, parts)) == assembly["bytes"], "source assembly length differs")
                    data = b"".join(parts)
                    require(sha(data) == assembly["sha256"], "source assembly digest differs")
                total += len(data)
                require(total <= MAX_OBJECT, "installed source trees exceed their aggregate byte bound")
                payloads[name] = data
            elif kind == "symlink":
                target = entry.get("link_target")
                require(name != "." and mode == 0o777 and isinstance(target, str) and target and
                        not target.startswith("/") and "\\" not in target and "\x00" not in target and
                        "content" not in entry and "assembly" not in entry, "invalid source symlink")
                relative(posixpath.normpath(posixpath.join(posixpath.dirname(name), target)))
            else:
                raise Stopped("unsupported source inode kind")
        for name in list(entries):
            for parent in PurePosixPath(name).parents:
                selected = str(parent)
                require(selected not in entries or entries[selected]["kind"] == "directory",
                        "source tree traverses a file or symlink")
                entries.setdefault(selected, {"path": selected, "kind": "directory", "mode": 0o700})
        entries.setdefault(".", {"path": ".", "kind": "directory", "mode": 0o700})
        require(len(entries) <= 65536, "source tree implicit directories exceed their bound")
        caches.append((ref["sha256"], raw, entries, payloads))
    return caches


def verify_source_cache(cache, raw, entries, payloads):
    directory(cache, mode=0o700)
    require({item.name for item in cache.iterdir()} == {"manifest.json", "tree"}, "source cache contains unexpected entries")
    require(read(cache / "manifest.json", len(raw), mode=0o444) == raw, "source cache manifest differs")
    tree = cache / "tree"
    device = tree.lstat().st_dev
    for name, entry in entries.items():
        target = tree / name
        parents(target.parent)
        info = target.lstat()
        require(info.st_uid == 0 and info.st_gid == 0 and info.st_dev == device and
                stat.S_IMODE(info.st_mode) == entry["mode"], "source cache inode ownership or mode differs")
        if entry["kind"] == "directory":
            require(stat.S_ISDIR(info.st_mode), "source cache directory changed kind")
        elif entry["kind"] == "symlink":
            require(stat.S_ISLNK(info.st_mode) and info.st_nlink == 1 and os.readlink(target) == entry["link_target"],
                    "source cache symlink differs")
        else:
            data = payloads[name]
            require(read(target, max(1, len(data)), mode=entry["mode"], allow_empty=not data) == data,
                    "source cache content differs; preserve the existing bytes")
    observed = {"."}
    for parent, directories, files in os.walk(tree, followlinks=False):
        for name in directories + files:
            observed.add(str((Path(parent) / name).relative_to(tree)))
            require(len(observed) <= 65536, "source cache inventory exceeds its bound")
    require(observed == set(entries), "source cache contains ungranted paths")


def install_source_caches(helper_state, caches):
    """Publish before starting the helper; every source is remeasured on use."""
    if not caches:
        return False
    changed = False
    sources = helper_state / "sources"
    directory(sources, mode=0o700)
    for digest, raw, entries, payloads in caches:
        cache = sources / digest
        if cache.exists() or cache.is_symlink():
            verify_source_cache(cache, raw, entries, payloads)
            continue
        directory(cache, mode=0o700)
        publish(cache / "manifest.json", raw, 0o444)
        tree = cache / "tree"
        directory(tree, mode=0o700)
        directories = sorted((name for name, entry in entries.items() if entry["kind"] == "directory"),
                             key=lambda name: (len(PurePosixPath(name).parts), name))
        for name in directories:
            directory(tree / name, mode=0o700)
        for name, data in payloads.items():
            publish(tree / name, data, entries[name]["mode"])
        for name, entry in entries.items():
            if entry["kind"] == "symlink":
                target = tree / name
                require(not target.exists() and not target.is_symlink(), "source symlink destination already exists")
                os.symlink(entry["link_target"], target)
        for name in reversed(directories):
            selected = tree / name
            selected.chmod(entries[name]["mode"])
            descriptor = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        verify_source_cache(cache, raw, entries, payloads)
        for selected in (cache, sources, helper_state):
            descriptor = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        changed = True
    return changed


def launch_enrollment(value, config, runtime_ref, runtime):
    fields(value, ("schema", "config", "generation", "projects", "runtimes"), ("supervisor", "network"))
    require(value["schema"] == "laneboss.launch-enrollment.v2" and value["config"] == config and
            type(value["generation"]) is int and 0 < value["generation"] < 1 << 53 and
            isinstance(value["projects"], list) and value["projects"] and
            isinstance(value["runtimes"], list) and value["runtimes"], "invalid launch enrollment")
    network = value.get("network", [])
    require(isinstance(network, list) and len(network) <= 1,
            "only the enrolled Anthropic API endpoint is supported")
    for endpoint in network:
        fields(endpoint, ("id", "host", "protocol", "port"), ("host_addresses",))
        addresses = endpoint.get("host_addresses", [])
        require(endpoint["id"] == "anthropic-api" and endpoint["host"] == "api.anthropic.com" and
                endpoint["protocol"] == "tcp" and type(endpoint["port"]) is int and endpoint["port"] == 443 and
                isinstance(addresses, list) and len(addresses) <= 256,
                "network enrollment must name the exact Anthropic API endpoint")
        for address in addresses:
            require(isinstance(address, str) and "%" not in address, "invalid host address inventory")
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                raise Stopped("invalid host address inventory") from None
            canonical_address = str(ip)
            # Match netip.Addr.String's dotted form for IPv4-mapped IPv6.
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                canonical_address = "::ffff:" + str(ip.ipv4_mapped)
            require(canonical_address == address, "invalid host address inventory")
    pins = {row["id"]: row for row in runtime["objects"]}
    identifiers, projects, drivers = set(), set(), set()

    def executable(item):
        fields(item, ("id", "sha256", "version"))
        identifier(item["id"])
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", item["id"]), "invalid launch executable identifier")
        require(item["id"] in pins and pins[item["id"]]["mode"] == 0o555 and
                item["sha256"] == pins[item["id"]]["content"]["sha256"] and
                isinstance(item["version"], str) and item["version"], "launch executable has no protected runtime pin")

    for project in value["projects"]:
        fields(project, ("id", "generation", "project_id", "object", "base", "history_scope"))
        identifier(project["id"])
        identifier(project["project_id"])
        require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", project[key]) for key in ("id", "project_id")), "invalid project enrollment identifier")
        fields(project["object"], ("id", "sha256", "bytes", "class"))
        identifier(project["object"]["id"])
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", project["object"]["id"]), "invalid project object identifier")
        require(project["id"] not in identifiers and project["project_id"] not in projects and
                type(project["generation"]) is int and 0 < project["generation"] < 1 << 53 and
                project["object"]["class"] == "manifest" and DIGEST.fullmatch(project["object"]["sha256"]) and
                type(project["object"]["bytes"]) is int and 0 < project["object"]["bytes"] <= MAX_OBJECT and
                re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", project["base"]) and
                project["history_scope"] in ("tree", "reachable"), "invalid or duplicate project enrollment")
        identifiers.add(project["id"])
        projects.add(project["project_id"])
    for selected in value["runtimes"]:
        fields(selected, ("enrollment_id", "generation", "backend", "driver", "executable", "manifest"),
               ("session_executable",))
        identifier(selected["enrollment_id"])
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", selected["enrollment_id"]), "invalid runtime enrollment identifier")
        require(selected["enrollment_id"] not in identifiers and selected["driver"] not in drivers and
                type(selected["generation"]) is int and 0 < selected["generation"] < 1 << 53 and
                selected["driver"] in ("codex", "claudock-cli") and
                selected["backend"] in ("linux-bwrap-landlock", "darwin-seatbelt") and
                selected["manifest"] == runtime_ref, "invalid or duplicate runtime enrollment")
        executable(selected["executable"])
        if "session_executable" in selected:
            session = selected["session_executable"]
            executable(session)
            require(sum(item["id"] == session["id"] and item["mode"] == 0o555 and
                        item["content"]["sha256"] == session["sha256"] for item in runtime["objects"]) == 1,
                    "session executable differs from the pinned runtime")
        if selected["driver"] == "claudock-cli" and selected["executable"]["id"] == "claudock":
            require(selected.get("session_executable", {}).get("id") == "claude",
                    "real Claudock requires its exact Claude session executable enrollment")
        identifiers.add(selected["enrollment_id"])
        drivers.add(selected["driver"])
    if "supervisor" in value:
        executable(value["supervisor"])


def initial_inputs(boot, config):
    names = ("initial_publication", "initial_publication_file", "initial_objects")
    present = [name in boot for name in names]
    require(not any(present) or all(present), "initial publication requires its manifest, protected file and object inventory")
    if not any(present):
        return None
    require("launch_enrollment" in boot and "admin_enrollment" in boot,
            "initial publication requires explicit launch and administrator endpoint enrollment")
    raw = read(boot["initial_publication_file"], 1048576, mode=0o444)
    blob(boot["initial_publication"], raw)
    value = document(raw)
    fields(value, ("schema", "config", "id", "generation", "runtime", "launch_enrollment",
                   "policy", "sources", "source_manifest", "profiles", "task", "l5", "l5_sources", "objects"))
    require(value["schema"] == "laneboss.initial.v2" and value["config"] == config and
            value["generation"] == 1 and value["runtime"] == boot["runtime_manifest"] and
            value["launch_enrollment"] == boot["launch_enrollment"], "initial publication differs from protected boot enrollment")
    identifier(value["id"])
    fields(value["l5"], ("level", "role"), ("instance_id",))
    require(value["l5"]["level"] == 5 and value["l5"]["role"] and
            not value["l5"].get("instance_id"), "initial publication requires the explicit L5 role")
    require(isinstance(value["objects"], list) and 0 < len(value["objects"]) <= 512 and
            isinstance(boot["initial_objects"], list) and len(boot["initial_objects"]) == len(value["objects"]),
            "initial object inventory is missing or unbounded")
    objects, total = {}, 0
    for item in boot["initial_objects"]:
        fields(item, ("ref", "file"))
        ref = item["ref"]
        fields(ref, ("id", "sha256", "bytes", "class"))
        identifier(ref["id"])
        require(ref["id"] not in objects and ref["class"] in ("manifest", "task", "artifact") and
                type(ref["bytes"]) is int and 0 <= ref["bytes"] <= MAX_OBJECT and
                (ref["bytes"] > 0 or ref["class"] == "artifact") and DIGEST.fullmatch(ref["sha256"]),
                "initial object reference differs")
        data = read(item["file"], ref["bytes"], mode=0o444, allow_empty=ref["class"] == "artifact")
        require(len(data) == ref["bytes"] and sha(data) == ref["sha256"], "initial object bytes differ from their declared digest")
        total += len(data)
        require(total <= 64 << 20, "initial publication exceeds its staging bound")
        objects[ref["id"]] = (ref, data)
    require(len({item["id"] for item in value["objects"]}) == len(objects) and
            all(objects.get(item["id"], (None,))[0] == item for item in value["objects"]),
            "initial object files differ from the declared publication")
    for name in ("runtime", "launch_enrollment", "policy", "sources", "source_manifest", "profiles", "task"):
        ref = value[name]
        require(objects.get(ref["id"], (None,))[0] == ref, "initial document is absent from its object inventory")
    runtime = document(objects[value["runtime"]["id"]][1])
    for item in runtime["objects"]:
        if item["role"] in ("claudock", "claude"):
            ref = item["content"]
            require(all(key != ref["id"] and kept[0]["sha256"] != ref["sha256"] for key, kept in objects.items()),
                    "vendor executable must remain an installation file")
    return raw, value, objects


def publish_initial(config, evidence):
    catalog = check(config)
    require("initial_publication" in catalog, "initial publication is not installed")
    installed = document(read(location(config), 1048576, mode=0o644))
    endpoint = installed.get("admin_enrollment")
    require(endpoint is not None, "initial publication requires its protected administrator endpoint")
    output = canonical(evidence)
    parents(output.parent)
    require(not output.exists() and not output.is_symlink(), "preserve existing publication evidence")
    directory(output, mode=0o700)
    binary = catalog["binary"]
    initial = document(read(Path(catalog["runtime_file"]).parent / "initial.json", 1048576, mode=0o444))
    response = document(command([binary, "internal", "helper", "--config", config,
        "--installation", str(location(config)), "--publish-initial", catalog["initial_request_file"]], output, "publication"))
    fields(response, ("schema", "config", "id", "manifest", "receipt", "operation_id", "event_id", "committed_seq", "generation"))
    require(response["schema"] == "laneboss.initial-receipt.v2" and response["config"] == config and
            response["manifest"] == catalog["initial_publication"] and response["generation"] == 1 and
            response["id"] == initial["id"] and response["operation_id"] == "initial-op-" + initial["id"] and
            response["event_id"] == "initial-event-" + initial["id"] and
            type(response["committed_seq"]) is int and 0 < response["committed_seq"] < 1 << 53,
            "initial publication lacks its real durable service receipt")
    for name in ("id", "operation_id", "event_id"):
        identifier(response[name])
    ref = response["receipt"]
    fields(ref, ("id", "sha256", "bytes", "class"))
    require(ref["id"] == "initial-receipt-" + config and ref["class"] == "manifest" and
            DIGEST.fullmatch(ref["sha256"]) and type(ref["bytes"]) is int and 0 < ref["bytes"] <= MAX_OBJECT,
            "initial publication receipt has no exact retained object")
    publish(output / "receipt.json", encoded(response), 0o600)
    return {"verified": True, "published": True, "receipt": response}


def judge(config, endpoint, credential=""):
    fields(config, ("provider", "model", "deployment_sha256", "tokenizer_sha256", "context_tokens",
                    "max_bytes", "max_questions", "command_deadline_ms", "guidance_deadline_ms",
                    "cache_ttl_ms", "outage_policy"))
    require(all(isinstance(config[name], str) for name in
                ("provider", "model", "deployment_sha256", "tokenizer_sha256", "outage_policy")), "invalid judge string field")
    provider = config["provider"] or "clef-sglang"
    require(provider in ("clef-sglang", "typesafe"), "unknown installed judge provider")
    require(all(type(config[name]) is int and config[name] >= 0 for name in
                ("context_tokens", "max_bytes", "max_questions", "command_deadline_ms",
                 "guidance_deadline_ms", "cache_ttl_ms")), "invalid judge bounds")
    require(config["context_tokens"] > 0 and 0 < config["max_bytes"] <= 262144 and config["max_questions"] > 0,
            "missing measured judge bounds")
    if provider == "clef-sglang":
        require(config["model"] in ("", "Cloudflare/clef-flash") and
                DIGEST.fullmatch(config["deployment_sha256"]) and DIGEST.fullmatch(config["tokenizer_sha256"]),
                "Clef enrollment requires measured deployment and tokenizer pins")
        config = dict(config, provider=provider, model="Cloudflare/clef-flash")
    else:
        require(config["model"] and credential, "TypeSafe requires its explicit model and credential handle")
        identifier(credential)
    parsed = urlsplit(endpoint)
    require(parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and
            not parsed.password and not parsed.query and not parsed.fragment, "invalid enrolled judge endpoint")
    return config


def enrollment(config):
    # The administrator supplies this policy in the protected boot input.
    # There is no production origin/RP default and no value from a client.
    fields(config, ("origin", "rp_id"))
    origin, rp = config["origin"], config["rp_id"]
    require(isinstance(origin, str) and isinstance(rp, str) and origin == origin.strip() and
            rp == rp.strip() and origin.startswith("https://") and rp, "invalid enrollment origin/RP policy")
    parsed = urlsplit(origin)
    require(parsed.scheme == "https" and parsed.hostname == rp and not parsed.username and
            not parsed.password and not parsed.path and not parsed.query and not parsed.fragment,
            "enrollment origin must match the configured HTTPS relying party")
    return dict(config)


def judge_worker(value, config, credential=""):
    fields(value, ("tokenizer_path", "tokenizer_executable_sha256", "price_file", "price_sha256",
                   "safety_tokens", "reserve_micros"), ("tokenizer_args", "credential_file"))
    for name in ("tokenizer_path", "price_file"):
        require(isinstance(value[name], str) and "\x00" not in value[name], "judge worker path is not valid text")
        canonical(value[name])
    require(all(isinstance(value[name], str) and DIGEST.fullmatch(value[name])
                for name in ("tokenizer_executable_sha256", "price_sha256")), "judge worker byte pins differ")
    require(type(value["safety_tokens"]) is int and 0 < value["safety_tokens"] < config["context_tokens"]
            and type(value["reserve_micros"]) is int and 0 < value["reserve_micros"] < 1 << 53,
            "judge worker bounds differ")
    arguments = value.get("tokenizer_args", [])
    require(isinstance(arguments, list) and len(arguments) <= 32 and
            all(isinstance(word, str) and len(word) <= 4096 and not any(c in word for c in "\x00\r\n")
                for word in arguments), "judge tokenizer arguments are unbounded")
    require(bool(credential) == bool(value.get("credential_file")), "judge credential handle and protected file disagree")
    if "credential_file" in value:
        require(isinstance(value["credential_file"], str) and "\x00" not in value["credential_file"], "judge credential path is not valid text")
        canonical(value["credential_file"])
    return dict(value)


def inference_enrollment(boot):
    result = {}
    if "policy_max_cost_micros" in boot:
        cap = boot["policy_max_cost_micros"]
        require(type(cap) is int and 0 <= cap < 1 << 53, "approved policy inference ceiling is invalid")
        result["policy_max_cost_micros"] = cap
    if "judge_worker" in boot:
        result["judge_worker"] = judge_worker(boot["judge_worker"], boot["judge"],
                                               boot.get("judge_credential_handle", ""))
    return result


def account(name):
    entry = pwd.getpwnam(name)
    require(entry.pw_uid != 0 and entry.pw_gid != 0 and entry.pw_dir == "/nonexistent" and
            entry.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin"), "installed account properties differ")
    groups = os.getgrouplist(name, entry.pw_gid)
    require(set(groups) == {entry.pw_gid}, "installed account has supplementary groups")
    shadow = read("/etc/shadow", 1048576)
    entries = [line.split(b":") for line in shadow.splitlines() if line.split(b":", 1)[0] == name.encode()]
    require(len(entries) == 1 and entries[0][1].startswith((b"!", b"*")), "installed account is not locked")
    return {"name": name, "uid": entry.pw_uid, "gid": entry.pw_gid}


def fixture_account_input(config, value):
    fields(value, ("run", "group", "users"))
    suffix = sha(config.encode("utf-8"))[:8]
    require(value["run"] == suffix, "fixture account run differs from configuration")
    fields(value["group"], ("name",))
    require(value["group"]["name"] == "lbrpc" + suffix, "fixture RPC group differs from configuration")
    require(isinstance(value["users"], list) and len(value["users"]) == 3,
            "fixture account pool must contain three users")
    prefixes = ("lbsvc", "lbop", "lblane")
    names = []
    for prefix, row in zip(prefixes, value["users"]):
        fields(row, ("name",))
        require(row["name"] == prefix + suffix, "fixture account name differs from configuration")
        names.append(row["name"])
    require(len(set(names)) == len(names), "fixture account names are not distinct")
    return {"run": suffix, "group": {"name": value["group"]["name"]},
            "users": [{"name": name} for name in names]}


def install_fixture_accounts(config, value, evidence):
    selected = fixture_account_input(config, value)
    group_name = selected["group"]["name"]
    names = [row["name"] for row in selected["users"]]
    for name in [group_name, *names]:
        try:
            if name in names:
                pwd.getpwnam(name)
            else:
                grp.getgrnam(name)
        except KeyError:
            continue
        raise Stopped("fixture account already exists without a completed installation")
    users = ("g %s -\n" % group_name).encode()
    users += b"".join(("u %s - \"Laneboss disposable fixture\" /nonexistent /usr/sbin/nologin\n" % name).encode()
                        for name in names)
    publish(evidence / "fixture-accounts.conf", users, 0o600)
    command(["/usr/bin/systemd-sysusers", str(evidence / "fixture-accounts.conf")], evidence, "fixture-accounts")
    group = grp.getgrnam(group_name)
    accounts = [account(name) for name in names]
    require(group.gr_gid != 0 and len({row["uid"] for row in accounts}) == 3 and
            len({row["gid"] for row in accounts}) == 3 and
            group.gr_gid not in {row["gid"] for row in accounts},
            "fixture account UID or GID separation failed")
    return {"run": selected["run"], "group": {"name": group_name, "gid": group.gr_gid},
            "users": accounts}


def fixture_account_catalog(config, value):
    fields(value, ("run", "group", "users"))
    selected = fixture_account_input(config, {"run": value["run"], "group": {"name": value["group"]["name"]},
                                              "users": [{"name": row["name"]} for row in value["users"]]})
    fields(value["group"], ("name", "gid"))
    require(type(value["group"]["gid"]) is int and value["group"]["gid"] != 0 and
            value["group"]["name"] == selected["group"]["name"],
            "fixture RPC group metadata differs")
    accounts = []
    for row in value["users"]:
        fields(row, ("name", "uid", "gid"))
        require(type(row["uid"]) is int and row["uid"] != 0 and type(row["gid"]) is int and row["gid"] != 0,
                "fixture account metadata is invalid")
        accounts.append(row)
    require(len({row["uid"] for row in accounts}) == 3 and len({row["gid"] for row in accounts}) == 3 and
            value["group"]["gid"] not in {row["gid"] for row in accounts},
            "fixture account metadata is not distinct")
    for row in accounts:
        require(account(row["name"]) == row, "fixture account changed after installation")
    require(grp.getgrnam(value["group"]["name"]).gr_gid == value["group"]["gid"],
            "fixture RPC group changed after installation")
    return {"run": value["run"], "group": dict(value["group"]), "users": accounts}


def location(config):
    return Path("/etc/laneboss-v2/service") / (config + ".json")


def catalog_path(config):
    return Path("/etc/laneboss-v2/boot") / (config + ".json")


def check(config):
    catalog = document(read(catalog_path(config), 1048576, mode=0o600))
    require(catalog["schema"] == "laneboss.boot-catalog.v2" and catalog["config"] == config and
            catalog["contract_revision"] == REVISION, "installed catalog revision differs")
    for item in catalog["files"]:
        measured = stream_file(item["path"], item["bytes"], item["uid"], item["mode"], allow_empty=item["bytes"] == 0)
        require(measured == (item["bytes"], item["sha256"]) and Path(item["path"]).stat().st_gid == item["gid"],
                "installed content digest or group differs")
        if item["mode"] & 0o111:
            unprivileged_file(item["path"])
    for item in catalog["directories"]:
        path = canonical(item["path"])
        parents(path.parent, item["uid"])
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                (item["uid"], item["gid"], item["mode"]), "installed private directory differs")
    for installed in catalog["accounts"]:
        require(account(installed["name"]) == installed, "installed account binding changed")
    if "fixture_accounts" in catalog:
        fixture_account_catalog(config, catalog["fixture_accounts"])
    installed = document(read(location(config), 1048576, mode=0o644))
    binding = document(read(installed["binding_file"], 1048576, mode=0o644))
    require(installed["schema"] == "laneboss.service-install.v2" and installed["config"] == config and
            binding["contract_revision"] == REVISION and binding["config"] == config and
            binding["service_uid"] == installed["service_uid"] and binding["socket"] == installed["socket"] and
            binding["artifact_sha256"] == installed["artifact_sha256"], "boot and endpoint binding differ")
    if "initial_publication" in catalog:
        base = Path(catalog["runtime_file"]).parent
        require(catalog["initial_request_file"] == str(base / "initial-ref.json") and
                catalog["binary"] == str(base.parent.parent / "laneboss"), "initial installed locations differ")
        request = document(read(catalog["initial_request_file"], 1048576, mode=0o444))
        fields(request, ("manifest",))
        require(request["manifest"] == catalog["initial_publication"], "installed initial reference differs")
        raw = read(base / "initial.json", 1048576, mode=0o444)
        blob(request["manifest"], raw)
        initial = document(raw)
        require(initial["config"] == config and initial["runtime"] == installed["runtime_manifest"] and
                initial["launch_enrollment"] == installed.get("launch_enrollment") and
                "admin_enrollment" in installed, "initial publication differs from the installed service")
        endpoint = installed["admin_enrollment"]
        require(endpoint["config"] == config and endpoint["service_uid"] == installed["service_uid"] and
                endpoint["installation_generation"] == binding["installation_generation"] and
                endpoint["helper"]["sha256"] == installed["artifact_sha256"] and
                endpoint["socket"] == str(Path(installed["socket"]).parent / "administrator" / "enrollment.sock"),
                "initial administrator endpoint differs")
    return catalog


def provision(args):
    source = Path(__file__).resolve().parents[2]
    # Reading root unit templates and executing subordinate code is permitted
    # only from a protected administrator source bundle.
    read(source / "scripts/v2-admin/boot.py", 1048576)
    helper_template = read(source / "packaging/v2/linux/laneboss-helper.service.in", 65536)
    service_template = read(source / "packaging/v2/linux/laneboss-service.service.in", 65536)
    credential_template = read(source / "packaging/v2/linux/laneboss-credential.service.in", 65536)
    binary = read(args.binary, 256 << 20)
    unprivileged_file(args.binary)
    manifest_bytes = read(args.manifest, 1048576)
    manifest = document(manifest_bytes)
    fields(manifest, ("version", "protocol", "schema", "artifacts", "source_sha256", "vendor_manifest"))
    require(re.fullmatch(r"[0-9][A-Za-z0-9._-]{0,31}", manifest["version"]) and
            manifest["protocol"] == PROTOCOL and manifest["schema"] == 2 and
            DIGEST.fullmatch(manifest["source_sha256"]), "release metadata differs")
    require(isinstance(manifest["artifacts"], list) and 0 < len(manifest["artifacts"]) <= 32, "release artifacts are unbounded")
    artifact_keys = set()
    for entry in manifest["artifacts"]:
        fields(entry, ("os", "arch", "sha256", "bytes"))
        key = (entry["os"], entry["arch"])
        require(key not in artifact_keys and entry["os"] in ("linux", "darwin") and entry["arch"] in ("amd64", "arm64") and
                DIGEST.fullmatch(entry["sha256"]) and type(entry["bytes"]) is int and 0 < entry["bytes"] <= 1 << 30,
                "invalid or repeated release artifact")
        artifact_keys.add(key)
    vendor = manifest["vendor_manifest"]
    fields(vendor, ("id", "sha256", "bytes", "class"))
    identifier(vendor["id"])
    require(DIGEST.fullmatch(vendor["sha256"]) and type(vendor["bytes"]) is int and
            0 < vendor["bytes"] <= MAX_OBJECT and vendor["class"] == "manifest", "invalid vendor manifest pin")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    artifacts = [item for item in manifest["artifacts"] if item["os"] == "linux" and item["arch"] == arch]
    require(arch and len(artifacts) == 1, "release platform is missing or ambiguous")
    artifact = artifacts[0]
    fields(artifact, ("os", "arch", "sha256", "bytes"))
    require(artifact["sha256"] == sha(binary) and artifact["bytes"] == len(binary), "release artifact pin differs")
    boot_bytes = read(args.boot, 1048576)
    boot = document(boot_bytes)
    fields(boot, ("schema", "runtime_manifest", "runtime_file", "runtime_roots", "secret_key_file", "judge", "judge_endpoint"),
           ("judge_credential_handle", "judge_alternative", "launch_enrollment", "launch_enrollment_file",
            "admin_enrollment", "initial_publication", "initial_publication_file", "initial_objects",
            "policy_max_cost_micros", "judge_worker", "fixture_accounts"))
    require(boot["schema"] == "laneboss.boot-input.v2", "invalid boot input schema")
    if "fixture_accounts" in boot:
        fixture_account_input(args.config, boot["fixture_accounts"])
    enrollment_config = enrollment(boot["admin_enrollment"]) if "admin_enrollment" in boot else None
    judge_config = judge(boot["judge"], boot["judge_endpoint"], boot.get("judge_credential_handle", ""))
    inference = inference_enrollment(boot)
    require(judge_config["provider"] == "clef-sglang", "initial enrollment requires the decided Clef default")
    if "judge_alternative" in boot:
        alternative = boot["judge_alternative"]
        fields(alternative, ("config", "endpoint", "credential_handle"), ("worker",))
        require(alternative["config"]["provider"] == "typesafe", "alternative repeats the default provider")
        judge(alternative["config"], alternative["endpoint"], alternative["credential_handle"])
        if "worker" in alternative:
            judge_worker(alternative["worker"], alternative["config"], alternative["credential_handle"])
    native_key = read(boot["secret_key_file"], 32, mode=0o600)
    require(len(native_key) == 32 and len(set(native_key)) > 1, "a real private 256-bit native data key is required")
    key_handle = "key-" + sha(native_key)[:32]
    runtime_bytes = read(boot["runtime_file"], 1048576)
    blob(boot["runtime_manifest"], runtime_bytes)
    runtime = document(runtime_bytes)
    fields(runtime, ("schema", "generation", "artifact", "bootstrap", "objects", "bindings"))
    require(runtime["schema"] == "laneboss.runtime.v2" and type(runtime["generation"]) is int and
            0 < runtime["generation"] < 1 << 53 and isinstance(runtime["bindings"], list), "invalid runtime generation")
    require(runtime["bindings"] == [], "fresh installation cannot import another endpoint's active identity")
    roots = {}
    for root in boot["runtime_roots"]:
        fields(root, ("id", "path"))
        identifier(root["id"])
        require(root["id"] not in roots, "duplicate enrolled runtime root")
        roots[root["id"]] = canonical(root["path"])
        parents(roots[root["id"]])
    objects, pins, identities, retained_bytes = [], {}, set(), 0
    require(isinstance(runtime["objects"], list) and 0 < len(runtime["objects"]) <= 128, "runtime inventory is empty or unbounded")
    for item in runtime["objects"]:
        fields(item, ("id", "role", "root_id", "relative_path", "content", "mode"), ("aliases",))
        aliases = item.get("aliases", [])
        require(isinstance(aliases, list) and len(aliases) <= 8 and
                (not aliases or (item["role"] == "runtime-cert" and item["mode"] == 0o444 and
                                 item["relative_path"].startswith("etc/ssl/"))), "invalid runtime certificate aliases")
        seen_aliases = {"/" + item["relative_path"]}
        for alias in aliases:
            require(isinstance(alias, str) and str(PurePosixPath(alias)) == alias and
                    (alias == "/etc/ssl/cert.pem" or (alias.startswith("/etc/ssl/certs/") and
                     "/" not in alias[len("/etc/ssl/certs/"):])) and "\x00" not in alias and
                    alias not in seen_aliases, "invalid runtime certificate alias path")
            seen_aliases.add(alias)
        identifier(item["id"])
        relative = PurePosixPath(item["relative_path"])
        require(str(relative) == item["relative_path"] and not relative.is_absolute() and relative.parts and
                not any(part in (".", "..") for part in relative.parts) and item["root_id"] in roots and
                item["id"] not in pins and item["mode"] in (0o444, 0o555), "invalid protected runtime object")
        identity = (item["root_id"], str(relative))
        require(identity not in identities, "runtime destination repeats")
        identities.add(identity)
        source = roots[item["root_id"]] / str(relative)
        if item["role"] in ("claudock", "claude"):
            data = vendor_file(item, source)
        else:
            data = read(source, MAX_OBJECT)
            retained_bytes += len(data)
            require(retained_bytes <= 256 << 20, "runtime enrollment exceeds its bounded staging budget")
            blob(item["content"], data)
        pins[item["id"]] = item
        objects.append((item, data))
    for executable in (runtime["artifact"], runtime["bootstrap"]):
        fields(executable, ("id", "sha256", "version"))
        require(executable["id"] in pins and pins[executable["id"]]["mode"] == 0o555 and
                executable["sha256"] == pins[executable["id"]]["content"]["sha256"] and
                isinstance(executable["version"], str) and executable["version"],
                "runtime executable has no retained pin")
    require(runtime["artifact"]["sha256"] == artifact["sha256"] and runtime["artifact"]["version"] == manifest["version"],
            "runtime artifact is not this release")
    require(("launch_enrollment" in boot) == ("launch_enrollment_file" in boot), "launch enrollment requires both reference and protected input file")
    enrollment_bytes = None
    if "launch_enrollment" in boot:
        enrollment_bytes = read(boot["launch_enrollment_file"], 1048576)
        blob(boot["launch_enrollment"], enrollment_bytes)
        require(boot["launch_enrollment"]["class"] == "manifest", "launch enrollment must be a manifest object")
        # Not named "enrollment": that name is the enrollment() function called above, and
        # assigning it here made it local to provision() (UnboundLocalError on fakediag12).
        launch_document = document(enrollment_bytes)
        launch_enrollment(launch_document, args.config, boot["runtime_manifest"], runtime)
        if launch_document.get("network"):
            egress_tools()
    initial = initial_inputs(boot, args.config)
    source_caches = source_cache_inputs(enrollment_bytes, initial)
    fingerprint = sha(encoded({"binary": sha(binary), "release": sha(manifest_bytes), "boot": sha(boot_bytes),
                              "helper_unit": sha(helper_template), "service_unit": sha(service_template),
                              "credential_unit": sha(credential_template),
                              "fixture_accounts": boot.get("fixture_accounts")}))
    if catalog_path(args.config).exists():
        catalog = check(args.config)
        require(catalog["fingerprint"] == fingerprint, "existing installed bundle differs; use an approved coherent upgrade")
        cache_changed = install_source_caches(Path("/var/lib/laneboss-v2/helper") / args.config, source_caches)
        return {"verified": True, "changed": cache_changed, "installation": str(location(args.config)),
                "publication": "pending" if initial is not None else "absent"}

    release_path = Path("/usr/lib/laneboss-v2") / manifest["version"] / "laneboss"
    if release_path.exists() or release_path.is_symlink():
        require(read(release_path, len(binary), mode=0o555) == binary,
                "different artifacts of one compiled version require separate fresh boxes")
    for path in (location(args.config), Path("/etc/laneboss-v2/admin") / (args.config + ".json"),
                 Path("/etc/laneboss-v2/bindings") / (args.config + ".json")):
        require(not path.exists() and not path.is_symlink(), "incomplete previous installation requires administrator recovery")

    evidence = canonical(args.evidence)
    parents(evidence.parent)
    require(not evidence.exists() and not evidence.is_symlink(), "preserve existing install evidence")
    directory(evidence, mode=0o700)
    fixture_catalog = None
    if "fixture_accounts" in boot:
        fixture_catalog = install_fixture_accounts(args.config, boot["fixture_accounts"], evidence)
    publish(evidence / "laneboss.input", binary, 0o555)
    publish(evidence / "release.input.json", manifest_bytes, 0o600)
    publish(evidence / "boot.input.json", boot_bytes, 0o600)
    version = document(command([str(evidence / "laneboss.input"), "--version"], evidence, "version"))
    require(version["program"] == "laneboss" and version["version"] == manifest["version"] and
            version["contract_revision"] == REVISION, "binary release metadata does not match the bundle")
    if initial is not None:
        initial_raw, initial_doc, initial_objects = initial
        initial_stage = evidence / "initial"
        directory(initial_stage, mode=0o700)
        directory(initial_stage / "initial-objects", mode=0o700)
        publish(initial_stage / "initial.json", initial_raw, 0o444)
        publish(initial_stage / "initial-ref.json", encoded({"manifest": boot["initial_publication"]}), 0o444)
        for key, (_, data) in initial_objects.items():
            publish(initial_stage / "initial-objects" / key, data, 0o444)
        validation = document(command([str(evidence / "laneboss.input"), "internal", "helper", "--config", args.config,
            "--validate-initial", str(initial_stage / "initial.json"), "--initial-ref", str(initial_stage / "initial-ref.json")], evidence, "initial-validation"))
        fields(validation, ("valid", "manifest", "id"))
        require(validation["valid"] is True and validation["manifest"] == boot["initial_publication"] and
                validation["id"] == initial_doc["id"], "initial documents failed the actual product validators")
    name_prefix = "lb-" + sha(args.config.encode())[:8]
    names = [name_prefix + "-svc", name_prefix + "-cred"] + [name_prefix + "-l%03d" % number for number in range(32)]
    for name in names:
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        raise Stopped("proposed account already exists without a completed installation")
    users = "".join('u %s - "Laneboss isolated account" /nonexistent /usr/sbin/nologin\n' % name for name in names).encode()
    publish(evidence / "accounts.conf", users, 0o600)
    command(["/usr/bin/systemd-sysusers", str(evidence / "accounts.conf")], evidence, "accounts")
    accounts = [account(name) for name in names]
    require(len({row["uid"] for row in accounts}) == len(accounts) and
            len({row["gid"] for row in accounts}) == len(accounts), "account UID or GID separation failed")
    service, broker, lanes = accounts[0], accounts[1], accounts[2:]
    publish(evidence / "service.json", encoded(service), 0o600)
    uid, gid = service["uid"], service["gid"]
    state = Path("/var/lib/laneboss-v2/service") / args.config
    secrets = Path("/var/lib/laneboss-v2/secrets") / args.config
    socket_directory = socket_root(args.config)
    helper_state = Path("/var/lib/laneboss-v2/helper") / args.config
    helper_runtime = Path("/run/laneboss-v2") / args.config
    release_root = Path("/usr/lib/laneboss-v2") / manifest["version"]
    runtime_root = release_root / "runtime" / args.config
    files, directories = [], []

    def make_dir(path, owner=0, group=0, mode=0o755):
        directory(path, owner, group, mode)
        directories.append({"path": str(path), "uid": owner, "gid": group, "mode": mode})

    def put(path, data, mode=0o644, owner=0, group=0):
        publish(path, data, mode, owner, group)
        files.append({"path": str(path), "uid": owner, "gid": group, "mode": mode,
                      "bytes": len(data), "sha256": sha(data)})

    make_dir(SOCKET_RUNTIME_ROOT)
    for path in (state, secrets, socket_directory):
        make_dir(path, uid, gid, 0o700)
    make_dir(helper_state, mode=0o700)
    install_source_caches(helper_state, source_caches)
    make_dir(helper_runtime, group=gid, mode=0o750)
    credential_control = Path("/run/lb-v2-cred") / sha(args.config.encode())[:32]
    make_dir(credential_control)
    make_dir(credential_control / "owners")
    broker_runtime = credential_control / "owners" / "broker"
    identity_runtime = credential_control / "owners" / "identity"
    make_dir(broker_runtime, broker["uid"], broker["gid"], 0o700)
    make_dir(identity_runtime, uid, gid, 0o700)
    make_dir(Path("/var/lib/laneboss-v2/lanes") / args.config)
    make_dir(release_root)
    put(release_root / "laneboss", binary, 0o555)
    make_dir(runtime_root)
    put(runtime_root / "manifest.json", runtime_bytes, 0o444)
    if enrollment_bytes is not None:
        put(runtime_root / "launch-enrollment.json", enrollment_bytes, 0o444)
    if initial is not None:
        put(runtime_root / "initial.json", initial_raw, 0o444)
        put(runtime_root / "initial-ref.json", encoded({"manifest": boot["initial_publication"]}), 0o444)
        make_dir(runtime_root / "initial-objects")
        for key, (_, data) in initial_objects.items():
            put(runtime_root / "initial-objects" / key, data, 0o444)
    installed_roots = {}
    for item, data in objects:
        root = runtime_root / item["root_id"]
        target = root / item["relative_path"]
        directory(target.parent)
        if item["role"] in ("claudock", "claude"):
            publish_vendor(target, data, item["content"])
            files.append({"path": str(target), "uid": 0, "gid": 0, "mode": 0o555,
                          "bytes": item["content"]["bytes"], "sha256": item["content"]["sha256"]})
        else:
            put(target, data, item["mode"])
        installed_roots[item["root_id"]] = str(root)
    enrolled_roots = [{"id": key, "path": value} for key, value in sorted(installed_roots.items())]
    put(runtime_root / "roots.json", encoded(enrolled_roots), 0o444)
    make_dir(secrets / "keys", uid, gid, 0o700)
    put(secrets / "keys" / (key_handle + ".key"), native_key, 0o600, uid, gid)
    put(secrets / "keys" / "enrollment.json", encoded({"schema": "laneboss.native-key.v2",
        "handle": key_handle, "algorithm": "aes-256-gcm", "key_file": key_handle + ".key"}), 0o600, uid, gid)
    binding_file = Path("/etc/laneboss-v2/bindings") / (args.config + ".json")
    installed = {"schema": "laneboss.service-install.v2", "config": args.config, "service_uid": uid,
                 "artifact_sha256": artifact["sha256"], "binding_file": str(binding_file),
                 "state_directory": str(state), "socket": str(socket_directory / "control.sock"),
                 "secret_directory": str(secrets), "secret_key_handle": key_handle,
                 "runtime_manifest": boot["runtime_manifest"], "judge": judge_config,
                 "judge_endpoint": boot["judge_endpoint"]}
    installed.update(inference)
    for optional in ("judge_credential_handle", "judge_alternative", "launch_enrollment"):
        if optional in boot:
            installed[optional] = boot[optional]
    if "admin_enrollment" in boot:
        administrator = socket_directory / "administrator"
        make_dir(administrator, uid, gid, 0o700)
        installed["admin_enrollment"] = dict(enrollment_config, config=args.config,
            socket=str(administrator / "enrollment.sock"), service_uid=uid, installation_generation=1,
            helper={"id": runtime["artifact"]["id"], "sha256": artifact["sha256"], "version": manifest["version"]})
    binding = {"schema": "laneboss.binding.v2", "contract_revision": REVISION, "protocol": PROTOCOL,
               "api_schema": 2, "config": args.config, "class": "human", "installation_generation": 1,
               "endpoint_generation": 1, "service_uid": uid, "service_gid": gid,
               "mapped_service_uid": uid, "mapped_service_gid": gid, "socket": installed["socket"],
               "artifact_sha256": artifact["sha256"], "service_version": manifest["version"],
               "backend": "linux-bwrap-landlock"}
    admin_file = Path("/etc/laneboss-v2/admin") / (args.config + ".json")
    admin = {"schema": "laneboss.admin.v2", "contract_revision": REVISION, "config": args.config,
             "generation": 1, "release": manifest, "artifact": artifact, "service": service, "lanes": lanes}
    for path in (binding_file, admin_file, location(args.config), catalog_path(args.config)):
        directory(path.parent)
    put(binding_file, encoded(binding))
    put(admin_file, encoded(admin))
    peer_file = Path("/etc/laneboss-v2/credential-peers") / (args.config + ".json")
    directory(peer_file.parent)
    def credential_peer(owner, role, executable_id):
        return {"UID": owner["uid"], "GID": owner["gid"],
                "Executable": {"id": executable_id, "sha256": artifact["sha256"], "version": manifest["version"]},
                "Bytes": len(binary), "Cgroup": "/system.slice/laneboss-%s@%s.service" % (role, args.config),
                "ContainmentID": "credential-" + role + "-" + args.config}
    put(peer_file, encoded({"Schema": "laneboss.credential-peers.v2", "Config": args.config, "Generation": 1,
        "Broker": credential_peer(broker, "credential", "credential-broker"),
        "Identity": credential_peer(service, "service", runtime["artifact"]["id"])}))
    for role, template in (("helper", helper_template), ("service", service_template), ("credential", credential_template)):
        unit = template.replace(b"@BINARY@", str(release_root / "laneboss").encode()).replace(b"@SERVICE@", service["name"].encode())
        unit = unit.replace(b"@INSTALLATION@", str(location(args.config)).encode())
        unit = unit.replace(b"@CRED@", str(credential_control).encode())
        unit = unit.replace(b"@BROKER@", broker["name"].encode()).replace(b"@KEY@", str(secrets / "keys" / (key_handle + ".key")).encode())
        unit = unit.replace(b"@SOCKET@", str(socket_directory).encode())
        put(Path("/etc/systemd/system") / ("laneboss-%s@%s.service" % (role, args.config)), unit)
    runtime_definition = ("d %s 0755 root root -\nd %s 0750 root %s -\nd %s 0700 %s %s -\n" %
                          (SOCKET_RUNTIME_ROOT, helper_runtime, service["name"], socket_directory,
                           service["name"], service["name"])).encode()
    runtime_definition += ("d %s 0755 root root -\nd %s 0755 root root -\nd %s 0700 %s %s -\nd %s 0700 %s %s -\n" %
        (credential_control, credential_control / "owners", broker_runtime, broker["name"], broker["name"],
         identity_runtime, service["name"], service["name"])).encode()
    if "admin_enrollment" in boot:
        runtime_definition += ("d %s 0700 %s %s -\n" % (administrator, service["name"], service["name"])).encode()
    directory("/etc/tmpfiles.d")
    put(Path("/etc/tmpfiles.d") / ("laneboss-" + args.config + ".conf"), runtime_definition)
    put(location(args.config), encoded(installed))
    catalog = {"schema": "laneboss.boot-catalog.v2", "contract_revision": REVISION, "config": args.config,
               "fingerprint": fingerprint, "files": files, "directories": directories, "accounts": accounts,
               "runtime_file": str(runtime_root / "manifest.json"), "runtime_roots": enrolled_roots,
               "runtime_manifest": boot["runtime_manifest"]}
    if fixture_catalog is not None:
        catalog["fixture_accounts"] = fixture_catalog
    if enrollment_bytes is not None:
        catalog["launch_enrollment"] = boot["launch_enrollment"]
        catalog["launch_enrollment_file"] = str(runtime_root / "launch-enrollment.json")
    if initial is not None:
        catalog["initial_publication"] = boot["initial_publication"]
        catalog["initial_request_file"] = str(runtime_root / "initial-ref.json")
        catalog["binary"] = str(release_root / "laneboss")
    command(["/usr/bin/systemctl", "daemon-reload"], evidence, "daemon-reload")
    publish(catalog_path(args.config), encoded(catalog), 0o600)
    check(args.config)
    return {"verified": True, "changed": True, "installation": str(location(args.config)),
            "publication": "pending" if initial is not None else "absent"}


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--install", action="store_true")
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--publish", action="store_true")
    parser.add_argument("--config", required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--boot", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        require(sys.platform == "linux" and os.getuid() == 0 and os.geteuid() == 0,
                "protected boot provisioning requires authorized Linux root")
        require(CONFIG.fullmatch(args.config), "invalid explicit configuration")
        if args.publish:
            require(args.evidence and not any((args.binary, args.manifest, args.boot)), "--publish accepts config and fresh evidence only")
            result = publish_initial(args.config, args.evidence)
        elif args.check:
            require(not any((args.binary, args.manifest, args.boot, args.evidence)), "--check accepts only --config and writes nothing")
            check(args.config)
            result = {"verified": True, "changed": False, "installation": str(location(args.config))}
        else:
            require(all((args.binary, args.manifest, args.boot, args.evidence)),
                    "install requires supplied binary, manifest, boot inputs and new evidence directory")
            # Serialize a fresh installation without touching a live service or
            # changing a binding to make a conflicting installation succeed.
            directory("/etc/laneboss-v2/install-locks", mode=0o700)
            lock_path = Path("/etc/laneboss-v2/install-locks") / (args.config + ".lock")
            descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                        stat.S_IMODE(info.st_mode) == 0o600, "unsafe installation lock")
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = provision(args)
            finally:
                os.close(descriptor)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Stopped as failure:
        # Stopped messages are authored verdicts, never interpolated inputs.
        print("FAIL: " + str(failure), file=sys.stderr)
        return 3
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError):
        # Never echo raw inputs, key bytes, account databases or private paths.
        print("FAIL: protected boot bundle differs, is incomplete or failed verification; preserve installation evidence.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

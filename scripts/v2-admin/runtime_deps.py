"""Enroll an executable's narrow, immutable Linux interpreter/library closure.

No dependency is discovered at lane start. The native loader resolves names at
enrollment with a clean environment; only its listed files are copied, pinned
and projected at their ABI paths. A bounded stdlib ELF reader records each
PT_INTERP/DT_NEEDED edge without requiring binutils on the installed host.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import struct
import subprocess


SEARCH_PATH = "/usr/bin:/bin"
ABI_ROOTS = ("/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/")
ELF_STRING_LIMIT = 4096
ELF_PROGRAM_LIMIT = 1024
ELF_DYNAMIC_LIMIT = 4096


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def protected(path):
    path = Path(path)
    for current in (path, *path.parents):
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022, "runtime dependency source is not protected")


def source_file(path):
    resolved = Path(path).resolve(strict=True)
    protected(resolved)
    info = resolved.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            0 < info.st_size <= 512 << 20, "runtime dependency is not a bounded ordinary file")
    return resolved


def command(argv, target=None):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, cwd="/",
                            env={"PATH": SEARCH_PATH, "LANG": "C"})
    logical = target if target is not None else "/runtime/" + Path(argv[-1]).name
    stderr = result.stderr[:1 << 20].decode("utf-8", "replace")
    stdout = result.stdout[:1 << 20].decode("utf-8", "replace")
    missing = (re.search(r"error while loading shared libraries: ([^\s:]+):", stderr) or
               re.search(r"(?m)^\s*(\S+)\s+=>\s+not found\b", stdout))
    if missing:
        raise ValueError("runtime loader returned an unresolved library: "
                         f"executable={logical!r} library={missing[1]!r}")
    require(result.returncode == 0 and len(result.stdout) <= 1 << 20,
            f"runtime dependency inspection failed: executable={logical!r} exit={result.returncode}")
    return result.stdout.decode("utf-8", "strict")


def elf_values(path):
    """Read only bounded ELF64 LE headers and file-backed dynamic strings."""
    with Path(path).open("rb") as stream:
        before = os.fstat(stream.fileno())
        size = before.st_size
        require(64 <= size <= 512 << 20, "runtime ELF header is truncated or unbounded")

        def extent(offset, count):
            require(0 <= offset <= size and 0 <= count <= size - offset,
                    "runtime ELF offset is outside file")

        def read_at(offset, count):
            extent(offset, count)
            stream.seek(offset)
            raw = stream.read(count)
            require(len(raw) == count, "runtime ELF changed or truncated during inspection")
            return raw

        def string_at(offset, available):
            require(available > 0, "runtime ELF string is outside table")
            extent(offset, available)
            raw = read_at(offset, min(available, ELF_STRING_LIMIT + 1))
            end = raw.find(b"\0")
            if end < 0:
                require(available <= ELF_STRING_LIMIT, "runtime ELF string exceeds its bound")
                raise ValueError("runtime ELF string is unterminated")
            require(end <= ELF_STRING_LIMIT, "runtime ELF string exceeds its bound")
            require(end > 0, "runtime ELF string is empty")
            try:
                return raw[:end].decode("utf-8", "strict")
            except UnicodeDecodeError as error:
                raise ValueError("runtime ELF string is not UTF-8") from error

        header = struct.unpack("<16sHHIQQQIHHHHHH", read_at(0, 64))
        ident, kind, machine, version = header[:4]
        require(ident[:7] == b"\x7fELF\x02\x01\x01",
                "runtime ELF requires ELF64 little-endian version 1")
        require(machine in (62, 183), "runtime ELF machine is unsupported")
        require(kind in (2, 3) and version == 1 and header[8] == 64,
                "runtime ELF header is unsupported")
        offset, stride, count = header[5], header[9], header[10]
        require(stride == 56 and 0 < count <= ELF_PROGRAM_LIMIT,
                "runtime ELF program table is unsupported or unbounded")
        require(offset >= 64, "runtime ELF program table overlaps its header")
        programs = read_at(offset, stride * count)
        # Section contents are not used, but their declared extent must fit.
        extent(header[6], header[11] * header[12])
        loads, interps, dynamics = [], [], []
        for entry in struct.iter_unpack("<IIQQQQQQ", programs):
            tag, _flags, start, address, _physical, length, memory, _align = entry
            extent(start, length)
            require(address + memory <= 1 << 64, "runtime ELF virtual extent overflows")
            if tag == 1:  # PT_LOAD: only file-backed bytes can supply DT_STRTAB.
                require(length <= memory, "runtime ELF load segment exceeds its memory extent")
                loads.append((start, address, length))
            elif tag == 3:
                interps.append((start, length))
            elif tag == 2:
                dynamics.append((start, length))
        require(len(interps) <= 1, "runtime ELF has ambiguous interpreters")
        require(len(dynamics) <= 1, "runtime ELF has ambiguous dynamic tables")
        for _start, length in interps:
            require(length <= ELF_STRING_LIMIT, "runtime ELF interpreter exceeds its bound")
        interpreters = [string_at(start, length) for start, length in interps]
        records = []
        if dynamics:
            start, length = dynamics[0]
            require(16 <= length <= 16 * ELF_DYNAMIC_LIMIT and length % 16 == 0,
                    "runtime ELF dynamic table is unsupported or unbounded")
            ended = False
            for tag, value in struct.iter_unpack("<qQ", read_at(start, length)):
                if tag == 0:
                    ended = True
                    break
                records.append((tag, value))
            require(ended, "runtime ELF dynamic table is unterminated")
        tables = [value for tag, value in records if tag == 5]
        sizes = [value for tag, value in records if tag == 10]
        references = [(tag, value) for tag, value in records if tag in (1, 14)]
        require(len(tables) <= 1 and len(sizes) <= 1,
                "runtime ELF has ambiguous dynamic string tables")
        require(len(references) <= 256, "runtime ELF dynamic strings exceed their count bound")
        needed, sonames = [], []
        if tables or sizes or references:
            require(len(tables) == 1 and len(sizes) == 1 and sizes[0] > 0,
                    "runtime ELF dynamic string table is missing")
            address, length = tables[0], sizes[0]
            mappings = [start + address - base for start, base, backed in loads
                        if base <= address and address - base <= backed and
                        length <= backed - (address - base)]
            require(len(mappings) == 1, "runtime ELF string table is not file-backed")
            base = mappings[0]
            extent(base, length)
            for tag, index in references:
                require(index < length, "runtime ELF string is outside table")
                value = string_at(base + index, length - index)
                (needed if tag == 1 else sonames).append(value)
        require(identity(os.fstat(stream.fileno())) == identity(before),
                "runtime ELF changed during inspection")
        return interpreters, sonames, needed


def metadata(path):
    with Path(path).open("rb") as stream:
        header = stream.read(256)
    if not header.startswith(b"\x7fELF"):
        require(header.startswith(b"#!") and b"\n" in header and b"\x00" not in header.split(b"\n", 1)[0],
                "runtime executable has neither ELF metadata nor a bounded shebang")
        words = header.split(b"\n", 1)[0][2:].decode("ascii").strip().split(None, 1)
        require(bool(words), "runtime script has no interpreter")
        return {"format": "script", "interpreter": words[0],
                "argument": words[1] if len(words) == 2 else "", "needed": []}
    interpreters, sonames, needed = elf_values(path)
    require(len(interpreters) <= 1, "runtime ELF has ambiguous interpreters")
    require(len(sonames) <= 1, "runtime ELF has ambiguous SONAME aliases")
    return {"format": "ELF", "interpreter": interpreters[0] if interpreters else None,
            "soname": sonames[0] if sonames else None,
            "needed": needed}


def abi_path(path):
    require(isinstance(path, str) and path.startswith(ABI_ROOTS) and
            str(PurePosixPath(path)) == path and
            all(part not in (".", "..") for part in path.split("/")[1:]) and
            not any(character.isspace() for character in path),
            "runtime interpreter or library is outside the system ABI roots")
    return path


def loader_paths(listed, target):
    resolved = {}
    for line in listed.splitlines():
        words = line.strip().split()
        if not words:
            continue
        # ld.so's nameless map: "\t (0x0000efa778cc0000)" in the
        # supplied loaderprobe1 uname output (ARM64 Ubuntu 24.04.5).
        if re.fullmatch(r"[ \t]*\(0x[0-9a-fA-F]+\)[ \t]*", line):
            continue
        if re.fullmatch(r"[ \t]*linux-(?:vdso|gate)\.so\.1[ \t]+"
                        r"\(0x[0-9a-fA-F]+\)[ \t]*", line):
            continue
        if len(words) >= 3 and words[1] == "=>":
            name, path = words[0], words[2]
        else:
            name, path = Path(words[0]).name, words[0]
        require(path.startswith("/"), "runtime loader returned an unresolved library: "
                f"executable={target!r} library={name!r} line={line!r}")
        resolved[name] = abi_path(path)
    return resolved


def stage(root, root_id, relative, role, mode, data, identifier):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    protected(target.parent)
    with target.open("xb") as stream:
        require(stream.write(data) == len(data), "runtime dependency copy was incomplete")
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)
    return {"id": identifier, "role": role, "root_id": root_id,
            "relative_path": relative, "mode": mode, "content": {
                "id": identifier, "class": "artifact", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}}


def enroll(root, root_id, executables, measured=False):
    """Return pinned runtime objects plus a pinned dependency graph artifact."""
    root = Path(root)
    protected(root)
    require(os.geteuid() == 0 and root.is_absolute() and root.is_dir(),
            "runtime dependency enrollment requires the protected Linux root")
    pending = [(str(path), "/runtime/" + name, True) for name, path in executables.items()]
    objects, graph, visited, staged, certificates = [], [], set(), {}, {}

    def retain(path, executable=False, role=None):
        if role is None:
            path = abi_path(path)
        if path in staged:
            require(not executable or staged[path]["mode"] == 0o555,
                    "runtime library was enrolled before its interpreter role")
            return
        source = source_file(path)
        before = source.stat()
        if role == "runtime-cert":
            with source.open("rb") as stream:
                pin = hashlib.file_digest(stream, "sha256").hexdigest()
                require(identity(os.fstat(stream.fileno())) == identity(before) and
                        identity(source.stat()) == identity(before), "runtime certificate changed while hashing")
            if pin in certificates:
                item = certificates[pin]
                aliases = item.setdefault("aliases", [])
                require(len(aliases) < 8, "runtime certificate alias bound exceeded")
                aliases.append(path)
                staged[path] = item
                graph.append({"path": path, "sha256": pin, "kind": role})
                return
        require(before.st_size <= 64 << 20 and len(objects) < 100 and
                sum(item["content"]["bytes"] for item in objects) + before.st_size <= 256 << 20,
                "runtime library closure exceeds its object or aggregate bound")
        target = root / path[1:]
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        protected(target.parent)
        mode = 0o555 if executable else 0o444
        digest, size = hashlib.sha256(), 0
        with source.open("rb") as stream, target.open("xb") as output:
            require(identity(os.fstat(stream.fileno())) == identity(before), "runtime library changed on open")
            while True:
                chunk = stream.read(min(1 << 20, before.st_size + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                require(size <= before.st_size, "runtime library grew during enrollment")
                digest.update(chunk)
                require(output.write(chunk) == len(chunk), "runtime dependency copy was incomplete")
            require(identity(os.fstat(stream.fileno())) == identity(before) and size == before.st_size and
                    identity(source.stat()) == identity(before), "runtime library changed during enrollment")
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), mode)
        identifier = "runtime-dep-" + str(len(objects))
        item = {"id": identifier, "role": role or ("runtime-interpreter" if executable else "runtime-library"),
                "root_id": root_id, "relative_path": path[1:], "mode": mode, "content": {
                    "id": identifier, "class": "artifact", "bytes": size, "sha256": digest.hexdigest()}}
        staged[path] = item
        objects.append(item)
        if role:
            graph.append({"path": path, "sha256": item["content"]["sha256"], "kind": role})
            if role == "runtime-cert":
                certificates[item["content"]["sha256"]] = item
        else:
            pending.append((str(root / path[1:]), path, executable))

    if measured:
        spec = importlib.util.spec_from_file_location("runtime_files", Path(__file__).with_name("runtime_files.py"))
        files = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(files)
        for path in files.START_PROGRAMS:
            retain(path, True)
        graph.append({"path": "/etc/resolv.conf", "classification": "provided",
                      "provider": "controlled-egress"})
        for path in files.paths():
            if path == files.CA_ALIAS:
                continue  # This name receives the accepted bundle's pinned bytes.
            if path.startswith("/etc/ssl/") and path != files.CA_BUNDLE:
                graph.append({"path": path, "classification": "omitted",
                              "reason": "individual certificate excluded; use pinned CA bundle"})
                continue
            try:
                if path == files.CA_BUNDLE:
                    protected(path)  # The bundle itself must not be a symlink.
                source_file(path)  # Metadata classification; opens no contents.
            except FileNotFoundError:
                graph.append({"path": path, "classification": "omitted", "reason": "absent"})
                continue
            except (ValueError, OSError) as error:
                graph.append({"path": path, "classification": "omitted",
                              "reason": str(error) if isinstance(error, ValueError) else "metadata unavailable"})
                continue
            role = "runtime-cert" if path.startswith("/etc/ssl/") else "runtime-config"
            if path.startswith("/lib/"):
                role = "runtime-library"
            try:
                retain(path, role=role)
                graph.append({"path": path, "classification": "pinned"})
            except ValueError as error:
                raise ValueError("measured runtime source refused: " + path) from error
        bundle = staged.get(files.CA_BUNDLE)
        require(bundle is not None and bundle["role"] == "runtime-cert",
                "measured runtime requires an accepted pinned CA store")
        bundle["aliases"] = [files.CA_ALIAS]
        graph.append({"path": files.CA_ALIAS, "classification": "pinned",
                      "kind": "runtime-cert", "source": files.CA_BUNDLE,
                      "sha256": bundle["content"]["sha256"],
                      "reason": "same pinned CA bundle bytes"})

    while pending:
        source, target, executable = pending.pop(0)
        if target in visited:
            continue
        require(len(visited) < 100, "runtime dependency closure is unbounded")
        visited.add(target)
        source = source_file(source)
        info = metadata(source)
        with source.open("rb") as stream:
            pin = hashlib.file_digest(stream, "sha256").hexdigest()
        row = {"path": target, "sha256": pin, "executable": executable, **info}
        graph.append(row)
        interpreter = info["interpreter"]
        if info["format"] == "script":
            retain(interpreter, True)
            if Path(interpreter).name == "env":
                words = shlex.split(info["argument"])
                if words and words[0] == "-S":
                    words = words[1:]
                else:
                    require(len(words) == 1, "env shebang requires one program or an explicit -S split")
                require(words and not words[0].startswith("-") and "=" not in words[0],
                        "env shebang has no fixed program")
                selected = shutil.which(words[0], path=SEARCH_PATH)
                require(selected is not None, "env shebang program is unavailable")
                row["program"] = selected
                retain(selected, True)
            continue
        if interpreter and executable:
            retain(interpreter, True)
            listed = command([str(source_file(interpreter)), "--list", str(source)], target)
            resolved = loader_paths(listed, target)
            for path in resolved.values():
                retain(path, path == interpreter)
            # The loader's --list is transitive. Check every DT_NEEDED edge,
            # including libraries' own dependencies, against that resolved set.
            paths = [(source, info), *[(source_file(path), metadata(source_file(path)))
                                     for path in sorted(set(resolved.values()))]]
            for path in sorted(set(resolved.values())):
                soname = metadata(source_file(path)).get("soname")
                if soname:
                    require(soname not in resolved or resolved[soname] == path,
                            "runtime loader returned ambiguous SONAME aliases")
                    resolved[soname] = path
            for _path, details in paths:
                for name in details["needed"]:
                    require(name in resolved, "runtime loader omitted a DT_NEEDED dependency: "
                            f"executable={target!r} library={name!r}")
            row["resolved"] = resolved
        else:
            # Shared objects are reached through the executable's transitive
            # list. A static executable may have no external NEEDED entries.
            require(not info["needed"] or target in staged,
                    "runtime ELF needs libraries but declares no interpreter")
    graph.sort(key=lambda row: row["path"])
    raw = (json.dumps({"schema": "laneboss.runtime-links.v1", "files": graph},
                      sort_keys=True, indent=2) + "\n").encode()
    objects.append(stage(root, root_id, "runtime-links.json", "runtime-linkage", 0o444,
                         raw, "runtime-links"))
    return objects


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--root-id", required=True)
    parser.add_argument("--executable", action="append", required=True)
    parser.add_argument("--measured", action="store_true")
    args = parser.parse_args()
    entries = {}
    for value in args.executable:
        name, separator, path = value.partition("=")
        require(separator and re.fullmatch(r"[A-Za-z0-9_-]{1,39}", name) and name not in entries,
                "runtime executable selector is invalid")
        entries[name] = Path(path)
    print(json.dumps(enroll(args.root, args.root_id, entries, measured=args.measured), sort_keys=True))


if __name__ == "__main__":
    main()

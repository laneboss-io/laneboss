"""Read-back manifests and atomic harvest publication, shared by box phases."""

import os
from pathlib import Path
import tarfile
import uuid

from support import (Failure, beneath, bytes_hash, evidence, load, require, save,
                     sha256, verify_evidence)


def manifest(directory):
    directory = Path(directory)
    paths = []
    for name in ("evidence", "admin"):
        scope = directory / name
        if scope.exists():
            for path in sorted(scope.rglob("*")):
                require(not path.is_symlink(), "linked evidence input")
                if path.is_file() and path.name != "manifest.json":
                    paths.append(path)
    for name in ("context.json", "resources.json", "provision.json"):
        path = directory / name
        if path.is_file():
            paths.append(path)
    items = [evidence(directory, path) for path in paths]
    target = directory / "evidence" / "manifest.json"
    save(target, {"schema": "laneboss.e2e-evidence.v2", "files": items})
    for item in load(target)["files"]:
        verify_evidence(directory, item)
    return sha256(target)


def verify_bundle(path, directory):
    expected = {item["path"]: item for item in
                load(Path(directory) / "evidence" / "manifest.json")["files"]}
    seen = set()
    with tarfile.open(path, "r:") as archive:
        for member in archive:
            require(member.isfile() and member.name not in seen, "invalid harvest member")
            source = archive.extractfile(member)
            require(source is not None, "unreadable harvest member")
            import hashlib
            digest = hashlib.sha256()
            size = 0
            for block in iter(lambda: source.read(1024 * 1024), b""):
                size += len(block)
                digest.update(block)
            if member.name == "evidence/manifest.json":
                require(digest.hexdigest() ==
                        sha256(Path(directory) / member.name), "harvest manifest differs")
            else:
                require(member.name in expected and
                        size == expected[member.name]["bytes"] and
                        digest.hexdigest() == expected[member.name]["sha256"],
                        "harvest member differs from manifest")
            seen.add(member.name)
    require(seen == set(expected) | {"evidence/manifest.json"}, "harvest omitted evidence")


def export_bundle(directory, output):
    directory, output = Path(directory), Path(output)
    require(output.is_absolute() and output.resolve() == output and
            not output.is_relative_to(directory), "invalid harvest destination")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    final = output / (directory.name + ".tar")
    require(not final.exists(), "preserve an existing harvest bundle")
    partial = output / (directory.name + "." + uuid.uuid4().hex[:8] + ".partial")
    try:
        with tarfile.open(partial, "x:") as archive:
            items = load(directory / "evidence" / "manifest.json")["files"]
            for name in [item["path"] for item in items] + ["evidence/manifest.json"]:
                path = beneath(directory, name)
                require(path.is_file(), "harvest input disappeared")
                archive.add(path, arcname=name, recursive=False)
        verify_bundle(partial, directory)
        # No observer may see a passing final bundle before complete read-back.
        os.replace(partial, final)
        return final
    except BaseException:
        if partial.exists():
            partial.unlink()
        raise


def finish(directory, summary, output=None):
    root = Path(directory) / "evidence"

    def write_summary():
        save(root / "summary.json", summary)
        (root / "exit-code.txt").write_text(str(summary["exit_code"]) + "\n")

    try:
        summary["artifact_collection_ok"] = True
        write_summary()
        manifest(directory)
        if output is not None:
            export_bundle(directory, output)
    except BaseException as error:
        summary.update({"exit_code": 2, "outcome": "evidence-error",
                        "artifact_collection_ok": False,
                        "artifact_error": type(error).__name__})
        write_summary()
        try:
            manifest(directory)
        except BaseException:
            target = root / "manifest.json"
            if target.exists():
                target.unlink()
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
    return summary["exit_code"]

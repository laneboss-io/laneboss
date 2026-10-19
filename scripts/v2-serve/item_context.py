"""Frozen installed context; input bytes are retained before execution."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def keep(path, raw):
    path = Path(path)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)
    require(path.read_bytes() == raw, "retained item bytes differ")
    return {"path": path.name, "sha256": sha(path), "bytes": len(raw)}


def frozen(source):
    root = Path(source) / "e2e" / "v2"
    # The case owns the frozen reader, including evidence fences. Import its
    # existing support module rather than maintaining a second result schema.
    sys.path.insert(0, str(root))
    try:
        spec = importlib.util.spec_from_file_location(
            "item_manifests", root / "manifests.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def private(path):
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path.resolve(strict=True) == path and
            stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700,
            "item scope is not a canonical private directory")
    return path


def retain_inputs(context, inputs):
    root = private(context["test_root"])
    rows = []
    for name, raw in sorted(inputs.items()):
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,39}", name) and
                name not in (".", "..", "context.json", "result.json",
                             "manifest.json", "binding.input.json", "inputs.json") and
                isinstance(raw, bytes), "invalid item input")
        rows.append(keep(root / name, raw))
    keep(root / "inputs.json", encoded(rows))
    return rows


def create(case, case_id, binding_file, profile_grant_ids, *,
           phase="candidate", mutation_id="", controls=None):
    reader = frozen(case.stage)
    manifest_path = (case.stage / "e2e" / "v2" / "cases" /
                     case_id / "case.json")
    manifest, entry = reader.case_file(manifest_path)
    require(manifest["id"] == case_id, "item manifest identity differs")
    binary = Path(case.binary)
    binding_file = Path(binding_file)
    for path in (binary, binding_file):
        info = path.lstat()
        require(path.is_absolute() and path.resolve(strict=True) == path and
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                not info.st_mode & 0o022,
                "item executable or binding is linked or writable")
    retained = case.root / "laneboss.input"
    require(sha(binary) == case.installed["artifact_sha256"] == sha(retained),
            "installed item executable differs from retained build")
    # source.tar includes product, shared harness and public case consumers.
    archive = case.root / "source.tar"
    require(archive.is_file() and not archive.is_symlink(),
            "complete retained item source is missing")
    inventory = json.loads((case.root / "source-files.json").read_bytes())
    expected = {row["path"]: row for row in inventory}
    require(len(expected) == len(inventory) and {
        "e2e/v2/manifests.py", "scripts/v2-serve/item_context.py",
        str(manifest_path.relative_to(case.stage)),
        str(entry.relative_to(case.stage)),
    } <= set(expected), "complete item source inventory is missing")
    found = set()
    with tarfile.open(archive, "r") as retained_source:
        for member in retained_source:
            relative = Path(member.name)
            require(not relative.is_absolute() and ".." not in relative.parts and
                    str(relative) == member.name and
                    (case.stage / relative).resolve(strict=True) == case.stage / relative,
                    "item source archive contains a noncanonical input")
            require(member.isfile() and member.name in expected and
                    member.name not in found, "item source archive inventory differs")
            row = expected[member.name]
            raw = retained_source.extractfile(member).read()
            require(len(raw) == row["bytes"] == member.size and
                    hashlib.sha256(raw).hexdigest() == row["sha256"] and
                    (case.stage / member.name).read_bytes() == raw,
                    "item source archive differs from consumed source bytes")
            found.add(member.name)
    require(found == set(expected), "item source archive omitted consumed inputs")
    stem = case.root / ("item-" + case_id)
    stem.mkdir(mode=0o700)
    test, output = stem / "input", stem / "evidence"
    test.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    context = {
        "schema": "laneboss.e2e-context.v2", "case_id": case_id,
        "phase": phase, "mutation_id": mutation_id,
        "binary": str(binary), "binary_sha256": sha(binary),
        "source_sha256": sha(archive), "config": case.config,
        "binding_file": str(binding_file), "test_root": str(private(test)),
        "evidence_root": str(private(output)),
        "profile_grant_ids": profile_grant_ids,
    }
    if controls is not None:
        context["controls"] = controls
    path = test / "context.json"
    keep(path, encoded(context))
    require(reader.context_file(path) == context,
            "frozen context read-back differs")
    keep(test / "manifest.json", manifest_path.read_bytes())
    keep(test / "binding.input.json", binding_file.read_bytes())
    return context, path


def collection(receipt, context):
    require(isinstance(receipt, dict) and
            receipt.get("processes_quiescent") is True and
            receipt.get("temporary_resources_collected") is True and
            isinstance(receipt.get("operation_ids"), list) and
            all(isinstance(value, str) and value for value in receipt["operation_ids"]) and
            len(set(receipt["operation_ids"])) == len(receipt["operation_ids"]) and
            isinstance(receipt.get("evidence"), list) and receipt["evidence"],
            "independent installed collection is incomplete")
    reader = frozen(Path(__file__).resolve().parents[2])
    for ref in receipt["evidence"]:
        reader.verify_evidence(context["evidence_root"], ref)
    return receipt

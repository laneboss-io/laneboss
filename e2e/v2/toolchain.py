"""Resolve the operator's Go once and verify the exact compiler used by setup."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil

from box_support import Recorder
from support import Failure, clean_environment, evidence, save, sha256


MESSAGES = {
    "missing": "Go executable was not found; supply --go",
    "invalid": "selected Go executable is not a regular executable file",
    "version": "selected Go version differs from the contract pin",
    "command": "selected Go version command failed",
    "module": "selected Go is older than the module minimum",
    "pin": "fixture Go toolchain pin is invalid",
    "changed": "selected Go executable changed during setup",
    "installer": "source installer toolchain pin differs from the fixture contract",
    "binary": "installed binary compiler differs from the fixture contract",
}


class ToolchainError(Failure):
    def __init__(self, kind):
        code = "prerequisite_missing" if kind in ("missing", "invalid") else "version_mismatch"
        owner = "lb-v2-packaging" if kind == "installer" else "lb-v2-e2e"
        super().__init__(MESSAGES[kind], code, owner)
        self.public_diagnostic = MESSAGES[kind]


@dataclass(frozen=True)
class Compiler:
    path: Path
    sha256: str
    selection: str

    def unchanged(self):
        try:
            same = self.path.is_file() and sha256(self.path) == self.sha256
        except OSError:
            same = False
        if not same:
            raise ToolchainError("changed")


def resolve_go(option=None):
    # This is the only lookup in the invoking operator's PATH. Never enumerate,
    # print, retain or forward that PATH or any other inherited variable.
    selector = os.environ.get("LANEBOSS_GO") if option is None else None
    found = os.fspath(option) if option is not None else selector or shutil.which("go")
    if found is None:
        raise ToolchainError("missing")
    try:
        path = Path(found).resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ToolchainError("invalid")
        digest = sha256(path)
    except (FileNotFoundError, NotADirectoryError):
        raise ToolchainError("missing") from None
    except OSError:
        raise ToolchainError("invalid") from None
    selection = "explicit" if option is not None else "operator-selector" if selector else "operator-path"
    return Compiler(path, digest, selection)


def version_tuple(value):
    return tuple(int(part) for part in value.removeprefix("go").split("."))


def validate_module(pin, source):
    if re.fullmatch(r"go[0-9]+\.[0-9]+\.[0-9]+", pin) is None:
        raise ToolchainError("pin")
    match = re.search(r"(?m)^go ([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*$", source)
    if match is None:
        raise ToolchainError("module")
    minimum = version_tuple(match[1])
    minimum = minimum + (0,) * (3 - len(minimum))
    if version_tuple(pin) < minimum:
        raise ToolchainError("module")
    return match[1]


def build_environment(directory, compiler):
    return {
        **clean_environment(directory / "controller-home", directory / "controller-tmp"),
        "LANEBOSS_GO": str(compiler.path), "GOTOOLCHAIN": "local",
        "GOWORK": "off", "CGO_ENABLED": "0", "GOENV": "off",
        "GOFLAGS": "", "GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0",
        "GOPATH": str(directory / "go-path"), "GOCACHE": str(directory / "go-cache"),
    }


def verify_compiler(directory, compiler, pin, module_source, source_root):
    compiler.unchanged()
    minimum = validate_module(pin, module_source)
    root = directory / "evidence"
    metadata = {"schema": "laneboss.e2e-go.v2", "path": str(compiler.path),
                "sha256": compiler.sha256, "selection": compiler.selection,
                "expected_version": pin, "module_minimum": minimum, "verified": False}
    save(root / "go-toolchain.json", metadata)
    environment = build_environment(directory, compiler)
    result = Recorder(root / "cmd").run(
        [str(compiler.path), "version"], label="go-version", timeout=60,
        environment=environment, cwd=source_root)
    metadata["version_receipt"] = evidence(root, result.receipt)
    match = re.fullmatch(
        rb"go version (go[0-9]+\.[0-9]+\.[0-9]+) ([a-z0-9]+)/([a-z0-9]+)\n?",
        result.stdout)
    metadata["observed_version"] = match[1].decode("ascii") if match else ""
    metadata["observed_exit"] = result.returncode
    metadata["version_matches"] = result.returncode == 0 and match is not None and (
        metadata["observed_version"] == pin)
    save(root / "go-toolchain.json", metadata)
    if result.returncode != 0:
        raise ToolchainError("command")
    if not metadata["version_matches"]:
        raise ToolchainError("version")
    compiler.unchanged()
    kept = root / "selected-go"
    shutil.copyfile(compiler.path, kept)
    if sha256(kept) != compiler.sha256:
        raise ToolchainError("changed")
    compiler.unchanged()
    metadata["executable"] = evidence(root, kept)
    metadata["verified"] = True
    save(root / "go-toolchain.json", metadata)
    return environment


def check_installer(directory, script, pin):
    """Refuse an explicit conflicting pin without changing packaging's script."""
    source = script.read_text(encoding="utf-8")
    pins = sorted(set(re.findall(
        r"(?m)^[ \t]*GOTOOLCHAIN=['\"]?(go[0-9]+\.[0-9]+\.[0-9]+)"
        r"(?:\+auto)?['\"]?(?:[ \t]|$)", source)))
    compatible = all(value == pin for value in pins)
    save(directory / "evidence" / "installer-toolchain.json", {
        "script_sha256": sha256(script), "selected_version": pin,
        "declared_versions": pins, "compatible": compatible})
    if not compatible:
        raise ToolchainError("installer")


def verify_binary(directory, compiler, pin, binary, source_root):
    compiler.unchanged()
    result = Recorder(directory / "evidence" / "cmd").run(
        [str(compiler.path), "version", str(binary)], label="binary-compiler",
        timeout=60, environment=build_environment(directory, compiler), cwd=source_root)
    if result.returncode != 0 or result.stdout != (str(binary) + ": " + pin + "\n").encode():
        raise ToolchainError("binary")
    compiler.unchanged()
    return result

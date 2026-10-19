"""Wave-zero source-install fixture, ported to frozen v2 command spellings."""

import os
from pathlib import Path
import re
import shutil
import tarfile
import time

from box_support import Context, Recorder
from support import (Failure, ROOT, clean_environment, copy_verified, immutable, load, require,
                     require_linux, save, sha256, verify_tar_inventory)
from toolchain import check_installer, verify_binary, verify_compiler


def run_directory(lane, run_id):
    require(re.fullmatch(r"lb-[a-z0-9-]{1,24}", lane) is not None and
            re.fullmatch(r"[a-z0-9]{8}", run_id) is not None, "invalid lane/run ID")
    directory = Path("/var/tmp") / (lane + "-" + run_id)
    directory.mkdir(mode=0o755)
    for name in ("evidence", "controller-home", "controller-tmp", "build", "requests"):
        (directory / name).mkdir(mode=0o700)
    return directory


def keep_source(directory):
    target = directory / "evidence" / "source.tar.gz"
    denied = {".git", ".agents", ".codex", ".aws", ".ssh", ".env", "__pycache__",
              ".venv", "node_modules", "credentials"}
    manifest = []
    with tarfile.open(target, "x:gz") as archive:
        for parent, names, files in os.walk(ROOT, followlinks=False):
            for name in names:
                path = Path(parent) / name
                require(not path.is_symlink(), "source contains a linked directory")
            names[:] = sorted(name for name in names if name not in denied)
            for name in sorted(files):
                path = Path(parent) / name
                if name in denied or path.suffix in (".pyc", ".pyo"):
                    continue
                require(path.is_file() and not path.is_symlink(), "linked/special source input")
                archive.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
                manifest.append({"path": str(path.relative_to(ROOT)),
                                 "bytes": path.stat().st_size, "sha256": sha256(path)})
    save(directory / "evidence" / "source-manifest.json", manifest)
    verify_tar_inventory(target, manifest)
    return target


def kit_step(directory, kit, step, argument=None, timeout=180):
    immutable(kit)
    recorder = Recorder(directory / "evidence" / "cmd")
    argv = ["sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", str(timeout),
            "/usr/bin/python3", "-I", "-B", str(kit), step, str(directory)]
    if argument is not None:
        argv.append(str(argument))
    result = recorder.run(argv, label="kit-" + step, timeout=timeout + 15,
                           environment=clean_environment(directory / "controller-home",
                                                         directory / "controller-tmp"),
                           recorded=["kit", step, str(argument or "")])
    require(result.returncode == 0, "named administrator step failed: " + step)
    return result


def setup(directory, kit, compiler):
    require_linux()
    immutable(kit)
    require(sha256(kit) == sha256(ROOT / "scripts" / "v2-e2e" / "privileged.py"),
            "sealed kit differs from reviewed source")
    contract = load(Path(kit).parent / "contract.json")
    require(contract == load(ROOT / "scripts" / "v2-e2e" / "contract.json"),
            "sealed fixture contract differs")
    for name in ("privileged.py", "contract.json", "bwrap.apparmor"):
        source_path = Path(kit).parent / name
        require(sha256(source_path) == sha256(ROOT / "scripts" / "v2-e2e" / name),
                "sealed kit companion differs")
        copy_verified(source_path, directory / "evidence" / name)
    environment = clean_environment(directory / "controller-home", directory / "controller-tmp")
    for program in ("git", "sudo", "timeout", "python3"):
        require(shutil.which(program, path=environment["PATH"]) is not None,
                "box image lacks a required tool: " + program, "prerequisite_missing")
    require(Path("/usr/bin/bwrap").is_file(), "box lacks bubblewrap", "prerequisite_missing")
    pin = contract["go_toolchain"]
    source = keep_source(directory)
    build_env = verify_compiler(directory, compiler, pin,
                                (ROOT / "go.mod").read_text(), ROOT)
    installer = ROOT / "scripts" / "install.sh"
    check_installer(directory, installer, pin)
    recorder = Recorder(directory / "evidence" / "cmd")
    compiler.unchanged()
    install = recorder.run(["sh", str(installer), "--prefix",
                            str(directory / "install")], label="source-install",
                           timeout=1200, environment=build_env, cwd=ROOT)
    require(install.returncode == 0, "source installer failed")
    installed = install.json()
    binary = (directory / "install" / "bin" / "laneboss").resolve(strict=True)
    require(binary.is_relative_to(directory / "install") and binary.is_file(),
            "source installer did not produce its actual binary")
    verify_binary(directory, compiler, pin, binary, ROOT)
    copy_verified(binary, directory / "build" / "laneboss")
    before = recorder.run([str(binary), "--version"], label="binary-version",
                          timeout=60, environment=environment)
    require(before.returncode == 0 and before.json().get("program") == "laneboss",
            "installed version command failed")
    require(before.json().get("version") == installed.get("installed") and
            before.json().get("api_protocol") == "laneboss.rpc.v2",
            "installer/version/API metadata disagree")
    save(directory / "evidence" / "build.json", {
        "source_sha256": sha256(source), "binary_sha256": sha256(binary),
        "go_path": str(compiler.path), "go_sha256": compiler.sha256,
        "installer_result": installed})
    save(directory / "provision.json", {
        "lane": directory.name.rsplit("-", 1)[0], "run_id": directory.name.rsplit("-", 1)[1],
        "binary_sha256": sha256(directory / "build" / "laneboss")}, mode=0o400)
    installed_fixture_required()
    kit_step(directory, kit, "provision")
    kit_step(directory, kit, "controls")
    context = Context(directory, kit)
    for role in ("operator", "lane"):
        result = context.as_user(role, ["/usr/bin/id", "-u"], label="uid-control")
        require(result.returncode == 0 and
                int(result.stdout.strip()) == context.data["accounts"][role]["uid"],
                "account switch did not reach intended non-root UID")
    kit_step(directory, kit, "apparmor")
    kit_step(directory, kit, "start-service")
    service = load(directory / "admin" / "service.json")
    if service["state"] in ("missing-command", "not-implemented"):
        # This is preparation for the ordinary red smoke, never a product pass.
        return context
    deadline = time.monotonic() + contract["startup_timeout_seconds"]
    while time.monotonic() < deadline:
        from support import process_identity
        require(process_identity(service["pid"]) == service["process"],
                "serve exited before readiness")
        metadata = context.kit_call("socket-info")
        require(metadata.returncode == 0, "socket observer failed")
        info = metadata.json()
        if info["present"]:
            expected = (context.data["accounts"]["service"]["uid"],
                        context.data["rpc_gid"], contract["socket_mode"])
            if (info["uid"], info["gid"], info["mode"]) == expected:
                ready = context.readiness()
                if ready.returncode == 0:
                    value = ready.json()
                    require(value.get("ready") is True and value.get("schema") == 2 and
                            value.get("protocol") == "laneboss.rpc.v2" and
                            value.get("artifact_sha256") == context.data["binary_sha256"],
                            "readiness did not affirm the real v2 artifact")
                    context.assert_live()
                    return context
                from support import decode
                error = decode(ready.stderr)
                if "error" in error:
                    error = error["error"]
                require(error.get("code") == "unavailable" and
                        error.get("retryable") is True and
                        "connection refused" in error.get("message", "").lower(),
                        "readiness failed for a reason other than connection refusal")
        time.sleep(0.1)
    raise Failure("service readiness deadline exceeded", "deadline_exceeded")


def retain_binary(directory):
    context = directory / "context.json"
    if context.exists():
        value = load(context)
        binary = Path(value["paths"]["binary"])
        require(binary.is_file() and not binary.is_symlink(), "tested binary is missing")
        require(sha256(binary) == value["binary_sha256"], "tested binary changed")
        target = directory / "evidence" / "tested-laneboss"
        copy_verified(binary, target)
        require(sha256(target) == value["binary_sha256"], "binary read-back differs")
    downloads = directory / "go-path" / "pkg" / "mod" / "cache" / "download"
    if downloads.exists():
        for path in downloads.rglob("*"):
            require(not path.is_symlink(), "linked build-download input")
        inventory = [{"path": "go-downloads/" + str(path.relative_to(downloads)),
                      "bytes": path.stat().st_size, "sha256": sha256(path)}
                     for path in sorted(downloads.rglob("*")) if path.is_file()]
        target = directory / "evidence" / "go-downloads.tar.gz"
        with tarfile.open(target, "x:gz") as archive:
            archive.add(downloads, arcname="go-downloads")
        verify_tar_inventory(target, inventory)
        save(directory / "evidence" / "go-downloads.json", inventory)


def installed_fixture_required():
    # Production installation and boot belong to the administrator's fixed
    # install.sh --install/--boot route, never this canary helper. That adapter
    # is not present in this source snapshot; do not guess its file protocol.
    raise Failure("administrator install.sh --install/--boot fixture handoff is absent",
                  "not_implemented", "lb-v2-admin")

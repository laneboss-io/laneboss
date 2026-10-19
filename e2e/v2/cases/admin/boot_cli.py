"""Observe the real root installer; supporting evidence for the serve case."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import shutil
import subprocess
import sys
import re


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(config, socket_root):
    result = {}
    roots = [Path("/etc/laneboss-v2"), Path("/etc/tmpfiles.d"),
             Path("/etc/systemd/system"), Path("/usr/lib/laneboss-v2"),
             Path("/var/lib/laneboss-v2"), Path("/run/laneboss-v2"),
             Path("/run/lb-v2")]
    socket_prefix = str(socket_root)
    for root in roots:
        if not root.exists():
            continue
        paths = sorted(root.rglob("*"))
        for path in paths:
            if (config not in str(path) and not str(path).startswith("/usr/lib/laneboss-v2/") and
                    not str(path).startswith(socket_prefix)):
                continue
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), "installed inventory contains a link")
            result[str(path)] = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                                 "gid": info.st_gid, "inode": info.st_ino, "mtime_ns": info.st_mtime_ns,
                                 "sha256": sha(path) if stat.S_ISREG(info.st_mode) else None}
    return result


def test_unit_runtime_paths(config):
    """Every generated unit /run path must be backed by generated tmpfiles."""
    tmpfiles = Path("/etc/tmpfiles.d") / ("laneboss-" + config + ".conf")
    require(tmpfiles.is_file(), "unit_runtime_paths: tmpfiles definition is missing")
    runtime_dirs = set()
    for line in tmpfiles.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "d" and fields[1].startswith("/run/"):
            runtime_dirs.add(fields[1].rstrip("/"))
    require(runtime_dirs, "unit_runtime_paths: no /run directory is generated")
    units = sorted(Path("/etc/systemd/system").glob("laneboss-*" + config + ".service"))
    require(units, "unit_runtime_paths: installed unit templates are missing")
    path_pattern = re.compile(r"/run/[A-Za-z0-9_@%+./-]+")
    for unit in units:
        text = unit.read_text().replace("%i", config)
        for path in path_pattern.findall(text):
            require(any(path == root or path.startswith(root + "/") for root in runtime_dirs),
                    "unit_runtime_paths: unit path lacks an installer runtime directory: " + path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--boot", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "authorized disposable Linux root required")
    require(args.evidence.is_absolute() and not args.evidence.exists(), "fresh absolute evidence required")
    boot_spec = importlib.util.spec_from_file_location("laneboss_boot", args.source / "scripts/v2-admin/boot.py")
    require(boot_spec is not None and boot_spec.loader is not None, "installer source module is unavailable")
    boot_module = importlib.util.module_from_spec(boot_spec)
    boot_spec.loader.exec_module(boot_module)
    longest = "a" * 32
    probe = boot_module.socket_root(longest) / "lanes" / ("lane-projection-" + "0" * 32 + ".sock")
    require(len(os.fsencode(str(probe))) < 108, "longest configuration still exceeds the Unix socket path limit")
    args.evidence.mkdir(mode=0o700, parents=True)
    args.evidence.chmod(0o700)
    entry = args.source / "scripts/v2-admin/install.sh"
    records = []

    def command(label, argv, expected=0):
        done = subprocess.run(argv, cwd="/", env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=180, check=False)
        (args.evidence / (label + ".stdout")).write_bytes(done.stdout)
        (args.evidence / (label + ".stderr")).write_bytes(done.stderr)
        (args.evidence / (label + ".command.json")).write_text(json.dumps(argv) + "\n")
        records.append({"label": label, "exit_code": done.returncode})
        require(done.returncode == expected, label + " did not reach the expected exit")
        return done

    def install(label, boot):
        return command(label, ["bash", str(entry), "--install", "--config", args.config,
                               "--binary", str(args.binary), "--manifest", str(args.manifest),
                               "--boot", str(boot), "--evidence", str(args.evidence / label)])

    passed, reason, current = False, None, "install"
    try:
        installed = install("install", args.boot)
        result = json.loads(installed.stdout)
        boot_file = Path(result["installation"])
        boot = json.loads(boot_file.read_bytes())
        require(boot["schema"] == "laneboss.service-install.v2" and boot["config"] == args.config,
                "missing installed boot bundle")
        require(boot_file.stat().st_uid == 0 and stat.S_IMODE(boot_file.stat().st_mode) == 0o644,
                "unsafe boot mode")
        binding = json.loads(Path(boot["binding_file"]).read_bytes())
        require(binding["contract_revision"] == "v2.0-draft.4" and binding["socket"] == boot["socket"],
                "installed binding differs")
        unit = Path("/etc/systemd/system") / ("laneboss-service@" + args.config + ".service")
        require(("--installation " + str(boot_file)).encode() in unit.read_bytes(),
                "installed unit lacks the boot file")
        test_unit_runtime_paths(args.config)
        supplied_boot = json.loads(args.boot.read_bytes())
        if "admin_enrollment" in supplied_boot:
            endpoint = boot.get("admin_enrollment", {})
            require(all(endpoint.get(name) == supplied_boot["admin_enrollment"][name] for name in ("origin", "rp_id")) and
                    endpoint.get("config") == args.config and endpoint.get("service_uid") == boot["service_uid"] and
                    endpoint.get("installation_generation") == binding["installation_generation"] and
                    endpoint.get("helper", {}).get("sha256") == boot["artifact_sha256"] and
                    endpoint.get("socket") != boot["socket"] and
                    Path(endpoint["socket"]) == Path(boot["socket"]).parent / "administrator" / "enrollment.sock",
                    "administrator enrollment policy, helper pin or private endpoint differs")
        else:
            require("admin_enrollment" not in boot, "installer invented an enrollment origin or RP")
        if "launch_enrollment" in supplied_boot:
            require(boot.get("launch_enrollment") == supplied_boot["launch_enrollment"],
                    "installed launch enrollment reference differs")
            catalog_file = Path("/etc/laneboss-v2/boot") / (args.config + ".json")
            catalog = json.loads(catalog_file.read_bytes())
            enrollment_file = Path(catalog["launch_enrollment_file"])
            require(catalog["launch_enrollment"] == supplied_boot["launch_enrollment"] and
                    enrollment_file.read_bytes() == Path(supplied_boot["launch_enrollment_file"]).read_bytes() and
                    enrollment_file.stat().st_uid == 0 and stat.S_IMODE(enrollment_file.stat().st_mode) == 0o444,
                    "protected launch enrollment bytes, owner or mode differ")
        else:
            require("launch_enrollment" not in boot, "diagnostic install invented launch enrollment")
        before = inventory(args.config, boot_module.socket_root(args.config))

        current = "check-readonly"
        checked = command("check", ["bash", str(entry), "--check", "--config", args.config])
        require(json.loads(checked.stdout)["verified"] is True, "check did not verify actual bundle")
        require(inventory(args.config, boot_module.socket_root(args.config)) == before, "acceptance: check wrote installed state")

        current = "repeat"
        install("repeat", args.boot)
        require(inventory(args.config, boot_module.socket_root(args.config)) == before, "acceptance: repeat rewrote installed state")

        current = "different-input"
        changed = json.loads(args.boot.read_bytes())
        changed["judge_endpoint"] += "/changed"
        changed_file = args.evidence / "changed-boot.json"
        changed_file.write_text(json.dumps(changed) + "\n")
        changed_file.chmod(0o600)
        command("different", ["bash", str(entry), "--install", "--config", args.config,
                             "--binary", str(args.binary), "--manifest", str(args.manifest),
                             "--boot", str(changed_file), "--evidence", str(args.evidence / "different")], expected=3)
        require(inventory(args.config, boot_module.socket_root(args.config)) == before, "acceptance: differing input overwrote installed state")

        current = "unsafe-mode"
        boot_file.chmod(0o666)
        try:
            command("unsafe", ["bash", str(entry), "--check", "--config", args.config], expected=3)
            require(stat.S_IMODE(boot_file.stat().st_mode) == 0o666, "check repaired unsafe mode")
        finally:
            boot_file.chmod(0o644)
        require(sha(boot_file) == before[str(boot_file)]["sha256"], "mode control changed boot bytes")
        current = "writable-source"
        copy = args.evidence / "source-control" / "scripts/v2-admin"
        copy.mkdir(mode=0o700, parents=True)
        for name in ("install.sh", "boot.py"):
            shutil.copyfile(args.source / "scripts/v2-admin" / name, copy / name)
        (copy / "boot.py").chmod(0o666)
        command("writable-source", ["bash", str(copy / "install.sh"), "--check", "--config", args.config], expected=3)
        passed = True
    except (AssertionError, OSError, ValueError, KeyError, subprocess.SubprocessError) as failure:
        reason = str(failure)
    (args.evidence / "result.json").write_text(json.dumps({"schema": "laneboss.boot-case.v2", "passed": passed,
        "stage": current, "reason": reason, "commands": records}, sort_keys=True, indent=2) + "\n")
    print("PASS: protected boot bundle" if passed else "FAIL: protected boot bundle")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Root namespace-entry acceptance; run only on disposable Ubuntu 24.04."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys


SWITCH = Path("/proc/sys/kernel") / "apparmor_restrict_unprivileged_userns"
CLONE = Path("/proc/sys/kernel") / "unprivileged_userns_clone"
PROFILE = Path("/etc/apparmor.d/laneboss-bwrap")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def switches():
    return {"restriction": SWITCH.read_bytes().decode(),
            "clone": CLONE.read_bytes().decode() if CLONE.exists() else None}


def snapshot(path):
    if not path.exists():
        return None
    require(path.is_file() and not path.is_symlink(), "unsafe profile object")
    info = path.stat()
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "mode": info.st_mode,
            "uid": info.st_uid, "gid": info.st_gid, "inode": info.st_ino, "mtime_ns": info.st_mtime_ns}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "root disposable Linux observer required")
    require(args.evidence.is_absolute() and not args.evidence.exists(), "new absolute evidence directory required")
    args.evidence.mkdir(mode=0o700, parents=True)
    args.evidence.chmod(0o700)
    script = args.source.resolve() / "scripts/v2-admin/namespace.sh"
    require(script.is_file(), "namespace entry is missing")
    ledger = args.evidence / "ledger"
    ledger.mkdir(mode=0o700)
    ledger.chmod(0o700)
    before = switches()
    profile_before = snapshot(PROFILE)
    records = []
    current = "setup"

    def command(label, argv):
        completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=600, check=False, cwd="/")
        (args.evidence / (label + ".stdout")).write_bytes(completed.stdout)
        (args.evidence / (label + ".stderr")).write_bytes(completed.stderr)
        (args.evidence / (label + ".exit")).write_text(str(completed.returncode) + "\n")
        return completed

    def invoke(label, mode):
        earlier = set(ledger.iterdir())
        completed = command(label, ["bash", str(script), mode, "--evidence", str(ledger)])
        added = set(ledger.iterdir()) - earlier
        require(len(added) == 1, "entry did not retain one invocation record")
        record_dir = added.pop()
        require(record_dir.stat().st_uid == os.geteuid() and record_dir.stat().st_mode & 0o777 == 0o700,
                "entry evidence directory is not private")
        result = json.loads((record_dir / "result.json").read_bytes())
        require(result["schema"] == "laneboss.namespace-setup.v2", "unknown entry result")
        require(result["exit_code"] == completed.returncode, "entry exit receipt differs")
        records.append({"label": label, "exit_code": completed.returncode, "result": result,
                        "record": record_dir.name})
        return completed, result

    passed, error = False, None
    try:
        current = "check-readonly"
        first, result = invoke("check-before", "--check")
        require(first.returncode in (0, 69), "initial check did not report readiness/prerequisite")
        require(result["ready"] == (first.returncode == 0), "check readiness contradicts its exit")
        require(snapshot(PROFILE) == profile_before and switches() == before, "check changed system policy")

        current = "install"
        installed, result = invoke("install", "--install")
        require(installed.returncode == 0 and result["ready"] is True, "namespace install failed")
        require(result["restriction"] == int(before["restriction"]), "installer inferred another restriction")
        require(result["switches_unchanged"] is True and switches() == before, "installer changed switches")
        profile_installed = snapshot(PROFILE)
        if int(before["restriction"]) == 0:
            require(profile_installed == profile_before and result["profile_action"] == "not_needed",
                    "restriction-zero install changed a profile")
        else:
            source = args.source / "packaging/v2/linux" / "laneboss-bwrap.apparmor"
            require(PROFILE.read_bytes() == source.read_bytes(), "installed profile read-back differs")

        current = "independent-probe"
        nobody = pwd.getpwnam("nobody")
        require(nobody.pw_uid != 0 and nobody.pw_gid != 0, "probe identity is privileged")
        prefix = ["/usr/bin/timeout", "--kill-after=2s", "15s", "/usr/bin/setpriv",
                  "--reuid=" + str(nobody.pw_uid), "--regid=" + str(nobody.pw_gid), "--clear-groups",
                  "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
                  "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C"]
        probe = command("outside-bwrap", prefix + ["/usr/bin/bwrap", "--die-with-parent", "--unshare-user",
                         "--unshare-pid", "--ro-bind", "/", "/", "--", "/usr/bin/true"])
        require(probe.returncode == 0, "entry claimed readiness while outside bwrap fails")

        current = "repeat-install"
        repeated, result = invoke("install-again", "--install")
        require(repeated.returncode == 0 and result["ready"] is True, "repeat installation failed")
        require(snapshot(PROFILE) == profile_installed, "repeat installation rewrote the profile")
        require(result["profile_action"] == ("unchanged" if int(before["restriction"]) == 1 else "not_needed"),
                "repeat installation unnecessarily reloaded the profile")
        current = "check-after"
        checked, result = invoke("check-after", "--check")
        require(checked.returncode == 0 and result["ready"] is True, "post-install check failed")
        require(snapshot(PROFILE) == profile_installed and switches() == before, "post-install check changed policy")

        current = "bad-source"
        copy = args.evidence / "bad-source"
        for relative in ("scripts/v2-admin/namespace.sh", "scripts/v2-admin/apparmor.sh"):
            target = copy / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(args.source / relative, target)
        bad = copy / "packaging/v2/linux" / "laneboss-bwrap.apparmor"
        bad.parent.mkdir(mode=0o700, parents=True)
        source = args.source / "packaging/v2/linux" / "laneboss-bwrap.apparmor"
        profile_source = source.read_bytes()
        require(profile_source.count(b"/usr/bin/bwrap") == 1, "broad-profile control did not identify one attachment")
        bad.write_bytes(profile_source.replace(b"/usr/bin/bwrap", b"/**", 1))
        declined = command("bad-source", ["bash", str(copy / "scripts/v2-admin/namespace.sh"),
                           "--install", "--evidence", str(ledger)])
        require(declined.returncode == 3, "broad source profile was not refused")
        require(snapshot(PROFILE) == profile_installed and switches() == before, "bad source changed system policy")
        passed = True
    except (AssertionError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as failure:
        error = str(failure)
    summary = {"schema": "laneboss.namespace-cli-case.v2", "passed": passed, "stage": current,
               "error": error, "invocations": records, "switches_before": before, "switches_after": switches()}
    (args.evidence / "result.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    print("PASS: namespace entry" if passed else "FAIL: namespace entry")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

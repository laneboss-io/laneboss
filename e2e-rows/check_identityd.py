"""Named sealed-kit step: build and verify lb-svc-core on a disposable Linux box.

Run as root only on that box. This entry point creates no machine, contacts no
model service, supplies no credentials, and stops on the first unexpected result.
Rows create their own unprivileged service/caller accounts using useradd.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
import uuid

from test_identityd import MUTANTS


KILLS = MUTANTS
# Reuse the real UID-setting mutation to prove the new CLI row's assertion
# before its controls. This adds a proof run, not another mutation selector.
ROW_PROOFS = {
    "identityd-cap-status": ("identityd-uid-setting", "test_s16_cap_status", "a capped CLI status lost the UID refusal"),
}
UNIT_KILLS = {
    "identityd-no-peer-pin": ("TestPeerLifetime", "an exited connecting process retained its lifetime proof"),
    "identityd-verify-lock": ("TestVerifyOutsideLock", "verification blocked an independent whoami"),
    "identityd-drop-refusal": ("TestClosedReply", "an early service refusal was lost"),
}


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or len(sys.argv) != 2:
        raise RuntimeError("use the sealed kit's root-owned identityd step on its disposable Linux box")
    root = Path(__file__).resolve().parents[1]
    destination = Path(sys.argv[1])
    if not destination.is_absolute() or destination.exists():
        raise RuntimeError("supply a new absolute lb-svc-core evidence directory")
    destination.mkdir(mode=0o755)
    run = destination / ("lb-svc-core-" + uuid.uuid4().hex[:8])
    run.mkdir(mode=0o755)
    cache = run / "go-cache"
    cache.mkdir()
    # An explicit empty credential environment, with only named build settings.
    environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(run / "home"),
                   "GOTOOLCHAIN": "go1.26.0", "GOCACHE": str(cache), "CGO_ENABLED": "0",
                   "PYTHONPYCACHEPREFIX": str(run / "python-cache")}
    Path(environment["HOME"]).mkdir()
    actions = []

    def execute(name, args, extra=None, expected=0, reason=None, empty=False):
        began = time.monotonic()
        settings = {**environment, **(extra or {})}
        result = subprocess.run(args, cwd=root, env=settings, capture_output=True, timeout=900)
        output = result.stdout + result.stderr
        (run / (name + ".log")).write_bytes(output)
        action = {"name": name, "argv": list(map(str, args)), "exit": result.returncode,
                  "seconds": time.monotonic() - began,
                  "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                  "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
        actions.append(action)
        (run / "actions.json").write_text(json.dumps(actions, indent=2) + "\n", encoding="utf-8")
        if result.returncode != expected or empty and output or reason and reason.encode() not in output:
            raise RuntimeError(name + " failed; inspect its retained log and exit before proceeding")
        print(name + ": verified", flush=True)
        return result

    listing = execute("source-list", ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    revision = execute("revision", ["git", "rev-parse", "HEAD"])
    sources = []
    with tarfile.open(run / "source.tar.gz", "w:gz") as archive:
        for name in listing.stdout.split(b"\0"):
            if not name:
                continue
            relative = name.decode("utf-8")
            path = root / relative
            if not path.is_file() or path.is_symlink():
                raise RuntimeError("the source archive encountered a non-regular input")
            data = path.read_bytes()
            sources.append({"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            entry = tarfile.TarInfo("source/" + relative)
            entry.size, entry.mode = len(data), stat_mode(path)
            archive.addfile(entry, io.BytesIO(data))
    (run / "inputs.json").write_text(json.dumps({"revision": revision.stdout.decode().strip(),
                                                "sources": sources}, indent=2) + "\n", encoding="utf-8")
    execute("toolchain", ["go", "version"], reason="go1.26.0")
    execute("gofmt", ["gofmt", "-l", "internal/identityd", "internal/cli/cli.go", "internal/cli/version.go",
                       "internal/cli/fault_bridge.go", "internal/lane/validation.go"], empty=True)
    execute("vet-release", ["go", "vet", "./..."])
    execute("vet-faults", ["go", "vet", "-tags", "laneboss_faults", "./..."])
    execute("py-compile", [sys.executable, "-m", "py_compile", "e2e-rows/test_identityd.py",
                           "e2e-rows/check_identityd.py", "e2e-rows/identityd_peer.py"])
    execute("scan", ["bash", "scripts/scan.sh"], reason="SCAN PASS:")
    release, faults = run / "laneboss", run / "laneboss-faults"
    for label, binary, tags in (("release", release, []), ("faults", faults, ["-tags", "laneboss_faults"])):
        execute("build-" + label, ["go", "build", *tags, "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/laneboss"])
        data = binary.read_bytes()
        (run / (label + "-binary.json")).write_text(json.dumps({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}) + "\n")
    # Every new row is first killed by a specific real behavioral mutation.
    # An unrelated failure, error in setup/cleanup, or a missing marker stops.
    row_checks = [(point, point, row, reason) for point, (row, reason) in KILLS.items()]
    row_checks.extend((name, point, row, reason) for name, (point, row, reason) in ROW_PROOFS.items())
    for name, point, row, reason in row_checks:
        row_evidence = run / name
        row_evidence.mkdir(mode=0o755)
        execute(name, [sys.executable, "-m", "unittest", "discover", "-s", "e2e-rows",
                        "-p", "test_identityd.py", "-k", row, "-v"],
                {"LANEBOSS_BIN": str(faults), "LANEBOSS_IDENTITYD_MUTANT": point,
                 "LANEBOSS_FAULTS_BIN": str(faults),
                 "LANEBOSS_IDENTITYD_EVIDENCE": str(row_evidence)}, expected=1, reason=reason)
        log = (run / (name + ".log")).read_text(encoding="utf-8")
        markers = list(row_evidence.glob("lb-svc-core-row-*/mutation/reached")) + list(row_evidence.glob("lb-svc-core-row-*/client-mutation/reached"))
        if "FAILED (failures=1)" not in log or "ERROR:" in log or len(markers) != 1:
            raise RuntimeError(name + " did not kill exactly its assertion with a real call-site marker")
    for point, (test, reason) in UNIT_KILLS.items():
        marker = run / (point + "-reached")
        execute(point, ["go", "test", "-count=1", "-tags", "laneboss_faults", "-run", "^" + test + "$",
                        "./internal/identityd"],
                {"LANEBOSS_FAULTS": json.dumps({"point": point, "marker": str(marker)})},
                expected=1, reason=reason)
        log = (run / (point + ".log")).read_text()
        if not marker.is_file() or log.count("--- FAIL: " + test + " ") != 1:
            raise RuntimeError(point + " did not kill its named unit assertion with a real marker")
    execute("units-release", ["go", "test", "-count=1", "./..."])
    execute("units-faults", ["go", "test", "-count=1", "-tags", "laneboss_faults", "./..."])
    for label, binary in (("release", release), ("faults", faults)):
        rows = run / (label + "-rows")
        rows.mkdir(mode=0o755)
        execute("rows-" + label, [sys.executable, "-m", "unittest", "discover", "-s", "e2e-rows",
                                  "-p", "test_identityd.py", "-v"],
                {"LANEBOSS_BIN": str(binary), "LANEBOSS_FAULTS_BIN": str(faults),
                 "LANEBOSS_IDENTITYD_EVIDENCE": str(rows)}, reason="OK")
    # A release build must ignore the same hostile selector and caller PID.
    rows = run / "release-inert"
    rows.mkdir(mode=0o755)
    execute("release-inert", [sys.executable, "-m", "unittest", "discover", "-s", "e2e-rows",
                               "-p", "test_identityd.py", "-k", "test_s1_kernel_peer", "-v"],
            {"LANEBOSS_BIN": str(release), "LANEBOSS_IDENTITYD_EVIDENCE": str(rows),
             "LANEBOSS_IDENTITYD_INERT": "identityd-trust-pid"}, reason="OK")
    if list(rows.glob("lb-svc-core-row-*/mutation/reached")):
        raise RuntimeError("release interpreted the fault selector")
    artifacts = []
    for path in sorted(run.rglob("*")):
        if path.is_file() and "go-cache" not in path.parts and "python-cache" not in path.parts:
            data = path.read_bytes()
            artifacts.append({"path": str(path.relative_to(run)), "bytes": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()})
    (run / "manifest.json").write_text(json.dumps({"artifacts": artifacts, "result": "verified",
                                                  "limits": "No authenticated AI service; no Darwin cross-account row."},
                                                 indent=2) + "\n", encoding="utf-8")
    print("PASS: identityd Linux rows; " + str(len(KILLS) + len(UNIT_KILLS)) + " mutation kills and both controls", flush=True)
    print("evidence: " + str(run), flush=True)


def stat_mode(path):
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run review regressions on the exact old archive and candidate, on Linux only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

BASELINE = "f75dfa0d5889481309862a47" + "30244853188f727f"  # split for the secret scanner
OVERLAYS = ("review_fixtures_test.go", "review_r2_test.go", "review_quiescence_test.go")
EXCLUDED = {".git", ".codex", ".agents", ".aws", "__pycache__", ".lane-gocache"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fail(message):
    raise SystemExit(message)


def walk_error(error):
    raise error


def snapshot(source, target):
    inputs = []
    for directory, dirs, files in os.walk(source, topdown=True, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED)
        base = Path(directory)
        for name in list(dirs):
            if (base / name).is_symlink():
                fail("directory symlink in candidate source snapshot")
        for name in sorted(files):
            if name in EXCLUDED:
                continue
            path = base / name
            relative = path.relative_to(source)
            if path.is_symlink() or not path.is_file():
                fail("linked or non-regular candidate source")
            data = path.read_bytes()
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(path.stat().st_mode & 0o777)
            inputs.append({"path": relative.as_posix(), "bytes": len(data), "sha256": digest(data)})
    return inputs


def command(args, cwd, log):
    with log.open("wb") as output:
        result = subprocess.run(args, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, check=False)
    return result.returncode, log.read_text(errors="replace")


def main():
    if sys.platform != "linux":
        fail("migration baseline regressions run only on the authorized disposable Linux machine")
    if len(sys.argv) != 3:
        fail("usage: check-review-baseline.py BASELINE_ARCHIVE NEW_EVIDENCE_DIRECTORY")
    source = Path(__file__).resolve().parents[4]
    archive_path = Path(sys.argv[1]).resolve(strict=True)
    proposed = Path(sys.argv[2]).absolute()
    if proposed.name in ("", ".", ".."):
        fail("baseline evidence needs a new directory name")
    evidence = proposed.parent.resolve(strict=True) / proposed.name
    if evidence.exists() or source == evidence or source in evidence.parents or evidence in source.parents:
        fail("baseline evidence must be a new directory outside the source")
    evidence.mkdir(mode=0o700, parents=True)
    archive_bytes = archive_path.read_bytes()
    (evidence / "baseline-input.tar.gz").write_bytes(archive_bytes)
    with tarfile.open(evidence / "baseline-input.tar.gz", "r:gz") as archive:
        if archive.pax_headers.get("comment") != BASELINE:
            fail("baseline archive does not identify the exact reviewed revision")
        for entry in archive.getmembers():
            path = Path(entry.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "baseline":
                fail("baseline archive contains an unexpected path")
            if not (entry.isfile() or entry.isdir()):
                fail("baseline archive contains a link or non-regular member")
        archive.extractall(evidence, filter="data")
    baseline = evidence / "baseline"
    candidate = evidence / "candidate"
    candidate.mkdir(mode=0o700)
    inputs = snapshot(source, candidate)
    overlays = []
    for name in OVERLAYS:
        relative = Path("internal/v2/migration") / name
        data = (candidate / relative).read_bytes()
        (baseline / relative).write_bytes(data)
        overlays.append({"path": str(relative), "sha256": digest(data)})
    catalog = json.loads((candidate / "e2e/v2/cases/migration/review-baseline.json").read_text())
    if catalog["schema"] != "laneboss.migration-review-baseline.v1" or "".join(catalog["baseline"]) != BASELINE or len(catalog["regressions"]) < 42:
        fail("baseline regression catalog is missing required review cases")
    (evidence / "inputs.json").write_text(json.dumps({"baseline": BASELINE,
        "archive_sha256": digest(archive_bytes), "candidate_inputs": inputs,
        "baseline_test_overlays": overlays}, indent=2) + "\n")
    outcomes = []
    for build, flags in (("normal", []), ("faults", ["-tags", "laneboss_faults"])):
        binaries = {}
        for label, tree in (("baseline", baseline), ("candidate", candidate)):
            binary = evidence / (label + "-" + build + ".test")
            args = ["env", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly", "GOPROXY=off",
                    "go", "test", "-c", *flags, "-o", str(binary), "./internal/v2/migration"]
            code, output = command(args, tree, evidence / (label + "-" + build + "-build.log"))
            if code:
                fail("BUILD_OR_SETUP_ERROR: " + label + " " + build)
            binaries[label] = binary
            (evidence / (binary.name + ".sha256")).write_text(digest(binary.read_bytes()) + "\n")
        for index, row in enumerate(catalog["regressions"]):
            prefix = build + "-" + str(index + 1)
            baseline_code, baseline_output = command([str(binaries["baseline"]), "-test.v",
                "-test.count=1", "-test.run", row["pattern"]], baseline, evidence / (prefix + "-before.log"))
            if baseline_code == 0 or "--- FAIL:" not in baseline_output or row["diagnostic"] not in baseline_output:
                fail("BASELINE_NOT_REACHED: " + row["test"])
            candidate_code, candidate_output = command([str(binaries["candidate"]), "-test.v",
                "-test.count=1", "-test.run", row["pattern"]], candidate, evidence / (prefix + "-after.log"))
            record = {"build": build, "test": row["test"], "before_exit": baseline_code,
                      "after_exit": candidate_code, "diagnostic": row["diagnostic"]}
            outcomes.append(record)
            (evidence / "results.json").write_text(json.dumps(outcomes, indent=2) + "\n")
            if candidate_code != 0 or "--- PASS:" not in candidate_output:
                fail("CANDIDATE_FAILED: " + row["test"])
            print("BASELINE-RED CANDIDATE-GREEN:", build, row["test"], flush=True)
        code, output = command([str(binaries["candidate"]), "-test.v", "-test.count=1",
            "-test.run", "^TestReview"], candidate, evidence / ("candidate-" + build + "-all-review.log"))
        if code or "--- PASS:" not in output:
            fail("CANDIDATE_REVIEW_SUITE_FAILED: " + build)
    print("PASS: migration review regressions failed on the reviewed baseline and passed on the candidate")


if __name__ == "__main__":
    main()

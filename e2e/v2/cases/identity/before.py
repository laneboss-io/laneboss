"""Linux-only base/candidate qualification with identical identity test bytes.

The supervisor supplies the nominated base source and candidate source. Only
candidate *_test.go files in the owned identity package overlay a disposable
base snapshot. No production source, original checkout or Git index is edited.
This is supporting package evidence, never installed serve acceptance.
"""

import argparse
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

from controls import (CASE, PACKAGES, ControlError, archive_source, assess_test,
                      atomic_json, build, collect_children, command, copy_source,
                      enable_subreaper, inventory, reference, run_test, tree_digest,
                      validate_case)


def overlay_tests(base, candidate, base_files, candidate_files):
    package = PACKAGES["identity"]
    selected = {name for name in candidate_files
                if Path(name).parent == package and name.endswith("_test.go")}
    prior = {name for name in base_files
             if Path(name).parent == package and name.endswith("_test.go")}
    if not selected or prior - selected:
        raise ControlError("base test removal is not a permitted overlay")
    for name in sorted(selected):
        (base / name).write_bytes((candidate / name).read_bytes())
        (base / name).chmod(candidate_files[name]["mode"])
    changed = inventory(base)
    if changed.keys() != base_files.keys() | selected:
        raise ControlError("base overlay changed an unexpected file set")
    if any(changed[name] != details for name, details in base_files.items()
           if name not in selected):
        raise ControlError("base overlay changed production or another input")
    if any(changed[name] != candidate_files[name] for name in selected):
        raise ControlError("base and candidate tests are not identical")
    return changed, sorted(selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-source", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--base-revision", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--tags", choices=["normal", "laneboss_faults", "both"], default="both")
    parser.add_argument("--case-plan", choices=["before-cases.json", "fix10-before-cases.json", "fix11-before-cases.json", "fix14-before-cases.json"], default="before-cases.json")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run only on the authorized disposable Linux test box")
    base, candidate = args.base_source.resolve(strict=True), args.source.resolve(strict=True)
    root = args.work_root.absolute()
    if base == candidate or root.exists() or not root.name.startswith("lb-v2-identity-") or \
            root.is_relative_to(base) or root.is_relative_to(candidate):
        parser.error("use distinct sources and a new lane-named evidence root outside both")
    if root.parent.resolve(strict=True) != root.parent or root.is_symlink():
        parser.error("evidence parent must be physically resolved")
    if any(not re.fullmatch(r"[a-f0-9]{7,64}", value)
           for value in [args.base_revision, args.revision]):
        parser.error("record the actual base and candidate revisions")
    enable_subreaper()
    root.mkdir(mode=0o700)
    report = {"schema": "laneboss.identity-before.v1", "scope": "package-fixture",
              "base_revision": args.base_revision, "source_revision": args.revision,
              "platform": {"system": sys.platform, "release": platform.release(),
                           "machine": platform.machine()}, "results": [], "status": "incomplete"}
    stage = "snapshot"
    try:
        original_base, original_candidate = inventory(base), inventory(candidate)
        red, green = root / "base-source", root / "candidate-source"
        copy_source(base, red, original_base)
        copy_source(candidate, green, original_candidate)
        archive_source(red, root / "original-base.tar.gz", original_base)
        atomic_json(root / "original-base-files.json", original_base)
        red_files, overlay = overlay_tests(red, green, original_base, original_candidate)
        report["test_overlay"] = overlay
        report["base_sha256"], report["candidate_sha256"] = tree_digest(red_files), tree_digest(original_candidate)
        atomic_json(root / "base-files.json", red_files)
        atomic_json(root / "candidate-files.json", original_candidate)
        archive_source(red, root / "base-with-tests.tar.gz", red_files)
        archive_source(green, root / "candidate.tar.gz", original_candidate)
        report["archives"] = [reference(root, root / name) for name in
                              ["original-base.tar.gz", "base-with-tests.tar.gz", "candidate.tar.gz"]]
        version = command(root, green, root / "go-version", ["go", "version"], 30)
        if version["exit"] != 0:
            raise ControlError("Go version query failed")
        report["go_version"] = version
        plan = json.loads((green / CASE / args.case_plan).read_bytes())
        if plan["schema"] != "laneboss.identity-before-cases.v1" or not plan["cases"]:
            raise ControlError("missing before-change case catalog")
        if not args.base_revision.startswith(plan["base"]):
            raise ControlError("base revision differs from the nominated before-change source")
        if len({case["id"] for case in plan["cases"]}) != len(plan["cases"]):
            raise ControlError("duplicated before-change case")
        for case in plan["cases"]:
            validate_case(case)
            if case["package"] != "identity" or not case["diagnostic"]:
                raise ControlError("before-change cases require a named identity assertion")
        modes = ["normal", "laneboss_faults"] if args.tags == "both" else [args.tags]
        for tags in modes:
            stage = tags + "/base-build"
            red_build = build(root, red, root / tags / "base-build", "identity", tags)
            green_build = None
            for case in plan["cases"]:
                stage = tags + "/" + case["id"]
                directory = root / tags / case["id"]
                directory.mkdir(parents=True)
                row = {"id": case["id"], "target": "/".join(case["test"]), "tags": tags,
                       "status": "incomplete", "base_build": red_build}
                report["results"].append(row)
                atomic_json(root / "report.json", report)
                row["base"] = run_test(root, red, directory / "base", "identity", case["test"], red_build)
                assess_test(row["base"], row["base"]["observation"], case["test"],
                            red=True, diagnostic=case["diagnostic"])
                row["status"] = "base-refuted"
                atomic_json(root / "report.json", report)
                if green_build is None:
                    stage = tags + "/candidate-build"
                    green_build = build(root, green, root / tags / "candidate-build", "identity", tags)
                    if green_build["binary"]["sha256"] == red_build["binary"]["sha256"]:
                        raise ControlError("base and candidate binaries are identical")
                stage = tags + "/" + case["id"]
                row["candidate_build"] = green_build
                row["candidate"] = run_test(root, green, directory / "candidate", "identity", case["test"], green_build)
                assess_test(row["candidate"], row["candidate"]["observation"], case["test"])
                if inventory(red) != red_files or inventory(green) != original_candidate or \
                        inventory(base) != original_base or inventory(candidate) != original_candidate:
                    raise ControlError("source or immutable test bytes changed during qualification")
                row["status"] = "qualified"
                atomic_json(root / "report.json", report)
                print(json.dumps({"id": case["id"], "tags": tags, "status": "qualified"}), flush=True)
        report["collection"] = collect_children()
        if not report["collection"]["quiescent"] or report["collection"]["observed"]:
            raise ControlError("qualification left an owned descendant")
        report["status"] = "passed"
    except (ControlError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["status"] = "failed"
        report["failure"] = {"stage": stage, "type": type(error).__name__, "message": str(error)}
        try:
            report["collection"] = collect_children()
        except (ControlError, OSError) as collection_error:
            report["collection"] = {"quiescent": False, "error": str(collection_error)}
        print(json.dumps({"stage": stage, "status": "failed"}), flush=True)
    atomic_json(root / "report.json", report)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())

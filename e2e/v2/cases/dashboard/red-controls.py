"""Linux-only dashboard controls, with retained compiling mutants and verdicts."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys


def python_verdict(result, test, red, diagnostic):
    stderr = result.stderr.decode("utf-8", "replace")
    method = test.rsplit(".", 1)[-1]
    expected = 1 if red else 0
    if result.returncode != expected or "Ran 1 test" not in stderr or "ERROR" in stderr:
        raise RuntimeError("Python control did not reach its single named verdict")
    if red:
        if "FAIL: " + method not in stderr or diagnostic not in stderr:
            raise RuntimeError("Python control missed its intended assertion")
    elif "\nOK\n" not in stderr:
        raise RuntimeError("Python candidate did not pass its named assertion")


def web_verdict(result, red, diagnostic):
    stderr = result.stderr.decode("utf-8", "replace")
    if red:
        if result.returncode != 1 or "AssertionError" not in stderr or diagnostic not in stderr:
            raise RuntimeError("Web control did not reach its intended assertion")
    elif result.returncode != 0 or result.stdout.decode().strip() != "PASS: dashboard presence rows" or stderr:
        raise RuntimeError("Web candidate did not pass its renderer assertions")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run only on the authorized disposable Linux test machine")
    source = args.source.resolve(strict=True)
    evidence = args.evidence.resolve()
    if evidence.is_relative_to(source) or source.is_relative_to(evidence):
        parser.error("source and evidence must be disjoint")
    evidence.mkdir(parents=True)
    helper_path = source / "e2e/v2/cases/integrate/red-controls.py"
    spec = importlib.util.spec_from_file_location("integrate_controls", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    manifest = Path(__file__).with_name("controls.json")
    controls = helper.launch_plan_controls(manifest)
    (evidence / "controls.json").write_bytes(manifest.read_bytes())
    for name, command in (("go", ["go", "version"]), ("python", [sys.executable, "--version"]), ("node", ["node", "--version"])):
        version = helper.run(command, source, evidence / ("version-" + name))
        if version.returncode != 0:
            raise RuntimeError("required control tool is unavailable")
    results = []
    for name, package, test, diagnostic, relative, edits in controls:
        mutant = evidence / name / "source"
        shutil.copytree(source, mutant, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        path = mutant / (relative if package in ("python", "web", "webgo") else "internal/v2/" + relative)
        path.resolve().relative_to(mutant.resolve())
        before = path.read_text()
        after = before
        for old, new in edits:
            after = helper.replace(after, old, new)
        path.write_text(after)
        (mutant.parent / "mutation.json").write_text(json.dumps({
            "file": str(path.relative_to(mutant)), "test": test, "edits": edits,
            "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
        }, indent=2) + "\n")
        if package == "python":
            command = [sys.executable, "-m", "unittest", "-v", "test_case." + test]
            red_source = mutant / "e2e/v2/cases/dashboard"
            candidate_source = source / "e2e/v2/cases/dashboard"
        elif package == "web":
            command = ["node", "e2e/v2/cases/dashboard/web-test.cjs"]
            red_source, candidate_source = mutant, source
        else:
            command = helper.go_command("dashboard" if package == "webgo" else package, test)
            if package == "webgo":
                command[-1] = "./web/v2"
            red_source, candidate_source = mutant, source
        red = helper.run(command, red_source, mutant.parent / "red")
        if package == "python":
            python_verdict(red, test, True, diagnostic)
        elif package == "web":
            web_verdict(red, True, diagnostic)
        else:
            helper.go_verdict(red, test, 1, diagnostic)
        candidate = helper.run(command, candidate_source, mutant.parent / "candidate")
        if package == "python":
            python_verdict(candidate, test, False, "")
        elif package == "web":
            web_verdict(candidate, False, "")
        else:
            helper.go_verdict(candidate, test, 0)
        results.append({"id": name, "test": test, "red_exit": red.returncode, "candidate_exit": candidate.returncode})
        (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print("PASS red/candidate " + name, flush=True)
    print("PASS: dashboard draft.4 controls", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

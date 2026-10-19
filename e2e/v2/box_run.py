"""Parent controller: source install, isolated unittest child, archive, harvest."""

import argparse
import os
from pathlib import Path
import signal
import sys
import uuid

from artifacts import finish
import box
from box_support import Recorder, audit_service_commands
from diagnostics import public_error, summary_line
from suite import module_paths, validate_child
from support import (Failure, ROOT, clean_environment, require, require_linux, save)
from toolchain import resolve_go


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", required=True, type=Path)
    parser.add_argument("--go", type=Path)
    parser.add_argument("--lane", default="lb-v2-e2e")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--red-fixture", choices=("stubborn",))
    parser.add_argument("modules", nargs="*")
    args = parser.parse_args()
    summary = {"outcome": "setup-error", "exit_code": 2, "tests_run": 0,
               "failures": 0, "errors": 0, "selected_test_ids": [],
               "cleanup_ok": False, "artifact_collection_ok": False}
    directory = None

    def interrupted(_number, _frame):
        raise KeyboardInterrupt()

    try:
        require_linux()
        os.umask(0o077)
        module_paths(ROOT / "e2e" / "v2" / "product", args.modules)
        directory = box.run_directory(args.lane, uuid.uuid4().hex[:8])
        compiler = resolve_go(args.go)
        save(directory / "evidence" / "invocation.json", {
            "source_revision": args.source_revision, "modules": args.modules,
            "lane": args.lane, "kit": str(args.kit),
            "go_path": str(compiler.path), "go_sha256": compiler.sha256,
            "go_selection": compiler.selection,
            "red_fixture": args.red_fixture or ""})
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGHUP, interrupted)
        context = box.setup(directory, args.kit, compiler)
        if args.red_fixture == "stubborn":
            box.kit_step(directory, args.kit, "start-stubborn")
        recorder = Recorder(directory / "evidence" / "cmd")
        result = recorder.run([
            sys.executable, "-B", str(ROOT / "e2e" / "v2" / "suite_child.py"),
            "--directory", str(directory), "--kit", str(args.kit), *args.modules],
            label="unittest-child", timeout=7200,
            environment=clean_environment(directory / "controller-home",
                                          directory / "controller-tmp"))
        child = validate_child(directory / "evidence" / "selected-tests.json",
                               directory / "evidence" / "child-result.json",
                               result.returncode)
        audit_service_commands(directory)
        summary.update({"tests_run": child["tests_run"], "failures": child["failures"],
                        "errors": child["errors"], "selected_test_ids": child["selected_ids"],
                        "exit_code": 0 if child["successful"] else 1,
                        "outcome": "passed" if child["successful"] else "failed"})
        if child["successful"]:
            # A crash after the smoke/last test cannot be a passing run.
            context.assert_live()
            final_health = context.readiness()
            require(final_health.returncode == 0 and final_health.json().get("ready") is True,
                    "service failed the final independent health check")
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        summary.update({"outcome": "interrupted" if isinstance(error, KeyboardInterrupt)
                        else "setup-error", "exit_code": 130 if isinstance(error, KeyboardInterrupt)
                        else 2, "diagnostic": str(error),
                        "public_diagnostic": public_error(error)})
        if isinstance(error, Failure):
            summary["error"] = error.wire()
    finally:
        if directory is not None:
            try:
                if (directory / "resources.json").exists():
                    box.kit_step(directory, args.kit, "teardown")
                summary["cleanup_ok"] = True
            except (Exception, KeyboardInterrupt) as error:
                summary.update({"exit_code": 2, "outcome": "cleanup-error",
                                "cleanup_diagnostic": str(error),
                                "public_diagnostic": "fixture collection failed: " +
                                public_error(error)})
            try:
                box.retain_binary(directory)
            except (Exception, KeyboardInterrupt) as error:
                summary.update({"exit_code": 2, "outcome": "evidence-error",
                                "binary_diagnostic": str(error),
                                "public_diagnostic": "binary evidence collection failed"})
            summary["run_directory"] = str(directory)
            finish(directory, summary, args.out)
            print("E2E evidence directory: " + str(directory))
    print(summary_line(summary))
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())

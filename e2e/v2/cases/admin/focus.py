"""Namespace-only outside acceptance; no service or launch contract is needed."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("namespace observer requires unprivileged disposable Linux")
    module_file = Path(__file__).with_name("run.py")
    spec = importlib.util.spec_from_file_location("admin_case", module_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    context = module.load(args.context)
    module.require(context["schema"] == "laneboss.e2e-context.v2" and context["case_id"] == "admin",
                   "invalid namespace context")
    root = Path(context["test_root"])
    result_file = module.beneath(args.result, root)
    fixture = module.load(root / "admin-input.json")
    observer = module.Observer(context, fixture, result_file)
    observer.keep("inputs/context.json", Path(args.context).read_bytes())
    observer.keep("inputs/admin-input.json", (root / "admin-input.json").read_bytes())
    verdict, reason, failed_label, receipt, failed_command = "fail", "not reached", "setup", None, None
    try:
        observer.userns()
    except (module.Failed, OSError, ValueError, KeyError, TypeError) as failure:
        reason = str(failure)
        failed_label = observer.last_label
        failed_command = observer.last_command
        # Retain the stopped step's actual receipt, without proceeding to any
        # launch, retry, overwrite or profile cleanup after its failure.
        if observer.profile_evidence is not None and observer.profile_evidence.exists():
            completed = observer.command("stopped-profile-receipt", ["sudo", "-n", "cat",
                                         str(observer.profile_evidence / "result.json")])
            if completed.returncode == 0:
                receipt = json.loads(completed.stdout)
    else:
        verdict, reason, failed_label = "pass", "namespace controls passed", "completed"
    after_switches = observer.switches()
    observer.keep_json("focus-sysctls.after.json", after_switches)
    before_path = Path(context["evidence_root"]) / "sysctls.before.json"
    switches_unchanged = before_path.is_file() and module.load(before_path) == after_switches
    summary = {"schema": "laneboss.admin-focus.v2", "test": "UBUNTU-USERNS",
               "verdict": verdict, "failed_label": failed_label, "reason": reason,
               "profile_receipt": receipt, "failed_command": failed_command,
               "switches_unchanged": switches_unchanged,
               "processes_quiescent": observer.commands_quiescent,
               "evidence": observer.refs}
    observer.keep_json("focus-summary.json", summary)
    pending = result_file.with_suffix(".pending")
    with pending.open("x") as stream:
        json.dump(summary, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(result_file)
    print("%s: UBUNTU-USERNS" % ("PASS" if verdict == "pass" else "FAIL"))
    return 0 if verdict == "pass" and observer.commands_quiescent and switches_unchanged else 1


if __name__ == "__main__":
    raise SystemExit(main())

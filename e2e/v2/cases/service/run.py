"""Installed CLI/socket SERVE-STATE driver. Run only on the authorized Linux box."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess

from scenario import Blocked, Failed, Scenario


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("the installed service case runs only on the authorized Linux box")
    if not args.context.is_absolute() or not args.result.is_absolute():
        parser.error("harness paths must be absolute")
    raw = args.context.read_bytes()
    context = json.loads(raw)
    if context["schema"] != "laneboss.e2e-context.v2" or context["case_id"] != "service":
        parser.error("wrong harness context")
    root = Path(context["test_root"]).resolve(strict=True)
    args.result.resolve().relative_to(root)
    evidence = Path(context["evidence_root"])
    if not evidence.is_absolute():
        parser.error("evidence path must be absolute")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    scenario = Scenario(context, evidence)
    scenario.keep("context.json", raw)
    failure, exit_code = None, 1
    try:
        scenario.run()
        exit_code = 0 if scenario.complete() else 69
    except Blocked as error:
        failure, exit_code = str(error), 69
    except (Failed, OSError, ValueError, TimeoutError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure, exit_code = str(error), 1
    finally:
        observation = {"steps": scenario.steps, "failed_step": scenario.current,
                       "reason": failure, "commands": scenario.commands,
                       "scope": "actual installed CLI/socket; no constructor fixture or SQL access"}
        scenario.keep("observations.json", json.dumps(observation, indent=2).encode() + b"\n")
        references = []
        for path in sorted(evidence.iterdir()):
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                references.append({"path": path.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        result = {"schema": "laneboss.e2e-result.v2", "case_id": "service", "phase": context["phase"],
                  "mutation_id": context["mutation_id"], "binary_sha256": context["binary_sha256"],
                  "source_sha256": context["source_sha256"],
                  "assertions": [{"id": "SERVE-STATE", "reached": scenario.complete(),
                                  "verdict": "pass" if exit_code == 0 and scenario.complete() else "fail",
                                  "observed_exit": exit_code, "evidence": references}],
                  "collection": {"processes_quiescent": scenario.quiescent,
                                 "temporary_resources_collected": scenario.complete() and scenario.quiescent,
                                 "evidence": references}}
        temporary = args.result.with_suffix(".pending")
        temporary.write_text(json.dumps(result, indent=2) + "\n")
        os.replace(temporary, args.result)
    if failure:
        print("SERVE-STATE " + scenario.current + ": " + failure, flush=True)
    elif exit_code == 0:
        print("PASS: installed SERVE-STATE", flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

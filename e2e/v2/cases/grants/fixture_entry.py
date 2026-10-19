"""Dispatcher unit fixture: measures file IO and a real cat child only.

It is never an installed grants case and supplies no product acceptance.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

import observer


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    context = json.loads(args.context.read_bytes())
    test, output = Path(context["test_root"]), Path(context["evidence_root"])
    plan = json.loads((test / "entry-plan.json").read_bytes())
    payload = (test / "payload.bin").read_bytes()
    with subprocess.Popen(["/bin/cat", str(test / "payload.bin")],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        stdout, stderr = child.communicate(timeout=10)
        worker = {"pid": child.pid, "exit_code": child.returncode,
                  "payload_sha256": sha(stdout), "nonce": plan["nonce"]}
    resource = output / "unit-resource"
    resource.write_bytes(stdout)
    (output / "worker.json").write_text(json.dumps(worker))
    (output / "unit-output.bin").write_bytes(stdout)
    ref = {"path": "unit-output.bin", "sha256": sha(stdout), "bytes": len(stdout)}
    measured = [sha(Path(context["binary"]).read_bytes()) == context["binary_sha256"],
                child.returncode == 0 and stdout == payload and not stderr]
    assertions = [{"id": name, "reached": True,
                   "verdict": "pass" if measured[index] else "fail",
                   "observed_exit": child.returncode, "evidence": [ref]}
                  for index, name in enumerate(plan["assertion_ids"])
                  if name != plan.get("drop")]
    receipt = observer.exchange({"action": "collect", "operation_ids": []})
    result = {"schema": "laneboss.e2e-result.v2", "case_id": context["case_id"],
              "phase": context["phase"], "mutation_id": context["mutation_id"],
              "binary_sha256": context["binary_sha256"], "source_sha256": context["source_sha256"],
              "assertions": assertions, "collection": {
                  key: receipt[key] for key in
                  ("processes_quiescent", "temporary_resources_collected", "evidence")}}
    args.result.write_text(json.dumps(result))
    print("unit child observed", worker["nonce"], worker["payload_sha256"])
    return plan.get("exit_code", 0) or (0 if all(measured) else 1)


if __name__ == "__main__":
    raise SystemExit(main())

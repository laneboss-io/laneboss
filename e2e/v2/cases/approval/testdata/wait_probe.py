"""Exercise real harness wait/reporting behavior without a human ceremony."""

import json
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from case import Case

root = Path(sys.argv[2])
case = Case({"evidence_root": str(root), "phase": "candidate", "mutation_id": "", "config": "wait-case", "binary": sys.executable})
case.f = {}
if sys.argv[3] == "wait":
    try:
        case.helper("confirm", [], "owner-review")
        raise AssertionError("missing human confirmation continued")
    except Exception as error:
        print(json.dumps({"code": getattr(error, "code", None),
                          "wait_for": getattr(error, "wait_for", None),
                          "type": type(error).__name__}))
else:
    case.simulated_presence = True
    case.summary("running")
    summary = json.loads(next((root / "approval").glob("summary-*.json")).read_bytes())
    print(json.dumps(summary))

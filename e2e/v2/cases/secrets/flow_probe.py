"""Native test driver for the real installed-CLI handoff adapter.

The caller supplies the protected component context and human/session facts.
This driver performs no enrollment, confirmation or secret-owner operation.
"""

import importlib.util
import json
from pathlib import Path
import sys


spec = importlib.util.spec_from_file_location("secret_flow_case", Path(__file__).with_name("run.py"))
case = importlib.util.module_from_spec(spec)
spec.loader.exec_module(case)
inputs = json.loads(Path(sys.argv[1]).read_bytes())
result = {"assertions": [{"evidence": []}]}
code, _, _ = case.flow_process(inputs["context"], inputs["steps"], Path(inputs["plan"]), result)
case.atomic_json(Path(inputs["context"]["evidence_root"]) / "probe-result.json", result)
raise SystemExit(code)

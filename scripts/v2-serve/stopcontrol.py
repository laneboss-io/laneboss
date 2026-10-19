"""Rebuild the installed suite with only the late-release fix removed."""

import importlib.util
from pathlib import Path
import sys


spec = importlib.util.spec_from_file_location("stop_serve", Path(__file__).with_name("run.py"))
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)
archive = serve.Case.archive


def control(case):
    result = archive(case)
    path = case.stage / "internal/v2/admin/credstop.go"
    original = path.read_bytes()
    fixed = b'(reason == "revoked" || reason == "release")'
    serve.require(original.count(fixed) == 1, "late-stop control anchor is missing or ambiguous")
    changed = original.replace(fixed, b'reason == "revoked"', 1)
    # This is the disposable build copy; the candidate stays unchanged. The
    # original source archive and this explicit mutation describe the control.
    path.write_bytes(changed)
    serve.require(path.read_bytes() == changed, "late-stop control writeback differs")
    case.keep_json("stop-control.json", {"path": "internal/v2/admin/credstop.go",
        "before": fixed.decode(), "after": 'reason == "revoked"',
        "original_sha256": serve.provision.sha(original),
        "control_sha256": serve.provision.sha(changed)})
    return result


serve.Case.archive = control
if __name__ == "__main__":
    sys.exit(serve.main())

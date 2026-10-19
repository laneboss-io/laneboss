"""Bounded public summary text; arbitrary exception strings stay in evidence."""

import json

from support import Failure
from toolchain import ToolchainError


def public_error(error):
    if isinstance(error, ToolchainError):
        return error.public_diagnostic
    if isinstance(error, KeyboardInterrupt):
        return "fixture run was interrupted"
    if isinstance(error, OSError):
        number = error.errno if isinstance(error.errno, int) else "unknown"
        return "operating system error (errno {})".format(number)
    if isinstance(error, Failure):
        descriptions = {
            "prerequisite_missing": "a required fixture prerequisite is missing",
            "deadline_exceeded": "a fixture command exceeded its deadline",
            "unsupported": "the fixture host is unsupported",
            "integrity": "a fixture integrity check failed",
            "invalid_request": "a fixture input is invalid",
            "containment_unknown": "process containment is unknown",
        }
        return descriptions.get(error.code, "a fixture check failed")
    return "fixture infrastructure failed"


def summary_line(summary):
    # These fields are populated with public_error's fixed vocabulary or the
    # fixed phase messages below. Never reflect raw exception/argv/env strings.
    diagnostic = summary.get("public_diagnostic", "none")
    if summary["outcome"] == "evidence-error":
        diagnostic = "evidence collection or read-back failed"
    elif summary["outcome"] == "failed" and diagnostic == "none":
        diagnostic = "product assertions failed"
    diagnostic = json.dumps(diagnostic[:240], ensure_ascii=True)
    return ("E2E summary: outcome={outcome} tests={tests_run} failures={failures} "
            "errors={errors} cleanup={cleanup_ok} evidence={artifact_collection_ok} "
            "exit={exit_code} diagnostic=").format_map(summary) + diagnostic

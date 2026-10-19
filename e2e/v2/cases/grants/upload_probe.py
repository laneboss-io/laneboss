"""Native staging regression driver; human authentication is component input.

Use the actual grants plan, flow adapter and sealed-canary producer. The native
test selects the plan through stage; persistent import is outside this scope.
"""

import base64
import hashlib
import json
from pathlib import Path
import sys
import uuid

from boot_bundle_input import BootFixture, GRANTS


def run(inputs):
    context = inputs["context"]
    evidence = Path(context["evidence_root"])
    case = BootFixture(evidence)
    case.config = context["config"]
    directory = evidence / "grants-upload"
    directory.mkdir(mode=0o700)
    selected = GRANTS.uploads.plan(directory)
    case.keep_json("grants-upload-full-plan.json", selected)
    boundary = next(index for index, row in enumerate(selected["steps"]) if row["method"] == "secret.import")
    selected["steps"] = selected["steps"][:boundary]
    proof = Path(context["test_root"]) / "proof.json"
    # Independently declared fresh session facts for the session-reset RED
    # control. No identity ceremony or proof consumption is credited here.
    replacement = json.loads(proof.read_bytes())
    replacement["id"] = uuid.uuid4().hex
    GRANTS.uploads.publish(directory / "replacement.proof.json", GRANTS.uploads.encoded(replacement))
    GRANTS.uploads.publish(directory / "replacement.json", GRANTS.uploads.encoded({}))
    with GRANTS.uploads.FileFlow(directory, context["binary"], context["config"],
                                context["binding_file"], proof, selected) as live:
        try:
            key = live.response("task-secret-key")
            GRANTS.uploads.publish(evidence / "human-1-response.json",
                GRANTS.uploads.encoded(live.receipts["task-secret-key"]["response"]))
            sealed = GRANTS.sealed_canary(case, Path(inputs["sealer"]), key, "flow.canary", "one")
            live.supply("task-secret-stage", sealed)
            # Retain the exact case-produced request for the independent
            # decoder and fresh-connection refusal checks in the native test.
            GRANTS.uploads.publish(Path(context["test_root"]) / "stage.json",
                                   (directory / "stage.json").read_bytes())
            raw = (directory / "stage.json").read_bytes()
            print(json.dumps({"stage_sha256": hashlib.sha256(raw).hexdigest(),
                "stage_bytes_base64": base64.b64encode(raw).decode()}), flush=True)
            live.response("task-secret-stage")
            live.finish()
        finally:
            case.keep("human-client.out", live.out.read_bytes())


if __name__ == "__main__":
    try:
        run(json.loads(Path(sys.argv[1]).read_bytes()))
    except GRANTS.uploads.Refused as error:
        print(json.dumps(error.error, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)

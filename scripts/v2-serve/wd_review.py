"""Select actual child uploads and drive the installed native test/review path."""

import base64
import json


def check_request(values, target):
    found = []
    for value in values:
        if value.get("type") != "assistant":
            continue
        for block in value.get("message", {}).get("content", []):
            text = block.get("text", "")
            if block.get("type") != "text" or not text.startswith("WD-CHECK-INPUT "):
                continue
            request = json.loads(base64.b64decode(text.split(" ", 1)[1], validate=True))
            if request.get("child") == target:
                found.append(request)
    if len(found) != 1:
        raise ValueError("current child capture has no unique owned checker input")
    request, = found
    if set(request) != {"child", "candidate", "test_plan", "budget"}:
        raise ValueError("child checker input has unexpected fields")
    for key in ("candidate", "test_plan"):
        ref = request[key]
        if ref.get("class") != "manifest" or not ref.get("id") or ref.get("bytes", 0) < 1:
            raise ValueError("child checker input has no actual committed manifest")
    return request


def measure(installed, target):
    # Reuse the existing capture reader: it checks actual primary offsets,
    # source actors, operation, exact bytes and gaps for this ended run.
    from wd_item import Relay, flow
    record = {"target": target}
    ends = [event for event in flow.events(installed.case, record, installed.require)
            if event["kind"] == "lane.ended" and event.get("origin") == "service" and
            event.get("life_id") == target["life_id"] and event.get("run") == target["run"]]
    installed.require(len(ends) == 1, "review preparation has no unique actual run end")
    record["operation"] = {"id": ends[0]["operation_id"]}
    capture = Relay(installed.case, record, installed.require, installed.fail)
    request = check_request(capture.values_now(), target)
    installed.case.keep_json("wd-check-" + target["life_id"] + "-" + str(target["run"]) + ".input.json", request)
    operation = installed.relay.call("grants test-child", request)
    installed.require(operation.get("status") == "succeeded" and operation.get("result") and
                      operation.get("life_id") == target["life_id"] and operation.get("run") == target["run"],
                      "native checker did not return its exact completed operation")
    installed.operations.append(operation["id"])
    raw = installed.blob(operation["result"])
    review = json.loads(raw)
    installed.require(review.get("target") == target and len(review.get("checks", [])) > 0 and
                      review.get("diff", {}).get("class") == "diff" and
                      review.get("record_inventory", {}).get("class") == "manifest",
                      "native checker published no correlated review inputs")
    return raw

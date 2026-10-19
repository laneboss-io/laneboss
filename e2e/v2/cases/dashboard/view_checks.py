"""Shared CLI/HTTPS populated-view acceptance checks."""

import re


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def positive_int(value):
    return type(value) is int and value > 0


def populated(aid, value):
    if not isinstance(value, dict) or value.get("error"):
        return False
    try:
        if aid == "DASH-DECISIONS":
            rows = value["decisions"]
            return bool(rows) and all(r.get("id") and r.get("text") and digest(
                r.get("source", {}).get("sha256")) for r in rows)
        if aid == "DASH-RAW":
            records, gaps, messages = value["records"], value["gaps"], value["messages"]
            return (len({r["id"] for r in records}) >= 2 and bool(gaps) and bool(messages)
                    and all(r.get("target", {}).get("life_id") and positive_int(r["target"].get("run"))
                            and digest(r.get("data", {}).get("sha256")) for r in records)
                    and all(g.get("reason") and g.get("target", {}).get("life_id")
                            and g.get("observed_at") for g in gaps)
                    and all(m.get("id") and m.get("content", {}).get("id") for m in messages))
        if aid == "DASH-TREE":
            rows = value["nodes"]
            return (any(r.get("configured") is True and r.get("live") is False
                        and r.get("instance_id") for r in rows)
                    and any(r.get("live") is True and r.get("life_id") for r in rows))
        if aid == "DASH-REFUSALS":
            rows = value["counts"]
            return (any(positive_int(r.get("refused")) for r in rows)
                    and any(positive_int(r.get("unscored")) or positive_int(
                        r.get("critical_unscored")) for r in rows)
                    and isinstance(value["receipts"], list))
        if aid in ("DASH-PLUGINS", "DASH-RESOURCES"):
            rows = value["resources"]
            pins = bool(rows) and all(r.get("id") and r.get("source", {}).get("id")
                and digest(r.get("sha256")) and r["source"].get("sha256") == r["sha256"]
                for r in rows)
            return pins and (aid != "DASH-PLUGINS" or any(
                r.get("declared") is True and r.get("verified_loaded") is True
                and r.get("kind") == "plugin" for r in rows))
        if aid == "DASH-LIFECYCLE":
            return bool(value["lanes"]) and all(r.get("life_id") and positive_int(r.get("run"))
                and positive_int(r.get("generation")) for r in value["lanes"])
        if aid == "DASH-APPROVALS":
            changes = {r["id"]: r for r in value["changes"]}
            approvals = {r["id"]: r for r in value["approvals"]}
            return bool(changes) and bool(approvals) and bool(value["applications"]) and all(
                r.get("id") and r.get("change_id") in changes and r.get("approval_id") in approvals
                and approvals[r["approval_id"]].get("change_id") == r["change_id"]
                and digest(r.get("manifest_sha256"))
                and changes[r["change_id"]].get("manifest_sha256") == r["manifest_sha256"]
                and approvals[r["approval_id"]].get("manifest_sha256") == r["manifest_sha256"]
                and positive_int(r.get("old_generation"))
                and positive_int(r.get("new_generation"))
                and r["new_generation"] > r["old_generation"]
                for r in value["applications"])
    except (KeyError, TypeError, AttributeError):
        return False
    return False


def cli_passed(probe):
    return bool(probe.get("exit") == 0 and probe.get("populated") is True
                and probe.get("session_proof_sha256") and not probe.get("stderr"))


def denied(status, raw, allowed, stale=False):
    import json
    try:
        reply = json.loads(raw)
        error = reply.get("error", {})
        code_ok = error.get("code") in ("unauthenticated", "forbidden")
        if stale and status == 404 and error.get("code") == "not_found":
            code_ok = True
        return (status in allowed and code_ok
                and bool(error.get("message")) and not reply.get("result"))
    except (ValueError, TypeError, AttributeError):
        return False

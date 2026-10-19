"""Independent checks of a launched fixture's raw installed-CLI evidence."""

import base64
import hashlib
import json
import os
from pathlib import Path
import stat


class InvalidEvidence(ValueError):
    """An absent, unexecuted, mismatched or fabricated observation."""


def require(condition, reason):
    if not condition:
        raise InvalidEvidence(reason)


def read(root, name):
    require(Path(name).name == name, "nonlocal agent evidence name")
    path = root / name
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            before.st_size <= 1048576, "unsafe agent evidence file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size) ==
                (after.st_dev, after.st_ino, after.st_size), "agent evidence changed")
        data = stream.read(1048577)
        require(len(data) == before.st_size, "agent evidence size changed")
    return data


def members(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate agent evidence member")
        result[key] = value
    return result


def document(data):
    value = json.loads(data, object_pairs_hook=members)
    require(isinstance(value, dict), "agent evidence is not an object")
    return value


def audit(root, expected):
    """Expected identity/paths must come from the real launch, not the agent."""
    require(expected.get("output") == "/home/lane/serve-state",
            "fixture output differs from its private home contract")
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "agent output is unavailable")
    log = document(read(root, "transcript.json"))
    require(log.get("schema") == "laneboss.serve-observed.v1" and
            log.get("program") == "laneboss-serve-fixture" and
            log.get("version") == expected["version"], "wrong fixture transcript")
    for name in ("config", "challenge", "life", "run", "uid"):
        require(log.get(name) == expected[name], "agent launch identity differs")
    require(type(log["uid"]) is int and log["uid"] != 0 and
            type(log["run"]) is int and log["run"] > 0, "invalid agent identity")
    calls = log.get("calls")
    require(isinstance(calls, list), "agent calls are absent")
    methods = {
        "identity": ["identity", "self"], "blob-begin": ["blob", "begin"],
        "blob-chunk": ["blob", "chunk"], "blob-commit": ["blob", "commit"],
        "append": ["records", "append"], "get": ["records", "get"],
        "read": ["blob", "read"], "retry": ["records", "append"],
        "changed": ["records", "append"], "unready": ["judge", "list"],
    }
    require([row.get("name") for row in calls] == list(methods), "incomplete agent command sequence")
    outputs, requests = {}, {}
    for row in calls:
        name = row["name"]
        require(row.get("started") is True and row.get("timed_out") is False and
                type(row.get("exit_code")) is int, "agent command did not execute")
        expected_code = 2 if name == "changed" else 0
        require(row["exit_code"] == expected_code, "agent CLI exit differs")
        request_name = "append.request.json" if name == "retry" else (
            "identity.request.json" if name == "unready" else name + ".request.json")
        require(row.get("request") == request_name and row.get("stdout") == name + ".stdout" and
                row.get("stderr") == name + ".stderr", "agent evidence mapping differs")
        request_id = expected["challenge"] + "-" + ("append" if name in ("retry", "changed") else name)
        argv = [expected["client"], *methods[name], "--config", expected["config"],
                "--binding", expected["binding"], "--request", expected["output"] + "/" + request_name,
                "--request-id", request_id]
        if name in ("blob-begin", "blob-chunk", "blob-commit", "append", "retry", "changed"):
            key = expected["challenge"] + "-" + ("append" if name in ("retry", "changed") else name)
            argv.extend(("--idempotency-key", key))
        require(row.get("argv") == argv, "agent invoked another client or binding")
        stdout, stderr = read(root, row["stdout"]), read(root, row["stderr"])
        requests[name] = document(read(root, request_name))
        if expected_code == 0:
            require(not stderr, "successful CLI emitted diagnostics")
            outputs[name] = document(stdout)
        else:
            require(not stdout, "refused CLI returned success bytes")
            outputs[name] = document(stderr)
    identity = outputs["identity"]
    actor = identity.get("actor", {})
    require(identity.get("config") == expected["config"] and actor.get("kind") == "lane" and
            actor.get("life_id") == expected["life"] and actor.get("id") and
            identity.get("launch_id") == expected["launch_id"], "CLI authenticated another caller")
    content = ("SERVE-STATE " + expected["challenge"] + "\n").encode()
    require(read(root, "content.input") == content, "agent used another challenge")
    content_sha = hashlib.sha256(content).hexdigest()
    upload = outputs["blob-begin"]["object_id"]
    require(requests["blob-begin"] == {"class": "record", "bytes": len(content), "sha256": content_sha},
            "blob begin differs from challenge")
    require(requests["blob-chunk"] == {"object_id": upload, "offset": 0,
            "data": base64.b64encode(content).decode(), "sha256": content_sha}, "blob chunk differs")
    require(requests["blob-commit"] == {"object_id": upload, "sha256": content_sha}, "blob commit differs")
    ref = outputs["blob-commit"]
    require(ref == {"id": upload, "sha256": content_sha, "bytes": len(content), "class": "record"},
            "CLI committed another object")
    record = outputs["append"]
    require(record.get("id") and record.get("collection") == "observations" and
            record.get("content") == ref and record.get("actor") == actor and
            record.get("life_id") == expected["life"] and record.get("run") == expected["run"],
            "CLI appended another record")
    require(requests["append"] == {"collection": "observations", "content": ref, "related_ids": []},
            "append request differs")
    require(requests["get"] == {"record_id": record["id"]} and outputs["get"] == record,
            "CLI record get differs")
    require(requests["read"] == {"object_id": upload, "offset": 0, "limit": len(content)},
            "CLI content request differs")
    observed = outputs["read"]
    require(observed.get("object_id") == upload and observed.get("offset") == 0 and
            observed.get("sha256") == content_sha and
            base64.b64decode(observed["data"], validate=True) == content, "CLI read different content")
    require(read(root, "retry.stdout") == read(root, "append.stdout") and
            requests["retry"] == requests["append"], "exact retry response differs")
    require(requests["changed"] == dict(requests["append"], collection="reports") and
            outputs["changed"].get("code") == "idempotency_conflict", "changed input was not refused")
    require(requests["identity"] == {} and requests["unready"] == {} and
            type(outputs["unready"].get("generation")) is int and outputs["unready"]["generation"] > 0 and
            outputs["unready"].get("projection", {}).get("id") and
            outputs["unready"]["projection"].get("class") == "manifest" and
            not outputs["unready"].get("code"), "judge list has no real committed configuration projection")
    require(not log.get("stopped_at"), "agent stopped before completing commands")
    return {"identity": identity, "record": record, "content_sha256": content_sha,
            "ordinary_retry": outputs["retry"], "changed": outputs["changed"],
            "unready": outputs["unready"], "calls": len(calls)}

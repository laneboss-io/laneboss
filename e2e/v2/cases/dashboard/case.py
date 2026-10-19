"""Black-box acceptance case for lb-v2-dashboard (DASH-* and HUMAN-SEND)."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import ssl
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from fixture_io import FixtureError, FixtureInputs, external_collected, private_read
from view_checks import cli_passed, denied, populated

CLI_EXITS = []

ASSERTION_IDS = [
    "DASH-DECISIONS",
    "DASH-RAW",
    "DASH-TREE",
    "DASH-REFUSALS",
    "DASH-PLUGINS",
    "DASH-RESOURCES",
    "DASH-LIFECYCLE",
    "DASH-APPROVALS",
    "DASH-STOP",
    "DASH-RESUME",
    "DASH-MERGED",
    "DASH-ABANDONED",
    "HUMAN-SEND",
]

VIEW_ASSERTIONS = [
    ("DASH-TREE", "tree"),
    ("DASH-RAW", "raw"),
    ("DASH-DECISIONS", "decisions"),
    ("DASH-REFUSALS", "refusals"),
    ("DASH-PLUGINS", "plugins"),
    ("DASH-RESOURCES", "resources"),
    ("DASH-LIFECYCLE", "lifecycle"),
    ("DASH-APPROVALS", "approvals"),
]


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def jcs_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def request_digest(config, method, params):
    canonical = {
        "config": config,
        "method": method,
        "params": params,
        "protocol": "laneboss.rpc.v2",
        "schema": 2,
    }
    return sha256_bytes(jcs_bytes(canonical))


def write_atomic_json(target, payload):
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    raw = (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode("utf-8")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)
    tmp.replace(target)


class EvidenceRecorder:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.items = []
        self.simulated_presence = False

    def save(self, rel_path, content):
        if isinstance(content, dict) and (marked_presence(content) or content.get("presence") == "simulated"):
            self.simulated_presence = True
        if isinstance(content, str):
            raw = content.encode("utf-8")
        elif isinstance(content, bytes):
            raw = content
        else:
            raw = (json.dumps(content, indent=2, sort_keys=True) + "\n").encode("utf-8")
        dest = (self.root / rel_path).resolve()
        dest.relative_to(self.root)
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)
        ref = {
            "path": rel_path,
            "sha256": sha256_bytes(raw),
            "bytes": len(raw),
        }
        self.items.append(ref)
        return ref


def parse_args(argv):
    if len(argv) != 5 or argv[1] != "--context" or argv[3] != "--result":
        raise SystemExit("usage: case.py --context CONTEXT_FILE --result RESULT_FILE")
    ctx_path = Path(argv[2])
    res_path = Path(argv[4])
    if not ctx_path.is_absolute() or not res_path.is_absolute():
        raise SystemExit("context and result paths must be absolute")
    return ctx_path, res_path


def run_cli(binary, args, env=None):
    merged = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if env:
        merged.update(env)
    proc = subprocess.run(
        [str(binary), *args],
        capture_output=True,
        text=True,
        env=merged,
        timeout=60,
        check=False,
    )
    CLI_EXITS.append(proc.returncode)
    return {
        "argv": [str(binary), *args],
        "exit": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def http_call(opener, url, *, method="GET", headers=None, body=None):
    req_headers = dict(headers or {})
    raw_body = None
    if body is not None:
        if isinstance(body, (dict, list)):
            raw_body = json.dumps(body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, bytes):
            raw_body = body
        else:
            raw_body = str(body).encode("utf-8")
    req = urllib.request.Request(url, data=raw_body, headers=req_headers, method=method)
    recorder = getattr(opener, "evidence_recorder", None)
    stem = "wire/" + uuid.uuid4().hex
    if recorder is not None:
        recorder.save(stem + ".request.json", {"method": method, "url": url, "headers": req_headers})
        recorder.save(stem + ".request.body", raw_body or b"")
    try:
        with opener.open(req, timeout=15) as resp:
            result = resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as err:
        with err:
            result = err.code, dict(err.headers.items()), err.read()
    if recorder is not None:
        recorder.save(stem + ".response.json", {"status": result[0], "headers": result[1]})
        recorder.save(stem + ".response.body", result[2])
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def dashboard_opener(base_url, ca_file=None, connect_address=None):
    parsed = urllib.parse.urlsplit(base_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("dashboard requires one exact HTTPS origin")
    context = ssl.create_default_context(cafile=ca_file)
    if connect_address is not None:
        if connect_address != "127.0.0.1":
            raise ValueError("isolated dashboard resolver must name its local listener")
        class LocalTLS(http.client.HTTPSConnection):
            def connect(self):
                connection = socket.create_connection((connect_address, self.port), self.timeout, self.source_address)
                try:
                    self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
                except Exception:
                    connection.close()
                    raise
        class LocalHandler(urllib.request.HTTPSHandler):
            def https_open(self, request):
                return self.do_open(LocalTLS, request, context=context)
        return urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalHandler(context=context), NoRedirect())
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context), NoRedirect())


def build_rpc_envelope(config, method, params, proof=None, req_id=None, idem_key=None):
    rid = req_id or ("req-" + uuid.uuid4().hex)
    ikey = idem_key or ("idem-" + uuid.uuid4().hex)
    digest = request_digest(config, method, params)
    env = {
        "protocol": "laneboss.rpc.v2",
        "schema": 2,
        "config": config,
        "request_id": rid,
        "idempotency_key": ikey,
        "request_sha256": digest,
        "method": method,
        "params": params,
    }
    if proof is not None:
        env["proof"] = proof
    return env


def verify_cli_flag_guards(binary, config, recorder):
    """Verify lb-v2-dashboard CLI flag and --request FILE validation guards."""
    checks = []
    bad_driver = run_cli(
        binary,
        ["dashboard", "raw", "--config", config, "--driver", "bare-claude"],
    )
    checks.append({"case": "invalid_driver", "result": bad_driver})
    bad_limit = run_cli(
        binary,
        ["dashboard", "tree", "--config", config, "--limit", "0"],
    )
    checks.append({"case": "invalid_limit_zero", "result": bad_limit})
    bad_level = run_cli(
        binary,
        ["dashboard", "tree", "--config", config, "--level", "2"],
    )
    checks.append({"case": "invalid_level_two", "result": bad_level})
    bad_flag = run_cli(
        binary,
        ["dashboard", "decisions", "--config", config, "--unknown-flag"],
    )
    checks.append({"case": "unknown_flag", "result": bad_flag})

    bad_req_path = recorder.root / "cli" / "bad_request_input.json"
    write_atomic_json(
        bad_req_path,
        {"driver": "bare-claude", "cursor": "", "limit": 0},
    )
    for _, subcmd in VIEW_ASSERTIONS:
        bad_file_res = run_cli(
            binary,
            [
                "dashboard",
                subcmd,
                "--config",
                config,
                "--request",
                str(bad_req_path),
            ],
        )
        checks.append({"case": f"bad_file_{subcmd}", "result": bad_file_res})

    ref = recorder.save("cli/red_flag_checks.json", checks)
    all_rejected = all(item["result"]["exit"] == 2 for item in checks)
    return all_rejected, ref


def probe_cli_views(binary, config, binding_file, recorder, inputs):
    """Run all dashboard CLI subcommands via --request FILE and record responses."""
    transcripts = {}
    missing_deps = set()
    valid_req_path = recorder.root / "cli" / "valid_request_input.json"
    write_atomic_json(valid_req_path, {"cursor": "", "limit": 50})
    for assertion_id, subcmd in VIEW_ASSERTIONS:
        proof_file = inputs.cli(assertion_id)
        proof_raw = private_read(proof_file)
        args = [
            "dashboard",
            subcmd,
            "--config",
            config,
            "--request",
            str(valid_req_path),
            "--proof", proof_file,
        ]
        if binding_file:
            args.extend(["--binding", binding_file])
        res = run_cli(binary, args)
        recorder.save("cli/" + subcmd + ".transcript.json", res)
        err_obj = None
        if res["stderr"].strip():
            try:
                err_obj = json.loads(res["stderr"].strip().splitlines()[-1])
            except ValueError:
                err_obj = {"raw_stderr": res["stderr"]}
        out_obj = None
        if res["stdout"].strip():
            try:
                out_obj = json.loads(res["stdout"].strip())
            except ValueError:
                out_obj = {"raw_stdout": res["stdout"]}
        if isinstance(err_obj, dict) and err_obj.get("code") in (
            "not_implemented",
            "prerequisite_missing",
        ):
            owner = err_obj.get("owner") or "lb-v2-service"
            missing_deps.add(owner)
        transcripts[assertion_id] = {
            "subcommand": subcmd,
            "exit": res["exit"],
            "stdout": out_obj,
            "stderr": err_obj,
            "populated": populated(assertion_id, out_obj),
            "session_proof_sha256": sha256_bytes(proof_raw),
        }
        if res["exit"] != 0:
            # Preserve the installed owner's exact refusal. No dependent view
            # or mutation may run past this failed public read.
            recorder.save("cli/view_probes.json", transcripts)
            raise FixtureError(err_obj or {"code": "read_failed", "owner": "lb-v2-dashboard",
                                           "message": "installed CLI read failed"})
    ref = recorder.save("cli/view_probes.json", transcripts)
    return transcripts, sorted(missing_deps), ref


def parse_sse_frames(raw_bytes):
    frames = []
    text = raw_bytes.decode("utf-8", errors="replace")
    for block in text.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        event_id = ""
        data_lines = []
        for line in block.splitlines():
            if line.startswith("id:"):
                event_id = line[3:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())
        if data_lines:
            payload = "\n".join(data_lines)
            try:
                frames.append({"id": event_id, "frame": json.loads(payload)})
            except ValueError:
                frames.append({"id": event_id, "raw": payload})
    return frames



def marked_presence(value):
    if isinstance(value, dict):
        return value.get("simulated_presence") is True or any(
            marked_presence(child) for child in value.values()
        )
    if isinstance(value, list):
        return any(marked_presence(child) for child in value)
    return False


def control_passed(red_denied, positive_ok):
    return bool(red_denied and positive_ok)


def service_state_seen(frames, target, readback, since=0):
    """Terminal frames cannot prove that a causal service event was delivered."""
    for item in frames:
        frame = item.get("frame", {})
        event = frame.get("event")
        if not isinstance(event, dict):
            continue
        if frame.get("end") or frame.get("error"):
            continue
        payload = event.get("payload", {})
        if (
            event.get("id")
            and event.get("kind") == "lane.state"
            and event.get("origin") == "service"
            and event.get("life_id") == target.get("life_id") == readback.get("life_id")
            and event.get("run") == target.get("run") == readback.get("run")
            and since < event.get("seq", 0) <= readback.get("last_seq", 0)
            and payload.get("from") in ("running", "stopping")
            and payload.get("to") == readback.get("state") == "verifying"
            and payload.get("generation") == readback.get("generation")
        ):
            return True
    return False


def positive_observed(method, request, status, response, readback, headers):
    if status != 200 or not isinstance(request, dict) or not isinstance(response, dict):
        return False
    result = response.get("result")
    if response.get("error") or response.get("request_id") != request.get("request_id") or not isinstance(result, dict):
        return False
    params = request.get("params", {})
    if marked_presence([request.get("proof"), result, readback]):
        if headers.get("X-Laneboss-Presence") != "simulated" or headers.get("X-Laneboss-Human-Approval") != "not_proven":
            return False
    if method == "mail.send":
        return bool(
            result.get("id") and result.get("queued_seq", 0) > 0
            and result.get("source") == "dashboard"
            and result.get("sender", {}).get("kind") == "human"
            and result.get("recipient_life_id") == params.get("recipient_life_id")
            and result.get("content") == params.get("content")
            and any(
                mail.get("id") == result["id"]
                and mail.get("content") == result.get("content")
                and mail.get("sender") == result.get("sender")
                and mail.get("queued_seq") == result.get("queued_seq")
                and mail.get("source") == result.get("source")
                and mail.get("recipient_life_id") == result.get("recipient_life_id")
                for mail in readback.get("messages", [])
            )
        )
    if result.get("status") != "succeeded" or not result.get("id") or result.get("error") or result.get("last_seq", 0) <= 0:
        return False
    target = params.get("target", {})
    expected_state = {"lane.stop": "verifying", "lane.resume": "running"}.get(method, params.get("state"))
    expected_run = target.get("run", 0) + (1 if method == "lane.resume" else 0)
    return bool(
        readback.get("life_id") == target.get("life_id") == result.get("life_id")
        and readback.get("run") == expected_run == result.get("run")
        and readback.get("state") == expected_state
        and readback.get("generation", 0) > params.get("expected_generation", 0)
        and readback.get("last_seq", 0) >= result["last_seq"]
    )


def exercise_positive(opener, origin, config, headers, aid, method, requests, recorder):
    request = requests.get(aid)
    if not isinstance(request, dict):
        ref = recorder.save(f"http/{aid.lower()}_positive.json", {
            "positive_observed": False,
            "reason": "missing exact authorized request from installed-service fixture",
        })
        return False, ref
    params = request.get("params")
    if (request.get("config") != config or request.get("method") != method
            or not isinstance(params, dict)
            or request.get("request_sha256") != request_digest(config, method, params)):
        raise ValueError("positive control request differs from its exact method/config/digest")
    # Preserve the supplied operation-bound request and retained retry key.
    wire = requests.wire(aid) if hasattr(requests, "wire") else json.dumps(request).encode("utf-8")
    recorder.save(f"inputs/{aid.lower()}.json", wire)
    before_seq = 0
    if method == "lane.stop":
        before_status, _, before_raw = http_call(
            opener, origin + "/api/v2/rpc", method="POST", headers=headers,
            body=build_rpc_envelope(config, "lane.status", params["target"]),
        )
        recorder.save("http/stop_before.json", before_raw)
        before_reply = json.loads(before_raw)
        before = before_reply.get("result", {})
        before_seq = before.get("last_seq", -1)
        if (before_status != 200 or before_reply.get("error")
                or before.get("life_id") != params["target"]["life_id"]
                or before.get("run") != params["target"]["run"]
                or before.get("generation") != params.get("expected_generation")
                or before.get("state") != "running"
                or type(before_seq) is not int or before_seq < 0):
            ref = recorder.save(f"http/{aid.lower()}_positive.json", {
                "positive_observed": False, "reason": "stop baseline did not match the authorized live target",
            })
            return False, ref
    status, response_headers, raw = http_call(
        opener, origin + "/api/v2/rpc", method="POST", headers=headers, body=wire
    )
    recorder.save(f"http/{aid.lower()}_initial_response.json", raw)
    response = json.loads(raw)
    if response.get("error"):
        raise FixtureError(response["error"])
    result = response.get("result", {})
    if result.get("error"):
        raise FixtureError(result["error"])
    if method != "mail.send" and result.get("id") and hasattr(requests, "observed_operation"):
        requests.observed_operation(result["id"])
    operation_id = result.get("id")
    # Pending acknowledges intent. Poll the same operation; never consume a new
    # proof or substitute a second mutation to manufacture completion.
    deadline = time.monotonic() + 10
    while method != "mail.send" and result.get("status") in ("pending", "running") and time.monotonic() < deadline:
        if not operation_id or result.get("id") != operation_id:
            break
        poll = build_rpc_envelope(config, "operation.get", {"operation_id": operation_id})
        poll_status, poll_headers, poll_raw = http_call(
            opener, origin + "/api/v2/rpc", method="POST", headers=headers, body=poll
        )
        recorder.save(f"http/{aid.lower()}_operation_{time.time_ns()}.json", {
            "status": poll_status, "headers": poll_headers, "response": json.loads(poll_raw),
        })
        polled = json.loads(poll_raw)
        if polled.get("error"):
            raise FixtureError(polled["error"])
        if polled.get("result", {}).get("error"):
            raise FixtureError(polled["result"]["error"])
        if (poll_status != 200 or polled.get("request_id") != poll["request_id"]
                or polled.get("result", {}).get("id") != operation_id):
            result = {}
            response["result"] = result
            break
        result = polled.get("result", {})
        response["result"] = result
        response_headers = poll_headers
        status = poll_status
        if result.get("status") in ("pending", "running"):
            time.sleep(0.1)
    if method == "mail.send":
        read_method = "mail.list"
        read_params = {"life_id": params["recipient_life_id"], "cursor": "", "limit": 200}
    else:
        read_method, read_params = "lane.status", dict(params["target"])
        if method == "lane.resume":
            read_params["run"] += 1
    read_status, _, read_raw = http_call(
        opener, origin + "/api/v2/rpc", method="POST", headers=headers,
        body=build_rpc_envelope(config, read_method, read_params),
    )
    recorder.save(f"http/{aid.lower()}_readback.json", read_raw)
    read_response = json.loads(read_raw)
    readback = read_response.get("result", {}) if read_status == 200 and not read_response.get("error") else {}
    ok = positive_observed(method, request, status, response, readback, response_headers)
    event_ref = None
    if method == "lane.stop":
        query = urllib.parse.urlencode({
            "life_id": params["target"]["life_id"], "run": params["target"]["run"],
            "until": "", "follow": "false", "since": before_seq,
        })
        event_status, _, event_raw = http_call(
            opener, origin + "/api/v2/events?" + query,
            headers={"Cookie": headers.get("Cookie", "")},
        )
        frames = parse_sse_frames(event_raw)
        event_bytes = recorder.save("http/stop_service_event.sse", event_raw)
        delivered = event_status == 200 and service_state_seen(frames, params["target"], readback, before_seq)
        event_ref = recorder.save("http/stop_service_event.json", {
            "status": event_status, "frames": frames, "service_state_delivered": delivered,
            "readback_last_seq": readback.get("last_seq"),
            "since": before_seq, "original_bytes": event_bytes,
        })
        ok = ok and delivered
    ref = recorder.save(f"http/{aid.lower()}_positive.json", {
        "status": status, "headers": response_headers, "response": response, "read_status": read_status, "readback": read_response,
        "positive_observed": ok,
        "service_event_evidence": event_ref,
        "presence": "simulated" if marked_presence([request, response, readback]) else "not_proven",
        "human_approval": "not_proven",
    })
    return ok, ref


def exercise_http_dashboard(base_url, config, session_cookie, mutation_id, recorder, positive_requests):
    """Exercise HTTP/SSE views, inert HTML, and authenticated vs red controls."""
    ca_file = getattr(positive_requests, "document", {}).get("ca_file")
    opener = dashboard_opener(base_url, ca_file, getattr(positive_requests, "document", {}).get("connect_address"))
    opener.evidence_recorder = recorder
    origin = base_url.rstrip("/")
    auth_headers = {"Cookie": session_cookie} if session_cookie else {}
    post_headers = {
        **auth_headers,
        "Origin": origin,
        "Content-Type": "application/json",
    }
    outcomes = {}

    # 1. Root HTML & inertness check
    st_root, hdr_root, body_root = http_call(opener, origin + "/", headers=auth_headers)
    html_text = body_root.decode("utf-8", errors="replace")
    inert_ok = (
        st_root == 200
        and "<!doctype html>" in html_text.lower()
        and "Content-Security-Policy" in hdr_root
        and "innerHTML" not in html_text
    )
    ev_root = recorder.save(
        "http/root_page.json",
        {"status": st_root, "headers": hdr_root, "inert_ok": inert_ok},
    )

    # 2. Unauthenticated GET must fail with 401
    st_unauth, _, body_unauth = http_call(opener, origin + "/api/v2/decisions")
    ev_unauth = recorder.save(
        "http/unauth_get.json",
        {"status": st_unauth, "body": body_unauth.decode("utf-8", errors="replace")},
    )

    # 3. Check each read-only GET route
    route_map = {
        "DASH-TREE": ("/api/v2/tree", "nodes"),
        "DASH-RAW": ("/api/v2/raw", "records"),
        "DASH-DECISIONS": ("/api/v2/decisions", "decisions"),
        "DASH-REFUSALS": ("/api/v2/refusals", "counts"),
        "DASH-PLUGINS": ("/api/v2/plugins", "resources"),
        "DASH-RESOURCES": ("/api/v2/resources", "resources"),
        "DASH-LIFECYCLE": ("/api/v2/lifecycle", "lanes"),
        "DASH-APPROVALS": ("/api/v2/approvals", "changes"),
    }
    for aid, (route, required_key) in route_map.items():
        no_auth, _, no_auth_raw = http_call(opener, origin + route + "?limit=50")
        ev_no_auth = recorder.save("http/" + aid.lower() + "_unsigned.json", {
            "status": no_auth, "response": no_auth_raw.decode("utf-8", "replace")})
        t_start = time.monotonic()
        st, view_headers, raw = http_call(opener, origin + route + "?limit=50", headers=auth_headers)
        elapsed_s = time.monotonic() - t_start
        parsed = {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            parsed = {}
        ev_view = recorder.save(
            f"http/{aid.lower()}.json",
            {"status": st, "elapsed_s": elapsed_s, "data": parsed,
             "presence": "simulated" if marked_presence(parsed) or view_headers.get("X-Laneboss-Presence") == "simulated" else "not_proven", "human_approval": "not_proven"},
        )
        presence_ok = not marked_presence(parsed) or (
            view_headers.get("X-Laneboss-Presence") == "simulated"
            and view_headers.get("X-Laneboss-Human-Approval") == "not_proven"
        )
        ok = (st == 200 and populated(aid, parsed) and st_unauth == 401 and presence_ok
              and denied(no_auth, no_auth_raw, (401,)))
        if aid == "DASH-DECISIONS":
            decisions = parsed.get("decisions") or []
            ok = ok and inert_ok and len(decisions) > 0 and all(
                d.get("text") and d.get("source", {}).get("sha256") for d in decisions
            )
        elif aid == "DASH-RAW":
            records = parsed.get("records") or []
            gaps = parsed.get("gaps") or []
            messages = parsed.get("messages") or []
            drivers_ok = len(records) >= 2
            gaps_ok = len(gaps) >= 1
            ok = ok and inert_ok and drivers_ok and gaps_ok and len(messages) >= 1
        elif aid == "DASH-TREE":
            nodes = parsed.get("nodes") or []
            has_cfg = any(n.get("configured") and not n.get("live") for n in nodes)
            has_live = any(n.get("live") and n.get("life_id") for n in nodes)
            ok = ok and has_cfg and has_live
        elif aid == "DASH-REFUSALS":
            counts = parsed.get("counts") or []
            has_refused = any(c.get("refused", 0) > 0 for c in counts)
            has_unscored = any(
                c.get("unscored", 0) > 0 or c.get("critical_unscored", 0) > 0
                for c in counts
            )
            ok = ok and has_refused and has_unscored and isinstance(parsed.get("receipts"), list)
        elif aid == "DASH-PLUGINS":
            resources = parsed.get("resources") or []
            has_declared = any(r.get("declared") for r in resources)
            has_verified = any(r.get("verified_loaded") for r in resources)
            ok = ok and len(resources) > 0 and has_declared and has_verified
        elif aid == "DASH-RESOURCES":
            resources = parsed.get("resources") or []
            ok = ok and len(resources) > 0 and all(
                r.get("sha256") and r.get("source", {}).get("id") for r in resources
            )
        elif aid == "DASH-LIFECYCLE":
            lanes = parsed.get("lanes") or []
            # The causal SSE assertion runs after the successful stop below.
            ok = ok and len(lanes) > 0
        elif aid == "DASH-APPROVALS":
            changes = parsed.get("changes") or []
            approvals = parsed.get("approvals") or []
            apps = parsed.get("applications") or []
            ok = ok and len(changes) > 0 and len(approvals) > 0 and len(apps) > 0
        outcomes[aid] = {
            "ok": ok,
            "exit": 0 if ok else 2,
            "evidence": [ev_root, ev_unauth, ev_no_auth, ev_view],
        }
        if not ok:
            recorder.save("status/http-outcomes.json", outcomes)
            raise FixtureError(parsed.get("error") or {
                "owner": "lb-v2-dashboard", "code": "view_failed",
                "message": "authenticated populated view or unsigned control failed: " + aid})

    # 4. Control mutations and red controls (unauthenticated, wrong-Origin, stale-proof)
    control_specs = [
        ("DASH-STOP", "lane.stop"),
        ("DASH-RESUME", "lane.resume"),
        ("DASH-MERGED", "lane.mark"),
        ("DASH-ABANDONED", "lane.mark"),
        ("HUMAN-SEND", "mail.send"),
    ]
    for aid, method in control_specs:
        supplied = positive_requests.get(aid, {})
        if not isinstance(supplied, dict) or not isinstance(supplied.get("params"), dict):
            raise ValueError("action requires an actual current installed fixture request")
        sample_params = supplied["params"]
        base_gen = sample_params.get("expected_generation", 0)

        # Red 1: unauthenticated
        env_unauth = build_rpc_envelope(config, method, sample_params)
        st_no_auth, _, raw_no_auth = http_call(
            opener,
            origin + "/api/v2/rpc",
            method="POST",
            headers={"Origin": origin, "Content-Type": "application/json"},
            body=env_unauth,
        )
        # Red 2: wrong Origin
        env_origin = build_rpc_envelope(config, method, sample_params)
        st_bad_origin, _, raw_bad_origin = http_call(
            opener,
            origin + "/api/v2/rpc",
            method="POST",
            headers={
                **auth_headers,
                "Origin": "https://evil.example",
                "Content-Type": "application/json",
            },
            body=env_origin,
        )
        # Red 3: stale proof
        stale_proof = {
            "id": "proof-stale",
            "request_sha256": request_digest(config, method, sample_params),
            "expires_at": "2020-01-01T00:00:00Z",
        }
        env_stale = build_rpc_envelope(config, method, sample_params, proof=stale_proof)
        st_stale, _, raw_stale = http_call(
            opener,
            origin + "/api/v2/rpc",
            method="POST",
            headers=post_headers,
            body=env_stale,
        )
        # Red 4: missing proof
        env_no_proof = build_rpc_envelope(config, method, sample_params)
        st_no_proof, _, raw_no_proof = http_call(
            opener,
            origin + "/api/v2/rpc",
            method="POST",
            headers=post_headers,
            body=env_no_proof,
        )
        ev_ctrl = recorder.save(
            f"http/{aid.lower()}_controls.json",
            {
                "unauth_status": st_no_auth,
                "wrong_origin_status": st_bad_origin,
                "stale_proof_status": st_stale,
                "missing_proof_status": st_no_proof,
                "base_generation": base_gen,
                "mutation_id": mutation_id,
            },
        )
        red_denied = (
            denied(st_no_auth, raw_no_auth, (401, 403))
            and denied(st_bad_origin, raw_bad_origin, (403,))
            and denied(st_stale, raw_stale, (401, 403, 404), stale=True)
            and denied(st_no_proof, raw_no_proof, (401, 403))
        )
        if not red_denied:
            raise FixtureError({"owner": "lb-v2-dashboard", "code": "red_control_failed",
                                "message": "action refused-control gate failed: " + aid})
        positive_ok, positive_ref = exercise_positive(
            opener, origin, config, post_headers, aid, method, positive_requests, recorder
        )
        if aid == "DASH-STOP":
            lifecycle = outcomes["DASH-LIFECYCLE"]
            lifecycle["ok"] = lifecycle["ok"] and positive_ok
            lifecycle["exit"] = 0 if lifecycle["ok"] else 2
            lifecycle["evidence"].append(positive_ref)
        passed = control_passed(red_denied, positive_ok)
        outcomes[aid] = {
            "ok": passed,
            "exit": 0 if passed else 2,
            "evidence": [ev_ctrl, positive_ref],
        }
        recorder.save("status/http-outcomes.json", outcomes)
        if not passed:
            raise FixtureError({"owner": "lb-v2-dashboard", "code": "action_failed",
                                "message": "positive action or causal read-back failed: " + aid})
    return outcomes


def main():
    ctx_path, res_path = parse_args(sys.argv)
    ctx = json.loads(ctx_path.read_text(encoding="utf-8"))
    if ctx.get("schema") != "laneboss.e2e-context.v2":
        raise SystemExit("unsupported context schema")

    binary = Path(ctx["binary"])
    actual_bin_sha = sha256_bytes(binary.read_bytes())
    if actual_bin_sha != ctx["binary_sha256"]:
        raise SystemExit("binary sha256 mismatch")

    recorder = EvidenceRecorder(ctx["evidence_root"])
    config = ctx["config"]
    binding_file = ctx.get("binding_file", "")
    phase = ctx.get("phase", "candidate")
    mutation_id = ctx.get("mutation_id", "")

    dashboard_url = os.environ.get("LANEBOSS_DASHBOARD_URL", "")
    session_cookie = os.environ.get("LANEBOSS_DASHBOARD_COOKIE", "")
    control_file = os.environ.get("LANEBOSS_DASHBOARD_CONTROLS_FILE", "")
    inputs, probes, http_outcomes, common = None, {}, {}, []
    failure = None
    try:
        if not dashboard_url or not session_cookie or not control_file or not binding_file:
            raise FixtureError({"owner": "lb-v2-service", "code": "prerequisite_missing",
                                "message": "private HTTPS/session/controls/binding handoff is incomplete"})
        inputs = FixtureInputs(control_file, config, recorder)
        if any(inputs.document.get(field) != ctx[field] for field in ("binary_sha256", "source_sha256")):
            raise ValueError("fixture source or installed binary hash differs from the frozen context")
        ver_res = run_cli(binary, ["--version"])
        common.append(recorder.save("cli/version.json", ver_res))
        if ver_res["exit"] != 0:
            raise ValueError("installed version command failed")
        flags_ok, ev_flags = verify_cli_flag_guards(binary, config, recorder)
        common.append(ev_flags)
        if not flags_ok:
            raise ValueError("CLI refused-input controls failed")
        probes, _, ev_probes = probe_cli_views(binary, config, binding_file, recorder, inputs)
        common.append(ev_probes)
        if not all(cli_passed(probes.get(aid, {})) for aid, _ in VIEW_ASSERTIONS):
            raise ValueError("an installed CLI view lacks successful authority or populated data")
        http_outcomes = exercise_http_dashboard(
            dashboard_url, config, session_cookie, mutation_id, recorder, inputs)
    except (FixtureError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure = error.error if isinstance(error, FixtureError) else {
            "owner": "lb-v2-dashboard", "code": "case_failed", "message": str(error)}
        common.append(recorder.save("status/first-failure.json", {"error": failure}))
        partial = recorder.root / "status/http-outcomes.json"
        if partial.exists():
            http_outcomes = json.loads(partial.read_bytes())

    # The producer runs independently of this case and collects its HTTPS,
    # retained native human connection, and every action target through actual
    # public operations and native read-backs. CLI exit alone never credits it.
    external = None
    required = set()
    if inputs is not None:
        for target in inputs.document.get("targets", []):
            required.add((target["life_id"], target["run"]))
        for aid, request in inputs.cache.items():
            params = request.get("params", {})
            target = params.get("target")
            if target:
                required.add((target["life_id"], target["run"]))
                if aid == "DASH-RESUME" and http_outcomes.get(aid, {}).get("ok"):
                    required.add((target["life_id"], target["run"] + 1))
            elif params.get("recipient_life_id"):
                required.add((params["recipient_life_id"], 1))
        try:
            external = inputs.collect(failure)
        except (FixtureError, OSError, ValueError, KeyError, TypeError) as error:
            external = {"error": error.error if isinstance(error, FixtureError) else str(error)}
    external_ok = external_collected(external, required)
    cli_quiet = bool(CLI_EXITS) and all(type(code) is int for code in CLI_EXITS)
    processes_quiescent = cli_quiet and external_ok
    temporary_resources_collected = processes_quiescent and external_ok
    assertions = []
    for aid in ASSERTION_IDS:
        info = http_outcomes.get(aid, {})
        cli_ok = aid not in dict(VIEW_ASSERTIONS) or cli_passed(probes.get(aid, {}))
        passed = info.get("ok") is True and cli_ok
        assertions.append({"id": aid, "reached": bool(info), "verdict": "pass" if passed else "fail",
                           "observed_exit": 0 if passed else info.get("exit", 69),
                           "evidence": [*common, *info.get("evidence", [])]})
    col_ref = recorder.save(
        "collection/summary.json",
        {
            "phase": phase,
            "mutation_id": mutation_id,
            "timestamp_ns": time.time_ns(),
            "presence": "simulated" if recorder.simulated_presence else "not_proven",
            "human_approval": "not_proven",
            "scope": "CLI children, external HTTPS/session and all prepared action targets",
            "external": external,
            "required_targets": [list(target) for target in sorted(required)],
            "cli_exit_codes": CLI_EXITS,
            "processes_quiescent": processes_quiescent,
            "temporary_resources_collected": temporary_resources_collected,
        },
    )

    result_payload = {
        "schema": "laneboss.e2e-result.v2",
        "case_id": ctx["case_id"],
        "phase": phase,
        "mutation_id": mutation_id,
        "binary_sha256": actual_bin_sha,
        "source_sha256": ctx["source_sha256"],
        "assertions": assertions,
        "collection": {
            "processes_quiescent": processes_quiescent,
            "temporary_resources_collected": temporary_resources_collected,
            "evidence": [col_ref],
        },
    }
    write_atomic_json(res_path, result_payload)

    if failure or not processes_quiescent or any(row["verdict"] != "pass" for row in assertions):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

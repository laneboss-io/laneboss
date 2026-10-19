#!/usr/bin/env python3
"""Synthetic reader transport; no identity enrollment or service authority."""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import sys


def emit(value):
    # Keep visible whitespace so tests can detect reconstructed stdout.
    sys.stdout.buffer.write(b"  " + json.dumps(value, separators=(", ", ": ")).encode() + b"\n")
    sys.stdout.buffer.flush()


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--bridge":
        import os
        import socket
        from unittest.mock import patch
        sys.path.append(str(Path(__file__).resolve().parents[2]))
        from readsession import SessionReader
        from reader import serve
        root = Path(sys.argv[2])
        # Synthetic transport setup only; the service is not impersonated.
        with patch("readsession.immutable", side_effect=Path), patch("draft4.immutable", side_effect=Path):
            reader = SessionReader(root / "reader", sys.argv[4], root / "human.json", root / "proof.json",
                                   root / "session", {"PATH": "/usr/bin:/bin"}, command=("internal", "reader"))
            with socket.socket(fileno=int(sys.argv[3])) as listener:
                listener.listen(4)
                os.write(1, b"ready\n")
                serve(listener, reader, sys.argv[4], os.getuid())
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--binding", required=True)
    parser.add_argument("--proof", required=True)
    words = sys.argv[1:]
    if words[:2] == ["internal", "reader"]:
        words = words[2:]
    args = parser.parse_args(words)
    proof = json.loads(Path(args.proof).read_bytes())
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    emit({"protocol": "laneboss.rpc.v2", "schema": 2, "request_id": secrets.token_hex(16), "last_seq": 1,
          "result": {"id": secrets.token_hex(16), "config": args.config, "expires_at": expiry,
                     "idle_expires_at": expiry, "simulated_presence": proof.get("simulated_presence", False)}})
    for raw in sys.stdin.buffer:
        Path("actual-input").write_bytes(raw)
        request = json.loads(raw)
        reply = {key: request[key] for key in ("protocol", "schema", "request_id")}
        reply["last_seq"] = 2
        if request["params"].get("fail"):
            error = {"code": "forbidden", "message": "synthetic reader refusal", "instead": "Retain this transport control.", "retryable": False}
            reply["error"] = error
            emit(reply)
            sys.stderr.buffer.write(json.dumps(error).encode() + b"\n")
            return 13
        reply["result"] = {"echo": request["params"], "method": request["method"]}
        emit(reply)
    return 0


if __name__ == "__main__":
    sys.exit(main())

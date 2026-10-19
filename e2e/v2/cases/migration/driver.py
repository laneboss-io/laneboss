#!/usr/bin/env python3
"""Black-box acceptance driver for MIGRATE-ROLLBACK (lb-v2-migration)."""

import argparse
import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def tree_snapshot(root: Path) -> dict:
    snap = {}
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        if p.is_symlink():
            snap[rel] = ("symlink", os.readlink(p))
        elif p.is_file():
            snap[rel] = ("file", sha256_file(p), p.stat().st_size)
        elif p.is_dir():
            snap[rel] = ("dir", p.stat().st_mode & 0o777)
    return snap


def make_blob_ref(obj_id: str, data: bytes, cls: str = "manifest") -> dict:
    return {
        "id": obj_id,
        "sha256": sha256_bytes(data),
        "bytes": len(data),
        "class": cls,
    }


def event_hash(env: dict) -> str:
    body = {
        "id": env["id"],
        "kind": env["kind"],
        "lane": env["lane"],
        "actor": env["actor"],
        "occurred_at": env["occurred_at"],
        "payload": env["payload"],
        "protocol_version": env["protocol_version"],
        "seq": env["seq"],
        "recorded_at": env["recorded_at"],
    }
    return sha256_bytes(canonical_json(body).encode("utf-8"))


def build_events_db(
    db_path: Path, cfg_name: str, store_id: str, created_at: str, events: list, projections: dict
):
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("CREATE TABLE meta (\n    key TEXT PRIMARY KEY,\n    value TEXT NOT NULL\n)")
    cur.execute(
        "CREATE TABLE events (\n"
        "    seq INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "    id TEXT NOT NULL UNIQUE,\n"
        "    kind TEXT NOT NULL,\n"
        "    lane TEXT,\n"
        "    actor TEXT NOT NULL,\n"
        "    occurred_at TEXT,\n"
        "    payload TEXT NOT NULL,\n"
        "    protocol_version TEXT NOT NULL,\n"
        "    recorded_at TEXT NOT NULL,\n"
        "    sha256 TEXT NOT NULL\n)"
    )
    cur.execute("CREATE TABLE lanes (\n    lane TEXT PRIMARY KEY,\n    projection TEXT NOT NULL\n)")
    cur.execute(
        "CREATE TRIGGER events_no_update BEFORE UPDATE ON events\n"
        "BEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"
    )
    cur.execute(
        "CREATE TRIGGER events_no_delete BEFORE DELETE ON events\n"
        "BEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"
    )
    cur.execute(
        "CREATE TRIGGER events_no_replace BEFORE INSERT ON events\n"
        "WHEN EXISTS (SELECT 1 FROM events WHERE seq = NEW.seq OR id = NEW.id)\n"
        "BEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"
    )
    cur.execute(
        "CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta\n"
        "BEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"
    )
    cur.execute(
        "CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta\n"
        "BEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"
    )
    meta = {
        "config": cfg_name,
        "created_at": created_at,
        "format": "event-store",
        "store_id": store_id,
    }
    for k in sorted(meta.keys()):
        cur.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (k, meta[k]))
    cur.execute(
        "CREATE TRIGGER meta_no_insert BEFORE INSERT ON meta\n"
        "BEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"
    )
    cur.execute("PRAGMA user_version = 1")
    for ev in events:
        payload_txt = canonical_json(ev["payload"])
        cur.execute(
            "INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ev["seq"],
                ev["id"],
                ev["kind"],
                ev["lane"],
                ev["actor"],
                ev["occurred_at"],
                payload_txt,
                ev["protocol_version"],
                ev["recorded_at"],
                ev["sha256"],
            ),
        )
    for lane_name in sorted(projections.keys()):
        cur.execute(
            "INSERT INTO lanes (lane, projection) VALUES (?, ?)",
            (lane_name, canonical_json(projections[lane_name])),
        )
    conn.commit()
    conn.close()


def build_decisions_export() -> tuple[bytes, dict]:
    rec = {
        "id": "dec-r48-blacklist",
        "kind": "owner-decision",
        "schema_version": 1,
        "asked_at": "2026-10-10T08:00:00+00:00",
        "answered_at": "2026-10-10T08:05:00+00:00",
        "project": "laneboss",
        "area": "policy",
        "topics": ["blacklist", "isolation"],
        "question": {
            "text": "Should commands use a blacklist or allowlist?",
            "background": "Isolation policy design.",
        },
        "answer": {
            "verbatim": "Blacklist only, never an allowlist.",
            "channel": "owner",
            "message_id": None,
            "sha256": sha256_bytes(b"Blacklist only, never an allowlist."),
        },
        "scope": {"applies_to": ["org", "lanes"]},
        "status": "in_force",
        "outcome": {},
        "provenance": {
            "recorded_by": "human",
            "recorded_at": "2026-10-10T08:06:00+00:00",
            "sources": [
                {
                    "path": "owner/decisions.md",
                    "line": 1,
                    "line_text": "R48: Blacklist only",
                    "sha256_of_line": sha256_bytes(b"R48: Blacklist only"),
                }
            ],
        },
    }
    first_sha = sha256_bytes(canonical_json(rec).encode("utf-8"))
    model_meta = {"model": "fake-embed-1", "provider": "fake", "dimension": 2}
    model_meta["entry_sha256"] = sha256_bytes(canonical_json(model_meta).encode("utf-8"))

    q_text = "Should commands use a blacklist or allowlist?\nIsolation policy design.\n\n\nblacklist\nisolation"
    q_sha = sha256_bytes(q_text.encode("utf-8"))
    vec_bytes = struct.pack("<ff", 0.5, 0.75)
    vec_b64 = base64.b64encode(vec_bytes).decode("ascii")

    egress_body = {
        "id": 1,
        "record_id": "dec-r48-blacklist",
        "which_text": "q_text",
        "text": q_text,
        "text_sha256": q_sha,
        "model": "fake-embed-1",
        "at": "2026-10-10T08:07:00+00:00",
        "endpoint_host": "127.0.0.1",
        "input_type": "document",
        "previous_entry_sha256": "",
    }
    egress_body["entry_sha256"] = sha256_bytes(canonical_json(egress_body).encode("utf-8"))

    vec_meta = {
        "record_id": "dec-r48-blacklist",
        "which_text": "q_text",
        "model": "fake-embed-1",
        "dimension": 2,
        "text": q_text,
        "text_sha256": q_sha,
        "vector_sha256": sha256_bytes(vec_bytes),
        "created_at": "2026-10-10T08:07:01+00:00",
    }
    vec_meta["entry_sha256"] = sha256_bytes(canonical_json(vec_meta).encode("utf-8"))
    vec_meta["vector"] = vec_b64

    manifest_line = {
        "type": "manifest",
        "format": "laneboss-decisions-jsonl",
        "schema_version": 1,
        "first_written": 1,
        "counts": {"records": 1, "models": 1, "vectors": 1, "egress": 1},
    }
    lines = [
        canonical_json(manifest_line),
        canonical_json({"type": "record", "record": rec, "first_written_sha256": first_sha}),
        canonical_json({"type": "model", "model": model_meta}),
        canonical_json({"type": "vector", "vector": vec_meta}),
        canonical_json({"type": "egress", "egress": egress_body}),
    ]
    raw = ("\n".join(lines) + "\n").encode("utf-8")
    return raw, {
        "record_id": rec["id"],
        "first_sha": first_sha,
        "vector_sha": vec_meta["vector_sha256"],
    }


def create_frozen_fixture(base_dir: Path, version: str, cfg_name: str) -> dict:
    root = base_dir / f"frozen-{version}"
    root.mkdir(parents=True, exist_ok=False)
    state_dir = root / "state"
    cfg_dir = root / "config"
    (cfg_dir / "projects").mkdir(parents=True, exist_ok=True)
    (cfg_dir / "rules").mkdir(parents=True, exist_ok=True)
    (state_dir / "lanes" / "alpha" / "inputs").mkdir(parents=True, exist_ok=True)
    (state_dir / "lanes" / "alpha" / "rendered").mkdir(parents=True, exist_ok=True)
    (state_dir / "lanes" / "beta" / "rendered").mkdir(parents=True, exist_ok=True)
    (state_dir / "lanes" / "beta" / "mail").mkdir(parents=True, exist_ok=True)
    (state_dir / "lanes" / "gamma" / "rendered").mkdir(parents=True, exist_ok=True)
    (state_dir / "lanes" / "gamma" / "worktree").mkdir(parents=True, exist_ok=True)
    (state_dir / "lanes" / "gamma" / "session").mkdir(parents=True, exist_ok=True)
    (state_dir / "archives").mkdir(parents=True, exist_ok=True)
    (state_dir / "owner").mkdir(parents=True, exist_ok=True)

    cfg_toml = (
        f'schema_version = 1\nname = "{cfg_name}"\nowner_channel = "owner"\n'
        '[owner_channels.owner]\nkind = "file"\npath = "owner/queue.jsonl"\n'
        '[runners.claudock]\ncommand = ["claudock"]\nresume = ["claudock"]\nprompt = "stdin"\n'
        '[supervisors.top]\nlevel = 5\nrunner = "claudock"\n'
    ).encode("utf-8")
    (cfg_dir / "config.toml").write_bytes(cfg_toml)
    (cfg_dir / "rules" / "standing.md").write_bytes(b"# Standing Rules\n")
    (cfg_dir / "projects" / "demo.toml").write_bytes(
        b'schema_version = 1\nname = "demo"\nrepository = "/work/demo"\nworkers = ["claudock"]\n'
    )

    brief_in = b"# Bootstrap lane\nRun the migration check.\n"
    brief_in_sha = sha256_bytes(brief_in)
    (state_dir / "lanes" / "alpha" / "inputs" / brief_in_sha).write_bytes(brief_in)

    proto_in = b"# Protocol 1.1.0\n"
    proto_in_sha = sha256_bytes(proto_in)
    (state_dir / "lanes" / "alpha" / "inputs" / proto_in_sha).write_bytes(proto_in)

    rendered_alpha = b"# Rendered Alpha Brief\n"
    rendered_alpha_sha = sha256_bytes(rendered_alpha)
    rendered_alpha_path = state_dir / "lanes" / "alpha" / "rendered" / f"{rendered_alpha_sha}.md"
    rendered_alpha_path.write_bytes(rendered_alpha)

    rendered_beta = b"# Rendered Beta Brief\n"
    rendered_beta_sha = sha256_bytes(rendered_beta)
    rendered_beta_path = state_dir / "lanes" / "beta" / "rendered" / f"{rendered_beta_sha}.md"
    rendered_beta_path.write_bytes(rendered_beta)

    alpha_log = b"run alpha\nread 25 bytes\n# Bootstrap lane\nexample-agent: done\n"
    (state_dir / "lanes" / "alpha" / "output.log").write_bytes(alpha_log)
    alpha_report = b"# Alpha Report\nCompleted task.\n"
    (state_dir / "lanes" / "alpha" / "report.md").write_bytes(alpha_report)

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        for arc_name, arc_bytes in [
            ("lane/output.log", alpha_log),
            ("lane/report.md", alpha_report),
        ]:
            ti = tarfile.TarInfo(name=arc_name)
            ti.size = len(arc_bytes)
            ti.mode = 0o600
            tf.addfile(ti, io.BytesIO(arc_bytes))
    tar_bytes = tar_buf.getvalue()
    tar_sha = sha256_bytes(tar_bytes)
    stem = "alpha-" + ("a1b2c3d4" * 4)
    (state_dir / "archives" / f"{stem}.tar").write_bytes(tar_bytes)
    arc_manifest = {
        "format": 1,
        "entries": [
            {
                "path": "lane/output.log",
                "type": "file",
                "size": len(alpha_log),
                "mode": 0o600,
                "sha256": sha256_bytes(alpha_log),
            },
            {
                "path": "lane/report.md",
                "type": "file",
                "size": len(alpha_report),
                "mode": 0o600,
                "sha256": sha256_bytes(alpha_report),
            },
        ],
        "remove_paths": [],
        "remove_paths_sha256": sha256_bytes(b"[]"),
    }
    arc_manifest_bytes = (json.dumps(arc_manifest, indent=2) + "\n").encode("utf-8")
    (state_dir / "archives" / f"{stem}.manifest.json").write_bytes(arc_manifest_bytes)
    arc_receipt = {
        "lane": "alpha",
        "run": 1,
        "tar": f"{stem}.tar",
        "sha256": tar_sha,
        "manifest": f"{stem}.manifest.json",
        "manifest_sha256": sha256_bytes(arc_manifest_bytes),
        "read_back": True,
        "remote_sha256": None,
        "remove_paths_sha256": sha256_bytes(b"[]"),
        "remove_count": 0,
    }
    arc_receipt_bytes = (canonical_json(arc_receipt) + "\n").encode("utf-8")
    (state_dir / "archives" / f"{stem}.receipt.json").write_bytes(arc_receipt_bytes)
    (state_dir / "archive-ledger.md").write_bytes(
        b"# Lane ledger\n\n## Archive\n\n- Lane alpha archived.\n"
    )

    mail1 = b"Delivered mail message 1 for beta.\n"
    mail1_sha = sha256_bytes(mail1)
    (state_dir / "lanes" / "beta" / "mail" / f"000000001-{mail1_sha}").write_bytes(mail1)

    mail2 = b"Waiting mail message 2 for beta.\n"
    mail2_sha = sha256_bytes(mail2)
    (state_dir / "lanes" / "beta" / "mail" / f"000000002-{mail2_sha}").write_bytes(mail2)

    (state_dir / "lanes" / "gamma" / "worktree" / "unfinished.txt").write_bytes(
        b"work in progress\n"
    )
    (state_dir / "lanes" / "gamma" / "session" / "history.jsonl").write_bytes(
        b'{"turn":1,"role":"assistant","text":"partial work"}\n'
    )

    owner_line = (
        canonical_json({"from": "supervisor:top", "to": "human", "text": "Owner summary 1"}) + "\n"
    )
    (state_dir / "owner" / "queue.jsonl").write_bytes(owner_line.encode("utf-8"))

    decisions_bytes, decisions_meta = build_decisions_export()
    (state_dir / "decisions.jsonl").write_bytes(decisions_bytes)

    store_id = "01234567" * 4
    created_at = "2026-10-15T00:00:00.000000Z"
    marker = {
        "config": cfg_name,
        "format": 2,
        "store": {"id": store_id, "created_at": created_at},
    }
    (state_dir / ".laneboss-state").write_bytes((canonical_json(marker) + "\n").encode("utf-8"))

    sock_path = f"/tmp/laneboss-1000/{cfg_name}-socket"
    launch1 = "11223344" * 4
    launch2 = "22334455" * 4
    launch3 = "33445566" * 4
    sess_uuid = "12345678-1234-4234-8234-123456789abc"
    rf_id = "rf-" + ("012345" * 4)
    cmd_txt = "printf 'blocked'"
    msg_txt = "refused by hook"

    start_alpha = {
        "run": 1,
        "how": "start",
        "launch": launch1,
        "runner": "claudock",
        "model": "claude-sonnet-4-20250514",
        "effort": "high",
        "account": "main",
        "chosen_by": {
            "runner": "supervisor",
            "model": "supervisor",
            "effort": "supervisor",
            "account": "supervisor",
        },
        "difficulty": "standard",
        "project": "demo",
        "worktree": str(state_dir / "lanes" / "alpha" / "worktree"),
        "branch": "alpha",
        "base": "deadbeef" * 5,
        "repository": "/work/demo",
        "budget_minutes": 30,
        "quiet_seconds": 60,
        "brief": {"path": str(rendered_alpha_path), "sha256": rendered_alpha_sha},
        "log": str(state_dir / "lanes" / "alpha" / "output.log"),
        "session": {"socket": sock_path, "name": "alpha"},
        "touches": [],
        "claims": None,
    }
    if version == "1.0.0-candidate":
        start_alpha["level"] = 3
        start_alpha["level_source"] = "org"
        start_alpha["starter"] = "supervisor:top"

    raw_events = [
        {
            "seq": 1,
            "id": "ev-alpha-started",
            "kind": "lane.started",
            "lane": "alpha",
            "actor": "laneboss",
            "occurred_at": None,
            "protocol_version": "1.1.0",
            "recorded_at": "2026-10-15T00:01:00.000000Z",
            "payload": start_alpha,
        },
        {
            "seq": 2,
            "id": "ev-alpha-refusal",
            "kind": "lane.refusal",
            "lane": "alpha",
            "actor": "laneboss",
            "occurred_at": None,
            "protocol_version": "1.2.0",
            "recorded_at": "2026-10-15T00:01:10.000000Z",
            "payload": {
                "run": 1,
                "refusal": rf_id,
                "guard": "raw-git-push",
                "kind": "hook",
                "format": "claude-code",
                "via": "hook",
                "hook": {"event": "PreToolUse", "name": "orghook"},
                "tool": "Bash",
                "at": "2026-10-15T00:01:09Z",
                "command": {
                    "text": cmd_txt,
                    "withheld": False,
                    "length": len(cmd_txt),
                    "sha256": sha256_bytes(cmd_txt.encode("utf-8")),
                },
                "message": {
                    "text": msg_txt,
                    "withheld": False,
                    "length": len(msg_txt),
                    "sha256": sha256_bytes(msg_txt.encode("utf-8")),
                },
                "targets": ["/work/demo/file.txt"],
                "call": {
                    "id": "call-1",
                    "record": {"path": "/work/demo/log.jsonl", "line": 1, "offset": 0, "item": 0},
                },
                "record": {"path": "/work/demo/log.jsonl", "line": 1, "offset": 0, "item": 0},
                "workarounds_checked": True,
            },
        },
        {
            "seq": 3,
            "id": "ev-alpha-ended",
            "kind": "lane.ended",
            "lane": "alpha",
            "actor": "laneboss",
            "occurred_at": None,
            "protocol_version": "1.2.0",
            "recorded_at": "2026-10-15T00:02:00.000000Z",
            "payload": {
                "run": 1,
                "reason": "exit",
                "exit_code": 0,
                "signal": None,
                "duration_seconds": 60,
                "pattern": None,
                "classification": None,
                "survivors": 0,
            },
        },
        {
            "seq": 4,
            "id": "ev-alpha-merged",
            "kind": "lane.state",
            "lane": "alpha",
            "actor": "human",
            "occurred_at": None,
            "protocol_version": "1.3.0",
            "recorded_at": "2026-10-15T00:03:00.000000Z",
            "payload": {"state": "merged"},
        },
        {
            "seq": 5,
            "id": "ev-alpha-cleaned",
            "kind": "lane.cleaned",
            "lane": "alpha",
            "actor": "human",
            "occurred_at": None,
            "protocol_version": "1.3.0",
            "recorded_at": "2026-10-15T00:04:00.000000Z",
            "payload": {
                "removed": [{"item": "branch", "name": "alpha"}],
                "kept": [
                    {
                        "item": "lane-directory",
                        "path": str(state_dir / "lanes" / "alpha"),
                        "why": "record",
                    }
                ],
            },
        },
        {
            "seq": 6,
            "id": "ev-beta-started-1",
            "kind": "lane.started",
            "lane": "beta",
            "actor": "laneboss",
            "occurred_at": None,
            "protocol_version": "1.2.0",
            "recorded_at": "2026-10-15T00:05:00.000000Z",
            "payload": {
                "run": 1,
                "how": "start",
                "launch": launch2,
                "runner": "claudock",
                "model": "claude-sonnet-4-20250514",
                "effort": None,
                "account": None,
                "chosen_by": {
                    "runner": "supervisor",
                    "model": "supervisor",
                    "effort": None,
                    "account": None,
                },
                "difficulty": None,
                "project": None,
                "worktree": str(state_dir / "lanes" / "beta" / "worktree"),
                "branch": None,
                "base": "deadbeef" * 5,
                "repository": None,
                "budget_minutes": 15,
                "quiet_seconds": 60,
                "brief": {"path": str(rendered_beta_path), "sha256": rendered_beta_sha},
                "log": str(state_dir / "lanes" / "beta" / "output.log"),
                "session": {"socket": sock_path, "name": "beta"},
                "session_id": sess_uuid,
                "mail": [],
                "idle_seconds": None,
                "touches": [],
                "claims": None,
            },
        },
        {
            "seq": 7,
            "id": "ev-beta-ended-1",
            "kind": "lane.ended",
            "lane": "beta",
            "actor": "laneboss",
            "occurred_at": None,
            "protocol_version": "1.2.0",
            "recorded_at": "2026-10-15T00:06:00.000000Z",
            "payload": {
                "run": 1,
                "reason": "exit",
                "exit_code": 0,
                "signal": None,
                "duration_seconds": 10,
                "pattern": None,
                "classification": None,
                "survivors": 0,
                "prompt": {"state": "written", "bytes": 24, "length": 24},
            },
        },
        {
            "seq": 8,
            "id": "ev-beta-mailed-1",
            "kind": "lane.mailed",
            "lane": "beta",
            "actor": "human",
            "occurred_at": None,
            "protocol_version": "1.2.0",
            "recorded_at": "2026-10-15T00:07:00.000000Z",
            "payload": {
                "sequence": 1,
                "sender": "human",
                "sha256": mail1_sha,
                "bytes": len(mail1),
            },
        },
        {
            "seq": 9,
            "id": "ev-beta-started-2",
            "kind": "lane.started",
            "lane": "beta",
            "actor": "laneboss",
            "occurred_at": None,
            "protocol_version": "1.2.0",
            "recorded_at": "2026-10-15T00:08:00.000000Z",
            "payload": {
                "run": 2,
                "how": "resume",
                "launch": launch3,
                "runner": "claudock",
                "model": "claude-sonnet-4-20250514",
                "effort": None,
                "account": None,
                "chosen_by": {
                    "runner": "previous",
                    "model": "previous",
                    "effort": None,
                    "account": None,
                },
                "difficulty": None,
                "project": None,
                "worktree": str(state_dir / "lanes" / "beta" / "worktree"),
                "branch": None,
                "base": "deadbeef" * 5,
                "repository": None,
                "budget_minutes": 15,
                "quiet_seconds": 60,
                "brief": {"path": str(rendered_beta_path), "sha256": rendered_beta_sha},
                "log": str(state_dir / "lanes" / "beta" / "output.log"),
                "session": {"socket": sock_path, "name": "beta"},
                "session_id": sess_uuid,
                "mail": [1],
                "idle_seconds": None,
                "touches": [],
                "claims": None,
            },
        },
        {
            "seq": 10,
            "id": "ev-beta-ended-2",
            "kind": "lane.ended",
            "lane": "beta",
            "actor": "laneboss",
            "occurred_at": None,
            "protocol_version": "1.2.0",
            "recorded_at": "2026-10-15T00:09:00.000000Z",
            "payload": {
                "run": 2,
                "reason": "exit",
                "exit_code": 0,
                "signal": None,
                "duration_seconds": 12,
                "pattern": None,
                "classification": None,
                "survivors": 0,
                "prompt": {"state": "written", "bytes": len(mail1), "length": len(mail1)},
            },
        },
        {
            "seq": 11,
            "id": "ev-beta-delivered-1",
            "kind": "lane.delivered",
            "lane": "beta",
            "actor": "laneboss",
            "occurred_at": None,
            "protocol_version": "1.2.0",
            "recorded_at": "2026-10-15T00:09:05.000000Z",
            "payload": {"run": 2, "sequences": [1]},
        },
        {
            "seq": 12,
            "id": "ev-beta-mailed-2",
            "kind": "lane.mailed",
            "lane": "beta",
            "actor": "human",
            "occurred_at": None,
            "protocol_version": "1.3.0",
            "recorded_at": "2026-10-15T00:10:00.000000Z",
            "payload": {
                "sequence": 2,
                "sender": "human",
                "sha256": mail2_sha,
                "bytes": len(mail2),
            },
        },
    ]
    for ev in raw_events:
        ev["sha256"] = event_hash(ev)

    projections = {
        "alpha": {
            "lane": "alpha",
            "state": "merged",
            "state_at": "2026-10-15T00:03:00.000000Z",
            "times": {
                "planned": None,
                "started": "2026-10-15T00:01:00.000000Z",
                "ended": "2026-10-15T00:02:00.000000Z",
                "timeout": None,
                "stuck": None,
                "resumed": None,
                "lost": None,
                "cleaned": "2026-10-15T00:04:00.000000Z",
            },
            "landing": {"merged": None, "deployed": None, "landed": None},
            "run": 1,
            "running": False,
            "runner": "claudock",
            "model": "claude-sonnet-4-20250514",
            "effort": "high",
            "account": "main",
            "worktree": str(state_dir / "lanes" / "alpha" / "worktree"),
            "branch": "alpha",
            "reason": "exit",
            "exit_code": 0,
            "resumes": 0,
            "lost": 0,
            "cleaned": True,
            "events": 5,
            "last_seq": 5,
            "refusals": {
                "recorded": {rf_id: {"run": 1, "seq": 2, "guard": "raw-git-push", "tool": "Bash"}},
                "suspected": {},
                "verdicts": [],
                "unreviewed": [],
            },
        },
        "beta": {
            "lane": "beta",
            "state": "waiting",
            "state_at": "2026-10-15T00:09:00.000000Z",
            "times": {
                "planned": None,
                "started": "2026-10-15T00:08:00.000000Z",
                "ended": "2026-10-15T00:09:00.000000Z",
                "timeout": None,
                "stuck": None,
                "resumed": None,
                "lost": None,
                "cleaned": None,
            },
            "landing": {"merged": None, "deployed": None, "landed": None},
            "run": 2,
            "running": False,
            "runner": "claudock",
            "model": "claude-sonnet-4-20250514",
            "effort": None,
            "account": None,
            "worktree": str(state_dir / "lanes" / "beta" / "worktree"),
            "branch": None,
            "reason": "exit",
            "exit_code": 0,
            "resumes": 0,
            "lost": 0,
            "cleaned": False,
            "events": 7,
            "last_seq": 12,
            "mail": {
                "turn_based": True,
                "idle_seconds": None,
                "last": 2,
                "waiting": [2],
                "returned": [],
                "in_flight": None,
                "delivered": 1,
                "settled": {
                    "run": 2,
                    "outcome": "delivered",
                    "reason": None,
                    "sequences": [1],
                    "announced": True,
                },
            },
        },
    }
    build_events_db(
        state_dir / "events.sqlite", cfg_name, store_id, created_at, raw_events, projections
    )

    quiescence = {
        "schema": "laneboss.quiescence.v2",
        "config": cfg_name,
        "source_version": version,
        "dispatch_frozen": True,
        "loop_stopped": True,
        "active_writers": 0,
        "survivors": 0,
        "running_lanes": [],
        "unfinished_lanes": ["beta"],
        "observed_at": "2026-10-15T00:15:00Z",
    }
    quiescence_bytes = (canonical_json(quiescence) + "\n").encode("utf-8")
    (root / "quiescence.json").write_bytes(quiescence_bytes)

    events_chain_sha = sha256_bytes(
        "\n".join(f"{e['seq']}:{e['id']}:{e['sha256']}" for e in raw_events).encode("utf-8")
    )
    verification = {
        "schema": "laneboss.verification.v2",
        "ok": True,
        "config": cfg_name,
        "store_id": store_id,
        "events": len(raw_events),
        "lanes": len(projections),
        "events_chain_sha256": events_chain_sha,
        "decisions_sha256": sha256_bytes(decisions_bytes),
    }
    verification_bytes = (canonical_json(verification) + "\n").encode("utf-8")
    (root / "verification.json").write_bytes(verification_bytes)

    entries = []
    blobs = {}
    for p in sorted(root.rglob("*")):
        if p.name in ("quiescence.json", "verification.json"):
            continue
        rel = p.relative_to(root).as_posix()
        if p.is_dir():
            entries.append({"path": rel, "kind": "directory", "mode": 0o700})
        elif p.is_file():
            data = p.read_bytes()
            obj_id = "blob-" + sha256_bytes((version + ":" + rel).encode("utf-8"))[:24]
            bref = make_blob_ref(obj_id, data, "archive")
            blobs[obj_id] = data
            entries.append({"path": rel, "kind": "file", "mode": 0o600, "content": bref})

    safe_ver = version.replace(".", "-")
    q_id = f"blob-quiescence-{safe_ver}"
    v_id = f"blob-verify-{safe_ver}"
    blobs[q_id] = quiescence_bytes
    blobs[v_id] = verification_bytes

    manifest = {
        "schema": "laneboss.migration.v2",
        "source_version": version,
        "source_protocol": "1.3.0",
        "source_revision": "d6f2a96",
        "inventory": {"schema": "laneboss.objects.v2", "entries": entries},
        "quiescence": make_blob_ref(q_id, quiescence_bytes, "manifest"),
        "verification": make_blob_ref(v_id, verification_bytes, "manifest"),
    }
    manifest_bytes = (canonical_json(manifest) + "\n").encode("utf-8")
    m_id = f"blob-manifest-{safe_ver}"
    blobs[m_id] = manifest_bytes
    manifest_path = root / "migration-manifest.json"
    manifest_path.write_bytes(manifest_bytes)

    return {
        "root": root,
        "state_dir": state_dir,
        "store_id": store_id,
        "created_at": created_at,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "manifest_ref": make_blob_ref(m_id, manifest_bytes, "manifest"),
        "quiescence": quiescence,
        "verification": verification,
        "blobs": blobs,
        "events": raw_events,
        "projections": projections,
        "decisions_meta": decisions_meta,
    }


def write_result_atomic(result_path: Path, payload: dict):
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=str(result_path.parent), prefix=".res-", delete=False, encoding="utf-8"
    ) as tf:
        json.dump(payload, tf, indent=2)
        tf.write("\n")
        tf.flush()
        os.fsync(tf.fileno())
        tmp_name = tf.name
    os.replace(tmp_name, str(result_path))


def record_evidence(ev_root: Path, rel_path: str, data: bytes) -> dict:
    full = ev_root / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    with full.open("xb") as stream:
        stream.write(data)
    return {
        "path": rel_path,
        "sha256": sha256_bytes(data),
        "bytes": len(data),
    }


class CaseFailure(Exception):
    def __init__(self, stage, message, exit_code=1, owner="lb-v2-migration"):
        super().__init__(message)
        self.stage = stage
        self.exit_code = exit_code
        self.owner = owner


class MigrationCLI:
    """One explicit binding; exact retained keys and bytes for every CLI call."""

    def __init__(self, context, evidence_root, test_root, evidence):
        self.context = context
        self.evidence_root = evidence_root
        self.test_root = test_root
        self.evidence = evidence
        self.calls = 0
        self.processes = []
        self.open_uploads = set()
        self.upload_uncertain = False
        self.observed_exit = None
        self.keys_path = test_root / "migration-mutation-keys.json"
        if self.keys_path.exists():
            self.keys = json.loads(self.keys_path.read_bytes())
        else:
            self.keys = {}

    def keep(self, name, data):
        reference = record_evidence(self.evidence_root, name, data)
        self.evidence.append(reference)
        return self.evidence_root / name

    def key(self, label):
        if label not in self.keys:
            self.keys[label] = os.urandom(16).hex()
            self.keys_path.write_text(canonical_json(self.keys) + "\n", encoding="utf-8")
        key = self.keys[label]
        if not isinstance(key, str) or len(key) != 32 or any(c not in "0123456789abcdef" for c in key):
            raise CaseFailure("retained-keys", "invalid retained mutation key")
        return key

    def invoke(self, label, words, request=None, flags=(), expected_error=None, retain_key=True):
        self.calls += 1
        stem = f"cli/call-{self.calls:04d}"
        argv = [self.context["binary"], *words, "--config", self.context["config"],
                "--binding", self.context["binding_file"], *flags]
        if request is not None:
            source = (canonical_json(request) + "\n").encode("utf-8")
            path = self.keep(stem + "-input.json", source)
            argv += ["--request", str(path)]
        # Reads may generate a new key, but every mutation must retain its own.
        # A retry label reuses the same key even when its body was changed.
        if retain_key:
            argv += ["--idempotency-key", self.key(label)]
        self.keep(stem + "-argv.json", (canonical_json(argv) + "\n").encode())
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin"}, start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()  # Exact owned PID; never a command-line pattern.
            stdout, stderr = process.communicate(timeout=5)
        self.observed_exit = process.returncode
        try:
            os.killpg(process.pid, 0)
            group_absent = False
        except ProcessLookupError:
            group_absent = True
        except PermissionError:
            group_absent = False
        self.processes.append({"pid": process.pid, "exit": process.returncode,
                               "group_absent": group_absent, "timed_out": timed_out})
        self.keep(stem + "-out", stdout)
        self.keep(stem + "-err", stderr)
        self.keep(stem + "-exit.json", (canonical_json(process.returncode) + "\n").encode())
        if timed_out or not group_absent:
            raise CaseFailure(label, "CLI deadline or process collection failed")
        if process.returncode != 0:
            try:
                error = json.loads(stderr)
            except (ValueError, UnicodeError) as exc:
                raise CaseFailure(label, "CLI failure omitted its typed error") from exc
            if not isinstance(error, dict):
                raise CaseFailure(label, "CLI failure returned an invalid error shape")
            if expected_error is not None:
                if process.returncode != 2 or error.get("code") != expected_error or stdout:
                    raise CaseFailure(label, "negative control failed for the wrong reason")
                return error
            owner = error.get("owner") or (
                "lb-v2-identity" if error.get("code") in {"unauthenticated", "forbidden"}
                else "lb-v2-service"
            )
            raise CaseFailure(label, "required CLI operation failed", process.returncode, owner)
        if expected_error is not None:
            raise CaseFailure(label, "forbidden operation succeeded")
        try:
            result = json.loads(stdout)
        except (ValueError, UnicodeError) as exc:
            raise CaseFailure(label, "CLI success omitted its typed result") from exc
        if not isinstance(result, dict):
            raise CaseFailure(label, "CLI result is not a typed object")
        return result


def upload_blob_via_cli(cli, label, data, cls):
    digest = sha256_bytes(data)
    cli.upload_uncertain = True
    upload = cli.invoke(label + "/begin", ["blob", "begin"],
                        {"class": cls, "bytes": len(data), "sha256": digest})
    object_id = upload["object_id"]
    chunk_size = upload["max_chunk_bytes"]
    if not isinstance(object_id, str) or type(chunk_size) is not int or not 0 < chunk_size <= 262144:
        raise CaseFailure(label, "invalid bounded upload lease")
    cli.open_uploads.add(object_id)
    cli.upload_uncertain = False
    for offset in range(0, len(data), chunk_size):
        part = data[offset:offset + chunk_size]
        chunk = cli.invoke(label + f"/chunk/{offset}", ["blob", "chunk"], {
            "object_id": object_id, "offset": offset,
            "data": base64.b64encode(part).decode("ascii"), "sha256": sha256_bytes(part),
        })
        if chunk.get("object_id") != object_id:
            raise CaseFailure(label, "chunk receipt belongs to another upload")
    committed = cli.invoke(label + "/commit", ["blob", "commit"],
                           {"object_id": object_id, "sha256": digest})
    if committed != make_blob_ref(object_id, data, cls):
        raise CaseFailure(label, "committed reference differs from actual uploaded bytes")
    cli.open_uploads.remove(object_id)
    return committed


def upload_frozen_fixture(cli, fixture, version):
    manifest = deepcopy(fixture["manifest"])
    for entry in manifest["inventory"]["entries"]:
        if entry["kind"] == "file":
            offline_ref = entry["content"]
            data = fixture["blobs"][offline_ref["id"]]
            entry["content"] = upload_blob_via_cli(
                cli, version + "/" + entry["path"], data, offline_ref["class"]
            )
    for field in ("quiescence", "verification"):
        offline_ref = manifest[field]
        manifest[field] = upload_blob_via_cli(
            cli, version + "/" + field, fixture["blobs"][offline_ref["id"]], "manifest"
        )
    source = (canonical_json(manifest) + "\n").encode("utf-8")
    cli.keep("committed/manifest-" + version + ".json", source)
    return manifest, upload_blob_via_cli(cli, version + "/manifest", source, "manifest")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--context", required=True)
    parser.add_argument("--result", required=True)
    ns = parser.parse_args()
    context_path, result_path = Path(ns.context), Path(ns.result)
    if not context_path.is_absolute() or not result_path.is_absolute():
        raise CaseFailure("context", "paths must be absolute", 2)
    context_bytes = context_path.read_bytes()
    context = json.loads(context_bytes)
    if context.get("schema") != "laneboss.e2e-context.v2" or context.get("case_id") != "migration":
        raise CaseFailure("context", "invalid context schema or case ID", 2)
    phase, mutation = context["phase"], context.get("mutation_id", "")
    if phase not in {"red", "candidate"} or bool(mutation) != (phase == "red"):
        raise CaseFailure("context", "invalid phase or mutation", 2)
    binary = Path(context["binary"])
    if not binary.is_absolute() or not binary.is_file() or sha256_file(binary) != context["binary_sha256"]:
        raise CaseFailure("artifact", "installed binary missing or digest mismatch", 2)
    test_root, evidence_root = Path(context["test_root"]), Path(context["evidence_root"])
    if not test_root.is_absolute() or not evidence_root.is_absolute():
        raise CaseFailure("context", "test and evidence roots must be absolute", 2)
    test_root.mkdir(parents=True, exist_ok=True)
    evidence_root.mkdir(parents=True, exist_ok=True)
    test_root, evidence_root = test_root.resolve(strict=True), evidence_root.resolve(strict=True)
    if not result_path.parent.resolve(strict=True).is_relative_to(test_root):
        raise CaseFailure("context", "result escapes disposable test scope", 2)
    binding_path = Path(context["binding_file"])
    if not binding_path.is_absolute():
        raise CaseFailure("binding", "installed binding must be absolute", 2)

    evidence = []
    cli = MigrationCLI(context, evidence_root, test_root, evidence)
    cli.keep("context-input.json", context_bytes)
    fixtures, snapshots, completed_rows = {}, {}, set()
    failure = None
    try:
        for version in ("0.7.0", "1.0.0-candidate"):
            fixture = create_frozen_fixture(test_root, version, context["config"])
            fixtures[version] = fixture
            snapshots[version] = tree_snapshot(fixture["root"])
            source = io.BytesIO()
            with tarfile.open(fileobj=source, mode="w:gz") as archive:
                archive.add(fixture["root"], arcname="frozen-" + version)
            cli.keep("fixtures/source-" + version + ".tar.gz", source.getvalue())

        for label, words, flags in (
            ("bad-plan-flag", ["migration", "plan"], ["--unknown-flag"]),
            ("missing-plan-input", ["migration", "plan"], []),
            ("bad-apply-flag", ["migration", "apply"], ["--unknown-flag"]),
        ):
            cli.invoke(label, words, flags=flags, expected_error="invalid_request")
        completed_rows.add("local-invalid-inputs")

        # A missing mutation key must fail before binding discovery or effects.
        missing_error = cli.invoke("retained-key", ["migration", "apply"],
                                   flags=["--plan-id", "migration-plan-probe"],
                                   expected_error="invalid_request", retain_key=False)
        if "retained" not in missing_error.get("message", ""):
            raise CaseFailure("retained-key", "mutation without a retained key reached the wrong gate")
        completed_rows.add("retained-mutation-key")

        health = cli.invoke("health", ["health"], {
            "client_version": "", "artifact_sha256": context["binary_sha256"],
        })
        if health.get("protocol") != "laneboss.rpc.v2" or health.get("schema") != 2 or not health.get("ready") or health.get("artifact_sha256") != context["binary_sha256"]:
            raise CaseFailure("health", "service readiness or installed artifact mismatch")
        binding = json.loads(binding_path.read_bytes())
        if (binding.get("contract_revision") != "v2.0-draft.4" or binding.get("config") != context["config"]
                or binding.get("class") != "human"):
            raise CaseFailure("human-fixture", "migration needs an installed human binding and a verified human ceremony fixture", 69, "lb-v2-identity")

        # Only real committed references enter requests. No invented offline ID
        # is a live service handle. Missing per-operation human proofs or a
        # missing browsing session stops at the actual typed service refusal.
        committed = {}
        for version, fixture in fixtures.items():
            manifest, reference = upload_frozen_fixture(cli, fixture, version)
            reference_file = cli.keep("committed/ref-" + version + ".json",
                                      (canonical_json(reference) + "\n").encode())
            plan = cli.invoke(version + "/plan", ["migration", "plan"], flags=[
                "--source-version", version, "--content-ref", str(reference_file),
            ])
            problems = plan.get("problems")
            if not isinstance(problems, list) or any(not isinstance(item, str) or not item for item in problems):
                raise CaseFailure(version + "/plan", "plan problems are not a typed diagnostic list")
            if problems:
                raise CaseFailure(version + "/plan", "migration prerequisites: " + "; ".join(problems), 69, "lb-v2-migration")
            if (plan.get("source_version") != version or plan.get("source_manifest") != reference
                    or plan.get("target_schema") != 2
                    or not plan.get("id") or not plan.get("requires_relaunch")):
                raise CaseFailure(version + "/plan", "positive frozen-source plan is incomplete")
            committed[version] = (manifest, plan)
            completed_rows.add("plan-" + version)

        manifest = committed["0.7.0"][0]
        controls = {}
        corrupt = deepcopy(manifest)
        corrupt["inventory"]["entries"].append({
            "path": "state/missing-file.txt", "kind": "file", "mode": 0o600,
            "content": make_blob_ref("blob-nonexistent", b"missing", "archive"),
        })
        controls["corrupt-evidence"] = (corrupt, "integrity")
        writer = deepcopy(manifest)
        wal = upload_blob_via_cli(cli, "control/wal", b"active-wal-writer", "archive")
        writer["inventory"]["entries"].append({
            "path": "state/events.sqlite-wal", "kind": "file", "mode": 0o600, "content": wal,
        })
        controls["active-writer"] = (writer, "conflict")
        rehashed = deepcopy(manifest)
        events = deepcopy(fixtures["0.7.0"]["events"])
        events[0]["actor"] = "forged-actor"
        events[0]["sha256"] = event_hash(events[0])
        rehashed_path = test_root / "rehashed-events.sqlite"
        build_events_db(rehashed_path, context["config"], fixtures["0.7.0"]["store_id"],
                        fixtures["0.7.0"]["created_at"], events, fixtures["0.7.0"]["projections"])
        rehashed_ref = upload_blob_via_cli(cli, "control/rehashed-db", rehashed_path.read_bytes(), "archive")
        for entry in rehashed["inventory"]["entries"]:
            if entry["path"] == "state/events.sqlite":
                entry["content"] = rehashed_ref
        controls["rehashed-history"] = (rehashed, "integrity")
        inplace = deepcopy(manifest)
        quiescence = deepcopy(fixtures["0.7.0"]["quiescence"])
        quiescence["in_place_ownership"] = True
        inplace["quiescence"] = upload_blob_via_cli(
            cli, "control/inplace-quiescence", (canonical_json(quiescence) + "\n").encode(), "manifest"
        )
        controls["inplace-ownership"] = (inplace, "conflict")
        for label, (control, error_code) in controls.items():
            reference = upload_blob_via_cli(cli, "control/" + label,
                                           (canonical_json(control) + "\n").encode(), "manifest")
            cli.invoke("control/" + label + "/plan", ["migration", "plan"],
                       {"source_version": "0.7.0", "source_manifest": reference},
                       expected_error=error_code)
            completed_rows.add(label)

        # Coverage is itself a gate. Plan-only evidence cannot pass the complete
        # MIGRATE-ROLLBACK assertion. The frozen harness has no human ceremony,
        # migration completion or matched rollback/relaunch observation port.
        required_rows = {
            "apply", "service-read-back", "no-duplicate-mail", "inert-decision-history",
            "confined-relaunch", "matched-rollback", "retain-new-work",
        }
        missing = sorted(required_rows - completed_rows)
        if missing:
            cli.keep("dependency/missing-rows.json", (canonical_json({
                "missing": missing, "needs": ["lb-v2-service", "lb-v2-identity", "lb-v2-grants",
                                             "lb-v2-lifecycle", "lb-v2-integrate"],
            }) + "\n").encode())
            raise CaseFailure("runtime-row-coverage", "complete migration evidence is unavailable", 69)
    except (CaseFailure, KeyError, ValueError, OSError, subprocess.SubprocessError) as exc:
        failure = exc if isinstance(exc, CaseFailure) else CaseFailure("setup", type(exc).__name__)

    originals_intact = all(tree_snapshot(fixture["root"]) == snapshots[version]
                           for version, fixture in fixtures.items())
    if not originals_intact:
        failure = CaseFailure("originals", "migration modified frozen originals")
    cli.keep("originals.json", (canonical_json({
        "unchanged": originals_intact, "snapshots": snapshots,
    }) + "\n").encode())
    cli.keep("coverage.json", (canonical_json({"completed_rows": sorted(completed_rows)}) + "\n").encode())
    if cli.keys_path.exists():
        cli.keep("retained-mutation-keys.json", cli.keys_path.read_bytes())
    if failure:
        cli.keep("dependency/missing.json", (canonical_json({
            "stage": failure.stage, "owner": failure.owner, "message": str(failure),
            "case_exit": failure.exit_code, "last_cli_exit": cli.observed_exit,
        }) + "\n").encode())
    collection = {
        "cli_processes": cli.processes, "open_upload_ids": sorted(cli.open_uploads),
        "upload_outcome_unknown": cli.upload_uncertain,
        "retained_fixture_roots": [str(fixture["root"]) for fixture in fixtures.values()],
    }
    collection_ref = record_evidence(evidence_root, "collection.json",
                                     (canonical_json(collection) + "\n").encode())
    evidence.append(collection_ref)
    exit_code = failure.exit_code if failure else 0
    result = {
        "schema": "laneboss.e2e-result.v2", "case_id": "migration", "phase": phase,
        "mutation_id": mutation, "binary_sha256": context["binary_sha256"],
        "source_sha256": context["source_sha256"],
        "assertions": [{"id": "MIGRATE-ROLLBACK", "reached": failure is None,
                        "verdict": "fail" if failure else "pass", "observed_exit": exit_code,
                        "evidence": evidence}],
        "collection": {
            "processes_quiescent": all(row["exit"] is not None and row["group_absent"]
                                      for row in cli.processes),
            "temporary_resources_collected": not cli.open_uploads and not cli.upload_uncertain,
            "evidence": [collection_ref],
        },
    }
    # Retain failed inputs, keys, source fixtures and outputs for the supervisor.
    # No source fixture or live service is removed after a failed gate.
    write_result_atomic(result_path, result)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

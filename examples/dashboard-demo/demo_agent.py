#!/usr/bin/env python3
"""Synthetic stream-json runner that reads real input and holds real processes.

Thinking/message text is demo narration. Read results, CLI outcomes, heartbeat
receipts and elapsed time come from actual operations, never invented test passes.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def emit(kind, block):
    print(json.dumps({"type": kind, "message": {"content": [block]}}), flush=True)


def message(text):
    emit("assistant", {"type": "text", "text": text})


def failed_output(label, stdout, stderr):
    print(f"FAIL OUTPUT {label}: stdout", flush=True)
    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
    print(f"\nFAIL OUTPUT {label}: stderr", flush=True)
    sys.stdout.buffer.write(stderr)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(stderr)
    sys.stderr.buffer.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "resume"))
    parser.add_argument("--mode", choices=("finish", "hold"), required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--lane", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--brief-file", type=Path)
    parser.add_argument("--message-file", type=Path)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path("/tmp") or not work.name.startswith("lb-dash-shots."):
        raise ValueError("demo work directory is outside the isolated run")
    source = args.message_file if args.action == "resume" else args.brief_file
    if source is None:
        raise ValueError("the runner needs its actual brief or follow-up file")
    emit("assistant", {"type": "thinking", "thinking":
         f"Synthetic demo: read the {args.action} input for {args.lane} before recording progress."})
    tool_id = f"demo-read-{args.action}"
    emit("assistant", {"type": "tool_use", "id": tool_id, "name": "Read",
         "input": {"document": "kept lane follow-up" if args.action == "resume" else "kept lane brief"}})
    data = source.read_bytes()
    task = data.decode("utf-8").split("## Your task\n", 1)[-1]
    heading = next(line for line in task.splitlines() if line.startswith("# "))
    emit("user", {"type": "tool_result", "tool_use_id": tool_id, "is_error": False,
         "content": f"Read {len(data)} bytes from the kept input.\n{heading}"})
    message(f"Read complete for {args.lane}. Demo model label: {args.model}; no AI-service request.")

    if args.mode == "finish":
        return
    release = work / "control/release.json"
    heartbeat = work / "control" / f"{args.lane}-heartbeat.json"
    pulse = 0
    started = time.monotonic()
    next_pulse = started
    while not release.exists():
        now = time.monotonic()
        if now - started >= 480:
            raise TimeoutError("capture did not release the held demo runner")
        if now >= next_pulse:
            pulse += 1
            event = {"kind": "demo.heartbeat", "lane": args.lane, "actor": "lane:" + args.lane,
                     "protocol_version": "1.3.0", "payload": {
                         "model": args.model, "runner": args.mode, "count": pulse,
                         "duration_seconds": round(now - started, 3), "source": "synthetic demo"}}
            heartbeat.write_text(json.dumps(event) + "\n", encoding="utf-8")
            try:
                result = subprocess.run([str(work / "bin/laneboss"), "event", "append", "--config", "demo",
                                         "--file", str(heartbeat)], capture_output=True, timeout=30)
            except subprocess.TimeoutExpired as error:
                failed_output(args.lane + "-heartbeat", error.stdout or b"", error.stderr or b"")
                raise
            evidence = work / "evidence" / f"{args.lane}-pulse-{pulse}"
            evidence.with_suffix(".stdout").write_bytes(result.stdout)
            evidence.with_suffix(".stderr").write_bytes(result.stderr)
            if result.returncode:
                failed_output(args.lane + "-heartbeat", result.stdout, result.stderr)
                sys.exit(result.returncode)
            receipt = json.loads(result.stdout)
            if not receipt.get("seq"):
                raise ValueError("the heartbeat has no stored sequence")
            message(f"Demo heartbeat {pulse} recorded; waiting for capture to finish.")
            next_pulse = now + 10
        time.sleep(0.25)
    message(f"Capture released {args.lane}; the held demo process is ending.")


if __name__ == "__main__":
    main()

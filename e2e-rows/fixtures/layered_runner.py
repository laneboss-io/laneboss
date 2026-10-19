"""Credential-free runner double: read the real prompt, emit env names only."""

import hashlib
import json
import os
from pathlib import Path
import sys
import time
import subprocess
import uuid


account = None
if len(sys.argv) > 2 and sys.argv[-2] == "--account":
    account = sys.argv[-1]
    del sys.argv[-2:]
prompt, calls, gate, model, effort, session = sys.argv[1:7]
data = sys.stdin.buffer.read() if prompt == "stdin" else Path(prompt).read_bytes()
names = sorted(os.environ)
with Path(calls).open("a", encoding="utf-8") as stream:
    received = {"names": names, "model": model, "effort": effort,
                "session": session, "prompt_sha256": hashlib.sha256(data).hexdigest()}
    if account is not None:
        received["account"] = account
    stream.write(json.dumps(received) + "\n")
print(json.dumps(names), flush=True)
deadline = time.monotonic() + 30
while Path(gate).read_text(encoding="utf-8") == "hold":
    if time.monotonic() >= deadline:
        raise RuntimeError("the fixture gate was not released")
    time.sleep(0.05)

if len(sys.argv) == 8:
    queue = Path(sys.argv[7])
    (queue / "ready").write_text(str(os.getpid()))
    deadline = time.monotonic() + 55
    while not (queue / "stop").exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("the fixture queue was not stopped")
        for path in sorted(queue.glob("*.request.json")):
            completed = path.with_name(path.name.replace(".request.json", ".result.json"))
            if completed.exists():
                continue
            request = json.loads(path.read_text())
            environment = dict(os.environ)
            for name in request.get("canary_names", []):
                environment[name] = uuid.uuid4().hex
            if request.get("fault"):
                environment["LANEBOSS_FAULTS"] = json.dumps(request["fault"])
            answer = subprocess.run(request["argv"], input=request.get("stdin"), env=environment,
                                    text=True, capture_output=True, timeout=40)
            completed.write_text(json.dumps({"exit_code": answer.returncode,
                                            "stdout": answer.stdout, "stderr": answer.stderr}))
        time.sleep(0.02)

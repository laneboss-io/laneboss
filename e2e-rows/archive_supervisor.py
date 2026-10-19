"""Real lane-process CLI driver for archive authority rows on the Linux box."""

import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    plan = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    sys.stdin.buffer.read()
    calls, results = [], []

    def cli(*args, observe=False):
        result = subprocess.run([plan["binary"], *map(str, args)], capture_output=True, text=True, timeout=60)
        calls.append({"args": list(map(str, args)), "code": result.returncode,
                      "stdout": result.stdout, "stderr": result.stderr})
        if observe:
            return calls[-1]
        if result.returncode != 0:
            raise RuntimeError("child CLI exited %d" % result.returncode)
        return json.loads(result.stdout)

    try:
        for operation in plan["operations"]:
            lane = operation["lane"]
            action = operation["action"]
            if not operation.get("existing", False):
                flags = ("--reuse",) if operation.get("reuse", False) else ()
                cli("lane", "start", "--config", "archive", "--project", "demo", "--lane", lane,
                    "--brief", plan["brief"], "--role", "executor", "--runner", "once",
                    "--level", "3", "--model", "archive-fixture-model-v1", "--budget", "2", *flags)
                deadline = time.monotonic() + 40
                while True:
                    status = cli("lane", "status", "--config", "archive", "--lane", lane)
                    live = status["live"]
                    if (not status["running"] and live["supervisor"]["alive"] is False
                            and live["session_alive"] is False and live["survivors"] == 0
                            and live["pending_events"] == 0 and live["refused_events"] == 0):
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("child lane did not become quiescent")
                    time.sleep(0.2)
                cli("lane", "mark", "--config", "archive", "--lane", lane, "--state", "merged")
            if action == "prepare":
                print("Supervisor prepared child " + lane, flush=True)
                continue
            # Negative rows assert these actual codes and streams in the test
            # process. Keep both calls even when the first wrongly succeeds.
            observed = cli("lane", action, "--config", "archive", "--lane", lane, observe=True)
            value = json.loads(observed["stdout"]) if observed["code"] == 0 else None
            results.append({"lane": lane, "action": action, "result": value, **observed})
            if not operation.get("observe", False) and observed["code"] != 0:
                raise RuntimeError("collection CLI exited %d" % observed["code"])
            print("Supervisor observed %s for %s: exit %d" % (action, lane, observed["code"]), flush=True)
    finally:
        Path(plan["result"]).write_text(json.dumps({"calls": calls, "results": results}) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

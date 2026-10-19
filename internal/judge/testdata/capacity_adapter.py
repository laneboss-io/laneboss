"""Credential-free judge stand-in; answers depend on the actual request bytes."""

import json
import os
from pathlib import Path
import sys
import time


records, release, mode = map(str, sys.argv[1:])
request = json.load(sys.stdin)
record = Path(records) / (str(os.getpid()) + ".json")
temporary = record.with_suffix(".tmp")
temporary.write_text(json.dumps({"pid": os.getpid(), "request": request}))
temporary.rename(record)
if mode == "wait":
    deadline = time.monotonic() + 20
    while not Path(release).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("test did not release the waiting adapter")
        time.sleep(0.02)

if request["kind"] == "typed":
    answers = {key: {"type": "noul", "noul": len(value["instructions"]) % 10 / 10}
               for key, value in request["questions"].items()}
    response = {"model": "m" * 128, "request": "r" * 128, "answers": answers,
                "usage": {"input_tokens": len(json.dumps(request)), "output_tokens": len(answers)}}
    if mode == "partial":
        answers.pop(next(iter(answers)))
    elif mode == "no-usage":
        del response["usage"]
else:
    response = {"probability": len(request["subject"]["text"]) % 10 / 10,
                "model": "capacity-1.0"}
print(json.dumps(response))

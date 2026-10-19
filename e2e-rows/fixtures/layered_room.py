"""Credential-free room adapter: answer from inputs and retain every probe."""

import json
from pathlib import Path
import sys


account, answers_path, probes_path = sys.argv[1:]
answers = json.loads(Path(answers_path).read_text(encoding="utf-8"))
with Path(probes_path).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"account": account}) + "\n")
answer = answers[account]
print(json.dumps(answer), flush=True)

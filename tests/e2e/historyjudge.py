"""A Choice judge stand-in whose answers come from test data indexed by the actual message's hash."""

import hashlib
import json
from pathlib import Path
import sys


def main(directory):
    request = json.load(sys.stdin)
    message = request["subject"]["message"]
    if request.get("kind") != "choice" or not isinstance(request.get("choices"), list):
        raise ValueError("the caller did not ask a Choice")
    root = Path(directory)
    with (root / "requests.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps(request, ensure_ascii=False) + "\n")
    answers = json.loads((root / "answers.json").read_text(encoding="utf-8"))
    key = hashlib.sha256(message.encode("utf-8")).hexdigest()
    if key not in answers:
        raise ValueError("the caller changed the test's actual subject")
    json.dump(answers[key], sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])

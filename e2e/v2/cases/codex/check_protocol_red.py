"""Retained Linux red/candidate checks for the black-box case's input reader."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def replace_anchor(name, source, before, after):
    count = source.count(before)
    require(count == 1, f"protocol mutation {name}: anchor count {count}, expected 1")
    return source.replace(before, after, 1)


EDITS = {
    "vendor-stream": [
        [
            "streams.get(\"vendor\")",
            "streams.get(\"structured\")"
        ],
        [
            "streams.get(\"vendor\", b\"\")",
            "streams.get(\"structured\", b\"\")"
        ]
    ],
    "stream-snapshot": [
        [
            "    return page, events\n",
            "    return {**page, \"events\": []}, events\n"
        ]
    ],
    "stream-end": [
        [
            "    require(values[-1][\"end\"], \"stream disconnected without an end frame\")\n",
            ""
        ]
    ],
    "stream-correlation": [
        [
            "                frame.get(\"request_id\") == request_id and\n",
            ""
        ]
    ],
    "event-scope": [
        [
            "                    event.get(\"life_id\") == life and\n",
            ""
        ]
    ],
    "read-session": [
        [
            "        method = \"human.session\" if command in SESSION_COMMANDS else \\\n            command.replace(\" \", \".\")\n",
            "        method = command.replace(\" \", \".\")\n"
        ]
    ],
    "staging-session": [
        [
            "SESSION_COMMANDS = READ_COMMANDS | {\"blob begin\", \"blob chunk\", \"blob commit\"}",
            "SESSION_COMMANDS = READ_COMMANDS"
        ]
    ],
    "review-reached": [
        [
            "                accepted = one_json(completed.stdout)\n                self.reached = True\n",
            "                accepted = one_json(completed.stdout)\n"
        ]
    ],
    "launch-effect": [
        [
            "    def failed_launch(self, command, request, control):\n        operation = self.call(command, request)\n",
            "    def failed_launch(self, command, request, control):\n        operation = self.call(command, request, error=control[\"code\"])\n"
        ]
    ],
    "lease-time": [
        [
            "require(intervals[0][1] <= intervals[1][0],",
            "require(intervals[0][0] <= intervals[1][0],"
        ]
    ],
    "red-target": [
        [
            "    def failure_reached(self):\n        return self.reached and (self.context[\"phase\"] != \"red\" or\n                                MUTATION_TARGETS[self.context[\"mutation_id\"]] == self.active)\n",
            "    def failure_reached(self):\n        return self.reached\n"
        ]
    ],
    "supervisor-plant": [
        [
            "isinstance(word, str) and word and all(c.isalnum() for c in word)",
            "isinstance(word, str) and all(c.isalnum() for c in word)"
        ]
    ],
    "collect-quiet": [
        [
            "        errors = []\n",
            "        errors = []\n        self.keep(\"collection-request.json\", json.dumps({\"lanes\": list(self.lives)}).encode())\n"
        ]
    ],
    "collect-state": [
        [
            "            while lane[\"state\"] not in (\"merged\", \"abandoned\"):",
            "            if lane[\"state\"] not in (\"merged\", \"abandoned\"):"
        ]
    ],
    "collect-clean": [
        [
            "            self.events(life, lane[\"run\"], follow=True, until=\"lane.cleaned\", since=lane[\"last_seq\"])\n",
            ""
        ]
    ],
    "collect-stop-all": [
        [
            "                errors.append({\"life_id\": life, \"error\": type(error).__name__ + \": \" + str(error)})\n",
            "                errors.append({\"life_id\": life, \"error\": type(error).__name__ + \": \" + str(error)})\n                raise\n"
        ]
    ],
    "workspace-bytes": [
        [
            "data.encode(\"utf-8\") == expected",
            "isinstance(data, str)"
        ]
    ],
    "workspace-command": [
        [
            "read_probe_command(item.get(\"command\", \"\"), path)",
            "bool(item.get(\"command\"))"
        ]
    ],
    "release-counts": [
        [
            "receipt[key] == 0 for key in",
            "receipt[key] >= 0 for key in"
        ]
    ],
    "json-duplicates": [
        [
            "        require(key not in value, \"duplicate JSON key\")\n",
            ""
        ]
    ],
    "evidence-path": [
        [
            "        require(not Path(name).is_absolute() and\n                all(part not in (\".\", \"..\") for part in Path(name).parts),\n                \"evidence path is not a confined relative name\")\n",
            ""
        ],
        [
            "        require(path.parent.resolve(strict=True).is_relative_to(self.evidence),\n                \"evidence parent escaped its scope\")\n",
            ""
        ]
    ],
    "turn-identity": [
        [
            "            if event[\"kind\"] == \"lane.turn\":\n                require(isinstance(event.get(\"logical_turn_id\"), str) and\n                        re.fullmatch(r\"[A-Za-z0-9_-]{1,128}\", event[\"logical_turn_id\"]),\n                        \"turn event omitted logical turn identity\")\n",
            ""
        ]
    ],
    "snapshot-identity": [
        [
            "Path(\"internal\") / \"identity\",\n                     ",
            ""
        ]
    ]
}

MUTATION_FILES = {"snapshot-identity": "check_red.py"}


def mutation(name, source):
    require(name in EDITS, "unknown protocol mutation: " + name)
    for before, after in EDITS[name]:
        source = replace_anchor(name, source, before, after)
    return source


CASES = {
    "vendor-stream": ("test_vendor_stream", "primary vendor capture absent"),
    "stream-snapshot": ("test_stream_snapshot", "initial snapshot was dropped"),
    "stream-end": ("test_stream_end", "stream EOF became completion"),
    "stream-correlation": ("test_stream_correlation", "foreign frame was accepted"),
    "event-scope": ("test_event_scope", "foreign life was accepted"),
    "read-session": ("test_read_proof", "read proof did not open a connection session"),
    "release-counts": ("test_release_counts", "unmeasured release became success"),
    "json-duplicates": ("test_json_shape", "invalid JSON became evidence"),
    "evidence-path": ("test_evidence_path", "evidence escaped its root"),
    "staging-session": ("test_session_staging", "blob staging requested an operation proof"),
    "review-reached": ("test_review_reached", "review pass-through did not reach assertion"),
    "launch-effect": ("test_launch_effect", "synchronous error demanded for a committed launch"),
    "lease-time": ("test_lease_intervals", "timestamp overlap was accepted"),
    "red-target": ("test_red_target", "unrelated red assertion counted as reached"),
    "supervisor-plant": ("test_supervisor_inputs", "empty supervisor word became a passing plant"),
    "collect-quiet": ("test_collection_waits", "collection reviewer raced quiescence"),
    "collect-state": ("test_collection_waits", "independent collection state decision is missing"),
    "collect-clean": ("test_collection_waits", "collection clean flag was premature or absent"),
    "collect-stop-all": ("test_collection_stops_all", "sibling stop was not attempted"),
    "workspace-bytes": ("test_workspace_probe", "write probe trusted different bytes"),
    "workspace-command": ("test_workspace_probe", "model text became a workspace read"),
    "turn-identity": ("test_turn_id", "turn without identity became evidence"),
    "snapshot-identity": ("test_red_snapshot", "red snapshot omitted required identity source"),
}


def keep_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def inventory(root):
    rows = []
    for path in sorted(root.iterdir()):
        if path.is_file():
            data = path.read_bytes()
            rows.append({"path": path.name, "sha256": hashlib.sha256(data).hexdigest(),
                         "bytes": len(data)})
    return rows


def run_test(root, evidence, stem, selected):
    selector = "test_protocol.ProtocolTests." + selected
    # Keep generated bytecode out of the retained snapshots. A same-size red
    # edit made within one timestamp tick must execute its changed source.
    command = [sys.executable, "-B", "-m", "unittest", "-v", selector]
    keep_json(evidence / (stem + "-command.json"), command)
    result = subprocess.run(command, cwd=root, capture_output=True, timeout=60)
    (evidence / (stem + "-stdout.txt")).write_bytes(result.stdout)
    (evidence / (stem + "-stderr.txt")).write_bytes(result.stderr)
    keep_json(evidence / (stem + "-exit.json"), {"exit": result.returncode})
    output = result.stderr.decode("utf-8", errors="strict")
    require("(" + selector + ")" in output and "Ran 1 test in" in output and
            "ERROR:" not in output and "skipped" not in output.lower(),
            "protocol test did not reach the selected assertion")
    return result, output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == "linux", "protocol regression execution requires Linux")
    source = args.source.resolve(strict=True)
    evidence = args.evidence.resolve()
    require(not evidence.exists() and not evidence.is_relative_to(source),
            "protocol evidence must be new and outside source")
    evidence.mkdir(parents=True, mode=0o700)
    case = source / "e2e" / "v2" / "cases" / "codex"
    candidate = evidence / "candidate"
    candidate.mkdir(mode=0o700)
    for name in ("run.py", "test_protocol.py", "check_red.py", "launch_red.json"):
        require(not (case / name).is_symlink(), "protocol source is linked")
        shutil.copyfile(case / name, candidate / name)
    shutil.copyfile(Path(__file__), evidence / "check_protocol_red.py")
    keep_json(evidence / "candidate-inputs.json", inventory(candidate))
    rows = []
    for name, (selected, reason) in CASES.items():
        print("protocol mutation: " + name, flush=True)
        tests = (candidate / "test_protocol.py").read_text()
        require(tests.count("    def " + selected + "(self):") == 1,
                f"protocol mutation {name}: selected assertion absent or ambiguous")
        red = evidence / ("red-" + name)
        shutil.copytree(candidate, red)
        path = red / MUTATION_FILES.get(name, "run.py")
        path.write_text(mutation(name, path.read_text()))
        keep_json(evidence / (name + "-red-inputs.json"), inventory(red))
        broken, output = run_test(red, evidence, name + "-red", selected)
        require(broken.returncode == 1 and "FAIL:" in output and reason in output,
                "protocol red failed outside the intended assertion")
        fixed, output = run_test(candidate, evidence, name + "-candidate", selected)
        require(fixed.returncode == 0 and output.rstrip().endswith("OK"),
                "candidate protocol assertion failed")
        rows.append({"id": name, "test": selected, "red_exit": broken.returncode,
                     "candidate_exit": fixed.returncode})
        keep_json(evidence / "results.json", rows)
    print("PASS: Codex case protocol red/candidate checks")


if __name__ == "__main__":
    main()

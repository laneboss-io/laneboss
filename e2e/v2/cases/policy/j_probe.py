"""Cloud-only transport probe; the fixture supplies no policy verdicts."""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace


source = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("policy", source / "scripts/v2-serve/case_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    def command(name, argv, **options):
        result = subprocess.run(argv, cwd=source, capture_output=True,
                                timeout=options.get("seconds", 60))
        if result.returncode:
            sys.stderr.buffer.write(result.stderr)
            raise ValueError("fixture command failed: " + name)
        return result.stdout
    case = SimpleNamespace(stage=source, root=args.root, config="policy-wire",
        command=command, keep=lambda name, raw: policy.publish(args.root / name, raw),
        keep_json=lambda name, value: policy.publish(args.root / name, value))
    try:
        boot = policy.boot(case)
        if "enrollment" not in boot:
            raise ValueError("producer lacks native judge enrollment")
        print(json.dumps(boot["enrollment"]), flush=True)
        for line in sys.stdin:
            request = json.loads(line)
            path = args.root / (request["stage"] + ".request")
            policy.publish(path, request)
            handoff = policy.document(policy.read_private(args.root / "policy-judge.input.json"))
            result = command("control", [handoff["controller"], "--request", str(path)])
            print(result.decode().strip(), flush=True)
    finally:
        if hasattr(case, "policy_judge"):
            print(json.dumps(case.policy_judge.close()), flush=True)


if __name__ == "__main__":
    main()

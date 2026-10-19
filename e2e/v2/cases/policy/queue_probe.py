"""Root canary entry: write a real coordinator job for a distinct queue UID."""

import argparse
import importlib.util
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

spec = importlib.util.spec_from_file_location("policy_consumer", Path(__file__).with_name("run.py"))
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
parser = argparse.ArgumentParser()
parser.add_argument("--queue", type=Path, required=True)
args = parser.parse_args()
consumer.atomic(args.queue / "0000.job.json", {"kind": "identity", "request": {}})

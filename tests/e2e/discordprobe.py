"""Exercise the installed Discord APIs with documents from files, without a gateway.

The suite first registers channels through the installed CLI. This probe then
uses the selected Go binary, or that installation's Python library, to read its
roles and convert actual payloads. A selected Go binary never falls back.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("library")
    parser.add_argument("operation", choices=("event", "line", "validate", "read"))
    parser.add_argument("org_dir")
    parser.add_argument("--message")
    parser.add_argument("--channel-names")
    arguments = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tests.e2e.support import faults_binary
    command = [str(faults_binary()), "org", "channel", "_probe", arguments.operation, arguments.org_dir]
    if arguments.message is not None:
        command.extend(["--message", arguments.message])
    if arguments.channel_names is not None:
        command.extend(["--channel-names", arguments.channel_names])
    return subprocess.run(command, check=False, timeout=25).returncode


if __name__ == "__main__":
    sys.exit(main())

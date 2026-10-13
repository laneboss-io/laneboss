"""Drive the Go history bridge; no Python product implementation is loaded."""

from pathlib import Path
import subprocess
import sys


def main(library, request_file):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tests.e2e.support import faults_binary
    return subprocess.run([str(faults_binary()), "decisions", "probe", "--file", request_file],
                          check=False, timeout=60).returncode


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))

"""Run a fault probe through the Go binary compiled with laneboss_faults.

Usage: python faults.py POINT MARKER COMMAND --db PATH [arguments...]
The release binary has no environment parser or bridge for these probes.
"""

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.e2e.support import faults_binary


if __name__ == "__main__":
    point, marker = sys.argv[1:3]
    binary = str(faults_binary())
    environment = dict(os.environ, LANEBOSS_FAULTS=json.dumps({"point": point, "marker": marker}))
    os.execve(binary, [binary, "decisions", *sys.argv[3:]], environment)

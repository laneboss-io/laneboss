"""The shared protocol shipped with the launcher; protocol.md carries its own version line."""

from pathlib import Path
import re

from ..errors import IntegrityProblem

PROTOCOL_FILE = Path(__file__).with_name("protocol.md")
VERSION_LINE = re.compile(rb"^Protocol version: ([0-9]+\.[0-9]+\.[0-9]+)$", re.MULTILINE)


def load_protocol():
    """Return the protocol's exact bytes and its version."""
    data = PROTOCOL_FILE.read_bytes()
    match = VERSION_LINE.search(data)
    if match is None:
        raise IntegrityProblem("the shipped protocol has no 'Protocol version: X.Y.Z' line")
    return data, match.group(1).decode("ascii")

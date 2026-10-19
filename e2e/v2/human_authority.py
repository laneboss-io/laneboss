"""Outside test coordinator handoff. Presence is verified only by the service."""

import json
import os
from pathlib import Path
import stat


class OwnerWait(RuntimeError):
    code = "prerequisite_missing"

    def __init__(self, step):
        if step not in {"human_confirmation", "fixture_preparation", "root_installation",
                        "vendor_authentication", "d6_confirmation", "human_send", "browser_gesture"}:
            raise ValueError("unknown owner wait")
        self.step = step
        super().__init__("owner step is waiting: " + step)

    def record(self):
        return {"schema": "laneboss.e2e-owner-wait.v2", "kind": "owner_wait",
                "code": self.code, "step": self.step, "completed": False}


def proof_arguments(root, binding_file, config, index, words):
    """Use a new genuine proof for this invocation; never reuse a session ID.

    The coordinator reads the retained request before supplying the numbered
    proof. For reads this is a fresh human.session proof and the CLI creates
    the session on the same connection. Mutations use their exact intent proof;
    root spawn uses the CLI's separate session prelude. Missing is a wait.
    """
    binding = json.loads(Path(binding_file).read_bytes())
    if binding.get("class") != "human" or binding.get("config") != config:
        raise OwnerWait("human_confirmation")
    parent = Path(root) / "authority"
    proof = parent / ("%06d.proof.json" % index)
    if not parent.exists() or not proof.exists():
        raise OwnerWait("human_confirmation")
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("unsafe human proof directory")
    fd = os.open(proof, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 0 < info.st_size <= 4096):
            raise RuntimeError("unsafe human proof input")
        # The real CLI validates the exact typed proof and the service checks
        # its current unconsumed authority. File presence never means approval.
        raw = os.read(fd, 4097)
        if len(raw) != info.st_size:
            raise RuntimeError("human proof input changed")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeError("invalid human proof input")
    finally:
        os.close(fd)
    flag = "--session-proof" if words in (["lane", "start"], ["lane", "adopt"]) else "--proof"
    return [flag, str(proof)]

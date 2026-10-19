"""Export actual producer bytes for the Go bundle decoder regression on Linux."""

import base64
import importlib.util
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[4]
CORE = Path(os.environ.get("LB_GRANTS_CORE", str(ROOT / "scripts" / "v2-serve")))
SPEC = importlib.util.spec_from_file_location("bundle_grants", CORE / "case_grants.py")
GRANTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GRANTS)


class BootFixture:
    def __init__(self, root):
        self.root = root.resolve(strict=True)
        self.stage = ROOT

    def keep(self, name, raw):
        path = self.root / name
        GRANTS.io.keep(path, raw)
        return path

    def keep_json(self, name, value):
        return self.keep(name, GRANTS.io.encoded(value))

    def command(self, label, argv, **options):
        result = subprocess.run(argv, cwd=self.root, capture_output=True, timeout=30,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.keep(label + ".stdout", result.stdout)
        self.keep(label + ".stderr", result.stderr)
        self.keep_json(label + ".exit.json", {"exit_code": result.returncode})
        if result.returncode != 0:
            raise RuntimeError("boot fixture command failed: " + label)
        return result.stdout


if __name__ == "__main__":
    case = BootFixture(Path(sys.argv[1]))
    prepared = GRANTS.boot(case)
    if len(sys.argv) == 3 and sys.argv[2] == "--enrollment":
        # Serialization fixture only: runtime obtains this handle from the
        # real secret import. This fixture neither enrolls nor grants it.
        imported = {"source_handle": os.urandom(16).hex(),
                    "name": "grants-canary-" + os.urandom(6).hex(), "version": "v1"}
        requests = {
            "resource": GRANTS.resource_enrollment_input(case),
            "secret": GRANTS.secret_enrollment_input(imported,
                case.grants_boot["resource_enrollment"]["expires_at"]),
        }
        encoded = {}
        for family, request in requests.items():
            raw = GRANTS.io.encoded(request)
            case.keep(family + "-enrollment.json", raw)
            encoded[family] = base64.b64encode(raw).decode()
        case.keep_json("enrollment-import-fixture.json", imported)
        sys.stdout.buffer.write(GRANTS.io.encoded(encoded))
        sys.exit(0)
    # No typed round trip or field repair: the Go decoder receives boot's fields.
    raw = GRANTS.io.encoded(prepared["bundle"])
    case.keep("boot-bundle.json", raw)
    sys.stdout.buffer.write(raw)

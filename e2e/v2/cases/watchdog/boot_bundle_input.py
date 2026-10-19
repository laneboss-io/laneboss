"""Export the actual watchdog boot input for the Linux bundle regression."""

import importlib.util
from pathlib import Path
import shutil
import sys


ROOT = Path(__file__).resolve().parents[4]
CORE = ROOT / "scripts" / "v2-serve"
sys.path.insert(0, str(CORE))
import case_watchdog
import provision

spec = importlib.util.spec_from_file_location("wd_bundle_launcher", CORE / "run.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def main():
    root = Path(sys.argv[1]).resolve(strict=True)
    case = launcher.Case.__new__(launcher.Case)
    case.stage, case.root = root / "source", root / "evidence"
    case.stage.mkdir(mode=0o755)
    case.root.mkdir(mode=0o700)
    shutil.copytree(ROOT / "templates", case.stage / "templates")
    prepared = case_watchdog.boot(case)
    base = provision.document(provision.read_protected(root / "base-input.json"))
    # Apply the same case-field overlay as provision.fixture_initial(). Keep
    # boot's JSON fields raw until the real assembler's decoder consumes them.
    for name, value in prepared["bundle"].items():
        if name == "sources":
            base[name].extend(value)
        elif name in {"documents", "contexts", "projects", "root_grants", "budget"}:
            base[name] = value
        else:
            raise ValueError("unsupported case bundle field")
    raw = provision.encoded(base)
    provision.administrator_input(root, "bundle-input.json", raw)
    sys.stdout.buffer.write(raw)


if __name__ == "__main__":
    main()

"""Reached assertion red/candidate pairs for fixture provenance, on Linux only."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

CONTROLS = (
    ("substitute-module", "test_actual_inputs", "acceptance: fixture provenance differs from actual module inputs",
     "selected.append(row)",
     "selected.append(dict(row, sha256=sha(Path(__file__).with_name('fixture.mod').read_bytes())) if name == 'go.mod' else row)"),
    ("unverified-source", "test_changed_source", "ValueError not raised",
     'require(inventory.get(name) == row, "fixture build source differs from retained inventory")',
     'require(True, "RED: omitted staged source correlation")'),
    ("unverified-vendor", "test_changed_vendor", "ValueError not raised",
     'require(vendor and (source / "vendor/modules.txt").read_bytes() == vendor,',
     'require(vendor,'),
    ("unverified-dependency", "test_changed_vendor", "ValueError not raised",
     'require(member.isfile() and dependencies.extractfile(member).read() == data,',
     'require(member.isfile(),'),
    ("omitted-harness", "test_harness_archive", "acceptance: harness archive lost a native control or unit test",
     'tuple(sorted(path.name for path in harness.glob("*.py")))',
     'tuple(sorted(path.name for path in harness.glob("*.py") if not path.name.endswith("_test.py") and path.name != "native_cleanup_control.py"))'),
)


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "linux", "provenance controls require disposable Linux")
    output = args.output
    require(output.is_absolute() and output.name.startswith("lb-v2-serve2-") and not output.exists(),
            "new absolute lane evidence directory required")
    source = Path(__file__).resolve().parent
    inputs = {name: (source / name).read_bytes() for name in
              ("provision.py", "fixture_provenance_test.py", "fixture.mod", "provenance_controls.py")}
    for _, _, _, before, after in CONTROLS:
        require(before != after and inputs["provision.py"].count(before.encode()) == 1,
                "provenance control anchor is missing or ambiguous")
    output.mkdir(mode=0o700, parents=True)
    save(output / "input-manifest.json", [{"path": name, "sha256": sha(data), "bytes": len(data)}
                                         for name, data in sorted(inputs.items())])
    report = {"complete": False, "scope": "harness build provenance; no installed or AI-service credit", "pairs": []}
    try:
        for identifier, test, diagnostic, before, after in CONTROLS:
            for phase in ("red", "candidate"):
                directory = output / identifier / phase
                directory.mkdir(mode=0o700, parents=True)
                retained = dict(inputs)
                if phase == "red":
                    retained["provision.py"] = retained["provision.py"].replace(before.encode(), after.encode(), 1)
                for name, data in retained.items():
                    (directory / name).write_bytes(data)
                save(directory / "source-manifest.json", [{"path": name, "sha256": sha(data), "bytes": len(data)}
                                                          for name, data in sorted(retained.items())])
                command = [sys.executable, "-B", str(directory / "fixture_provenance_test.py"), "FixtureProvenance." + test, "-v"]
                started = time.monotonic()
                with (directory / "stdout").open("xb") as out, (directory / "stderr").open("xb") as err:
                    process = subprocess.Popen(command, cwd=directory, stdout=out, stderr=err)
                    save(directory / "pid.json", {"pid": process.pid})
                    try:
                        code = process.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise ValueError("provenance control timed out; no mutation credit") from None
                transcript = (directory / "stderr").read_text()
                save(directory / "command.json", {"command": command, "exit_code": code,
                     "elapsed_ms": round((time.monotonic() - started) * 1000)})
                require(all((directory / name).read_bytes() == data for name, data in retained.items()),
                        "provenance control source changed during execution")
                require("ERROR:" not in transcript and " skipped" not in transcript and "Ran 1 test" in transcript,
                        "provenance control failed before its intended assertion")
                if phase == "red":
                    require(code == 1 and "FAIL: " + test in transcript and diagnostic in transcript,
                            "provenance control survived or failed at another assertion")
                else:
                    require(code == 0 and transcript.rstrip().endswith("OK"), "provenance candidate failed")
                report["pairs"].append({"id": identifier, "phase": phase, "test": test, "exit_code": code,
                                        "diagnostic": diagnostic if phase == "red" else "OK"})
                print(identifier, phase, "observed", flush=True)
        require(all((source / name).read_bytes() == data for name, data in inputs.items()), "original harness changed")
        report["complete"] = True
    finally:
        save(output / "result.json", report)
    print("PASS: fixture provenance red/candidate controls", flush=True)


if __name__ == "__main__":
    main()

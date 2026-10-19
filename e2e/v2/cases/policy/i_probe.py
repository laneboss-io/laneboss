"""Export actual boot/assembler bytes for the root installer-validation test."""

import argparse
import base64
import importlib.util
import os
from pathlib import Path


spec = importlib.util.spec_from_file_location("controls", Path(__file__).with_name("test_producer.py"))
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    controls.producer.require(os.geteuid() == 0, "initial probe requires the authorized root Linux scope")
    test = controls.ProducerControls()
    try:
        case, boot = test.boot_fixture()
        assembled, contents = test.assemble_boot(boot, case.config)
        for row in assembled["documents"]:
            identifier = row["ref"]["id"]
            test.assertNotIn(identifier, contents)
            contents[identifier] = base64.b64decode(row["data"], validate=True)
        objects = args.output / "initial-objects"
        objects.mkdir(mode=0o700)
        def keep(path, raw):
            controls.producer.publish(path, raw)
            path.chmod(0o444)
        for ref in assembled["initial"]["objects"]:
            raw = contents[ref["id"]]
            test.assertEqual(len(raw), ref["bytes"])
            test.assertEqual(controls.producer.sha(raw), ref["sha256"])
            keep(objects / ref["id"], raw)
        keep(args.output / "initial.json", base64.b64decode(assembled["raw"], validate=True))
        keep(args.output / "initial-ref.json", controls.producer.encoded({"manifest": assembled["ref"]}))
        keep(args.output / "role-task.input", (controls.source / "e2e/v2/cases/policy/role.md").read_bytes())
    finally:
        if not test.doCleanups():
            raise RuntimeError("actual boot fixture cleanup failed")


if __name__ == "__main__":
    main()

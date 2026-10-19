"""Export policy boot/assembler/binder inputs for launch/materialization tests.

Only enrolled grant identities are component fixtures. This does not perform
human authorization, protected profile enrollment, or installed root issuance.
No launch request fields or ceiling decisions are replaced by this probe.
"""

import argparse
import base64
import copy
import importlib.util
from pathlib import Path
import secrets


spec = importlib.util.spec_from_file_location("controls", Path(__file__).with_name("test_producer.py"))
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--extra-copy-source", action="store_true")
    parser.add_argument("--wall-ms", type=int)
    args = parser.parse_args()
    test = controls.ProducerControls()
    try:
        case, boot = test.boot_fixture()
        if args.wall_ms is not None:
            boot["bundle"]["budget"]["wall_ms"] = args.wall_ms
        project_destination = boot["bundle"]["root_grants"]["data"][0]["destination"]
        if args.extra_copy_source:
            def keep_control(name, kind, raw):
                ref = {"id": name, "class": kind, "sha256": controls.producer.sha(raw), "bytes": len(raw)}
                boot["bundle"]["documents"].append({"ref": ref, "data": base64.b64encode(raw).decode()})
                return ref
            content = keep_control("ceiling-control-file", "artifact", secrets.token_hex(16).encode())
            tree = keep_control("ceiling-control-project", "manifest", controls.producer.encoded({
                "schema": "laneboss.objects.v2", "entries": [
                    {"path": "control.txt", "kind": "file", "mode": 0o444, "content": content}]}))
            extra = copy.deepcopy(boot["bundle"]["root_grants"]["data"][0])
            extra["source_object_id"], extra["source_sha256"] = tree["id"], tree["sha256"]
            extra["destination"] = "/work/extra"
            boot["bundle"]["root_grants"]["data"].append(extra)
        assembled, _ = test.assemble_boot(boot, case.config)
        documents = {row["ref"]["id"]: base64.b64decode(row["data"], validate=True)
                     for row in assembled["documents"]}
        approved = controls.producer.document(documents[assembled["initial"]["profiles"]["id"]])
        # The existing store fixture installs primitive enrolled ceilings and
        # tickets. Preserve every approved capability field; assign only the
        # opaque identities that normal root issuance supplies.
        ceiling = {name: copy.deepcopy(approved[name]) for name in controls.producer.FAMILIES}
        for family in controls.producer.FAMILIES:
            for member in ceiling[family]:
                test.assertEqual(member.get("id", ""), "")
                test.assertFalse(member.get("parent_grant_id"))
                member["id"] = secrets.token_hex(16)
        ceiling.update(id=secrets.token_hex(16), life_id=secrets.token_hex(16), sha256="",
                       generation=1, policy_generation=assembled["initial"]["generation"],
                       expires_at=max(row["expires_at"] for family in controls.producer.FAMILIES
                                      for row in ceiling[family]), revoked=False)
        run = controls.producer.sibling("run")
        binder = run.Case.__new__(run.Case)
        binder.root = case.root
        binder.generated_launches = True
        binder.initial = assembled["initial"]
        binder.initial_receipt = {"generation": assembled["initial"]["generation"]}
        binder.egress_anthropic = False
        binder.human_prefix = "ceiling-component"
        binder.keep_json = case.keep_json
        binder.fixture_profile_selectors = case.fixture_profile_selectors
        inputs = case.root / "initial-inputs"
        inputs.mkdir(mode=0o700)
        controls.producer.publish(inputs / binder.initial["profiles"]["id"],
                                  documents[binder.initial["profiles"]["id"]])
        launches = copy.deepcopy(assembled["lanes"])
        for launch in launches.values():
            binder.bind_root_launch(launch, ceiling)
        project_grants = [row for row in ceiling["data"]
                          if row["source_object_id"] == case.policy_boot["project"]["id"]
                          and row["destination"] == project_destination]
        test.assertEqual(len(project_grants), 1)
        controls.producer.publish(args.output, {
            "approved": approved, "root_request": assembled["root_request"],
            "ceiling": ceiling, "launches": list(launches.values()),
            "documents": assembled["documents"], "project": case.policy_boot["project"],
            "project_grant_id": project_grants[0]["id"],
            "enrollment": assembled["initial"]["launch_enrollment"],
            "runtime": assembled["initial"]["runtime"],
            "org_snapshot": controls.producer.document(documents[assembled["initial"]["sources"]["id"]]),
            "policy": controls.producer.document(documents[assembled["initial"]["policy"]["id"]]),
        })
    finally:
        if not test.doCleanups():
            raise RuntimeError("actual policy boot fixture cleanup failed")


if __name__ == "__main__":
    main()

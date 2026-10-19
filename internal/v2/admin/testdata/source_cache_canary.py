"""Exercise the actual installer cache step on synthetic retained objects."""

import base64
import importlib.util
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("boot_cache_canary", root / "scripts/v2-admin/boot.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
value = json.loads(Path(sys.argv[1]).read_bytes())
if "source_cache_limit" in value:
    # Test-only module instance: exercise a >64 MiB assembled source without
    # changing boot.py, any installed ceiling or the production object rule.
    ceiling = value["source_cache_limit"]
    if type(ceiling) is not int or ceiling != 256 << 20:
        raise ValueError("large assembly fixture requires its explicit 256 MiB cache ceiling")
    boot.MAX_OBJECT = ceiling
objects = {row["ref"]["id"]: (row["ref"], base64.b64decode(row["data"], validate=True)) for row in value["objects"]}
enrollment = base64.b64decode(value["enrollment"], validate=True)
if len(sys.argv) == 4:
    selected = json.loads(enrollment)
    ref = selected["projects"][0]["object"]
    tree = json.loads(objects[ref["id"]][1])
    mode = sys.argv[3]
    if mode == "changed_blob":
        content = tree["entries"][0]["content"]
        objects[content["id"]] = (content, b"changed source bytes")
    else:
        if mode == "escape":
            tree["entries"][0]["path"] = "../ungranted"
        elif mode == "duplicate":
            tree["entries"].append(dict(tree["entries"][0]))
        elif mode == "linked_parent":
            tree["entries"][0]["path"] = "alias/child"
            tree["entries"].append({"path": "alias", "kind": "symlink", "mode": 0o777, "link_target": "target"})
        else:
            raise ValueError("unknown source control")
        raw = json.dumps(tree, separators=(",", ":")).encode()
        ref = dict(ref, bytes=len(raw), sha256=boot.sha(raw))
        objects[ref["id"]] = (ref, raw)
        selected["projects"][0]["object"] = ref
        selected["projects"][0]["base"] = ref["sha256"]
        enrollment = json.dumps(selected).encode()
initial = {}
if "data_grants" in value:
    raw = json.dumps({"schema": "laneboss.root-grants.v2", "resources": [], "data": value["data_grants"],
                      "secrets": [], "profiles": [], "network": [], "channels": []}, separators=(",", ":")).encode()
    ref = {"id": "canary-root-grants", "class": "manifest", "bytes": len(raw), "sha256": boot.sha(raw)}
    objects[ref["id"]] = (ref, raw)
    initial["profiles"] = ref
caches = boot.source_cache_inputs(enrollment, (b"", initial, objects))
changed = boot.install_source_caches(Path(sys.argv[2]), caches)
print("source-cache:changed" if changed else "source-cache:verified")

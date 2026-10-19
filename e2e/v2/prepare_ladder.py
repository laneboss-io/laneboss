"""Prepare inert inputs; only operators enroll grants and credentials."""

import argparse
from pathlib import Path
import secrets

from ladder import SCENARIO, structure
from ladder_ready import PLAN, instance_rows, ready_plan
from support import (ROOT, atomic_bytes, bytes_hash, decode, load, require,
                     require_linux, save, sha256)


def prepare(root, configs, seed):
    root = Path(root)
    require(root.is_absolute() and root.resolve() == root and
            not root.is_relative_to(ROOT), "prepare outside the source checkout")
    require(configs == ["tree-a", "tree-b"], "use the two separate tree bindings")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    nodes = structure(seed)
    readiness = ready_plan()
    row_bytes = PLAN.read_bytes()
    require(decode(row_bytes) == readiness, "row plan changed during preparation")
    row_hash = bytes_hash(row_bytes)
    private = {"schema": "laneboss.ladder-plan.v2", "seed": seed, "answers": {},
               "pings": {}, "load_samples": []}
    draw = {"schema": "laneboss.ladder-draw.v2", "seed": seed, "nodes": nodes}
    save(root / "draw.json", draw, mode=0o400)
    draw_hash = sha256(root / "draw.json")
    save(root / "draw.sha256.json",
         {"file": "draw.json", "sha256": draw_hash}, mode=0o400)
    private["draw_sha256"] = draw_hash
    private["row_plan_sha256"] = row_hash
    atomic_bytes(root / "row-plan.json", row_bytes, mode=0o400)
    public = {"schema": "laneboss.ladder-input.v2", "seed": seed, "nodes": nodes,
              "configs": configs, "draw_sha256": draw_hash}
    task_template = (SCENARIO / "task.md").read_text(encoding="utf-8")
    sources = {path.name: sha256(path) for path in sorted(SCENARIO.iterdir())
               if path.is_file()}
    save(root / "scenario-sources.json", sources, mode=0o400)
    for config in configs:
        directory = root / config
        directory.mkdir(mode=0o700)
        allocation = load(SCENARIO / (config + ".json"))
        require(allocation["config"] == config, "wrong allocation configuration")
        save(directory / "allocation.json", allocation, mode=0o400)
        private["answers"][config] = {}
        private["pings"][config] = {
            node["name"]: secrets.token_hex(16) for node in nodes}
        for node in nodes:
            data = directory / node["name"]
            data.mkdir(mode=0o700)
            # The seeded PRNG never enters challenge generation.
            parent = data / ("p-" + secrets.token_hex(8))
            parent.mkdir(mode=0o700)
            target = parent / ("c-" + secrets.token_hex(8) + ".txt")
            token = secrets.token_hex(16)
            target.write_text(token + "\n", encoding="ascii")
            target.chmod(0o400)
            private["answers"][config][node["name"]] = {
                "path": str(target.relative_to(data)), "token": token}
            children = [child for child in nodes
                        if child["parent"] == node["name"]]
            duties = (SCENARIO / node["brief"]).read_text(
                encoding="utf-8").format(
                    children=", ".join(child["name"] for child in children)
                    or "none")
            fields = {**node, "parent": node["parent"] or "human"}
            text = task_template.format(
                **fields, config=config, duties=duties)
            task = data / "task.md"
            task.write_text(text, encoding="utf-8")
            task.chmod(0o400)
            dispatch = [{**child, "task": child["name"] + "/task.md",
                         "ping_nonce": private["pings"][config][child["name"]]}
                        for child in children]
            save(data / "dispatch.json", {
                "config": config, "self": node, "children": dispatch,
                "draw_sha256": draw_hash, "row_plan_sha256": row_hash,
                "acceptance_rows": instance_rows(readiness, node["name"])}, mode=0o400)
    save(root / "public-plan.json", public, mode=0o400)
    save(root / "observer-plan.json", private, mode=0o400)
    return private


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--config", action="append", required=True)
    parser.add_argument("--seed", type=int)
    args = parser.parse_args()
    require_linux()
    seed = args.seed if args.seed is not None else secrets.randbelow(2**53)
    prepare(args.directory, args.config, seed)
    print("ladder inputs prepared; live execution pending")


if __name__ == "__main__":
    main()

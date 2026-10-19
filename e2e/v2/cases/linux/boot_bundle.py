"""Exercise the actual boot/export/assembler path on the root Linux test box."""

import argparse
import base64
import importlib.util
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[4]
CORE = ROOT / "scripts/v2-serve"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


LINUX = module("linux_boot_bundle", CORE / "case_linux.py")
PROVISION = module("linux_boot_export", CORE / "provision.py")


class Fixture:
    def __init__(self, root):
        self.root = root / "evidence"
        self.root.mkdir(mode=0o700)
        self.stage = root / "source"
        self.stage.mkdir(mode=0o700)
        self.linux_plan_file = None
        # Match the installed exporter's protected staging, using exact source
        # bytes rather than depending on ownership of the test checkout.
        for name in (
                "e2e/v2/cases/linux/canary.py",
                "scripts/v2-serve/fixtures/README.md",
                "templates/v2/org/default.md",
                "templates/v2/org/drivers.toml",
                "templates/v2/org/workflow.toml",
                "templates/v2/roles/L5/supervisor.md",
                "templates/v2/roles/L5/supervisor.toml"):
            target = self.stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            LINUX.put(target, (ROOT / name).read_bytes(), mode=0o444)

    def keep(self, name, raw):
        return LINUX.put(self.root / name, raw)

    def keep_json(self, name, value):
        return self.keep(name, LINUX.encoded(value))

    def command(self, label, argv, **options):
        result = subprocess.run(argv, capture_output=True, timeout=60,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.keep(label + ".stdout", result.stdout)
        self.keep(label + ".stderr", result.stderr)
        self.keep_json(label + ".exit.json", {"exit_code": result.returncode})
        LINUX.require(result.returncode == 0,
                      "actual bundle assembler failed: " + result.stderr.decode())
        return result.stdout


def document(identifier, kind, raw):
    return {"ref": {"id": identifier, "class": kind,
                    "sha256": LINUX.sha(raw), "bytes": len(raw)},
            "data": base64.b64encode(raw).decode("ascii")}


def pack_records(fixtures):
    """Losslessly remove repeated wire base64 from canonical JSON inputs."""
    blobs = {}

    def leaf(raw):
        try:
            return {"text": raw.decode("utf-8")}
        except UnicodeDecodeError:
            return {"data": base64.b64encode(raw).decode("ascii")}

    def split(value, key=""):
        if isinstance(value, str) and key in ("data", "runtime", "project", "task"):
            raw = base64.b64decode(value, validate=True)
            digest = LINUX.sha(raw)
            blobs[digest] = leaf(raw)
            return {"base64_sha256": digest}
        if isinstance(value, dict):
            return {name: split(part, name) for name, part in value.items()}
        if isinstance(value, list):
            return [split(part) for part in value]
        return value

    def join(value):
        if isinstance(value, dict):
            if set(value) == {"base64_sha256"}:
                blob = blobs[value["base64_sha256"]]
                raw = blob["text"].encode("utf-8") if "text" in blob else base64.b64decode(blob["data"], validate=True)
                return base64.b64encode(raw).decode("ascii")
            return {name: join(part) for name, part in value.items()}
        if isinstance(value, list):
            return [join(part) for part in value]
        return value

    for fixture in fixtures:
        for record in fixture["records"]:
            raw = base64.b64decode(record.pop("data"), validate=True)
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                record.update(leaf(raw))
                continue
            if LINUX.encoded(value) == raw:
                value = split(value)
                LINUX.require(LINUX.encoded(join(value)) == raw,
                              "packed JSON does not preserve its exact input bytes")
                record.update(format="json-indent-2-sort", json=value)
            else:
                record.update(leaf(raw))
    return {"fixtures": fixtures, "blobs": blobs}


def plan(case, kind):
    if kind == "no-plan":
        return
    value = {}
    if kind != "empty-plan":
        # The same extra documents are accepted only when selected by a real
        # project tree; the orphan control removes that selection alone.
        content = document("linux-plan-file", "artifact", os.urandom(31))
        tree = document("linux-plan-tree", "manifest", LINUX.encoded({
            "schema": "laneboss.objects.v2", "entries": [{
                "path": "fixture.bin", "kind": "file", "mode": 0o444,
                "content": content["ref"]}]}))
        value["bundle"] = {"documents": [content, tree], "projects": []}
        if kind == "selected-plan":
            value["bundle"]["projects"].append({
                "id": "linux-plan-project", "generation": 1,
                "project_id": "linux-plan-tree", "object": tree["ref"],
                "base": tree["ref"]["sha256"], "history_scope": "tree"})
        asset = case.keep("plan-asset.bin", os.urandom(29))
        raw = asset.read_bytes()
        value["assets"] = [{"id": "linux-plan-asset", "role": "case-tool",
                            "file": str(asset), "mode": 0o444,
                            "sha256": LINUX.sha(raw), "bytes": len(raw)}]
    case.linux_plan_file = case.keep_json("plan.json", value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--tool", type=Path)
    parser.add_argument("--kind", choices=(
        "no-plan", "empty-plan", "selected-plan", "orphan-plan"))
    args = parser.parse_args()
    LINUX.require(sys.platform == "linux" and
                  (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == (0, 0, 0, 0),
                  "boot validation requires the authorized root Linux box")
    if args.pack is not None:
        records = [json.loads(path.read_bytes()) for path in
                   sorted(args.pack.glob("*/boot-record.json"))]
        LINUX.require(records, "no actual boot inputs were retained")
        raw = LINUX.encoded(pack_records(records))
        data = base64.b64encode(lzma.compress(raw)).decode("ascii")
        print("BOOT INPUT xz-base64 sha256=" + LINUX.sha(raw) +
              " bytes=" + str(len(raw)) + " data=" + data)
        return
    if args.root is None or args.tool is None or args.kind is None:
        parser.error("--root, --tool and --kind are required for boot")
    os.umask(0o077)
    # Isolate this fixture from any live plan without reading or printing it.
    os.environ.pop("LANEBOSS_LINUX_PLAN", None)
    case = Fixture(args.root)
    plan(case, args.kind)
    item = LINUX.boot(case)
    case.keep_json("boot.json", item)
    objects = args.root / "runtime"
    objects.mkdir(mode=0o700)
    binary = LINUX.put(objects / "laneboss", os.urandom(43), mode=0o555)
    raw = binary.read_bytes()
    pin = document("laneboss", "artifact", raw)["ref"]
    executable = {"id": pin["id"], "sha256": pin["sha256"], "version": "inert-fixture"}
    runtime = {"schema": "laneboss.runtime.v2", "generation": 1,
               "artifact": executable, "bootstrap": executable, "bindings": [],
               "objects": [{"id": "laneboss", "role": "serve-fixture-agent",
                            "root_id": "serve_assets", "relative_path": "laneboss",
                            "mode": 0o555, "content": pin}]}
    for asset in item["assets"]:
        runtime["objects"].append(PROVISION.runtime_asset(objects, asset))
    config = "linux-boot-unit"
    LINUX.put(objects / "serve-agent.json", LINUX.encoded({"config": config}))
    LINUX.put(objects / "serve-task.json", b"Inert Linux bundle validation fixture.\n")
    runtime_raw = LINUX.encoded(runtime)
    runtime_file = LINUX.put(args.root / "runtime.json", runtime_raw)
    boot = {"runtime_file": str(runtime_file),
            "runtime_manifest": document("runtime", "manifest", runtime_raw)["ref"],
            "judge": {"provider": "clef-sglang", "model": "Cloudflare/clef-flash",
                      "deployment_sha256": LINUX.sha(b"inert deployment"),
                      "tokenizer_sha256": LINUX.sha(b"inert tokenizer"),
                      "context_tokens": 256, "max_bytes": 256, "max_questions": 1,
                      "command_deadline_ms": 1000, "guidance_deadline_ms": 1000,
                      "cache_ttl_ms": 0, "outage_policy": "critical-only"}}
    inputs = args.root / "inputs"
    inputs.mkdir(mode=0o700)
    PROVISION.fixture_initial(inputs, objects, boot, case.root,
                              {"version": "inert-fixture"}, case.stage,
                              args.tool, case.command, item_inputs=item)
    request = PROVISION.immutable_input(inputs, "initial-ref.json",
                                       LINUX.encoded({"manifest": boot["initial_publication"]}))
    retained = {
        "boot.json": (case.root / "boot.json").read_bytes(),
        "canary.py": (case.root / "linux-canary.input.py").read_bytes(),
        "boot-pins.json": (case.root / "linux-boot.input.json").read_bytes(),
        "bundle-input.json": (inputs / "bundle-input.json").read_bytes(),
        "initial.json": Path(boot["initial_publication_file"]).read_bytes(),
        "assembler-output.sha256": (LINUX.sha(
            (case.root / "bundle-assemble.stdout").read_bytes()) + "\n").encode(),
        "initial-ref.json": request.read_bytes(),
    }
    # Retain precisely the immutable files consumed by RunInitialValidation,
    # without wrapping the same objects again in the assembler's base64 JSON.
    for path in sorted((inputs / "initial-objects").iterdir()):
        retained["objects/" + path.name] = path.read_bytes()
    if case.linux_plan_file is not None:
        retained["plan.json"] = case.linux_plan_file.read_bytes()
    if args.kind in ("selected-plan", "orphan-plan"):
        retained["plan-asset.bin"] = (case.root / "plan-asset.bin").read_bytes()
    records = [{"name": name, "sha256": LINUX.sha(data), "bytes": len(data),
                "data": base64.b64encode(data).decode("ascii")}
               for name, data in retained.items()]
    result = LINUX.encoded({
        "config": config, "manifest": boot["initial_publication"],
        "initial": boot["initial_publication_file"], "request": str(request),
        "records": records})
    LINUX.put(args.root / "boot-record.json", result)
    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    main()

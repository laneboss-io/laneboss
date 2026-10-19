"""Supervisor-only box recipe. This file provisions no machine or login."""

import argparse
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile

from artifacts import finish
from box import keep_source, run_directory
from ladder import SCENARIO
from ladder_live import missing
from ladder_observer import Observer, RemoteFailure
from prepare_ladder import prepare
from support import (Failure, ROOT, Recorder, clean_environment, exact_keys,
                     immutable, load, regular, require, require_linux, save, sha256,
                     verify_evidence)
from toolchain import (check_installer, resolve_go, verify_binary,
                       verify_compiler)


def bundle_file():
    # Read exactly this name; never enumerate/print inherited environment data.
    value = os.environ.get("LANEBOSS_LADDER_BUNDLE")
    if not value:
        raise Failure("vendor bundle absent", "prerequisite_missing", "lb-v2-secrets")
    try:
        directory = Path(value)
        require(directory.is_absolute() and directory.resolve(strict=True) == directory and
                not directory.is_relative_to(ROOT), "invalid private bundle location")
        info = directory.stat()
        require(info.st_uid == 0 and info.st_mode & 0o022 == 0,
                "vendor bundle is not administrator protected")
        manifest = load(immutable(directory / "public.json"))
    except (OSError, Failure):
        raise Failure("vendor bundle unavailable", "prerequisite_missing",
                      "lb-v2-secrets") from None
    exact_keys(manifest, ("schema", "go_archive", "go_sha256", "vendors",
                          "namespace_sha256", "install_contract", "observer_binding"))
    require(manifest["schema"] == "laneboss.ladder-bundle.v2",
            "unsupported private bundle manifest")
    # Credentials themselves are never opened by this process. The installed
    # administrator/broker consumes the original directory at its own authority.
    return directory, manifest


def capacity(directory, pins):
    fields = dict(line.split(":", 1) for line in
                  Path("/proc/meminfo").read_text(encoding="ascii").splitlines())
    facts = {"cpus": len(os.sched_getaffinity(0)), "memory_bytes": int(fields["MemTotal"].split()[0])*1024,
             "free_disk_bytes": shutil.disk_usage(directory).free}
    save(directory / "evidence" / "capacity.json", facts)
    require(facts["cpus"] is not None and facts["cpus"] >= pins["minimum_cpus"] and
            facts["memory_bytes"] >= pins["minimum_memory_gib"]*1024**3 and
            facts["free_disk_bytes"] >= pins["minimum_disk_gib"]*1024**3,
            "box is below the two-ladder capacity floor", "prerequisite_missing")


def keep_file(source, target):
    shutil.copyfile(source, target)
    target.chmod(0o400)
    require(sha256(source) == sha256(target), "retained input read-back differs")


def prep(directory, manifest, pins):
    evidence = directory / "evidence"
    kit = Path("/opt/lb-v2-e2e-kit")
    for name in ("privileged.py", "contract.json", "bwrap.apparmor"):
        source = immutable(kit / name)
        require(sha256(source) == sha256(ROOT / "scripts" / "v2-e2e" / name),
                "sealed kit differs from reviewed source")
        keep_file(source, evidence / name)
    environment = clean_environment(directory / "controller-home",
                                    directory / "controller-tmp")
    recorder = Recorder(evidence / "prep-commands", environment)
    for program in ("git", "sudo", "timeout", "python3", "dpkg-query", "aa-status"):
        require(shutil.which(program, path=environment["PATH"]) is not None,
                "required Linux prep tool absent: " + program, "prerequisite_missing")
    bwrap = regular("/usr/bin/bwrap")
    require(bwrap.stat().st_uid == 0 and bwrap.stat().st_mode & 0o6022 == 0,
            "bubblewrap must be protected and non-setid")
    keep_file(bwrap, evidence / "bwrap")
    result = recorder.run([str(bwrap), "--version"], "bwrap-version")
    require(result.exit_code == 0, "bubblewrap version failed")
    archive = immutable(manifest["go_archive"])
    require(sha256(archive) == manifest["go_sha256"], "Go archive SHA-256 differs")
    keep_file(archive, evidence / "go.tar.gz")
    go_root = directory / "toolchain"
    go_root.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as source:
        for item in source.getmembers():
            path = Path(item.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    path.parts and path.parts[0] == "go" and
                    (item.isdir() or item.isfile()), "unsafe Go archive member")
        source.extractall(go_root, filter="data")
    compiler = resolve_go(go_root / "go" / "bin" / "go")
    build_env = verify_compiler(directory, compiler, pins["go"],
                                (ROOT / "go.mod").read_text(), ROOT)
    # The source installer owns its compiler policy. Never override a conflict.
    check_installer(directory, ROOT / "scripts" / "install.sh", pins["go"])
    install = Recorder(evidence / "build-commands", build_env).run(
        ["sh", str(ROOT / "scripts" / "install.sh"), "--prefix",
         str(directory / "install")], "source-install", cwd=ROOT, timeout=1200)
    require(install.exit_code == 0, "source build/install failed")
    binary = (directory / "install" / "bin" / "laneboss").resolve(strict=True)
    verify_binary(directory, compiler, pins["go"], binary, ROOT)
    keep_file(binary, evidence / "tested-laneboss")
    require(set(manifest["vendors"]) == {"claudock-cli", "claude", "codex"},
            "both vendors and Claude Code must be pinned")
    for name, value in manifest["vendors"].items():
        exact_keys(value, ("path", "sha256", "version", "version_output"))
        executable = immutable(value["path"])
        require(sha256(executable) == value["sha256"], "vendor executable hash differs")
        require(name not in pins or value["version"] == pins[name],
                "vendor version differs from ladder pin")
        require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"]) is not None,
                "vendor exact version is absent")
        words = ["version"] if name == "claudock-cli" else ["--version"]
        result = recorder.run([str(executable), *words], "version-" + name)
        require(result.exit_code == 0 and
                result.stdout.read_text(encoding="utf-8") == value["version_output"] and
                value["version"] in value["version_output"], "actual vendor version differs")
        keep_file(executable, evidence / ("vendor-" + name))
    return binary, compiler


def install_trees(directory, binary, bundle, manifest, inputs):
    installer = ROOT / "scripts" / "v2-admin" / "namespace.sh"
    if not installer.is_file():
        missing("namespace.sh --install", "lb-v2-admin")
    require(sha256(installer) == manifest["namespace_sha256"],
            "namespace installer differs from operator review")
    # This E2E-owned file handshake is proposed, not an invented production
    # CLI. The admin owner must explicitly adopt it in its sealed contract.
    contract = load(immutable(manifest["install_contract"]))
    require(contract == {"request": "laneboss.ladder-install.v2",
                         "response": "laneboss.ladder-installed.v2",
                         "namespace_sha256": sha256(installer)},
            "namespace installer handshake is not approved")
    request = directory / "requests" / "install.json"
    save(request, {"schema": "laneboss.ladder-install.v2", "binary": str(binary),
                   "binary_sha256": sha256(binary), "inputs": str(inputs),
                   "configs": ["tree-a", "tree-b"],
                   "output": str(directory / "evidence" / "installation")}, mode=0o400)
    environment = clean_environment(directory / "controller-home",
                                    directory / "controller-tmp")
    # The bundle path is passed only to the reviewed installer, never argv or
    # evidence. Do not propagate it into agent/client/unit environments.
    environment["LANEBOSS_LADDER_BUNDLE"] = str(bundle)
    recorder = Recorder(directory / "evidence" / "admin-commands", environment)
    result = recorder.run(["bash", str(installer), "--install"], "install-trees",
                          cwd=ROOT, stdin=request, timeout=1200)
    if result.exit_code != 0:
        value = load(result.stderr)
        raise RemoteFailure(value.get("error", value), "lb-v2-admin")
    installed = result.json()
    exact_keys(installed, ("schema", "context_file", "result_file", "fixture_file",
                           "receipt_file", "observer_binding"))
    require(installed["schema"] == "laneboss.ladder-installed.v2",
            "namespace installer returned an unknown receipt")
    require(installed["observer_binding"] == manifest["observer_binding"],
            "namespace installer replaced the independent observer")
    receipt = load(immutable(installed["receipt_file"]))
    exact_keys(receipt, ("schema", "artifact_sha256", "configs", "allocations",
                         "controls", "sysctls_before", "sysctls_after"))
    require(receipt["schema"] == "laneboss.ladder-prep.v2" and
            receipt["artifact_sha256"] == sha256(binary) and
            receipt["configs"] == ["tree-a", "tree-b"] and
            receipt["allocations"] == [load(inputs / config / "allocation.json")
                                       for config in receipt["configs"]],
            "installation receipt differs from requested two bindings")
    require(receipt["sysctls_before"] == receipt["sysctls_after"] and
            receipt["sysctls_before"]["unprivileged_userns_clone"] == 1 and
            receipt["sysctls_before"]["apparmor_restrict_unprivileged_userns"] == 1,
            "AppArmor restriction-on fixture was relaxed or absent")
    controls = receipt["controls"]
    require(set(controls) == {"unprofiled", "profiled", "unprofiled-copy"},
            "AppArmor actual positive/red controls are incomplete")
    for name, reference in controls.items():
        verify_evidence(Path(installed["receipt_file"]).parent, reference)
        observed = load(Path(installed["receipt_file"]).parent / reference["path"])
        require(type(observed["exit_code"]) is int and
                (observed["exit_code"] == 0 if name == "profiled"
                 else observed["exit_code"] != 0) and
                observed["timed_out"] is False and bool(observed["stdout_sha256"]) and
                bool(observed["stderr_sha256"]), "actual AppArmor control failed")
    keep_file(immutable(installed["receipt_file"]),
              directory / "evidence" / "installation-receipt.json")
    return installed


def check_termination(receipt_path, harvest):
    """Check the supervisor's externally retained provider observations."""
    receipt_path = immutable(receipt_path)
    receipt = load(receipt_path)
    exact_keys(receipt, ("schema", "resource_id", "before", "after", "bundles"))
    require(receipt["schema"] == "laneboss.ladder-termination.v2" and
            bool(receipt["resource_id"]), "termination receipt has no actual resource")
    for name, expected in (("before", "running"), ("after", "terminated")):
        item = receipt[name]
        exact_keys(item, ("resource_id", "state", "observed_at", "query_exit", "raw"))
        require(item["resource_id"] == receipt["resource_id"] and
                item["state"] == expected and item["query_exit"] == 0,
                "provider did not confirm this resource's termination")
        verify_evidence(receipt_path.parent, item["raw"])
    from datetime import datetime
    start = datetime.fromisoformat(receipt["before"]["observed_at"])
    end = datetime.fromisoformat(receipt["after"]["observed_at"])
    require(start.tzinfo is not None and end.tzinfo is not None and end > start,
            "termination observation did not follow the live box observation")
    required = {"prep", "inputs", "installation", "units", "ladder", "final"}
    require(set(receipt["bundles"]) == required, "phase copy-back inventory is incomplete")
    for phase, item in receipt["bundles"].items():
        verify_evidence(harvest, item)
        # Re-read every tar member against the manifest inside that bundle.
        path = Path(harvest) / item["path"]
        with tarfile.open(path, "r:") as archive:
            members = archive.getmembers()
            manifests = [member for member in members
                         if member.name == "evidence/manifest.json"]
            require(len(manifests) == 1, "copied bundle omitted its manifest")
            source = archive.extractfile(manifests[0])
            require(source is not None, "copied bundle manifest is unreadable")
            from support import bytes_hash, decode
            expected = decode(source.read())["files"]
            by_name = {entry["path"]: entry for entry in expected}
            require(len(by_name) == len(expected) and len(members) == len(expected) + 1,
                    "copied bundle inventory is duplicated or incomplete")
            seen = set()
            for member in members:
                require(member.isfile() and member.name not in seen, "unsafe copied bundle member")
                seen.add(member.name)
                if member.name == "evidence/manifest.json":
                    continue
                stream = archive.extractfile(member)
                require(stream is not None and member.name in by_name,
                        "unexpected copied bundle member")
                data = stream.read()
                wanted = by_name[member.name]
                require(len(data) == wanted["bytes"] and bytes_hash(data) == wanted["sha256"],
                        "copied evidence differs from its retained hash")
            require(seen == set(by_name) | {"evidence/manifest.json"},
                    "copy-back omitted retained evidence")
    return {"machine_terminated": True, "phase_read_back": True,
            "release_accepted": False}


def snapshot(directory, output, phase):
    # Copy to the operator's mounted off-box evidence sink each phase. The
    # standard exporter hashes and reads back every byte before atomic publish.
    summary = {"exit_code": 2, "outcome": "incomplete", "phase": phase,
               "release_accepted": False, "machine_terminated": False}
    for item in load(directory / "evidence" / "source-manifest.json"):
        source = regular(ROOT / item["path"])
        require(source.stat().st_size == item["bytes"] and
                sha256(source) == item["sha256"], "executed source inputs changed during the phase")
    finish(directory, summary, output / phase)
    require(summary["artifact_collection_ok"],
            "phase evidence copy-back failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--check-termination", type=Path)
    parser.add_argument("--harvest", type=Path)
    args = parser.parse_args()
    if args.check_termination is not None:
        require(args.harvest is not None and args.out is None and
                args.source_revision is None and args.seed is None,
                "termination check requires only a receipt and harvest")
        result = check_termination(args.check_termination, args.harvest)
        save(args.harvest / "termination-check.json", result)
        return 0
    directory, installed, observer = None, None, None
    summary = {"exit_code": 2, "outcome": "setup-error", "release_accepted": False,
               "machine_terminated": False}
    try:
        require_linux()
        require(args.source_revision and args.out is not None,
                "box run requires source revision and external evidence sink")
        os.umask(0o077)
        bundle, manifest = bundle_file()
        require(args.out.is_absolute() and args.out.resolve() == args.out and
                not args.out.is_relative_to(ROOT) and
                not args.out.is_relative_to(bundle), "invalid external evidence sink")
        directory = run_directory("lb-v2-ladder", os.urandom(4).hex())
        keep_source(directory)
        environment = clean_environment(directory / "controller-home",
                                        directory / "controller-tmp")
        revision = Recorder(directory / "evidence" / "revision-commands", environment).run(
            ["git", "rev-parse", "HEAD"], "source-head", cwd=ROOT)
        require(revision.exit_code == 0, "source revision read failed")
        head = revision.stdout.read_text(encoding="ascii").strip()
        require(re.fullmatch(r"[0-9a-f]{7,40}", args.source_revision) is not None and
                head.startswith(args.source_revision), "source revision differs from checkout")
        save(directory / "evidence" / "source-revision.json",
             {"source_revision": head, "requested_revision": args.source_revision})
        pins = load(SCENARIO / "pins.json")
        capacity(directory, pins)
        binary, compiler = prep(directory, manifest, pins)
        snapshot(directory, args.out, "prep")
        seed = args.seed if args.seed is not None else int.from_bytes(os.urandom(6), "big")
        inputs = directory / "ladder-inputs"
        prepare(inputs, ["tree-a", "tree-b"], seed)
        # Plans contain synthetic challenges, never vendor credentials.
        retained = directory / "evidence" / "ladder-inputs"
        shutil.copytree(inputs, retained, symlinks=False)
        for source in inputs.rglob("*"):
            if source.is_file():
                require(sha256(source) == sha256(retained / source.relative_to(inputs)),
                        "retained ladder input bytes differ")
        snapshot(directory, args.out, "inputs")
        # Units must reject deliberate reds before either credentialed root.
        environment = clean_environment(directory / "controller-home",
                                        directory / "controller-tmp")
        environment["LANEBOSS_GO"] = str(compiler.path)
        environment["GOTOOLCHAIN"] = "local"
        recorder = Recorder(directory / "evidence" / "run-commands", environment)
        units = recorder.run(["bash", str(ROOT / "scripts" / "v2-e2e" / "unit.sh"),
                              "--out", str(directory / "evidence" / "units")],
                             "harness-units", cwd=ROOT, timeout=1800)
        require(units.exit_code == 0, "harness unit/red controls failed")
        snapshot(directory, args.out, "units")
        installed = install_trees(directory, binary, bundle, manifest, inputs)
        observer = Observer(installed["observer_binding"],
                            directory / "evidence" / "box-observer",
                            sha256(binary), load(inputs / "observer-plan.json")["draw_sha256"])
        context = load(immutable(installed["context_file"]))
        require(context["binary_sha256"] == sha256(binary) and
                Path(context["evidence_root"]).is_relative_to(directory / "evidence"),
                "installed case did not retain the exact candidate within evidence")
        snapshot(directory, args.out, "installation")
        fixture = load(immutable(installed["fixture_file"]))
        require(load(Path(context["test_root"]) / "ladder.json") == fixture,
                "installed fixture differs from case inputs")
        case = recorder.run(["bash", str(ROOT / "e2e" / "v2" / "cases" / "e2e" / "run.sh"),
                             "--context", installed["context_file"], "--result",
                             installed["result_file"]], "ladder-case", cwd=ROOT, timeout=7200)
        keep_file(Path(installed["result_file"]), directory / "evidence" / "case-result.json")
        summary.update({"exit_code": case.exit_code,
                        "outcome": "case-passed" if case.exit_code == 0 else "case-failed"})
        snapshot(directory, args.out, "ladder")
    except (Failure, OSError, ValueError, KeyError, TypeError) as error:
        failure = error if isinstance(error, Failure) else Failure("ladder box infrastructure failed")
        summary.update({"exit_code": 69 if failure.code in (
            "not_implemented", "prerequisite_missing", "unsupported") else 2,
                        "error": failure.wire()})
        print("ladder-box failed: " + failure.code + "; owner " + failure.owner,
              file=sys.stderr)
    finally:
        if observer is not None:
            try:
                result = observer.call("collect", {"configs": ["tree-a", "tree-b"]})
                require(result["processes_quiescent"] is True and
                        result["temporary_resources_collected"] is True,
                        "ladder collection is incomplete")
                save(directory / "evidence" / "box-collection.json", result)
            except (Failure, OSError, KeyError, TypeError) as error:
                summary.update({"exit_code": 2, "outcome": "cleanup-error",
                                "collection_error": type(error).__name__})
        if directory is not None:
            # Actual machine termination is checked by the supervisor after
            # this last copy-back. An on-box command cannot prove its own death.
            finish(directory, summary, args.out / "final")
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())

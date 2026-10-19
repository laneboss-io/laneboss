"""Consume the real serve report before an installed ladder handoff or launch."""

import argparse
import os
from pathlib import Path
import sys

from ladder_ready import ready_plan, require_ports
from ladder_supporting import verify_supporting
from manifests import context_file
from serve_handoff import verify_serve
from support import Failure, ROOT, require, require_linux, save, sha256


def launch_context(path, retained):
    context = context_file(path)
    require(context["case_id"] == "e2e" and context["phase"] == "candidate" and
            context["config"] == "tree-a", "launch requires the candidate two-tree ladder context")
    require(retained.report["scope"] == "installed-lifecycle",
            "serve-state cannot satisfy the installed lifecycle launch prerequisite")
    require(context["binary_sha256"] == sha256(retained.path("laneboss.input")) and
            sha256(context["binary"]) == context["binary_sha256"] and
            context["source_sha256"] == sha256(retained.path("source.tar")),
            "launch context differs from serve's exact installed binary or source archive")
    require_ports(ready_plan())
    verify_supporting(context)
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("service", "launch"), required=True)
    parser.add_argument("--serve-evidence", type=Path, required=True)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "linux", "installed handoff runs only on the authorized Linux box", "unsupported")
    require(args.result.is_absolute() and args.result.parent.resolve(strict=True) == args.result.parent and
            not args.result.exists() and not args.result.is_symlink(),
            "preserve existing result; use a fresh canonical absolute result path")
    require(not args.result.is_relative_to(args.serve_evidence), "keep ladder results outside serve evidence")
    require((args.context is not None) == (args.phase == "launch"),
            "service consumes serve evidence; only launch takes a frozen --context")
    record = {"schema": "laneboss.ladder-serve-handoff.v1", "phase": args.phase}
    error, retained = None, None
    try:
        retained = verify_serve(args.serve_evidence, record)
        if args.phase == "launch":
            require_linux()
            context = launch_context(args.context, retained)
            require(args.result.parent == Path(context["test_root"]).parent,
                    "launch result is outside the frozen case scope")
    except (Failure, OSError, KeyError, TypeError, ValueError) as caught:
        error = caught if isinstance(caught, Failure) else Failure("installed handoff input is missing or invalid")
    record["verified"] = error is None
    record["error"] = error.wire() if error is not None else None
    handoff_path = args.result if args.phase == "service" else args.result.with_name("serve-handoff.json")
    require(not handoff_path.exists() and not handoff_path.is_symlink(), "preserve existing handoff evidence")
    save(handoff_path, record)
    if error is not None:
        print("installed handoff failed: owner=%s code=%s; retain %s" %
              (error.owner, error.code, handoff_path.name), file=sys.stderr)
        upstream = record.get("upstream_failure")
        if isinstance(upstream, dict) and upstream.get("owner") and upstream.get("code"):
            print("retained serve failure: owner=%s code=%s" %
                  (upstream["owner"], upstream["code"]), file=sys.stderr)
        return 69 if error.code == "prerequisite_missing" else 1
    if args.phase == "service":
        print("serve evidence verified; units are stopped; ten-instance acceptance remains pending")
        return 0
    entry = ROOT / "e2e/v2/cases/e2e/run.sh"
    os.execv("/bin/sh", ["sh", str(entry), "--context", str(args.context), "--result", str(args.result)])


if __name__ == "__main__":
    sys.exit(main())

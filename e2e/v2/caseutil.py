"""Entry-side helpers. The outer runner independently validates every receipt."""

import argparse
from pathlib import Path

from manifests import context_file
from support import Failure, evidence, load, require, save, sha256


class Case:
    def __init__(self, assertion_ids):
        parser = argparse.ArgumentParser()
        parser.add_argument("--context", required=True, type=Path)
        parser.add_argument("--result", required=True, type=Path)
        args = parser.parse_args()
        self.context = context_file(args.context)
        self.result_path = args.result
        require(args.result.is_absolute() and
                args.result.parent.resolve() == Path(self.context["test_root"]).parent,
                "result path is outside the case scope")
        self.root = Path(self.context["evidence_root"])
        self.inputs = Path(self.context["test_root"])
        self.assertion_ids = assertion_ids
        self.assertions = []
        self.observed_exit = 0

    def check_artifact(self):
        require(sha256(self.context["binary"]) == self.context["binary_sha256"],
                "candidate bytes changed before invocation")

    def reference(self, path):
        return evidence(self.root, path)

    def finish(self, failure=None, *, reached=True, collection=None, presence=None):
        for path in self.root.rglob("*"):
            require(not path.is_symlink(), "linked evidence file")
        if presence is not None:
            target = self.root / "presence-summary.json"
            if target.exists():
                retained = load(target)
                require(all(retained[key] == value for key, value in presence.items()),
                        "case presence differs from retained aggregate provenance")
            else:
                save(target, presence)
        if failure is not None:
            save(self.root / "failure.json", failure.wire() if isinstance(failure, Failure) else
                 Failure("entry infrastructure failed").wire())
        refs = []
        for path in sorted(self.root.rglob("*")):
            require(not path.is_symlink(), "linked evidence file")
            if path.is_file():
                refs.append(self.reference(path))
        # There is no inferred collection success. A case must supply real facts.
        collection = collection or {"processes_quiescent": False,
                                     "temporary_resources_collected": False,
                                     "evidence": []}
        assertions = self.assertions or [
            {"id": name, "reached": reached, "verdict": "fail" if failure else "pass",
             "observed_exit": self.observed_exit, "evidence": refs}
            for name in self.assertion_ids]
        save(self.result_path, {
            "schema": "laneboss.e2e-result.v2",
            **{key: self.context[key] for key in ("case_id", "phase", "mutation_id",
                                                "binary_sha256", "source_sha256")},
            "assertions": assertions, "collection": collection})
        if failure is None:
            return 0
        return 69 if isinstance(failure, Failure) and failure.code in (
            "not_implemented", "prerequisite_missing", "unsupported", "unavailable") else 1

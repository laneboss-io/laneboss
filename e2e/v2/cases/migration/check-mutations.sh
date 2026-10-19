#!/usr/bin/env bash
# Applies one named mutation (or all) to an isolated copy of the repository,
# runs the focused migration tests, and verifies that the targeted test fails
# (Red) before passing on the unmutated tree (Green).
set -euo pipefail

case_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$case_dir/../../../.." && pwd)"

list_mutations() {
    cat <<'EOF'
mut-skip-hash-compare        internal/v2/migration/readers.go   TestMutSkipHashCompare
mut-skip-readback-verify     internal/v2/migration/readback.go  TestMutSkipReadbackVerify
mut-duplicate-delivered-mail internal/v2/migration/import.go    TestMutDuplicateDeliveredMail
mut-import-active-authority  internal/v2/migration/import.go    TestMutImportActiveAuthority
mut-allow-corrupt-evidence   internal/v2/migration/readers.go   TestRedControls/missing-brief
mut-allow-active-writer      internal/v2/migration/readers.go   TestRedControls/active-writer
mut-relaunch-unconfined      internal/v2/migration/relaunch.go  TestMutRelaunchUnconfined
mut-rollback-relink-old      internal/v2/migration/rollback.go  TestMutRollbackRelinkOld
mut-allow-rehashed-history   internal/v2/migration/readers.go   TestRedControls/rehashed-hist
mut-allow-inplace-ownership  internal/v2/migration/readers.go   TestRedControls/inplace-owner
mut-allow-label-parent       internal/v2/migration/relaunch.go  TestRedControls/label-parent
EOF
    python3 -I - "$case_dir/review-controls.json" <<'PYLIST'
import json
import sys
from pathlib import Path
controls = json.loads(Path(sys.argv[1]).read_text())["controls"]
if len(controls) != 71:
    raise SystemExit("migration review catalog must retain all 71 controls")
for row in controls:
    print(row["id"], row["edits"][0]["file"], row["test"])
PYLIST
}

if [ "${1:-}" = "--list" ]; then
    list_mutations
    exit 0
fi

if [ "$(uname -s)" != Linux ]; then
    printf 'migration mutations run only on the authorized disposable Linux test machine\n' >&2
    exit 2
fi

run_one_mutation() {
    local mut_id="$1"
    local work_copy
    work_copy="$(mktemp -d "${TMPDIR:-/tmp}/lb-v2-migration-mut.XXXXXX")"
    # Keep source, mutation bytes, binaries, transcripts and exits on failure as
    # well as success. The supervising box runner harvests these before cleanup.
    printf 'EVIDENCE: %s %s\n' "$mut_id" "$work_copy"

    python3 -I - "$repo_root" "$work_copy" "$mut_id" <<'PY'
import os
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys

src = Path(sys.argv[1]).resolve(strict=True)
dst = Path(sys.argv[2]).resolve(strict=True)
mut_id = sys.argv[3]

if src.is_relative_to(dst) or dst.is_relative_to(src):
    raise SystemExit("source and mutation snapshot directories must not overlap")

# Test-box source archives have no Git metadata. Inventory actual filesystem
# inputs in either an archive or a checkout, without following directory links.
excluded = {".git", ".codex", ".agents", ".aws", "__pycache__"}
reserved = {"source-inputs.json", "source-inputs.sha256", "source-revision.txt", "mutation-before.go.txt",
            "mutation-after.go.txt", "mutation-edits.json", ".test_pattern", ".diagnostic", "go-version.txt", "test.out", "red-build.out",
            "red-binary.sha256", "red.exit", "candidate-build.out", "candidate-binary.sha256", "candidate.out",
            "candidate.exit", "migration-red.test", "migration-candidate.test"}
paths = []


def walk_error(error):
    raise error


for directory, directories, files in os.walk(src, topdown=True, followlinks=False, onerror=walk_error):
    base = Path(directory)
    directories[:] = sorted(name for name in directories if name not in excluded)
    for name in list(directories):
        path = base / name
        if path.is_symlink():
            paths.append(path.relative_to(src))
            directories.remove(name)
    paths.extend((base / name).relative_to(src) for name in sorted(files) if name not in excluded)

inputs = []
for rel in sorted(paths):
    if rel.is_absolute() or ".." in rel.parts or any(part in excluded for part in rel.parts):
        raise SystemExit("source snapshot contains an unsupported path")
    if len(rel.parts) == 1 and (rel.name in reserved or (rel.name.startswith("mutation-") and rel.name.endswith(".go.txt"))):
        raise SystemExit("source input collides with a reserved evidence output")
    s, d = src / rel, dst / rel
    name = rel.as_posix()
    d.parent.mkdir(parents=True, exist_ok=True)
    if s.is_symlink():
        link = os.readlink(s)
        resolved = s.resolve(strict=True)
        if Path(link).is_absolute() or not resolved.is_relative_to(src):
            raise SystemExit("source snapshot contains an absolute or escaping symbolic link")
        if any(part in excluded for part in resolved.relative_to(src).parts):
            raise SystemExit("source snapshot symbolic link targets excluded metadata")
        if not (d.parent / link).resolve().is_relative_to(dst):
            raise SystemExit("symbolic link would escape the mutation snapshot")
        os.symlink(link, d)
        inputs.append({"path": name, "link": link})
    elif stat.S_ISREG(s.lstat().st_mode):
        shutil.copy2(s, d)
        data = s.read_bytes()
        copied = d.read_bytes()
        if copied != data:
            raise SystemExit("source snapshot copy differs from its input")
        inputs.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                       "mode": stat.S_IMODE(s.stat().st_mode)})
    else:
        raise SystemExit("source snapshot contains a missing or unsupported file")
inventory = (json.dumps(inputs, sort_keys=True, indent=2) + "\n").encode("utf-8")
(dst / "source-inputs.json").write_bytes(inventory)
(dst / "source-inputs.sha256").write_text(hashlib.sha256(inventory).hexdigest() + "\n", encoding="utf-8")
(dst / "source-revision.txt").write_text(
    "unavailable: filesystem source snapshot; see source-inputs.json and the supervising source archive\n",
    encoding="utf-8",
)

specs = {
    "mut-skip-hash-compare": (
        "internal/v2/migration/readers.go",
        "if int64(len(data)) != ref.Bytes || DigestBytes(data) != ref.SHA256 {",
        "if false && (int64(len(data)) != ref.Bytes || DigestBytes(data) != ref.SHA256) {",
        "^TestMutSkipHashCompare$",
    ),
    "mut-skip-readback-verify": (
        "internal/v2/migration/readback.go",
        'if !exists || rec.Content.SHA256 != api.Digest(lev.SHA256) || rec.Origin != "legacy_import" {',
        'if false && (!exists || rec.Content.SHA256 != api.Digest(lev.SHA256) || rec.Origin != "legacy_import") {',
        "^TestMutSkipReadbackVerify$",
    ),
    "mut-duplicate-delivered-mail": (
        "internal/v2/migration/import.go",
        "if mail.Delivered && resendDeliveredMail() {",
        "if mail.Delivered && (true || resendDeliveredMail()) {",
        "^TestMutDuplicateDeliveredMail$",
    ),
    "mut-import-active-authority": (
        "internal/v2/migration/import.go",
        'if (event.Kind == "lane.started" || event.Kind == "lane.adopted") && importActiveAuthority() {',
        'if event.Kind == "lane.started" || event.Kind == "lane.adopted" || importActiveAuthority() {',
        "^TestMutImportActiveAuthority$",
    ),
    "mut-allow-corrupt-evidence": (
        "internal/v2/migration/readers.go",
        'return integrityErr(fmt.Sprintf("missing rendered brief %s for event seq %d", rel, ev.Seq))',
        "return nil",
        "^TestRedControls$/^missing-brief$",
    ),
    "mut-allow-active-writer": (
        "internal/v2/migration/readers.go",
        'return nil, conflictErr(fmt.Sprintf("active writer sidecar or lock file present in inventory: %s", entry.Path))',
        "continue",
        "^TestRedControls$/^active-writer$",
    ),
    "mut-relaunch-unconfined": (
        "internal/v2/migration/relaunch.go",
        "if opts.UseSharedLastHome {",
        "if false && opts.UseSharedLastHome {",
        "^TestMutRelaunchUnconfined$",
    ),
    "mut-rollback-relink-old": (
        "internal/v2/migration/rollback.go",
        "if req.RelinkOntoV2Store {",
        "if false && req.RelinkOntoV2Store {",
        "^TestMutRollbackRelinkOld$",
    ),
    "mut-allow-rehashed-history": (
        "internal/v2/migration/readers.go",
        'if bundle.Verification.EventsChainSHA256 != "" && chainDigest != bundle.Verification.EventsChainSHA256 {',
        'if false && bundle.Verification.EventsChainSHA256 != "" && chainDigest != bundle.Verification.EventsChainSHA256 {',
        "^TestRedControls$/^rehashed-hist$",
    ),
    "mut-allow-inplace-ownership": (
        "internal/v2/migration/readers.go",
        "if quiescence.InPlaceOwnership || quiescence.SharedStore {",
        "if false && (quiescence.InPlaceOwnership || quiescence.SharedStore) {",
        "^TestRedControls$/^inplace-owner$",
    ),
    "mut-allow-label-parent": (
        "internal/v2/migration/relaunch.go",
        "if opts.UseLegacyLabelsForParent {",
        "if false && opts.UseLegacyLabelsForParent {",
        "^TestRedControls$/^label-parent$",
    ),
}

review_data = json.loads((dst / "e2e/v2/cases/migration/review-controls.json").read_text())
if review_data["schema"] != "laneboss.migration-review-controls.v1":
    raise SystemExit("unsupported migration review-control catalog")
if len(review_data["controls"]) != 71:
    raise SystemExit("migration review catalog must retain all 71 controls")
review_rows = {}
for row in review_data["controls"]:
    if row["id"] in specs or row["id"] in review_rows or not row["edits"]:
        raise SystemExit("duplicate or empty migration review control")
    review_rows[row["id"]] = row
    first = row["edits"][0]
    specs[row["id"]] = (first["file"], first["before"], first["after"], row["pattern"])

if mut_id not in specs:
    sys.stderr.write(f"unknown mutation id: {mut_id}\n")
    sys.exit(2)

rel_file, before, after, test_pattern = specs[mut_id]
edits = review_rows[mut_id]["edits"] if mut_id in review_rows else [
    {"file": rel_file, "before": before, "after": after}]
applied = []
for index, edit in enumerate(edits):
    rel = Path(edit["file"])
    if rel.is_absolute() or ".." in rel.parts or not rel.as_posix().startswith("internal/v2/migration/") or rel.suffix != ".go":
        raise SystemExit("mutation target is outside the migration module")
    target = dst / rel
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(dst):
        raise SystemExit("mutation target is missing, linked or escaping")
    before, after = edit["before"], edit["after"]
    if not isinstance(before, str) or not before or not isinstance(after, str):
        raise SystemExit("mutation edit must name exact source bytes")
    original = target.read_bytes()
    text = original.decode("utf-8")
    if text.count(before) != 1:
        raise SystemExit(f"mutation {mut_id}: expected 1 match in {rel}, found {text.count(before)}")
    suffix = "" if index == 0 else f"-{index + 1}"
    (dst / f"mutation-before{suffix}.go.txt").write_bytes(original)
    changed = text.replace(before, after, 1).encode("utf-8")
    target.write_bytes(changed)
    (dst / f"mutation-after{suffix}.go.txt").write_bytes(changed)
    applied.append({"file": rel.as_posix(), "before_sha256": hashlib.sha256(original).hexdigest(),
                    "after_sha256": hashlib.sha256(changed).hexdigest()})
(dst / "mutation-edits.json").write_text(json.dumps(applied, sort_keys=True, indent=2) + "\n", encoding="utf-8")
(dst / ".test_pattern").write_text(test_pattern, encoding="utf-8")
diagnostics = {
    "mut-skip-hash-compare": "expected source blob sha256 mismatch integrity failure",
    "mut-skip-readback-verify": "expected VerifyMigratedState to fail when read-back origin differs",
    "mut-duplicate-delivered-mail": "unexpected duplicate mail delivery effect",
    "mut-import-active-authority": "migration emitted forbidden identity.bound event",
    "mut-allow-corrupt-evidence": "expected missing rendered brief integrity error",
    "mut-allow-active-writer": "expected conflict error for active WAL sidecar",
    "mut-relaunch-unconfined": "expected shared --last home relaunch to be rejected",
    "mut-rollback-relink-old": "expected RelinkOntoV2Store to fail with conflict",
    "mut-allow-rehashed-history": "expected integrity error for rehashed bad history",
    "mut-allow-inplace-ownership": "expected conflict error for in-place ownership change",
    "mut-allow-label-parent": "expected forbidden error for label-derived parent in PrepareRelaunch",
}
diagnostics.update({name: row["diagnostic"] for name, row in review_rows.items()})
(dst / ".diagnostic").write_text(diagnostics[mut_id], encoding="utf-8")
PY

    local pattern
    pattern="$(cat "$work_copy/.test_pattern")"
    local out_file="$work_copy/test.out"
    go version >"$work_copy/go-version.txt"
    if ! (cd "$work_copy" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off go list -deps -test ./internal/v2/migration ./migration/v2 >/dev/null 2>"$out_file"); then
        printf 'BUILD_OR_SETUP_ERROR: %s failed transitive dependency resolution\n' "$mut_id" >&2
        cat "$out_file" >&2
        return 1
    fi
    if ! (cd "$work_copy" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off go test -c -o "$work_copy/migration-red.test" ./internal/v2/migration) >"$work_copy/red-build.out" 2>&1; then
        printf 'BUILD_OR_SETUP_ERROR: %s failed compilation\n' "$mut_id" >&2
        cat "$work_copy/red-build.out" >&2
        return 1
    fi
    sha256sum "$work_copy/migration-red.test" >"$work_copy/red-binary.sha256"
    set +e
    (cd "$work_copy" && "$work_copy/migration-red.test" -test.v -test.run "$pattern") >"$out_file" 2>&1
    local code=$?
    set -e
    printf '%s\n' "$code" >"$work_copy/red.exit"

    if [ "$code" -eq 0 ]; then
        printf 'SURVIVED: %s passed %s unexpectedly\n' "$mut_id" "$pattern" >&2
        cat "$out_file" >&2
        return 1
    fi
    if ! grep -q -- '--- FAIL:' "$out_file"; then
        printf 'BUILD_OR_SETUP_ERROR: %s did not reach a failing test assertion\n' "$mut_id" >&2
        cat "$out_file" >&2
        return 1
    fi
    local diagnostic
    diagnostic="$(cat "$work_copy/.diagnostic")"
    if ! grep -Fq -- "$diagnostic" "$out_file"; then
        printf 'WRONG_ASSERTION: %s did not reach its named migration invariant\n' "$mut_id" >&2
        cat "$out_file" >&2
        return 1
    fi
    local failed_tests
    failed_tests="$(awk '/--- FAIL:/ {print $3}' "$out_file" | paste -sd ',' -)"
    if ! (cd "$repo_root" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off go test -c -o "$work_copy/migration-candidate.test" ./internal/v2/migration) >"$work_copy/candidate-build.out" 2>&1; then
        printf 'BUILD_OR_SETUP_ERROR: %s candidate failed compilation\n' "$mut_id" >&2
        cat "$work_copy/candidate-build.out" >&2
        return 1
    fi
    sha256sum "$work_copy/migration-candidate.test" >"$work_copy/candidate-binary.sha256"
    set +e
    (cd "$repo_root" && "$work_copy/migration-candidate.test" -test.v -test.run "$pattern") >"$work_copy/candidate.out" 2>&1
    local candidate_code=$?
    set -e
    printf '%s\n' "$candidate_code" >"$work_copy/candidate.exit"
    if [ "$candidate_code" -ne 0 ] || ! grep -q -- '--- PASS:' "$work_copy/candidate.out"; then
        printf 'CANDIDATE_FAILED: %s\n' "$mut_id" >&2
        cat "$work_copy/candidate.out" >&2
        return 1
    fi
    printf 'KILLED: %s failed %s at its named assertion (exit %d); candidate passed\n' "$mut_id" "$failed_tests" "$code"
}

target_mut="${1:-all}"
if [ "$target_mut" = "all" ]; then
    mutation_rows="$(list_mutations)"
    while read -r mid _ _; do
        [ -n "$mid" ] || continue
        run_one_mutation "$mid"
    done <<EOF
$mutation_rows
EOF
    printf 'PASS: all migration red mutations were killed by their focused tests\n'
else
    run_one_mutation "$target_mut"
fi

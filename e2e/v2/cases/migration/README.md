# MIGRATE-ROLLBACK Black-Box Acceptance Case (`lb-v2-migration`)

## Overview

`e2e/v2/cases/migration/` contains frozen-source fixtures, typed installed-CLI probes, plan controls and the 82-control mutation checker for `lb-v2-migration`: eleven original controls plus 71 review controls in `review-controls.json`. The complete `MIGRATE-ROLLBACK` runtime case remains blocked on the ports listed in `internal/v2/migration/CONTRACT-GAPS.md`.
The harness invokes `run.sh --context CONTEXT_FILE --result RESULT_FILE` on a disposable Ubuntu 24.04 Linux spot box.

## Required Runtime Dependencies

Full black-box execution requires the following lanes to be integrated:
- `service` (`lb-v2-service`: socket client transport, blob staging, durable store transactions/read-back)
- `identity` (`lb-v2-identity`: human challenge/confirmation proof and peer authentication)
- `grants` (`lb-v2-grants`: confined data worker materialization and archive verification)
- `lifecycle` (`lb-v2-lifecycle`: `lane.adopt` for relaunching selected unfinished sessions in new confinement)
- `integrate` (`lb-v2-integrate`: composition root and `records.*` read-back routes)

The context must supply the installed `binding_file`. Every invocation passes that binding and the named configuration explicitly. Mutation keys are retained by logical call; upload chunks have distinct retained keys. Fixture-local IDs are replaced with actual committed BlobRefs before a live plan request is sent. The ergonomic plan route uses `--content-ref FILE --source-version VERSION`.

A human binding does not itself authorize reads or mutations. The current harness has no reviewed human ceremony fixture. Missing proof/session support stops at the actual typed refusal; the case does not fabricate one. A transport stub returning `not_implemented` (exit 69) records its owner in `evidence_root/dependency/missing.json` and fails the case. Setup and incomplete runtime coverage use `reached: false` and cannot kill a mutation.

Positive plans and every control upload must succeed before dependent checks. Negative controls require the intended typed error, rather than any nonzero exit. The complete case also requires apply, service read-back, no duplicate delivered mail, inert decision history, confined relaunch, retention of new work and matched rollback evidence. Its coverage gate currently reports those missing runtime rows and refuses a pass even if plan controls succeed.

The driver retains exact fixture archives, request files, argument lists, stdout, stderr, exits, mutation keys, original-tree snapshots and observed CLI process collection. Failed fixtures are retained for the supervisor. CLI process-group observations are not native containment acceptance; the enclosing harness must independently verify its owned test scope.

## Named Red-Before-Green Mutations (`check-mutations.sh`)

Run `bash e2e/v2/cases/migration/check-mutations.sh` (or supply one mutation ID) on the authorized disposable Linux test machine. The checker refuses runtime execution on other platforms. It applies each mutation to an isolated source copy, builds and retains its test binary, requires the named test assertion to fail, then builds and executes the same focused test on the unmutated candidate. Compile/setup errors, another failing diagnostic, a surviving mutation or a failing candidate stop the checker.

The checker inventories the filesystem directly and works with source archives
that contain no `.git`. It excludes Git metadata, Python bytecode caches and
private agent/credential directories. It does not follow directory links and
refuses absolute, escaping, dangling or excluded-metadata symbolic links,
unsupported files, overlapping source/snapshot roots and copy mismatches.
Inventory/copy errors remain setup failures; no mutation is silently skipped.

Each printed `EVIDENCE` directory retains source inputs and their inventory hash,
an explicit revision-unavailable marker, before/after bytes, Go version,
red/candidate binaries and hashes, transcripts and exit codes. The supervising
source archive supplies the revision; the checker never requires Git to infer
one. Harvest these directories before collecting the machine. Static
shell/Python validation does not establish a killed mutation.

The table below lists the eleven original controls. The complete review catalog,
including lane argument, lane error context and rollback read-limit regressions,
is in `review-controls.json`; the round-4 delta is described in
`migration/v2/CATCHUP4.md`. Both catalog loaders require all 71 review controls.

| Mutation ID | Acceptance rule in `MIGRATE-ROLLBACK` | Target file | Focused test that must fail |
| --- | --- | --- | --- |
| `mut-skip-hash-compare` | Compare every source hash/ID/sequence | `internal/v2/migration/readers.go` | `TestMutSkipHashCompare` |
| `mut-skip-readback-verify` | Verify new service bytes, hashes and legacy provenance | `internal/v2/migration/readback.go` | `TestMutSkipReadbackVerify` |
| `mut-duplicate-delivered-mail` | No duplicate delivered mail | `internal/v2/migration/import.go` | `TestMutDuplicateDeliveredMail` |
| `mut-import-active-authority` | No imported active authority | `internal/v2/migration/import.go` | `TestMutImportActiveAuthority` |
| `mut-allow-corrupt-evidence` | Corrupt/missing evidence stops without changing originals | `internal/v2/migration/readers.go` | `TestRedControls/missing-brief` |
| `mut-allow-active-writer` | Active writers stop without changing originals | `internal/v2/migration/readers.go` | `TestRedControls/active-writer` |
| `mut-relaunch-unconfined` | Relaunch selected history in new confinement | `internal/v2/migration/relaunch.go` | `TestMutRelaunchUnconfined` |
| `mut-rollback-relink-old` | Rollback restores matched old data+binary after retaining new work | `internal/v2/migration/rollback.go` | `TestMutRollbackRelinkOld` |
| `mut-allow-rehashed-history` | Rehashed bad history must fail | `internal/v2/migration/readers.go` | `TestRedControls/rehashed-hist` |
| `mut-allow-inplace-ownership` | In-place ownership changes must fail | `internal/v2/migration/readers.go` | `TestRedControls/inplace-owner` |
| `mut-allow-label-parent` | Label-derived parents must fail | `internal/v2/migration/relaunch.go` | `TestRedControls/label-parent` |

The draft.4 item-by-item port audit and unexecuted regression requirements are
in `migration/v2/DRAFT4-PORT.md`. Prior checkpoints do not cover this source
revision; all 82 controls must be rerun. No authenticated AI-service or native-isolation
acceptance is claimed by these fixtures.

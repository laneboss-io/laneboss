# Migration catch-up 2

This round addresses the three reviews of f75dfa0d. The supplied green box is
baseline evidence. This Mac performs static checks only; no new unit assertion,
baseline red/green run or runtime mutation kill is claimed here. Fault hooks
remain unchanged. The authority/label/mail hook findings identified by the
brief as non-findings were not treated as production paths.

The complete candidate must pass the normal and faults suites and all 76
migration controls on the supervising Linux box. Eleven original controls are
retained; review-controls.json adds 65 controls. Setup/compile failures never
count as kills. The review runner now requires the complete catalog, checks
listing status before its loop and retains each edit of a multi-edit control.

| Review item | Change and accepted/refused input regression |
| --- | --- |
| Fable P0 legacy IDs/arguments | legacy_inputs.go validates the original and selected values before adoption output. Session IDs use the same lowercase UUID shape as the two runner adapters; lane/role use v2 ID shape; branch uses canonical Git-safe components; base is an exact 40/65 lowercase hex pin; model uses the runners' bounded non-option label shape; effort is a closed driver-specific vocabulary. Missing session/base values and non-string payload fields refuse with their field name. Only a validated lane can supply the branch fallback. TestReviewLegacy, TestReviewLegacyTypes, TestReviewBranchComponent and TestReviewRole cover valid values and exact field refusals. |
| Fable P1 backup matching | Rollback requires verification.json, quiescence.json, events.sqlite, the ownership marker and configuration; verifies receipt schema/config, actual source data, and the quiescence source version against TargetVersion. ExpectedBinarySHA256 and ActiveV2StateDir are mandatory. TestReviewRollback accepts a measured matched copy and rejects empty/missing/mismatched backups, absent/wrong digest and absent active-state identity at their specific typed field gates. |
| Fable P1 / Gemini a3 rollback paths | rollback_files.go opens every directory component with descriptor-relative O_NOFOLLOW; backup files are read from held directories and must be regular. Both output directories must be absent and are created exclusively. Writes use held directory FDs, O_EXCL and O_NOFOLLOW, sync and read back the opened file. Ancestor/root/child symlinks, FIFOs, existing planted-link targets and retained-work overlap refuse before restore writes. EvalSymlinks errors conservatively count as overlap. TestReviewRollback and TestReviewOverlap retain an external canary and check exact typed field/code refusals. |
| Gemini a4 actual quiescence / retention | The caller's V2Quiescent true flag is never sufficient. Rollback requires a nonnil store and its MigrationQuiescence read; missing support returns typed not_implemented. Current config/freeze/epoch, known process/effect inventories, zero pending capture/effects, actual exited/zero survivors and a fresh timestamp are checked. The retained event history is always read through the store. TestReviewRollback live-process/no-measurement/nil-store and TestReviewQuiescence cover independent provider state, unknown counts, foreign config, pending work and stale measurements. |
| Gemini a2 completion publication | Import commits inert history and activating only. CompleteMigration first performs an internal staging read-back; only its success permits the atomic complete-phase plus migration.completed transaction. Public VerifyMigratedState requires complete and its correlated event. A failed read-back cannot publish completion or finish the effect. TestReviewCompletion and TestReviewReadback: activating cover both completed success and post-import failure. |
| Fable P2 / Gemini a5 computed problems and cache safety | Plan problems are computed from verified source facts and the presence of the complete effect-inventory producer. Completion rechecks both explicit and computed problems under the cache lock, then rechecks presence/problems before updating the bundle. TestReviewPlanProblems distinguishes a supported store from a store without the inventory port. TestReviewCompletion problems/source-problem/deleted rejects changed or disappearing cache state. |
| Gemini a5 mail and effect coverage | Returned mail has its own count and is not pending. MigrationEffects inventories the original operation across pending, claimed and completed effects, without the first-200 PendingEffects shortcut. Missing support refuses. TestReviewReadback checks all three states with a duplicate beyond 250 unrelated effects, returned mail and active-authority injection. TestReviewLargeOutbox accepts unrelated work without claiming a truncated inventory is complete. |
| Fable P2 credentials | Paths cover the listed netrc, Git, package-manager, AWS, Docker, gh, SSH and certificate/key-store files. Both session and worktree bytes additionally pass the existing pure credentialtext shape detector; a worktree credential is refused rather than silently dropped. TestReviewCredentials accepts plain history/source and refuses each listed path and a credential-shaped neutral filename. No matched value is emitted. |
| Fable P2 missing hostile inputs | TestReviewInventory adds traversal, absolute/noncanonical paths and escaping links. TestReviewApply and TestReviewProofFacts add missing proof, wrong digest, nonhuman principal, missing/stale human connection, consumed/expired proof and foreign verified facts, with no commit and the exact field/code. Read-back rejects injected authority/delivery and completion with failed store verification. Existing assertions and fault controls are preserved. |
| Gemini b P2 archive members | Tar member paths, privileged/mismatched mode, symlink target/correlation and unsupported member types are checked before accepting their read-back. TestReviewArchive includes a safe file and individual path/mode/link/type refusals. Tar and manifest bytes stay in the exact frozen source; the plan now states that only archive receipts are imported as records. |
| Gemini b P2 history order | Session paths are sorted before concatenation. TestReviewHistoryOrder requires the lexical byte order for multiple files across repeated reads. It does not rely on a particular Go map order. |
| Gemini b P2 projection/config inventory | Every lane with lane events requires its projection, verification.Lanes must equal the projection count, and sqlite metadata config must match the source config. TestReviewProjection checks a valid source and each changed selector/count. |
| Gemini b P3 two decision stores | A frozen source containing both sqlite and JSONL decision stores is ambiguous and now refuses before loading either. TestReviewDecisionSource accepts the single JSONL source and refuses the competing source at decisions.source. |
| Gemini b P3 supplied grants | A supplied GrantSet must have its actual unsigned canonical digest and an unexpired UTC timestamp before Materialize. TestReviewGrant accepts a sealed set and refuses a wrong digest or expired set with a freshly resealed digest, so the expiry test reaches the expiry gate. |
| Fable P3 proof expiry | Fresh apply checks actual expiry after exact receipt replay, preserving legitimate replay without consuming proof again. TestReviewApply: expired refuses an expired fresh proof; valid proof fixtures use future dates rather than a date about to expire. |
| Fable P3 canonical JSON | CanonicalJCS uses api.CanonicalJSON, the shared RFC 8785 encoder, instead of its separate Go g-format float path. TestReviewCanonical checks the deciding 0.000001 encoding. |

The synthetic positive legacy fixtures now carry explicit base pins. They do
not claim a native repository/history import; the real lifecycle/materialize
worker must still verify its granted source and base before launch. The black-box
driver reports a computed problems list as a prerequisite failure and cannot
count that plan as a completed row. It no longer assumes the implementation
always manufactures an empty list.

Two producer integrations are explicitly required. They are narrow optional
reads on the service-owned store, not public RPCs, request-supplied callbacks,
new credentials, a second writer or alternate authority types:

- MigrationEffects(context.Context, api.Scope, api.ID) returns the complete
  original operation's api.EffectRecord inventory in the pinned read view,
  including claimed/completed effects. Absence is a plan problem and read-back
  refuses. An empty result must be an actual authoritative inventory.
- MigrationQuiescence(context.Context, api.Scope) returns the current bound
  installation's api.QuiescenceReceipt from its actual frozen dispatch/helper
  state. It must not echo RollbackRequest.V2Quiescent or caller counts. Absence
  refuses rollback. Native store/helper owners must supply and verify the
  actual freeze and process/capture/outbox facts.

These ports are not currently implemented by the installed store merely
because the module can type-check. The in-memory tests implement them from
their own outbox/lifecycle model; this is not measured native quiescence or
installed migration acceptance. No permissive production adapter was added.

Fable P3's durable/bounded plan cache remains deferred. A hard-coded eviction
limit without a retained-plan/recovery contract could discard an in-flight
approved migration and change replay behavior. The cache remains in-memory;
restart still requires reopening the same retained manifest, and disappearance
now refuses safely instead of dereferencing a missing entry.

Fable/Gemini P3's vector/egress entry_sha256 recomputation remains deferred.
Its exact historical encoding differs across the supported sqlite/JSONL
formats and needs a versioned hash-recipe audit rather than a guessed checksum.
Source BlobRef/chunk/whole-file digests and existing text/vector/chain checks
remain enforced, and these records remain inert. This residual is not described
as complete inner-record verification.

The following controls name their deciding assertions. Exact edits and
patterns are retained in e2e/v2/cases/migration/review-controls.json.

| Control | Named test | Deciding assertion diagnostic |
| --- | --- | --- |
| mut-r2-legacy-session_id | TestReviewLegacy: session_id | legacy argument escaped its field gate |
| mut-r2-legacy-branch | TestReviewLegacy: branch | legacy argument escaped its field gate |
| mut-r2-legacy-base | TestReviewLegacy: base | legacy argument escaped its field gate |
| mut-r2-legacy-model | TestReviewLegacy: model | legacy argument escaped its field gate |
| mut-r2-legacy-effort | TestReviewLegacy: effort | legacy argument escaped its field gate |
| mut-r2-legacy-lane | TestReviewLegacy: lane | legacy argument escaped its field gate |
| mut-r2-branch-part | TestReviewBranchComponent | unsafe branch component was accepted |
| mut-r2-legacy-type | TestReviewLegacyTypes: branch | legacy non-string argument was accepted |
| mut-r2-credential-path | TestReviewCredentials: .netrc | credential material entered legacy history |
| mut-r2-credential-shape | TestReviewCredentials: notes.txt | credential material entered legacy history |
| mut-r2-worktree-secret | TestReviewCredentials: worktree | worktree credentials were silently accepted |
| mut-r2-history-order | TestReviewHistoryOrder | legacy history order is not deterministic |
| mut-r2-backup-required | TestReviewRollback: verification | unsafe rollback input escaped its field gate |
| mut-r2-backup-version | TestReviewRollback: version | unsafe rollback input escaped its field gate |
| mut-r2-digest-required | TestReviewRollback: digest | unsafe rollback input escaped its field gate |
| mut-r2-digest-match | TestReviewRollback: digest-mismatch | unsafe rollback input escaped its field gate |
| mut-r2-active-required | TestReviewRollback: active-empty | unsafe rollback input escaped its field gate |
| mut-r2-restore-overlap | TestReviewRollback: active-overlap | unsafe rollback input escaped its field gate |
| mut-r2-backup-overlap | TestReviewRollback: backup-overlap | unsafe rollback input escaped its field gate |
| mut-r2-retain-overlap | TestReviewRollback: retained-overlap | unsafe rollback input escaped its field gate |
| mut-r2-resolve-error | TestReviewOverlap | unresolved rollback path was treated as disjoint |
| mut-r2-backup-ancestor | TestReviewRollback: backup-parent | unsafe rollback input escaped its field gate |
| mut-r2-backup-root | TestReviewRollback: root-link | unsafe rollback input escaped its field gate |
| mut-r2-nonregular | TestReviewRollback: fifo | unsafe rollback input escaped its field gate |
| mut-r2-existing-target | TestReviewRollback: existing-target | unsafe rollback input escaped its field gate |
| mut-r2-rollback-store | TestReviewRollback: nil-store | unsafe rollback input escaped its field gate |
| mut-r2-quiescence-port | TestReviewRollback: no-measurement | unsafe rollback input escaped its field gate |
| mut-r2-quiescence-live | TestReviewRollback: live-process | unsafe rollback input escaped its field gate |
| mut-r2-phase | TestReviewReadback: activating | activating migration was advertised as verified |
| mut-r2-readback-before-publish | TestReviewCompletion: readback | completion was published before read-back |
| mut-r2-early-event | TestReviewCompletion: readback | completion was published before read-back |
| mut-r2-completion-problems | TestReviewCompletion: problems | completion ignored unresolved or disappearing plan |
| mut-r2-source-problems | TestReviewCompletion: source-problem | completion ignored unresolved or disappearing plan |
| mut-r2-plan-disappears | TestReviewCompletion: deleted | completion escaped its final verification gate |
| mut-r2-plan-problems | TestReviewPlanProblems | plan problems were not computed from dependencies |
| mut-r2-effects-all-states | TestReviewReadback: completed | all-state read-back missed duplicate delivery |
| mut-r2-effects-port | TestReviewMissingEffects | missing complete effect inventory was accepted |
| mut-r2-returned-mail | TestReviewReadback: returned | returned mail was counted as pending |
| mut-r2-proof-required | TestReviewApply: proof | apply input escaped its deciding guard |
| mut-r2-proof-digest | TestReviewApply: digest | apply input escaped its deciding guard |
| mut-r2-proof-expiry | TestReviewApply: expired | apply input escaped its deciding guard |
| mut-r2-human-only | TestReviewApply: actor | apply input escaped its deciding guard |
| mut-r2-connection | TestReviewApply: connection | apply input escaped its deciding guard |
| mut-r2-stale-binding | TestReviewApply: stale | apply input escaped its deciding guard |
| mut-r2-proof-facts | TestReviewProofFacts | apply accepted foreign verified proof facts |
| mut-r2-proof-consumed | TestReviewApply: consumed | apply input escaped its deciding guard |
| mut-r2-inventory-path | TestReviewInventory | inventory path escaped its refusal |
| mut-r2-inventory-link | TestReviewInventory: symlink | inventory symlink escaped its refusal |
| mut-r2-archive-path | TestReviewArchive: path | unsafe archive member was accepted |
| mut-r2-archive-mode | TestReviewArchive: mode | unsafe archive member was accepted |
| mut-r2-archive-link | TestReviewArchive: link | unsafe archive member was accepted |
| mut-r2-archive-type | TestReviewArchive: type | unsafe archive member was accepted |
| mut-r2-projection-missing | TestReviewProjection: missing | event lane without projection was accepted |
| mut-r2-projection-config | TestReviewProjection: config | source projection metadata mismatch was accepted |
| mut-r2-projection-count | TestReviewProjection: lanes | source projection metadata mismatch was accepted |
| mut-r2-grant-sha | TestReviewGrant: sha256 | relaunch accepted an invalid supplied grant set |
| mut-r2-grant-expiry | TestReviewGrant: expires_at | relaunch accepted an invalid supplied grant set |
| mut-r2-decision-source | TestReviewDecisionSource | ambiguous decision sources were accepted |
| mut-r2-canonical | TestReviewCanonical | migration canonical JSON diverged from RFC8785 |
| mut-r2-effects-causal | TestReviewEffectInventory | complete effect inventory omitted its causal migration |
| mut-r2-legacy-runner | TestReviewLegacy: runner | legacy argument escaped its field gate |
| mut-r2-role | TestReviewRole | invalid relaunch role was accepted |
| mut-r2-backup-directory | TestReviewRollback: non-directory | unsafe rollback input escaped its field gate |
| mut-r2-measurement-shape | TestReviewQuiescence: config | unmeasured rollback quiescence was accepted |
| mut-r2-measurement-age | TestReviewQuiescence: stale | stale rollback measurement was accepted |

The baseline manifest selects 42 new-behavior regression cases. Existing
security gates that only lacked a hostile-input test are not falsely listed
as defects that must fail on the old revision. Their new controls still must
reach the exact error-field assertion on a mutant and pass on the candidate.

On the authorized Linux machine, create an archive with the exact reviewed
revision and the baseline/ prefix, then run:

```sh
python3 -I e2e / v2 / cases / migration / check-review-baseline.py \
  /absolute/path/to/f75dfa0d-baseline.tar.gz \
   / absolute / path / to / new-lb-v2-migration-baseline-evidence
bash e2e/v2/cases/migration/check-mutations.sh
```

The baseline checker verifies the archive's full Git revision, keeps its
bytes, overlays only the new test files, and records source/binary hashes,
logs and exits. It requires a reached named failure and diagnostic on f75dfa0d,
then the same candidate assertion to pass in normal and faults builds. No
build/setup failure, missing test, skip or nonzero candidate result can pass.
The existing supervising parallel suite automatically discovers the 65 review
controls through the expanded catalog.

Final static vet, formatting/syntax and archive results are recorded in the
external round-2 report. Runtime before/after results, all 76 kills, complete
normal/faults unit results and the independent delta reviews remain pending
the supervising Linux run. No physical-presence, live model, native rollback
or installed serve result is inferred from these sources.

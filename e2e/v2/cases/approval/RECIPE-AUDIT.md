# Static audit of approval mutation recipes

This audit covers the **142 current component recipes** in [catalog.py](catalog.py).
Each row gives the exact source target, selected Go test, required failing
assertion, fixture/remaining-guard reasoning, acceptance-rule tags and measured
compile phase. All 12 installed recipes remain pending runtime evidence; their
owners, cells and requirements are in [MUTATIONS.md](MUTATIONS.md).

The guard/fixture reasoning below is source analysis. It states why the named
assertion is expected to detect that deliberate mutation. It is not a semantic
red result, a real authentication/publication result or an observed security
exploit. A later guard may still refuse a mutant; where the selected assertion
requires the original typed error, that changed outcome is intentional
sensitivity evidence rather than a claim that every defense was removed.

## Exact current inventory

A JavaScript-only literal/source inspection of the current catalogue resolved
all 142 sites exactly once with no duplicate file/transformation pairs.
catalog.py was not imported or executed on the Mac. The four cli_stub rows
target one frozen handler each; all other rows use one literal replacement.
The full before/after bytes, package and rule lists remain authoritative in
catalog.py.

The six adapter guard/digest recipes are actual source mutations rather than
extra copies of a handler stub. Retired duplicate names are recorded only in
the consolidation note below. This table replaces the old 110-recipe table;
it does not carry forward obsolete selected tests or old CLI-stub descriptions.

## Measured compilation and source phases

The final column records actual normal/fault-tag vet exits, in that order.
It distinguishes the retained source phases:

- R10 is the prior d4fix4 static audit: 137 exact one-file overlays, with 274
  Linux amd64 vet commands returning 0. run-10/static-inputs.tar retains that
  input phase; static-mutants/results.json retains each exact command and exit,
  and each recipe directory retains source, overlay, metadata and logs.
  This phase predates the last authority test and the supervisor's final
  formatting correction. Its results are not relabeled as final-tree runs.
- R11 scratch is apply_authority on an actual retained source copy from the
  formatted continuation tree. Only service.go's currentL6 error check is
  changed, using the exact catalogue transform; its bytes were read back and
  the production file was confirmed unchanged. Linux amd64 vet returned 0
  both normally and with laneboss_faults. The copy, inputs and logs remain in
  run-11/apply-authority.
- The R11 unmutated packages also passed go vet for Linux amd64, Linux
  amd64 with laneboss_faults, and Darwin arm64 in R11. Clean gofmt -l, Python
  compilation and shell syntax checks passed after the supervisor formatted
  the two test files. These checks do not execute the tests or case.

- R13 (d4fix6) retains ten exact overlays for the changed/new content guards,
  fresh-byte verification, apply input isolation and related handler/source
  fixtures. All twenty Linux amd64 normal/fault vet commands returned 0.
  Current unmutated approval/CLI/case packages passed Linux, Linux-fault and
  Darwin vet; formatting, Python compilation and shell syntax passed. These
  compile results use the fresh-ID fixture and do not claim semantic red.

No Go test, race test, project interpreter run, product binary or red runner ran
on the development Mac. Every named semantic red/restored-green assertion
below still requires the authorized Linux execution. Static compilation alone
cannot establish mutation sensitivity.

## Complete component audit

Files other than commands_approval.go are under internal/v2/approval.
commands_approval.go is the owned file under internal/v2/cli. Test paths and
assertion text are copied from the current catalogue without relaxing them.

| Recipe and target | Exact focused test | Required failing assertion | Guard, fixture and remaining checks | Acceptance rules | Static vet normal / faults |
| --- | --- | --- | --- | --- | --- |
| `level` · `service.go` | `TestL6Authority/level_5` | `expected typed forbidden` | The altered level/launch field otherwise matches the fixture. Removing its guard reaches a later refusal with a different code or observable protected reads; the exact forbidden assertion remains sensitive. | `l6_only` | R10: 0 / 0 |
| `revoked` · `service.go` | `TestL6Authority/revoked` | `expected typed forbidden` | The altered level/launch field otherwise matches the fixture. Removing its guard reaches a later refusal with a different code or observable protected reads; the exact forbidden assertion remains sensitive. | `l6_only` | R10: 0 / 0 |
| `manifest` · `validate.go` | `TestGetTamperedManifest` | `expected typed integrity` | The old replacement removed the only use of digest and could not compile. The fixture's recomputed-digest positive control passes every other retained-change check; only the stale manifest binding remains invalid. | `wrong_hash` | R10: 0 / 0 |
| `base` · `canonical.go` | `TestManifestEffects/base` | `manifest omitted changed base` | The pure manifest test changes one covered value, with otherwise valid deltas and renderer. Omitting that field makes its digest equal the original and fails the named changed-field assertion. | `stale_base` | R10: 0 / 0 |
| `sources` · `canonical.go` | `TestManifestEffects/source` | `manifest omitted changed source` | The pure manifest test changes one covered value, with otherwise valid deltas and renderer. Omitting that field makes its digest equal the original and fails the named changed-field assertion. | `source_bytes` | R10: 0 / 0 |
| `derived` · `canonical.go` | `TestManifestEffects/derived` | `manifest omitted changed derived` | The pure manifest test changes one covered value, with otherwise valid deltas and renderer. Omitting that field makes its digest equal the original and fails the named changed-field assertion. | `review_diff` | R10: 0 / 0 |
| `renderer_hash` · `canonical.go` | `TestManifestEffects/renderer` | `manifest omitted changed renderer` | The pure manifest test changes one covered value, with otherwise valid deltas and renderer. Omitting that field makes its digest equal the original and fails the named changed-field assertion. | `review_diff` | R10: 0 / 0 |
| `human_kind` · `service.go` | `TestProofBeforeReplay/lane` | `expected typed forbidden` | The selected completed approval changes only the actor kind while retaining valid human fields, proof shape and the original receipt. Removing the shared kind guard permits that replay; no lane-field or read-proof guard masks it. Policy and ordinary human-preflight tests remain in the unit suite. | `review_diff`, `policy_current` | R10: 0 / 0 |
| `proof_digest` · `service.go` | `TestHumanPreflight/digest` | `expected typed forbidden` | The same proof-digest helper runs before lookup and in approval. The changed digest is well shaped; removing the shared equality bypasses both calls, so the exact forbidden assertion fails. | `wrong_hash` | R10: 0 / 0 |
| `approve_hash` · `service.go` | `TestHumanPreflight/staged_hash` | `expected typed conflict` | The request mismatch is well formed and the retained change is internally valid. After the relationship comparison is removed, the missing snapshot yields not_implemented rather than the required conflict. | `wrong_hash` | R10: 0 / 0 |
| `approve_base` · `service.go` | `TestHumanPreflight/staged_base` | `expected typed conflict` | The request mismatch is well formed and the retained change is internally valid. After the relationship comparison is removed, the missing snapshot yields not_implemented rather than the required conflict. | `stale_base` | R10: 0 / 0 |
| `duplicates` · `json.go` | `TestStrictJSON/duplicate` | `expected typed invalid_request` | The pure decoder sees two otherwise valid change_id fields. With the duplicate guard disabled, the map and encoding/json accept the last value; no later shape check rejects it. | Generic validation | R10: 0 / 0 |
| `paths` · `validate.go` | `TestResourceDeltaRefusals/path` | `expected typed invalid_request` | The old parent test executes ../outside with the guard removed; disjointFiles then repeatedly computes path.Dir(".."), which returns "..". The redundant-separator a//b case has a terminating parent chain and no other invalid field. | Generic validation | R10: 0 / 0 |
| `before_hash` · `validate.go` | `TestResourceDeltaRefusals / replace_before` | `expected typed invalid_request` | The replace input retains valid After bytes and changes only the absent before digest. Deleting the replace-before guard leaves all other normalized-file checks satisfied. | Generic validation | R10: 0 / 0 |
| `chunk_hash` · `blob.go` | `TestBlobIntegrity/hash` | `expected typed integrity` | Only the data-chunk hash is corrupted; data bytes, full-object hash and EOF are authentic. The later full-object/EOF checks cannot mask the missing chunk-hash check. | `source_bytes` | R10: 0 / 0 |
| `eof_length` · `blob.go` | `TestBlobIntegrity` | `expected typed integrity` | The prefix reference has matching projected metadata and its own valid hash. Only the EOF probe detects the longer actual object; the required failure occurs in the selected parent test. | `source_bytes` | R10: 0 / 0 |
| `dependency` · `service.go` | `TestNewDependencies` | `expected typed prerequisite_missing` | Each case removes one mandatory dependency while the others remain valid. Omitting the absence check returns a Service and fails the exact prerequisite assertion. | Generic validation | R10: 0 / 0 |
| `generation` · `validate.go` | `TestReceiptBounds` | `expected typed integrity` | Both generation values remain valid positive integers; only their adjacency is wrong. The removed equality is the remaining receipt defect. | `apply_receipts` | R10: 0 / 0 |
| `nonce_field` · `validate.go` | `TestReceiptBounds/nonce` | `expected typed integrity` | Only NonceID is empty in a structurally valid approval with valid times. No later shape check rechecks that reference. | `replayed_nonce` | R10: 0 / 0 |
| `intent` · `service.go` | `TestScopeIntent/digest` | `expected typed invalid_request` | The old replacement removed the only use of digest and could not compile. The altered digest has valid shape; after its comparison is disabled, a later reservation conflict differs from the required invalid_request. | `wrong_hash` | R10: 0 / 0 |
| `cancel` · `service.go` | `TestCancelled` | `cancelled operation reached dependencies` | Removing requestScope's cancellation guard permits a launch read before a later blob cancellation check. The error may remain cancelled, but the named dependency-count assertion then fails. | Generic validation | R10: 0 / 0 |
| `owner` · `service.go` | `TestGetOwnerAndHistory` | `expected typed not_found` | The sibling life has a matching current launch; the retained change is valid and keeps the original requester. Omitting the visibility comparison exposes the read and fails exact not_found. | Generic validation | R10: 0 / 0 |
| `error_propagation` · `service.go` | `TestDependencyErrors` | `dependency refusal was changed` | The fixture returns the exact Launch error sentinel. Swallowing it reaches a different later error, so the identity assertion fails rather than accepting another refusal. | Generic validation | R10: 0 / 0 |
| `registry` · `service.go` | `TestRegisterAndDecode` | `registration error was swallowed` | The fixture fails the second registration. Swallowing its error returns nil and leaves an incomplete registry, violating the named error/count assertion. | Generic validation | R10: 0 / 0 |
| `scope_digest` · `service.go` | `TestRawRequestDigest` | `valid retained optional member was lost by a typed digest` | The valid raw proposal explicitly includes an empty before_sha256 on an add. Typed canonical Params omit that member. Replacing the raw-byte digest input with typed Params rejects this valid request and fails the positive retained-intent assertion; the shared API vector remains a separate test. | Generic validation | R10: 0 / 0 |
| `resource_scope` · `validate.go` | `TestAllResourceKinds` | `D6 scope was narrowed by a resource-kind list` | Every resource path is valid. Adding a notes prefix prohibition rejects the ordinary notes case, which must remain accepted regardless of resource category. | `source_bytes` | R10: 0 / 0 |
| `false_success` · `service.go` | `TestMutationContractStops` | `expected typed not_implemented` | Blob inputs and authority pass before the real missing-snapshot refusal. Returning nil for that error violates the exact not_implemented assertion without any fake dependency. | `no_mutation` | R10: 0 / 0 |
| `render_sources` · `binding.go` | `TestRenderedBinding/sources` | `expected typed integrity` | The candidate is rehashed after the single binding change; org/base edits also update snapshot metadata. ValidateChange therefore accepts it before the named input/result comparison. | `source_bytes` | R10: 0 / 0 |
| `render_pin` · `binding.go` | `TestRenderedBinding/renderer` | `expected typed integrity` | The candidate is rehashed after the single binding change; org/base edits also update snapshot metadata. ValidateChange therefore accepts it before the named input/result comparison. | `review_diff` | R10: 0 / 0 |
| `render_scope` · `binding.go` | `TestRenderedBinding/org` | `expected typed integrity` | The candidate is rehashed after the single binding change; org/base edits also update snapshot metadata. ValidateChange therefore accepts it before the named input/result comparison. | `source_bytes` | R10: 0 / 0 |
| `extra_effect` · `binding.go` | `TestRevalidationEffects/extra` | `expected typed conflict` | Disable only the sorted Derived content comparison. The extra delta has valid metadata and a self-consistent fresh manifest; fresh IDs alone are allowed. Diff content still matches. Removing this guard therefore returns nil and fails the selected extra subtest's exact conflict assertion. | `extra_effect` | R13: 0 / 0 |
| `review_diff` · `binding.go` | `TestRevalidationEffects/diff` | `expected typed conflict` | Disable only Diff SHA/size/class comparison. The derived tuple list remains content-identical despite fresh IDs and manifest. The changed valid diff is then accepted, so the selected diff subtest fails its own exact conflict assertion. | `review_diff` | R13: 0 / 0 |
| `revalidation_ids` · `binding.go` | `TestRevalidationEffects/fresh_ids` | `byte-identical fresh IDs were refused` | Restore manifest/whole-Diff identity equality. The positive fresh_ids subtest changes both output IDs and the ID-sensitive manifest while preserving every content tuple. The restored old restriction refuses that valid output and fails its named positive assertion. | `source_bytes`, `review_diff` | R13: 0 / 0 |
| `apply_fresh_blobs` · `service.go` | `TestApplyFreshOutputs/corrupt_diff` | `expected typed integrity` | Ignore the handler's verifyRenderedBlobs error. Fresh Diff metadata still declares the approved SHA/size/class but its actual same-length bytes are corrupted; retained objects and the publication fixture remain valid. Ignoring this integrity error lets codeIs fail first. | `source_bytes`, `review_diff` | R13: 0 / 0 |
| `fresh_diff_bytes` · `blob.go` | `TestApplyFreshOutputs/corrupt_diff` | `expected typed integrity` | Ignore the helper's fresh Diff verifyBlob error. Metadata and individual chunk hashes are valid for their declared/actual values; the complete object hash reveals corrupted fresh bytes. The good derived object and approved publication cannot hide removal of this result check. | `source_bytes`, `review_diff` | R13: 0 / 0 |
| `fresh_after_bytes` · `blob.go` | `TestApplyFreshOutputs/corrupt_after` | `expected typed integrity` | The fresh Diff is valid and the fresh derived object's metadata still matches approved content, but its actual bytes are corrupted. Ignoring that derived verifyBlob error permits valid-shaped publication; the corrupt_after exact integrity assertion must fail first. | `source_bytes`, `extra_effect` | R13: 0 / 0 |
| `approval_hash` · `binding.go` | `TestApprovalBinding/hash` | `expected typed conflict` | The altered approval retains valid reference/hash/generation shapes and lifetime. Removing its change relationship comparison leaves no other mismatch. | `wrong_hash` | R10: 0 / 0 |
| `approval_base` · `binding.go` | `TestApprovalBinding/base` | `expected typed conflict` | The altered approval retains valid reference/hash/generation shapes and lifetime. Removing its change relationship comparison leaves no other mismatch. | `stale_base` | R10: 0 / 0 |
| `approval_expiry` · `binding.go` | `TestApprovalBinding/expired` | `expected typed forbidden` | The supplied clock equals approval expiry but remains before stage expiry. Other lifetime checks pass; removing approval-currentness permits the expired approval. | `expired_nonce` | R10: 0 / 0 |
| `approval_stage` · `binding.go` | `TestApprovalBinding/outlives_stage` | `expected typed integrity` | The stage expiry is after now and creation but before approval expiry. Its lifetime is valid; only the approval-within-stage comparison rejects it. | `expired_nonce` | R10: 0 / 0 |
| `result_org` · `results.go` | `TestProposeResult/org` | `expected typed integrity` | The response is rehashed and its snapshot org/base is kept consistent. Pure structural validation passes; only its relationship to the original request rejects the altered result. | `source_bytes` | R10: 0 / 0 |
| `result_base` · `results.go` | `TestProposeResult/base` | `expected typed integrity` | The response is rehashed and its snapshot org/base is kept consistent. Pure structural validation passes; only its relationship to the original request rejects the altered result. | `stale_base` | R10: 0 / 0 |
| `result_sources` · `results.go` | `TestProposeResult/extra` | `expected typed integrity` | The response is rehashed and its snapshot org/base is kept consistent. Pure structural validation passes; only its relationship to the original request rejects the altered result. | `source_bytes` | R10: 0 / 0 |
| `result_get` · `results.go` | `TestGetResult` | `expected typed integrity` | The alternate result ID is a valid ID and does not alter the manifest. Only request/result ID equality rejects it. | Generic validation | R10: 0 / 0 |
| `result_approval_id` · `results.go` | `TestApproveResult/change` | `expected typed integrity` | ValidateApproval accepts the otherwise valid altered receipt. The selected change/hash/base equality is its only request relationship defect. | `apply_receipts` | R10: 0 / 0 |
| `result_approval_hash` · `results.go` | `TestApproveResult/hash` | `expected typed integrity` | ValidateApproval accepts the otherwise valid altered receipt. The selected change/hash/base equality is its only request relationship defect. | `wrong_hash` | R10: 0 / 0 |
| `result_approval_base` · `results.go` | `TestApproveResult/base` | `expected typed integrity` | ValidateApproval accepts the otherwise valid altered receipt. The selected change/hash/base equality is its only request relationship defect. | `stale_base` | R10: 0 / 0 |
| `result_apply_change` · `results.go` | `TestApplyResult/change` | `expected typed integrity` | ValidateReceipt accepts the altered receipt; the base case advances both generations. Only the selected request/result relationship comparison rejects it. | `apply_receipts` | R10: 0 / 0 |
| `result_apply_id` · `results.go` | `TestApplyResult/approval` | `expected typed integrity` | ValidateReceipt accepts the altered receipt; the base case advances both generations. Only the selected request/result relationship comparison rejects it. | `apply_receipts` | R10: 0 / 0 |
| `result_apply_base` · `results.go` | `TestApplyResult/base` | `expected typed integrity` | ValidateReceipt accepts the altered receipt; the base case advances both generations. Only the selected request/result relationship comparison rejects it. | `apply_receipts` | R10: 0 / 0 |
| `proof_id` · `results.go` | `TestProofRef/id` | `expected typed invalid_request` | Each pure ProofRef fixture changes one shape/intent/time condition. The other checks pass, and no current-clock freshness check masks local shape validation. | Generic validation | R10: 0 / 0 |
| `proof_intent` · `results.go` | `TestProofRef/intent` | `expected typed invalid_request` | Each pure ProofRef fixture changes one shape/intent/time condition. The other checks pass, and no current-clock freshness check masks local shape validation. | `wrong_hash` | R10: 0 / 0 |
| `proof_time` · `results.go` | `TestProofRef/time` | `expected typed invalid_request` | Each pure ProofRef fixture changes one shape/intent/time condition. The other checks pass, and no current-clock freshness check masks local shape validation. | Generic validation | R10: 0 / 0 |
| `deadline_kind` · `context.go` | `TestDeadline` | `expected typed deadline_exceeded` | An already-expired context reaches contextFailure before dependencies. Changing its code to cancelled directly violates the exact deadline assertion. | Generic validation | R10: 0 / 0 |
| `cancel_finish` · `blob.go` | `TestBlobCancelled/empty` | `expected typed cancelled` | The empty-object read cancels the context after its initial checks. Its bytes/hash are valid and no EOF probe follows; removing the final cancellation check returns nil. | Generic validation | R10: 0 / 0 |
| `cancel_eof` · `blob.go` | `TestBlobCancelled/nonempty` | `cancelled blob verification performed another read` | A valid nonempty read cancels the context. Omitting the pre-EOF cancellation check causes a second fixture read; final cancellation still returns cancelled, but the named read-count assertion fails. | Generic validation | R10: 0 / 0 |
| `stage_cas` · `service.go` | `TestStageCommit` | `stage CAS did not bind the current org` | The shared structural validator does not require propose's org CAS. The typed fixture therefore receives the mutated transaction and its exact comparison-list assertion detects the missing org comparison. | `stale_base` | R10: 0 / 0 |
| `proof_guard` · `service.go` | `TestApprovalCommit` | `approval guarded transaction refused` | The shared validator rejects a missing ProofUse before Transact. The selected test's existing guarded-transaction refusal diagnostic is deliberately required; its exact typed fixture assertions remain. | `replayed_nonce` | R10: 0 / 0 |
| `apply_guard` · `service.go` | `TestApplyCompletion/complete` | `application did not return the durable publication reply` | The shared validator rejects a missing ApprovalUse before Transact. The complete case must instead succeed, so its existing durable-publication-reply diagnostic detects the missing guard. | `replayed_nonce` | R10: 0 / 0 |
| `publication_wait` · `transaction.go` | `TestApplyCompletion/complete` | `application did not return the durable publication reply` | Omitting AwaitReceipt supplies an empty receipt. Scope/operation checks return integrity, and the complete case's exact durable-reply assertion fails. | `apply_receipts` | R10: 0 / 0 |
| `completed_reply` · `transaction.go` | `TestCompletedReplay/org.change.propose` | `completed replay reached freshness or current state` | Reply is removed only after reservation validation. The consumer then repeats freshness/preflight work and fails the exact completed-replay assertion rather than replaying original bytes. | `idempotent_retry` | R10: 0 / 0 |
| `worker_alias` · `service.go` | `TestStageWorkerAlias` | `worker mutated retained input or committed an altered source` | Mutating the aliased worker input can mask the immediate source comparison, but it permits a transaction before the later result mismatch. The named zero-mutation/input-alias assertion catches that effect. | `source_bytes` | R13: 0 / 0 |
| `render_config` · `binding.go` | `TestRenderedBinding/config` | `expected typed integrity` | The candidate is rehashed after the single binding change; org/base edits also update snapshot metadata. ValidateChange therefore accepts it before the named input/result comparison. | `source_bytes` | R10: 0 / 0 |
| `render_reason` · `binding.go` | `TestRenderedBinding/reason` | `expected typed integrity` | The candidate is rehashed after the single binding change; org/base edits also update snapshot metadata. ValidateChange therefore accepts it before the named input/result comparison. | `review_diff` | R10: 0 / 0 |
| `render_snapshot` · `binding.go` | `TestRenderedBinding/snapshot` | `expected typed integrity` | The candidate is rehashed after the single binding change; org/base edits also update snapshot metadata. ValidateChange therefore accepts it before the named input/result comparison. | `source_bytes` | R10: 0 / 0 |
| `render_ownership` · `binding.go` | `TestRenderedBinding/ownership` | `expected typed integrity` | The candidate is rehashed after the single binding change; org/base edits also update snapshot metadata. ValidateChange therefore accepts it before the named input/result comparison. | `source_bytes` | R10: 0 / 0 |
| `result_reason` · `results.go` | `TestProposeResult/reason` | `expected typed integrity` | The response is rehashed and its snapshot org/base is kept consistent. Pure structural validation passes; only its relationship to the original request rejects the altered result. | `source_bytes` | R10: 0 / 0 |
| `source_owner` · `snapshot.go` | `TestSnapshotRefusals/generated` | `expected typed forbidden` | The source add collides only with the derived inventory, not its own inventory. Removing ownership checks at both production call sites permits it; all metadata and rendering inputs remain valid. | `source_bytes` | R10: 0 / 0 |
| `source_before` · `snapshot.go` | `TestSnapshotRefusals/before` | `expected typed conflict` | The existing-file replacement has valid shape and a wrong valid before hash. Deleting the preimage comparison leaves its inventory membership and other mode/action checks satisfied. | `source_bytes` | R10: 0 / 0 |
| `source_mode` · `snapshot.go` | `TestSnapshotRefusals/mode` | `expected typed conflict` | The deletion has the correct before hash and no After bytes; only its ordinary mode differs from the inventory. Removing the deletion-mode comparison permits it. | `source_bytes` | R10: 0 / 0 |
| `snapshot_base` · `snapshot.go` | `TestSnapshotRefusals/base` | `expected typed conflict` | Snapshot generation remains structurally valid but differs from the requested base. Removing this comparison later yields integrity at rendered provenance, not the exact conflict the selected test requires. | `stale_base` | R10: 0 / 0 |
| `verified_config` · `proof.go` | `TestVerifiedFacts/config` | `expected typed forbidden` | The direct verified-facts test changes one field while retaining the authentic Ref, other authority facts and times. Result construction uses the original scope, so no later check duplicates the omitted facts comparison. | `review_diff` | R10: 0 / 0 |
| `verified_principal` · `proof.go` | `TestVerifiedFacts/principal` | `expected typed forbidden` | The direct verified-facts test changes one field while retaining the authentic Ref, other authority facts and times. Result construction uses the original scope, so no later check duplicates the omitted facts comparison. | `review_diff` | R10: 0 / 0 |
| `verified_target` · `proof.go` | `TestVerifiedFacts/target` | `expected typed forbidden` | The direct facts test changes only Target. The local target is otherwise unused, so deleting the comparison prevented compilation. The corrected disabled comparison compiles in both Linux modes; no later result check duplicates the omitted target binding. | `wrong_hash` | R10: 0 / 0 |
| `verified_consumed` · `proof.go` | `TestVerifiedFacts/consumed` | `expected typed forbidden` | The direct verified-facts test changes one field while retaining the authentic Ref, other authority facts and times. Result construction uses the original scope, so no later check duplicates the omitted facts comparison. | `replayed_nonce` | R10: 0 / 0 |
| `verified_future` · `proof.go` | `TestVerifiedFacts/future` | `expected typed forbidden` | Verification remains before proof expiry but is just after now. Omitting the future-time check permits it; the remaining expiry and generated approval checks accept it. | `expired_nonce` | R10: 0 / 0 |
| `stage_lifetime` · `proof.go` | `TestVerifiedFacts/expired_stage` | `expected typed forbidden` | Omitting the expired-stage refusal clamps approval expiry to now. A later structural check yields integrity, not the exact forbidden required by this selected test. | `expired_nonce` | R10: 0 / 0 |
| `retained_config` · `validate.go` | `TestRetainedProvenance/config` | `expected typed integrity` | Only the selected retained provenance field is invalid. These fields are not independently covered by the effect manifest, so removing the selected provenance term permits the candidate. | `source_bytes` | R10: 0 / 0 |
| `retained_reason` · `validate.go` | `TestRetainedProvenance/reason` | `expected typed integrity` | Only the selected retained provenance field is invalid. These fields are not independently covered by the effect manifest, so removing the selected provenance term permits the candidate. | `source_bytes` | R10: 0 / 0 |
| `retained_ownership` · `validate.go` | `TestRetainedProvenance/ownership` | `expected typed integrity` | Only the selected retained provenance field is invalid. These fields are not independently covered by the effect manifest, so removing the selected provenance term permits the candidate. | `source_bytes` | R10: 0 / 0 |
| `retained_org` · `validate.go` | `TestRetainedProvenance/org` | `expected typed integrity` | Only the selected retained provenance field is invalid. These fields are not independently covered by the effect manifest, so removing the selected provenance term permits the candidate. | `source_bytes` | R10: 0 / 0 |
| `retained_base` · `validate.go` | `TestRetainedProvenance/base` | `expected typed integrity` | Only the selected retained provenance field is invalid. These fields are not independently covered by the effect manifest, so removing the selected provenance term permits the candidate. | `stale_base` | R10: 0 / 0 |
| `read_config` · `service.go` | `TestReadConfig` | `expected typed integrity` | The foreign config is a valid identifier and the retained change is otherwise consistent. ValidateChange has no current-caller config, leaving readChange's scoped comparison as the only refusal. | Generic validation | R10: 0 / 0 |
| `blob_metadata` · `blob.go` | `TestBlobMetadata` | `expected typed integrity` | Only projected BlobRef.Class differs; the ACL config, actual bytes, chunk hashes and EOF are valid. Removing metadata-reference equality permits the read. | `source_bytes` | R10: 0 / 0 |
| `raw_frame` · `transaction.go` | `TestRetainedFrame/changed` | `expected typed integrity` | Only the original frame's request ID differs. Params remain canonically equal, and propose's shared shape check does not bind RawRequest; removing the exact envelope comparison permits a commit. | Generic validation | R10: 0 / 0 |
| `commit_status` · `transaction.go` | `TestIncompleteCommit` | `expected typed integrity` | The pending commit contains the correct operation and final reply. Omitting only succeeded-status checking admits it and fails the exact integrity assertion. | `apply_receipts` | R10: 0 / 0 |
| `await_status` · `transaction.go` | `TestApplyCompletion/pending_reply` | `expected typed integrity` | The awaited receipt has the correct scope/key/operation and a valid success result, but pending status. Omitting the status gate returns that result and fails exact integrity. | `apply_receipts` | R10: 0 / 0 |
| `deadline_operation` · `transaction.go` | `TestApplyCompletion/deadline` | `publication deadline lost the original operation reference` | The wait error remains deadline_exceeded. Removing the copied original operation reference fails the selected original-operation assertion. | Generic validation | R10: 0 / 0 |
| `receipt_config` · `transaction.go` | `TestReceiptScope/lookup/config` | `expected typed integrity` | The injected foreign-config receipt has the original key, actor, operation and valid original result. Direct injection avoids normal fixture domain checks; removing the consumer comparison exposes the reply. | `idempotent_retry` | R10: 0 / 0 |
| `await_config` · `transaction.go` | `TestReceiptScope/await/config` | `expected typed integrity` | The injected foreign-config receipt has the original key, actor, operation and valid original result. Direct injection avoids normal fixture domain checks; removing the consumer comparison exposes the reply. | `idempotent_retry` | R10: 0 / 0 |
| `replay_proof_id` · `service.go` | `TestProofBeforeReplay/id` | `expected typed forbidden` | The human proof's ID alone is invalid and the completed receipt is valid. Removing that ID check permits replay before proof consumption, violating exact forbidden. | `review_diff` | R10: 0 / 0 |
| `await_bytes` · `transaction.go` | `TestAwaitOriginalReply` | `await did not return the exact original scoped reply` | The independent await consumer test requires a nonnil reply with the exact retained bytes. Replacing its return with nil directly fails that assertion. | `idempotent_retry` | R10: 0 / 0 |
| `deferred_binding` · `service.go` | `TestApplyCompletion/complete` | `application did not return the durable publication reply` | Removing Deferred makes guarded apply invalid under the shared public catalog. The unchanged complete subtest requires the durable publication reply and fails its named assertion. | `apply_receipts` | R10: 0 / 0 |
| `deferred_commit` · `transaction.go` | `TestDeferredCommit/key` | `invalid deferred commit reached publication wait` | The returned Deferred key alone differs, with correct operation and pending status. Removing its binding comparison reaches the fixture's explicit invalid-commit await sentinel. | `apply_receipts` | R10: 0 / 0 |
| `pending_retry` · `service.go` | `TestDeferredRetry/pending` | `pending retry did not return the original durable reply` | The pending receipt is well scoped. Omitting pending replay repeats preflight against the missing snapshot instead of awaiting, failing the named original-durable-reply assertion. | `idempotent_retry` | R10: 0 / 0 |
| `deferred_key` · `transaction.go` | `TestDeferredReceipt/lookup/key` | `expected typed integrity` | The outer receipt key/actor/operation are valid; only Deferred.Key differs. Removing this inner binding reaches an unavailable await instead of exact integrity. | `idempotent_retry` | R10: 0 / 0 |
| `deferred_effect` · `transaction.go` | `TestDeferredReceipt/await/effect` | `expected typed integrity` | The alternate effect ID is syntactically valid and all other receipt fields match. Only comparison with the expected original binding rejects it; the direct await helper avoids downstream result validation. | `apply_receipts` | R10: 0 / 0 |
| `frame_params` · `transaction.go` | `TestFrameParams` | `equivalent params lost the original frame or were refused` | The positive frame has equivalent reordered Params and identical envelope metadata. Restoring byte equality rejects only that valid encoding and fails its exact positive assertion. | Generic validation | R10: 0 / 0 |
| `frame_intent` · `transaction.go` | `TestFrameParams` | `expected typed integrity` | The changed frame Params are valid JSON but differ in generation. Omitting semantic comparison normalizes the parsed Params before envelope comparison and misses that change, failing exact integrity. | Generic validation | R10: 0 / 0 |
| `l6_human` · `service.go` | `TestActorGate/org.change.apply/human` | `expected typed forbidden` | The human actor keeps L6-shaped role, ID and life fields and matching recorded launch facts. Removing the authenticated lane-kind guard reaches the reservation sentinel instead of the exact forbidden refusal. | `l6_only` | R10: 0 / 0 |
| `cli_registration` · `commands_approval.go` | `TestCLIFileInputs/get/invalid` | `invalid input reached a dependency` | Removing only get's initialization row leaves its common file form unavailable. The test requires the exact owned invalid_request before poisoned proof/key/binding inputs, so missing registration cannot count as semantic validation. | `source_bytes` | R10: 0 / 0 |
| `cli_propose` · `commands_approval.go` | `TestCLIRejectsMissingFiles/propose` | `invalid input reached a dependency` | Each recipe replaces only its named frozen handler with a typed not_implemented stub. The test requires this module's exact invalid_request, exit 2 and empty stdout, so common transport/binding errors cannot mask an unreached handler. | `source_bytes` | R10: 0 / 0 |
| `cli_get` · `commands_approval.go` | `TestCLIRejectsMissingFiles/get` | `invalid input reached a dependency` | Each recipe replaces only its named frozen handler with a typed not_implemented stub. The test requires this module's exact invalid_request, exit 2 and empty stdout, so common transport/binding errors cannot mask an unreached handler. | `source_bytes` | R10: 0 / 0 |
| `cli_approve` · `commands_approval.go` | `TestCLIRejectsMissingFiles/approve` | `invalid input reached a dependency` | Each recipe replaces only its named frozen handler with a typed not_implemented stub. The test requires this module's exact invalid_request, exit 2 and empty stdout, so common transport/binding errors cannot mask an unreached handler. | `source_bytes` | R10: 0 / 0 |
| `cli_apply` · `commands_approval.go` | `TestCLIRejectsMissingFiles/apply` | `invalid input reached a dependency` | Each recipe replaces only its named frozen handler with a typed not_implemented stub. The test requires this module's exact invalid_request, exit 2 and empty stdout, so common transport/binding errors cannot mask an unreached handler. | `source_bytes` | R10: 0 / 0 |
| `cli_json` · `commands_approval.go` | `TestCLIRefusesMalformedInput/duplicate` | `invalid input reached a dependency` | Replace the adapter's strict DecodeJSON call with json.Unmarshal. The duplicate-key case requires the approval-owned early invalid_request; a later shared-parser or transport refusal has the wrong owner/boundary and cannot pass. | `source_bytes` | R10: 0 / 0 |
| `cli_files` · `commands_approval.go` | `TestCLIRefusesFileAliases` | `invalid input reached a dependency` | Remove O_NOFOLLOW from the actual owned file open. The first fixture is a symlink to an otherwise valid existing request; following it reaches a later boundary instead of the required owned invalid_request. | `source_bytes` | R10: 0 / 0 |
| `cli_options` · `commands_approval.go` | `TestCLIProhibitsMutationProof/propose` | `invalid input reached a dependency` | Remove only the proof-file prohibition for propose/apply. Existing valid request/proof files, a correctly bound session-proof shape, retained key and deliberate missing binding keep this an option test. The fixed path requires the exact prohibition message; the mutant reaches a dependency and fails the owned invalid_request assertion. | `source_bytes` | R10: 0 / 0 |
| `cli_proof` · `commands_approval.go` | `TestCLIProofInput/time` | `invalid input reached a dependency` | Ignore the error from ValidateProofRef(proof, digest) at the actual operation-proof call site. The selected malformed canonical expiry must be refused by the owned adapter before connection work; another boundary cannot supply the required error. | `source_bytes` | R10: 0 / 0 |
| `cli_read_proof` · `commands_approval.go` | `TestCLIReadProof/time` | `invalid input reached a dependency` | Ignore the distinct ValidateProofRef(proof, intent) error in the human.session branch. The read-session time fixture must reach its own shape refusal before opening the socket, independently of the operation-proof branch. | `source_bytes` | R10: 0 / 0 |
| `cli_raw_digest` · `commands_approval.go` | `TestCLIRawRequestDigest` | `valid raw optional member did not reach transport` | Hash checked typed re-marshalling while retaining original raw Params in the request. An explicit empty optional member is valid, but the two digests differ; the required positive transport-boundary assertion detects that typed reconstruction. | `source_bytes` | R10: 0 / 0 |
| `approval_window` · `proof.go` | `TestApprovalWindow/short_proof` | `approval lost its independent window` | Restore proof expiry as the approval expiry. A proof valid for 30 seconds must still produce the independent ten-minute approval (subject to stage expiry), so the positive expiry assertion fails without using an expired proof. | `expired_nonce` | R10: 0 / 0 |
| `apply_independent` · `service.go` | `TestApplyIndependentRender` | `expected typed conflict` | Restore cloneChange(change) as worker input. Only the wrongly supplied-output branch echoes its input; clean input retains fresh Diff/After refs with independently different derived bytes. The fixed path conflicts, while the old input can pass content/byte checks and expose the viable receipt. | `extra_effect` | R13: 0 / 0 |
| `apply_requester` · `service.go` | `TestApplyHandlerGuards/requester` | `expected typed forbidden` | The caller is another current recorded L6; launch facts match it while the valid staged change retains its original requester. A viable completion remains after the requester guard, so removing it fails the exact forbidden/zero-intent assertions. | `l6_only` | R10: 0 / 0 |
| `apply_authority` · `service.go` | `TestApplyReplayAuthority` | `expected typed forbidden` | Ignore currentL6's error at the actual apply call site. A revoked recorded launch accompanies an otherwise valid original completed receipt. Replay would return that receipt before fresh requester/state checks, so the exact forbidden assertion directly decides this call-site control. | `l6_only`, `idempotent_retry` | R11 scratch: 0 / 0 |
| `apply_base` · `service.go` | `TestApplyHandlerGuards/base` | `expected typed conflict` | Only ExpectedGeneration differs from the valid staged base. The completion fixture derives response correlation/generations from the actual request, avoiding an unrelated result fixture mismatch. The handler must refuse conflict before publication intent. | `stale_base` | R10: 0 / 0 |
| `apply_snapshot` · `service.go` | `TestApplyHandlerGuards/snapshot` | `expected typed conflict` | The approved snapshot has a different valid manifest digest while config/org/base and the staged change remain valid. The actual apply snapshot-binding error check must stop before the viable publication path. | `stale_base` | R10: 0 / 0 |
| `apply_approval_id` · `service.go` | `TestApplyHandlerGuards/approval_id` | `expected typed integrity` | A direct Approval callback returns another valid approval ID with all other bindings intact, bypassing the fixture store's normal ID filter. The handler's own foreign-approval check must return integrity. | `apply_receipts` | R10: 0 / 0 |
| `apply_binding` · `service.go` | `TestApplyHandlerGuards/approval_hash` | `expected typed conflict` | A well-formed approval carries another manifest hash. Other cases in the same handler test cover base, life, change and expiry. Removing this one ValidateApprovalBinding error check reaches viable completion instead of exact conflict. | `wrong_hash`, `expired_nonce` | R10: 0 / 0 |
| `apply_revalidation` · `service.go` | `TestApplyHandlerGuards/extra` | `expected typed conflict` | A fresh render adds an unreviewed derived effect and rehashes its own valid manifest. The fresh Diff/After objects are registered with real fixture bytes, so missing-object verification cannot mask a disabled handler comparison. Exact conflict and no publication intent decide the control. | `extra_effect`, `review_diff` | R13: 0 / 0 |
| `apply_blobs` · `service.go` | `TestApplyHandlerGuards/blob` | `expected typed integrity` | The renderer's independent byte plan retains a fresh valid Diff while only the approved Diff object is corrupted. Fresh verification passes, then the stored-object verification must return integrity before publication. Ignoring that actual handler check reaches a viable receipt. | `source_bytes` | R13: 0 / 0 |
| `apply_manifest` · `service.go` | `TestApplyHandlerGuards/publication` | `expected typed integrity` | The durable reply contains a different valid manifest digest but correct change/approval IDs, generations and timestamp. Shape validation alone accepts it; the fresh handler's staged-manifest comparison must return integrity. | `apply_receipts` | R10: 0 / 0 |
| `approve_snapshot` · `service.go` | `TestApproveHandlerGuards/snapshot` | `expected typed conflict` | A valid but different approved snapshot digest is returned to the human approval handler. The actual snapshot-binding check must reject conflict before proof verification or a viable approval commit. | `stale_base` | R10: 0 / 0 |
| `approve_blobs` · `service.go` | `TestApproveHandlerGuards/blob` | `expected typed integrity` | Corrupted retained diff bytes must be detected in the approval handler before checking the real proof facts or committing. Removing the actual verifyChangeBlobs error check admits the viable approval transaction. | `source_bytes` | R10: 0 / 0 |
| `approve_facts` · `service.go` | `TestApproveHandlerGuards/facts` | `expected typed forbidden` | The verifier facts name a different principal. Ignoring approvalFromProof's error loses the required forbidden propagation; later empty-result/transaction checks may still refuse, but with a different typed outcome. This control does not claim that all later guards disappear. | `review_diff` | R10: 0 / 0 |
| `approve_verifier_error` · `service.go` | `TestApproveHandlerGuards/verifier_error` | `CheckProof error was not propagated unchanged` | Replace the original CheckProof error with a newly constructed forbidden error. The test requires the same returned error identity, so preserving only its code cannot hide changed dependency diagnostics. | `review_diff` | R10: 0 / 0 |
| `human_read_session` · `service.go` | `TestHumanReadAuthority/missing` | `expected typed forbidden` | Bypass the actual humanRead call with the supplied scope. The selected human get lacks ReadAuthority but otherwise has valid shape and a readable staged fixture; exact forbidden and zero retained reads must fail when the call is bypassed. | `review_diff` | R10: 0 / 0 |
| `read_proof_forbidden` · `service.go` | `TestReadOperationProof` | `expected typed forbidden` | Disable the method restriction on envelope Proof. The human read otherwise has a valid live-session fixture and well-formed matching proof; accepting a read operation proof then exposes a result instead of exact forbidden. | `review_diff` | R10: 0 / 0 |
| `zero_run` · `service.go` | `TestZeroRunRead` | `expected typed forbidden` | Remove only recorded Target.Run == 0 from currentL6. The read fixture has otherwise matching recorded facts and a valid retained change; there is no later event/publication run check to mask this get boundary. | `l6_only` | R10: 0 / 0 |
| `human_lane_fields` · `service.go` | `TestHumanReadAuthority/lane_life` | `expected typed forbidden` | Remove only the human LifeID prohibition. The bound human read and other actor fields remain valid; session binding itself does not repeat this lane-field prohibition, so exact forbidden decides the control. | `review_diff` | R10: 0 / 0 |
| `proof_stage_time` · `proof.go` | `TestApprovalWindow/before_stage` | `expected typed forbidden` | Verification precedes change creation by one second while the proof is otherwise fresh and short-lived. Removing the before-stage check creates a valid-shaped approval instead of the required forbidden. | `review_diff` | R10: 0 / 0 |
| `proof_max_time` · `proof.go` | `TestApprovalWindow/overlong` | `expected typed forbidden` | The malformed verifier facts place expiry 121 seconds after verification. This is a secondary consistency bound under the documented proof-expiry-equals-challenge-expiry invariant; it is not a test of challenge lifetime from issuance. Removing it still fails the selected exact forbidden assertion. | `expired_nonce` | R10: 0 / 0 |
| `proof_evidence_class` · `proof.go` | `TestApprovalWindow/evidence_class` | `expected typed forbidden` | AssertionEvidence uses report, a valid closed blob class. Generic BlobRef validation still succeeds, leaving the artifact-only comparison as the intended forbidden decision. | `review_diff` | R10: 0 / 0 |
| `proof_evidence_size` · `proof.go` | `TestApprovalWindow/zero_evidence` | `expected typed forbidden` | Zero evidence bytes remain legal for a generic BlobRef but cannot describe a verified assertion artifact. Removing this specific lower bound fails exact forbidden. | `review_diff` | R10: 0 / 0 |
| `proof_evidence_max` · `proof.go` | `TestApprovalWindow/large_evidence` | `expected typed forbidden` | Evidence is one byte larger than MaxFrameBytes but within MaxObjectBytes. The generic object cap cannot mask removal of the stricter assertion-evidence cap. | `review_diff` | R10: 0 / 0 |
| `derived_array` · `validate.go` | `TestRetainedEmptyDerived` | `expected typed integrity` | Allow nil only for the derived list in normalizedFiles. The positive JSON round trip retains [], while nil can then normalize to the same effect digest; removing strict null rejection fails exact integrity. | `source_bytes` | R10: 0 / 0 |
| `blob_classes` · `validate.go` | `TestClosedCatalogs` | `unknown blob class was accepted` | Omit validBlobClass from generic blob validation. An otherwise valid invented class is then accepted; the explicit unknown-class assertion detects the missing closed enum. | `source_bytes` | R10: 0 / 0 |
| `ownership_class` · `validate.go` | `TestClosedCatalogs` | `expected typed integrity` | Remove manifest-only ownership typing while retaining generic closed-class validation. Artifact is a valid generic class and ownership is outside the effect digest, so the exact integrity assertion decides this additional restriction. | `source_bytes` | R10: 0 / 0 |
| `change_status` · `validate.go` | `TestClosedCatalogs` | `expected typed integrity` | Replace the closed status check with nonempty-only. Invented/control-containing nonempty statuses otherwise leave the retained manifest valid; accepting them fails exact integrity. | `source_bytes` | R10: 0 / 0 |
| `propose_status` · `results.go` | `TestClosedTransitions` | `expected typed integrity` | Remove the proposed-only result condition. An approved retained object is structurally valid but cannot be a fresh proposal result; the positive relationship validator must still return integrity. | `source_bytes` | R10: 0 / 0 |
| `approve_status` · `service.go` | `TestClosedTransitions/rejected/org.change.approve` | `expected typed conflict` | Ignore the fresh-approval status guard. The d4fix5 fixture now uses readyFixture's ordinary approval commit; the old apply-only fixture failed on its Deferred assertion first. With valid snapshot/blobs/proof facts, the mutant returns an approval and codeIs is the first failure. The selected test and diagnostic remain unchanged. | `policy_current` | R12: 0 / 0 |
| `apply_status` · `service.go` | `TestClosedTransitions/rejected/org.change.apply` | `expected typed conflict` | This is the sole READY recipe after approve_status. It retains completeApplyFixture, matching approval/base/provenance, a clean identical render and the actual deferred/await reply. Disabling only status can return the valid receipt, so codeIs fails before the secondary external-work assertion. No later fixture mismatch was found in the static walk. | `policy_current` | R12: 0 / 0 |

## Consolidation and source-specific limits

The old policy_human and replay_proof_kind transformations were duplicates of
human_kind. The current selected TestProofBeforeReplay/lane changes only actor
kind while leaving other human-shape facts valid and retaining a completed
approval. This avoids both the new read-proof prohibition and lane-field
checks masking the intended kind guard. Policy and ordinary human-preflight
tests remain in the suite.

replay_proof_digest was consolidated into proof_digest on the same shared
intent comparison; completed-replay digest coverage remains. l6_apply_level
was consolidated into level on the same helper check, while apply_authority
now protects the distinct service call site before replay. No retained test
or acceptance rule was removed to reduce the count.

scope_digest now targets raw-versus-typed reconstruction in service.go, not the
removed duplicate canonical request-digest implementation. cli_raw_digest
covers the equivalent adapter decision. The shared API JCS vector and
manifest's restricted canonical profile remain separate tests.

cli_json, cli_files, cli_options, cli_proof and cli_read_proof now target their
strict decode, no-follow open, option prohibition and two distinct proof
validation sites. The option fixture has existing valid files, a retained key
and the exact owned message. The four frozen CLI handler stubs remain distinct.

manifest, intent and verified_target keep local references while disabling
comparisons, so a deleted-only-use compiler error cannot count as a red.
The handler error-check recipes likewise retain rendered/snapshot/target
bindings through false && err != nil. Static success never overrides the red
runner's compile/crash exclusion. The path recipe selects the terminating
redundant-separator case; every original malformed path remains in full tests.

Nonce presence is not one-use enforcement. Guard shape is not a real store
transaction. Completed replay must precede current projections/freshness, while
current revocation still precedes replay. The store owns immutable completion
binding against the original approved change and filesystem marker; the
dispatcher owns reservation serialization and final preflight-error sealing.
Those requirements are quoted in
[CONTRACT-GAPS.md](../../../../internal/v2/approval/CONTRACT-GAPS.md).

## d4fix6 content and byte checks

Both retained/rendered changes still validate, including each manifest against
its own object IDs. ValidateRenderedChange preserves source/provenance/renderer
bindings. Revalidation then compares the sorted derived Path/Action/Mode/
BeforeSHA256 and After SHA/Bytes/Class, plus Diff SHA/Bytes/Class, independently
of retention IDs and the fresh manifest's different digest.

The valid renderer fixtures retain fresh Diff IDs; TestApplyFreshOutputs also
retains a new derived ID from the actual fixture source bytes. Its positive
case requires both new identities, a new manifest, actual fresh-object reads
and EOF probes, and unchanged approved publication references. The two corrupt
cases leave metadata equal to approved content while changing only actual
fresh bytes. This prevents metadata-only comparison or checking only the old
objects from producing a passing regression.

extra_effect and review_diff remain distinct comparison omissions selecting
their own extra/diff subtests. revalidation_ids reintroduces the old identity
restriction and must fail the positive fresh-ID assertion. apply_fresh_blobs,
fresh_diff_bytes and fresh_after_bytes separately omit the handler's error
handling and the helper's Diff/After verification error handling. Their selected
integrity assertions must be the actual failures on Linux.

TestRevalidationEffects also refuses changed path, action, mode, before hash,
after bytes/size/class and diff size/class, plus a corrupted own manifest.
The independent-render counterexample retains its intentional echo branch only
for already dirty input; the clean-input branch creates fresh objects. Extra
effect handler fixtures register their new objects so an unrelated not_found
does not mask the intended comparison.

proof_max_time remains a verifier-facts sanity check. Original challenge
issuance/expiry and proof-expiry equality are identity obligations, now
explicit in CONTRACT-GAPS.md; VerifiedAt subtraction is not an issuance check.

## Required Linux evidence

R12 (d4fix5) statically traces the reported approve_status assertion mismatch
to the apply-only transaction fixture: approve supplies Reply with no Deferred,
which hit the fixture's publication fatal before codeIs. The corrected test
uses the ordinary approval fixture for approve and the deferred fixture for
apply. Both recipe selections and the exact expected typed conflict assertion
remain unchanged. The supplied Linux log reports the assertion mismatch, but
does not contain the failed subtest's raw JSON transcript; this location is a
source trace rather than a newly executed Mac test.

The only later READY recipe is apply_status. Its requester/base/provenance,
approval lifetime/binding, clean render, stored bytes, transaction shape and
deferred completion were walked with status rejected. No competing fixture
refusal was found. Removing only that status guard can return the valid
receipt, making codeIs the first failure; the restored guard returns conflict
before external work.

Both exact status mutants were retained as one-file overlays and vetted in
Linux amd64 normal/fault modes with the corrected test: all four exits were 0.
The two R12 entries above record those compile results, not semantic red/green.
The current unmutated approval/CLI/case packages also passed Linux,
Linux-fault and Darwin vet; gofmt, Python compilation and shell syntax passed.
All R12 source bytes, commands and logs are retained with the lane evidence.

red.py must observe the exact selected failed test and assertion, exclude
compile errors/panics/unrelated failures, restore the exact source/modes and
then observe that selected test pass. Full units, fault-tag units and race
must run on the same changed tree. A selection containing pending installed
rows cannot report complete acceptance.

The installed harness uses case.json and --context/--result, drives the
hash-verified CLI under real enrolled actors, constructs its own defect inputs
and retains actual command exits, canonical effects and collection evidence.
A setup crash, absent service/UI/control job, failed Clock enrollment, wrong
artifact or unknown containment is unreached failure, not a killed mutation.
No component fixture or static result replaces installed candidate/red or
hardware/live-human evidence.

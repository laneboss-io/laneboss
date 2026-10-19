# ORG-APPROVAL mutation map

The current [catalogue](catalog.py) contains **142 component recipes**, 12
pending installed-service recipes and 13 acceptance rules. The
[recipe audit](RECIPE-AUDIT.md) lists every current component recipe, exact
selected test, required assertion, acceptance-rule links and static compile
phase. The old 110-recipe count and duplicate transformations are superseded.

Component fixtures measure owned guards, typed port interactions and result
relationships. They do not establish native authentication, durable nonce
consumption, store serialization, confined rendering or filesystem publication.
Those require installed candidate/red artifacts from their owning lanes.

## Exact component selection

Every READY entry names one owned production-file transformation, one focused
Go test and the exact assertion that must fail. The four cli_stub entries
replace only the named frozen handler; other entries replace an exact guard
or expression. Current source inspection resolves all 142 sites exactly once
and finds no duplicate file/transformation pairs.

On the authorized Linux machine, red.py copies the source, applies the selected
transformation, requires the selected failed test/assertion from Go JSON events,
restores exact bytes/modes, and requires that same test to pass. Compile errors,
panics, unrelated failures, missing tests, timeouts, surviving mutants and
incomplete restoration fail. Exit 0 alone is insufficient. No expected error
code or assertion is weakened.

Use fresh evidence outside the checkout:

```sh
go test -count=1 ./internal/v2/approval ./e2e/v2/cases/approval
go test -tags laneboss_faults -count=1 \
  ./internal/v2/approval ./e2e/v2/cases/approval
go test -race -count=1 ./internal/v2/approval ./e2e/v2/cases/approval

python3 e2e/v2/cases/approval/red.py \
  --source . --all --evidence /test/evidence/approval-component-red
python3 e2e/v2/cases/approval/red.py \
  --source . --mutation apply_authority \
  --evidence  / test / evidence / approval-apply-authority-red
```

These are Linux runtime commands, not development-Mac checks. A selected
component pass is scoped to its selection. --all --require-complete still
returns 69 while installed rows are pending, even after component success.
Requesting a pending row does not create an implementation or substitute pass.

## d4fix4 boundaries

approval_window restores the wrong proof-expiry clamp. A fresh 30-second proof
must produce the independent min(now+10 minutes, stage expiry) approval window.
Proof freshness and the stage ceiling remain separately checked.

apply_independent restores retained outputs in the worker input.
TestApplyIndependentRender has nonempty stored output and an input-dependent
echo/regenerate worker: clean input reveals independently different bytes and
must conflict. apply_revalidation targets the actual handler comparison.

The new apply_* and approve_* controls exercise actual service checks with
viable guarded/deferred completion fixtures. They cover requester/base/
snapshot, approval identity/binding, extra effects/diff, retained blob bytes,
publication manifest, verified facts and unchanged CheckProof errors.
apply_authority ignores currentL6's error at apply's call site. Its revoked
launch and valid completed receipt ensure a later fresh-requester check cannot
mask authority omitted before replay. Propagation controls may detect a changed
typed error even when another guard still refuses; the audit states that limit.

Human reads require bound refreshed session facts and accept no operation
Proof. Actor shape, nonzero launch Run, proof creation-time ordering, the
120-second bound and bounded artifact assertion evidence have deciding tests.
Closed BlobRef/status enums and fresh status transitions have separate recipes.
derived_array checks the strict null refusal while preserving a real [] round
trip.

scope_digest now mutates typed reconstruction in requestScope; cli_raw_digest
mutates it in the owned adapter. Both retain an explicit empty before_sha256
on a valid add. Shared api.RequestDigest hashes raw Params; TestRequestJCS pins
its vector. Manifest's restricted canonical-value tests remain separate.

The frozen cli_propose/get/approve/apply stubs remain. Other CLI recipes now
target their actual guards:

| Recipe | Production transformation | Deciding fixture |
| --- | --- | --- |
| cli_json | Replace strict owned decoding with json.Unmarshal. | Duplicate-key input must receive the owned early invalid_request. |
| cli_files | Remove O_NOFOLLOW from approvalFile. | A symlink to an existing valid request must fail before transport. |
| cli_options | Remove the mutation proof-file prohibition. | Propose/apply have existing valid files and a retained key; the exact option refusal must precede the missing binding. |
| cli_proof | Ignore ValidateProofRef(proof, digest)'s error. | Malformed canonical expiry must fail in the operation-proof branch. |
| cli_read_proof | Ignore the separate ValidateProofRef(proof, intent) error. | Malformed canonical expiry must fail in the human.session branch. |
| cli_raw_digest | Hash checked typed re-marshalling while retaining raw Params. | An explicit empty optional member must reach transport rather than fail digest binding. |

The following are retired duplicate names, not deleted tests:

| Retired names | Current recipe and retained coverage |
| --- | --- |
| policy_human, replay_proof_kind | human_kind selects TestProofBeforeReplay/lane on the shared kind guard. Policy and ordinary human-preflight tests remain. |
| replay_proof_digest | proof_digest targets the shared intent comparison; completed-replay digest coverage remains. |
| l6_apply_level | level targets the shared level check. Both actor tests remain; apply_authority separately guards the apply call site. |

## d4fix6 content revalidation

ValidateRevalidation validates both retained/rendered changes, including each
manifest's own references, and preserves immutable renderer-input bindings.
It compares the sorted Derived list by Path/Action/Mode/BeforeSHA256 and
After SHA256/Bytes/Class, plus Diff SHA256/Bytes/Class. New retention IDs and
the resulting different rendered manifest digest are permitted. Publication
still uses the original approved change and manifest.

The ready renderer fixture allocates a fresh Diff ID on every render. The
successful TestApplyFreshOutputs case also allocates a fresh derived After ID,
requires a different rendered manifest and checks that actual fresh bytes/EOF
were read while the approved references remain intact. Its corrupt_diff and
corrupt_after cases retain matching declared metadata but alter only fresh
object bytes, so checking the old objects or metadata alone cannot pass.

extra_effect and review_diff now disable their separate content comparisons
and still select their own exact TestRevalidationEffects subtest with expected
typed conflict. The helper's other table cases cover path/action/mode/preimage,
after bytes/size/class, diff size/class and malformed rendered-manifest refusal.

Four additional controls guard this correction:

| Recipe | Deciding test and assertion |
| --- | --- |
| revalidation_ids | TestRevalidationEffects/fresh_ids must fail with byte-identical fresh IDs were refused when ID/manifest equality is restored. |
| apply_fresh_blobs | TestApplyFreshOutputs/corrupt_diff must fail expected typed integrity when the handler ignores fresh verification's error. |
| fresh_diff_bytes | The same corrupt_diff assertion guards the helper's Diff verifyBlob result. |
| fresh_after_bytes | TestApplyFreshOutputs/corrupt_after must fail expected typed integrity when the fresh derived verifyBlob error is ignored. |

The valid-body helper registries keep the apply_revalidation mutant's extra
objects readable, so a missing object cannot mask that comparison. The input
isolation counterexample still echoes only wrongly supplied retained outputs;
the valid clean-input path independently retains fresh objects.

The proof_max_time control remains a secondary malformed-facts consistency
check. The actual challenge issuance lifetime and ProofRef expiry equality
belong to identity, as explicitly recorded in CONTRACT-GAPS.md.

## Complete acceptance-rule mapping

The d4fix5 correction gives TestClosedTransitions a method-specific completion
fixture. Approve uses readyFixture's ordinary verified approval transaction;
apply uses completeApplyFixture's deferred publication and durable receipt.
Previously both methods used the apply-only fixture, so removing approve's
status guard reached its unrelated "apply fixture did not receive the deferred
publication" fatal assertion before codeIs. The mutation, selected subtest and
required "expected typed conflict" diagnostic are unchanged.

The only READY recipe after approve_status is apply_status. Its static path
retains matching requester/base/snapshot/approval facts, clean independent
render inputs, identical outputs, valid stored objects and a complete deferred
reply. With only the status guard disabled, it can return its valid receipt;
codeIs is then the first failing assertion. With either status guard restored,
the corresponding closed change must conflict before external work. These
source traces still require the supervisor's actual Linux red/green rerun.

Counts and component names below come directly from each current recipe's
rules list. Generic recipes with no rule tag remain in the complete audit.

| Acceptance rule | Mapped component count and recipes | Pending installed recipe → cell |
| --- | --- | --- |
| `source_bytes`: L6 stages exact script, tool, config, template and note bytes | 43; `sources`, `chunk_hash`, `eof_length`, `resource_scope`, `render_sources`, `render_scope`, `revalidation_ids`, `apply_fresh_blobs`, `fresh_diff_bytes`, `fresh_after_bytes`, `result_org`, `result_sources`, `worker_alias`, `render_config`, `render_snapshot`, `render_ownership`, `result_reason`, `source_owner`, `source_before`, `source_mode`, `retained_config`, `retained_reason`, `retained_ownership`, `retained_org`, `blob_metadata`, `cli_registration`, `cli_propose`, `cli_get`, `cli_approve`, `cli_apply`, `cli_json`, `cli_files`, `cli_options`, `cli_proof`, `cli_read_proof`, `cli_raw_digest`, `apply_blobs`, `approve_blobs`, `derived_array`, `blob_classes`, `ownership_class`, `change_status`, `propose_status` | `publish_exact` → `apply`; `source_catalog` → `generated_source` |
| `review_diff`: human reviews the exact source and derived diff with a pinned renderer | 22; `derived`, `renderer_hash`, `human_kind`, `render_pin`, `review_diff`, `revalidation_ids`, `apply_fresh_blobs`, `fresh_diff_bytes`, `render_reason`, `verified_config`, `verified_principal`, `replay_proof_id`, `apply_revalidation`, `approve_facts`, `approve_verifier_error`, `human_read_session`, `read_proof_forbidden`, `human_lane_fields`, `proof_stage_time`, `proof_evidence_class`, `proof_evidence_size`, `proof_evidence_max` | `source_catalog` → `generated_source`; `human_verify` → `no_human`; `render_apply` → `extra_effect` |
| `apply_receipts`: application yields exactly those bytes, one generation and retained receipts | 13; `generation`, `result_approval_id`, `result_apply_change`, `result_apply_id`, `result_apply_base`, `publication_wait`, `commit_status`, `await_status`, `deferred_binding`, `deferred_commit`, `deferred_effect`, `apply_approval_id`, `apply_manifest` | `publish_exact` → `apply` |
| `l6_only`: L5 cannot propose and only the current authenticated L6 may mutate | 6; `level`, `revoked`, `l6_human`, `apply_requester`, `apply_authority`, `zero_run` | `live_l6` → `l5` |
| `filesystem`: a lane cannot update canonical org files directly | 0; No component fixture establishes the native filesystem boundary. | `writable_org` → `filesystem` |
| `stale_base`: stale or rebased changes fail | 11; `base`, `approve_base`, `approval_base`, `result_base`, `result_approval_base`, `stage_cas`, `snapshot_base`, `retained_base`, `apply_base`, `apply_snapshot`, `approve_snapshot` | `current_base` → `stale` |
| `wrong_hash`: a wrong review hash fails | 9; `manifest`, `proof_digest`, `approve_hash`, `intent`, `approval_hash`, `result_approval_hash`, `proof_intent`, `verified_target`, `apply_binding` | Installed `approve_hash` → `wrong_hash` still requires real fixtures. |
| `extra_effect`: new generated effects after review fail | 4; `extra_effect`, `fresh_after_bytes`, `apply_independent`, `apply_revalidation` | `render_apply` → `extra_effect` |
| `expired_nonce`: expired proof or approval fails | 7; `approval_expiry`, `approval_stage`, `verified_future`, `stage_lifetime`, `approval_window`, `apply_binding`, `proof_max_time` | `proof_expiry` → `expired` |
| `replayed_nonce`: consumed proof or approval cannot authorize another operation | 4; `nonce_field`, `proof_guard`, `apply_guard`, `verified_consumed` | `nonce_once` → `replayed` |
| `policy_current`: approval-policy edits require current-policy human approval | 3; `human_kind`, `approve_status`, `apply_status` | `human_verify` → `no_human`; `policy_bypass` → `policy_shortcut` |
| `idempotent_retry`: identical completed retry returns its original receipt; changed intent refuses | 7; `completed_reply`, `receipt_config`, `await_config`, `await_bytes`, `pending_retry`, `deferred_key`, `apply_authority` | `retry_receipt` → `retry`; `key_conflict` → `retry` |
| `no_mutation`: every refusal leaves canonical resources unchanged | 1; `false_success` | `publish_exact` → `apply`; `current_base` → `stale`; `nonce_once` → `replayed` |

Nonce-field presence and guard shape do not prove one-use consumption.
Supplied-clock expiry checks do not prove serialization under the real commit
lock. Snapshot/binding fixtures do not prove current store generation.
Reference comparison does not attest confinement or actual publication.

## Installed candidate and red cells

case.json discovers the frozen entry, which accepts exactly:

```sh
sh e2e/v2/cases/approval/run.sh \
  --context /test/cases/approval/context.json \
  --result /test/cases/approval/result.json
```

Candidate runs all eight constructed negatives plus source/review/human/apply/
retry/history, L5 and native-filesystem observations. Red supplies a distinct
installed artifact and mutation_id; RED_CELLS maps the pending names below,
plus approve_hash → wrong_hash, to the intended operation. The former
--fixture/--evidence/--cell entry and arbitrary actor/control argv are removed.
Fixed enrolled jobs run the hash-verified installed CLI under authentic actors;
refusals must be actual CLI stderr with the real exit.

| Pending installed recipe | Cell | Effective decision to mutate | Owners | Required runtime input/evidence |
| --- | --- | --- | --- | --- |
| `publish_exact` | `apply` | publish bytes outside the approved manifest or return before the generation switch. | `approval/service/grants` | draft.3 actual publisher/store completion and installed red artifact. |
| `source_catalog` | `generated_source` | permit a generated file to enter the editable source inventory. | `approval/store/grants` | draft.3 real approved source inventory and installed red artifact. |
| `human_verify` | `no_human` | omit verification of the operation-bound human assertion. | `identity/approval/store` | draft.3 authentic assertion verification and installed red artifact. |
| `live_l6` | `l5` | omit the effective authenticated L6 authorization decision. | `identity/service/approval` | authentic peer and service fixtures; other lane ownership. |
| `writable_org` | `filesystem` | expose the canonical org as writable in the L6 sandbox. | `linux/admin` | production isolation artifact; other lane ownership. |
| `current_base` | `stale` | omit the current org-generation comparison under the apply lock. | `approval/store` | draft.3 atomic store CAS, publication gate and installed red artifact. |
| `render_apply` | `extra_effect` | omit the staged-versus-rendered effect comparison at the production apply call site. | `approval/grants` | apply comparison is wired; real worker and installed red artifact remain. |
| `proof_expiry` | `expired` | omit the effective approval-receipt expiry decision at apply, including preflight and commit rechecks. | `identity/store/approval` | real registered Clock, current stage/base and coherent installed expiry red artifact. |
| `nonce_once` | `replayed` | omit the durable consumed-nonce comparison and atomic consumption. | `identity/store/approval` | draft.3 durable one-use guard and installed red artifact. |
| `policy_bypass` | `policy_shortcut` | authorize a policy edit using its proposed weaker policy instead of current policy. | `approval/store/policy` | draft.3 real current-policy authority and installed red artifact. |
| `retry_receipt` | `retry` | check stale base before replay or create a new receipt for the completed request key. | `service/store/approval` | draft.3 authorized durable replay, crash completion and installed red artifact. |
| `key_conflict` | `retry` | ignore changed request bytes under the same idempotency key. | `service/store/approval` | draft.3 real scoped key/digest conflict and installed red artifact. |

Installed mutations must affect the effective decision, including independent
preflight/commit checks where necessary. Removing only one redundant defense
may leave a surviving mutant; a different refusal is not a killed mutation.
The harness independently verifies actual target, artifact, input, effects and
the reached failure.

Stale setup creates and verifies a separately approved intervening generation.
Replay uses the consumed approval proof with a fresh key on the current base,
before proof expiry and before application. Expiry advances a registered
fixture Clock beyond receipt expiry while the stage remains current and probes
authority/base. Extra-effect setup independently fetches changed outputs with
fixed sources/base/pin; a new object ID alone does not count. The case itself
constructs wrong hash, unverified proof, generated-as-source and actual
approval-policy source edits.

Every refusal retains full canonical before/after snapshots. The same native
write job first updates a writable observer, then must reach a real canonical
OS refusal. Missing jobs/clocks/UI/ports, setup errors and unknown containment
remain unreached failures. The case writes the frozen atomic result and actual
collection facts; it does not manufacture a control response.

The [README](README.md) specifies data fixtures, protected job/control bindings,
human UI and evidence. [CONTRACT-GAPS.md](../../../../internal/v2/approval/CONTRACT-GAPS.md)
records dispatcher reservations/error completion, immutable publication replay,
object ACL, nonnil-array and common alias obligations. Component success cannot
close those dependencies.

## Measured scope

Run-10 retained 137 actual overlays and 274 successful Linux amd64 vet commands,
normal and fault-tag modes, on its archived source phase. Run-11 retains the
final apply_authority as an actual scratch copy with successful vet in both
modes. It also records current full-package Linux/Linux-fault/Darwin vet, a
clean gofmt listing, Python compilation and shell syntax after the supervisor's
formatting correction.

These are static measurements from their explicit source phases. They are not
semantic red/restored-green, race, installed candidate/red, hardware/live-human
or authenticated AI-service results. Linux runtime evidence remains required.
No project module, case, test binary, product binary or red runner was executed
on the Mac.

Run-12 (d4fix5) adds the method-correct status fixture described above. The
current packages passed the required static checks, and approve_status plus
the sole later READY recipe apply_status each passed Linux normal/fault vet
as exact retained overlays. Their expected diagnostics were preserved. These
four compile results still require the actual selected Linux red/green rerun.

Run-13 (d4fix6) adds byte-based revalidation and fresh-object verification.
The current package checks pass, and ten affected/new controls compile under
Linux normal/fault vet on exact retained overlays. These twenty static exits
do not establish the semantic assertions; the full 142-recipe Linux red/green
run remains required.

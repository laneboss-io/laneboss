# Draft.4 ladder: active contract gaps

Historical record restored from f64e2ea. Current source and installed readiness
are maintained in cases/ladder/READY.md and plan.json; old missing-port claims
and prior test counts below are not current acceptance results.

Base inspected: 693011a, including lb-v2 51c8319. Contract coverage retains
draft.4 fixes 10/11. The serve2 handoff was read at its authorized 179f3f0.
The current row-by-row lane/port/landed inventory is cases/ladder/plan.json;
cases/ladder/READY.md gives the installed-only phases and exact Linux commands.
Only E2E-owned files change.
Source findings are not live service, native isolation or vendor-auth evidence.

The plan cites actual source, not the supervisor's old lane inventory. Admin,
identity attestation, Codex, dashboard and secrets contain real merged code.
Grants resolution/materialization coordination, template rendering and watchdog
coordination also exist. Service, client, store, lifecycle, Linux launch and
migration still contain required stubs. A lane having code does not make each
port landed. All 22 rows remain blocked at this source revision.

The installed wrapper consumes serve2 report.json and its config-relative
manifest, bundle, receipts, numbered outputs and journal timings. No context
or result path is inferred from the producer. A completed serve report follows
unit shutdown and is not a live installation handoff. The source ledger and
precise item-1/item-3 sequence are in cases/ladder/READY.md.

| Owner | Symbol / handoff | Need |
| --- | --- | --- |
| lb-v2-serve, lb-v2-service | serve / health | Run the composed installed artifact. The case retains its real typed failure until readiness and actual public lifecycle/blob evidence exist. No fixture readiness is supplied. |
| lb-v2-service, lb-v2-identity | client.Open/Call/Close / human.session | The E2E readsession adapter now reuses one production public client connection for events, chunks and projections. Install its reviewed binary and real session proof per tree. Missing native ports retain their real owner error. Active reads refresh idle authority; renewal needs a genuinely fresh proof after the absolute cap. No observer proof provider exists. |
| lb-v2-service, lb-v2-integrate, lb-v2-e2e | MutationReceipt.Config / Transaction | These are internal Go types, not RPC replies. Adopt and implement the proposed protected observation normalization of original receipt config/key/actor/reply and actual write shapes. The case must not infer original Config from its current caller or open management files. Missing draft4-mutations coverage refuses before roots. |
| lb-v2-service, lb-v2-lifecycle, lb-v2-identity, lb-v2-e2e | ReserveLaunch / LaunchBinding / launch_audits | Provide authentic retained reservation, consumed authority event, prepared identity/recovery objects and policy at gate release through an approved observation transport. The reader fetches referenced bytes through blob.read; it never opens state files. No guessed public launch-audit RPC is added. Missing draft4-launch-pins/policy coverage refuses before roots. |
| lb-v2-service, lb-v2-grants, lb-v2-lifecycle | ReviewVerifier / ReviewEvidence | Supply the protected required-check inventory as review_requirements and actual frozen subject/test/snapshot/tool/EOF evidence. Historical review receipts without Evidence cannot authorize this ladder. Missing draft4-review coverage refuses before roots. |
| lb-v2-service, lb-v2-identity, lb-v2-approval | simulated presence | Preserve proof / use / session / ticket / operation / receipt marks and the declared software device identifiers. The dedicated test build and actual registration/signature checks remain required. Missing draft4-presence coverage refuses; simulated rows and aggregate report human_approval=not_proven. |
| lb-v2-identity, lb-v2-service, lb-v2-e2e | native read connection observations | Provide actual same-socket session/read correlation and nonmutating read transaction measurements. Public Scope omits its internal ConnectionContext; a JSON session ID cannot prove the connector. Missing draft4-reads coverage refuses before roots. |
| lb-v2-integrate, lb-v2-service | Event / StreamFrame / timing | Supply authentic durable-commit and actual parent-receive times in one monotonic domain, bound to config/event/life/run/reader. Draft.4 still lacks this public observation transport. No wall-clock or model elapsed-time substitute is accepted. |
| lb-v2-admin, lb-v2-identity | namespace.sh --install / Ticket | Adopt or replace the file handoff and install matched draft.4 bindings. Supply ticket_file per tree with the real principal_id/config/endpoint_generation, genuine enrollment and exact delivered inputs. Root start uses Ticket, not a generic root-operation proof. |
| lb-v2-admin, lb-v2-e2e | install.sh --install / --boot | The real administrator route is present. The two-tree live fixture/context handoff remains distinct from serve2's retained report and stopped fixture installation. The legacy source-box handshake has no reviewed producer; namespace.sh handles prerequisites, not a ladder-install JSON request. Use the real boot installer and retain the active installations, fresh tickets and bindings. |
| lb-v2-admin | ProjectCredentials / native endpoints / fixed worker input | credential_stubs.go:21 and gate_linux.go:366, 376, 389 and 393 under internal/v2/admin still refuse required projections. Real RegisterSpec, Prepare, OpenGate, capture, data-worker and release code do not complete these gates. |
| lb-v2-grants | root profiles / Render / VerifyReview / Archive | root.go:14 under internal/v2/grants refuses nonempty protected profile enrollment. render.go:68, review_stubs.go:57 and service.go:133 under internal/v2/dataworker still refuse the corresponding confined jobs. |
| lb-v2-secrets | internal.credential | internal/v2/secrets/internal.go:20 refuses the fixed credential job/material channel despite real Acquire, Inject and outside usage coordination. |
| lb-v2-approval | ChangeApproval presence | internal/v2/approval/proof.go:46 constructs the approval without copying simulated presence. This is a source omission; runtime impact is unmeasured. It is not credited as complete merely because approval code merged. |
| lb-v2-admin, lb-v2-lifecycle | helper.released / ReleaseReceipt | Supply actual helper-measured releases. The verifier rejects old lease payloads, foreign bindings, unknown survivors and live connections/jobs/writable exports. Source assertions do not prove the helper measured those resources. |
| lb-v2-lifecycle, lb-v2-grants, lb-v2-service | ArchiveReceipt.Manifest | Publish archive export/part mapping to committed public content refs. Acceptance fetches actual bytes through the CLI and compares hashes with the parent receipt and independent read-back. |
| lb-v2-lifecycle, lb-v2-watchdog | cancellation / ContinuationRequest.Swap | Preserve turn, history, task, prompt, mail, budgets and counters and expose the sole typed Swap fence. The harness checks observed epochs and Swap fields; it invents no public continuation method or duplicate outer fence. |
| lb-v2-e2e, lb-v2-approval | Transaction.Deferred | Deferred exists in api.Transaction and api.Commit, with validated completion in api/deferred.go. No observer normalization for deferred completion exists. This ladder applies no org change; a future apply cell must observe actual publication and its retained final reply. |
| lb-v2-e2e | laneboss.e2e-control.v2 | Optional protected controls binding now passes through the runner/context validator. The real controller/discovery for restart_service, run_confined_canary and advance_fixture_clock remains absent; dependent integration rows must refuse. These are separate harness controls, never service RPCs or an arbitrary root command route. |
| lb-v2-linux, lb-v2-admin, lb-v2-identity | independent observer | Supply real sibling canaries, native process-image/lifetime sampling, source inventories and idempotent collection. The client exists; no stand-in observer server is supplied. |
| lb-v2-packaging | scripts/install.sh / compiler | Both build commands still request Go 1.26.0 while the box fixture pins actual Go 1.26.5. Align packaging or publish the supported selector. This setup failure is not missing-serve E2E evidence. |
| lb-v2-claudock, lb-v2-codex, lb-v2-secrets | vendor pins / bundle | Confirm pinned authentication, refresh ownership, transcripts and explicit resume. The external bundle handoff remains risk A and untested. Credentials never enter source, fixture HOME or evidence. |

The E2E write-shape file follows the relevant draft.4 public catalog rows,
including WorkerLeases on start/adopt/resume/turn and cancellation. It is an
acceptance expectation, not production authority. No StateWrites, Transaction,
MutationReceipt or InternalIntent is submitted through a public endpoint.
The proposed observer data needs an approved real producer, not a new guessed
RPC. Missing coverage cannot produce a pass.

The original 99 harness methods and mandated ladder reds remain. New controls
exercise wrong provenance, missing/foreign receipts, missing keys/replies,
state-changing reads, out-of-domain writes, retained resources and stale epochs.
Both normal/fault builds need the supervisor's actual Linux tests, installed
serve E2E, independent Claude reviewer read and Gemini cross review before merge.

Fix 10 supersedes the earlier cross-review timing model. ReserveLaunch consumes
the ticket atomically with its pending receipt/reservation/PlanLaunch, before
helper_prepare creates the ready lane and binding. Redemption lies inside the
original receipt's sequence interval; later lane.created retains that operation.
The verifier and fixture now follow this reservation-before-creation order.

Fix 11 separates current work from historical replay/selection. Normalized
policy_context records the current approved generation and fresh, exact_replay
or retained_selection use. This is observation metadata, never a way for a
public caller to choose an old policy. Lane policy advances require authentic
lane.policy events; sealed unopened plans cannot be edited after drift.

HelperLeaseRequest selects a life, and LaunchSpec binds the actual lease and
run. The contract does not mandate a fresh lease on every resume or globally
unique lease IDs across identity.bound events. The verifier retains consistent
lease/run bindings, rejects conflicts and requires every completed child run
to belong to an allocated, eventually released lease. Each release follows its
bound run's end and covers the final run using that lease. It accepts distinct
per-run leases as well. It does not silently overwrite conflicting bindings.

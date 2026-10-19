# Draft.4 fixes 10 and 11 candidate report

The candidate starts at 01c866a77fc8 with the
incoming cf894d100097 merge left open. Changes are
uncommitted. The working content of the four stub conflicts is resolved;
the merge index remains unmerged for the supervisor to stage and conclude.
The incoming index already contains other owners' staged changes.

Validation stopped at a failed named Python check. Its command named a file
that does not exist: `e2e/v2/cases/service/actor.py`. The exact diagnostic is:

```text
[Errno 2] No such file or directory: 'e2e/v2/cases/service/actor.py'
```

This was an authoring error in the check invocation. The check was not retried.
Implementation edits stopped, and vet and mutation-anchor verification were
not started. Formatting and both shell syntax checks had completed successfully
in the same independent batch. This candidate has no compiled/unit, mutation,
native-helper or installed acceptance result in this lane.

## Regression first

The supervisor's input unit log on 01c866a reported that lane identities in
the socket/health/dispatch and canonical-record fixtures lacked launch plans.
The production refusal remains: lane identity requires its store-issued
launch plan. There is no historical-import exception or Linux skip.

The shared launch fixture now has NewIn for an existing component store.
socketRecord obtains its identity through ReserveLaunch, source/grant issuance,
registered capture planning, retained spec, prepared binding and observed
opened transition. It retains record bytes while the planner claim is live.
The query regression moved to an external store test using the same real
fixture. Health/head assertions read the actual journal head. Component helper
UID/GID values match the test process so real socket credentials are coherent;
these fixture values do not establish installed OS isolation.

## Group A

| Requested item | Source outcome and tests awaiting Linux |
| --- | --- |
| Startup enrollment inventory | Store.New calls CheckHumanEnrollmentPolicy after journal verification. The incoming assembly already calls the same inventory check before constructing endpoints. HumanEnrollments reads the complete protected inventory, including revoked credentials, checks ownership/ambiguity and propagates errors. An actual empty inventory supports first enrollment; an unavailable inventory is not treated as empty. Production refuses software markers, including revoked entries. Dedicated tagged tests retain the marked DTO provenance. |
| Administrator enrollment | InstallHumanEnrollment keeps its concrete fixed signature. The service's separate mode-0600 endpoint permits only begin/complete enrollment messages. Linux verifies native root credentials, every-fragment frame identity, actual helper executable hash and kernel process lifetime against protected installation data. The store retains an unexported commit capability, rechecks that same native channel under its writer lock, and rejects direct generic admin_enroll transactions. It commits the actual retained validator handoff, exact registration evidence, global absent baseline, consumed challenge and actual blob/operation receipt atomically. Exact replay reads that receipt. TestEnrollmentCeremonyFences, TestEnrollmentValidationFences and TestEnrollmentExactBytes isolate the nonce, baseline, channel, capability, key and byte guards. Real attestation remains the identity owner's validator; Darwin retains its typed native-capability barrier. |
| Simulated presence | Current enrolled credential markers must match both verified proof and ProofRef. Proof-use receipts retain the mark. Ticket, session, operation, approval and application and mutation receipts derive it from retained causal authority. Pending operation completion and internal life-target work preserve a prior true mark. Operation evolution and receipt reads reject loss. TestProofPresenceFences, TestPresenceWriteFences, TestPendingPresenceSurvives and TestPresenceEvolution name the propagation failures. The software-authenticator build tests are separate from the two ordinary mutation variants. |
| LaunchControlSource.Plan | Server.Plan resolves a retained reservation and current durable stage claim, validates that claim against the store, then reads StateStore.LaunchPlan under the claim's private execution authority. It preserves actual store errors and rejects a different returned reservation. TestPrivatePlanRead includes a stale inventory snapshot to isolate the store's actual expired-claim guard. |
| PolicyAt | Reads immutable projection history for an approved generation and verifies actual stored bytes/hash, generation and uniqueness. Unknown/future or ambiguous history refuses. TestPolicyHistoryAndAdvance and TestPolicyHistoryIntegrity distinguish retained snapshots from current approval. |
| RefreshLanePolicy | Uses current life/grants, lane CAS and cancellation epoch. It changes only the lane policy/generation/LastSeq and appends one actual lane.policy event; an already-current receipt appends none. Direct internal refresh writes must use the actual next journal sequence. Historical launch bindings and issued grants remain intact. TestPolicyAdvanceGuards and TestPolicyRefreshJournal isolate the fences. |
| Fix-10 reservation authority | ReserveLaunch calls the shared closed request validator before writing. Submitted root TicketUse has an empty Target and must match the actual retained ticket ceiling; the store assigns the issued child and consumes authority under the writer. Retained-life proof/cancellation guards and continuation cancellation guards are explicit. Reservations retain consumed ticket/proof or genuine starter identity plus level/role/driver. TestReservationAuthority checks those pins. |
| Fix-10 prepared binding | The store calculates the exact impending identity event ID/sequence/hash under its writer before shared helper_prepare validation, then compares it with the real atomic append. Agent bindings still require the matching bound plan/recovery and ready lane/turn/endpoint. New live identity kinds cannot omit or mismatch agent/worker. TestPreparedIdentityBytes isolates event/receipt corruption; the full shared launch fixture uses the production prepared-binding path. |
| Fix-10 emitter and natural completion | launch_plan is an explicit internal emitter. lane.check validates the actual retained exited/zero-survivor observation, authentic target/controller, life CAS, epoch, unchanged unrelated state and matching end/state events. The store supplies service event provenance and the actual final journal head. TestNaturalCompletionCommit and TestNaturalObservationFence exercise these gates. |
| Capture refusal approval | Default refusal remains disabled. An enabled protected exception must have its actual consumed D6 approval, matching application generation/manifest and actual application event. Current-policy checks preserve that provenance. TestCaptureRefusalD6Provenance includes distinct manifest/generation/event controls. This is not physical capture or a D6 ceremony measurement. |

These are source outcomes. Group A still requires the regression unit rerun,
deciding mutation reds/candidate greens, dedicated authenticator build, actual
administrator helper/validator composition and the installed serve gate.

## Group B

| Requested item | Current scope and remaining work |
| --- | --- |
| Durable read-session refresh | Store RefreshReadSession checks current durable session/enrollment, connection/configuration, revocation, revision and expiry; it caps idle expiry at the existing absolute bound. Transport callbacks occur before the writer lock. ReadAuthorityRefresher replaces only the same committed session revision; BindReadAuthority is one-use and local reads do not extend idle time. Failed transport refresh closes the connection. Component controls are authored; real identity/transport composition is unmeasured. |
| Causal revocation and close receipts | Store stamps/read-backs LaunchRevocation from the actual committed revoked identity and original event/cause. Server.InvalidateLaunch verifies that stored decision, blocks matching new admissions, closes registered lifetimes, and waits for their delivery completion before returning counts. Identity's RevokeLaunch coordinator, installed delivery races and deciding revocation controls still require completion/verification. This source is not an installed close guarantee. |
| Guidance ownership | Immutable candidate pages, one winner per life/logical turn, retained owner/cost/deadline, observer Acquired=false, bounded waits and expired-owner unavailable recovery are implemented in source. Completion uses claim CAS/epoch and actual turn/result. Scored or judgment-bearing completion remains typed not_implemented until measured judge provenance and complete coverage/cost joins exist. Fresh-task/epoch preflight still precedes existing-claim lookup and needs the contract's replay-order correction. Binding-context ownership/recovery tests do not accept full guidance. |
| Worker mapping | Store.WorkerBinding remains typed not_implemented. Protected helper allocation/boot, fixed WorkerLease consumption, stage/claim, installed worker record/endpoint and actual PeerFacts must be joined before a principal can be returned. Existing capture component fixtures still exercise the older capture_supervisor/unconsumed-lease path; they do not satisfy fix-11 mapping. |
| Materialization and worker outbox | Store.LaunchDataStage, service.MaterializationStage, AwaitMaterialization, WorkerInput and WorkerResult remain typed not_implemented. No stage/lease is guessed or allocated by label, and no held-storage/open-token, worker output or successful exit is fabricated. The helper registry, narrow worker plan, exact output acknowledgement, observed quiescence and restart joins remain required. |

## Administrator channel handoff

This is a separate private socket at AdminEnrollmentEndpoint.Socket. It uses
the existing bounded length-prefixed frame transport. Each connection carries
one closed JSON object and one response, followed by close:

```json
{"action":"begin","request":{"config":"example","ceremony_id":"id","principal_id":"id","expected_generation":0}}
```

The other action is complete, with request encoded as the exact
api.EnrollmentValidationRequest DTO. The response is either
`{"result": <typed DTO>}` or `{"error": <api.Error>}`; DTO result member names
follow their encoding/json definitions in the shared API. This endpoint accepts
no public RPC method, serialized Scope or InternalIntent. The installed root
helper client still needs to consume this private framing. Identity owns real
webauthn.create attestation and supplies the retained validated DTO, not a
service-authored crypto substitute. Parent cancellation closes accepted sockets.

## Static results and evidence

The environment was Darwin arm64, Go 1.26.5 and Python 3.13.11. The only project
interpreter operation was the authorized isolated py_compile command. No
product/test binary, runtime test, cloud machine or model request was started.

| Check | Observed result | What would fail it |
| --- | --- | --- |
| gofmt -w | Exit 0 on the retained owned Go-file list | A Go parse/format error |
| gofmt -l | Exit 0 and an empty output log | Any remaining path in output or nonzero exit |
| py_compile | Exit 1: nonexistent actor.py input, quoted above | Missing input or Python syntax error; this invocation proves no complete Python check |
| bash -n run.sh | Exit 0 | Shell syntax error |
| bash -n run-mutations.sh | Exit 0 | Shell syntax error |
| Three vet variants | Not run after the failed Python check | Compilation/vet diagnostics or an unavailable cache/toolchain |
| Mutation literal/anchor audit | Not run after the failed Python check | Duplicate/missing anchor, malformed inventory or a test-file edit |
| Unit/mutation/native/installed runs | Not run in this lane | The exact assertions and FAIL paths in MUTATIONS.md, followed by unchanged candidate controls |

The authored inventory contains 155 controls: the 98 existing IDs plus 57 new
controls, or 310 red/candidate pairs across the normal and faults variants and
ten final package/tag suites. The earlier enrollment-attestation control now
targets the deciding exact-byte comparison; the inventory assertion text tracks
the explicit production/tagged marker split. Every added refusal control names
its own leaf subtest. The two concurrency property controls name their whole
single test. Anchor uniqueness and deciding runtime behavior remain unverified.

External evidence is retained under the lane's evidence root in
`d4fix11-01c866a`: both briefs, integration handoffs, source revisions/archives,
phase snapshots, current diff/status/index records, static commands/logs/exits
and a final manifest. The first checkpoint archive command used an unsupported
tar option and failed; the corrected second checkpoint uses existing named
directories and succeeded. The Python failure and stopped validation are kept.
No tested binary exists for this static-only candidate.

The supervisor must review the candidate, authorize recovery of the failed
check invocation, execute the required Linux work, stage the resolved content
and conclude the open merge. This report grants no acceptance or deployment.

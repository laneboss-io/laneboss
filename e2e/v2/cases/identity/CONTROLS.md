# Package fixture and omission controls

Run 45 has 325 distinct executable package/test/edit controls after removing
two duplicate rows. `f11-read-expiry` is covered by `omit-session-idle`;
`omit-root-cgroup-check` is covered by `omit-dedicated-registration`. Their
canonical predicates, selected tests and diagnostics are unchanged. The old
rows remain in the retained initial source archive; no duplicate receives
separate runtime credit. A catalog regression rejects repeated control cases.

Run 37 preserved both merge-parent inventories: 307 serve2 and 326 lb-v2
controls became 327 IDs, including the two duplicate cases removed above;
104 and 105 fixture entries became 106.
The signed confirmation-generation regression and all G6/G9 worker controls
remain. The two moved worker guards retain their original selectors and
diagnostics. Authentication failure cleanup is anchored to Authenticate's
acquired-peer defer, so CurrentConnectionScope's separate cleanup does not
make its anchor ambiguous. The histories below describe the earlier inputs;
they do not claim that the merged runtime/control suites have executed.

The serve2 run-19 confirmation correction starts at 71ab8f48. It preserves all
273 prior controls and 96 fixture entries, adding one omission control and one
fixture entry for 274 controls and 97 fixtures (548 and 194 normal/faults rows).
The authorized cross-lane identity change advances StoredChallenge.Generation
with its consumed proposal; store's current-unused/next-revision CAS is intact.

omit-confirm-generation-advance removes only that increment and selects
TestConfirmGenerationFixture/fresh. Its required red diagnostic is exactly
"fixture check: confirmation did not advance the challenge revision". Require
the reached named failure before passing the unchanged candidate test. The
full fixture also separates the challenge revision from target, credential
and enrollment generations and checks immutable challenge facts. The real
SQLite TestChallengeGenerationCAS in the store package separately preserves
stale, jumping, already-used and immutable-fact refusal controls. See the
[serve confirmation trace](../serve/HUMAN-CONFIRM-GENERATION.md) for source
attribution and green17's installed acceptance requirements.

Both new tests compile in the applicable static vet matrix, including faults
and the dedicated authenticator build. Runtime red/candidate pass remains
pending on the authorized Linux machine; this Mac run executes no project test.

The G6/G9 identity round starts at b50be312. G6 adds the separate protected
worker permit consumer and real Linux descriptor validation; G9's existing
projection consumer remains unchanged. Confirmation now advances the consumed
challenge revision. All 306 prior IDs remain. request-worker-before-store follows
the moved wrong-kind refusal, and omit-worker-permit-gap follows the private
native-handoff dependency. Their selectors and diagnostics are unchanged.

Twenty controls and two fixtures give 326 controls and 105 fixtures, requiring
652 mutation rows and 210 fixture rows across normal/faults. Every new selected
path and filename is under 40 characters. The worker fixtures use actual memfds,
seals, descriptor flags and bytes; peer/registry/store metadata are controlled
projections. They do not establish a real installed bootstrap, helper gate or
process execution. No in-process materializer runs in identity. The dedicated
confirmation fixture signs actual assertion bytes and observes the exact
consumed revision plus proof/counter/evidence handoff at the store boundary.

| New control | Selected assertion | Required red diagnostic |
| --- | --- | --- |
| g6-worker-current | TestWorkerBind/current | fixture check: retained native worker handoff did not produce its exact permit: |
| g6-worker-request | TestWorkerBind/request | fixture check: want conflict, got success |
| g6-worker-input | TestWorkerBind/input | fixture check: want integrity, got success |
| g6-worker-endpoint | TestWorkerBind/endpoint | fixture check: want integrity, got success |
| g6-worker-seals | TestWorkerBind/seals | fixture check: want unauthenticated, got success |
| g6-worker-readonly | TestWorkerBind/readonly | fixture check: want unauthenticated, got success |
| g6-worker-argv | TestWorkerBind/argv | fixture check: want integrity, got success |
| g6-worker-claim | TestWorkerBind/claim | fixture check: want conflict, got success |
| g6-worker-grants | TestWorkerBind/grants | fixture check: want forbidden, got success |
| g6-worker-policy | TestWorkerBind/policy | fixture check: want conflict, got success |
| g6-worker-allocation | TestWorkerBind/allocation | fixture check: want containment_unknown, got success |
| g6-worker-cancel | TestWorkerBind/cancel | fixture check: want conflict, got success |
| g6-worker-drift | TestWorkerBind/drift | fixture check: want conflict, got success |
| g6-worker-native | TestWorkerBind/native | fixture check: want unauthenticated, got success |
| g6-worker-guard | TestWorkerBind/guard | fixture check: worker guard refusal was lost: |
| g6-worker-close | TestWorkerBind/close | fixture check: worker guard refusal was lost: |
| g6-worker-missing | TestWorkerBind/missing | fixture check: want not_implemented, got success |
| g6-worker-life | TestWorkerConsumerFixture/life-label | fixture check: want containment_unknown, got success |
| confirm-revision-1 | TestConfirmRevision/1 | fixture check: confirmation did not advance the consumed challenge revision |
| confirm-revision-41 | TestConfirmRevision/41 | fixture check: confirmation did not advance the consumed challenge revision |

The native-drift control omits both independently deciding post-checks. The guard
refusal control omits both authentication/check error decisions. Neither can
qualify by a compile/setup failure or by suppressing a failure in the runner.
Unknown or absent native producer state remains a typed refusal, not an empty
permit. Check/Close failures must propagate and return no authority. Both
revision controls use the same omission with their own reached signed assertions.

Run all fixtures and controls on the authorized Linux box, requiring each named
red before the unchanged candidate pass. Include existing G9 projection and all
prior controls, full units and authenticator builds. Compile, setup, skip, panic,
timeout and collection failures cannot count as red. Mac work is static only.
Exact current source locations and remaining admin/service/native/assembly
requests are recorded in contract-gaps.md and the authoring report. Historical
G1/G4 and attestation handoffs follow.

G1/G4 round b is the authorized continuation of the stopped efd9e9b3 candidate.
omit-bound-authority-id now matches the complete intended BindReadAuthority call,
preserving its ID, selector, diagnostic and deliberate connection-ID corruption.
It is not removed or relaxed. All other 272 baseline controls are unchanged.

Static mutant compilation found that the first g1-expired edit deleted the only
use of idle. The corrected edit uses false && on that same deadline comparison,
so it omits exactly the same decision while remaining compilable. Its ID,
selector and expected diagnostic are unchanged. The failed bytes/output are
retained separately; the compile failure never qualifies as a runtime red.

The common CLI now implements --session-proof for root start/adopt, calls the
actual identity.self on the same client after human.session, and leaves the
spawn ticket body and nil envelope proof intact. The two exact CLI production
files are allowed as client mutations only; other paths/package/kind combinations
remain refused. The Python harness regression checks that boundary. Assembly
wires only the protected store's capability; current store/dispatcher/lifecycle
stubs and missing feature validators remain explicit requests in contract-gaps.md.

Thirteen round-b controls and three fixtures supplement the twenty/four from
the first G1/G4 candidate. Totals are 306 controls and 103 fixtures, requiring
612 mutation rows and 206 fixture rows across normal/faults. New selectors and
file names stay under 40 characters. The event-origin control restores the
reported scope.Source bug and must fail the actual transaction's positive test.

| Round-b control | Selected assertion | Required red diagnostic |
| --- | --- | --- |
| g1-event-origin | TestHumanEventSource | fixture check: service-origin human event failed: |
| g4-cli-start | TestSpawnPrelude/start | fixture check: root spawn did not use its live session prelude: |
| g4-cli-adopt | TestSpawnPrelude/adopt | fixture check: root spawn did not use its live session prelude: |
| g4-cli-receipt | TestSpawnPrelude/receipt-only | fixture check: refused prelude reached root spawn |
| g4-cli-foreign | TestSpawnPrelude/foreign | fixture check: refused prelude reached root spawn |
| g4-cli-wrong-proof | TestSpawnPrelude/wrong-proof | fixture check: refused prelude reached root spawn |
| g4-cli-ambiguous | TestSpawnPrelude/ambiguous | fixture check: session helper accepted an ambiguous or foreign operation |
| g4-cli-method | TestSpawnPrelude/method | fixture check: session helper accepted an ambiguous or foreign operation |
| g4-option-help | TestSessionOption/help | fixture check: root help omits the session proof route |
| g4-option-duplicate | TestSessionOption/duplicate | fixture check: invalid session option was not refused before dispatch: |
| g4-option-empty | TestSessionOption/empty | fixture check: invalid session option was not refused before dispatch: |
| g4-option-ambiguous | TestSessionOption/ambiguous | fixture check: invalid session option was not refused before dispatch: |
| g4-option-method | TestSessionOption/method | fixture check: invalid session option was not refused before dispatch: |

Each expected failure must reach its named assertion and then pass unchanged on
Linux. A missing validator, unimplemented service/store, compile/setup failure,
skip, panic, timeout or collection failure is not red qualification. Mac results
remain static only. The run-18 failed anchor evidence is retained separately;
round-b results must qualify the complete final source and all exact edits again.
The earlier G1/G4 and attestation handoffs follow for historical context.

The installed G1/G4 round starts at efd9e9b3. All 273 prior controls and
96 fixture entries remain unchanged. Twenty controls and four fixtures give
293 controls and 100 fixtures, requiring 586 mutation rows and 200 fixture rows
across Linux normal/faults. Every new selected path is under 40 characters.

G1 uses a protected committed-session read-back and private replay finalizer.
The private port is supplied at construction and resolves the verified request,
not a caller session label. Public ReadSession still requires actual connection
read authority. The regression restores that public read before activation to
recreate the reported cycle. Negative controls separately omit the deciding
request / bytes / revision / credential / proof / presence / deadline guard, refuse false
transport bind success, preserve private-read errors and require a capability
before commit. Exact same-connection replay must reuse its original initial
authority without another bind; foreign replay must never reach binding.

G4 selects a same-socket session prelude using a separate session proof. The
identity gate requires current read authority for human spawn, refreshes it
through the existing CAS path, and retains the ban on spawn envelope proofs.
Its fixture observes no launch transaction or ticket consumption. The requested
common CLI option and service/lifecycle wiring are in contract-gaps.md; no
existing --proof substitution is credited as a working root prelude.

TestNativeSession sends real SCM_CREDENTIALS frames across a Linux Unix socket,
uses the native peer verifier, creates a real challenge and verifies an ECDSA
assertion before session creation and the first authorized public read. Its
store is explicitly a controlled in-memory projection of those actual handoffs.
It proves neither installed durable persistence nor hardware presence. Native
stale/foreign controls assert zero binding attempts before the refusal; the
transport's independent refusal cannot mask a missing identity check.

| New control | Selected assertion | Required red diagnostic |
| --- | --- | --- |
| g1-private-read | TestSessionFinalize/current | fixture check: private session finalization failed: |
| g1-stale | TestSessionFinalize/stale | fixture check: want unauthenticated, got success |
| g1-foreign | TestSessionFinalize/foreign | fixture check: invalid finalization reached connection binding |
| g1-credential | TestSessionFinalize/credential | fixture check: want unauthenticated, got success |
| g1-proof | TestSessionFinalize/proof | fixture check: want unauthenticated, got success |
| g1-receipt | TestSessionFinalize/receipt | fixture check: want integrity, got success |
| g1-bytes | TestSessionFinalize/bytes | fixture check: want integrity, got success |
| g1-expired | TestSessionFinalize/expired | fixture check: want unauthenticated, got success |
| g1-presence | TestSessionFinalize/presence | fixture check: want unauthenticated, got success |
| g1-read-fail | TestSessionFinalize/read-fail | fixture check: durable receipt masked private finalization refusal |
| g1-capability | TestSessionFinalize/missing | fixture check: session committed without private read-back capability |
| g1-retained | TestSessionFinalize/unretained | fixture check: want integrity, got success |
| g1-replay-same | TestSessionReplay/same | fixture check: exact finalization replay replaced or lost authority: |
| g1-replay-foreign | TestSessionReplay/foreign | fixture check: foreign socket reached committed-session activation |
| g4-current | TestRootPrelude/current | fixture check: root prelude did not authorize read-only preflight: |
| g4-ticket-only | TestRootPrelude/ticket-only | fixture check: want unauthenticated, got success |
| g4-envelope | TestRootPrelude/envelope | fixture check: want forbidden, got success |
| g1-native-current | TestNativeSession/current | fixture check: native same-socket session finalization failed: |
| g1-native-stale | TestNativeSession/stale | fixture check: native stale session reached transport binding |
| g1-native-foreign | TestNativeSession/foreign | fixture check: native foreign session reached transport binding |

All named red assertions must be reached before the exact unchanged candidate
passes on the authorized Linux box. Compilation/setup errors, skips, panic,
timeout or collection failures never qualify. Run the full normal/faults
fixture/control matrices and dedicated-authenticator units, plus installed G1/G4
canaries after composition. Only static checks run on this Mac. The following
attestation and earlier handoffs are historical context.

The R131 compatibility follow-up starts at a7b4aa6b and addresses review items
Medium 1, Low 2 and Low 3. All 267 prior control entries and all 96 fixture
entries are unchanged. Six new controls give 273 controls and 96 fixtures,
requiring 546 mutation rows and 192 fixture rows across normal/faults. The new
selected paths are all shorter than 40 characters.

TestAttestation/no-key-usage uses a newly signed synthetic leaf with KeyUsage 0
and independently parses the DER to require that the Key Usage extension is
absent. It must enroll through the real chain and signature verifier while
preserving the credential key, counter, exact evidence and ordinary presence.
The fixture's ordinary digitalSignature template is unchanged. Its paired
no-key-sig and no-key-root cases also have no Key Usage; they respectively
tamper the signed statement or use an unpinned synthetic CA and require
unauthenticated plus an empty enrollment result. Thus omitting verification
cannot satisfy the new acceptance regression. A present keyEncipherment-only
usage is still refused by the existing common leaf check.

| New control | Selected TestAttestation assertion | Required red diagnostic |
| --- | --- | --- |
| attest-no-key-usage | no-key-usage: absent Key Usage is accepted | fixture check: valid direct attestation was refused or marked simulated: |
| attest-no-key-sig | no-key-sig: signature remains mandatory without Key Usage | fixture check: want unauthenticated, got success |
| attest-no-key-root | no-key-root: pinned trust remains mandatory without Key Usage | fixture check: want unauthenticated, got success |
| attest-key-usage | bad-key-usage: incompatible present usage refuses | fixture check: want unauthenticated, got success |
| attest-u2f-aaguid | u2f-aaguid: model certificate AAGUID is not compared to zero data AAGUID | fixture check: valid direct attestation was refused or marked simulated: |
| attest-unsupported | unsupported: an apple-shaped statement without sig is unsupported | fixture check: want unsupported, got invalid_request |

The first control restores the overstrict production clause, and the U2F and
unsupported controls restore their reported incompatibilities. The other three
omit the exact deciding usage/signature/trust guard. Every new test has its own
named assertion and control, even where a source omission is shared with a
prior control. New selectors are part of the existing attestation-direct fixture.
The six new source variants must compile in each supported mode and must reach
their exact named red assertion before the unchanged candidate passes on Linux.
The prior attbox green and reviewer approval were reported by the supervisor
for a7b4aa6b; they do not qualify this new source. Static checks on this Mac are
not runtime red/pass or hardware evidence. Keep normal/faults fixture/control
matrices and dedicated-authenticator units as qualification gates. Store
enrollment stubs, protected install trust and required UV/direct producer options
are routed in internal/v2/identity/contract-gaps.md. The owner performs his real
key enrollment at R131 final acceptance.

The initial attestation handoff follows for historical context.

The R131 attestation round starts at 20fc030b. It retains all 255 control IDs
and 93 fixture entries, adds twelve controls and three fixtures, and requires
534 mutation rows and 192 fixture rows across normal and `laneboss_faults`.
The only prior edit retargeted is `f11-enrollment-signature`: the signature
verifier moved from enrollment.go to attestation.go. Its selector and expected
diagnostic are unchanged. All new selected paths are shorter than 40 characters.

The new synthetic-CA fixtures exercise the actual enrollment verifier. Valid
packed and U2F cases include distinct attestation/credential keys, and require
the original credential key, counter, exact request evidence and format without
simulated presence. Negative cases require the named refusal and an empty
EnrollmentInstall. Constructor cases require immutable copied trust and refusal
of malformed roots/allowlists/context. None of these synthetic keys is hardware
evidence or part of a production build.

| Control | Selected TestAttestation assertion | Required red diagnostic |
| --- | --- | --- |
| attest-none | none: generic empty none is forbidden | fixture check: want forbidden, got success |
| attest-packed | packed: trusted certificate registration succeeds | fixture check: valid direct attestation was refused or marked simulated: |
| attest-u2f | u2f: trusted U2F registration succeeds | fixture check: valid direct attestation was refused or marked simulated: |
| attest-allowlist | unknown: unknown AAGUID is forbidden | fixture check: want forbidden, got success |
| attest-chain | untrusted: request-supplied CA is not a root | fixture check: want unauthenticated, got success |
| attest-subject | subject: malformed packed subject refuses | fixture check: want unauthenticated, got success |
| attest-cert-aaguid | cert-aaguid: certificate/data AAGUID differ | fixture check: want unauthenticated, got success |
| attest-u2f-signature | u2f-signature: changed statement signature refuses | fixture check: want unauthenticated, got success |
| attest-config | config: trust belongs to this configuration | fixture check: want forbidden, got success |
| attest-installation | installation: trust belongs to this generation | fixture check: want forbidden, got success |
| attest-missing-roots | missing-roots: trust is mandatory | fixture check: want forbidden, got success |
| attest-no-self | self: ordinary self-attestation refuses | fixture check: want forbidden, got success |

The missing-roots mutation omits both the installed-policy preflight and chain
verification, because either independently prevents enrollment without trust.
The U2F and retained packed-signature controls share the same source omission
but select their own signed-payload assertions. There are thirteen affected
catalog entries and twelve distinct mutant sources. Setup/compile failures,
unreached assertions, skips, panic, timeout and collection failures never qualify
as red. Each unchanged candidate assertion must pass after its named reached red.

On the authorized Linux box run all fixtures and all controls in both normal and
faults modes with the existing run-controls.sh interface and fresh physical
evidence roots. Also run package units with `laneboss_e2e_authenticator` and with
`laneboss_e2e_authenticator,laneboss_faults`: TestTaggedAttestation requires the
exact marked none/self path to remain simulated without ordinary roots, while
TestAttestation/none still forbids generic none. TestProdAttestation in normal
and faults requires production refusal of the marked paths. Include
TestAttestationPolicy in the Linux regressions. Retain the exact archived
candidate tests for before/after qualification; new helpers cannot be overlaid
onto old production and a resulting compile error called a red assertion.

This Mac round permits gofmt, vet, byte-compilation and shell syntax/static
catalog checks only. No runtime red, candidate pass or real hardware result is
claimed here. Protected install trust wiring remains requested in
internal/v2/identity/contract-gaps.md, and the owner must perform R131's final
real-key enrollment himself.

The earlier fix-12 binding handoff follows for historical context.

Fix-12 round 2 repairs TestProjGate/binding on e882a8ab. Changing only
Prepared.ProcessGeneration made the request disagree with its own LaunchRecord,
so the shape preflight correctly returned invalid_request before the intended
durable-binding comparison. The fixture now changes both process generations,
recomputes the foreign record digest and requires both launch-record and binding
preflights to pass. It still requires conflict, an empty returned projection,
zero projection-store reads and unchanged protected binding bytes.

The new f12-binding-exact control omits only the durable/caller binding comparison.
Its selected TestProjGate/binding must fail with exactly
`fixture check: want conflict, got success`, then pass unchanged on the candidate.
It cannot count a preflight/setup failure as red. Production error codes and
validation are unchanged. All 254 prior control IDs and all 93 fixture entries
remain; the totals are 255 controls and 93 fixtures (510 and 186 normal/faults
rows). New selected paths remain under 40 characters.

Run the focused control first on the authorized Linux box from the committed
candidate matching the archived source, then the existing complete matrices:

```sh
set -eu
sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision "$(git rev-parse HEAD)" \
  --work-root  / test / evidence / lb-v2-identity-fix12-binding-r2 \
  --mode mutations --mutation f12-binding-exact --tags both
```

The fix-12 candidate on 175cab85 keeps every prior 235 control ID and 84 fixture
entry, adds nineteen controls and nine fixtures, and requires 508 mutation rows
and 186 fixture rows across normal/faults. Native projection authorization reads
the protected record and current effect/life/grants/policy, compares the complete
request, requires the real private-channel/native-executable verifier and checks
fresh source/fence state after that call. The current ordinary native verifier
does not supply CredentialProjectionPeers; the production path stays explicitly
closed until its native owner implements that dependency. TestProjAuth models
the required producer and its errors without claiming native authentication.

TestProjGate checks the actual API held-receipt gate and a final protected record
read. TestProjPermit requires it before the real BindLaunch permit. TestProjWorker
uses the protected selected worker credentials and rejects a caller replacement
or a materialize worker. TestProjRecord and TestProjState isolate deciding
identity guards from independent native/API checks. TestRegistrationID checks
reserved software-ID normalization without dropping any presence/provenance
field; the existing dedicated tagged signed flow checks the real enrollment.
Production-marked refusal remains active. The shared TestTurnEvent fixture checks
the fix-12 common logical_turn_id envelope; identity has no lane.turn/session
producer and the frozen Session DTO has no such member.

The four existing selectors f14-sealed-policy-current, omit-plan-epoch,
omit-plan-current-grants and omit-grant-content now use TestPlanFence. Their edits
and diagnostics are unchanged, and their original full permit fixtures still
run. The complete original grant, event, plan and read-session assertions remain.
All new selected test paths are under 40 characters. No mutation edits shared API
or any native producer outside this lane's ownership.

Run on the authorized Linux box from the supervisor-committed source matching
the archived bytes. Both roots must be new and physically resolved:

```sh
set -eu
sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision "$(git rev-parse HEAD)" \
  --work-root  / test / evidence / lb-v2-identity-fix12-fixtures \
  --mode fixtures --tags both
sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision "$(git rev-parse HEAD)" \
  --work-root  / test / evidence / lb-v2-identity-fix12-controls \
  --mode mutations --mutation all --tags both
go test -count=1 -tags laneboss_e2e_authenticator ./internal/v2/identity
go test -count=1 -tags laneboss_e2e_authenticator,laneboss_faults ./internal/v2/identity
```

Each control must compile, reach its selected assertion with the exact intended
diagnostic, then pass the identical candidate assertion. Keep actual binary
hashes and process quiescence. Static vet runs normal, faults, Darwin and both
dedicated-authenticator variants; it proves no runtime red or native handoff.
Historical before catalogs remain tied to their archived source generations.
Do not overlay current new-helper tests on those older implementations and
count their compile failures as red results.

The d4fix15 follow-up starts from e3a5d8c1 and retains all 235 controls and
84 fixtures. The endpoint omission reaches BindReadAuthority with the stored
foreign endpoint generation. Its independent transport check still returns
unauthenticated, so the d4fix14 fixture reaches its activation-attempt assertion
instead of the endpoint control's older expected nil-error assertion.

Invalid receipts now check zero activation attempts before checking the returned
error. The deciding assertion names the actual receipt case and prints observed
attempt/success counters. Each control requires the complete case-specific
diagnostic, including both counters; a generic activation or error message does
not qualify. Refusal-code, empty-session and zero-success assertions remain,
as do the current receipt's one-attempt/one-success and read-authority checks.
All six controls selecting TestSessionReceiptBindingFixture keep their IDs,
selectors and exact single-site production edits. Static tracing gives these
expected red paths in both normal and laneboss_faults builds:

| Control | Named case | Expected deciding failure |
| --- | --- | --- |
| omit-session-receipt-principal | principal | Activation assertion: attempts=1 binds=1; the fixture transport does not validate principal. |
| omit-session-receipt-connection | connection | Activation assertion: attempts=1 binds=0; transport independently rejects the connection ID. |
| omit-session-receipt-endpoint | endpoint | Activation assertion: attempts=1 binds=0; transport independently rejects the endpoint generation. |
| stale-session-activation-clock | expired | Activation assertion: attempts=1 binds=1; stale pre-commit time permits the expired receipt to reach transport. |
| omit-session-activation | current | Existing positive binding assertion: attempts=0 binds=0 after the bind is omitted. |
| omit-bound-authority-id | current | Existing positive binding assertion: attempts=1 binds=0 after transport rejects an empty connection ID. |

These are static traces, not observed candidate runtime kills. On the authorized
Linux box, use the committed candidate matching the archived bytes and qualify
all six controls in both modes, each with a new physical evidence root:

```sh
set -eu
for receipt_control in \
  omit-session-receipt-principal omit-session-receipt-connection \
  omit-session-receipt-endpoint stale-session-activation-clock \
  omit-session-activation omit-bound-authority-id
do
  sh e2e/v2/cases/identity/run-controls.sh \
    --source /test/candidate --revision "$(git rev-parse HEAD)" \
    --work-root " / test / evidence / lb-v2-identity-receipt-f15-$receipt_control" \
    --mode mutations --mutation "$receipt_control" --tags both
done
```

Every red must reach its exact diagnostic before the unchanged candidate test
passes, with distinct binary hashes and process quiescence. The full 470
mutation rows and 168 fixture rows remain qualification gates. No production
validation or harness failure matching is changed by this follow-up.

The d4fix14 follow-up retains all 225 prior control IDs and 79 fixture IDs,
adds ten policy controls and five fixtures, and requires 470 mutation rows and
168 fixture rows across normal and laneboss_faults. The policy fixture first
authenticates a running lane at generation 3, advances approved D6 policy to 4,
and checks current authorization before and after a contract-validated coordinator
projection update. Launch, issued grants and endpoint bytes must stay unchanged.
Restoring any old scope/record/projection/current-policy equality reaches a named
failure; future or missing generations and revoked/changed grants still refuse.
Human and worker generation drift requires conflict and a successful reload on
the same connection; identity drift still requires unauthenticated. Separate
omissions prove that generation checks cannot simply be dropped.

New permits resolve a current scope before running-life validation and call
ValidateLaunchPolicyCurrent at their final plan-authority check.
The fixture uses registered capture so the capture-refusal validator cannot hide
an omitted launch-policy check. It requires conflict and no permit after D6,
including when the coordinator already advanced the lane projection.
omit-policy-generation now targets the current-policy check on IdentitySelf's
projection, preserving its original future-scope case and diagnostic.
omit-current-policy isolates the issued-grant consumer's future-policy refusal;
independent currentLaunch bounds cannot conceal that omission.

The matched fix14-before-cases.json nominates a522d51b and five assertions for
ten base/candidate rows. The prior before catalogs remain unchanged. On the
authorized Linux box, qualify those reached red assertions before candidate
passes, then the focused receipt control and complete matrices:

```sh
python3 e2e/v2/cases/identity/before.py \
  --base-source /test/base --source /test/candidate \
  --base-revision a522d51b --revision "$(git rev-parse HEAD)" \
  --case-plan fix14-before-cases.json \
  --work-root  / test / evidence / lb-v2-identity-before-f14 --tags both
```

In d4fix13,
read-session activation began projecting the stored connection ID through
ReadAuthorityFromSession. Removing only the receipt connection comparison
therefore still returned unauthenticated from the transport's independent
connection check, hiding the missing receipt check from its named test.

TestSessionReceiptBindingFixture now counts every transport activation attempt,
including refused attempts. A valid receipt must make exactly one attempt and
bind successfully; each invalid receipt must make none, return unauthenticated,
return no session and confer no authority. The unchanged single-site
omit-session-receipt-connection edit reaches the activation assertion, whose
common d4fix14 diagnostic is made case-specific by d4fix15 above.
Both production checks remain intact. This measures receipt validation before
the transport handoff; it does not claim the transport accepted foreign authority.

Run the focused control first on the authorized Linux box, from the committed
candidate whose source bytes match the handoff archive:

```sh
sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision "$(git rev-parse HEAD)" \
  --work-root  / test / evidence / lb-v2-identity-receipt-f14 \
  --mode mutations --mutation omit-session-receipt-connection --tags both
```

Require the named red assertion and the unmodified candidate pass in both
normal and laneboss_faults modes, with the harness's binary and process checks.
The full 470 mutation rows and 168 fixture rows remain Linux qualification
gates. The Mac follow-up performs static checks only and claims no runtime kill.

The prior d4fix13 candidate adopts shared fix 11 on f5f6ba9a. All 192 prior
control IDs/diagnostics and 60 fixture IDs remain; 33 consumer controls and 19
fixtures give 225 controls and 79 fixtures. The normal/faults matrix requires
450 runtime mutation rows and 158 fixture rows. Six added fixtures execute the
shared API contracts read-only; only owned identity/peer/identity-CLI production
sources remain mutable. No API mutation target is allowed.

The new f11-* rows cover consumed create challenge/evidence, real signed
registration/COSE/CBOR, build/marker policy and presence propagation, store CAS
and same-connection read refresh, causal revocation/counts, and protected worker
mapping/claim/operation/frame checks. The inventory/baseline and worker input/
result API fixtures do not implement their durable/native producer dependencies.
Worker pre-gate BindLaunch still lacks a reviewed protected worker handoff;
the connection and private operation paths use the actual WorkerBinding port.

Nine existing session controls now isolate the same early guard through
TestReadSessionPreflightFixture. The original TestReadSessionFixture still runs
the entire authorization/refresh path with every assertion preserved. The two
activation edits follow ReadAuthorityFromSession. Absolute/connection refresh
controls omit both independent consumer validator calls, with controlled store/
transport projections allowing the identity checks to decide. The record revoke
control requires zero transport calls for an unrevoked but correctly hashed
record; later validation cannot conceal incorrect invalidation order. Production
credential refusal includes revoked marked inventory. The default/faults controls
never enable the dedicated authenticator build.

Current before qualification uses the matched fix-11 catalog. The unchanged
historical catalogs remain separate; their older API generations cannot compile
the current fixture DTOs. Run from /test/candidate on the authorized Linux box:

```sh
python3 e2e/v2/cases/identity/before.py \
  --base-source /test/base --source /test/candidate \
  --base-revision f5f6ba9a --revision f5f6ba9a \
  --case-plan fix11-before-cases.json \
  --work-root  / test / evidence / lb-v2-identity-before-f13 --tags both

sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision f5f6ba9a \
  --work-root  / test / evidence / lb-v2-identity-fixtures-f13 \
  --mode fixtures --tags both

sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision f5f6ba9a \
  --work-root  / test / evidence / lb-v2-identity-controls-f13 \
  --mode mutations --mutation all --tags both

go test -count=1 -tags laneboss_e2e_authenticator ./internal/v2/identity
go test -count=1 -tags laneboss_e2e_authenticator,laneboss_faults ./internal/v2/identity
```

Use the actual committed candidate revision once the supervisor commits these
exact archived bytes. The 20 before/candidate rows still require reached named
assertions, never setup/compile/skip/panic failures. The new tagged fixture uses
real create/get signatures and observed store handoffs; it establishes presence
simulation provenance only. Production build refusal, atomic enrollment/use,
real idle-refresh races, transport close completion, native worker bootstrap and
installed serve acceptance remain distinct Linux gates. Mac static checks run
no project interpreter, test or executable binary.

The following d4fix12 and earlier notes are retained as historical context.

The current d4fix12 follow-up starts from fc1599f0 and keeps shared draft.4
fix 10. Shared fix 11 is outside this round. The supervisor reports green
units and approved Fable review for the preceding candidate, plus passing
before/harness stages on redbox5. The complete fixture/control stages stopped
at CLI compilation setup; their partial rows are not a full-suite pass.

Exact static materialization reproduced both CLI failures in both tag modes:
commands_guidance.go imports internal/jsontext, which the reduced INPUTS list
did not retain. The fixture snapshot and the require-borrowed-cli-client red
snapshot both lacked that local package. Retaining it exposed the next omitted
package, internal/typesafe, imported by judge/audit.go. The partial-fix check
stopped with that second diagnostic. INPUTS now includes both local packages.
Production CLI code and the require-borrowed-cli-client edit are unchanged.
test_cli_snapshot_retains_jsontext and test_cli_snapshot_retains_typesafe check
the actual dependency bytes, digest, mode and copied inventory. Removing either
input must fail its named assertion before the same reporter test passes on the
candidate, on Linux only.

The worker dependency gate now follows Store.LaunchBinding and uses the stored
record's Kind and Actor.Kind. Request validation still runs first. The existing
worker fixture stores a worker tuple while supplying an independently valid
agent request, so a request label cannot select the gap. A second fixture
requires invalid_request for worker labels over an agent binding. Two new
controls restore request-keyed and early request gating. All prior 190 control
IDs/assertions and 59 fixture IDs remain: there are now 192 controls and 60
fixtures, requiring 384 mutation rows and 120 fixture rows across both tags.

The fix10-before-cases.json catalog keeps all 10 IDs and the same 9f7b5ad0 base.
Its worker dependency row now expects the base's integrity diagnostic: the
updated fixture has an agent request and a stored worker without agent Recovery,
so the old base reaches retainedLaunchPlan instead of the request shape guard.
The candidate must return not_implemented and no permit. This diagnostic update
does not turn a setup or compile failure into a red kill. Both local packages
exist in the nominated base and are retained from that base's own bytes.

On the authorized Linux box, first run the reporter regression against the
retained old INPUTS list in a disposable copy, then the unchanged candidate test.
Next run the full harness and these focused controls before the complete matrix:

```sh
sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision fc1599f0 \
  --work-root /test/evidence/lb-v2-identity-cli-f12 \
  --mode mutations --mutation require-borrowed-cli-client --tags both

sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision fc1599f0 \
  --work-root  / test / evidence / lb-v2-identity-worker-f12 \
  --mode mutations --mutation request-keyed-worker-gate --tags both

sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision fc1599f0 \
  --work-root  / test / evidence / lb-v2-identity-worker-request-f12 \
  --mode mutations --mutation request-worker-before-store --tags both
```

Use the actual candidate revision after the supervisor commits the exact bytes.
Retain all failing setup evidence and require named reached red assertions,
unchanged-candidate passes, distinct binaries and process quiescence. Static vet
must target the actual reduced fixture and mutated source copies; a whole-tree
vet pass alone cannot show that their dependency closure is complete.

The following d4fix11 details are retained as historical context.

The current d4fix11 candidate adopts shared draft.4 fix 10 at 9f7b5ad0. All
172 prior mutation IDs and 53 fixture IDs remain, with 18 controls and six
fixtures added for 190 controls and 59 fixtures. The supervisor reports the
prior candidate's 344/344 controls killed; that is received historical evidence
and does not qualify the current 380 mutation rows or 118 fixture rows.

The new pin/authority fixtures execute identity's real retained-plan consumer.
Role/level cases keep a correctly hashed record while the stored reservation
keeps its original pins. Authority and driver omissions disable both shared
validator calls because either one independently rejects that invalid stored
plan. These controlled source copies never modify shared API validation.
Other controls omit current capture-policy, event-actor or agent-kind checks,
restore nil-sensitive grant comparison, or remove the resource projection copy.
Nonempty grant content changes must still refuse. The closed worker-permit
row establishes the dependency refusal only.

Current base/candidate qualification uses the added matched-contract catalog:

```sh
python3 e2e/v2/cases/identity/before.py \
  --base-source /test/base --source /test/candidate \
  --base-revision 9f7b5ad0 --revision 9f7b5ad0 \
  --case-plan fix10-before-cases.json \
  --work-root  / test / evidence / lb-v2-identity-before-f11 --tags both

sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision 9f7b5ad0 \
  --work-root  / test / evidence / lb-v2-identity-fixtures-f11 \
  --mode fixtures --tags both

sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision 9f7b5ad0 \
  --work-root  / test / evidence / lb-v2-identity-controls-f11 \
  --mode mutations --mutation all --tags both
```

Run from the candidate source and use its actual revision after a supervisor
commit. The uncommitted handoff is based on 9f7b5ad0 and identified by exact
archive/manifest hashes. Sources must be unchanged, roots new and physical,
and all 20 base/candidate rows must reach their named assertion before passing
on the candidate. Pin/authority tests already rejected by shared fix 10 use
omission controls instead of claiming a before-change failure on that base.
The unchanged historical before-cases.json selects 84ae053, whose API cannot
compile current fix-10 test DTO fields; use its separately retained historical
results and never silently substitute shared API bytes. No project test,
binary build or interpreter run is authorized on the authoring Mac.

These are supporting checks. The current round is accepted only by the
installed serve base/candidate E2E owned by lb-v2-serve. No fixture result,
identity scenario result or local static check completes that gate.

These commands run only on the authorized disposable Ubuntu 24.04 box. They
build and execute project tests. Do not run them on the authoring Mac. Python
3.12, Go 1.26, socket-bound pidfds, host procfs and unified cgroup v2 are
required. No agent/model request, login, enrolled private key or paid service
is needed. The run-2 brief explicitly authorizes this script to change one
mutation at a time in a disposable source copy. No input checkout, Git index,
shared contract, other branch or real configuration is written.

First run the reporter's own unit tests. Their synthetic event streams test
classification only and are never product/identity acceptance evidence:

```sh
python3 -m unittest discover \
  -s e2e/v2/cases/identity -p 'test_*.py'
```

Run the actual package fixtures in both tag modes:

```sh
sh e2e/v2/cases/identity/run-controls.sh \
  --source "$PWD" --revision "$(git rev-parse HEAD)" \
  --work-root /tmp/lb-v2-identity-fixtures \
  --mode fixtures --tags both
```

Run every named omission in both tag modes:

```sh
sh e2e/v2/cases/identity/run-controls.sh \
  --source "$PWD" --revision "$(git rev-parse HEAD)" \
  --work-root /tmp/lb-v2-identity-mutations \
  --mode mutations --mutation all --tags both
```

One independently reproducible control has the same entry point:

```sh
sh e2e/v2/cases/identity/run-controls.sh \
  --source "$PWD" --revision "$(git rev-parse HEAD)" \
  --work-root /tmp/lb-v2-identity-one-origin \
  --mode mutations --mutation omit-origin --tags normal
```

Each work root must be new, physically resolved, outside the supplied source,
and carry `lb-v2-identity-`. An existing directory is refused and retained.
The script retains the exact go.mod/go.sum, internal/v2 tree, release identity,
protocol and credential-text dependencies, and this case folder. The extra
dependencies let the CLI fixture compile its real shared client/assembly path.
Native composition remains a separate package with only API/identity/Linux
peer production dependencies. The snapshot
rejects linked or special source files and excludes Python bytecode caches.
It never copies HOME or credentials and never lists environment values.

The byte replacement anchors, named rule, focused test, expected assertion
diagnostic and mutation kind are all in `mutations.json`. A missing or repeated
anchor fails the control. Production Go files in the two owned packages can
be mutated. The exact owned commands_identity.go file is additionally allowed
only for the cli package's client controls. No other CLI source is mutable.
The sole fixture-code exception is `descriptor_linux_test.go`,
which contains the transfer decoder and no Test/Example/Fuzz entry points.
Only `fixture-helper` controls may target it, and adding a test entry point
causes refusal. Test assertions in the separate checks file remain immutable.
The normal code has no mutation-ID
branch or environment-selected bypass. Unsafe omissions exist only in the
retained red source copies and their deliberately broken test binaries.

For each selected mutation the runner:

1. Copies and hashes the input source, applies exactly the declared edit, and
   independently checks that no other source/test file changed.
2. Builds a retained test binary with `go test -c`. A compile failure stops;
   it never kills a mutation.
3. Runs the exact focused test through test2json. It requires that test's run
   and fail events, exit 1 and its declared assertion diagnostic. A skip,
   setup/cleanup failure, panic, unrelated failing test, wrong diagnostic,
   timeout or missing test fails the runner.
4. Runs the identical test source against the unchanged candidate, after the
   red failure. Candidate exit 0, a matching pass event, no failed tests and
   no skips are required. Only then is the mutation marked `killed`.
5. Verifies distinct red/candidate binary hashes and unchanged source bytes.
   It retains every phase's inputs, binaries, commands, exits and outputs.

`--tags both` repeats those steps with normal compilation and with
`laneboss_faults`; tags do not choose the mutation. Green package binaries may
be reused, but every selected test executes again after its own red control.
No test-result cache substitutes for a run of a retained binary.

`report.json` has schema `laneboss.identity-controls.v1` and scope
`package-fixture`. Exit 0 requires every selected row to finish, all expected
red failures and subsequent green passes, and independent owned-process
quiescence. The report names the actual failed tests. Raw events and argv are
kept in phase files, with hashes/byte counts. Source archives, exact test
binaries and source manifests are retained alongside them. The runner becomes
a Linux subreaper and stops unexpected owned descendants only by their pidfd;
any leftover descendant makes the control fail, even if it is then collected.
No source copies or evidence are deleted. Copy back, verify and archive each
phase before the supervising operator collects the test machine.

The fix-10 stdout failure row includes stage, exception type/message, relevant
path, command argv and operation. A manifest-validation failure names the
selected manifest and the runner invocation; a failed subprocess names its
actual argv. The same fields remain in report.json. Diagnostics do not convert
a setup failure into a kill, skip a control or relax an exact-copy check.

The earlier mutation snapshot failure was selection validation: the literal
lane.start component of omit-human-root-endpoint was rejected by a regex that
allowed no dots. Fixtures had no dotted components. Literal dotted components
are now accepted and each component still passes through re.escape before
test2json. Regex/path metacharacters and dot-only components remain refused.
No Git lookup is used by controls.py; an archive needs its explicit revision:

```sh
sh e2e/v2/cases/identity/run-controls.sh \
  --source "$HOME/src" --revision ccd2470 \
  --work-root "$HOME/lb-v2-identity-controls-f10" \
  --mode mutations --mutation all --tags both
```

Use a new work root and the actual candidate revision after the supervisor
commits it. Preserve the prior failed root. All 172 edits must apply uniquely,
all 344 runtime rows must reach their declared red assertion and then pass on
the candidate, and collection must be quiescent. The new test_snapshot.py
regressions use temporary source bytes and simulated subprocess faults only;
they do not count as identity guard kills or installed serve acceptance.

The manifest kinds describe what the result establishes:

| Kind | What a killed mutation establishes |
| --- | --- |
| `crypto` | Removing a signature/assertion check makes the real signed-input test fail. Software fixtures do not establish hardware presence. |
| `kernel` | Removing a native fact/lifetime/containment check makes its actual process/socket fixture fail. Generation contradictions and UID snapshot mismatch are fixtures, not actual PID reuse/UID transition certification. |
| `projection` | Removing a durable scope/life comparison makes a controlled Store projection fixture fail. There is no installed authenticated connection in that fixture. |
| `refusal` | Removing an early request/proof guard changes its observed refusal, usually to the existing not_implemented dependency result. No committed unauthorized effect is claimed. |
| `closed-gap` | Replacing the missing-dependency refusal with success is caught. This does not provide the missing proof/ticket store. |
| `fixture-helper` | A regression in fixture code is caught by unchanged test assertions. This establishes fixture behavior, not service authentication. |
| `transaction` | Removing a typed write/guard/receipt check is caught at the module-to-store handoff. The receipt callback does not implement a durable database or one-use redemption. |
| `client` | Reintroducing a CLI preparation regression is caught before opening a socket. This does not establish an installed RPC or authenticated session. |

The four requested controls are `omit-containment`, `omit-generation`,
`omit-proof` and `omit-nonce`. Their exact limited scopes are recorded in
the manifest. Other named controls cover RP/origin, UP/UV, algorithms,
expiry/counters, signed JSON, stale/config/endpoint/policy/run projections,
and ticket issue guards. None is called black-box acceptance.

`fixture-cases.json` separately lists each fixture's excluded claims and the
remaining HUMAN-IDENTITY, PEER and TICKET-ONCE dependencies. The passed-socket
fixture actually transfers a connected FD: a different process writes bytes
while the original connector remains the peer reported by the kernel; after
connector exit another holder still writes, but the lifetime check refuses.
It demonstrates why per-message writer authentication is still required.

Draft.4 supplies ProofUse/TicketUse and typed state writes. Their actual atomic
implementation belongs to the service-owned store and lifecycle. A fixture
model that pretended to redeem a ticket would test itself. This suite instead
checks the write/guard handoff and records durable redemption as pending. The
installed-socket `run.sh` and its three assertions provide
supporting canaries, with real namespaces, real human confirmation,
single-use ticket redemption, independent effects and collection evidence.

## Retained draft.3 controls

The draft.3 set supplied 23 fixture rows and 107 source-copy controls. All 59
earlier controls remain. Those controls cover
committed launch tuples, current launch/lineage/grants/policy, borrowed peer
ownership, descendant generations, stored human facts, exact frames,
challenge/counter/evidence writes, atomic proof guards, retained replies,
connection-bound sessions and protected containment metadata/directory checks.

The retained omit-proof-commit-gate ID now catches swallowing the Proof lookup
failure; CheckProof is nonconsuming in draft.3. The retained ticket-store gate
catches returning success before the typed ticket-write handoff. Neither
control proves an actual durable mutation or redemption. The source test
assertions and the descriptor helper exception retain their original limits.

The human-write fixture verifies actual signed assertion processing and the
one-transaction handoff, then returns that transaction's bytes through a
receipt callback. The retained-reply fixture supplies a different original
receipt and catches returning the new proposal. These callbacks are explicitly
package fixtures; the installed-socket case must exercise the real store,
lost replies, changed intent under a retained key and one-use proof/ticket
guards. Remaining carrier / digest / revocation / worker / session / actor conventions
are documented in the identity contract note.

## Draft.4 port and native composition

Both manifests now name v2.0-draft.4, and the runner compares that value to
the actual API source before compiling any test binary. All 107 prior omission
IDs and 23 fixture IDs remain. The d4fix2 follow-up also retains all 136/38
draft.4 IDs. There are now 151 controls and 44 fixtures in total.
The additional controls remove peer binding/failure cleanup, own-life/grant/
L6/child claims, root starter rules, ticket receipt provenance, stored session
receipt binding/activation, freshness after a delayed commit, and self-read
authority. The encrypted-staging checks require its human-read session without
turning staging into a new operation-proof mutation. The registry lock control
uses TryLock inside the resolver callback to observe an incorrectly held
verifier lock; it neither waits for nor accepts a timeout as a deadlock result.
Registration refuses the real cgroup root, and revocation bookkeeping retains
the UID/pin/tombstone until helper collection. Its isolated bookkeeping fixture
does not claim that an ordinary test directory was enrolled as containment.

The build-only native package under native/ uses real Unix sockets, native
SO_PEERCRED/SO_PEERPIDFD and per-fragment SCM_CREDENTIALS, then calls the actual
identity service with two generated public-key fingerprints. The fixed-principal
and proof-omission controls must reach their exact assertions. Enrollment and
policy in that package are controlled store projections. This does not exercise
durable administrator enrollment, a real helper-created lane, the installed
CLI or the serve E2E. Mutation targets remain restricted to the two owned
production packages and the exact owned identity CLI file; adding build
packages does not allow edits to tests or other owners' source.

The current shared contract c6c68ca closes the old 74354cd human.confirm matrix
gap. It permits Objects and enforces validAssertionEvidence before the Store
callback. The positive TestHumanWritesFixture/confirm remains intact. The
omit-challenge-use-write and expose-assertion-evidence controls still change
only their original properties, but now expect the focused test's invalid
typed transaction shape failure at the API preflight: that exact check now
rejects an unconsumed challenge or a nonprivate evidence ACL. This is a stronger
check, not a weaker target. The identical candidate must still pass the full
signed-assertion handoff with private bytes/proof/challenge/counter writes.
The counter-advance control keeps its callback diagnostic. The
omit-transaction-proof control expects the stricter draft.4
transaction-shape refusal before the Store callback, with the unchanged focused
ticket test still passing on the candidate.

The retained omit-ticket-principal ID removes both the ticket entry's human
class check and the enrollment helper's human class check. Keeping either one
still correctly refuses the nonhuman fixture, so a single-site omission would
survive and cannot be called a kill. The target test and its expected refusal
are unchanged; only the deliberate source-copy omission spans both sites.

Run focused kernel composition and new claim/session checks on the box as
supporting evidence, in both normal and laneboss_faults builds:

```sh
go test -count=1 -v ./e2e/v2/cases/identity/native
go test -count=1 -v -tags laneboss_faults ./e2e/v2/cases/identity/native
```

The package control commands above include that native test and all new rows.
After owners compose real enrollment/launch/store,
the supervisor must run the installed serve case from the composed source.
Its exact check mapping and outstanding owners are in
internal/v2/identity/contract-gaps.md. The authoring Mac has run no project test,
test binary or E2E for this round.

## d4fix2 review regressions

Fifteen added controls cover all five CLI registrations, the shared human
session-method class for blob staging/previews, rejected envelope proofs,
bound ConnectionID and dispatch snapshots, non-lane L6 refusal, lane-proof
refusal before decoding start/adopt, and human self's policy generation.
The L6 fixture includes current L6 success, lower/forged/revoked lane refusals,
and human callers with/without an operation proof on both propose and apply.
These are authorization projections; they do not perform D6 publication.

The five CLI valid-file tests explicitly permit only prerequisite_missing or
not_implemented, exit 69, owned outside identity. This accommodates the real
uninstalled-binding refusal without pinning a dependency's stub text. Invalid
semantic files require identity's invalid_request before any missing proof or
key is read. Invalid nonempty self/session objects hit the common exact-shape
decoder first, per the frozen ordering; no semantic variant of {} exists.

RunnerTests uses synthetic subprocess results only. On the box, run its
binding/config, malformed-output continuation and test-root containment cases
against the prior run.py from 03dc905 in a disposable source copy first, then
against the candidate. The prior runner must fail their named assertions;
neither reporter result counts as product or installed-socket acceptance.

## Draft.4 fix 9 and the counted review

The manifest preserves all 151 earlier controls and 44 fixtures and now contains
172 controls and 53 fixtures. The 21 added controls target the real retained
plan selector/error, plan revision/bound phase/handoff, the shared binding-plan
validator call, caller/store recovery equality, projected ready generation,
current cancellation/grants and committed identity event. Recovery inputs cover
a caller path/executable, foreign reservation, changed original request/budget
and missing recovery. The event controls check a missing event, wrong kind,
changed original requester and changed payload. A higher revision on the same
opened life is a positive case; a projection older than the ready reservation
refuses. Existing live run/launch/grant/policy/endpoint guards still apply.

WebAuthn's extra members are accepted only inside signed clientDataJSON. A
strict-parser regression must fail TestClientDataFixture/extra, and removing
the topOrigin refusal must fail the signed top-origin assertion. The retained
omit-json-duplicate ID now omits the owned complete-JSON validation call before
the known-field projection; duplicate members still refuse. Unknown members
remain covered by the actual signature. Outer identity requests stay strict.
No browser, hardware presence or durable proof issuance is claimed here.

The unused verifier path-binding maps/methods are removed. Native fixtures
revoke through their explicit registry and close original directory descriptors
after the registry fixture has its own duplicate. The retained
omit-dedicated-registration ID omits both actual Registry root comparisons and
targets TestRegistryRegistrationFixture/root. The retained omit-binding-gate
ID targets validateBindingRequest directly, because the shared fix-9 validator
independently refuses an invalid stored gate. Run 45's two alias removals are
listed above; the deciding predicates and assertions remain covered.

before.py separately requires 30 reached assertions to fail on nominated base
84ae053 production and then pass on the candidate with identical test bytes.
It overlays only owned identity *_test.go files in a disposable base copy,
rejects removal of existing base tests, inventories all production and test
inputs, retains original/overlaid base and candidate archives and test binaries,
and rejects source drift. It uses controls.py's strict real exit/test2json and
independent pidfd/subreaper cleanup. A dependency/setup/build failure is never
a qualified red. The overlay reporter's own tests do not count as identity
or installed-service evidence.

Run on the authorized disposable Linux box after placing the unchanged base
archive at /test/base and the exact candidate at /test/candidate:

```sh
python3 e2e/v2/cases/identity/before.py \
  --base-source /test/base --source /test/candidate \
  --base-revision 84ae053 --revision 84ae053 \
  --work-root /test/evidence/lb-v2-identity-before-f9 --tags both

sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision 84ae053 \
  --work-root  / test / evidence / lb-v2-identity-controls-f9 \
  --mode mutations --mutation all --tags both

sh e2e/v2/cases/identity/run-controls.sh \
  --source /test/candidate --revision 84ae053 \
  --work-root  / test / evidence / lb-v2-identity-fixtures-f9 \
  --mode fixtures --tags both
```

Here --revision names the source base before these uncommitted owned changes;
the runner also records exact source hashes/archives. Use the actual candidate
revision when the supervisor has committed it. Runtime qualification remains
pending until these commands really pass. Installed serve with a genuinely
launched caller remains the acceptance gate, with a separately retained correct
base failure and composed candidate pass. These 30/172/53 package rows do not
replace that gate or authenticate an AI-service session.

## Descriptor fixture regression details

The run-3 box result stopped at the old combined recvmsg assertion. Its
`flags != 0` predicate rejects a normal Linux result: Go's Linux
ReadMsgUnix passes MSG_CMSG_CLOEXEC to recvmsg, and Go's own syscall
credentials test expects it in the returned flags. That bit requests safe
descriptor inheritance behavior; it is not MSG_TRUNC or MSG_CTRUNC. The old
combined assertion reported a nil syscall error instead of the failed flag
condition. The exact box flag was not included in the supplied failure log;
the corrected fixture logs the actual counts and flags on a successful run.

The decoder now rejects payload/control truncation, unknown flag bits, wrong
payload size/marker, wrong message/descriptor counts, and descriptors missing
FD_CLOEXEC. It reads the actual descriptor flags rather than setting them
after receipt. Parsed descriptors are closed on refusal. Send and receive
failure messages identify the individual condition and observed counts.

`reject-cloexec-flag` reinstates the old reject-all-nonzero behavior in the
decoder only. `TestDescriptorFlagsFixture/cloexec` must fail with the named
valid-transfer diagnostic, followed by an unchanged-candidate pass. The
separate negative cases require truncation/count/marker/CLOEXEC refusals and
check that rejected descriptors are closed. Additional `fixture-helper`
mutants remove those checks or the specific diagnostic; the immutable
negative test must then fail for its declared reason. A diagnostic-only kill
does not imply that the omitted check allowed a bad descriptor through other
checks. The complete passed-socket test
must still transfer a real connection, observe another process's writes,
observe writes after connector exit and require lifetime refusal.

Run the focused regression before the full fixture suite:

```sh
sh e2e/v2/cases/identity/run-controls.sh \
  --source "$PWD" --revision "$(git rev-parse HEAD)" \
  --work-root /tmp/lb-v2-identity-cloexec-r3 \
  --mode mutations --mutation reject-cloexec-flag --tags both

go test -count=1 -v ./internal/v2/peer/linux \
  -run 'TestPassedSocketFixture|TestDescriptor.*Fixture'

go test -count=1 -v -tags laneboss_faults ./internal/v2/peer/linux \
  -run 'TestPassedSocketFixture|TestDescriptor.*Fixture'
```

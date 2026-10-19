# Guidance red-control handoff

The versioned `mutations.json` catalog is the executable specification, pinned
to v2.0-draft.4. The original 36 controls remain, with their targets ported to
ScopedJudge, shared request preparation and the current JSON field map. It has
111 ready component controls and nine pending integration controls. No mutation
is selected by task text in product code. The runner edits only a retained
copy of this lane's production Go files; it never edits tests to create a
failure, modifies the real checkout, stages, commits, or contacts a host.

Run only on the authorized disposable Linux test box. These commands must not
execute on the authoring Mac. The supervisor supplies absolute source/evidence
paths. Each evidence destination must be fresh, outside the source, carry
`lb-v2-guidance`, and have an existing parent directory.

```sh
python3 -m unittest discover \
  -s e2e/v2/cases/guidance -p 'test_*.py' -v

python3 e2e/v2/cases/guidance/mutate.py \
  --source /test/source \
  --evidence /test/lb-v2-guidance-red-plain \
  --components

python3 e2e/v2/cases/guidance/mutate.py \
  --source /test/source \
  --evidence /test/lb-v2-guidance-red-faults \
  --components --faults
```

To run one control, replace `--components` with, for example,
`--mutation ignored-task`. The runner applies exactly that named behavioral
defect. Multi-edit controls implement one defect, such as caching a selection
across independent logical turns. `--list` prints names, scope, state and test
targets; it does not run a test. Unknown names fail before running anything.

For each ready control the runner:

1. Copies regular source files, excludes Git metadata/byte caches, rejects
   links, bounds the input size, retains exact source bytes in an archive and
   records file/hash/mode manifests. It copies no environment or credentials.
2. Requires every replacement anchor to match once in the copied production
   source. It retains the before/after bytes, hashes and patch. A changed
   anchor is a setup failure, never permission to patch another location.
3. Runs `go test -mod=readonly -json -count=1` for the exact catalog test (and
   subtest). The red run must exit 1, contain a real run+fail event for that
   test, and include the named assertion diagnostic. Build errors, skips,
   panic, unrelated failures, a missing test, or deadline exhaustion fail the
   mutation phase. It cannot count a dependency stub/setup crash as a kill.
4. Only after that intended red failure, restores the original copied bytes
   and requires the identical focused test to run and pass with exit zero.
   It checks the source manifests before/after each phase and verifies that
   the original checkout did not change. Red always precedes green here.
5. Writes result.json with observed exits, failed/passed test names, command
   arrays, source identity, edits and hashed evidence paths. The source copy,
   archive, Go version and raw stdout/stderr remain for supervisor collection.

Exit zero means the selected **component** mutation was killed and the
restored focused test passed. A batch stops at its first incomplete/surviving
control. Its summary retains partial results and explicitly lists the pending
integration controls; component success is never GUIDE-TURN acceptance.
`test_mutate.py` checks classifier behavior using labeled JSON data fixtures,
source-copy integrity, edit anchors and the pending-feature result. It does
not fabricate a real Go process output or validate a production service.

## Acceptance mapping

The catalog includes exact source edits, test/subtest names and the required
assertion message. This table connects each section rule to those controls.

| Acceptance rule | Ready component mutation → focused test | Remaining integration mutation → test |
| --- | --- | --- |
| Initial, resume, mail and idle each invoke one hook | `missing-rpc-hook` → TestRegisterFrozenMethod proves only RPC registration. | `missing-hook-initial`, `missing-hook-resume`, `missing-hook-mail`, `missing-hook-idle` → GUIDE-TURN; remove the selection call in the real delivery path. |
| Each independent turn selects with no reminder cooldown | `reminder-cooldown` → TestEvaluateEveryTask caches one private selection across distinct turns. | All four delivery-hook controls still require actual lifecycle wiring. |
| Task bytes influence selection | `ignored-task` → TestEvaluateEveryTask; `truncate-task` → TestEvaluateFullInput. | `drop-input` → GUIDE-TURN; omit source/task rendering from the actual prompt. |
| Vary recent, old and unrelated history | `recency-off`, `ignore-half-life` → TestRankClockAndHalfLife; `ignore-clock` → TestEvaluateUsesClock; `unrelated-fill` → TestRankRelevance. | Authoritative applicable history still needs the real store projection. |
| Fourteen-day default and exact weight metadata | `default-half-life`, `weight-off` → TestRankDefaultHalfLife; `future-age` → TestRankFutureAge; `saturate-age` → TestRankAncientHistory. | Controlled service-clock workload is still supplied by integration. |
| Current binding policy never ages out or consumes history slots | `binding-decay`, `binding-drop` → TestRankBindingContext; `binding-spends-slot` → TestRankCapAndMean; `binding-judged` → TestEvaluateEveryTask. | `proposal-poisoning` → GUIDE-TURN; remove provenance/scope filtering from real retrieval. |
| At most five reminders plus binding context | `six-reminders`, `top-five-mean` → TestRankCapAndMean. | `drop-input` also checks the actual prompt, beyond the private receipt stage. |
| Empty differs from unavailable and valid zero stays zero | `empty-as-outage` → TestRankEmpty; `fake-zero`, `partial-as-scored` → TestRankUnscored/partial; `missing-as-zero` → TestRankUnscored/nil. | `missing-receipt` → GUIDE-TURN; remove durable receipt completion on delivery. |
| Complete per-ID scored judgment and exact provenance | `duplicate-answer` → TestRankUnscored/duplicate; `unknown-answer` → TestRankUnscored/unknown; `unstable-ties` → TestRankStableTies. | Draft.3 source/audit ports now exist; actual store/judge implementation and Linux evidence remain required. |
| No inference with unproved input fit or lost coverage | `unproved-fit`, `fit-bytes`, `fit-tokenizer` → the matching TestEvaluateFitGuard subtest; `batch-truncate` → TestEvaluateEmptyAndBound now requires complete batching. | Durable claim/completion and actual audit integration remain pending. |
| One total guidance deadline | `reset-parent-deadline` → TestEvaluateParentDeadline; `reset-fit-deadline` → TestEvaluateSharedDeadline. | Durable reservation must start the budget before store/queue wait. |
| No false success for an unfinished dependency | `stub-as-outage` → TestEvaluateErrorsStayTyped / not_implemented-fit-true; `fake-completion` → TestSelectContractIsUnavailable. | Finishing the actual RPC requires the amendments in CONTRACTS.md. |
| Current life/run/turn and strict file-backed inputs | `stale-turn` → TestSelectRejectsStaleTurn/turn; `request-duplicates` → TestRequestShape/duplicate; `rpc-task-class` → TestRequestShape/class. | `cli-duplicates` → TestCLIRejectsMalformedFile/duplicate needs the shared-parser red artifact; the common structural decoder rejects it before the registered semantic hook. Service authentication remains the responsible service/identity owners' gate. |
| Profile continuation reuses the original logical-turn selection | No component imitation is counted as this proof. | `repeat-selection` → GUIDE-TURN; remove the actual durable replay check after integration implements it. |

## Pending controls are visible failures

Selecting any catalog entry whose state is `not_implemented` writes its
result.json with that status, no test phases and a typed dependency description,
then exits 69. It does not edit a neighboring lifecycle/store/template file or
pretend the existing RPC stub can be a continuation/delivery proof. The exact
future check to remove is recorded as `intended_mutation`; only the owning
lane/integrator can provide the reviewed shared edit after the interface lands.

Do not count pending controls or a passed component batch as full red coverage.
After integration supplies those nine controls, GUIDE-TURN must fail at the
actual targeted delivery and pass on the restored artifact with retained
prompt, guidance, judgment, input, continuation and collection evidence.

## Draft.3 additional component controls

The new tests are focused contract fixtures. They do not certify the actual
state owner, human authenticator or live judge. The earlier claim contract gap
was closed by fix 11; real store/outbox and installed acceptance remain required.

| Mutation | Focused test and required failing observation |
| --- | --- |
| retained-task | TestSelectTaskIsRetained; a replacement visible task must conflict. |
| pending-as-new | TestPendingDoesNotRejudge; an observed pending claim must use protected await. |
| replay-zero | TestReplayRejectsCorruption / fake-zero; unavailable cannot carry a score. |
| replay-rewrite | TestSelectRetainedReplay; replay seals a reply without another selection write/event. |
| first-page-only | TestCandidatePagesComplete; the final reminder page must survive. |
| mixed-snapshots | TestCandidatePageFailures / snapshot; every page must use the same immutable snapshot. |
| task-prefix | TestTaskObjectBytes; a forged prefix reference cannot hide a retained tail. |
| ignored-cutoff | TestRankApprovedCutoff; a positive approved scalar must apply, while zero uses the 0.50 default. |
| lost-judge-scope | TestEvaluateScopedAuthority; the original authenticated Scope must reach ScopedJudge. |
| ignored-judge-default | TestEvaluateJudgeDefault; R108 resolution retains deployment/tokenizer policy. |
| batch-suffix-loss | TestBatchesCoverEveryCandidate; all 25 candidates, actual receipt IDs and binding slots remain. |
| partial-batch-zero | TestBatchFailureKeepsBinding; partial inference is unavailable with binding context and no score. |

Selecting pending integration controls still exits 69. Fix 11 now supplies the
claim semantics and guidance consumes them. Real service/store/outbox and
lifecycle/template/controller implementations are prerequisites for installed
controls. A missing backend is not a kill.

The original cli-duplicates edit is retained as blocked_edits, with its test
and assertion intact. The common draft.4 --request path calls InvokeRaw before
the feature adapter; removing the adapter's duplicate check cannot establish
the real CLI boundary. This entry now explicitly exits 69. Integration owns
the shared-parser mutation or validation hook needed to restore an executable
red control. The Python anchor test also checks the preserved blocked edit.

## Draft.4 additional controls

At the initial draft.4 port, all 56 prior names remained. Those three controls
brought the total to 59, with 50 ready and nine explicitly pending. They are component fixture checks;
their actual Linux red/green results must be retained before acceptance.

| Mutation | Focused test and required failure |
| --- | --- |
| unapproved-single | TestEvaluateApprovedPins / single / deployment; bypassing approved-policy comparison must fail the forbidden assertion before fit/inference. |
| unapproved-batches | TestEvaluateApprovedPins / batches / deployment; overwriting a different request config with approved pins must still be rejected. |
| rpc-task-class | TestRequestShape/class; removing the service request's task-class check must fail invalid_request. This is separate from the blocked common CLI route. |

The pin test also varies tokenizer, context, provider and each policy generation
and requires zero provider calls after refusal. The R108 positive test retains
the approved deployment/tokenizer pins with empty provider/model spelling.
CLI negatives now have retained valid keys and exact code/message/owner checks,
so the missing-key guard cannot masquerade as the missing semantic guard.

## Draft.4 fixes 3-7 registration controls

At that round all 59 earlier names remained. Five controls brought the catalog
to 64: 55 ready components and nine pending integration controls. After cross
review the four hook controls now remove their four separate field predicates
in a retained production source copy. Each named negative assertion must fail
before exact restoration. Registration removal has its own new control.
The fifth introduces rejection of valid input and must fail the positive
transport-boundary assertion. No test/helper is edited to produce the red.

| Mutation | Focused test |
| --- | --- |
| cli-hook-zero-run | TestCLIRejectsMalformedFile/zero-run |
| cli-hook-class | TestCLIRejectsMalformedFile/class |
| cli-hook-large-task | TestCLIRejectsMalformedFile/large-task |
| cli-hook-negative | TestCLIRejectsMalformedFile/negative |
| cli-rejects-valid | TestCLIValidFileReachesTransport |

The valid fixture requires exit 69, empty stdout and one of the two exact
binding/transport outcomes documented in VALIDATION.md. It supports the
service scaffold and real missing-binding refusal. Guidance-owned errors,
invalid_request and every other code/message fail, so omitted registration
and the reject-valid mutation still cannot satisfy it. Runtime red/green
checks run only on Linux. The common duplicate control remains pending.

## Counted cross-review controls

All 64 prior names remain. Thirty-three additional component controls bring
the catalog to 97 entries: 88 ready and nine pending. No new runtime kill is
claimed until the exact candidate is run on Linux in both builds.

| Controls | Focused boundary / failing observation |
| --- | --- |
| foreign-life, ancestor-as-self, worker-as-self | TestSelectSelfAuthority; forbidden must precede any target read, independently of Source, level or role labels. |
| lane-operation-proof, lane-read-authority, foreign-run-binding | TestSelectSelfAuthority; lane metadata and installed run target must constrain access. |
| foreign-judge-config | TestStageSelfAuthority; a different judge context config cannot reach fit. |
| stale-human-session, human-proof-guard | TestReplayRechecksLiveSession / TestHumanSessionReplay; live connection authority is required and ProofUse is forbidden for preview. |
| human-source-port, human-authority-mismatch, human-replay-path | HumanDecisionProvenance / HumanReceiptPathless; canonical pathless human records resolve through Decision and preserve exact source/authority. |
| proposal-authority, d6-zero-generation | TestCandidateAuthorityKinds; proposal and incomplete D6 authority must be rejected. |
| replay-turn-policy, replay-scope-policy, replay-reservation-policy | TestReplayPolicyGeneration; generation checks precede replay and reject a mutually consistent stale reservation/result pair. |
| scored-without-judgments, empty-with-judgments, replay-non-utc, snapshot-non-utc | Judgment/status provenance and UTC clocks must remain checked. |
| zero-cutoff-default | TestRankApprovedCutoff; zero means default 0.50 and cannot admit probability 0.01. |
| reply-model, reply-deployment, reply-negative-cost, reply-over-cost, reply-negative-latency | TestEvaluateReplyAudit; a corrupted actual provider audit cannot become scored guidance. |
| zero-cost-cap, costed-reply-rejected, batch-cost-renewed | The explicit cap is positive, valid positive costs succeed, and later batches receive the remaining total. |
| long-guidance-deadline, unavailable-keeps-score | Five-second cap and unavailable clearing apply even to an empty baseline. |
| cli-missing-registration | The separate registration control complements the four distinct field-predicate controls. |

evaluateCandidates now delegates to the one complete batching path. Existing
clock / task / binding / truncation / default / policy / deadline mutations were ported to
their actual new production locations without removing names or test targets.
The over-twelve test now requires complete multi-batch selection, not a second
private refusal policy. partial-batch-zero removes the new common score
clearing. replay-rewrite now expects the precise invalid transaction refusal
before Transact, rather than an impossible later rewrite assertion.

The new test_guide_turn.py contains explicit adversarial oracle data and
paired positive controls: missing later inputs, raw setup errors after reach,
constant/unchanged task relevance, clock/task confounds, uniform ages, absent
below-cutoff coverage, skipped event windows, prior-run/forged events, missing
provenance and human bindings. It tests classifier/oracle behavior only. The
Go mutation runner still mutates only owned production Go; no Python fixture
success is counted as an installed service mutation kill.

## d4fix5: scored receipt survivor

On 939e3bbf the supervisor reports 146 kills and the same
scored-without-judgments survivor in both builds. The old fixture's nil
JudgmentIDs marshaled as null and hit DecodeObject before the intended guard.
The generic integrity assertion therefore accepted a different failure.

The production edit and TestReplayJudgmentProvenance / scored-missing target
are unchanged. The fixture now removes IDs from an accepted scored receipt
using an explicit empty array. It proves wire-shape validity first and requires
the exact status/provenance error. The unchanged guard deletion must return
success to that assertion and fail with:

```text
want typed integrity at retained guidance status differs from its judgment provenance
```

Null remains a separate subtest expecting the earlier shape error. Other
receipt tests now require their exact intended diagnostics. Seven catalog
failure_contains values are tightened; no production edit, test target, name
or readiness state is removed or weakened. Counts remain 88 ready and nine
pending. guidance/VALIDATION.md records the audit and focused Linux commands.
The current red/green result must be collected on Linux; static Mac analysis
cannot establish that the survivor is killed.

## Fix 11 consumer controls

All 97 previous names remain. Nineteen owned production controls bring the
catalog to 116 entries: 107 ready and nine pending. The six named handoff
controls are local consumer checks; the integration catalog's shared API
controls remain separate. No shared API or another owner's manifest is edited.

| Local controls | Consumer assertion |
| --- | --- |
| f11-guidance-win, f11-guidance-owner | Observed acquisition must await; foreign attempt must refuse before fit or judgment. The shared validator remains a second guard. |
| f11-guidance-rejudge, f11-guidance-recover-new | Recovery cannot re-enter the judge or reserve a missing claim. |
| f11-guidance-cause, f11-guidance-cas, f11-guidance-epoch | The original owner cause and pending CAS/epoch must survive transaction construction and catalog validation. |
| f11-guidance-current, f11-guidance-exact | Fresh selection uses current policy; exact replay bypasses mutable fresh-turn preflight. |
| f11-guidance-budget, f11-guidance-no-budget, f11-guidance-task | Positive authoritative budget and full nonempty retained task must reach the judge; exhausted budget stops before reservation. |
| f11-guidance-empty, f11-guidance-method | Known empty corpus remains empty; internal callers use an empty method without relabelling lane.turn. |
| f11-guidance-cancelled, f11-guidance-event | Cancelled claims refuse; event bytes must equal the actual completed receipt. |
| f11-guidance-two-keys, f11-guidance-await-expiry | A real pending waiter cannot return prematurely; deadline expiry recovers the same claim without a new judge call. |

Five earlier entries were ported because the former refusal/pending-policy
behavior was superseded: fake-completion drops the real reserve port error;
pending-as-new removes the required await route; replay-turn-policy introduces
the invalid comparison against current policy; replay-scope-policy overwrites
the retained turn generation; replay-reservation-policy removes both retained
generation checks. Names and focused tests remain, with assertion diagnostics
updated to the new contract. These are not deletion or weaker retargeting.

The concurrency fixture holds the winning evaluator until another key has
entered protected await. Recovery uses the same stored cause and fixture
CAS/epoch, then replays without another selection event. Exact reply fixtures
retain actual bytes and policy generation. These tests are component evidence
only after Linux execution; they are not authenticated native/store/provider
or installed acceptance. Expected full runtime count is 222 kills in both
builds, not a measured result.

The replay regression correction keeps all earlier controls and adds four:
f11-guidance-retained-owner and f11-guidance-retained-deadline remove the
shared claim-validation refusal and target completed owner/deadline rows;
f11-guidance-exact-continuation restores strict target equality and must fail
the second run-2 replay assertion; f11-guidance-exact-target drops the future
run bound and must fail the precise target-check diagnostic. The catalog has
120 entries including the nine pending integration cases.

Replay fixtures use nonempty task bytes, actual request digests, reservation
and shared-validated completion transactions. They avoid the replay code under
mutation during setup. The pending test starts pending and completes only
after protected await is observed. It does not edit a completed record backward.
The reservation-policy negative case also checks that mismatched pins do not
reach historical policy lookup, so an unrelated missing-history error cannot
masquerade as its intended gate.

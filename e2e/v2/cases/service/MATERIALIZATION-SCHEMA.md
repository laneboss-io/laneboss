# Materialization schema and control reachability

The authoring base is c929311a. The supplied Linux mat-red1 log for 09163272
records BUILD-OK and one successful pair, data-stage-grant normal, before
stopping at worker-principal-boot. Its deciding output is:

```text
=== RUN   TestWorkerPrincipalPins
    materialization_linux_test.go:63: invalid_request: unknown schema enum
--- FAIL: TestWorkerPrincipalPins (0.56s)
```

The mutant did not reach its named assertion and earns no red credit. The
reported candidate green for data-stage-grant is limited to that source and
normal variant; it is not evidence for the other nine rows or this candidate.

The first failing source path is DataFixture.Open → Seal →
store.SealDataStage → retainDataBytes(class materialize_input) → store.retain
→ wire.Decode(BlobRef) → enum(BlobRef.class). The original enum omitted the
fix-11 private class. The fixed input class is required by
api.ValidateLaunchDataStage and by the dataworker/admin consumers, so renaming
the fixture to manifest or skipping the retention check would hide the defect.

The service-owned wire validator now recognizes materialize_input and
worker_result BlobRef classes, WorkerPlan kind materialize, and DataGrant
delivery bind_ro. These values already occur in the frozen materialization
ports; no API DTO or public method is changed. BlobBeginRequest retains its
previous class enum, and DataGrantRequest retains copy/mount delivery. The
private enum correction grants no public upload/delegation or execution
authority. Unknown classes/kinds/delivery names remain refused.

DataFixture.Seal/Open now identify sealing, child claim, claim retention,
handoff, identity binding and process retention failures separately. The
fixture still uses the actual store path and computes digests from retained
variable bytes. It does not overwrite records, relabel a worker as an import,
substitute an allowed blob class, invent a digest or suppress a failed step.

The original ten rows and their exact named assertions are retained. The
audit below is static path analysis; each row still requires its compiling
Linux mutant and unchanged candidate to run in both tag variants.

| Original control | Setup and deciding path after the correction |
| --- | --- |
| data-stage-grant | NewData stops at the reserved stage, before sealing. The supplied normal pair already reached its marker. The test now also requires the selector-conflict code/message, so another refusal cannot pass the candidate. |
| worker-principal-boot | Open seals the required materialize_input, claims the child, binds identity and records the process. A current WorkerBinding is checked first. The fault changes only the nonempty peer boot; the candidate must return the exact containment_unknown boot refusal. Removing that guard leaves all other principal pins intact and must reach "worker principal accepted another native boot". |
| data-stage-current-grants | NewData stops before sealing. The fault revokes the actual issued agent grant generation. The mutation removes both the current-launch check and the retained-grant refusal, leaving the same reserved stage/lease to reach its existing marker. No input-class decode precedes that marker. |
| data-registration-pin | MaterializationStage seals the same private input and reaches the helper registration receipt. The fixture changes only receipt.Config. Candidate requires the exact registration-integrity refusal; the mutant continues through the real store binding/permit/process path to its unchanged marker. |
| data-await-process | Open and WorkerResult require the two corrected private classes. ObserveDataWorker returns a foreign process handle; candidate requires the exact process-integrity refusal. The mutant continues to MeasureDataWorker, whose read-back uses the original process and actual retained output/manifest bytes, then completes the same effect and reaches the unchanged marker. |
| worker-input-own-job | Open requires the corrected input class. The fixture first checks the real sealed input/hash. The fault changes only the requested lease selector; candidate requires the exact forbidden selector refusal. The mutant returns the authenticated worker's own input, which passes input validation and reaches the unchanged marker. |
| worker-result-measurement | Open and Result read the sealed input. The fault changes only source identity and recomputes exact JCS result bytes. Candidate requires the exact measurement-integrity refusal. The mutant retains actual worker_result bytes, hashes them, commits a valid receipt, and reaches the unchanged marker. |
| worker-result-own-job | Open and Result preserve all output measurements. The fault changes only submission.LeaseID; candidate requires the exact forbidden selector refusal. The mutation normalizes that selector and follows the valid actual-result retention/receipt path to the unchanged marker. |
| worker-result-replay | Open and initial submission require both corrected private classes. Exact replay must preserve receipt and event inventory. The fault appends a newline to the actual result bytes. Candidate requires the exact idempotency_conflict refusal. The mutation removes that refusal and its repeated receipt-digest validation, returning the original receipt at the unchanged marker. Restart verification remains a subsequent candidate requirement. |
| worker-ingress-frame | Open uses the corrected input class. The service fixture first proves the authenticated connection overrides supplied actor labels. The fault changes only the frame's input selector while the called request remains correct; candidate requires the exact frame-integrity refusal. Removing that comparison lets the dedicated store input call return the still-correct requested job and reach the unchanged marker. |

TestMaterializationSchema independently round-trips the exact reference,
plan, narrow grant, bootstrap and acknowledgement DTOs through wire.Decode.
Its bytes and hashes are derived from variable input. It also checks that
public uploads and delegation cannot name the private forms, and that an
unknown worker kind is refused. Each complete test/subtest path is under
40 characters. Four new controls remove one private enum value at a time:

| Control | Exact test path | Required assertion |
| --- | --- | --- |
| materialize-input-schema | TestMaterializationSchema/input | frozen materialization schema refused |
| worker-result-schema | TestMaterializationSchema/result | frozen materialization schema refused |
| materialize-plan-schema | TestMaterializationSchema/plan | frozen materialization schema refused |
| materialize-grant-schema | TestMaterializationSchema/grant | frozen materialization schema refused |

The mutation rows continue to target production files only and leave tests
unchanged. Every red must compile and reach its declared marker; another setup
refusal, a schema refusal in a different original test, a panic, timeout or skip
cannot receive credit. No row is removed, blocked or converted to a skip.

The two run-2 generic-scope controls also share DataFixture.Open, so the same
input-class fix removes their predicted setup barrier. Their centralized
fail-closed production refusal and exact assertions remain unchanged.

This authoring lane runs static checks only. No new unit, mutation, native
worker or installed-service result is claimed. The supervisor's Linux rerun
must establish all fourteen materialization schema/control pairs on the exact
retained candidate, followed by the relevant candidate suites. The composed
installed boundary and authenticated AI-service tests remain unmeasured here.

Authoring validation on Darwin arm64 with Go 1.26.5 passed gofmt -w and an
empty gofmt -l result for all five changed Go files; go vet for the wire,
store/... and service packages targeting Linux, Linux with laneboss_faults,
and Darwin; py_compile of mutations.py; bash -n of both service drivers;
and git diff --check. Static source inspection found unique edit anchors and
present assertion/test declarations for all ten original rows, four schema
rows and two run-2 scope rows. The registry contains 187 controls. This is
static evidence only and does not replace runtime anchor preflight, builds
or reached red/candidate assertions. The three reserved files are unchanged.

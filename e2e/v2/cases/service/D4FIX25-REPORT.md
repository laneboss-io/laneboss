# Draft.4 fix 25 report

This round starts at aa60d80. The supervisor reports that green15 proved the
previous linear read-back change: initial publication passed at 2373 ms and
read_back at 480 ms. Those are attributed supervisor observations; this round
did not run or independently collect green15. The new unit box was still
running when the brief arrived, and no result is inferred from it.

## 1. Cause and applicability

The supplied 9a484ef red-verifier log records TestAwaitDataCancellation failing
in the normal unmutated candidate suite at this assertion:

```text
materialization expiry did not return a typed deadline integrity: launch request is not the exact original receipt bytes
```

The brief reports both builds. The copied log establishes the normal candidate
failure; it does not independently establish a faults result. No mutation was
credited by that failure.

Source tracing found a production error-classification defect. checkLaunchBytes
combined the receipt SQL read error and the exact bytes comparison in one
condition. A context deadline or cancellation during that query therefore
returned the same integrity error as successfully read different bytes. The
failed query had not supplied bytes on which to base that comparison.

No request re-encoding was found in the materialization fixture path. Admit
saves json.MarshalIndent output as f.Raw and passes it to ReserveRequest.
The receipt retains those exact raw bytes. ReserveLaunch retains the launch
object directly from receipt.RawRequest, rather than remarshal the request.
The read compares that persisted object with the receipt's request column.
The materialization fixture does not replace either representation on expiry.

A Git source comparison of launch_plan.go, materialization.go, the cancellation
test and the shared materialization fixture from 9a484ef to aa60d80 exited 0
with an empty diff. The same failed-query condition therefore still applied
at this round's base. The deterministic controls below isolate it without
relying on a scheduler placing the 10 ms expiry inside a particular query.
They have not been executed on this Mac, so no new runtime cause measurement
is claimed.

## 2. Preserve query failures and the integrity gate

checkLaunchBytes now calls the private checkLaunchReceipt helper. The helper
reads the same receipt column with the same operation selector. A missing row
still returns the original integrity refusal. Other failed reads preserve
their actual error; an expired failed query returns its context cause,
including when SQLite reports an interrupted operation through a driver error.
Only a successful read proceeds to bytes.Equal, and different bytes still
return exactly launch request is not the exact original receipt bytes.

The existing AwaitMaterialization error conversion already maps context
deadline/cancellation into CodeDeadline and CodeCancelled. It is unchanged.
The reservation's immutable object checks, request digest and exact byte
comparison remain. There is no deadline increase, retry loop, remarshal repair
or changed expected error. A real byte mismatch is not reclassified as expiry.

## 3. Regression and deciding failures

The existing TestAwaitDataCancellation retains its 10 ms wait and exact typed
deadline/cancelled assertions. Before expiry and after each failure, it now
checks both the real receipt's RawRequest against f.Raw and the actual retained
launch input against those receipt bytes through Server.Original. A failure
cannot pass by silently changing the source representation.

TestLaunchReceiptRead creates an actual transaction receipt with indented
request bytes, first proves the healthy exact-byte lookup, then reaches the
same receipt SQL boundary through a counting query wrapper. The wrapper never
fabricates rows, request bytes or database errors. Its cases cover an already
expired deadline, cancellation at the query boundary, a compact representation
of the same JSON, a genuinely absent operation, a closed real sql.Conn and the
unchanged exact input. Every case checks the original stored bytes afterward.
The deadline is already expired and cancellation is explicit; no sleep or
timer race is needed to reach the deciding checks.

TestLaunchReceiptIntegrity exercises the real LaunchPlan path. After a passing
read, it changes only the disposable fixture's receipt representation to
compact JSON and restores its immutability trigger. The original launch object,
digest and request semantics stay unchanged. LaunchPlan must return the exact
integrity refusal. The positive control and separate unrelated-error assertion
prevent a setup or foreign refusal from counting as this result.

| New control | Test and leaf | Deciding assertion |
| --- | --- | --- |
| launch-receipt-deadline | TestLaunchReceiptRead, deadline | receipt read lost its context failure |
| launch-receipt-cancelled | TestLaunchReceiptRead, cancelled | receipt read lost its context failure |
| launch-receipt-byte-gate | TestLaunchReceiptRead, changed | receipt read lost its exact byte integrity gate |
| launch-receipt-missing | TestLaunchReceiptRead, missing | receipt read lost its exact byte integrity gate |
| launch-receipt-sql-error | TestLaunchReceiptRead, read_error | receipt query failure became a byte mismatch |
| launch-receipt-call | TestLaunchReceiptIntegrity | launch plan accepted changed receipt bytes |

The context mutants restore the false integrity classification. The others
remove the byte comparison, permit a missing receipt, relabel a real SQL failure
or bypass the launch path's receipt check. Tests remain unchanged in each
mutant. All six deciding red failures followed by candidate passes remain
required on Linux.

## 4. Static verification and remaining proof

gofmt -w ran on all five changed Go files before checks. gofmt -l then exited
0 with empty output. Python py_compile of mutations.py and test_diagnostics.py,
bash -n of run-mutations.sh and git diff --check each exited 0. The authoring
host is Darwin arm64, Go 1.26.5 and Python 3.13.11.

Data-only literal inspection in orchestration JavaScript found 262 unique
controls and 277 sequential edit anchors. Every anchor matches exactly once.
All 256 previous rows, edits, tests/leaves and deciding assertions are unchanged.
No project code was imported or executed by that source inspection.

The sole vet attempt was:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off go vet ./internal/v2/store ./internal/v2/service
```

It exited 1 on two Go build-cache permission refusals. The exact command and
both refusal lines are retained verbatim in external checks.json and vet.log.
Vet stopped; remaining variants were skipped under the brief's explicit
recovery route. No alternate cache, permissions change or retry was attempted.
Only reporting and evidence collection followed that refusal.

Compilation, new unit outcomes, red/candidate results and installed acceptance
remain unestablished by this round. No tests, product builds, machines/jobs,
real model requests, extra agents/sessions, Git staging or commits were started
here.

The external lb-v2-service round d4fix25-aa60d80 retains complete governing
inputs, starting source archive, supplied older failure log, source trace,
catalog/anchor audit, six mutant source snapshots, exact commands/outputs/exits,
final source archive, diff, status and SHA-256 manifest. There is no tested
product binary from this static-only round.

The Linux verifier must run TestAwaitDataCancellation, both new test groups
and the six new controls in normal and faults builds before crediting the fix.
The complete mutation inventory is now 524 targeted pairs and ten final
component package/tag suites. Retain all exact test inputs, binary bytes/hashes,
outputs and exits; unrelated failures cannot earn mutation credit.

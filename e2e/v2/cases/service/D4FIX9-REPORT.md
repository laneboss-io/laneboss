# d4fix9 service/store recovery report

Source revision: e4e125c, plus the uncommitted
candidate in this same service checkout. The fix-9 brief, enrollment addendum
and authorized anchor-recovery brief were read completely. No other worktree,
branch, remote, machine, model request, staging or commit was used.

The service/store row and both enrollment store ports are implemented in
candidate source. The pending-key control is repaired and all 87 controls
have unique anchors. Formatting and Python/shell syntax checks pass. Go vet
is unavailable because the existing Go cache refused access; the recovery
brief explicitly permits skipping vet in this case. Compilation, Linux
red/candidate execution and installed launch acceptance remain unverified.

## Pending-key recovery

The earlier evidence round stopped with pending-key-digest anchor counts
[1, 0]. Its stale second anchor omitted the existing durable-dispatch else-if
branch. The recovery changes only that control's second old/new edit pair.
The first digest-check removal, test and required assertion are unchanged:

- Test: TestPendingKeyRejectsChangedIntent.
- Required assertion: pending key accepted changed intent.
- Mutated production file: internal/v2/store/transaction.go.
- Changed candidate region: lines 100 through 111, containing the pending
  digest check and its adjacent reserved-frame protection.

The second anchor now includes the exact current reserved-frame branch and
dispatch else-if. Its replacement removes the reserved-frame protection and
assignment while retaining dispatchAllowed for unreserved work. Together
with the unchanged first edit, the mutant breaks the intended pending-key
protection. In-memory comparison confirmed that its prefix and suffix are
unchanged outside this one region. The complete named test file is unchanged
from the pre-recovery source archive.

Static literal parsing found 87 controls, 94 edits and 33 production files.
Every old-text anchor occurs exactly once in the unchanged candidate and once
at its sequential application point. All controls remain present. Only
pending-key-digest differs from the pre-recovery inventory, and the runtime
mutation checker is unchanged. This is a source result; the mutant was not
compiled or executed.

## Per-item status

“Source implemented” below does not grant runtime acceptance. Positive and
refusal tests and deciding mutations are authored; none has been executed in
this static-only round.

| Item | Candidate source completed | Remaining integration or verification |
| --- | --- | --- |
| ReserveLaunch / LaunchPlan | One-store request-owner handoff, issued reservation/name/launch/spec/grant IDs, exact original bytes and pending reply, root ticket and parent/D9 authority, phase CAS, cancellation and policy/grant fences. Retained lives and continuation preserve requester, private identity, grants, ancestry and budget. | Linux positive/refusal/restart execution. Real lifecycle, grant and materialization owner implementations must supply their retained results. |
| ClaimEffect / CompleteEffect / Transact | Actual current claim/expiry/epoch checks, immutable replay comparisons, measured worker outcomes, opened-plan/process completion, closed reservation/capture ingress and ready-binding/run-advance fences. | Linux mutation and candidate execution; actual helper/worker outcomes and planner transitions. Owning typed not_implemented errors continue to propagate. |
| LaunchBinding | Complete retained recovery/spec/home/capture/lease and committed identity-event verification, canonical commit digest, missing-recovery refusal at lookup and reopen. | Linux corruption/reopen execution and real atomic helper_prepare/helper_open integration. |
| CaptureState / AppendCapture | Fixed-worker endpoint/lease/lifetime authentication, sealed binding and private chunk provenance, contiguous offset/CAS/EOF, exact range/hash replay, one-use pipes and reconstruction from immutable events. | Linux range/replay/foreign-worker/restart execution. Native outside channel, spool, producer and post-revocation drain attestation remain owner work. |
| Service LaunchControlSource / capture ingress | Durable original-input and stage-claim lookups, exact helper input/receipt completion, independent probe, authenticated capture state/append and narrow RetainCapture byte ingress. Body-supplied internal intent refuses. | Real helper journal/receipt-loss reconciliation and authenticated native channel wiring. Component helper/transport identities are not installed observations. |
| BindRuntime / recovery jobs | Requires planning dependencies for pending planning effects. Launch readiness/admission additionally requires the active healthy recovery/capture loop. Reconciliation uses retained original identities and records actual observations/gaps without speculative opening. | Assembly must forward the concrete recovery ports and wire LaunchPlanner, helper, worker, launcher and independent IsolationEvidence. Linux job-loop and installed startup/restart acceptance remain pending. |
| HumanEnrollments | Protected concrete inventory port matches the serve startup consumer; includes revoked credentials and exact recorded credential IDs, markers, keys, counters and generations. Wrong configuration, malformed inventory, closed store and cancellation refuse. | Integrate fix 11 / serve must forward HumanEnrollments through its hosted-store wrapper and call the startup software-authenticator guard. No public RPC was added. |
| Initial admin_enroll | Atomic absent-baseline CAS, one private retained evidence object plus blob.committed, valid public credential shape, exact intent replay and global second-baseline refusal. Concrete InstallHumanEnrollment entry is supplied. | Integrate fix 11 must provide and authenticate the fixed administrator ceremony entry. Identity/admin own attestation, hardware UP/UV, administrator authentication and production software-authenticator policy. Later current-key changes retain identity's typed missing-ceremony refusal. |
| Mutation controls / handoff | 25 new controls plus 62 retained controls; all 94 edit anchors across 87 controls are unique. Pending-key control repaired without changing tests, diagnostic or checker. Current report and handoff updated. | 174 Linux red/candidate pairs and ten final package/tag suites remain unrun. The composed installed serve E2E remains the acceptance gate. |

## Exact integrate fix 11 names

The protected startup/identity inventory is the concrete store method below,
matching assembly/software_auth.go in serve commit 58d70272:

```go
HumanEnrollments(context.Context, string) ([]api.HumanEnrollment, error)
```

The string is the configuration ID. The inventory preserves revoked entries
and their raw credential/marker bytes. It is an in-process service-owned port;
it accepts no path or principal selector.

The concrete fixed-ceremony write entry is:

```go
InstallHumanEnrollment(context.Context, api.Scope, api.InternalIntent,
    api.EnrollmentInstall, api.ObjectWrite) (api.Commit, error)
```

Alternatively the ceremony may call the existing StateStore.Transact with
InternalAdminEnroll, one EnrollmentInstall and one ObjectWrite. Both routes
use the same writer and guards. Initial ExpectedGeneration is zero,
enrollment Generation is one, and CeremonyEvidence names the same atomic
nonempty bounded artifact. Its service-origin, service-owned owner-only ACL,
configuration and matching blob.committed event are required. The store
entry does not establish the ceremony's authentication, attestation or human
presence. Those are the remaining fix-11 ceremony entry obligations.

LAUNCH-PLAN.md also names RetainCapture, LaunchInventory,
LaunchControlIntent, RetainedProcess, RecordLaunchObservation,
RecordCaptureFailure and the independent IsolationEvidence wiring ports.
CONTRACT-GAPS.md retains each actual owner dependency.

## Static results and failure conditions

Host: Darwin arm64. Tools: Go 1.26.5, Python 3.13.11 and Bash 5.3.15.
Only the checks permitted by the brief ran on this Mac.

| Check | Scope and observed result | What fails the check |
| --- | --- | --- |
| gofmt -w | All 40 changed/new Go files; exit 0. Trailing blank lines were stripped from the changed documents as well. | Formatter error. Formatting-only changes are explicitly authorized. |
| Final gofmt -l | Same 40 Go files; exit 0, empty output. | A nonzero exit or any listed file. |
| Mutation source anchors | All 87 controls / 94 edits in 33 production files; every original and sequential count is 1. Pending-key scope and unchanged-test comparisons pass. | Missing/duplicate anchor, removed control, unrelated changed control/checker, changed test/diagnostic or mutation outside the intended pending-key region. |
| Linux go vet | GOOS=linux GOARCH=amd64; attempted once, exit 1 on existing Go-cache opens with operation not permitted. No passing compile/vet result. | Cache access refusal occurred before a useful analysis result. Full verbatim output is retained in vet-linux.log. |
| Linux faults go vet | GOOS=linux GOARCH=amd64 with -tags laneboss_faults; skipped under the brief's explicit cache-refusal recovery. | Not run; no pass is claimed. |
| Darwin go vet | GOOS=darwin GOARCH=arm64; skipped under the same explicit recovery. | Not run; no pass is claimed. |
| python3 -m py_compile | scenario.py, mutations.py and run.py in this service case; exit 0. Bytecode is retained outside the checkout in the evidence round. | Invalid Python syntax or a nonzero compiler exit. Project modules were not imported or run. |
| bash -n | run.sh and run-mutations.sh, checked individually; each exit 0. | Invalid shell syntax or a nonzero parser exit. |

The attempted vet command was:

```sh
GOOS=linux GOARCH=amd64 go vet ./internal/v2/client/... ./internal/v2/service/... ./internal/v2/store/... ./internal/v2/cli/...
```

The two skipped variants use that same package scope. No cache setting was
changed and no alternate cache, bypass or repeat was attempted. The supervisor
must run all three variants in its permitted environment.

No tests, product binary builds/execution or project interpreter execution ran
on the Mac. No before/after red credit, Linux runtime result, installed-service
launch, native helper/capture, authenticated AI-service or hardware-presence
measurement is claimed. Component fixtures retain explicit data and transport
identities; the installed acceptance gate remains outstanding.

## Retained evidence

The fresh protected round is
lb-v2-service-evidence / d4fix9-anchor-recovery-e4e125c. The prior failed round
d4fix9-e4e125c remains unchanged. The recovery retains exact brief/addendum
bytes, pre-recovery and final candidate source including untracked files,
source inventories, diffs/status, literal parser and 87-control inventory,
all anchor counts, the isolated pending-key mutant and its scope result,
command outputs/exits, the cache refusal, skipped-variant records and a final
manifest with hashes. No tested product binary exists in this static-only
round.

The source and permitted non-vet static work are ready for supervisor review.
Compilation, Linux runtime controls and composed installed acceptance are
still required; this candidate has not been accepted, staged or committed.

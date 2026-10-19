# Group merge resolution

The working tree resolves the supplied no-commit merge of group candidate
354cd86 into service HEAD
4d84291. The index entries are unchanged from
entry. No git add, commit or merge command ran; the three unmerged paths remain
in the index for the supervisor to stage and conclude. The working files have
no remaining conflict markers.

## Files

| File | Resolution |
| --- | --- |
| internal/v2/api/plan_cleanup.go | Exact incoming stage-3 shared-owner file, blob 880c807. It retains ValidateFailedPlanWrite and its correlation/shape/complete-batch preflight. The earlier service copy is superseded. |
| internal / v2 / service / launch_control_stubs.go | Removed after retaining its supplied bytes. Real launch-control methods remain in launch_control.go. |
| internal/v2/service/stub.go | Exact service-side file, also identical to serve2 6a019007. One IsolationEvidence dependency remains; the duplicate interface from the stub branch is omitted. The actual artifact-hashing constructor and service methods remain. |
| internal/v2/service/launch_control.go | Existing real Probe retained unchanged. It checks context and installed controlScope, selects the independent dependency/helper port, preserves a typed missing-provider refusal and returns the actual provider result/error. Its method matches serve2 6a019007 exactly. |
| internal/v2/service/server.go | Real NewServer and installed constructor path retained unchanged. |
| internal/v2/assembly/assembly.go | Existing wiring retained: both service.New and service.NewServer receive IsolationEvidence: helper. The helper receives the protected runtime/launch inputs. No adapter invents availability. |
| internal/v2/service/probe_test.go | Exact resolved serve2 6a019007 fixture. It uses an explicitly verified component host/controller for delegation, checks original errors and changing unavailable/successful result data, and separately refuses unverified, controller-less and closed hosts. |
| e2e/v2/cases/admin/mutations.json | probe-service-port reanchored exactly to the serve2 real Probe row. All 333 unique IDs remain, with the fix-12 union intact and no unrelated row change. Its ID, selector and deciding assertion remain. |
| e2e/v2/cases/admin/mutate.py | The single allowed service file changes from the removed stub to launch_control.go, as in serve2. Other ownership, root/tag, source-integrity and runtime qualification checks remain. |

The eight checked administrator provider/worker files are byte-identical to
354cd86: isolation.go, isolation_other.go, proof_linux.go, proof_store_linux.go,
canary_linux.go, worker_native.go, worker_fds_linux.go and worker_linux.go.
Their incoming and working blob hashes are retained in provenance.json.

## Additional merge break and deciding checks

The incoming TestProbeEvidencePort built an unverified Server with no execution
controller. The real Probe correctly refuses such a host before entering the
provider. The fixture now uses the exact resolved serve2 form, preserving the
production guard. TestProbeInstalledScope separately verifies every unready
state with zero provider calls.

Removing the obsolete stub also invalidated the administrator control's file
target and single-file allowlist. Both now refer to the actual delegation in
launch_control.go. The deciding diagnostic remains acceptance: service probe
invented or discarded independent evidence. The new target anchor matches
exactly once. Only this one of the 333 union rows changed.

TestProbeEvidencePort additionally rejects forced availability at service
probe replaced unavailable measured evidence with availability and changed
successful data at service probe changed the independent provider's successful
result. TestProbeInstalledScope rejects missing host guards at unready service
host entered the independent isolation provider. These are component checks;
no fixture claims real installed isolation measurements. Deciding Linux
red/candidate and installed G5/G6 results remain required.

## Verification

Candidate-only go vet ./... passed with exit 0 and empty output for Linux amd64
and arm64, normal and laneboss_faults, plus Darwin arm64 and amd64. Every Go vet
used GOCACHE=/private/tmp/lb-shared-gocache, GOWORK=off, GOPROXY=off and
GOSUMDB=off. No additional compile/vet break was found in this complete matrix.
gofmt -l, Python py_compile, git diff --check and exact source comparisons pass.
No tests, product binary builds, project interpreter execution, mutant
compilation/vet, cloud jobs or additional agents ran on this Mac.

Evidence is retained under lb-v2-service-evidence / group-merge-4d84291, including
both input source archives, exact governing inputs, incoming/owner sources,
index snapshots, resolved candidate source, command results, source comparisons,
control reanchor and verified manifest. No product binary was built in this
static-only round, so there are no tested product binary bytes/hash to claim.

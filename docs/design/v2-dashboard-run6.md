# HTTP review fixture correction

The Linux baseline at revision 1c05de0 failed TestHTTPControlsAndSSE at the
accepted transition in both builds. Source inspection identified a reviewer
binding mismatch: proof staging can replace the fixture's latest connection,
while the cookie remains bound to the original authenticated read session.
The shared acceptance validator compares the review actor with that session's
actor. Its launch-reservation recovery text is the generic invalid-request
hint, not a separate diagnosis of a missing launch field.

The fixture now resolves the reviewer through the established session ID and
checks it against the authenticated resume actor and connection. The actual
resume frame, consumed proof, operation and previous lane are retained. A
synthetic reservation, enrolled project/runtime, grants, workspace/session,
capture binding, canonical spec and exact recovery record follow the current
API and runner test fixtures. Shared reservation, enrollment, plan and recovery
validators remain active. All referenced objects retain their actual bytes and
hashes in the in-memory fixture. Identity and end events are retained and the
review subject derives its launch, snapshot, session and capture from the plan.
These synthetic records do not prove an installed service or a real process.

TestHTTPControlsAndSSE retains the fabricated-review refusal and the real
HTTP proof/transport/dispatch calls for accepted and merged. Both positive
steps now also assert the resulting state and generation; merged checks the
authenticated actor and dashboard source. Its retained subtest compares exact
resume bytes, decodes and compares retained launch/recovery objects, and checks
source enrollment and identity/end event bindings. Its reviewer subtest sends
a service-recorded review from the staging principal through HTTP and requires
the shared independent-review refusal without changing lane state.

The six added controls name the deciding assertion:

| Control | Named regression | What makes it fail |
| --- | --- | --- |
| d6-review-principal | TestHTTPControlsAndSSE | Restoring the latest staging principal makes shared review acceptance reject the fixture. |
| d6-review-original | TestHTTPControlsAndSSE/retained | Replacing retained resume bytes with an empty object loses the exact HTTP frame. |
| d6-review-sources | TestHTTPControlsAndSSE | Removing the enrolled project source makes the shared launch-plan validator refuse. |
| d6-review-recovery | TestHTTPControlsAndSSE | Removing the recovery's original request breaks its exact reservation binding. |
| d6-review-actor-gate | TestHTTPControlsAndSSE/reviewer | Checking against the receipt's own actor admits the staging-principal review through HTTP. |
| d6-mark-state | TestHTTPControlsAndSSE | Returning an operation without changing the lane to accepted fails the state assertion. |

All added test paths are shorter than forty characters. The existing run-5
controls and approved source changes remain intact. No production service
code, API validator or acceptance rule was changed. The fixture's unimplemented
launch ports still return their owning failure.

Only static checks are authorized on this Mac. Candidate tests and all six
red controls require the supervisor's disposable Linux environment. A compiling
mutant must reach its named assertion before the candidate passes; source
inspection alone does not establish either result. No build, test, project
interpreter, renderer, browser, cloud machine or real model request ran here.
The run-6 external evidence retains the exact brief, Linux baseline log, full
baseline revision/source, final overlay and patch, hashes and check outputs.

Observed static results: gofmt -w completed for the three changed Go files;
gofmt -l printed no paths and git diff --check printed no errors, both with
exit 0. Source inspection found 126 unique control IDs, test paths at most
34 characters long and one match for every mutation anchor. Linux go vet
exited 1 because opening the default Go cache returned operation not permitted.
The brief's explicit recovery route was followed: no cache change or retry,
and Linux/faults and Darwin vet were skipped. No passing Go type-check or
candidate/red runtime result is claimed.

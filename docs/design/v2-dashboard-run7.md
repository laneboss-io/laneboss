# Remaining dashboard review corrections

This overlay starts at a41251f. It addresses the open timestamp portion of
earlier review item 5 and the four new findings in the second re-read. The
review considered pagination and snapshot/mail replay guards fixed; those
guards and their existing controls are retained. Source corrections do not
establish a green Linux candidate or a new review approval. Landing still
requires the supervisor's green box and Gemini approval.

| Review item | Resulting source behavior | Regression and deciding assertion |
| --- | --- | --- |
| New 1: fixture connection rotation | Only a human.challenge for human.session rotates a previously authenticated staging connection. Operation challenges preserve it. The run-6 reviewer still comes from the established read session, independently of a later genuine authentication ceremony. Both diagnoses are addressed. | TestDashProofBinding covers stop, resume, mark, mail and a new session challenge, then confirmation, unchanged original session facts and a usable original cookie. TestHTTPControlsAndSSE explicitly starts a second session ceremony before constructing the review, preserving the run-6 principal control and both real accepted/merged HTTP transitions. |
| Item 5 / new 2: tree filters | Configuration membership is collected unconditionally. Untimed static rows are excluded when time or lane selectors are present; matching live lanes retain their configured instance identity. | TestDashTreeBounds uses policy and bootstrap sources, Since, Until, both bounds, life/run/driver selectors and their combination. A one-row page must contain the correct live lane with no cursor or leaked static row, and retain Configured and InstanceID. Out-of-range queries are empty. |
| Item 5 / new 3: resource observation | State generation and the generation of a known observation are tracked separately. An unchanged digest keeps actual observation history across policy advances, including a published snapshot and multiple historical observations. A changed digest cannot inherit another content version's timestamp. Deletion retains its version fence. | TestDashResourceTimes exercises scripts and plugins with applied/bootstrap history, multiple observations, different hashes, absent/invalid times, published snapshots, snapshot precedence and deletion followed by older replay. It checks exact time, digest and state version before testing each time-bound form. |
| New 4: lane observation | The latest valid service timestamp is chosen by its own event sequence, independently of Store.Lanes.LastSeq. All five launch event kinds can resolve an omitted envelope life ID through their decoded lane. Newer snapshot state remains intact. | TestDashLaneTimes checks a snapshot ahead of history, all five launch kinds, unknown/invalid times, a later invalid timestamp and untrusted origin. Exact reconciled time and state are checked before lifecycle/tree bounds. TestDashTimeOrder checks both event orders. |

Neither resource nor lane reconciliation invents a timestamp from the current
clock. Missing or invalid observations remain unknown unless matching real
history supplies a valid time. The bounded views continue to exclude unknown
times. An earlier observation is retained independently of a newer untimed
state record; it is not presented as a newly measured observation.

Fourteen new source controls retain a named failure before the candidate can
pass on Linux:

| Control | Named regression | What makes it fail |
| --- | --- | --- |
| d7-proof-operation | TestDashProofBinding/lane.stop | Broad challenge rotation changes the authenticated connection. |
| d7-proof-session | TestDashProofBinding/human.session | Selecting another method for rotation reuses the old session connection. |
| d7-tree-static | TestDashTreeBounds/policy/since | Removing time selectors from the static-row exclusion leaks an untimed configured row. |
| d7-tree-membership | TestDashTreeBounds/bootstrap/both | Filtering the membership lookup removes the live lane's configured identity. |
| d7-resource-time | TestDashResourceTimes/applied_script | Omitting observation backfill loses the actual applied time. |
| d7-resource-latest | TestDashResourceTimes/latest_plugin | Filling only once retains the oldest matching history instead of the newest. |
| d7-resource-hash | TestDashResourceTimes/digest_script | Dropping digest equality copies a different content version's timestamp. |
| d7-resource-published | TestDashResourceTimes/published_script | Dropping same-content timestamp retention loses the published observation on a policy advance. |
| d7-resource-default | TestDashResourceTimes/unknown_script | Filling a timestamp from the fixture clock replaces an unknown observation. |
| d7-lane-ahead | TestDashLaneTimes/ahead | Fencing observation time on snapshot LastSeq loses the last actual timestamp. |
| d7-lane-payload | TestDashLaneTimes/prepared | Omitting the payload life-ID fallback loses a launch observation. |
| d7-lane-valid | TestDashLaneTimes/bad_latest | Admitting an invalid later timestamp replaces valid history. |
| d7-lane-order | TestDashTimeOrder | Dropping the observation sequence fence lets older events replace newer time. |
| d7-lane-default | TestDashLaneTimes/unknown | Filling an absent timestamp with the wall clock fails the exact-time assertion. |

The six run-6 controls remain in the manifest, including restoration of the
wrong staging principal, removal of exact retained request/recovery evidence,
the independent-review gate and a mark operation without a state change. The
HTTP test's second authentication ceremony keeps that principal control
meaningful after operation challenges stop rotating connections.

Only static checks are authorized on the authoring Mac. No Go test, build,
project interpreter, renderer, browser, red mutant, remote access, machine or
model request was started here. All new controls require Linux execution:
their mutants must compile and reach the nominated assertion before their
candidates pass. A compile error, skip or unrelated failure is not a red pass.
No staging or commit was performed. The external run-7 evidence retains the
exact brief and review, baseline revision/source, final overlay and complete
patch, source hashes, static-check output and evidence manifest.

Observed static checks: gofmt -w completed for the four changed Go files;
gofmt -l printed no paths and git diff --check printed no errors, both with
exit 0. Static inspection found 140 unique controls, one match for every
mutation anchor and 54 new source-inferred test paths, all at most 38
characters long. This is not a compiled test inventory or a runtime result.
Linux go vet exited 1 at the default Go-cache boundary with operation not
permitted. Following the explicit brief, the remaining Linux/faults and Darwin
vet variants were skipped, with no cache change or retry. No passing Go
type-check or candidate/red execution is claimed.

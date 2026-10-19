# Migration catch-up 4

Lane names now pass both the unchanged opaque-ID check and legacyArgument at
plan-time legacy validation and at PrepareRelaunch entry. The new fixtures use
option-shaped lane names with the explicit valid branch safe/branch. They
exercise plan validation, the relaunch option guard independently of target
selection, and a matching stored target that would otherwise reach adoption.
All cases require invalid_request at legacy.lane, after accepting valid input.

Plan-time missing/invalid legacy fields still refuse the whole source. The
error now names the affected lane and preserves its typed code, field, owner
and recovery guidance. Multi-lane fixtures check missing required values and
all six non-string payload fields; a valid second lane cannot mask the error.

Rollback reads retain descriptor-relative no-follow regular-file checks and
now enforce api.MaxObjectBytes (64 MiB) per file, including the old binary.
The size is checked before allocation; a limited reader and a second size
check also refuse growth beyond the cap during the read. Sparse-file fixtures
cover small input, the exact boundary and one byte over. This is a per-file
bound; aggregate tree size and file count are not bounded by this change.

| New control | Focused test | Removed protection |
| --- | --- | --- |
| mut-r4-lane-plan | TestReviewLaneArgument/plan | Source lane argument shape |
| mut-r4-lane-option | TestReviewLaneArgument/option | Relaunch lane argument shape before target lookup |
| mut-r4-lane-adopt | TestReviewLaneArgument/adopt | Both lane argument gates on a matching target |
| mut-r4-plan-lane-missing | TestPlanLaneErr / missing-session_id | Lane identity on shape/missing-field errors |
| mut-r4-plan-lane-type | TestPlanLaneErr/type-branch | Lane identity on non-string payload errors |
| mut-r4-rollback-size | TestReviewRollbackReadLimit/oversized | Pre-read and streamed size enforcement |

The two affected older controls follow the strengthened lane predicate and
the contextual type-error message. All original controls remain, for eleven
original plus 71 review controls (82 total). The README and both catalog count
guards use that inventory. Runtime assertions and reached-red/candidate-green
results remain for the supervising Linux run; Mac verification is static only.
The 42-case baseline regression run remains a separate acceptance gate, with
its split baseline revision unchanged. Other deferrals in CATCHUP2.md remain.

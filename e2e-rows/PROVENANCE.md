# External lifecycle projection rows

These are standalone CLI rows for an already built release binary on the
disposable Linux test host. Run no tests or product binaries on the development
Mac. The runner is a stand-in, with real launcher starts, stored events,
process records, mail bytes and cleanup. It does not contact an AI service.

Lifecycle observations remain valid projection input. The store replaces a
claimed actor with `event.append:<authenticated principal>`, covered by its
existing event hash. Payloads, envelope shape, SQLite schema and validation
order stay compatible. The reserved actor namespace is not a principal ID.
Only the authenticated human and configuration-resolved L4-L6 supervisory
roles may append lifecycle kinds. Lane callers are refused for both their
own name and another lane, with an instruction to report up. Existing payload
and replay-scope validation runs before this access check. Observations still
reduce into the same display projection when allowed by the lifecycle gates.
Run-advancing starts, resumes and adoptions are refused once the launcher has
recorded that name, with `Instead: use lane start, resume or turn`. Names the
launcher never launched still accept these observations. The prior residual
for external ends/losses is withdrawn: `lane.ended`, `lane.lost` and `lane.gone`
also refuse for launcher-recorded names, with an instruction to use lane stop
or lane check after the supervisor is gone. Timeout and stuck only record
observations; they do not close or settle a run and remain unchanged.
Caller identity, report lines and ancestry ignore these observations. An
external-only projection cannot authorize reuse. An existing external
projection supplies only a target name to the permission check, with no level,
starter or recorded node. After that check, `lane send` requires a launcher-made
run. Humans and qualifying local supervisors therefore receive exit 2 for an
external-only target, with unchanged events and mail directory. An appended
runner that cannot take turns selects the runner-capability refusal; otherwise
the exact refusal is `lane X has not run yet, so it takes no mail` followed by
`Instead: lane adopt the running session, or lane start --turns`. L3 lane senders
remain refused by the permission check; claimed ancestry grants nothing. The
same L3 sender must also receive `may not message` for a launcher-made lane
under another supervisor, so the no-run gate cannot mask that boundary.
Launch, signal, archive and clean readers reconstruct their operational state
from launcher events; append/replay and display keep the full projection.

The observation fixture deep-copies its actual control start. When it claims
a starter, the optional settings delegation names that same starter; when it
claims no starter, it omits that optional delegation record. Settings values,
layers, source bytes and allowlists stay copied from the real start. The
starter-less resume uses the same copy rule. This keeps the forged input
valid before testing authority, without changing the genuine control record
or removing the assertions about origin, identity, ancestry or delivery.

Keep each row separate. All names below belong to
`test_legacy_lanes.CurrentLaneRows`:

| Method | Required check and release-head failure |
| --- | --- |
| `test_append_grants_no_legacy` | A starter-less resume for the real lane is refused without a state change; unrelated `top-a` remains refused with `may not message`, and `mini-a` delivery stays non-legacy. A separate never-launched observation retains the external-origin control and tagged origin mutant. |
| `test_append_grants_no_identity` | A forged start cannot identify an unrelated headless process claiming its lane label; the real-lane control still receives exact bytes. The release head refuses the input before this check. |
| `test_append_grants_no_ancestry` | A forged starter does not authorize descendant collection; the real L4 control still launches an actual L3 child with its own recorded starter. The release head refuses the input. |
| `test_append_grants_no_reuse` | An ended, abandoned external projection cannot authorize a human `lane start --reuse`; no runner starts and no event is appended. The release head refuses the initial lifecycle input. |
| `test_dashboard_marks_external` | An ordinary `lane.state` append appears with `externally_appended: true` and a visible label; a genuine launcher start is unmarked. This append succeeds without a fault on the release head, whose dashboard lacks the external-origin mark. |
| `test_ledger_marks_external` | The same append has a labelled external lifecycle row in JSON and text without adding a completed task. On the release head the fault-free append succeeds but the ledger omits the labelled row. |
| `test_human_external_target` | The human reaches an external adoption's empty turn. Human and registered-supervisor sends require exit 2 with the exact no-run refusal and recovery text, without changing events or mail. An L3 lane remains refused with `may not message`, including forged starters naming its supervisor or itself; the same sender is also refused by the permission boundary for a launcher-made lane under another supervisor. The release head refuses the adoption. |
| `test_lane_life_refused` | An actual L3 runner cannot append lifecycle events for itself or a second running lane, and no events change. On the prior provenance snapshot the harmless first `lane.planned` append succeeds, failing the named permission assertion without corrupting the live fixture. On the fix the row also reaches the ended and next-run probes. |
| `test_supervisor_life_append` | Registered L4, L5 and L6 harness supervisors append real state observations with exact payload and origin. Then `lane clean` still refuses the launcher's waiting lane with no event or worktree change, and the human records the real decision. The release head honours the appended state and fails the clean refusal. |
| `test_running_stoppable` | Human and L4-L6 attempts to append ended/lost/gone for a real running lane must fail with `run-closing append was accepted` naming a missing gate. Events stay unchanged, the next-run append also refuses, then real stop exits 0 with zero survivors and the runner PID disappears. |

Run against the release head first, retaining each named failure; then use the
fixed binary and require exit 0, with no errors or skips. The origin-view rows
must fail on their missing-mark assertion, not on setup or append. Set
`LANEBOSS_ROW_EVIDENCE` to an absolute directory outside the checkout so the
fixture retains its inputs and state before cleanup.

```sh
release_bin=/absolute/path/to/cli
row_evidence=/absolute/path/to/rows
LANEBOSS_BIN="$release_bin" \
LANEBOSS_ROW_EVIDENCE="$row_evidence" \
python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py -k CurrentLaneRows -v
```

The focused Go checks are in these packages:

| Package | Function |
| --- | --- |
| `event` | `TestLifecycleAppendAuthorized` |
| `event` | `TestMessageAppendStillRefused` |
| `event` | `TestLifecycleLaneRefused` |
| `event` | `TestLifeValidationFirst` |
| `event` | `TestAdvanceGate` |
| `event` | `TestClosingGate` |
| `eventstore_test` | `TestExternalLifecycleStoredOrigin` |
| `eventstore_test` | `TestExternalStartValidationOrder` |
| `caller` | `TestExternalStartNoIdentity` |
| `caller` | `TestExternalStartNoAncestry` |
| `caller` | `TestExternalStartNoLegacy` |
| `report` | `TestHumanExternalProjectionTarget` |

They check actual store reads,
hashes, duplicate receipts, rebuild, validation diagnostics and authority
decisions, with genuine unmarked controls.

In package `lane`, `TestLifecycleAuthorityIgnoresProjection` checks the latest-life reader
and operational projection against the real event store, while the display
retains the external run. It also checks that launching with a divergent public
run counter refuses before execution. As an extra mutation check, the
one-line mutant in `internal/lane/provenance.go` changes
`return owned, nil` in `launcherEvents` to `return events, nil`. This restores
the unfiltered observation stream to authority readers. The direct-store
unit must fail at its named reader safety assertions;
a setup or compilation failure is not a kill. No such mutant or canary was
executed on the development Mac.
The CLI rows now reject the forged advance before operational reads. Removing
that new gate fails their append-refusal assertion. The reader-only mutant
can leave those CLI rows green because the earlier append boundary still holds.
This mutant does not remove the separate caller, mail-target or view filters.
Identity, ancestry, legacy and target rows still test those boundaries with
valid observations; their matching filter changes are separate mutations.
The launcher clean control remains a positive control.

The authority rows use module `test_legacy_lanes`, class `LifeRows`. Each has
its own fresh fixture and one operation under test:

| Method | Named base failure |
| --- | --- |
| `test_clean_blocks_forgery` | `clean removed the appended worktree` |
| `test_archive_blocks_forgery` | `archive removed the appended worktree` |
| `test_reuse_blocks_forgery` | `reuse used the appended session or worktree` |
| `test_resume_blocks_forgery` | `resume used the appended session or worktree` |
| `test_clean_launcher_control` | Positive control: a real launcher decision removes its own worktree/branch and archives the exact output bytes. It should pass on both trees. |
| `test_diverged_recovery` | The forged advance must be rejected before divergence. The row then exercises human abandonment and a new name, checks the actual new cwd/session, preserves the appended target and cleans the new lane. The base fault path fails the retained resume protection. |

On the fixed head, each attack row now requires the run-advancing append to
be refused with the new instruction and no event, runner or target change.
It then returns after those complete safety assertions. Only the exact old
release refusal permits the base-only fault seam and the operation path below.

The first four start and end a real run 1 but do not give it a real collection
decision. They create a second real worktree/branch with a same-lane fixture
claim, then append a run 2 naming it. The same claim prevents the foreign-claim
guard from masking the life-selection probe. No SQL or product output is faked.

Setup always tries plain `event append` first. Only an exit 2 whose first
diagnostic line is exactly the base lifecycle refusal permits retrying that
one input with `LANEBOSS_FAULTS_BIN` and `event-allow-started`. Its real fault
marker is required. On the fix plain append refuses, and the fault binary is
never used. `append-path.json` retains `blocked` or `base-fault`, both command
responses where relevant, and the original input remains in its advance file.

The base also refuses hand-appended end events. Both setups therefore use
normal `lane check` against the genuinely ended supervisor record, then append
`lane.state` abandoned. This settles the observed run without another fault
or a direct store write. The runner captures its actual working directory,
session and stdin outside the worktrees. Resume/reuse must not execute there;
archive/clean must not remove the named worktree or branch. The raw command
result and Git/runner observations are saved before the safety assertions.

Run the same row bodies first with the base pair and then the fixed pair:

```sh
release_bin=/absolute/path/to/cli
fault_bin=/absolute/path/to/faults
row_evidence=/absolute/path/to/rows
LANEBOSS_BIN="$release_bin" \
LANEBOSS_FAULTS_BIN="$fault_bin" \
LANEBOSS_ROW_EVIDENCE="$row_evidence" \
python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py -k LifeRows -v
```

Require each attack row to fail on the base for its named operation effect,
and to pass on the fix after a refused plain append. The launcher-made clean control
must pass on both. A failure of setup, the marker or cleanup is incomplete
evidence. Retain `after-operation.json`, `operation.json` where present, the
full fixture and the exact built binary bytes and hashes outside the checkout.
The recovery row requires the rejected advance, then retains the human
decision, new start and clean responses. The release head fails at the
operation protection assertion. The projection remains shared; closing a
launcher-recorded run must come through its lane commands.

For the tagged process fault, `lane.TestProcFaultReachesLaneReader` calls the
real caller reader before the lane reader. It fails if the caller consumes
either one-shot error, if wrapped ESRCH is not treated as an exited process,
if EACCES is not refused, if the fault marker does not name `lane.linuxInfo`,
or if the following read is not real. The private wrapped-ESRCH mutation stays
unchanged. Run these packages with and without `laneboss_faults` on Linux:

```sh
GOTOOLCHAIN=local go test ./internal/event ./internal/eventstore ./internal/caller ./internal/report ./internal/lane
GOTOOLCHAIN=local go test -tags laneboss_faults ./internal/event ./internal/eventstore ./internal/caller ./internal/report ./internal/lane
```

Static checks on the Mac do not establish any red/green test result. Both Linux
test runs and the separate security review are required before acceptance.

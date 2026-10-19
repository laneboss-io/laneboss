# Layered settings rows and red controls

These rows execute on the disposable Linux test box. The executor lane runs only
formatting, vet and Python syntax compilation on macOS; laneboss owns the box
run. None of the controls below is a measured pass until its real transcript,
exit code, inputs and retained binaries are available.

Build the current source as the release CLI and with `-tags laneboss_faults` on
the box. Also supply an actual pre-settings CLI, for example from revision
`19292aa`, for the historic-lane row. That row starts a real lane using the old
binary and asserts that its start response has no settings snapshot. It never
removes a field from an event or edits SQLite to create historical state.

Run the supplied-binary checker with absolute paths:

```sh
sh e2e-rows/check-layered-settings.sh /absolute/laneboss /absolute/laneboss-faults /absolute/laneboss-pre-1.0
```

Exit 0 and `PASS: layered settings` are both required. The checker retains the
three binaries and their hashes, source archive, original fixture bytes, CLI
inputs/outputs, actual lane state and the mutant verdicts. The runner reads the
actual prompt and prints environment names only. Descendant CLI/hook calls run
inside its real recorded process ancestry; responses come from subprocess output.
They are not canned permission decisions. The fixture never calls an AI service.

The org hook uses blacklist behavior for both `blacklist` and deprecated
`strict` sources. Strict-source renders and validations require one deprecation
warning. Protected settings files keep their exact built-in
`[blacklist:laneboss-files]` refusal; explicit tool denies, deny unions,
snapshots, historic-lane behavior and environment-grant ceilings remain tested.

Eight rows whose only purpose was enforcing or refreshing a tool allowlist
have been removed: `test_hook_tool_allow`, `test_delegate_tools_refused`,
`test_role_grant_refused`, `test_empty_starter_refused`,
`test_resume_owned_grant`, `test_resume_tools_widened`,
`test_turn_tools_widened`, and `test_turn_tools_narrowed_legacy`.
The tool-only subcase of `test_resume_grants_refused` is also removed.
Their obsolete mutant entries are absent from the tables below.
`test_hook_deny_beats_allow` remains a deny row, covered by the deny-skipping
mutant. Data-shape compatibility rows may retain `allowed_tools` or
`tool_allow_add` fields without treating them as permission grants.
The decision-guide B6 row covers ignored legacy allowlists and incomplete
observations under strict, blacklist and unversioned hook sources.

The mutant meta-rows run a named suite for each actual fault and compare the
failed row names to its complete expected list. Each named row must fail once
by its own assertion message, and must reach its own mutation marker. Missing,
unexpected or duplicate failures, including cleanup failures, fail the gate.
The message comes from the actual assertion exception, so a matching phrase in
a traceback's source line cannot count as a kill. The same complete named
suite must pass after restoration, with no errors, skips or expected-failure
annotations. The environment-delegation mutants additionally observe the unlisted canary
name inside every relevant child. A normal environment-subset row is the control.

Each point's required suite is explicit below. The environment point covers
explicit and instance-derived grants. The tool-deny point covers a live
instance, matching ignored allow data, and a recorded lane.
Each suite writes its complete `POINT-red.json` before checking the failure
verdict, and `POINT-green.json` before checking restoration, so an unexpected
fixture failure retains its identity and traceback. Successful verdicts also
retain a separate `POINT-ROW.json` for every named row.

The mismatch assertion includes both complete sorted lists as explicit JSON in
its message, independently of unittest's shortened comparison or diff. Red
records and mismatch messages also name each failure's phase (`test`, `setUp`
or `tearDown`). A matching name and assertion from a fixture phase cannot count
as a kill. Queued fixture runners are released through their stop files, then
the existing bounded completion helper requires their actual successful exits,
quiescence, zero survivors and zero pending/refused events. This avoids racing
their normal exits with a later `lane stop` based on an older status reading.

| Point | Exact required failed rows |
|---|---|
| `settings-frozen-delegation` | `test_resume_env_widened`, `test_turn_env_widened`, `test_resume_revoke_refused`, `test_turn_revoke_refused` |
| `settings-inherit-env` | `test_environment_names` |
| `settings-paths-unprotected` | `test_settings_protected` |
| `settings-role-required` | `test_missing_role_allows` |
| `settings-short-instance` | `test_long_instance_allows` |
| `settings-tool-deny-skip` | `test_hook_tool_deny`, `test_hook_deny_beats_allow`, `test_hook_lane_snapshot` |
| `settings-history-live` | `test_hook_historic_lane` |
| `settings-deny-replace` | `test_deny_union` |
| `settings-delegate-env` | `test_delegate_env_refused`, `test_instance_grant_refused` |

The policy fixture supplies both required refusal-example arrays and still
requires actual rendering and org validation. The configuration-binding row
requires the binding-first refusal before a foreign configuration is read; it
does not assume that this guard uses the word "conflicts".

| Ordinary row | Regression or pre-fix red | Required failure |
|---|---|---|
| `test_settings_protected` | `64c496c`, or `settings-paths-unprotected` | A settings write in a declared L5 scope is allowed, so the protected-file denial assertion fails. An ordinary state write is the allowed control. |
| `test_missing_role_allows` | `64c496c`, or `settings-role-required` | A validated legacy org without `roles/` refuses an ordinary read, so the allowance assertion fails. |
| `test_long_instance_allows` | `64c496c`, or `settings-short-instance` | The actual hook refuses a 65-character instance before its ordinary read. The fixed row then renders and validates the org and resolves that instance's settings. |
| `test_hook_tool_deny` | Pre-settings `19292aa`, or `settings-tool-deny-skip` | The live file's deny is ignored and the actual hook allows Read. |
| `test_hook_deny_beats_allow` | Pre-settings `19292aa`, or `settings-tool-deny-skip` | The actual hook ignores an explicit tool deny because matching legacy allow data is present. |
| `test_hook_lane_snapshot` | Pre-settings `19292aa`, or `settings-tool-deny-skip` | The authenticated lane allows the recorded denied tool after a live file edit. The live instance is the opposite control. |
| `test_hook_historic_lane` | `64c496c` is already correct; `settings-history-live` supplies the red | A real pre-1.0 lane acquires a later live deny that was never recorded at its start. |
| `test_deny_union` | `64c496c`, or `settings-deny-replace` | An empty narrower definition clears the org deny. The fixed row also checks a role deny and a lane empty array in the effective union. |
| `test_delegate_env_refused` | `64c496c`, or `settings-delegate-env` | An L4 lane starts an L3 child with an undeclared environment grant. The canary value is generated in memory by the fixture and only its received name is observed. |
| `test_instance_grant_refused` | `97cb018`, or `settings-delegate-env` | Selecting a different instance supplies an unowned environment name without `--set`. The mutant must actually deliver the names-only canary. |
| `test_resume_grants_refused`, `test_turn_grants_refused` | `97cb018` | Re-resolution adds a role-derived grant outside the saved starter ceiling. Refusal must occur before a second runner call. |
| `TestEffectiveGrantBounds` | Compile this unit row with the `97cb018` implementation | Each inherited scope supplies an excess effective value while Overrides stays empty; the old check accepts it. The owned inherited control must still pass. |
| `test_runner_pinned`, `test_turn_runner_pinned` | `64c496c` | A file edit starts the other configured runner under the old session instead of refusing. Both configured runners use the permitted stand-in driver. |
| `test_launch_flag_screen` | The account cases fail on `64c496c` | A credential-shaped account choice reaches account validation instead of the credential screen. Every rejected canary must remain absent from stdout/stderr. |
| `TestOrphanOverrides` | Compile this added unit test with the `64c496c` settings implementation | Decode accepts an override that has no entry/lane winner. Valid empty and matching-override controls must still decode. |

The earlier release does not contain `settings get`/`list`, so the pre-settings
binary is used for the compatible hook rows and historical start, not for the
new command surface. The current fault-build controls avoid that fixture mismatch.
Run the changed packages' Go unit tests on the same box, including
`go test ./internal/settings`; run the shell check there as well. Retain the
base-red and restored-green command outputs before claiming runtime verification.

The grant-refresh and linked-source regressions use revision `949c43e` as their
actual failing base. On Linux, supply that built CLI as the release binary and
run these named ordinary rows with the same current fixture; retain each base
trace and exit before running the fixed release. The separate pre-settings
binary still supplies the historic row and is not this regression base.
Static inspection and the frozen-ceiling mutant do not replace the actual
`949c43e` red run. The new mutant restores the old carried ceiling at `Again`
and the old early return at `Bind`, so its required suite contains both
environment-widening rows and both revoke rows. Every row must fail by its own
named assertion and the complete four-row suite must pass after restoration.

| New row | Why it must fail on `949c43e` |
|---|---|
| `test_resume_env_widened` | Resume refuses the newly org-owned environment name instead of satisfying `resume must apply owned env_allow widening`. |
| `test_turn_env_widened` | Turn refuses the newly org-owned environment name instead of satisfying `turn must apply owned env_allow widening`. |
| `test_resume_revoke_refused` | The old ceiling admits a retained environment override after its starter loses that name; `the next run must refuse a revoked explicit grant` fails. |
| `test_turn_revoke_refused` | The old ceiling admits that revoked override on a turn, failing the same refusal assertion. |
| `test_linked_org_source` | An in-root final-component org symlink is followed, so `a linked org settings source must be refused` fails. |
| `test_linked_role_source` | Configuration loading already refuses the role link, but the instance session's live hook follows it through the old reader; `a linked source must fail the live hook closed` fails. |
| `test_linked_instance_source` | The instance source symlink is followed, so `a linked instance settings source must be refused` fails. |

Every environment-widening row starts without the added grant, delivers it in
run 2, then removes it for run 3. Observations come from actual runner names.
Tool allowlist data does not restrict any hook call. Every linked row first resolves a
regular file and confirms an ordinary allowed hook, then requires both the
linked-source read and lane start to refuse and the live hook to deny. No row
edits stored events or supplies an invented permission decision.

The fail-closed regression rows require actual base reds on `d891278`. The
executor has authored these rows but has not run them on macOS; the authorized
Linux run must retain both the base failures and restored results.

| Row | Named base failure |
|---|---|
| `test_removed_starter_resume` | `resume must refuse delegation from the removed starter`: the base reuses its previous ceiling, starts run 2 and exits 0 instead of refusing. |
| `test_removed_starter_turn` | `turn must refuse delegation from the removed starter`: the base likewise starts a resumed turn under the previous ceiling. |
| `test_removed_instance_starter_resume` | `an instance starter's removed grant must be refused`: the recorded `instance:stream-starter` no longer resolves, but the base resumes with its past ceiling and exits 0. |

The two lane-starter rows start an actual L4 caller while the org grants `LAYERED_ALLOWED`, then
removes the org grant before that caller creates its L3 children. The parent's
recorded run alone owns the name. Current child settings explanations must show
only the empty org grant and base, with no role or instance grant. The named
child retains an explicit selection of that delegated name; its sibling selects
no additional names. Both children are created by real descendant CLI calls.
Every child resume, send and turn also runs through the actual starter lane's
queue. That lane stays alive until teardown, including after its instance is
retired. Its recorded process ancestry authenticates the permitted parent/child
message path before the delegation gate. `supervisor:top` never sends those
follow-ups, so its unrelated messaging refusal cannot stand in for a base red.

After the starter's instance is retired, the existing L5 own-instance hook
control must still allow an ordinary state write. The child's next resume or
turn must refuse with the exact first line and `Instead:` route, leave the run unchanged,
start no runner and retain a `settings-delegation` refusal whose native log bytes
match the actual CLI output. The sibling without delegated names must resume
successfully before any owner re-grant. This detects blanket resume refusals.

The owner then grants `LAYERED_ALLOWED` only in the current org file. The row
checks the actual settings provenance, retains the child's original override,
requires run 2 with the same session and observes delivery of the name in the
real runner. The starter's instance stays absent. Removing that fresh org grant
must refuse again, with a second retained refusal and no third run. This makes
recovery depend on a current owner grant rather than an old ceiling or another
pre-existing source.

`test_adopted_turn_resolvable_starter` replaces `test_adopted_turn_fallback` as
an allowed control, expected to pass on `d891278` too. It adopts a real stale
session record through an authenticated L4 descendant and requires the actual
adopter's `lane:settings-lane` identity in both the report line and limits. The
starter's instance remains attached and resolves before each of two resumed
turns. Both must deliver the granted name with the supplied session identity
and no fallback notice. An excess name inherited after adoption must still
refuse, so skipping the adopted starter check cannot satisfy the row. No row
inserts an event or edits the store. Adopted sessions continue through
send/turn, as the release contract requires.

`add_runner` serializes dictionaries as TOML inline tables with `=` assignments,
including each `records` entry and its nested path array. It parses the complete
result with `tomllib` and requires the new runner to equal the intended command,
resume and records structure before writing it. The adoption row still supplies
and requires its real session-record path; removing records is not a fixture fix.

`test_removed_instance_starter_resume` creates a lowercase L4 org instance with
the actual `org instance add` command. The briefing CLI's name validator rejects
uppercase `L4-stream` before caller registration; a label alone cannot supply
identity. The existing `caller.Role` binding supports a lowercase instance name
on both `d891278` and the current binary. The row asserts that `stream-starter`
has no `[supervisors]` entry, then runs a real pipe-only parent from its instance
directory with `LANEBOSS_INSTANCE=stream-starter`. The real `start --role`
command records its process binding before it starts the child. Both the report
line and settings limits must name `instance:stream-starter`, so a configured
supervisor or lane identity cannot pass. Only that instance's settings grant
the environment name. A separate real
controlling terminal issues the child's follow-up; the test parent stays
unregistered so an inherited supervisor identity cannot mask the human. Removing
the instance must reach the `settings.Instance` failure path and produce the
exact recorded refusal without a second runner call. A fresh org grant must
then resume the same session and actually deliver the name while the instance
remains absent. The shared headless and terminal helpers execute the supplied
binary and preserve its output; the checker retains their source with the rest
of the input archive. No role label or invented session record supplies identity.

The public `test_account_value_never_echoed` mirrors the account refusal row:
an actual `lane start --account` with a synthetic token-shaped value must refuse
with the original account problem and the configured account alternatives,
without repeating the rejected value or calling the runner. Starting the same
lane with a listed account must work. A later resume with the token must also
refuse safely, leave run 1 unchanged, call no second runner and append no resume
event. `test_turn_account_value_never_echoed` exercises the corresponding turn
request. Both rows then put the synthetic value in the actual role source and
require credential refusal before restoring and validating that source.

The account rows require base reds on `4b6d73c` at `account requests must retain
the original known-account refusal`: the old launch-choice screen instead emits
an org-role credential error with no known account names. The token is generated
by the fixture; no service credential is used. Account request flags reach the
runner's existing account validator before any run is recorded. Screening of
real org/role/instance files and `--set` input is retained. The remaining launch
choice credential checks stay in `test_launch_flag_screen`.

The room controls use a real configured command backed by
`fixtures/layered_room.py`. It reads a retained account-to-answer input file and
records each actual probe. The runner can also record the actual rendered
`{account}` argument, so a response's account field alone is not enough to pass.
`test_turn_room_automatic_account` starts without an account request, then
requires the command to probe the previous account with no room and the next
listed account with room, in order. The turn must record the latter with
`chosen_by.account: room`, keep default account provenance and deliver that
account to the real runner in the same session. A later turn requesting the
full account explicitly must refuse after probing that account alone.

`test_turn_room_explicit_setting` starts with `--set account=...` and requires
the next unnamed turn to retain that setting and refuse when it has no room,
even though another listed account does. These are allowed controls, expected
to pass on `0367cee` too; they must not be reported as the requested regression
red. Their runtime results remain subject to the authorized Linux run.

The account lifetime regression rows require actual base reds on `0367cee`:

| Row | Named required failure on the base |
|---|---|
| `test_turn_room_start_account` | `an unnamed turn must rotate after a start-only account flag`: the base carries the start flag as an override and refuses the full account instead of trying the other one. |
| `test_resume_room_start_account` | `an unnamed resume must rotate after a start-only account flag`: the same retained flag prevents ordinary resume from walking the room candidates. |
| `test_turn_flag_keeps_set` | `a temporary account flag must preserve the persistent account setting`: after a successful turn requesting the account with room, the base overwrites the retained `--set` choice and incorrectly starts the next unnamed turn. |

The rotation rows start through the real CLI with `--account`, require delivery
of that account in run 1, then require a real room probe of that full account
followed by another configured account with room. They check the actual runner
receipt, unchanged session, `chosen_by.account: room`, per-run flag provenance
and absence of the flag from persistent overrides. The preservation row starts
with `--set account`, temporarily masks it with a successful turn flag, then
requires the following unnamed turn to return to the retained setting and
refuse. It also checks that the temporary run's effective account and retained
override are distinct and valid in the stored snapshot.

The snapshot unit row `TestRunAccountProvenance` uses the same recorded wire
shape. A temporary request may mask a proven persistent account, while treating
the request itself or an unrelated value as a persistent override must fail
decoding. On `0367cee`, the legitimate masked-setting case is rejected and a
temporary request can be presented as a persistent winner; these are required
unit reds when compiling this row against the base implementation. No unit or
E2E red/green is measured by the executor's macOS static checks.

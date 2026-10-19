# Watchdog R4 handoff

The R8 initial-publication closure fix and real bundle/validator regression are
recorded in [R8.md](R8.md). The supervisor reruns the installed item.

The R7 protected boot-input staging fix and its reached RED/GREEN regression
are recorded in [R7.md](R7.md). The supervisor reruns the installed item.

R6 merge resolutions and native test/review input production are recorded in
[R6.md](R6.md), which supersedes the current status below. The installed suite
has not been credited as passing.

The retained R5 status and evidence are in [R5.md](R5.md). R6 adds native review
input/check production to its fresh Room and usage handoff fixes. The complete
installed suite still requires the supervisor's box run; no installed
acceptance is claimed.

The following is the retained R4 record, superseded by the R5 status above.
Base revision: `92d62b72`, the supervisor's R3 commit. The supervisor committed
R4 as `834a4d29`. The repeated-driver G0 blocker is resolved in component
verification. No installed acceptance, vendor authentication or live model
turn is claimed. The installed requirements below remain open.

## Explicit profile selection (R4)

The R4 brief grants exactly the selection hunk in
`scripts/v2-serve/run.py`, `Case.bind_root_launch`, beginning at line 604.
It reads the case's `fixture_profile_selectors` map, matches the named
logical profile selector and driver against the approved inventory, and
then binds the actual issued grant ID through the existing checks. All
inventory, source, provider, delegation, expiry and issued-ID checks remain
in place. A driver with several profiles still refuses when no selector
is named. Empty, undeclared, foreign-driver and issued-ID-as-selector
values refuse too. A unique-profile driver retains its prior behavior.

`wd_item.boot()` explicitly names the baseline Claudock and Codex selectors
and retains their exact metadata in `wd-selectors.input.json`. This is
in-process fixture setup, not a new public request or frozen-context field.

R4 RED request `1792329706514-84111` reached the original
`fixture profile selection is ambiguous` failure using the producer's real
boot declaration and the shared binder. The added shared serve checks also
reached `PermissionError: [Errno 13] Permission denied` under `/opt`: their
vendor-retention test explicitly requires a Linux root fixture. The case's
Go wrapper and `BOX-SUITE.sh` now run those checks through the disposable
box's authorized sudo setup. No root-owned check is skipped or redirected
to a less restrictive directory.

GREEN request `1792329899441-17474` passed `TestProducerG0`: both watchdog
Python checks and all 21 shared serve Python checks passed. The regression
also chooses the second Claudock profile, tests unnamed and invalid
selection refusals without proposal mutation, rejects inventory drift and
checks the existing unique-driver behavior. These are pure helper and
fixture tests; no native worker scope or service-issued grant is invented.

The final G0 rerun, `1792330336446-89221`, also passed all 23 Python checks
with exit 0 after strengthening the unselected-profile drift assertion.
The full eight-package BOX-SUITE component set ran through request
`1792330006965-35641` and ended with `LB-BOX-TEST EXIT 0`. This includes the
API, store, secrets, admin, service, assembly, watchdog case and native
fixture packages. Its retained output is truncated, so no aggregate Go
test count is inferred from it. The earlier R3 RED remains retained as
request `1792327765745-63574`.

Mac static checks passed: Python compilation for the three changed Python
files, shell syntax for `BOX-SUITE.sh`, gofmt for `handoff_test.go`, Linux
amd64 vet for the case wrapper and `git diff --check`. The changed Go
wrapper is explicitly Linux-only; no Darwin runtime or wrapper vet result
is claimed. No Go production source changed in R4.

R4 changes are confined to this selection hunk, `wd_item.py`, the watchdog
`producer_test.py` and `handoff_test.go`, the root serve-unit step in
`BOX-SUITE.sh`, and this handoff. No other product capability was changed.

## Wiring now present

`case_watchdog.py` exports G0's `boot(case)`,
`prepare(case, require, fail, blocked)` and `abort(case, require, fail)`.
The older direct-context entry is retained as `prepare_context()`.
`wd_item.py` declares L6/L3 role sources, a child project, two same-provider
delegated Claudock selectors, the baseline Codex selector, bounded budgets
and immutable runtime assets. Preparation uses actual HumanRoot ticket and
mail ceremonies, an original confined L6 relay, real primary capture
offsets and hashes, a separate `internal reader` process and a provider
under the installed service UID. The context schema is unchanged.

The provider accepts usage queries only from its closed set of actual
helper-enrolled worker UIDs. The root helper derives its endpoint from the
installation, verifies the real service peer and enrolls or removes its
issued lease/UID pair. Lane UIDs cannot enroll, restore room or query usage.
The root-owned phase input is mirrored outside the lane. The native
fixture retains task history itself and obtains quota bytes from that
outside provider. No provider reply supplies a continuation token.

The native executable also preserves the baseline L5 fixture and the L6
mail relay. Its independent probe mode executes real file, signal and
forged-event attempts after an outside inspection of its PID, UID,
executable and cgroup. The controller pins the original process lifetime
with a pidfd, checks the projected target's actual bytes, and measures
termination and containment inventory. Those installed paths remain unrun.

The credential-service construction now binds `UsageJobs`, an actual
worker-bootstrap proxy and the installed service scope. New service/store
adapters create a separate narrow usage job, claim its real effect, seal
its input and spec, allocate a native UID/cgroup, commit its worker
identity, and hold the actual input/result frames while the broker
normalizes and retains the command's TSV. Completion releases the real
worker only after provenance checks, then measures and collects its
native resources. No scope, frame or successful command result is
manufactured by the adapter.

The E2E helper allows credential-free execution only for the exact
protected fixture enrollment. Other vendor runtimes retain the typed gate
`usage runtime requires protected native worker credential projection`.
This is not a live vendor credential implementation.

## Next installed requirements

These are source findings, not installed success or security claims:

- `secrets.Room` still reads the initial protected credential observation.
  The provider's fresh quota counters are not yet connected to that room
  observation. No-room and restoration cannot be credited from that initial
  observation. No room availability or normalized room receipt is supplied
  by Python.
- The current review verifier in `dataworker/review_stubs.go` retains
  `review confined verifier job, frozen post-run snapshot, authenticated check/capture inventory and measured result handoff`
  as a not-implemented gate. The case's review-input callback stops with a
  named prerequisite. Review and judge worker files were not edited.
- The new installed UsageJobs conversation, helper launch and six public
  cells have not run together. Component writer, fixture and admission
  checks cannot substitute for that installed run. Error/restart recovery
  of an in-flight usage job also remains unproved.

## R3 verification history

All project executions used the authorized Linux queue. Mac commands were
limited to source reads and static checks.

The initial R3 RED showed missing UsageJobs admission and missing G0
exports. Additional reached REDs covered private-object audience rejection,
a replay that replaced its durable usage job, conflated worker/vendor
executable pins, closed usage-UID enrollment and an O_PATH read attempted
as a readable descriptor. Their focused candidates passed.

The broad Linux run `1792327064145-55423` found a regression in
`TestCredentialWorkerInventory`. The new lookup incorrectly required an
installed usage stage for an existing generic sealed worker job. The fix
preserves that existing job's exact runtime/input/effect validation and
uses the durable stage for the new distinct vendor/bootstrap path.
Focused request `1792327871361-78938` passed all three store tests,
including both the existing inventory and the new installed-stage writer.
The final full store rerun, request `1792328038208-95051`, passed all 298
top-level tests with zero failures and skips. The earlier full rerun had
consumed the version before the SQL no-row error was translated to the
store's typed missing-stage result; that failed evidence is retained too.

Focused run `1792326804807-98238` passed 14 top-level Go tests and 65 Python
checks. Its seven fixture mutations failed their reached assertions before
their candidates passed. These cover driver affinity, lane usage access,
room reset, copied history tokens, canned limits, false old-process exit
and loose private-file permissions. Actual native ELF/TSV/history tests
passed; they are fixture component tests.

The final targeted fixture/control run `1792328107969-4665` passed 49
top-level Go tests and 64 Python component checks with no failures or skips.
It excludes the separately recorded, still-failing G0 integration regression.

The pinned-descriptor regression failed with
`read pinned-fixture: bad file descriptor`, then request
`1792327213315-80081` passed all four targeted wrappers after reopening the
held inode through its descriptor and rechecking the bytes. The Darwin
fallback initially referenced Linux-only mount types; the corrected
Darwin arm64 vet passed. Linux amd64 vet also passed the touched packages
and CLI importer. No Darwin runtime test was run.

Evidence is retained under the lane's own `boxq/` directory. Failed runs
remain evidence and are not counted as passing acceptance.

## Supervisor command

On a fresh disposable AWS Ubuntu 24.04 machine with Go, sudo and internet,
after the named gates have been repaired:

```sh
sh e2e/v2/cases/watchdog/BOX-SUITE.sh /opt/lb-v2-case-watchdog-r4
```

The evidence path must be fresh. The script prints each step and its exit,
stops dependent steps after failure, retains the original exit and ends
with `(exit $rc)`. Its installed command is:

```sh
sudo -n env "PATH=$PATH" python3 -I -B scripts/v2-serve/run.py \
  --source "$PWD" --evidence /opt/lb-v2-case-watchdog-r4 \
  --item-case watchdog
```

The shared serve checks remain required. The supervisor launches the
installed run; this lane did not run it on the Mac.

## R3 file inventory

- Case delivery: `case_watchdog.py`, `wd_item.py`, `wd_usage.py`,
  `wd_control.py` in `scripts/v2-serve/`; `run.py`, `item_bridge.py`,
  `checks_test.py`, `producer_test.py`, `producer_red.py`,
  `handoff_test.go`, `BOX-SUITE.sh`, this file and native
  `main.go`, `canary.go`, `legacy.go`, `relay.go` in the watchdog case.
- API and assembly: `api/usage_jobs.go`; `assembly/assembly.go`,
  `assembly/usage_grants.go`, `assembly/runners_partial.go`.
- Secrets: new `usage_plan.go`; the completion callback in
  `usage_source.go`.
- Service: new `usage_jobs.go`, `usage_jobs_test.go`; routing/ownership
  hunks in `server.go`, `materialization.go`, `host.go`,
  `reconcile_attempt.go`.
- Store: new `usage_stage.go`, `usage_bind.go`, `usage_worker.go`,
  `usage_objects.go`, `usage_test.go`; routing/ACL hunks in
  `worker_bootstrap.go`, `credential_worker.go`, `objects.go`;
  driver-parametric component inputs in `testfx/launch_linux.go`.
- Admin: new `usage.go`, `usage_client.go`, `usage_ctl.go`,
  `usage_executable_linux.go`, `usage_fixture.go`,
  `usage_fixture_partial.go`, `usage_fixture_partial_test.go`,
  `usage_gate_linux.go`, `usage_home_linux.go`, `usage_journal.go`,
  `usage_launch_linux.go`, `usage_open.go`, `usage_other.go`,
  `usage_provider.go`, `usage_provider_partial.go`, `usage_recover.go`;
  routing/allocation hunks in `lease.go`, `arch_ctl.go`,
  `arch_worker_launch_linux.go`, `containment_linux.go`,
  `data_access.go`, `gate_linux.go`, `worker_handoff_linux.go`.

No Git mutation, login, model request, provisioning or owner-channel
message was performed by this lane.

# Materialization service handoff

The candidate starts at 5e613b9e on the disposable materialization branch.
The five requested ports now have implementations and Linux regressions.
This authoring lane runs only static checks on macOS. No test binary, unit
test, mutation, native worker or installed-service E2E runs here. Runtime red
and candidate results remain unmeasured and cannot be accepted from this file.

The run-3 follow-up is recorded in MATERIALIZATION-SCHEMA.md. It preserves the
supplied mat-red1 failure and the one observed data-stage-grant normal pair,
then documents the private enum correction and per-control setup audit. Its
new candidate runtime results remain unmeasured.

Observed static results on Darwin arm64 with Go 1.26.5 are exit 0 for gofmt,
Linux go vet, Linux go vet with laneboss_faults, Darwin go vet, py_compile of
mutations.py, and bash -n of each service driver. Vet covers
./internal/v2/service and ./internal/v2/store/... including Linux test sources
in the two Linux variants. gofmt -l prints no changed file; git diff --check
is clean. The three reserved server/client/reconciler files are unchanged.
These results establish static validity only.

| Port | Retained behavior | Regression / deciding red |
| --- | --- | --- |
| store.LaunchDataStage | Under the sole writer, select the sourced reservation and actual parent claim, completed agent allocation, current policy/grants/epoch and enrolled worker artifact; issue one stage and narrow job grant set, retain the plan's DataStageID with its next generation, and refuse changed selectors or stored pins. | TestDataStagePins / data-stage-grant; TestDataStageGrantDrift / data-stage-current-grants. |
| service.MaterializationStage | Open helper-held roots, seal exact JCS input/candidate tree plus the child outbox intent, claim it, retain a fixed spec and worker-only binding, register/prepare, commit identity, validate its permit, open the worker and retain the returned process. Repeat calls return the original launched stage. | TestDataStageDispatch; TestDataRegistrationPin / data-registration-pin. |
| service.AwaitMaterialization | Wait outside the writer lock, bounded by the original child claim and a maximum 60-second invocation; honor context cancellation. Observe the retained process, require known zero exit/survivors, request helper read-back for the actual acknowledgement, validate every correlation, and complete that same effect before returning a result. | TestAwaitDataResult; TestAwaitDataCancellation; TestAwaitDataProcess / data-await-process. |
| service.WorkerInput | Authenticate the real connection/frame, authorize the fixed private operation, and reload only that worker's exact sealed bytes. Private object.read traverses only the sealed source/candidate manifest references. | TestWorkerInputOwnJob / worker-input-own-job; TestWorkerIngressFrame / worker-ingress-frame. |
| service.WorkerResult | Authenticate the same worker/job, require its original input hash and revision, strictly decode exact JCS LaunchData and compare storage/source/grant/manifest measurements. Retain actual output bytes and one blob event/receipt atomically with the worker revision. Exact retries replay the original receipt; changed bytes conflict. Acknowledgement alone does not complete materialization. | TestWorkerResultMeasurement / worker-result-measurement; TestWorkerResultOwnJob / worker-result-own-job; TestWorkerResultReplay / worker-result-replay; TestWorkerResultIngress; TestDataResultNeedsMeasurement. |

WorkerBinding now resolves a materialization principal from retained stage,
worker lease, actual prepared identity/event, endpoint, helper allocation,
current claim, epoch and grants. It derives boot/allocation generation from
protected retained records and compares native peer facts. Identity must still
verify the live helper containment registry and native connector lifetime.
TestWorkerPrincipalPins / worker-principal-boot changes the peer's nonempty
boot while preserving all other facts, so a missing boot guard reaches its
named assertion. Other fixed worker kinds keep typed absence until their
own protected stage mappings exist.

The private worker listener uses the existing framed Unix transport with
per-fragment native writer credentials. Its host socket lives under the
service-owned 0700 workers directory and is projected by the helper into the
worker namespace. It admits only input.read, object.read and result.append;
no new public Methods entry, caller-selected path, Scope or InternalIntent is
accepted. Its connections participate in host close and revocation tracking.
Darwin refuses this listener until its native writer evidence is implemented.

Preparation phases are retained because helper root opening precedes final
input sealing. The initial preparation record carries the actual parent claim
only for that preparatory step. Sealing creates the immutable child effect
with complete input bytes, then RecordDataClaim replaces that preparatory
snapshot with the actual current child claim. A final launched stage must pass
ValidateLaunchDataStage. An existing DataStageID whose row is missing or whose
phase is unknown refuses; it never authorizes a replacement stage or worker.

Measurement is retained before CompleteEffect. The completed effect and its
actual operation event are the visibility gate; a retained measurement alone
is unavailable as success. CompleteEffect checks the acknowledged result and
measurement, and startup verifies frozen input, child effect, exact output
bytes and acknowledgement event. The planner's existing stage validation now
joins a nonempty DataStageID to that completed measured result. The older
import receipt path remains for plans without a DataStageID; this change does
not claim removal or acceptance of that historical path.

The component fixtures compute hashes from variable retained source/input/
output bytes and use real store reservation, transaction, claim, identity and
receipt operations. Helper/native process records are explicit test doubles.
They do not prove copy/Git, real UID isolation, descriptor pins or process exit.
The installed composed case must measure those boundaries with actual helper
and dataworker consumers; no digest constant or fixture exit counts as that
measurement.

The new private store operations use only frozen API values, and no shared
API schema or public command is changed. The admin helper is consumed through
the DataWorkerControl signatures present in aba9611. Integration must also
resolve the following existing consumer differences on the composed source:

- That admin revision discovers planning claims with PendingEffects(limit
  1000), expects effect state running, and derives its scope from Context.Actor.
  This store's retained claim vocabulary is claimed/reconciling, its pending
  page has a 200 maximum and excludes live claims, and execution scope follows
  ClaimantID. The admin discovery/claim join must use the service's actual
  protected inventory/current claimant before its real helper path can run.
- The inspected identity consumer requires the worker Actor.LifeID to equal
  its target life; aba9611's fixed worker record validator requires it empty.
  The frozen worker target remains in LaunchRecord.Target and WorkerLease.Target.
  This candidate follows the administrator's empty worker Actor.LifeID with
  zero level/role. The integration owner must align the native consumer check.
- The inspected grants internal-worker entry still reports its missing private
  client/native principal/projected-root bridge. The parallel service/client
  lane owns that bridge. This candidate does not edit its three reserved files.
- The existing host/reconciler has no materialize Worker dispatch case for an
  interrupted unclaimed child. The private materialization control owns the
  normal child claim here; the parallel reconciler must route retained child
  recovery through that original stage and must not launch a generic worker.
- A lost/expired original parent or child claim refuses new execution. A service
  restart can replay an acknowledged/measured original job, but it does not
  rebuild an already projected socket inode or silently replace an unknown
  gate. Interrupted native endpoint/gate reconciliation still needs the
  installed supervisor's recovery evidence.

Run the new targeted controls on the authorized unprivileged Linux source in
both normal and laneboss_faults modes, retaining compiling red binaries,
unchanged candidate binaries, exact assertion observations and source bytes.
The existing run-mutations.sh supports --mutation NAME and --variant both.
Every row must fail its own assertion before the unchanged candidate passes.
No compiler failure, setup refusal, panic, timeout, skip or sibling assertion
receives credit. The composed installed serve case remains the acceptance gate.

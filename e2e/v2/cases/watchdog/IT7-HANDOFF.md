# Item 7 integration handoff

This records round 1. See `ROUND2.md` for the later reservation, slot,
completion and framing changes and the remaining gates.
`ROUND3.md` records the per-run guard and native-check outcome after integration.

This round builds regression-tested integration pieces. It does not pass the
six installed watchdog cells or authenticated vendor acceptance. The demo
runner remains a stand-in. No owner confirmation, login, spend, browser action,
message, production installation, merge or deployment is reported as done.

## Implemented pieces

The installed service now calls `watchdog.Service.ReconcileAutomatic` inside
its dispatch admission/freeze barrier, independently of pending effects. The
watchdog scans bounded current-life pages, recovers its durable wait/claim,
classifies committed completed-run captures through the real runner port and
submits the existing consumed-once continuation identity. It never acquires a
loose credential slot. Only the exact persisted backoff is treated as a wait;
other typed failures remain failures. Raw partial pipe chunks are refused as
missing complete vendor frames, never relabelled as complete capture.

The real SQLite store permits the internal watchdog's life, object and
whole-life journal reads while preserving its own principal. Public endpoints
cannot borrow this authority by relabelling their actor. Public event reads
still require an exact run. The watchdog journal now has stable event IDs and
a writer-assigned operation distinct from its intent and causing launch. The
store stamps both copies of that operation, retains a receipt even when no new
domain event is needed, checks life/grant/continuation CAS and epoch, preserves
task/history/workspace/counters/budget and refuses a foreign causing run.

The credential owner retains each measured usage envelope's authenticated
producer and protected profile/runtime enrollment in its encrypted journal.
`ReadUsageProvenance`, `UsageWorker` and `UsageProfile` reread those records,
current grants, native worker mapping and exact private envelope/TSV bytes.
The watchdog and Claudock consumer now agree with the broker's worker-owned,
service-audience ACL. Usage references are recognized by the private wire
schema without enabling their public upload classes. Legitimate internal
service and watchdog callers can refresh usage; public connections cannot.
Assembly binds these readers and the existing runner-owned credential validators.

The watchdog Python case preserves exactly the sealed lane binding and O_PATH
socket descriptors at their original numbers. Its Linux child-process canary
also checks that an unrelated descriptor remains closed. This establishes a
descriptor handoff, not `identity.self` authentication or isolation acceptance.
Dashboard calls require an independently supplied reader object. The L6 case
never launches a human CLI merely because proof files were selected. Missing
setup is retained as `laneboss.e2e-wait.v2`, `prerequisite_missing`, `passed:false`.

## Remaining gates and integration hooks

- **7A remains open.** `assembly.realRunners` still needs the protected per-run
  launch selectors, vendor executable/compatibility enrollment, private home
  records and native live-slot callbacks required by the strict adapters.
  Missing enrollment retains its typed refusal. Mode validators alone do not
  establish a real vendor turn or profile continuation.
- **7B remains open for native execution.** Bind an actual
  `secrets.Dependencies.UsageJobs` implementing `StartUsage`/`RunUsage` through
  the separately confined fixed usage worker and its native store mapping.
  It must use the existing sealed bootstrap/result protocol and narrow grants,
  not execute usage as the event-service UID. The new provenance reader consumes
  that job's authenticated result; it cannot create the job or its native facts.
- **7C has an installed scheduler but remains open for native continuation.**
  The existing lifecycle/store continuation composition must prove the real
  claim, selected-slot persistence and next launch. Source inspection still
  shows `reserveInternalContinuation` selecting an existing `continuation_claim`
  and `reserveContinuation` requiring its slot; no synthetic claim or slot was
  added here. The capture owner must also supply honest complete framing for
  the runner's existing capture contract. The six installed race/restart cells
  remain required; component scheduling cannot certify them.
- **7D remains open for native human identity.** An outside harness can construct
  `Case(context, human_reader=reader)`. `reader.read(method, exact_request_bytes,
  request_id, idempotency_key)` must run the exact installed shared CLI under an
  independently enrolled human principal, establish a fresh same-connection
  `human.session`, and return its actual stdout/stderr/exit. An object supplied
  by JSON, a transferred session ID or an L6 subprocess is insufficient. The
  standalone entry stops with a typed wait until this real bridge exists.
- **7E remains open.** Supply the declared synthetic quota/history fixture,
  protected outside room controller, enrolled forge/file/signal canary with
  actual existing targets, and measured service restart selector. Execute all
  LIMIT / NO-ROOM / TAMPER / STOP-RACE / RESUME-RACE / RESTART rows on the installed system.
  Root descriptor tests do not certify R157's file/signal targets or survivor
  and credential-transfer invariants.

The service hook is already wired in `service.reconcileLoop`. Alternate
composition roots must bind `RuntimeServices.Watchdog` to a watchdog with the
automatic reconciliation port, and bind `Dependencies.ResolveUsage` to the
credential owner's `ReadUsageProvenance`. The runner usage callbacks must use
that same protected owner. No new public swap or controller action was added.

Owner-in-person prerequisites remain root installation, any applicable fresh
D6 confirmation, the real human session, and the owner's chosen authenticated
same-provider profiles and approved budget for live acceptance. Human sends
and browser gestures remain owner actions wherever their acceptance cells
require them. Do not spend requests merely to manufacture exhaustion.

## Regression scope

Linux red runs reached missing watchdog visibility, rejected broker ACLs,
missing automatic dispatch, an unstamped journal, missing usage provenance,
rejected legitimate usage callers, accepted foreign causing run, missing typed
wait and missing narrow descriptor handoff. Their corresponding candidate
checks use the real SQLite writer, encrypted native broker journal, actual
synthetic source process, or actual inherited descriptors where applicable.
The Go component journal and Python observer doubles do not prove native
worker identity, authenticated vendor usage or a real human session. Queue
transcripts retain the exact commands, observed exits and measured test scope.

| Regression | Deciding failure |
| --- | --- |
| `TestInstalledWatchdogReads` | Real-store life/object/journal is invisible; foreign config or relabelled public peer gains visibility. |
| `TestInstalledWaitJournal` | Missing event/operation identity, launch/intent ID alias, changed task/history/counters/budget, early restart dispatch or cancelled replay. |
| `TestInstalledJournalRejectsForeignRun` | The real writer accepts a different causing run or changes the actual life while refusing. |
| `TestBrokerUsageAudience`, `TestBrokerUsageOwner` | Broker-shaped private evidence is rejected, or another worker/life/audience is accepted. |
| `TestUsageProvenance`, `TestUsageQueryReaders` | Protected producer records disappear on service reconstruction, stale/foreign/missing producers pass, legitimate internal readers refuse, or a public worker borrows the reader. |
| `TestAutomaticDurableWait`, `TestAutomaticCompletedRun` | Missing automatic dispatcher, reset backoff, missing restored-room handoff, cancelled revival or loose slot acquisition. |
| `TestReconcilerDrivesWatchdog`, `TestFrozenReconcilerNoWatchdog` | Idle queues never drive the watchdog, or frozen dispatch admits it. |
| `TestObserverHandoffs` | The 54 Python checks fail; native `Case.call` loses required descriptors or leaks another one, or missing human identity reaches dependent dispatch. |

The final normal, faults-tagged and root/integration queue receipts and the
cross-platform static-check commands are retained in the lane's evidence.

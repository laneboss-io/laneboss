# Claudock draft.4 fix 10 handoff gaps

Baseline: supervisor-supplied `d205742`, merging Claudock fix 9 `ba53c1e` with
fix 10 contract `3803f4d`. The public runner signatures stay unchanged;
Session.HistoryID is now explicitly checked against PrivateHome.HistoryID.
No shared API, authentication, store matrix or helper implementation is changed
by this lane. No additional contract amendment is assumed.

The historical missing-binding matrix below predates the installed planning
implementation. Its current credential-selection, measured bootstrap and
helper-owned home bindings are described in
[the native planning note](../../admin/CLAUDOCK-PLANNING.md). Provider
authentication, whole-run usage/refusal evidence and automatic profile-swap
acceptance remain separate gates.

## Fix 10 authority and policy handoff

Store/lifecycle derive and retain Level, Role, Driver and consumed Authority from
the real original request/current life, D9, policy and parent grant ceilings.
The adapter consumes those reservation pins, checks original start intent and
previous recovery, and retains the full reservation in its planning result and
input seal. It creates no ticket, proof, starter identity or child reservation.

The protected policy publisher/store must authenticate the actual consumed D6
approval for AllowCaptureRefusal and CaptureRefusalApprovalID and recheck revocation
and current generation before release. Metadata shape, a copied policy snapshot
or a lane's claimed approval ID cannot enable the exception. The adapter calls
real StateStore.Policy and ValidateCapturePolicy, keeps its typed unavailable
barrier, and blocks current/prior refused capture from continuation/extraction.
The helper owns nonblocking discard disposition and measured quiescent collection
of any partial capture job. No incomplete capture is acceptance evidence.

Lifecycle/store/identity own the unconditional helper_prepare transaction gate,
including attempts with no LaunchPlans. A new agent binding must atomically keep
Kind=agent, matching reservation pins, complete Recovery, bound plan, ready Lane
and authentic events/CAS/cancellation fences. The adapter's consumers require
the complete plan and ValidateLaunchBindingPlan; neither a legacy Kind nor an
existing prepared binding without its plan enables capture or restart. Shared
transaction/native provenance remains a required installed integration gate.

The upstream fix 10 handoff records a stopped loader-control preparation. This
lane reads that failure and adopts the supervisor-supplied contract revision
under the new brief; it does not modify or retry that other owner's loader step
and makes no acceptance claim from the handoff's static results.

## Fix 9 dependencies actually called

This row adapts the prior concrete Claudock runner; there was no new local
`contract_stubs.go` to replace. It now calls the real typed launch/capture ports
and shared validators. No in-package success substitute implements another
owner's method. On this baseline the following methods still return their
owner's typed `not_implemented`, which is preserved by the adapter:

| Owner / port | Required implementation or wiring |
| --- | --- |
| service/store: `LaunchPlan`, `Effect`, `Policy`, `Grants`, `ObjectMetadata`, `Blob`, `LaunchBinding`, `CaptureState` | Return the actual config-scoped reservation/claim, original private service-origin bytes, current grants/policy and complete identity recovery/capture journal. New reserved lives need the existing cancellation fence even before a Lane exists; reads must not turn an expired/lost claim or cancelled reservation into authority. |
| admin: `ResolveLaunchSources`, `ResolveLaunchStorage` | Re-read installed enrollment and the helper allocation journal by selectors; open/recheck the same owned storage root/life/generation, never infer a host path or reallocate after a missing receipt. |
| admin: `ReconcileCapture` | Check the actual fixed outside producer, protected spool and unique pipe/kernel/boot lifetime against the registered binding after restart. Unavailable producer evidence remains unavailable; no supplementary transcript is primary capture. |
| grants: `Resolve` | Re-resolve the retained reservation against its original request and current ceilings/revocation/expiry before the child Lane exists. A changed/narrowed result refuses this reserved plan rather than silently changing its inputs. |
| secrets: `UsageWindows`; identity/service: `UsageWorker`, `State.WorkerBinding`; enrollment: `UsageProfile` | Produce and retain real fix 11 outside usage_window and usage_raw objects. Supply protected native worker lookup and delegated vendor-profile mapping. The adapter validates envelope, producer, freshness and pinned TSV, then retains the actual normalized object reference in its signal. |
| assembly/lifecycle/credential worker | Replace `claudock.New(Dependencies{})` in assembly with the installed config, real typed ports and selector-only current-job bridge. Implement durable Run and helper-registry HomePath, both executable pins and real VerifyMode/VerifySlot/LimitGuard. No fixture receipt enables production. |

Start/Resume/Turn are candidate implementations of the owned row, with exact
retained argv and input seals. Imported adoption still lacks the authorized
import-binding handoff described below. Automatic Continue additionally needs
the current durable continuation claim, original logical turn, prompt and
remaining-budget proof tied to its reservation. The unchanged RunnerRequest
does not identify that intent; the private selector bridge currently carries
only planning selectors. The adapter reads previous recovery and refuses
Continue with an owning typed `not_implemented` rather than resetting a budget
or inventing a continuation intent. Lifecycle/service must freeze and supply
that retained input bridge (or an agreed internal selector extension) before
automatic profile-swap acceptance. Ordinary reserved Resume/Turn do not use
that unavailable shortcut.

## Outside usage implementation and live gate: LP-CAPTURE-IO-1

The helper's registered pipe producer is now required by session/limit
extraction, together with opened-plan LaunchBinding recovery, canonical primary
metadata, acknowledged stream offsets and immutable object provenance. These
checks reject refused, unbound, supplementary and changed-producer evidence.
They do not distinguish a lane-local process's vendor-shaped bytes from the
vendor's own bytes in a shared stdout pipe. The counted review's exploitation
scenario remains **suspected**, not a measured live exploit.

Fix 11 freezes the normalized envelope and exact five-column TSV source for
fresh outside `claudock usage --max-age 0` evidence. The adapter consumes that
source before any signal, authenticates its producer via the actual protected
worker lookup, checks the causing from-profile against enrollment, validates
fresh successful post-exit exhaustion and reads back both private objects.
UsageWindowEvidence.ID selects the committed normalized object, whose BlobRef
is retained in LimitSignal.UsageEvidence. LimitGuard still proves whole-run
stream/auth/guard coverage; Room.Available no longer supplies exhaustion.
The real secrets producer, native lookup and enrollment composition remain
owner dependencies, with typed failures when unavailable.

Unit fixtures use the pinned TSV format and real shared validators with
separately retained synthetic worker, native, enrollment and object records.
The controls rehash malformed source/envelope bytes so the relevant fields
decide. This establishes no authenticated outside usage or kernel evidence.
The raw lane-local forged-record **live** cell still needs the installed
outside-usage producer above and a retained canonical primary range known to
come from the harmless same-lane writer, with a terminal zero-survivor run and
no unrelated successful/auth/refusal record deciding the outcome first.
The existing quoted-tool-content cell is not credited as this raw-pipe canary.
Neither it nor the unit fixture proves source authenticity. This is an explicit
pending live gate, not a pass or a claim of a demonstrated exploit.

## Runtime and public read handoffs

The helper/credential worker must establish and attest vendor **umask 077**
before exec through VerifySlot; the library cannot change the event service's
global umask. The live case now checks the first transcript is a regular,
single-link 0600 file through grants test-child, and performs a separate actual
vendor-tool workspace write with independent byte/hash read-back. Its probe
must run as the target child with the real home/workspace projections. Existing
strict vendor-tree permissions remain in force, including TestVendorTreeGuards.

Public `lane status` and non-follow `event tail` currently use run 0 to select
current/all retained runs in the live consumer. Only the internal store lookup
has that sentinel explicitly frozen on this baseline. Lifecycle/service must
freeze those public read semantics or expose the exact selected run through
the start/operation receipt for the consumer to follow. No public sentinel
meaning is claimed from these static changes.

These are implementation dependencies or unresolved representation questions,
not observed production exploits. Missing evidence remains a failing typed
dependency or an incomplete case, never a fixture substitute.

| Owner / consumers | Required handoff | Acceptance evidence |
| --- | --- | --- |
| lifecycle, service capture store, both runners, watchdog, integration | Resolve the exact CaptureRecord framing representation. This adapter consumes canonical blobs containing complete JSONL records; arbitrary split pipe chunks remain refused. Either retain honestly identified complete-frame spans with exact offsets/hashes/coverage or review a shared multi-record span amendment. Keep original bytes and gaps. | A real stream split inside JSON is reconstructed with exact retained provenance; malformed/gapped/replacement controls still refuse. |
| assembly, lifecycle, secrets, launchers | Bind the adapter's durable Run, HomePath, Profile, VerifyMode, VerifySlot, Capture, Observation, LimitGuard and ReportHome dependencies. Keep companion pins in the actual runtime manifest and a common canonical-login lock domain. | Installed serve path reaches the real adapter with exact history/run/session bindings, selected credential projection and independent live mode receipts. Missing callbacks stay typed not_implemented. |
| secrets, admin/runtime resolver, Linux launcher | Prove the credential worker's access to its selected private home plus protected Records without exposing Records to lanes or widening event-service filesystem authority. Preserve private modes and live process/refresh ownership across restart. | Actual UID/mount canaries, selected credential injection and same-session slot rotation under the production boundary. |
| E2E, identity, lifecycle, service | Execute this case and its CLI descendants as an authentic delegated parent lane, with the supplied draft.4 binding and actual lower-level spawn/control rights. A copied binding alone cannot authenticate a host harness. Human-root tickets or dashboard read sessions are not fabricated by the case. | Native peer/containment checks authorize the actual connector/writer, and every CLI call uses that exact config/binding and retained key. Wrong containment or revision refuses before effects. |
| policy, packaging, service projections | The lane-scoped ConfigProjection for view show must expose the selected installed vendor Resource receipts: exact ID/version/hash and verified_loaded, readable through normal object ACLs. The case moved off the human-only dashboard method and still requires the same measured artifact claims. | Public config read plus hash-checked blob read returns the real approved current projection. Missing/false receipts fail; caller-authored vendor-inputs alone never prove loading. |
| lifecycle, admin/helper, service effect completion, E2E | Public stop must cancel pending continuation for these owned disposable lives and complete actual runtime collection without deleting their retained history. Committed helper.released events must contain ReleaseReceipt, with exact causal lease, containment, operation, effect, life and run bindings and independently measured zero process, connection, job and export counts. | The case stops each owned life, observes zero survivors and correlates allocation/release receipts before reporting resources collected. Unknown/nonzero counts or old HelperLease payloads fail. |
| watchdog, lifecycle, secrets, service/store | Retain ProfileSwap's sole expected generation/cancellation epoch/eligibility copy and the exact swap on the resumed LaunchEvent. Preserve Session.HistoryID, task, counters, logical turn, budget and truthful next run. Lifecycle owns slot acquisition. | A live structured provider limit drives one eligible same-provider continuation, without task failure/retry increments or budget reset; quoted/auth/stop controls do not rotate. |

The adapter version is now `claudock-cli/v2.0-draft.4-fix10`. Older protected home
generations and live-mode receipts are not silently upgraded. Integration and
migration must preserve those bytes and supply an explicit recovery/migration
route if prior draft homes are to be reused. New independent test homes need
no migration and are created private under the actual test identity.

The additional stream-correlation mutation directly targets the attribution
test, so every new consumer test has a named red control for Linux execution.

The current Linux verification handoff is the race-enabled unit suite in both
build variants and `mutations.py` (80 Go controls plus 24 case-consumer
controls, each bracketed by green candidate suites). The new Python tests mock
only CLI subprocess responses to test consumer parsing/argv retention; the
installed black-box entry always calls the real CLI and service. None of those
unit results proves actual vendor authentication or the native OS boundary.

No contract draft.4 acceptance is claimed from static checks. The combined
installed serve E2E, independent review, authenticated credential-mode cells
and CLAUDOCK-TWO-TURN remain required supervisor-run gates.

## Exact requests from the d4fix1 review

1. **Credential modes and native execution — integration, secrets, Linux/Darwin
   launchers and both runners.** Keep helper/API/native Darwin unavailable until
   the pinned vendor's actual helper or API authentication, selected injection,
   refresh ownership, settings precedence and native private-home behavior have
   independent authorized live receipts. Define the retained receipt binding to
   adapter version, both executable digests, mode and installed isolation/runtime
   generation, and supply it through VerifyMode/VerifySlot. No subscription
   refusal enables a paid fallback. This is an implementation/evidence gap; no
   new mode name or client enable flag is requested.
2. **Capture framing — integration, lifecycle/capture store, both runners and
   watchdog.** Specify whether each CaptureRecord.Data is a canonical complete
   JSONL frame/span, with honest ID, stream offset, exact bytes/hash, observation
   time and coverage, while retaining original raw chunks. If arbitrary chunks
   remain the unit, amend the shared API with explicit constituent byte ranges
   and coverage rather than concatenating under an unrelated capture ID. The
   acceptance control splits inside a JSON string and a multibyte character,
   reconstructs exactly, and still refuses gaps/replacement/partial evidence.
3. **Companion pins and composition — integration/assembly, packaging, runtime
   resolver and secrets.** Replace assembly's empty Claudock Dependencies with
   protected config-bound durable ports. Pin both Claudock and the actual Claude
   binary in the existing RuntimeManifest and RuntimeObjects; independently
   validate the resolved PATH lookup and construct fresh environment values in
   the confined launch/credential worker. RunnerPlan's one Executable and
   names-only environment do not supply a second executable pin or credential
   handoff. Decide a shared typed runtime binding only if the existing resolver
   cannot express this; do not add another public driver or put values in events.
4. **Adoption/migration binding — integration, lifecycle, migration, confined
   import worker, both runners and assembly.** Provide an explicit trusted,
   one-time import-binding handoff that correlates the retained AdoptionManifest,
   its actual source/history hashes, authorized new life, run, home, history and
   model, vendor session/cwd and independently verified quiescence. Decide
   whether to extend the internal Runner interface or supply a composition-only
   binding port, with coordinated callers and positive/red import evidence.
   This adapter can then validate the private tree/projection/conversation and
   atomically bind only an absent protected record. A plain Home.Adopt(request)
   without import provenance, or implicit binding during Resume, would supply
   no such authority and is not added. Unbound imported history stays refused.
   Bound Resume/Turn now checks drift before history lookup, yielding integrity
   for drift and not_found only for genuinely missing bound history.
5. **Nonexecuting abort evidence — admin/helper, lifecycle, service completion
   and E2E.** Correlate the helper's actual AbortReceipt with the committed
   service-origin launch.failed/no-execution event and outside prepared/exited
   zero-survivor observation. Expose retained receipts through existing scoped
   operation/object evidence as needed by the harness; do not invent a lane
   helper RPC. The case no longer demands ReleaseReceipt for an already aborted
   unopened gate. Real release receipts retain their own target run and measured
   zero counts even when the lease-level event omits Run. Synchronous error
   replies require an unchanged old run and no execution, rather than invented
   launch.failed events that the write catalog forbids.

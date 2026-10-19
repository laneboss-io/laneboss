# Draft.4 fix 11 integration requirements

The Codex consumer reads retained launch/capture objects and builds its pinned
argv. This does not complete the composed launch path or certify a provider.
Edits stay in this runner and its case subtree relative to starting HEAD
2995134 for this correction. No frozen API, shared CLI, assembly, dependency file or Git index is
changed. The full implementation/control map is in
[LAUNCH-PLAN.md](LAUNCH-PLAN.md).

1. **Lifecycle, service and assembly: supply an operation-scoped adapter.**
   RunnerRequest has no reservation selector or Scope. Construct the runner
   with the current authentic ReadScope/ReadView, Planning.Lease and original
   AllocationEffectID after the sourced/allocation stages. Keep that view alive
   and close it after the invocation. Do not change one shared Service's fields
   for concurrent calls. The runner reloads Store.Effect and LaunchPlan and
   compares the actual running claim, claimant, expiry, full record and
   reservation cause. Store must independently enforce current cancellation,
   actor/operation ownership, claim expiry and visibility; a returned ID or
   shape is not bearer authority. Missing selectors return lifecycle-owned
   not_implemented. Actual store stubs are called and their typed refusals
   propagate rather than being replaced locally.

   Fix 10 also requires real reservation Guards and atomic consumption of the
   root ticket, retained human proof or authentic starter authority. The store
   derives Level/Role/Driver from that authority, D9 and current role/grant
   policy. The adapter reads those reservation pins, compares the original
   request and retained life, and preserves the consumed authority ID. Shape
   checks and synthetic fixture references cannot establish actual consumption.

2. **Admin and data worker: resolve actual enrolled sources and owned storage.**
   Supply LaunchSourceResolver and LaunchStorageResolver, backed by protected
   LaunchEnrollment/RuntimeManifest and the real helper allocation journal.
   ResolveLaunchSources revalidates enrollment origin, generation and the
   granted project/runtime; ResolveLaunchStorage must reopen/recheck the
   existing life-owned objects, not allocate replacements or derive host paths
   from IDs. The runner compares the original helper effect/outcome, lease,
   PrivateHomeBinding and workspace. Retained runs additionally preserve the
   preceding recovery's exact home RootID/generation and workspace ID.
   Source, helper and materialization stages and their real receipts remain
   their owners' work. Calling their unimplemented ports remains a failed gate.

   Fix 11 materialization must finish before argv: retain DataStageID and the
   distinct original child worker/effect, narrow job grants, opened descriptor
   projection and measured LaunchDataResult. Supply MaterializationControl so
   AwaitMaterialization can return the actual committed result. The adapter
   checks shared validators, the original parent/inputs/storage, succeeded child
   and output/observation plus exact result bytes. Planned/spec_retained replay
   reuses the validated complete plan. No service-UID copy/Git or guessed job.

3. **Lifecycle/data/secrets: retain prepared session and prompt before argv.**
   Store.Turn must expose the authentic retained selection for this reserved
   life/run/logical turn, including its exact Prompt. ResolveSession must read
   the prepared service-issued Session from protected worker records.
   Home.PreparedSession provides a reload helper; Slot.Reserve can retain the
   issued session before construction. ResolveHome still audits the actual
   physical home and returns its logical descriptor. CheckProject maps the
   actual materialization to physical bounded paths; VerifySlot checks the
   worker's real lease/projection via Slot.Matches. Do not implement these as
   callbacks that merely accept matching caller labels. The pre-binding
   availability/lifetime of turn/session selections must be supplied by the
   planning owner; the runner calls the ports and refuses unavailable inputs.

4. **Packaging/admin/helper: pin actual runtime and namespace mapping.**
   Runtime contains protected installed vendor/self-helper paths and exact
   executable/version/hash and compatibility references. Sources must select
   that enrolled executable and installed manifest. Helper's post-spec
   RuntimeResolver, prepared-spec registration, one-use gate and release-time
   pin checks remain mandatory. A blob ID or logical cwd is not a host path.
   Environment needs a separately verified absolute home in the launch
   namespace; a root-relative .codex label cannot manufacture that mapping.
   The outer Linux/Darwin boundary must be effective before the explicit
   disabled vendor sandbox can execute.

5. **Store/admin/identity/capture: retain original registered evidence.**
   CaptureState must return the exact registered/refused binding and committed
   per-stream positions. LaunchBinding must return complete LaunchRecovery,
   original spec reference/bytes and stamped identity event. The runner reads
   and validates those objects, current policy/grants, original cause, home,
   capture.bound/identity.bound and actual capture ranges. Limit interpretation
   additionally requires capture.closed and acknowledged EOF. Refused capture
   is visible but cannot provide session/limit facts. Actual producer kernel
   ownership, helper pipe/spool journal, authenticated append, cancellation
   drains and restart reconciliation remain the owning ports' obligations.
   LP-CAPTURE-IO-1 still covers scoped input/resize/attach and real pinned
   vendor tool/session/limit schemas. A text stream is not complete inventory.

   Opened capture compares issued grants with the sealed reservation generation,
   retaining snapshot, expiry and Revoked checks across D6 advances. The store
   must still authorize current control/visibility rights on every scoped read.
   New launch policy stays current; a historical replay cannot open a stale plan.
   Supply UsageWindows, protected UsageWorker native facts and UsageProfile
   enrollment. Store.WorkerBinding must join the actual current usage job. The
   adapter validates fresh post-exit exhausted from-profile evidence, raw TSV,
   private ACL/provenance and committed normalized bytes, then retains the exact
   BlobRef in LimitSignal.UsageEvidence. The secrets owner supplies real outside
   query/normalization; no native Codex usage command is invented. Its stub is a
   real unavailable gate, and nil evidence does not authorize rotation.
   The integration owner should align section 11's older structured/transcript
   text with stdout/stderr/vendor; the scoped case now accepts vendor.

   helper_prepare must retain a valid bound plan, Recovery, Kind=agent identity,
   ready Lane and created/adopted event together under life/reservation CAS and
   cancellation guards. An omitted LaunchPlans list must refuse the new agent
   binding or Lane/event write. Legacy or
   worker bindings cannot acquire new live agent authority. The adapter always
   calls the shared binding validator for recovery; atomic persistence belongs
   to lifecycle/store/identity. For refused capture, publish the default-false
   D6 exception only after verifying actual consumed approval. Retain its policy
   snapshot and binding metadata and recheck current policy/revocation at release.
   The adapter checks current policy and the snapshot before returning the
   refusal, and refuses retained-run continuation without registered capture.

6. **Lifecycle/migration: imported first-run provenance.**
   Fix 9 supplies a retained launch plan, but RunnerRequest still has no
   authenticated imported vendor-history association. Adopted first managed
   Resume remains a typed unavailable barrier. Define the verified import
   association and lifetime together with the data/session consumer. A
   caller-supplied Session, unreferenced manifest or lane-side history label
   cannot authorize that mapping. The forged-adoption live fixture must reach
   its intended import validator and exact error before any agent executes.

7. **Lifecycle/watchdog: retained continuation and unmapped startup.**
   The adapter receives no ContinuationID selector with which to load the
   current durable continuation/eligibility/slot fence. A reserved continue
   therefore remains lifecycle-owned not_implemented; no budget/profile fallback
   is inferred from the original public frame. Supply that association through
   coordinated internal wiring before enabling the route. Separately, the
   fix-9 validators permit start only at run 1 and require a vendor ID for a
   retained plan. The earlier unmapped-startup helper preserves its local
   guards but cannot establish a valid public fix-9 retry. Resolve that
   contract route explicitly; no new mode or schema field was invented here.

8. **Packaging/E2E: vendor evidence remains open.**
   Resume argv order against the actual pinned CLI and a real retained
   provider-limit sample remain unverified. The earlier official reference
   fetch failed DNS resolution; there is no newly claimed citation or vendor
   run. Keep exec/resume help, effective approval/sandbox mode, actual
   file-login/continuation and workspace write/read evidence, real limit
   samples and independent review in receipts for codex-exec-v4. The full
   supported effort and model names must be approved. API/local modes and
   unproved L4/L5/L6 capabilities remain unavailable.

9. **Identity/E2E: supply authentic proofs, tickets and negative fixtures.**
   Human read and blob-staging calls use fresh human.session proofs on each
   command connection. Other mutations retain their own method/params proof
   and retry key. Root launches need current unconsumed tickets with complete
   provenance. Every helper/session negative fixture fixes one preflight or
   effect route before execution; synchronous errors write no lane/events,
   while committed launch Operations require their correlated measured failure.
   Missing setup or another component's error cannot kill a red target.

10. **Lifecycle/E2E: independently review and collect actual resources.**
    MarkRequest.review is required even for abandonment; supply its real
    service-issued route or a coordinated encoding. The case quiesces every
    owned run before requesting independent state decisions, waits through
    intermediate accepted states and awaits clean's Operation/lane.cleaned.
    Helper release requires actual known-zero survivor/connection/job/export
    counts. Credential refresh/revocation/rotation is the real secrets
    worker's obligation. No fixture or self-acceptance substitutes for it.

The driver retains the original 42 Go controls, 77 fix-9 controls, 25 fix-10
controls and 26 fix-11 controls, each in both builds: 340 result rows. It includes real admin/store/secrets source packages
in its unit snapshot so dependency-refusal tests invoke the owning ports.
Future owner imports must remain present in that exact-source test snapshot;
a compile/setup failure never counts as a reached red. The protocol driver
has 21 rows. Both drivers and the live/installed cases require authorized
Linux execution and independent review. No current runtime result is inferred
from static checks or the earlier revision's box report. The supplied ca1e78f
box report failed both race builds and the Go candidate, while its protocol
tests and reds passed. Re-execute the corrected fixture and all Go controls on
Linux before acceptance.

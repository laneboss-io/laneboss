# Item 7, round 3

The source base is dae926d4. This round extends the incoming
`runner_enrollment.go` guard and its existing composition point. It adds no
second enrollment source, public method, actor identity or owner confirmation.
Item 7 remains incomplete.

## 7A: protected per-run checks

The guard now receives the actual store, clock, native source/storage ports
and credential broker. A shaped installation reference alone cannot reach the
vendor adapter. Each planning call reloads the live durable claim, reservation,
current grants and policy; reads the exact private enrollment/runtime bytes;
matches the selected project and vendor pins; checks the original new-run
profile, model, effort and budget plus retained plan pins; and compares the
broker's storage with a fresh native storage read. It rechecks the claim and
plan before forwarding.
The original installation reference is copied and is never mutated per run.

`VerifyRunnerSlot` reads the encrypted broker journal under its existing lock.
It checks the actual slot, stable planning pin, target/operation/request,
profile generation and fingerprint, current delegation, selected model/runtime,
source availability and canonical login ownership. Released, changed, foreign
or revoked slots refuse. It returns storage metadata and creates no new slot,
credential projection, refresh lock or native execution proof.

`TestRunnerNeedsAuthority` first showed shape-only metadata reaching the adapter.
`TestRunnerStorePins` uses the real SQLite store and rejects missing/foreign
configuration, claims, generations, vendor, home, slot, profile, model, effort,
budget, run and runtime manifest. Its adapter probe records every attempted
call and stops with a typed boundary error; it returns no successful plan.
`TestRunnerSlotRead` uses the real encrypted backend and exact synthetic source
bytes, with claim/home/lease/release/profile/source controls and stable replay.
These are component tests, not authenticated vendor acceptance.

The underlying strict adapters still need native operation-owned runtime and
home records, companion executable pins, reviewed live compatibility evidence
and their run/capture/projection callbacks. This guard does not replace those
callbacks with inferred paths or successful booleans. Claudock and Codex retain
their owning unavailable/not-implemented results when that wiring is absent.

## 7C: continuation authority hook

The helper now reads the canonical internal `ContinuationRequest` retained by
round 2, compares the actual claimed intent and sole swap fence, and permits
the selected `profile_wait` life during preparation. Source lookup may precede
slot acquisition. It neither invents a public request nor completes selection.
The old retained claim envelope keeps its original cause and slot checks for
compatibility, including the existing swapped-profile review regression.

`TestContAuthority` first reached the public-request decoder on the real new
reservation. It now checks the native source authority consumer with a real
SQLite selection, live claim and explicit component publication prerequisite.
Foreign claim/configuration controls refuse, the intent remains claimed with
no slot, and its operation remains pending. The older review regression caught
a compatibility mistake in the first candidate; that mistake was corrected.

The minimal helper hooks are in `launch_authority.go` and `launch_sources.go`,
sharing `cont_check.go`. No capture, materialization or native gate was bypassed.

Separately confined `StartUsage`/`RunUsage` jobs remain unbuilt. The fixed worker
selector, protected native worker mapping and sealed input/result composition
still need the real usage job. No worker scope or peer was fabricated and no
usage command was run as the event service to stand in for confinement.

## Native check and remaining gates

The installed credential-exec check stopped with the exact result:
`prerequisite_missing: installed canary requires its fixed helper control unit`.
The native packet therefore failed. Worker launch and metadata owner controls
passed in that packet, but neither closes installed credential acceptance.
Root installation remains an owner wait; the missing unit was not installed.

7E's quota/history/forge/file/signal/restart fixture and the six installed public
cells remain open. 7D's independently enrolled human-reader bridge remains open;
missing human setup continues to wait before upload or dispatch. Owner D6,
human sessions, authenticated profiles, approved spend, sends and browser
gestures remain waits. No sign-in, model request, owner send, production commit,
merge, push or deployment was performed.

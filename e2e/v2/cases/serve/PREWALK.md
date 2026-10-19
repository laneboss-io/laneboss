# Installed lifecycle prewalk

Audited source: 179f3f0, with the run-16 harness changes. This is a static audit,
not installed acceptance. Source-ready means real code and checks are present,
assuming valid inputs and prior gates; it never means an executed pass. Blocked
names a source-derived refusal after its prerequisites. Unknown requires native
measurement or a pending owner handoff. A later source-ready row cannot bypass
an earlier block. These classifications are not read by the acceptance harness.

The table follows all 78 lifecycle catalog rows. Shared proof pairs are reused
and can execute before their displayed position: admin.publication already uses
human.read.challenge/confirm. G0-G11 are the ordered dispatch requests in
REQUESTS.md. PREWALK.json preserves structured code references and exact expected
refusals. No runtime verdict is inferred from a stub or not_implemented port.

| # | Step | Static result | Path and deciding condition |
| --- | --- | --- | --- |
| 1 | `platform` | unknown | Linux/unprivileged UID, sudo and installed kernel prerequisites require the actual disposable box. `scripts/v2-serve/run.py:683` |
| 2 | `source` | source-ready | Stages a real source archive, records input bytes and rejects linked or incomplete source. `scripts/v2-serve/run.py:691`, `scripts/v2-serve/provision.py:347` |
| 3 | `build` | unknown | Actual trimpath tagged Go build, artifact digest and release pairing run only on Linux. `scripts/v2-serve/run.py:702` |
| 4 | `fixture.build` | unknown | Builds the declared vendor stand-in from its retained module/source; no executable was built here. `scripts/v2-serve/run.py:722` |
| 5 | `authenticator.build` | unknown | Builds the dedicated software authenticator and requires explicit simulated provenance. `scripts/v2-serve/run.py:736` |
| 6 | `root.stage` | source-ready | Uses a new protected administrator evidence root and retained inputs, without credentials or real model execution. `scripts/v2-serve/run.py:751` |
| 7 | `boot.inputs` | source-ready | Real bundle assembler validates source/launch/policy pins; semantic Sources and empty Derived match the current initial validator only. [G2] `scripts/v2-serve/run.py:755`, `scripts/v2-serve/provision.py:268` |
| 8 | `namespace.install` | unknown | Real host namespace prerequisite installation must succeed on Linux. `scripts/v2-serve/run.py:789` |
| 9 | `namespace.check` | unknown | Requires actual native namespace checks, not interface presence. `scripts/v2-serve/run.py:789` |
| 10 | `admin.install` | unknown | Runs the real protected installer and native initial validator; future Derived adoption needs G2 coordination. [G2] `scripts/v2-serve/run.py:803` |
| 11 | `admin.check` | unknown | Checks the actual installed artifact, accounts, protected paths and unit state. `scripts/v2-serve/run.py:824` |
| 12 | `installation` | source-ready | Requires exact retained installation fields and pairing, not a generated success constant. `scripts/v2-serve/run.py:831` |
| 13 | `fixture.enrollment` | source-ready | Requires complete pinned dual-driver enrollment under the dedicated partial/authenticator build. `scripts/v2-serve/run.py:858` |
| 14 | `serve` | unknown | Starts the actual installed service and checks its live unit/socket; source constructs real owners. `scripts/v2-serve/run.py:872`, `internal/v2/assembly/assembly.go:71` |
| 15 | `health` | source-ready | Fresh native public-health socket returns actual artifact/snapshot/capability observations; it is not launch readiness. `scripts/v2-serve/run.py:892` |
| 16 | `authenticator.create` | source-ready | Creates the explicit software device; fresh signatures use the persisted monotonic counter. `scripts/v2-serve/run.py:289` |
| 17 | `human.enroll.begin` | source-ready | Installed root helper reserves the actual empty-baseline ceremony and exact endpoint generations. `scripts/v2-serve/human.py:32` |
| 18 | `human.enroll.attestation` | source-ready | Real software registration consumes the returned challenge; the marked attestation path remains explicit. `scripts/v2-serve/human.py:41` |
| 19 | `human.enroll.complete` | source-ready | Native admin/identity/store commit requires exact evidence, event, receipt and simulated presence. `scripts/v2-serve/human.py:50` |
| 20 | `human.enrollment` | source-ready | Credits only the actual installed enrollment receipt and named writer from the preceding commit. `scripts/v2-serve/human.py:63` |
| 21 | `admin.publish` | unknown | Known initial-read amplification is being fixed by service; installed timing/receipt outcome remains unmeasured on this source. [G0] `scripts/v2-serve/run.py:367` |
| 22 | `admin.publish.retry` | source-ready | Only runs after first publication succeeds; native exact replay and identical durable receipt/read-backs remain mandatory. [G0] `scripts/v2-serve/run.py:380` |
| 23 | `admin.publication` | blocked | First public blob read needs a same-socket human.session and hits G1. After that fix, the new exact-generation org.validate reaches G2. Expected `lb-v2-service / unauthenticated`: connection has no current read authority. [G1, G2] `scripts/v2-serve/run.py:385`, `internal/v2/identity/human.go:262`, `internal/v2/store/contract_stubs.go:101`, `internal/v2/service/connection.go:96` |
| 24 | `human.session.challenge` | source-ready | Native authentication uses the private HumanPolicyGeneration bootstrap, then commits a real operation-bound nonce. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34`, `internal/v2/identity/binding.go:72` |
| 25 | `human.session.confirm` | source-ready | Verifies actual WebAuthn assertion and counter, then atomically retains proof/evidence and consumes the challenge. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 26 | `human.session` | blocked | Receipt may already be durable while its connection bind failed. The strengthened same-socket identity.self read now exposes the unbound-authority refusal. Expected `lb-v2-service / unauthenticated`: connection has no current read authority. [G1] `internal/v2/identity/human.go:262`, `internal/v2/store/contract_stubs.go:101`, `internal/v2/service/connection.go:96` |
| 27 | `human.read.challenge` | source-ready | Prepares a fresh human.session proof for each CLI read, not a session ID reused across sockets. `scripts/v2-serve/human.py:130`, `scripts/v2-serve/human.py:72` |
| 28 | `human.read.confirm` | source-ready | Uses the real signer and identity verifier; the subsequent session bind still needs G1. [G1] `scripts/v2-serve/human.py:130`, `internal/v2/identity/human.go:94` |
| 29 | `uid.direct-open` | unknown | Actual dropped-UID direct-open canary must observe protected database/WAL refusal on Linux. `scripts/v2-serve/run.py:521` |
| 30 | `human.claudock.session.challenge` | source-ready | claudock: commits a fresh human.session challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 31 | `human.claudock.session.confirm` | source-ready | claudock: checks the actual human.session assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 32 | `human.claudock.grants.challenge` | source-ready | claudock: commits a fresh grants.root challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 33 | `human.claudock.grants.confirm` | source-ready | claudock: checks the actual grants.root assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 34 | `human.claudock.ticket.challenge` | source-ready | claudock: commits a fresh ticket.issue challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 35 | `human.claudock.ticket.confirm` | source-ready | claudock: checks the actual ticket.issue assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 36 | `human.claudock.read.challenge` | source-ready | claudock: commits a fresh human.session challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 37 | `human.claudock.read.confirm` | source-ready | claudock: checks the actual human.session assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 38 | `human.claudock.control.challenge` | source-ready | claudock: commits a fresh exact lifecycle control challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 39 | `human.claudock.control.confirm` | source-ready | claudock: checks the actual exact lifecycle control assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 40 | `human.claudock.session` | blocked | Receipt may already be durable while its connection bind failed. The strengthened same-socket identity.self read now exposes the unbound-authority refusal. Expected `lb-v2-service / unauthenticated`: connection has no current read authority. [G1] `internal/v2/identity/human.go:262`, `internal/v2/store/contract_stubs.go:101`, `internal/v2/service/connection.go:96` |
| 41 | `human.claudock.grants` | blocked | After session bootstrap is repaired, this nonempty approved profile manifest reaches the explicit protected-root resolver gap. Expected `lb-v2-grants / not_implemented`: root enrolled capability handles require the protected enrollment resolver is not implemented. [G3] `scripts/v2-serve/human.py:155`, `internal/v2/grants/root.go:13` |
| 42 | `human.claudock.ticket` | source-ready | Issues an actual exact-scope ticket only after real root grants and confirmed proof; expiry and simulated provenance are checked. [G3] `scripts/v2-serve/human.py:155`, `internal/v2/identity/human.go:189` |
| 43 | `lane.claudock.inputs` | source-ready | Checks the actual published L5 role/task/policy, enrolled driver/project and unticketed proposal. Real returned grant IDs bind later. `scripts/v2-serve/lifecycle.py:185`, `scripts/v2-serve/run.py:509` |
| 44 | `lane.claudock.start` | blocked | Fresh CLI has only its root ticket. Lifecycle's Store.Policy read has no bound read authority; no proof/session prelude is sent. Expected `lb-v2-service / unauthenticated`: connection has no current read authority. [G4, G5, G6, G7, G8, G9] `scripts/v2-serve/lifecycle.py:185`, `internal/v2/lifecycle/launch.go:59`, `internal/v2/service/connection.go:96` |
| 45 | `lane.claudock.running` | unknown | Requires completed real PlanLaunch and native running survivors. The pending probe, worker, profile, source and projection/capture gaps prevent source acceptance. [G5, G6, G7, G8, G9] `scripts/v2-serve/lifecycle.py:149`, `internal/v2/service/launch_control.go:449` |
| 46 | `lane.claudock.events` | source-ready | Reads actual paged lane events and requires lane.created, lane.started and identity.bound with exact config/life/run and service origin. `scripts/v2-serve/lifecycle.py:86`, `internal/v2/lifecycle/read.go:244` |
| 47 | `lane.claudock.reason` | source-ready | Uploads actual stop-reason bytes through blob begin/chunk/commit and checks the returned immutable ref. `scripts/v2-serve/lifecycle.py:118`, `scripts/v2-serve/human.py:139` |
| 48 | `lane.claudock.stop` | unknown | Commits an exact proof/CAS-bound stop intent and waits for the native launcher outcome; no terminal result is synthesized. [G9] `scripts/v2-serve/lifecycle.py:118`, `internal/v2/lifecycle/control.go:371` |
| 49 | `lane.claudock.quiescent` | unknown | Requires a real terminal exit or signal and zero survivors, then rereads generation before marking. [G9] `scripts/v2-serve/lifecycle.py:118`, `internal/v2/lifecycle/control.go:193` |
| 50 | `lane.claudock.abandon` | source-ready | Abandoned-only path bypasses positive review requirements, but retains exact proof/CAS, observed quiescence and durable state event. `scripts/v2-serve/lifecycle.py:149`, `internal/v2/lifecycle/review.go:265` |
| 51 | `lane.claudock.archive` | blocked | With prior gates/quiescence satisfied, lifecycle explicitly lacks the durable archive worker intent. Expected `lb-v2-lifecycle / not_implemented`: durable quiescent archive worker intent is not implemented. [G10] `scripts/v2-serve/lifecycle.py:149`, `internal/v2/lifecycle/archive.go:40` |
| 52 | `lane.claudock.clean` | blocked | Even with a genuine archive receipt, owned workspace/object removal and its retained receipt are unimplemented. Expected `lb-v2-grants / not_implemented`: owned data removal and retained-object receipt is not implemented. [G11] `scripts/v2-serve/lifecycle.py:149`, `internal/v2/lifecycle/archive.go:127` |
| 53 | `lane.claudock.collected` | unknown | Requires actual cleaned state plus retained lane.cleaned event; G10/G11 currently prevent reaching this observation. [G10, G11] `scripts/v2-serve/lifecycle.py:149`, `internal/v2/lifecycle/read.go:13` |
| 54 | `human.codex.session.challenge` | source-ready | codex: commits a fresh human.session challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 55 | `human.codex.session.confirm` | source-ready | codex: checks the actual human.session assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 56 | `human.codex.grants.challenge` | source-ready | codex: commits a fresh grants.root challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 57 | `human.codex.grants.confirm` | source-ready | codex: checks the actual grants.root assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 58 | `human.codex.ticket.challenge` | source-ready | codex: commits a fresh ticket.issue challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 59 | `human.codex.ticket.confirm` | source-ready | codex: checks the actual ticket.issue assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 60 | `human.codex.read.challenge` | source-ready | codex: commits a fresh human.session challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 61 | `human.codex.read.confirm` | source-ready | codex: checks the actual human.session assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 62 | `human.codex.control.challenge` | source-ready | codex: commits a fresh exact lifecycle control challenge bound to method, target, digest, generation, origin and RP; prior gates must hold. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:34` |
| 63 | `human.codex.control.confirm` | source-ready | codex: checks the actual exact lifecycle control assertion, enrolled key, persisted counter and one-use nonce, then commits the exact ProofRef. `scripts/v2-serve/human.py:72`, `internal/v2/identity/human.go:94` |
| 64 | `human.codex.session` | blocked | Receipt may already be durable while its connection bind failed. The strengthened same-socket identity.self read now exposes the unbound-authority refusal. Expected `lb-v2-service / unauthenticated`: connection has no current read authority. [G1] `internal/v2/identity/human.go:262`, `internal/v2/store/contract_stubs.go:101`, `internal/v2/service/connection.go:96` |
| 65 | `human.codex.grants` | blocked | After session bootstrap is repaired, this nonempty approved profile manifest reaches the explicit protected-root resolver gap. Expected `lb-v2-grants / not_implemented`: root enrolled capability handles require the protected enrollment resolver is not implemented. [G3] `scripts/v2-serve/human.py:155`, `internal/v2/grants/root.go:13` |
| 66 | `human.codex.ticket` | source-ready | Issues an actual exact-scope ticket only after real root grants and confirmed proof; expiry and simulated provenance are checked. [G3] `scripts/v2-serve/human.py:155`, `internal/v2/identity/human.go:189` |
| 67 | `lane.codex.inputs` | source-ready | Checks the actual published L5 role/task/policy, enrolled driver/project and unticketed proposal. Real returned grant IDs bind later. `scripts/v2-serve/lifecycle.py:185`, `scripts/v2-serve/run.py:509` |
| 68 | `lane.codex.start` | blocked | Fresh CLI has only its root ticket. Lifecycle's Store.Policy read has no bound read authority; no proof/session prelude is sent. Expected `lb-v2-service / unauthenticated`: connection has no current read authority. [G4, G5, G6, G7, G8, G9] `scripts/v2-serve/lifecycle.py:185`, `internal/v2/lifecycle/launch.go:59`, `internal/v2/service/connection.go:96` |
| 69 | `lane.codex.running` | unknown | Requires completed real PlanLaunch and native running survivors. The pending probe, worker, profile, source and projection/capture gaps prevent source acceptance. [G5, G6, G7, G8, G9] `scripts/v2-serve/lifecycle.py:149`, `internal/v2/service/launch_control.go:449` |
| 70 | `lane.codex.events` | source-ready | Reads actual paged lane events and requires lane.created, lane.started and identity.bound with exact config/life/run and service origin. `scripts/v2-serve/lifecycle.py:86`, `internal/v2/lifecycle/read.go:244` |
| 71 | `lane.codex.reason` | source-ready | Uploads actual stop-reason bytes through blob begin/chunk/commit and checks the returned immutable ref. `scripts/v2-serve/lifecycle.py:118`, `scripts/v2-serve/human.py:139` |
| 72 | `lane.codex.stop` | unknown | Commits an exact proof/CAS-bound stop intent and waits for the native launcher outcome; no terminal result is synthesized. [G9] `scripts/v2-serve/lifecycle.py:118`, `internal/v2/lifecycle/control.go:371` |
| 73 | `lane.codex.quiescent` | unknown | Requires a real terminal exit or signal and zero survivors, then rereads generation before marking. [G9] `scripts/v2-serve/lifecycle.py:118`, `internal/v2/lifecycle/control.go:193` |
| 74 | `lane.codex.abandon` | source-ready | Abandoned-only path bypasses positive review requirements, but retains exact proof/CAS, observed quiescence and durable state event. `scripts/v2-serve/lifecycle.py:149`, `internal/v2/lifecycle/review.go:265` |
| 75 | `lane.codex.archive` | blocked | With prior gates/quiescence satisfied, lifecycle explicitly lacks the durable archive worker intent. Expected `lb-v2-lifecycle / not_implemented`: durable quiescent archive worker intent is not implemented. [G10] `scripts/v2-serve/lifecycle.py:149`, `internal/v2/lifecycle/archive.go:40` |
| 76 | `lane.codex.clean` | blocked | Even with a genuine archive receipt, owned workspace/object removal and its retained receipt are unimplemented. Expected `lb-v2-grants / not_implemented`: owned data removal and retained-object receipt is not implemented. [G11] `scripts/v2-serve/lifecycle.py:149`, `internal/v2/lifecycle/archive.go:127` |
| 77 | `lane.codex.collected` | unknown | Requires actual cleaned state plus retained lane.cleaned event; G10/G11 currently prevent reaching this observation. [G10, G11] `scripts/v2-serve/lifecycle.py:149`, `internal/v2/lifecycle/read.go:13` |
| 78 | `cleanup` | unknown | Retains both journals and timings, stops owned units and preserves refused product cleanup; cannot credit uncollected lanes. [G10, G11] `scripts/v2-serve/run.py:975`, `scripts/v2-serve/lifecycle.py:236` |

The owned fixes strengthen the measured path. admin.publication now invokes
the actual org.validate with the committed generation and requires valid=true
with an empty problems array. human.session keeps its actual receipt checks and
also requires a fresh CLI's session prelude plus identity.self on that same
socket. A returned durable receipt alone can no longer credit session usability.
No session ID, proof, profile member, target or successful review is invented.

Integrate fix 13c (fd1ab1a) fixes one reading: Sources keep semantic prompt,
drivers, policy, source or task kinds; Derived entries use file and must be
nonempty; manifest-tree file kinds remain structural. OrgSnapshot uses both
exact selectors in the authenticated config. The current initial validator
requires empty Derived, so the fixture cannot be made compatible with the full
rule merely by changing its kinds or adding an unvalidated placeholder. G2
records the required owner coordination and real generated inventory.

894a31f changes current-claim checking, transient stage errors, failed-plan
cleanup evidence, credential lookup, opened history and revocation/collection.
It changes no LaneStart handler or root-session/probe contract. c43d622 is
test-only. Neither commit supplies the G1-G11 missing integrations. No merge,
test, cloud action, authentication or real model request was performed here.

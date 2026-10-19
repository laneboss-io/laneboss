# Guidance fix 11 adoption

Base: 4cb2373, containing the merged fix-11 consumer. Edits remain inside this
lane's guidance and acceptance-case ownership. The user reports the integration
commit's 170 red controls green; that evidence is not this consumer's runtime
acceptance. The subsequent Linux unit/faults run on that base failed replay
setup; the correction below still requires Linux runtime verification.

## Retained claim fixture correction

Fix 11 section 5 keeps ClaimID and original owner facts immutable on completed
claims and fixes one total deadline at creation. It provides no legacy claim
exemption. The old replay fixture carried those fields but its zero-byte task
failed the shared positive-task requirement, producing the generic
owner/deadline refusal. Production reservation validation remains in place.

Replay setup now reads actual nonempty task bytes and their digest, obtains
the candidate snapshot, reserves through the stateful ReserveGuidance port,
and completes through a shared-validated transaction with original cause,
pending CAS, epoch, turn pointer and event. Scored and pathless human fixtures
use their actual candidates before reservation. Only negative tests corrupt
completed records. Setup retains its request and transaction trace; replay
observation counters are reset separately.

Setup avoids the replay validators and reply-sealing path being mutated, so
replay defects reach each named assertion. Pending observation starts from a
pending reservation, signals entry to protected await, and receives the owner's
actual completion with no new reservation or judgment. It never rewinds a
completed claim into pending. A timeout remains a setup failure, not a kill.

An exact continuation reply may retain the original positive run in the same
life, bounded by the authenticated request's run. The exact key/digest, task,
turn, claim validation and byte-equality checks remain. Foreign lives, zero
runs and future runs refuse before reading the claim.

## Current authorization and retained policy

Self access remains authenticated own life or a current bound human session,
with lane proof/read metadata and worker scopes refused before reads.
ReadAuthority is refreshed from the connection at entry/reply, and no ProofUse
is consumed for human preview. Source/role labels confer no authority.

Completed exact receipt replay validates exact config/actor/key/digest through
PolicyGenerationForReplay, loads PolicyAt and checks the retained selection.
It precedes mutable turn preflight. Other keys and human previews of the same
turn use the existing claim's original policy, task, snapshot and binding items.
Current policy remains the authorization context; a historical result grants
no permission to execute a new action under old policy. Future/unknown snapshots
and current revocation still refuse.

Fresh selection uses the current approved generation and refreshes only the
live lane policy projection after proving there is no claim. It does not
rewrite old grants, launch records or receipts. The tests model generation 3
completion, D6 generation 4, lane replay, human preview and fresh generation 4.

## One evaluator and one completion

selectFresh retrieves complete candidates and task bytes, reads the actual
positive remaining life budget and allocates a random attempt ID. ReserveGuidance
owns atomic creation under the pending public receipt, expected turn revision
and cancellation epoch. An invocation gets evaluation rights only with Acquired
and matching GuidanceCanEvaluate pins. A same-key retry or observer awaits the
retained result. No first-read or matching ClaimID heuristic is used.

Judge input contains actual full task/candidate bytes, approved current pins,
role, target/turn, grants hash, cwd and authoritative cost cap. Private evaluation
uses complete batches, one entry budget of at most five seconds and remaining
cost. Existing typed dependency, authority and integrity errors are preserved.

Internal completion carries original owner causality, pending claim CAS and
epoch. It commits result/turn pointer/event atomically, verifies read-back, and
then seals only the public reply. Expired/interrupted recovery commits one
unavailable result with exact retained bindings, no new judgments or score.
RecoverGuidance cannot reserve a missing claim. Competing completion can only
replay an already completed identical claim. No second provider call or new
owner is allowed. The service/store/outbox owns durable scheduling and real
current authorization, as detailed in CONTRACT-GAPS.md.

## Fable P3 decisions

Internal callers use an empty method, preserving authentic scope and pending
cause; lane.turn is not silently reinterpreted. TestInternalMethodContract
checks both forms. This package registers no new RPC.

Known empty history is returned before the post-ranking context interruption
fallback. TestEmptyAfterRankingCancel uses deterministic cancellation from
the clock callback and requires empty/zero with no judge. Explicit unavailable
fallback still clears scores, including if it is called on an empty baseline.

## Controls and limits

All 97 earlier control names and 63 earlier Go test function names remain.
Five control edits were ported to the implemented paths: fake-completion now
drops an actual ReserveGuidance dependency error; pending-as-new skips protected
await; replay-turn-policy and replay-scope-policy introduce the forbidden
current-generation barrier; replay-reservation-policy removes both retained
generation comparisons. These ports preserve their intended boundary under
the new contract rather than requiring the superseded refusal behavior.

Nineteen local consumer controls were added, including the six named
f11-guidance-win, f11-guidance-owner, f11-guidance-rejudge, f11-guidance-cause,
f11-guidance-cas and f11-guidance-epoch controls. They edit owned product
code and target real consumer calls/transactions. Four regression controls
cover retained owner/deadline validation and exact continuation/target rules.
The catalog now has 120 entries: 111 ready components and nine pending
installed-integration controls.
Their runtime red-before-green evidence is required on Linux; none is claimed
from static compilation. Existing mutation names and test functions are kept.

New stateful fixtures compare requests, record owner attempts and CAS/epoch,
signal actual pending waiters and retain exact replies. Full nonempty task
bytes and their actual digest reach the judge fixture. They are not the real
store, transport, authenticated provider or installed E2E. The remaining
delivery controls stay visibly pending until their owners wire the real paths.

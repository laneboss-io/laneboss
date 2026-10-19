# G1/G4 integration after green17

Run 20 starts at merged source 6cd128f7, which contains identity's private
session finalization hook and the common CLI's --session-proof prelude. The
retained green17 result on c2ab4978 passed human.read.confirm and then refused
admin.publication with lb-v2-service unauthenticated, exactly
"connection has no current read authority". This document describes the
composed implementation and its static checks; installed runtime acceptance
of the new source remains pending for green18.

## Protected store read-back

internal/v2/store/session_commit.go implements identity.SessionReadback on the
actual store. Assembly's existing constructor assertion sees it through the
embedded concrete ownedState and passes it only as identity.Dependencies.Sessions.
There is no new RPC, configuration key or caller-supplied session selector.

ReadSessionCommit requires the original authenticated human.session frame and
its operation-bound proof. It checks the installed human binding, pinned native
peer lifetime, exact frame/request correspondence and current connection.
Transport verification occurs before and after the database snapshot, outside
the store lock. Under the read lock, a single read-only SQL transaction selects
all durable facts. A frozen connection supplies only its ID and binding inside
that lock; no native transport or frame callback is available there.

The receipt is loaded by the actual frame's key from receipts/replies. Its raw
request must match exactly, including request ID, idempotency key and proof.
The immutable receipt's operation and the current operations row must agree
with the completed successful reply, sequences and commit timestamp. Current
policy must match both the receipt and authenticated scope.

The typed completed reply selects the current stored session. The store checks
its actual database revision and typed revision are both the initial revision
1, and verifies reply equality, principal, credential, connection, endpoint,
revocation, presence and bounded unexpired absolute/idle deadlines. It loads
the current unique endpoint enrollment and original proof in that same snapshot.
The proof must match the exact session intent and supplied ProofRef and have
ConsumedBy equal to the completed operation. Its proof_use row must identify
the same operation, nonce, credential and presence. The actual private assertion
object must match the proof's bounded artifact reference, hash, owner/ACL,
identity origin, challenge and credential. The current credential must remain
enrolled and unrevoked. Proof lifetime is checked at the durable commit instant;
a still-live committed session does not need a renewed proof for finalization.

Every decoded byte slice belongs to the returned snapshot. Public ReadSession,
readScope, refresh/CAS and their authority gates are unchanged. The private
method neither calls ReadAuthority nor binds it. After the store lock is released,
identity independently validates its snapshot, performs the one-use bind and
reads the actual transport authority back. Its exact already-bound initial
authority may be finalized again without a second bind. A foreign socket or a
refreshed/stale initial revision cannot activate an old receipt.

## Dispatch success and post-commit failure

internal/v2/service/dispatch_mutation.go consumes the private
FinalizeHumanSession hook before returning every successful human.session
receipt, including fresh execution, another reservation winner and completed
receipt replay. The hook's session must equal the exact retained reply.

If a handler has committed its session and then returns a finalization error,
dispatch preserves that error for the current call. It does not write a failure
over the immutable successful receipt, reload success over the error or retry
the bind during that invocation. A later exact replay is independently finalized
on its actual connection. The strict raw-frame and initial-revision requirements
remain; this change does not broaden retry correlation or permit another socket
to borrow a closed CLI's session. connection.go's one-use binding and public
read/refresh checks are unchanged.

## Root start prelude

scripts/v2-serve/lifecycle.py retains each driver's original StartRequest,
RootTicketID and generated spawn key in name-start.intent.json before obtaining
a new proof. It requests a real human.session proof over the exact empty session
input and passes that returned proof file through session_proof to checked_cli.
The common option becomes --session-proof; it is not an envelope spawn proof.
Case.cli still retains the actual --request file and the full command input,
including the same retained spawn key.

The merged common CLI uses one open client for human.session, an actual
identity.self read, and the unchanged lane.start request. A receipt alone cannot
skip that prelude. The root ticket remains in the spawn body and its envelope
Proof remains nil. In this checkout lifecycle/launch.go already passes the
original authenticated scope through LaneStart/spawnPreflight, including its
connection and policy. Store.Policy and the eventual ticket reservation retain
that scope. No lifecycle production change or new ticket-derived scope is needed.

## Files changed across lane ownership

The compile repairs are isolation/linux/service_test.go and
lifecycle/launch_fixture_test.go. The helper tripwire now implements the merged
credential-control interface with observed refusal behavior. Effect fixtures
use EffectPending, EffectClaimed, EffectCompleted and EffectFailed, mapping
successful operation outcomes to completed effects rather than casting strings.

The G1 production changes are store/session_commit.go and
service/dispatch_mutation.go. Their new regressions are
store/session_commit_linux_test.go and service/session_dispatch_test.go. These
paths are under internal/v2. The G4 caller change is
scripts/v2-serve/lifecycle.py. The service omission catalog adds four controls;
existing control entries remain unchanged. Grants G3 and its assembly work remain
their owners' separate round.

## Verification and controls

TestSessionCommitReadback requires a real durable session receipt, owned snapshot
bytes, public-read refusal while unbound, no private authority access/bind, and
transport callbacks outside the store lock. TestSessionCommitIdentityFinalize
composes the real identity hook with that store and requires one bind, a usable
public session read and exact replay without rebinding. Its native peer and
previously verified assertion are explicit component inputs, not kernel,
hardware or installed-service evidence. TestSessionCommitProofTime preserves
commit-time proof validation after proof expiry while the session is still live.
TestSessionCommitRefusals checks foreign connection, changed frame, consumed-proof
operation/target, revoked credential/session, stale typed/database revision,
expiry, policy, current operation, private evidence, presence and proof-use rows.

TestSessionDispatchPostCommitError fails if successful receipt reload masks the
handler's post-commit error. TestSessionDispatchFinalization requires the hook
and actual connection authority on fresh/replayed success; refused, missing or
inconsistent finalizers must not return success. Its receipt ledger is an
explicit dispatch fixture; actual persistence is covered by the store tests.

| Omission control | Selected regression | Required reached red diagnostic |
| --- | --- | --- |
| session-dispatch-finalize | TestSessionDispatchFinalization/new | successful session receipt bypassed connection finalization |
| session-dispatch-post-commit | TestSessionDispatchPostCommitError | successful durable receipt masked the post-commit finalization error |
| session-read-proof-use | TestSessionCommitRefusals/proof_used | private session read accepted proof_used |
| session-read-raw-frame | TestSessionCommitRefusals/raw | private session read accepted raw |

The raw-frame control removes both independent exact-byte comparisons; leaving
either one intact still correctly rejects the changed frame. All four omission
source variants passed Linux amd64 vet using retained source overlays, without
changing the candidate. That checks compilation only, not reached red assertions.

The candidate passed all ten required Go vet configurations with all touched
packages and their production/test importers: Linux amd64/arm64 with default,
faults, partial/authenticator and partial/authenticator/faults tags, plus Darwin
arm64 with default and partial/authenticator tags. Every Go invocation used the
requested shared cache and readonly module mode with downloads disabled. Both
changed Python files passed byte-compilation. No project test or binary ran on
this Mac. New runtime red/candidate pass remains unmeasured.

## What green18 should show

On the authorized Linux machine, require each omission's named reached red
before the unchanged candidate passes; setup/compile failures and skips cannot
qualify. Run the focused store/service/identity and CLI prelude regressions in
normal/faults and applicable partial/software-authenticator modes.

Installed serve must retain the existing real challenge/confirm successes and
prove a new session's durable read-back precedes one-use binding. The same
connection must then perform its actual protected read. A post-commit failure
must remain a failed call despite its retained successful mutation receipt,
and foreign, revoked, stale or changed-frame controls must remain refused.
Keep the full publication/retry and org.validate checks. For each root start,
retain the new proof, spawn request/key and same-socket session -> identity.self
-> lane.start sequence with the original root ticket. Preserve independent G2,
G3 and later owner failures. Presence remains simulated and human approval
remains not proven; these runs are not authenticated AI-service acceptance.

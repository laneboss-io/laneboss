# Green16b first confirmation: challenge revision

The blocker is case (b), in identity's transaction producer. The store's
comparison is correct: confirming an unused challenge must propose the next
stored challenge revision. Before this correction, identity set Consumed=true
but proposed the unchanged revision. A newly issued revision-1 challenge was
therefore submitted as consumed revision 1 when the store required revision 2.

The authorized cross-lane correction adds `stored.Generation++` beside the
consumed proposal in `internal/v2/identity/human.go:155`. No store guard or
harness ordering is changed. This is independent of publication generation,
operation target generation, endpoint generation and credential generation.

## Observed result and attribution limits

Green16b ran source 71ab8f48 and credited 25 of 78 checks. Its retained log
records the passed human.read.challenge for method human.session, then
human.read.confirm, label human-confirm, 032-human-confirm, exit 2 in 104 ms:

```json
{"code":"conflict","message":"challenge already consumed or generation changed","instead":"Preserve the service state and repair the named prerequisite through its supervisor.","retryable":false,"owner":"lb-v2-service"}
```

The original log, supplied source archive/checksum and byte-matched trace
sources are retained in run-19 evidence. The log contains one unique reported
read-challenge ID. It does not include the raw confirmation input or a database
snapshot of the rejected transition. The measured prior failure is distinct
from the exact generation attribution, which follows from the tested source.
This Mac run performs static checks only and does not retry the installed call.

## Why the caller is not reusing an earlier ceremony

1. `scripts/v2-serve/run.py:908-909` enrolls the human and then publishes the
   initial state. Registration's enrollment challenge is a separate create
   ceremony, not the later operation-bound human.challenge being confirmed.
2. `run.py:378-385` completes initial publication and its exact retry before
   beginning the public read-back. The first marker read at line 390 calls
   publication_blob, whose read at line 355 enters HumanRoot.read.
3. `scripts/v2-serve/human.py:132` creates that read's human.session proof.
   Its proof method at lines 72-101 obtains one intent, calls human.challenge
   once, signs the actual returned challenge file, checks the assertion's
   challenge ID against that response, and calls human.confirm once. There is
   no publication call, challenge replacement or confirm retry in this path.
4. `run.py:235-251` raises on a nonzero checked CLI result and preserves the
   typed refusal. A failure cannot silently become another confirmation.

No harness request is changed to issue a replacement challenge or to evade a
publication ordering bug. The returned challenge and its operation digest
remain the exact ones signed and confirmed.

## The wrong handoff and the correct comparison

`internal/v2/identity/human.go:57-59` issues StoredChallenge with Generation=1
and the zero-value Consumed=false. `internal/v2/store/identity_writes.go:49`
also rejects a new challenge that is consumed or has a generation other than 1.
The challenge is not marked consumed at issue.

Confirmation loads that row at `identity/human.go:102`. Its check at line 107
rejects a row already consumed before proceeding to signature verification;
that path would return identity's unauthenticated refusal, not this store
conflict. Before the fix, line 154 only changed Consumed on the proposal.

The exact deciding predicate is `store/identity_writes.go:36`:

```go
scope.Request.Method != "human.confirm" || prior.Consumed || !challenge.Consumed || challenge.Generation != prior.Generation+1
```

For a first confirmation, the old proposal has Generation=1 and the retained
prior has Generation=1, so its last term is `1 != 2`. The resulting line 37
is exactly the observed conflict message. The corrected proposal is generation
2. Store still compares the unused retained row and the next revision under
the same transaction, then verifies all immutable challenge facts at lines
39-42. An already-consumed row or a stale/jumping revision continues to refuse.

HumanChallenge.BaseGeneration is the approved operation target's base, not the
challenge row revision. For this human.session intent the harness supplies 0.
Publication does not participate in the comparison above. Credential counter
CAS remains independently bound to CredentialCounterChange.ExpectedGeneration.
The contract at docs/design/v2-contracts.md:1990-2019 requires atomic stored
challenge use, verified counter update, proof, private assertion evidence,
event and reply; the correction keeps that single handoff and all its checks.

## Regression and red controls

TestConfirmGenerationFixture in identity/confirmation_generation_test.go runs
real assertion verification and observes the resulting atomic handoff for
stored challenge revisions 1 and 9. The operation bases are independently 0
and 71; enrollment and credential revisions are 19 and 23. It requires the
next challenge revision, unchanged nonce/intent/principal/connection facts,
an untouched precommit stored row, and the independent verified counter CAS.
The callback is a transaction observer, not evidence of a durable store commit.

The registered identity omission control omit-confirm-generation-advance
removes only the new generation increment from a disposable source copy. Its
selected TestConfirmGenerationFixture/fresh must reach exactly:

```text
fixture check: confirmation did not advance the challenge revision
```

The unchanged candidate must then pass the same test. Compilation failures,
setup failures, unreached assertions and skips cannot qualify as red. All 273
prior omission controls and 96 fixture entries are preserved; the catalogs
now contain 274 controls and 97 fixture entries. The new selector is shorter
than 40 characters, and its source anchor is statically verified as unique.

TestChallengeGenerationCAS in store/challenge_generation_linux_test.go uses
the real SQLite challenge writer. It requires issue to retain unused revision
1 and valid confirmation to retain consumed revision 2. Its stale, jump and
used inputs require conflict; its changed immutable target requires forbidden.
After each refusal the previously retained challenge must remain identical.
This isolates the store guard using explicit enrollment/connection fixtures;
native authentication and the complete signed durable transaction remain
installed acceptance work.

All ten vet configurations passed on Go 1.26.5, Darwin arm64: Linux amd64 and
arm64 with default, faults, partial/authenticator, and partial/authenticator/
faults tags; Darwin arm64 with default and partial/authenticator tags. Scope
includes both touched packages and their transitive production/test importers.
Every Go invocation used /private/tmp/lb-shared-gocache and readonly module mode
with downloads disabled. The regression and red control are authored and
type-checked, with runtime red/pass qualification still pending on Linux.

## What green17 should show

First qualify omit-confirm-generation-advance with the existing identity
run-controls.sh on the authorized Linux machine, in normal and faults modes,
using the exact candidate source and unchanged test bytes. Require the named
red assertion followed by candidate pass. Run both new focused tests with
normal/faults and dedicated software-authenticator configurations as applicable.

Then run installed serve without changing the original ceremony sequence.
Require human.read.challenge and human.read.confirm to pass for the same
returned challenge and exact digest; independently retain the unused revision
1 to consumed revision 2 transition, proof, counter update, private evidence,
event and exact reply as one committed operation. Continue to the real
same-socket session/read gate and preserve any independent G1/G4, G2 or G3
owner failure. Presence remains simulated and human approval remains not proven.

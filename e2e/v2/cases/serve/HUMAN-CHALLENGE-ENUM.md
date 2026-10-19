# Green15 first human challenge: event origin

The rejected enum is `Event.origin = "cli"` in identity's transaction, not
`HumanChallengeRequest.method = "human.session"` in the harness input. The
closed event schema is correct. Identity's event producer copied the internal
request transport into the event trust origin. The producer now emits
`origin: "service"` for its authoritative human events, retaining the actual
authenticated human in both `actor` and `requested_by`.

## Observed failure and evidence limits

The retained installed green15 log for source `29de3815` records
`human.read.challenge`, command label `human-challenge`, evidence label
`030-human-challenge`, exit code 2, and 105 ms. Its exact error is:

```json
{"code":"invalid_request","message":"unknown schema enum","instead":"Correct the bounded schema-2 file input and retry.","retryable":false,"owner":"lb-v2-service"}
```

The log and source archive are retained under the lane's run-18 evidence,
with checksums and byte-matched copies of the twelve source files used for the
trace. The relevant identity, service, store and wire files match the tested
green15 revision. The later harness session read-back assertion is the only
difference in human.py; its challenge preparation and read intent are unchanged.
The supplied evidence does not contain the raw challenge request or a retained
failed event. Thus the error and command exit are measured; the precise field
attribution below is a deterministic trace through the tested source, not a
new runtime capture or a passing rerun.

## Exact source trace

Paths below are relative to the repository. Line numbers refer to the run-18
checkout, with the old producer line and the earlier harness line called out
explicitly. The contract and schema remain unchanged.

1. `scripts/v2-serve/human.py:132` (green15 line 122) requests a proof for `human.session`, with
   `{}` as that operation's input. Lines 81-86 obtain the authenticator's
   operation-bound intent and send it through the real `human challenge` CLI.
2. `cmd/laneboss/serve-authenticator/main.go:219-233` constructs exactly
   `HumanChallengeRequest`: method, target ID, request digest and base generation.
   `internal/v2/api/identity.go:3-8` defines those four fields. There is no
   event origin or transport source in that request. `api/methods.go:25` admits
   `human.session` as a mutation with `human-proof` access. Identity's
   `validation.go:36-44` accepts that intent class. Changing this method would
   change the operation being authorized and invalidate the read-session proof.
3. `internal/v2/client/wire/json.go:329-332` validates Method against the RPC
   catalog and reports `unknown RPC method` for an unknown value. That is a
   different error from the observed `unknown schema enum`. The relying-party
   URL in `HumanChallenge.origin` is also a different field; the enum switch
   does not restrict it to event origins.
4. `internal/v2/service/server.go:435` sets the authenticated internal
   `scope.Source` to `cli`. `internal/v2/identity/human.go:60-61` invokes
   `commitHuman` for the actual challenge. Before this correction, line 342
   set that new event's `Origin` to `scope.Source`, necessarily producing
   `Event.origin = "cli"` for this installed CLI path.
5. `internal/v2/store/transaction.go:266-267` validates the emitted event using
   `wire.ValidateEvent`. `internal/v2/client/wire/schema.go:36-37` admits only
   `service observation legacy_import` for Event.origin; lines 104-112 return
   the observed `unknown schema enum` when the value is `cli`.
   `wire/json.go:27-29` supplies the observed bounded-input retry instruction.
   This is an event transaction validation failure, despite that generic
   instruction referring to caller input. A replacement harness enum cannot
   repair it.

## Contract reason and correction

`docs/design/v2-contracts.md:494-498` specifies exactly those three origins
and reserves authoritative identity events for trusted service emission. Its
emitter table at lines 511-514 assigns human challenge, confirmation and session
events to identity. The store independently requires service origin for these
authoritative kinds at `internal/v2/store/transaction.go:284-285`. Selecting
observation or legacy_import would still violate that rule even if the enum
decoder admitted it.

The same contract at lines 239-243 defines Scope.Source as internal,
server-derived request provenance, including cli. It is not an event origin
or a field the harness can change in its mutation body.

The correction is confined to identity's shared `commitHuman` event producer.
It also covers confirmation, session and ticket events emitted through that
helper. The incoming method, operation digest, target, generation, WebAuthn
origin/RP, real challenge and proof checks remain intact. The event's human
actor/requester remains intact, as required by the contract's actor rule at
lines 478-481. No schema enum is added and no store validation is relaxed.

This does not implement G1's session read-back/bind cycle, G4's root-start
preflight, G3's protected root profiles, or G2's full org validation. Those
owner requests still apply. The green15 publication repair remains adopted.

## Static verification

Go 1.26.5 on Darwin arm64 completed gofmt and `go vet -mod=readonly` over
identity plus its transitive production and test importers, selected from
each configuration's actual Go metadata. All ten configurations passed:
Linux amd64 and arm64 with default tags, fault tags, partial/authenticator tags,
and partial/authenticator/fault tags; Darwin arm64 with default tags and with
partial/authenticator tags. The Linux importer closure contains 22 packages,
or 23 with the authenticator tag; Darwin contains 20 or 21 respectively.

Every Go command used the ignored `.lane-gocache` inside this worktree.
Downloads were disabled. The initial `-mod=vendor` metadata attempt stopped
with inconsistent vendoring; its exact output is retained, and the successful
attempt follows Go's documented `-mod=readonly` alternative. These are static
type/vet checks, including test compilation, not test execution or a new
installed-service build. The existing installed harness is the runtime
regression gate; no new unit-test pass is claimed.

## What green16 must show

Run the installed credential-free software-authenticator path with the actual
partial/authenticator build tags and the corrected producer. Keep the exact
intent input/output and challenge request/response, then require
`human.read.challenge` to return the real operation-bound challenge with method
`human.session`. Verify its committed `human.challenge` event has service origin
and the actual authenticated human actor/requester. An accepted request alone
does not prove the durable event or successful later authority binding.

Continue through real confirmation and the same-socket session/read gates;
retain every independent owner failure instead of crediting a session receipt
or substituting a method. Keep the publication/retry read-backs, full
org.validate and new live session read assertion. Presence remains simulated
and human approval remains not proven. Run 18 performs static checks only;
green16 owns runtime acceptance and no end-to-end success is claimed here.

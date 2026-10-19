# Credential projection state

The private store lifecycle implements Draft.4 fix 12's native transfer,
holding, withdrawal, and prepare/open fences. A configuration and prepared gate
select one durable record; a separate projection-ID index selects that same
gate during withdrawal. Both rows and their history commit in one SQLite
transaction. Revisions progress from reserved to held to withdrawing to
withdrawn, with exact fence and completion replays returning their original
records. A second holding commit refuses; broker acknowledgement replay reads
the already committed holding instead.

Reserve checks the current helper-prepare lease and retained plan, handoff,
allocation, home, grants, policy and cancellation epoch. A reclaimed attempt
can replace only the claim on an unchanged reserved request. Commit compares
the submitted receipt with an independent helper observation, then repeats
the current claim and row checks under the writer. Cleanup requires the
retained abort, stop or release effect for the same gate or allocation and a
live claim. Completion additionally requires all helper and broker counts to
be known zero. No credential values, descriptors or source pathnames are
stored here.

`Dependencies.CredentialProjection` is an installed native metadata/control
port. It must authenticate the helper and outside broker executables,
lifetimes, boot and installation and join the actual current source inventory.
It does not assign the projection ID, revision, request or targets. Its holding
observer must measure the helper's existing held objects. Calls occur outside
the store writer lock, including the recheck used immediately before a fresh
opening. During acknowledgement the broker already owns its canonical journal
and refresh lock, so the port must not recursively enter that journal.

The default assembly constructs its deferred native source before the store,
binds the real administrator client, and connects the real data worker before
publishing runtime. Native source and holding reads use a separate authenticated
metadata endpoint. The ordinary helper remains serialized; its state lock is
lent only during authenticated outside-owner exchanges and regained before
mutations resume. The outside broker lends its actual canonical journal read
capability during acknowledgement, so metadata callbacks do not recursively
acquire that journal. Native facts are never filled from request labels.

Channel and usage workers join their assigned durable lease, current job claim,
immutable sealed input, enrolled runtime, current issued grants and cancellation
fence. Usage selection comes from the existing sealed usage input; channel
selection joins the protected enrolled destination to its exact current source.
Worker handoffs are registered under the explicit current job attempt before a
helper prepare can claim them. Capture and materialize acquire no credential
permissions through this path.

Cleanup fencing, completion and their replays require the explicit exact current
effect attempt. A retained author's actor is not the current claimant. Private
native frames carry an existing attempt without creating one from a stored head.
Fresh independent holding measurements may have a later observation time; all
objects, counts, ownership, targets, generations and the closed gate must match.

Missing native support still refuses with `prerequisite_missing` and the exact
reason `credential projection requires its installed native metadata source`.
The composed regressions execute the actual assembly source adapter, store,
encrypted broker, identity, planner, reconciler and protected worker selector.
Privileged helper/gate/home/peer observations remain explicit component fixtures.
The native callback canary measures actual Unix frames, SCM writers and pidfd
liveness. These tests do not certify installed privileged credential delivery
or an authenticated AI-service launch.

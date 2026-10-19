# Item 2C and 2D candidate handoff

The later merge and recovery result is in [ITEM-2-MERGE.md](ITEM-2-MERGE.md).
It supersedes this round's premature-drain limitation and records the single
grant-policy owner alongside the preserved native resource owners.

This candidate implements durable grant revocation for retained agent runs and
their registered capture workers, and sealed continuation of already-issued
child authority after a measured ancestor exit. It does not certify the
installed item-2 checklist or replace the independent native/owner prerequisites.

## Revocation

The public grants handler passes its original frame and atomic human-proof
guard to the private writer coordinator. Under the sole SQLite transaction,
the writer derives the affected grant sets from authentic parent lives and
retained root-template ceilings. It verifies the current controller, exact
generation, retained reason and collection prerequisites, revokes each set,
advances affected cancellation epochs, cancels continuations and retains Stop
effects with the original request, operation and requester. Exact replay
returns the original reply. A generic grants.revoke transaction cannot submit
its own affected lives, service events or process handles.
Current lane/worker authorization checks the revoked grant projection at the
writer head, so new reads and mutations stop at commit before transport closes.
The standard error-only receipt route retains prerequisite refusals and exact
replay without changing grants or consuming authority guards.

The installed reconciler invokes causal lifecycle revocation before stopping.
The original identity binding remains immutable recovery evidence. The current
launch projection, endpoint and identity.revoked decision are committed before
the actual authenticator closes transport. Its validated receipt is read back
and retained under the live Stop claim. Zero survivors alone cannot complete
revocation. RecordStoppedRun retains the real end and stable HelperRelease;
an earlier release keeps its original operation and must finish before the new
revocation can succeed. Interrupted claims reuse those same effects.

Native release drains the exact capture streams and measures containment,
connections, jobs and writable exports. A final collection stage revokes the
registered captured-worker identity and validates transport close under the
same release claim. Completion checks those retained decisions and receipts.
It cannot substitute the agent's measurement for an independent worker or an
external resource owner's collection.

Missing retained native process facts, an unbound launch cleanup, an independent
worker without its causal/native/transport collection or external resource
collection returns prerequisite_missing. Those owners must supply their real
measurements. No owner completion, model authentication or narrower restart is
fabricated. Already-read copies cannot be recalled.

## Post-exit delegation

The writer seals an eligible direct child's existing scope at the ancestor's
actual lane.ended commit. The private, domain-separated HMAC binds both exact
grant sets, the original parent launch and cancellation fence, authentic child
creation, measured parent end, policy and expiry. Restart verification checks
the seal and immutable source records, independently of generic projection
history checksums.

Revalidation and retained-starter resolution require that lease for an
accepted, merged or abandoned ancestor. They still check current grants,
policy, run, ancestry, revocation and expiry. Lost/unknown containment, missing
leases, changed authority and cleaned lives refuse. A lease preserves only
previously delegated child scope; a terminal ancestor cannot issue a new child.
Ineligible children receive no lease and do not prevent recording a real end.

## Composition hooks and verification

The production hooks are confined to grants' handler/revalidation, the store's
transaction / authority / effect / verification paths, lifecycle revocation and
release, identity transport read-back, and the service Stop/HelperRelease
executor and retry path. No public RPC, schema field, administrator production
code, runner, capture producer or materialization implementation is added.

The existing tagged native release test harness has two new driver dispatches
and one exact stop dispatch. Its natural-release driver has an optional prior
child setup and final lease assertion. These are test-only hooks. The native
canaries use the actual helper, kernel process/cgroup measurements, capture
drain and file-backed release journal, with the SQLite writer running under
its unprivileged UID. Ancestor/child authority fixtures are identified in the
drivers; they are not human-presence or authenticated AI-service evidence.
The delegation driver establishes real pipe EOF before its first collection
call. Earlier attempts using the natural-release driver's premature-drain
sequence retained an EOF prerequisite failure; recovery of that sequence is
not claimed here. The existing premature-drain case remains separate.
The browser enrollment test uses its lifecycle API port instead of importing
the concrete lifecycle implementation, which removes a tagged test import cycle.

External round-2 evidence retains baseline reds, reached negative controls,
candidate package results, native results and the required static vet targets.
The earlier item-2 handoff and its owner steps remain applicable to all other
gates. No Git operation, installation, deployment or owner message is performed
by this candidate.

The final named Linux package run passed 2,482 tests with zero failures and
zero skips. Candidate-only vet is clean for Linux amd64, Linux amd64 with
laneboss_faults, Darwin arm64 and Linux amd64 with both native integration
tags. Baseline failures and reached controls are retained in the lane's
separate round-2 evidence; no archive or manifest is produced in this light round.
Both final native tests, TestGrantCascadeNative and TestSealedDelegationNative,
passed with the root/integration tags, including actual helper release and
state verification. Installed human/vendor acceptance remains open.

The exact shared test hooks are the driver/stop dispatches in
internal / v2 / admin / release_join_root_test.go, the optional prior-child setup and
lease assertions in internal / v2 / service / release_canary_linux.go, and the unused
dependency adjustment in internal / v2 / identity / browser_enrollment_test.go.
No production administrator, assembly, dataworker, capture producer or
materialization file was edited for those hooks.

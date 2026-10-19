# Item 2 merge and recovery handoff

This round resolves the three conflicts between the round-2 candidate
`0b09a243` and serve2 `cf30d484`. The item-1 planner implementation and its
check words were left unchanged. No Git operation was performed by this lane.

## Conflict decisions

The reconciler retains transient completion retries for ApplyChange, Stop and
HelperRelease. Its existing execution retries, including Deliver, remain.
The store requires the original completion claimant for PlanLaunch,
HelperRelease, Stop and Deliver, while ApplyChange keeps its dedicated guarded
publication completion path. Existing claim, generation, launch, outcome and
read-back checks remain in force.

The transaction writer retains both the private grant cascade and serve2's
change admission, public lane-event admission and lineage checks. Service
event attribution covers lane.check, the private cascade, org.change.propose
and org.change.approve. Downstream actor and requester checks remain in force.
The union is in service/reconcile_attempt.go, store/effects.go and
store/transaction.go, all under internal/v2.

## One owner for each decision

The round-2 private store cascade remains the only public grants.revoke
coordinator. The store's delegation lease remains the only seal for prior
child scope after a measured ancestor exit. Their grants handlers, identity
collection and lifecycle ports remain the control path.

The merged administrator export journals, registered export gate, egress and
native containment revocation remain the resource owners. Assembly retains
the per-run runner enrollment gate. These enforce native resource and vendor
prerequisites; they do not implement another grant cascade or delegation seal.
No second policy implementation or substitute success path was added.

## Premature drain recovery

The native canary's claim-expiration fixture closes and reopens the writer.
The service host was rebound, but its lifecycle coordinator retained the
closed writer. After real pipe EOF, the second attempt therefore deferred
with run_unavailable_service and never committed a release receipt.

The tagged driver now rebuilds that coordinator from the reopened store and
the same identity, clock, dispatcher and native observer. Natural release and
sealed delegation share one sequence: attempt before EOF, retain the same
claimed effect without a terminal outcome, close the actual writers, wait for
producer EOF, expire the claim, reopen and rebind, reclaim the original effect,
then drain and release through the real helper. The former delegation bypass
of the premature-drain attempt was removed.

The canaries check the exact helper receipt and effect/operation pins, native
zero-resource measurements, exact completion replay, retained output, one
lane.ended and helper.released, capture closure after the end and before the
release, and full store verification. Delegation additionally checks its seal
before and after recovery and rejects the parent's own grant set. The native
EOF and containment guards were unchanged. This fixes test composition after
writer restart; it does not weaken production recovery requirements.

## Verification and limits

Linux queue request 1792247449915-79702 passed 935 tests, with zero failures
and zero skips, over service, store, grants, lifecycle, messaging and approval.
Request 1792247830492-43255 reached the native recovery failure described
above. Request 1792247912529-53639 passed the repaired natural-release test.
Request 1792248042629-69368 passed the natural-release, grant-cascade and
sealed-delegation native tests, with zero failures or skips. Native requests
used both root and integration tags and the actual helper on disposable Linux.
Each successful request also passed the queue's vet step. The lane's external
round-3 evidence records the final whole-package run and local candidate vet.
The full plain request 1792248288753-8844 exited zero and reported 32 successful
package results. Its result omitted aggregate counters, so no total test or
zero-skip count is inferred. Candidate vet passed Linux amd64, Linux amd64
with fault tags, Darwin arm64 and the affected native integration packages.
Request 1792248736741-71543 additionally passed both serve2 native capture
monitor and planning-deadline tests, with vet/test exit zero and no skips.

Unbound launch cleanup still needs its retained cleanup owner. Independent
workers need their own causal identity, measured helper release and transport
collection. External resources need their owner's measured collection. These
remain typed prerequisite waits; a lane's zero-survivor count cannot satisfy
another owner's collection. No planner shortcut or fabricated owner receipt
was added.

Administrator installation, genuine human confirmations, vendor enrollment,
budgets and claimed hardware gestures remain owner steps. No installed human
or authenticated model-service acceptance is claimed. Earlier handoffs remain
applicable except that their separate premature-drain recovery limitation is
superseded by the shared passing native sequence described here.

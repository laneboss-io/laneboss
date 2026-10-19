# Natural exit and stop ordering

The normal-completion requirement below is approved and incorporated into
[the contracts](design/v2-contracts.md). It grants no new credential authority.

The native helper's credential decision uses its protected lease journal.
`Gate.State == ended` and the validated, handle-matching `Gate.Observation`
must already be committed when it selects the stop disposition. A successful
kernel wait, process absence, capture EOF or wall-clock comparison cannot
replace that record. A stop that wins this ordering retains rotation even if
a later wait discovers that the process had exited naturally.

The service's `lane.stopping` intent and its later `lane.ended` event are
separate commits. The native credential decision and the service's run-end
reason therefore need separate evidence. Current code chooses credentials
before the native stop fence in `internal/v2/admin/gate.go`; lifecycle end
reason follows the service intent in `internal/v2/lifecycle/control.go`.

## Approved normal-completion requirement

For normal completion, the helper shall validate its original wait owner,
the exact process handle and zero survivors, then durably commit the native
exit before removing the live containment registration or its cgroup.
The retained terminal record shall survive removal and helper restart.
If that commit fails, cleanup shall retain ownership and refuse completion.
Credential return shall import any supported refresh through the existing
broker checks before freeing the canonical seat.

Revocation, cancellation, boot mismatch and lost native ownership shall
remain distinct from normal completion. They may deny live authentication
before a terminal record exists and shall retain the applicable rotation
requirement. A generic `containment_unknown` response shall never prove a
natural exit or authorize credential release.

The current ordinary release already saves its ended observation before
resource removal in `internal/v2/admin/lease.go`. The containment refusal in
`internal/v2/admin/containment_linux.go` also covers revoked records, inactive
phases and boot mismatch; its message does not mean that `Spec` was deleted.
An unconditional rule that every missing current registration means natural
exit would weaken those cases. The proposed ordering applies to normal
completion only.

## Race exposure and measurement

The reaper in `internal/v2/admin/gate_wait_linux.go` retains its wait result
in memory. A trusted observation commits the exit through `observeGate`.
Each naturally ending run can have an interval between those two steps.
Stop preflight normally observes that exit; an exit between a running
preflight observation and the native stop fence can still lose the durable
ordering. This patch keeps that conservative result.

No daily incidence rate is established by the available evidence. The two
initial lifecycle lanes in the supplied installed run were observed running
and later reported signal 9. Those samples measure live cancellation, not
the frequency of natural exits during the commit interval. A daily rate
requires counters for native exits, committed exit records and stop-fence
order, with values and private selectors excluded from aggregate reporting.
Proactive journaling on natural wait completion could narrow the interval;
that would require serialized native validation and a commit before cleanup,
plus fault/restart controls. It is a separate product change for L6 review.

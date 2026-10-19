# Bounded helper relay replies

The helper work deadline formerly expired at ten seconds, before the
fifteen-second forwarding child could finish. The same expired socket write
deadline then prevented the refusal from reaching the CLI. The handoff also
showed a service with ten seconds of work and a separate one-second refusal
writer. This repair preserves that service work limit and reserves time at
each surrounding hop.

| Boundary | Maximum | Reply contract |
| --- | --- | --- |
| Service work | 10 seconds | Its transport survives for 11 seconds. |
| Daemon to service | 12 seconds | Covers service work, its reply and hop slack. |
| Helper work | 13 seconds | The forwarding child reserves one second inside it. |
| Helper transport | 14 seconds | Work expiry leaves one second for the final write. |
| CLI or ordinary service client | 15 seconds | Covers the helper transport and hop slack. |

These are fixed upper bounds. An earlier inherited deadline shortens local
work and preserves a reply reserve; it never extends that parent. A forwarding
hop refuses before dialing if its remaining time cannot cover the service's
ten-second work and one-second reply. Dial/read/write cancellation still closes
the outgoing socket. Parent shutdown closes the responder socket immediately;
work expiry alone leaves it alive until its transport bound. Both successful
and refused replies get their own bounded write deadline, clipped to that hard
transport limit. A failed reply write retains only a fixed stage, a catalog
code and an allowed component owner in its diagnostic.

The baseline of this slice lacked the later root-daemon relay described by
the installed handoff. The fixed native relay and shared administrator frame
contract from that handoff revision are brought forward here. The external
root CLI proves its installed artifact to the daemon; it does not borrow the
unit's cgroup or connect directly as an invented service peer. The daemon
selects only the protected canonical installation and forwards only the three
fixed administrator forms. Root callers cannot dispatch ordinary helper
methods, and service callers cannot enter the administrator relay. Native
credentials, message writers, pidfds, installed artifact, unit, endpoint,
nonce and installation rechecks remain. The stronger exact initial receipt
bindings from the handoff are retained as well.

## Complete command audit

All ordinary methods use Service.call, its fifteen-second context, the same
bounded socket adapter, native pinning and the helper responder window:

| Family | Methods |
| --- | --- |
| Probe and lease | probe, allocate, allocate_launch, prepare, release, abort |
| Runtime and storage | register_spec, resolve_runtime, resolve_storage |
| Gate | open_gate, observe_gate, stop_gate, reconcile_gate |
| Capture | register_capture, reconcile_capture |
| Containment | containment, containment_revoke |
| Data | data_open, data_query, data_selector, data_lease, data_register, data_prepare, data_gate, data_observe, data_measure, data_revoke, data_collect |

All three administrator forms, enroll_begin, enroll_complete and
initial_publish, use runEnrollment, relayEnrollment and forwardEnrollment.
The distinct service-owned listener in the integrated deployment must retain
its existing ten-second work and eleven-second transport contract when this
slice is combined. The admin-owned ServeEnrollment path uses the same split.
No other administrator helper IPC dial or request responder exists in this
source. The separate 250-millisecond stale-socket liveness observation is not
a command relay and retains its existing contract.

## Typed receive failures and deciding regressions

A timed-out receive returns deadline_exceeded and the fixed message
"helper frame receive timeout". EOF before a frame, reset or closed socket
returns unavailable and "helper frame peer closed". A partial EOF or invalid
length returns invalid_request and a fixed malformed-frame message. Native
paths and wrapped cause text never enter these peer errors. Native writer or
descriptor violations retain their stricter forbidden refusal. Explicit
context cancellation remains cancelled, and an expired caller cannot accept
a successful frame.

TestRelaySlowPeer requires exact random response bytes after a real delay.
TestRelayLateReply requires an actual timeout, a correlated typed refusal at
the caller after work expiry, and rejection of the peer's late write.
TestRelayClosed requires the closed-peer code and message at the caller.
TestPeerReceive covers native timeout, closed, partial and length cases.
TestReceiveSanitized rejects native-cause and diagnostic-message leakage.
TestHelperBudgets checks nested and shortened deadlines, including refusal
before a service call with insufficient remaining time. TestRelayCancel and
TestWindowCancel require the outgoing and parent-cancelled responder sockets
to close. TestReplyBound requires a blocked refusal write to end within its
short window. TestRelayCaller and TestRelayBinding reject crossing the native
caller, endpoint and envelope boundaries.

The mutation catalog retains all 239 previous controls and adds 16 deciding
controls for these regressions. Each new row has one source edit and a named
runtime failure; compilation failure cannot count as killed red. This Mac is
authorized only for formatting and static checks. Native unit, fault-tag,
mutation and installed-service execution remains for disposable Linux. The
installed publication's load/validate/commit/read-back phase cost is still
unmeasured here; this structural deadline repair does not establish that the
publication fits the service work limit or that its durable receipt was read
back. There is no automatic retry or weakened object verification.

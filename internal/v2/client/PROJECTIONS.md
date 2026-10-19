# Native lane and worker projections

This implements the consumption and lane binding portions of v2-contracts §2,
§14 "Binding, connection lifetime and every-message identity", and fix-11
items 4 and 9 (LP-DATA-JOB-1). File ownership follows the service/admin/grants
sections of v2-lanes. Native tests and installed acceptance remain required;
this document is an integration handoff, not a passing E2E claim.

The fixed Linux destinations are:

| Capability | Lane | Worker |
| --- | --- | --- |
| Sealed binding | `/run/laneboss/binding.json` | `/runtime/laneboss-worker.json` |
| Pinned socket | `/run/laneboss/service.sock` | `/runtime/laneboss-worker.sock` |
| Installed client | `/run/laneboss/client` | The enrolled fixed worker executable |
| Exact sealed job input | None | `/runtime/laneboss-worker-input.json` |

Bindings and sockets use the existing inherited descriptor contract: a fixed
read-only namespace link to `/proc/self/fd/N`, with N at least 6. Binding reads
require all four immutable memfd seals, regular type, exact 0444 mode, bounded
strict JSON and the matching class/config/version/socket. Worker input reads
add exact reference/class/length/hash checks without changing the shared offset.
Lane and worker descriptor projections never fall back to ordinary files.
Human bindings keep the administrator-owned protected-file validation, including
when that regular human file is explicitly named at the lane discovery path.
The decoded class, rather than the path alone, selects endpoint projection;
a regular lane-class binding is refused. Binding failures retain their client
owner and stable diagnostic instead of becoming owning-service semantic errors.

PinEndpoint requires the corresponding sealed binding before retaining its own
O_PATH socket duplicate. It checks socket type, 0666 mode, link count and mapped
service ownership. Every reconnect uses that duplicate through /proc/self/fd,
checks the original projection still names the same inode, and verifies the
actual server credentials. Every reply fragment retains SCM_CREDENTIALS checks.
A server outside the private PID namespace has PID zero inside: only an owned
projected socket permits this server form. Service-side PeerCredentials still
requires a visible connector PID. NamespaceServiceIDs reads the real kernel
overflow UID/GID outside the fixed single-UID gate; host service IDs are not
copied into the namespace fields. The materialization and archive producers use
the same mapping as the lane binding producer.

Go callers must use InheritLaneCommand before starting a child CLI, then close
the returned duplicates after Start, including failure. It forwards only the
sealed binding and pinned socket at their exact original descriptor numbers.
It rejects preexisting ExtraFiles, started commands and conflicting configuration
bindings. The serve vendor fixture now uses this handoff. Programs that discard
unknown FDs need the same explicit cooperation; this contract does not make
inherited descriptors survive a launcher that deliberately closes them.
Go does preserve an arbitrary descriptor whose CLOEXEC flag has been cleared,
even when it is absent from ExtraFiles. The handoff therefore marks the parent's
nonstandard descriptor table CLOEXEC with CloseRange before Start. It leaves
the parent's handles open; only the two explicit child mappings become
inheritable again. This process-wide behavior means every concurrent child
launcher must declare its capabilities explicitly.

The service creates each lane listener under its protected runtime's
`lanes/LAUNCH.sock`, with a service-owned 0700 parent. PrepareIntent establishes
it after matching the actual retained plan/claim/spec. Its native connections
dispatch using that lane's sealed binding, including the class gate before human
administration, never the host's human binding. Replays keep the same inode and
refuse a changed binding. Preparation request cancellation leaves ownership with
the service. Revocation, terminal observation and host close cancel and drain it.
Recovery never unlinks an unexpected/stale socket or replaces a helper pin; an
unreconstructable listener remains a refusal requiring owner reconciliation.

## Gate-owner integration

The admin `laneEndpointMounts(ctx, record)` returns exactly three owned nativeMounts:
the sealed binding, pinned lane socket and verified installed client executable.
It derives the binding from the protected installation and retained spec/UID
lease, shares the existing socket-chain and fdpath pin checks, and verifies the
client bytes against the enrolled release. Partial failure closes all its pins.

startConfinedGate now obtains and appends these mounts before startNativeGate.
Its existing refusal for arbitrary RuntimeManifest.Bindings stays in place.
nativeGateArgs creates `/run/laneboss` before its projections and retains the
read-only root remount. retainBootstrapDescriptors adds only LaneBindingPath as
a sealed input and LaneSocketPath as an O_PATH socket, alongside the existing
fixed worker targets. All native type, seals, mode, size, duplicate and exact
descriptor-link checks still apply. The client mount is an ordinary read-only
executable projection; its source FD remains CLOEXEC. Only the sealed binding
and socket survive vendor exec. Installed acceptance remains required.

## Deciding Linux checks

The ordinary tests exercise real sealed memfds, exact byte reads, real socket
challenge/response, root replacement, filesystem writes, subprocess FD closure,
per-run service frames, human-method refusal and listener cleanup. The existing
grants materialization suite still exercises actual copy/home/result bytes and
the current lease/grant/claim controls. No fixture peer proves installed native
containment or authentic AI-service access.

TestProjectedServerPIDNamespace, under laneboss_gate_integration, launches a
distinct-UID service and actual bwrap user/PID namespace on the disposable Linux
test kit. It requires sealed binding input, a pinned socket, actual mapped server
ownership, PID zero, strict visible-connector refusal and matching credentialed
reply bytes. Fixture exits 101–110 identify reached client stages; setup refusal,
timeout or wrong stage is incomplete evidence, never a successful red control.

New mutation controls must run red-before-candidate on that kit. Never vet their
overlays on the authoring Mac. The lane evidence contains the exact commands,
candidate source archive and control handoff.

TestInstalledLaneGateEndpoint adds a gate-owner regression under both
laneboss_root_canary and laneboss_gate_integration. It runs in the installed
fixture's exclusive delegated root control unit with the matched release. It
first requires startConfinedGate to refuse its absent credential receiver,
then uses the shared production mount composer and actual native gate with
real private storage, an empty native network namespace, sealed prompt stdin
and the enrolled CLI as its executable. An outside peer runs
under the installed service UID/GID, receives the exact lane.status request
from the lane UID/GID, and returns a correlated strict response derived from
that request. Its observation pipe must stay quiet before gate release; the
request must arrive after release and the actual CLI must exit zero. This peer
is a transport fixture, not the production lifecycle dispatcher. This component
does not claim credential projection or capture approval; the complete installed
E2E must exercise those owners. No authenticated model access is proven here.

TestLaneDescriptorInventory is root-only with laneboss_root_canary. A child
creates its projections in a private mount namespace on a private /run tmpfs.
It exercises the actual retainBootstrapDescriptors and executePreparedGate
with real sealed memfd, O_PATH socket, release pipe and exec. Valid aliases at
unlisted targets, wrong target classes, native types, duplicates and a changed
exact projection must be refused. The post-exec child must read the sealed lane
binding, pin the socket and observe that both the unrelated file and executable
source inode are absent from its inherited table. This component canary does
not replace the installed gate regression or the composed service E2E.

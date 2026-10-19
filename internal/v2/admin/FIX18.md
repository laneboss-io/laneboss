# Installed G5/G6 administrator handoff

The source baseline is 070042a.
The complete request was inspected at 6cd128f7. Several paths named by that
handoff are newer than this checkout: the local Linux launcher and service
constructors still contain their owned stubs. The classifications below name
the actual local paths and distinguish authored implementation from observed
runtime acceptance. This Mac performed static checks only.

## G5: independent installed isolation evidence

Implemented now: admin/isolation.go:64 provides Service.IsolationEvidence.
It calls a distinct authenticated helper operation, checks the returned exact
retained bytes/pin and current boot/kernel/ABI, and validates the complete
independent proof. It does not convert generic helper checks into evidence.
admin/proof_linux.go:130 creates a durable private probe reservation before
using a free installed pool account or cgroup. This is an explicit helper
self-test reservation, not a fabricated lifecycle effect, worker principal,
human approval or service operation.

The probe uses the production runtime pins, native cgroup placement, private
namespace join, fixed bootstrap, syscall filter, Landlock and one-use release.
The outside observer requires both output pipes to be empty at closed-gate
readiness; verifies the exact helper-owned network namespace and real cgroup
inode/limits; then releases that original process once. A second release must
be refused. Its fixed installed canary requires all of the following actual
controls and observations:

- A successful host loopback transfer of fresh exact bytes, followed by a
  denied attempt to reach that listener from the private network namespace.
- A successful outside unshare(0), followed by EPERM inside the production
  syscall filter, with measured no-new-privileges and filter mode.
- An exact read of the sealed runtime input and an allowed workspace write
  with read-back, a refused runtime write, and a refused read of the same
  input after applying the production Landlock routine with that path omitted.
- Exact nonce-bound stdout/stderr, actual zero exit, native UID/cgroup zero
  survivors, collection, durable proof publication and exact persisted-byte
  read-back.

An eight-second measurement context leaves bounded collection and reply time
inside the existing helper relay contract. The doctor evidence request allows
twelve seconds for the complete helper observation. A cancelled or failed
native measurement remains a failure. The private reservation/proof bytes
remain under the helper state proofs directory. Incomplete reservations or
pending publication block helper inventory on restart instead of freeing a
pool UID silently. The evidence reference names these administrator-owned
retained bytes; it is not a fabricated service-store object.

Implemented now: service/stub.go:21 declares the matching independent port,
service/launch_control_stubs.go:59 delegates to it, and
assembly/assembly.go:110 and :115 explicitly supply the administrator provider.
The later service implementation already has this interface: on combination,
keep its verified host/control-scope guard and delegate through the same
dependency. Do not replace that implementation with the older local stubs.

Already real: the default-deny per-lease namespace implementation lives in
admin/network_linux.go. The old helper.egress placeholder now measures actual
namespace creation as its narrow prerequisite. The independent port additionally
requires the network denial control above. This supports the credential-free
fixture's empty network grants. Nonempty network grants still refuse in
admin/network_linux.go:83 and the native gate; no forwarding owner, network
permission, authenticated service or vendor readiness is invented. Native
capture pipe measurement does not credit the separate G9 capture producer,
acknowledgement or recovery integration.

Routed: local isolation/linux/stub.go:22 and :29 are owned by lb-v2-linux;
service/server.go:22 is owned by lb-v2-service. Their real constructor/launcher
landings remain necessary to execute this wiring in the installed service.
The pinned installed handoff has later real implementations; this slice does
not port or claim acceptance of those owners' complete source trees.

## G6: fixed materialization worker handoff

Already real: admin/data.go:437 and :459 enter RegisterDataWorker and
PrepareDataWorker. The latter reaches data_ctl.go's prepareData and
admin/worker_linux.go:61 startDataGate. That separate path pins the actual
source/workspace/home roots, derives only the retained worker's service-owned
socket, mounts its sealed endpoint and creates a closed production native
gate with its own UID and wait owner. The pinned service materialization
implementation already calls those explicit ports. The generic worker refusal
at admin/gate_linux.go:393 is not that path and is intentionally preserved.
No generic worker is redirected into an in-process copy or an agent identity.

Implemented now: worker_fds_linux.go seals and projects the exact retained
materialize_input bytes at /runtime/laneboss-worker-input.json. Length, digest,
class and ID must match the issued pin; all four immutable memfd seals and
0444 mode are installed. JSON whitespace is preserved. The native worker gate
revalidates its whole data seal immediately before projection. The existing
/runtime/laneboss-worker.json endpoint and derived Unix socket remain pinned
through their existing ownership, mode, link and ancestor checks.

Implemented now: worker_native.go:27 exposes DataWorkerNativeSource for the
original unopened retained job. The service facade repeats current authority,
claim, policy and revocation checks. worker_fds_linux.go:40 requires that exact
prepared gate and native owner, rechecks its inner pidfd lifetime/generation,
private namespaces, actual cgroup, executing installed artifact and all native
UID/GID fields. The observation binds the original selector, native lease,
prepared tuple, installed endpoint, boot and actual peer. It grants no permit
and cannot reopen or replace a gate. This is the concrete administrator port
for the identity/service owners' durable worker join.

Routed: identity/service.go:300, owned by lb-v2-identity, still refuses its
retained worker launch authority. Its implementation must consume the checked
native observation and join the exact committed worker lease, claim, endpoint,
identity receipt and cancellation epoch before minting a permit. The new port
does not replace that write. dataworker/internal.go:27 names the remaining
lb-v2-service/private worker bootstrap and projected-root bridge. It must
authenticate the actual worker endpoint/session, correlate the projected exact
input with WorkerInput, open only the fixed projected roots, and call the real
RunInternalJob/RunMaterialization path. These owners' missing integrations remain
typed failures. Credential files and the credential execution path were not
edited by this slice.

## Verification scope

All 22 changed/new Go files are formatted. Vet compiled and checked the full
internal/v2 tree and its identified command/fixture importers for Linux amd64
and arm64, both with and without laneboss_faults; Darwin amd64 and arm64; and
both Linux architectures with laneboss_gate_integration. Every variant exited
zero using only the shared Go cache. The mutation runner's small exact service
allowlist addition passed py_compile. No unit test, native canary, test binary,
product build or installed run executed on this Mac.

The catalog retains all 255 old rows and adds 28, for 283. The new regressions
cover actual immutable descriptors and pipes, retained proof metadata/recovery,
pool selection, adversarial proof and worker correlation, and unchanged error
delegation through the service port. Wire-shape fixtures are explicitly not
native evidence. TestInstalledIsolationProof is a separate installed native
fixture under laneboss_gate_integration; it requires the real protected inputs,
exclusive helper lock and kernel boundaries, and fails missing prerequisites.
Ordinary/faults red-before-green controls, that installed deciding red/candidate
and the composed G5/G6 lifecycle steps remain for disposable Linux. No stub,
empty receipt, compile-only result or authored canary is credited as runtime
evidence in this handoff.

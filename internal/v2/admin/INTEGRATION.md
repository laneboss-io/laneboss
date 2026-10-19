# Administrator draft.4 integration

For fix-11 adoption and the two reported Linux findings, read FIX11-STATUS.md
first. It documents the protected enrollment helper/listener, identity/store
handoff ports and the exact remaining service composition and materialization
work. A bound callback is not a running enrollment ceremony or serve acceptance.

For the current part-2 slice based on bda14f35, read FIX9-STATUS.md and
GATE-NOTES.md first. They describe the new fixed native gate, one-use permit,
registered capture I/O, native collection measurements and exact remaining
credential / endpoint / worker / forwarding / acknowledgement barriers. The sections
below are historical pre-part-2 handoff context; their method-stub descriptions
and mutation counts are superseded by those files and the current catalog.
No installed launch or acceptance is claimed.

This work continues from bdf1ec5 with the open merge of contract draft.4
(6e462a7). The working conflict in stub.go is resolved without replacing its
implemented methods with the integration stub. Laneboss owns staging, scan,
merge conclusion and all Linux runs. Only this lane's files are edited.

Acceptance for this round is ONLY the installed serve CLI/socket case on the
composed tree, with a base run failing for the right reason. Unit tests and
static checks support that result and cannot complete the round. No composed
serve PASS, root provisioning PASS, kernel PASS or mutation PASS is claimed.

Read CONTRACT-GAPS.md for exact requests to lb-v2-serve and the other owners.
REVIEW-FIXES.md maps every supplied review finding to code, a supporting test
or an explicit open limitation. Both reviews and every follow-up brief were
read completely. The supervisor's earlier Linux passes concern older slices;
they do not verify this implementation.

## Implemented boundaries

New/Register retain protected release/config/service identity checks and only
register doctor. Private IPC and installed data require contract v2.0-draft.4.
Doctor gives lanes cached actual Health or an unavailable cached-health result,
without calling the root helper or launcher. Human diagnostics share a short
cache. Its bwrap availability probe uses nobody, not the service UID, under
the verified helper unit's inherited no_new_privs. BindIsolationProbe remains
one-time and actual selected-backend checks still determine availability.
The ergonomic doctor adapter uses Invocation's shared/borrowed socket rather
than opening or closing an explicitly supplied client. The common exact-file
readiness-exit discrepancy remains integration-owned.

Doctor registers ValidateDoctorInput at CLI initialization; registration errors
stop initialization. The common file form and ergonomic InvokeRaw adapter use
that hook, and the service handler calls the same validator. It strictly decodes
api.Empty: only an empty object with optional JSON whitespace is valid. Shape
errors remain the shared decoder's exact typed invalid_request errors. Invalid
files are checked against that error before proof, request keys or sockets;
valid files must pass this lane and reach transport. The positive test accepts
only non-admin not_implemented or prerequisite_missing, without pinning another
lane's message. The latter covers the composed client's missing protected
binding. TestAdminDoctorTransport additionally checks unchanged file bytes and
the ergonomic form on an explicitly injected borrowed socket.

The doctor-input-drop mutation removes only this lane's CLI registration and
must fail TestAdminDoctorFiles/valid before a clean candidate passes. The test
checks the actual catalog owner and the registered callback's function identity
against admin.ValidateDoctorInput, then compares valid and invalid JSON behavior
and complete typed diagnostics with that implementation. Presence of a doctor
key or a generic api.Empty shape validator cannot satisfy this registration
assertion. doctor-input-generic registers an owner-valid generic shape callback
through the real registry to control that specific false success. Shared JSON
decoder error ownership and request validation order remain unchanged.
The runner retains the full v2 dependency and embedded
protocol sources, but can edit only this lane's commands_admin.go outside the
existing admin/script/unit roots. This control and all new tests await Linux
execution; static checks are not red/green evidence.

The four still-unwired native integrations in gate_linux.go now return the
administrator-owned not_implemented classification adopted from the integration
preview: credential projection, runtime endpoints, selected environment values
and the generic worker descriptor handoff. These remain stopped gates. The
credential test and mutation retain the early refusal and reject nil success;
this classification change does not implement credential projection.

Allocate durably reserves distinct life UID/GID/cgroup identities before kernel
effects. Later effect/run requests for the same authentic life retain that
same lease and immutable resource/runtime envelope, with durable per-effect
input history and changed-replay refusal. Lease lifetime spans runs until final
collection; ordinary run stop must not release the life. Repeated-run gate
preparation remains open. memory.max expectations use the actual kernel page
size and sub-page allocations fail before reservation. UID observation scans
every process task/TID. Cgroup absence still requires real UID quiescence.

Prior-boot records load for diagnosis and nonexecuting recovery without enabling
activation/authentication. Valid root-owned unpublished pending records are kept
as evidence, do not replace the last atomic state, and appear as an unavailable
probe capability. Failed unpublished writes discard only their own new staging
name. Root startup recovers only its protected same-inode Unix socket whose
connect proves ECONNREFUSED, under the process/store lock. Live/unknown endpoints
are preserved and refused.

RegisterSpec resolves actual original bytes and ObjectMetadata through
StateStore, verifies their config/life/operation, raw/JCS digests and exact
LaunchSpec, then checks current grants/policy. Authenticated root IPC validates
its active life lease, budget envelope and protected installed runtime asset
pins before syncing the registration receipt. It accepts no caller root path
or arbitrary privileged argv. The registered ID is not a process/gate receipt.

RegisterContainment / ResolveContainment / RevokeContainment are implemented on
Linux. Registration requires the exact helper-created inode ticket, current
boot/config/lease/target/launch and an owned duplicate of the real cgroup
directory. Resolution verifies endpoint/artifact/service identity, actual host
UID/GID, current cgroup path/inode, a native pidfd and the peer's own generation.
The native convention is boot-id:start-ticks, consistent with the repository's
existing native implementation. Descendants never borrow the leader's ticks.
Each returned directory handle is an owned duplicate; revocation closes the
registry's handle and refuses later resolution. Native Darwin remains unsupported
by this Linux helper and needs its separate backend.

AbortGate implements the never-prepared allocation route only. Before any
success it proves the journal has no prepared/opened phase and independently
observes UID/cgroup quiescence, including a failed reservation without a cgroup.
It syncs an abort receipt/transition and collects only empty kernel containment.
There is no invented process ID, generation, exit code or signal. The explicit
empty prepared/spec fields for pre-Prepare abort are queued for integration's
context-specific schema clarification in CONTRACT-GAPS.md. Prepared-gate abort
still needs the actual gate owner.

Release adopts (ReleaseReceipt, error) and helper_release causality. The caller's
observation is only a comparison claim. The state machine checks independent
terminal facts, disagreement, known-zero survivors/connections/jobs/exports,
durable measured receipts and exact replay before collection. Production's
ObserveRelease returns containment_unknown until real gate wait status and the
resource-owner counters exist; it never copies caller values to fill that gap.
Service/store must commit EffectOutcome.Release/helper.released exactly once.
Supporting injected resource tests do not establish a measured production release.

OpenGate now loads StateStore.LaunchBinding and compares the actual stamped
event/sequence/digest and prepared/life/containment/endpoint tuple, current grants
and installed lane UID. It still returns typed not_implemented before permit
consumption or execution because opened runtime/capture/network/gate descriptors
are absent. Shape/receipt comparison alone cannot open an agent.

## Installed boot bundle

install.sh delegates only to protected root-owned boot.py. A supplied
laneboss.boot-input.v2 file must pin actual runtime/bootstrap objects, a private
native encryption key and complete measured Clef enrollment. The installer
publishes the assembly.Installation file, matching public/admin bindings,
separate private state/secret/runtime directories, retained immutable runtime,
native key handle/enrollment and fixed instance units. The service unit now
passes its exact --installation file. Unit socket families retain ordinary
IPv4/IPv6 and private loopback; helper capabilities/write roots cover its future
fixed setup work without broadening the service UID.

Matching completed installs are idempotent. Differing and uncertain partial
state stops without overwrite. --check has no filesystem write, lock, evidence,
repair, account, reload or activation path: it verifies actual inventory bytes,
metadata, privacy and account facts. Provisioning command inputs/outputs/exits
are retained; the completed catalog is published only after required commands
succeed. No code or template from a user-writable source tree is executed as root.
The native-key disk convention and retained runtime seed require the named
secrets/store consumers; file provisioning is not a claimed backend or authority.

The namespace entry now uses the same capability-requiring control before/after:
unshare --user --map-root-user --mount -- /usr/bin/true. Restriction one requires
actual exit 1 with a permission diagnostic; restriction zero requires success.
No switch is changed or inferred. The root-owned 0750 probe directory prevents
replacement by nobody. Profile loader code/assets and evidence ancestors are
protected. Existing namespace red controls still operate through exact copied,
hashed root-owned assets on their disposable machines.

The full admin case now passes --binding and retained mutation keys, distinguishes
directory ACL from an actual root nonservice socket peer, checks draft.4 measured
release payloads, and restores/disarms root artifact controls from finally even
after independent failures. Real root source protection remains in force.

## Remaining typed failures and consumers

Prepare, OpenGate execution, ObserveGate, StopGate, ReconcileGate and ResolveRuntime
remain not_implemented until the shared causal preparation/control and opened
runtime / materialization / credential / capture / network handoffs reach the fixed
bootstrap. The Linux lane's current contract note independently lists those
missing inputs. Identity owns BindLaunch; it must use actual StateStore receipts,
never a fabricated Scope or UID label. Consumers: Linux/Darwin, identity/peers,
lifecycle, grants/dataworker, secrets, service/store and assembly.

StageDeployment, ActivateDeployment and RestoreDeployment remain not_implemented.
They require their separately approved durable deployment/backup/activation
workflow; lane leases grant no deployment authority. Automatic uninstall of
uncertain failed accounts/units/state/keys is also open; preserve ownership and
evidence rather than delete possibly live or historical resources.

The common CLI exact-file doctor readiness handling and disk threshold/latch
remain outside this lane's owned files/API. No shared CLI/contracts were edited.

## Box commands and meaning

On the composed source, run these supporting checks:

```sh
go test -count=1 -race ./internal/v2/admin
go test -count=1 -tags laneboss_faults ./internal/v2/admin
go test -count=1 ./internal/v2/cli -run '^TestAdminDoctor'
go test -count=1 -tags laneboss_faults ./internal/v2/cli -run '^TestAdminDoctor'
python3 -I -B e2e/v2/cases/admin/cleanup_test.py
```

The 54 named mutations (49 Go, five namespace) keep all previous red controls.
Each Go pair must reach the intended named assertion, then pass on the clean
copy. Namespace phases still use separate fresh restriction-one machines and
now stage exact protected root assets. Read the case's MUTATIONS.md.

The root namespace entry and the actual Linux suite must pass on restriction
zero and then restriction one, without changing either host switch:

```sh
bash scripts/v2-admin/namespace.sh --install
bash scripts/v2-admin/namespace.sh --check
```

Read scripts/v2-admin/README.md for the exact boot input schema and complete
install/check/supporting black-box command. Those inputs must be real retained
bytes/keys/pins supplied on the authorized box, never placeholders.

Round acceptance is the lb-v2-serve branch's installed case on the composed tree:

```sh
bash e2e/v2/cases/serve/run.sh \
  --source /test/source --evidence /test/evidence/lb-v2-admin-serve
```

Require actual base red reason, then exit 0/PASS: installed serve on composed
bytes, all checks reached/passing, no pending owner setup and complete evidence.
Expected admin deltas are namespace.install/check, admin.install and installation.
serve/health need real composition, service hosting, native identity and native
key consumption. state.authorized and later mutation/retry/cardinality checks
also need genuine launch/enrollment, receipts/effects and the harness controls.
The existing harness's old installer arguments and standalone setpriv startup
must change as requested in CONTRACT-GAPS.md. No serve pass is possible by
substituting an unconfined fixture caller or relabeling an earlier failure.

Mac validation stays static: whole-tree Linux vet with/without fault tags,
Darwin vet, gofmt, py_compile, bash -n, shellcheck and whitespace/source inspection.
No test, build, project binary, sudo, install entry or remote command ran here.
Exact input/source bytes, static outputs/exits and hash/read-back evidence belong
to the lane's external evidence root in run-5. Staging/scan/merge remain Laneboss's.

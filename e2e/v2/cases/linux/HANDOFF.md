# Installed Linux handoff

The producer now implements the published G0 v1 contract. The shared owner
calls `boot(case)` before installation and `prepare` after its publication,
enrollment and baseline checks. Boot supplies measured assets and exact bundle
documents. Prepare returns the original human binding, real profile IDs,
populate/transport/collect callbacks, and the `itemlinux` catalog scope.
The enclosing serve finally block calls `abort` as defined by G0. The canary
is delivered through the selected `linux-canary` runtime asset only; its
evidence copy is not an extra published document. Optional plan documents
must have a real manifest/runtime/source/project/data selection. The
installer's unchanged `initialClosure` rejects unselected plan objects.

The installed rerun uses the real suite entry:

```sh
python3 scripts/v2-serve/run.py \
  --source /test/source --evidence /test/linux-evidence \
  --suite lifecycle --item-case linux
```

G0 emits the canonical frozen context and invokes the manifest's `run.sh`
with context/result files inside the private input scope. Evidence is its
separate sibling. RPCs use the original human's installed transport. The
case's collector checks actual helper release, original lease/process,
native workspace/branch removal, UID/cgroup and outside fixtures; its receipt
is available before result publication and cached for G0's post-entry call.

The optional private plan path is supplied as `LANEBOSS_LINUX_PLAN`; no value
is printed. The plan is root-owned mode 0600 with protected ancestors.
Without explicit real-profile authority, prepare retains the named owner
wait and stops. A runtime declared as a vendor stand-in also stops before
case preparation. The credential-free G0 baseline is never counted as a
real driver cell. No login, model request or provisioning is authorized by
setting this path alone.

The plan is case input, not a new product schema:

| Field | Actual input |
| --- | --- |
| `bundle` | Optional G0 boot fields; every document needs a selected reference. |
| `assets` | Optional runtime assets with exact file, mode, SHA-256 and byte pins. |
| `cell` | Selected host-cell identifier. |
| `start_template` | File with the fully selected real StartRequest. |
| `authorization` | Supervisor-issued explicit live authorization file. |
| `native_fixture` | Private native fixture described below. |
| `root_grant_set` | Existing root grant-set response from the service. |
| `profile_grant_ids` | Actual selected root grants for the G0 context. |
| `human` | Pinned signer refs for standalone use only; G0 reuses its human. |
| `descriptor_observation` | Actual helper descriptor observer output. |
| `review_input` | Independent review inputs for the actual ended run. |
| `public_parent` | Optional fresh outside-canary parent; default /var/tmp. |

Each human reference has path, sha256 and bytes. The authenticator is an
actual pinned executable. The private key stays in its existing protected
store; do not copy it into a checkout or test home. Public metadata may be
staged as protected input with its original bytes. The installed service
checks every challenge/signature/proof. Software presence remains simulated
and human approval not proven, independent of real driver authentication.

Authorization uses `laneboss.linux-live.v1`. It binds config, cell, driver,
selected profile grant, full model, effort, exact budget, runtime digest and
expiry with explicit model-request authority. No usable example is shipped.
Missing authority exits 69 with OS-LINUX unreached. Selected profile IDs must
match the exported context and real root grant set. The producer issues a
fresh ticket for those existing grants; it does not invent grant IDs. The
existing grant set is read back through the service under a fresh human
session proof, recorded explicitly as `grants.get`, with no new grant
issuance claimed.

The native fixture uses `laneboss.linux-native.v1`. It binds config, artifact,
runtime and canary digests. Its cell has id, restriction, ABI, hook and
inner_sandbox. Restriction and ABI equal the unchanged live probes. Hook is
absent/allow and inner_sandbox is off. The owner retains matching actual
published hook/driver inputs; a label alone establishes no compatibility.

Logical paths name canary, input, output, work, tmp, home, readonly and nested
inside the real runtime. Input/output/work lie beneath its actual workspace
logical CWD. The published project must already ignore the canary scratch
tree. A late ignore-file edit cannot repair a collection failure.

Protected targets are readonly, nested, state and sibling. Each has area
(workspace or absolute), path and an independently measured digest. They
identify delivered protected exports and real state/sibling files. Copies
with equal bytes cannot replace those targets. The leased UID/GID must
actually open outside/readonly/nested canaries for both read and write in
the unsandboxed DAC control; otherwise the boundary remains unmeasured.

Permitted is the actual pre-enrolled IPv4 endpoint and nonzero port. The
real echo listener independently records the random canary payload. Foreign
TCP/UDP IPv4/IPv6 and Unix listeners receive control traffic before start,
then report actual lane traffic relative to that baseline. A real owned
signal target acknowledges the observer control and reports later delivery.

The fixture supplies inherited_fd. The descriptor observation binds actual
target, helper lease, helper pre-exec stage, host PID/start time, descriptor
and planted digest. The observer reads that live helper descriptor, checks
its helper cgroup and requires CLOEXEC not already set. Missing staging is
the admin owner's helper_fd_canary gate. The installed FD red must reach
that same descriptor through the final-child boundary.

No UID or cgroup is predicted. After start, the observer reads the actual
launch event, protected helper journal and workspace registry, then checks
UID/GID, containment and inode against real OS observations. It records
file/DAC baselines before releasing exact canary bytes through held directory
descriptors. Redirected directories or a changed input digest stop the case.

The delayed review file binds config, actual target and artifact digest.
Its review member contains committed diff/check/inventory/refusal-resolution
inputs from independent jobs. The real service review must return complete
verifier/tool-record coverage and successful checks before mark/clean. A
public refusal stops further lane operations and retains unknown collection.

## Remaining matrix

All 16 rows are incomplete. This is the conservative full cross-product;
the original case requires both restrictions/hooks and a separate ABI-3
floor. This executor ran no installed host cell. A single installed result
credits only its actual driver, restriction, hook and kernel role.

| Driver | Restriction | Hook | Kernel role | State |
| --- | --- | --- | --- | --- |
| claudock-cli | 0 | absent | current | incomplete |
| claudock-cli | 0 | allow | current | incomplete |
| claudock-cli | 1 | absent | current | incomplete |
| claudock-cli | 1 | allow | current | incomplete |
| codex | 0 | absent | current | incomplete |
| codex | 0 | allow | current | incomplete |
| codex | 1 | absent | current | incomplete |
| codex | 1 | allow | current | incomplete |
| claudock-cli | 0 | absent | ABI 3 | incomplete |
| claudock-cli | 0 | allow | ABI 3 | incomplete |
| claudock-cli | 1 | absent | ABI 3 | incomplete |
| claudock-cli | 1 | allow | ABI 3 | incomplete |
| codex | 0 | absent | ABI 3 | incomplete |
| codex | 0 | allow | ABI 3 | incomplete |
| codex | 1 | absent | ABI 3 | incomplete |
| codex | 1 | allow | ABI 3 | incomplete |

Different policies/ABIs need separately authorized hosts and installed scopes.
A current kernel above ABI 3 credits no floor cell. The matrix receipt credits
a cell only after candidate exit zero, reached/pass and complete collection.

## Remaining installed reds

No installed red artifact was built or run in this lane. Each row needs its
own retained mutated artifact, real target reach and collection. The existing
component mutation catalog does not supply these installed artifacts.

| Mutation | Required observed failure |
| --- | --- |
| linux-broad-root | Outside file operation succeeds. |
| linux-writable-nested | Nested write succeeds. |
| linux-inherited-fd | Planted descriptor remains open in the actual canary. |
| linux-no-landlock | Nested write succeeds. |
| linux-no-network | Foreign TCP/UDP/IPC independently receives traffic. |
| linux-no-cgroup | Actual populated/membership observation differs. |
| linux-false-zero | Marker-bearing process survives reported stop. |
| linux-unmeasured-release | Release receipt is absent, unknown or foreign. |

Setup failure, denied DAC, missing live authority, absent descriptor staging,
an unrelated failed positive control or unknown collection kills no mutation.
Preserve the first owning gate. A demo runner establishes no authenticated
AI-service result or real driver compatibility.

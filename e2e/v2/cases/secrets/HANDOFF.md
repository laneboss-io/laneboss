# Installed secrets suite

The concrete entry is `installed.py`. It uses the installed service, human
identity, native encrypted store, helper, confined runtime and actual enrolled
stand-in agent. The supervisor owns the fresh-box acceptance run. This lane
also has an explicitly selected Linux queue entry for installed diagnosis;
its exact observed result and remaining gate are recorded in retained evidence.
Component results and static checks do not establish an installed E2E pass.

The selected-profile scope is **installed-standin**. Initial publication enrolls
the case-owned executable through the existing stand-in profile path. The agent
compares its actual injected Claude or Codex stand-in credential with the
selected profile, configuration, challenge and executable digest. No vendor
login, real credential, model request or authenticated AI-service test occurs.
Software human presence remains `simulated`; human approval is `not_proven`.
The real Claude turn remains outside this case pending LB-301/302/304.

## Exact supervisor command

From this checkout on a fresh authorized AWS Ubuntu 24.04 box, as its normal
nonroot user with Go, sudo and public package egress, run:

```sh
sh e2e/v2/cases/secrets/BOX-SUITE.sh
```

The script installs the public system prerequisites, runs the case and its
relevant product packages with normal and `laneboss_faults` tags, then invokes
the installed suite. It stops dependent steps at a nonzero exit and ends with
`(exit $rc)`. It accepts either amd64 or arm64 through the shared installer.
Do not use the package-installing script on a box without package egress.
Both modes now include the administrator package. Before the installed
step, the script runs the selected root-only credential guard close test in
an empty environment. That check exercises real Unix frames and native peer
pins; it does not start a service, enroll a credential or request a model.
The revision-forwarding control selects the installed Python command by its
actual script token, so the separate root Go command cannot make that selection
ambiguous. Its real child probe still checks the forwarded revision, rejects
an unrelated inherited token and refuses revision disclosure in output.

The opt-in root queue entry is `TestInstalledStandin`, selected with
`laneboss_root_canary` and `laneboss_secret_install`. It runs
`QUEUE-INSTALLED.sh` on the already authorized Linux queue box, installs the
same public prerequisites and invokes the actual `installed.py` entry in a
fresh private `/opt` directory. Its complete output and actual exit remain
there. `queue-input.json` names the known base revision plus changed working
tree scope; the case retains the real source archive and build-input hashes.
The queue's archive has no Git metadata, and this input does not claim a new
commit or replace the source bytes. The installed test is excluded from the
ordinary unit build unless both opt-in tags are selected. Missing tools,
failed preparation and a nonzero installed exit remain failures.

The r10 queue attempt reached actual service startup, then stopped at
`service private directory: installed path has a symlink, untrusted owner or
shared-writable parent`. Its typed recovery is `Repair the administrator-installed
service generation before opening state or launching work.` Both main
assertions remain unreached in that attempt. The directory guard and its
failure were preserved; no installed pass or progress past the baseline's
blob upload is claimed from this queue run. Separate store checks reached
actual manifest begin/chunk/commit/read-back with observation provenance.

After the serve box has already passed its installation checks and has these
prerequisites, the exact additional case line is:

```sh
sudo env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 LB_SRC_REV="${LB_SRC_REV-}" python3 -I -B \
  e2e/v2/cases/secrets/installed.py \
  --source "$(pwd -P)" \
  --evidence /opt/lb-secrets
```

This creates a separate fresh configuration and retains its installation. It
does not borrow the serve case's lanes or clear an active session binding.
The evidence path must not exist; preserve a previous run rather than replace
it. The root entry uses a private umask. Its outside helper tools alone have
explicit root-owned executable/traversal permissions for the service UID.

The box runner may ship an archive without `.git`. In that case its named
`LB_SRC_REV` input must contain a full lowercase Git object ID (40 or 64 hex
digits). The shell entry forwards that one input through the empty environment;
it never prints its value. The case retains the exact revision plus newline
in `source-revision.txt`, with `source-revision.origin.json` explicitly recording
runner provenance and that no Git command executed. A checkout with `.git` uses
the existing owner-bound Git command, and a Git failure is not replaced by the
runner input. Missing or malformed archive revision input fails at `source`
with a fixed diagnostic. The archive and actual build-input hashes remain
independent evidence of the bytes tested.

## Human preparation and first service start

The installed entry uses serve's own order: `install`, `prepare_human`,
`human.enroll`, `publish_initial`, then `human.session`. Installation builds
the original tagged software authenticator and retains its executable bytes.
The case verifies that exact artifact and its declared simulated provenance
before preparation. It then verifies the freshly prepared private directory,
key, counter and public descriptor before enrollment, and checks them again
before each case-issued proof. Missing, replaced or unprotected material stops
the case. The existing signer and real enrollment/confirmation operations
still validate and consume the identity; metadata checks confer no proof.
The private key and counter remain outside source and evidence archives.

The fifth installed attempt exhausted the bounded socket wait. Its service
journal contains `conflict` with the fixed diagnostic `retain an existing
credential listener for administrator recovery`. The case had stopped and
started the units to add the hidden environment. The product intentionally
retains credential listeners on close, and those restarts failed before the
human socket could be published. A longer socket wait cannot repair that
refusal.

The case now prepares the hidden random source, environment file and both
unit drop-ins before serve captures the helper's effective unit policy. It
reloads systemd once, then leaves serve's original helper/service start calls,
dependency ordering, unit names and installed socket path in use. Both starts
validate the prepared bytes. The producer consumes that exact retained hidden
source, and the baseline joins its digest with the actual unit inputs before
performing its unchanged service calls. Baseline setup no longer restarts the
credential listeners. No retained listener is removed or replaced, and the
product's recovery refusal remains in force.

The baseline still checks the actual protected human binding and socket with
a thirty-second publication bound, matching serve's initial startup bound.
It retries only a missing pathname. The binding must match the installation's
human class, configuration, socket, service UID and artifact hash. An existing
path must be a Unix socket with the bound UID/GID and mode `0660`; mismatches
fail immediately. The observed binding hash and socket device/inode/UID/GID
are retained in `human-endpoint.ready.json`, then the unchanged human ceremony
and actual `identity.self` call must succeed. Path metadata alone is not a
service round trip or installed E2E credit. A publication timeout remains a
`human.endpoint` failure with a fixed value-free diagnostic.

## Diagnosing a failed installed run

The following installed rerun also exhausted the baseline primary stdout
deadline. A focused Linux regression now reproduces a concrete blocker before
that first output: the stand-in reads its assigned task through `blob.read`,
but the human upload's immutable owner-only ACL did not make the object visible
to its assigned lane. The store now joins the exact task reference to the
authenticated lane's current launch. It keeps the original upload owner/ACL;
unassigned tasks and foreign lives remain refused. The stand-in's baseline
turn reads through this real store path, writes to an OS pipe and then requires
the real capture writer's correlated `capture.appended` stdout event. Restoring
the former visibility decision yields EOF and `object is absent or not visible`
before any primary output. Identity and transport in this regression remain
component inputs. The installed wait and event observer are unchanged.

Start ownership is retained immediately when the actual `lane.start` response
names its reserved life/run, before polling or terminal-error handling can
raise. Successful start handling reuses that same record. Collection still
requires public stop, zero survivors, archive and clean. The new file-backed
ownership mutation removes this early retention and fails at the missing
owned life; the candidate also requires that a refusal for one life leaves
the overall result failing while collection attempts continue for other owned
lives. The control uses declared lifecycle doubles and confers no installed
cleanup credit.

The store's lifecycle-stop withdrawal path now requires its exact retained
`launch_control` cause, current claim and generation. It does not treat an
arbitrary caller-provided stage ID as retained authority. The component
regression drives the actual stop-control lookup, rejects another cause ID,
and completes the credential withdrawal with an explicit nonzero-exit,
zero-survivor observation. Native counts in that test are component fixtures.
The installed cleanup refusal remains unverified until a fresh acceptance run.

The round-12 queue installed attempt stopped at administrator installation,
before startup or cleanup could be measured. Its actual exit and complete
private installer evidence were retained; the attempt was not retried and no
installation or ownership guard was changed. Required component/package
results do not replace that failed installed attempt.

The seventh fresh-box run passed the human socket and manifest-upload gates,
then exhausted the primary stdout wait during baseline start. Its service
journal includes a `control.Open` refusal: `launch input lookup has no
current original stage claim`. The exact installed cause remains subject to
rerun because the retained public log does not include the private lane event
inventory or complete worker outcome. A guard release race is suspected.

The helper previously closed its guard socket and returned immediately. The
broker's guard stopped only after its owner observed EOF, leaving an interval
in which the launch owner could complete while the broker still rechecked
the now-completed open claim and fenced the credential projection. The
helper now sends the fixed `guard_close` operation and waits for the broker
to finish the actual guard Close before returning an empty acknowledgement.
Only then is the private stream closed. A failed or missing acknowledgement
remains an error. The request retains native peer/response correlation and
the helper's callback lock handoff, including during cancellation. Repeated
local cleanup returns its original close result. No live claim, credential,
capture requirement or wait bound is relaxed.

The root regression drives the helper's actual guarded open and one-use
native descriptor gate. Its child writes the random primary canary only after
release; the helper must remain pending until the correlated broker release
acknowledgement arrives. It retains its executable bytes/hash, input, private
request frames and observed canary output. It fails on the former EOF-only
behavior before receiving any release acknowledgement. The broker regression
requires its owned guard
to close and cancellation to complete before acknowledging; it also checks
invalid input, an absent guard and the original Close failure. Service start
regressions drive the real planning/materialization writers and actual
broker open-control lookup, including the Claude stand-in driver, then
require the original cause and opened plan. Native process observations in
those service tests remain component fixtures. These checks confer no
installed primary capture or authenticated AI-service credit.

The ordinary queue command is unsuitable for the separate isolation kernel
package: its temporary executable is owned by the build account. The optional
`TestInstalledIsolationRecovery` adapter, selected only with
`laneboss_root_canary,laneboss_isolation_recovery` and root, follows the Linux
case's documented recovery. It installs the real test executable under a
root-owned path, then runs those bytes as the original nonroot source owner
with a new private home. It retains both executable bytes, hash, build output,
complete test output and actual exit. Removing the executable ownership makes
this adapter fail at the original prerequisite. With the prerequisite restored
and its home supplied, all 99 existing isolation tests passed. This additional
component result supplies no installed secrets acceptance credit and changes
no isolation source, host switch or guard. The prior failed attempts remain
in the lane's retained queue evidence.

The suite prints JSON-line diagnostics to its inherited stderr before returning
the installed-step exit status. Every unexpected failure names its enclosing
check, a typed service or local reason code, and bounded source/line locations.
Known missing fields and command labels are included only when they are literal
names in the consumed source. Assertion failures caught during independent
evaluation and failures during collection are reported at their original
boundary; cleanup cannot replace the first failure in the final summary.

The failing call retains its actual API refusal as `refusal`, with only
`code`, `message`, `owner` and `instead`. Journal API errors and the actual
typed detail on credential refusal events retain the same fields. The code
must be a known API error code; text is bounded, owner names must be product
owner names, and other fields are omitted. Product messages are retained even
when no normalized diagnostic reason is known. Registered private sources,
their raw/base64/hex forms, the configuration, evidence root and human
principal are redacted within those strings. The case registers private
sources before the corresponding operation; a typed error is not permission
to print a credential or arbitrary response fields.

On the first failure it queries the last twelve lines of the actual helper,
credential-owner and service unit journals for this configuration, then queries
them again after cleanup. Each record lists its source-declared JSON field
names, including nested paths. Unknown map keys become `*`. Only known enum
values under `event`, `reason`, `code`, `stage`, `method`, `outcome` and `kind`
are retained in `enum_fields`; other values outside the typed refusal remain
redacted. Normalized reasons are mapped only when they exactly match
source-defined diagnostics. Systemd PID 1
records for the exact queried unit retain fixed Started/Starting/Stopped/
Stopping/Failed/exit-code state words and known result or exit-kind words.
Unit descriptions, exit details, private identifiers, native paths, settings,
environment values and arbitrary error details are redacted. The exact
original journal stdout/stderr remains private beside
`diagnostics.jsonl`; these bytes are never substituted for sanitized terminal
output. Query failures are reported explicitly. The shell prints the installed
step's exit code and still ends with `(exit $rc)`.

A failure inside the baseline lane's actual Claude stop is printed as
`lane.claudock.stop`, with driver `claudock-cli`. An observed credential receive
deadline is mapped to `credential_frame_recv_deadline` and adds the known
regression marker `claudock_stop_under_repair`. Earlier status/preparation
failures retain their own attribution. The inherited serve2 regression remains
under repair by its owner. This case reports that failure and retains the
nonzero result; it does not alter deadlines, containment or credential behavior
to make the stop pass. The first installed attempt's cause remains unknown
because its retained public log lacked a failing check and its box is gone.

## Inputs and build selection

The baseline's first dynamic root-grant proposal uses a human-session
`blob.begin` of class `manifest`, followed by chunk/commit and an independent
`grants.root` confirmation. The store previously refused that class while
the grants contract required it. The product now permits this inert manifest
upload for a human scope. It retains owner-only ACL and observation origin;
the label grants no enrollment or trusted service provenance. Lane/worker
manifest uploads and capture, policy, archive, approval and launch-spec uploads
still require their appropriate emitters. The root-manifest parser, exact
human confirmation, protected handle resolution and policy checks still
decide whether any grants are issued.

`SecretInstall` subclasses the existing installer without changing shared
files. It stages the case's Go/Python inputs into the actual source archive and
inventory, builds both stock and case-owned main packages from that same module
and vendor tree, and selects the case agent's retained bytes for the existing
fixture enrollment. The selected executable's hash is checked at version,
enrollment, native launch and outside observation. The native reader and sealer
are built from that staged source; their exact executable bytes are retained.

The shared item exporter was not published in the inspected tree. The entry
therefore writes the documented `laneboss.e2e-context.v2` shape directly: `case_id`,
`phase`, `mutation_id`, `binary`, `binary_sha256`, `source_sha256`, `config`,
`binding_file`, `test_root`, `evidence_root`, and `profile_grant_ids`. The profile
list contains the two actual service-issued seed grant IDs. It is never empty
and is independently joined to their enrolled profile IDs. No shared exporter,
dispatcher or source is edited.

All requests, proof files, retry keys, random private sources and sealer inputs
are retained before their use. Dependent stage IDs and proofs come from actual
service replies. The consumer checks the exact prepared request/proof/key
against the retained wire frame, not a producer completion flag.

## Twenty-one service steps

| Steps, in required order | Actual boundary |
| --- | --- |
| human-session, key | Service-confirmed human session and its connection-owned public sealing key. |
| stage-env, import-env | Fresh sealed env upload and proof-bound native import. |
| stage-file, import-file | Fresh sealed binary file upload and proof-bound native import. |
| stage-hidden, import-hidden | Separately imported source excluded from the selected launch ticket. |
| start | Confined digest comparisons of selected env/file bytes, real write-open refusal, undelegated env/file absence and the reserved baseline. |
| reserved | Actual forbidden reserved-target diagnostic; no unrelated invalid-request credit. |
| wider | Actual refusal of a source granted by a different root ticket. |
| bad-stage | Fresh key, altered GCM tag, stage and proof-bound import on one persistent connection; exact integrity refusal. |
| stop, archive | Actual stop, zero-survivor observation, abandonment and verified archive receipt. |
| restart-locked | Broker restart with its enrolled key withheld, actual locked native fetch, and public launch refusal. |
| recover | Native sealed recovery through protected descriptors compares the imported bytes; after restoring the original enrolled key, a new confined launch compares them again. |
| tamper | Actual encrypted record tag is changed while the broker remains running; both native and public launch must report integrity. Exact original bytes/inode are restored. |
| lease-first | Actual selected Codex stand-in turn and native canonical refresh/slot observations. |
| lease-second | Actual competing selected-login refusal with unchanged native refresh owner. |
| release-running | Public clean refuses while running; independent native inspection still finds the live slot, projection and refresh lock. |
| release-quiet | Actual zero-survivor stop, archive and clean, followed by released slot and independently unlocked canonical login. |

The clean-while-running call reaches the public lifecycle gate. Its conflict
alone is not credited as a direct broker quiescence test: the retained native
slot/projection, kernel refresh lock and live containment supply that evidence.
The locked public launch can report `unavailable` when systemd cannot load the
withheld key. That transport result is accepted only alongside the separate
native `prerequisite_missing` fetch with no digests. Recovery does not claim a
new public key-repair RPC: it exercises the actual native Recover port and then
restores the exact original enrolled key for the broker's public launch.

## Independent observations

The reserved baseline comes from an actual confined Claude stand-in lane.
The hidden environment canary is present in the outside helper/service units.
A separate outside readable file holds the hidden file canary, so a missing or
unreadable author-side source cannot satisfy the absence control.

Child metadata is joined to `launch.planned.payload.plan.lease`, the root helper
journal's `spec.handoff.spec`, the actual lane task and runner prompt hashes,
executable bytes, UID/GID, process generation, PID/mount namespaces and cgroup
membership. The outside observer independently finds the matching kernel
process and checks its mount inventory. It rejects the observer's own identity
and namespaces. It never enumerates environment values or command lines.

Private history is a record created/uploaded by the baseline lane. The outside
reader checks the actual state object's bytes, owner-only ACL and lane binding;
the credential lane must receive a real public refusal when reading that ID.
Other-profile/key/registry controls derive from actual protected enrollment.
Their inodes are compared with actual mount destinations in the matched agent
process. This is the stated mount-inventory scope, not a claim that every
possible filesystem alias has been searched.

Archive bytes come from the committed native `archive_job.Parts` and actual
object rows. The observer checks `Input.receipt_id`, `Input.intent.Request`,
`Job.Intent.OperationID`, and each object's `Ref`, `ACL.Config`, `ACL.LifeID`,
`Origin`, `SourceOperationID`, size and digest, then the receipt's two aggregate
digests. It scans the actual archive members for raw/base64/hex canaries; it
does not rebuild a tar from a producer tree or use the receipt's manifest as tar
bytes. Primary captures are independently reconstructed from public event/blob
reads with exact offsets, binding, run and hashes.

The native reader consumes existing key/recovery/backup descriptors, never key
argv or a copied credential home. It reads the real encrypted profile/login/
slot journal and probes the canonical kernel lock through an independent open.
Headless profile metadata records a measured missing login journal; file-login
profiles still require that actual canonical journal. No missing Codex login
can satisfy the selected-profile or refresh assertions.
Collection requires helper release/abort receipts, gone process generations,
an empty whole-UID inventory, empty cgroups and removed actual runtime roots.
Executor exit is never collection evidence. Secret and credential groups run
and evaluate independently; failure in one preserves the other's observations.
Unit logs, wire output, results, primary captures and archive contents are
checked for canary disclosure, with exact private failure bytes retained.

## Checks and retained results

The Linux queue runs `./e2e/v2/cases/secrets/...` plus grants, native secrets and
assembly. `check_case.py --source . --unit` includes the installed observer
checks. `TestInstalledControls` mutates isolated source copies, requires each
named assertion to fail for its actual boundary, then requires candidate GREEN.
It retains the input bytes and primary outputs and emits their hashes into the
queue transcript. The installed entry also retains those isolated control
trees and primary outputs under `observer-controls` in its evidence directory.
Each phase's input hash is printed alongside a digest of the complete phase
records, which retain stdout/stderr hashes; the compact transcript fits the
queue's response bound without losing its header or last control.
Go agent/native controls likewise require actual encrypted
canaries, injected auth files, write attempts and kernel locks. No skip or
compiler error can count as a killed control. No deliberate fault remains in
the candidate source.

The human setup controls replace retained artifact bytes, remove private
identity, omit preparation and delay real Unix socket publication. Separate
controls require refusal for a permanently absent socket, a different
configuration binding and a public-writable socket. Each isolated fault must
reach its named assertion before the same candidate passes. The preparation
order uses a component double, and private-file tests use random dummy bytes;
these checks do not claim an actual enrollment or usable signing key.

Hidden-environment controls omit preparation before the original unit policy
capture, change the environment file or drop-in, substitute the producer's
hidden source, restart an existing listener or break the baseline source
join. Journal controls remove field names or enum values, permit private enum
values, omit systemd states or accept records from another sender or unit.
The unit ordering tests use component command doubles and actual temporary
input files; they confer no installed systemd or service credit.

Typed-refusal controls remove the actual call or journal fields, allow an
unknown error shape, bypass private-source redaction or omit registration
of a real prepared canary. Product upload checks commit and read back actual
manifest bytes through a real stored human session and verify observation
provenance. Removing the human-only exception must make lane/worker boundary
checks fail. The native peer and assertion in those store checks are declared
component fixtures; their result is not an installed authentication claim.

The installed entry retains a frozen result and `secret-suite.json` beneath
the configuration's evidence directory. Require command exit zero, suite
scope `installed-standin`, both assertions reached/pass, both collection flags
true, every wire step and its actual exit, and retained native evidence.
Those are required future installed observations, not observations claimed by
this handoff. Preserve failure evidence and dispose the authorized test box
only through the supervisor's collection route. No commit is performed by
this lane; installed queue measurements are reported with their exact scope.

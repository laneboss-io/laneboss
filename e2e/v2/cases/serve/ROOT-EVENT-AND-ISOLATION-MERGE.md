# Root issuance identity and installed isolation integration

Run 24 starts at 76e03912 with the administrator merge of 2f5f91f already
in progress. The brief reports green22 at 38/78 PASS, with
human.claudock.grants returning lb-v2-service/invalid_request and
"invalid object ID". This run performs static checks only and claims no new
installed result, vendor authentication or native isolation measurement.

The failing producer field is the empty grants.issued Event.ID. After protected
profile resolution, grants.issueRootSet builds that event without an ID.
Store.Transact fills sequence, operation/request correlation, timestamps and
the starter chain, then calls wire.ValidateEvent. Its event decoder checks ID
before the payload and rejects the empty string with the reported message.
The store never mints that producer-owned event ID.

The retained profile evidence identifier has the form initial-profile- plus
32 lowercase digest characters, for 48 characters total. The stand-in source
and canonical metadata handles use the same allowed alphabet and are shorter
than 128 characters. Issued grant/member IDs use g_ plus 16 random bytes in
hexadecimal. wire.NewID uses 16 random bytes in hexadecimal; its ValidID grammar
also permits the existing hyphen and underscore prefixes. No profile/evidence
rekey or validator change is required.

The root producer now calls its existing freshID helper for the issuance event,
propagates a randomness error and includes that ID in the transaction. The
human proof, encrypted profile reads, source checks, exact grant set, durable
reply and replay behavior retain their existing gates. The change also applies
to root grants containing data without profiles, since they share issueRootSet.

The merge keeps serve2's real launch_control.go and its installed-host/control
scope guard. The obsolete launch_control_stubs.go is removed from the working
tree. Dependencies keeps one IsolationEvidence field and uses the existing
interface in launch_control.go. The incoming assembly wiring passes the actual
administrator helper to both service.New and service.NewServer; the installed
constructor retains those dependencies and the real Server.Probe delegates the
original context/result/error to that provider. No constant availability or
replacement prerequisite booleans are introduced.

The administrator provider and fixed worker handoff remain unchanged from the
incoming working-tree bytes. IsolationEvidence still calls its distinct native
helper operation, checks retained proof bytes and current host/kernel/runtime,
and validates the complete measured boundary. The worker input still passes
exact byte, length, class, digest, immutable descriptor and native gate checks.
This integration grants no worker identity, launch permit, credential lease or
model access. The remaining identity worker join and private worker client/root
bridge remain their owners' operation-bound refusals.

The incoming probe test now supplies the real server's required installed-scope
component facts. It compares the complete provider result and original error,
exercises both unavailable and available component results, and retains missing
provider and cancelled-context checks. These are declared component fixtures,
never native proof. The administrator mutation runner's one permitted service
file and probe-service-port mutation now target the actual launch_control.go.
Its scope remains that exact file and service package. The provider is untouched.

The cross-lane integration edits relative to the initial in-progress merge are:

| Files | Change |
| --- | --- |
| internal/v2/grants/root.go | Mint the producer-owned issuance event ID. |
| internal/v2/grants/root_event_test.go | Exercise the full profile-root path and actual strict event validator. |
| internal / v2 / service / launch_control_stubs.go | Preserve serve2's deletion of the obsolete implementation. |
| internal/v2/service/stub.go | Resolve the conflict to one existing dependency field/interface. |
| internal/v2/service/probe_test.go | Adapt the incoming delegation regression and add installed-scope refusals. |
| e2e/v2/cases/admin/mutate.py, mutations.json, MUTATIONS.md | Retarget the existing exact service-port control. |
| e2e / v2 / cases / integrate / contract-controls.json | Register event-ID omission, installed-scope omission and constant-availability controls. |
| e2e/v2/cases/serve/REQUESTS.md and this file | Retain the diagnosis, scope and verification handoff. |

The adopted incoming assembly file is internal/v2/assembly/assembly.go. The
administrator files preserved without further edits are:

* internal/v2/admin/FIX18.md, canary_linux.go, data_ctl.go, data_other.go,
  doctor_probe.go, helper_linux.go, internal.go, isolation.go,
  isolation_other.go and lease.go.
* internal/v2/admin/probe_linux.go, proof_inst_linux_test.go, proof_linux.go,
  proof_linux_test.go, proof_store_linux.go, store_linux.go,
  worker_fds_linux.go, worker_linux.go and worker_native.go.

The added or adapted regressions have these failure conditions:

| Test | What makes it fail |
| --- | --- |
| grants.TestRootGrantIssuedEvent | The producer omits or corrupts its ID, changes issuance context/payload, fails the production wire decoder after store-owned assignments, or weakens rejection of the empty ID. |
| service.TestProbeEvidencePort | Probe fails to call the actual dependency, changes its complete result/error, substitutes availability, calls a provider after cancellation, or loses the missing-provider owner. |
| service.TestProbeInstalledScope | An unverified, closed or controller-less host calls the independent provider or returns success. |

The integrate catalog registers three corresponding mutations. The existing
admin probe-service-port control is retained with its corrected path/anchor.
Each control must reach its named failing diagnostic on disposable Linux before
the same candidate test passes. Mutation anchors and diagnostics were inspected
as data here; no overlay was compiled or vetted. Runtime red/candidate results,
the imported native canary and the composed installed lifecycle remain pending.

All sixteen candidate-only go vet configurations passed using Go 1.26.5 and
the shared cache. Linux amd64/arm64 each covered default tags, laneboss_faults,
partial/authenticator tags, all three tags, laneboss_gate_integration and that
integration tag with faults. Darwin amd64/arm64 each covered default and
partial/authenticator tags. Changed packages and their transitive production/
test importers were included. gofmt -l, git diff --check and py_compile of the
retargeted administrator runner also passed. Go source hashes were retained
before checks and verified unchanged afterward. No project test, project
binary, project interpreter run, installed service, cloud operation or model
request ran on this Mac.

The source conflicts are resolved in the working tree. HEAD, MERGE_HEAD and
every index stage are left unchanged for the supervisor to stage and conclude
the merge. Git therefore still reports the original unmerged index entries;
this report does not claim a completed Git merge.

Green23 should preserve publication, org validation, human sessions and exact
profile enrollment, then pass root grants with a valid issuance event and reach
the real ticket/launch path. When reached on the prepared box, G5 must use the
independent retained native proof through the real Server.Probe, and G6 must
use the exact sealed worker input/native handoff. Report the actual first
remaining owner refusal; the worker identity join and private bootstrap/root
bridge remain possible later gates. No exact PASS count or completed lane is
predicted. Presence remains simulated, human approval remains not_proven and
the stand-in still has no authenticated vendor room.

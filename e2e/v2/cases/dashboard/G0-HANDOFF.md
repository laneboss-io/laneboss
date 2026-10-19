# G0 dashboard handoff

The producer implements the G0 version 1 hooks against r7 base `b87965c3` and
the in-progress items1 merge. The bundle conflict keeps both sides' helpers
and tests; laneboss stages and commits that resolution.
The native entry is now implemented in new service, assembly and CLI files.
The assembly registration hunk is immediately after `server.BindDashboard(views)`;
it calls `bindDashboardEntry` and adds its closer to the owned resources.
The CLI registration is `dashboard open` in `integrateCommands`.
No review-owner file, judge registration, frozen RPC schema or shared serve
exporter is changed.

The service configures the real dashboard from the installed administrator
origin and RP ID, and owns `.browser` and `.web` Unix listeners beside the
installed control socket. The native listener authenticates the actual human
peer and exact credential-bearing frames. Ordinary RPC frames use the existing
service dispatcher. Its separate bootstrap form calls the existing
`IssueDashboardBootstrap`, with an already authenticated issuer connection,
a second fresh redemption connection, and that connection's actual proof.
Closing the host closes its owned listeners and retained native connections.

The matched installed CLI has two modes:

```sh
laneboss dashboard open --config NAME --binding BINDING \
  --mode session --directory PRIVATE_DIR --ready READY_FILE --wait 30m
laneboss dashboard open --config NAME --binding BINDING \
  --mode host --origin HTTPS_ORIGIN --listen 127.0.0.1:443 \
  --certificate CERT_FILE --key PRIVATE_KEY --ready READY_FILE
```

Session mode retains its real connection and exchanges exact request/response
files in a caller-private directory. Host mode terminates TLS and forwards to
the service's actual dashboard handler. Host, Origin, cookies, proofs and SSE
remain subject to that handler and the service dispatcher. The proxy retains
the incoming Host and server-owned presence headers.

The producer constructs these children itself. It obtains issuer and browser
proofs on their actual native connections, consumes only the issuer session,
mints the browser handoff, closes the issuer, and redeems over HTTPS to obtain
the real cookie. The test certificate key remains outside the checkout and
evidence; its public CA is retained. The isolated client connects to loopback
while retaining the enrolled hostname for SNI and certificate verification.
The three private dashboard environment inputs are supplied only to G0's child.

Boot publishes the measured L3/L6 role sources and one enrolled case project
containing the actual README and plugin bytes, with a bounded zero-spend
baseline. The baseline serve publication keeps its single original data view;
the dashboard issues separate confirmed root grants and tickets for its one
case project data view. `from_checkpoint` builds five
independent launch requests and an L6 relay from G0's actual publication. D6
proposes, approves and applies plugin/configured-instance source bytes. No
service event, loaded flag, capture gap, policy score or review receipt is
seeded. Abandonment carries the typed zero review; merged requires the actual
service-issued complete review and authenticated worker evidence.

R5 connects the native `review-inputs` handoff to the installed writer's
`ReviewSnapshot` and administrator's `RequiredReviewChecks`. A current human
read session is required. The service frames actual drained capture before
freezing the subject, reads both actual trees and their content, and retains
candidate diff/tool/inventory objects with read-back. It selects check objects
for that exact frozen run and reports missing required checks explicitly.
The subsequent HTTPS `lane.review` uses the merged `ReserveReviewWorker` and
`AwaitReviewResult` path. Only its complete verified receipt can authorize
merged. The producer first commits and awaits acceptance, reads back its new
generation, and prepares merged with a fresh proof. The native preparation
supplies no review receipt or test verdict. Tool coverage is derived from the
actual provider boundaries and paired tool records, then rechecked by the writer.

The review target now uses the actual Claudock fixture proposal and a natural
successful exit. Its stand-in emits provider session boundaries and paired
tool-use/results containing actual installed CLI inputs, exits and output.
Relay telemetry is wrapped in provider system frames. The outside relay reads
the actual partial primary chunks, checks run/operation/offset binding and
reassembles split JSON without changing capture coverage. The raw-view gate
requires a gap at the exact end of an actual primary partial record.
Before exit the target uploads its actual README candidate and immutable test
plan. `actor/check.go` runs the case-owned file check against an expected digest;
changed bytes fail. The measured actor binary is separately enrolled as the
check tool. Native preparation waits for every primary EOF. If checks are
missing, the producer sends the actual `grants.test-child` request with a fresh
proof, awaits that same operation and rereads the native frozen inputs.

The scored source is the case-owned `scored-judge.json` runtime asset. Only
the partial/authenticator build binds it, through the separate policy-source
hunk in `assembly.go`; production builds keep the installed scoped judge.
The fake source derives each probability from the full request and question
using SHA-256, and reports `dashboard-fake-sha256-question-v1`. Its block
tokenizer and deployment are pinned to the actual enrolled asset bytes.
Its nominal cost is zero and it makes no network or model request. D6 approves
those pins/bounds and one additional critical fixture rule. Ordinary policy
evaluation commits the resulting scored and zero-spend unscored decisions;
the producer reads back their retained inputs and checks the fake provenance.
No policy events or refusal projections are seeded.

The producer installs the administrator's protected review requirements file
for the actual project and current D6 generation on the disposable Linux host.
The native review identity handoff is present in r6. R6 also repairs the five
stale lifecycle mutation anchors. The provenance mutants remove their current
allow-and-log observation; they do not restore obsolete refusing guards.
`TestReviewJobPreflight` now checks the missing coordinator explicitly. Its
plan, immutable lease and generation controls use the real verifier-result
fixture in `dataworker/review_result_test.go`, after the native handoff.

R6 adds `scripts/v2-serve/item_test_child.py`. The sole dispatcher hunk is
named `TestChild adapter: preserve actor transport; collect its native results`
at the beginning of `item_dispatch.run`, before population. The narrow
`bind(case, prepared, context_io)` interface wraps the original transport and
collector, and exposes `case.item_test_child.execute(request, submit,
subject=..., required=...)` to the dashboard callback. The callback still
sends the original `grants.test-child` HTTPS request with its fresh proof.
The adapter awaits the same native operation, reads exact output objects,
reassembles primary capture through both actual EOFs, checks the frozen check
records and independently reads the protected helper journal, cgroup and UID.
Its actual test operation is included in outside collection even though the
dashboard prepared it inside an input callback. Exact inputs, results and
captured bytes are retained. Neither this adapter nor its unit doubles create
authoritative worker facts or execute candidate code as the observer.

R7 implements the native TestChild path. Grants carries the original native
scope and verified proof-use guard through the private `testjob.Call` into
the installed dataworker coordinator. The service reauthenticates the frame,
waits for both primary EOFs and obtains the actual frozen subject. Staging
retains inert inputs. The same public transaction then consumes the proof and
commits the one exact test lease and effect, with current lane/grant/policy
checks. No worker can execute an unadmitted stage. Synchronous dispatch and
the reconciler drive that same admitted job after lost responses.

Test workers use the common native post-run journal with their distinct
`test` kind, separate UID, containment, sealed input, installed worker socket,
identity permit and measured retirement. They are not relabelled review
verifiers. The pinned wrapper reads only the candidate/plan object closure,
copies the candidate into its own private namespace, verifies the executable
pin, executes the actual argv and retains bounded stdout, stderr and command
exit. The authoritative writer validates the returned frozen check identity.
The wrapper measures the actual stdout/stderr pipe inode IDs; capture
bindings preserve those measured identities with the native worker lifetime.
Only native successful known-zero retirement publishes the check, actual
capture ranges/EOFs, worker completion and helper release together. Store
verification reconstructs those capture positions independently. Primary
capture remains partial; EOFs and exact output bytes are checked explicitly.

The administrator selects the single protected check name when review policy
exists; a test cannot stand in for multiple protected names. Without review
policy, the executable's enrolled ID names the test result. Native review
continues to require its protected requirements. Neither path issues a review
receipt merely because a test completed.

R7's native canary executes an actual frozen candidate in the real helper
namespace through the installed worker entry, authentic store/identity and
socket, then verifies actual output, zero survivors, retirement and store
integrity. It found and fixes a native freeze defect: cloned post-run jobs
must preserve the original source operation used to derive file-object IDs.
`archiveJournal.SourceOperationID`, `ArchiveOperation` and the clone in
`review_journal.go` retain that original source while each worker keeps its
own causal operation. The wrong source operation fails the native RED
control before the unchanged candidate passes.

The adapter's outside observer now reads the actual collected test worker in
the canonical parent journal's `reviews` slot, compares its exact retirement
release and measures the worker's cgroup and leased UID. No standalone worker
lease file is invented. The earlier shared scope failure is fixed by the
items1 dispatcher merge; its existing root RED/candidate importer controls
pass without another dashboard dispatcher change. The bundle's root-only
installer checks run in the root step. No installed thirteen-ID pass is
claimed; laneboss runs that next.

The installed suite owner uses a fresh evidence directory and runs:

```sh
sudo -n env PATH="$PATH" python3 -I -B scripts/v2-serve/run.py \
  --source "$PWD" --evidence /test/dashboard-installed \
  --item-case dashboard
```

`BOX-SUITE.sh` installs its listed system prerequisites, runs focused RED then
GREEN controls and package checks, invokes this command, and ends with
`(exit $rc)`. Presence remains `simulated`; human approval is `not_proven`.

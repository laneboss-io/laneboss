# Draft.4 fix 24 report

This follow-up starts at 9a484ef. It changes complete object read-back and
does not raise any work or transport budget. All verification in this
authoring round is static; no runtime CPU improvement or installed pass is
claimed.

## 1. Linear verified object reads

The complete owner request at serve2 179f3f0 was read and retained. Its green13
observations report a service-owned initial-publication deadline and aggregate
CPU cost. The source-derived amplification is concrete: ObjectMetadata and
every Blob range called objectRow, which selected and hashed the entire object.
For the stated 26,522,426-byte object, 102 ranges plus metadata imply
2,731,809,878 bytes of full-object loading/hashing. This is a source operation
count using the supplied size, not a measured profile or a claim about which
stage dominated green13 or green14.

The existing store-owned ReadView now retains verified persisted object rows.
The first metadata/range lookup selects the actual SQLite bytes and checks
identity, length and the complete digest through objectRow. Later ranges use
those same verified bytes inside that view. No offset-based digest exemption
or service-wide cache was added. ObjectMetadata and Blob still check current
read authority, select the authorized reader and enforce the ACL on every call.
Chunk bounds, chunk digests and returned-byte copying remain.

The view pins the database snapshot and the creating scope's configuration,
full actor, launch, endpoint/policy generations, connection and request identity,
key and digest. Another request/caller cannot use its object pins. Caller and
view-context cancellation are checked before cached access. Closing or
cancelling clears retained objects; Close still tears down the actual read
transaction and removes the view from the store. Metadata participant slices
are cloned so a caller cannot mutate the verified ACL. Blob ranges continue
to return copies of the retained bytes.

The private BeginObjectRead capability uses the existing protected BeginRead
mechanism. The small objectread.Bind adapter borrows an existing request view
or opens one for a complete internal read and closes it on return. Owned close
errors join the result error. A backend without this private capability keeps
its original fully checked Blob path; no check is omitted as a fallback.
Hosted stores must forward the capability to obtain the linear path.

## 2. Reader sweep and native publication adapter

Eleven complete-read helpers now bind one view around metadata and ranges:

| Package | Complete-read helper |
| --- | --- |
| service | Original |
| guidance | taskBytes |
| messaging | artifact and content |
| approval | verifyBlob |
| policy | put, after the retained write |
| judge | auditObject |
| runner/claudock | objectBytes |
| runner/codex | readBlob, including its metadata lookup |
| secrets | protectedObject |
| watchdog | blob |

Their existing reference, provenance, range, EOF, content screening and final
digest assertions remain. Shared dependency scopes are not mutated. WorkerObject
also reuses a verified manifest when the same frame selects that root as its
object; this reuse is local to the invocation. New worker/native Blob requests
remain independently authorized and verified. Records and the remaining judge
task read use one bounded Blob call rather than a multi-chunk loop. The generic
service BlobRead adapter delegates its one range unchanged.

The installed administrator implementation is absent from this checkout,
whose admin package is still a stub. Copying the full implementation would
require unrelated owner/API integration. Instead,
[initial-read.patch](initial-read.patch) is the concrete adapter against the
complete admin initial_commit.go at 179f3f0. Its applicability check passed
against retained exact owner bytes. The full adapted file is also retained
outside the checkout. This patch must accompany the store change when the
supervisor integrates the installed publication implementation.

The adapter opens its view for post-commit read-back, reselects the marker
inside that view and requires exact metadata equality. It then shares the view
across metadata, marker/object ranges, receipt operation/event, snapshot and
policy checks. Standalone initialReadObject also binds a view. The original
native channel/context, fixed range bound, object pins, complete final digest,
receipt/event/operation comparisons and final native recheck remain. It never
reads pre-commit bundle bytes as persisted evidence. The small marker-discovery
lookup preceding read-back remains a separate checked lookup.

The traced service publication entry passes its real Store directly to
admin.PublishInitial, so the concrete writer's private capability is visible.
A hosted wrapper that hides it must forward BeginObjectRead. The native
adapter and full owner implementation are integration requirements, not an
installed result already achieved in this stub checkout.

## 3. Deterministic regression and red controls

TestObjectReadLinear retains a variable object larger than three chunk bounds
through the real transaction path. Its context-local private hook observes
actual full persisted-byte loads immediately before objectRow's digest check.
Metadata, four ranges and EOF must cause exactly one full verification and
exactly the object's byte count. Exact reconstructed bytes and the final
digest are checked independently. A second request must perform a new full
verification, and the first request's view must already be collected. No timer
is used as the complexity assertion.

TestObjectReadTamper changes an actual persisted byte or metadata digest in its
disposable SQLite fixture, restores the immutability trigger, then opens a
production view. It requires the exact committed-object integrity refusal and
zero returned data. TestObjectReadScope covers changed request/caller,
closed/cancelled view, mutable metadata slices and mutable returned chunks.
TestObjectReadRevocation warms a view under a current human read session,
revokes the actual retained session, and requires the next range to refuse.
The identity fixture is a component double, not native enrollment evidence.

| New control | Deciding assertion |
| --- | --- |
| object-read-linear | multi-chunk read repeated full verification |
| object-read-tamper | verified read accepted tampered object |
| object-read-metadata | verified read accepted tampered object |
| object-read-request | verified read crossed request binding |
| object-read-metadata-copy | metadata caller mutated the verified pin |
| object-read-chunk-copy | chunk caller mutated verified bytes |
| object-read-release | whole object read retained request view |
| object-read-revocation | verified read reused revoked authority |

The linear mutant restores Blob's per-range objectRow call. The integrity
mutants remove only the whole-digest comparison; identity/length checks remain.
Other mutants remove the relevant binding/copy/release/live-authority guard.
They leave tests unchanged. All deciding red failures followed by candidate
passes remain required on Linux; none was run on this Mac.

## 4. Static verification and remaining evidence

gofmt -w ran on all eighteen changed Go source files and the retained native
adapter before checks. gofmt -l exited 0 with empty output. Python py_compile
of the runner and its diagnostic regression, bash -n of run-mutations.sh,
git diff --check and the owner patch applicability check all exited 0.
The authoring host is Darwin arm64, Go 1.26.5 and Python 3.13.11.

Data-only literal parsing in orchestration JavaScript found 256 unique
controls and 270 sequential edit anchors, each matching once. All 248 previous
rows, edits, target tests/leaves and deciding assertions are unchanged. The
new helper is inside the dependency snapshot's existing internal/v2 root.
No project Python code was imported or executed by this inspection.

The sole vet attempt used GOWORK=off, GOOS=linux, GOARCH=amd64, GOPROXY=off
and GOSUMDB=off and named all twelve changed packages: store, service,
objectread, approval, guidance, judge, messaging, policy, both runner packages,
secrets and watchdog. It exited 1 with twelve Go build-cache access refusals.
The exact command and all refusal lines are retained verbatim in external
checks.json and vet.log. The command was not retried, no alternate cache or
permissions change was attempted, and remaining vet variants were skipped
under the brief's explicit recovery route. Only reporting and evidence
collection followed that refusal.

Compilation, Linux test results, red/candidate results and installed acceptance
remain unestablished. No test, product build, cloud machine/job, real model
request, extra agent/session, staging or commit was started in this round.

The external lb-v2-service round d4fix24-9a484ef retains the full brief/rules,
starting source archive, complete owner request and adapter inputs, final
source snapshot, eight mutants, reader sweep, literal audit, exact static
commands/outputs/exits, diff, status and SHA-256 manifest. There is no tested
product binary because product builds were not authorized on this Mac.

The Linux verifier must run all eight new red/candidate pairs in both tag
variants and the complete inventory of 512 pairs plus ten final component
suites. Both complete package/tag suites must also cover the other changed
reader packages. Integrate the native adapter with the composed source, retain
actual publication stage timing, and rerun the installed service E2E under the
original ten-second work bound. An earlier-stage CPU bottleneck or a later
receipt failure must remain failed. No timing result from the still-running
green14 job was consumed or inferred here.

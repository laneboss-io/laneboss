# Draft.4 fix 26 report

This round starts at c9ce9592. All four gread5 findings have source corrections
and regression controls. Whole-tree compilation and vet pass for Linux amd64
and arm64, both normal and laneboss_faults, and Darwin arm64 and amd64. Runtime
regressions, mutation red/candidate outcomes and installed enrollment/publication
acceptance remain for the disposable Linux verifier.

The brief attributes the earlier installed enrollment and admin.publish passes
to the serve2 integration source at c2ab497.
It also reports a green full unit job on the merged base. Those observations
are supervisor supplied; this round did not independently run or collect them.
The later Fable review was not available in the active brief, and no findings
or result are inferred from it.

## 1. P0: administrator frame, replies and helper verification

The service listener now accepts api.AdminEnrollmentFrame, validates the
installed protocol, revision, configuration, generation, artifact, nonce and
method, and dispatches enroll_begin, enroll_complete and initial_publish.
The last branch calls Server.PublishInitialFrame. All parameter decoders remain
strict. These methods stay outside the public RPC catalog.

Every listener failure converges on the bounded AdminEnrollmentReply writer,
including schema and native peer refusals. Work has ten seconds; transport has
eleven seconds and the writer resets its write deadline for the one-second
reply window. An expired read deadline therefore does not suppress a writable
refusal. Unwritable/closed transports retain the fixed journal diagnostic.
An oversized encoded result or error becomes a small response-stage refusal,
rather than reaching WriteFrame with an oversized payload.

Per-file adoption from the pinned serve2 revision is as follows.

| File | Taken | Changed here |
| --- | --- | --- |
| internal/v2/service/enrollment_listener.go | Shared frame/reply aliases, strict frame validation, nonce correlation, all three handlers, native checks, bounded refusal writer and fixed journal fields. | Extracted the method dispatch into a private enrollmentResult helper for a regression that can reach each real decoder. Added the encoded-frame size fallback. |
| internal/v2/store/enrollment_ceremony.go | Shared AdminEnrollmentFrame validation, enroll_complete selector and Params binding. | Extracted the private checkEnrollmentFrame parser for focused tests and used DecodeAdminEnrollmentFrame for fixed-field diagnostics. Native VerifyAdministrator still runs before this helper and before retaining validation. |
| internal/v2/client/wire/admin_linux.go | The whole file, including fixed root helper control-unit membership, protected socket/directory checks, installed artifact hashing and process lifetime checks. | No source change beyond adoption; it matches the pinned file. |
| internal/v2/client/wire/enroll_json.go | DecodeAdminEnrollmentFrame and AdminEnrollmentNonce from serve2's json.go. | Kept them in a short separate file; the normal strict Decode remains the acceptance gate. |

Administrator verification no longer asks the unprivileged service to open the
root helper's /proc/PID/exe. It checks the real root connector, credential-pinned
frame, fixed cgroup-v2 control unit with its sole PID, protected helper socket,
protected installed artifact digest/release, and kernel lifetime before/after.
The privileged daemon remains responsible for verifying its own mapped artifact.
No supplied UID, source label or service actor replaces those native checks.
This adoption is not a new security canary or installed acceptance measurement.

TestEnrollmentReplies uses actual Linux Unix sockets with per-write credentials.
It checks old frames, protocol/config/method drift, and the unprivileged peer
refusal for each supported method. TestEnrollmentDispatch reaches each actual
typed parameter decoder. TestEnrollmentExpiredWrite uses a real expired pipe
deadline; TestEnrollmentReplyBound sends a genuinely oversized typed error.
TestEnrollmentFrameBinding checks a matching complete frame and changed params,
method, generation and the old envelope. TestAdminMembership checks exact,
foreign, shared, duplicate and missing membership data. The parser tests do not
claim native root helper authentication.

## 2. P1: bind the merged object readers

The initial publication adapter is applied directly to initialRead and
readInitial in internal/v2/admin/initial_commit.go. The implementation follows
serve2's view binding and marker re-selection, without importing its unrelated
timing wrappers or renamed wrapper functions. commitInitial keeps its pre/post
commit metadata selection outside a view; readInitial opens the post-commit
view, reselects the marker, checks equality, and shares the view through the
complete read-back. A standalone initialRead owns its own view. Each owned view
closes on success and failure; an existing view is borrowed.

The seven other reader files named by the review are also adapted.

| File | Complete-read helper |
| --- | --- |
| internal/v2/admin/enroll_commit.go | verifyEnrollmentReceipt |
| internal/v2/admin/launch_authority.go | readLaunchObject |
| internal/v2/admin/spec.go | RegisterSpec |
| internal/v2/lifecycle/read.go | readBlob |
| internal/v2/dashboard/views.go | readVerifiedBlob |
| internal/v2/grants/sources.go | readCommitted |
| internal/v2/templates/service_inputs.go | readBlob |

Each binds before its metadata/payload read and shares the same scope across
chunks. Existing range, digest, provenance, ACL and final object checks remain.
Lifecycle and dashboard retain their existing error wrapping when view creation
fails. No reader from the review remains delegated to another owner.
The old initial-read.patch is historical; the adapter is now in the merged Go
source and must not be reapplied.

TestInitialReadView checks actual multi-chunk file-backed component bytes and
owned-view release, including a digest refusal. TestInitialSnapshotView checks
that the real component publication replay shares one view across the marker
and object set. The existing SQLite TestObjectReadLinear still measures actual
full payload loads and digest verification. The new tests establish view
propagation only when executed; no new publication latency is measured here.

## 3. P1: interrupted reads keep their cause

Failed SQL reads in storedProjection, objectRow, effectRow, dataAllocation,
dataParent and allocationBudget now consult ctx.Err() inside the failure
branch. A driver error without a wrapped context can therefore retain its
deadline/cancellation cause. Successful queries do not take that branch.
The changed production paths are internal/v2/store/atomic_support.go,
internal/v2/store/objects.go, internal/v2/store/effects.go,
internal/v2/store/materialization.go, internal/v2/service/materialization.go
and the new internal/v2/service/data_error.go.

dataAllocation maps only sql.ErrNoRows to the existing forbidden allocation
refusal. Other database errors are preserved. Existing missing-row behavior in
the other readers is unchanged. The prior checkLaunchReceipt exact-byte gate
and its six controls remain unchanged.

AwaitMaterialization normalizes untyped failed work against the actual caller
or fixed-wait context. It normalizes before its own deferred cancel, so cleanup
cannot turn another error into cancellation. Successful results and explicit
typed integrity refusals remain intact. The 10 ms cancellation test and its
typed deadline/cancelled expectations are unchanged.

TestSQLReadCauses reaches the actual query boundary for six readers. A genuine
closed sql.Conn supplies ErrConnDone independently of the context; the boundary
wrapper only cancels and forwards the real SQL call. Live-context database
failures and real absent-row refusals are opposite controls. Cancelled/expired
failed reads must preserve their cause. TestSQLSuccessAfterCancel cancels only
after a successful object query has supplied its bytes and requires the actual
verified bytes to survive. TestMaterializeErrors separately checks typed context
conversion, successful reads, integrity refusals and unrelated errors.

## 4. P2: authorize before payload retention and bound the cache

internal/v2/store/object_read.go first reads metadata inside the actual view
and checks visibility before loading a missing object's full payload. It checks
the verified metadata's visibility again before insertion. A denied object is
neither payload-loaded nor cached. Public reads still recheck live authority
and the returned ACL on every access.

Each view retains at most 16 entries and 64 MiB of payload. Before an insertion
would exceed either bound it evicts the previous working set. The current
maximum-size object can still serve all chunks from one verification. An
evicted object must be loaded and verified again. internal/v2/store/snapshot.go holds the byte
counter; cancellation and close clear both the payload map and counter. These
are retained-cache limits, not a claim about total process memory.

TestObjectCacheVisibility uses actual retained public/private objects and the
store's existing component human-session fixture. The owner read and visible
object are positive controls. Denied metadata/blob reads must return not_found,
load zero private payload bytes, and leave no private cache entry.
TestObjectCacheBounds exercises 18 small objects and two objects each larger
than 32 MiB. It checks retained payload/count bounds, one verification for the
current object, re-verification after eviction and clearing on close.

## 5. Deciding controls and Linux proof still required

All 262 previous mutation rows, edits, tests/leaves and assertions are unchanged.
There are 23 additions, for 285 unique controls and 301 sequential edit anchors.
Every anchor matches exactly once in the final source. Every one of the 13 new
test declarations is under 40 characters and has a deciding red control.
All required assertion strings are present. This audit parses source literals
as data in orchestration JavaScript; it does not import or execute project code.

| Control | Test / leaf | Deciding assertion |
| --- | --- | --- |
| sql-success-context | TestSQLSuccessAfterCancel | successful SQL read was replaced by context expiry |
| enroll-reply-bound | TestEnrollmentReplyBound | administrator reply exceeded its bound |
| sql-context-parent | TestSQLReadCauses/parent/cancelled | failed SQL read lost its context cause |
| sql-context-budget | TestSQLReadCauses/budget/cancelled | failed SQL read lost its context cause |
| enroll-refusal-reply | TestEnrollmentReplies/old_frame | administrator refusal reply was silent |
| enroll-initial-dispatch | TestEnrollmentDispatch | administrator method did not reach its typed decoder |
| enroll-expired-reply | TestEnrollmentExpiredWrite | expired read deadline made the refusal silent |
| enroll-frame-params | TestEnrollmentFrameBinding/params | enrollment retained a foreign frame |
| admin-helper-unit | TestAdminMembership/unit | administrator accepted foreign helper membership |
| admin-helper-sole | TestAdminMembership/shared | administrator accepted foreign helper membership |
| initial-object-view | TestInitialReadView | initial chunks did not share a released view |
| initial-snapshot-view | TestInitialSnapshotView | initial read-back did not share one view |
| sql-context-projection | TestSQLReadCauses/projection/cancelled | failed SQL read lost its context cause |
| sql-context-object | TestSQLReadCauses/object/cancelled | failed SQL read lost its context cause |
| sql-context-effect | TestSQLReadCauses/effect/cancelled | failed SQL read lost its context cause |
| sql-context-allocation | TestSQLReadCauses/allocation/cancelled | failed SQL read lost its context cause |
| sql-allocation-error | TestSQLReadCauses/allocation | SQL read failure was relabeled as authority |
| materialize-context | TestMaterializeErrors/deadline | materialization lost the interrupted context |
| materialize-success | TestMaterializeErrors/cancelled | materialization changed a successful read |
| object-cache-visible | TestObjectCacheVisibility | unauthorized object entered the read cache |
| object-cache-entries | TestObjectCacheBounds/entries | object read cache exceeded its retained bounds |
| object-cache-bytes | TestObjectCacheBounds/bytes | object read cache exceeded its retained bounds |
| object-cache-release | TestObjectCacheBounds/entries | closed view retained cache bytes |

These are prepared controls, not observed kills. Each mutant must build, reach
its exact assertion/FAIL path and exit 1, followed by the unchanged candidate
passing that same path on Linux. Compiler errors, unrelated refusals, panic,
skip, race, process timeout and survivors earn no credit. The independent
component read-deadline tests intentionally assert their own bounded refusal
failure; they are not Go test-process timeout credit.

The runner now includes admin as its sixth component package. The complete
inventory is 570 targeted red/candidate pairs across normal and faults, followed
by twelve final component package/tag suites. It still requires
complete_inventory=true, exit 0 and PASS: service component mutation controls.
The tagged native enrollment/presence case and installed enrollment/publication
must also run on the composed candidate. New installed speed and acceptance
results remain unestablished.

The added test files are internal / v2 / service / enroll_wire_linux_test.go,
internal/v2/service/data_error_test.go,
internal / v2 / client / wire / admin_unit_linux_test.go,
internal/v2/store/enroll_frame_test.go,
internal/v2/store/sql_read_linux_test.go,
internal / v2 / store / object_cache_linux_test.go and
internal/v2/admin/initial_view_test.go.

## 6. Static verification and retained evidence

gofmt -w ran on every changed Go file before checks. After a final adjustment
preserving reader error wrappers, the complete vet matrix ran again on the
final Go source. Every following command exited 0 with empty output:

| GOOS | GOARCH | Tags | Scope |
| --- | --- | --- | --- |
| linux | amd64 | none | go vet ./... |
| linux | arm64 | none | go vet ./... |
| linux | amd64 | laneboss_faults | go vet -tags laneboss_faults ./... |
| linux | arm64 | laneboss_faults | go vet -tags laneboss_faults ./... |
| darwin | arm64 | none | go vet ./... |
| darwin | amd64 | none | go vet ./... |

Each vet command explicitly used GOCACHE=/private/tmp/lb-shared-gocache,
GOWORK=off, GOPROXY=off and GOSUMDB=off. The shared cache was usable; no fallback
folder or permission override was needed. Whole-tree vet covers all touched
packages, their importers and their applicable test files. It establishes
compilation/static analysis, not runtime test outcomes or a product build.

Formatting, Python byte-compilation of mutations.py/test_diagnostics.py, shell
syntax, whitespace and final literal checks pass. The host is Darwin arm64,
Go 1.26.5 and Python 3.13.11. The initial orchestration audit parser stopped on
adjacent Python string literals; its correction and completed data-only audit
are retained. No product refusal was hidden by that audit-tool correction.

The external lb-v2-service round d4fix26-c9ce959 retains the complete governing
brief/rules/review, tracked starting source archive, pinned adopted files,
complete candidate source, exact check commands/outputs/exits, final diff/status,
all 23 mutant source snapshots, catalog/audit and SHA-256 manifest. There is no
tested product binary from this static-only round. No runtime tests, cloud
machine/job, real model request, additional agent/session, staging or commit was
started. All changes remain unstaged and uncommitted.

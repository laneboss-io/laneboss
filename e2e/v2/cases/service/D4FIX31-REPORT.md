# Fix 31: enrollment proof, bound refusal delivery and test declarations

The candidate starts at dae0925. Each assigned
finding has a source correction and a deciding regression or control. This
round ran static checks only on macOS. Runtime outcomes and installed acceptance
remain pending the disposable Linux verifier. Nothing is staged or committed.

## Legacy enrollment administrator proof

serveEnrollmentConnection no longer calls verifyEnrollmentHelper from the
unprivileged service. It retains pinPeer's actual root UID/GID and pidfd, checks
pidfd liveness on revalidation, and reads the frame with wire.ReadPinnedFrame.
The new private enrollmentConnection pins wire.NewAdministratorPeer and the
installed administrator socket binding, then calls wire.VerifyAdministrator.
That shared check covers the native connector, credential-aware frame, current
lifetime, fixed control unit, protected helper socket/artifact and installation
generation. Protected installation/human-binding reload, endpoint/socket ACL
and final channel verification remain. No peer check was replaced by a label
or removed without a shared verifier.

The API adapter rejects replacement peers and human read authority. The
listener continues to own the socket/reply lifetime. Privileged helper/relay
uses of verifyEnrollmentHelper remain outside this unprivileged service path.
The inspected serve2 revision is 6a01900;
its legacy function still contains the old call. Its exact source is retained.
The implementation follows the shared verifier already used by InitialContext
and the service-owned enrollment listener, without claiming an owner-source
adoption that the inspected legacy file does not contain.

TestEnrollmentSharedVerifier uses a real Unix connection from the unprivileged
runner and requires the shared peer_uid refusal before any component peer or
frame callback. It also checks the real cancellation cause. The bypass control
must fail enrollment lost shared administrator proof. This negative component
case does not prove accepted installed root-helper enrollment. That accepted
path and its opposite native controls remain required on Linux.

## Bound worker and stream refusals

serveDataWorker now creates one private authenticationReplyWindow per request
and carries it through WorkerInput, WorkerResult, workerScope/object reads and
the delivery captureScope recheck. A failed recheck that requests Close emits
one correlated fixed typed refusal through the bounded writer, then returns to
the lifetime close. Initial authentication uses the same window. Parent and
hard-deadline callbacks retain the actual raw lifetime and can still close it.
Successful requests still execute the final delivery recheck.

serveStream creates a matching window for each bound authentication recheck.
On refusal it writes the terminal StreamFrame before honoring the requested
physical close. Direct capture ingress continues to propagate Close immediately.

TestWorkerRefusalFlush uses actual credential-aware Unix frames and a real
retained materialization stage. Identity/containment remain explicit component
dependencies. Its entry, delivery and later leaves fail at distinct bound
rechecks; later first requires a successful complete input response. Every
refusal must retain protocol/schema/request correlation and the typed fixed
verdict, followed by exact EOF and handler completion. TestStreamRefusalFlush
uses an actual pipe and bound connection, checks its correlated terminal error
and cursor before exact EOF, then requires producer and handler cleanup.

## Store suite declaration

The supplied d4f25red normal store suite exited 0 with PASS, but the runner
rejected its declared inventory. On that run's a04ea8ed source,
presence_tagged_linux_test.go declares TestTaggedInventoryRetainsPresence under
linux && laneboss_e2e_authenticator. tests_in previously read every *_test.go
regardless of build constraints. Neither normal nor laneboss_faults enables
that authenticator tag. The old source and exact supplied log are retained.

The final-suite expected inventory now comes from Go's selected TestGoFiles
and XTestGoFiles for the same race and variant flags retained with the compiled
binary. Source declarations remain independent of observed test output. The
runner keeps exact ran/passed equality and all refusal/skip/crash checks;
test-observation.json now records expected, missing and unexpected names.
Selected file names, tags and names are retained in declared-tests.json, with
separate Go metadata stdout/stderr. Targeted mutation checks remain strict.

test_selected_inventory in the Python diagnostics suite queries actual Go
selection for normal, faults and the dedicated authenticator tag. Its temporary
Go declarations are metadata inputs that fail if executed, not passing tests.
Restoring broad all-file declaration must fail build constraints changed
declared test inventory. The separate Python control is retained as data for
Linux; it was not run or imported on this Mac. A missing active test still
fails the unchanged exact inventory comparison. The authenticator test remains
for its separately tagged Linux run.

## Deciding controls and verification

| Control | Exact test path | Required failing assertion |
| --- | --- | --- |
| enroll-shared-proof | TestEnrollmentSharedVerifier | enrollment lost shared administrator proof |
| worker-entry-window | TestWorkerRefusalFlush/entry | worker recheck lost its correlated refusal |
| worker-delivery-window | TestWorkerRefusalFlush/delivery | worker recheck lost its correlated refusal |
| worker-later-window | TestWorkerRefusalFlush/later | worker recheck lost its correlated refusal |
| stream-refusal-window | TestStreamRefusalFlush | stream recheck lost its terminal refusal |
| stream-refusal-close | TestStreamRefusalFlush | stream recheck refusal did not close |
| Python broad-selection control | test_selected_inventory | build constraints changed declared test inventory |

All 303 earlier mutation rows are unchanged. Six additions reach 309 unique
controls and 327 sequential anchors, each matching once. The full normal/faults
inventory requires 618 targeted pairs and fourteen final suites, followed by
the separately required tagged/installed proof. The three new Go test names
are under 40 characters. A compiler, setup, sibling refusal, timeout, panic or
skip earns no kill credit.

All six candidate-only whole-tree go vet variants passed with empty output:
Linux amd64/arm64 normal and laneboss_faults, plus Darwin amd64/arm64. Every
Go vet used GOCACHE=/private/tmp/lb-shared-gocache, GOWORK=off, GOPROXY=off and
GOSUMDB=off. gofmt -l, Python py_compile, bash -n and git diff --check passed.
No runtime test, project interpreter execution, product binary build, mutant
compilation/vet, cloud job or additional agent ran. The six-method Python suite,
its control and all new Go red/candidate pairs still need Linux execution.

External evidence is retained under lb-v2-service-evidence/d4fix31-dae0925,
including governing inputs, source snapshots, supplied failure evidence, exact
static commands/results, control/assertion mappings, diff and verified manifest.
No product binary was built in this static-only round, so there are no tested
product binary bytes or hash to claim.

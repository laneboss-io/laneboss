# Fix 29: current authentication, cgroup modes and event selection

The candidate starts at 9ec1de8. The three
assigned gread7 findings have source corrections and deciding component
regressions. This round performed static checks on macOS only. Runtime
regressions, mutation kills and installed acceptance are pending Linux proof.
The separate legacy ServeEnrollment review item was not assigned by this brief
and is unchanged. All changes remain unstaged and uncommitted.

## P0-1: revalidate the original connection and propagate closure

`identity/service.go` adopts only the CurrentConnectionScope comment and method
from serve2 e9e2f66. The method requires the
original peer, reuses connectionScope to read current durable authority, never
calls Verify or BindPeer, and closes on failure. The exact adopted bytes and
pinned owner source are retained in external evidence.

`service/authentication.go` requires the private current-scope port when Peer
is already bound. Missing capability returns a typed prerequisite and closes
the connection; it cannot attempt Authenticate again. A compile-time test
assertion verifies that the actual identity service implements this port.
Authentication Close now calls the underlying connection Close.

The existing native refusal response still needs a writable socket after an
authentication failure. Only its socket dispatcher creates a private reply
window, tied to that same connection. It records Close while the dispatcher
writes one bounded refusal, then the dispatcher returns to its physical-close
defer. Initial worker authentication has the same bounded window. Direct
capture and subsequent worker checks use the actual transport. Cancellation
retains the raw lifetime callback. The existing native refusal privacy test
must still pass on Linux; it is not credited by static vet.

TestCurrentScopeRecheck uses the actual identity service with component
dependencies. It counts verifier calls and peer binds, preserves the original
peer, reads a changed durable policy generation, and closes an ended peer's
connection. TestBoundScopeRequiresPort checks the typed refusal, zero fresh
authentication calls and actual net.Pipe EOF. TestAuthClosePropagation checks
EOF from Close itself. TestCaptureAuthClose uses a retained launch fixture and
an actual pipe, requiring the capture refusal to reach EOF. These fixtures do
not establish native kernel identity or installed transport acceptance.

Existing service, admission and materialization authenticators now explicitly
provide current-scope methods; they no longer depend on the removed fallback.
Their current-scope methods require a bound live peer and reuse their existing
scope derivation. The materialization fixture reads the actual retained launch.

## P0-2: expose read/traverse permission without widening writes

`admin/resources_linux.go` checks each protected root-owned path, then calls
readableCgroup after creating lanes and lanes/<containmentID>. The new Linux
helper performs os.Chmod(path, 0755) and returns a prerequisite on failure.
This overrides the fixed helper unit's 0077 creation mask. The existing control
directory correction remains. No umask, recursive chmod or wider write bit is
introduced.

TestCgroupReadMode creates real 0700 directories and requires exactly
os.ModeDir|0755 on the same inode afterward. It also requires a missing path
to fail. The 0700 and 0777 controls share its exact mode assertion. Actual
root-owned cgroup-v2 creation under UMask=0077 and unprivileged service traversal
remain installed Linux requirements; temporary-directory checks do not prove
those kernel and UID properties. Both call sites are part of the retained diff.

## P2: select configuration events before pagination

`store/read.go` uses coalesce(life_id, '') and coalesce(run, 0) equality in SQL
for all event selectors. Configuration queries therefore select only empty
life and run zero before the 1,001-row scan and 200-event page bounds. The
decoded event's life/run equality is also required. Internal authorization,
public selector refusal, visibility checks and exclusive-since behavior remain.

TestConfigurationEvents now commits 1,205 actual lane events in bounded
transactions between two configuration events. One Events call since the
first configuration event must return exactly the later configuration event.
The broad-query control keeps the SQL argument count and decoded filter, so
late filtering alone cannot reach the target past the scan bound. The original
config-events-query ID, test and diagnostic are retained.

## Deciding controls

These are authored controls awaiting execution. An unrelated refusal, fixture
failure, compile error, panic, timeout or skip earns no red credit.

| Control | Exact test path | Required failing assertion |
| --- | --- | --- |
| current-scope-rebind | TestCurrentScopeRecheck | bound scope recheck acquired or rebound a peer |
| current-scope-close | TestCurrentScopeRecheck | failed current scope did not close its connection |
| auth-close-transport | TestAuthClosePropagation | authentication close did not reach the transport |
| capture-auth-close | TestCaptureAuthClose | failed capture authentication kept its transport open |
| auth-bound-fallback | TestBoundScopeRequiresPort | bound connection attempted fresh authentication |
| cgroup-read-mode | TestCgroupReadMode/lanes | cgroup facts lost exact read-only traversal mode |
| cgroup-mode-wide | TestCgroupReadMode/lanes | cgroup facts lost exact read-only traversal mode |
| config-events-query (reanchored) | TestConfigurationEvents | internal configuration event read was refused or changed |

The catalog retains all 296 previous IDs, with only config-events-query's
source edit changed, and adds seven controls. The candidate-only literal
audit finds 303 unique controls and 320 sequential edit anchors, each matching
once. Identity joins the final package set. The full inventory requires 606
targeted normal/faults pairs and fourteen final package/tag suites. All five new
test names are under 40 characters. No mutant was compiled or vetted here.

## Static verification and remaining proof

Every Go vet invocation used GOCACHE=/private/tmp/lb-shared-gocache, GOWORK=off,
GOPROXY=off and GOSUMDB=off. Candidate-only `go vet ./...` passed with empty
output for Linux amd64 and arm64, both normal and laneboss_faults, and Darwin
arm64 and amd64. This covers changed packages, tests and their importers.
The initial Linux amd64 vet failed with `cgroup_mode_linux.go:11:18: undefined:
api`; its full output is retained. The missing API import was corrected, then
all six final variants passed. No cache fallback was needed.

gofmt -l was empty for all changed Go files. Python py_compile passed for the
mutation runner and its diagnostics tests; bash -n passed for run-mutations.sh.
git diff --check passed. No project tests or interpreter execution, product
binary build, cloud job, model session, staging or commit occurred.

External evidence is retained under lb-v2-service-evidence/d4fix29-9ec1de8.
It includes governing inputs, pinned owner source, base and candidate source
archives, exact command results including the corrected compile failure,
catalog/anchor audit, test/control mappings, diff, source hashes and manifest.
No binary was built, so this round has no tested product binary to hash.
The supervisor must run the new deciding reds and unchanged candidates on the
disposable Linux runner, followed by final suites and composed installed
authentication, cgroup and publication/enrollment canaries. Static compilation
does not close those runtime gates.

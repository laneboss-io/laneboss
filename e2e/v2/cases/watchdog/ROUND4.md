# Item 7, round 4

The source head is 087b668e, with incoming da1586f2 left in the merge index.

The merge text retains serve2's fresh-Start behavior and the existing per-run
authority checks. Start may arrive without a vendor version; Resume and Turn
still require it. The second version comparison in run_check.go now follows
that rule too. The fresh-Start test reaches the adapter with real SQLite
reservation and claim records. No Git index or commit was changed; the three
resolved files still have unmerged index entries for the supervisor to finish.

The merge also exposed a normal scheduled-turn failure: the outer runner tried
to decode the private loop cause as a public request. It now checks that cause
and uses its retained session, home, logical turn and remaining budget, together
with the previous run's model and effort. TestRunnerLoopInput first failed at
the public decoder, then passed with changed-input controls.

## Usage work and its limit

The fixed dataworker now accepts a UsageJob, reads its bootstrap input, executes
the pinned usage command through held executable/home handles, and appends and
validates the canonical result receipt. TestUsageWorker executes a real native
synthetic query against unpredictable file bytes. It retains measured exits 0
and 23 and checks input, transport, append, acknowledgement and scope failures.
The first behavioral red was the fixed dispatcher's unsupported-job result.
A second red exposed the actual native peer format: boot plus start tick. The
command engine accepts that format and accounts for a private PID namespace;
the native worker endpoint remains responsible for host-PID authentication.

This is a worker engine, not completed 7C. Installed StartUsage/RunUsage job
allocation, narrow credential projection, durable usage-stage mapping and the
actual input/result-frame rendezvous are still absent. Assembly does not wire
UsageJobs, and the store's native bootstrap mapping still handles data/archive
stages. No service-UID query or fabricated native scope fills that gap.

## Reader work and its limit

The installed CLI has an internal reader entry sharing its session pump with
the older helper. This avoids selecting a separately built executable whose
hash differs from the installed binding. The outside test-identity bridge is
file-driven and reaches that CLI through a persistent human.session. The L6
case uses the bridge's native Unix socket, preflights before upload, retains
the exact body and actual outputs, and requests measured reader closure.
Real human presence remains a typed wait. README.md documents both setup files.

TestInternalReader first failed for the missing installed route and now checks
the real handler with proof, config, mutation and reply controls. The Python
bridge tests first failed for missing adapters, then used actual child pipes
and a separate native socket process. They preserve simulated-presence labels,
random request data, exact output whitespace, failed exit 13 and clean closure.
Their synthetic service transport establishes no actual human enrollment.

7E's public R157 quota/history/forge/file/signal/restart fixture and all six
installed watchdog cells remain open. No authenticated model, login, paid
fallback, owner send, deployment, merge or production commit was performed.
Round-4 box receipts are retained under this lane's own boxq evidence directory.
The final report names the completed candidate checks and any failed native gate.

## Candidate verification

The authorized Linux full plain set, plus the reader and watchdog observer
packages, passed with exit 0 in request 1792254111579-93982. The final three
vet configurations passed for active touched packages and direct importers:
Linux amd64, Linux amd64 with laneboss_faults, and Darwin arm64. Formatting,
Python compilation and diff whitespace checks also passed.

The broader fault-tag packet 1792254558761-84293 failed: 936 top-level tests
passed, one failed and none skipped. Its touched Go packages and 56 watchdog
Python checks passed. TestHarnessPython failed in test_converged, test_current,
test_ladder and test_review. Separate diagnostic runs retained those failures.
The first three stop on the same readiness evidence error:
`stale file:line source evidence: internal/v2/service/server.go:65`.
NewServer is now at line 95. The ordering test never reaches installation or
observer creation. The readiness catalog was not refreshed and its check was
not weakened. The native packet was held after this failed aggregate check.
This round therefore claims no installed native credential acceptance.

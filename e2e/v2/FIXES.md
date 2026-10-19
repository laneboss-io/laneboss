# Wave-zero review fixes in this port

Historical record restored from f64e2ea. Current source and installed readiness
are maintained in cases/ladder/READY.md and plan.json; old missing-port claims
and prior test counts below are not current acceptance results.

Run 3 received a supervisor-reported Ubuntu result of 48 harness units, exit 0,
for revision 8ac0555. Its two fixture runs stopped before tests at missing Go
on the fixed child PATH. Compiler selection now happens once from the operator
PATH or --go; the canonical path, bytes/hash and exact Go 1.26.5 version are
recorded. Clean children receive that absolute selector. Fifteen new compiler
and summary-diagnostic controls await Linux execution.

The packaging-owned source installer still forces Go 1.26.0. The fixture now
reports this as an explicit dependency failure instead of silently changing
compilers. See contract-requests.md. No new source-smoke result is claimed.

Both complete reviews were read before continuing the port. Security findings
remain suspected code findings until the supervisor executes the real canaries.
The changes below are implemented candidates, not executed Linux proof.

| Review item | Candidate fix and control |
| --- | --- |
| Claude 1 / Gemini 3: zero-test default discovery | suite.module_paths/load_suite validates every default and named module, rejects nested/bad filenames, zero tests and foreign base classes. Child selected IDs are retained and exact completion/count is checked. DiscoveryControls exercises each rejection and a nonempty control. |
| Claude 2 / Gemini 5: stale passing harvest | artifacts.export_bundle publishes only after .partial read-back. Failure removes partial output and finish rewrites exit 2 and regenerates/removes the manifest. ArtifactControls injects read-back/full-disk errors and checks the actual output directory, summary and hashes. |
| Claude 3 / Gemini 4: privileged path races | The self-contained helper walks descriptors with O_NOFOLLOW, opens leaf files nonblocking/no-ctty, uses fstat and reads only that FD. Hardlinks and special files refuse. Writes validate the open inode before truncation. DescriptorControls and the actual root fixture controls exercise safe bytes, links, traversal and FIFO. |
| Claude 4 / Gemini 2,8: socket fixture manufactured success | Service has a private primary group and supplementary RPC group, umask 022, root-owned common ancestor and runtime 0750. socket_group/socket_mode are explicit. A plain service-UID socket must be 0755/private-group and fail the production comparison; real product readiness waits for exact 0660/RPC metadata. |
| Claude 5 / Gemini 3: service authority and early controller exit | Test as_user accepts only operator/lane; the helper independently rejects service. Setup-only service calls stay private. A child executes product tests; the parent audits command evidence and completion IDs/count/exits. No-CLI and missing/partial child controls fail. |
| Claude 6: probe in service group | Lane-probe gets only its private primary group. Actual fixture group controls check all memberships, private primaries and absence of sudo. |
| Claude 7 / Gemini 7: AppArmor controls and stale profile | Actual pre-profile refusal, post-profile unprofiled refusal and profiled positive run are recorded with both unchanged sysctls. Profile names are per-run. Teardown verifies/copies, unloads and removes the exact file. Disabled userns fails setup. Runtime execution remains pending. |
| Claude 8: mutable root imports | Root helper is self-contained, all three sealed inputs are checked and invocation is python3 -I -B. The isolated-import control plants a shadow json module, observes the ordinary invocation fail, then requires isolated help to succeed. |
| Claude 9 / Gemini 6: missed resources / forced cleanup | Preflight accounts/groups/process UIDs are retained. New unregistered resources fail before archive. Numeric pidfd signals tolerate exit races and rescan UIDs. Forced termination retains failure while safe profile/account/group collection continues. Drift and SIGKILL-race controls are included; forced-cleanup box proof remains pending. |
| Claude 10 / Gemini 1,6,8-10: smaller and timeout issues | Inner timeouts execute at the switched authority; controller output uses files and bounded wait without Popen context-manager hang. Actual switched sleep timeout is a fixture control. Serve classification uses its actual error/exit, immediate unrelated exit fails, readiness retries only typed transient connection-refused, and socket chmod settles before health. Lane/run names are validated lowercase. Source directory links fail explicitly. Root steps hold a per-run lock. Bubblewrap bytes/version/package and Go inputs are retained. Non-UTF-8 process names are byte parsed; live threads prevent a zombie leader becoming false zero. |

The shell wrappers' initial SC1007 empty-assignment warning was corrected and
shellcheck then exited 0. Python compilation and Linux/Darwin vet are static
checks only. No unit, smoke, adversarial root control, live driver or ladder has
been executed on the authoring Mac. Staging/scanning belongs to the supervisor.

## Mixed-ladder preparation lane

The scenario, live CLI collector, box recipe and full-run/pair red controls are
authored candidates. The new code has not run tests, builds, vendor programs or
project interpreters on the Mac. The authorized static checks and exact source
bytes are retained in this lane's external evidence. Linux unit/red execution,
the first serve-build failing case, actual credentials/continuation, canaries,
phase collection, machine termination and the independent independent Claude reviewer read remain
supervisor gates. No earlier 48-unit result applies to this new slice.

| Ladder check | What makes it fail |
| --- | --- |
| Seed and draw | Wrong graph/mix, changed draw hash, or any repeated seed determining a token/path/nonce. |
| Answers and report line | Wrong token/path, another lane's path, missing self/descendant answer, duplicate result or upward skip. |
| Mail and parent wait | PONG before causal delivery, wrong nonce/turn/run, historical/hidden/fake end, wrong process handle, late parent receipt or carried-sender actor. |
| Runtime | Missing vendor session mapping, changed history/driver, task failure/retry, non-exit or nonzero exit, missing/raised/reset budget or invalid quota continuation. |
| Primary/raw capture | Missing/changed blob bytes, missing transcript, gap/replacement or overlapping/noncontiguous primary ranges. |
| Privacy and sources | Missing actual sibling canary/own-data control, readable sibling data/mail/session or changed/absent source inventory. |
| Parent collection | Missing parent review/accepted/merged mark, wrong review actor/receipt, absent actual archive bytes, mismatched read-back or missing owned-object removal. |
| Two-tree execution | Shared binding/resources, sequential snapshots, nonoverlapping process lifetimes, wrong actual UID or a stand-in executable image. |
| Final containment | Missing/unknown containment inventory, changed UID or any surviving process. |

e2e-rows/v2/ladder-controls.json names every mandated deliberate red control.
The units assert the exact named rejection through the production verifier
functions before testing a fresh uncorrupted verifier input. Those fixture
controls establish no authenticated model or product E2E result.

## Draft.4 port checkpoint

Base 2c3bd81 combines the prior ladder slice with draft.4 final. The original
99 harness methods and their assertions remain; draft.4 controls are additive.
The port uses explicit retained mutation keys, genuine per-invocation human
read proofs on the CLI's shared socket, committed content references, new
Ticket provenance and original MutationReceipt.Config in independent normalized
observations. It checks public write shapes, typed replies, read immutability,
actual requester/worker separation, helper ReleaseReceipt counts, cancellation
and the sole typed continuation Swap fence. No org change is applied.

All new controls require the supervisor's Linux run. The Mac session is limited
to compilation, formatting/vet, shell checks and publication scan. CONTRACT-GAPS.md
names unfinished producers/transport and bootstrap dependencies. A missing
check is not a passing check, and no fixture driver or observer server is
supplied. independent Claude reviewer plus Gemini review and installed serve E2E remain merge gates.

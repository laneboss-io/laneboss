# Installed review handoff

This change implements the service review coordinator, compiled fixed verifier,
sealed input reader, measured-result reader and lifecycle lease transition.
Component RED/GREEN does not establish an installed review or lifecycle pass.
The frozen entry and its required collection checks remain the acceptance gate.

Path aliases below are relative to the repository:

- S: internal/v2/service
- D: internal/v2/dataworker
- L: internal/v2/lifecycle
- W: internal/v2/client/wire
- J: internal/v2/reviewjob
- A: internal/v2/assembly
- P: scripts/v2-serve

S/review_control.go supplies PrepareReview and ResolveReview. Resolution keeps
the actual dispatcher frame and reauthenticates its native connection. It pins
one read view and compares the current life, committed known-zero end, frozen
snapshot, drained capture positions, actual object bytes and protected required
check names. Preparation keeps the original pending operation and dispatcher
ownership, reads the retained worker lease and enrolled runtime, and verifies
the exact sealed input. WithReviewResult reauthenticates before and after the
native result wait and keeps its private service read capability in a callback.

D/review_worker.go supplies RunReview. The fixed native export entry reads its
original sealed manifest input and authenticated worker principal. It reads
both actual object trees and recomputes the workspace diff. Storage object IDs
and multipart partitioning alone are not changes. Every referenced object is
read and hashed, including aggregate multipart content. Check receipt bytes
must match retained measured test facts; inventory bytes must match drained
capture facts. Coverage is complete only when the shared acceptance validator
accepts required checks, ranges, EOF, tool coverage and refusal resolutions.
Other valid evidence remains partial and cannot authorize acceptance.

D/review_stubs.go now reads the actual fixed verifier result. The installed
coordinator must supply the original native result. Its reader independently
checks the consumed worker, allowed lease generation advance, completed effect,
matching process lifetime, successful exit, known-zero survivors and result
object provenance, then reads and validates the retained output bytes.
No label, uploaded check or success-shaped pending operation substitutes for
these observations. RunReview verifies prior test results; it does not create
those test executions from candidate labels.

L/review_context.go recognizes the complete sealed input as well as retained
legacy subject inputs. L/review.go accepts only the exact consumption/result
generation advances in J/generation.go. The measured-execution guard still
runs before review and again at acceptance. The single A/assembly.go hunk is
the addition of ReviewControl: server to lifecycle.Dependencies; Review remains
the real dataworker.

W/review_input_linux.go adds a fixed-projection reader without modifying the
existing reader. It uses the same descriptor grammar, immutable seals, exact
read-only mode, size bounds and digest checks. The native endpoint continues
to authenticate the actual worker; descriptor shape is not actor authority.
Existing W files are untouched.

## Required installed producers

J/ports.go names the remaining private capabilities precisely. They add no
public RPC and must be implemented by the installed authoritative owners:

- ReviewSnapshot must resolve a real post-run native freeze and retained
  snapshot, end, inventory sequence and capture binding. A launch-time source
  snapshot is insufficient. It must preserve the same frozen identity during
  verifier execution and accepted/merged review.
- ReserveReviewWorker must atomically retain one exact original-operation
  export job, sealed input, lease, effect and native launch bindings. It must
  resolve retries to the same actual worker, without replacing an uncertain
  allocation or asserting a test execution from supplied receipt labels.
- AwaitReviewResult must wait for the original native job, authenticated output
  and completed measured effect. Missing, failed or unknown containment stops
  the gate and preserves the original resources and evidence.
- RequiredReviewChecks must read current protected project/policy names through
  the installed administrator. It must not infer requirements from the public
  request, submitted check list or an empty default.

The current store and administrator do not implement those new capabilities.
The coordinator explicitly refuses their absence. Native test worker execution
and result preparation are prerequisites to complete evidence. No in-memory
fixture is installed as an implementation of any of these capabilities.

## Merge-owned wire amendment

The current W/schema.go BlobRef.class row omits diff and check, although the
review API requires those retained worker outputs. The exact one-line merge
change is to append `diff check` to that row's existing `values` string. Keep
the BlobBeginRequest.class row unchanged: this request adds no public check
upload authority. This lane does not edit the existing W/schema.go file.

## Installed case gate

P/item_context.py and P/item_dispatch.py are not published in this candidate.
The case producer cannot import a guessed shared exporter or fabricate actor
authority. Authentic actor transports, both simultaneous load trees, seven
physical controls, three subject runs, durable monotonic commit timing,
independent archive observation and collection remain required.

After those real prerequisites exist, the installed suite invokes
`sh e2e/v2/cases/lifecycle/run.sh --context CONTEXT --result RESULT`.
CONTEXT and RESULT must be absolute paths beneath the same test_root. The
entry must exit zero, reach and pass LIFECYCLE-TREE, and independently read
every collected life before any installed E2E pass is reported.

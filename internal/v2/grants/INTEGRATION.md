# Grants integration at draft.4 fix 11

This phase starts on 7e9c6ba with the supervisor's open cf894d1 merge. It repairs
the resource-total control and implements fix-11 item 9's dataworker consumer,
narrow job grants, confined tree/home work and input/result/read-back checks.
The obsolete stub conflicts are resolved in the working tree by preserving
the existing implementation and adding Controls; the index remains untouched.
This lane changes only its files; it does not stage, modify shared contracts
or execute project runtime code on Mac.

[CONTRACT-GAPS.md](CONTRACT-GAPS.md) is the current list of remaining work,
with owners and exact missing handoffs. It supersedes the draft.3 gap list.
The merged assembly supplies Config/Controls to dataworker and Config/Human to
grants, plus Review and messaging Worker. Assembly stays read-only here. Actual
service/store/admin/identity job backends and the private worker client bridge
still return owner-named failures; representation/wiring is not runtime proof.

Every new launch fixture supplies fix-10 Level/Role/Driver/Authority and calls
ValidateLaunchReservation plus ValidateLaunchReservationRequest. Retained
fixtures build Kind=agent bindings and pass the actual plan/handoff/binding
validators. Their continuation intent and swap share one distinct operation.
Registered capture and explicitly D6-approved refusal are separate fixture
dispositions. No validator is bypassed for a positive fixture.

Grants selects role/level/driver/ticket authority from the stored reservation;
the original frame is checked for disagreement. Retained runs preserve the
previous plan's pins and require registered capture. Materialization replay
checks current capture exception policy again after input/output/journal reads.
The old LP-DATA-JOB-1 representation refusal is replaced by the real stage/await
consumer. Actual missing owner implementations still refuse before success.

Review and channel preflights now use fix-10 shapes and current retained job
authority. They still return owning typed errors before actual job execution,
coverage, preparation or delivery. CONTRACT-GAPS describes the exact missing
authenticated worker IO/result and identity/permit handoffs. Candidate refs,
synthetic DTOs and read-only preflights are not measured runtime evidence.

Implemented review changes:

- Normal ancestor states retain delegation, with every set/digest/expiry/
  policy and strict-lower relationship still checked. Ended lives require
  the missing sealed lease.
- Human reads require a live human connection and current ReadAuthority for
  the exact configuration/principal/endpoint and both expirations.
- Human mutations validate the exact authenticated frame, typed params,
  intent digest, AuthorizationTarget and HumanVerifier.CheckProof facts.
  Uploaded immutable data and protected enrolled channel root grants commit StateWrites.Grants,
  grants.issued, absent-ID comparisons, the exact RPCReply and ProofUse
  together. A noncompleted/malformed/substituted durable reply is refused.
- Human TestChild remains closed before worker dispatch until its proof and
  worker effect can be recorded together. Unsupported revocation/root
  enrollment/publication backends remain explicit errors, not dummy receipts.
- GrantsGet returns the sealed stored record to authorized readers, including
  revoked/expired/cleaned or older-policy records. Hidden and absent identities
  use the same not_found result for get/revoke.
- Revalidation keeps scoped snapshots open across reads and carries actual
  lane life/role/level into policy resolution. Store.Grants/Launch still need
  a scoped snapshot contract; no claim is made that this fixes those ports.
- Symlinks cannot cross a selected root at an intermediate step or create a
  directory graph cycle. Case-folding aliases and file roots are rejected.
  Implicit directory indexing is bounded as well as declared entry count.
- Candidate files must reference committed artifact metadata; repeated refs
  are deduplicated, total logical file bytes fit DiskBytes, and service reads
  have byte/metadata budgets. Service preflight does not read candidate file
  bodies. The streaming content primitive lives in manifest for the confined
  worker and reads at most one bounded chunk at a time.
- Grant-set expiry is an upper ceiling; a shorter member does not clamp the
  requested lifetime of unrelated capabilities. The common CLI owns file,
  proof, session, retry key, strict decoding and socket lifetime handling.

The existing digest convention remains SHA256(JCS of GrantSet with sha256
empty). Public GrantsValidate returns an inert preview with prospective IDs.
Internal Resolve takes only a reserved selector, reloads original inputs and
returns the exact reserved set/life plus stable member IDs; lifecycle commits
them under its original plan claim, grant CAS and cancellation guard. Retained
lives keep their current set, prior home/history and recovery binding. Internal
Lane run zero means the current life projection. No preview or read check
replaces release CAS. Tree is the current history spelling; snapshot remains
a compatible stored tree ceiling. Reachable history is permitted only for a
complete granted source root and is reduced to tree for file/subtree selection.

MaterializeLaunch performs sourced-input, current-grant, protected-source and
helper-journal checks, and verifies prior materialization bytes for replay.
Initial tree/private-home preparation now has a confined worker implementation.
The acknowledged JCS result, independent terminal-zero/read-back envelope and
actual manifest bytes are required. Completed stage replay preserves the same
job/receipt and never reruns the copy. Existing Materialize is not substituted.
Reachable Git awaits protected export/runtime pins; RunInternal awaits the
actual private client/native bootstrap/root bridge. The dataworker document
MATERIALIZATION.md records the preparation sequence and private job encoder.

All 149 existing ready control IDs are retained. Resource-total removes its
upper ceiling instead of duplicating the negative clause that vet rejected.
launch-data-barrier follows the actual missing Controls port. The 25 new
f11-data-* controls bring the ready count to 174, with eight blocked OS plans
and 184 exact patch anchors. The proof runner rejects unrelated failing
subtests and prints its retained failure category. Static checks are not red
proof; every named failure and same-candidate pass still must run on Linux.

The case now uses retained explicit mutation keys, final draft.4 bindings,
both nondelegable flag values and independent per-assertion setup/evidence.
Each assertion records failure when setup/runtime dependencies are absent.
The case still does not certify the blocked mutable-source/Git/Darwin cells.

All 43 earlier unit controls remain, with three mechanical ports: revoked-set
validation is shared with stored-record validation, symlink control removes
both the new traversal floor and final bound, and assembly byte checks moved
to the worker primitive. New review controls are cataloged individually.
The source remains unaccepted until the supervisor retains actual Linux unit
and red/candidate output in both builds, the external case and composed serve
case, and the independent delta read. Static anchors and vet are not runtime
proof. No authenticated AI-service test is performed by these synthetic cases.

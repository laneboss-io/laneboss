# Item 2 implementation handoff

The supplied base is `83c3926b`. This round changes the uncommitted candidate;
it does not certify installed checklist item 2. The real-store and native
canaries below use synthetic bytes and explicit component authority. They do
not authenticate an AI service or prove physical human presence.

| Gate | Candidate outcome and remaining work |
| --- | --- |
| 2A | Partial. Missing administrator/Linux fixtures and human proof files stop with a retained `prerequisite_missing` owner wait. Missing live profile grants in secrets stop at `vendor_authentication`. Authentic installed fixture production, dedicated unused UIDs and actual actors remain open. |
| 2B | Open. `dataworker.TestChild`, the human atomic proof/job handoff and generic non-archive worker execution still refuse. No parent-authority execution fallback was added. |
| 2C | Open. `grants.revoke` still refuses until its atomic cascade, causal stop, transport invalidation and measured endpoint/lease collection exist. |
| 2D | Open. Terminal ancestor states still require a sealed post-exit delegation lease. No terminal state or copied launch label is treated as retained authority. |
| 2E | Open. Registered exports, additional destinations, writer handoff and the mutable-volume/Git-history matrix remain unimplemented. The existing main-workspace copy cell does not certify them. |
| 2F | Partial. Assembly installs the actual Codex and Claudock credential validators. Per-run vendor enrollment/callbacks, supported live credential modes and controlled egress remain open. |
| 2G | Built at the component boundary. Metadata-only listing authenticates native records and reads one service-owned event snapshot, checks the current human session or exact life/run and grants, filters lane results, and rechecks authority. Import/rotate/revoke now produce supported service-origin events and durable metadata-correlated replies. Verification reconstructs the private projections from immutable events. The installed secrets client now retains an actual same-connection metadata request/response. Installed execution and migration of historical successful events lacking the new private projections remain unproved. |
| 2H | Observer contract repaired. Administrator event queries name the prepared child/run, preserve the initial sequence floor across cursor pages and reject foreign/replayed events. Administrator and Linux CLI calls use numbered fresh proof files. Missing confirmation leaves a failed, unreached assertion. A genuine installed human peer/session ceremony remains required. |
| 2I | The fixture concern is proved by the actual installed constructor: reconstruction with the retained protected key unlocks, while a raw native reconstruction stays locked and an absent installed key refuses construction. The tagged native canary distinguishes failed wrong-key recovery, successful protected recovery and tampered records, and measures an unprivileged read denial against a readable control. A reviewed installed service recovery/control producer remains open. |

## Composition hooks

The sole item-1 composition hook is the two runner-owned validators passed to
`secrets.New` in `internal/v2/assembly/assembly.go`. Capture, materialization and
agent launch implementations were not edited by this round.

`e2e/v2/lane_handoff.py` provides `lane_descriptors(config, binding_file)` for
Python actors already running inside a lane. Supply its result as `pass_fds`
with `close_fds=True`. It retains exactly the sealed binding and O_PATH socket
at their original descriptor numbers and validates the active configuration.
The grants actor calls it. Other actor owners must adopt the same narrow hook;
their files were not changed here. The actual installed inside `identity.self`
canary remains required; the subprocess test proves descriptor identity/bytes
and absence of an unrelated inheritable FD, not service peer authentication.

Outside administrator/Linux coordinators must prepare private
`test_root/authority/NNNNNN.proof.json` files. The administrator number is its
next retained command number, also used by `request-NNN.json`; Linux uses its
CLI invocation index. The authority directory is 0700 and proof files are 0600.
The coordinator derives the proof from the retained exact method/body. Reads
need a fresh `human.session` proof; the CLI establishes that session on the same
connection. Root spawn uses `--session-proof`; exact mutations use `--proof`.
File presence never means confirmation: the real client and service validate
the proof, its intent and its unconsumed authority. A missing proof emits an
`owner_wait` evidence object with `completed: false` and stops the dependent
operation. Never replace it with a copied session or a completion flag.

The native backend's private `WithMetadata` callback exports authenticated
`SecretInfo` only, under its ordinary cross-process mutation lock. Another
backend must implement equivalent protected enumeration before list works.
No value lookup, writer or key is exported by this capability. Human listings
contain committed public heads; unrelated private profile enrollment stays
unpublished. An interrupted change to an existing public name remains a
reconciliation conflict. Lane listings contain only exact current delegated
source/version selections, including an older still-delegated version.

## Verification scope

`TestMetadataRecords` and `TestMetadataAuthentication` first failed at the
missing native capability and then passed. `TestSecretMetadataRealStore` and
its fences first reached the public stub. Their actual SQLite/native path then
exposed and repaired the unsupported event origin, the configuration-history
read scope and the missing store reply projection. Rotation/replay and
`state verify` run through the real owners. Session/native peer/assertion
inputs remain explicit component facts.

`TestSecretMutationRequestFence` first demonstrated acceptance of stale-base,
foreign-name and missing-event input, then requires atomic refusal without
changing metadata or consuming the proof. `TestSecretMetadataProjectionIntegrity`
first demonstrated that generic projection checksums were insufficient; the
candidate must reject changed metadata by replaying the immutable journal.
`TestSecretMetadataPrivateEnrollment` proves an unpublished protected profile
source neither leaks nor blocks unrelated committed public metadata.

`TestSecretMetadataDelegated` checks a parent-only source with exact replay.
Its deliberate red widens the result to all heads; the deciding diagnostic
must be reached before the restored candidate is counted green. Delegated
controls cover foreign actors/lives/sources, stale runs, revoked or expired
grants and missing readers/resolvers. These are component transport/grant
facts with real encrypted sources, not an installed L5-to-L3 execution.

`TestPythonLaneHandoff` first reached the actual child FD-read failure (exit 83)
without inheritance. Its candidate checks the exact sealed bytes and socket
inode and rejects forwarding an unrelated inheritable FD. The projection
paths are checked against the compiled client constants.
`TestOutsideObserverContract` first fails for unselected event queries, missing
proof forwarding, execution without confirmation, foreign events and the
untyped missing-live-auth prerequisite. The candidate must retain typed waits.

`TestMetadataNativeOwnerCanary`, selected with
`laneboss_root_canary,laneboss_gate_integration`, uses the disposable root kit
for actual native ownership and recovery controls. It installs no service or
owner authenticator. The approved package suite and candidate-only vet results
are retained in this lane's external evidence; they are not installed E2E
acceptance. No source archive or evidence tarball is produced in this light round.

`TestInstalledRestartIsUnlocked` runs the actual `installedSecrets` constructor
twice against test-owned protected enrollment/key/record bytes. It separately
measures an unopened native backend and missing installed key. This proves the
2I composition concern; it does not claim a systemd restart or owner recovery
ceremony occurred.

## Owner steps

Administrator installation, genuine human session/operation confirmations,
owner-chosen vendor enrollment and budgets, and any claimed physical hardware
gesture remain owner steps. D6 confirmations, human sends and browser gestures
were not executed or credited. Their owning harnesses must stop on the
corresponding typed wait. No owner message, real model request, credential
transfer, commit, merge or deployment was performed by this round.

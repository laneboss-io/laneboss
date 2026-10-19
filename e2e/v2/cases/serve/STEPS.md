# Installed service E2E steps

The default scope is installed-lifecycle. It requires first human enrollment,
a verified session and both disposable L5 roots, Claudock first and Codex second,
through their real service lifecycle. All required rows must execute and pass.
The independent serve-state scope remains available with --suite state; a
lifecycle result does not satisfy its outstanding recovery/count/capture checks.
That scope uses the default fixture's protected launch proposal, or an explicit
--launch-request selecting the externally supplied publication's L5 inputs.
Every dependent row displays presence=simulated and human_approval=not_proven.
The hardware authenticator and vendor executables are declared fixtures; native
identity, authority, helper gates, store, workers and observations remain real.

Run on a fresh authorized Ubuntu 24.04 box only:

```sh
serve_tree=/test/candidate
sudo -n bash "$serve_tree/e2e/v2/cases/serve/run.sh" \
  --source /test/candidate \
  --evidence /test/evidence/lb-v2-serve-lifecycle \
  --suite lifecycle
```

The default install-input step builds the standalone harness assembler and
supplies its protected publication, root request and launch proposals. See
scripts/v2-serve/README for the fixture scope, validators, retained bytes and
unresolved product contracts. This input preparation is not an installed pass.

An external bundle can instead add --config case-serve,
--boot /opt/test-admin/boot-input.json,
--lane-inputs /opt/test-admin/l5-roots.json and
--root-grants /opt/test-admin/root-grants.json. l5-roots.json is an object keyed
by claudock-cli and codex. Each value is an exact
StartRequest with level 5, the matching driver, approved role/model/effort and
actual enrolled project/profile/task selectors. It contains no root_ticket_id;
the ceremony supplies each separately issued one-use ticket. root-grants.json
is a real RootGrantRequest referencing the actual committed manifest. These
files must be root-owned regular single-link files with protected ancestors.
The supplied configuration must equal the InitialManifest config. The complete
--boot schema, including launch and initial publication fields, is documented
in the administrator README. Every initial descriptor/object is root-owned
0444. The supplied runtime pins must match this checkout's actual trimpath
builds, exact dependencies, toolchain and tags; no descriptor is repinned to
make an input pass. RootGrantRequest.manifest must select the published profiles
object, and each StartRequest must select its real L5 role/task/policy/project.
The default assembler names immutable input objects before installation. Issued
grant/ticket IDs always come from actual service responses; the driver never
seeds the store.
Missing files remain FAIL/unrun with named owner requests, not fabricated RPC
refusals. A product refusal is retained verbatim with its actual typed owner.

The driver generates request/proof files and records each exact argv in the
numbered evidence files. In the commands below, cli means its actual installed
binary, cfg the unique e2e configuration, binding its published binding file,
installation the admin-returned service installation, and key a fresh retained
idempotency key. File variables name the exact retained inputs, not inline JSON.
No variable below is filled from an inherited environment or printed credential.
The begin and registration helper inputs are exact copies of the retained files
in a fresh private directory below protected /opt, not the evidence paths below
shared /var/tmp. Each call retains file hashes and native metadata for both
request paths, the installed helper, configuration and every ancestor. The
helper input must be root-owned, regular, single-link and mode 0600. No product
integrity check is relaxed.

Private enrollment failures now return a typed error and fixed failure_field,
and the service journal names that field without request values. Preserve the
actual reply and journal before attributing a receive failure to the JSON frame.
A success still requires exact nonce correlation and all installed native gates.
The frame field audit and native prerequisite are in FORWARD.md.
AUTHENTICATION.md records the later human-endpoint failure and run-8 fix.
Every public CLI call retains native caller/binding/socket metadata before
its single actual attempt. Transport errors retain a named owner and fixed
stage. Authentication/admission failures are journaled without request values,
replied to once and followed by owned teardown. A refused call is not reopened
or counted as a successful check.
The supervisor confirmed that prerequisite as cross-user executable access.
The CLI now authenticates to the installed root daemon and requests only its
fixed enrollment relay. The daemon forwards the exact ceremony to the service;
the service checks its sole native control PID, stable lifetime, protected IPC
and installed-byte digest. Neither the command form nor the real ceremony steps
below are skipped or replaced. Kernel writer checks and descriptor refusal remain.

| Step | Owner lane / required port | Exact command form and required observation |
| --- | --- | --- |
| Build inputs | serve / actual fixture sources and current assembly | Stage and archive actual source/dependency bytes. Build the service with laneboss_partial and laneboss_e2e_authenticator, and both separate fixtures with the dedicated authenticator tag. No project execution occurs on the Mac. |
| Install prefix | admin / namespace and boot installer | Run the existing namespace --install/--check and install --install --boot FILE/--check entries from protected /opt staging. Require real ready/verified receipts and exact installed bytes/UIDs. |
| Public health | service / installed listener | `"$cli" health --config "$cfg" --binding "$binding"`; require actual protocol/artifact and observed host capabilities. |
| Device | serve / dedicated tagged authenticator | `"$auth" create --private "$private" --config "$cfg" --origin "$origin" --rp-id "$rp"`; key/counter stay private, shared public markers declare simulated presence. |
| Begin registration | admin -> service -> identity / BeginHumanEnrollment, BeginEnrollment, ReserveEnrollment | `"$cli" internal helper --config "$cfg" --installation "$installation" --enroll-begin "$begin"`; require the actual stored create challenge, fixed RP/origin, generations and unconsumed empty-baseline ceremony. |
| Attestation | serve / test-tag-only P-256 device | `"$auth" register --private "$private" --config "$cfg" --challenge "$challenge"`; actual packed self-attestation, COSE P-256 key and shared AAGUID/marker. It grants no authority. |
| Complete registration | admin/service/identity/store / CompleteHumanEnrollment, ValidateEnrollment, admin_enroll | `"$cli" internal helper --config "$cfg" --installation "$installation" --enroll-complete "$registration"`; require real configuration-wide empty-baseline commit receipt, evidence/event/operation/sequence and SimulatedPresence=true. |
| Initial publication | admin/service/store / PublishInitialFrame, CommitInitial, Transact | Run install.sh --publish twice with config and separate new protected evidence directories. Require identical actual receipts bound to the supplied descriptor, publication ID, operation, event, committed sequence, marker and generation one. The native writer rereads the exact first publication event, policy, snapshot and all objects. |
| Publication observation | serve/identity/store / actual human-session reads | Read the committed marker, descriptor and policy blobs, and the operation through the installed CLI. Require exact input bytes/pins and first_seq=last_seq=committed_seq. Current typed policy/snapshot and exact event verification belong to the native writer's read-back. No unrelated event or caller-supplied receipt satisfies this gate. |
| Operation challenge | identity / HumanChallenge | `"$cli" human challenge --config "$cfg" --binding "$binding" --request "$intent" --idempotency-key "$key"`; bind method, target, exact digest/base, RP/origin and nonce. |
| Assertion | serve / real key in private test directory | `"$auth" sign --private "$private" --config "$cfg" --operation "$body" --method "$method" --target "$target" --generation "$generation" --challenge "$challenge"`; real advancing counter/signature. |
| Confirmation | identity/store / HumanConfirm | `"$cli" human confirm --config "$cfg" --binding "$binding" --request "$assertion" --idempotency-key "$key"`; only this real response supplies ProofRef; require simulated_presence=true. |
| Human session | identity/transport/store / HumanSession and read-session refresh | `"$cli" human session --config "$cfg" --binding "$binding" --request "$empty" --proof "$proof" --idempotency-key "$key"`; require real bounded session and simulated mark. Each later read gets its own fresh session proof on the read's same CLI socket. |
| Root grants | grants / GrantsRoot, protected source/profile resolver | `"$cli" grants root --config "$cfg" --binding "$binding" --request "$root" --proof "$proof" --idempotency-key "$key"`; require actual current root grant set, never a caller-created ID. |
| Root ticket | identity/store / TicketIssue | `"$cli" ticket issue --config "$cfg" --binding "$binding" --request "$ticket" --proof "$proof" --idempotency-key "$key"`; bind principal/config/level 5/role/grants/expiry and simulated provenance. Repeat with a fresh ticket for the second driver. |
| Start each L5 root | lifecycle/service/grants/admin/identity / ReserveLaunch and PlanLaunch | `"$cli" lane start --config "$cfg" --binding "$binding" --request "$start" --idempotency-key "$key"`; require actual reservation/operation/life/run and simulated mark. A pending operation is not a running process. |
| Await operation | service / Operation | `"$cli" operation get --config "$cfg" --binding "$binding" --request "$operation" --proof "$session_proof"`; await the same actual operation, preserving any asynchronous typed error/owner. |
| Status | lifecycle/store / LaneStatus | `"$cli" lane status --config "$cfg" --binding "$binding" --request "$target" --proof "$session_proof"`; assert level 5, approved role, requested driver, root lineage, same life/run/launch. |
| Native running/check | lifecycle/helper/identity / LaneCheck and actual ObserveGate | `"$cli" lane check --config "$cfg" --binding "$binding" --request "$target" --proof "$operation_proof" --idempotency-key "$key"`; require matching containment and running with positive survivors before stop. This is a control mutation, not a session read. |
| Events | lifecycle/service/store / EventTail | `"$cli" event tail --config "$cfg" --binding "$binding" --request "$events" --proof "$session_proof"`; follow real pagination, assert lane.created, identity.bound and lane.started for this root/run. |
| Stop reason | service / committed blob staging | `"$cli" blob begin`, `blob chunk`, `blob commit`, each with config/binding/request, a new session proof and retry key; commit actual task-class stop reason bytes. No fabricated BlobRef. |
| Stop | lifecycle/helper/service / LaneStop and committed stop outbox | `"$cli" lane stop --config "$cfg" --binding "$binding" --request "$stop" --proof "$operation_proof" --idempotency-key "$key"`; await actual operation then observe terminal exit or signal and explicit zero survivors. |
| Abandon disposable work | lifecycle / LaneMark | `"$cli" lane mark --config "$cfg" --binding "$binding" --request "$abandon" --proof "$operation_proof" --idempotency-key "$key"`; only abandoned is requested. The required review field is empty and claims no review/acceptance. |
| Archive | lifecycle/dataworker/service / LaneArchive and archive read-back | `"$cli" lane archive --config "$cfg" --binding "$binding" --request "$archive" --proof "$operation_proof" --idempotency-key "$key"`; require the actual verified archive receipt/hash/read-back for this life. |
| Clean | lifecycle/dataworker/helper / LaneClean, owned-object collector | `"$cli" lane clean --config "$cfg" --binding "$binding" --request "$clean" --proof "$operation_proof" --idempotency-key "$key"`; use that real archive ID, await operation, check cleaned=true and lane.cleaned via CLI. No host Git deletion or forced collection. |
| Finish | serve/admin / owned process collection | Stop only the named installed units, verify MainPID=0/socket collection, retain journals and unknown lane collection as FAIL. A refused stop is not retried through another route. |

The private key never enters any request, artifact/runtime archive, checkout,
HOME or command output. Only attestation/assertion/public data cross the helper
or RPC boundary. EnrollmentChallenge/EnrollmentReceipt use their frozen Go JSON
field names; the complete request uses EnrollmentValidationRequest's field map.
The client and real validated software registration now share the declared
software credential selector. Production software-presence rejection is unchanged.
The boot installer publishes admin_enrollment only from explicit protected
origin/RP input; it derives UID, socket, generation and helper pins from the real
installation. The helper modes already exist, and its nonce-bound envelope now
matches the listener/store. The harness decodes the actual simulated receipt
wrapper and still requires human_approval=not_proven. FORWARD.md lists every later
entry point and the remaining actual implementation/data gates.

Missing owner methods must return their actual not_implemented with owner. A
different refusal remains FAIL with its actual code; the harness never rewrites
forbidden, unavailable, input/setup or compilation failure as not_implemented.
report.json includes the exact failing step, owner/code and unchanged raw error;
summary.txt prints them plus all failed/unrun counts. Reprint on the box with:

```sh
serve_tree=/test/candidate
serve_evidence="/test/evidence/lb-v2-serve-lifecycle"
python3 -I -B "$serve_tree/scripts/v2-serve/summary.py" \
  --report "$serve_evidence/report.json"
```

The summary uses the complete shared step catalog independently of the report's
claimed required rows. A shortened catalog, stored refusal, unexecuted step or
erased simulation cannot pass. Cleanup cannot overwrite the original failed row;
uncollected lanes remain failures even after named unit shutdown. The state
scope's historical unready.owner label requires real judge projection data.

This Mac run is static only. No ceremony, unit, mutation, native or installed
acceptance result is claimed. The source base is 7331595 with run-8 connection
integration and concluded admin/service/grants/templates merges. STARTUP.md
lists every constructor and the production startup test.
REQUESTS.md names the actual remaining owner boundaries.

# Your first lane

This walkthrough follows one human-started L5 lane. It uses one installed
configuration. Read the [command conventions](README.md#how-to-read-the-commands)
and [installation limits](install-linux.md) first.

The brief's installed E2E stopped at its first lane start. Sections 4–9 below
describe source-backed operations, not a passing end-to-end run. Stop if any
earlier prerequisite fails. Do not skip a refusal to reach the later sections.

## 1. Install and enroll

Complete the [Linux installation](install-linux.md). Retain the matching binary,
release manifest, install evidence and real enrollment receipt. The first human
enrollment uses the fixed administrator helper and a security key with PIN or
biometric verification. A software authenticator proves simulated presence only.

Your administrator must supply the approved project and driver enrollment,
initial L5 role sources, task and root-profile declarations. The CLI cannot
invent those installation facts. An authenticated model run also requires a
real profile enrolled by the owner outside the source checkout. Doctor and
profile metadata do not prove vendor authentication.

## 2. Publish the first org setup

An **org** is the service-owned set of policy, roles, prompts and resources.
The installation staged its first generation. Publish those exact installed
bytes as root, from the protected source bundle:

```sh
bash scripts/v2-admin/install.sh --publish --config NAME \
  --evidence PUBLICATION_EVIDENCE
```
<!-- source: scripts/v2-admin/install.sh; scripts/v2-admin/boot.py; internal/v2/service/initial.go -->

`PUBLICATION_EVIDENCE` must be a new canonical absolute directory with protected
ancestors. Require exit 0, `verified: true`, `published: true` and a `receipt`.
That receipt has `schema`, `config`, `id`, `manifest`, `receipt`, `operation_id`,
`event_id`, `committed_seq` and `generation`. Require schema
`laneboss.initial-receipt.v2`, the installed configuration, generation 1 and
a positive committed sequence. Keep the retained `receipt.json`.

This route compares an empty org and publishes the initial policy, sources and
objects together. A retry of the same installed publication returns the retained
receipt. Use a fresh evidence directory for the retry. A conflicting baseline
stops. After bootstrap, org changes use [L6 proposal and owner approval](policy.md).
<!-- source: scripts/v2-admin/boot.py; internal/v2/admin/initial.go; internal/v2/service/initial.go -->

## 3. Prepare human authority

The CLI accepts files. It has no interactive WebAuthn prompt. Use your deployment's
approved human interface to calculate the request intent and operate the key.
If that interface is absent, stop here. The following commands expose its
file-backed interface; they do not generate signatures themselves.

For each confirmation, first finish and save the target request. Have that
interface calculate `api.RequestDigest` for the exact configuration, protocol,
schema, method and params. This is a canonical request-intent digest. It is
different from the raw SHA-256 of the JSON file.
<!-- source: internal/v2/api/json.go; internal/v2/client/prepare.go; internal/v2/cli/commands_identity.go -->

1. Save a challenge request with `method`, `target_id`, `request_sha256` and
   `base_generation` for that target operation.
2. Request the challenge through the installed human endpoint:

```sh
laneboss human challenge --config NAME --request CHALLENGE_REQUEST \
  --idempotency-key CHALLENGE_KEY
```
<!-- source: internal/v2/cli/commands_identity.go; internal/v2/api/identity.go; internal/v2/cli/cli.go -->

3. Have the human interface perform a WebAuthn assertion for the returned
   challenge, origin and RP. Require PIN or biometric verification. Save the
   confirm request with `challenge_id`, `credential_id`, `client_data_json`,
   `authenticator_data` and `signature`. Byte arrays use JSON base64 strings.
4. Submit that actual assertion:

```sh
laneboss human confirm --config NAME --request CONFIRM_REQUEST \
  --idempotency-key CONFIRM_KEY
```
<!-- source: internal/v2/cli/commands_identity.go; internal/v2/api/identity.go; internal/v2/cli/cli.go -->

Save the returned ProofRef privately. It contains `id`, `request_sha256`,
`expires_at` and, in the test build, optional `simulated_presence`. It authorizes
one exact intent until expiry. Keep the challenge and confirm retry keys with
their respective original inputs.

Select the challenge target using the service's target rules. For the operations
in this walkthrough, the mapping is:

| Method being confirmed | `target_id` | `base_generation` |
| --- | --- | --- |
| `human.session` | The enrolled principal ID from your enrollment receipt. | 0. |
| `grants.root`, `mail.send` | The configuration name. | 0. |
| `ticket.issue` | The issued root grant-set ID. | Its current grant generation. |
| `lane.stop`, `lane.mark`, `lane.archive`, `lane.clean` | The target life ID. | The request's `expected_generation`. |
| `lane.review` | The target life ID. | Its current life generation. |

Use the exact completed request's digest in every row. The human interface must
match these targets; a matching file hash alone is insufficient.
<!-- source: internal/v2/store/projection_reads.go; internal/v2/identity/human.go -->

There are two different uses of proof:

| Intended action | Proof to prepare |
| --- | --- |
| Read state, browse the dashboard or upload a file | Confirm `human.session` with the empty params object `{}`, your enrolled principal ID as `target_id` and `base_generation` 0. Use the returned proof as `SESSION_PROOF`. |
| Issue root grants or a ticket; send human mail; stop, review, mark, archive or clean | Confirm that exact method and completed request. Pass the returned proof as `--proof` on that mutation. |
| Start the human's root lane | Issue the root ticket first. Use a separate `human.session` proof as `--session-proof`; the ticket is in the start request. |

For a read, common `--proof SESSION_PROOF` creates and binds the human session
on the **same socket** before making the read. The command closes that socket
when done. Obtain a fresh session proof for each separate CLI invocation shown
below. Do not reuse a consumed proof. Running a session command in an earlier
process does not authenticate the next process.
<!-- source: internal/v2/cli/cli.go; internal/v2/cli/commands_identity.go; internal/v2/identity/session.go; internal/v2/store/projection_reads.go -->

Use this read path to check your identity and published org. Substitute the
initial publication's generation for `GENERATION`:

```sh
laneboss identity self --config NAME --proof SESSION_PROOF
laneboss org validate --config NAME --generation GENERATION --format json \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_identity.go; internal/v2/cli/commands_templates.go; internal/v2/cli/cli.go -->

Identity must name the correct configuration and a human actor. Org validation
must exit 0 with `valid: true` and `problems: []`. Run
[doctor](install-linux.md#4-check-readiness-with-doctor) and require readiness
before requesting a lane.

### Prepare committed content

Not yet verified on an installed service.

The initial publication already supplies the first task and root manifest.
For a new message, reason or task, save its original text in a local file.
Use the blob transfer interface to commit those exact bytes before confirming
a request that refers to them:

```sh
laneboss blob begin --config NAME --request BLOB_BEGIN_REQUEST \
  --proof SESSION_PROOF --idempotency-key BLOB_BEGIN_KEY
laneboss blob chunk --config NAME --request BLOB_CHUNK_REQUEST \
  --proof SESSION_PROOF --idempotency-key BLOB_CHUNK_KEY
laneboss blob commit --config NAME --request BLOB_COMMIT_REQUEST \
  --proof SESSION_PROOF --idempotency-key BLOB_COMMIT_KEY
```
<!-- source: internal/v2/cli/commands_service.go; internal/v2/cli/cli.go; internal/v2/api/common.go -->

Begin has `class`, `bytes` and `sha256` for the whole input. It returns
`object_id`, `max_chunk_bytes` and `expires_at`. Each chunk has that `object_id`,
its byte `offset`, base64 `data` and the chunk's `sha256`. Transfer in order,
within the returned size limit. Use a distinct retained key for each chunk.
Commit has `object_id` and the whole input's `sha256`. It returns a BlobRef.
Require its ID, class, byte count and hash to match the input. A failed transfer
stops the remaining transfer and target request.

Use class `task` for the start task and stop reason. Use class `report` for mail
content. Do not upload secrets through this general blob route.
<!-- source: internal/v2/api/common.go; internal/v2/client/wire/service_input.go; internal/v2/lifecycle/input.go; internal/v2/messaging/validation.go -->

### Issue root grants and the root ticket

Not yet verified on an installed service.

Prepare `ROOT_REQUEST` with `manifest` pointing to the committed
`laneboss.root-grants.v2` document, and an explicit `budget`. Review its project
data and enrolled profile selectors. For this first run, request only the
capabilities the approved task needs. Confirm that exact `grants.root` intent,
then submit:

```sh
laneboss grants root --config NAME --request ROOT_REQUEST \
  --proof ROOT_PROOF --idempotency-key ROOT_KEY
```
<!-- source: internal/v2/cli/commands_grants.go; internal/v2/cli/cli.go; internal/v2/api/grants.go -->

Retain the returned GrantSet. Its `id` selects the set. Each member has its own
issued grant ID. Profile selectors are not login credentials. Missing protected
profile enrollment or capability resolution stops this step.
<!-- source: internal/v2/grants/root.go; internal/v2/grants/root_profiles.go -->

Prepare `TICKET_REQUEST` with `level` 5, the initial L5 `role`, that
`grant_set_id` and a future `expires_at` within the grants' lifetime.
Confirm the exact `ticket.issue` intent, then run:

```sh
laneboss ticket issue --config NAME --request TICKET_REQUEST \
  --proof TICKET_PROOF --idempotency-key TICKET_KEY
```
<!-- source: internal/v2/cli/commands_identity.go; internal/v2/cli/cli.go; internal/v2/api/identity.go -->

Keep the issued ticket `id`, level, role, grant set and expiry. It must be unused,
current and bound to this human and endpoint. It is redeemed by the root launch.
Do not give a human ticket to an agent to change that agent's identity.
<!-- source: internal/v2/identity/human.go; internal/v2/lifecycle/launch.go -->

## 4. Start the lane

Not yet verified on an installed service.

Prepare `START_REQUEST` with these exact `StartRequest` fields:

| Field | Value to select |
| --- | --- |
| `lane` | A new, unused lane name. |
| `project_id` | The administrator-enrolled project ID. |
| `level`, `role` | Level 5 and the exact initial L5 role authorized by the ticket. |
| `task` | The committed nonempty task BlobRef from the initial publication. |
| `grants` | A GrantRequest with explicit `resources`, `data`, `secrets`, `profiles`, `network` and `channels` arrays. Select only current authority from the root grant set. |
| `driver`, `profile_grant_id` | The enrolled driver and matching issued profile grant. Supported driver values are `claudock-cli` and `codex`. |
| `model`, `effort` | The full model name and effort supported by that enrolled driver and role. |
| `budget` | Explicit `wall_ms`, `cpu_seconds`, `memory_bytes`, `processes`, `disk_bytes`, `spend_micros` and three-letter uppercase `currency`. Stay within approved limits. |
| `root_ticket_id` | The ticket just issued. |
| `expected_policy_generation` | The current approved policy generation. |

Obtain a fresh session proof and run the root start:

```sh
laneboss lane start --config NAME --request START_REQUEST \
  --session-proof SESSION_PROOF --idempotency-key START_KEY
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/commands_identity.go; internal/v2/cli/cli.go; internal/v2/api/lifecycle.go; internal/v2/api/runtime.go -->

This returns an Operation, not a v1 lane-start record. Keep its `id`, `status`,
`life_id`, `run`, `first_seq` and `last_seq`. An operation can be `pending` or
`running`. Those states do not prove the agent executed. A failure has an error;
preserve it. The first run is run 1, under its new immutable life ID.

For any pending operation in this tutorial, save an operation-get params file
with `operation_id` equal to the returned ID, and query its original operation:

```sh
laneboss operation get --config NAME --request OPERATION_REQUEST \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_service.go; internal/v2/cli/cli.go; internal/v2/api/common.go -->

Require the operation's actual completion and the appropriate committed events.
Do not submit a different start to get past a pending or failed launch.

## 5. Watch the lane on the dashboard

Not yet verified on an installed service.

Read the tree and lifecycle views. Replace `LIFE_ID` and `RUN` with the start
operation's real target. Each command needs its own fresh session proof:

```sh
laneboss dashboard tree --config NAME --proof SESSION_PROOF
laneboss dashboard lifecycle --config NAME --life-id LIFE_ID --run RUN \
  --proof SESSION_PROOF
laneboss dashboard raw --config NAME --life-id LIFE_ID --run RUN \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_dashboard.go; internal/v2/cli/cli.go -->

These commands print JSON views. Read the recorded state and raw capture. A
missing capture or an unavailable view is not an empty successful run.
For a bounded event follow, save the sequence before the action being observed:

```sh
laneboss event tail --config NAME --life LIFE_ID --run RUN --since SEQUENCE \
  --follow --until lane.started --deadline-ms 60000 --format jsonl \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go -->

Require a `lane.started` event for this life and run with service origin.
JSONL follow starts with an EventPage, then StreamFrames. It is not a stream of
bare event objects. Keep the cursor and check the authenticated end frame.
A deadline or disconnection is not evidence of completion.

The web components include a tree, raw views and controls. They need an installed
HTTP bridge and authenticated human session. This revision's CLI has no command
to start a web server and assembly does not host those pages. Use the CLI views
above when operating this source snapshot.
<!-- source: internal/v2/dashboard/http.go; internal/v2/assembly/assembly.go; internal/v2/cli/dispatch.go -->

## 6. Send a message

Not yet verified on an installed service.

Write a short follow-up in a file. For example, ask the lane to report its
current progress. Commit it as a `report` blob using section 3. Prepare
`MAIL_REQUEST` with `recipient_life_id`, `content` and `ask`.
For a first direct message, `ask` can be false. Omit `reply_to` when there is
no earlier message to reply to. Also omit `channel_grant_id` for this direct
human-to-lane message. Confirm that exact
`mail.send` request with the key, then run:

```sh
laneboss mail send --config NAME --request MAIL_REQUEST \
  --proof MAIL_PROOF --idempotency-key MAIL_KEY
```
<!-- source: internal/v2/cli/commands_messaging.go; internal/v2/cli/cli.go; internal/v2/api/mail.go -->

The Mail result's `id`, `queued_seq` and `status: "queued"` prove enqueueing.
They do not prove delivery or an answer. Inspect the mailbox and raw view:

```sh
laneboss mail list --config NAME --life-id LIFE_ID --limit 50 \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_messaging.go; internal/v2/cli/cli.go -->

Follow the message's ID through its delivery or return receipt. A `profile_limit`
exit does not acknowledge mail. An agent's reply does not set `answered` by itself.
<!-- source: internal/v2/messaging/receipts.go; internal/v2/messaging/routing.go; internal/v2/api/mail.go -->

## 7. Stop and establish quiescence

Not yet verified on an installed service.

Read the current life before preparing the stop:

```sh
laneboss lane status --config NAME --life LIFE_ID --run RUN \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go -->

Save its current `generation` and `last_seq`. Commit your stop reason as a `task`
blob. Prepare `STOP_REQUEST` with `target` containing `life_id` and `run`,
`expected_generation` from that status, and the committed `reason` BlobRef.
Confirm the exact `lane.stop` request, then run:

```sh
laneboss lane stop --config NAME --request STOP_REQUEST \
  --proof STOP_PROOF --idempotency-key STOP_KEY
laneboss event tail --config NAME --life LIFE_ID --run RUN --since SEQUENCE \
  --follow --until lane.ended --deadline-ms 60000 --format jsonl \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go -->

`SEQUENCE` is the saved value from before stop. Require the stop operation to
complete and the selected run's real end event. Its payload contains `reason`
and `observation`. Require `observation.state` to be `exited` and a known
`observation.survivors` equal to 0. A missing survivor count means unknown.
Inspect the exit code or signal and capture status; a requested stop does not
prove a successful task. Re-read status. Preserve all leases if containment is
unknown. A stale-generation refusal requires reviewing fresh state and making
a new explicit decision, not changing the old request under its retry key.
<!-- source: internal/v2/api/events.go; internal/v2/api/runtime.go; internal/v2/lifecycle/control.go -->

## 8. Record the disposition

Not yet verified on an installed service.

For this stopped tutorial, choose `abandoned` after inspecting and retaining the
work. This records that the task will not be landed. Prepare `MARK_REQUEST` with
the current `target`, fresh `expected_generation` and `state` equal to `abandoned`.
Use a real ReviewReceipt as its required `review` member. Obtain it through the
[independent review procedure](lanes.md#review-before-acceptance), using the actual
diff, checks and record inventory. Retain failed checks as failures.

The lifecycle does not require successful review for abandonment. However,
this snapshot's socket decoder still validates all nested IDs, hashes, enums
and required fields. An empty review object or zero-valued receipt will refuse.
If no real, well-formed receipt is available, stop here and preserve the work
until the owning implementation provides a supported disposition route.
Do not create a dummy receipt to reach clean.
<!-- source: internal/v2/api/lifecycle.go; internal/v2/lifecycle/input.go; internal/v2/lifecycle/review.go; internal/v2/client/wire/json.go; internal/v2/client/wire/schema.go -->

Confirm the exact abandonment request:

```sh
laneboss lane mark --config NAME --request MARK_REQUEST \
  --proof MARK_PROOF --idempotency-key MARK_KEY
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go; internal/v2/lifecycle/input.go; internal/v2/lifecycle/review.go -->

Require completion and a `lane.state` event whose payload `to` is `abandoned`.
Re-read status before the next mutation.

For useful completed work, follow the independent review process in
[lanes](lanes.md#review-before-acceptance). Acceptance needs actual diff, required
check and capture evidence. Only verifying work can become `accepted`; only
accepted work can become `merged`. Marking merged records a decision. It performs
no Git merge or deployment. Do not mark merged just to make clean succeed.

## 9. Archive, then clean

Not yet verified on an installed service.

Prepare `ARCHIVE_REQUEST` with the current `target` and `expected_generation`.
Confirm that exact `lane.archive` request, then run:

```sh
laneboss lane archive --config NAME --request ARCHIVE_REQUEST \
  --proof ARCHIVE_PROOF --idempotency-key ARCHIVE_KEY
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go; internal/v2/lifecycle/archive.go -->

Keep the returned ArchiveReceipt. It contains `id`, `life_id`, `manifest`,
`archive_sha256`, `read_back_sha256`, `verified_at` and `store_id`.
Require the correct life, a real stored manifest and matching archive/read-back
hashes. A committed `archive.verified` must refer to this receipt after the
run's quiescent end. A fabricated archive or a copied successful log is not enough.

Read status again. Prepare `CLEAN_REQUEST` with `target`, its fresh
`expected_generation` and `archive_receipt_id` equal to that receipt's ID.
Confirm that exact `lane.clean` request, then run:

```sh
laneboss lane clean --config NAME --request CLEAN_REQUEST \
  --proof CLEAN_PROOF --idempotency-key CLEAN_KEY
laneboss lane status --config NAME --life LIFE_ID --run RUN \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go; internal/v2/lifecycle/archive.go; internal/v2/lifecycle/collect.go -->

Clean requires merged or abandoned work and verified quiescence. Its Operation
may still be pending. Require actual completion, `lane.cleaned` and the final
life's `cleaned: true`. Inspect the event's `archive_receipt`,
`removed_object_ids`, `retained_object_ids` and `quiescence`. Retained work is
not proof of removal. Dirty, foreign or unknown work must be retained. Do not
force-remove it. Keep the archive, raw records, inputs and receipts.
Use the immutable life ID to read a cleaned lane; name lookup selects active
uncleaned lives. A cleaned life cannot resume.
<!-- source: internal/v2/lifecycle/archive.go; internal/v2/lifecycle/collect.go; internal/v2/cli/commands_lifecycle.go -->

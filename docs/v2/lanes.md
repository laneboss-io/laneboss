# Operate lanes

Read the [tutorial](tutorial.md) for the first lane. This page explains the
choices and checks you will repeat. It describes revision `d7403ec`.

Not yet verified on an installed service.

The installed E2E reported in the brief stopped at the first lane start.
The lifecycle, messaging, grants, secret delivery and account continuation
behavior below still needs installed-service evidence.

## Choose a level and role

| Level | Typical responsibility | Lower levels it can start |
| --- | --- | --- |
| L6 | Org policy and exact org-change proposals. | L5, L4, L3. |
| L5 | Coordinate a domain. | L4, L3. |
| L4 | Supervise one stream of work. | L3. |
| L3 | Execute or review a task. | None. |

A lane can start only a **strictly lower** level. A human starts a root through
a confirmed, single-use ticket for its exact level, role and root grant set.
An L5 can start L3 directly. The service records that actual starter, rather
than inventing an L4 parent. L1 and L2 are outside the supported lane range.
Role names select approved prompt and driver sources. A name in a brief is
not proof of authority.
<!-- source: internal/v2/lifecycle/launch.go; internal/v2/lifecycle/starter.go; internal/v2/identity/claims.go; docs/design/v2-contracts.md -->

Keep three identifiers separate. A lane name is a human label. `life_id` is the
immutable identity of that lifetime. `run` identifies one execution within it.
Resume and account continuation retain the life while creating a later run.
`logical_turn_id` binds one delivered task or message turn. Reusing a name does
not transfer old descendants or access rights to a new life.
<!-- source: internal/v2/api/lifecycle.go; internal/v2/lifecycle/starter.go; internal/v2/lifecycle/continuation.go -->

## Read status and events

As a human, obtain a fresh session proof for each command. As a live lane, use
the service-created binding and omit human proof. Use actual life/run values:

```sh
laneboss lane status --config NAME --life LIFE_ID --run RUN \
  --proof SESSION_PROOF
laneboss event tail --config NAME --life LIFE_ID --run RUN --since SEQUENCE \
  --follow --until lane.ended --deadline-ms 60000 --format jsonl \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go -->

Status includes `state`, `generation`, `run`, `last_seq`, `cleaned`, grants,
workspace, session and policy pins. Save `last_seq` before a new action.
Follow only the selected life and run after that sequence. JSONL output contains
an initial EventPage followed by StreamFrames. Each event records its actor,
requester, operation, sequence, ancestry and origin. Read the payload as well
as the event kind.
<!-- source: internal/v2/api/lifecycle.go; internal/v2/api/events.go; internal/v2/cli/commands_lifecycle.go -->

Use `lane.started` or `lane.resumed` to establish execution. `lane.created`
does not establish release of an agent. `lane.ended` carries the actual terminal
observation. Check exit code or signal, prompt status and known zero survivors.
`capture.gap`, `capture.refused` and unknown containment need investigation.
A lane-authored observation cannot create a trusted lifecycle event.
<!-- source: internal/v2/lifecycle/capture.go; internal/v2/api/events.go; internal/v2/lifecycle/control.go -->

To resume, retain a ResumeRequest file with `target`, current
`expected_generation`, committed `message` of class `task`, and explicit
`budget`. The budget cannot exceed the retained remaining budget. Confirm the
exact operation as a human, then use:

```sh
laneboss lane resume --config NAME --request RESUME_REQUEST \
  --proof RESUME_PROOF --idempotency-key RESUME_KEY
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go; internal/v2/lifecycle/launch.go -->

Resume requires an eligible ended, uncleaned life, real quiescence and its
retained private session and workspace. It does not reconstruct missing vendor
history or choose the most recent session from a shared home. Re-read the new
operation's run and start your event follow from the previously saved sequence.

## Send messages along the recorded tree

| Sender | Permitted destination |
| --- | --- |
| Verified human | A lane at any level, including L3. |
| Lane | A same-level sibling with the same direct parent. |
| Lane | Any lower descendant in its actual starter chain. |
| Lane reporting upward | Its direct starter only. |
| L5 or L6 contacting a human | An exact, current org channel grant. |

A common root or matching level alone does not make two lanes peers.
L3 and L4 cannot fall back to an owner channel. Rights are checked when mail is
queued and again when it is delivered. The service derives actor and source
from the endpoint. Do not put a claimed sender into a request.
<!-- source: internal/v2/messaging/routing.go; internal/v2/api/mail.go -->

A lane can submit a report to its authentic direct starter. Save a ReportRequest
with committed `content`, `ask` and an explicit `artifacts` array. Supply
`reply_to` only when replying to a real earlier message; otherwise omit it.
Use `channel_grant_id` only for an authorized human channel. From that live lane:

```sh
laneboss report submit --config NAME --request REPORT_REQUEST \
  --idempotency-key REPORT_KEY
```
<!-- source: internal/v2/cli/commands_messaging.go; internal/v2/cli/cli.go; internal/v2/api/mail.go -->

Keep mail as original, nonempty UTF-8 text, at most 262,144 bytes. Credential-shaped
values, terminal controls and appended launcher blocks refuse. A queued receipt
is not a delivered receipt. Track the message ID through `queued`, `delivering`,
`delivered`, `returned` or `answered`. A profile-limit exit does not settle mail.
Only an authorized canonical decision answer can set `answered`.
<!-- source: internal/v2/messaging/screen.go; internal/v2/messaging/receipts.go; internal/v2/messaging/queue.go -->

## Delegate grants to a child

A grant is explicit access, not an instruction in a prompt. Start by reading the
parent's current GrantSet. Choose a subset for the child. The request has six
explicit arrays: `resources`, `data`, `secrets`, `profiles`, `network` and
`channels`. Use empty arrays for unused categories.

Each requested item identifies its `parent_grant_id`. The parent must permit
delegation. Child expiry cannot exceed that member's expiry or the parent set's
expiry. A child cannot widen read-only data to writable data, select another
secret version or invent an account, network endpoint or owner channel.
Resource ceilings can only narrow.
<!-- source: internal/v2/api/grants.go; internal/v2/grants/subset.go -->

Prepare a GrantValidateRequest with `parent_life_id`, `child_level`, `requested`
and `expected_policy_generation`. From the actual parent lane, preview it:

```sh
laneboss grants validate --config NAME --request GRANT_REQUEST
```
<!-- source: internal/v2/cli/commands_grants.go; internal/v2/cli/cli.go; internal/v2/api/grants.go -->

The result contains `effective` and `warnings`. A preview does not persist a child
or start a process. Put the reviewed subset in the child's start request.
Lifecycle rechecks current authority before release. Revocation blocks new use
and requires affected processes and leases to settle. It cannot make an agent
forget bytes it has already read.

Data access and delivery are separate choices. Use `ro` or `rw` for access.
An independent `copy` is the supported baseline. This snapshot's grant derivation
refuses live `mount` delivery without a verified export lease. Do not describe
an independent copy as a live shared directory. Test a child's output under the
child's effective grants; do not execute it with the parent's wider rights.
<!-- source: internal/v2/grants/subset.go; internal/v2/grants/root.go; internal/v2/grants/service.go -->

## Inject only the selected secrets

Task secret grants and vendor profile grants are separate. A task secret selects
one name, source version and delivery target. Delivery is `env` or `file`.
Environment targets must be nonreserved names. File targets are relative names
in the private read-only secret runtime. They are not files in the worktree.
The injector rejects control variables such as home, path and loader settings.
<!-- source: internal/v2/api/grants.go; internal/v2/grants/manifest/values.go; internal/v2/secrets -->

The owner imports secrets through the encrypted secret staging interface.
It uses an ephemeral public key and ciphertext, then an exact confirmed import
or rotation. Never send plaintext secrets through general blobs, mail, briefs,
command arguments or source archives. The native backend keeps encrypted records
and key material separately. Only selected values reach the final runtime.
Audit records contain names, versions, grant IDs and outcomes, not values.
A lane can read a secret deliberately granted to its tools.
<!-- source: internal/v2/cli/commands_secrets.go; internal/v2/secrets/wire; internal/v2/secrets/native; internal/v2/api/ports.go -->

Some capability and delivery integrations remain incomplete. In particular,
the current root-grant path refuses root secrets, network and resource handles
without their protected resolver. A schema accepting a secret declaration does
not prove end-to-end secret delivery. Keep the original owning error.
<!-- source: internal/v2/grants/root.go; internal/v2/assembly/assembly.go -->

## Understand the watchdog's account switching

The service watchdog handles authenticated Claudock quota limits. It does not
trust a line of agent text saying that an account is exhausted. It requires
outside capture, a real run exit with zero survivors, and fresh usage evidence
from an enrolled producer. It checks remaining budget, current grants, profile
expiry, exclusions and model/session compatibility before selecting another
already-delegated profile.

Continuation retains the life, logical turn, task, session history, workspace,
counters and remaining budget. It creates a later run. It must not deliver the
same prompt or mail again. Automatic switching from a free profile to a paid
profile is ineligible. If no permitted profile is available, the watchdog
records `watchdog.waiting` and retains bounded backoff. Manual control and
revocation cancel stale continuation work.
<!-- source: internal/v2/watchdog/service.go; internal/v2/watchdog/usage.go; internal/v2/watchdog/signals.go; internal/v2/lifecycle/continuation.go -->

Inspect `watchdog.limit`, `watchdog.waiting`, `watchdog.swapped` and
`watchdog.cancelled` alongside the same life's runs. A wait operation is not a
launched replacement. The snapshot's outside usage producer and installation
wiring still have explicit unavailable paths. Do not assume switching works
because another profile is listed. There is no operator watchdog-switch command.
<!-- source: internal/v2/watchdog/usage.go; internal/v2/assembly/assembly.go; internal/v2/cli/dispatch.go -->

## Review before acceptance

An executor cannot review or accept its own life. Have an authorized independent
human or supervisor inspect the exact output snapshot, diff, required checks,
raw-record inventory, gaps and refusal resolutions. Commit real check receipts;
a file that merely says a test passed does not establish service provenance.

Prepare a ReviewRequest with `target`, `diff`, a nonempty `checks` array,
`record_inventory` and `refusal_resolution`. As a human, confirm the exact
`lane.review` request, then run:

```sh
laneboss lane review --config NAME --request REVIEW_REQUEST \
  --proof REVIEW_PROOF --idempotency-key REVIEW_KEY
```
<!-- source: internal/v2/cli/commands_lifecycle.go; internal/v2/cli/cli.go; internal/v2/lifecycle/review.go -->

Keep the returned ReviewReceipt. Acceptance needs its stored, current evidence
with complete coverage and successful required checks. Submit that receipt in
the mark request. Only `verifying` can become `accepted`, and only `accepted`
can become `merged`. `abandoned` records a separate disposition without claiming
successful review. The [tutorial](tutorial.md#9-archive-then-clean) covers archive
and clean. Both require real quiescence. Clean is complete only after the
collector's committed result, not its initial pending Operation.
<!-- source: internal/v2/lifecycle/review.go; internal/v2/api/review_validation.go; internal/v2/lifecycle/collect.go -->

# Policy and owner approval

Policy tells agents how to work. The service and Linux isolation enforce their
actual authority. A policy allow does not grant a file, account or network right.
This page describes revision `d7403ec`.

Not yet verified on an installed service.

The brief's installed E2E does not verify live judged policy, per-turn guidance
or an L6-to-owner change cycle. Use the checks below when their installed
dependencies are available. Preserve an unavailable result.

## Inspect the effective blocklist

The effective rules combine the org baseline, the lane's own level-and-role
layer, and every higher level's role layers. Each rule must also apply to the
selected role and level. A missing local layer leaves the org rules in force.
A child cannot lower the thresholds of an inherited rule. Thresholds and
calibration remain attached to the source that defined the rule.
<!-- source: internal/v2/policy/resolve.go -->

As a human, read the policy of a real lane with a fresh session proof:

```sh
laneboss policy get --config NAME --life-id LIFE_ID --format json \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_policy.go; internal/v2/cli/cli.go -->

Inspect `generation`, `sha256`, `context`, `sources`, `rules`, `skip` and `judge`.
Each rule carries its text, `instead`, band, scope, source and thresholds.
Ask L6 to propose a change to the defining source if the policy is wrong.
Do not edit generated rule or hook files.

Membership is judged against explicit rules. There is no extra deterministic
pattern veto after a semantic allow. An unknown ordinary command is not refused
merely because it is absent from a list. Refuse-band matches can block.
Warn-band matches warn. The decision records rule IDs, source hashes and the
stated recovery route.
<!-- source: internal/v2/policy/evaluate.go; internal/v2/policy/resolve.go; internal/v2/api/policy.go -->

To preview a command, save a PolicyEvaluateRequest with the current `target`,
`logical_turn_id` and `command`. CommandData contains `tool`, exact base64
`command` bytes, `argv`, `declared_paths`, absolute `cwd` and `raw_sha256`.
Use explicit arrays and hash the actual command bytes. Preview does not execute
the command. Obtain a fresh human session proof, then submit:

```sh
laneboss policy evaluate --config NAME --request POLICY_REQUEST \
  --proof SESSION_PROOF --idempotency-key POLICY_KEY
```
<!-- source: internal/v2/cli/commands_policy.go; internal/v2/cli/cli.go; internal/v2/api/policy.go -->

Inspect `result`, `policy_generation`, `audit_complete` and `rules`.
Each rule result has `rule_id`, `result`, optional `probability`, `reason`
and `instead`.
The preview prints its decision without enforcing the installed hook's exit.
The installed `org hook` adapter is decision-aware: a deny exits nonzero.
Its raw `--request` form is explicitly unsupported. Use its existing
`--command-file` adapter with actual life, run, turn, tool and cwd metadata.
Give every new command invocation a fresh retained key. Exact receipt replay
can return its original policy generation; a new invocation must evaluate
the current approved policy.
<!-- source: internal/v2/cli/commands_policy.go; internal/v2/cli/cli.go; internal/v2/policy/hook.go; internal/v2/policy/rpc.go -->

## Understand the judge interface

The shared judge interface first checks whether the complete formatted request
fits, then evaluates it. It treats rule text, command bytes, task and candidate
decisions as named input data. The service supplies the trusted instructions
and authentic role, grants and policy context. A lane cannot select a different
provider by putting one in the request.

The default provider is `clef-sglang`, using the full model name
`Cloudflare/clef-flash`. It is self-hosted. The administrator must enroll its
real endpoint, deployment hash, tokenizer hash and positive context limit.
TypeSafe, provider `typesafe`, is optional. It requires an explicit approved
full model name and matching enrolled endpoint and credential handle.
Clef unavailability never selects TypeSafe automatically.
<!-- source: internal/v2/api/policy.go; internal/v2/assembly/judges.go; internal/v2/judge/clef/stub.go; internal/v2/judge/typesafe/stub.go -->

Read the current judge configuration projection:

```sh
laneboss judge list --config NAME --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_judge.go; internal/v2/cli/cli.go -->

The result is a ConfigView with `generation`, `sources`, `projection` and
`warnings`. It is not a fabricated list of working remote models.
Compare the projection and source pins with the approved policy and installation.
Changing provider, model or deployment is an org-resource change.

The complete serialized judge request is bounded to 262,144 bytes and at most
12 questions per batch. Fit must use the pinned tokenizer and actual context
window. Scores must be finite probabilities from 0 to 1, with a complete answer
for every question. Overflow, partial replies, timeout or unavailable inference
are explicit unscored results. Missing probabilities must not be displayed as 0.
<!-- source: internal/v2/api/base.go; internal/v2/judge/wire/request.go; internal/v2/judge/wire/response.go; internal/v2/judge/stub.go -->

Only an applicable org-marked critical refuse-band rule fails closed when its
judgment is unscored. Other inference outages produce a notice; warn rules do
not block. Invalid authority, missing audit, unavailable storage and a missing
approved inference budget can still refuse the operation. They are not ordinary
inference outages. Preserve their typed errors and recovery routes.
<!-- source: internal/v2/policy/evaluate.go; internal/v2/policy/service.go; internal/v2/policy/rpc.go -->

Cache and approved skip entries are optimizations with source and context pins.
A skip cannot override a deny or an unresolved critical refusal. A cache or
skip miss invokes normal evaluation. It does not create a command allowlist.
Calibrate thresholds on the actual deployed stack before live enforcement.
<!-- source: internal/v2/policy/skip.go; internal/v2/policy/evaluate.go; internal/v2/policy/resolve.go -->

## Read per-turn guidance

The lifecycle selects guidance for each logical prompt-delivery turn: initial
task, resume, mail turn or loop turn. A profile continuation keeps that logical
turn and reuses its selection. Historical reminders are advisory. They cannot
grant access or refuse a command.

The judge scores relevance. Ranking multiplies relevance by a recency weight
with a default half-life of 14 days. The default relevance cutoff is 0.50.
At most five historical reminders are offered. Binding decisions and current
policy remain separate, regardless of age. Unavailable guidance keeps a visible
notice and has no weighted score. An empty candidate set is a different result.
<!-- source: internal/v2/guidance/rank.go; internal/v2/guidance/evaluate.go; internal/v2/lifecycle/turn.go -->

To inspect the selection for an authentic current turn, save a GuidanceRequest
with `target`, `logical_turn_id` and its exact committed `task` BlobRef.
From that lane's current service binding, use:

```sh
laneboss guidance select --config NAME --request GUIDANCE_REQUEST \
  --idempotency-key GUIDANCE_KEY
```
<!-- source: internal/v2/cli/commands_guidance.go; internal/v2/cli/cli.go; internal/v2/api/policy.go -->

Read `status`, `notice`, `items`, `policy_generation`, candidate snapshot and
judgment IDs. Preserve the returned selection. Do not start a second independent
selection for a quota continuation or relabel old task history as current.

## Change org resources through L6 and the owner

All canonical org resources use the exact-change approval route, called D6.
That includes policy, prompts, driver settings, scripts, tools, notes, plugins,
channels, judge settings and generated effects. L6 proposes and applies.
The owner reviews and approves. Lower levels report inert proposals upward.
They do not write the canonical org tree.
<!-- source: internal/v2/approval/context.go; internal/v2/approval/service.go; internal/v2/identity/claims.go -->

1. From an authentic current L6 lane, commit proposed source bytes and a reason.
   Prepare a ChangeProposeRequest with `org_id`, current `base_generation`,
   `files` and `reason`. Each file delta has an org-relative `path`, `action`
   (`add`, `replace` or `delete`) and `mode`. Replace/delete include
   `before_sha256`. Add/replace include a committed `after` BlobRef.
2. Submit the proposal as that L6 lane:

```sh
laneboss org change propose --config NAME --request PROPOSE_REQUEST \
  --idempotency-key PROPOSE_KEY
```
<!-- source: internal/v2/cli/commands_approval.go; internal/v2/cli/cli.go; internal/v2/api/approval.go -->

3. Retain the ChangeRequest and its `id`, `manifest_sha256`, `diff`, `files`,
   `derived`, renderer pin and base generation. The service stages the complete
   generated effects. The owner reads that exact diff. To fetch it, prepare
   a ChangeGetRequest with `change_id` and use a fresh human session proof:

```sh
laneboss org change get --config NAME --request CHANGE_REQUEST \
  --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_approval.go; internal/v2/cli/cli.go; internal/v2/api/approval.go -->

4. The owner prepares a ChangeApproveRequest with that `change_id`,
   `manifest_sha256` and `base_generation`. Obtain fresh security key proof
   for that exact approval. A general browsing session does not approve it:

```sh
laneboss org change approve --config NAME --request APPROVE_REQUEST \
  --proof APPROVE_PROOF --idempotency-key APPROVE_KEY
```
<!-- source: internal/v2/cli/commands_approval.go; internal/v2/cli/cli.go; internal/v2/api/approval.go -->

5. Retain the ChangeApproval. Before it expires, the same authorized L6 prepares
   a ChangeApplyRequest with `change_id`, `approval_id` and
   `expected_generation`. Apply as that L6 lane:

```sh
laneboss org change apply --config NAME --request APPLY_REQUEST \
  --idempotency-key APPLY_KEY
```
<!-- source: internal/v2/cli/commands_approval.go; internal/v2/cli/cli.go; internal/v2/api/approval.go -->

Require a ChangeReceipt that matches the approved manifest, change and approval,
and advances the org generation. Inspect `org.change.applied`. Approval covers
only the exact staged bytes and derived effects. Changed bytes, a changed base,
expired approval or changed requester require a new reviewed proposal.
Keep source edits and generated effects in the same publication. Never repair
generated files by hand to make validation pass.
<!-- source: internal/v2/approval/service.go; internal/v2/approval/transaction.go; internal/v2/approval/results.go -->

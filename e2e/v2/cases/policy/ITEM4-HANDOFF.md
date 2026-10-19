# Item 4 integration handoff

This round changes the item-4 components and their private store ports. Its
Linux component and native canaries are not installed policy/judge/guidance
acceptance or an authenticated AI-service test.

The item-1 hooks are limited to passing administrator-supplied optional
`policy_max_cost_micros` and `judge_worker` enrollment through
`scripts/v2-admin/boot.py`, and supplying that ceiling, measured-price callback
and protected worker enrollment at `assembly.build`. No capture, agent launch,
materialization or initial-publication implementation is changed.
The launch-guidance reservation also limits its inference claim to that
protected ceiling; it does not rewrite the retained launch budget.

The ceiling has no positive default. The policy service uses the smaller of
that ceiling and remaining lane spend; the judge store separately reserves
positive cost under the admitted operation. Unknown usage keeps its entire
reservation. The installation's tokenizer executable and price file are
root-owned protected inputs with exact byte pins. The tokenizer must consume
the complete System One request and emit `api.TokenFit` JSON; a character/byte
estimate is not a production serving-tokenizer proof. The native test uses an
explicit synthetic tokenizer only to measure protected process transport.
Credential files additionally require one link, no world access and only the
dedicated service group's optional read access; the root canary uses synthetic
bytes to reject a world-readable file and accept the protected control.

The native worker owner must bind `installedJudge.worker` to an authenticated
fixed worker implementing `api.JudgeWorker.EvaluateLeased`. The worker receives
the original `api.JudgeExecution` and must validate its current store claim,
native peer, sealed job input and controlled egress before sending. The
installed adapter refuses when this port is absent. `judge.RunInternal` still
refuses its missing native job lease; no in-process provider call substitutes
for this boundary. `ReserveJudgeExecution`, `ValidateJudgeExecution` and
`CompleteJudgeExecution` retain exact pins, live claim and measured audit.
Expired/interrupted sends cannot acquire a second claim. Completing recovery
and native worker enrollment remains required before calling 4C installed-ready.
The reservation-bound `api.LaunchGuidanceJudge` entry also remains unimplemented;
initial/resume/mail launch paths keep their truthful unavailable result until
that original planning claim can reach the same native judge worker.

Guidance joins every retained batch to its original operation/turn/task,
candidate snapshot, deadline and shared cost. It independently recomputes
ranking from measured probabilities and the historical approved policy.
Public briefing input resolves the authenticated life before considering
request claims; preparing launches retain their separate private reader.
Public brief.start/brief.render and configuration read outputs retain real
internal read causality. Output read-back uses a fresh authenticated view after
the stable input snapshot, and prompt tests use the repository's actual assets.
Policy audit-input retention joins the original admitted operation, actual
requester, target/turn and visible task before binding its component writer.
The canonical role-union reader now reconstructs approved source documents
through policy.Resolve. The same reader supplies show/settings/roles/plugins/
channels with real defining sources and declared resource pins. The source
format and enrollment limits are documented in the policy package's
CANONICAL.md. Public briefing resolves its authentic role and grant claims
before policy selection. Legacy flattened input cannot prove a different
role's union or complete configuration and keeps a typed prerequisite.
Atomic D6 source/policy publication and installed acceptance remain required.
The protected policy-refresh writer and judge.list also use the canonical
role resolver. Their retained digest and source inventory must describe the
actual life. Losing a previously enrolled canonical baseline refuses even
on the already-current writer path; it cannot fall back to a flattened view.

`judge.list` uses a protected `api.JudgeView` blob. It identifies the approved
policy digest, generation, context, judge pins and complete consumed source
inventory, without assigning arbitrary defining sources to individual fields.
The store derives its retention operation from the actual authenticated read
frame and checks the committed bytes. It contains no endpoint or credentials.

The Python descendants use the single lane_descriptors helper and preserve
only the validated fixed binding and O_PATH
socket descriptors. The native omission control proves Python otherwise drops
them. An actual installed `identity.self` child canary remains an acceptance
observation, not something the descriptor-only test claims.
HandoffRefusal retains a screened prerequisite projection with completed=false.
The four case callers preserve it in their failure evidence or private worker
queue. A failed handoff starts no child CLI and supplies no success receipt.

The integration fixture must supply `test_root/inference-budget.json` with
schema `laneboss.e2e-judge-budget.v1`, config, current policy_generation,
deployment_sha256, tokenizer_sha256 and a positive max_cost_micros no greater
than actual remaining spend. This file is only a checked fixture claim; the
installed service independently enforces protected approval. No cap is invented.

Owner-in-person waits remain real: each of the six D6 stages needs a fresh
confirmation at its actual base; canonical decision seeding needs its real
operation proof. Protected installation and provider/tokenizer/price/capacity
enrollment need the authorized administrator/owner. There is no service login,
paid request, owner send, browser gesture or root installation credited here.
Policy retains `owner-wait.json` when its fresh D6 input is absent; guidance
retains typed prerequisite_missing for an absent operation confirmation.
Five authentic role workers, private queues, current approvals, canonical
decision seeds, task/clock controls and real turn deliveries still need their
installed producers from the lifecycle, approval and watchdog owners.

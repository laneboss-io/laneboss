# Remaining paths without a fresh judgment

The review asks whether lane-controlled non-UTF-8 or over-provider-cap command
input should be treated differently from an inference outage. The current
frozen contract explicitly makes unknown fit/overflow/partial/timeout/cost-cap
outcomes unscored and closes only applicable critical refuse entries; warn
never blocks. This lane preserves that behavior and actual input bytes.

The owner must choose any stronger policy through the normal contract/D6 path:
mark the seeded cloud/PR/plugin denies critical in the approved baseline, or
amend the contract so deliberately unjudgeable input refuses with an Instead
route to resubmit judgeable data. No baseline rule is changed, no implicit
command allowlist is added, and no owner message is sent by this executor.

The warning-threshold scalar is a separate shared contract request in
CONTRACT-GAPS.md. Neither policy choice is inferred from fixture expectations.

The remaining design-accepted paths are explicit:

- Non-UTF-8 command bytes and failed/unproved fit, including a command above the
  approved provider byte/token cap, produce unscored results. Lane-controlled
  input can reach these paths; only applicable critical refuse entries close.
- A deadline expiring before fit produces unscored results under the frozen
  inference-outage rule. Cancellation, real provider outages, partial/invalid
  replies and genuine scoped-judge cost-cap errors also retain absent scores.
  Some have already called fit or inference; none is a scored membership proof.
- Later batches do not start after the current command's approved reservation
  is consumed or its usage becomes unknown. Their unresolved rules are unscored
  under that same contract, and applicable critical refuse entries close.
- An empty deny union needs no judge. A still-current, fully scored and audited
  cached decision needs no new call. An approved exact-work skip with nonempty
  rules requires a positive proof for the full current caller context first;
  an empty-rule skip needs no proof. An exact durable request replay returns
  its committed reply rather than judging the same operation twice.

A lane starting a fresh judgment with rules and zero remaining spend is now a
typed budget_exhausted refusal with an Instead route to obtain an approved
budget. The previous zero-spend unscored allow assumption is withdrawn for this
round. No free fallback judge, implicit paid provider, baseline critical flag
or deterministic command gate is introduced. Invalid/not-found judge errors
preserve their exact typed failures in fit and evaluate, rather than entering
the outage paths. Fix 11 resolves generation selection and refuses raw hook
files; their protected-port/native acceptance limits remain in CONTRACT-GAPS.md.
Q1 about lane-controlled unjudgeable input remains open and unchanged.

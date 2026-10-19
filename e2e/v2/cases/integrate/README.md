# Integration acceptance

Run this case only on the authorized Ubuntu 24.04 test machine, through the
shared harness, with the installed artifact and a separately bound authenticated
lane endpoint. The entry accepts only `--context FILE --result FILE` as specified
in the frozen harness contract. It never starts a service, machine or real model
request. Input files, command exits and exact output bytes remain under the
context's evidence directory.

`INTEGRATE-RECORDS` writes an independently random observation through the CLI,
retrieves it by its returned ID and by keyword, reads the committed blob back,
and compares every byte and digest, including a same-key append replay. It also
checks the service-resolved judge default and a scored, audited public
`judge.ask` reply select the pinned Clef-flash deployment. The harness must enroll
an independently instrumented, credential-free provider fixture and one approved
scoped rule for this cell; the request has a zero cost ceiling. No live model or
paid provider is authorized by this workload. Unknown fields, attempted authoritative ledger
writes, and decision promotion without D6 must fail with typed errors. A missing
dependency, unavailable store or stub fails the candidate; an empty successful
query cannot pass the random round trip.

The common file form also requires each method owner's registered semantic
validator. This lane registers all eleven integrate-owned methods. The case
remains red until the service health/blob, identity, policy, lifecycle, grants
and judge owners register their file validators on the exact combined source,
along with the real service dependencies. The explicit unavailable common file
forms are inventoried per method in cli/dispatch.go; registration removes an
entry, and the catalog audit rejects an undeclared gap at any owner. A refusal
at the initial health-stage input-validator prerequisite never reached the
service and must not be reported as a service fault or an authenticated append
result. The case stays reached: false until its actual append succeeds.

Before candidate acceptance, run this same case against distinct mutated
artifacts with `phase: red` and one of these mutation IDs:

| Mutation | Intended reached failure |
| --- | --- |
| `drop-record-write` | A returned append receipt has no retrievable random record. |
| `constant-record-read` | Retrieved ID/content does not match the independently generated input. |
| `trust-record-collection` | A lane can append a fresh authoritative ledger outcome. |
| `promote-lane-decision` | An ordinary lane can commit an authoritative decision. |
| `jev-default` | Effective policy or the actual judge.ask path selects TypeSafe instead of Clef. |

A setup error never kills a mutation. The entry records `reached: false` until
an authenticated observation append succeeds. A red run must fail the targeted
operation, not merely return nonzero. The independent harness must check the
retained operation transcript and the mutation's distinct artifact hash.

This first vertical slice is not the INTEGRATED-RELEASE gate. The parity ledger
in `docs/design/v2-lanes.md` lists the remaining cases: CLI/socket/dashboard
parity, confined vector/import/export/cloud workers, report/owner-sheet/gateway,
lost reply and restart, denied direct state, cross-config overlap, D6, profile
continuation, hook deletion and two concurrent real ladders. Those cells and
both independent reviews must be supplied on identical final artifacts. This
case's success cannot stand in for any of them.

The publication scanner's separate source-only regression workload is
`python3 scripts/scan_self_test.py --evidence /test/evidence/integrate/scan`.
Run it on the disposable Linux box. It retains each temporary input tree and
actual stdout/stderr/exit; positive imports and negative literals/lookalikes/
other-rule cases must all satisfy their assertions. It is not run by this case's
record assertion and is not claimed executed on the authoring Mac.

Draft.3 freezes the harness-only controller maps in `control.schema.json`.
Its root accepts exactly a binding, request or response map. This is a protocol
source for the E2E owner, not a controller implementation or product endpoint.
Only registered restart/canary/fixture-clock operations are supported. Unknown
containment is a typed failure with evidence; only a known exit can be a canary
result. A controller result alone cannot substitute for independent OS evidence.

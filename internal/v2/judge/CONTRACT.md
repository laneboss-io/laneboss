# Credential-screen ownership boundary

| JSON path | Join treatment | Authorship and enforcement |
| --- | --- | --- |
| `$.state.commands[*].command` | Caller join. | Exact lane-authored command bytes. |
| `$.state.commands[*].cwd`, `$.state.context.cwd` | Caller join. | Workspace CWD can contain lane-selected text even when read from StateStore. |
| `$.state.commands[*].argv[*]`, `$.state.commands[*].declared_paths[*]`, `$.state.commands[*].tool` | Caller join. | Caller-supplied command fields. |
| `$.state.task` and every string/key in its decoded documents | Caller join. | Task storage/readback establishes identity, not service authorship of the content. |
| `$.state.decisions[*].text` and all unknown fields/keys anywhere | Caller join. | Decision text stays in the task's joined data scope. Conservative default includes metadata-like names and unexpected containers at scalar metadata paths or inside metadata lists. |
| `$.model` | Exclude scalar value from joins. | Selected approved config, resolved by ResolveJudgeForScope and compared by the adapter; no caller model substitution. |
| `$.questions.*` map keys | Exclude keys from joins. | Payload emits approved rule/decision IDs. resolveQuestions compares full entries with policy/decision snapshots; preview replaces the rule list from policy. |
| `$.questions.*.type` | Exclude scalar value from joins. | Payload's fixed noul literal. |
| `$.questions.*.instructions` | Exclude scalar value from joins. | Payload's fixed instruction template with array indexes only; no caller text interpolation. |
| `$.questions.*.criteria.true`, `$.questions.*.criteria.false` | Exclude scalar values from joins. | Payload's fixed true/false criterion strings. |
| `$.state.rules[*].id` | Exclude scalar value from joins. | Exact approved policy rule ID, replaced for preview or matched for blacklist. |
| `$.state.rules[*].text` | Exclude scalar value from joins. | Exact approved policy text; caller-edited text fails resolveQuestions. |
| `$.state.rules[*].source_sha256` | Exclude scalar value from joins. | Approved policy SourceRef digest, matched with the complete rule. |
| `$.state.rules[*].criteria_version` | Exclude scalar value from joins. | Service-selected CriteriaVersion, checked with the complete approved rule. |
| `$.state.decisions[*].id`, `$.state.decisions[*].source.id` | Exclude scalar values from joins. | Store-generated decision/source identities; DecisionDocument has no caller ID. resolveQuestions requires the complete candidate to equal the authoritative DecisionCandidates snapshot. |
| `$.state.decisions[*].source.path` | Exclude scalar value from joins. | Org-authored source path resolved against the authoritative store snapshot, never an arbitrary request override. Full-candidate equality includes this path. |
| `$.state.decisions[*].source.sha256`, `$.state.decisions[*].source.generation` | Exclude metadata leaves. | Store-projected source digest and numeric generation, checked with the complete candidate at one policy/snapshot generation. |
| `$.state.decisions[*].authority.receipt_id` | Exclude scalar value from joins. | Store-generated authority receipt identity, validated and exact-matched with the authoritative candidate. |
| `$.state.decisions[*].authority.kind`, `$.state.decisions[*].authority.org_generation`, `$.state.decisions[*].authority.source_seq` | Exclude metadata leaves. | Store-projected authority kind and numeric org generation/source sequence; resolveQuestions validates authority and exact-matches the complete snapshot entry. |
| `$.state.decisions[*].effective_at` | Exclude scalar value from joins. | Org-approved UTC timestamp in the authoritative decision document; complete-candidate equality prevents request substitution. |
| `$.state.decisions[*].applies_to.roles[*]`, `$.state.decisions[*].applies_to.project_ids[*]`, `$.state.decisions[*].applies_to.life_ids[*]` | Exclude direct string members from joins. | Org-authored applicability resolved by the store for the target and matched with the complete candidate. No exemption for nested containers, unknown applicability fields or caller documents. |
| `$.state.decisions[*].applies_to.levels[*]`, `$.state.decisions[*].binding` | No text value exclusion. | Numeric levels and boolean binding come from the same authoritative candidate. Unexpected text remains caller-joined. |
| `$.state.commands[*].raw_sha256` | Exclude scalar value from joins. | Payload recomputes Digest(Command) and rejects a mismatch; caller cannot supply arbitrary digest bytes. |
| `$.state.context.config` | Exclude scalar value from joins. | Authenticated connection/scope configuration binding; supplied override is rejected. |
| `$.state.context.grant_set_id` | Exclude scalar value from joins. | Service-issued grant set for the live lane; resolveRequest checks current grants and expiry. |
| `$.state.context.grants_sha256` | Exclude scalar value from joins. | Current grant-set digest supplied by StateStore and verified against the live scope. |
| `$.state.context.logical_turn_id` | Exclude scalar value from joins. | Service lifecycle's durable turn identity, matched by lane and turn snapshots; a request claim cannot replace it. |
| `$.state.context.policy_generation` | Exclude metadata leaf. | Current policy generation; numeric in the typed API and matched to scope/lane/grants. |
| `$.state.context.target.life_id`, `$.state.context.target.run` | Exclude metadata leaves. | Current service lane life/run, checked against actor, connection binding and StateStore. Run is numeric. |
| `$.state.context.role.role`, `$.state.context.role.level`, `$.state.context.role.instance_id` | Exclude metadata leaves. | Approved role/instance snapshot and current lane role/level; resolveRequest requires agreement. Level is numeric. |

Every excluded key/value is still inspected completely for a credential or exact
supplied-key echo. An excluded scalar containing JSON receives its own complete
embedded-document screen. Exclusion never suppresses complete-field screening.
Only string leaves use metadata exclusion; an unexpected map/array at a scalar
path or inside an approved metadata list defaults to caller data. Only direct
string members of the three listed applicability arrays receive the exclusion.
There is no blanket exclusion by key spelling.

The following **known schema keys only** are also excluded from joins. Their
values follow the table above, so command/CWD/task bytes remain joined:

| Parent JSON path | Exact service-emitted key names |
| --- | --- |
| `$` | `model`, `questions`, `state` |
| `$.state` | `commands`, `rules`, `context`, `task`, `decisions` |
| `$.state.commands[*]` | `command`, `cwd`, `argv`, `declared_paths`, `tool`, `raw_sha256` |
| `$.state.context` | `config`, `cwd`, `grant_set_id`, `grants_sha256`, `logical_turn_id`, `policy_generation`, `target`, `role` |
| `$.state.context.target` | `life_id`, `run` |
| `$.state.context.role` | `level`, `role`, `instance_id` |
| `$.state.rules[*]` | `id`, `text`, `source_sha256`, `criteria_version` |
| `$.state.decisions[*]` | `id`, `text`, `source`, `authority`, `effective_at`, `applies_to`, `binding` |
| `$.state.decisions[*].source` | `id`, `path`, `sha256`, `generation` |
| `$.state.decisions[*].authority` | `kind`, `receipt_id`, `org_generation`, `source_seq` |
| `$.state.decisions[*].applies_to` | `levels`, `roles`, `project_ids`, `life_ids` |
| `$.questions.*` | `instructions`, `type`, `criteria` |
| `$.questions.*.criteria` | `true`, `false` |

screen_fields.go enforces this complete table by location. Unknown fields/keys,
including id/model/rules/raw_sha256 names inside caller documents, retain joins.
The table applies to protected worker Payload output after scoped resolution,
not arbitrary RPC claims. Raw adapters cannot authenticate snapshots themselves;
the worker must supply the resolved request and the dispatch gate remains closed
until that protected integration exists. Audit readback is compared with Payload
of the independently resolved request. Changing a producer's authorship requires
revisiting the exclusions, rather than trusting a caller-supplied marker.

Each valid Payload has zero or one command. Its caller bytes, shared context CWD,
task and unknown state form one scope for that command (one task scope for
guidance). Two fixed views use the same six key/value/combined streams, spaced
and unspaced: canonical byte-sorted document order with raw plus decoded text,
then command execution order cwd/command/argv/declared_paths/tool with embedded
JSON transparent to adjacency. Each pass permits at most 65,536 visited
value/key nodes, including all embedded scopes: at most 131,072 visits overall.
Only the node counter and view buffers reset between passes. The same 8 MiB
byte/work allowance and exhaustion state cover both passes; depth remains at
32, input/views at 1 MiB and supplied keys at 8,192 bytes. Exhaustion always
withholds. No field pairs or arbitrary permutations are constructed.
Nonconforming multiple-command bodies use the conservative full generic screen
without exclusions. Every original generic split canary remains in that screen.

The only reference-only omission remains structured-join, now narrowed: the
independent frozen caller projection must have no hit in either order and all
complete fields must be clean. A whole-reference hit then necessarily depends
on bytes from an excluded service field/key. The evidence records the caller
verdict and exact excluded paths; any caller-only hit must withhold regardless
of the full-frame reference verdict. A new named extra, caller-join, permits
additional detection only when that independent projection proves a genuine
caller signature (including decoded adjacency/execution order). It grants no
additional omission. The frozen reference itself is unchanged.

TestCallerServiceBoundary completes the short caller CWD /work/task-3 with the
computed command digest into an sk- shape. It is allowed if individual fields
and caller-only views are clean: the digest is service-computed and cannot carry
arbitrary caller secret bytes. TestBenignStructuredRequestsScore requires the
same case to score through actual HTTP. A complete credential in even an excluded model or
rule field is still withheld. A split made entirely of caller bytes, including
CWD plus command or caller text plus embedded JSON, is always withheld.

# Consumer requirements for single-string look-alikes

The frozen sk-/pa- signature rules still withhold matching complete strings,
including an approved rule ID such as risk-assessment-phase-2-review-1 or a CWD
such as /work/risk-assessment-2026-q4. Metadata exclusions remove only manufactured
cross-field matches. They do not relax secretText or make such strings usable.

The policy owner, **lb-v2-policy**, must apply secretText to every proposed rule
ID and rule text at **D6 approval**. A hit must reject approval with a clear
configuration error naming the affected rule/field and the credential-shape
conflict, without echoing secret-bearing content. It must not defer this error
to an unavailable judge observation. This is a policy consumer requirement;
implementation and its approval-path tests remain with that owner.

The lifecycle owner, **lb-v2-lifecycle**, must keep logical CWDs synthesized from
service-controlled workspace identities, rather than deriving them from human
task names. Command/context CWDs still share caller joins and complete-string
screening. This requirement belongs to lifecycle's workspace producer; it does
not authorize excluding CWD text or weakening sk-/pa- screening here.

# Remaining draft.4 integration gaps

This lane changes no shared API or composition file. This note reconciles its
earlier requests with draft.4 sections 14–15 and names the exact remaining ports.
No private RPC, event kind, StateWrites field or configuration key is invented.
CONTRACT-GAPS.md adds the counted review's precise prepare-stage audit and
multi-batch preview requirements. Prepare-stage withholding remains explicit
unavailable/unscored; preview currently supports one complete batch only.

The contract supplies ScopedJudge, authenticated connection/frame handles, turn/task
and decision snapshots, ObjectMetadata/RetainObject, InternalJudgeEvaluate,
JudgeAudit reads/writes, normalized Request/BatchIDs, and client.PrepareRequest.
The port consumes these where their authority is complete: scoped preflight/fit,
task metadata/byte validation, current rule/decision checks, exact request refs,
cache copies and common request preparation. These are no longer contract gaps.
Draft.4's Clef/TypeSafe selection and resolved approved-pin comparison are
implemented, including equivalent default spellings and no fallback. Connection
checks consume ID/Conn/Peer and the pinned lifetime. The feature CLI uses the
common invocation for borrowed/shared sockets, read sessions and mutation keys.
CommitAudit consumes JudgeAudits under the internal write matrix and validates
retained bytes, fit, raw probabilities, cancellation, CAS and stored readback.
It is a completion consumer, not a reservation or dispatch service.

1. **Authenticated judge dispatch and durable egress accounting.** ScopedJudge
   provides the requested scope argument, but no typed judge dispatch,
   reservation, recovery or job-consumption operation exists. StateWrites now
   has JudgeAudits for completion, which this port consumes. It has no typed
   reservation/claim or known/unknown cost capacity. Effect has
   no judge payload and WorkerPlan's fixed kind catalog has no judge job. A
   WorkerLease read is not its atomic claim/consumption or authorization to send.
   InternalJudgeEvaluate identifies a trusted emitter, not a lease or reserve.
   Generic ReserveRequest explicitly authorizes no effect (§14). The
   judge.completed payload is a JudgeReply, not a complete reservation,
   tokenizer proof and recoverable unknown outcome. Add one reviewed internal
   operation/typed intent that atomically retains exact inputs, reserves outcome
   bytes and cost, dispatches a peer-bound fixed worker once, and finalizes or
   recovers its measured result after cancellation/crash. Specify the compatible
   audit projection and sent/outcome records or version them together. Consumers:
   service/store, identity, helper/worker framework, secrets, judge, policy,
   guidance, records and E2E. Until supplied, JudgeAsk/EvaluateForScope stop at
   judge.worker.egress-lease and RunInternal at internal.judge.job-lease.
   CommitAudit currently completes a live authenticated in-process observation;
   recovery after caller disconnection/cancellation still needs that persisted
   worker claim. Its isolated completion fixture is not recovery evidence.

2. **A readable judge configuration projection.** RetainObject now publishes
   trusted immutable outputs. The remaining issue is how judge.list obtains
   its authorized parent intent/input refs and per-setting defining sources.
   It is a read RPC, has no reserved operation, and StateStore exposes no
   existing ConfigView/settings projection. ConfigProjection's closed view
   catalog has no judge-specific view. Supply either an authorized settings
   projection with judge-setting provenance through a typed dependency/store
   read, or specify the trusted read-projection retention context and source
   mapping. Do not assign every setting to an arbitrary first SourceRef or
   invent an operation ID. Consumers: policy, service/store, judge, composition.
   JudgeList retains judge.config-projection until this is defined.

3. **Provider request ID and unknown usage/cost.** The exact input reference
   request is closed and implemented. A dedicated normalized provider request
   ID and explicit known/unknown input/output usage and cost are still missing.
   Nonoptional zero integers cannot express an uncertain timeout bill. The
   screened raw object preserves the provider ID, but does not repair normalized
   accounting or permit releasing an unknown reservation. Consumers: judge,
   service/store, policy/guidance, records, CLI/dashboard and evaluator.

4. **Choice distributions.** Rules/Decisions already support complete Noul
   batches; no replacement request is needed. There is still no trusted typed
   Choice question/answer union with option IDs, full distributions and
   provider-specific confidence. The twenty Choice corpus rows receive only
   structural checks; no missing probability is substituted. Consumers: judge,
   guidance, policy's Noul-only consumer, evaluator and CLI/dashboard.

5. **Composed `laneboss serve`.** On the merged checkpoint, store.New,
   service.New and client.Open still return their owning lane's typed
   not_implemented. Assembly's installedJudge constructs providers with config,
   endpoint and an optional credential handle, but supplies no material, Fit,
   SafetyTokens, Retain, Cost or ReserveMicros. A raw adapter cannot infer those
   protected capabilities from pins or claim a token proof. Assembly/service,
   secrets and worker owners must wire the real capabilities, dispatch claim
   and this completion consumer. The E2E case deliberately fails at absent
   dependencies and continues to require the public CLI and real HTTP fixture.
   No isolated adapter/audit fixture is evidence that this composition runs.

The common client-construction request is closed: feature adapters use the
shared PrepareRequest and preserve exact Params. Its transport/authentication
implementation remains the service lane's work, not another schema request.
R108 is consumed through ResolveJudgeConfig; there is no Jev comparison,
shadow-promotion gate or outage-driven provider switch.

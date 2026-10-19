# GUIDE-TURN acceptance

This case now requires the matched v2.0-draft.4 InstalledBinding. A mismatched
binding is a failed setup, never a selected empty history. Decision inputs and
public projections include the required authority and applies_to objects.
Guidance retains target/task, policy generation, candidate snapshot,
reservation and all actual judgment IDs. JudgeReply.Request must reference
the exact downloaded judge input bytes. Fix 11 supplies claim ownership and
recovery, now consumed by guidance. Owner dependencies and acceptance limits
are recorded in guidance/CONTRACTS.md.

Run this case only on the authorized disposable Ubuntu 24.04 box, through the
shared v2 harness. The case executes the installed CLI and reads public event,
decision and blob responses. It does not open a database, import Go internals,
provide a third runner, authenticate a vendor, or call a model itself.

The frozen harness invocation is:

```sh
sh e2e/v2/cases/guidance/run.sh \
  --context /test/guidance/context.json \
  --result /test/guidance/result.json
```

Service, judge, lifecycle and templates must be real implementations. The
integration harness must additionally supply its authenticated, isolated
workload at `test_root/workload.json`. That is test input, not a new service
method or production configuration. The workload is needed because the frozen
context does not carry root tickets, decision approval proofs, initial launch
requests, or a controlled-clock facility. No missing prerequisite is a pass.
See `internal/v2/guidance/CONTRACTS.md` for the consumer implementation and
remaining real service/store/outbox acceptance requirements.

Create any positive fixture configuration, state or binding directory read by
production privacy checks with mode 0700 and ownership of the ordinary test
identity. Do not rely on t.TempDir's returned mode under the box umask. Keep
input files private, check setup errors, and leave the production privacy and
ownership checks active. A setup refusal cannot count as a killed GUIDE-TURN
mutation. This case does not create an authenticated configuration on behalf
of the harness or change the harness's identity/ownership.

The workload has `steps`, `candidates`, `turns`, and `collection` arrays/objects.
Every step supplies an `idempotency_key` generated with at least 128 random
bits and retained for that exact change/retry. The case passes the key and the
context's explicit installed `--binding` on each CLI call, and retains the
actual argv before executing it. It never silently generates a fresh mutation
key. A missing or malformed key is failed setup.

An optional step `proof` names a JSON file beneath test_root. Its original
bytes and resolved proof-reference bytes are retained, and its evidence file
is passed with `--proof`. It may use the same prior-response references as
request files. The harness supplies actual operation-bound proofs for human
mutations. For a human read, the proof is for human.session with params {},
not for that read. The common CLI opens the session and performs the read on
the same invocation socket. A separate CLI invocation needs its own fresh
session proof. The case does not sign in, generate an assertion or turn an
actor/session label into authority. Request/proof/evidence files are private.

Each step has a unique `name`, a CLI `command` word array (for example
`["lane", "start"]`), and a `request` path relative to test_root. All requests
are exact frozen API request bodies in files. There is no shell command
interpolation. Every CLI call adds the context's explicit `--config` and
`--request`; nonzero exits stop the workload and remain evidence. A step cannot
mark itself successful or supply an expected CLI result. An object with exactly
`$step` and `$path` keys references a previous CLI result; `$path` is an array of
JSON object keys/array indexes. References are resolved as JSON values before
the resulting request is saved and sent. This permits service-issued blob,
decision, operation, life and turn IDs without hard-coding a returned value.

Seed actual approved decisions with `decisions mutate` steps before any launch.
Upload their exact bytes with ordinary blob steps first. `candidates` contains
the corresponding exact `DecisionCandidate` input metadata, including the
service-issued IDs resolved by the fixture preparation, source/version, text,
effective time and current binding status. The harness must verify this input
against the seed receipts; it must never let a lane proposal set its own binding
status. The case checks every candidate's text against seed input files via
its `input_file`, and requires a real decision mutation response for its ID.
`view_step` names a `dashboard decisions` read whose exact public candidate
projection must match these inputs. Nonbinding history needs a human author or
an applied D6 receipt; a lane proposal alone fails the oracle.
Every candidate must identify a canonical human `seed_step` or an applied D6
`approval_step`. Canonical human decisions, including bindings, have empty
source paths, source ID equal to decision ID and org generation zero. They
need their human mutation receipt; binding alone does not require a D6 apply.
D6 candidates require their actual org change apply receipt, nonempty source
path and matching positive org/source generation. Proposal/lane authority fails.

Each turn describes observations from the workload, never expected scores:

- `kind` is `initial`, `resume`, `mail`, `idle`, `continuation`, `empty`, or
  `unavailable`. `action_step` identifies the actual delivery operation.
- `events_step` identifies a public `event tail` response with the authentic
  launch/turn, `guidance.selected`, and `judge.completed` events. A continuation
  uses a separate run's events and `continuation_of` names the original turn.
  Every turn supplies the authentic `run`. Its event request must specify that
  life/run, `since: 0`, empty cursor/until and `follow: false`, and return a
  complete page. The oracle filters service origin, config, life, run and
  logical turn. This includes the continuation's pre-launch events without
  confusing the prior run's selection with a duplicated new selection.
- `prompt_step` identifies a `blob read` response for the launch/turn's prompt;
  `task_file` names the actual delivered input. `as_of` is the fixture service
  clock for that delivery. `half_life_seconds` is the approved policy value.
- `policy_step` identifies the actual authorized policy get response. The
  oracle checks its generation against guidance and uses its approved
  guidance_min_relevance (default 0.50 when zero) and
  guidance_half_life_seconds (default fourteen days when zero), rather than a fixture-selected
  relevance threshold. `policy_generation` remains the expected delivery
  generation in the controlled input.
- `judge_input_step` identifies an authorized `blob read` of the retained exact
  JudgeRequest audit object. Its task and candidate bytes are compared with
  the real inputs. For multiple batches, use `judge_input_steps`, a list with
  one actual request blob per judge.completed receipt. The oracle matches
  references by object ID, checks each batch's full task and exact candidate
  text/authority, requires disjoint complete question/answer coverage, and
  compares all actual receipt IDs with guidance. At least one scored turn
  must have more than twelve historical candidates and multiple judgments.
  Each resolved JudgeRequest.Config and selected model/deployment must equal
  the approved policy, including its real tokenizer/context pins. R108 empty
  provider/model spellings normalize to the Clef default; missing pins or a
  different provider/deployment remain failures. A reported model echo is not
  deployment or live-accuracy evidence.
  Each actual input carries a positive explicit cost cap; reply cost/latency
  must be nonnegative and batches may not renew the remaining total cost cap.
  `mail_step` identifies the actual queued `mail send` for a
  mail delivery. The continuation's action can be an `operation get` read of
  the watchdog's actual operation; no client swap command is invented.
- `candidate_ids` lists the independently seeded candidates applicable to that
  turn. `logical_turn_id` and `life_id` identify the authentic delivery. They
  come from preparation by the integration harness, never actor claims.
- `empty` and `unavailable` describe receipt outcomes and may use a real lane
  start, resume or turn. Their command and authentic delivery event must agree.

The fixture clock, judge reply fixtures, identities and real drivers belong to
their owning harness cells. Controlled judge replies test plumbing and ranking,
not semantic model accuracy. The test must not use a missing service response
as an empty history or accept a constant judge score as a live accuracy proof.
The workload must contain every kind, at least six eligible reminders, an old
binding decision, an actual continuation and an observed below-cutoff candidate
that is excluded. It must include a controlled task pair with identical clock,
candidate history, cutoff, half-life and judge pins; changing the task must
change actual relevance probabilities and the selected decision ID set. It
must also include a controlled clock pair with identical task, candidate
history, policy and probabilities that reverses two differently aged selected
reminders. Recency must change an order compared with pure relevance. Because
equal exponential aging preserves the ratio of two already-historical choices,
the clock pair can straddle a candidate's effective time and exercise future
age clamping. Merely changing labels or varying task and clock together fails.
`collection` names public observation step(s) for the owned processes and
resource removal. A claimed collection boolean in the workload is insufficient.

The oracle recomputes the approved relevance filtering, recency, ordering, the five
reminder limit and weighted mean from actual judge receipts and seeded inputs.
It checks exact IDs, source versions, probabilities, prompt bytes, no duplicate
selection in a continuation, and absent scores during an outage. The distinct
empty-history case must have score zero and no judge result substituted for it.
An unavailable case must retain binding context and no probability or score.
All required files and every authentic delivery are preflighted before the
assertion is reached. Raw setup exceptions clear reached even after earlier
deliveries; only authored product assertions after preflight can be reached
failures. Missing setup is never a killed integration red control.

Run deliberate red artifacts before the candidate. Each mutation must reach
GUIDE-TURN through an actual delivery and fail its named observation:

| Mutation | Required failing observation |
| --- | --- |
| `missing-turn-hook` | One initial/resume/mail/idle delivery lacks selection. |
| `reminder-cooldown` | A successive distinct turn omits eligible reminders. |
| `fake-zero` | Unavailable guidance carries a zero weighted score. |
| `binding-decay` | An old current binding source is absent or weighted down. |
| `ignored-task` | Two different task files get the same injected task bytes or unchanged relevance despite the controlled judge inputs. |
| `six-reminders` | A prompt/receipt offers more than five historical reminders. |
| `repeat-selection` | A continuation independently selects or judges again. |
| `unrelated-fill` | A below-0.50 candidate fills a reminder slot. |
| `drop-input` | A prompt drops task bytes or a selected source's text. |

The component mutation runner and exact catalog are documented in
[MUTATIONS.md](MUTATIONS.md). They prove the focused ranking/judge checks only;
nine integration controls remain visibly not_implemented, including the
preserved cli-duplicates control blocked by the shared --request route. The
catalog now has 111 ready component controls and is pinned to draft.4. The shared harness
supplies full-service mutated artifacts and verifies their distinct digests.
A setup failure (including a typed not_implemented error) is incomplete
acceptance, not a killed mutation. Until the real owner implementations and workload
exist, this case deliberately reports a reached=false failure, never a skip.

The local command registers guidance.select's semantic parser with the shared
owner-checked registry. Its four field-predicate controls and separate missing
registration control protect that boundary. Component human replay now uses
bound read authority with zero proof guards. These structural fixtures do not
establish native authentication or installed GUIDE-TURN. Fresh selection now
consumes fix 11's Acquired, protected await, fixed positive budget and original
cause/CAS/epoch completion. D6 replay retains its old policy; fresh claims use
current policy. CONTRACT-GAPS.md describes the service/store/outbox handoff.

`test_guide_turn.py` supplies labeled oracle data/classifier controls. Run it
with `test_mutate.py` only on the authorized Linux box, using unittest discovery
with `-p 'test_*.py'`. Those controls test the oracle's ability to reject setup,
provenance and variation defects; they do not fabricate real CLI outputs.

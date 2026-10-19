# Template acceptance on Ubuntu 24.04

This case uses the installed CLI and its authenticated service connection. It
does not import product code or read management files. Run it only on the
disposable Linux test box. A missing service, policy, approved-source resolver,
prompt-retention operation or lifecycle proof is a failure, never a skip.

The harness supplies its normal context and creates `templates-inputs.json`
inside `test_root`. This input is a retained fixture receipt from independent
setup through the administrator, identity, grants, D6 and lifecycle APIs. It
contains these fields:

- `reader_kind`: `lane`, `worker` or `human`, matching the independently
  authenticated endpoint. `identity.self` must agree before validation counts
  as reached. Lane/worker grant and life claims must stay on that endpoint's
  current life. A different fallback life uses a separate enrolled binding.
- `session_proofs`: for human readers, an ordered list of relative proof-reference
  file paths under `test_root`, issued independently for `human.session` with
  params `{}`. Each read CLI process consumes a fresh proof; include enough for
  every blob chunk/end read and both output forms. Subcalls within one template
  command share its connection/session. Empty or reused proof inputs fail.
- `mutation_inputs`: for human non-session mutations, records containing `command`, the exact
  `request`, retained `idempotency_key` and relative `proof_file`. Supply exactly
  one matching record for an operation-proof mutation. policy.evaluate and
  blob staging instead consume fresh entries in session_proofs. D6 proposal
  negatives run on a separately authenticated L6 lane and use no human proof.
  Operation proofs bind the actual mutation rather than human.session.
  Lane/worker commands use new random keys retained in argv evidence.
- `render_request`: the exact `TemplateRequest` for the fixture child.
- `start_request`: a `BriefingRequest` for the authenticated life when using a
  lane endpoint. An authenticated human reader may instead select a supervisor
  life. A lane/worker endpoint cannot impersonate another role or life for this check.
- `start_expected`: `life_id` and `task_file` for that same life. The task file
  is retained from independent setup, relative to `test_root`, and must match
  the actual Lane.Task reference and start's exact framed output.
- `event_request`: an `EventTailRequest` for the child's actual launch, with
  `follow: false`. Include `lane.started` and `prompt.observed` events.
- `expected`: `level`, `role`, `life_id`, `parent_life_id`,
  `template_id`, `template_generation`, `template_sha256`, `policy_generation`,
  `task_file`, `source_files`, and `grant_set_id`. File paths are relative to
  `test_root`. `source_files` maps org-relative source paths to retained files.
  Template identity and bytes must come from the applied D6 receipt, not from
  the render response being checked.
- `negative_requests`: objects with `name`, `command` (a CLI word array),
  `request` (the exact body) and `error_codes` (expected typed errors). Required
  names are `wrong-hash`, `wrong-generation`, `wrong-role`, `malformed-source`
  and `bare-claude`. Set up the invalid sources through independent D6 staging
  controls; never install them by editing service state. Each request must
  reach validation and fail without launching an agent or changing org state.
  Each row can carry `binding_file` relative to test_root, `reader_kind` and,
  for human reads, its own `session_proofs` pool. A D6 proposal must use a lane
  whose actual identity.self level is 6, not a human or child binding.
- `ordinary_request`: a `PolicyEvaluateRequest` for an unfamiliar harmless
  local tool under the fixture child's actual grants. The effective fixture
  policy contains only the twelve workflow entries. The command must be
  unrelated to agent sessions or cloud machine creation.
- `fallback`: a second `render_request` for a quiescent fixture life whose role
  has no local source pair, plus `expected` containing `life_id`, `task_file`,
  `org_template_file` and `template_generation`. The two file paths are relative
  to `test_root` and come from the independent setup receipt. This verifies
  fallback without changing live org sources during the case. It can carry an
  alternate relative `binding_file`, corresponding `reader_kind` and a human
  session proof pool. All prompt chunk/end reads use that same chosen caller.

An alternate binding is checked by an actual identity.self invocation before
its data or negative row. Reusing a binding reuses its remaining proof pool;
it cannot relabel the reader or reset consumed proofs. A lane fallback must
match its own life and role. No live process binding or environment is changed,
and every CLI process still passes the same explicit configuration.
Primary and alternate binding paths use the same physically resolved identity,
including when test_root or the temporary-directory parent traverses a symlink.

Negative controls must return a recognized validation error for their named
boundary. Draft.4 may reject a hash at committed metadata or retained-task
comparison before the formatter runs. The case accepts only its closed list
of those specific errors and the setup's expected typed codes. A transport,
authentication or stub failure cannot satisfy them.

For a public `brief render` hash control, keep the task ID/length/class,
context and grant set unchanged and change only its valid digest. For a public
role control, keep task/grants/instance unchanged and change the valid level or
role. The case checks those differences before invoking the CLI. The public
generation control can use `org validate` with a different positive org
generation. Its actual error code is conflict. The task-claim hash control also
returns conflict; committed-object/source digest controls return integrity.
These public rows cover the task claim and org generation claim only. They do
not establish template-source hash/generation validation. The case retains this
limit in inputs/coverage.json. Source-byte/generation evidence is separate in
the component matrix; D6 wrong-before-sha256 and stale-base proposal acceptance
are not claimed by these two public rows.
Malformed source and unsupported-driver controls still need real D6 staging
validation. SourceRef path/hash/generation checks additionally have the focused
component mutations; TemplateRequest has no caller-selectable source inventory.
Never install invalid canonical state merely to satisfy a case fixture.
The setup must leave the observed lane projections stable for the comparison.
The case's own authenticated client may run in an active fixture containment;
an active fixture must not become a reason to skip the before/after comparison.
This entry creates no lane, agent,
service or cloud resource; it compares the prompt from the independently
executed lifecycle fixture with the render result and the `prompt.observed`
receipt. Real driver execution and its authentication, where needed to produce
that receipt, belong to the separate lifecycle cell. This case makes no live
AI-service claim of its own. Keep setup inputs and proof with the case evidence.

Invoke the entry with `--context /absolute/context.json --result
/absolute/result.json`. The shared harness verifies result and evidence hashes.
The entry preserves every request, stdout, stderr and exit status before
examining output. It writes a failed result even when a dependency is absent.
It stops at the first unexpected failure; assertions not reached remain failed.

Run each guarding mutation in `red-controls.json` first with `phase: red`, then
the unchanged candidate with `phase: candidate`. The case uses the same
assertions in both phases; it never treats a mutation name as a passing result.
A red setup failure does not kill a mutation. There is no local passing E2E
claim until the integration owner executes these commands and retains evidence.

The executable component controls are documented in [MUTATIONS.md](MUTATIONS.md)
and implemented by `mutations.py`. They apply one owned source mutation in a
retained copy, observe a named assertion failure, then restore and pass the same
focused test. They use explicit memory fixtures for the draft.4 ports and
are separate from this case's actual launch and delivery acceptance.

The CLI's render path validates returned source identity, hash, generation and
role before reading output. It then verifies prompt bytes and separately reads
the assigned task to compare its exact framed bytes. The rule-list command must
appear before task content. A byte-identical response still needs authenticated
service retention and actual lifecycle delivery; these checks do not supply
either missing dependency.

The feature file form is now `--request-file FILE`, combined with `--format
json|markdown`. The common `--request FILE` path emits raw typed JSON and
bypasses the feature output verification. The case invokes the feature form,
compares its JSON-referenced bytes with Markdown output, and separately invokes
the ergonomic render flags with the original `--brief FILE`. That file must
match the life’s retained task; it does not assign a newly uploaded task ID.
For a follow-up task different from initial Lane.Task, the ergonomic form accepts
`--task-ref FILE` containing its committed task reference alongside `--brief`.
The file bytes must match that reference; the service still checks the actual
active/reserved turn assignment. BriefStart continues to print initial Lane.Task.

Draft.4 setup must retain LaunchEvent.Task, Lane.Task, Lane.LaunchID, the logical
turn and the actual prompt.observed TurnEvent.Task/prompt association. The case
matches the observed life/run/turn and exact prompt ref to the actual launch.
A prepared hash or a delivery receipt from a different run cannot satisfy it.
Blob reads include the exact-end empty-byte/hash receipt, so a valid prefix of
a longer object is not accepted as a complete prompt or task.

The unchanged-org comparison reads and verifies the actual ConfigProjection
bytes, typed scope and generation. It does not treat a newly retained output
object ID as a canonical org change. The lane comparison retains every lifecycle
field and excludes only the observational last_seq cursor, which immutable
object retention may advance. Run, generation, launch ID and the complete
remaining lane projection must stay unchanged.

Both `test_root` and `evidence_root` must be 0700 and owned by the test identity.
The binding is protected installation data, not a bearer credential. Run the
case with real authenticated containment/transport authority. A human binding
alone cannot authenticate separate CLI processes: human reads need fresh proofs
through the common connection-bound session flow. The case retains each proof's
exact bytes with its command and refuses duplicate proof IDs across connections.
Human non-session mutations use their exact preconfirmed request/key/proof inputs. An
unavailable flow or exhausted proof list fails the cell before dependent checks.
No read-session ID, user label or test fixture may be used as an auth bypass.
The case checks identity.self before marking template validation reached. A
misbound fixture lane cannot count as a killed source/role mutation.

The policy assertion observes an allow result with complete audit. It does not
claim that an ordinary tool executed. Actual ordinary-tool and OS containment
execution remain independent lifecycle/harness canary observations.

Every command records an explicit idempotency key in argv before execution,
including `policy evaluate`, which is a mutation. Reuse the recorded argv and
exact body for a retry; generating another key would describe another operation.
The case does not mint proofs, authenticate profiles or treat a public session
ID as a bearer credential.

The input-routing unit fixtures in test_case.py verify per-binding selection,
session-proof consumption for policy preview and refusal of escaping paths.
They do not stand in for the real endpoint identity checks or E2E result.

For initial org setup outside this case, the feature bootstrap form supports
`--name NAME --content-ref FILE --proof FILE --idempotency-key ID`. FILE holds
the already committed source-manifest BlobRef confirmed by that proof. Optional
`--manifest FILE` must match its bytes and digest. An exact `--request-file`
also carries a committed reference. A proof-bound bootstrap refuses to upload
a new manifest before executing the confirmed intent.

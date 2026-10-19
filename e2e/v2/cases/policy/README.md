# Policy acceptance: BL-RESP / SKIP

The installed serve producer, role-worker runtime, sequential D6 inputs and
independent collection handoff are documented in [SERVE.md](SERVE.md). That
path retains the frozen entry below and uses a native Go queue worker;
`worker.py` remains the manual Python adapter for an already confined life.
Component GREEN results do not establish a passed installed E2E.

The executable component controls and the exact named mutation/test mappings
are in [MUTATIONS.md](MUTATIONS.md). That utility retains separate red and green
test binaries and stops at an unexpected failure. It is not a passing result
for this public CLI/socket case.

Run only on the authorized Ubuntu 24.04 test machine. This case was written
before the implementation. It deliberately fails when any dependency or
observation is missing. A fixture judge cell tests policy wiring, thresholds
and outages; it does not establish semantic accuracy or authenticated AI use.
Use the judge lane's calibrated self-hosted cell for semantic acceptance.

The entry uses the frozen `--context FILE --result FILE` interface. It drives
the installed CLI through `worker.py` processes that the supervising harness
starts **inside actual separately authenticated lives**. Queue names are test
coordination labels, never caller identities. Each worker stays bound to one
configuration and never changes a session binding. No expected policy verdict
is passed to a worker. Workers execute file-backed CLI requests and retain
their real exits, stdout and stderr. No service state file is read or edited.

The declared lifecycle and templates dependencies provide public event.tail,
briefing and blob-observation routes. The case reads retained inputs/briefs
through blob.read, verifies their actual sizes/hashes, and checks the briefing's
rule-list discovery command and effective source paths. A missing route remains
a dependency failure.

The harness grants each worker only its own queue beneath `test_root/queues/`
and supplies `test_root/setup.json` with these fields:

- `schema`: `laneboss.policy-case.v2`.
- `contract_revision`: `v2.0-draft.4`, also checked against each worker's
  actual binary version result.
- `actors`: `executor`, `tester`, `reviewer`, `fallback`, `l6`. Each has
  `life_id`, `run`, and `logical_turn_id`, obtained from authentic launches.
  Executor/tester/fallback are L3; reviewer is L4; l6 is L6.
- `changes`: file-backed, already staged and individually human-approved
  `ChangeApplyRequest` bodies named `baseline`, `skip`, `rules`, `timeout`,
  `partial`, and `cost`. The L6 worker applies them through `org change apply`.
  Every approval must still be current when used. Preapproving one change
  does not authorize the next. The harness can populate the next request
  immediately before its queue job; it must never bypass D6 for convenience.
  The coordinator publishes `approval-STAGE.json` with its nonce and current
  generation, then waits up to 120 seconds for that stage's request file.
  The external approval harness stages/proves each real change at that point;
  future base generations cannot be preapproved at startup.
- `rules`: IDs named `org`, `own`, `higher`, `lower`, `cloud`, `pr`, `plugin`,
  `critical`, `notice`. These identify the approved source entries below.

Create test_root, evidence_root and each queue as private 0700 directories,
owned by the identity that executes their reader. The independent harness
provides its authorized coordination access; a lane gains only its own queue.
The coordinator and workers check their directory ownership/mode and create
files under umask 077. Production privacy checks are not relaxed for tests.

The change receipt's old/new generation is the org generation. EffectivePolicy
has its own generation: the coordinator reads it after each D6 receipt and
requires it to advance for these policy changes. Every SourceRef must carry
the current approved org generation, including unchanged file revisions.
Hook and briefing results use the separate policy generation. Setup must not
assume those two counters have equal numeric values.

Baseline has an org entry, an L3 executor entry, an L4 reviewer entry and an
L3 tester-only entry. Give cloud/PR/plugin descriptions the responsibility
semantics in isolation.md, scoped so the tester does not inherit those denies.
The reviewer must not inherit lower-level entries. Fallback has no own layer.
Use different defining-scope match thresholds: org 0.80, executor 0.95,
reviewer 0.85. The fixture judge must score the cloud command 0.90, PR/plugin
commands above their defining match threshold, and unfamiliar reads zero.
Legacy pattern inputs should match the unrelated tmux control while semantic
membership scores it zero; it must proceed. Nothing in the case executes the
sample cloud/PR/plugin commands.

The skip change installs an approved exact-input exemption for the executor's
public-read input from the first evaluation receipt. It binds the effective
rule digest and stable SkipContextDigest **for the resulting D6 generation**.
That approved work digest binds exact command/tool/argv/paths/cwd, configuration,
role/instance, policy generation and judge pins, without predicting launch/turn
identifiers. The positive proof still binds the full live caller context.
After the change the first read must be a fresh scored allow with neither skip_id
nor cache_of; the next read can skip using that proof. A restart, turn/grant
refresh or expired proof requires a fresh judgment before the same approved
exemption can be reused. It never causes a refusal. Do not use a program-name list. The
rules change changes that read into a semantic deny and changes the source
generation. Outage changes configure the judge lane's outside fixture worker
to time out, return a partial answer and exhaust its cost reservation. They
also install an explicitly critical refuse entry and a critical warn entry
within the executor's scope. No testing fault selector is added to a production
policy RPC. Keep the fixture's actual requests, responses and reservations.

Start each worker with the installed binary and its own immutable binding
already installed by the harness, for example inside the executor's boundary:

```sh
python3 worker.py --binary /test/artifacts/laneboss \
  --config case-policy --queue /test/queues/executor --deadline 1500
```

Then invoke `sh e2e/v2/cases/policy/run.sh --context CONTEXT --result RESULT`.
All paths in the context are absolute. The coordinator stops the workers even
after a failure. Before acceptance the independent harness must provide
`evidence_root/collection.json` from its process/containment observer with
`processes_quiescent: true`, `temporary_resources_collected: true` and a
nonempty `observations` array. The observer also echoes the unpredictable
`nonce`, `binary_sha256` and `config` from `collection-request.json`, which the
coordinator writes after sending stop jobs. Missing or stale collection
evidence is a failure.
Do not synthesize that file from the workers' success responses.

Hook workers use the enforcing --command-file adapter with explicit life, run,
logical turn, tool, cwd and the job's retained key. They retain and read back the
actual command-file bytes before/after invocation. The coordinator requires
that form, exact byte hashes and retained request/wire data matching its input.
It also requires exit 2 plus typed forbidden/Instead on refuse and exit 0 for
allow/warn/ordinary unscored outcomes. It never manufactures a process exit
from the printed decision. The case's requests have empty argv/declared_paths;
the worker refuses nonempty arrays instead of silently discarding those fields.

Other operations retain --request FILE without --format. Fix 11 explicitly
refuses that form for org hook with unsupported, owner lb-v2-policy, exit 69
and empty stdout before generic file handling. It remains unsupported for
installed hooks. TestRawFileHookOutcome now drives real cli.Run for all four
cases and checks the exact code/owner/message/Instead/exit; any other failure
or printed decision fails. The ordinary adapter test still uses an explicit
synthetic transport and retains its actual binary and test2json streams.

The rules change occurs after successful hook calls on the existing executor.
The coordinator saves public lane.status before applying the actual approved
file through the L6 worker, then lists current policy and saves status again.
The entire lane must remain unchanged by those reads. A fresh hook evaluates
the same command under the new policy generation with no old cache/skip, and
status must keep the same life/run/turn/task/launch/grants and other identity
pins while advancing the live policy projection. Exactly one service-origin
lane.policy event must match the from/to generations, narrow life increment,
policy hash and unchanged grant-set ID. No worker relaunch or direct pin edit
can stand in for that D6-mid-run path. The checker includes explicit no-change,
read-refresh, changed-identity and missing/duplicate/wrong-event negatives.

Fresh judgments with rules and zero lane spend now refuse with budget_exhausted
and an approved-budget Instead route. The genuine judge cost-cap outage case
still uses a positive call cap and an actual judge budget error. Invalid/not-found
judge failures preserve typed errors in both fit and evaluate. The component
catalog contains 121 controls; both build modes and the shared-file gate
need fresh Linux evidence for this artifact.

Every hook/apply job retains an independently random idempotency_key before
dispatch, and the worker passes that exact value through --idempotency-key.
The job and reply are retained as evidence; existing jobs are not overwritten.
Retry the same job/key for the same operation. Reads use independent fresh
correlation keys. No worker silently invents a replacement mutation key.
The installed CLI owns the connection lifetime and any human.session ceremony;
the role workers do not claim human authority from JSON or a login UID.

Acceptance on the composed serve path additionally requires the shared
installed-CLI serve E2E on the same draft.4 source/binary artifact. This case
cannot substitute for service hosting, native peer/containment identity,
human assertions or the independent reviews.

The result has reached failing assertions on an operation failure and
unreached failing assertions on a missing setup. The current scaffold is
expected to fail with the dependency's typed `not_implemented` error, not pass.

Run each mutation against the same entry before the candidate, with a distinct
artifact hash and `phase: red`. Required red controls are:

| Mutation | Intended reached failure |
| --- | --- |
| refuse unknown commands / require positive membership | BL-RESP unfamiliar read |
| restore legacy pattern veto after a semantic allow | BL-RESP private tmux |
| inherit a lower role / omit higher roles | BL-RESP list union |
| replace an inherited threshold with the child threshold | BL-RESP cloud refusal |
| convert an unscored reply into probability zero | BL-RESP outage receipt |
| close all entries on outage / let critical warn refuse | BL-RESP outage bands |
| ignore raw input, cwd, source generation or role in cache | SKIP invalidation |
| treat a skip miss as refusal / allow stale skip | SKIP miss / rules change |
| omit or fabricate an audit event | BL-RESP matching durable event |

For unit-test red controls, mutate each named boundary and run its focused
`Test...` case on Linux. A setup crash, missing dependency, unavailable real
judge, or absent collection evidence is an incomplete run, never a killed
mutation. Source/installer/binary hashes and exact bytes are retained by the
outer harness as required by the shared case contract.

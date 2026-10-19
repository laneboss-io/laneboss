# Policy through installed serve

The producer implements the published G0 v1 contract in
[ITEM-CONTRACT.md](../serve/ITEM-CONTRACT.md). It supplies boot, prepare,
populate, transport, collect and abort hooks. The shared dispatcher invokes
the original policy manifest entry while the installed units are active.
The existing serve checks and the independent entry cgroup observation remain
required. Component tests are not an installed E2E result.

The exact installed command, run by the supervisor after its checks, is:

```sh
python3 scripts/v2-serve/run.py \
  --source "$source" --evidence "$evidence" --item-case policy
```

Source and evidence paths must be absolute, and evidence must be new.
G0 creates the frozen context and sibling private evidence directory. It
executes the unchanged manifest entry with:

```sh
sh e2e/v2/cases/policy/run.sh \
  --context "$context" --result "$result"
```

The case module is an imported producer, not a separate entry or a second
installer. It uses the current serve Case and HumanRoot; it never restores
an object from copied authority metadata. The dedicated human prefix is
itempolicy, preserving the baseline serve catalog rows.

## Before and after publication

AGENT_PACKAGE selects the measured policy_agent executable before runtime
hashes are calculated. Boot supplies ten actual role prompt/driver sources
and five contexts: L6 supervisor, L4 reviewer and L3 executor/tester/fallback.
It also supplies a real child project/object/task inventory, explicit
delegated fixture data/profiles and positive bounded budgets. G0 retains the
independent baseline project data. Empty declaration IDs are explicit typed
fields; only actual service replies supply issued grant IDs.

The role task is retained privately at boot and excluded from the initial
publication. Its old standalone policy-role-task object was unreachable
from the selected initial L5 task and rejected by initialClosure. After
installation, the authenticated human uploads the exact role-task bytes
before requesting the L6 ticket. The original L6 then uploads those same
bytes through its private CLI queue before starting its children. Launches
use only actual returned task references from their original uploaders.

The role prompt includes the four sections required by the existing template
validator. Unit controls feed the complete policy boot output through the
real G0 assembler. No typed validator is relaxed. The worker authenticates
startup through the installed CLI and emits the actual reserved session,
home, history and vendor session fields. Baseline L5 runs retain their normal
service-stop lifecycle and clean workspaces before the policy item starts.

Prepare obtains a genuine ticket for the L6. Each child is then started by
that original L6 using actual delegated IDs. Outside lane status and the
inside CLI identity/status must match. The helper's protected workspace
registry supplies queue paths, with inode/config/target checks. A UID or
queue label never supplies identity. G0 populate installs private queue
aliases and retains actual setup bytes in its allocated input scope.

## Native judge and declared provider fixture

This producer binds the installed api.JudgeWorker.EvaluateLeased contract:
the original durable JudgeExecution, authenticated native job/peer, protected
tokenizer and price pins, once-only egress, per-job exact retention and
measured cost. Assembly supplies the real native worker through
service.NewJudgeWorker. The fixture supplies only HTTP provider responses;
it never supplies a policy verdict or replaces the native worker boundary.

Boot writes the policy fixture controller handoff as a root-owned mode-0600
policy-judge.input.json in the serve evidence root. This case-owned document
has schema laneboss.policy-judge.v1, config, controller,
controller_sha256 and judge. Judge must equal the actual approved
configuration. The controller must be a protected executable matching its
exact bytes. The installation must have a positive policy_max_cost_micros.

The shared pre-install enrollment hook consumes boot's judge, judge_worker,
judge_endpoint and policy_max_cost_micros before hashes and publication.
policy_judge.py starts an ephemeral loopback-only HTTP listener, retains its
implementation/deployment specification, and builds the existing standalone
byte-fixture tokenizer. The measured runtime declares that tokenizer asset.
The protected, traversable staged price/tokenizer files have exact byte pins;
private controller and HTTP evidence stay outside the workers. Requests allow
12 questions, 65536 bytes and a 262144-token declared fixture window. Command
and guidance deadlines are 2 and 5 seconds, and SKIP has a positive 30-second
TTL. The lane's 50-million-micro budget preserves room for unknown timeout
reservations. Each durable inference claim is capped at two million micros;
the worker reserves one million. The cost fixture exceeds that worker
reservation while remaining inside the original durable claim, so the
unscored result and measured usage can pass the real audit validator.
Normal fixture responses score cloud at 0.90, PR/plugin/new-read
above their defining thresholds, and unrelated work at zero. This measures
policy wiring, not semantic calibration, live inference or model login.

For each outage the pinned outside executable accepts --request FILE with
stage, config, nonce and next org_generation. It stages a real timeout,
partial response or measured cost overrun. Timeout withholds the actual HTTP
response past the command deadline. Partial sets the provider's actual
input_truncated flag. Cost reports output usage above the pinned reservation
at the declared one-micro-per-token price, exercising the product's
"actual judge cost exceeds its reserved budget" boundary. No price or
protected installation input is rewritten between phases. Actual HTTP input,
response and delivery observations remain private, including disconnects.
Its response echoes those four fields,
input_sha256 and a nonempty evidence array of protected absolute path,
sha256 and bytes refs. The producer rereads, hashes and retains every ref.
The controller uses a private mode-0600 Unix socket, checks the real peer UID,
and fences config, nonce, generation and stage order. No testing selector is
passed to org.hook or another policy RPC. Missing enrollment, a changed
controller, a provider error or incomplete collection remains a stopped gate.

## D6, private IPC and collection

The frozen consumer sends six nonce-bound stage notices through G0's private
peer-UID/token checked observer channel. The original L6 uploads/proposes
exact bytes. A fresh same-connection human session reads the actual staged
source, derived files, diff and ownership bytes. Each exact manifest at its
current base receives a separate installed confirmation. Only then is its
apply request exposed to the consumer's L6 queue. A matching actual apply
receipt must precede the next stage. No future generation is preapproved.

Skip hashes use the policy owner's real RuleSetDigest/SkipContextDigest for
the resulting generations. A higher-role skip-only source avoids a circular
rule hash. The executor stays in its original run across rules changes,
preserving the existing cache, skip and lane.policy rollover checks.

Control traffic uses a separate queue. All coordinator jobs are exclusive
mode-0600 writes for the queue's real UID. The native worker retains exact
inputs, mutation keys, descriptor inheritance, command bytes, outputs and
real process exits. It never executes the sample cloud/PR/plugin commands.

Before writing its result, the consumer requests outside collection. The
observer retains queue bytes, waits for actual native zero-survivor exit,
and performs ordinary abandon/archive/read-back/clean operations. The native
helper journal and independent worktree/branch observations are required.
The collector also closes the fixture's real HTTP/control listeners, joins
all serving/request threads and removes its checked socket directory. It
copies and rehashes the complete HTTP/control evidence into the allocated
G0 evidence scope. It reads and retains the actual judge_egress record pages
and object bytes through the authenticated CLI, then joins each observed
HTTP request to one original durable claim/attempt and its measured outcome.
All four HTTP phases must be observed. Scored probabilities must match the
retained provider body, partial/cost outcomes must be unscored with the actual
measured cost, and a missing timeout outcome must keep its positive original
reservation as unknown. A missing or duplicated send/outcome, wrong hash,
zero reservation or failed boundary cannot pass. Shared teardown calls item
abort even if boot/publication failed before a lane was issued, so these
fixture resources are still joined.
Only then is a collection receipt emitted. G0 separately validates/caches it
and verifies entry-scope collection after the entry exits. Missing, dirty,
unknown or refused collection cannot pass. Abort names all remaining
original lives and retains the first failure without changing actor/route.

Presence remains simulated and physical human approval not_proven. No login,
live model request, paid service, owner-channel message, commit, push, merge
or deployment is part of this case.

## Disposable-box checks

Use a non-root controller on a fresh AWS or GCP Ubuntu 24.04 arm64 or amd64
box with sudo and internet:

```sh
sh e2e/v2/cases/policy/BOX-SUITE.sh
```

The script installs Python or the distribution Go launcher through APT if
missing; Go's automatic toolchain selection honors the pinned go.mod version.
It runs policy Python controls and the generic harness as the non-root
controller. Shared protected-input Python controls and the distinct-UID
canary run in the explicit root phase. No check is skipped for permissions.
The changed Go packages and their harness importer also run vet. It stops
dependent phases at the first nonzero result and finishes with that status.
Worker-session controls remove a real guard through a Go overlay, require the
specific reached RED assertion, and leave the candidate source unchanged.
No unit test or source inspection is reported as passed in installed E2E.

TestPolicyJudgeWire launches the same producer/controller and drives the real
job.Options tokenizer and measured-price callback through wire.Adapter over
HTTP. It fails on an absent enrollment, wrong Noul mapping, missing complete
request retention, a timeout that does not reach its deadline, a partial
response that becomes scored, a cost overrun that does not reach the reserved
budget boundary, or live fixture threads/listeners after collection. The
producer boot control also checks executable/price pins, reordered control
rejection. The separate actual-boot assembler regression uses the complete
boot bundle, its actual judge enrollment and tokenizer asset pins. It checks
the emitted effective policy and canonical source against that enrollment,
then changes only cache_ttl_ms back to the invalid 300000 and requires the
real assembler's typed rejection. The existing validateJudge boundary in
internal/v2/policy/resolve.go allows at most 30000 milliseconds; a zero-TTL
replacement judge in the old test had hidden the invalid producer value.
These are credential-free component
checks; the supervisor runs the installed command above for native acceptance.

The separate root-only TestPolicyBootInitial exports those same real boot
and assembler bytes to protected files, then calls admin.RunInitialValidation
with its actual file reader and initialClosure. It checks the exact validation
receipt. Its paired mutation adds the original standalone role task with
correct bytes, digest and manifest pins; only reachability is wrong, and the
unchanged installer must reject it as an unselected object. This check runs
in the explicit root phase alongside the shared protected-input checks.

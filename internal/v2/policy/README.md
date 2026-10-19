# Policy module integration

This is the policy lane's draft.4 port. The obsolete `stub.go` is removed;
`New`, `Register` and all four frozen PolicyAPI functions retain their real
implementation. This revision adopts the merged draft.4 fix-11 current-versus-
retained generation rule and explicit raw-hook refusal. It needs fresh runtime
evidence for its exact source artifact on the authorized Ubuntu machine.

The module uses `api.StateStore` and `api.ScopedJudge`. It executes no command,
provider HTTP call, source edit or direct state-file write. Missing dependencies
propagate typed errors. `DefaultJudgeConfig` selects self-hosted Clef and
`Resolve` uses `api.ResolveJudgeConfig`; neither supplies invented deployment,
tokenizer, context-fit or calibration evidence.

## Policy and source authority

`Resolve` selects one org baseline, the own (level, role) pair and every
higher role, validates unselected sources too and preserves defining-source
thresholds/calibration. Missing role files fall back to org. It never builds
a command/program allowlist or restores a deterministic pattern veto.
Guidance defaults to relevance 0.50 with the org defining source; profile
exclusions default to an empty array. The canonical loader must provide any
approved nondefault guidance/profile fields in its complete policy projection.

`PolicyGet` validates the canonical effective-policy hash, actual role and
policy generation. Public human reads refresh the live connection's session
authority with WithReadAuthority before lookup or retention. Lane reads check
the current uncleaned life, policy generation, launch/config/actor/endpoint and
unrevoked, unexpired grants. Supplied context must match the current instance
as well as level/role. `OrgSnapshot` and `Source` bind its source identities,
hashes, content references and current org generation to the complete approved
inventory. Org generation and policy generation are independent. Unchanged
file history uses ResourceFile.RevisionGeneration. A target-specific human
read resolves `BriefingInput` with the original human scope; it never
impersonates the target's lane actor.

Fix 11 permits historical launch/grant pins and an older live lane projection
while reading current approved policy. Zero/future pins and a stale current
Scope still refuse. Reads and verified human previews do not refresh the target
lane. Fresh lane evaluation, after its receipt/target/turn and budget checks,
selects PolicyNewEvaluation and uses the protected
RefreshLanePolicy port with the actual life CAS/cancellation epoch. It validates
the returned narrow projection/event through ValidatePolicyAdvance and binds
cache/audit to the returned life generation. Only the store coordinator writes
lane.policy; historical launch/grants and unrelated live fields stay intact.
Already-current work makes no refresh call. Production protected store ports
remain the owning service's acceptance requirement in CONTRACT-GAPS.md item 7.

`ConfigRead` returns a committed `laneboss.config-view.v2` ConfigProjection
for `list` and `path`. Lanes see effective policy sources; verified humans may
inspect the complete approved inventory. Retained lane projections keep the
life ACL. Human Context requests resolve approved
BriefingInput. The old ad hoc policy/sources JSON projections are no longer
used as ConfigProjection wire objects; policy remains available through
policy.get. Full show/settings/roles/channels/plugins projections still need
the canonical typed projection port described in [CONTRACT-GAPS.md](CONTRACT-GAPS.md).
They return typed not_implemented rather than incomplete configuration data.

`ConfigValidate` validates effective policy plus the injected complete source
validator, using the actual org generation. Its ValidateSources adapter can
be wired to TemplatesAPI.OrgValidate; the read-back snapshot now supplies the
generation that the old Store.Policy-only contract lacked. A nil adapter is a
typed not_implemented wiring gap, not a successful validation.

## Evaluation and durable replies

The dispatcher authenticates in draft.4 order: native ConnectionContext,
PeerVerifier with its InstalledBinding and containment, then identity binding.
Policy borrows that verified Scope; it never constructs a peer or connection.
The dispatcher must authenticate the connection and every frame, refresh scope
authority and reserve a public mutation before dispatch. It looks up/replays
receipts before module preflight and makes pending retries await their owner.
For read handlers it supplies one pinned Scope.ReadView, closes it after the
handler and uses its actual head for Response.last_seq. Policy does not create
a second store, replace a connection handle or invent transport identity.

`PolicyEvaluate` additionally looks up the reserved receipt, checks exact
frame/envelope/typed-parameter and JCS intent binding, and replays a completed
typed reply before source/turn comparisons or inference. It uses the actual
operation ID. Receipt Config, key, digest and original actor remain mandatory;
fixture maps use config / kind / principal / life / method / key and retain those facts.
PolicyGenerationForReplay chooses the receipt's retained generation using the
current authenticated scope generation after current authority/visibility
checks. PolicyAt supplies actual approved immutable history; its hash and
generation must match, as must the returned decision's generation stamp.
Replay does not load fresh sources, refresh the lane or judge again. Missing
history/ports, unknown/future generations and mismatched bindings remain errors.
Lane proofs and malformed proof IDs/digests refuse before lookup/replay.
Under draft.4 fixes 3-7, policy.evaluate is a bounded session-scoped preview.
The human actor is preserved and WithReadAuthority refreshes exact live
connection / principal / config / endpoint / session facts before lookup, inference and
replay. The transaction has no consuming proof/ticket/approval guard. A fresh
preview may reuse a current verified session with a distinct retained key;
closed, revoked, expired or borrowed authority cannot replay a result.
New work validates life/run/launch/role/grants and the retained
TurnSnapshot task. Human previews retain their original principal throughout
source lookup, judging, retention and event attribution.

Retained inputs contain exact command bytes, argv, tool, paths, cwd, original
wire params, org/policy/turn snapshots, fit and provider observations.
`Store.RetainObject` receives a structured InternalIntent with real requester,
request, operation and target facts. Actual ObjectMetadata ACL/provenance and
every byte are read back; the exact-end empty chunk also detects a hidden
suffix. Actual approved source objects and the retained task are InputRefs;
the fixture keeps and hashes those input bytes as well as the output bytes.
No public upload is promoted into trusted provenance. The current
emitter catalog needs the explicit clarification in CONTRACT-GAPS.md before this
port may be considered production-wired. The in-memory fixture is not proof
of that store authorization.

All fit/evaluate calls use ScopedJudge with the unchanged authenticated scope.
The installed host uses NewInstalled to construct its read-capable policy
component before an approved inference ceiling exists. It validates the real
store, judge, clock and command deadline. Fresh evaluation without that ceiling
retains an unscored audit without starting inference; zero is never interpreted
as a free or unbounded budget.
New requires a positive installed/org-approved MaxCostMicros. An omitted or
nonpositive ceiling returns a named assembly prerequisite; no unbounded default
or silent zero ceiling is substituted. Evaluation takes the minimum of this
ceiling and the lane's actual remaining spend.
A new rule-covered request with zero remaining spend follows the same protected
input and audit path with an explicit unscored budget_exhausted observation.
Ordinary entries allow; an explicitly critical refuse entry retains its designed
unresolved refusal. No probability or provider usage is invented. A real lane
still refreshes its policy generation; a human preview leaves that lane alone.
Exact completed receipt replay still precedes evaluation. Empty rules need no budget.
Empty rules and valid scored cache/positive-proof reuse require no fresh call.
Policy normalizes the approved Clef spelling without changing its retained policy
hash, applies ResolveJudgeForScope, and propagates typed scope/policy/provider
refusals. Such a refusal cannot become an ordinary unscored allow.
Invalid-request and not-found errors also preserve the judge's exact typed
error and recovery route in both fit and evaluate. Genuine judge cost-cap
outages under a positive cap retain the contract's separate unscored behavior.
The judge component owns raw-provider confinement, authoritative context,
cost reservation and JudgeAudit/request-byte retention. Policy independently
checks complete finite bijective probabilities, fit/tokenizer/context limits,
selected model/deployment, response usage and the shared deadline/cost budget.
Unscored has no numeric probability. Only critical refuse entries close on
inference outage; warn never blocks. Scored uncertainty remains scored.

Only the catalogued policy.evaluated event is submitted by the public policy
mutation; Policy, JudgeAudits, Grants, Channels and WorkerLeases are never its
writes. The fixture applies api.ValidateTransactionShape to both that public
transaction and the separate trusted object-retention transaction. The ConfigRead
fixture asserts that no public transaction is submitted.

Audit commits the exact PolicyDecision in both `policy.evaluated` and
`Transaction.Reply`, together with the exact retained request and the actual
reserved operation. CAS uses the closed org/lane/grants catalog. The store
must recheck current endpoint/identity/revocation at commit, and every life,
turn/task, launch or grant change must advance the compared projection.
The module checks the actual committed sequences, operation and exact reply;
a replay returns the original reply rather than a new verdict.

A failed durable commit returns a typed error carrying OperationID. The current
contract does not permit the former successful audit_complete:false fallback. No
uncommitted result enters the semantic cache. The dispatcher completes any
reserved preflight error with its own atomic typed Error receipt. A protected
object failure also remains a typed error; no unsanctioned local spool is used.

Cache/proof keys bind exact inputs, principal, life/run/turn, role/instance,
launch/endpoint/lane/grant generations, retained task/prompt/turn generation,
source/rule/policy versions and judge pins/criteria/thresholds. Cache age is
checked after source/input-retention waits; TTL is at most thirty seconds and
a hit never extends it. Only fully scored audited results enter the cache.
An approved skip uses SkipContextDigest for exact command/tool/argv/paths/cwd,
configuration, role/instance, policy generation and judge pins. That approved
work digest excludes ephemeral launch/turn facts. The positive-proof key still
uses full ContextDigest, including caller, life, launch, endpoint, grants, turn
and task. Each new authority context judges before using the same approved
exemption; a human cannot seed a lane proof. Skips never override a deny or an
unresolved critical refuse entry. Empty rules need no semantic proof. Misses judge normally.

## CLI and verification

All private package declarations in the owned CLI file use lbV2Policy names;
the four frozen dispatch entry names remain unchanged. The owned adapter
delegates to Invocation.InvokeRaw and decodes its captured typed result.
The adapter registers all four owned methods' shared input checks at init;
registration failure stops initialization. Strict shape and actual semantic
checks cover command bytes/digest, argv/paths, cwd, life/run/turn and bounds.
The service uses the same validator. Invalid file input keeps its exact typed
module error before proof/key/socket work; a valid body proceeds to the retained
key check. Config reads admit only the seven frozen views; config/read are
command words, not view values. Empty validates exactly an object without
fields. Its malformed forms fail the common shape check before the callback.

The prescribed installed hook uses --command-file with explicit life/run/turn,
tool, cwd and a retained idempotency key. It prints the real PolicyDecision on
stdout and returns exit 2 plus typed forbidden/Instead on deny; allow, warn and
ordinary unscored outcomes exit 0. Command files use the wire frame bound, so
provider overflow reaches explicit unscored handling in the service. Command
semantics and retained keys are checked before secondary target lookup.

Hook callers must mint a fresh retained idempotency key for each command
invocation, including an identical command repeated later. Reuse a key only to
resume a cut-off call. Exact replay returns the committed decision under its
retained policy, including an old allow after a tightening change; each new
command invocation needs its own fresh key and current-policy evaluation.

Common code owns PrepareRequest, mandatory retained mutation keys, read-proof
human.session and the invocation's socket. An explicit Client stays borrowed.
Secondary identity/status calls share the connection but use independent read
keys and never borrow a primary mutation proof. Sample bytes are never executed.

`HookOutcome` enforces only org hook; previews remain nonblocking.
`RenderBlacklist` prints actual words, Instead and source provenance.
Fix 11 makes cli.Run refuse org hook --request before generic file handling
with policy-owned unsupported, exit 69 and empty stdout. That raw form remains
unsupported for installed hooks. The case worker
uses --command-file and refuses nonempty argv/declared_paths rather than dropping
them. Arbitrary full file-body hooks are not a supported alternative.

TestInstalledHookExit drives real cli.Run parsing, preparation and the owned
adapter for allow/deny/warn/unscored fixture replies. An owned testdata file is
compiled into cli through Go's test overlay and borrows its existing test
transport; no production test bypass or other lane file is added. The test
retains its exact CLI test binary, hash, overlay, fixture and build/test streams
outside source. It requires all named test2json outcomes and rejects build,
timeout, skip, panic or unrelated failures as mutation evidence. These fixtures
do not establish native transport or model-service behavior.

TestRawFileHookOutcome uses that retained overlay/binary harness to drive actual
cli.Run raw requests for all four cases. Every case requires exactly exit 69,
unsupported, owner lb-v2-policy, the product's message/Instead and empty stdout.
No socket or ordinary adapter runs. The previous invokeFile expectation changes
because fix 11 refuses raw hooks; arbitrary nonzero exits do not pass. The
ordinary hook's decision-aware exit test remains separate and unchanged.

The [mutation ledger](../../../e2e/v2/cases/policy/MUTATIONS.md) preserves all
118 earlier controls (including the original 49) and adds three follow-up
controls, for 121 in total. Human-preview and lane-refresh controls cover both
sides of the actor boundary. The zero-spend ordering control returns before
the protected audit, so checking an allow alone cannot kill it. The
spend-with-zero control covers a later batch after the reservation is consumed;
zero-spend-refuse restores the old refusal and must fail the ordinary audit test.
Permanent judge-not-consulted must be killed by
TestConfiguredInferenceBudget. Permanent hook-ignores-deny must be killed by
TestInstalledHookExit with the named deny case actually exiting zero under the mutant.
It requires actual red assertion failures followed by restored green runs on
distinct binaries.
The receipt-preflight and human-replay anchors now call replayPolicy with their
original focused tests/markers intact. The generation diagnostic now rejects
a future live projection; historical pins are legitimate under fix 11. Cache
and skip generation fixtures advance current policy without rewriting the lane
pin. The public case performs an actual mid-run D6 apply and verifies unchanged
read state, current evaluation and the single narrow refresh event.
Compile errors, wrong failures, panics, skipped tests, source changes and
partial sets fail the run. Private test directories are 0700 and owned by
the executing test identity; the runner sets a private umask for its copies.
No mutation or unit/E2E command is run on the authoring Mac.

Run on the authorized disposable Ubuntu machine:

```sh
evidence=/test/evidence
go test -count=1 ./internal/v2/policy -args \
  -lb-v2-policy-hook-evidence "$evidence/lb-v2-policy-cli-plain"
go test -tags laneboss_faults -count=1 ./internal/v2/policy -args \
  -lb-v2-policy-hook-evidence "$evidence/lb-v2-policy-cli-faults"
```

Full D6, authenticated socket/hook, calibrated semantic membership, retention
authorization, installer and independent collection evidence remain required.
Fixture ports and static consistency cannot substitute for those gates.

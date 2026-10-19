# Draft.4 templates integration needs

Base: `71ec497`, the supplied G8 checkout after the candidate merge.
G8's request describes a different store implementation from this checkout.
The source ports and G2 consumer repairs are implemented here; missing backend
and reserved-life dependencies remain explicit routed prerequisites. This lane
edits only its own sources and the explicitly authorized store source ports.

## Protected bootstrap construction

The templates constructor requires `Human`, `BootstrapRenderer` and
`BootstrapOwnership` for real bootstrap. Assembly must provide the identity
verifier and protected installed org-renderer executable and committed initial
ownership manifest. A generic runtime bootstrap executable is not automatically
an enrolled org renderer. A Publisher interface alone does not resolve the pins.
Missing inputs return a typed prerequisite failure. Owners: assembly, packaging,
admin, approval/publisher and service/store.

## Causal child and asynchronous rendering

Draft.4 absolutely limits lane/worker public render claims to their own current
life/grants. A parent lane cannot render a child by labelling Scope.Request as
`lane.start`. Templates now enforces that before selected input/object reads.

The receipt route checks prepared lifecycle config/key/digest before input
selection and later verifies the reserved life and original lane/human requester.
The plan route reloads a bounded selector's actual Effect and LaunchPlanRecord,
checks its current held/unexpired claim, causal service and reservation metadata,
and accepts only reserved/sourced phases. Empty public methods are valid only
for a real continue reservation, including service/scheduler/watchdog requesters.
Retention preserves the original reservation requester/request/operation. No
effect is claimed or advanced. Direct lane/worker calls stay self scoped.
A public request's matched plan is authoritative: grant or launch mismatch
fails integrity before input lookup or receipt fallback. Internal continuation
searches may skip another grant set, but cannot skip a mismatched launch for
the selected grants. A failed plan or expired claim cannot become a missing plan.

Exact request to lifecycle/store/integrate: invoke the child renderer through
the bound lifecycle service component with the original prepared request and
its durable operation. Make the trusted store lookup resolve that original
lane/human receipt unambiguously for the service component, while public
LookupReceipt domains remain config + actor kind/principal/life + method/key.
Do not grant cross-principal receipt lookup merely from an Actor.Kind string or
a public method label. Freeze the receipt-derived requester convention in the
Sources and briefing contract. If the current Scope/LookupReceipt signature
cannot carry an authenticated original operation/request selector, provide the
service-only causal port rather than fabricating an actor or request. The
current PlanLaunch route uses the existing typed Effect/LaunchPlan ports;
provide its real current claim and reserved input view, including before a ready
Lane row exists. PendingEffects is only a bounded selector inventory, not
authority. No new public RPC field or context.Value authentication is introduced.

## Retained assignment on resume/turn

BriefRender now requires `BriefingInput.Task == request.Task`, preserving the
active/reserved TurnSnapshot assignment independently of initial Lane.Task.
BriefStart still requires the initial Lane.Task. Supply that distinction from
the authentic store view with its exact current or reserved run/generation/grants.
Do not substitute a merely visible object. CLI follow-up flags accept a committed
`--task-ref FILE` alongside exact `--brief FILE` bytes, or the full request file.
Owners: lifecycle, store, guidance and templates.

Existing live policy checks retain grant issuance <= lane <= current policy,
while new-life start/adopt preparation requires equality. These reads do not
rewrite grants or call RefreshLanePolicy. The API's launch-plan shape/current
policy validators remain enabled; source producers must satisfy those frozen
launch checks as well as the briefing's historical record semantics.

Store/bootstrap completion must preserve verified simulated-presence marks on
the committed operation, durable reply and replay. Templates checks the proof's
reference mark and the returned commit/reply; it cannot attest a real human
credential or implement the store's atomic one-use proof validation.

## Immutable prompt reuse

The prompt key now hashes canonical config, life/run/lane generation, policy
and org generation, rendered digest, ACL, exact input refs and original cause.
Repeated reads with identical inputs therefore request the same object key.
Exact request to service/store: atomically return the existing committed ref
for a matching key/bytes/class/ACL/origin/input set, without appending another
object; reject any collision with different immutable metadata. Keep actual
causal journal evidence for internal calls. Component fixtures exercise this
behavior, but templates cannot implement the store's uniqueness transaction.

## CLI and independent acceptance

The owned feature adapter now uses the shared Invocation socket and common
human.session-before-read behavior. It registers semantic validators for all
four methods and uses Invoke for typed subcalls, InvokeRaw only for retained
feature file bytes. Session-scoped mutations follow HumanSessionMethod.

Exact request to integrate: route common `--request FILE` for brief.render,
brief.start (including start), org.validate and org.bootstrap through the
corresponding feature handler, preserving exact body bytes, common proof/key/
request IDs, the same invocation socket and configuration binding. In particular,
render/start must verify actual prompt and task bytes before output, and failed
org validation must keep its feature exit behavior. Until then advertise the
working `--request-file FILE` feature form in common help and contract section
12. The dead feature-local --request/--binding-file registrations are removed;
binding options remain common parser inputs. No dispatch/common file is edited.

The owned `_cli_test.go` asset runs mocked positive handler flows through the
common injectable transport via a retained Go overlay. It does not add a
production test hook or write a shared CLI file. The installed service/client
and common --request routing still need outside-in acceptance; mocked transport
tests cannot prove native peer identity, actual retention or prompt delivery.

The disposable-box setup must supply real identity/containment, approved source
and task receipts, fresh human session proofs per process and launch/turn
prompt-delivery observations. Fallback and each negative row can select a
separate enrolled relative binding with its reader kind and proof pool. Each
binding is verified with identity.self; a lane fallback must match its own life
and role, and D6 proposal negatives require a real L6 lane. policy.evaluate and
blob staging consume session proofs, not operation proofs. No live binding is
changed. Actual source-negative and launch rows cannot pass from component
fixtures. The public hash control covers the retained task claim and the public
generation control covers the org generation claim; source hash/generation
failures remain separate component/D6 evidence. Each case retains coverage.json.

## Ports and acceptance gates

### Installed G8 and G2 routing on this base

Store.TemplateSources and Store.Source are now implemented in
`internal/v2/store/sources.go`. They pin a read view, request the exact org
generation, select only exact committed inventory references and verify object
metadata through the store's existing authenticated getter. They propagate
backend and close failures. Cross-owner edits also remove only those two
definitions from `internal/v2/store/contract_stubs.go`.

The supplied base still has Store.New as not_implemented at store/stub.go:21,
BeginRead at store/contract_stubs.go:31, ObjectMetadata at :81, OrgSnapshot at
:96 and BriefingInput at :101. Lane, Policy, Grants, launch-plan and effect
readers are stubs too. Owner lb-v2-service / integration must land its actual
SQLite backend before these source adapters can execute. The backend present
in the requested reference commit is not present in this checkout. No new
read-only database, memory store or constant success is substituted for it.

G8 BriefingInput remains routed to the real store owner until that backend is
available: resolve the authentic current/reserved life and logical turn, its
initial task, effective policy, exact grants and published source selection
under one authenticated read view. A preparing reservation is not a ready Lane
row. Preserve guidance's real turn/candidate-snapshot/judgment gates. Neither
template fixtures nor source metadata selection establish this port.

The templates half of G2's selectors and kinds is repaired. OrgValidate now
passes config ID and requested generation; render passes the complete provided
snapshot selector. Sources accept only semantic prompt/drivers/policy/source/task,
Derived only structural file, with the exact generation-specific inventory
shape required by the shared contract.
All prior digest/mode/revision/renderer/ownership gates remain. The new
Service.ValidateSources is the full source-only callback and never calls
ConfigValidate or OrgValidate.

Exact remaining routes:

- lb-v2-integrate: wire policy.Dependencies.ValidateSources at
  assembly/assembly.go:159 to a source-only templates callback, not OrgValidate.
  ValidateSources currently remains unset on this base; policy/service.go:335
  refuses it. Solve construction order with a bound callback, without skipping
  full policy/source validation.
- lb-v2-policy: policy/sources.go:18 still supplies an empty snapshot selector.
  Resolve and pass the exact authenticated publication ID/generation; policy
  generation is distinct and must not be relabelled as org generation.
- Initial-shape route resolved in the templates reader: templates/initial.go accepts
  only an explicit initial empty Derived shape. This matches fix 13's shared
  api.ValidateOrgKinds contract: generation one requires an empty array rather
  than null; later generations require generated entries. The full templates
  reader now delegates that exact shape gate to the shared validator while
  retaining all kind / content / digest / mode / revision / renderer / ownership gates.
  Initial publication does not need invented generated files.
- lb-v2-service / lb-v2-lifecycle / templates: the live planner requires an
  empty public method at lifecycle/plan_claim.go:53 and an actual claimed lease
  at :63. The legacy template preflight's PendingEffects selector at
  templates/launch_render.go:48 asks for 257, whereas the real reference store
  accepts at most 200 and excludes held claims. Do not raise that limit or scan
  expired work to manufacture authority. Supply the actual private retained
  planning claim/reservation to the renderer, preserving original requester,
  request/operation, role, target and epoch. Current internal start/resume/turn
  planning cannot be credited through the legacy continuation-only fallback.
  The state check itself now uses the frozen api.EffectClaimed value.

These are current source routes, not measured installed refusals. No G8
BriefingInput, guidance judgment or installed lifecycle pass is claimed.

Service/store owns authenticated pinned read views, scoped receipt persistence,
source/object metadata, trusted object retention, mutation guards and outbox
completion. Approval/dataworker owns verified confined publication. These must
provide measured results and preserve errors under the draft.4 catalogs; a
pending bootstrap reply is not completed publication.

The Mac port has static checks only. Linux unit tests in normal/fault builds,
all 181 component red/green controls in both builds, installed-CLI serve E2E,
and the requested independent Fable/Gemini reviews remain supervisor gates.
No host access or reviewer session is authorized to this executor.

### G8 review follow-up

Full org/source validation now checks the semantic kind of every discovered
template path, including unselected role pairs: prompt Markdown, driver TOML
and workflow policy. OrgValidate rejects foreign org IDs before policy checks;
render rejects foreign provided org IDs before snapshot lookup. The merged
checkSnapshot configuration-ID equality remains in force.

The store adapters reject empty configurations and mismatched borrowed views,
preserve borrowed-view ownership, and require positive committed ACL generation.
Binding checks precede request validation; malformed source IDs, paths, digests
and unsupported generations refuse before opening a read view. Template source
generations use the shared exact org-selector validator. Well-formed missing
references remain not_found and stale positive generations remain conflict.
The new store tests cover adapter preflight and metadata validation only; the
backend remains a prerequisite and is not replaced by a fixture.

The installed green20 source bundle constructs generation one's Derived as an
explicit empty array in scripts/v2-serve/bundle/main.go. Admin publishes that
snapshot with only publication stamps added; the store returns the retained
projection. The templates reader's unconditional nonempty-Derived check caused
the reported initial-publication integrity failure. Its generation-specific
shared gate is now the authority. Runtime rerun and red-before-green evidence
are still required; a source trace and candidate vet are not installed success.

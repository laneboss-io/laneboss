# V2 judge port

The Clef and TypeSafe packages implement the frozen `api.Judge` interface.
Both use the complete System One JSON body, indexed trusted Noul questions,
named command/rule/decision/task/context data, pinned model/deployment/tokenizer
settings, total deadlines and complete, atomic probability validation. Clef
supports a bearer key supplied by its outside worker; it reads no credential
file or environment variable. TypeSafe requires supplied credential material.
Neither provider changes policy, thresholds, grants or provider selection.

Under R108, self-hosted `Cloudflare/clef-flash` is the default chosen by the
composition owner. `typesafe` remains an explicit pluggable alternative with a
full Jev version. `api.ResolveJudgeConfig` supplies the decided Clef defaults
without inventing pins or changing an explicit TypeSafe choice. Under draft.4,
the Clef-only corpus calibrates thresholds; a Jev comparison and a two-week
shadow period are neither promotion nor release prerequisites. An outage never
selects another provider.

`wire.Options` and each provider's `Dependencies` are protected constructor
dependencies, not a configuration schema or RPC input. The worker supplies an
exact serving formatter/tokenizer callback, an explicit safety margin, protected
byte retention, approved usage-cost calculation and a positive conservative
reserved cost ceiling. Zero reservations are invalid for both providers, before
retention or HTTP. A tokenizer callback must honor its context and count the full
serving template. There is no production byte-token approximation, constant fit
proof or implicit seven-token allowance. Both 8,192 and 16,384 windows work when
actually configured and proved; no deadline grows with the context window.

Requests above the complete byte limit, at/above the safe token limit, lacking
proof, containing credential-shaped text, or beyond budget have no score and
perform no HTTP exchange. Every outgoing decoded string is screened before
retention and before the byte gate. Response string keys and values are screened
after strict JSON decoding, including escaped echoes of the exact bearer key.
Credential signatures match substrings even when ASCII or Unicode word characters
touch either end. The original long suffix canary exposed the old left word
boundary: `界` directly before `Bearer` prevented a match. The suffix length and
payload are retained. All caller-controlled command text, CWD, argv, paths,
tool, task and unknown state are joined in one command scope. The default is
to join; only the explicit service/approved paths in CONTRACT.md are excluded.
Approved rule IDs/text, fixed question strings, service-issued context IDs and
computed hashes cannot complete a caller fragment into a manufactured shape.
Every excluded string/key still receives complete credential inspection.
Unknown locations, unexpected containers and embedded caller documents inherit
no metadata exclusion. Decision text remains joined; store-generated decision
IDs and org-authored provenance/applicability metadata are excluded only after
complete-candidate comparison with the authoritative store snapshot.
Two fixed caller views preserve canonical raw/decoded document order and add
execution order with JSON transparent to adjacency. Both use spaced/unspaced
key, value and combined streams. Both share the byte/work allowance and all
depth/buffer caps, with the node allowance counted separately for each pass.
A short risk-review / pa-review / hf_build / npm_build rule ID or /work/task-3 CWD
must score, while cross-field caller credentials must withhold. Generic data
keeps the frozen joins. Response protocol fields and completion metadata use
complete-string screening; response joins retain exact split bearer-key checks.
These views never replace or shorten the actual request. Benign references still
receive explicit negative controls. This is credential-shape screening, not a
claim of detecting every possible encoding of arbitrary secret material.

The input screen has a 1 MiB serialized-input cap, depth 32, at most 65,536
visited value/key nodes per pass (131,072 overall for the two request passes),
and one shared 8 MiB byte/work-unit allowance. Embedded scopes share the current
pass's node allowance; only the second fixed request pass resets that counter. Inspected,
copied and decoded text and radix steps spend that allowance. A complete fixed
RE2 pattern set is charged once per string or view; its individual pattern
passes contribute a fixed multiplier to the total character visits. Exceeding
any limit withholds
the observation before request retention, fit checks or HTTP. Caps never produce
an unscreened pass. The response uses the same bounded screen after strict decode.

Assignment matches are found in one RE2 pass. Each keeps the original complete
first-value semantics: leading Unicode padding, quoted/reference values and
the first unquoted word plus its more-words context. A following assignment
never truncates the value; nested matches are independently inspected. The
reference's placeholder/prose rules remain unchanged. Three named extra
detections withhold a bare suffix immediately after a closing quote or complete
angle/brace reference: `quote-tail`, `spaced-tail` and `reference-tail`. A suffix
can otherwise hide behind an empty/redacted first value. Whitespace and
`,;)}]` end that value normally; complete references, redactions, prose and code
references retain negative controls. Every inspected
region spends a per-string allowance of eight times the string bytes plus 32,
as well as the shared work budget. Overlapping nested references can exhaust
that allowance; they then withhold with `credential screening cap reached`.
An individual search can inspect at most one additional complete string before
that exhaustion is observed, keeping the cost linear. Values over the 1 MiB
string cap also withhold. A cap never becomes an ordinary credential match or
an unscreened pass.
Key order uses byte-radix passes rather than repeated common-prefix comparisons.
There are six fragment streams (keys, values and their combination, with and
without separators). Each retains a complete view of at most 1 MiB and runs the
fixed signature set once, after collection. The old 512-byte overlap could lose
long separators, JWT segments or URL userinfo. Those shapes have variable length;
a finite short overlap cannot prove their coverage. Complete capped views keep
every supported shape's key, separator and value together. Overflow withholds
the request rather than discarding a prefix. Exact supplied-key echoes have a
separate 8,192-byte key cap. Generic assignment heuristics apply to individual
fields, preserving complete benign references when unrelated fields follow them.
All original fix-1 split canaries remain covered. No fragment pairs, rolling partial matches or
per-start-offset regex loops are constructed. Geometric buffer growth clamps
each allocation to 1 MiB and copies less than twice the final size; those copies
spend the same work budget. Each scope has at most six 1 MiB buffers. An exact
response-key view can coexist with one embedded-document scope; both spend the
same frame budget and neither resets depth or node accounting. Work remains
O(charged bytes + radix steps), and any cap exhaustion withholds. These are
algorithmic bounds, not measured latency.

The Linux-only benchmark checks actual complete 262,144-byte request bodies with
4,096 small fields and 24 embedded JSON levels, and with repeated assignments.
It pairs each benign workload with a same-size credential-tail variant and fails
if an individual screen exceeds 500 ms. That is one quarter of the default
two-second command budget; the benchmark does not extend the deadline. Runtime
timings on this candidate remain unverified here. The supervisor reported that
both cases exceeded 500 ms on the previous `f9bf8cf` tree, Ubuntu 24.04,
c5.large, 2 vCPU amd64. No duration was supplied. This candidate adds necessary
literal prefilters before the unchanged credential RE2 patterns, folds each
string once for the insensitive patterns, omits the redundant optional prefix
from unanchored assignment search, and checks placeholders before regex helpers.
Absent literals can skip an RE2 pass; they never constitute a positive match.
The assignment prefix contains no separator and cannot change a match's value
start; an independent comparison checks its end offsets against the frozen
grammar. Unicode fold controls cover long s, Kelvin sign and dotted/dotless i.
The failure reports case, input bytes, sample and actual elapsed duration.
These changes target both `many-fields-deep` and `assignment-tails` without
changing workloads, time limits, detection patterns, views or caps.
New canaries isolate assignment truncation after more than
1 KiB of padding and cross-field signatures with a 513-byte separator; the
supervisor must retain their failing run on the old source and passing candidate.
The test-only screen from `7328683` is frozen in `wire/screen_reference_test.go`
with identifier prefixes only. It imports no production screening helpers.
Normal differential coverage has 4,175 complete JSON requests; the long build
tag has 32,847. The original seeded rows, split/suffix canaries, cap boundaries
and three assignment-tail extras are preserved, with eighteen caller-split and
unknown-container frames plus seven realistic benign frames. The frozen oracle
source is unchanged; the independent ownership table now covers decision metadata.
The sole reference-only omission, structured-join, now requires an independent
caller projection with no hit in either fixed order. Its literal ownership table
uses only frozen grammar and standard JSON; it does not call production's path
or screening helpers. Any reference hit reachable from caller bytes alone must
withhold. Removing only excluded service keys/values must explain the omission,
and the JSONL records caller verdicts plus excluded paths.
The new extra caller-join permits only additional detections independently
proved by that caller projection (execution order or decoded adjacency). It
creates no new omission. Six actual adapter canaries cover cwd/command,
command/argv, argv/paths, context-CWD/task, caller/embedded-document and tool/CWD.
Unknown fields and containers at scalar metadata paths have separate controls.
Every input leaf is checked as non-sensitive before the split assertion.
The seven benign requests require real HTTP scores, exact bytes and actual
probabilities. Caller plus an excluded computed digest is explicitly allowed
when caller-only views and every complete field are clean; the service owns
that digest, so it is not an arbitrary caller secret fragment. A full credential
inside an excluded field still withholds. CONTRACT.md gives every excluded
JSON path and its producer/provenance requirements.
The guidance fixture uses /decisions/task-7 immediately before its source digest;
the frozen whole-frame reference withholds, while its caller projection is clean.
Decision text joined to task text, decoded task JSON or another decision still
withholds. Direct string members of approved applicability lists remain fully
screened; nested containers, unknown fields and unexpected text levels retain
caller joins. Exact 65,535/65,536/65,537-node conforming requests pin the per-pass
boundary, and a separate two-pass control requires shared-work exhaustion.
Malformed JSON cannot be fully screened and therefore is not retained as raw
content. Screened shape failures, wrong-model and partial responses can retain
protected raw bytes; they never expose probabilities. Provider input usage must
agree with the complete serving-token proof, which catches a truncated count.
That agreement alone does not establish live deployment fidelity.

Protected retention callbacks must return the exact class, byte count and hash.
The adapter retains complete HTTP request bytes and screened response bytes.
The raw response preserves the provider's request ID. The normalized
`Request` now points to the exact retained outgoing bytes; scored validation
checks its class, length and digest. Cache copies include Request and BatchIDs.
The normalized reply still has no dedicated provider-request-ID field; this is in
`CONTRACT.md`. Numeric zero metadata on an unavailable reply cannot establish
known usage or cost; the missing representation is also a production gate.

The normalized contract contains per-question Noul probability only. A scored
batch has every requested ID exactly once, each with its own probability pointer.
There is no special `match` question, top-level match probability, Choice-to-Noul
cast or Score support. Arbitrary questions are not accepted through CLI preview.
Full Choice distributions and provider-specific confidence await the shared
contract amendment; the corpus's twenty Choice rows are not called evaluated.

The cache binds the semantic typed request, including complete rule and decision
lists, raw command bytes and hash, argv, paths, role/instance, grants, policy and
deployment/tokenizer configuration. Per-ask ID, DeadlineMS and MaxCostMicros do
not enter the key. Invalid inputs, cancellation and zero budget still bypass
reuse. It retains only normalized scored replies
and protected BlobRefs. It charges serialized bytes plus fixed entry overhead,
evicts in expiry order, clones probabilities/references, and merges identical
concurrent misses. Its byte charge is not a measurement of process RSS. Cache
hits retain the original observation ID, refs, probabilities and historical
usage/cost; a hit does not create another inference bill. Authorization and egress leases must
be rechecked outside the cache; the cache grants no authority.

The service registers `judge.ask` and `judge.list`, strictly validates their
draft.4 JSON, checks the connection/frame binding and live pinned peer, and derives current
context/grants/policy from StateStore. `FitForScope` resolves the actual turn/task,
verifies metadata and complete bytes, checks approved rules or paged authoritative
decisions, and delegates to the protected fit provider. Task or authority claims
cannot replace those store facts. Its total deadline starts before preflight.
Resolved request/policy configurations must agree through `ResolveJudgeForScope`;
empty provider/model spellings equal the explicit default only with identical
approved pins. The resulting provider selects `Dependencies.Clef` or `TypeSafe`.
An unavailable alternative or outage never falls back to another provider.
`CommitAudit` now consumes draft.4's `StateWrites.JudgeAudits` and `judge.completed`
under `InternalJudgeEvaluate`, with current lane/grant CAS and cancellation guard.
It independently reads metadata and all request/raw chunks, verifies hashes,
fit and raw probabilities, then verifies the committed audit projection. It
also serializes and screens the complete reply before the write. There is no
caller-set screened flag. Screening request/provider bytes does not by itself
establish that derived reply metadata is safe.
The audit fixture uses the shared correlation-ID generator; its old textual
`ask-one` ID is a scored control for the manufactured metadata join. Poisoned
completion reasons and complete credential-shaped IDs still refuse at the
actual completion screen before any transaction. CommitAudit
does not grant dispatch authority or register a new public method. Internal
completion has no RPCReply; public mutations require their final typed reply
under the empty `judge.ask` write row. A fixture checks both matrix boundaries.
`EvaluateForScope` and `JudgeAsk` still stop before provider execution because
the contract lacks once-only judge dispatch/egress reservation and recovery.
`JudgeList` and `RunInternal` retain their named typed gates. CONTRACT.md records
the exact remaining ports and composed-serve prerequisites. These are open
production dependencies, not a passing composed service.
Prepare-stage unavailable outcomes cannot currently produce a valid JudgeAudit;
preview supports one complete batch and returns typed unscored at thirteen
rules. CONTRACT-GAPS.md specifies the missing audit/aggregation evidence and
the tests that protect those explicit limitations. DEPENDENCIES.md inventories
every reviewed legacy path and the byte-identical owned corpus fixture.
The CLI supports file-backed `--request FILE` and `--format json`, preserves the
validated input bytes as RPC params, and delegates envelope/transport work to the
shared `Invocation.InvokeRaw`, which owns `client.PrepareRequest`, retained
mutation keys, human-session reads and the invocation's shared socket. An explicit
Client is borrowed. The common file-backed command path uses that same code.
Missing client
transport/worker capabilities fail explicitly.

No unit test, E2E, model call, binary build or executable run was performed on
the authoring Mac. Static checks cannot certify model accuracy, real tokenizer
fit, Linux worker isolation, crash accounting or a production-ready CLI.

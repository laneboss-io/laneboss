# Messaging acceptance

This case is authored before the messaging implementation. Run it only on the
authorized Ubuntu 24.04 machine, using the installed artifact and the frozen
context/result interface in the lane plan. It calls the public CLI and human
dashboard; it never opens the service store or fabricates a launch record.
Missing dependencies fail the case. A scaffold, an absent actor, or a failed
setup is not a killed mutation and is not a passing relation test.

The fixture cell is credential-free with respect to external AI and delivery
services. The lifecycle/identity harness must supply actual service-created,
confined lives and authentic inside processes. An API mock, a UID chosen with
runuser, a copied launch record, or a client-supplied actor is insufficient.
This cell does not establish authenticated vendor operation or hardware human
presence. Those retain their independent live/hardware cells.

The shared harness supplies `test_root/fixture.json`, in addition to the frozen
context. Its `actors` object maps the names below to private control socket
paths. Each socket is served by this case's `actor.py`, already running as an
actual descendant in that life. Only the outside harness can reach all the
sockets; each actor sees its own control directory only. The harness starts
actors through the two supported drivers, never a third production driver.
The case reads identity and lane status through each actor and checks the
starter graph before testing messages. Socket paths and display names confer
no service authority.

The authentic topology is:

```
root (L6)
  a5 (L5)
    a4 (L4)
      a3 (L3)
      peer3 (L3)
    peer4 (L4)
      cousin3 (L3)
    direct3 (L3)
  b5 (L5)
    b4 (L4)
      b3 (L3)
other (L6, a different root)
```

The setup also supplies a human control socket `human` using the identity
lane's enrolled disposable authenticator and the dashboard lane's real HTTPS
endpoint. It must perform real operation-bound confirmation for authenticated
requests and send identical unsigned requests for the negative control. It
does not put cookies, private keys or human confirmation tokens into context,
argv, fixture JSON or retained transcripts. Its response contains the public
HTTP status and RPC response only. The fixture's `channel_grants` maps `a5`
and `root` to exact current D6-approved channel grant IDs. Channel delivery is
to an independently observed disposable sink, with controllable transient
failure and stable delivery-key deduplication, never a real owner destination.

The actor bridge protocol is test orchestration, not a product RPC. A request
is one length-prefixed JSON object containing `command` (CLI words), `params`
(the exact file-backed request body), and optionally `file_bytes` (base64
mail content) and `flags`. The bridge writes these inputs in private scratch,
executes the installed binary with explicit config, and returns its actual
exit/stdout/stderr. It cannot change its authenticated life. The human and
scenario-control bridges require integration with the identity/dashboard/
lifecycle harness; their absence is an explicit failing prerequisite.

`fixture.json` has these case-local fields. All socket/log/temporary paths
are absolute and beneath the context's test_root. `actors` contains every
name in the topology above. `human` and `control` are private harness sockets;
`channel_grants` maps a5/root to their enrolled grant IDs;
`partial_channel_grant` selects the approved disposable destination group;
`channel_destinations` maps each selected grant ID to the exact distinct
destination channel IDs enrolled for the disposable sink;
`sink_log` names the independently retained sink JSONL; `temporary_paths`
enumerates the owned runtime sockets/resources that collection must remove.
It must include every actor socket. The source tree contains no default
fixture that can create synthetic authority.

The scenario-control bridge runs real public operations for `drain-channel`,
`drain-turn`, `revoke-sender`, `attempt-turn`, `retire-reuse`,
`fail-one-destination`, `drain-partial`, `recover-channel-worker`,
`manual-turn`, `limit-then-continue` and `collect`. Its transport result is
`{exit: integer, public_operations: [{request: Request, response: Response,
exit: integer}]}`. The outer exit describes orchestration; each inner exit
is the actual public operation's result, including the deliberately refused
turn. Public traces exclude proof/cookie/credential material; the enrolled
human fixture retains protected authentication evidence separately. Each
response must match its actual request ID, protocol, schema and configuration.
The case independently reads mail, blobs, events, sink bytes and collection
status; a bridge's claim that an assertion passed is never an observation.
The human bridge also handles `dashboard-raw`, using the real authenticated
dashboard raw-view route, and returns its public HTTP status/RPC response.
The case compares the raw-view Mail object with the original human message.

Actors remain in ordinary active runs until a turn-control step. On a real
run end the old actor relay must end too. The lifecycle harness starts a new
relay through the next actual confined run and reconnects its host routing;
it never keeps a revoked endpoint alive or impersonates its previous process.
The recheck cell queues both messages before any recipient turn. Collection
closes relays, quiesces every original and replacement life, obtains actual
lane.check observations, archives/cleans through public operations, and returns
the subsequent lane.status results. The entry requires zero survivors,
cleaned records and disappearance of the listed fixture runtime paths.

The assertions are driven from outside and require independent observation:

* **MSG-REL:** file-backed mail from `a3` to `peer3`, `a4` to `peer4`, `a5`
  to `b5`, `a5` to `a3`, `a4` to `a3`, and `a5` to `direct3` succeeds. The
  direct report lines `a3` to `a4` and `direct3` to `a5` succeed. `a3` to
  `cousin3`, `a3` to `b3`, `a3` to `a5`, `a4` to `b3`, and cross-root mail
  refuse. L3/L4 human-channel attempts refuse even if a higher life's grant
  ID is supplied. Both granted L5/L6 channel sends must actually reach the sink.
  Compare the immutable content hash and unpredictable input bytes at the
  receiving life, not just the enqueue response. Reused display names must
  produce different life IDs; old messages/rights must not transfer.
* **HUMAN-SEND:** real verified dashboard mail reaches `a3`, retains source
  `dashboard`, sender `human` and exact hash, and has a completed logical-turn
  receipt visible in public raw/history views. The identical unsigned HTTP
  request must refuse. A supplied human label must also refuse.
* **MSG-RECHECK:** enqueue a message, revoke its sender's effective rights or
  retire/reuse its target life before delivery, then request a normal turn.
  It must not deliver to the replacement life. Independently observe no
  recipient prompt containing the unpredictable message and the recorded
  refusal/return. Every carried sender must be checked, including a later
  invalid sender following a valid first message.
* **MSG-RETRY:** send through a disposable channel sink, fail one delivery
  after another has confirmed, restart/retry the same durable operation, and
  count confirmed sink records by stable delivery key. Each confirmed send
  appears exactly once, the failed outcome remains visible, and its retry
  completes. Lost replies must not duplicate a confirmed external send.
* **MSG-ACTOR:** a manual turn with mail from a different life keeps the
  authenticated requester as event actor; an automatic turn keeps scheduler
  as actor. Each mail retains its own sender. A provider-limit exit cannot
  acknowledge or return the mail; only actual completed logical delivery can.

Run each assertion red first. Guarding mutations remove enqueue relation
validation, remove delivery revalidation (including a later carried sender),
substitute the first mail sender as turn actor, acknowledge on profile-limit
exit, bypass fresh human proof, or resend a confirmed channel delivery. The
red artifact has its own hash. The same observer/assertion must reach and fail
for the intended operation; setup failures do not count. Then run candidate
against the exact candidate artifact. The harness supplies mutations; a case
never changes production behavior based on its phase or a magic input string.

`run.sh --context /absolute/context.json --result /absolute/result.json`
retains inputs, CLI/HTTP bytes, exits, observed events and SHA-256 evidence
references. Collection must be verified through real stop/check/clean and
zero-survivor observations by the harness. No absent assertion or missing
collection evidence is represented as a pass. Source, installed binary and
fixture input hashes belong in the shared archive outside the checkout.

Draft.4 supplies enrolled channels, leased jobs, internal delivery transactions
and worker-lease writes. The fixed channel transport/read-back path, hosted
composition and real scenario fixtures remain failing prerequisites. Current
needs and consumers are in messaging's CONTRACT-GAPS.md; the older amendment
file is historical. Enqueue alone is not external delivery acceptance.

The d4fix1 channel preparation path now refuses explicitly with
channel.job.prepare before committing the former empty-target Deliver intent.
The exact missing fixed worker runtime/input/result handoff is requested in
CONTRACT-GAPS.md. The channel acceptance rows must remain failing prerequisites
until that handoff and the real executor are supplied.

Queue/report events for lane senders carry that sending life's authentic
lineage. Mail itself retains its immutable recipient. The outside case joins
the sender's and recipient's separately authorized event views for delivery
verification, without granting a recipient raw access to a sibling's history.

Every bridged CLI request now retains its explicit idempotency key in the
operations transcript. A retry reuses that key, including derived inline-upload
keys. The context binding must identify the exact draft.4 artifact. Observers
require positive mail generations and artifact arrays, and compare the retained
artifact references along with sender/content provenance. For a human CLI
mutation, upload first and use `--content-ref FILE` plus the actual operation
proof and retained key. Human reads use a proof for human.session on their
shared connection through the common Invocation path. Nothing in fixture JSON
is a bearer credential.

[MUTATIONS.md](MUTATIONS.md) maps each acceptance rule to a named red control,
its focused failing test and the disposable-copy runner. Observer unit controls
share observations.py with the real entry and remain separate from actual
service/OS/vendor acceptance. Positive relation/report cells now require an
authentic completed logical-turn receipt after checking the received bytes;
an enqueue or inbox entry alone cannot complete those cells.

The inside CLI also validates successful mail/mailbox/upload result bodies
against their exact frozen shapes before printing them. Duplicate keys,
unexpected or omitted fields, null, unpaired Unicode escapes and invalid
provenance cannot turn a malformed response into a successful empty object.
The receipt preflight now requires the causal queue references, one unambiguous
authentic end, ordered observations and actual known-exit evidence. The named
component mutations in MUTATIONS.md cover these checks without substituting
observer fixtures for actual service/worker execution.

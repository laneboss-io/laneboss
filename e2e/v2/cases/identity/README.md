# Installed identity canaries

The current d4fix13 consumer adoption implements fix-11 registration validation,
declared software-presence propagation, read-session refresh, causal transport
invalidation and native worker connection/per-operation mapping. Pre-gate worker
BindLaunch still requires a reviewed retained job/helper handoff. The supporting
catalogs retain all previous IDs and now contain 225 controls and 79 fixtures.
Use fix11-before-cases.json with the actual f5f6ba9a base, and run the dedicated
authenticator-tag positive crypto/projection tests separately from production
refusal controls. CONTROLS.md records the precise scopes and Linux commands.

The d4fix12 package-runner follow-up retains internal/jsontext and
internal/typesafe in the reduced source snapshot used by the real CLI fixtures
and controls. It also moves the
worker dependency decision onto the stored binding and adds two deciding
controls and one fixture, preserving all earlier IDs for 192 controls and 60
fixtures. Exact snapshot vet and runtime qualification are separate evidence;
the details and Linux commands are in CONTROLS.md. Shared fix 11 is deferred.

This is supporting identity coverage. The sole acceptance gate for the current
round is the installed serve E2E owned by lb-v2-serve, with a correct base
failure and a composed candidate pass. Neither this case nor package tests
complete that gate. Missing enrollment/launch/store setup makes this case fail;
it cannot be filled with a raw UID, forged scope or prewritten success.

This case runs only on the authorized Ubuntu 24.04 box, against the installed
artifact and socket. Run `sh run.sh --context CONTEXT --result RESULT`.
It never starts a model, enrolls a key, provisions a machine, or uses a login
UID as human approval. Hardware-presence evidence requires the enrolled human
and dashboard. L6 separately authorizes a declared software WebAuthn
authenticator for installed serve: it must use real enrollment and signed
assertions, be refused without its dedicated test build tag, and retain an
explicit simulated-presence mark on credentials, proofs and reports. The
current shared contract lacks that metadata/validation handoff; the exact
request and constant coordination names are in
[contract-gaps.md](../../../../internal/v2/identity/contract-gaps.md).
Software signatures or a declared fixture do not establish hardware presence.

Run 2 adds `run-controls.sh`, `controls.py`, `mutations.json` and
`fixture-cases.json` for the package fixtures and source-copy controls described
in [CONTROLS.md](CONTROLS.md). Those commands emit a distinct fixture schema;
they do not produce or substitute for this installed-socket case's result.

Fix 9 adds before.py/before-cases.json for 30 named base/candidate package
assertions with identical test bytes. It also adds 21 omission controls and
nine fixtures while preserving all earlier IDs, for 172 controls and 53
fixtures. The runner and exact box commands are documented in CONTROLS.md.
Static vet and source-anchor inspection do not qualify a runtime red or a
candidate pass. Full launch/store/helper composition remains necessary.

The d4fix11 adoption consumes shared draft.4 fix 10 at base 9f7b5ad0. It keeps
all 172 earlier controls and 53 fixture IDs, adding 18 controls and six fixtures
for 190 controls and 59 fixtures. before.py --case-plan fix10-before-cases.json
selects 10 matched-contract base/candidate assertions. The original 30-case
catalog is unchanged historical evidence; its old API cannot compile current
fix-10 fixture fields. Exact Linux commands and limitations are in CONTROLS.md.

The supervisor first prepares independent client processes inside real helper
namespaces and the human dashboard. It writes `identity-scenarios.json` in
the context's test root. This is a case-local input, not an extension of the
shared context schema. It contains `contract_revision: v2.0-draft.4` and a
`scenarios` array. The case executes the installed artifact's `--version` and
retains its output/exit; a different contract revision fails setup. Each scenario has
`id`, `assertion`, `argv`, `expected_exit`, and `expect` fields. `argv` invokes
the actual context binary (possibly through a namespace entry tool); it must
carry an explicit configuration and scenario's actual installed binding.
Use --binding or --binding-file, in separate or inline form. Inside a namespace
the actual protected /run/laneboss/binding.json path is valid even when it is
not visible from the host. Only ticket-wrong-config may select a different
configuration; it must use that configuration's real protected binding and
the actual issued ticket. Other RPCs stay bound to the context configuration.
The collection command is an independent observer and needs no dummy binary,
config or binding arguments. `expect` is
a map of dotted JSON result paths to exact expected values. Refusals must
assert an actual typed error code, never merely a nonzero exit. Successful
mutations assert their receipt and are followed by an independent status or
event read. Retain all inputs and raw outputs in the evidence directory.

Required scenario IDs and observations are enforced by the entry:

* HUMAN-IDENTITY: `human-no-proof`, `human-wrong-origin`, `human-replay`,
  `human-wrong-intent`, `human-expired`, `human-confirmed`, `human-lost-reply`,
  `human-key-conflict`, and `human-effect`.
  The first five refuse; the confirmed request succeeds only after a real
  enrolled assertion and the independent effect read matches it. A lost-reply
  retry with the same intent/key and a new correlation ID must return the
  original receipt without another proof use/effect. A changed intent under
  the same key must return idempotency_conflict.
* PEER: `peer-child`, `peer-detached`, `peer-forged-label`, `peer-uid-drift`,
  `peer-generation`, `peer-stale-launch`, `peer-passed-fd`,
  `peer-foreign-containment`, and `peer-effect`.
  The child/detached controls succeed. Forged request labels, a changed UID,
  a dead/reused connector PID, revoked launch and a different process writing
  a passed connected socket must refuse. A forged environment label must not
  change the actor returned for an authentic client. The independent effect
  read must show the authentic operation and no denied operation.
  The foreign-containment canary uses the enrolled lane UID outside its
  registered containment, so UID checking cannot stand in for containment.
* TICKET-ONCE: `ticket-issue`, `ticket-first`, `ticket-second`,
  `ticket-wrong-level`, `ticket-wrong-role`, `ticket-lost-reply`, and
  `ticket-effect`. Issue with
  real operation confirmation, redeem once, reject reuse and altered scope,
  and independently read back the single root life at its issued role/level.
  A lost-reply retry of ticket issuance returns its original ticket/receipt;
  it cannot mint another ticket or consume the proof again.

Each negative input must be a real operation in its named process, not a
prewritten answer or an internal-state inspection. Prepare scenario commands
that block until the live canary event they exercise has occurred. The entry
does not accept a transcript in place of running a command. Namespace setup,
PID reuse pressure, UID transition and FD passing belong to the installed
helper/transport test setup; missing setup is a failing dependency, not a skip.

For red runs supply the separately built fault artifact and select one of
`omit-containment`, `omit-generation`, `omit-proof`, `omit-nonce`. Run the
same scenario inputs against that artifact. The relevant negative scenario
must reach the operation and fail its expected refusal assertion. A missing
scenario or setup crash never counts as killing a mutation. The identity
lane's package runner now supplies those four named omissions at the available
fixture boundaries. `omit-proof` checks the early ticket proof guard only;
`omit-nonce` checks signed challenge matching only. Installed transport/launch/
store fault modes still require the implementations of the draft.4 ports. A package kill
does not close an installed-socket assertion.

The entry runs every required scenario, records actual exits and stdout/stderr,
and writes a failing structured result when a prerequisite is missing. It does
not report collection complete until an independently prepared `collection`
scenario has observed no remaining owned processes or temporary resources.
Hardware-backed presence and a credential-free signature fixture are never
reported as interchangeable evidence.

Evidence and result paths must remain under the physical context test_root;
symlinked parents cannot escape it. An existing result path is preserved.
Missing JSON result keys or wrong value types fail that scenario, while
malformed JSON fails it as unreached. Later observations and collection still
run. Such failures do not relax the named red-canary qualification rules.

Draft.4 also requires these scenario IDs. Each command still executes the
installed artifact and independently reaches its named operation:

* HUMAN-IDENTITY adds `human-read-session`, `human-self-no-session`,
  `human-read-new-connection`, `human-read-revoked`, `human-read-idle`,
  `human-stage-session` and `human-stage-no-session`.
  Establish human.session with a valid proof and perform a nonmutation read on
  that same shared socket. The negative reads have no bound session, use a
  fresh socket after the first session, use a revoked credential/session, or
  reach the stored idle deadline. A public session ID does not activate a new
  connection. The live service clock and persisted session facts supply these
  conditions; a fabricated expired reply is not a canary.
  Encrypted secret.stage uses that same current read session and carries no
  additional operation proof. Its real broker must validate the ciphertext;
  the no-session control must still refuse.
* PEER adds `peer-brief-own`, `peer-brief-other-life`, `peer-brief-level`,
  `peer-template-other-grants` and `peer-grant-other-parent`. The first renders
  the authentic own-life briefing; the others submit valid request shapes with
  a foreign life, changed level, foreign grant set or foreign grant parent and
  require forbidden before that requested authority is selected.
* TICKET-ONCE adds `ticket-wrong-principal`, `ticket-wrong-config`,
  `ticket-wrong-endpoint` and `ticket-lane-endpoint`. Use the actual issued
  ticket under a different enrolled principal/config/current endpoint or a
  real launched lane endpoint. Each must refuse; issuer/config/endpoint fields
  in issue writes, ticket.issued events and lookup must remain identical.

These additions require 41 operation scenarios plus collection. They retain
all prior IDs and all four red target mappings. Real worker job authentication
is still unavailable in identity; its root-ticket claim refusal has a separate
package fixture and cannot be presented as a successful installed worker test.

Draft.4 preserves exact request/proof files and stable retry keys through common
CLI preparation. Use --binding or --binding-file as aliases, never both. Human
proof confirmation may cross connections only for the same enrolled principal,
class/config/current endpoint and exact operation; read sessions remain bound
to one live connection. Independent CLI processes cannot authenticate reads by
carrying a public session ID. A typed containment_unknown response (CLI exit 75)
can establish a reached peer refusal; missing/stub/deadline/shape failures do
not count as a mutation kill.

Red qualification records every scenario's verdict and actual exit in
identity-observations.json. It requires the named canary to contradict its
expected refusal, permits its independent effect check to change, and requires
all other controls to reach/pass. The exact targets are foreign containment,
process generation, no-proof and assertion replay respectively. Assertion
replay means old signed bytes under a fresh server nonce/challenge ID; reusing
an already consumed proof exercises the separate atomic guard. Invalid plan
expectations are rejected before execution. Unrelated failures, an effect-only
failure, missing scenarios and surviving mutants cannot qualify.

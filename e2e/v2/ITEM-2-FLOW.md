# Item 2 installed client handoff

Round 4 starts from the supervisor-supplied serve2 revision da1586f2. It clears
the secrets case's separate-client transport blocker. It does not certify the
complete installed item-2 case or authenticate a model service.

## Runnable public flow

The secrets case previously selected a separately built human client. The
public client verifies its own executable against the installed binding, so a
different helper artifact cannot be the installed CLI. Separating key, stage
and import into ordinary CLI processes also loses their connection-bound
session and upload state.

The installed human session command now accepts --flow FILE. It opens the
ordinary public client once, establishes its genuine session, then invokes
each retained typed request on that connection. Request IDs and retry keys
remain caller inputs. Mutation proofs come from their files and still reach
the service's normal validation. The flow emits actual request/response
envelopes as JSON lines. It stops at a failed operation and preserves its
original connection owner. Streaming calls retain their separate commands.

The secrets entry now invokes context.binary directly. It publishes each
reply and the existing human-flow.json handoff while the socket remains open,
so the outside coordinator can construct the next sealed request or exact
confirmation. It retains the actual command, stdout, stderr, exit, requests
and responses. The final metadata read uses that same live session.
The incompatible standalone transport helper was removed.

A missing request or proof produces an incomplete typed prerequisite wait.
The case retains the corresponding fixture_preparation or human_confirmation
owner record. A timeout never confirms or completes anything. The public
session recipe is in [v2-cli-session.md](../../docs/v2-cli-session.md).

## Measured controls

TestSessionFlow first failed because the ordinary identity handler did not
accept --flow. Its successful candidate checks multiple public replies,
unchanged request correlation, the same borrowed connection and stop on a
real refusal. Missing request/proof controls require an incomplete typed wait
without dispatching the dependent operation.

The Python test_item2_flow regression first reached the obsolete session_client
requirement. It now checks use of the installed executable, all eight retained
operation envelopes, metadata, evidence hashes and the owner-wait handoff.
These Python transport records are explicit protocol fixtures.

TestSessionWire runs the actual installed-binding client and CLI over native
Unix sockets against the production secrets key/stage owner under an
unprivileged UID. It obtains a real upload key, seals random synthetic bytes,
stages them on the original connection and checks the actual stage receipt.
A Python process runs the actual handoff adapter and the matched CLI. The
outside producer reads its live key reply and supplies the next sealed file
while the original connection remains open.
A new connection cannot reuse that key. Restoring legacy identity dispatch
reached the native test's missing-flow diagnostic, followed by the passing
candidate. Human/session facts are explicit simulated component inputs; this
does not test persistent import, the full installed dispatcher, systemd,
physical human presence or vendor authentication.

External round-4 evidence retains every failed candidate check, functional
red, green, final package run and required candidate-only vet result. No
archive, manifest, Git command, installation or owner message was performed
by this lane.

The broad Linux request reported success for all 32 tested packages in the
named internal/v2 set, but its additional e2e/v2 package failed four Python
harness groups. Focused runs reached stale readiness source references.
The reported NewServer location and the verified one-line shifts in identity
were corrected in the source plan. A later run still stops at
internal/v2/approval/proof.go:46. No readiness statuses or checks were changed.
The broad harness remains failed; further catalog repair belongs to its owner.

## Still required

The installed coordinator must supply genuine confirmations, encrypted stage
requests derived from actual key receipts, exact mutation proofs, launch
inputs, live profile authorization and independent capture/collection facts.
The full SECRET-INJECT and CREDENTIAL-BOUND case has not been measured by this
round. Its vendor and fixture waits remain.

Unbound launch cleanup and independent worker/external collection still need
their original owners. The private grant cascade and sealed lease remain the
sole grant-policy implementation. This round adds no replacement receipt,
collection owner, planner shortcut or security policy. The earlier native
drain recovery handoff remains applicable; installed recovery and complete
item-2 acceptance still need their own run. Child test-worker execution also
remains an explicit unfinished owner path.

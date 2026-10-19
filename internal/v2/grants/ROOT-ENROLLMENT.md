# Protected resource and secret root handles

Root issuance consumes the existing immutable object store contract. A handle
is the ID of a retained manifest object containing one existing ResourceGrant
or SecretGrant JSON object. Its id is empty, parent_grant_id is absent/empty,
and source_handle equals that object's ID. The operator path adds one typed
enrollment proposal/RPC. It uses the existing manifest class and grant shape;
resolution performs no key lookup or credential-material read.

The protected enrollment producer must retain the record with Origin service,
ACL.Config equal to the installed configuration, ACL.Owner equal to the human
principal, no life scope, and immutable ACL.Generation 1. This is the existing
ordinary object writer's supported generation. Updating enrollment requires
a new immutable object/handle; mutable launch-plan generations are refused.
Public blob commits are observations and cannot become enrollment records.
A caller-supplied grant-shaped object, placeholder handle, or root approval
alone is not enrollment.

The operator uses `grants enroll --request FILE` with the ordinary binding,
request/idempotency keys and exact human proof. The RPC is grants.enroll;
its request is CapabilityEnrollmentRequest with exactly one resource or secret
arm, and its reply is the committed manifest BlobRef. The proof targets the
installed configuration at base generation zero. The service infers owner,
configuration and immutable generation; the caller cannot provide those facts.

A resource proposal uses ResourceEnrollment and omits id, parent_grant_id and
source_handle; the service assigns its opaque handle. A secret proposal uses
SecretEnrollment, omits id and parent_grant_id, and names an existing source
returned by secret.import/rotate in source_handle. Issued IDs are not proposal
fields. An explicitly empty or malformed source_handle still fails the wire
ID validator; an operator-chosen resource handle remains rejected. The
approved fields become the existing retained grant shape only inside the
service and writer. The secret source's authenticated native metadata must match
name/version/handle and be live. The store checks the committed source/head
generation and original import event's human owner, and repeats this check
under the enrollment commit lock. Secret material never enters the enrollment
request, object or reply. The native metadata lock stays held through commit.

One proof guard, one service-origin immutable object, one blob.committed event
and the typed reply share the existing Transact path. The store independently
checks exact approved fields, owner/configuration/generation, current expiry
and the committed object correlated to the reply. Refusals roll back record and
proof consumption. Enrollment grants no worker, machine, credential lease or
root set; the separate grants.root approval still selects the returned handle.

The installed grants fixture publishes neither resource nor secret handles
during boot. After its real session it enrolls the resource through the CLI,
uses secret.key/stage/import to commit a freshly generated harmless sealed
canary, and enrolls that secret capability through the same CLI. It reads both
records through authenticated blob reads, checking full hashes, exact EOF and
the returned fields. Only then does it upload the root manifest naming those
actual handles. Initial installation files and manifests are never patched.

The case uses the installed `human session --flow FILE --proof FILE` path for
secret.key, secret.stage and secret.import on one live connection. Upload keys
and staged ciphertext bind principal, connection, read-session and endpoint
generation. Separate human.read CLI processes cannot carry either allocation
between them. HumanSessionRequest has no upload-session kind or reusable ID
credential. The flow takes its key from the real reply, publishes the sealed
request atomically, and waits for the actual stage receipt before preparing
the exact import request and its independent operation proof. Import runs on
that original flow connection too. The sealing helper builds before key
issuance. No secrets owner check or session lifetime is relaxed.

The adapter retains the plan, input files, request/reply trace, stderr, process
ID and exit status. Missing dependent files remain incomplete waits. A typed
refusal stops the flow and is retained as the original error; it cannot select
a new session, substitute a handle, or continue enrollment. Only the owned CLI
process is terminated on interruption, and the service retains its own state.

The root request first passes its unchanged authenticated frame/proof and
immutable manifest gates. Each enrollment lookup opens a current authority
view and checks policy before metadata. Unknown records return not_found;
foreign owner/configuration, observation origin or life scope returns
forbidden; an unsupported immutable generation returns conflict. Wrong
identity/class, malformed payload or mismatched bytes fails integrity. Store
errors other than absent metadata keep their original typed owner and code.

Requested resource provider and handle must match; region/image/machine
selections, concurrency, hourly/total cost, delegation and expiry stay within
the record. Secrets preserve exact handle, name, version, delivery and target,
with no wider delegation or expiry. A nondelegable enrollment can issue a
nondelegable root member. Validation uses the existing grant manifest grammar.

After source/channel reads, issuance refreshes policy and the original live
human scope, then checks the immutable enrollment again before the existing
root transaction. Mixed profile roots retain the encrypted profile journal
lock through that transaction. Both families receive fresh member IDs and
participate in the sealed set's expiry, existing proof guard, grants.issued
event, generation-zero compares and durable typed reply. No lease or effect
is created during root resolution.

TestRootEnrolledCapabilities exercises both families, each alone, narrower
scope, nondelegable enrollment and mixed protected profiles. The declared
component store supplies actual serialized record bytes and metadata; human
transport and enrollment production are unit fixtures. Refusal, read-order
and post-source-change tests require the deciding typed code and no writes.
The mutation catalog restores the original blanket refusal before testing the
unchanged candidate, and removes ownership, scope, generation, provenance,
subset or final recheck gates separately. The box suite retains those proofs
outside the checkout and runs normal/fault-tagged tests as the login user and
under sudo. Definitions and static checks are not runtime GREEN evidence.

The operator tests use the real SQLite store, identity proof guard and native
encrypted source backend. Human assertions/session authority are declared
component inputs. Mutations restore a missing enrollment endpoint and remove
proof, union, chosen-handle, source-owner/generation and writer authority checks.
The r10 source-read recheck test now injects changes during the actual manifest
read rather than an artifact whose bytes are not read during root validation.

TestGrantsEnrollmentInputs exports the actual case request builders as exact
file bytes, then checks them with wire.Decode, CLI PrepareRequest,
wire.ValidateRequest and EnrollmentInput. Its imported secret handle is a
declared random serialization fixture, not enrollment evidence. Producer
controls reintroduce empty issued IDs, empty/malformed source handles, a
caller-chosen resource handle, substituted secret source and invalid delivery.
Each must reach its named decoder, selection or semantic assertion before the
unchanged candidate passes. The cloud transcript retains each request's bytes
as base64 and its digest. This regression does not replace installed-service
proof or change the global nonempty object-ID rule.

TestSessionWire/grants runs the case's actual flow adapter and sealed-canary
producer through the real CLI/client, native peer/frame verifier, registered
secrets decoder and SecretKey/SecretStage owners. Authentication/session facts
are declared component inputs. Its selected plan ends after staging; it does
not credit persistent import, hardware presence or a system installation. The
candidate must also refuse the same actual key/request on a fresh connection
with the exact not_found code and live-session diagnostic. RED controls change
the read session between key and stage, substitute the key ID, and corrupt the
nonce. The full case's import remains in its original flow with an independent
proof. Runtime results require the Linux box suite and installed case rerun.

TestGrantsFlowDispatch closes the additional dispatcher boundary: the shared
case plan, sealed-canary producer and import-input builder pass through the
registered identity/secrets owners and the real dispatcher and SQLite writer
on one bound connection. A generated test key signs actual challenge replies;
confirmation, proof consumption and encrypted import use their actual owners.
Only prior enrollment and peer entry facts are component inputs. Every mutation
must have the exact returned reply in its durable receipt. This adds no hardware
presence or installed-service acceptance claim.

The former secret.stage handler returned only its in-memory receipt. It now
commits that metadata reply and original encrypted frame with the current read
authority, while retaining all key/session checks. The operator-stage-uncommitted
control restores the former return and must reach the dispatcher's exact
integrity diagnostic at secret.stage. The cleanup control requires a failed
commit to leave no retained stage allocation. Both need Linux RED/candidate
results before credit. The union-enrollment fixture now supplies independently
well-formed proposal arms so it reaches the exactly-one-arm semantic gate.

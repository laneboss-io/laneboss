# ORG-APPROVAL

This case runs only on the authorized disposable Linux acceptance machine.
Missing service, identity, renderer, controller, enrolled actor, fixture Clock or
human confirmation is a failed/incomplete run. No product script, test or binary
was executed on the development Mac.

The case is discovered through case.json. Its run.sh entry accepts exactly:

```sh
sh e2e/v2/cases/approval/run.sh \
  --context /test/cases/approval/context.json \
  --result /test/cases/approval/result.json
```

Context and atomic result use the frozen laneboss.e2e-context.v2 and
laneboss.e2e-result.v2 maps in docs/design/v2-lanes.md, including artifact/source
digests, phase/mutation, reached verdicts, command exits, evidence references and
measured collection. Candidate runs every cell. A red context selects the
installed mutation's cell from RED_CELLS in case.py. A setup failure stays
unreached; only the actual selected operation can produce a reached red failure.
A surviving mutation returns pass for that cell and is not a killed mutation.

The former --fixture/--evidence/--cell entry and arbitrary actor/control command
prefixes are removed. The fixture is now data at the fixed path
test_root/approval-fixture.json. Every product call executes context.binary:
the native human observer invokes it directly; authentic L6/L5 operations run
the fixed owned cli_canary.py through the frozen run_confined_canary control.
The case verifies actual binary/job/adapter digests, argv, input bytes, target,
binding, process exit and controller containment evidence. Refusals must be real
api.Error JSON on CLI stderr with exit 2 or 3; an exit-zero printed error
envelope cannot pass.

write_canary.py is a retired standalone helper. It is not invoked by the case,
registered as its measured filesystem job, or retained as its job artifact.
The measured job is write_job.py, selected through run_confined_canary and
checked against the actual native-write observation. red.py may copy the
retired file with the case's source archive; that copied presence is not
execution or acceptance evidence.

## Component and harness tests

Run the exact changed source on Linux:

```sh
go test -count=1 ./internal/v2/approval ./e2e/v2/cases/approval
go test -tags laneboss_faults -count=1 \
  ./internal/v2/approval ./e2e/v2/cases/approval
go test -race -count=1 ./internal/v2/approval ./e2e/v2/cases/approval
python3 e2e/v2/cases/approval/red.py \
  --source . --all --evidence /test/evidence/approval-component-red
```

TestHarnessEntry invokes the real entry in both phases with a deliberately
missing fixture and verifies discovery, an atomic correlated failed result,
unreached setup and independently hashed retained evidence. It cannot establish
installed service behavior. The new handler tests provide a viable deferred
Transact/Await path, including a positive completion, before exercising the
actual apply/approve call-site checks. No dependency stub is a negative pass.

catalog.py names one mutation, selected Go test and required assertion per
distinct guard. CLI JSON, no-follow file, forbidden proof option, operation
proof and session proof recipes now target their actual guards. The four
frozen CLI handler stubs remain separate. Duplicate kind/digest/level recipes
were consolidated without deleting the tests or their acceptance-rule mapping.

red.py changes one production source file in a retained isolated copy, requires
the named assertion to fail, rejects compile errors/panics/unrelated failures,
restores the exact bytes and requires the same test to pass. Its pass covers
only the selected component recipes. --all --require-complete still returns 69
while any installed production row is pending. Static vet and syntax results
never substitute for semantic red and restored green evidence.

See MUTATIONS.md, RECIPE-AUDIT.md and
internal/v2/approval/CONTRACT-GAPS.md for current mappings and ownership.

## Data fixture

The fixture contains no executable command prefixes, credentials, private keys,
bearer cookies, environment snapshots or serialized session authority.

| Field | Required meaning |
| --- | --- |
| contract_revision, config | v2.0-draft.4 and the context's single configuration. |
| org_id, base_generation | Actual disposable main org and current enrolled generation. |
| source_snapshot, ownership_manifest, renderer | Independently supplied approved baseline and exact renderer pin. Ownership class is manifest. |
| canonical_root, canonical_boundary | Absolute outside observer tree; an optional protected generation-pointer boundary. Child symlinks are refused. |
| paths | Existing approved source paths named script, tool, config, template, note and approval_policy. These names are fixture categories, never a product permission list. |
| candidate_files | Optional category-to-file map of schema-valid authored replacements. Otherwise text/shell/TOML/Markdown sources receive fresh harmless comments. The approval_policy candidate is mandatory for that cell. |
| expected_derived | Nonempty exact list of generated effect paths in the main flow. Every effect parent directory must already exist. |
| actors.l6, actors.l5 | target LifeRef, cli_canary_id and the actual protected binding_file visible inside that authentic actor. L6 also names write_canary_id. No argv is accepted. |
| writable_target, writable_observer | Internal and outside paths for the same existing disposable writable file. |
| canonical_target | L6-visible path corresponding to canonical_root/paths.script, enrolled by the independent controller. The native observation must name this exact path. |
| confirm, read_confirm | Each has an absolute executable and its actual sha256. These independent UI helpers produce real ProofRefs only, never product responses. Their executable bytes are retained. |
| controls | Eight isolated disposable org datasets keyed by the cell names below. Each supplies org/base, root/boundary, source_snapshot, ownership_manifest and renderer; paths/candidate_files may override the main data. argv/request_file fields are refused. |
| clock | Where needed, enrolled clock_id, current generation and now timestamp. It selects an injected fixture Clock, never host/OS time or live policy. Shared IDs retain their updated generation across cells. |

The fixture's internal/outside path mapping and org provenance are independently
established by the E2E owner. The case never opens a service database or grants
authority from a role/UID label. It checks actual identity self through the
installed CLI before using either recorded actor.

Source/reason uploads use the closed artifact blob class. Every fetched object
is checked in full against its declared SHA/size with a separate EOF probe.
Canonical snapshots include file bytes/modes, directory/root modes and empty
directories. The exact opaque diff, preimages, after bytes, reason, ownership,
renderer pin and recomputed manifest are retained for the human review package.

## Enrolled controller jobs

Context.controls names the root-owned protected frozen control binding.
harness.py uses bounded four-byte-length framing, verifies the control socket
and SO_PEERCRED UID, and correlates case/artifact/request/nonce/action plus
actual input, target, exit and known zero survivors. Only already enrolled
canary and fixture-clock IDs are selectors. Controller evidence paths, bytes
and hashes must resolve beneath context.evidence_root without symlinks.

The E2E owner installs the exact owned job and harness.py bytes read-only,
enrolls fixed jobs under the authentic actor's current containment/grants, and
passes --settings, --input and --result from that protected registration.
Input is the exact committed artifact BlobRef resolved by the controller,
not a host command or executable selector.

cli_canary.py settings have schema laneboss.approval-cli-job.v2 and fields
binary, binary_sha256, config, binding_file, target and scratch_root. The settings
file is root-owned and unwritable by the actor. The lane binding must be the
fixed sealed inherited descriptor projection at `/run/laneboss/binding.json`;
its socket must be the fixed O_PATH projection at `/run/laneboss/service.sock`.
The adapter validates seals, exact binding/config/artifact/target, socket inode
type/owner/mode and retained descriptor identity, then passes exactly those two
descriptors to the child at their original numbers. A regular JSON copy is not
an installed lane binding. Input has schema
laneboss.approval-cli-input.v2, one of the closed METHODS, base64 Params,
request_id and idempotency_key. The job constructs argv itself, invokes the
hash-verified executable directly with --request/--binding, observes its process
group and removes its private request directory. The controller retains the
real result as approval-cli.json. It returns the actual product exit, including
2/3 refusals. An uncollected process or temporary directory fails the job.

write_job.py settings have schema laneboss.approval-write-job.v2 and a fixed
targets map for workspace and canonical. Input contains only schema
laneboss.approval-write-input.v2, one target selector and base64 payload. It
attempts a real no-follow native write to that registered existing path and
retains approval-write.json with actual target path, attempted/write result,
native errno and exit. The same fresh payload must first change the writable
outside observer, then fail on the actual canonical target. A missing runtime,
wrong target, invalid payload, constant refusal, full disk or unknown
containment cannot pass. The controller retains both job observations and
independently verifies the installed job/artifact identity.

These registration conventions are harness data, not new product API fields
or a general command runner. Missing enrollment fails before the cell is reached.

## Human confirmation

read_confirm receives --config, --request-file containing {}, and --proof-file.
It obtains a fresh real human.session ProofRef. The installed CLI creates the
session and performs its read/upload on the same live socket without attaching
an operation proof to the read. Each CLI process obtains a fresh confirmation;
a copied session ID or ambient cookie never supplies authority.

confirm receives --config, --request-file, --change-file, --review-file and
--proof-file. It displays and checks the actual service-backed UI against the
retained package, then obtains a genuine operation-bound assertion. The case
checks the exact request intent and uses the installed CLI/verifier for actual
authority. The wrong-hash negative fixture must support confirming its displayed
test intent even though that hash deliberately differs from the actual staged
manifest; refusing that setup is not a product red detection.

Credential-free authenticator fixtures establish wiring only. Independent
hardware/live-human evidence is a separate mode and cannot be replaced by this
case or a component fixture. No AI-service sign-in or model request occurs.

## Constructed negative cells

Every final refusal has its own retained exact Params/proof/key/CLI observation
and before/after canonical snapshots. The main org remains unchanged throughout
the isolated negative controls.

| Cell | Constructed defect and independent control | Required real CLI error |
| --- | --- | --- |
| stale | Stage/approve the old change, then stage/approve/apply a separate intervening change and verify its exact canonical effects before submitting the old apply. | conflict |
| wrong_hash | Change one digest digit in an otherwise exact approval body; obtain a real proof for that distinct intent. | conflict |
| extra_effect | Stage/approve, advance the enrolled fixture Clock while approval remains current, then restage the same sources/base/pin and fetch the changed renderer outputs. Actual path/action/mode/bytes/diff must differ; a new object ID alone is insufficient. Apply the original approval. | conflict or integrity |
| expired | Approve, advance the registered Clock past receipt expiry while the stage remains current, and successfully probe proposal authority/base before applying the expired receipt. | forbidden |
| replayed | Approve once, successfully probe the unchanged current base, then reuse the consumed proof with a fresh operation key before its expiry and before application. | forbidden or conflict |
| no_human | Obtain the real shape/intent, then replace the proof ID with an unverified random reference while preserving the exact body, digest and fresh expiry. | forbidden |
| generated_source | A real seed render identifies an existing generated output distinct from the sources. Construct a valid replacement with its actual before SHA/mode and committed after bytes. | forbidden |
| policy_shortcut | Stage actual schema-valid approval-policy source bytes, then attempt approval with an unverified proof under current policy. No invented waiver field or historical approval is used. | forbidden |

The positive flow retains all five source categories and derived outputs,
performs actual human review/approval, verifies publication's exact canonical
effects and generation, and checks dashboard staged/approval/application history.
Same-key same-intent apply must return the original durable receipt; changed
intent under that key must be idempotency_conflict, and a fresh key cannot reuse
the consumed approval.

All currently pending installed mutations still require a coherent production
red artifact from their owning lanes. Pending ownership and runtime dependencies
are explicit in catalog.py and CONTRACT-GAPS.md. This case does not fabricate
those artifacts, start another service, provision a box or claim runtime success.

# Installed item handoff

G0 version 1 is final. These interfaces are shared by the seven case lanes.
Implementation repairs preserve this contract and the frozen case schemas.

The shared exporter lives in `scripts/v2-serve/item_context.py` and
`item_dispatch.py`. A case producer is `case_<id>.py` in that directory.
The serve entry accepts `--item-case <id>` and dispatches before stopping
the installed service. The existing serve checks remain required.
Producers using the existing `HumanRoot` set `case.human_prefix` to
`item<case_id>` while preparing and collecting. Their session, grants,
ticket, read and control challenge/confirmation rows have dedicated
catalog entries, so they cannot overwrite the baseline serve rows.

The producer exports `boot(case)` and `prepare(case, require, fail,
blocked)`. Boot runs before installation and returns a dictionary with
`bundle` and `assets` members. Bundle accepts additional `documents`,
`sources`, `contexts`, `projects`, `root_grants` and `budget`. Documents
contain `ref` and base64 `data`; references must match their exact bytes.
Sources use the assembler's `id`, `path`, `kind` and base64 `data` shape.
Contexts contain level and role. Assets contain `id`, `role`, `file` and
`mode`; their files are measured and enrolled before publication hashes
are calculated. No late manifest edit is supported.
`root_grants` supplies the explicit case families and additional data;
the baseline project's workspace data remains in the assembled root.
All extra role sources, contexts, projects, objects, budgets and grants
still pass the existing typed product validators. A producer may declare
`AGENT_PACKAGE` to select its own measured vendor stand-in executable.
That executable implements the existing serve fixture invocation and
version declaration, emits the real reserved session fields, and uses
the normal installed client inheritance helper for all lane RPCs.

Prepare runs after publication and human enrollment, while both units
are active. It returns `binding_file`, `profile_grant_ids`, `collect`,
and optionally `inputs`, `populate`, `environment`, `controls`, phase
fields and `transport`. Inputs maps leaf filenames to exact bytes.
Populate is called as `populate(context)` after scope allocation and
returns more such inputs; duplicate or reserved filenames fail.
Binding is an absolute
canonical metadata file; a confined actor retains its original sealed
binding and socket. Transport is a case-owned adapter, never authority
made from copied metadata. Collect is a callback invoked after the entry
has finished, including on failure, as `collect(context, operation_ids)`.
For consumers that require the receipt before writing their result, the
same outside callback is available through the private observer channel;
the post-entry call reuses its verified receipt. It returns both
collection flags, nonempty evidence and actual managed operation IDs.
The dispatcher validates and retains that independent receipt separately
from the public result. Unit shutdown alone supplies no case credit.
The public entry runs in its own systemd scope. After it exits, the
dispatcher independently stops any remaining scope tasks and records
the real cgroup inventory or absence as `entry_collection`. That
observation is required in addition to worker and fixture collection.
Evidence references use paths relative to `context.evidence_root` with
the actual SHA-256 and byte count. Producers stop mutations at a native
refusal and report incomplete collection. They also export
`abort(case, require, fail)` for the enclosing serve finally block; it
returns a list of remaining collection problems, never invented success.

Transport receives an object with `action: rpc`, the space-separated
`command`, typed `request`, `denied`, `request_id` and `idempotency_key`.
It returns the actual `exit_code` and base64 `stdout` and `stderr`.
The optional channel is a private local Unix socket with a peer-UID check
and a per-invocation token. It supplies no authority to a product RPC.
The producer must retain the original actor transport and correlate its
real responses. No transport callback means no observer socket is made.

`item_context.create(case, case_id, binding_file, profile_grant_ids)`
creates canonical sibling input/output directories, returns the context
dictionary and its file path, and hashes the retained complete source
and installed binary. The context contains exactly the twelve fields
defined in `e2e/v2/manifests.py`; candidate mutation ID is empty.
Optional controls use only that reader's existing extension. Context and
result files live inside the input directory; evidence lives in the
separate output directory. No socket is copied as a fixture file.
The complete source inventory is checked against its retained archive
and staged bytes before the context is emitted. Red invocations supply
`phase: red`, a nonempty `mutation_id`, `red_assertion` and, when needed,
`red_check`; they use a separately installed and retained mutated artifact.
Candidate invocations use the default phase and empty mutation ID.

`item_dispatch.run(case, case_id, prepared)` invokes the manifest entry
with `--context` and `--result`, retains stdout, stderr, argv and exit,
and uses the frozen result validator. Python entries use Python; shell
entries use their declared shebang interpreter. Explicit environment
additions are private input, never printed. All declared assertion IDs
must be reached and pass. A missing result, failed collector or typed
owner refusal remains failed. Case results never replace serve rows.

Grants uses a local observer adapter to a real L5 process. Requests are
delivered through authenticated public mail; replies are read from that
process's primary capture. The L3 process commits its own candidate and
worker-plan objects before exiting. The outside observer executes the
compiler control and verifies actual helper and workspace collection.
This is a credential-free declared vendor fixture. It proves no vendor
authentication, live model turn or hardware approval.

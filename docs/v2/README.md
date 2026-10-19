# Laneboss v2 operator guide

Laneboss runs a tree of supervised agent tasks. Each task runs in a **lane**.
A lane has a level, a role, a budget and explicit access to data and accounts.
Use it when several agents need separate workspaces and a clear reporting line.
This guide is for the person who installs the service and operates that tree.

In v2, one service owns the data for a named configuration. State commands send
requests to that service over a Unix socket. The CLI reads local input files and
transfers their bytes. It does not open a second writable state database.
The administrator helper performs fixed privileged setup operations. The state
service runs as a separate, unprivileged account.

On Linux, lanes use separate identities and containment. The selected backend is
`linux-bwrap-landlock`. It combines bubblewrap namespaces, Landlock and cgroups
with service checks. A lane receives its granted workspace and runtime inputs.
It does not receive the service's writable state or the owner's whole home.
An agent's policy verdict does not replace that operating system boundary.
<!-- source: internal/v2/client/client.go; internal/v2/service/host.go; internal/v2/assembly/platform_linux.go; internal/v2/admin/spec.go; docs/design/isolation.md -->

## Read these pages in order

| Page | What to do with it |
| --- | --- |
| [Install on Linux](install-linux.md) | Prepare the protected boot bundle, install the units, enroll the first human and run doctor. |
| [First lane tutorial](tutorial.md) | Publish the first org setup, obtain root authority and follow one lane through messaging, stop, archive and clean. |
| [Operate lanes](lanes.md) | Choose levels, inspect events, delegate grants and understand secrets and account switching. |
| [Policy and owner approval](policy.md) | Inspect blocklists, judge results, guidance and exact org changes. |
| [Migration from v1](migrate-from-v1.md) | Read the draft migration order and the questions still assigned to the migration implementation. |

## Status of this guide

These pages describe source revision `d7403ec`. The wire protocol is
`laneboss.rpc.v2`, schema 2, with contract revision `v2.0-draft.4`.
The CLI still labels its implementation `v2-incomplete`.
<!-- source: internal/v2/api/base.go; internal/v2/cli/cli.go -->

The task brief reports an installed Linux E2E at step 42 of 78. It passed
installation, enrollment (with the test authenticator build), first org publication and sessions. It stopped at the
first lane start. That report does not verify a complete lane or a real security
key ceremony. These documents add no new installed-service measurements.
Lane start and every later tutorial step carry this warning:

Not yet verified on an installed service.

There are also source-level composition gaps. For example, assembly constructs
the migration module, whose constructor still returns `not_implemented`.
Assembly also omits the positive inference cost ceiling required by the policy
constructor. A service built from this snapshot can stop before it listens.
Preserve that failure and wait for the owning implementation. Do not remove a
module or weaken a check to continue the tutorial.
<!-- source: internal/v2/assembly/assembly.go; internal/v2/migration/stub.go; internal/v2/policy/service.go -->

## How to read the commands

Use the matched installed v2 executable as `laneboss`. Check its command list
and version before sending state requests:

```sh
laneboss --version
laneboss --help
```
<!-- source: internal/v2/cli/cli.go -->

Version output includes `program`, `version`, `protocol_version`, `api_protocol`,
`implementation` and `contract_revision`. Compare the artifact and contract with
the administrator's release manifest. A matching version string alone does not
prove matching executable bytes.

Uppercase words in command blocks are **metavariables**. Replace them before
running a command. `NAME` is the same installed configuration throughout.
`FILE`, `START_REQUEST` and similar words mean operator-supplied files, not
shipped sample paths. `LIFE_ID`, `RUN` and `GENERATION` come from real service
responses. Never invent their values. Commands in a block run one at a time.
Stop at the first nonzero exit.

Every state command needs an explicit `--config NAME`. Keep an active session
bound to that configuration. Use a separate process for another configuration.
The default human binding is `/etc/laneboss-v2/bindings/NAME.json`. Inside a lane,
the client can use the projected `/run/laneboss/binding.json` instead.
<!-- source: internal/v2/cli/cli.go; internal/v2/client/client.go -->

The common `--request FILE` form takes the exact JSON **params object**, not a
whole RPC envelope. The CLI adds the envelope. Inputs are bounded regular files.
Unknown fields and duplicate JSON fields refuse. A blob reference has `id`,
`sha256`, `bytes` and `class`. Those fields identify committed bytes; they are
not a local pathname.
<!-- source: internal/v2/cli/cli.go; internal/v2/api/common.go; internal/v2/api/json.go -->

A mutation needs a retained `--idempotency-key`. Generate at least 128 random
bits, encoded as 22–128 letters, digits, underscores or hyphens. Keep that key
with the original request and response. Retry an interrupted request with the
same key and bytes. Use a new key for a new decision. A key is not permission.
Common options also accept `--name=value`. Pass a key beginning with `-` as
`--idempotency-key=KEY` so its exact bytes remain the option's value.
<!-- source: internal/v2/client/prepare.go; internal/v2/cli/cli.go -->

Human reads need a verified session. Human control mutations need fresh proof
for that exact operation. [The tutorial](tutorial.md#3-prepare-human-authority)
explains the distinction. Keep proof files private. Never put credential values,
private keys or account names into briefs, examples or logs.

For failures, retain stdout, stderr, exit status and the request bytes separately.
CLI errors on stderr have `code`, `message`, `instead` and `retryable`, with
optional `owner` and `operation_id`. Follow the returned `instead` route.
Exit 69 means unavailable, unsupported, missing prerequisites or unfinished
implementation. Exit 3 means integrity failure. Exit 75 means a deadline or
unknown containment. Other typed refusals normally exit 2. Exit 70 means the
client could not encode its error. None is a passing check.
<!-- source: internal/v2/api/base.go; internal/v2/cli/cli.go -->

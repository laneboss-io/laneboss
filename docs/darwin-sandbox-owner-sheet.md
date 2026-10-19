# Owner Terminal sheet: macOS lane sandbox, option A

The owner runs this sheet from a new, unbound Terminal.app window at 08:00.
No agent runs these commands on the workstation. Do not run the sheet through
Codex, Claude Code, an agent tool shell or another already-sandboxed process.
The earlier `sandbox_apply: Operation not permitted` result was an application
failure, not a passing protection or mutation row.

Use the lb-svc-sandbox checkout as the current directory. The commands build the
actual tagged launcher and run executable stand-ins named codex, claude and
claudock. No real AI runner, authentication, model request, service user, daemon
installation or sudoers change is needed. The HTTP server is a temporary thread
inside the checker. The launcher uses `tmux -S` with the row's unique
configuration/state-derived socket and `-f /dev/null`. A recording wrapper
executes the real tmux, rejects any other socket/config flags and retains the
actual command names and socket verdicts. It never uses the default/shared
server or touches another configuration's sessions. All fixtures and lane
records are retained for review.

Type these commands in order. Stop at a nonzero exit or a FAIL line. Do not
change or clear an existing session binding to make the sheet run.

```sh
test -z "${LANEBOSS_CONFIG:-}"
test -z "${LANEBOSS_LANE:-}"
test -z "${LANEBOSS_INSTANCE:-}"
test -f cmd/laneboss/main.go
mkdir -p /private/tmp/lb-svc-sandbox
GOCACHE="/private/tmp/lb-svc-sandbox-cache" GOTOOLCHAIN=local go build -trimpath -tags laneboss_faults -o /private/tmp/lb-svc-sandbox/laneboss ./cmd/laneboss
python3 e2e-rows/darwin_sandbox_rows.py --binary /private/tmp/lb-svc-sandbox/laneboss --evidence "/private/tmp/lb-svc-sandbox-proof"
```

The inputs are the supplied launcher, `e2e-rows/darwin_sandbox_rows.py`,
`e2e-rows/sandbox_standin.py`, `e2e-rows/sandbox_tmux.py`, and the tiny Go module under
the lane sandbox's `testdata/ordinary-go/` directory. Each row is a separate isolated
process with its own temporary HOME, Laneboss configuration/state homes, claims
registry, org, repository and lane. It never changes the Terminal session's HOME
or binding. It records actual CLI exits and bytes before parsing them. The
stand-ins receive and read the actual rendered lane brief.
Every Claude fixture seeds the org setting with `sandbox.enabled=true` and
renders it again. The non-opted macOS row keeps that setting and its own sandbox;
opted Claude/Claudock rows get a per-run false overlay while source bytes stay
protected. Additional rows place `org_dir` outside both launcher roots and
attempt writes to its org and instance definitions as well as hook settings.
SDK session writes must still succeed in these external-org rows.

For every provider, both the start event and `lane status` must contain:

```text
runner sandbox: replaced by laneboss lane sandbox
```

The runner log must contain the corresponding actual mode verdict:

```text
STANDIN sandbox off: codex
STANDIN sandbox off: claude
STANDIN sandbox off: claudock
```

The complete successful checker output is:

```text
PASS org-sandbox-preserved: non-opted macOS
PASS protection: codex
PASS ordinary-work: codex
PASS runner-own-sandbox-off: codex
PASS other-configuration: codex
PASS tmux-isolated: codex
PASS protection: claude
PASS ordinary-work: claude
PASS runner-own-sandbox-off: claude
PASS other-configuration: claude
PASS tmux-isolated: claude
PASS protection: claudock
PASS ordinary-work: claudock
PASS runner-own-sandbox-off: claudock
PASS other-configuration: claudock
PASS tmux-isolated: claudock
PASS external-org: codex
PASS external-org: claude
PASS external-org: claudock
MUTANT KILLED drop-denies: protection row failed
MUTANT KILLED broad-home: ordinary-work row failed
MUTANT KILLED drop-home: other-configuration row failed
PASS empty-home: full-access runner not started
PASS: darwin sandbox owner rows
```

Exit 0 and every line above are required. Protection checks attempted writes to
the rendered hook settings and launcher state, with the same-account
unsandboxed write controls succeeding first. The ordinary-work result requires
real Go test/build, a Git commit with the actual proof bytes in the worktree,
writes to `/tmp` and `~/.cache`, a local curl returning the served source bytes,
and vendor-home session writes. Protection also covers another configuration's
state and the whole Laneboss home. The empty-home row must end with exit 125
before executing the stand-in. A fake pass line cannot replace any of them.

The drop-denies row uses the supplied binary's `laneboss_faults` instrumentation
at the actual profile generation point and requires its reached marker. The
broad-home row uses the real `[lanes] sandbox_deny_extra` setting. The drop-home
row must write both cross-configuration canaries while selected policy remains
protected. The broad-home failure must be an actual denied SDK session write.
A failure to execute the stand-in, a missing replacement record, a setup error,
an enabled runner sandbox or an unrelated exit cannot kill a mutant.

Examples of wrong output are:

```text
FAIL: PROTECTION ROW FAILED: codex
FAIL: ORDINARY WORK ROW FAILED: codex
FAIL: drop-denies mutant did not fail protection for the right reason
FAIL: broad-home mutant did not fail ordinary work for the right reason
FAIL: NON-OPTED MACOS PRESERVATION ROW FAILED: claude
FAIL: EXTERNAL ORG ROW FAILED: claude
FAIL: TMUX ISOLATION ROW FAILED: claude
```

A checker setup/execution failure also exits 1 and retains its raw stderr; it
does not produce the final PASS line. In particular, `sandbox-exec:
sandbox_apply: Operation not permitted` means the row did not enter the runner.
Read the saved output instead of retrying from another agent shell.

Review the retained per-call stdout/stderr/exit files, profile mutation marker,
lane logs and events, `row-spec.json`, worktree proof, commits and verdicts.
The checker retains worktrees and branches because their changes are evidence;
collection follows the supervisor's review. Archive with macOS metadata
disabled, keep the executable bytes and source inputs, and verify their hashes.
This is a credential-free stand-in proof, not an authenticated AI-service test.

The Linux preservation control and mutant are prepared for an authorized
existing Linux box with Landlock, the tagged launcher and these retained inputs.
They are not run on this Mac and do not prove outer Linux enforcement. From that
box's checkout, with the supplied binary at `/tmp/lb-svc-sandbox/laneboss`, run:

```sh
python3 e2e-rows/darwin_sandbox_rows.py --native-only --binary /tmp/lb-svc-sandbox/laneboss --evidence /tmp/lb-svc-sandbox-native
```

The required lines, all with exit 0, are:

```text
PASS org-sandbox-preserved: linux
MUTANT KILLED unconditional-render: Linux preservation row failed
PASS: Linux Claude preservation rows
```

The control starts a real lane with the org setting on and requires the
stand-in's genuine inner Landlock apply. The tagged mutant restores the old
unconditional renderer injection. Its reached marker, changed effective mode,
ordinary work and absent replacement record are required before it can be
counted as a failed Linux preservation row. A setup/exec failure cannot kill it.

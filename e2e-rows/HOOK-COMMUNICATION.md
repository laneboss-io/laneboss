# Communication through the installed org hook

Run these rows only on the authorized disposable Linux test machine, using
already built executables. They contact no AI, Discord or owner service. The
real launcher starts credential-free L3 stand-ins; their descendants invoke the
hook command read from each provider's rendered settings. In this unified
release that is `laneboss org hook`, the same handler as the retained
`laneboss-org hook` entry point. Only an actual hook allow permits execution of
the identical Bash command. Setup and cleanup invoke the real CLI independently
of the selected hook mutation.

The three original long method names were shortened without scan exemptions.
All source, inputs, outputs and evidence must be retained outside the checkout.
`LANEBOSS_ROW_EVIDENCE` is mandatory. The row copies its private fixture,
requests, raw responses, generated settings, input documents, row sources,
syntax source, tested binary bytes and binary digest there before cleanup.
The box driver must also retain the source/build archive, command transcript,
process exit and compiler/toolchain identification. An empty directory or a
successful setup is not passing E2E evidence.

Archive the build inputs and build both executables on the box:

```sh
tar -czf /tmp/lb-comms-hook-source.tgz go.mod go.sum cmd internal e2e-rows docs/org-hooks.md
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o /tmp/lb-comms-hook-bin ./cmd/laneboss
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build -tags laneboss_faults \
  -trimpath -buildvcs=false -o /tmp/lb-comms-hook-faults ./cmd/laneboss
sha256sum /tmp/lb-comms-hook-source.tgz /tmp/lb-comms-hook-bin /tmp/lb-comms-hook-faults
```

Each command must succeed before the next command starts. Keep the printed
hashes and the bytes they name. Builds and unit/runtime checks never run on the
Mac used to edit the source.

## Blacklist contract and retained boundaries

The org hook has one behavior: blacklist. The deprecated `strict` source
spelling uses that same behavior and emits one deprecation warning when
rendered or validated. Tool declarations do not grant permission. A parsed
Laneboss call without a `hook` annotation is allowed and its callback records
`inspection_complete: false` with the incomplete-inspection notice, unless a
retained denial matches.

`test_all_other_verbs` derives the unannotated calls from the grammar. Its
org-directory and database inputs deliberately name protected fixture paths;
their declared writes still require the exact
`[blacklist:laneboss-files] Refuses:` reason. Other parsed unannotated calls
must be allowed with an incomplete receipt, and none of these grammar probes
execute. Unknown options and unparseable argv remain refused.

The old `orghook-cli-drop` mutant-table entry is removed: losing effect
coverage alone must no longer deny report/send. The communication rows still
execute their allowed commands and check real delivery, bytes, actors and
collection authority. Removing a syntax annotation is no longer a valid
permission-denial mutant. No runtime result is claimed by this source update.

## Controls available in this revision

```sh
GOTOOLCHAIN=go1.26.0 go test -count=1 ./internal/orghook ./internal/cli ./internal/peers
GOTOOLCHAIN=go1.26.0 go test -count=1 -tags laneboss_faults \
  ./internal/orghook ./internal/cli ./internal/peers
LANEBOSS_BIN=/tmp/lb-comms-hook-bin \
  LANEBOSS_ROW_EVIDENCE="/tmp/lb-comms-hook-control-evidence" \
  python3 e2e-rows/test_orghook_communication.py \
  OrgHookCommunicationRows.test_report_hook \
  OrgHookCommunicationRows.test_send_hook \
  OrgHookCommunicationRows.test_supervisor_delegation_hook \
  OrgHookCommunicationRows.test_stdin_and_wrappers \
  OrgHookCommunicationRows.test_read_views \
  OrgHookCommunicationRows.test_help_and_version \
  OrgHookCommunicationRows.test_all_other_verbs \
  OrgHookCommunicationRows.test_shell_guards \
  OrgHookCommunicationRows.test_ordinary_tool \
  OrgHookCommunicationRows.test_external_effects \
  OrgHookCommunicationRows.test_installed_scope \
  OrgHookCommunicationRows.test_cli_identity \
  OrgHookCommunicationRows.test_secret_input -v
```

These checks must exit 0. Run the same selected rows against the tagged binary
without a mutation selector as a second control. The private fixtures are
collected by lane stop/mark/clean and release their directory claims.

| Row | What makes it fail |
| --- | --- |
| `test_report_hook` | A hook denial, failed command, missing dashboard delivery, altered text, wrong sender/supervisor or wrong lane actor. |
| `test_send_hook` | A hook denial, failed command, missing mail, changed bytes/digest or wrong sender/actor. |
| `test_supervisor_delegation_hook` | Either provider denies the literal L4 child start, the same command fails to start a real L3 runner, the event loses the L4 starter/actor, the L3 clean loses its exact CLI authority refusal, or an obscured start loses its established hook refusal. |
| `test_stdin_and_wrappers` | Literal joined options, standard-input messages or the ordinary command/nice wrapper stop working, or delivery loses the lane actor. |
| `test_read_views` | A permitted view is denied or fails, returns the wrong lane/decision, or appends an event. |
| `test_help_and_version` | A declared help/version call is denied, fails, or returns the wrong output kind. |
| `test_all_other_verbs` | A parsed unannotated call is refused solely for missing coverage, its incomplete receipt is absent, a declared protected write loses its exact built-in refusal, or any grammar probe executes. |
| `test_shell_guards` | A substitution, context/environment override, detaching wrapper, unknown output option or out-of-worktree redirect is allowed or loses its established reason. A state-directory redirect must not inherit the adapter's state scope. |
| `test_ordinary_tool` | An ordinary supported cat call is denied, fails or returns changed bytes. |
| `test_external_effects` | Report file channels or decision recovery outside the configuration state directory are allowed. |
| `test_installed_scope` | The checked state effect or ordinary worktree write is refused by a legacy positive scope, or a direct hook-policy write loses the exact protected-file refusal. |
| `test_cli_identity` | The actual CLI accepts an unidentified reporter or stores a report from it. |
| `test_secret_input` | A protected report input is allowed, or the ordinary public-input control is denied. |

The delegation row reads the L4 hook commands from an instance rendered by the
supplied CLI. It invokes each command from a recorded L4 runner descendant,
executes the identical literal child start after the allow, and checks both
`lane.started` provenance and the child's recorded live runner identity. Its
literal start includes an instance overlay and two distinct `--set` values.
Removing `--instance` or the repeatable `--set` syntax also turns this row red.
The L3 clean call must pass the hook and then exit 2 with the CLI's exact collection
authority refusal; the child worktree and absence of `lane.cleaned` are checked.
Unknown options, nohup, env -C, env assignments, substitutions and variables are
denied before execution, with their established reasons.

Effect annotations remain useful for inspecting state writes and input reads.
The delegated start's protected `--brief` input must still be checked, and
unknown flags, wrappers, substitutions and redirects keep their established
denials. The literal start, its checked reads, and the CLI's own authority
remain runtime assertions; an annotation is never an allowlist entry.

## The explicit --ask gate

`lane send --ask` arrives with the decision-guide integration. This revision's
`syntax.json` has no flag for it. Its row is written now, but the named
`require_ask_syntax` assertion fails before any lane is created, with:

```text
ASK SYNTAX MISSING: lane send in internal/cli/syntax.json has no --ask flag; the decision-guide integration is required
```

```sh
LANEBOSS_BIN=/tmp/lb-comms-hook-bin \
  LANEBOSS_ROW_EVIDENCE="/tmp/lb-comms-hook-ask-evidence" \
  python3 e2e-rows/test_orghook_communication.py \
  OrgHookCommunicationRows.test_ask_hook -v
```

The expected exit is currently 1 at that named assertion, never a skip or a
pass. The source archive and captured transcript preserve this guard input and
output even though no lane fixture is created. Running the entire module also
fails on this gate. Selecting the implemented controls above states their scope
explicitly and does not convert the full suite into a pass.

After integration adds the real CLI flag to the same syntax source, the row
continues through both providers' hooks and executes the actual `--ask` command,
then checks delivery of a unique unanswered question with the lane actor. The
adapter consumes the new declared flag without an option-list edit. Decided
question echoes require the integration's own decision-guide rows; this lane
does not claim that missing feature was tested.

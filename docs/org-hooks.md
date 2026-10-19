# Org hook policy

Laneboss has one synchronous `PreToolUse` hook for Claude and Codex. The hook
observes the call, records a callback receipt, and applies the blacklist of the
org that owns the caller. The hook has one behavior, blacklist: a call is
allowed unless a deterministic blacklist pattern or a TypeSafe judgement says
that an applicable entry matches. An unknown program, interpreter, script,
pipeline, or command whose file effects cannot be inspected is therefore
allowed and recorded with `inspection_complete = false`.

Malformed hook events, an unknown instance, and an unreadable policy remain
hook errors. A hook error is a refusal because there is no trustworthy caller
or policy to observe. The refusal includes an `Instead:` route and must be
reported verbatim.

## The org configuration

Blacklist entries are authored in `.laneboss/org.toml`. `org init` writes the
default mode and the [laneboss-provided tasks pack](#laneboss-provided-tasks).
Edit this source file with the supervisor's file tool, then run
`laneboss org render ORG`; `render` validates the source and
regenerates the runner settings and manifests. Shared and level
`hooks/rules.toml` and refusal descriptions are optional owner-authored sources;
init creates none. Render makes installed policy sources read-only; use the
supervisor's file tool to edit them and render again. Runner registries,
settings and manifests are generated files.

## Laneboss communication and views

Every Laneboss command written plainly and fully parsed against the embedded
CLI grammar passes the hook unless a blacklist entry matches, its form is
obscured, or its declared effects write protected files. The CLI decides the
caller's authority: passing the hook grants no lane, account or policy authority.
A missing `hook` annotation does not refuse a command. Such a call is recorded
with `inspection_complete = false`. Each path-bearing argument has a `hook_path`
effect in `syntax.json`: input files and org/workspace reads reach secret-read
checks; outputs, archive destinations, org/workspace writes and database
sidecars reach protected-file and L3 worktree checks. Judge `NAME=FILE` subjects
inspect the file part. Path-valued instance selectors are reads; bare instance
names select implicit org policy. Review `--path` is recorded metadata, not a
content read, and still receives the secret-name check. These declarations do
not inspect arbitrary effects inside an unannotated implementation. Protected
roots and write targets use the same physically resolved spelling, including
missing roots beneath symlinked parents.

The argv adapter parses the dispatcher's embedded `internal/cli/syntax.json`;
it has no separate command-option inventory. Reviewed `hook` annotations in
that source provide fuller state and input-effect inspection for some commands. The
unified executable and the retained `laneboss-org` executable initialize the
same grammar. A missing grammar refuses every Laneboss call. New literal flags
declared for lane send are parsed automatically. The rendered report line
advertises `--ask` only when that same grammar declares it.
Lane start also declares the CLI's `--instance NAME` overlay, repeatable
`--set KEY=VALUE` overrides and repeatable `--touches` values. Their semantics
and delegated grants are still checked by the CLI. Truly unknown flags remain
opaque and refused.

Pass the bound configuration explicitly on state commands. The adapter loads
that configuration and names its physically resolved state directory. Its
declared CLI writes receive scope only there, including through the L3 worktree
boundary; explicit protected-path policies continue to apply. Input files keep
their ordinary read and secret-file checks. The adapter does not resolve the
sender: the CLI continues to enforce identity, report routing and permitted
peer relationships and lane authority. Start and adopt declare `--brief` reads;
resume declares `--message` reads. Attach reads typed messages from standard
input, follows the recorded state/logs, and can queue mail, start turns and stop
the turns it started, so its annotation declares state writes rather than a
read-only view. These calls grant no general shell access to another worktree.

These are potential file effects, including SQLite journal recovery during
read-only views. A database outside the named state receives ordinary write
checks, including the L3 worktree boundary. The adapter conservatively checks
every configured report file channel because
the CLI selects its channel after authenticating the caller. This does not grant
writes into the configuration or org directories.

Shell redirects remain ordinary writes, separate from the adapter's state
effects. A redirect into the state directory does not inherit that scope.
Variables, substitutions, environment overrides, wrappers that change context,
detaching wrappers and all other forms already refused by the shell inspector
stay refused. Ordinary supported tools retain their previous behavior.

The credential-free Linux rows and restoring-mutant commands are documented in
[HOOK-COMMUNICATION.md](../e2e-rows/HOOK-COMMUNICATION.md). They run the hook
command taken from each provider's rendered settings, then execute the identical
shell command only after an allow and verify actual delivery with the lane actor.

The command inspector accepts literal read-only sed print and substitution
scripts. In-place flags, write and execution commands, script files, r/R reads,
blocks, branches and uncertain grammar remain opaque. Every accepted input file
uses the same read and secret rules as cat. The head, tail, wc, grep, nl, cut and
sort adapters inspect known options and reject unknown forms. Sort output and
explicit temporary directories are writes; pattern files and random sources
are reads. Expansion metacharacters stay opaque where literal quoting cannot
be proven.

The one entry schema is:

```toml
[hooks]
mode = "blacklist" # the only behavior

[[hooks.blacklist]]
id = "publish"
description = "Pushing changes to a remote from a supervising level."
band = "refuse" # "warn" records guidance and allows the call
argv_prefix = ["git", "push"]
instead = "Leave the changes local for review and ask the supervising level to publish them."

[hooks.blacklist.applies_to]
levels = [5, 6]
roles = ["top", "supervisor"]
```

An entry must have a plain-language `description` and a `band`. A deterministic
matcher or a `decision` reference is optional; a description-only entry is
judged by TypeSafe. The old `refuses` field is not accepted: put the refusal
wording in `description`. `argv_prefix` is one positional argv prefix; shell
operators are rejected as pattern words. `argv_words` is a nonempty array of
literal words: its first word must equal the basename of the normalized
executable, and each remaining word must occur in order as a whole argv word
after it. Options may occur before or between these words. The matcher does
not search substrings, split quoted arguments, use glob patterns or combine
words from separate commands. For example, `argv_words = ["codex", "exec"]`
matches `codex -c k=v exec` and `/opt/tools/codex -c k=v exec`, while
`git commit -m "codex exec"` does not match because its program is Git.
`argv_words` rejects shell operators and cannot be combined with `argv`,
`argv_prefix` or `pattern` in the same entry. `path_glob` uses the existing matcher
against a resolved path and its basename. `tool` matches the runner's actual
tool name; Codex's `functions.` prefix is removed before matching. `decision`
and `job` references guide the same TypeSafe path. A rule without `applies_to`
applies to every level and role.

Set `pattern_only = true` to evaluate an entry only through its deterministic
matcher. It requires an argv prefix, `argv_words`, path or tool matcher and cannot carry a
`decision` or `job` reference. The default is false, preserving existing
TypeSafe scoring for authored entries. A pattern-only entry is never submitted
to TypeSafe and adds no judge-unavailable warning to an unrelated call.
Descriptions remain required refusal text. `org blacklist try` still lists the
entry's pattern result, with a null score and `judge_band = "not-applicable"`.

Layered settings also validate `secrets` as an alias for `secret_names`, paths
relative to the org root, optional `worktree`, and bounded `allowed_tools` and
`writable_repos` values. Instance lookup walks upward to
`.laneboss/instances/NAME`; rendered hooks pin identity with `--instance`.
Actual runner specifications in `instance.toml` are checked when present,
otherwise the generated registry is checked. Shell wrappers, missing settings,
another instance's settings, hook-disable switches, and Codex hook overrides
are refused.

`allowed_tools`, `tool_allow_add` and legacy `tool-allowlist` rules are recorded
compatibility data and never restrict hook calls. `tool_deny_add` remains the
union of defining layers. Command-pattern denials, explicit write deny paths,
secret-read checks and applicable blacklist job and decision entries still apply.

## Rule data

Each present shared/level `hooks/rules.toml` has `schema_version = 1` and a `rules`
array. A missing file means that layer has no rules, without an error or warning;
an existing empty file must explicitly say `schema_version = 1` and `rules = []`.
Unreadable or malformed files still refuse. The hook validates every
referenced refusal before allowing anything and evaluates shared rules, level
rules, then instance rules.

When caller resolution for a named configuration fails, including a lane label
with no matching recorded lane, layered tool checks refuse before
applying any additions. The first reason line is
`org hook fails closed: layered tools cannot resolve their caller`, followed by
the refusal scope and an `Instead:` route. An environment label does not supply
the authenticated starter or its grants.

```toml
schema_version = 1

[[rules]]
id = "workspace"
kind = "write-scope"
paths = ["{writable_repos}"]
deny_paths = ["{hook_paths}"]

[[rules]]
id = "publish"
kind = "command-pattern"
patterns = [["git", "push"]]
```

Write roots use resolved component containment, including symlinks. Denied
paths protect ancestor removals and replacements. `{hook_paths}` includes the
org configuration, shared and level hook/refusal directories, decision-guide
services, the installed hook package, and instance policy files. Instance state
directories remain outside this protected set where layered settings require
ordinary state writes.

## Effective blacklist

Run `laneboss org blacklist list` first inside a lane to read its current rules in plain words. The command authenticates the calling process and detects its org, level, role and instance, then uses the hook's effective entries and scope filters to show each ID, refusal or warning band, description, `Instead:` route and source file, followed by built-in protections; `--format json` exposes the same list. It executes no sampled command, calls no judge and writes no callback receipt. The generated brief points to this command and lists absolute blacklist source paths in hook order, current at the start of that run; resume and turn refresh the paths. Human `org blacklist try --config NAME -- COMMAND...` previews retain their existing behavior.

An instance's effective blacklist is the union of the org-wide
`[[hooks.blacklist]]` entries, its own `(level, role)` source's `[[blacklist]]`
entries, and entries from **every role at every higher enabled level**. For
example, an L3 executor receives its L3 executor entries plus all L4, L5 and L6
role entries. An L3 reviewer does not receive the L3 executor's entries. An L6
instance receives no entries from lower levels. An L5 reviewer entry applies
to that L5 reviewer and all roles at L3 and L4; an L5 peer role does not inherit
it. Built-in fallback roles contribute no entries of their own.

Only org-owned `.laneboss/L<N>/roles/<role>.toml` sources add role blacklist
entries. They use the same schema, `refuse`/`warn` bands, `Instead:` route,
argv-prefix matching and optional scope filters as org-wide entries. Existing
org-wide `applies_to` filters remain in force. `pattern_only = true` requires
a deterministic matcher and omits that entry from TypeSafe judging. A role
refusal includes its entry ID and defining pair, for example
`[review-domain-publish] Refuses: ... [source: (L5, reviewer)]`.

Rendering validates the complete org role catalog and prepares the same hooks
for both runners. The hook and `org blacklist try --level N --role ROLE` load
the effective entries from source. Malformed entries and IDs duplicated
anywhere in the org fail validation; an unused role's bad policy is also an
error. These sources only add restrictions and grant no tools or permissions.

## Writing blacklist entries

Make each description about one concern. Use concrete nouns and actions, and
say why the action matters in the same sentence when that makes the boundary
clear. For example, “Do not delete another lane's worktree” is easier for
TypeSafe to judge than “protect the workspace”. `examples_not_ok` and
`examples_ok` are short anchors placed in the judge state; they show the
intended boundary without replacing the description.

Patterns are optional. Add one when the case is clear-cut and deterministic,
such as an argv prefix for a remote push or a path glob for a key file. Leave
the pattern out when the description needs context or intent. Use
`laneboss org blacklist try --config NAME --level N --role ROLE -- COMMAND...`
to see every applicable entry, the TypeSafe score and band, and the resulting
refuse/warn/allow decision. `try` is a preview: it writes no decision or hook
receipt. Its judge requests use the normal interrupt-safe egress log, so the
request and outcome are auditable without creating a decision record. It cannot
run from inside a lane session. When no judge is configured or reachable it
says so and reports the pattern-only result.

The thresholds and TypeSafe configuration are shared with decision guidance in
`.laneboss/shared/services/guide.toml`:

```toml
enabled = true
configuration = "rows"
judge = "typesafe"
warn_threshold = 0.50
refuse_threshold = 0.85
```

For a `refuse` entry, a score at or above `refuse_threshold` refuses and quotes
the entry and its `Instead:` route. For a `warn` entry, a score at or above
`warn_threshold` adds a warning and never refuses. A lower score allows the
call. A deterministic pattern is evaluated before the judge; a judge can add
a warning or refusal but can never relax a deterministic refusal.

An org entry identifies itself as `[entry-id] Refuses: ...` or
`[entry-id] Warning: ...`. Converted legacy refusals also retain their `Why:`
text and `Instead:` route. The built-in protected-file refusal keeps its own
`[blacklist:laneboss-files]` label.

Literal ANSI-C path fragments are decoded for secret-file read checks,
including fragments concatenated with ordinary path text. A decoded protected
read is refused with `org hook fails closed: ANSI-C shell quoting cannot be
inspected`. Ordinary encoded paths remain incomplete observations in blacklist
mode; the quoting alone does not refuse them.

Legacy command-pattern and secret-read rows become blacklist entries. A legacy
write-scope row contributes only its explicit `deny_paths`; its `paths`
allowlist is ignored. Existing refusal descriptions keep their ids, wording
and audience filters. New orgs do not seed tool-allowlist rules.

Unversioned org sources and the legacy `[hooks] mode = "strict"` spelling use
the same blacklist behavior. Render and validate retain these sources and emit
one deprecation warning naming the ignored tool allowlists:
“strict mode and tool allowlists were removed in 1.0.0; the org hook enforces
only blacklist entries, obscured forms and protected files”.

## TypeSafe and decision guidance

The hook sends each applicable blacklist description, except entries with
`pattern_only = true`, and the complete rendered
tool call through the same TypeSafe request machinery and score dial used by
recorded decision guidance. The request is credential-screened, logged by the
judge service, and split into the same bounded action windows. The hook gives a
judge request at most two seconds in total for its synchronous blacklist pass;
the configured judge timeout can be shorter. A timeout, unavailable judge,
invalid answer, withheld text, or a call longer than the readable windows
produces a notice and leaves deterministic results in force. It never creates
an indefinite block.

Recorded decisions are guidance by default. A conflict adds a
warning whose wording becomes stronger as its score rises; decisions remain in
every applicable brief and turn, and decided questions are answered by the
decision store. A decision or job refuses only when the org lists its id in a
blacklist entry with `band = "refuse"`; that entry's threshold then applies.
The same decision conflict without a blacklist entry warns and never refuses.

The callback receipt keeps the tool name, the allow/deny result, the reason,
hashes of inspected read paths, the runner and the judge summary. It never
keeps command arguments or file contents. An opaque or incomplete call has
`inspection_complete = false`; ordinary coding work still receives the clean
permission reason `org policy permits this tool call`.

## Built-in protection

The following deterministic blacklist entries are always active and cannot be
removed from `.laneboss/org.toml`: writes to the org configuration, hook
settings and registry, refusal catalog, decision-guide services, installed
hook executable, and instance definitions and runner settings. This keeps the
observer and its records true. User-level runner settings such as `~/.claude`
and `~/.codex`, a worktree's own `.claude/` and `.codex/` directories, and Git
hooks are outside this list unless an org entry names them. Nothing else is
built in. A write to one of these paths is refused even when a judge is
unavailable when the hook can parse the write. Opaque programs and
uninspectable shell can still write these files because the default observer
does not execute or guess at their effects. Until the 1.0.0 service runs hook
state under a separate user, same-user OS permissions provide no protection
against those opaque escapes. The launcher's external state under
`~/.local/state/laneboss/` is not in this built-in list.

The raw backstop has one accepted residual: when a write target contains a
variable the hook cannot resolve and that variable absorbs a one-component
tail such as `$X/hooks/...`, the tail may remain allowed. The fallback requires
a distinctive multi-component protected suffix (with `org.toml` and
`instance.toml` as exact-name exceptions); resolved variables are checked as
paths, and literal targets use the parsed file effects.

## Laneboss-provided tasks

When Laneboss provides a task, use its command. New orgs receive twelve narrow
`[[hooks.blacklist]]` entries in their `org.toml` source, all with
`band = "refuse"`, `pattern_only = true` and no level or role restriction.
Every pack entry uses `argv_words` with the words listed below. The pack refuses
ordered whole-word matches without consulting TypeSafe, so it adds
no scoring requests or judge warnings to unrelated work. Other calls continue through
the org's ordinary blacklist policy. A matching refusal ends with the exact
`Instead:` route below; the alternative still requires the caller's authority.

| Entry id | Ordered argv words | Instead |
|---|---|---|
| `raw-codex-exec` | `codex exec` | `laneboss lane start / laneboss lane resume / laneboss lane turn` |
| `raw-claude-p` | `claude -p` | `laneboss lane start / laneboss lane resume / laneboss lane turn` |
| `raw-claude-print` | `claude --print` | `laneboss lane start / laneboss lane resume / laneboss lane turn` |
| `raw-claudock-run` | `claudock run` | `laneboss lane start / laneboss lane resume / laneboss lane turn` |
| `raw-tmux-new-session` | `tmux new-session` | `laneboss lane start` |
| `raw-tmux-new` | `tmux new` | `laneboss lane start` |
| `raw-tmux-kill-session` | `tmux kill-session` | `laneboss lane stop` |
| `raw-tmux-send-keys` | `tmux send-keys` | `laneboss lane attach` |
| `raw-tmux-attach` | `tmux attach` | `laneboss lane attach` |
| `raw-tmux-attach-session` | `tmux attach-session` | `laneboss lane attach` |
| `raw-aws-run-instances` | `aws ec2 run-instances` | `laneboss box` |
| `raw-gcloud-instances-create` | `gcloud compute instances create` | `laneboss box` |

The executable is anchored and the remaining words match in order, including
flag-first forms such as `claude --model m -p`, `tmux -L s new-session` and
`aws --region r ec2 run-instances`. The pack does not blacklist the whole program:
`codex --version`, `claude --help`, `claudock --help`, `tmux ls`, `tmux -V`,
`tmux list-sessions`, `aws ec2 describe-instances` and
`gcloud compute instances list` remain allowed by this pack. A quoted
`"codex exec"` argument in `git commit -m "codex exec"` does not match either;
ordinary write scopes and other policy still apply to the Git operation.
Aliases and opaque programs retain the existing blacklist and inspection rules.

New orgs seed only these twelve blacklist entries, with no sample hook rules,
refusal catalog, starter examples or tool allowlist fields. Protected Laneboss
files (including the decision store and all of `shared/services/`) and L3 lane
boundaries are built-in checks independent of optional rule files. Existing orgs keep
their authored rules, including a broad legacy rule if they have one. Neither
`org render`, `org validate`, role installation nor instance addition installs
this pack into an existing org.

An org that already copied an earlier pack can explicitly add
`pattern_only = true` to those twelve source entries, then render and validate.
Entries without that flag retain their existing TypeSafe scoring behavior.
For an earlier positional pack, the owner also replaces each `argv_prefix` key
with `argv_words`, retaining its word array. Rendering does not migrate the
source or widen any existing entry automatically.

### Bootstrap: add your own entries

In 1.0.0, write-scope rules retain only `deny_paths`, so built-in protection
covers `declared-writes` and the empty deny lists make `worktree-writes` and
`supervisor-writes` do nothing, while the pack replaces `runner-launches`;
these four legacy rules therefore have no copy-text here.

At bootstrap, choose the policy your org needs. These are documentation examples
to copy into `.laneboss/org.toml`; init writes none of them:

```toml
[[hooks.blacklist]]
id = "remote-push"
description = "Do not push changes to a remote from L5 or L6."
band = "refuse"
examples_not_ok = ["git push origin main"]
examples_ok = ["git status", "git diff"]
[hooks.blacklist.applies_to]
levels = [5, 6]
roles = ["top", "supervisor"]

[[hooks.blacklist]]
id = "credential-files"
description = "Do not read or print credential, key or token files."
band = "refuse"
path_glob = "*.key"
examples_not_ok = ["cat deploy.key"]
examples_ok = ["printf '%s\\n' credential-name"]

[[hooks.blacklist]]
id = "destructive-history"
description = "Do not delete a repository, its history or another lane's worktree."
band = "warn"
examples_not_ok = ["rm -rf ../other-lane", "git push --force"]
examples_ok = ["git status"]
```

For deterministic secret-file reads and push denials, create
`.laneboss/shared/hooks/rules.toml` with this optional policy:

```toml
schema_version = 1

[[rules]]
id = "secret-files"
kind = "secret-read"
names = ["{secret_names}", ".env", ".env.*", "*.key", "*.pem"]

[[rules]]
id = "no-push"
kind = "command-pattern"
patterns = [["git", "push"]]
```

Each rule also needs its matching refusal source. Copy this into
`.laneboss/shared/refusals/secret-files.toml`:

```toml
id = "secret-files"
refuses = "Reading or printing a file whose name is protected as a secret."
why = "Secret values must remain outside agent output at every level."
instead = "Refer to secrets by name and request a public or redacted input."
examples_allowed = ["Read README.md."]
examples_refused = ["Read .env."]
[applies_to]
levels = [3, 4, 5, 6]
identities = ["*"]
```

Copy this into `.laneboss/shared/refusals/no-push.toml`, then render and validate:

```toml
id = "no-push"
refuses = "Pushing repository changes from an executor or mini-supervisor."
why = "Publishing changes belongs to the supervising level."
instead = "Leave the changes for review and ask the supervisor to publish them."
examples_allowed = ["git status"]
examples_refused = ["git push"]
[applies_to]
levels = [3, 4]
identities = ["*"]
```

### Explicit opt-in for an existing org

The owner or supervising policy editor can opt in with a source edit:

1. Keep a copy of the existing `.laneboss/org.toml` and shared hook source.
   Create a separate fresh reference org with
   `laneboss org init /absolute/path/to/rawpack-reference --name rawpack-reference`.
   This starts no agent or service.
2. With the file tool, copy the twelve active `[[hooks.blacklist]]` tables from
   the reference org's `.laneboss/org.toml` into the existing org's source.
   Preserve its other tables and custom entries. Do not copy `[hooks]` a second
   time, and do not replace custom entries that reuse an id without reviewing
   that policy. If the old source uses `blacklist = []`, remove that empty-array
   assignment before adding array tables. The hook uses blacklist behavior for
   both versioned and unversioned org sources.
3. If the existing shared hook source still has the legacy `runner-launches`
   command-pattern row with `patterns = [["claude"], ["codex"]]`, explicitly
   remove that complete row from `.laneboss/shared/hooks/rules.toml` as part of
   the reviewed opt-in edit. Keep the other rows and its refusal catalog.
   Otherwise that independent broader rule continues to refuse ordinary reads.
4. Run `laneboss org render /absolute/path/to/existing-org`, then
   `laneboss org validate /absolute/path/to/existing-org --format json`.
   Require successful exits and `valid: true` with `problems: []`. Generated
   settings and manifests are produced by render; do not edit them by hand.

The built-in protected-file gate still refuses the same writes. Its message
uses `Instead: laneboss lane send` for lane mail and
`Instead: laneboss report` for report records and protected owner-channel state.
Policy and other protected files retain their supervisor-change route. This
wording grants no direct file access or delivery permission.

The credential-free black-box rows are in
[`e2e-rows/test_rawpack_rows.py`](../e2e-rows/test_rawpack_rows.py), with independent
vectors in [`rawpack.json`](../e2e-rows/rawpack.json). On the disposable Linux
machine, point `LANEBOSS_BIN` at an already built CLI and
`LANEBOSS_ROW_EVIDENCE` at an absolute evidence directory, then run
`python3 e2e-rows/test_rawpack_rows.py`. They invoke the actual hook commands
from both runners' rendered settings at L3–L6, pair each refusal with an allowed
control, check exact routes against the CLI grammar, exercise the explicit
source opt-in and preserve requests, outputs, source bytes and the binary hash.
The harness initializes private Git workspaces for the allowed Git control;
submitted vector commands, including `git commit`, are never executed.
Unit coverage for default initialization,
source opt-in and protected-route wording is in `internal/orgtree/rawpack_test.go`
and `internal/orghook/rawpack_routes_test.go`. Flag-first refusals and their
allowed controls run through the installed pack in
`internal/orgtree/rawpack_words_test.go`; literal-word and raw-shell boundaries
are covered in `internal/orghook/argvwords_test.go`.

Static checks do not establish a passing E2E. Before acceptance on the Linux
machine, first run the new rows and units against a pre-pack build or a restored
missing-pack mutation and require the corresponding assertion to fail; then run
the unchanged checks against the completed build. Widening a prefix must fail
an allowed control, a wrong route must fail the last-line assertion, and silent
policy insertion must fail source-byte equality. A missing refusal alone is
never a passing control.

## Runner registration and refusal handling

`org init`, `org instance add` and `org render` install one direct Go command
hook per runner. Claude receives its instance settings path; Codex receives an
instance `CODEX_HOME` and the explicit `features.hooks=true` setting. The
registry and settings are checked before a runner is started. A runner command
that disables, replaces or narrows the mandatory synchronous hook fails
validation.

Every refusal ends with `Instead:`. Stop the refused action, report the exact
refusal and the start of the command to the supervisor, and use only the route
named by that refusal. A route grants no exception and remains subject to every
blacklist, scope and secret check.

When the decision guard warns, the same object also carries `additionalContext`, the text that the runner puts in front
of the model next to the tool result. The guard runs only after the rules above have allowed a call, adds a `guard`
member to the call's callback receipt. Guidance always warns when it finds a
conflict or cannot score a call; its settings and bands are in
[Guiding agents](decisions.md#guiding-agents). It only adds: a call that the rules refuse keeps its answer to the letter whatever the guard's settings, store and judge are, and the guard is not called
for a refused call. Incomplete allowed observations can still receive guidance.

For shell calls that baseline policy allows, the generated job catalog uses the same judge and warning threshold.
Scores at or above that threshold name the generated `laneboss` command in `additionalContext` by default. Refusal
requires a separately set `jobs_refuse_threshold` and an independently recorded managed target, then names the command
in `Instead:`. A `none` choice and low scores add nothing. Supported literal tmux/curl/kill and Git forms can be
inspected; unsupported or opaque forms can be refused before scoring, and the L3 raw-network boundary still applies.
A stale catalog, unreachable judge, invalid answer or timeout keeps baseline policy and adds a short notice. Decisions
and jobs share one 30-second deadline; the whole job ask gets at most ten seconds of the remaining budget, including
log locks, with three seconds reserved for cleanup. Rendered hook entries set a 60-second timeout. Baseline denials skip
both judges and retain their complete original reason. See
[Laneboss jobs at the hook](decisions.md#laneboss-jobs-at-the-hook) for generated hashes, rows and the acceptance assertion.

Signalling a process with an inspectable `kill` call stays warn-by-default under the catalog policy. An org that wants a
hard refusal for signalling its supervisor or a sibling lane adds a blacklist entry to its hook-rule sources. For
example, after recording the protected process's current PID, replace `42424` below and add this row to
`shared/hooks/rules.toml`:

```toml
[[rules]]
id = "protected-process"
kind = "command-pattern"
patterns = [["kill", "42424"], ["kill", "-TERM", "42424"], ["kill", "-KILL", "42424"]]
```

Add the matching `shared/refusals/protected-process.toml` source:

```toml
id = "protected-process"
refuses = "Signalling the protected supervisor or sibling process."
why = "The org reserves stopping this process to its supervisor."
instead = "Report up with laneboss report and ask the supervisor to stop the lane."
examples_allowed = ["Signal an unrelated child outside the protected prefixes."]
examples_refused = ["kill 42424", "kill -TERM 42424"]
[applies_to]
levels = [3, 4, 5, 6]
identities = ["*"]
```

Render after editing these sources. The example covers the listed argv prefixes; refresh recorded PIDs after a restart
and extend the patterns to the signalling forms the org uses. An org that chooses to refuse every raw `kill` call can
use `patterns = [["kill"]]`. These explicit blacklist decisions run before guidance and job scoring.

## Verification and boundaries

The hook never executes submitted commands. It resolves literal paths without
following unsafe links, checks bounded directory searches, and keeps the
existing shell, Git, patch and runner adapters for deterministic blacklist matching. The observer is not a sandbox: a call it
cannot inspect is recorded as incomplete and allowed in the default mode. The
L3 lane boundary still applies in blacklist mode: a lane may write only inside
its recorded worktree unless the owner-controlled grant below applies, and may
not use raw network clients or detached process identities.

An owner may grant an intentional worktree escape with exactly
`allow_worktree_writes = true` in
`.laneboss/shared/hooks/boundary.toml`. This owner-controlled file is part of
the protected shared hook policy. The grant applies to L3 write containment for
the org; it does not grant raw network clients or detached process identities,
and shared message paths and Laneboss protected files remain refused. For
example, an owner can write the following file before a lane starts when that
lane must update a separately reviewed repository:

```toml
allow_worktree_writes = true
```

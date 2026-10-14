# Org hook policy

The org has one implementation, `laneboss.orghook`, and one generated bootstrap
at `.laneboss/shared/hooks/org-hook.py`. Every instance uses that bootstrap with
its own pinned `instance.toml`. Rules are TOML data, not per-level programs.
The hook reads one PreToolUse event from standard input and returns a permission
decision. Invalid JSON, invalid TOML, missing policy files, unknown instances,
unknown tools and uninspectable commands produce a denial.

The Bash adapter recognizes a whole literal apply_patch/applypatch invocation
with a quoted heredoc, or one single-quoted patch argument without an apostrophe.
It checks the patch's touched paths through the ordinary scope and protected
path policy. Extra commands, unquoted delimiters, pipes, redirects and expanded
arguments remain refused. Broken quoting on a write receives an Instead route
to the native apply_patch tool or a quoted heredoc; a read keeps its read route.

Report every refusal verbatim, including the start of the refused command. If it
names an Instead route, take exactly that route under the same policy; otherwise
stop. Do not invent another rewrite or use an override.

The command inspector accepts literal read-only sed print and substitution
scripts. In-place flags, write and execution commands, script files, r/R reads,
blocks, branches and uncertain grammar remain opaque. Every accepted input file
uses the same read and secret rules as cat. The head, tail, wc, grep, nl, cut and
sort adapters inspect known options and reject unknown forms. Sort output and
explicit temporary directories are writes; pattern files and random sources
are reads. Expansion metacharacters stay opaque where literal quoting cannot
be proven.

Literal shell compounds can use if/then/elif/else/fi, boolean chains, semicolons,
newlines, negation and fixed-arity test predicates. The inspector collects file
effects from every condition and branch without evaluating which branch runs.
Known simple-command adapters still decide the effects: content reads retain
their secret checks, literal redirects are writes checked against scope, and
unknown commands stay refused. File predicates inspect metadata and protected
names without recursively reading directory contents. Variables, substitutions,
globs, loops, functions, heredocs, subshells and uncertain grammar remain refused
inside compounds. The complete quoted patch adapter above keeps its own grammar.

Every compound part carries the state effects of its resolved command, after
literal unquoting and wrapper/assignment resolution. Directory-stack builtins,
environment and option changes, aliases, eval and source are refused in any
branch. Set a tool's explicit workdir for a relative command instead of changing
directory inside a compound. Unknown resolution also fails closed.

Codex bypass runs refuse `default_permissions`, permission tables,
`approvals_reviewer`, MCP server definitions and any approval policy other than
`never` in every vetted configuration layer. They also refuse automatic review,
full-auto and managed worktree flags. Unknown permission, sandbox and approval
directives are refused. The legacy workspace sandbox must exclude both implicit
temp roots, and only its vetted cwd may be writable.

Codex argv uses an allowlist of the start, resume, bypass and probe flags passed
by the launcher and bundled acceptance adapter. Unknown flags and
--ignore-user-config are refused. No launcher path needs -o/--output-last-message,
so those flags are refused. notify, use_legacy_landlock, guardianv2 and guardian_ext
are refused in vetted configuration and feature switches. CODEX_HOME selects the
vetted instance; provider authentication and endpoint names are transport inputs.
Other CODEX_* controls are refused at launch by name, without exposing values.

## How the org commands use it

The hook commands `org hook`, `org refusals` and `org check-hooks` share the one
`laneboss org` command group with init, instance add, render and validate:

1. `org init` calls `orghook.seed_hook_rules(org, levels)` after creating
   `org.toml`. It creates generic rules and one structured TOML description per
   rule in shared and level `refusals/` directories. Existing policy files are
   preserved.
2. `org init`, `org instance add` and `org render` call
   `orghook.render_hook_settings(org)`. It returns a mapping from instance names
   to runner specifications and writes the same specifications to each
   instance's `hooks/runners.json`. Use the returned command arrays as launch
   prefixes; append the runner's ordinary model, prompt and resume arguments.
   Claude gets `--settings INSTANCE/.claude/settings.json`. Codex gets
   `env CODEX_HOME=INSTANCE/.codex codex -c features.hooks=true`, which selects
   its `hooks.json` and explicitly enables the vendor feature. Render also
   sets `[features] hooks = true` in the instance's `config.toml`, retaining
   unrelated configuration values. Ordinary table and dotted forms keep their
   existing text and comments; unusual inline forms may be serialized again.
   Credentials are not copied or printed. A file whose content and mode are
   already right is not rewritten, so a repeated render changes nothing.
3. `org validate` calls `orghook.check_hooks(org)` and fails when
   `report["ok"]` is false.

Not built yet: `laneboss lane start` and `lane resume` do not yet check the
command they execute with `check_runner_command(instance_file, runner, command)`.
Until they do, an org instance is protected when its runner is started with the
prefix from `hooks/runners.json`; a registry alone does not enforce a launch that
ignores it.

The default template restricts writes to declared repositories, restricts L3 to
its own worktree, refuses L3/L4 pushes, refuses secret-file reads at every level,
uses each identity's tool allowlist, and protects all instances' policy and hook
settings. Direct runner launches from tool calls are refused; launch authority
uses the checked command prefixes above. `orgexamples.py` holds one canonical
data source for both the seed rules and their refusal descriptions.
Rendered hook settings, the helper, rule files and refusal files are read-only.

Claude settings keep `disableAllHooks = false` and reject managed-only hooks.
Codex `hooks.json` accepts only `hooks` and optional `description`. Re-rendering
refuses unsupported top-level Codex keys before writing settings; remove the
unsupported fields explicitly and render again.

Codex lane starts, resumes and turns explicitly add `-c features.hooks=true`.
Before launch, laneboss runs the selected executable's `features list` with the
same configuration/profile/feature flags and instance environment. The result
must contain exactly one `hooks` row with value `true`. A missing, disabled,
unreadable or unsupported feature refuses the launch before `lane.started`.
The capability cache belongs to that one run and is keyed by executable path,
version and configuration scope; a later run always probes again. These probes
are local, non-interactive commands and do not call a model.

Lane supervisors keep stdout and stderr separate while recording their live
output. Before the first `turn.started` or model/tool output, a Codex stdout
`item.completed` event with an `error` item qualifies only when its `message`
starts with the exact prefix `failed to parse hooks config `. Plain vendor
startup stderr qualifies only at the start of a line with that same prefix.
Agent messages, command output, tool results, quoted text and historical logs
are never searched for diagnostic phrases. Other wording requires an explicit
prefix and a compatibility row. A detected failure stops the tracked process tree and
records `lane.ended` with reason `hook-config` and launcher exit code 125. Status
and rebuilt events retain that reason. Resumes and turns refuse until the failed
hooks file has changed and validates with synchronous `PreToolUse` command hooks.
The lane keeps a private file-path/hash marker and prints no settings values.

## Instance fields

```toml
name = "example-executor"
level = 3
role = "executor"
writable_repos = ["worktrees/example-executor"]
allowed_tools = ["Bash", "Read", "Write", "exec_command", "apply_patch"]
secret_names = ["service.private"]
```

These fields are required. `secrets` is accepted as an alias for `secret_names`
for a Phase A schema that already uses that name; values are file/secret names,
never credentials. Paths in `writable_repos` are absolute or relative to the org
root. Optional `worktree` has the same path convention. Without `worktree`, a
single writable repository is the worktree; otherwise the instance directory is
the conservative default. Empty `allowed_tools` permits no tools. An empty
`writable_repos` permits no writes under the template.

Instance lookup walks upward from the event's working directory to
`.laneboss/instances/NAME`. `LANEBOSS_INSTANCE` may instead name an instance in
the current org or hold an absolute instance directory/instance.toml path.
Rendered hooks use `--instance` to pin identity even when a tool works in a
repository. An environment identity that disagrees with the pinned instance,
or a working directory belonging to another instance, is refused. No environment
values appear in diagnostics.

An instance may declare actual launch specifications in `instance.toml`:

```toml
[runners.claude]
command = ["claude", "--settings", ".claude/settings.json"]
resume = ["claude", "--settings", ".claude/settings.json", "--resume", "example-session"]
```

When `[runners]` exists, the checker inspects those actual commands, including
resume commands. Otherwise it inspects the generated `hooks/runners.json`.
Commands must directly launch the declared runner with literal argv. Shell
wrappers, missing settings, another instance's settings, multiple settings
arguments, hook-disable switches and Codex hook overrides fail the check.
The JSON report contains names, fields and verdicts, never command contents or
settings objects. A failing check exits 1; a missing registry is a failure.

## Rule data

Each shared/level `hooks/rules.toml` has `schema_version = 1` and a `rules` array.
An empty layer must explicitly say `rules = []`. The hook validates both required
files and every referenced refusal before allowing anything. It evaluates shared
rules first, then the instance's level, then optional `[[hooks.rules]]` entries
in `instance.toml`. Instance rules add restrictions; they cannot disable earlier
rules. Identity fields fill placeholders in shared and level data.

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

[[rules]]
id = "private-files"
kind = "secret-read"
names = ["{secret_names}", ".env", ".env.*"]

[[rules]]
id = "tools"
kind = "tool-allowlist"
tools = ["{allowed_tools}"]
```

Write roots use resolved paths and component containment, including symlinks;
matching a directory name as a string prefix is insufficient. Denied paths also
protect ancestor removals/replacements. `{hook_paths}` expands to the org config,
shared/level hook and refusal directories, the installed hook package, and every instance's definition,
hook registry, refusal directory and runner settings. Agents' state directories
are not included in that protected set. Other path placeholders are `{org}`,
`{laneboss}`, `{instance}`, `{level}` and `{worktree}`. `{writable_repos}` expands
as a whole entry to the identity's repository roots.

Command patterns match an argv prefix with optional `fnmatch` patterns per word.
They never search raw command text. Executable basenames, shell separators,
quoting, supported wrappers, nested literal `sh -c` commands and Git `-C` options
are inspected. A literal `printf '%s' 'git push'` is permitted, while a parsed
Git push matches the refusal. Shell redirections and supported file utilities
contribute read/write paths. Changed directories are supported in `&&` chains.
Alternate Git repository options and mutation through a linked Git worktree are
refused until an adapter accounts for their writes outside the worktree folder.

Secret names match the original filename, its resolved filename, or an exact
configured path. Directory reads inspect a bounded set of descendant names,
including hidden files, without reading contents. Literal echo/printf arguments
are not file reads. `Glob` and `LS`, plus supported shell `ls` and read-only
`find` predicates, list names and metadata without reading file contents.
`find -delete` and other mutation actions remain subject to write inspection.
Redirection targets exactly equal to `/dev/null`, `/dev/stdout` or `/dev/stderr`
do not add a write effect; other device targets still do.

`Grep` searches file contents at its `path`, defaulting to the hook's working
directory. A directly protected path is always refused, even with a filter.
Directory searches inspect up to 20,000 entries, including hidden entries.
Any protected name anywhere inside refuses the search, regardless of `glob`,
`type` or other filters. The hook makes no exclusion proof about the search
engine's selection semantics. Exceeding the bound or encountering an
uninspectable directory also refuses the search. The refusal tells the agent to
narrow `path` to a folder or file without secrets. The walk reads metadata only;
symlink directories and multiply linked files remain refused when their reads
cannot be inspected safely.

Tool names use the runner's actual tool spelling; Codex's
`functions.` prefix is removed before matching. Names, identities and command
words can use `fnmatch` patterns; write paths must be literal paths/placeholders.

## Refusal files and runner events

Every rule's id names `LAYER/refusals/ID.toml`, or an instance's `refusals/ID.toml`
for inline instance rules:

Every denied callback ends with its own `Instead:` route. Inspection failures name a supported literal operation or a supervisor repair route. Policy refusals preserve the recorded description and supply a route for the rule's kind. The route remains subject to all tool, secret and write-scope checks; it grants no exception. Variable or substitution failures request one literal command per non-secret file or an allowed file-reading tool. Denied parseable calls retain a callback receipt, with `inspection_complete=false` when effects could not be inspected.

```toml
id = "publish"
refuses = "Pushing changes from an executor."
why = "Publishing belongs to the supervising level."
instead = "Leave the changes for review."
examples_allowed = ["git status", "printf '%s' 'git push'"]
examples_refused = ["git push", "git -C repository push origin topic"]

[applies_to]
levels = [3, 4]
identities = ["*"]
```

The description's `applies_to` controls applicability. A duplicate `applies_to`
on the rule must be identical. The deny text uses this file's id, refuses, why
and instead verbatim. Descriptions are reloaded on every call.
`laneboss org refusals ORG --format json` prints all shared, level and instance
descriptions with their org-relative `source` paths for TypeSafe consumption.

Both command-hook runners accept the native envelope used here:

```json
{"hook_event_name":"PreToolUse","cwd":"/srv/example-org/.laneboss/instances/example-executor","tool_name":"Bash","tool_input":{"command":"git status"}}
```

Codex's shell tools also accept `cmd` strings or argv arrays, JSON argument
strings, and `functions.exec_command`. Its `apply_patch` input can be a raw
patch string or an object with `input`, `patch` or `command`. File tools accept
`file_path`, `path` or `notebook_path`; ambiguous or missing fields deny. Patch
add/update/delete and move paths are all checked.

Both runners currently consume `hookSpecificOutput` with `hookEventName` set
to `PreToolUse`, `permissionDecision` set to `allow` or `deny`, and
`permissionDecisionReason`. A deny is a valid hook result with exit status 0;
the runner blocks from the permission decision. A Stop-style `decision:block`
response is not used for PreToolUse.

## Verification and boundaries

This lane's permitted local checks are compilation and CLI help only. The
CLI tests in `laneboss-e2e:tests/e2e/test_org_hooks.py` are for the supervisor's disposable
machine. They must be run against a RED tree with these tests only and a GREEN
tree with the implementation; no behavioral pass is claimed by this lane.

| Check | What makes its assertion fail |
| --- | --- |
| Four rule-kind matrices | Either the allowed control is denied or the prohibited action is allowed, at either level, identity or runner; a deny also must name the fixture's refusal. |
| Level and identity selection | L3/L4 pushes are allowed, L5/L6 pushes are refused, an identity writes another identity's repository, or applies_to audience filters are ignored. |
| Layer ordering | Shared, level and inline instance restrictions do not take effect in that order as earlier restrictions are removed. |
| Refusal-file reload | Editing a description to a random new explanation fails to change the hook's denial. |
| Broken/missing policy and unknown identity | A harmless control remains allowed after TOML damage, a missing policy file, or an unknown instance. |
| JSON failure and non-echoing errors | Malformed, duplicate-field or nonfinite JSON allows a call, or the diagnostic repeats an untrusted marker. |
| Discovery/pinning | A nested instance cwd or explicit worktree identity is not found, or mismatched identities are allowed. |
| Symlinks, redirects, cwd changes and patch moves | A named write/read escapes its policy, or a move's destination is ignored. |
| Protected settings | A broad writable org root permits changing another instance's definition or any hook policy/settings. |
| Directory searches and tool workdirs | A directory search with a protected descendant is allowed, or an explicit workdir grants another identity's write scope. |
| Opaque command handling | Unknown programs, eval, malformed quoting, substitutions or dynamic paths receive an allow. |
| Refusal catalog | JSON omits a file/field, drops its audience/examples, or prints a different explanation. |
| Mandatory hook checks | A correctly registered runner fails, an unhooked start/resume passes, disabled/narrow/asynchronous/changed registrations pass, or missing launch data yields success. |
| Checker integrity | A modified helper, writable rule data or a Codex hook config override receives an ok verdict. |

The inspector has bounded input and token limits and rejects unsupported
programs, interpreters and command effects. Adding an arbitrary script to a tool
allowlist does not bypass inspection; it needs an adapter. Directory reads with
uninspectable symlink directories or multiply linked files fail closed. The
launcher still needs its filesystem sandbox to cover filesystem races and
processes started outside its checked launch path. A host-wide running-session
audit is a separate launcher integration; this module checks configured launch
commands and guards individual tool calls. Real vendor startup and the combined
Phase A init/render/validate path require the supervisor's runtime verification.

The referenced black-box files live in the separate `laneboss-e2e` repository. Run its commands there with `LANEBOSS_SRC` set to an absolute laneboss checkout. Go unit tests remain `go test ./...` in this repository.

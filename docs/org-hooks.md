# Org hook policy

The org has one implementation, `laneboss.orghook`, and one generated bootstrap
at `.laneboss/shared/hooks/org-hook.py`. Every instance uses that bootstrap with
its own pinned `instance.toml`. Rules are TOML data, not per-level programs.
The hook reads one PreToolUse event from standard input and returns a permission
decision. Invalid JSON, invalid TOML, missing policy files, unknown instances,
unknown tools and uninspectable commands produce a denial.

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
   `env CODEX_HOME=INSTANCE/.codex codex`, which selects its `hooks.json`.
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
are not file reads. Tool names use the runner's actual tool spelling; Codex's
`functions.` prefix is removed before matching. Names, identities and command
words can use `fnmatch` patterns; write paths must be literal paths/placeholders.

## Refusal files and runner events

Every rule's id names `LAYER/refusals/ID.toml`, or an instance's `refusals/ID.toml`
for inline instance rules:

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
CLI tests in `tests/e2e/test_org_hooks.py` are for the supervisor's disposable
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

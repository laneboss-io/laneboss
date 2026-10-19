Codex config.toml is vetted by parsed meaning rather than a file checksum. Ordinary project trust levels, notices and model-migration state do not define an executable hook and remain allowed. Hook-bearing keys, project-root and managed-directory overrides, enabled plugins and profile hook settings remain refused. The invocation explicitly enables hooks and disables plugins, and its feature probe verifies that effective configuration. The rendered hooks.json still must match its recorded bytes and contain the single rendered org-hook command.

Every rendered instance config sets agents.enabled to false and sets features.multi_agent_v2 and features.collab to false. The launch gate requires the rendered agents table to contain only enabled=false. Home, repository, system, managed, profile and preference layers cannot enable collaboration or supply agent role tables; command overrides and feature switches cannot change those controls. Diagnostics name the rejected keys without their values. Codex therefore does not offer collaboration tools such as spawn_agent. Laneboss coordinates work through lanes and does not require Codex sub-agents.

The keys immediately under projects are project path names. They are not hook directives even if the path contains hook-worktrees. Their table contents are still recursively vetted, so an added hooks table inside a project entry refuses.

Trust refusals name the source file and the violated rule. Configuration refusals locate the rejected key through the same recursive semantic predicate used by the gate. TOML parser errors report invalid TOML without parser excerpts or values. File checks identify regular-file, size, hard-link, parent-alias, identity and read rules. Render-marker, repository, system and preference errors retain their source context. Diagnostics never print configuration values or complete settings objects.

A workspace may be inside an instance's sibling state directory. It must not contain the Codex home, instance definition, render marker, settings/configuration or vetted org-hook executable, and it must not be at or below the Codex home. Containment compares device and inode identity along the ancestor chains, including resolved aliases. Repository vetting recognizes only the already-vetted home at that instance's ancestor; other repository hook/config sources still refuse. The acceptance L4 and L5 use their state directories and write review.md or plan.md there. Runner failures retain sanitized vet stderr so the lane log names the refused file and rule.

Unknown hook-trust records remain refused until their meaning is established from source or a canary. Project-trust and notice rows exercise allowed resume, while an added hooks table must refuse with the file and key named.

Bypass runs require sandbox_workspace_write.exclude_slash_tmp and
exclude_tmpdir_env_var to be true in the instance config. Lane preparation
renders one additional root in the vetted org instance's `.codex/config.toml`:
`sandbox_workspace_write.writable_roots = [STATE_DIR]`, where `STATE_DIR` is the
resolved **configuration StateDir**, including a custom `state.path`. It is not
the StateHome containing other configurations. The configuration and org must
match the effective runner environment. Rendering follows full hook vetting;
an existing hand-edited root is checked, never silently repaired. Start, resume
and turn preparation use this renderer, and the executing supervisor re-vets it.

Before any Codex provider probe, start, resume and turn preparation check the
runner's effective PATH after applying every literal `env` prefix in its command.
The executing supervisor repeats the check against the exact execution
environment. Each entry must be absolute and resolvable; empty and relative
entries refuse because they can select the working directory. Symlinks are
followed and paths are cleaned before comparing filesystem containment against
the worktree, the configuration state directory and the other vetted writable
roots. A path sharing only a spelling prefix with a writable root is allowed;
an alias into that root is refused. Unresolvable entries fail closed. Diagnostics
show only the offending entry, never the whole PATH or other environment values.
Set PATH in the runner command's `env` prefix to installed tool directories
outside these roots, such as `/usr/bin`, `/bin` and the installed laneboss
directory. An unsafe inherited PATH can be replaced by that safe effective one.

Only this top-level instance setting gets the allowance. It must contain exactly
one absolute, canonical path with the store's inode identity. Every component is
checked without following symlinks; `..`, prefix matches, parent directories,
duplicates, other roots and additional roots (including `.git`) refuse with the
existing writable_roots message. The whole state tree is checked for symbolic
links, multiply linked files, special files and `.git` entries. Linux mount IDs
are checked at every component and descendant, including files; mount boundaries
fail closed, so bind aliases and mounted descendants cannot extend the grant.
This conservative check also refuses a state directory beneath a separate mount.
Repository, system and profile roots, command overrides and add-dir arguments
remain refused. The worktree cannot overlap the protected store or org inputs.

The OS grant lets the CLI update its records; it does not distinguish the CLI
from other descendants. The org hook protects the entire configuration state
tree, including reports, decisions, SQLite sidecars and other lanes' files.
Direct file-tool and shell writes remain refused. Only the checked CLI adapter's
declared state effects receive an exception to the shared `{hook_paths}` state
entry; redirects, other protected policy paths and explicit owner deny paths do
not receive that exception. This remains hook enforcement with the documented
same-account and uninspected-script limits, not isolation of the store from an
arbitrary process that bypasses the hook.

On Linux, Codex lanes are executors: they edit, test and report from their worktree. Supervisors that start lanes, commit or merge run from the human terminal, as a Claude-runner lane, or on macOS under the laneboss-files sandbox.

Full-access sandbox modes also refuse except for a configuration-owned macOS
Laneboss lane sandbox replacement. That owner-selected path renders exactly one
`--sandbox danger-full-access` selector, records the replacement in the start
event and status, and checks it again before exec. The outer sandbox protects
only Laneboss's files, so the rest of the machine is not sandbox-protected. The
instance config remains vetted; the exception does not permit unvetted permission
or hook sources. The ordinary cwd root is checked against shared org policy
paths, including shared/level/instance refusal files and directories. Acceptance
work uses a fresh folder under the box user's home. Linked worktrees also vet
the main checkout's corresponding relative .codex sources, and refuse when the
main checkout cannot be determined. A .git directory without HEAD does not stop
the ancestor walk.

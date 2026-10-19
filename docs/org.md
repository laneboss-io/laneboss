# An org in one folder

An org keeps its repositories, lane worktrees, rules and agent instances together. `laneboss org` creates and
maintains this structure in the Go launcher. Its example rules describe generic supervision;
edit the protocol sources for your own topic.

The commands take the org folder explicitly. Init, roles, instance add and render work independently of the
launcher's named configuration and event stores. A configuration can select this org with `org_dir`; lane
start, adoption, resume and turn then enforce its role templates and driver lists. `org validate --config NAME`
also checks that configuration's runners and recorded lane usage. The shared hook and its runner registration
are described in [org-hooks.md](org-hooks.md). Selecting a role does not assign a lane to an org instance.

## Create an org

```sh
laneboss org init ./research --levels 3-6 --name research
laneboss org instance add ./research L3-review --level 3 --role reviewer \
    --secret REVIEW_API_KEY --secret REVIEW_CHAT_TOKEN
laneboss org render ./research
laneboss org validate ./research
laneboss org validate ./research --format json
laneboss org validate ./research --format json-diagnostics
```

`org init ORG_DIR [--levels LEVELS] [--name NAME]` defaults to levels 3 through 6 and the org folder's basename as
its name. `--levels` accepts an ascending range (`3-5`), a comma list (`3,5`) or one level (`5`); only 3, 4, 5 and
6 are allowed. The name must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Init sets `company` to the same name, for
later use as a guard scope identifier; you can edit it in `org.toml`.

Init creates missing directories and may use an existing empty `.laneboss/`. It refuses a nonempty `.laneboss/`,
a `.laneboss` symbolic link, or existing root `CLAUDE.md` or `AGENTS.md` files. Preserve existing rules and prepare
their content as protocol sources before initializing a folder that already has them. Existing repositories and
an existing ordinary `worktrees/` directory are retained.

Init seeds only the twelve Laneboss-first blacklist entries in `org.toml`.
It writes no shared or level `hooks/rules.toml`, refusal descriptions, starter
blacklist examples or `allowed_tools` field. Add your own policy at bootstrap
as shown in [org-hooks.md](org-hooks.md#bootstrap-add-your-own-entries).
Built-in Laneboss-file protections and L3 lane boundaries do not depend on
these optional sources; existing org policy is preserved.

## The tree and each file's role

The default layout has all four levels. A level omitted with `--levels` has neither a level directory nor an
example instance. Working repositories are placed alongside `.laneboss/` by their owner; init creates no Git
repository or worktree.

```text
research/
  CLAUDE.md
  AGENTS.md
  project/                         your working repository, added separately
  worktrees/                       lane worktrees, added separately
  .laneboss/
    org.toml
    render-manifest.json
    shared/
      protocol/rules.md
      hooks/
      tools/
      services/
    L6/                            also L5/, L4/ and L3/
      protocol/role.md
      roles/                       created only by org roles init
        supervisor.md             editable role scope and responsibilities
        supervisor.toml           driver basenames for this level and role
      CLAUDE.md
      AGENTS.md
      hooks/
      tools/
    instances/
      L6-super-top/                also L5-top/, L4-stream/, L3-lane-example/
        instance.toml
        CLAUDE.md
        AGENTS.md
        state/
          notes.md
          ledger.jsonl
          board.md
          inbox/
          outbox/
```

| Path | Role and who edits it |
|---|---|
| Root `CLAUDE.md`, `AGENTS.md` | Generated shared org rules for sessions in the org and its repositories. |
| `worktrees/` | Working area for lane worktrees; the org commands check its presence. |
| `.laneboss/org.toml` | Org identity, enabled levels, owner channel name, external secret store, instance defaults and the org hook blacklist/mode. Edit this source data, then render. |
| `.laneboss/render-manifest.json` | Hashes of the last generated rule files. Render owns this file; keep it with the generated files when backing up the org. |
| `shared/protocol/*.md` | Editable shared protocol sources, including `rules.md`. Every level receives them. |
| `shared/hooks/` | The Go hook's executable/hash manifest (`org-hook.json`) and optional owner-authored org-wide rule data (`rules.toml`), absent after init. The installed `laneboss` binary executes the hook. |
| `shared/tools/` | Org-wide tools supplied by the org owner. Init leaves it empty. |
| `shared/services/` | Service configs supplied by the org owner. Values such as channel ids and secret names belong here; secret values do not. Init leaves it empty. It also holds what the decision guard reads (`guide.toml`, `history.toml`, the decision store), and the org hook protects the whole folder from every instance, so an agent cannot change a service config. |
| `L<N>/protocol/*.md` | Editable rules for this level, including `role.md`. Other levels do not receive these sources automatically. |
| `L<N>/roles/<role>.md` | Editable role template for one role at this level. Included in that role's instance rules and lane briefs. |
| `L<N>/roles/<role>.toml` | Editable `drivers`, optional `[settings]` and `[[blacklist]]` entries for this exact level and role. A template and its TOML file are required together. |
| `L<N>/CLAUDE.md`, `L<N>/AGENTS.md` | Generated shared rules followed by this level's rules. |
| `L<N>/hooks/` | Optional owner-authored rule data for this level (`rules.toml`); init leaves it empty. |
| `L<N>/tools/` | Tools used only by this level; initially empty. |
| `instances/<name>/instance.toml` | This instance's identity, level, role, service and secret names, channel id and future hook policy data. |
| Instance `CLAUDE.md`, `AGENTS.md` | Generated shared rules, the instance's own level and its notes. |
| Instance `state/notes.md` | Editable context for one instance. Included in both of its generated rule files. |
| Instance `state/ledger.jsonl` | Initially empty ledger for the instance's own records. |
| Instance `state/board.md` | Editable board for queued, active and completed work. |
| Instance `state/inbox/`, `state/outbox/` | Directories for the instance's own incoming and outgoing records; phase A sends nothing. |

## Add an instance

```text
laneboss org instance add ORG_DIR NAME --level N --role ROLE
    [--discord-channel ID] [--secret NAME]...
```

The instance name uses `[A-Za-z0-9][A-Za-z0-9_.-]{0,95}` (1 to 96 characters), shared by org validation, hooks,
caller identity and layered settings. Its level must already be enabled and its
directory must not exist. Role is nonempty UTF-8 text of at most 128 characters and must be one safe filename:
no `/`, backslash, controls, `.` or `..`. Its paired Markdown template and TOML driver policy must resolve at
that level, first from the org's `roles/`, then from the embedded library. A role absent from both is refused,
including in an org with no `roles/` directory. An incomplete or unsafe org pair is refused rather than replaced
by a fallback. `--discord-channel` takes a
decimal channel id as a string, with 1 to 20 digits. `--secret` may be repeated and accepts uppercase secret
names, never their values. Duplicate names are refused.

The new instance inherits the `services`, `secrets` and `writable_repos` arrays from the org's
defaults, and the optional legacy `allowed_tools` array only when supplied there.
Command-line secret names are appended to the default secret names; a command-line channel id replaces
the default channel id. The command creates the state skeleton and renders all rules after checking the existing
generated files for hand edits. It installs no service or secret and sends no message.

## Role library and lane roles

Role TOML sources may add blacklist entries beside `drivers` and `[settings]`:

```toml
drivers = ["claude", "codex", "claudock"]

[[blacklist]]
id = "review-domain-publish"
description = "Publishing changes before domain review."
band = "refuse"
argv_prefix = ["git", "push"]
pattern_only = true
instead = "Leave the changes local and report to the supervising level."
```

The entry schema and validation are the same as `[[hooks.blacklist]]` in
`org.toml`; IDs must be unique across the entire org, including all role sources
and org-wide entries. Edit the org-owned source, then run `org render` and
`org validate`. The built-in role library ships no blacklist entries. Entries
from the selected pair and every higher level's roles form the additive policy
described in [org-hooks.md](org-hooks.md#effective-blacklist). A role entry
cannot remove a deny from the org or a higher level.

The binary embeds the role library from `internal/rolepolicy/library/` with `go:embed`. Bare `org init` creates
no `roles/` directories and uses these read-only built-ins for rendering and lane selection. `org roles init`
installs editable copies for the enabled levels without a network request or an agent session. The org owner
can edit those sources or add another paired Markdown and TOML file. Org-owned sources take precedence for the
same level and role; their driver list replaces the built-in list. The default example instances use `executor` at L3, `supervisor`
at L4, the historical `top-supervisor` alias at L5 and `supervisor` at L6. Both `top-supervisor` and the modern
`top` have real, paired role and driver sources with the same policy.

An existing level's `roles/` directory is explicit org driver policy. A fallback's
effective drivers are the intersection of its embedded list and drivers permitted
by the valid org-owned roles at that level. An explicitly empty directory permits
no fallback driver. With no `roles/` directory, the shipped default policy applies,
as in a bare-init org. Malformed, unreadable or incomplete entries refuse; they
never request fallback. Built-ins add no settings or tool permissions. Existing
org settings and hooks continue to apply. The org driver sources that constrain a
fallback are retained with its lane inputs and bound into its driver-policy hash.

| Level | Role | Scope | Default drivers |
|---|---|---|---|
| L3 | `executor` | Implement one change in its worktree and verify it with tests. | `codex`, `claude`, `claudock` |
| L3 | `reviewer` | Read a change and report findings with severity and file:line; never edit. | `codex`, `claude`, `claudock` |
| L3 | `tester` | Write and run black-box tests against the running system. | `codex`, `claude`, `claudock` |
| L3 | `docs` | Write and check documentation. | `codex`, `claude`, `claudock` |
| L3 | `researcher` | Read sources and report conclusions without code changes. | `codex`, `claude`, `claudock` |
| L4 | `supervisor` | Plan, brief and verify L3 lanes; merge nothing. | `claude`, `claudock` |
| L4 | `reviewer` | Independently review a stream; read only, with no implementation or dispatch authority. | `codex`, `claude`, `claudock` |
| L5 | `top` | Own a domain, decide authorized merges and report to the human. | `claude`, `claudock` |
| L5 | `top-supervisor` | Historical alias of `top`, used by the L5 example instance. | `claude`, `claudock` |
| L5 | `supervisor` | Coordinate a domain within its explicit brief. | `claude`, `claudock` |
| L5 | `reviewer` | Independently read domain changes and evidence; give a verdict without editing or landing work. | `claude`, `claudock` |
| L6 | `supervisor` | Maintain org policy and supervision boundaries. | `claude`, `claudock` |

```sh
laneboss org roles list ./research
laneboss org roles init ./research
laneboss org roles init ./research --update
```

List prints JSON with `library` and `roles` arrays. Each entry names the level, role, default or current drivers,
and the actual Markdown source hash. `roles` lists the effective sources: org paths start with `.laneboss/` and
embedded fallback paths with `builtin/`. Embedded role and driver bytes are retained with lane brief inputs;
instance rules include the built-in role text directly because it has no on-disk import target.
`org roles init` creates missing library sources and leaves every existing source
unchanged. It renders instance rules from the resulting sources. `--update` explicitly authorizes replacing
existing library sources; it prints their current-to-library diff to stderr before writing any replacement.
Custom roles outside the library are retained. Generated files still pass the existing hand-edit checks.

For example, `.laneboss/L3/roles/reviewer.md` is ordinary Markdown without front matter:

```markdown
## Scope

Review the assigned change without editing it.

## Responsibilities

Inspect the diff and test evidence. Explain each defect and its effect.

## Deliverable

Findings with severity and file:line, or the reviewed scope and remaining limits.

## Must not

Edit files, merge, deploy, or accept an executor's report without reviewing its evidence.
```

Its neighboring `reviewer.toml` contains only the driver list:

```toml
drivers = ["codex", "claude", "claudock"]
```

The four named sections are required; their bodies are free text. Sources must be ordinary bounded UTF-8 files
inside the org. Role paths, driver paths, their parent directories and protocol sources cannot be symbolic links.
Drivers are distinct command basenames, compared exactly to `argv[0]`'s basename. A wrapper such as `sh`, `bash`
or `zsh` needs its own explicit entry; the launcher does not strip a wrapper to find an allowed inner command.
Allowing a wrapper therefore authorizes that wrapper itself.

The one exception is a bare `env` followed by one or more plain `NAME=VALUE` words and then the program, which is
what `laneboss init` writes for Codex (`env CODEX_HOME=... codex ...`): the command is then also allowed when that
program is on the role's list. A name is a shell identifier, and a value holds only ASCII letters, digits and
`_ . / : , + @ % = -`. A value with `$`, a backtick, a quote, a backslash, a brace, whitespace or a control
character is not plain, and neither is a word that carries `=` but is not `NAME=VALUE`. `env` with any option (any
word starting with `-`, such as `-i`, `-u`, `-C`, `-S`, `--split-string` or `--`), with no assignment, with another
`env` after its assignments, or named by a path such as `/usr/bin/env` is not looked through: it is refused unless
`env` has its own entry. The assignments are not otherwise judged: a `PATH=` or `LD_PRELOAD=` there changes what
the named program runs, as another program with the same basename would.

Bind the named configuration to the absolute org folder in its `config.toml`:

```toml
org_dir = "/absolute/path/to/research"
```

When `org_dir` is absent, `organisation = "research"` selects the org folder under
`$LANEBOSS_HOME/orgs/research`. Lane flags cannot choose an alternative org or a template file. The default lane
level is 3; `--level` can select another enabled level.

```sh
laneboss lane start --config research --project project --lane review-change \
    --brief briefs/review.md --level 3 --role reviewer --difficulty review --budget 15
laneboss lane adopt --config research --lane existing-review --worktree /absolute/path/to/worktree \
    --session SESSION_UUID --runner agent --model example-model-medium-1 \
    --brief briefs/review.md --level 3 --role reviewer --budget 15
laneboss org validate ./research --config research --format json
laneboss config validate research
```

The caller defaults to the `supervisor` principal. Every start or adoption, for either principal, needs a role
template at the selected level, including when the human setting below is enabled. Missing or unknown roles are
refused with an `Instead:` line listing that level's roles. The selected runner must also be allowed by that
exact role at that exact level. Start checks `command`; adoption checks both `command` and `resume`; resume
and turn recheck `resume` against the recorded role and current org sources. The worker checks again before
executing its runner, and refuses source changes made between planning and execution.

The rendered lane brief contains shared org sources, the selected level protocol, a
`## Your role: reviewer (L3)` section with the template bytes, and then `## Your task` and the original task
bytes. The launcher block follows the task. `brief.rendered` retains all consumed org source bytes under their
hashes. `lane.started` and `lane.adopted` record `role` and `role_context`, whose fields are `org_dir`, `level`,
`sha256` (the Markdown bytes), `drivers_sha256` (the driver file bytes), `org_sha256` (the org setting bytes),
and `principal`. Resume and turn retain
the role and refresh its source hashes. They refuse a configuration that selects a different org from the
recorded one. Historic events without this extension remain readable.

The generated `## What your org hook refuses` section tells the agent to run `laneboss org blacklist list` first and follow its rules. It names absolute source paths in hook order: `org.toml`, the selected role's TOML when present, and every existing role source at higher enabled levels. Embedded fallback roles have no source path. The list command detects the authenticated lane's identity and shows its effective entries with bands, descriptions, `Instead:` routes and source files, plus built-in refusals. Paths are current at the start of the run and refresh on resume and turn; the hook and list command read current policy sources.

Idle turns started automatically by `lane loop` preserve a separate byte contract: the complete configured
idle payload starts at byte zero, followed by the shared protocol, level protocol, role and applicable recorded
decisions in the same message. The policy following that payload introduces no additional task. A manual
`lane turn --idle`, ordinary task turns and mail turns retain policy before `## Your task` and the original
payload bytes, even when those bytes match the idle message. Queued mail takes precedence over
`lane turn --idle` and keeps the task ordering. Both forms retain the policy source bytes and hashes.

The same two events also record the lane's report line (see [the dashboard guide](dashboard.md)): `level`,
`level_source` and `starter`, beside `role` and `role_context`. The lane's level is the `--level` of the start or
adoption (3 when absent), and `--role` always names the org role template at that level; it is never read as a
`[supervisors]` entry or an org instance name. The level is recorded with the source `protocol` for L3, the
protocol's own lane level, and with the source `org` for a higher level that the org's role policy chose. A lane's
level must be below its starter's recorded level, and the launcher block of the rendered brief carries the lane's
`## Report line` section after the org sources, the role section and the task.

The human at a controlling terminal, with no recorded lane, session or ticket, can explicitly use `--principal human`.
A launcher-bound lane cannot change its
principal to human: its runner process carries `LANEBOSS_LANE` and `LANEBOSS_PRINCIPAL=supervisor`, and the
launcher refuses `--principal human` when `LANEBOSS_LANE` or `LANEBOSS_INSTANCE` is set or `LANEBOSS_PRINCIPAL` is
`supervisor`. The flag declares the caller at the local CLI boundary, not an authenticated remote identity: an org
instance identified only by its working directory carries none of these variables, and any process can clear
them. The launcher resolves who is calling before the role gate runs. A `LANEBOSS_LANE` label that no recorded lane
carries, or that names a lane other than the one the caller's process ancestry proves, is refused first, as an
unproven identity (`LANEBOSS_LANE disagrees with the caller's recorded lane identity`); the role gate never sees
such a start. Where the identity does resolve, it decides instead of the flag and the environment: a lane (by its
recorded process ancestry or terminal pane), a supervisor (by its recorded session or terminal ticket) or an org
instance that declares `--principal human` is refused by the role gate with its own message (`a supervised
session cannot select a human principal`), before any role is selected, and a lane, supervisor or instance cannot
be turned into the human by removing an environment variable. A caller that nothing identifies (a headless
process with no recorded session and no terminal) is not the human either, and it starts nothing: a lane start or
adoption from it is refused first, with `the caller has no recorded identity` and an `Instead:` route (register with
`laneboss start --role ROLE` from the persistent session, or run the command from a terminal as the human), before
`--principal` or the role gate is looked at, so no lane's `role_context` records a human that the launcher did not
authenticate. The environment markers above remain a second check for the authenticated human. No start or adoption is role-free for
either principal. The org owner may still write this setting in `.laneboss/org.toml`:

```toml
[lane_roles.L3]
allow_human_without_role = true
```

The setting is accepted and validated (the default is false at every enabled level), but it grants nothing until
identity binding can authenticate a human: a role-free start is refused with or without it. There is no
`require_role` setting that can relax the gate.

Older orgs with no role directories resolve supported roles from the embedded library. Custom roles and
historical aliases absent from that library need paired org sources before they can render or launch.
Use `org roles init` to install editable templates and supported legacy aliases. That
command installs the library and supplies templates for the previous generator's `stream-supervisor`,
`top-supervisor` and `org-supervisor` example identities when present, without changing instance identities.
An instance with no template in either source library is a validation error. A historic lane without a
recorded role needs a new start with a role; reading its events does not migrate its identity.

## Schema version 1

Both TOML files require `schema_version = 1`, refuse unknown fields and reject controls and Unicode surrogates in
strings. Arrays contain no duplicates. Names and ids are data; validation does not grant their permissions.

An org config created with the name `research` contains the following identity
and defaults, plus the twelve entries described in [org-hooks.md](org-hooks.md#laneboss-provided-tasks):

```toml
schema_version = 1
name = "research"
company = "research"
levels = [3, 4, 5, 6]
owner_channel = "owner"

[secret_store]
kind = "keychain"
path = "laneboss/research"

[defaults]
level = 3
role = "executor"
services = []
secrets = []
writable_repos = []
```

| Org field | Shape |
|---|---|
| `schema_version` | Required integer, exactly 1. |
| `name`, `company`, `owner_channel` | Required simple names using `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Owner channel is a channel name, not a credential or URL. |
| `levels` | Required nonempty array of distinct integers from 3 to 6. |
| `secret_store.kind` | Required `keychain` or `file`. |
| `secret_store.path` | Required nonempty string. For keychain, simple names separated by `/`. For file, an absolute path outside the org, without empty, `.` or `..` components. |
| `defaults` | Required table with `level` and `role`; optional instance channel id and the four arrays described below. The default level must be enabled. |
| `lane_roles.L<N>.allow_human_without_role` | Optional boolean for an enabled level. Default false. Accepted and validated, but it grants nothing until identity binding: every start still needs a role. |

An instance config looks like this:

```toml
schema_version = 1
name = "L4-review"
level = 4
role = "reviewer"
discord_channel_id = "123456789012345678"
services = []
secrets = ["REVIEW_API_KEY", "REVIEW_CHAT_TOKEN"]
writable_repos = ["project", "worktrees/review"]
```

| Instance field | Shape |
|---|---|
| `schema_version` | Required integer, exactly 1. |
| `name` | Required simple name, equal to its directory name. |
| `level` | Required integer from 3 to 6, enabled in `org.toml` and with a level directory present. |
| `role` | Required nonempty UTF-8 string, at most 128 characters. When its level has a role directory, it must be safe as one filename and have a template there. New instances require a safe filename even before migration. |
| `discord_channel_id` | Optional string of 1 to 20 decimal digits. A channel id is not a secret. |
| `services` | Required array of simple service names. Phase A checks shape, not service availability. |
| `secrets` | Required array of secret names matching `[A-Z][A-Z0-9_]{0,63}`. |
| `writable_repos` | Required array of org-relative repository or worktree paths, with no backslash, empty, `.` or `..` components. The repositories need not exist yet. |
| `allowed_tools` | Optional legacy array of tool names matching `[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`; recorded compatibility data, never enforced as a hook allowlist and omitted by init. |

`writable_repos` and `allowed_tools` remain recorded instance data. The org hook
uses one blacklist behavior: tool allowlists and legacy write allowlists are not
enforced, including for unversioned orgs and the old `mode = "strict"` spelling.
Explicit denials, protected files, secret reads and the L3 lane boundaries remain
active. `org render` and `org validate` warn once about ignored legacy allowlists. The `defaults.level` and `defaults.role`
fields describe the org's default identity for future integration; `instance add` still requires both explicit
flags. Init gives each example its own level and the corresponding generic role.

## Render and load the rules

`laneboss org render ORG_DIR` reads Markdown sources in each protocol directory in sorted relative-path order,
including nested Markdown files. It renders the org root, every enabled level and every instance. Shared sources
come first, then the selected level, its instance role template, and the instance's notes. Add or edit source
files and run render again.
Protocol source path components use letters, digits, `.`, `_` and `-`, starting with a letter or digit, so every
generated relative import is unambiguous.

Claude Code follows import lines in `CLAUDE.md` (`@` and a relative path). The root file imports shared sources, a level file
imports shared and level sources, and an instance file with a role template has three imports:

```text
@../../L5/CLAUDE.md
@../../L5/roles/top.md
@state/notes.md
```

Start the agent with its instance folder as its working directory. Claude's ancestor rules include the org root;
the explicit level import supplies the level rules even though that level directory is not an ancestor. Claude
sessions started in a repository or worktree receive shared org rules from the root. Phase A does not automatically
assign an instance to a session launched elsewhere.

Codex discovers `AGENTS.md` through its directory instruction hierarchy, which may begin at the Git project root
rather than the enclosing org. When starting Codex directly in a repository or worktree, ensure its instructions
include the org rules; the org commands do not modify repositories. Claude-style imports (`@` and a path) are treated as
unsupported in Codex: every generated `AGENTS.md` has the actual source text inlined, including the selected level
and instance notes. Relative imports in source text are expanded by
laneboss for Codex, rather than left for the agent to load. This safe form keeps both runners' rule content drawn
from the same sources. Current runner discovery details are described in the
[official Codex guide](https://developers.openai.com/codex/guides/agents-md); the template does not depend on an
undocumented Codex import feature.

Protocol imports must resolve to readable source files inside the org. Cycles and excessive nesting are refused.
Sources should refer to source files, rather than generated `CLAUDE.md` or `AGENTS.md` files. Do not place secret
values in an imported file.
Render checks expanded output for credential shapes before writing, as well as checking the source files.

Render uses `.laneboss/render-manifest.json` to check the previous generated bytes before writing. Identical bytes
are left in place, including their modification times. A hand edit anywhere in generated rules stops rendering
before it changes any file, with a hint to edit the protocol source. Move the intended change into the relevant
source, restore the last generated file from your backup, then render. Do not change the manifest to approve a
hand edit. A missing generated file can be recreated; a missing or damaged manifest requires restoring the
manifest alongside its generated files. Writes are atomic per file; an I/O failure can leave a partly updated
tree, so keep backups and inspect the tree before retrying.

## Validate and keep secrets outside the org

`laneboss org validate ORG_DIR [--format text|json] [--config NAME]` checks required directories and files, both
TOML schemas, generated file ownership, imports, instance level and role references, and paired driver files.
With `--config`, it checks only that named configuration, reports runner commands no level and role permits,
and reads its lane role records without writing to the store. `config validate NAME` also reports such runner
commands. An unused template is a warning; without `--config`, the warning states that lane usage was not
checked, and with it the warning covers instances and lanes in that named configuration. It also scans root rules and every file inside
`.laneboss/`, including protocols, hooks, tools, services and state, plus any source files reached by imports.
It scans the remaining org contents, including repository and worktree files, for credential text as well. Git
metadata directories and `.git` worktree links are excluded. Workspace symbolic links are scanned as entries
(their names and stored targets), without following their contents outside the org.

The secret detector checks known credential shapes, such as token prefixes, private keys, authentication headers,
password-bearing URLs and webhook URLs, and literal assignments to credential fields. It checks raw text as well
as parsed managed TOML and JSON, so a token in a comment or an escaped managed value is still refused. Diagnostics
name the file and the rule without repeating the secret. Unknown arbitrary strings cannot be proved to be secrets;
names-only configs and external storage remain the rule.

The binary decision store is recognized only at exactly `.laneboss/shared/services/decisions.sqlite`.
Its `-wal`, `-shm` and `-journal` paths receive binary handling only when their contents have the corresponding
SQLite format for that database's page size; WAL checksums and SHM header checksums and WAL salts are checked.
Without the main store, or when a companion is not valid, it is an ordinary managed file subject to the UTF-8
and credential rules. Every path must still be a regular file, never a symbolic link or device.

The scan copies the bounded, no-follow snapshot bytes into a private `0700` temporary folder with `0600` files.
SQLite opens that copy read-only, without `nolock`, and reads its current committed WAL pages. Locks and SHM
updates affect the copy only; the live store is never opened by SQLite. The copy is removed before the scan
returns, and removal failures are reported. Live file identities, sizes, modification times and hashes are
checked before and after reading. Both a committed WAL and a checkpointed WAL-mode store are supported.
The scan reads schema text and every ordinary table's string values, including FTS shadow tables and decisions
that are no longer in force. FTS virtual-table text is read once through its ordinary content shadow table,
so the same bytes are not charged twice against the text budget.
Valid UTF-8 BLOB values are scanned too, including `records.verbatim`; non-UTF-8 encodings are allowed only for
the named vector and FTS binary columns. The schema must match the same version-4 contract used by lane hooks;
unknown tables, views, triggers, indexes or changed definitions are refused. Ordinary extra tables are scanned
before refusal; unknown virtual-table modules are not invoked. Stored record JSON is also checked after decoding.
The same credential detector used for files scans snapshot record values separately, using SQLite record
boundaries, including older main-file and committed WAL page images. Overflow payloads are reassembled before
their individual values are checked. Raw unused regions, free space and trailing bytes remain covered, along
with companion bytes. Separate live values and unused regions are not joined into a synthetic credential.
Diagnostics identify the file or table, row key and column without repeating a secret.

An unreadable, corrupt, changing or unrecoverable store fails with
`decision store cannot be read; secret scan could not complete`. The existing time and entry budgets apply.
Each store file and the total schema/row text scanned are bounded by the 2 MiB validation limit; exceeding a
budget fails validation. The exception remains limited to the exact default path: a configured alternate store
path or case variant still takes the ordinary UTF-8 rule. Decision-service, CLI and lane-history writers enable
`secure_delete` to erase deleted content,
but the raw-byte scan also checks older bytes that might already exist.

Binary files are not imported into generated rules or briefs. The decision guide screens text quoted in briefs
and both `--ask` response paths screen recorded answers before returning them. The org hook protects the whole
`shared/services/` folder from instance writes. Other binary files, including a neighboring `notes.bin`, still
fail the UTF-8 rule.

All other managed files must be ordinary UTF-8 text of at most 2 MiB each; symbolic links, devices, unreadable files and
files that cannot be scanned fail validation. Service TOML and managed JSON must parse. Service configs have no
service-specific schema in phase A. A service credential field can refer to a name such as `REVIEW_API_KEY`;
a channel id can be stored directly, while a webhook URL must stay in the external secret store.
Workspace files are scanned in chunks, including recognizable credential text in binary assets; they have no
org-specific schema or text-size limit. Repository publication checks still belong in each repository's workflow.

Secret values live in the OS keychain or a file with mode `0600` outside the org and every repository. A keychain
`path` names the namespace; a file `path` locates an external store. Validation checks the path's shape and its
separation from the org. It never opens the external store or tests secret availability. Phase A neither creates
the secret store nor connects to services.

The default text format prints `org is valid` on success and warnings to stderr. On failure it prints one
diagnostic line per problem to stderr. `--format json` preserves the two-key validation object on stdout:

```json
{"valid": true, "problems": []}
```

On failure, `valid` is false and `problems` holds objects with `path` and `message` fields. Validation exits 0 for
a clean tree, including one with warnings, and 2 for problems. Use `--format json-diagnostics` to include a
`warnings` array alongside `valid` and `problems`, or read the default text diagnostics. Both JSON forms retain
every real problem and the same exit status. `--config NAME` adds named lane usage to either diagnostic form.
Init, roles init, instance add and render print one JSON object with `ok` and a count of
changed files on success, and exit 2 with diagnostics on a refused request.

The generic generator, schemas and documentation belong in the public laneboss repository. An org's own rules,
configs, instances, generated files and state are private. Keep the org folder outside public repositories and
back it up privately; if an enclosing repository tracks other material, exclude `.laneboss/` and the root rule
files from publication. Working repositories retain their own public or private status.

Supervisor registration follows the named configuration's identity mode. With a
configured service, the human at its attested terminal issues a scoped ticket and
the persistent supervisor presents `--ticket-file PATH`; later start/adopt gates
resolve that service-owned registration. Local `sessions/` and `roles/` files
cannot create new supervisor identities in this mode. Freeze existing live legacy
records once during activation, then require tickets after those processes exit.
Without a service, the 0.7.0 bootstrap remains open and emits the R25 notice.

# An org in one folder

An org keeps its repositories, lane worktrees, rules and agent instances together. `laneboss org` creates and
maintains this structure using only the Python standard library. Its example rules describe generic supervision;
edit the protocol sources for your own topic.

The commands take the org folder explicitly. They work independently of `--config`, `LANEBOSS_HOME` and the
launcher's existing configuration and event stores. They provide the tree, instance data, rendering, validation,
the shared hook and its runner registration ([org-hooks.md](org-hooks.md)). Lane start does not check an org
instance's runner command yet.

## Create an org

```sh
laneboss org init ./research --levels 3-6 --name research
laneboss org instance add ./research L4-review --level 4 --role reviewer \
    --discord-channel 123456789012345678 --secret REVIEW_API_KEY --secret REVIEW_CHAT_TOKEN
laneboss org render ./research
laneboss org validate ./research
laneboss org validate ./research --format json
```

`org init ORG_DIR [--levels LEVELS] [--name NAME]` defaults to levels 3 through 6 and the org folder's basename as
its name. `--levels` accepts an ascending range (`3-5`), a comma list (`3,5`) or one level (`5`); only 3, 4, 5 and
6 are allowed. The name must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Init sets `company` to the same name, for
later use as a guard scope identifier; you can edit it in `org.toml`.

Init creates missing directories and may use an existing empty `.laneboss/`. It refuses a nonempty `.laneboss/`,
a `.laneboss` symbolic link, or existing root `CLAUDE.md` or `AGENTS.md` files. Preserve existing rules and prepare
their content as protocol sources before initializing a folder that already has them. Existing repositories and
an existing ordinary `worktrees/` directory are retained.

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
| `.laneboss/org.toml` | Org identity, enabled levels, owner channel name, external secret store and instance defaults. Edit this data. |
| `.laneboss/render-manifest.json` | Hashes of the last generated rule files. Render owns this file; keep it with the generated files when backing up the org. |
| `shared/protocol/*.md` | Editable shared protocol sources, including `rules.md`. Every level receives them. |
| `shared/hooks/` | The one shared hook (`org-hook.py`) and the org-wide rule data (`rules.toml`). |
| `shared/tools/` | Org-wide tools supplied by the org owner. Init leaves it empty. |
| `shared/services/` | Service configs supplied by the org owner. Values such as channel ids and secret names belong here; secret values do not. Init leaves it empty. |
| `L<N>/protocol/*.md` | Editable rules for this level, including `role.md`. Other levels do not receive these sources automatically. |
| `L<N>/CLAUDE.md`, `L<N>/AGENTS.md` | Generated shared rules followed by this level's rules. |
| `L<N>/hooks/` | This level's rule data for the shared hook (`rules.toml`). |
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

The instance name uses the same simple-name grammar as the org name. Its level must already be enabled and its
directory must not exist. Role is a nonempty string of at most 128 characters. `--discord-channel` takes a
decimal channel id as a string, with 1 to 20 digits. `--secret` may be repeated and accepts uppercase secret
names, never their values. Duplicate names are refused.

The new instance inherits the `services`, `secrets`, `writable_repos` and `allowed_tools` arrays from the org's
defaults. Command-line secret names are appended to the default secret names; a command-line channel id replaces
the default channel id. The command creates the state skeleton and renders all rules after checking the existing
generated files for hand edits. It installs no service or secret and sends no message.

## Schema version 1

Both TOML files require `schema_version = 1`, refuse unknown fields and reject controls and Unicode surrogates in
strings. Arrays contain no duplicates. Names and ids are data; validation does not grant their permissions.

An org config created with the name `research` contains:

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
allowed_tools = []
```

| Org field | Shape |
|---|---|
| `schema_version` | Required integer, exactly 1. |
| `name`, `company`, `owner_channel` | Required simple names using `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Owner channel is a channel name, not a credential or URL. |
| `levels` | Required nonempty array of distinct integers from 3 to 6. |
| `secret_store.kind` | Required `keychain` or `file`. |
| `secret_store.path` | Required nonempty string. For keychain, simple names separated by `/`. For file, an absolute path outside the org, without empty, `.` or `..` components. |
| `defaults` | Required table with `level` and `role`; optional instance channel id and the four arrays described below. The default level must be enabled. |

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
allowed_tools = ["shell", "file.write"]
```

| Instance field | Shape |
|---|---|
| `schema_version` | Required integer, exactly 1. |
| `name` | Required simple name, equal to its directory name. |
| `level` | Required integer from 3 to 6, enabled in `org.toml` and with a level directory present. |
| `role` | Required nonempty string, at most 128 characters. |
| `discord_channel_id` | Optional string of 1 to 20 decimal digits. A channel id is not a secret. |
| `services` | Required array of simple service names. Phase A checks shape, not service availability. |
| `secrets` | Required array of secret names matching `[A-Z][A-Z0-9_]{0,63}`. |
| `writable_repos` | Required array of org-relative repository or worktree paths, with no backslash, empty, `.` or `..` components. The repositories need not exist yet. |
| `allowed_tools` | Required array of tool names matching `[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`. |

`writable_repos` and `allowed_tools` are policy data for the phase B hook. Phase A validates their shape and keeps
them in `instance.toml`; the current launcher does not enforce them. The `defaults.level` and `defaults.role`
fields describe the org's default identity for future integration; `instance add` still requires both explicit
flags. Init gives each example its own level and the corresponding generic role.

## Render and load the rules

`laneboss org render ORG_DIR` reads Markdown sources in each protocol directory in sorted relative-path order,
including nested Markdown files. It renders the org root, every enabled level and every instance. Shared sources
come first, then the selected level, then the instance's notes. Add or edit source files and run render again.
Protocol source path components use letters, digits, `.`, `_` and `-`, starting with a letter or digit, so every
generated relative import is unambiguous.

Claude Code follows import lines in `CLAUDE.md` (`@` and a relative path). The root file imports shared sources, a level file
imports shared and level sources, and an instance file has two imports:

```text
@../../L5/CLAUDE.md
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

`laneboss org validate ORG_DIR [--format text|json]` checks required directories and files, both TOML schemas,
generated file ownership, imports and instance level references. It also scans root rules and every file inside
`.laneboss/`, including protocols, hooks, tools, services and state, plus any source files reached by imports.
It scans the remaining org contents, including repository and worktree files, for credential text as well. Git
metadata directories and `.git` worktree links are excluded. Workspace symbolic links are scanned as entries
(their names and stored targets), without following their contents outside the org.

The secret detector checks known credential shapes, such as token prefixes, private keys, authentication headers,
password-bearing URLs and webhook URLs, and literal assignments to credential fields. It checks raw text as well
as parsed managed TOML and JSON, so a token in a comment or an escaped managed value is still refused. Diagnostics
name the file and the rule without repeating the secret. Unknown arbitrary strings cannot be proved to be secrets;
names-only configs and external storage remain the rule.

Managed files must be ordinary UTF-8 text of at most 2 MiB each; symbolic links, devices, unreadable files and
files that cannot be scanned fail validation. Service TOML and managed JSON must parse. Service configs have no
service-specific schema in phase A. A service credential field can refer to a name such as `REVIEW_API_KEY`;
a channel id can be stored directly, while a webhook URL must stay in the external secret store.
Workspace files are scanned in chunks, including recognizable credential text in binary assets; they have no
org-specific schema or text-size limit. Repository publication checks still belong in each repository's workflow.

Secret values live in the OS keychain or a file with mode `0600` outside the org and every repository. A keychain
`path` names the namespace; a file `path` locates an external store. Validation checks the path's shape and its
separation from the org. It never opens the external store or tests secret availability. Phase A neither creates
the secret store nor connects to services.

The default text format prints `org is valid` on success. On failure it prints one diagnostic line per problem
to stderr. JSON format always prints one object to stdout:

```json
{"valid": true, "problems": []}
```

On failure, `valid` is false and `problems` holds objects with `path` and `message` fields. Validation exits 0 for
a clean tree and 2 for problems. Init, instance add and render print one JSON object with `ok` and a count of
changed files on success, and exit 2 with diagnostics on a refused request.

The generic generator, schemas and documentation belong in the public laneboss repository. An org's own rules,
configs, instances, generated files and state are private. Keep the org folder outside public repositories and
back it up privately; if an enclosing repository tracks other material, exclude `.laneboss/` and the root rule
files from publication. Working repositories retain their own public or private status.

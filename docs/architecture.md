# Architecture of the launcher core

The launcher is one command, `laneboss`, for supervisor sessions that start
mini-supervisors, executors and reviews. It carries one versioned shared protocol and reads one
configuration per company. The package is generic: it holds no company settings, credentials or
state. This page describes install, configurations and their isolation, the event and state store,
lanes (starting, watching, resuming and collecting runs), refusals (what guards refused in a lane, read from the raw
session records, and the suspected workarounds after them), the protocol and brief rendering, doctor and the commit
scan.

## Layout

| Path | Contents |
|---|---|
| `cmd/laneboss/`, `internal/cli/` | One executable: top-level help, version, safe usage errors and in-process dispatch of every group. |
| `internal/identity/` | Program name, environment prefix and release version. |
| `internal/config/` | Configuration loading, schema validation, bindings and isolation. |
| `internal/event/`, `internal/state/`, `internal/eventstore/` | Event commands, state commands, append-only SQLite storage, hashes and projections. |
| `internal/brief/`, `internal/protocol/` | Brief rendering and embedded shared protocol assets. |
| `internal/lane/`, `internal/laneturns/` | Lane lifecycle, workers, refusal scans, mail, turns, loop and attach. |
| `internal/selfexec/` | Worker arguments for the single binary and migration harness entry points. |
| `internal/doctor/`, `internal/doctorbase/`, `internal/disk/` | Environment checks and disk monitoring. |
| `internal/start/`, `internal/judge/` | Supervisor briefings and the external judge contract. |
| `internal/org/`, `internal/orgtree/`, `internal/orghook/`, `internal/orgdiscord/` | Org commands, rules, hooks and owner channels. |
| `internal/decisions/`, `internal/decisionsrv/` | Decision storage, search, ingestion, resident service and org history. |
| `internal/plugin/`, `plugins/claude-code/` | Installed plugin lookup and the shell plugin's assets. |
| `cmd/laneboss-<group>/` | Per-group entry points retained for the existing `GO_GROUPS` migration harness; not installed. |
| `scripts/install.sh`, `scripts/install/` | Pinned Go builds and immutable, manifest-checked installation. |
| `install.sh` | Fetches a source version and calls that source's installer. |
| `scripts/scan.sh`, `scripts/install-hooks.sh` | Publication scan and its pre-commit hook. |
| `examples/minimal/` | Invented configuration and a shell stand-in runner. |
| `tests/` | Existing black-box harness, moving to its own repository at merge; `LANEBOSS_BIN` selects an absolute path to the single executable. |

The installed runtime is one Go binary. The build uses Go 1.26.0, the TOML parser and the pure-Go SQLite
driver pinned in `go.mod` and `go.sum`. Agent programs, Git and tmux remain external commands.

## Names

`internal/identity/` defines `laneboss`, `LANEBOSS_` and the release version. Installed paths and the
configuration defaults remain `~/.config/laneboss` and `~/.local/state/laneboss`.
The decision export format retains compatibility with earlier names.

## Install

`scripts/install.sh [--prefix DIR]` defaults to `~/.local`. It builds `cmd/laneboss` with the pinned
Go 1.26.0 toolchain, `-trimpath` and `-buildvcs=false`, then runs the temporary Go install helper.
The version directory contains `bin/laneboss`, the plugin files and a SHA-256 `MANIFEST`.
The installer checks every installed file, refuses missing, extra, changed or linked files and incorrect
plugin executable modes, then atomically switches the relative `PREFIX/bin/laneboss` link.
Existing versions stay available for a rollback. See [install.md](install.md) for the commands and layout.

## Command line contract

Every successful command prints one JSON value on stdout (ASCII-safe, sorted keys), except
`event tail` and `doctor`, which print one JSON object per line, `lane loop` without `--detach`, `--status` or `--stop`,
which prints one JSON line for each loop event it appends, as `event tail` prints events, for as long as it runs (it
prints one JSON value for each of the three options), `start`, which prints Markdown
unless `--format json` is given, and `lane attach`, which prints text for a person and has its own exit codes ("Lanes",
"Commands"). Errors go to stderr, one line each,
prefixed with `refused:`, `invalid configuration:` or `integrity problem:`; no message repeats a
value that looks like a credential.

| Exit code | Meaning |
|---|---|
| 0 | Success. |
| 1 | `doctor`: at least one check failed (every check is still reported). |
| 2 | Invalid input or a refused request: usage, validation, binding, isolation, credential shape, a missing brief section, an existing output file, a lane request the lane's state does not allow, or a lane command that could not be carried out (tmux could not create the session, Git refused to remove a worktree). |
| 3 | Integrity problem: a hash, the schema, the sequence or the owner of stored data does not match, or an event id was reused with other content. |
| 70 | An unexpected internal error; `LANEBOSS_DEBUG=1` shows the traceback. |

| Command | Result |
|---|---|
| `laneboss --version` | `{"program", "version", "protocol_version"}` |
| `laneboss decisions ARGS` | Decision-store arguments pass unchanged to the Go decision packages. |
| `laneboss config list` | The names of the configurations, sorted. |
| `laneboss config show NAME` | The validated configuration: `name`, `config_dir`, `state_dir`, `config`, `projects`. |
| `laneboss config validate NAME` / `--all` | `{"valid": true, "configs": [...]}`; `--all` also refuses equal or nested state directories. |
| `laneboss config path NAME` | `name`, `config_dir`, `config_file`, `state_dir`, `store`, and `socket`: the configuration's tmux socket, which its lanes record. |
| `laneboss event append --config N --file F` | Appends one event read from a file (`-` is stdin; never from an argument): `{"id", "seq", "recorded_at", "sha256", "duplicate"}`. |
| `laneboss event tail --config N [--since SEQ] [--lane L] [--follow] [--until KIND]` | One JSON line per stored event with `seq > SEQ`, in order (with `--lane`, only that lane's); `--follow` keeps polling (every 0.2 s) and prints new events as they are committed by any process, until interrupted (exit 0) or, with `--until`, until it has printed an event of that kind (exit 0). |
| `laneboss state events --config N` | Every event as one JSON array. |
| `laneboss state lanes --config N` | The stored lane projection, sorted by lane. |
| `laneboss state rebuild --config N` | Recomputes the projection from events alone, replaces the stored one and prints it in the `state lanes` format. |
| `laneboss state verify --config N` | See "Integrity". |
| `laneboss brief render ...` | See "Briefs". |
| `laneboss lane ACTION ...` | See "Lanes". |
| `laneboss doctor --config N` | See "Doctor". |
| `laneboss start [--config N] [--role ROLE] [--format text\|json]` | The session briefing: Markdown by default, or one JSON value with the keys `configuration` (its name, description, organisation, binding and warnings), `protocol`, `rules`, `role`, `checks`, `lanes`, `events` and `unknown`. Without a configuration, the list of configurations. The `role` section is the `[supervisors]` entry that `--role` names, with its level (the text line `- Level: L5 (top supervisor)`; `level` and `level_name` in the JSON entry; see "Levels"). The `lanes` section groups the lanes as `running`, `ended`, `accepted`, `lost` and `idle` (the lanes of state `waiting` with no run going on, that is, turn-based lanes between two turns, each item with `waiting`: the number of messages that wait for a turn, the returned ones included), and counts the rest as `others`; the JSON key `idle` is always there, and the text form prints the group "Idle, waiting for a turn (N):" only when N is above 0. Read-only: no event, no state (what every reader of the store may still do is under "Known limits"). After a successful binding (an overlap the binding itself knows is refused before that, with exit 2), an unsound store, or a state directory of its own that is not isolated, gives exit 3 and no briefing; another configuration that cannot be read gives a warning. |
| `laneboss plugin path [--agent claude-code]` | One JSON string: the directory of the installed plugin. Not bound to a configuration. |

## What isolation covers

Configurations of different companies often live under one operating-system account. The isolation
layer keeps them apart when the supervisors and agents using them cooperate but make mistakes:

- a wrong `--config`, or a binding that is missing or conflicting;
- a wrong or stale path, given on the command line or written in a configuration;
- a leftover or copied symbolic link, an aliased directory, or a path that differs only in letter
  case on a case-insensitive file system;
- a state directory copied, moved or shared between configurations, or two configurations that name
  the same or nested state locations;
- a careless edit of a launcher file: a deleted, emptied or replaced store, a damaged marker, a
  changed event or projection row, a missing kept copy.

It does **not** defend against a process of the same account that works against the launcher while it
runs, and it is not built to:

- moving or swapping a directory or file between the launcher's check and its use (for example
  moving an output directory into another configuration after it was checked, or replacing the store
  file with a link just before SQLite opens it);
- mounts placed over the launcher's directories (bind mounts), and descriptors handed in through
  `/dev/fd` or `/proc`;
- launcher files written by hand to deceive it (a forged marker, store or event that is internally
  consistent);
- a hard link to another configuration's file, which is the same file under a second name.

Such a process can read and write the other configuration's files directly, without the launcher.
Separating configurations against it needs separate operating-system accounts or containers, which is
outside this package. The checks below are written for the first list; where this page says a path is
"refused", it means the launcher refuses it when it finds it, not that another process is prevented
from changing it afterwards.

## Configurations and isolation

The schema is in `docs/configuration.md`. A configuration is loaded and fully validated by every
command that uses it.

- **Binding.** Every command that reads or writes state (`event`, `state`, `brief`, `doctor`, `lane`) is
  bound to exactly one configuration: `--config NAME` or `LANEBOSS_CONFIG` (an empty value counts as
  unset). Both given and different: refused. Neither: refused, with the list of names; the launcher
  never guesses, even when one configuration exists. `config show`, `path` and `validate NAME`
  refuse a name other than `LANEBOSS_CONFIG` when it is set, and `validate --all` refuses to run while
  `LANEBOSS_CONFIG` is set.
- **Derived paths.** Every path a command uses comes from the bound configuration: its directory,
  its state directory and its store.
- **Identity, not path text.** Whether a path lies inside a directory is decided by the device and
  inode of the path's real ancestors (`src/laneboss/fsguard.py`), so a stale or copied symbolic link, an
  aliased directory or a different letter case on a case-insensitive file system does not move a path
  in or out. For a directory that does not exist yet, its deepest existing ancestor is compared by
  identity and the missing part by name without letter case.
- **A configuration directory may itself be a link** (for example into a dotfiles checkout). Every
  file read inside it (`config.toml`, `projects/`, each project file, each standing-rules file) must
  resolve inside that same directory; a link to another configuration or outside is refused before
  anything is read. Links that stay inside the directory are allowed.
- **Inside a state directory nothing is a link.** The marker, the store, `lanes/`, each lane
  directory, `inputs/` and every kept copy are reached through the opened state directory without
  following a link; a link found there is refused before anything is read or written.
- **Other configurations, failing closed.** Every command that reads or writes state reads, for every
  other configuration, only its name and its state location (`state.path`, or the default under
  `$LANEBOSS_STATE_HOME`), through the same guarded reader the configuration's own loading uses, so a
  `config.toml` that leaves its directory through a link is not read. When the bound configuration's
  state directory is the same as, inside or around another configuration's state directory or
  configuration directory, the command is refused, and the other configuration's commands are refused
  for the same reason, so neither side wins. A configuration that cannot be read at all (its
  `config.toml` leaves its directory, is not valid TOML, or its directory cannot be entered, for
  example a link into a directory without search permission) does not stop bound commands, but
  `doctor` fails its isolation check and names it. `start` still prints its briefing then, with a
  warning as the first line under `## Configuration` (and in `configuration.warnings` in `json`) that names
  each unreadable configuration, and the `state.isolated` line stays FAILED. `start` prints no briefing
  (exit 3) only when the `store.recorded` check of its own store fails, or when `state.isolated` fails for a
  reason of the bound configuration's own state directory (it lies inside, contains or overlaps another
  state directory, or cannot be checked).
- **Ownership markers.** A state directory holds `.laneboss-state`, naming its configuration and, once
  created, its store. Every marker from a path up to the root is checked, not only the nearest one: a
  marker of another configuration (or an unreadable marker) anywhere above a state directory or a
  path argument refuses it, so a stray or copied marker nearer to the path does not hide a real one
  above. The state directory's own marker is validated field by field (configuration name, format,
  store id as 32 hex digits, creation time in the launcher's timestamp form, no other field); a marker
  that fails is an integrity problem and nothing from it is printed. A marker's owner is printed only
  when the whole marker is valid and names a configuration that exists under the configuration home;
  any other marker that does not name the bound configuration (a damaged one, or one naming a
  configuration that does not exist) is reported as belonging to "another or an unknown
  configuration", without its content. When markers above a path disagree, a known owner is reported
  first, so a damaged marker does not hide it.
- **Path arguments, checked where they are used.** `--file`, `--in` and `--out` are opened through
  their directory: the directory is opened, its real ancestors are read back through `..` and checked
  (other configurations by identity, every marker, the configuration home and the state home), and
  only then is the file opened relative to that directory without following a link. A path that, as
  written, passes through the bound configuration's own directory or state directory and leaves it
  through a link is refused. An input must be a regular file (a FIFO, device or directory is refused
  without waiting on it) and is read once; those bytes are the ones validated, rendered and kept.
  `--out` is refused inside the bound configuration's own state directory, which only the store
  writes, and when the file exists.
- **Static checks.** No state directory, default or custom, may overlap the configuration home
  (so `LANEBOSS_STATE_HOME` inside `LANEBOSS_HOME` is refused). A custom `state.path` also must not contain the
  state home or lie in another configuration's default state directory; `validate --all` refuses
  equal or nested state directories across configurations.

`laneboss decisions` is a verbatim passthrough (its own `--db` path) and is not yet bound to a
configuration; binding it is left to a later lane.

## Organisations

A configuration can say which organisation it belongs to: `organisation = "NAME"` in `config.toml`
(`docs/configuration.md`). An organisation has a directory of its own, next to `configs/`, and the launcher knows
nothing else about it:

| Path | Contents |
|---|---|
| `$LANEBOSS_HOME/orgs/NAME/` | The organisation's directory. It may itself be a link, like a configuration directory. |
| `$LANEBOSS_HOME/orgs/NAME/tools/` | The organisation's tools: the programs and scripts that the commands of its configurations run. |
| Files inside `$LANEBOSS_HOME/orgs/NAME/` | The organisation's rules files, listed by `organisation_rules`. |

Several configurations may name the same organisation, and a configuration without the key belongs to none. In this
version the launcher only reads under `orgs/`: it never creates, writes or removes anything there. The person who
owns the organisation makes and keeps its directory, its tools and its rules files, and a configuration that names
an organisation is valid even when that directory does not exist yet.

- **The organisation's rules files.** `organisation_rules` lists relative paths (the grammar of `rules`: no `..`, no
  `.`, no empty part), and is refused when `organisation` is absent. Each file is read inside `orgs/NAME/` with the
  same guarantees a configuration's own files have: it must resolve inside that directory, so a link that leads
  outside it, or into another organisation's directory, is refused; it is at most 1 MiB, UTF-8 and free of
  credential shapes (the refusal names the line, never prints it); and a missing file is refused by `config
  validate`. Every refusal names the key path, for example `organisation_rules[0]`. They are rules files like the
  others, with a place in the order: the organisation's files come first (in the order listed), then the
  configuration's, then the project's. `Configuration.rules()` returns them in that order, each organisation file
  under the label `orgs/NAME/<path>`, and a rendered brief (`brief render` and `lane start`) appends their text under
  that label, the `brief.rendered` event lists them among its inputs (role `rules`) with the hash of their bytes,
  and the briefing prints them first. Because `orgs/NAME/<path>` is that label and must mean one thing, a `rules`
  entry of a configuration or of a project whose first part is `orgs` is refused by `config validate`, naming the key
  path.
- **What an organisation's rules say is the organisation's own business.** The launcher reads, hashes and passes
  them on; it ships none, writes none and interprets none.
- **Tools are not shared between organisations.** `laneboss config validate` refuses a configuration that names an
  organisation and in which an element of a runner's `command` or `resume`, or of a judge's `command`, is an absolute
  path inside `orgs/OTHER/` for an organisation OTHER that is not its own. A path inside the configuration's own
  organisation is accepted. The path is compared as written, after `..`, `.` and repeated slashes are folded away,
  without following any link. The message names the key path (for example `runners.local.command[0]`), never repeats
  the value, and says that tools are not shared between organisations.
- **A configuration that names no organisation is not refused for pointing into one.** It may have been written before
  organisations existed, and it keeps working: `config validate` accepts it, and it renders briefs as before.
  `laneboss doctor` fails its check `organisation.tools` instead, with a detail that names the key path of the first
  such element (never the path) and says that the configuration names no organisation: add `organisation = "NAME"`.
  Once the configuration names the organisation whose directory its commands point into, doctor passes; naming
  another one is refused, as above.
- **Known limits of the rule.** Only whole elements that are absolute paths are looked at, so a path inside an option
  (`--tools=PATH`), a relative path, a command found on `PATH` and a link that leads into another organisation's
  directory are not recognised. Since the comparison is of text, neither is a different letter case on a
  case-insensitive file system. The commands of `[test_environments]` are not looked at. An organisation's directory
  that is itself a link is followed, so a link from one organisation's directory to another's makes the first read the
  second's files.
- **Briefing and doctor.** The configuration section of `laneboss start` has the lines `- Organisation: NAME` and
  `- Organisation tools: PATH (present)` (`(missing)` when the path is not a directory), or the single line
  `- Organisation: none`; in JSON, `configuration.organisation` is `null` or `{"name", "tools", "tools_present"}`.
  `laneboss doctor` has the check `organisation.tools`, see "Doctor". Reading whether the tools directory is there
  changes nothing on disk.

## Levels

The layers of sessions that exist have levels, and a larger number is a higher level. The names are written once in
the code (`LEVEL_NAMES` in `src/laneboss/config.py`), and the briefing and the messages of the launcher take them
from there.

| Level | Name | What it is |
|---|---|---|
| L6 | super top | A supervisor above top supervisors. |
| L5 | top supervisor | The highest supervisor of one domain of work. |
| L4 | mini-supervisor | A supervisor of one stream of work, under a top supervisor. |
| L3 | executor lane | One lane: one brief, one executor or reviewer, one worktree. |
| L2, L1 | reserved | What lives inside one session (L2: a sub-agent or a hook-started short session; L1: one tool call). Not used by the launcher. |

The launcher gives the levels their numbers and names and enforces only what a configuration can show:

- A `[supervisors.NAME]` entry of the configuration has a `level`, 4, 5 or 6 (`docs/configuration.md`).
  `role = "mini"` and `role = "top"` are the old spelling of 4 and 5 and are still read. Level 3 is a lane, and a
  lane is not a `[supervisors]` entry; levels 2 and 1 are not used.
- A project's `landing_authority` names a supervisor of level 5 or 6.
- A role is not a level: it is the name of a `[supervisors]` entry, chosen with `laneboss start --role NAME`. The
  briefing's `role` section says the level of the entry it shows.

What a level may decide, which level creates which, who merges and who speaks to an owner are an organisation's own
rules. They are part of its configuration, written in its rules files; the launcher ships none of them and enforces
none beyond the points above.

## Event and state store

One SQLite file per configuration: `STATE_DIR/events.sqlite`. The state directory (mode 0700) is
created on the first write; its marker and the store are created under an exclusive lock on the state
directory, and the marker only ever appears complete (it is written under a temporary name and linked
or renamed into place). Readers hold a shared lock on the state directory while they read the marker
and open the store, so they never see a creation half done, and a reader that still sees content the
marker does not record looks again before it reports anything. Readers create nothing, with one
exception: on a file system where a directory cannot be locked, every command, readers included,
locks a file `.lock` inside the state directory instead and creates that file when it is missing, so
there a reader needs write permission on the state directory and may leave `.lock` behind (an empty
file that holds no data; a lock is released when its process ends). `tests/e2e/test_store.py` reaches
this path by running the installed program unchanged under an interpreter whose `flock` refuses
directories.

Tables: `meta` (format, owning configuration, creation time and a random store id; immutable),
`events` (append-only) and `lanes` (the projection). Triggers abort every `UPDATE` and `DELETE` on
`events` and `meta`, every `INSERT` that would replace an existing event (same `seq` or `id`, which
also refuses `INSERT OR REPLACE` and `REPLACE`), and every `INSERT` into `meta` after creation. The
store is opened by path, after the state directory check showed that `events.sqlite` is a regular
file and not a link (SQLite itself is not asked to refuse links: its `nofollow` URI parameter was
found to have no effect and is not used); its identity (version, schema presence and metadata) is
read in one snapshot.

**A store that existed is never recreated.** Creating the store records its id and creation time in
the ownership marker. From then on every command, `event append` and `doctor` included, refuses with
exit 3 (doctor: a failed check) a store file that is missing, empty or truncated, or that is not the
store the marker records; nothing is recreated. A store file that no marker records is refused the
same way when it holds events, whether the marker is missing or records no store. Only a store
without events (an interrupted creation: the schema was committed, the marker not yet updated) is
adopted by the next write; readers see it as empty.

**Starting over.** Starting a configuration's state again is a deliberate act by a person: remove
both the store and the record of it, `STATE_DIR/events.sqlite` and `STATE_DIR/.laneboss-state` (or the
whole state directory). Keep a copy first if the events matter. The next write creates a new store
from `seq` 1.

**Envelope.** An event file is one JSON object; duplicate keys and non-finite numbers are refused.
A number with a fraction or an exponent must be exactly representable as a double (its shortest
decimal form must equal what was written, so `0.1` and `1e2` pass and `9007199254740993.0` or
`1e400` are refused with a message naming the number rule, never stored rounded). Integers are kept
exactly up to 4,300 digits, Python's limit for converting integers to and from text (the installed
command runs with `-I`, so no environment variable changes it); a longer integer is refused with a
message naming the limit. Write larger numbers as strings.

| Field | Rule |
|---|---|
| `id` | Optional; `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` (the decision store's grammar). Generated as `ev-` and 32 hex digits when absent. |
| `kind` | Required; dotted lowercase, `[a-z][a-z0-9_]{0,31}` parts, two to four of them (`lane.ended`). |
| `lane` | Optional; `[a-z0-9][a-z0-9._-]{0,63}`. Required for `lane.*` kinds. |
| `actor` | Required; `[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}`. |
| `occurred_at` | Optional; the decision store's timestamp grammar (`2026-10-08T09:00:00Z`, optional 3- or 6-digit fraction, `Z` or `+HH:MM`). |
| `payload` | Required JSON object, at most 1 MiB in canonical form. |
| `protocol_version` | Required; `X.Y.Z`, the protocol version the producer follows. |

`seq`, `recorded_at` and `sha256` are set by the store; a caller that supplies one is refused.
Unknown fields are refused. Before anything is stored (before the state directory is even created),
every key and string of the envelope is checked for credentials. A refused value is never printed,
by construction: the error names the top-level field, the depth below it and the rule (for example
`payload (a value at depth 2): looks like a credential (secret-assignment)`), and never prints a key
taken from the input below the top level. A top-level key that holds the refused value, or is part of
it, is described as "a top-level field" instead of printed. The same rule applies to configuration
files, and a configuration file that fails to parse is reported by file, line and column only, never
with the parser's own message.

Reserved kinds are checked against what the launcher itself writes before anything is stored, whoever
appends them: `lane.*` kinds as described under "Lanes", and `brief.rendered` only with exactly the
payload rendering writes (a lane; `inputs` listing the brief, the protocol and each rules file with
`role`, `sha256`, `copy` and `path` or `version`, each copy at `lanes/LANE/inputs/SHA256` present and
hashing to its name; `output` with an absolute path and its hash; `project`; sorted `touches`;
`launcher_version`). So an event that `state verify` would reject is never stored. The kinds of the loop (`loop.*`) are
reserved too, with one difference: their forms are checked at append and nowhere else, never by `state verify` or
`state rebuild`, so that a store written before the loop was built, which may hold such an event of any form that was
appended by hand, still verifies and rebuilds ("The `lane loop` command", "Events").

**Append.** `EventStore.append(envelope)` is the only function that writes events. It validates the
envelope, opens `BEGIN IMMEDIATE`, and then:

- an existing id with identical content (compared in canonical form) is a no-op reported as
  `"duplicate": true` with the stored seq, which makes replay from a spool safe;
- an existing id with different content is an integrity problem (exit 3);
- otherwise it assigns the next `seq` (monotonic, never reused), sets `recorded_at` from the
  launcher's UTC clock (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), computes `sha256`, inserts the row and
  updates the lane projection in the same transaction.

The function takes a plain dictionary and returns a plain dictionary, with no command-line concern,
so a later single-writer network service and an offline spool can sit in front of exactly it.
Nothing else writes an event. Four other writes exist and none of them is an event: creating an
empty store (schema and metadata, once, also inside `BEGIN IMMEDIATE`), `rebuild()` replacing the
derived lane table, the content-addressed copies `laneboss brief render` keeps before it appends the
event that names them, and the message files that `laneboss lane send` keeps in a lane's `mail/` directory,
written once before the `lane.mailed` event that names them and never moved, renamed or deleted (see
"Turns, mail, the loop and attach"). The service lane will move these behind the service as well.

**Hash.** `sha256` is the SHA-256 of the canonical JSON (sorted keys, no whitespace, UTF-8, `null`
for an absent optional field) of `actor`, `id`, `kind`, `lane`, `occurred_at`, `payload`,
`protocol_version`, `recorded_at` and `seq`. Reads (`event tail`, `state events`) recompute it for
every row and fail with exit 3 on a mismatch.

**Credentials.** One detector (`src/laneboss/credentials.py`) checks configuration values, standing-rules
files, events and briefs, with two kinds of rule:

- *Shapes*: private-key headers, authorization headers and bearer tokens, the prefixes of
  code-host, chat, cloud, payment, package-registry, model-hub and embedding-service tokens, JSON web
  tokens and URLs with a password. Hex digests, commit ids and UUIDs match no shape.
- *Assignments*: a value given to a credential name, `token`, `secret`, `password` (or `passwd`),
  `passphrase`, `credentials`, or `api key`, `access key`, `secret key`, `private key`,
  `client secret`, `auth token` written with a space, a hyphen, an underscore or nothing between
  the words, with any prefix such as `DEPLOY_TOKEN` or `db.password`; in text after `:`, `=`, `:=`
  or `=>` (a comparison such as `==`, `!=`, `<=` or `>=` is not an assignment), or as a JSON or TOML
  key with a string value. Every assignment on a line is examined, not only the first one. The value
  is a credential, however short, unless it is a reference or plain language:

| Accepted value | Example |
|---|---|
| A secret name: capitals and digits with at least one underscore | `api_key = E2E_DEPLOY_KEY` |
| `$NAME` (capitals) or `${name}` | `token = $DEPLOY_TOKEN`, `token = ${DEPLOY_TOKEN}` |
| `<placeholder>` or `{placeholder}` | `token = <placeholder>`, `token = {placeholder}` |
| A placeholder word, a type name or a mask | `none`, `required`, `str`, `****` |
| Code: a call, an attribute, an index, a snake_case or camelCase name | `password = read_password()` |
| Unquoted prose: a word (one letter is enough) followed by more words | `Token: a parser symbol.` |

A quoted value is the value itself, and so is the string value of a JSON or TOML field with a
credential name: several words in quotes are a passphrase (`password = "correct horse battery
staple"`, `{"password": "correct horse battery staple"}`), not prose. Everything else under a
credential name is refused, including an upper-case literal (`HUNTER2LETMEIN`), a value that merely
starts with `/`, `$` or `%`, a second assignment after an accepted one on the same line
(`token = $DEPLOY_TOKEN; password = ...`), and a hex digest or UUID (real keys have those shapes).
`tests/e2e/test_detector.py` holds the table both ways, applied to events, briefs, rules files and
configuration values. A refused event leaves nothing behind, not even an empty store: the envelope
(and, for the reserved kind `brief.rendered`, its structure and kept copies) is checked before the
state directory, its marker or the store is created.

## Lanes

A lane is one piece of work done by one executor, mini-supervisor or reviewer: one brief, one runner process
at a time, one working directory, one time budget. `laneboss lane` starts, watches, resumes and collects lanes.
A supervisor learns about every change from events in the store (it subscribes with `laneboss event tail
--follow`), never by polling files and never from the executor's own summary. The launcher starts runs, stamps
times, enforces budgets and reports; it never decides for the supervisor: it does not retry, resume, merge,
accept or clean up on its own. That holds for the lane commands. A lane that a supervisor starts with `--turns` is
continued turn by turn: `lane send` stores a message and `lane turn` starts the next turn, each on the supervisor's
word, and the lane waits between turns (built; see "Turns, mail, the loop and attach"). `lane attach` shows such a lane
in a terminal and types to it (built). `lane loop` is a separate command, started by a supervisor on purpose, that acts
only as declared (built, T3). The one
place where the launcher cleans up on its own is not a lane command either (designed, not built): a resource of a lane
that has ended, whose hard cap has passed, is released by `resource check --read-back` when the adapter's configuration
asks for it with `release_by_itself` ("Resources and cost").

### Life cycle

```
lane start ──> lane.started ──┬─> lane.stuck (log quiet; the run goes on) ─┐
   (run 1)                     ├─> lane.timeout ─> lane.ended reason timeout ├─> lane.ended
                               ├─> lane stop ────> lane.ended reason stopped │   reason exit, limit or dropped
                               └─> supervising process gone ─> (no event) ─> lane check ─> lane.lost
lane resume ─> lane.resumed ─> lane.started (run N+1) ─> ...   (after any end, once no process of it survives)
lane mark --state verifying|accepted|merged|abandoned, --landing merged|deployed|landed
lane clean (merged or abandoned only) ─> lane.cleaned
lane start --turns ─> ... ─> lane.ended ─> state waiting      (a turn-based lane waits; it is never verifying)
lane send ─> lane.mailed        lane turn ─> lane.resumed ─> lane.started (with mail) ─> ... ─> lane.ended
                                                     ─> lane.delivered, or lane.returned (the messages go back)
```

A lane is known to the store once it has a `lane.*` event. `lane start` refuses a known lane that has run
(`run` 1 or more) unless the lane is merged or abandoned and the caller passes `--reuse`; the new run then
continues the lane's run numbers, and `lane.started` says `"how": "reuse"`. A reused project lane gets a new
worktree and branch, so its old ones must be gone first (`lane clean` removes them for a merged lane; an
abandoned lane's branch is kept and must be removed by hand, or the reuse takes `--worktree`). A lane that was
only planned (`lane.planned`, never run) starts normally. A `brief render --lane L` alone does not make a lane
known.

### Commands

All are bound to one configuration and print one JSON value, except `lane attach`, which prints text for a person;
refusals exit 2 and say why.

| Command | What it does |
|---|---|
| `lane start --lane L --brief FILE [--project P] [--difficulty D] [--runner R] [--model M] [--effort E] [--account A] [--budget MINUTES] [--touches billing] [--touches deploy] [--worktree PATH \| --base REF] [--reuse] [--turns [--idle SECONDS]]` | Checks everything first, the disk line (`[disk]`) included; then creates the worktree, renders the brief, starts the run in the background and returns at once with the `lane.started` payload, `lane` and `event` (its id and seq). At the configured stop line the start is refused there, before a branch, worktree or lane directory is made, with the reading in one line and a `disk.stop` event; at the warn line it goes on, says so on standard error and records `disk.warn`. With `--turns` the lane is turn-based: run 1 takes the brief on standard input and its `lane.started` carries `mail` (`[]`), `idle_seconds` (`--idle`, else `[turns] idle_seconds`, else `null`) and the lane's `session_id`; the start is refused, naming each missing part, unless the chosen runner has `{session}` in `command` and in `resume`, `prompt = "stdin"` and a `resume` template. `--idle` needs `--turns` and is a whole number of seconds from 1 to 604800. `--reuse` is refused while a message of the lane waits or has returned, with `--turns` or without it. |
| `lane resume --lane L [--message FILE] [--account A] [--budget MINUTES]` | Continues the same lane in the same working directory with the runner's `resume` template; refused while the lane is running, while its last run's supervising process lives or any of its recorded processes survives, when its latest launch has no run record and no end event without survivors and no `lane.gone` declaration (nothing would show its processes are gone), for a cleaned lane, when the directory no longer carries the lane's claim, and when the lane's session identity and the runner's resume template do not go together: the template uses `{session}` and the lane has no identity, or the lane has one and the template does not use it ("Session identity"). Refused for a turn-based lane (its latest run start carries `mail`): the message says to send with `lane send` and start the turn with `lane turn`. Prints the new `lane.started` payload and the `lane.resumed` event's id and seq. |
| `lane send --lane L (--file PATH \| -) [--from NAME]` | Stores one message for a turn-based lane as a file of the lane's `mail/` directory and announces it with `lane.mailed`; see "Mail". The message is read from the file or, with `-`, from standard input, never from an argument. Prints `lane`, `sequence`, `sender`, `sha256`, `bytes`, `file`, `event` (its id and seq) and `waiting`. |
| `lane loop [--detach \| --status \| --stop]` | The loop of the configuration: it decides when the turns of the turn-based lanes start, and nothing else; see "The `lane loop` command". Without an option it runs in the foreground and prints one JSON line for each loop event it appends; `--detach` runs it in the tmux session `laneboss+loop` and prints `loop`, `pid` and `session`; `--status` prints the loop and its lanes and appends nothing; `--stop` ends the loop and stops no turn. A second loop for the configuration is refused at once. |
| `lane turn --lane L [--idle] [--account A] [--budget MINUTES]` | Starts the next turn of a turn-based lane: a resume whose message is the lane's waiting and returned mail, joined and rendered once, or, with `--idle` and no mail, the configuration's idle message; see "The `lane turn` command". With nothing to send it starts nothing and prints `{"lane", "started": false, "reason": "no mail", "waiting": 0}`. |
| `lane adopt --lane L --session ID --runner R --model M --worktree PATH --brief FILE [--project P] [--effort E] [--account A] [--idle SECONDS] [--budget MINUTES]` | Takes a session that something outside the launcher started and makes it a turn-based lane ("Adopting a session that already runs"). Checks inputs before recording a lane event, taking a claim or rendering a brief; holds the lanes lock from the store refresh through the append. Then takes the working directory's claim, renders the brief (`brief.rendered`) and appends `lane.adopted`. It starts no run: the lane is run 1, not running, state `waiting`, and its first turn is run 2, a resume of the given session. `--idle` defaults to `[turns] idle_seconds`; `--budget` records `budget_minutes`, else `[lanes] budget_minutes`, with no budget in force at adoption. Prints the `lane.adopted` payload, `lane` and `event` (its id and seq). A refused check exits 2, appends no lane event, takes no claim and renders no brief; the state directory, its lock file `lanes.lock` and the account's claims registry may have been created. |
| `lane attach --lane L` | A terminal view of a lane and a keyboard for it; see "The `lane attach` command and the stream readers". It prints text for a person and returns when the person leaves: exit 0 for `/exit` and end of input, 129 and 143 for a closed terminal and SIGTERM, 130 when Ctrl-C leaves it, and 2 for a refusal (a lane that the configuration does not know, for one) or a stop that could not be completed. |
| `lane stop --lane L [--run N]` | Acts on one launch: the lane's latest run (refused when `--run` names another). While its supervising process lives (checked by its recorded identity), it is asked to stop the run; it stops the whole process tree and records `lane.ended` with reason `stopped` (`stopped_by` `supervisor`); a supervising process that cannot be signalled refuses the stop. When the supervising process is gone, already or before it recorded the end of the run it was asked to stop, the run is a lost run with a record: `lane stop` removes the recorded processes that survive itself, each by its identity (`stopped_by` `lane-stop`); `removed` counts only those it then sees gone, and when any survives (a signal could not be delivered, or the process did not end) the command is refused and names every survivor. Prints `lane`, `run`, `launch`, `reason`, `exit_code`, `signal`, `survivors`, `stopped_by`, `event`, `pending` and `removed`. |
| `lane status [--lane L]` | The projection row(s) with `session_id` (the lane's session identifier, or null for a lane that has none; see "Session identity"), `prompt` (what became of the latest run's prompt on standard input, written or cut, from its `lane.ended`; null while it runs and for a runner that takes none), `idle` (on every row: true exactly when the lane's state is `waiting` and no run is going on, that is, a turn-based lane between two turns; a turn that is running is `running`, as any run is) and `live`: the launch, the session (`socket`, `name`) and whether it exists, the supervising process (`pid`, `alive`), how many recorded processes survive it, `stopping` (`since`, `survivors`) while the supervising process cannot remove the run's runner, how many events wait in the pending file (`pending_events`) and how many the store refused for good (`refused_events`), how long the run has been going, the budget left, how long the log has been quiet and its size. Appends nothing. |
| `lane check [--lane L]` | With `--lane` it looks at that lane only (a lane that the configuration does not know is refused, and a lane that is not running gives empty lists); the loop runs it that way for a lane whose supervising process it sees gone, and without `--lane` it checks every lane. First appends every lane's pending events: `recorded` counts those stored, `refused` those the store refused for good (kept in `refused.jsonl`), `pending` what still cannot be appended. Then it reads the lanes the store believes are running, and only after that the process table: a run whose supervising process that complete observation shows gone (by its recorded identity), and that has nothing pending, gets `lane.lost` with the number of its recorded processes that survive. When the process table cannot be read, the command is refused and appends no `lane.lost`; the pending events it appended first stay appended (they were waiting already). Safe to run from a timer: it appends at most one `lane.lost` per run. When the lost run carried mail, its loss returns the messages, and `lane.returned` (reason `lost`, actor `laneboss`) is appended right behind the `lane.lost`; each entry of `lost` has `returned` (the announcement's `id` and `seq`, or null when none was due) and, only when one was due and could not be appended, `returned_error` (one line; the exit code stays 0). |
| `lane mark --lane L --state S`, `--landing F` or `--gone` | Records a supervisor's decision as `lane.state` (verifying, accepted, merged or abandoned; refused while running), one landing fact (`lane.merged`, `lane.deployed`, `lane.landed`), or, with `--gone`, `lane.gone`: the supervisor's statement that the lane's open launch (no end event and no readable run record) is gone. `--gone` is refused while that launch's run record can be read (then `lane stop` applies), while its tmux session is open, and when its end or a declaration is already recorded; afterwards resume, reuse and clean go on, and the launch's end stays unknown. For a run that carried mail, `--gone` also appends the announcement that is due, `lane.returned`, right behind `lane.gone` (reason `gone`, or `lost` when an earlier `lane.lost` settled the messages and nobody announced it), and prints `returned` (its `id` and `seq`, or null when none was due) and, only when one was due and could not be appended, `returned_error`. On a turn-based lane only `abandoned` can be recorded with `--state` (the store refuses any other state at append, after the scan of the gate when `accepted` or `merged` has one), and the state `waiting` is never recorded by it. `--state accepted` and `--state merged` hold the lanes lock; with guards they first scan the lane and are refused while a suspected workaround has a path without a verdict or a run is not covered (`--accept-uncovered` records what was not covered instead; see "Refusals"); the output then has `scan`. `--landing merged` records the landing fact `lane.merged` only: it is not the gated acceptance and does not change the state. Actor `supervisor`, after the lane's pending events. |
| `lane clean --lane L` | For a merged or abandoned lane that is not running: see "Cleaning". |
| `lane scan`, `lane refusals`, `lane review` | Refusals and suspected workarounds: see "Refusals". |

### Choosing runner, model and account

With `--difficulty`, the first usable `[routing]` entry of that difficulty gives the runner, model and effort
(`docs/configuration.md`, "[routing]"); `--runner`, `--model`, `--effort` and `--account` win over it one by one.
Without `--difficulty`, `--runner` and `--model` are required. A model is always a full name with its version; a
family alias is refused. The account is `--account` (the runner must list it and the project must not exclude
it), else the runner's first account the project does not exclude, else none for a runner without accounts. `lane start`
never asks a runner's `room` command (the room command of `lane start`'s first account is designed, not built:
"Accounts and adoption"); a later turn or a resume of a runner with a `room` command takes its account through it.
`lane.started` records the choice and, in `chosen_by`, who made each part: `routing`, `supervisor`, `default` (the
account), `previous` (a resume keeps the previous run's values) or `room` (the account of a turn or a resume that the
walk of the runner's list took through the room command; never at a start). With `--project`, the lane name
must start with the project's `lane_prefix` and the runner must be one of its `workers`.

### Session identity

An agent program can be given a session identifier at the start and resumed by it, so the launcher makes one for the
lane and keeps it: a resume then names the session it continues, never "the newest session of this directory", which a
second session started in the same directory (by a hook, or by hand) can be. The identifier exists for a lane whose
runner's `command` template uses the placeholder `{session}` (`docs/configuration.md`, "Session identity and the prompt
on standard input"):

- **Made at the start.** `lane start` makes a random UUID in its usual lower-case form (8-4-4-4-12 hexadecimal digits)
  and hands it to the `command` template. It belongs to the lane, not to a run: a `lane resume` hands the same one to the
  `resume` template, and `lane start --reuse` (the name of a merged or abandoned lane started again) makes a new one. A
  runner that does not use `{session}` makes none.
- **Kept in `lane.started`**, as `session_id` (a string; the lane's tmux session is `session`, an object). Every run's
  `lane.started` carries it (a resume copies the previous run's). The key is optional when an event is read: a store
  written by an earlier version has none, and verifies, lists, shows its status and resumes exactly as before; an event
  that has the key must hold a valid identifier, or it is refused at append. The projection does not carry it: `lane
  status` shows it as `session_id` (null for a lane that has none).
- **A lane without an identifier** (an earlier version started it, or its runner's command did not use `{session}`
  then) is refused a resume by a runner whose `resume` template now uses `{session}`, before anything is started, with
  a message that says the lane has no recorded session identity and that it can only be resumed by a runner whose
  template does not use `{session}`. The runner as it was resumes it as before.
- **A lane with an identifier** is resumed only by a runner whose `resume` template uses `{session}` (a template that
  does not would continue the newest session of the directory, whichever it is): `lane resume` is refused before
  anything is started, with a message that names the runner and the key `runners.NAME.resume`. This is the case after
  a configuration edit that dropped the placeholder from the template; the edit that restores it resumes the lane.
  That every run of a lane carries the same identifier is the launcher's rule, not the store's: the store checks only
  the form of the key.
- **Records by session.** A `records` path with `{session}` names exactly the files of that session ("Refusals"); for a
  lane without an identifier it is `no-session`: the run is not covered, with that reason.

### Working directory

With `--project` naming a project whose `repository` is an absolute path to a local Git work tree, the lane gets a
new branch named after the lane, from `--base REF` or the repository's current HEAD (`git branch`), and a new
worktree for it at `<repository>-<lane>` (`git worktree add`). The repository's main working copy is never touched,
and `--worktree PATH` may not name it or anything inside it; `--worktree` uses an existing directory instead (no
branch is made). When Git cannot be asked whether a directory lies inside a repository (no `git` on PATH, a Git that
fails for any other reason than "not a git repository", an answer of an unexpected form, or a `.git` entry in or
above the directory that Git does not recognise), `--worktree` is refused rather than taken for a plain directory.
Every working directory is checked like other path arguments (outside every other configuration, the configuration
home, the state home and the own state directory). Lanes whose names differ only by `.` against `_` cannot coexist
in one configuration, because tmux turns `.` into `_` in session names.

A start that fails before its run begins takes back what it made, and only that: the claim it created, the worktree
it created, and the branch it created, deleted only the way Git allows without force (`git branch -d`). A branch or
worktree that existed before, or that another command made in the meantime, is never touched.

**Claims.** One lane of one configuration works in a directory at a time. Starting a lane writes a claim naming
the configuration (with its state directory), the lane, the launch and the directory, created atomically (linked
into place, so it fails when a claim exists). Nothing of it is written into the working directory: for a linked Git
worktree it is `laneboss-claim` in that worktree's own administrative directory (`.git/worktrees/NAME` of its
repository); for any other directory it is a file in the account's claims registry (mode 0700, this user's alone,
refused otherwise), named by the directory's identity (device and inode), where every configuration of the user
finds it and the executor's Git never sees it, even when the executor makes the directory a repository afterwards
(resume and clean look in the registry first). There is one registry per account, whatever the environment says:
`HOME/.local/state/laneboss/.lane-claims/`, with HOME the account's home directory as the user database gives it,
not `LANEBOSS_HOME`, `LANEBOSS_STATE_HOME` or the `HOME` variable; only `LANEBOSS_TEST_CLAIMS_DIR` moves it, and it is
for tests. `lane.started` records the registry that holds the claim (`claims`), and a later command for the lane
that would look in another registry refuses. Start, resume and clean read the claim: another lane's or another
configuration's claim refuses them before any runner starts or anything is removed. Within one configuration, `lane start` also refuses a directory that another lane works in until that
lane is cleaned. Start, resume and clean hold the configuration's lanes lock (`STATE_DIR/lanes.lock`) from their
first check to their last action, so they never interleave: a resume cannot start while a clean removes the
directory, and two starts cannot both claim one directory. The lock is waited for at most `[lanes]
lock_wait_seconds` (default 60); then the command is refused and does nothing.

**Git.** The launcher's own Git commands run without any `GIT_` variable of the caller's environment (`GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR`, `GIT_CONFIG` and the like would redirect them to another
repository, work tree, index or configuration). The runner's own environment is the caller's and keeps them.

### Files

Everything a lane leaves in the state directory is in `STATE_DIR/lanes/LANE/`, reached through the opened state
directory without following a link, and never deleted by the launcher:

| Path | Contents |
|---|---|
| `inputs/SHA256` | Kept copies of every input that was rendered: briefs, follow-up messages, the protocol, rules files. |
| `rendered/SHA256.md` | Rendered briefs and follow-up messages, named by the hash of their bytes; equal renders are kept once. The runner gets this path. |
| `output.log` | The runner's standard output and error, every run appended (never overwritten); `{log}` names it. |
| `watch.log` | The supervising process's own messages (what started, why a run was stopped, errors). |
| `runs/LAUNCH.json` | The run record of one launch: the identities (process id, process group, session and start time as the operating system reports it) of its supervising process, its runner and every process sampled from its tree, whether its processes are gone (`finished`), `stopping` while the runner cannot be removed, and `log` (`start` and `end`: the run's byte range of `output.log`). |
| `scans/LAUNCH.json` | What the latest scan covered of one launch's session records (see "Refusals"). |
| `mail/SEQUENCE-DIGEST` | The messages of a turn-based lane, one file each: SEQUENCE is the message's number as nine digits, DIGEST the SHA-256 of the file's bytes, which are the message exactly as sent. Written once by `lane send` and never moved, renamed or deleted; names that start with `.tmp-` are an interrupted write and are skipped by every reader. |
| `mail.lock` | The lane's mail lock, held by `lane send` from the read of the lane's last sequence to the append of its event; created when missing. |
| `pending.jsonl` | Events that could not be appended yet, one complete envelope a line, in order. |
| `pending-LAUNCH-ID.jsonl` | Events a supervising process could not record or write to `pending.jsonl` before it exited, written whole under the lane's lock; every drainer moves them behind `pending.jsonl` (writing the pending file anew before it removes this one). |
| `refused.jsonl` | Events the store refused for good when they were finally appended, one `{"envelope", "reason"}` a line, each event once (kept, never dropped, counted as refused); a line that was no event at all is kept the same way (`envelope` null, `line`). |
| `.launch-ID.fifo` | Exists only while a run is being started; see below. |

Next to the lanes, `STATE_DIR/lanes.lock` is the lanes lock, and the lanes' tmux sockets are in
`/tmp/laneboss-UID/` (see below). The loop (`lane loop`) keeps three files of its own in the state directory, which it
never deletes and which hold nothing of its environment, and a FIFO that exists only while a detached loop is being
started ("The `lane loop` command"):

| Path | Contents |
|---|---|
| `loop.lock` | The loop's lock: one loop runs for a configuration, under an exclusive lock on this file that it asks for without blocking (ten tries, 50 ms apart) and holds for as long as it lives; the kernel frees it whatever ends the loop. Created when missing. |
| `loop.json` | The record of the loop that took the lock, written whole through a temporary name under the lock: `loop` (its id), `pid` and `start` (its process identity), `since`, `detached` and `last_error` (`null`, or the time and the text of the latest failure: the line written to `loop.log` for a pass that could not be made, for a lane that could not be read, for a started turn whose `loop.turn` could not be recorded, or for an attempt to record `loop.started` that failed). It is written again, whole, each time one of these fails. It stays after a kill, and is believed only while a process with that identity lives. |
| `loop.log` | The loop's own messages, a line with the time for each, appended; the output of a detached loop goes to it. |
| `.loop-ID.fifo` | Exists only while `lane loop --detach` starts the loop; see "The `lane loop` command". |

### Running

`lane start` and `lane resume` do every check before anything starts, including the payloads they will append
(so a credential-shaped path or an alias model refuses the start, not the run). They then claim the directory and
create the worktree (start), render the brief or message (appending `brief.rendered`), and start the run:

1. The configuration has its own tmux server, reached only through an explicit socket path that the launcher
   chooses and every `lane.started` records: `/tmp/laneboss-UID/CONFIGURATION-HASH`, where HASH is 12 hex digits of
   the SHA-256 of the state directory's real path. `/tmp` keeps the path within the length a Unix socket allows on
   every system; the directory is created with mode 0700. On every use (status, check, stop, start, resume, clean),
   the directory is refused when it is a link, another user's or open to others, and the socket path when it is a
   link or not a socket. Commands about an existing launch use the socket its event records, so `TMUX_TMPDIR` or
   `TMUX` in a command's environment never changes which server it reaches. tmux is called with an argument vector,
   `-f /dev/null` (no user configuration) and a fixed environment of five names (`PATH`, `HOME`, `LANG`, `TMPDIR` and
   `USER`), so the server keeps no other variable of its caller. No command kills a session by its name.
2. A new detached session named after the lane runs the launcher's supervising process (`supervise.py`, the same
   interpreter and installed version) with one argument: the path of a FIFO made in the lane's directory. The
   starting command writes the launch's run record with the supervising process's identity (the session's pane
   process).
3. The starting command writes the caller's environment and the run's description (argument vector, working
   directory, payloads, budget, quiet time, grace, patterns) into the FIFO and removes it. The environment never
   touches a file or an argument list, and the run gets the environment of the session that started it, not the
   tmux server's. The lanes lock is released here.
4. The supervising process checks that the run record names it, appends `lane.resumed` (resume) and `lane.started`
   after any events of the lane still waiting in its pending file (when one of those cannot be appended, each
   append waiting at most 10 seconds for a busy store, or the opening events cannot be, the launch ends and nothing
   runs), then creates the runner's argument vector,
   without a shell, in the working directory, in a process group and session of its own (so both ids are the
   runner's process id from that moment, with no second query), with standard input from `/dev/null` and standard
   output and error appended to `output.log`, and adds the runner's identity to the run record. A runner whose `prompt`
   is `stdin` gets a pipe instead of `/dev/null`: a thread of the supervising process writes the bytes of the rendered
   brief (a start) or of the rendered follow-up message (a resume) into it and closes it, so a runner that never reads
   them does not hold up the control loop (its budget and a stop request still end the run, which ends the write, unless
   a descendant that escaped the run's tracking still holds the read end: the write then waits, and the daemon thread
   does not keep the supervising process from ending). The prompt is decoded before the runner is created, and the
   thread starts inside the region that stops the run on any error. What became of it is recorded in `lane.ended` as
   `prompt` (written or cut, with the bytes written) and shown by `lane status`: a failed or short write is also noted in
   `watch.log`, a runner that closes its input early and exits 0 ends normally, with `prompt` `cut`, and so does a
   runner that could not be created (its program is not found: `lane.ended` has no exit status, and `prompt` is `cut`
   with 0 bytes, so a delivery is never claimed). The honest
   limits: written means written into the pipe and closed, not read, so a prompt that fits what the pipe holds (a
   platform default, 64 KiB on Linux, not measured here) is written whole even when the runner never reads it; and a
   supervising process that is killed (SIGKILL) in the middle leaves the runner a short prompt that it cannot tell from
   a whole one, while the launcher later records only a lost run. The runner's environment is the caller's without
   `TMUX` and `TMUX_PANE`, plus `LANEBOSS_CONFIG`, `LANEBOSS_LANE` and `LANEBOSS_RUN`.
5. The starting command returns as soon as it sees its own `lane.started` (matched by the `launch` id), or refuses
   when the supervising process ended first; what it made (claim, worktree, branch) is then given back, since
   nothing ran.

While the run goes on, the supervising process's control loop polls every 0.2 seconds (the runner's exit, a stop
request, the budget, the log's size) and samples the run's process tree when 0.5 seconds have passed since the last
sample. A pass of the loop does no recording beyond writing the run record (a local file), so the time between two
samples is at least 0.5 seconds and at most 0.5 seconds plus one pass: reading the process table (on Linux `/proc`,
elsewhere `ps`, which is given at most 10 seconds) and writing the run record. The store and its locks never enter
the loop. A sample takes:

- on Linux every descendant of the supervising process, which is the run's child subreaper and so adopts every
  process of the run that detaches (unless `LANEBOSS_PROCESSES=portable`);
- the descendants of the runner and of every process it remembers whose identity (id and start time) the same
  sample shows alive; a remembered process seen ended is never used as a parent again, so a reused process id
  leads nowhere;
- the members of the runner's process group and session while that id is verifiably the runner's: the runner is not
  yet collected (its exit is noticed without collecting its status, so its zombie keeps the id while the rest of the
  run is looked for), or a remembered member of the group is seen alive. Outside Linux `ps` gives no session ids,
  so there only the process group is used.

New identities go into the run record, which is written again on every pass until a write succeeds. When the
process table cannot be read, the sample is skipped and nothing is concluded from it.

- **Order.** Whatever ends a run, the supervising process first makes sure every process of the run is gone, and
  only then records anything. Recording never delays stopping.
- **Budget.** When the budget passes, the run's processes are stopped, then `lane.timeout` (with the moment the
  budget passed) and `lane.ended` with reason `timeout` are recorded.
- **Quiet log.** When `output.log` has not grown for the quiet time, `lane.stuck` is recorded once; the run is
  not stopped, and a new quiet period after growth is reported again.
- **Stopping.** Every recorded process of the run and every process found by a last sample get SIGTERM, whatever
  still lives after `stop_grace_seconds` gets SIGKILL. Each signal goes only to a process whose id and start time
  both match its record (on Linux through a pidfd, so the id cannot pass to another process in between; where a
  pidfd cannot be opened, as outside Linux, the check and the signal are two calls); process groups are never
  signalled as a whole. Only what is seen gone afterwards counts as removed. `lane stop` sends SIGTERM to the
  supervising process (checked the same way), which does this and records `lane.ended` with reason `stopped`.
- **A runner that cannot be removed.** `lane.ended` is recorded only once the runner is seen gone. While it cannot
  be removed (a signal is not delivered, it does not end, or the process table cannot be read), nothing is
  recorded: the run record gets `stopping` (`since`, `survivors`), `lane status` shows it, and the supervising
  process tries again every 2 seconds. Once the runner is gone and collected, what else of the run lives gets one
  more SIGTERM and, after the leftover grace, SIGKILL; `survivors` counts what is alive after that, never what an
  observation from before the runner's end showed.
- **Session gone.** SIGHUP (the session or the tmux server was killed behind the launcher's back) stops the run's
  processes and writes no event: `lane check` later records `lane.lost`, as for a machine that restarted.
- **End.** When the runner exits by itself, processes left of its tree (its process group included, whose id its
  uncollected zombie still holds) get SIGTERM and at most one second (or the grace, when shorter) before SIGKILL.
  Then the run's own output is classified by the runner's `limit_patterns` and `dropped_patterns`: the last 64 KiB
  of what this run wrote, each line cut to 4096 characters, matched in a separate process that is stopped after 2
  seconds. That process also ends by itself 3 seconds after it started (an alarm), so a supervising process killed
  while it ran leaves it alive for at most that long (on macOS the end of the session does not end it). The last
  matching line gives reason `limit` or `dropped` (`classification` `matched`), else the reason is `exit`
  (`unmatched`, or `timed-out` when the bound stopped the matching). `lane.ended` carries the runner's real exit
  status, never a made-up one: `exit_code` or `signal` as the system reported it, both null only for a runner that
  could not be created at all, and `survivors`, the number of the run's other processes still alive.
- **When the end is queued.** The end's `occurred_at` is the moment the runner's end was seen. It is queued after
  the leftovers are stopped, the refusal scan's last pass is over and the output classified. With a process table that
  answers, the delay is the sum of the explicit waits: up to the leftover grace (1 second, or the grace when shorter)
  and up to 2 seconds for SIGKILL to take effect, twice at most (before and after the runner is collected), up to 7
  seconds for the refusal scan's last pass and the scanning process's stop (only with guards, see "Refusals"), and up
  to the 2-second classification bound: 15 seconds, plus the time each read of the process table takes (on Linux
  `/proc`, quick; elsewhere `ps`, given at most 10 seconds per read). Usually it is at once. While the process table cannot be read, nothing is
  concluded and the end is not queued: the supervising process tries again every 2 seconds, without a bound, and
  says so in `watch.log`. A stopped or timed-out run is queued once its processes are gone, which has no bound while
  the runner resists (see above).
- **Recording.** The control loop queues each event with the moment it was observed as `occurred_at`. One recorder
  thread beside the loop owns the queued events from then on, the one in flight included, and appends them in
  order. An event the store cannot take within 2 seconds (it is busy) or at all (it cannot be written) is kept in
  `pending.jsonl`, with its own id, and later events of the lane queue behind it. An event leaves the recorder only
  when it is in the store, in the pending file, or refused by the store for good (then it moves to `refused.jsonl`
  with the store's reason and is counted as refused, never as recorded); any other failure (an unreadable pending
  file, an unexpected error) keeps it, and it is tried again every second. Every change to these files replaces the
  file whole (written under a temporary name, synced and renamed), so it is made completely or not at all. At a
  normal exit the control loop only asks the recorder to finish and waits for its answer: from then on the next
  failed attempt ends the attempts, and the event held and every event behind it are kept in
  `pending-LAUNCH-ID.jsonl` in the lane's directory, which every drainer moves behind `pending.jsonl`; then the
  pending events are retried for 10 seconds, and after that `lane check` appends them. An event that cannot be kept
  even there is reported in `watch.log` and the supervising process exits with status 1; so does a recorder that
  ended unexpectedly. `watch.log` ends with the exit status. With a free store `lane.ended` is in the store about 2
  seconds after it was queued at most; otherwise it waits in a pending file with its observed time. `lane status`
  shows how many wait, and `lane stop` and `lane check` take a pending end for an end.
- **Order of a lane's events.** No command appends an event of a lane while the lane has waiting events: the store
  checks for them and appends under the lane directory's lock, refusing (except to the one appending the waiting
  events in order), and lane commands first append the waiting events or are refused. Every write of waiting events,
  a leftover file of the recorder included, holds the same lock, so whoever holds it goes first: a direct append
  that has checked for waiting events is stored before a leftover file published after it, and once a leftover file
  is published, later direct appends are refused until a drain has appended it. A drain waits for the lock without
  a deadline, and each event's append waits at most 10 seconds for a busy store; the first event that cannot be
  appended ends the drain.

The life-cycle events never quote the log. A `lane.refusal` read from a text record does carry an excerpt of the log's
matching line, which is withheld when the credential detector finds anything in it (see "Refusals"). Every value a lane
event carries is checked by the credential detector like any other event.

### Resuming

`lane resume` continues the lane's latest run in the same working directory with the runner's `resume` template
(refused without one), the same runner, model and effort, and the same log (appended). It is refused while the
previous run's supervising process lives or any of its recorded processes survives (`lane stop` removes them), for
a cleaned lane, and when the working directory no longer carries the lane's claim. `--account` changes the account
(the runner must list it, the project must not exclude it); without it the previous run's account is checked the
same way against the configuration as it is now. For a runner with a `room` command the account comes through the choice
of "Accounts and adoption" for a resume as for a turn (`continue_lane` serves both): a previous account the runner no
longer lists or the project excludes is passed over, not refused, and when no account has room the resume is refused
with the message of a turn. `--budget` changes the budget (default: the previous run's).
`{brief}` is the lane's rendered brief, handed over only when it is still a regular file in the lane's `rendered`
directory whose bytes hash to the recorded value; otherwise the resume is an integrity problem (exit 3). When the
template uses `{message}`, or the runner's `prompt` is `stdin`, it gets a rendered follow-up message: `--message FILE`,
rendered like a brief (protocol block and standing rules, no mandatory sections), or, without `--message`, the
package's `protocol/continue.md`. A `--message` for a template without `{message}` is refused, since it would not reach
the runner, unless its `prompt` is `stdin`: the bytes of the rendered message then arrive on its standard input,
whatever the template says. A template that uses `{session}` gets the lane's session identifier ("Session identity");
the resume of a lane that has none is refused before anything is started, and so is the resume of a lane that has one
by a template that does not use `{session}`. The run number grows by one, and
`lane.resumed` records the run, the reason the previous run ended (`after`) and the message. A turn of a turn-based
lane takes this path too: `lane turn` is the same function (`continue_lane` in `src/laneboss/lanecmd.py`) with its
message taken from the lane's mail, and `lane resume` itself is refused for a turn-based lane ("The `lane turn`
command").

### Cleaning

`lane clean` takes a lane marked merged or abandoned that is not running and not cleaned yet, whose last run's
supervising process is gone and of whose recorded processes none survives; a latest launch without its run record
refuses the clean unless an end event without survivors shows its processes are gone (so do resume and a reused
start). When the lane's working directory carries another lane's or another configuration's claim, the clean is
refused before anything is removed.

1. A worktree the launcher created is removed only when it still carries this lane's claim and has this lane's
   branch checked out; anything else at that path (a worktree made there by hand afterwards, for example) is kept
   with `why` `not-this-lane`, and a kept worktree keeps no claim of this lane (it is released).
2. Such a worktree that holds uncommitted or untracked work (`git status --porcelain`) refuses the whole clean:
   nothing is removed and nothing is appended.
3. The worktree is removed with `git worktree remove`, never with force. When Git fails, the clean stops and says,
   from the file system, what the worktree looks like afterwards: unchanged, or partly removed (how many of its
   entries are gone).
4. The branch is deleted only for a merged lane and only when Git agrees it is merged (`git branch -d`); an
   abandoned lane keeps its branch.
5. A tmux session that has the lane's name at the lane's socket is not the lane's (its supervising process is
   gone) and is never killed: it is kept with `why` `not-this-lane`. A `--worktree` directory is kept, and its
   claim is released last; the lane's registry claims on that path under another identity (the directory no longer
   exists, or was removed and made again) are released too, and a directory made there since, with its own claim, is
   left alone.
6. `lane.cleaned` lists what was removed and what was kept, and why. The lane's directory in the state directory
   (logs, rendered briefs, kept inputs, run records) is always kept.

### Events

Every `lane.*` event has a documented payload. `EventStore.append()` checks it before anything is stored, whoever
appends it (a hand-written event included), and checks it against the lane's projection in the same transaction:
`lane.started` and `lane.resumed` only when no run is going on and with the next run number, `lane.ended`,
`lane.timeout`, `lane.stuck` and `lane.lost` only for the run that is going on, a reuse only of a merged or
abandoned lane, and `lane.cleaned` only for a merged or abandoned lane that is not running; the rules of mail (a message only to a
turn-based lane and in sequence, a turn that carries the head of the queue, an announcement due once) are in "Mail
events, the new lane state and the projection". A `lane.started` must
also name the receiving configuration's own tmux socket, the session of its own lane and its own lane's log and
rendered brief (a `lane.resumed` its own lane's rendered message), so an event copied from another configuration
or lane is refused at append. A payload holds exactly the fields below; paths are absolute, hashes are 64 hex
digits.

| Kind | Written by | Payload |
|---|---|---|
| `lane.planned` | a supervisor | `{}` |
| `lane.started` | the supervising process | `run` (1, 2, ...), `how` (`start` for run 1, `resume`, `reuse`), `launch` (32 hex digits), `runner`, `model`, `effort` (or null), `account` (or null), `chosen_by` (`runner`, `model`, `effort`, `account`: `routing`, `supervisor`, `default`, `previous` (and, for `account`, `room`) or null with a null value), `difficulty` (or null), `project` (or null), `worktree`, `branch`, `base` (commit) and `repository` (null for `--worktree`), `budget_minutes` (above 0, at most 10080), `quiet_seconds`, `brief` (`path`, `sha256` of the rendered brief), `log`, `session` (`socket`, `name`: the lane's tmux session), `touches`, `claims` (the claims registry that holds the working directory's claim, or null when the claim is in a linked worktree's administrative directory), and, only when the runner's `command` used `{session}` at the lane's start, `session_id` (the lane's session identifier: a UUID in lower-case 8-4-4-4-12 form; a resume's event carries the previous run's, which is the launcher's rule and not checked by the store; the key is absent for any other lane, and a key that is there must hold a valid identifier), and, only for a run of a lane that was started with `--turns`, `mail` (the sequences of the messages the run carries: increasing whole numbers from 1 to 999999999, at most 64, `[]` for run 1, a `--reuse` start and an idle turn) and `idle_seconds` (null, or a whole number from 1 to 604800), which are there together, and a `lane.started` that has `mail` must also have `session_id` |
| `lane.resumed` | the supervising process | `run` (2 or more), `after` (the previous end's reason or `lost`, or null), `message` (`path`, `sha256`, or null) |
| `lane.stuck` | the supervising process | `run`, `quiet_seconds`, `output_bytes` (what the run has written so far) |
| `lane.timeout` | the supervising process | `run`, `budget_minutes`, `elapsed_seconds` |
| `lane.ended` | the supervising process | `run`, `reason` (`exit`, `timeout`, `stopped`, `limit`, `dropped`), `exit_code` and `signal` (at most one is set, as the system reported the runner's end; neither for a runner that could not be created), `duration_seconds`, `pattern` (`limit_patterns[N]` or `dropped_patterns[N]` for limit and dropped, else null), `classification` (`matched`, `unmatched`, `timed-out`, or null when nothing was classified: a stopped or timed-out run, no patterns), `survivors` (how many of the run's other processes were still alive when the runner was gone), and, only for a run whose runner takes its prompt on standard input, `prompt` (`state` `written`, when every byte of the prompt went into the pipe and it was closed, or `cut`, when the runner closed its input, the write failed before the end, or the runner could not be created (then 0 bytes); `bytes` written and the prompt's `length`: written is not read, and a prompt that fits what the pipe holds, 64 KiB by default on Linux and not measured here, is written whole even when the runner never reads it) |
| `lane.lost` | `lane check` | `run`, `survivors` (how many recorded processes of the run outlived its supervising process) |
| `lane.state` | `lane mark`, a supervisor | `state`: queued, running, verifying, accepted, merged or abandoned (the store also refuses `waiting`, which only the end of a run of a turn-based lane sets, and refuses every state but `abandoned` for a turn-based lane); for accepted or merged with `--accept-uncovered`, also `not_covered` (`run`, `reason`, `path` or null), what the scan could not cover |
| `lane.refusal`, `lane.workaround_suspected`, `lane.refusal_reviewed` | see "Refusals" | see "Refusals" |
| `lane.merged`, `lane.deployed`, `lane.landed` | `lane mark`, a supervisor | `{}` |
| `lane.gone` | `lane mark --gone` | `run` (the lane's latest run) and `launch`: the supervisor declares that launch gone; nothing about its end |
| `lane.cleaned` | `lane clean` | `removed`: items `{"item": "worktree", "path"}`, `{"item": "branch", "name"}`, `{"item": "session", "name"}`; `kept`: the same with `why` (`not-created`, `missing`, `not-this-lane`, `abandoned`, `not-merged`, `record`), always including `{"item": "lane-directory", "path", "why": "record"}` |
| `lane.ingested` | `laneboss decisions ingest-lane` | `lane`, `rows_added`, `rows_existing` and `rows` (items `{"id", "sha256"}`, at most 4096): the receipt of the lane's records that went into the decision store, whose `id` names the configuration, the lane, the part (`report`, `events` or `attachment`) and the first 16 hex digits of the source hash. It records what was ingested and changes nothing else of the lane; the decision store keeps the text and it is never embedded or sent |
| `lane.mailed` | `lane send`, actor `supervisor` | `sequence` (1 to 999999999), `sender` (`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`), `sha256` (of the message file), `bytes` (1 to 262144): never the text |
| `lane.delivered` | the supervising process behind `lane.ended` | `run` (2 or more), `sequences` (1 to 64 increasing whole numbers from 1 to 999999999) |
| `lane.returned` | the supervising process behind `lane.ended`, `lane check` behind `lane.lost`, `lane mark --gone` behind `lane.gone` | `run`, `sequences` (as for `lane.delivered`) and `reason` (`exit`, `timeout`, `stopped`, `limit`, `dropped`, `lost`, `gone` or `cut`: why the end of the run sent the messages back) |

Events the launcher writes have actor `laneboss`, those of `lane mark` and `lane send` actor `supervisor`, and
`occurred_at` is the moment the thing happened.

The loop writes four kinds of its own. They are not `lane.*` events: the projection ignores them, `check_transition` does
not see them, and `EventStore.append()` checks only their form (`lanes.check_loop()`), at append and nowhere else, so
`state verify` and `state rebuild` do not check them. Their actor is `laneboss`. The payloads are in "The `lane loop`
command".

| Kind | Written by | Envelope's `lane` | Payload |
|---|---|---|---|
| `loop.started` | `lane loop`, once, when the loop has the lock | absent | `loop`, `pid`, `start`, `detached`, `unrecorded_end` |
| `loop.stopped` | `lane loop`, when it ends | absent | `loop`, `reason` (`stop` or `error`), `turns`, `skips` |
| `loop.turn` | `lane loop`, behind the `lane.started` of the turn it started | the lane | `loop`, `kind` (`mail` or `idle`), `sequences`, `run` |
| `loop.skipped` | `lane loop`, once for each wait | the lane | `loop`, `reason` (`backoff` or `refused`), `until`, `after`, `detail` |

The disk line writes two kinds of its own, when a start (or a supervisor's `lane start`) reads a file system the
`[disk]` section watches. They belong to no lane, like the loop's: the envelope's `lane` is null, the actor is
`laneboss`, and the projection ignores them. Their payload is the reading they were taken from (`docs/configuration.md`).

| Kind | Written by | Envelope's `lane` | Payload |
|---|---|---|---|
| `disk.warn` | `lane start`, when the reading is at or above the warn line and the start goes on | null | `path`, `used_percent`, `free_bytes`, `warn_percent`, `stop_percent` |
| `disk.stop` | `lane start`, when the reading is at or above the stop line and the start is refused | null | as for `disk.warn` |

### Projection

Lanes are a projection of `lane.*` events. Each lane row holds `state`, `state_at`, `times` (`planned`, `started`,
`ended`, `timeout`, `stuck`, `resumed`, `lost`, `cleaned`), `landing` (`merged`, `deployed`, `landed`), `run` (the
latest run's number, 0 before the first), `running`, the latest run's `runner`, `model`, `effort`, `account`,
`worktree` and `branch`, the latest end's `reason` (`exit`, `timeout`, `stopped`, `limit`, `dropped` or `lost`) and
`exit_code`, `resumes` and `lost` (counts), `cleaned`, `events` and `last_seq`, and, once the lane has a refusal event,
`refusals` (see "Refusals"; the three refusal kinds change nothing else of the row) and, once a run start of the lane
has carried `mail`, `mail`: the lane's messages and what became of them, with the fields `turn_based`, `idle_seconds`,
`last`, `waiting`, `returned`, `in_flight`, `delivered` and `settled`, derived from the lane's events alone ("Mail
events, the new lane state and the projection"). The rows of every other lane have no `mail`. The state of a
turn-based lane between two turns is `waiting`: the end of any of its runs sets it, not `verifying`.

| Kind | Effect |
|---|---|
| `lane.planned` | `times.planned`; state `queued` |
| `lane.started` | `times.started`; state `running`; `run`, `running`, the run's runner, model, effort, account, worktree and branch; clears `reason`, `exit_code` and `cleaned`; with `mail`, the lane is turn-based and the messages the run carries leave the queue and are in flight; without it, a row that has `mail` is no longer turn-based |
| `lane.resumed` | `times.resumed`; `resumes` + 1 |
| `lane.ended` | `times.ended`; state `verifying` (the supervisor verifies next), or `waiting` for a turn-based lane (an abandoned row keeps `abandoned`); `running` false, `reason`, `exit_code`; the messages in flight are delivered or return |
| `lane.lost` | `times.lost`; state `verifying` (`waiting` for a turn-based lane); `running` false, `reason` `lost`, `lost` + 1; the messages in flight return |
| `lane.gone` | state `verifying` (`waiting` for a turn-based lane); `running` false; `reason` and `exit_code` unchanged (the end stays unknown); the messages in flight return |
| `lane.mailed` | `mail.last` is the sequence and the sequence joins the end of `mail.waiting`; the state does not change |
| `lane.delivered`, `lane.returned` | `mail.settled.announced` becomes true |
| `lane.timeout`, `lane.stuck` | the time only; no state change |
| `lane.state` | state `payload.state` |
| `lane.merged`, `lane.deployed`, `lane.landed` | the landing fact's time only |
| `lane.cleaned` | `times.cleaned`; `cleaned` true |

Landing is three separate facts and never one: a merge is not a deployment and a deployment is not
landed. An event's time is its `occurred_at` when given, else `recorded_at`; each time is the most
recent event of that kind. Another `lane.*` kind, a lane event without `lane`, a payload that breaks its form or
an event the lane's projection does not allow is refused at append.

`append()` updates the stored projection; `state rebuild` recomputes it from events alone with the
same `apply()` and replaces the stored rows (derived data only), so its output equals `state lanes`
byte for byte. What each of the three checks:

- `append()`: the envelope and its payload (form, grammars, credentials), a `brief.rendered` event against the
  kept inputs, a `lane.started` or `lane.resumed` event's binding to this configuration and lane (socket, session,
  log, rendered files), no pending events of the lane, an id already stored only with the same content, and the
  life cycle against the lane's projection.
- `state rebuild`: every stored event's hash, its envelope and payload as `append()` checks them, and the life
  cycle replayed from the start. It does not check bindings, kept inputs, gaps in the sequence or the schema.
- `state verify`: everything `state rebuild` checks, and the schema, the store's metadata and marker, the sequence
  without gaps, `recorded_at`, the stored projection against the recomputed one, and the `brief.rendered` events and
  kept inputs. It does not check bindings either.

So a stored lane event whose payload or life cycle `append()` would refuse is an integrity problem for all three,
never an internal error; a binding that a hand-made store breaks is caught only at append.

**Stores of 0.2.0.** Version 0.2.0 accepted lane events with any payload and kept a smaller projection. A store
written by it verifies under this version only if its lane events carry the payloads above; then run
`state rebuild` once to rewrite the projection in the new form. A lane row in the earlier form makes lane commands
and lane appends stop with an integrity problem that says so. A store with lane events written without those
payloads gives an integrity problem from `state verify`, `state rebuild` and a lane append alike.

### Not built yet

The judge that picks a difficulty, account choice by remaining quota, messages to a running executor (a message of
`lane send` waits for the next turn and is never given to a run that goes on), checking which model a run really used,
the owner channel, test machines (`{machine}`), cost accounting and the remote store. Turn-based lanes with mail
(`lane send` and `lane turn`), the loop (`lane loop`) and `lane attach` with the stream readers are built. Built from
"Turns, mail, the loop and attach" (T5): the room command of an account and the choice of the account it feeds, the
command `lane adopt`, and the event `lane.adopted` with the readers that take it for a run 1 already over. Designed, not
built there: the rule that a pass starts no room command for an account while an earlier one for it still runs, the room
command of `lane start`'s first account, and the remaining quota of an account, read by an adapter under
`integrations/`. Designed, not built
("Resources and cost"): the resources that a lane holds outside the machine the launcher runs on, with the adapters that
make and end them, the release check and the gate at `lane mark`, and the recorded cost of them.

## Turns, mail, the loop and attach

Built in part: this section describes lanes that are continued turn by turn, lanes whose agent session lives across many
runs and is given its work as messages. Four steps build it and test against it, named T2 to T5; each part below names
the step that builds it, and a step turns its part from design into description in the commit that builds it. T2, T3 and
T4 are built: their parts, headed "built, T2", "built, T3" and "built, T4", say what the launcher does today, and each
statement in them was read back from the code and the tests of this branch. T5 is built in part: its part is headed
"Accounts and adoption (T5; built in part)" and says in its first lines which half of it the launcher does today and
which is designed, not built, and what is not built there (the rule about a room command
already running for an account, the room command of `lane start`'s first account, and the remaining quota of an account)
is named in "Not built yet" as well, and nothing outside this section
says that one of those exists. What a sentence says about
the launcher as it was before T2 is checked against the code and the documents of `main`, those on a lane's session
identity, `{session}`, `session_id` in `lane.started`, the runner key `prompt` and `prompt` in `lane.ended` ("Session
identity" and `docs/configuration.md`) included, which `main` has.

| Step | Builds |
|---|---|
| T2, built | Mail and turns: `lane start --turns`, `lane send` and `lane turn`; the events `lane.mailed`, `lane.delivered` and `lane.returned`; the optional keys of `lane.started`; the lane state `waiting`; the `mail` row of the projection; the checks of `state verify`; protocol 1.2.0; the configuration table `[turns]` with `idle_message` and `idle_seconds`; idle lanes in `lane status` and in the briefing; `lane resume` refusing a turn-based lane; a `laneboss doctor` warning for a turn-based runner without `limit_patterns`. |
| T3, built | The loop: `lane loop`, `lane loop --status`, `lane loop --stop` and `--detach`; the `loop.*` events; the loop's keys in `[turns]` (`poll_seconds`, `backoff_seconds` and `limit_backoff_seconds`); `lane check --lane`. |
| T4, built | Attach and the stream: the runner key `stream`, the named readers `text` and `claude-stream-json`, and `lane attach`. |
| T5, built in part | Accounts: the room command and its `slots`, the choice of the account and its recording, the hold of a lane whose accounts have no room, the command `lane adopt`, and the event `lane.adopted` with the readers that take it for a run 1 already over. The rule about a room command already running for an account, the room command of `lane start`'s first account, and the remaining quota of an account are not built. |

### Purpose and the picture

A lane today is one brief and one run, or one run after another that a supervisor starts by hand with `lane resume`.
When a run ends, the lane waits for the supervisor to verify it. Some work does not end: an assistant that a supervisor
talks to, a mini-supervisor that is asked something every few minutes, a reviewer that is consulted again and again.
For these the agent's session lives on, and each piece of work is a **turn**: one run of the same lane that resumes the
same session with one message. The design adds four things to the lanes the launcher has, all four built (the first two
by T2, the third by T3 and the last by T4):

- **Mail (built).** A message is stored as an immutable file of the lane and announced by an event that carries its hash
  and size, never its text.
- **The turn (built).** `lane turn` takes the messages that wait, renders them once as one follow-up message and resumes
  the lane's session with it. A turn is a run: it has the run number, time budget, supervising process, run record,
  events, refusal coverage and gate that every run has.
- **The loop (built, T3).** `lane loop` is a separate command that a supervisor starts on purpose. It decides only when
  a turn starts, as the supervisor declared, and records every decision as an event.
- **Attach (built).** `lane attach` shows the live turn from the lane's own log and turns a typed line into mail and a
  turn.

T5 (built in part) adds what turns need to choose an account and to take over a session that already exists: the room
command of an account and the choice of the account it feeds. The command `lane adopt` is built.

```
1. lane start --turns    Run 1 takes the brief on standard input. When it ends the lane is waiting (idle).
2. lane send             At any time: a message becomes a file, then the event lane.mailed. It waits.
3. lane turn, or loop    The waiting messages are joined and rendered once. Run N (how resume, N is 2 or more)
                         takes them on standard input.
4. lane.ended            Reason exit, exit code 0 and a prompt written whole: the messages are delivered. Any
                         other end, lane.lost or lane.gone: they go back, in front of newer mail. The lane is
                         waiting again.
```

### The design in brief

These statements are fixed; the parts that follow work them out. What they say of mail, the turn, the state and the
session identity is built (T2); what they say of the loop is built (T3); what they say of attach and the stream is built
(T4); what they say of the room is built (T5); what they say of `lane adopt` is built (T5).

- **A turn is a run.** One turn of a turn-based lane is one run of that lane. The run number, the time budget, the
  supervising process, the lane's records, the refusal coverage and the gate of `lane mark` apply to it unchanged.
  There is no second kind of process and no second store. The first turn is `lane start` with the brief, which
  reaches the runner on standard input; mail turns are run 2 or more, started with `how` `resume`. `lane turn` on a
  lane that never ran is refused for that reason.
- **Mail is files, never arguments.** `lane send` stores one message as a payload file. The files are one directory
  per lane of immutable files, each named by its sequence number and digest, written once and never moved, renamed or
  deleted, the same class as the rendered briefs. The event of a message carries its sequence, sender, sha256 and
  size, not its text. A message is checked when it is sent, with every refusal the brief renderer applies, credential
  shapes included, so a bad message is refused when sent; the check is made again when a turn takes the message, and a
  refusal then names the message's sequence (it can come only after a change of the launcher). Sequence numbers are per lane,
  without a gap in the events, and two sends at once do not collide.
- **A message is in flight until its turn ends well, and everything is computed from events.** Which messages wait,
  are in flight, are delivered or have returned follows from the lane's events alone; no file is moved. `lane turn`
  is refused while a run of the lane is live. It takes the waiting messages in order, puts each under a header line
  that names its sender and time, and renders the whole once with the existing renderer as one follow-up message, so
  the protocol block and the standing rules appear once per turn. A run that ends with reason `exit`, exit code 0 and a
  prompt that was written whole (the `prompt` that the launcher records in `lane.ended`) delivers its messages, which are
  kept and never deleted; any other end returns them, in their old order and in front of newer mail. With no mail,
  `lane turn --idle` sends the configuration's idle message, and plain `lane turn` does nothing and says so, with exit
  0. Putting mail back is a delivery rule, so that no message is lost; it is not a retry. The next turn starts only by
  a person, or by the loop's declared schedule (T3).
- **The loop only decides when.** `lane loop` is a command of its own that a supervisor starts on purpose, one process
  per configuration, under a lock. It acts only on lanes that the supervisor declared turn-based, and only as
  declared: a turn when mail waits, a turn after the declared idle interval, and the declared back-off. It never
  accepts, merges, cleans, marks or retries work by its own judgement, and it never stops anything by a name pattern:
  a hung turn is the time budget of the run, which already exists. It has its own status and its own stop, and every
  decision it takes (a start, a skip and why, a back-off) is an event. The lane commands stay as they are and decide
  nothing.
- **No room means no turn.** A turn that cannot get an account is not started and the mail stays waiting. The loop
  records why as an event; for a person's `lane turn` the refusal message says why, because a refused command appends
  nothing. The account's room is asked by a command per account, configured (T5, built), whose standard output is one
  small JSON object; the core knows no vendor. A runner without such a command has no room check, and "no room" for its
  turns is what the launcher can see: a start that is refused for the account, or a run that ends with reason `limit`.
- **Attach is a view and a keyboard, not a runner.** It shows the live turn's output from the lane's own log as the log
  grows, shows "idle" between turns, and turns a typed line into `lane send` followed by `lane turn`. It never starts
  an agent itself, and leaving it never stops the turn. It shows the permission mode that the agent reports and warns
  plainly on bypass, shows the turn's cost at its end from the stream's result line, never gives a traceback for any
  stream line, and strips terminal control characters from what the agent wrote.
- **A turn-based lane needs a session identity and the prompt on standard input.** A lane whose runner lacks
  `{session}` in `command` and in `resume`, lacks `prompt = "stdin"`, or has no `resume` is not turn-based, and
  `lane send` and `lane turn` refuse it for that reason.
- **The stream is the runner's, read by a named reader.** The launcher stores what the runner prints. A runner gains
  one key, `stream`, that names a reader: `claude-stream-json` or `text`, and absent means `text`: lines shown as they
  are, no cost. A vendor's format lives only in a named reader, as the `records` formats already do, and nothing in
  the core knows it outside that reader. `docs/configuration.md` has the key.

### Mail (built, T2)

**Where it lives.** `lanes/LANE/mail/` in the state directory holds the lane's messages, one file each, named
`SEQUENCE-DIGEST`: SEQUENCE is the message's sequence number as nine decimal digits with leading zeros, from `000000001`,
and DIGEST is the SHA-256 of the file's bytes as 64 lower-case hexadecimal digits. A listing is then in sequence order,
and a name says what its bytes must hash to. The file holds the message exactly as it was sent, UTF-8 text with nothing
added. It is written once, through a temporary name and put in place without replacing anything (`fsguard.write_new`),
and the launcher never moves, renames, rewrites or deletes it. The directory is reached through the opened state
directory without following a link, like every directory below `lanes/`. `lanes/LANE/mail.lock` is the lane's mail lock,
a lock file that is created when it is missing.

**The send command.** `lane send --lane L (--file PATH | -) [--from NAME]` stores one message. `--file` reads it through
the checked reader that `--brief` and `--message` use (a regular file, opened through its checked directory, read once);
`-` reads standard input. The text is never taken from an argument, because a shell would expand it before the launcher
saw it: `--file` together with `-`, a positional argument that is not `-`, and neither of the two are refused, and a
`--file` path that looks like a credential is refused without being repeated. The sender and the message are checked
before the lane is looked at (`mail.check_sender`, `mail.read_message`, `mail.check_message`). `--from NAME` names the
sender and defaults to `supervisor`; it matches `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` and is checked for credential shapes.
The command appends one event, `lane.mailed`, with actor `supervisor`, and prints one
JSON value: `lane`, `sequence`, `sender`, `sha256`, `bytes`, `file` (the absolute path), `event` (`id` and `seq`) and
`waiting` (how many messages now wait for a turn, the returned ones included).

**What is checked when a message is sent.** All of it is checked before a byte is written, and a refusal (exit 2)
leaves no file and no event. The lane's checks (`lanecmd.mail_target`) are made once before the mail lock is taken and
again under it, on the row as it is then:

- The lane is known, is turn-based (its row has `mail` with `turn_based` true, which a lane started with `--turns` has,
  and, from T5, so does one that was adopted), is not abandoned and not cleaned, and its runner, as the
  configuration has it now, has `{session}` in `command` and in `resume`, `prompt = "stdin"` and a `resume` template.
  Each missing part is named.
- The message is UTF-8, is not empty after white space is taken away, and is at most 262,144 bytes.
- The refusals that the renderer applies to a brief hold for a message: it must not contain a launcher block, and it
  must not contain a credential shape (the error names the line and never repeats it). The mandatory sections of
  `--touches` do not apply, as for a follow-up message today.
- The lane has fewer than 1,000 messages that wait or have returned.

**The send algorithm.** The file comes first and the event second. The command holds the lane's mail lock (waited for
at most `[lanes] lock_wait_seconds`, as for the lanes lock) from step 2 to step 4:

1. The lane's pending events are appended first, as for every command that appends an event of the lane; some that
   cannot be appended refuse the send.
2. The sequence is `mail.last + 1`, from the lane's stored row (0 when it has no mail yet).
3. The file `SEQUENCE-DIGEST` is written. A file of that name that exists already, left by an interrupted send of the
   same bytes, is read back: when its bytes hash to its name it is the file; otherwise the send is an integrity problem
   (exit 3).
4. `lane.mailed` is appended through `EventStore.append()`, which checks in the same transaction that stores it that
   `sequence` is `mail.last + 1`. The append waits at most 10 seconds for a busy store, like every lane command's
   append.
5. The lane's row is read again for `waiting`, the lock is released and the result is printed.

| Failure | What it leaves |
|---|---|
| Before step 3 is done (the process is killed, the disk is full) | Nothing, or a temporary file whose name starts with `.tmp-`, which no reader looks at. `state verify` skips such names, as it skips them in the kept inputs. |
| Between steps 3 and 4 (the process is killed, the store stays busy for 10 seconds, the event is refused) | An orphan: a complete file named by the grammar that no event names. There is no message, and the sender saw no success. |
| After step 4 and before the result is printed | A stored message that the sender was not told about. A second send makes a second message, and neither carries ` (again)`; no check can tell the two are one ("The failure table", "Known limits"). |

**Who cleans up an orphan.** Nobody deletes it. An orphan is inert: no turn or status reads a file that no event
names (nor does the loop of T3), and `state verify` counts such files (`mail_orphans`), so a person can see them. A send of the same bytes gives
the orphan its meaning back: the sequence is the same, so is the name, and step 3 takes the file that is there. Other
bytes get the same sequence and another name, and the orphan stays beside them as a record.

**Sequence numbers.** They are per lane, start at 1 and continue when a lane's name is started again. They are
without a gap in the events: `lane.mailed` is refused unless `sequence` is `mail.last + 1` ("Mail events, the new lane
state and the projection"). Two sends at once cannot collide, because the second waits for the mail lock and then reads
a `mail.last` that includes the first. Were the lock bypassed, the check at append would refuse the second event and
leave only an orphan.

**Limits.** These numbers are in `src/laneboss/lanes.py` (`MAX_MESSAGE_BYTES`, `MAX_QUEUE`, `MAX_TURN_MESSAGES`,
`MAX_TURN_BYTES` and `MAX_SEQUENCE`), and the tests pin them: a message is at most 262,144 bytes; at most
1,000 messages wait or have returned; a turn carries at most 64 messages and at most 1,048,576 bytes of joined text,
header lines and separators included, so a turn takes the head of the queue up to these bounds and the rest waits for
the next turn; sequence numbers run to 999,999,999. The renderer's own bound for a brief, 4 MiB, never binds.

**What `state verify` checks.** The checks of "Integrity" stay, and these are added for every lane directory that has a
`mail` directory:

- Every name in it is `SEQUENCE-DIGEST` by the grammar above, or starts with `.tmp-` and is skipped. Any other name is
  an integrity problem (the name is printed only when it matches a grammar of the launcher, as for kept inputs).
- Every entry is a regular file that is not a link, and its bytes hash to the digest in its name.
- Every `lane.mailed` event has its file: the name made from its `sequence` and `sha256` exists and has `bytes` bytes. A
  missing or changed file is reported with the lane, the sequence and the event's `seq`.
- The sequences of a lane's `lane.mailed` events start at 1 and have no gap. The replay of the lane's events checks
  this with the same rule that `append()` applies.
- A file that no event names is an orphan: it is counted, never a problem. The output of `state verify` gains
  `mail_files` (the files checked) and `mail_orphans`.

`state rebuild` reads events only and is not changed by mail files.

**Writers of kept files.** "Event and state store" lists the writes that are not events: creating an empty store,
`rebuild()`, the content-addressed copies that `brief render` keeps, and the mail directory, a fourth with files of the
same class: kept by the launcher, immutable and never deleted. `lane send` is its only writer (`mail.store_file`). Its
names are not the digest alone, because the sequence is part of them, so the check above takes the place, for this
directory, of the rule in "Integrity" that a kept input's name equals the SHA-256 of its bytes; "Event and state store"
and "Integrity" say so.

### Mail events, the new lane state and the projection (built, T2)

**The new events.** Three kinds join the reserved `lane.*` kinds. `EventStore.append()` checks them before anything is
stored, whoever appends them, like every lane event: the form of the payload, its grammars, credentials, and the lane's
projection. A hand-written event is held to the same rules.

| Kind | Written by | Payload |
|---|---|---|
| `lane.mailed` | `lane send`, actor `supervisor` | `sequence` (1 to 999999999), `sender` (`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`), `sha256` (the hash of the message file, 64 hex digits), `bytes` (1 to 262144) |
| `lane.delivered` | the supervising process, after `lane.ended`; actor `laneboss` | `run` (2 or more), `sequences` (1 to 64 whole numbers from 1 to 999999999, increasing) |
| `lane.returned` | the supervising process after `lane.ended`, `lane check` after `lane.lost`, `lane mark --gone` after `lane.gone` (and for a `lane.lost` that was never announced); actor `laneboss` | `run` (2 or more), `sequences` (as for `lane.delivered`), `reason` (`exit`, `timeout`, `stopped`, `limit`, `dropped`, `lost`, `gone` or `cut`: why the end of the run sent the messages back. `cut` is an end with reason `exit` and exit code 0 whose prompt was not written whole, a missing `prompt` counting as `cut`; any other end gives its own reason) |

The text of a message is in no event. `lane.delivered` and `lane.returned` are the launcher's own delivery rule, not a
decision of a supervisor, so their actor is `laneboss` even when `lane mark` appends one.

**What a turn's end says about its prompt.** The launcher records in `lane.ended`, for every run whose runner takes its
prompt on standard input, the key `prompt`: `state` (`written` when every byte of the prompt went into the pipe and the
pipe was closed; `cut` when the runner closed its input, the write failed before the end, or the runner could not be
created), `bytes` (how many were written) and `length`. It is defined in `src/laneboss/lanes.py` (`PROMPT_FATE`), written
by the supervising process in `src/laneboss/supervise.py` (`Prompt.fate()`, called by `Run.end()`), and documented in
`docs/configuration.md`, in the row of `prompt`. Every turn has `prompt = "stdin"`, so every turn's `lane.ended` has the
key; one that lacks it (a hand-written event, or a run whose prompt could not be decoded, which runs nothing) does not
deliver: `lanes.settlement()` counts it as `cut`. Written is not read ("Known limits").

**The optional keys of `lane.started`.** The event gains two keys that are there together or not at all. A run start
that has them is a turn of a turn-based lane; one that has neither is not. `lanes.check()` adds the keys to the form of
the payload only when `mail` is present, as it does for `session_id`, so an event written by 1.1.0 passes unchanged and
a key that is present must be valid; `idle_seconds` without `mail` is refused.

| Key | Form |
|---|---|
| `mail` | The sequences of the messages that this run carries: whole numbers from 1 to 999999999, increasing, at most 64. The list is `[]` for a run that carries none: run 1, a start with `--reuse`, and an idle turn. |
| `idle_seconds` | `null`, or a whole number from 1 to 604800: the idle interval that the supervisor declared when it started the lane. The loop (T3) starts an idle turn after it, counted from the lane's last state change, and a person starts one with `lane turn --idle`. Every turn copies the previous run's value. |

A start that has `mail` must also have `session_id`. A first turn, `how` `start`, carries `[]` because it carries the
brief, which is not mail. `lane.resumed` does not change: its `message` is the rendered join of the mail, or the
rendered idle message.

**The four states of a message.** A message is **waiting** when it was mailed and no run has carried it, **in flight**
while the run that carries it is going on, **delivered** when that run ended with reason `exit`, exit code 0 and a
prompt written whole, and **returned** when it ended in any other way (including a cut prompt, lost and declared gone)
and no run has carried the message since. This is the rule that `lanes.settlement()` implements. It is the standing rule that a loss the
launcher can see is never counted as delivered, applied to mail: a prompt that was cut is such a loss, and an end that
does not record its prompt is not taken for one written whole, as a record that cannot be read is never taken for "no
refusals" ("Refusals"). The next turn takes the returned messages and then the waiting ones, which is the order of
their sequence numbers: a turn carries the head of the queue, so every returned message has a lower sequence than every
waiting one.

**The derivation.** The four sets follow from the lane's events, read in the order of their `seq`, and from nothing
else. Start with `waiting`, `returned` and `in_flight` empty, no message delivered and `turn_based` false, and take each
event of the lane in turn:

1. `lane.mailed`: its sequence joins the end of `waiting`.
2. `lane.started` with `mail`: `turn_based` becomes true. The listed sequences leave `returned` and `waiting`, and when
   the list is not empty, `in_flight` is the list together with this run's number. `lane.started` without `mail`:
   `turn_based` becomes false. `lane.adopted` (T5, built) is read as a run 1 that is already over:
   `turn_based` becomes true and nothing is in flight.
3. `lane.ended`, `lane.lost` or `lane.gone` of the run that `in_flight` names settles the messages in flight. They are
   delivered when the event is `lane.ended` with reason `exit`, `exit_code` 0 and a `prompt` whose `state` is
   `written`. They return, to `returned` in sequence order, when it is any other `lane.ended` (an `exit` with exit code
   0 whose `prompt` is `cut` among them, and a missing `prompt` counts as `cut`), a `lane.lost` or a `lane.gone`.
   `in_flight` is empty afterwards. A closing event with nothing in flight (a run that carried no mail, or a second
   closing event of a run that is already closed) settles nothing.
4. `lane.delivered` and `lane.returned` change none of the four sets. They announce what step 3 decided.

What a message is now is where the derivation left it. A sequence from 1 to `last` that is in none of `waiting`,
`returned` and `in_flight` is delivered.

| Event, in order | Waiting | In flight | Returned | Delivered |
|---|---|---|---|---|
| `lane.mailed` 1, `lane.mailed` 2 | 1, 2 | none | none | 0 |
| `lane.started` run 2 with `mail` `[1, 2]` | none | run 2: 1, 2 | none | 0 |
| `lane.mailed` 3 | 3 | run 2: 1, 2 | none | 0 |
| `lane.ended` run 2, reason `limit` | 3 | none | 1, 2 | 0 |
| `lane.started` run 3 with `mail` `[1, 2, 3]` | none | run 3: 1, 2, 3 | none | 0 |
| `lane.ended` run 3, reason `exit`, exit code 0, `prompt` `written` | none | none | none | 3 |
| `lane.mailed` 4, `lane.started` run 4 with `mail` `[4]` | none | run 4: 4 | none | 3 |
| `lane.ended` run 4, reason `exit`, exit code 0, `prompt` `cut` | none | none | 4 | 3 |

Three cases need a word of their own:

- **A run that is lost or gone.** No `lane.ended` exists, and the run's closing event is the `lane.lost` that `lane check`
  records once the supervising process is seen gone, or the `lane.gone` that a supervisor declares with
  `lane mark --gone`. Either settles the messages in flight as returned, because nothing shows that the turn took
  them. Until then they stay in flight and the lane is running in the projection, so `lane turn` is refused. A
  `lane.gone` that follows the `lane.lost` of the same run, which `lane mark --gone` allows once the run record can no
  longer be read, settles nothing: the messages were settled at the loss, and the row's `settled` keeps that outcome and
  its reason `lost`.
- **A run whose `lane.ended` is still pending.** Nothing is settled before the end is stored: the supervising process
  queued it, or it waits in the lane's pending file. The messages stay in flight and the lane is running. A `lane turn`
  first appends the lane's pending events, as `lane resume` does. When the store takes the end, the derivation settles
  the messages and the turn goes on, unless a supervising process of the lane still lives; when the store cannot take
  it, the turn is refused and the messages stay in flight. `lane check`, and every other command that appends an event
  of the lane, appends the pending end in the same way. An end that is lost for good (the known limit "Events queued in
  memory") becomes `lane.lost` by `lane check`.
- **The order of `lane.delivered` against `lane.ended`.** `lane.delivered` comes after `lane.ended`, in the same queue
  of the supervising process, so the recorder appends them in that order. The end is the fact and the delivery is its
  consequence; the derivation settles at the end, so the projection is right after `lane.ended` whether or not the
  announcement has been appended, and a lost announcement does no harm. `lane.returned` takes the same place after
  `lane.ended`, `lane.lost` and `lane.gone`. An announcement is due when the row's `settled` names the lane's latest run
  and has `announced` false, and whoever appends it copies `run`, `sequences`, `outcome` (which gives the kind) and
  `reason` from `settled`, so that a late announcement is accepted and correct. The supervising process cannot read the
  row before its own end is stored, so it derives the same values from its end event and from the `mail` of its run, by
  step 3 of the derivation. `lane check` appends the announcement after its `lane.lost`. `lane mark --gone` appends it
  after its `lane.gone` when that event settled the messages (reason `gone`), and also when an earlier `lane.lost`
  settled them and its announcement was never appended, in which case the reason is `lost` and not `gone`, because
  `lane.gone` settled nothing. When the run carried no mail, or the announcement was appended, nothing is due. When an
  announcement is refused or cannot be appended (the store is busy, or the next run started between the command's look at the row and its append), nothing is wrong:
  `lane check` and `lane mark --gone` say so in their output and exit 0. When the next run started before the command looked, no announcement is due, and `returned` is null without `returned_error`. The supervising process keeps the event in
  `refused.jsonl` like any event the store refuses. Such an announcement stays due for `lane mark --gone` as long as the
  lane has not run again.

**The new state and the projection.** `STATES` gains `waiting`: the state of a turn-based lane between turns. A
turn-based lane's run end (`lane.ended`, `lane.lost`, `lane.gone`) sets `waiting`, and not `verifying`. The lane is
never `verifying`, `accepted` or `merged`, and `abandoned` ends it: a row that has `mail` whose state is `abandoned`
keeps `abandoned` at a closing event, whether its `turn_based` is true or false (a lane started again with `--reuse` and
without `--turns` keeps its `mail`), so that a `lane.gone` that arrives after an abandonment does not undo it.
`lane mark --landing` is accepted on a turn-based lane, because a landing fact changes no state. The question of
`apply()`, which is a pure fold over events and has no configuration, is answered by the events: the lane's declaration
is in its `lane.started` events, as the optional key `mail` (and, from T5, built, by a `lane.adopted` event, whose
kind itself declares the lane turn-based; that event has no key `mail`), and the fold carries it in the row as
`mail.turn_based`. A `lane.ended` arrives for the run that a `lane.started` began, so the row
already says whether the lane is turn-based.

The lane row gains one optional field, `mail`, there from the first run start that carries `mail`. The rows of every
other lane are exactly what they are today. `lanes.current_form()` accepts a row with or without `mail`, as it does
with `refusals`, and requires exactly these fields in it:

| Field | Meaning |
|---|---|
| `turn_based` | True while the latest run start carries `mail` (and, from T5, from the lane's adoption); false after a start without it. |
| `idle_seconds` | The latest run start's `idle_seconds`. |
| `last` | The highest sequence assigned; 0 before the first message. |
| `waiting`, `returned` | The sequences in those states, increasing. |
| `in_flight` | `null`, or `{"run", "sequences"}` for the run that is going on. |
| `delivered` | How many messages were delivered. |
| `settled` | `null`, or `{"run", "outcome", "reason", "sequences", "announced"}`: what the closing event of the latest run that carried mail decided (`outcome` `delivered` or `returned`, and `reason` null or the one that `lane.returned` must carry), and whether its announcing event was appended. A run that carried no mail leaves it as it is, and so does the start of a new life of the lane (`last`, `delivered` and `settled` all go on). It exists so that `append()` can check the announcement, and so that whoever announces copies `run`, `sequences`, `outcome` and `reason` from it, a late announcement included. |

| Kind | Effect on a lane whose row has `mail` (any other lane: as today) |
|---|---|
| `lane.mailed` | `last` is the sequence and the sequence joins the end of `waiting`; the state does not change |
| `lane.started` with `mail` | What it does today; then `turn_based` true, `idle_seconds`, the listed sequences leave `returned` and `waiting`, and `in_flight` is set (`null` for an empty list). A row without `mail` gets the field here, at its starting values |
| `lane.started` without `mail` | What it does today; `turn_based` false |
| `lane.ended`, `lane.lost`, `lane.gone` | What each does today, with state `waiting` instead of `verifying` when `turn_based` is true (a row that has `mail` whose state is `abandoned` keeps `abandoned`); then the messages in flight are settled (step 3: delivered only by a `lane.ended` with reason `exit`, exit code 0 and `prompt` `written`) and `settled` records the outcome, with `reason` `cut`, `lost` or `gone` where those apply, not announced yet |
| `lane.delivered`, `lane.returned` | `settled.announced` becomes true |

**Rules at append** (`check_transition`, replayed by `state rebuild` and `state verify`). The rules of today stay: a run
starts only when none is going on and with the next run number, and the run's own events are accepted only for the run
that is going on. These are added:

- `lane.mailed`: the row has `mail` with `turn_based` true; the lane is not abandoned and not cleaned; `sequence` is
  `last + 1`; fewer than 1,000 messages wait or have returned.
- `lane.started` with `how` `reuse`, with `mail` or without it, on a row that has a message waiting or returned:
  refused. A new life of the lane is never sent mail that was written for the old one, and an ordinary life must not
  keep it as waiting in its row.
- `lane.started` with `mail`: for `how` `start` and `reuse` the list is empty. For `how` `resume` the row has `mail`
  with `turn_based` true, and the list is the head of `returned` followed by `waiting`, in that order, as many entries
  as the list has.
- `lane.started` without `mail`, `how` `resume`, on a row with `turn_based` true: refused. It is also what stops a
  `lane resume` from starting a turn without its mail list.
- `lane.resumed`, and `lane.started` with `how` `resume`, on a turn-based row whose state is `abandoned`: refused. A
  supervisor's abandonment that is recorded while a turn is starting (after the command released the lanes lock and
  before the supervising process appends these events) stands: the launch ends, nothing runs and the messages stay
  waiting.
- `lane.delivered` and `lane.returned`: the lane is not running; `settled` is not null, its `run` is the lane's latest
  run and its `announced` is false; its `outcome` is the kind's; `run` and `sequences` equal those of `settled`, and so
  does `reason` for `lane.returned`. A late announcement is accepted while that run is still the lane's latest, with
  the values of `settled` and no others.
- `lane.state`: only `abandoned` on a row with `turn_based` true, and never `waiting` on any row: that state is set by
  the end of a run.

**Order of appends.**

| Operation | Events, in this order |
|---|---|
| `lane send` | The file, which is not an event, then `lane.mailed` |
| `lane turn` | `brief.rendered` (the rendered message, by the command); `lane.resumed` and `lane.started` with `mail` (by the supervising process, after any events of the lane that wait); when the run ends, `lane.timeout` if the budget passed, then `lane.ended`, then `lane.delivered` or `lane.returned` if the run carried mail |
| `lane check` | `lane.lost`, then `lane.returned` with reason `lost` when the row's `settled` names that run and has `announced` false, which it does when the run carried mail |
| `lane mark --gone` | `lane.gone`, then `lane.returned` with the values of the row's `settled` when it names the lane's latest run and has `announced` false: reason `gone` when `lane.gone` settled the messages, reason `lost` when an earlier `lane.lost` settled them and its announcement was never appended; nothing when the run carried no mail, or the loss was announced |

**Compatibility with stores written by 1.1.0.** The protocol version line of `protocol.md` went from 1.1.0 to 1.2.0 in
T2 (the rules text did not change), and the events that the launcher writes carry it (`load_protocol()`, in
`lanecmd.py` and `supervise.py`). That line is the only version that a step of this design changes:
the package version is raised by the person who installs a build, not by a step. A store written by 1.1.0 (by 0.5.0, or
by `main`, whose events carry `session_id` and `prompt` and are still 1.1.0) has none of the new `lane.*` kinds and none
of the new keys, and it verifies, reads and rebuilds under 1.2.0 without a change:

- The schema of the store, its metadata and its marker do not change.
- A 1.1.0 store may still hold events of other kinds that were appended by hand with `event append`, `loop.started`
  and the other `loop.*` kinds among them, in any form: on 1.1.0, only the `lane.*` kinds and `brief.rendered` are
  checked beyond the envelope. Since T3 is built, `event append` checks the `loop.*` kinds ("The `lane loop` command",
  "Events") and refuses one that is not in the documented form, so a store written after that holds only forms that are
  right; but they are checked at append and nowhere else, never in `state verify` or `state rebuild`, so a store of 1.1.0
  that holds such an event by hand verifies and rebuilds as it did, and the loop ignores every `loop.*` event that is
  not in the documented form, whatever its actor and its `protocol_version`, which `event append` takes from the caller.
- Every 1.1.0 event passes `lanes.check()` and `check_transition` as it did: a `lane.started` without `mail` is not a
  turn, its run end sets `verifying`, and the rows that `state rebuild` computes for such lanes have no `mail` field and
  equal, byte for byte, the rows of 1.1.0.
- A stored row without `mail` stays in the current form, so no rebuild is needed after the upgrade, as with `refusals`.
- The other direction is not supported: a program of 1.1.0 refuses the new `lane.*` kinds in `state verify` and
  `state rebuild` (it checks no `loop.*` event), and a row with `mail` makes its lane commands stop with "not in this
  version's form". It still reads and hash-checks every event (`event tail`, `state events`). "Install" ("Rolling back to
  0.5.0 across the changes of this version") says, trigger by trigger and command by command, what 0.5.0 refuses; the
  changelog says the same of the 0.3.0 launcher and the refusal kinds ("Changed" in `CHANGELOG.md`).
- T2 to T5 go out in one release; T2, T3 and T4 are built, and T5 is built in part (its part, "Accounts and adoption",
  says which half). Stores written by an unreleased build
  between two of the steps are not supported, as the stores of unreleased builds of refusal detection are not
  ("Refusals").

No rule that says what a MAJOR, MINOR or PATCH step of the protocol version means is written in the repository:
`protocol_version` is documented only as "the protocol version the producer follows". The step to 1.2.0 is a MINOR step
under the reading that a MINOR step adds kinds and optional keys, changes no existing payload and keeps every older
store valid, even a store that holds events of a kind that the step newly reserves, written by hand: those events are
checked at append only. "Open points" asks for that reading to be confirmed.

### The `lane turn` command (built, T2)

**Declaring a lane turn-based.** A supervisor declares a lane turn-based by starting it with `lane start`, whatever
other options it needs, and the new option `--turns`, with `--idle SECONDS` as an option of its own. The command is
refused unless the chosen runner is turn-based: `{session}` in `command` and in `resume`, `prompt = "stdin"` and a
`resume` template; the message names each missing part. `--idle` needs `--turns`.
The brief is the lane's first message, on standard input, and run 1 is the first turn. Its `lane.started` carries
`mail` as `[]`, `idle_seconds` (the value of `--idle`, else `[turns] idle_seconds` of the configuration, else `null`)
and `session_id`. Without `--turns` a lane is an ordinary lane, whatever its runner can do, and runs end in
`verifying` as they do today. This form of declaration is derivable from events alone, needs nothing from the
configuration when `apply()` runs, is made per lane by the supervisor that starts it, and leaves a runner free to serve
ordinary lanes as well. "Open points" asks the top to confirm it.

**The command.** `lane turn --lane L [--idle] [--account A] [--budget MINUTES]` starts the next turn of a turn-based
lane. It is `lane resume` with the message taken from the mail. It holds the lanes lock from its first check until the
run's session exists and its description has been handed to the supervising process, as a resume does ("Running", step
3), appends the lane's pending events first, takes the working directory's claim for the new launch, creates the lane's
tmux session and the supervising process as a resume does, and returns once `lane.started` of the new run is stored.
The lock is released before that event is stored, which is why the rule at append against an abandoned row exists.
`--account` and `--budget` mean what they mean for `lane resume`. A turn of a runner that has a `room` command takes
its account through the choice of "Accounts and adoption": the one `--account` names and only that one, else the
previous run's account, else the runner's other accounts in the order it lists them, skipping the project's exclusions.
A runner without a `room` command has no room check and the turn uses the previous run's account unless `--account`
names another (T5, built). `lane turn` has no back-off: the back-off belongs to the loop (T3), and a
person who starts a turn means it. The function is `continue_lane` in `src/laneboss/lanecmd.py`, which `lane resume`
calls with `by_mail` false and `lane turn` with `by_mail` true; `lane turn` (`turn()`) hands over the environment of its
own process, and the loop calls the same function with the environment that it captured when it started.

**What it refuses.** Exit 2, with nothing appended and nothing started, and the reason in the message:

- The lane is not known to the configuration, or has not run yet ("lane L has not run yet; start it with lane start
  --turns", the reason `lane resume` gives today, with the hint changed).
- A run of the lane is live. These are the conditions on which `lane resume` is refused today (`refuse_if_live` and the
  checks around it in `lanecmd.py`): the lane is running; a supervising process of any launch of the lane lives, a
  launch that another command is starting included; a recorded process of any run survives; the latest launch has no
  run record and neither an end event without survivors nor a `lane.gone` declaration; or a tmux session of the lane's
  name is still open at the lane's socket.
- The lane's pending events cannot be appended first. The message says how many wait, and nothing is done; the messages
  of a run whose end is among them stay in flight.
- The lane is not turn-based: its row has no `mail` with `turn_based` true (it was not started with `--turns`, and it
  was not adopted: the event `lane.adopted` is built, T5, and makes a lane turn-based), or its runner, as the
  configuration has it now, lacks `{session}` in `command` or in `resume`, lacks
  `prompt = "stdin"`, or has no `resume` (the message names what is missing).
- The lane was cleaned, is abandoned or is merged. A merged lane is never turn-based, and the message says that it is
  merged.
- The working directory is gone or no longer carries the lane's claim, the account is not listed by the runner or is
  excluded by the project, or the rendered brief is not what the store says (the last is exit 3), all as for
  `lane resume`.
- No account has room (T5, built: "Accounts and adoption"): the account `--account` named, else the walk of the
  previous run's account and the runner's list, found none whose checked answer is `room` true with `slots` of 1 or
  more. The message carries the account's own reason.
- `--idle` is given, no mail waits, and the configuration has no `[turns] idle_message`.

Exit 3, an integrity problem: a message that waits has no file, is not a regular file, or no longer hashes to its name.
The sequence is named, no turn starts and the messages stay as they are.

A lane that is abandoned keeps its mail as it is: the messages that wait are never delivered and never deleted, and
`state verify` goes on checking their files. A supervisor who still needs what the waiting messages ask for starts
another lane for it.

**Without mail.** Plain `lane turn` on a lane with no message waiting does nothing and says so: it appends nothing,
starts nothing and prints `{"lane": "L", "started": false, "reason": "no mail", "waiting": 0}` with exit 0. With
`--idle` it starts a turn that sends the configuration's idle message. With `--idle` and mail waiting, the mail is what
is sent: the idle message is for a lane with none.

**What it takes.** The returned messages and then the waiting ones, in sequence order, up to 64 messages and 1,048,576
bytes of joined text, header lines and separators included; at least one message always goes. Each message is read
from `mail/SEQUENCE-DIGEST` through the opened lane directory without following a link, and its bytes are checked
against its digest and against `bytes` in its `lane.mailed` event before anything is built. Each message is read and checked up to the 64th message, or up to and including the first one that does not fit the byte bound, whichever comes first, so a damaged file of that message can refuse the turn although the turn would not have carried it.

**How the prompt is built and rendered.** For each message, in order, there is a header line, an empty line and the text
of the message, with a final newline added when it has none; an empty line separates two messages. The header line is
`## Message SEQUENCE from SENDER at TIME`, where TIME is the `occurred_at` of the message's `lane.mailed` event, or its
`recorded_at` when the event has none (a hand-written one), as the projection does for the time of any event. It is
followed by ` (again)` when the message is returned, that is, when an earlier turn carried it and did not end well.

    ## Message 12 from supervisor at 2026-10-10T07:00:00.123456Z (again)

    Please summarise the open review comments.

    ## Message 13 from supervisor at 2026-10-10T07:01:10.654321Z

    Then list what is blocked.

The join is the follow-up message. It is rendered once by the existing renderer (`brief.compose_for_lane` and
`brief.render_for_lane`), as `--message` is for a resume: the launcher block, which holds the protocol and the standing
rules, appears once after the last message, and no mandatory section is required. The message is kept and announced by
one `brief.rendered` event, whose input for the message names, as its `path`, the real path of the lane's mail
directory, put through the credential check as the path of `--message` is, and its rendered file arrives on the
runner's standard input, as `lane resume` does (`prompt = "stdin"`). With `--idle` the
message is the idle message as it is, without a header line, and the `path` of its brief input is the real path of the
idle message file in the configuration directory. The renderer's refusals hold at turn time too: each message that goes
is checked again by the renderer's text check (`brief.check_text`), labelled `message N`, so that a refusal names its
sequence; it cannot fire for a message that was accepted at send time except after a change of the launcher ("Known
limits"). The joining is `mail.take` and the message of a turn is chosen by `turn_message`, both read by `continue_lane`.

**What it appends.** In the order of the table "Order of appends": `brief.rendered`, then, by the supervising process,
`lane.resumed` and `lane.started` with `mail` set to the sequences taken, `idle_seconds` and `session_id` copied from
the previous run, and when the run ends the end events and the delivery event. The messages are in flight from the
moment `lane.started` is stored. A turn that is refused, or that fails before `lane.started`, leaves them waiting.

**Output and exit codes.** On a start, `lane turn` prints what `lane resume` prints (the `lane.started` payload, `lane`,
`event`, and `resumed`), and `started` true and `turn` with `kind` (`mail` or `idle`) and `mail` (the sequences taken).
The exit code is 0 for a start and for "no mail", 2 for a refusal, 3 for an integrity problem and 70 for an unexpected
internal error.

**Changes to commands that exist.**

- `lane start` gains `--turns` and `--idle SECONDS`.
- `lane resume` refuses a lane whose latest run start carries `mail`, and says to use `lane send` and `lane turn`.
- `lane status` gains `idle` (true exactly when the lane's state is `waiting` and no run is going on) and shows the
  row's `mail`. A running turn is `running`, as any run is.
- `lane start --reuse` is refused while any message of the lane waits or has returned, with `--turns` or without it.
- `lane check` appends `lane.returned` after the `lane.lost` of a run whose loss settled messages, and
  `lane mark --gone` after its `lane.gone` when the row's `settled` names the run and has `announced` false, which
  includes a loss whose announcement was never appended, announced with reason `lost` (the rule of "Order of appends").
  Each prints `returned`, which is the event's `id` and `seq` (in `lane check`, in the entry of the lost run), or `null`
  when none was due or the announcement was refused or could not be appended. In the second case it also prints
  `returned_error`, one line with the reason, and the exit code stays 0.
- The supervising process appends `lane.delivered` or `lane.returned` after `lane.ended` of a run that carried mail.
- `laneboss doctor` gains the check `turns.limit_patterns` (`doctor.turn_limit_warning`). It never fails: its `ok` is
  true, and its `detail` begins with `warning:` and names every runner that can take turns (`{session}` in `command` and
  in `resume`, `prompt = "stdin"` and a `resume` template) and has no `limit_patterns`, because a turn that ends at a
  limit with exit code 0 is then counted as delivered ("Known limits"). The line is there only when it names a runner,
  so a configuration with no such runner has the lines it had. A runner without patterns is not refused, because a
  refusal would add a condition to what makes a runner turn-based. The briefing's checks show the same line.
- `laneboss start` lists idle lanes (state `waiting`, no run going on) in a group of their own, `idle`, in its `lanes`
  section, each with `waiting`: the number of messages that wait for a turn, the returned ones included. Before T2 such
  a lane would have been counted under `others`. The JSON key is always there (an empty list when no lane is idle); the
  text form prints the group "Idle, waiting for a turn (N):" only when N is above 0, its lines ending `; messages
  waiting: N`. A running turn, an ordinary lane and an abandoned lane are not in the group.
- `lane clean` takes an abandoned turn-based lane as it takes any abandoned lane; the mail files stay with the lane's
  other records.

**The configuration.** T2 added the table `[turns]` to `docs/configuration.md`, with two keys (the keys of the loop, T3,
joined them: "The `lane loop` command"):

| Key | Type | Meaning |
|---|---|---|
| `idle_message` | relative path | The message `lane turn --idle` sends: a file inside the configuration directory, UTF-8, at most 64 KiB, with no credential shape, read and checked like a standing-rules file. Without it `lane turn --idle` is refused. |
| `idle_seconds` | integer 1 to 604800 | The idle interval that `lane start --turns` records when it gets no `--idle`. Without it, and without `--idle`, the lane has no idle interval. |

**Where the text of the design was silent, and what the launcher does.** These points were not fixed by the design; the
launcher does as follows (`lanecmd.py`, `mail.py`, `doctor.py` and `startcmd.py`; `tests/e2e/test_mail.py`,
`test_turn.py` and `test_turn_ends.py` hold the tests of mail and turns):

- `lane turn` looks at the lane's state first: the lane is unknown, has not run, is running, was cleaned, is merged, is
  abandoned or is not turn-based (`refuse_turn`), then the conditions of a live run (`refuse_if_live`; the open tmux session of the lane's name is checked after the answer "no mail", together with the working directory, the claim, the account and the rendered brief). Only then does
  it look for mail, and "no mail" is the answer for a lane that could take a turn; the checks of the working directory,
  of its claim, of the account and of the rendered brief come after that answer and matter only when a turn starts.
- `lane send` checks the sender and the message before it looks at the lane, and the lane's checks run twice, before the
  mail lock is taken and under it; a bare `-` is standard input.
- The `brief.rendered` event of an idle turn names the idle message file as its brief input; the renderer's text check is
  made again for each message that a turn takes, and a refusal there names the message by its sequence.
- `lane status` shows `idle` on every row (false for a lane that takes no turns).
- `lane mark --state` on a turn-based lane is refused by the rule at append (exit 2), with `abandoned` the only state it
  can record; for `accepted` and `merged` the scan of the gate comes first when the configuration has guards.
- `laneboss doctor` reports `turns.limit_patterns` only when it names a runner; the briefing prints its idle group in
  the text form only when a lane is idle and has the JSON key always; the group counts the waiting and the returned
  messages; and the briefing's checks show the doctor's line.
- A turn-based lane whose run was lost or declared gone is `waiting`, so the briefing lists it as idle, not under "Lost
  or declared gone", and its messages are returned.
- `lane check` prints `returned` in every entry of `lost` (`null` when none was due) and `returned_error` only when an
  announcement was due and could not be appended; `lane mark --gone` prints `returned` and `returned_error` the same way
  and no other `lane mark` prints them.

### The `lane loop` command (built, T3)

Built in `src/laneboss/loopcmd.py` (the command, its lock, its passes and its events), `lanes.py` (`check_loop()` and
`loop_form()`, the forms of the events), `events.py` (the check at append, and `kind_events()`), `lanecmd.py` (`turn()` and
`begin()` take the environment to hand over, and `check()` takes `--lane`) and `config.py` (the keys of `[turns]`); the tests
are `tests/e2e/test_loop.py`. The design names two items of `--status` without saying where the first comes from or how
the second is written, `last_error` and what the loop would start next in the entry of each lane. The supervisor decided
both readings, and both are built: `last_error` is the latest failure of a pass, kept in `loop.json`, and the entry of a
lane has the key `next` ("Status"; "Where the text of the design was silent, and what the launcher does").

**What it is.** `lane loop` decides when a turn starts for the turn-based lanes of one configuration, and nothing else.
It is a command of its own: the lane commands decide nothing, and the loop is not one of them. A supervisor starts it on
purpose; nothing starts it, and a restart of the machine does not. The loop acts on a lane only if the supervisor
declared the lane turn-based, with `--turns` (or, from T5, by adopting it: "The `lane turn`
command", "Declaring a lane turn-based"), which means that the lane's row has `mail` with `turn_based` true, and the lane
is neither abandoned nor cleaned. It acts only as declared:

- a turn when mail waits (a message waiting or returned);
- a turn when the lane has been idle for the declared `idle_seconds`, counted from the lane's last state change;
- the declared back-off after a turn that did not end well.

It never accepts, merges, cleans, marks or stops anything, never retries work by its own judgement and never signals a
process by a name pattern. A turn that follows a failed one is the declared schedule (mail waits, the back-off is over),
not a retry by judgement. A hung turn is the run's time budget, which exists already, and the loop does not shorten it.

**Forms.** `lane loop [--detach]` runs the loop, in the foreground unless `--detach` is given; `lane loop --status` and
`lane loop --stop` are its own status and stop. `--detach`, `--status` and `--stop` exclude each other.

**The lock.** One loop runs per configuration. The loop holds an exclusive lock on `loop.lock` in the state directory
for as long as it lives. It asks for the lock without blocking, ten times, 50 ms apart, because `--status`, `--stop` and
`--detach` look at the lock for an instant with a shared lock, and a loop that starts in that instant is not another
loop; a loop that is another one holds the lock for its whole life. A second `lane loop` for the configuration is
refused after about half a second and names the first loop's process id; `lane loop --detach` is refused at once,
because it looks at the lock before it makes anything. The lock is the kernel's, so it is free when the loop is gone,
whatever ended it. The loop
also writes `loop.json` in the state directory, whole through a temporary name, under the lock: its id, its process
identity (process id and start time as the operating system reports it), when it started, whether it is detached and its
latest failure (the keys `loop`, `pid`, `start`, `since`, `detached` and `last_error`, which is `null` or `{"at",
"message"}`: the time and the text of the line that the loop wrote to `loop.log` for its latest failure: a pass that
could not be made, a lane that could not be read, a started turn whose `loop.turn` could not be recorded, or an attempt
to record `loop.started` that failed). It is written when the loop takes the lock and again, whole, each time one of
these fails, and a loop that is started again replaces it. `loop.log` in the state directory holds the loop's own
messages, as `watch.log` does for a run: a line, with the time,
for each attempt to record `loop.started` that failed, for each pass that could not be made, for each lane that could
not be read, for each turn that started and whose `loop.turn` could not be recorded, and for each loss that the loop
recorded (the last is not a failure and is not in `last_error`); a line that looks like a credential is written as
`(withheld)`. None of the three files holds anything of the environment that the loop captured.

**Back-off.** After any end other than reason `exit` with exit code 0 and a prompt written whole, which includes
`lane.lost` and `lane.gone`, the loop waits before it starts the lane's next turn: `backoff_seconds` (default 300, five
minutes) after the end, and `limit_backoff_seconds` (default 1800, thirty minutes) after reason `limit`. Both are
configuration, keys of `[turns]`. The end's time and reason are read from the lane's latest closing event, so a loop
that is stopped and started again waits exactly as the one before it would have. The reason of the end is its own
reason, `lost` for `lane.lost`, `gone` for `lane.gone`, and `cut` for an `exit` with exit code 0 whose prompt was not
written whole; without a back-off after that last end, a runner that closes its input early and exits 0 would be given
a new turn at every pass. A person's `lane turn` ignores the back-off: it belongs to the loop.

**A pass.** Every `poll_seconds` (key of `[turns]`, default 10, from 1 to 3600) the loop reads the store once and takes
every declared lane in turn:

1. A lane that is running and whose supervising process is seen gone gets the check of `lane check`, for that lane
   only, so that its `lane.lost` (and `lane.returned`) is recorded and the lane can go on; `lane check` gains an optional
   `--lane L` for this, and without it checks every lane, as it does today. A lane that is running and supervised is
   left alone, with no event.
2. A lane that is not running is looked at for what there is to start: a mail turn if mail waits, else an idle turn if
   `idle_seconds` is set and has passed, else nothing, with no event.
3. When there is something to start and the lane is in back-off, the loop records a skip with reason `backoff`.
4. Otherwise it starts the turn through the code of `lane turn` (T5: the account's room is asked first, unless the
   runner has no `room` command). That code waits for
   the lanes lock as every lane command does, at most `[lanes] lock_wait_seconds`, and the other lanes of the pass wait
   behind it. A refusal by any of that command's checks, the lock that stays held included, is recorded as a skip with
   reason `refused` and the first line of the message as `detail`, except the refusal that no account has room, which is
   recorded with reason `no-room` and, as `detail`, what the refusal says after "no turn starts, because " (T5); either
   way the lane is not tried again for `backoff_seconds`.
   That hold is honoured only while it ends within `backoff_seconds` from now, so a hold that lies further ahead than
   that (appended by hand with `event append`, written while the clock was wrong, or written before `backoff_seconds`
   was lowered) counts as over, and the lane is tried at the next pass. A turn that starts is recorded as `loop.turn`.
5. The loop does not wait for a turn it started. The turn belongs to its own supervising process, in the lane's own tmux
   session, as every run does. The turns that the loop starts get the environment that the loop captured when it
   started, handed over as `lane start` hands the caller's environment to a supervising process, and keep it until the
   loop is restarted: a restart of the loop is how that environment changes, and the loop's own environment decides
   which credentials its turns see. The captured environment is never written to an event, to a log (`loop.log`
   included), to a file of the state directory or to the run record. The loop holds it in its own memory and hands it
   over through the FIFO of `lane start`, which keeps nothing once it is read; `loop.json` and the `loop.*` events do
   not name any of it. Every tmux command of the launcher runs with a fixed environment of five names (`PATH`, `HOME`,
   `LANG`, `TMPDIR` and `USER`, as the caller has them), so the configuration's tmux server, which copies the environment
   of the command that started it, keeps no other variable of its caller. A run receives the rest of its environment only
   through the FIFO.

The loop loads the configuration again at the start of every pass, so a runner that was edited since refuses the turn as
`lane turn` would (the failure table), and a change of the three keys of `[turns]` takes effect at the next pass; a
configuration that cannot be loaded makes the pass write a line to `loop.log`, and the loop tries again at the next
one. The passes of a loop that was started with another environment than its configuration's are not different: only
the environment is kept from the start. A lane that cannot be read (an event of an earlier version, a run record that
cannot be read) gets a line in `loop.log` and the pass goes on with the next lane.

**Events.** Every decision is an event of its own kinds, reserved like `brief.rendered` but checked at append and
nowhere else: not in `state verify` and not in `state rebuild`, so that a 1.1.0 store that holds such events written by
hand still verifies and rebuilds. The loop ignores every `loop.*` event that is not in the documented form, whatever its
actor and its `protocol_version`. They are not `lane.*` events and the lane projection ignores them. The envelope's
`lane` is the lane for `loop.turn` and `loop.skipped` and absent for the others. Their actor is `laneboss`.

| Kind | Payload |
|---|---|
| `loop.started` | `loop` (32 hex digits), `pid`, `start` (the process's start time as recorded in its identity), `detached` (boolean), `unrecorded_end` (the id of the most recent earlier loop of the configuration whose `loop.started` has no `loop.stopped`, else `null`) |
| `loop.stopped` | `loop`, `reason` (`stop`, or `error` when an unexpected internal error ends the loop: it appends the event if the store takes it, prints the error as every command does and exits 70), `turns` (turns it started), `skips` (skips it recorded) |
| `loop.turn` | `loop`, `kind` (`mail` or `idle`), `sequences` (what the turn carries), `run` (its number) |
| `loop.skipped` | `loop`, `reason` (`backoff`, `refused` or `no-room`), `until` (a timestamp, or `null`), `after` (for `backoff`, `{"run", "reason"}` of the end that caused it, with the reasons of `lane.returned`, else `null`), `detail` (`null`, or one line of at most 200 characters) |

The forms are in `lanes.check_loop()`, which `EventStore.append()` calls for every kind that starts with `loop.`, whoever
appends it (`event append` included): an event that breaks its form, or a `loop.*` kind that is not one of the four, is
refused with exit 2 and nothing is stored. The check looks at the kind, at the envelope's `lane` (required for
`loop.turn` and `loop.skipped`, absent for the other two) and at the payload (exactly its keys; `loop` 32 hex digits;
`pid` a whole number from 1; `start` at most 64 characters of letters, digits, spaces, `:`, `.` and `-`; `sequences` as
in `lane.started`; `run` 2 or more; a `loop.turn` of kind `idle` has no sequences and one of kind `mail` has some; `after`
is given exactly for the reason `backoff`; `until` a timestamp or `null`; `detail` one line of 1 to 200 characters or
`null`), and not at the actor or the protocol version. `loop.skipped` accepts the reasons `backoff`, `refused`
and `no-room` (from T5, built). `loop_form()` is the same check for
an event that is read: the loop trusts an event of a loop kind only when it is in its form.

A back-off is a skip with reason `backoff`. It is recorded once, when the loop first has something to start for the lane
and finds it in back-off, with `until`, the moment the wait ends. The loop does not record it again on the passes that
find the same wait, and it records a new skip when the reason or `until` changes. `until` is the moment the loop will
look at the lane again: for `backoff`, the end of the wait, and for `refused` and `no-room`, `backoff_seconds` after the
skip. The loop rebuilds what it has recorded from the events when it starts: for each declared lane it reads only the
latest `loop.skipped` of that lane, written by any loop, and compares its reason and `until` with what it finds now, so
a restarted loop does not repeat a skip.

**Status.** `lane loop --status` appends nothing and prints one JSON value: `running` (the lock is held), `loop`, `pid`,
`since`, `detached`, `session` (`laneboss+loop` for a detached loop, else `null`), `last_error`, `unrecorded_end`, and
`lanes`: a list with one entry for each declared lane, with its `lane`, its `state`, `waiting` (the number of messages
that wait for a turn, the returned ones included, the name that the idle group of the briefing gives it),
`backoff_until` (the end of the wait that the lane's latest end makes, a timestamp, or `null` when the lane is running,
the wait is over or the end was good), `next` and `bad_ends` (how many turns in a row ended in a way other than `exit`
with exit code 0 and a prompt written whole, whoever started them, counted from the lane's events alone, one for each run
by the first closing event it has). `next` is what the loop would start for the lane now, from the lane's row, its events
and the clock, as a pass decides it: `null` while a turn runs and when there is nothing to start, `mail` when a message
waits or has returned, `idle` when the lane has an idle interval that has passed (counted from its last state change), and
`backoff` when one of the two is due and the lane's latest end makes it wait (`backoff_until` says until when). It is
read from the events and the clock, whether or not a loop runs. `last_error` is `{"at", "message"}`, the time and the text
of the latest failure of a pass, or `null`; the loop keeps it in `loop.json` ("The lock"), and a message that looks like a
credential is printed as `(withheld)`, the way the detail of a refused turn is. The lock decides `running`; `loop.json` is
only read for the rest, and it is believed only when its process identity matches a process that lives, so that for a
loop that is not running, and for a record that names another process, `loop`, `pid`, `since`, `detached`, `session`,
`last_error` and `unrecorded_end` are `null`. `unrecorded_end` is the one in the `loop.started` of the loop that runs.

**Stop.** `lane loop --stop` reads `loop.json`, checks the identity and sends SIGTERM through the checked signal that
the lane commands use. SIGTERM, SIGINT and SIGHUP all end the loop the same way: it finishes the step it is in (a turn
start is never cut in half), appends `loop.stopped` with reason `stop`, releases the lock and ends with exit 0.
`--stop` waits up to 30 seconds for the lock to be free and prints `{"stopped": true, "pid", "event": {"id", "seq"}}`
(the event is the loop's `loop.stopped`, or `null` when the loop could not record it); when the loop is still there after
that it is refused and names the process. It never kills the loop, and it never stops a turn: a turn that is running goes
on under its own supervising process. When no loop runs, `--stop` is refused (exit 2), and so it is when a loop holds the
lock but `loop.json` does not name a live process, because nothing is signalled that the record does not identify.

**Foreground, and detached.** In the foreground the loop prints one JSON line for each loop event it appends, as
`event tail` prints events (the whole stored event, with its `seq`, `recorded_at` and `sha256`), until it is stopped.
`--detach` starts the loop in a tmux session of the configuration's own server (the socket that its lanes record), handing
it the caller's environment through a FIFO (`.loop-ID.fifo` in the state directory, removed once it is read) as `lane
start` hands it to a supervising process, and returns after `loop.started` is stored, printing `loop`, `pid` and
`session`. The session starts in the state directory, and the output of the detached loop goes to `loop.log`. A second
`--detach`, or a foreground loop, while a loop runs is refused before any session is made. No command kills a session by
its name, so a detached loop is stopped with `--stop`, as above.

The session is named `laneboss+loop`, and no lane's tmux session can have that name. A lane's session is named by
`session_name()` from the lane's name, which the lane grammar (`[a-z0-9][a-z0-9._-]{0,63}`) limits to lower-case
letters, digits, `.`, `_` and `-`, with `.` turned into `_`. The character `+` is not among them, so a name that holds
it cannot be any lane's. A `.` could not serve as that character, because tmux turns it into `_`, which a lane name may
hold. That the installed tmux keeps `+` in a session name is checked by the test of `--detach` (`tests/e2e/test_loop.py`,
`DetachTest`), which lists the sessions of the configuration's server; an upper-case letter, which the lane grammar also
refuses, would be the fallback if a tmux did not keep it.

**When the store is busy, or a turn cannot start.** The loop never dies of either. A pass that cannot open or write the
store within 10 seconds writes a line to `loop.log`, appends nothing, and tries again at the next pass; `last_error` in
the status shows that line, and keeps showing it after later passes that succeed, until a later failure replaces it
("Status"). A decision is re-derived from events and the clock on every pass, so nothing is lost by skipping a pass. A
turn that cannot start is a skip with reason `refused`, as above. Only an unexpected internal error ends the loop, with
`loop.stopped` and reason `error`: an error of the launcher's own kinds (a refusal, an integrity problem, a store that
cannot be used) or a file that disappeared is an expected one, written to `loop.log` and kept as `last_error`, and every
other exception is unexpected. An unexpected error is printed as every command prints it and the loop exits 70: a
foreground loop prints it to the terminal, and a detached loop, which has none, writes a line with the time and the
traceback to `loop.log` (a launcher error that ends a detached loop is written there too, with its own exit status).
This holds for an error of any kind met while the loop runs, an `OSError` or a `KeyError` included; only a failure of
the start itself (the spec it reads, the configuration, the state directory, `loop.log`) ends a detached loop with exit
status 2. A launcher error that is raised in that start, before the output of the loop goes to `loop.log` (loading the
configuration, building the zones, opening the state directory), is written to the terminal of the pane, which closes
with the process, and not to `loop.log`; the errors met while the loop runs are written to `loop.log`. The loop that
began while the store was busy records `loop.started` as soon as the store takes it, and starts no turn before.

**When it is killed.** The kernel frees the lock, `loop.stopped` is never written, `loop.json` stays and is believed by
nothing. Turns that were running go on under their own supervising processes and end as turns do; mail that arrives
meanwhile waits and is lost by nobody. The next `lane loop` takes the lock, replaces `loop.json`, and records in
`loop.started` the id of the loop whose end was never recorded as `unrecorded_end`: the most recent earlier loop whose
`loop.started` has no `loop.stopped`, read as the events table says, so that every later loop of the configuration names
that loop again, because no event ever records its end. A detached loop's tmux session ends with its process. A kill between the moment a turn's `lane.started` is stored and the moment the loop appends
`loop.turn` leaves a turn without its loop event, and the restarted loop does not repair it: "every decision is an
event" holds up to that window, and the turn itself is recorded in full by its own events.

**The configuration.** T3 adds three keys to `[turns]` (`config.py`, `TURNS`; `docs/configuration.md`):

| Key | Type | Meaning |
|---|---|---|
| `poll_seconds` | integer 1 to 3600 | How often the loop looks. Default 10. |
| `backoff_seconds` | integer 1 to 604800 | The wait after an end other than `exit` with exit code 0 and a prompt written whole. Default 300. |
| `limit_backoff_seconds` | integer 1 to 604800 | The wait after reason `limit`. Default 1800. |

**Where the text of the design was silent, and what the launcher does.** These points were not fixed by the design; the
launcher does as follows (`loopcmd.py`, `lanes.py`, `lanecmd.py`; `tests/e2e/test_loop.py` holds the tests):

- The entry of a lane in `lanes` of `--status` is an object of a list, with the key `lane`, as every per-lane output of
  the launcher is, and the number of messages that wait is `waiting`, as in the briefing. `--stop` prints `stopped` as
  `true`, with `pid` and `event`.
- `unrecorded_end` is read as the events table says, and so a loop that was killed is named by every loop after it
  ("When it is killed").
- A pass loads the configuration again, and takes its three numbers from that load ("A pass"). A `loop.skipped` carries
  as `detail` the first line of the refusal, cut to 200 characters, or `(withheld)` when that line looks like a credential,
  which the store would refuse.
- `bad_ends` counts runs, not events: a `lane.gone` that follows a `lane.lost` of the same run is one turn, and run 1,
  the first turn, counts.
- `lane check --lane L` for a lane that the configuration does not know is refused (exit 2), as the other lane commands
  refuse it; for a lane that is not running it prints empty lists.
- `loop.json` is written by the loop that takes the lock, when it takes it and again each time a pass fails. The FIFO
  that hands a detached loop its environment is `.loop-ID.fifo` in the state directory, and the session of a detached
  loop starts there.
- `last_error` (decided by the supervisor, not by the design): the loop keeps its latest expected failure, the line that
  it writes to `loop.log` (a pass that could not be made, a lane that could not be read, a started turn whose
  `loop.turn` could not be recorded, an attempt to record `loop.started` that failed), in `loop.json` as `{"at",
  "message"}`, with the time of the line and its text; a later failure replaces it and a good pass does not clear it.
  The status prints it only while `loop.json` names a loop that lives, else `null`. A message that looks like a
  credential is withheld (`(withheld)`) as the detail of a refused turn is, in the line, in `loop.json` and in what the
  status prints. A turn that cannot start is not a failure of a pass: it is a skip, and it is not in `last_error`. A damaged mail file is such a refusal, so a damaged file does not set
  `last_error`; a busy store and a configuration that cannot be loaded do.
- `next` (decided by the supervisor): each lane entry of the status has the key `next`, one of `mail`, `idle`, `null`
  (nothing to start, or a turn runs) and `backoff` (something is due and the lane's latest end makes it wait). The wait
  that the loop holds after a refused attempt or a no-room skip (a `loop.skipped` with reason `refused` or `no-room`, for
  `backoff_seconds`) is not in `next` or in `backoff_until`: the design calls that wait "not a back-off after an end but
  the same number reused" (Open point 15), and the decision names the back-off only. A lane in either hold shows its
  `next` as it would be without the hold.
- The turn that the loop starts is refused by `lane turn`'s own check while the supervising process of the lane's last
  run still lives, which is true for a second or two after `lane.ended` is stored. A message that arrived during a turn,
  or an idle interval that ends then, is refused for that reason once, and the loop records `refused` and does not try
  the lane again for `backoff_seconds` (300 by default): the design says so, and "Known limits" names it.

### The `lane attach` command and the stream readers (built, T4)

`lane attach --lane L` prints text for a person, not one JSON value, and its exit code is its own ("Leaving"). Its code is
`src/laneboss/attach.py`, which `cli.run_lane` calls, and the readers are in `src/laneboss/streams.py`. Each statement in
this part was read back from that code and from `tests/e2e/test_attach.py` and `tests/e2e/test_streams.py`; where the
design was silent, the last paragraph says what the launcher does.

**What attach is.** `lane attach --lane L` is a terminal view of a lane and a keyboard for it. It reads the lane's own
log and the store, it writes only the mail and the turns that a typed line asks for, it never starts an agent, and it
keeps no child process: the tmux commands that `lane turn` runs end before it returns, and the supervising process it
asks for belongs to the lane's tmux session, not to attach. A real agent program runs its shell tools in process groups
of their own, so one run has more than one group, and a front that signals one group leaves processes of the run behind.
Attach signals no process itself and no group: a stop is the code of `lane stop --run N`, which signals the run's
supervising process (checked by its recorded identity), and the run belongs to that process, which stops the run's
processes one by one, each by its recorded identity, and never signals a process group as a whole ("Running"). Nothing
of the agent can outlive attach, because attach never owned it. The main thread of attach reads the keyboard; a thread of
its own, the follower, reads the log and the store with a session of the store that only it uses; one writer, which both
use, puts every line of output on the terminal (the prompt and the echo of a typed line are written by `readline`, and
the refusal of a `lane stop` goes to standard error).

**The view.** Attach first finds the lane (a lane that the configuration does not know is refused with exit 2, "lane L is
not known to configuration C", as every lane command says, and nothing else is printed). Then it prints, in this order:
the line `lane L: state S, run N, session ID, runner R, model M` (`none` for a lane without a session identity); for a
lane that is not turn-based, the line `this lane is not turn-based: attach is a view only here, and a typed line is
refused by lane send`; the permission mode ("The permission mode"); and, for a lane that does not run, one line, the idle
display or `not running: state S`. Then it follows the lane:

- While a turn is live it says `following run N (live)` and shows the live run's output from `output.log`, opened
  through the lane's directory without following a link and read from `log.start` of the live launch's run record, which
  is the run's byte range of the log. It polls the log every 0.2 seconds, as `event tail --follow` polls the store, and
  reads the store every 0.5 seconds for the state of the run. Every complete line goes through the lane's stream reader.
  When the run ends, the rest of its range is shown (up to `log.end` of its run record, else up to the start of the next
  run, else to the end of the log), a last line without a newline included; then one line for the end,
  `[run N | exit CODE | ...]` ("Cost"), where `CODE` is `signal S` for a runner that a signal ended and `none` for one
  that never ran; then the idle display. A run that was recorded as lost or declared gone has no `lane.ended`, and gets
  `run N ended without an end event (reason R)` for the end line. A run is found by its number and not by being live at
  a look: attach keeps the number of the last run it has shown (at its start the number the lane is at, or the one
  before it when a run is live), so a run that began and ended between two looks at the store, as a short turn can, is
  shown after the fact, in its turn: `run N had ended when attach looked`, its range of the log, its end line, and, for
  the latest run, the idle display.
- Between turns it shows `idle: run N ended with reason R, exit code C, T ago; messages waiting: K`, and, when K is above
  0, `; type /turn to start a turn for them`. K is the number of messages that wait or have returned (the number the
  briefing gives), T is counted from the lane's last change of state, and `exit code none` stands for a run that no exit
  code ended. `lane status` shows `idle` true for exactly the lanes that have this line (state `waiting`, no run going
  on), with the same `reason`, `exit_code` and `mail`.
- For a lane that is not turn-based it is a view only and says so; a typed line is refused by `lane send` with its
  reason.

**The keyboard.** The prompt is `attach> ` (`... ` for the line after one that ends with a backslash). A typed line is one
message. Attach sends it with the code of `lane send` (`lanecmd.send_message`: the sender is `attach`; the text never goes
through a shell or an argument), exactly as typed and with nothing added, and prints `message N sent`; then it runs the
code of `lane turn` and prints `turn started: run N (messages ...)`. A line that ends with a backslash continues on the
next line, and the lines of a message are joined with a newline, the backslash dropped. An empty line is ignored. `/turn`
runs `lane turn` for mail that waits, `/stop` does what the first Ctrl-C does (below), `/help` lists these and `/exit`
leaves. A line that starts with `/` and is not one of them (its trailing white space dropped) is refused (`not sent: LINE
is not a command (type /help)`, the line cut to 60 characters) and never sent; a line of that kind that holds a
credential shape is refused as `not sent: the line is not a command (type /help); it holds a credential shape, which is
not repeated`, with nothing of the line; a line that starts with a space is sent. When a turn is live, `lane turn` is
refused by its own check, and attach prints `message N queued: ` and the refusal, and says that the message goes with the next turn,
which the loop or a person starts: attach does not start that turn itself.

Attach reads a line with the standard library's line input, with `readline` when the interpreter has it and standard
input and output are terminals, so the keys of the terminal edit it, Ctrl-C at the prompt discards what was typed and
prints a hint, and Ctrl-D ends the input. A typed line that `lane send` refuses (a busy store, a lane that cannot take
mail, a message that is empty or too large) is printed again, after `not sent: ` and the refusal, as `your line: ...`,
and the next prompt holds the line for editing; where the interpreter has no `readline`, the line is only printed again,
after the refusal. A line that holds a credential shape is refused with the refusal that names it, and is not printed
again or held, because a credential shape is never repeated ("The failure table"); a several-line message that was
refused is printed again but not held.

**Live output and the typed line.** While a line is being typed, attach holds back what the log shows and prints it at
the next prompt, when the line has been entered or discarded. It never redraws a line: a line in the terminal's own line
mode belongs to the terminal, and what is typed reaches attach whole when the line is entered. A line is being typed
when the line buffer of `readline` is not empty; when it is empty, the output goes above the prompt, which is shown
again (a new line is started, the cursor goes back up onto the prompt's line, which is erased with `ESC [ K`, the
complete lines are written and the prompt is written again, so that the `readline` that waits goes on with the line it
holds, and a recording of the session, which keeps what a terminal would have erased, has the output on lines of its
own). The follower looks every 0.2 seconds whether the line has been
emptied, so a line that is discarded (Ctrl-U, for one) lets the held output go above the prompt, and a line that is
entered lets it go before the next prompt. Only complete lines go above a prompt: the unfinished last line of the
output waits for its end, and the end of a turn completes it. Where the interpreter has no `readline`, attach cannot see
a typed line and holds nothing back: the typed bytes are intact, and only the look of the line suffers.

**Leaving.** `/exit`, end of input (Ctrl-D), a closed terminal (SIGHUP) and SIGTERM leave attach. A live turn goes on,
whoever started it. The exit code is 0 for `/exit` and end of input, and 128 plus the signal number for a signal (129
and 143). A closed terminal reads as the end of the input as well, so after the end of the input attach waits 0.2
seconds for the SIGHUP that comes with it; the handlers of the signals are installed once attach has found the lane.
When it leaves, attach stops its follower, moves the cursor to the start of a line and shuts its writer, so that a
follower that is still in a long pass when attach returns writes nothing.

**The stop path.** Ctrl-C does one of three things, by what the store says at that moment. `/stop` does the same.

- With no turn of the lane live, it clears the line being typed and prints a hint (`the line was discarded; nothing was
  stopped; leave with /exit or Ctrl-D ...`). What the hint says about a discard depends on what attach knows, and it
  says only what is true (`attach.hint_text`). Where it knows that a line was discarded (the line editor says that a
  line was being typed, or the lines of a message that goes on had been read), it begins `the line was discarded;`.
  Where it knows that none was (the line editor says that the line is empty, and a key that came while attach was busy
  discarded no line), it begins `nothing was stopped`. Where the line editor cannot say what is typed, it begins
  `anything typed was discarded; nothing was stopped; ...`, which is true whether a line was typed or not. That is the
  case on macOS, where the line editor is libedit, whose `get_line_buffer()` is the buffer of its own line, which it does
  not clear between two lines (the bytes of the line entered before are in it at an empty prompt, so its answer cannot
  be trusted either way); it is also the case when there is no line editor, or when its buffer cannot be read
  (`attach.typed_buffer` is None). The real trial of T4 found `the line was discarded` at an empty prompt on a Mac; the
  libedit path itself was seen only in that trial, and the decision is tested with stand-ins for the line editor. The
  same three-way answer decides whether the console holds the output back (`Console.typing`): only a line that the line
  editor says is being typed holds it, so that a stale buffer cannot hold the output of a turn until Enter. Nothing is
  stopped.
- While a turn that this attach started is live (attach keeps the numbers of the runs that `lane turn` started for it),
  the first Ctrl-C says `stopping run N` and asks for the stop of that run with the code of `lane stop --lane L --run N`,
  where N is the number of the run that attach started. `lane stop` acts only on the lane's latest run and is refused
  when `--run` names another, so attach cannot stop a turn it did not start, even when the loop or a person has started
  another turn since. The supervising process stops the whole run and records `lane.ended` with reason `stopped`, and
  the mail of that turn returns. Attach asks in two parts, as `lane stop` does (`lanecmd.stop_request`, then
  `lanecmd.stop_finish`). When the request has gone out, that is, when the supervising process has been signalled
  (checked by its recorded identity), attach says `stop requested for run N; press Ctrl-C again to stop waiting (the
  request stands)`, waits for the end (at most the stop grace plus 30 seconds), prints `run N ended with reason stopped;
  survivors S`, and goes on at the prompt. Until the request has gone out a further key is only counted and never
  raised into it, so a second key that follows the first at once, a double tap, cannot cancel the request: attach asks
  all the same and then leaves with exit 130, and the supervising process finishes the stop. A Ctrl-C during the wait
  only stops the waiting: attach leaves with exit 130, the stop request stands, and the supervising process finishes the
  stop; if the supervising process has gone by then, attach says so (`leaving attach; the supervising process has gone,
  so the stop may be incomplete: run lane stop --lane L`) and does not promise a finish. When the request is refused
  because run N is not going on (the lane's latest run is another, or the lane is not running: the run ended as the key
  was pressed, or another has begun; `lanecmd.NotGoingOn`), attach says `run N had ended; nothing was stopped` and stays
  at the prompt. Every other refusal, from the request or from the wait, is written to standard error as `refused: ...`
  with each survivor named, and attach exits with that command's exit code, 2; attach does not look at the store to
  explain it away.
- While a turn that this attach did not start is live (a person started it, or the loop did), Ctrl-C leaves attach with
  exit 130 and stops nothing.

**A key while attach is busy.** Attach has one handler of SIGINT for the whole of its life. It raises
`KeyboardInterrupt` only at the prompt and while a stop is waited for, and it sets itself to count keys before it raises
for the first key, so that a key that follows at once is counted too. Anywhere else a key is only counted, and a lane
command is never cut in two by it. While a line is sent (`lane send`) and its turn started (`lane turn`) a key is
therefore counted and acted on when the command has returned, as the first Ctrl-C of the turn that has just started: it
stops that run when this attach started it. A line that was stored is never reported as discarded: the line `message N
sent` says what became of it.

Three places need more than that, and each has a rule.

- *The command that waits.* A lane command waits for the lanes lock (`lock_wait_seconds`, 60 by default) and for the
  start of a run (up to 30 seconds more), and every look at the store waits for the state directory's lock with no bound,
  so a key counted meanwhile may wait long. The follower, which looks every 0.2 seconds, prints once for the command
  (unless its own look waits for the same lock) `Ctrl-C noted: attach acts on it when the lane command now running
  returns; another Ctrl-C at least 2 seconds after this one leaves attach now, without waiting`; the handler itself
  writes nothing and takes no lock, and reads the monotonic clock. Two keys less than 2 seconds apart are a double tap,
  what a person does who regrets a line just after Enter, and `lane turn` spends most of its time waiting for the run
  it has started to record its start: the two keys are counted, and when the command returns they act as one Ctrl-C,
  which stops the run that attach started and leaves attach at its prompt. A key that comes 2 seconds or more after the
  first one counted in the same command (the line being sent and its turn started, or `/turn`) means that the command
  is slow or blocked, and leaves attach at once, with exit 130. The line says what is not known, and what was not done:
  in `lane turn`, `leaving attach; a turn for message N may be starting, and it was not stopped: see lane status, and
  lane stop --lane L stops it` (`a turn may be starting` when no message is known, as after `/turn`); in `lane send`,
  `leaving attach; the lane command that was running may not be finished; see lane status`. It never says that the turn
  began or that it was stopped. The lane commands are crash-safe, so nothing of attach's own is left half written. The
  stop path is not a command in this sense: there a second key is only counted until the request has gone out ("The
  stop path"), so a state directory's lock that blocks the stop path is left by closing the terminal.
- *The prompt that is not yet armed.* A key that comes while attach writes the output it held back before a prompt
  (`Console.before_prompt`) is counted, and when attach has armed the prompt it acts on the key as a Ctrl-C at an empty
  prompt: the lines of a message that goes on are dropped, and a turn that this attach started is stopped, without an
  Enter.
- *The prompt that is being drawn.* The line editor runs a function of attach's while it draws the prompt (the hook that
  tells the console that the prompt is on the screen) and clears an exception that is raised in it, so a handler that
  raised there would lose the key and, with it, the switch that makes the next key raise. The handler therefore only
  counts a key that comes while that function runs (it looks at the frame it interrupted), and the hook arms the prompt
  again when it ends: the next key raises as usual. A key lost that way is counted, like a key during a command: it is
  acted on when the line has been entered, and when the next key raises at that prompt it counts as a key before the
  request, so attach asks for the stop and then leaves with 130, as after a double tap. (A SIGTERM or SIGHUP that comes
  while the line editor runs attach's hook is cleared by the line editor in the same way, and attach does not guard
  against that: the signal can be sent again. While output floods, the hook waits for the console's lock and the window
  is long.)

**The stream readers.** The launcher stores what the runner prints, line by line, and classifies the end of a run by the
runner's `limit_patterns` and `dropped_patterns` on those lines as written. A runner's `stream` key names the reader
that attach uses to show them: `text` or `claude-stream-json`, and without the key `text`. The key goes in
`[runners.NAME]`; `docs/configuration.md` has it ("The stream of a runner"), and a name that is not one of the two, or a
value that is not a string, is refused by `config validate` (the names are `streams.READERS`). A reader lives in
`src/laneboss/streams.py`, one named reader for each format, and nothing else in the launcher knows a vendor's format:
attach handles only what a reader returns, and knows of a reader only that `text` gives whole lines and neither a mode nor a
cost, and what the reader module itself exports: `streams.BYPASS_MODES`, the names of the permission modes that mean
that approvals are bypassed, which the warning of attach takes from there. A runner whose `stream` is `claude-stream-json` prints its limit message inside a JSON line, so its
`limit_patterns` must be written to match the line as it is printed; the reader plays no part in the end's
classification. A pattern that no longer matches makes a turn that ended at a limit count as delivered, which the doctor
warning of T2 does not catch, because it names only the runners that have no pattern at all; `test_attach.py` tests the
case ("The test plan for T2 to T5").

A reader takes one line of the log and returns a list of items, each a plain mapping with a `kind`: `answer` (text of
the agent), `tool` (a one-line label), `mode` (the permission mode the agent reports), `result` (cost, whether it is an
error, the denials), `notice` (what the agent program wants the person to see, cut to 100 characters like a label), or
`raw` (a line that is not of a shape the reader knows). A line that is of a shape the reader knows and that no person
needs gives no item at all (see `claude-stream-json` below). No line of any shape may give a
traceback: attach calls a reader inside a guard, so that a line that is not JSON, JSON that is not an object, fields of
the wrong type, a huge or deeply nested value, or bytes that are not UTF-8 give at worst a `raw` item, shown cut to 200
characters (for `claude-stream-json`: the `text` reader shows any line whole, as an answer), and a reader that raises
anyway is caught, with one note for the turn.

- `text` returns every line as an `answer` and never a mode or a cost.
- `claude-stream-json` reads the lines of a headless Claude Code run that prints one JSON object per line
  (`--output-format stream-json --verbose --include-partial-messages`): the `system` line with subtype `init` gives the
  `mode` from its `permissionMode`; partial-message lines (`stream_event`) give the streamed text of the answer; whole
  `assistant` lines give the text blocks that were not already streamed and, for `tool_use` blocks, a `tool` label of the
  tool's name and the first 100 characters of its command, file path, pattern, path or url (the first of them that the
  call has); the `result` line gives `total_cost_usd`, `is_error` and `permission_denials`. Each denial is shown as one
  line, `[denied NAME]` and the first 100 characters of the same field, before the end-of-turn line, and the first denial of an attach is followed by one line
  (`note: this request ran without approval rights.`). A result line whose `is_error` is true is followed by one line
  that says the request ended in an error. These shapes are what a front for such a run read when this was designed;
  the real trial of T4 (a real headless session, three turns, a tool, Ctrl-C with the tool running) confirmed them, and
  showed what else a real session prints. About fifty lines in the three turns were of shapes that the reader did not
  know, and each was shown as a raw line, a wall of JSON between the person's line and the answer. The reader now gives
  NO item (the line is dropped, as a `stream_event` of no text is) for: a `system` line with the subtype `hook_started`,
  `ui_invalidate`, `status`, `thinking_tokens`, `task_started` or `task_notification` (the agent program's own
  bookkeeping: `streams.QUIET_SUBTYPES`); a `hook_response` that succeeded (its `outcome` is `success` and its
  `exit_code` is 0 or missing); a `rate_limit_event` whose `rate_limit_info.status` is `allowed`; and a `user` line
  that carries a `tool_result` block that is not an error (the tool's result, which the answer and the tool label stand
  for). What a person needs is shown: a `system` line with the subtype `notification` and a text gives a `notice`
  item, which attach shows as `notice: TEXT`, because it carries what the agent program wants the person to see; a
  `hook_response` that did not succeed (the `outcome` is another string, or the `exit_code` is not 0) gives a `notice`
  `hook NAME: OUTCOME (exit CODE)`, made of the fields that are strings and integers (a field that is missing, of
  another type or an empty string is left out, and a boolean is no integer; the text is made inert and cut to 100
  characters like a label), because a hook that fails or refuses can be a guard of the agent's environment that did not
  run; and a `user` line with a `tool_result` block whose `is_error` is true gives one `tool` item (for the first such
  block), `[tool error] ` and the first 100 characters of the block's content (a string, or the first text block of a
  list; made inert), a line of its own like a tool label. These stay raw, as
  before: a `rate_limit_event` whose status is anything but `allowed`, or whose `rate_limit_info` is missing or not an
  object (it may be a refusal, and the person should see it), a `hook_response` with no outcome that is a string and no
  exit code that is an integer, a `notification` whose text is missing, empty or not a string, a `user` line of any
  other content, and every other line that is not known. All of this is in `streams.py`, where the vendor's format
  lives; attach knows only the kind `notice` (a `tool` item it showed already), and the `text` reader is unchanged.

Attach shows the items as follows. An `answer` of a `text` stream is a line and is written with its newline; an `answer`
of another reader is a piece of text, written as it is, and the line it is on is closed (a newline) before a label, a
denial, a mode line, a raw line or the end line follows. A whole `assistant` text (the item carries `streamed: False`) is
dropped when the pieces of it were shown as deltas (attach keeps the text it showed since the last result line, and the
whole text is dropped when it is found in it, after which the text up to and including it is forgotten), and is shown
as a block otherwise. A `tool` is its label on a line of its own, a `notice` is `notice: ` and its text on a line of its
own, and a `raw` item is its text on a line of its own. A reader that
raises, or an item of a shape that attach does not take, is caught: the line is skipped and one note
(`note: the stream reader failed on a line of this turn; the line was skipped`) is written for the turn.

**Cost.** For `claude-stream-json` the `total_cost_usd` of the result line is taken to be the session's running total, as
the design assumes (T4's real trial confirms or refutes it: "Known limits"), so one turn costs the difference between its
total and the total at the end of the turn before. Attach takes the earlier total from the earlier run's range of the log
when that range has a result line (the cost of the last one), and otherwise prints only the total, with "this turn"
unknown; so it does when that cost is not a number, when the difference would be negative, and for the first run of a
lane. A turn whose own result line is missing or has no number prints `unknown` for both. At the end of a turn it prints
one line, `[run N | exit CODE | this turn $X | session $Y | S seconds]`, with the amounts in dollars to four decimals and
S to one. `text` has no cost: its line is `[run N | exit CODE | S seconds]`.

**The permission mode.** The launcher passes no permission option of its own: the runner's `command` does, and an
account's own default may differ from what a person expects. Attach therefore shows the mode that the agent reports,
as `permission mode (as the agent reports it): MODE`, at its start from the latest `init` line found in the log, and
again whenever a new `init` line reports another. When the mode is `bypassPermissions` it also prints, in plain text
that is never dimmed (attach uses no styling at all), `WARNING: approvals are bypassed: the agent may run any command and
change any file it can reach.` When no `init` line has been seen it says `permission mode: not reported yet`; a `text`
stream never reports one. At the start the latest `init` line is found by taking the runs of the lane from the latest
back and reading the range of the log of each, the first range that has a mode deciding (the last mode in it); a new
`init` line that reports the mode already shown prints nothing.

**Control characters.** Everything attach prints from the stream passes through one filter, raw lines and labels
included (`streams.UNSAFE` and `streams.CONTROL`: the reader applies them to the answer text, the labels, the denials and
the raw lines, and attach applies the second to the mode, which the reader returns as the agent wrote it). In answer text
the C0 control characters other than tab and newline, DEL and the C1 control characters are removed. In a label, a mode
or a raw line every control character becomes a space. An escape sequence in the agent's text can then neither move the
cursor nor set the title nor write to the clipboard of the terminal; what remains of it is visible and inert. The same
filter is applied to a refusal that attach prints and to the line it prints again.

**Status.** `lane status` shows `idle` for a lane in state `waiting` that has no run going on (T2). That is the state
attach shows as "idle", and the briefing lists such lanes.

**Where the design was silent or its places did not agree, and what the launcher does.** `test_attach.py` pins what it can
of these; the rest is marked.

- A key while attach is busy, and a stop that is refused. The design says that the first Ctrl-C during a turn that this
  attach started stops it, and that a stop that cannot be completed is reported; it is silent on a key that comes while
  the line is still being sent and its turn started, on a second key that follows the first at once, and on a refusal of
  `lane stop --run N` for a run that has just ended. Attach counts such a key and acts on it when the command has
  returned or the request has gone out, says once that it has noted it, takes two keys less than 2 seconds apart for
  one Ctrl-C, leaves at a key 2 seconds or more after the first in a command, and tells a refusal because the run is not
  going on from every other refusal ("A key while attach is busy", "The stop path"). A Ctrl-C that finds nothing typed
  does not say that a line was discarded, and one whose line editor cannot say (libedit on macOS, no line editor) says
  `anything typed was discarded`, which is true either way.
- The lines of a real session that the design did not list. The design lists the shapes that a reader reads; the real
  trial showed about fifty lines of other shapes in three turns. The reader drops the agent program's bookkeeping, a
  hook that succeeded, a rate limit that is `allowed` and the result of a tool that did not fail; it shows a
  `notification` as a `notice`, a hook that did not succeed as a `notice` and a tool that failed as `[tool error]`; and
  it leaves everything else raw ("The stream readers"). Readings of mine: "a `user` line" is read as a `user` line that
  carries a `tool_result` block (a `user` line of any other content, an interrupt message for one, stays raw); a
  `notification` whose text is empty or not a string stays raw; a `hook_response` with neither a non-empty string
  outcome nor an integer exit code stays raw, and a null `exit_code` counts as missing; a failed tool result with no
  text is `[tool error] ` alone, and a line with several failed results shows the first. All are reversible.
- The view of a short turn. The design says that attach shows a live turn and, when it ends, the rest of its range and
  its end; read as "a run is shown when a look at the store finds it live", that misses a turn that begins and ends
  between two looks (the stand-in's turns of a few lines do). Attach follows runs by their numbers, as "The view" says.
- The mode. The reader returns the permission mode as the agent wrote it, though its documentation says that the text of
  every item is filtered; attach filters the mode itself, as "Control characters" says.
- A refused line that holds a credential shape. "The keyboard" says a refused line is printed again and held, and "The
  failure table" says that a credential shape is reported by its line and never repeated. Attach follows the second for
  that case only.
- `/stop` is the same handler as Ctrl-C, so with a turn live that this attach did not start it leaves attach and stops
  nothing (not tested).
- After a stop that completed attach goes on at the prompt, as it does after any turn (not tested). Leaving by Ctrl-C
  (a turn that attach did not start, or the second Ctrl-C) exits with 130, 128 plus SIGINT, which is also the code of
  `cli.main` for an interrupt.
- Text that the design did not give: the prompt `attach> `; the lines `message N sent`, `turn started: ...`, `message N
  queued: ...`, `not sent: ...`, `your line: ...` and `following run N (live)`; the end line `[run N | exit CODE | S
  seconds]` of a `text` stream; four decimals for an amount; `unknown` for a total or a difference that is not known; the
  hint at Ctrl-C; `no turn started: ...`, `stopping run N`, `stop requested for run N; ...`, `run N had ended; nothing
  was stopped`, `Ctrl-C noted: ...`, `leaving attach: ...` and `leaving attach; ...` (the stop request stands; the
  supervising process has gone; a turn may be starting and was not stopped; the lane command may not be finished), the
  line `run N ended without an end event (reason
  R)` and the notes that begin `note: ` (a result line that says the request ended in an error, a reader that failed, a
  lane that the view could not read for a moment). A typed message is stored as typed, with no
  newline added.
- The cost: a negative difference of totals counts as unknown, and a first run has no earlier total.
- A several-line message that is refused is printed again but not held; a runner that the configuration no longer has is
  read as `text`; a line of the log has no length limit; a refusal of `lane stop` is written to standard error as
  `refused: ...`, like the command's own.
- The design says attach sends with "the code of `lane send`", which reads its message from a file or standard input:
  `send_mail` is split into itself and `send_message`, which takes the bytes, so that attach calls the same checks, lock
  and events; the order of the checks does not change.
- "A turn that the loop started" (the test plan): the tests use a turn that `lane turn` started outside attach. Attach
  keeps the runs that it started and does not tell who started another, so that turn stands for one that the loop (T3,
  built) started; no test of attach runs the loop.

### Accounts and adoption (T5; built in part)

Built: the room command of an account and the choice of the account it feeds (`accounts.room_of`,
`accounts.choose_account`), the wiring of that choice into a person's `lane turn` and `lane resume` and into the loop,
the hold of a lane whose accounts have no room, the command `lane adopt`, and the event `lane.adopted` with the
projection and the readers that take it for a run 1 already over. Designed, not built:
the rule that a pass starts no room command for an account while an earlier one for it still runs, the room command of
`lane start`'s first account (no form of `lane start` asks it), and the remaining quota of an account, read by an
adapter of its own under `integrations/` and a later piece.

**No room means no turn.** A turn that cannot get an account is not started. The mail stays waiting. For the loop, the
`loop.skipped` with reason `no-room` and the command's reason as `detail` says why, and the lane is held for
`backoff_seconds` as a lane whose turn was refused is. For a person's `lane turn`, the refusal message (exit 2) says why
and no event does, because a refused command appends nothing ("Open points"). A runner without a `room` command has no
room check, and "no room" for it is the two things the launcher can see: a start that is refused for the account (it is
not listed, or the project excludes it), and a run that ends with reason `limit`, whose mail returns and whose lane
waits out the limit back-off.

**The room command (built, T5).** The runner key `room` is an argument vector with a program that is a command name or
an absolute path, and the placeholder `{account}` as its only placeholder, so that one template serves every account of
the runner. The launcher runs it without a shell, with standard input from `/dev/null` and the caller's environment,
once for each account that it considers, and waits at most `[lanes] room_timeout_seconds` (from 1 to 60; the caller
reads that setting, and `accounts.DEFAULT_TIMEOUT_SECONDS`, which is 20, is the default it falls back to when the
configuration leaves the key out). After every run — whether it ended in time, timed out, or wrote too much — the
command's process and every process of its tree, group and session are stopped by their identity (SIGTERM, then SIGKILL
after `stop_grace_seconds`), never by a name pattern and never by a group signal, as the supervising process stops a
run; each look is walked to a fixpoint before any signal is sent, and a process the stop found that is not seen gone
afterwards (or a process table that cannot be read) is no room as well. The command's tool belongs to the organisation:
the check of "Organisations" that refuses an absolute path into another organisation's tools applies to `room` as it
does to `command` and `resume`. The core knows no vendor; the command reads whatever the vendor offers and answers in
one fixed form. There is one template for each runner, which serves all its accounts through `{account}`, and an
override for one account is not part of the design; the effect is the same while every account of a runner uses one
program.

What that stop does not promise, and what the code does not claim: a descendant outside the command's process group
and session whose parent has ended before a look of the stop walked from it — before the first look, or during the
stop, as when a process the stop found in a session of its own starts a child and ends — is not found, not stopped and not
counted, and the answer can then be room while it runs. That gap is named and kept: such a descendant is not adopted
back into the command's tree, because the process that runs the room command (`lane turn`'s, `lane resume`'s or the
loop's) does not make itself a child subreaper: only a run's supervising process calls `processes.become_subreaper`
(`supervise.py`). Outside Linux the gap is wider: `ps` reports no session id, so a process
that only left the command's group is missed the same way.

**Not built.** A pass does not yet keep from starting a room command for an account while an earlier one for it still
runs, so a command that hangs can leave one more process at every pass. Each run stops the whole tree it can see, which
is what holds that case today ("Not built yet").

Its standard output is exactly one JSON object of at most 4 KiB with these keys and no others:

| Key | Form |
|---|---|
| `room` | `true` or `false`: whether the account can take a turn now. |
| `slots` | A whole number from 0 to 64: how many turns, in addition to those already running on the account, it can take now. `0` when `room` is `false`, and 1 or more when it is `true`. |
| `reason` | A string on one line of at most 200 characters: why, for a person to read. It may be empty when `room` is `true`. It is checked for credential shapes, and one that has a shape is replaced by `(withheld)` in events and messages. |

The command must exit with status 0. A non-zero exit, a timeout, output that is not exactly that object (a missing or
extra key, a wrong type, a number out of range, more than 4 KiB, text that is not UTF-8) counts as no room, with the
reason `the room command of account A did not answer in the documented form`; the account is never guessed to have
room. Nothing from such output is printed except that sentence.

**Slots and the choice of the account (built, T5).** A turn takes the account in this order: the one that `--account`
names, and only that one — it is asked, and when it has no room nothing else is asked and the answer carries its own
reason; else the previous run's account, when the runner lists it and the project does not exclude it; else the runner's
other accounts in the order it lists them, skipping those the project excludes. The first candidate whose checked answer
is `room` true with `slots` of 1 or more — and that has not already taken `slots` turns in this pass — is used, and
`chosen_by.account` records who chose it: `room` when a turn or a resume of a runner with a `room` command took an
account of the runner's list other than the previous run's; an account `--account` named stays `supervisor`, and the
previous run's account `previous`, even when the room command was asked; `default` is written only by `lane start`,
for the runner's first account the project does not exclude, and never by a turn or a resume. A runner without a
`room` command has no room check: its turns use the previous run's account as before. In one pass the loop starts at
most `slots` turns on an account, counting the turns it started in that pass. A lane the pass could not start, because
no account had room or because its accounts had already taken their `slots` in the pass (its `detail` then says
`account A has taken its N turn(s) for this pass`), is recorded `no-room` and held for `backoff_seconds` like any
`no-room` lane: it is tried, and the command asked for it, when the hold ends, not at the next pass. The command, which
can see what is running, stays the authority. A person's `lane turn` asks it as well, for
the account it would use.

**Adopting a session that already runs.** The event `lane.adopted`, the projection that reads it and the readers that
take it where no `lane.started` exists are built (T5). The command `lane adopt` is built too: it takes a session
that exists, because something outside the launcher started it, and makes it a turn-based lane, so that the next
`lane turn` resumes it:

`lane adopt --lane L --session ID --runner R --model M --worktree PATH --brief FILE [--project P] [--effort E]
[--account A] [--idle SECONDS] [--budget MINUTES]`

`--lane`, `--session`, `--runner`, `--model`, `--worktree` and `--brief` are required. `--project` records the named
project or `null`; `--effort` and `--account` are `null` when omitted. No routing or default account is chosen.
`--idle` defaults to `[turns] idle_seconds`, else `null`. `--budget` is recorded as `budget_minutes`, else the value
of `[lanes] budget_minutes`; `quiet_seconds` is the runner's `quiet_seconds`, else `[lanes] quiet_seconds`, else 900.
`branch`, `base` and `repository` are `null`, and `touches` is `[]`.

It is the one lane command that makes a lane whose first run the launcher did not supervise; `event append` can still
store a `lane.adopted` written by hand, which meets the checks at append and none of the command's. It appends two events:
`brief.rendered` and then `lane.adopted`, whose payload is the payload of a `lane.started` without `run`, `how` and
`launch`, so that it holds everything that a turn reads from the previous run, in the same grammars and under the
same consistency rules. Its
`session_id` is required and is the identifier given, `idle_seconds` is added, `difficulty` is `null`, and every part of
`chosen_by` whose value is given is `supervisor`, while a part whose value is null is null, which is the consistency
rule of `lane.started`. The binding checks of `lane.started` apply as well: the tmux session is this configuration's
session for the lane, the log is the lane's log and the brief is the lane's rendered file. The projection takes the
event as a run 1 that is already over: `run` 1, not running, state `waiting`, `mail` with `turn_based` true, and the
runner, model, effort, account, worktree and branch of the payload, so that the first turn is run 2 with `how` `resume`
and `after` `null`. No entry of `times` is set, because the launcher started and ended nothing, and `state_at` is the
time of the adoption. That run 1 is a number and not a run: it had no supervising process of the launcher, no run
record, no budget in force and no refusal coverage ("Open points"). The code that `lane turn` shares with `lane resume`
reads "the previous run" from the latest `lane.started`, and it and `lane status` take the payload of `lane.adopted`
where no `lane.started` exists. At append, `lane.adopted` is accepted only for a lane that has no `lane.*` event yet,
and the lane's next `lane.started` must be run 2. The brief is rendered and kept as for any lane (`brief.rendered`)
and is the lane's standing brief; the launcher sends it as a message nowhere. The command also takes the working
directory's claim
and holds the lanes lock from the store refresh through the append. The store reads that decide whether the lane,
session and working directory are available run under that lock. It prints the `lane.adopted` payload plus `lane`
and `event` (its `id` and `seq`), as `lane start` does. `lane send` is accepted, and the first turn resumes the given
session identifier.

Every check below runs before a lane event is recorded, a claim is taken or a brief is rendered. A refused check
exits 2, appends no lane event, takes no claim and renders no brief; the state directory, its lock file `lanes.lock` and
the account's claims registry may have been created:

- a lane name the configuration already knows, in any state; `lane adopt` has no `--reuse`;
- a session identifier that is not a lower-case UUID, or that another lane of the configuration has (one session
  belongs to one lane, counting every `lane.started` and `lane.adopted` in any state: a session adopted by mistake
  cannot be adopted again in this configuration);
- a runner that cannot take turns (`{session}` in `command` and `resume`, a `resume` template and `prompt = "stdin"`),
  an account that the runner does not list or the project excludes, and the other
  checks that `lane start` makes of the runner, model, effort and project;
- a resume template that uses `{effort}` or `{project}` while the adoption leaves that value `null`: no turn could
  fill it, so the call must give that option;
- a working directory that does not exist, that is not allowed (a launcher zone or a repository's main working copy),
  or that another lane works in or claims;
- a live launch of the lane, an unavailable tmux command, a tmux session name that would collide with another lane's,
  or a tmux session of the lane's name that is open on this configuration's socket;
- a runner that has no `records` entry whose path uses `{session}`: nothing then could show that the session exists or
  that nothing is writing to it;
- a session whose records, found by the runner's `{session}` templates, do not exist, or whose newest record was
  written within the runner's quiet seconds;
- no time budget: neither `--budget` nor `[lanes] budget_minutes` supplies one;
- the checks every lane command makes of its input: the form of `--lane`, `--idle` and `--budget`, a `--worktree` or brief
  path that looks like a credential, a brief that `brief render` would refuse, and a lanes lock that another command holds
  past `[lanes] lock_wait_seconds`.

The runner's records templates decide where the session's record is found. A template that does not mention
`{worktree}` finds the record whatever `--worktree` is, so `lane adopt` does not check that the session worked in
that directory. `lane adopt` starts no run and supervises nothing. A session that something
else keeps driving after it is adopted is outside what the launcher can see, and the person who adopts it says that it
is not.

### The failure table

Each row is one ordinary mistake or failure, what then happens, and the check that blocks it or records it. Two unusual
things at once are in "Known limits". The rows that name a room command describe what T5 built, and so does a clause
about them inside another row, except the clause that no pass starts another room command for an account while one
still runs, which is not built; the row that names attach describes what T4 built, and every other row, the rows that
name the loop included, describes what T2 and T3 built.

| Mistake or failure | What happens | What blocks or records it |
|---|---|---|
| A second `lane send` at once | Both messages are stored, with consecutive sequence numbers. | The mail lock orders them. Were it bypassed, the check `sequence` is `mail.last + 1` at append would refuse the second event, and its file would stay as an orphan. |
| `lane send` during a turn | The message is stored and waits. The turn's text was rendered when it started and does not change; the next turn carries the message. | Nothing needs to block it: the running turn's `mail` list does not name it, so that turn cannot deliver it. |
| `lane send` to a lane that is not turn-based, whose runner can no longer take turns, or that is abandoned or cleaned | Refused with exit 2 and the reason. No file and no event. | The checks of `lane send`, and the rules for `lane.mailed` at append. |
| A bad message: not UTF-8, empty, over 262,144 bytes, a launcher block, a credential shape | Refused when it is sent, with exit 2. A credential shape is reported by its line and never repeated. | The checks of `lane send`: the renderer's refusals and the limits. |
| The machine restarts in the middle of a turn, or the tmux server is killed | The run's processes are gone and the projection still says running. `lane check`, or the loop for its own lanes, records `lane.lost` and then `lane.returned` with reason `lost`. The messages go first in the next turn, marked `(again)`. The agent may have acted on them already: delivery is at least once. | `lane check`, which records a run lost only after a complete observation that its supervising process is gone. The derivation settles at `lane.lost`. |
| A sender that saw no result sends the same message again | Both copies are stored and wait as two messages. Both are delivered, neither carries ` (again)`, and the agent may do the work twice. | Nothing blocks it: the launcher cannot tell a resend from a second message ("Known limits", "Open points"). |
| The supervising process is killed | As above; processes of the run may survive it. `lane.lost` says how many of the recorded processes survive, and `lane turn` is refused while a recorded process survives. `lane stop` removes them. | The conditions on which `lane resume` is refused today, which `lane turn` shares; `lane check`; `lane stop`. A process that no sample saw is not recorded and not counted: the known limits "Processes the run record does not have" and "Processes that leave the tree between two samples". |
| The store is busy | `lane send` waits up to 10 seconds for the store and is then refused; its file stays, and the same bytes sent again reuse it. `lane turn` is refused in the same way and appends no lane event. The loop skips the pass and looks again at the next. A supervising process keeps its end and delivery events in the lane's pending file, appended in order. | The 10-second append wait, the pending file, `loop.log` and `last_error` in `lane loop --status`. |
| Two loops | The second `lane loop` is refused after about half a second (`--detach` at once) and names the first loop's process id. | `loop.lock`. Were two to run, they could not start two turns of one lane: `lane turn` is refused while a run is live, under the lanes lock. |
| The loop is killed | The kernel frees the lock. No `loop.stopped` is written. Turns that run go on and end as turns do, mail waits, and the next loop records `unrecorded_end`. | The kernel's lock, and `unrecorded_end` in `loop.started`. |
| A mail file is removed or changed by hand | `state verify` reports it with the lane, the sequence and the `seq` of the event. `lane turn` exits 3 and starts nothing, so the messages stay as they are, and the loop records a skip with reason `refused`. Putting the same bytes back under the same name repairs it. | The check of the file's name, size and hash, in `lane turn` and in `state verify`. |
| The runner exits 0 with a limit message | The end is classified by `limit_patterns` as reason `limit` and not `exit`: the messages return and the loop waits the limit back-off. | The runner's `limit_patterns`, which exist already. A runner without one ends with reason `exit` and code 0, and its messages count as delivered when the prompt was written whole, because the launcher has no other way to tell; `laneboss doctor` warns about such a runner. |
| The runner never reads its input | The supervising process writes the prompt from a thread of its own and never waits for a read, so the control loop is not held up. A prompt that fits what the pipe holds is written whole whether or not the runner reads it, and a larger one is cut when the runner ends. The turn ends when the runner ends, or at the time budget with reason `timeout`, and the messages return unless the run ended with reason `exit`, exit code 0 and a prompt written whole. | The budget and the quiet-time check, which exist already, and `prompt` in `lane.ended`. A runner that exits 0 without having read a prompt that fitted the pipe counts as having taken the turn ("Known limits"). |
| The runner closes its input early and exits 0, or cannot be created | `lane.ended` has `prompt` `cut`. The run ends with reason `exit`. With exit code 0 its messages return with reason `cut`, as they do when `lane.ended` has no `prompt` at all (a hand-written event): a missing `prompt` counts as `cut`. When the runner could not be created there is no exit code, and they return with reason `exit`. The loop waits the back-off in every case. | `prompt` in `lane.ended`, which `main` records, and the derivation. |
| The runner fails on every turn (the session never existed, or a message makes the agent fail) | Each turn ends badly and its messages return. The loop waits the back-off between turns, and `bad_ends` in `lane loop --status` grows. Nothing is dropped, and nothing spins. | The back-off. A person decides: stop the loop, or abandon the lane and start another. |
| The configuration changes under a lane: the runner loses `{session}` from both templates, or `prompt = "stdin"`, or `resume` | `lane send` and `lane turn` are refused with the reason, and the loop records `refused`. An edit that leaves `{session}` in only one of the two templates, or that removes `prompt = "stdin"` from a runner whose `command` has no `{brief}`, makes the configuration invalid instead: every command is refused at load, and `config validate` names the key. | The turn-based checks, made against the configuration as it is now, and the checks of a runner that `main` makes when the configuration loads (`config.py`, `runner_entry`: `{session}` in both templates or in neither, `{brief}` unless `prompt = "stdin"`). |
| The key `[turns] idle_message` is removed from the configuration | Only `lane turn --idle` with no mail waiting is refused. `lane send` and a mail turn go on, and the loop records `refused` for an idle turn and goes on with the mail turns. A file that the key names and that is missing makes the configuration invalid, as for a standing-rules file, and every command is refused. | The check of the idle message at `lane turn --idle`, and the load of the configuration. |
| A supervisor abandons a lane while a turn is starting (after the command released the lanes lock and before the supervising process appends `lane.started`) | The abandonment is recorded and stands. The starting turn is refused at append: the launch ends, nothing runs, and the messages stay waiting. | The rule at append that refuses `lane.resumed` and `lane.started` with `how` `resume` on an abandoned turn-based row. |
| An announcement is refused or cannot be appended (the store is busy, or the next run started between the command's look at the row and its append) | Harmless: the derivation settled at the closing event. `lane check` and `lane mark --gone` print `returned` null and `returned_error` and exit 0, and the supervising process keeps the event in `refused.jsonl`. While the lane has not run again, the announcement stays due, and `lane mark --gone` appends it with the values of `settled`, so after an unannounced `lane.lost` with reason `lost`, not `gone`. | The rule that an announcement needs the row's `settled` to name the lane's latest run and to have `announced` false, and to carry its values. Only a race between two appends reaches this row, and no end-to-end test can place it; the rule and the late announcement are tested ("The test plan for T2 to T5"). |
| `lane turn` by a person and by the loop at the same moment | One starts the turn, and the other is refused because a run is live. | The lanes lock and the live-run conditions. |
| `lane resume` on a turn-based lane | Refused, with the instruction to use `lane send` and `lane turn`. | `lane resume`'s own check; otherwise the rules at append refuse a `lane.started` without `mail`. |
| A terminal is closed, SIGTERM arrives, or Ctrl-C is pressed, in attach | A closed terminal and SIGTERM leave attach (exit 129 and 143), and a turn goes on. Ctrl-C stops only a turn that this attach started, and only that run; for a turn that it did not start, Ctrl-C leaves attach (exit 130) and stops nothing. | Attach keeps no child process and signals nothing. `lane stop --run N` acts only on the lane's latest run. |
| No account has room (T5, built) | No turn starts and the mail stays waiting. The loop records `loop.skipped` with reason `no-room` and holds the lane for `backoff_seconds`, and a person's `lane turn` is refused with the command's reason, which no event records. | The room command's answer, which counts as no room whenever it is not in the documented form. |
| A room command hangs (T5, built) | At the timeout the command's process and every process of its tree, group and session are stopped by identity (except the descendant that "The room command" names: one outside the command's group and session whose parent has ended, and outside Linux one that only left the group) and the account counts as having no room. The rule that no pass starts another room command for that account while one still runs is not built. | `[lanes] room_timeout_seconds` and the identity-checked stop. |

### Rolling back to 0.5.0 across the changes of this design

The triggers of what T2, T3 and T4 built (the table `[turns]` with its keys, the kinds `lane.mailed`, `lane.delivered`
and `lane.returned`, the keys `mail` and `idle_seconds` of `lane.started`, the row field `mail` and the state `waiting`,
the mail files, the protocol version 1.2.0, of the loop its kinds, its files and its session, and of attach the runner
key `stream`) are in the paragraph "Rolling back to 0.5.0 across the changes of this version" under "Install", as built
facts. This subsection adds the triggers of T5, which are built, each by the step named beside it, and
then the written procedure that runs 0.5.0 against all of them. Every lane that takes turns has `session_id` in
its `lane.started` events and `prompt` in its `lane.ended` events (a runner needs `{session}` and `prompt = "stdin"` to
take turns), so what that paragraph says of those two keys holds for it as well. Every statement was read from the code of
0.5.0 (commit 919af68), in the files and lines named, which are all in `src/laneboss/` and are those of that commit, and
none was run. As for the triggers of that paragraph, a version that writes any of the first three triggers below makes a
rollback to 0.5.0 impossible on a configuration or a store that has them. A relink back needs the configuration edited as
soon as it has one of the new keys, and a store that has one of the new lane events or one of the new values of
`lane.started` fails `state verify`, `state rebuild`, `doctor` and the briefing of 0.5.0, and the commands named in that
paragraph. A configuration can be edited back; a store cannot, because no command edits or removes an event ("Event and
state store").

- **The new configuration keys (T5):** the runner key `room` (T5, which joins the runner key `stream` of T4); and the
  key `room_timeout_seconds` of `[lanes]` (T5). The keys of the loop, `poll_seconds`, `backoff_seconds` and
  `limit_backoff_seconds` of `[turns]` (T3, which join the keys `idle_message` and `idle_seconds` of the table that T2
  built), and the runner key `stream` (T4) are in the paragraph under "Install". 0.5.0's tables list their keys, and
  `table()` refuses any other with "unknown key" when the configuration loads (`config.py:125-137`, the tables at 400-416
  and 441-462, `load` at 686-698), as an invalid configuration (exit 2, `errors.py:13-21`) that names the file and the
  key path, for example `runners.NAME.room`. So every 0.5.0 command bound to the configuration fails at load, even
  before any turn has used the keys (`cli.py:177-184` and `193-207`), and `doctor` reports its `config` check failed
  (`doctor.py:168-177`). A relink back needs the configuration edited: remove these keys, and the table `[turns]`,
  `prompt` and `{session}` as "Install" says. Two launchers of different versions must not share a configuration from
  the moment it has one of them.
- **The kind `lane.adopted` (T5).** 0.5.0's `lanes.check` refuses a `lane.` kind that is not in its list (`lanes.py:26`
  and `337-338`), and `validate_envelope` calls it for every such kind (`events.py:148-149`), exactly as it does for the
  kinds of mail that T2 built. So `event append` of one is refused (exit 2), and `state verify` and `state rebuild`
  replay every stored event through the same check and fail with exit 3 for the whole store (`events.py:544-546` and
  `601-605`); `doctor` (its `store.recorded` check calls `verify`, `doctor.py:65`) and the session briefing
  (`startcmd.py:333-336`) refuse with them. The events are still read: `event tail` and `state events` hash-check and
  print them (`events.py:390-405` and `488-490`). No 0.5.0 lane command reads a lane event of a kind that it does not
  list, because they read a lane's events by kind (`events.py:492-524`), so by themselves these kinds refuse nothing
  more; the row that holds an adopted lane does: an adopted lane has a row with `mail`, which "Install" says of the row
  field `mail`.
- **`room` as the account in the `chosen_by` of `lane.started` (T5).** `lanes.check` accepts exactly the values it lists
  for `chosen_by.account` (`lanes.py:220-223`; the keys of `lane.started` at 247-256 and `obj` at 131-137), so a
  `lane.started` whose account was chosen by `room` is refused at append, and `state verify` and `state rebuild` fail on
  it as above. A lane command that reads that lane's `lane.started` through `last_event` or `lane_events`
  (`events.py:492-524`) fails with exit 3, in words that blame an earlier version (`events.py:503-505` and `521-523`):
  the commands that "Install" names for a `lane.started` with `session_id` refuse here too, for the same reason.
The triggers of T3 (the keys of the loop, its `loop.*` kinds, `loop.lock`, `loop.json` and `loop.log`, and the session
`laneboss+loop`) are built and are in the paragraph under "Install", where the lines of 0.5.0 that each statement was read
from are named.

Nothing else that T5 writes is refused by 0.5.0. The events of a turn that are not named above or in "Install" have
the payloads that 0.5.0 lists, and a lane started without `--turns` writes what `main` writes.

**Confirming the statements by running 0.5.0.** The statements of "Install" about the triggers of T2, T3 and T4, and
those above about T5, were read, not run. The procedure below runs them. It is written here so that the
supervisor, or the lane of the step, can run it on a test machine, beside the real trial of the step ("The test plan for
T2 to T5"); a statement that the run shows wrong is corrected in the text, in the commit that finds it. It is not part of
`tests/`, and it needs no agent program and no account.

1. On a disposable test machine that the configuration names for tests, make two empty directories for the run, one for
   `LANEBOSS_HOME` (the configurations) and one for `LANEBOSS_STATE_HOME` (the states), so that nothing of a person's own
   is touched. Unpack the source of the two versions into two empty directories: commit 919af68 (0.5.0) and the commit
   under test, each from `git archive`. Run each version's own `scripts/install.sh --prefix PREFIX` with a prefix of its
   own, so that both stay runnable (`PREFIX_OLD/bin/laneboss` and `PREFIX_NEW/bin/laneboss`).
2. Write, with the file tool, one configuration `trial` for the new version: a runner that can take turns (the stand-in
   runner of `tests/e2e/standin.py` through a command that uses `{session}` in `command` and in `resume`, with `prompt =
   "stdin"`), a second runner that uses neither `{session}` nor `prompt`, a project or `--worktree` directories made for
   the run, and a `[turns]` table with `idle_message`. Keep a copy of this configuration.
3. With the new version, make two stores, each copied when it is made: first one ordinary lane on the second runner, run
   to its end, which has none of the triggers (the copy B, "before the first trigger"); then one lane with `lane start
   --turns` on the first runner, two `lane send` (the messages as files or on standard input) and one `lane turn`, run
   to the end of the turn, so that the store has `lane.mailed`, `lane.delivered`, a `lane.started` with `mail` and
   `idle_seconds`, a row with `mail`, the state `waiting` and the files `mail/` and `mail.lock` (the copy C). With the
   file tool, add to a second copy of B a directory `lanes/LANE/mail/` with one file named as `lane send` names one and
   a file `lanes/LANE/mail.lock`, for the ordinary lane (the copy D). For the loop (T3), on a third store made with the
   new version, run `lane loop` in the foreground against a lane that takes turns and has one message waiting, until the
   turn has ended, and end it with `lane loop --stop`, so that the store has `loop.started`, `loop.turn` and
   `loop.stopped`, and the state directory has `loop.lock`, `loop.json` and `loop.log` (the copy E, its configuration kept
   as it is). The commands below run on copies, never on the originals.
4. With the old version, run each command below, as a file, on the copy named, and record, for each, its exit code and
   the first two lines of what it prints on standard output and on standard error. The statements of "Install" say what
   is expected; this table is their short form. The rows after the first three run with the copy of the configuration
   from which `[turns]`, `prompt` and `{session}` were removed, because the old version refuses the other at load.

   | What is run (old version) | Expected |
   |---|---|
   | `config validate trial` on the configuration with `[turns]`, with a runner that has `prompt`, with a runner that uses `{session}` | exit 2, `invalid configuration:`, naming the key path (`turns`, `runners.NAME.prompt`, ...) |
   | the same after removing `[turns]`, `prompt` and `{session}` from the configuration | exit 0 |
   | the same on a copy of that edited configuration in which one runner has `stream = "text"` (the key of T4) | exit 2, `invalid configuration:`, naming `runners.NAME.stream` and the words `unknown key` |
   | `event tail` and `state events` on C | exit 0, every event printed, the new kinds among them |
   | `state verify` and `state rebuild` on C | exit 3, `integrity problem: event seq N:` and the form that 0.5.0 lists |
   | `doctor` and `start` on C | `doctor`: exit 1 with its `store.recorded` check failed; `start`: exit 3, `the store.recorded check failed` |
   | `state lanes`, `lane status` (with and without `--lane`), `lane check` and `lane start` of a new lane, on C | exit 3, `the lane projection is not in this version's form` |
   | `lane resume`, `stop`, `mark --state abandoned`, `clean`, `scan`, `review` and `refusals --lane`, for the turn-based lane, on C | exit 3 |
   | `lane mark --state abandoned` or `--landing merged` for the ordinary lane, on B | exit 0 |
   | `event append` of a file holding a `lane.mailed` event, on B | exit 2, `kind: lane events are` and the list of kinds |
   | `event append` of an event of another kind whose `protocol_version` is `1.2.0`, and `brief render`, on B | exit 0 |
   | `state verify`, `doctor`, `start` and `lane status` on D | exit 0, and the files of `mail/` and `mail.lock` are the same afterwards (compare their hashes) |
   | `event append` of a file holding a `loop.started` event (in any form), on B | exit 0: 0.5.0 checks no `loop.*` event |
   | `event tail` and `state events` on E | exit 0, every event printed, the `loop.*` events among them (the rest of E fails the commands of the rows for C: the lane that took turns has the triggers of T2) |
   | `state verify` and `state rebuild` on a copy of B to which a `loop.started`, a `loop.turn`, a `loop.skipped` and a `loop.stopped` were added with `event append` of 0.5.0, and the files `loop.lock`, `loop.json` and `loop.log` were added to its state directory with the file tool | exit 0, and the three files are the same afterwards (compare their hashes) |

5. Keep, in the lane's evidence directory outside the repository, the command files, the outputs and exit codes with a
   manifest of their hashes, the two archives' hashes and the table with what was seen against what was expected. A
   difference is corrected in the statement, never in the run, and is reported with the command and its output.

### The test plan for T2 to T5

Each step is built test first, as `CONTRIBUTING.md` asks: its tests are written from the text of its part, run, and seen
to fail because the feature is missing, and only then does the code change. The end-to-end tests drive the installed
`laneboss` command, as the tests in `tests/e2e/` do. They use the stand-in runner `tests/e2e/standin.py`, which each step
extends with the behaviours it needs (on `main` it has `deaf`, a runner that never reads its input, `shut`, a runner
that closes its input without reading it and exits 0, and a record of what it read on standard input), and they mock
nothing of the launcher. They run on a disposable machine. Each step also has one real trial against the real program:
a real headless Claude Code session on a small model, named in full as the configuration routes it, a handful of
requests, and after them a count of the processes of the run. One of the requests makes the agent run a shell command, so that a tool's processes are among those that the run must stop and count; the answer shows that the command ran, because the number of process groups does not: a real agent runs helper processes in groups of their own even when it uses no tool. The run record names the processes by identity, none may be alive after the end, and the record must show more than one process group, because a real agent runs its helpers and tools in groups of its own where the stand-in has one. The real trial is a
written procedure that the step's lane runs on the test machine and reports; it is not part of `tests/`, and the suite
needs no agent program, account or environment variable. Where a real trial may run, and with which account, is the
configuration's rule (rule 1 of the shared protocol), not this document's.

**T2, mail and turns (built).** The end-to-end tests are `tests/e2e/test_mail_model.py` (the data model, through
`event append` and `state verify`), `test_mail.py` (`lane send`, the lock, orphans and the limits), `test_turn.py`
(`lane start --turns`, `lane turn`, delivery, refusals, bounds and `[turns]`) and `test_turn_ends.py` (a lost, gone or
stopped turn, the idle group and the doctor warning), written from this list and run on a disposable machine. The list:

- `lane start --turns` records `mail` `[]`, `idle_seconds` and `session_id` in run 1; when the run ends the state is
  `waiting`, `lane status` says `idle`, and `laneboss start` lists the lane. Without `--turns` the run ends in
  `verifying`. A runner that lacks `{session}`, `prompt = "stdin"` or `resume` refuses `--turns`.
- `lane send` with a file and with standard input: sequences 1, 2 and 3 without a gap, the files named by the grammar, no
  event with text, and `state verify` passing with `mail_files` 3 and `mail_orphans` 0.
- Refusals of `lane send`: not UTF-8, empty, over the limit, a launcher block, an invented credential shape (the line is
  named, the value never printed), a bad `--from`, a lane that is not turn-based, abandoned or cleaned, 1,000 messages
  waiting; each leaves no file and no event.
- The mail lock: the test holds `lanes/L/mail.lock` itself and starts a send. The send waits, and finishes after the
  lock is released, with the next sequence. With the lock held past a small `[lanes] lock_wait_seconds` the send is
  refused (exit 2) and leaves no file and no event. Two `lane send` processes started together give two sequences
  without a gap, which alone proves nothing about the lock, because sends that do not overlap succeed without it.
- An orphan made by hand (a complete file by the grammar, no event): `state verify` counts it and does not fail; a send
  of the same bytes takes its name and appends one event. Two sends of the same bytes make two messages with two
  sequences, which pins the resend case of "Known limits" so that a change of it is deliberate.
- The rules at append, in one table test through `event append`, the launcher's own interface for hand-written events,
  each event refused with nothing stored: `lane.mailed` with a gap, on a lane that is not turn-based, and on an
  abandoned lane; `lane.delivered` while the lane is running, twice, and with other sequences; `lane.returned` with
  another reason than that of `settled`, and one for a run that is no longer the lane's latest (the next run was
  started by hand after the loss); `lane.started` with a `mail` list that is not the head of the queue; `lane.started`
  without `mail`, `how` `resume`, on a turn-based row; `lane.state` `waiting`, `verifying` and `accepted` on a
  turn-based row; `lane.resumed` and `lane.started` with `how` `resume` on an abandoned turn-based row (an abandonment
  is never undone by a turn that is starting); `lane.started` with `how` `reuse` on a row with a message waiting, with
  `mail` and without it.
- A missing `prompt` counts as `cut`: after the supervising process of a run that carried mail was killed, a
  `lane.ended` with reason `exit`, exit code 0 and no `prompt` is appended by hand; the messages return, a
  `lane.returned` with reason `exit` is refused for it, and one with reason `cut` is accepted.
- `lane turn` with three messages: the stand-in's record of standard input holds the three headers in order and the
  launcher block once; `lane.started` has `mail` `[1, 2, 3]`; on exit 0 with a prompt written whole `lane.delivered`
  follows `lane.ended` and the row's `mail` shows three delivered.
- A turn with the stand-in `shut` and a join larger than the pipe holds (more than 64 KiB, the default on Linux that
  `main` documents): `lane.ended` has reason `exit`, exit code 0 and `prompt` `cut`, and the messages return with
  `lane.returned` reason `cut` and are not delivered. The other half, that written is not read, uses a behaviour that T2
  added to the stand-in, `idle-open`: it holds its standard input open without reading it for one second, and then exits
  0. With a small join the prompt is written whole while the input is open, so the turn ends with `prompt` `written`
  and its messages are delivered. `shut` cannot show that half, because it closes its input as it starts, and whether a
  small write comes before or after that is a matter of timing; it serves the large join only, where the write cannot
  finish without a reader.
- A failing turn (exit 3), a turn at reason `limit` (a stand-in that prints the limit line and exits 0), a stopped turn
  and a turn that passes its budget: each ends with `lane.returned` and the right reason; the next turn carries the same
  messages first, with ` (again)`, before newer mail. The stopped turn uses a stand-in behaviour whose child runs in a
  session of its own (`setsider` or `stubborn` of `tests/e2e/standin.py`) and asserts that the child is gone after the
  stop.
- A killed supervising process: `lane check` records `lane.lost` and then `lane.returned` with reason `lost`; `lane mark
  --gone`, for another killed one, records `lane.gone` and then `lane.returned` with reason `gone`.
- An announcement that is not due, and one that is late. `lane mark --gone` after a lost run whose loss `lane check`
  announced, with the run record made unreadable, stores `lane.gone`, appends no `lane.returned`, prints `returned` null
  and exits 0. The late one is the corner of an unannounced loss: a `lane.lost` for a run that carried mail, appended
  through `event append` so that no announcement follows it, the run record removed, then `lane mark --gone`. It stores
  `lane.gone` and appends `lane.returned` with reason `lost`, the reason of `settled` and not `gone`; it prints that
  event as `returned` and exits 0; the derivation is as the loss left it, with the messages returned once. A
  `lane.gone` after `lane mark --state abandoned` keeps the state `abandoned`, for a row whose `turn_based` is true and
  for one that has `mail` and was started again with `--reuse` and without `--turns`.
- The refused announcement of `lane check` and of `lane mark --gone` (`returned` null with `returned_error`) is reached
  only by a race between the two appends of one command, which no end-to-end test can place: nothing a test does can
  fall between them. Its rule is covered by the table test through `event append` above and by the late announcement.
- `lane turn` refusals: never ran, running, cleaned, abandoned, merged, not declared, runner not turn-based, nothing
  waiting (exit 0, `started` false), a removed mail file (exit 3). `lane turn --idle`: the idle message goes without a
  header line; with the key removed it is refused; with mail waiting the mail is sent instead. The bounds of a turn: 65
  messages give a turn of 64, and a joined text over 1,048,576 bytes gives fewer messages, at least one.
- `lane start --reuse` with a message waiting is refused, with `--turns` and without it. `lane resume` on a turn-based
  lane is refused. `laneboss doctor` warns, and still exits 0, for a turn-based runner without `limit_patterns`.
- A store written before this design, with events appended by hand in the 1.1.0 forms of 0.5.0 and of `main` (the latter
  with `session_id` in `lane.started` and `prompt` in `lane.ended`) and with a hand-appended `loop.started` in another
  form: `state verify` passes and `state rebuild` changes nothing. The rows that `main` computes for those events (the
  rows of 0.5.0 for the events it can read are the same) are pinned in the test as literal JSON, so that the suite needs
  no second source tree, and the rows of 1.2.0 equal them byte for byte. `laneboss --version` says protocol 1.2.0.

The real trial of T2 is a written procedure, run by the supervisor after the head is reviewed, on the machine and with an
account that the configuration names for it (rule 1 of the shared protocol); it is not part of `tests/`. It covers
`lane start --turns` with a brief that gives the agent a word to remember, two `lane send` and one `lane turn`; the
agent's answer to the turn must show the word and both messages, so that the resume reached the session and the messages
reached the agent; and the processes of the run are counted afterwards. The procedure:

1. The runner, `RUNNER`, is a runner of the configuration `CONFIG`, both named by the supervisor for the trial, and it has: `{session}` in `command` and in `resume`,
   `prompt = "stdin"`, `limit_patterns`, a `records` entry that finds the agent program's record of the session by
   `{session}`, and a small model named in full. The account is one that the configuration lists for that runner. The
   lane belongs to a project whose repository is local, and its working directory is the one `lane start` makes by
   default (a sibling of the repository named after the lane), because the runner's `records` path names the agent
   program's project directory for that working directory, and a lane started with `--worktree` elsewhere would not
   match it. The lane name is one that the project's `lane_prefix` allows and that carries the step (T2) and the date.
2. With the file tool, write three files in a directory made for the trial: `brief.md`, which gives the agent a made-up
   word (with the time in it, so that nothing can guess it) and asks it to answer `ready`; `message-1.md`, a sentence
   made up for the trial; and `message-2.md`, another sentence that also asks the agent to run one shell command that
   prints a number, and to answer with the word from the brief, the text of the two messages and the number. No command
   of the trial takes a message as an argument: each is a file, or standard input from one.
3. Start the lane: `laneboss lane start --config CONFIG --lane LANE --project P --brief brief.md --runner
   RUNNER --model MODEL --account ACCOUNT --budget 10 --turns`. Follow `laneboss event tail --config CONFIG
   --lane LANE --follow --until lane.ended` in the background mode of the shell tool, without polling. When it ends,
   `lane status` shows state `waiting`, `idle` true and a `session_id`, and `lane.started` has `mail` `[]` and
   `idle_seconds`.
4. Send the two messages: `laneboss lane send --config CONFIG --lane LANE --file message-1.md`, then the same with
   `message-2.md`. The two answers have `sequence` 1 and 2, and the second has `waiting` 2.
5. Start the turn: `laneboss lane turn --config CONFIG --lane LANE`. It prints `started` true, `turn` with `kind`
   `mail` and `mail` `[1, 2]`. Follow `laneboss event tail --config CONFIG --lane LANE --since SEQ --follow --until lane.ended` in the background mode again, where SEQ is the `event.seq` that `lane turn` printed. When it ends, `lane status` shows `live.supervisor.alive` false once the supervising process has appended its announcement and exited (normally already true when the follower has ended; when it is not, look again once, later); read the announcement once with `laneboss event tail --config CONFIG --lane LANE --since SEQ` without `--follow`: `lane.delivered` continues with step 6; `lane.returned` with reason `limit` is the result of step 9; `lane.returned` with any other reason is a failure of T2, reported with the event and the lane's log as step 6 reports one.
6. Read the agent's answer from the lane's log, in the byte range that the run record of the turn gives (`lanes/LANE/
   runs/LAUNCH.json`, key `log`), and keep it in a file. It must contain the word, the text of both messages and the
   number that the command printed. An answer without the word means that the resume did not reach the session; one
   without a message means that the join did not reach the agent. Either is a failure of T2, reported with the file.
7. Count the processes of the turn from its run record: the identities (process id, process group, session and start
   time) of every process that was sampled. None of them may be alive after the end (`ps` by process id, and the start
   time compared with the recorded one, because a process id can be reused), and the record must show more than one process group: the agent program runs helper processes in groups of their own, with or without a tool, so the count reaches beyond the runner's group. The number of groups does not show that the shell command ran; the number in the answer (step 6) does. The `lane.ended` of the turn has `survivors` 0. The first turn is counted the same way; it too may show several process groups although the agent uses no tool.
8. Check the store with the same interface: `event tail --lane LANE` lists, in this order (a `lane.stuck` may come in
   between), `brief.rendered` (the brief),
   `lane.started` (run 1), `lane.ended`, two `lane.mailed`, `brief.rendered` (the turn's message), `lane.resumed`, `lane.started` (run 2, `mail` `[1, 2]`), `lane.ended` (reason
   `exit`, exit code 0, `prompt` `written`) and `lane.delivered` (`sequences` `[1, 2]`); `state verify` passes with
   `mail_files` 2 and `mail_orphans` 0; `lane status` shows the row's `mail` with `delivered` 2, and `idle` true.
9. A turn that ends at a usage limit is a result of its own (`lane.returned` with reason `limit`, the messages waiting
   again): it is reported as that, and the trial is repeated with another account that the configuration lists. When the
   trial is over the lane is marked `abandoned` (the only state a turn-based lane can be marked with) and cleaned, and
   what the trial made is collected.
10. The evidence is the command files with their outputs and exit codes, the events printed, the agent's answer, the run
    records and the process counts with the way they were counted, and the output of `state verify`. It is kept in the
    lane's evidence directory, outside the repository, with a manifest of the hashes, and the report names the path and
    the scope of every number it states. Nothing in the repository names the account, the machine or the session.
11. Beside this trial the supervisor runs "Confirming the statements by running 0.5.0" ("Rolling back to 0.5.0 across the
    changes of this design"), on a store that this trial or the test lane's stand-in made, and keeps its evidence the same
    way.

**T3, the loop (built).** The end-to-end tests are `tests/e2e/test_loop.py` (a class for each group of the list below:
`StartTest`, `LockTest`, `BackOffTest`, `RefusedTest`, `BusyTest`, `RestartTest`, `DetachTest`, `EnvironmentTest`,
`FormTest`, `PlantedTest`, `CheckLaneTest`, `TurnsKeysTest`, `LastErrorTest` and `NextTest`), written from this list and
run on a disposable machine.
The loop runs in the foreground as a child of the test, or detached, with `poll_seconds` 1 and waits of 3 and 6 seconds,
and every turn it starts is a run of the stand-in. The list:

- A mail turn is started within `poll_seconds` of a message, and an idle turn after `idle_seconds`; each is a
  `loop.turn`, and a lane that was not declared with `--turns` is never touched, even when its supervising process has
  been killed.
- A second `lane loop` is refused and names the first; `--status` reports the loop and its lanes; `--stop` ends it with
  `loop.stopped`, and a turn that was running is still running afterwards.
- Back-off: a failing turn gives one `loop.skipped` with reason `backoff`, `until` and `after`, and no second one on the
  passes that follow, and the turn starts when the wait is over; after reason `limit` the wait is the limit back-off.
  Both numbers come from the configuration.
- A loop killed with SIGKILL: the lock is free, a new loop starts, and its `loop.started` names `unrecorded_end`.
- A turn that is refused is a `loop.skipped` with reason `refused`, a refusal for a lanes lock that stays held past
  `[lanes] lock_wait_seconds` included; a busy store gives a line in `loop.log` and no crash; `--detach` starts the
  session named `laneboss+loop`, which no lane's session can have, and the loop can be stopped with `--stop` without
  killing any session.
- `lane check --lane L` records the loss of that lane only.
- A turn that ends with reason `exit`, exit code 0 and `prompt` `cut` gives a back-off whose `after` reason is `cut`;
  `bad_ends` counts a turn that a person started; a person's `lane turn` during the back-off is not refused for it.
- `loop.*` events that were appended by hand in another form, with another actor and `protocol_version`, change neither
  the loop's decisions nor its `unrecorded_end`.
- The environment of the loop's turns: the test sets a distinctive harmless variable in the loop's own environment (a
  name and a value made for the test, with a timestamp in the value), starts the loop, and lets it start a turn. The
  stand-in reports only whether it saw the variable with that value, by printing a fixed word and never the value, so
  the turn is shown to have the environment that the loop captured when it started. Afterwards the test searches every
  file of the state directory (the store file, `loop.log`, the lane's logs, the run records, the pending files,
  `loop.json` and the mail) and every event that `event tail` prints, and finds the value nowhere. The same test runs
  with a detached loop. A second lane of the configuration is started with the plain environment and given a turn that
  goes on, so that the configuration's tmux server runs when `--detach` creates the loop's session, and was started
  without the variable: the test reads the server's global environment (`show-environment -g`) before and after
  `--detach` and finds no such variable in it, so only the FIFO can have given the variable to the loop, and the
  loop's turn sees it. A second test of the same kind lets `--detach` start the server itself: the lane's first run has
  ended and no session of the configuration is alive (the test waits until the server is gone), so the first command that
  reaches the socket is `--detach`, whose environment holds the variable. The test finds that the loop's session is the
  only one, finds no such variable in the server's global environment, and sees the loop's turn have it all the same,
  since every tmux command of the launcher runs with a fixed environment of five names (`PATH`, `HOME`, `LANG`, `TMPDIR`
  and `USER`) and a run receives the rest of its environment only through the FIFO. A turn that a person starts, in each
  of the two tests, does not see the variable.
- The forms of the `loop.*` events: `event append` refuses each event of a table of cases in another form (a missing or
  an extra key, a wrong type or grammar, a lane where there must be none and none where there must be one, an idle turn
  with sequences, a `backoff` without `after`, a kind that is not one of the four, a `no-room` skip that has an `after`)
  and accepts the forms of the design (a `no-room` skip without `after` among them, from T5), whatever the actor and the
  protocol version say; `state verify` and `state rebuild` pass on a store
  that holds such events written into the store file (as 1.1.0 could have kept them), and `event append` refuses the same
  events.
- The lock and the record: the forms `--detach`, `--status` and `--stop` exclude each other; `--stop` of a loop that
  cannot end (it is stopped by a signal) is refused after 30 seconds and kills nothing, and the loop ends when it can run;
  `--stop` with no loop is refused; a record that a kill left, and a record that names another live process, are believed
  by nothing and nothing is signalled; `--status` appends nothing and lists only the declared lanes. A loop that starts
  while a probe holds the shared lock on `loop.lock`, as `--status` takes it, is not refused: the test holds that lock,
  starts the loop, waits until `loop.log` exists (the loop creates it just before it asks for its lock) and lets go 0.2
  seconds later, and the loop must start (its ten tries, 50 ms apart, outlast the probe).
- A detached loop that meets an error nobody expected (the test makes the directory of a running lane's run records
  unreadable) appends `loop.stopped` with reason `error`, writes `internal error` and the traceback, with the name of
  the error, to `loop.log`, and ends with exit status 70; the status then says that no loop runs. The exit status is
  read from the loop's own process: the test runs the command that `--detach` starts in the pane (the installed package
  gives it, `loopcmd.loop_argv`) as a child of its own, hands it the same input through a FIFO of the state directory,
  and takes the status of the child from the operating system, because tmux does not always record the exit status of
  a pane whose process ended (`#{pane_dead_status}` can stay empty for good). A second test runs the real `--detach`
  and looks only at what does not need that status: the session of the loop ends, `loop.stopped` says `error` and
  `loop.log` has the error.
- A `loop.skipped` event in the documented form, with reason `refused` and an `until` in the year 2999, appended by
  `event append`, does not hold the lane: the loop starts the turn that is due. An event in another form that would hold
  the lane for 50 seconds, with `backoff_seconds` 60, does not hold it either, and the turn starts before the hold would
  have ended: the form is what the loop looks at, and the length of the hold is what it checks.
- A turn that outlives a killed loop goes on, mail that arrives meanwhile waits, and the next loop starts the next turn
  after the wait; a lost turn (its supervising process gone) is recorded by the loop's own check of that lane, and the
  next turn follows the schedule; a runner edited since refuses the turn at the next pass, because the loop loads the
  configuration again; a restarted loop repeats no skip.
- Without a `[turns]` table the loop looks every 10 seconds and the waits are 300 and 1800 seconds (the `until` of the
  skips), and the three keys of `[turns]` are accepted at both ends of their ranges and refused outside them, as a
  string, as a fraction and as a boolean.
- `last_error`: the status says `null` before any failure. A busy store (the test holds the store's write lock) makes a
  pass fail, and afterwards the status and `loop.json` hold `{"at", "message"}` equal to the last line of `loop.log` (its
  time and its text), which has SQLite's own words in it, also after the store is free again and the loop has started its
  turn; when the loop is stopped the status says `null` and `loop.json` keeps the failure. A configuration that cannot be
  loaded (a key that `[turns]` does not have, put in place whole while the loop runs, and mended again) makes every pass
  fail until it is mended; the status shows the latest line, a good pass does not clear it, and a later failure with
  another key replaces it. A `loop.json` that someone edited so that the message looks like a credential is printed as
  `(withheld)` with its time. The text of a failure is made of messages of the launcher, whose values were screened
  already, so no failure of a pass can be made to look like a credential: that part has no other test.
- `next`: one status call over five lanes (a lane with mail waiting, a lane idle for its interval, a lane with nothing to
  start, a lane whose turn failed and whose wait is long, and a lane whose turn runs) says `mail`, `idle`, `null`,
  `backoff` and `null`, with the rest of each entry (`waiting`, `backoff_until`, `bad_ends`) in agreement and no event
  appended; a loop started on the same store then starts the mail turn and the idle turn, records the wait of the fourth
  lane, and touches nothing of the other two.

The real trial of T3 is a written procedure, run by the supervisor after the head is reviewed, on the machine and with
an account that the configuration names for it (rule 1 of the shared protocol); it is not part of `tests/`. It covers a
real turn-based lane with a detached loop: a message starts a real turn, the idle interval starts another, one request
makes the agent run a shell command, a turn is still running when the loop is stopped and goes on, and the processes of
each run are counted afterwards. The procedure:

1. Install the commit under test with its own `scripts/install.sh --prefix PREFIX`, and make two empty directories for
   the trial, one for `LANEBOSS_HOME` and one for `LANEBOSS_STATE_HOME`, in the environment of every command of the
   trial, so that nothing of a person's own is touched. The configuration `CONFIG` and its runner `RUNNER` are named by
   the supervisor for the trial; the runner has what step 1 of the real trial of T2 asks, and the table `[turns]` of
   `CONFIG` has `poll_seconds = 5` and an `idle_message` that asks the agent to answer in one line with the word it was
   given. The account is one that `CONFIG` lists for `RUNNER`, and the lane name carries the step (T3) and the date.
2. With the file tool, write in a directory made for the trial: `brief.md` (it gives the agent a made-up word, with the
   time in it so that nothing can guess it, and asks it to answer `ready`), `message-1.md` (a sentence made up for the
   trial, and the request to run one shell command that prints a number and to answer with the word, the sentence and the
   number), `probe.md` (it asks the agent to run a shell command that says whether the variable `LB_TRIAL_PROBE` is set,
   without printing its value, and to answer `set` or `unset`) and `message-2.md` (it asks the agent to run one shell
   command, a computation of about 150 seconds, and then to answer `done`, so that its turn is still running when the
   loop is stopped; it does not ask for a bare `sleep`, which a hook or guard of the agent program can refuse (the
   session may then refuse later waits too, since a refused command is not run in another form); if the long command is
   refused as well, the refusal is reported and the step is not tried in another form). No command of the trial takes a
   message as an argument: each is a file, or standard input from one.
3. Start the lane: `laneboss lane start --config CONFIG --lane LANE --project P --brief brief.md --runner RUNNER --model
   MODEL --account ACCOUNT --budget 15 --turns --idle 120`. Follow `laneboss event tail --config CONFIG --lane LANE
   --follow --until lane.ended` in the background mode of the shell tool, without polling. When it ends, `lane status`
   shows state `waiting` and `idle` true, and `lane.started` has `mail` `[]` and `idle_seconds` 120.
4. Send the first message BEFORE the loop starts: `laneboss lane send --config CONFIG --lane LANE --file message-1.md`.
   A loop that does not run starts nothing, so however long the supervisor takes, no idle turn comes first; and when the
   loop looks at the lane, a waiting message is started before the idle interval (`due()` prefers mail). Then start the
   loop with a distinctive harmless variable in its environment: `LB_TRIAL_PROBE=VALUE laneboss lane loop --config CONFIG
   --detach`, where VALUE is made for the trial and has the time in it. It prints `loop`, `pid` and `session`
   (`laneboss+loop`). `lane loop --status` shows `running` true, `detached` true, the same `pid` and `last_error` `null`,
   and the session is in `tmux -S SOCKET list-sessions` (SOCKET is `socket` of `config path CONFIG`); the entry of the
   lane says `waiting` 1 and `next` `mail`, or, when the loop has already started the turn, `waiting` 0 and `next`
   `null`, and either is right. Follow `laneboss event tail --config CONFIG --since SEQ --follow --until loop.turn` in
   the background (SEQ is the `seq` of `loop.started`; the follower replays the events after it, so it ends at once when
   the loop was faster than the supervisor). It ends on the `loop.turn` that the loop appends in its first pass, within
   the time the turn takes to start: its payload has `kind` `mail`, `sequences` `[1]` and `run` 2. Follow `--lane LANE
   --since SEQ --follow --until lane.ended` (SEQ is that of the `loop.turn`), then read the announcement once without
   `--follow`: `lane.delivered` continues with step 5; `lane.returned` with reason `limit` is a result of its own (the
   trial is repeated with another account); any other reason is a failure of T3, reported with the event and the lane's
   log.
5. Read the agent's answer to the turn from the lane's log, in the byte range that the run record of the turn gives
   (`lanes/LANE/runs/LAUNCH.json`, key `log`), and keep it in a file. It must contain the word, the sentence and the
   number that the command printed: the turn that the loop started reached the session. Then send `probe.md` and follow
   the `loop.turn` of kind `mail` with `sequences` `[2]` and its `lane.ended`, in the background as above: the answer
   must be `set`, so the turn has the environment that the loop captured when it started, and the value is in no file of
   the state directory and in no event (search the state directory, and the output of `event tail`, for it). The loop
   starts an idle turn whenever the lane has been idle for 120 seconds and no message waits, so the supervisor's own
   speed can put one or more idle turns between the turns of the messages (for example while it reads the answer above);
   the turns of the messages are found by their `sequences`, and the idle turns are counted in steps 7 and 9.
6. The idle turn: with no message waiting, follow `--lane LANE --since SEQ --follow --until loop.turn` once more (SEQ is
   the `seq` of the last event read). It ends on a `loop.turn` of kind `idle` with `sequences` `[]`, whose
   `lane.started` is at least 120 seconds after the `lane.ended` before it. Then follow `--lane LANE --since SEQ
   --follow --until lane.ended` (SEQ is that of the `loop.turn`), and only then read the answer to the idle message,
   which contains the word. An idle turn that came earlier (step 5) is this one, and this step is then only the reading.
7. Send `message-2.md` and follow `--until loop.turn` for the `loop.turn` of kind `mail` with `sequences` `[3]` (the
   turn starts); `lane status` shows `running` true. While it still runs, stop the loop: `laneboss lane loop --config
   CONFIG --stop` prints `stopped` true, the `pid` and the `loop.stopped` event (reason `stop`, `skips` 0 when nothing
   was refused, and `turns` the number of the `loop.turn` events so far: the three mail turns and the idle turns, one or
   more, each at least 120 seconds after the end before it). `lane loop --status` shows
   `running` false, the session `laneboss+loop` is gone from `tmux list-sessions`, and the lane's own session and its
   supervising process are alive. The turn then ends by itself (follow `--lane LANE --since SEQ --follow --until
   lane.ended` in the background): its end has reason `exit`, exit code 0 and `prompt` `written`, and its message is
   delivered.
8. Count the processes of each run from its run record: the identities (process id, process group, session and start
   time) of every process that was sampled. None of them may be alive after the end (`ps` by process id, and the start
   time compared with the recorded one, because a process id can be reused), and each `lane.ended` has `survivors` 0. A
   real agent program runs helper processes in groups of its own, with a tool or without one, as the real trial of T2
   showed, so the number of process groups does not show that a shell command ran: the agent's answer does (the number in
   the answer to the first message, the word `done` after the long command). The loop's own process, which `loop.json`
   names, is gone after `--stop`.
9. Check the store with the same interface: `event tail --config CONFIG` lists `loop.started` (`detached` true), the
   `loop.turn` events of the mail turns with `sequences` `[1]`, `[2]` and `[3]` in that order, and one or more of kind
   `idle` with `[]` (each at least 120 seconds after the end before it; the number of them depends on how long the
   supervisor took, and the runs are numbered from 2 in the order of the turns), and `loop.stopped`, each `loop.turn`
   behind the `lane.started` of its run; `state verify` passes with `mail_files` 3 and `mail_orphans` 0; `lane status`
   shows the row's `mail` with `delivered` 3 and `idle` true, and `lane loop --status` shows `bad_ends` 0.
10. The evidence is the command files with their outputs and exit codes, the events printed, the agent's answers, the run
    records and the process counts with the way they were counted, `loop.json`, `loop.log` and the output of `state
    verify`. It is kept in the lane's evidence directory, outside the repository, with a manifest of the hashes, and the
    report names the path and the scope of every number it states. Nothing in the repository names the account, the
    machine or the session. When the trial is over the lane is marked `abandoned` (the only state a turn-based lane can be
    marked with) and cleaned, and what the trial made is collected.
11. Beside this trial the supervisor runs "Confirming the statements by running 0.5.0" ("Rolling back to 0.5.0 across the
    changes of this design"), with the store of this trial as the copy E.

**T4, attach and the stream (built).** The end-to-end tests are `tests/e2e/test_attach.py` (attach, and `config validate`
for the key `stream`) and `tests/e2e/test_streams.py` (the readers by themselves), written from this list and run on a
disposable machine. They run attach on a pseudo-terminal, as a person's terminal holds it (a session leader whose
controlling terminal it is, so the byte 3 typed there is a Ctrl-C and closing the master is a hang-up), and feed it a
stand-in runner that prints invented stream lines (the stand-in's behaviour `streamer` plays a script of lines, bytes,
waits and an exit that the test writes):

- The init line with `bypassPermissions` gives the plain warning; another mode is shown without it; no init line gives
  "not reported yet".
- Streamed text, tool labels and the result line: the cost is shown at the end of the turn, the turn's cost as the
  difference from the earlier total, and the total alone when the earlier one cannot be read.
- A table of odd lines (not JSON, JSON that is not an object, wrong types, a deep or huge value, bytes that are not
  UTF-8, an escape sequence in the text) never gives a traceback, and control characters do not reach the terminal.
- A typed line becomes `lane send` and `lane turn` (the events are there), and when a turn is live the line is queued
  and no second turn starts. A line that starts with `/` and is no command is never sent (no `lane.mailed`). A line that
  `lane send` refuses is printed with the refusal and held for the next prompt.
- A line that is partly typed: on an interpreter that has `readline`, the test writes bytes without a newline to the
  pseudo-terminal while the stand-in prints more lines. Attach shows none of those lines until the line is entered or
  discarded, then shows them, in order, before the next prompt, and the line that was typed is sent whole (`lane.mailed`
  has its bytes). With no line typed, a line that the stand-in prints appears at once, above the prompt.
- Ctrl-C during a turn that attach started stops that run only (reason `stopped`); the stand-in's child runs in a session
  of its own (`setsider` or `stubborn` of `tests/e2e/standin.py`) and is gone after the stop. During a turn that the
  loop started it leaves attach and stops nothing (the test uses a turn that `lane turn` started outside attach, which
  attach cannot tell from the loop's, and no test of attach runs the loop); a closed terminal, SIGTERM, `/exit` and the end of the input each leave the turn running.
- `lane status` and the idle display agree. A lane that the configuration does not know is refused with exit 2.
- An unknown `stream` name is refused by `config validate`. A stand-in that prints a limit message inside a JSON line
  and exits 0, with a `limit_patterns` entry written for that line as printed, ends with reason `limit`; the
  `permission_denials` of a result line are shown as lines of their own.

The real trial of T4: attach on a real session, one typed line, the mode the agent reports, the cost, and Ctrl-C
during a second request that makes the agent run a shell command; the processes of the run are counted after the stop,
and none may remain, in any process group of the run record. It is a written procedure, run by the supervisor after the head is
reviewed, on the machine and with an account that the configuration names for it (rule 1 of the shared protocol); it is
not part of `tests/`, and it has not been run on this branch. It also checks, against the lines of a real session, the
shapes that the reader `claude-stream-json` takes, and the design's assumption that `total_cost_usd` is the session's
running total. The procedure:

1. The runner, `RUNNER`, is a runner of the configuration `CONFIG`, both named by the supervisor for the trial, and it
   has: `{session}` in `command` and in `resume`, `prompt = "stdin"`, `stream = "claude-stream-json"`, a `command` that makes the agent
   program print one JSON object per line (`--output-format stream-json --verbose --include-partial-messages`) and
   names the permission mode that the trial is to show, `limit_patterns` written for the JSON line as the agent program
   prints it, a `records` entry that finds the agent program's record of the session by `{session}`, and a small model
   named in full. The account is one that the configuration lists for that runner. The lane belongs to a project whose
   repository is local, and its working directory is the one `lane start` makes by default, as in the real trial of T2.
   The lane name is one that the project's `lane_prefix` allows and that carries the step (T4) and the date.
2. With the file tool, write three files in a directory made for the trial: `brief.md`, which gives the agent a made-up
   word (with the time in it, so that nothing can guess it) and asks it to answer `ready`; `line-1.md`, one sentence made
   up for the trial that asks the agent to answer with the word, in one line, and to run no command; and `line-2.md`,
   one sentence that asks the agent to run one shell command that first writes, into a file that `line-2.md` names (a
   file of the lane's working directory), the number of process groups that `ps` shows in the command's own session,
   and then keeps running for about two minutes by a computation that uses the processor (a loop in the interpreter that
   the agent has at hand), not by a bare `sleep`, which a hook or guard of the agent program can refuse. No command of
   the trial takes a message as an argument: each is a file, or standard input from one.
3. Start the lane: `laneboss lane start --config CONFIG --lane LANE --project P --brief brief.md --runner RUNNER --model
   MODEL --account ACCOUNT --budget 10 --turns`. Follow `laneboss event tail --config CONFIG --lane LANE --follow --until
   lane.ended` in the background mode of the shell tool, without polling. When it ends, `lane status` shows state
   `waiting` and `idle` true.
4. Attach needs a terminal. Start a tmux session on a socket of the trial's own, with a window of 200 columns and 50
   rows, that runs `laneboss lane attach --config CONFIG --lane LANE`, and read its screen with `tmux capture-pane -p`
   into a file after each step. Keys reach attach through tmux and never through an argument: a typed line is a file that
   is loaded into a tmux buffer (`load-buffer`) and pasted (`paste-buffer`; its last newline enters the line, and one
   more Enter is an empty line, which attach ignores), and Ctrl-C is `send-keys C-c`. The first screen shows the lane's
   line, `permission mode (as the agent reports it): MODE` (the brief's run printed an `init` line) with the warning when
   MODE is `bypassPermissions`, and the idle display. Compare MODE with the mode that the runner's `command` asks for,
   and report both.
5. Note the `seq` of the last event of the lane (`laneboss event tail --config CONFIG --lane LANE`, its last line) as SEQ,
   and follow `laneboss event tail --config CONFIG --lane LANE --since SEQ --follow --until lane.ended` in the
   background mode of the shell tool, without polling. Type `line-1.md`. The screen shows `message 1 sent`, `turn
   started: run 2 (messages 1)`, the answer once (it contains the word), and then `[run 2 | exit 0 | this turn $X |
   session $Y | S seconds]` and the idle display. When the follower has ended, `lane status` shows
   `live.supervisor.alive` false once the supervising process has appended its announcement and exited (normally already
   true when the follower has ended; when it is not, look again once, later); read the announcement once with `laneboss
   event tail --config CONFIG --lane LANE --since SEQ` without `--follow`: `lane.delivered` continues with step 6;
   `lane.returned` with reason `limit` is the result of step 8; `lane.returned` with any other reason is a failure of
   T4, reported with the event and the lane's log. Read the result lines of the log in the byte ranges that the run
   records of run 1 and run 2 give (`lanes/LANE/runs/LAUNCH.json`, key `log`) and keep them in a file: the second
   `total_cost_usd` must be the first plus the cost of the second request, so that `X` is the difference. If the second
   total is the cost of the second request alone, the assumption is refuted: the report says so with both lines ("Open
   points", 11).
6. Follow the next turn in the same way (SEQ is the last event again). Before `line-2.md` is typed, start, in the
   background mode of the shell tool, ONE command that ends when the file that `line-2.md` names has been written in the
   lane's working directory: a wait on the file system's own event, `inotifywait -t 300 -e close_write --include NAME`
   on that directory (NAME is the file's name, escaped as a pattern). It waits for an event, so nothing polls and no
   sleep is used; it ends only after the number has been written (the event `create` comes before it); and it is
   started first, so that the file cannot appear before the wait begins. Its limit of 300 seconds is for a command that
   was refused and wrote nothing: the wait then ends with exit status 2 (and with 1 on an error of its own), and the
   step is reported, not waited on for ever and not tried in another form. Type `line-2.md`. When the wait has ended
   with exit status 0, the command has run and has written its number: press Ctrl-C. The screen shows `stopping run 3`,
   then `stop requested for run 3; press Ctrl-C again to stop waiting (the request stands)` and then `run 3 ended with
   reason stopped; survivors 0`, and the follower ends on `lane.ended` with reason `stopped`.
7. Count the processes of the stopped turn from its run record: the identities (process id, process group, session and
   start time) of every process that was sampled. None of them may be alive after the stop (`ps` by process id, and the
   start time compared with the recorded one, because a process id can be reused), and the record must show more than one process group: the agent program runs helper processes in groups of their own, with or without a tool, so the count reaches beyond the runner's group. The number of groups does not show that the shell command ran, and neither does the `tool_use` line, which shows only that the agent asked for it; the file that the command wrote does, and the trial reports its number. The `lane.ended` of the turn has reason `stopped` and `survivors` 0, and the mail of the turn has returned (`lane status`, `mail.returned`). The first turn is counted the same way; it too may show several process groups although the agent uses no tool.
8. Read every line of the three runs' ranges that attach showed as a raw line (a line the reader does not know) and
   every shape of the list in "The stream readers" against the real lines: a difference is corrected in the reader and
   its tests, in the commit that finds it. A request that ends at a usage limit is a result of its own (`lane.returned`
   with reason `limit`, the messages waiting again): it is reported as that, and the trial is repeated with another
   account that the configuration lists. When the trial is over the lane is marked `abandoned` (the only state a
   turn-based lane can be marked with) and cleaned, and what the trial made is collected.
9. The evidence is the command files with their outputs and exit codes, the screen captures, the events printed, the run
   records and the process counts with the way they were counted, the result lines, and the output of `state verify`. It
   is kept in the lane's evidence directory, outside the repository, with a manifest of the hashes, and the report names
   the path and the scope of every number it states. Nothing in the repository names the account, the machine or the
   session.

**T5, accounts and adoption.** The end-to-end tests are `tests/e2e/test_room.py` (the runner key `room`, the configured
command run for real, and the check of its answer, with answers `true`, `false`, a bad object, a missing key, too large
an output, a timeout and a non-zero exit; a `reason` with a credential shape becomes `(withheld)`, and output that is not
in the documented form is never printed, only the fixed sentence is; a room command that sleeps past the timeout and
starts a child is stopped, and both are gone), `test_room_choice.py` (the choice of the account in the design's order,
the record of which candidates were asked, and the outcome of each case) and `test_adopt.py` (the event `lane.adopted`,
its payload, the rule at append, the projection, and the readers of `lane status`, `lane send`, `lane turn` and
`lane start --reuse`, driven through `event append`). No room is no turn, the mail waits, and the loop records
`no-room`; `slots` limits the turns started in a pass; `--account` asks only for its account.

`lane adopt` is tested in `tests/e2e/test_adopt_command.py` (18 tests): the command exists, a valid call and its printed
payload, event order, rendered brief, claim and waiting state; omitted `--effort` and `--account`, and the recorded
`--budget`; `lane send` and the first turn (run 2, `how` `resume`, the given session identifier); twelve
refusals (a known lane, an identifier that is not a lower-case UUID, a session that another lane's `lane.started` holds,
a runner that cannot take turns, an account the runner does not list, an account the project excludes, a runner without
a `{session}` records template, a missing directory, a directory that another lane of the configuration works in, a
tmux session of the lane's name open on the configuration's socket, no session record, and a record written within the
quiet seconds); the refusal of a resume template needing an omitted effort; and a refusal that disturbs no good
adoption, which also refuses a session that another lane's `lane.adopted` holds.
`tests/e2e/adoptsupport.py` writes the session's record under `{worktree}/.sessions/{session}.jsonl`, with an old or
fresh modification time for these checks.

Not tested by the command tests: the lanes lock (its wait and a race between two adoptions), a failure after the claim,
a launcher-zone directory, a repository's main working copy, a directory whose claim a lane of another configuration
holds (the claimed-directory test meets the neighbours check of this configuration's lanes first), a live launch of the
lane, an unavailable tmux command, a tmux session name that collides with another lane's, the refusal when neither
`--budget` nor `[lanes] budget_minutes` gives a budget, an unknown project, a project's lane prefix and its workers, the
forms of `--lane`, `--model`, `--effort`, `--account`, `--idle` and `--budget`, a brief that `brief render` would refuse, the
default of `--idle`, `--budget` beyond its recorded value, a records template not rooted at the working directory, a resume
template needing an omitted project, and the loop acting on an adopted lane.
Not built, and so not tested: the rule that no second room command starts for an account while one still runs.
The refusal at append of an adoption event that names another configuration's tmux socket
is tested through `event append`, which is built.

The real trial of T5 is written and not yet run: a session started by a plain headless call is adopted, and one turn
resumes it, makes the agent run a shell command, and shows that it remembers what it was told before the adoption. The
processes of that turn are counted afterwards. This is the only place where the real program takes part in T5's checks
of adoption.

**What each step amends.** Besides the document of its own part, a step that builds a part also edits the existing text
that the part makes untrue, in the commit that builds it:

| Step | Existing text it amends |
|---|---|
| T2 | In "Event and state store", the sentence that lists the writes that are not events; in "Integrity", the kept-file checks and the output of `state verify`; in "Lanes", the commands table (`lane start`, `lane resume`, `lane status`, `lane check`, `lane mark`, and rows for `lane send` and `lane turn`), the events table, "Projection", "Files" and "Not built yet"; the briefing in "Command line contract"; the table of checks in "Doctor" (`turns.limit_patterns`); `docs/configuration.md` (`[turns]`); `protocol.md` (its protocol version line); the README and the changelog. |
| T3 | "Command line contract" (`lane loop` prints one JSON line for each loop event, as `event tail` does), "Files" (`loop.lock`, `loop.json`, `loop.log`), the `lane check` row, the events tables and `docs/configuration.md`; with them the commands table (a row for `lane loop`), "Layout", "Not built yet", "Known limits", the reserved kinds of "Event and state store", the compatibility with stores written by 1.1.0, "Rolling back to 0.5.0 across the changes of this version" (under "Install"), the README and the changelog. |
| T4 | "Command line contract" (`lane attach` prints text for a person, as `start` prints Markdown) and `docs/configuration.md` (`stream`). |
| T5 | The commands table (`lane adopt`), the events table, the form of `chosen_by`, the checks of `lane send` and of the loop (they read the row's `mail.turn_based`, so that an adopted lane is turn-based for them), "Organisations" (the check on tools covers `room`) and `docs/configuration.md` (`room`, `room_timeout_seconds`). |

### Open points

**Decided.** These were open points. The top confirmed each default, and each now stands in the part that it names:

- The delivery rule, that a turn delivers its messages only when it ends with reason `exit`, exit code 0 and a prompt
  written whole, and that any other end returns them: "Mail events, the new lane state and the projection" ("The four
  states of a message").
- A new life of a lane with mail waiting: `lane start --reuse` is refused while a message waits or has returned, with
  `--turns` or without it: the same part ("Rules at append") and "The `lane turn` command" ("Changes to commands that
  exist").
- A turn-based runner without `limit_patterns` is not refused, and `laneboss doctor` warns about it: "The `lane turn`
  command" ("Changes to commands that exist").
- One room command template for each runner, with `{account}`, run for each account: "Accounts and adoption" ("The room
  command").
- The turns that the loop starts get the environment that the loop captured when it started, which it holds in its own
  memory and writes to no file of the state directory; every tmux command of the launcher runs with a fixed environment
  of five names (`PATH`, `HOME`, `LANG`, `TMPDIR` and `USER`), so the tmux server keeps no other variable of its caller,
  and a run receives the rest of its environment only through the FIFO: "The `lane loop` command" ("A pass").
- The idle interval counts from the lane's last state change: "The `lane loop` command" ("What it is").
- A person's `lane turn` ignores the back-off, which belongs to the loop: "The `lane turn` command" ("The command") and
  "The `lane loop` command" ("Back-off").
- A row that has `mail` and is abandoned stays abandoned at a closing event: "Mail events, the new lane state and the
  projection" ("The new state and the projection").

Each point below is a place where the design could not be settled from what exists, or where its proposal needs the
top's confirmation. The proposal stands unless the top says otherwise.

1. **How a lane is declared turn-based.** Proposal: `lane start --turns [--idle SECONDS]`, recorded as the optional keys
   `mail` and `idle_seconds` of the lane's `lane.started` events. Why: it is derivable from events alone, so `apply()`
   needs no configuration; it is a choice of the supervisor who starts the lane, per lane; a runner stays free to serve
   ordinary lanes; and the loop and the projection read the same fact. Alternatives that were considered: a runner key in
   the configuration (every lane of the runner would be turn-based, which would stop such lanes from ever being accepted
   or merged), and a separate event after the start. The idle interval belongs to the declaration, with the
   configuration's `idle_seconds` as its default; changing it for a running lane would need one more event, and the
   design has none: abandon the lane and start another.
2. **The protocol version.** No rule that says what a MAJOR, MINOR or PATCH step of the protocol version means is written
   in the repository (searched: `docs/`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `protocol.md` and the protocol
   package). Proposal: read the step to 1.2.0 as a MINOR step that adds kinds and optional keys, changes no existing
   payload and keeps every older store valid, a store that holds hand-written events of a newly reserved kind that is
   not `lane.*` included (they are checked at append only). Make that step once for the whole design, with these
   additions, which the top confirms as one step: the kinds `lane.mailed`, `lane.delivered`, `lane.returned`,
   `lane.adopted`, `loop.started`, `loop.stopped`, `loop.turn` and `loop.skipped`; the keys `mail` and `idle_seconds` of
   `lane.started`; the reasons of `lane.returned` (`lost`, `gone` and `cut` besides those of `lane.ended`); the value
   `room` of `chosen_by.account`; and the state `waiting`. T2 raises the protocol version line of `protocol.md` from
   1.1.0 to 1.2.0 and T3 to T5 add their kinds under it, as unreleased builds between steps are not supported; and the
   rules text of `protocol.md` stays unchanged apart from that line. That line is the only version that a step of this
   design changes: the package version is not a step of it, and is raised by the person who installs a build.
   Alternatives: one MINOR step for each of T2, T3 and T5, and a new rule of the protocol that tells a turn-based
   session how a turn ends.
3. **Where `loop.*` events live.** Proposal: their own reserved kinds, not `lane.*`, checked at append and nowhere else,
   so that a 1.1.0 store that holds such events written by hand still verifies and rebuilds, and not in the projection,
   so that the lane projection and `check_transition` stay as they are for lanes that the loop only looks at. The loop
   ignores every `loop.*` event that is not in the documented form. The loop's state is what its events say and nothing
   else.
4. **The loop records the loss of its own lanes' runs.** Proposal: `lane check` gains `--lane L`, and the loop runs the
   check for a declared lane whose supervising process is seen gone, so that a restart of the machine does not need a
   person. The check records a fact; it does not accept, merge, clean, mark, stop or retry anything. Without this the loop
   would wait for a person or a timer to run `lane check`.
5. **A turn that exits 0 without having read its input.** The delivery rule sees a write and not a read: a prompt that
   fits what the pipe holds is written whole whether or not the runner reads it, so a runner that exits 0 without
   reading such a prompt counts as having taken the turn ("Known limits"). Proposal: leave it so. A refinement that
   could see a read is not part of this design; the top confirms.
6. **The numbers and the names of the new keys.** 262,144 bytes for a message; 1,000 messages waiting; 64 messages and
   1,048,576 bytes of joined text for a turn, so that a turn takes the head of the queue up to these bounds and the rest
   waits for the next turn; nine digits of sequence; 64 KiB for the idle message; the loop's defaults of 10, 300 and 1800
   seconds; 20 seconds for the room command and 4 KiB of its output; 200 characters of `detail` and `reason`; and the
   names `[turns]`, `idle_message`, `idle_seconds`, `poll_seconds`, `backoff_seconds`, `limit_backoff_seconds`,
   `stream`, `room` and `[lanes] room_timeout_seconds`. They are proposals chosen to be large enough for real use and
   small enough to be checked; T2 to T5 pin them in tests.
7. **Sentences outside the section.** The mail directory is a writer of kept files, and "Event and state store" lists
   the other writers, "Integrity" lists the kept-file checks, and "Command line contract" lists the commands whose
   output is not one JSON value. Proposal: this section lists the directory and its checks itself, and leaves those
   sentences as they are until the step that makes them untrue (T2 for the first two, T3 and T4 for the third) edits them
   in its own commit ("What each step amends"), so that nothing outside the section claims a command or an event that
   does not exist. The top may prefer the sentences to be edited now, marked as designed.
8. **Delivery is at least once.** A turn that is killed after the agent has acted on a message returns the message, and
   the next turn carries it again, marked `(again)`. Proposal: accept it; exactly-once delivery would need the agent's
   cooperation, which the launcher cannot ask for.
9. **The loop's session name.** Proposal: `laneboss+loop`, with `+`, a character that the lane grammar refuses. Whether
   the installed tmux keeps `+` in a session name was not run on the machine where this was written: T3's tests pin it,
   and an upper-case letter is the fallback.
10. **Adoption.** Proposal: `lane adopt` records a new event `lane.adopted` that the projection reads as a run 1 that is
    already over, requires a `records` entry with `{session}` so that the launcher can see that the session exists and is
    quiet, and refuses everything listed. That run 1 is a number and not a run: it had no supervising process, no run
    record, no budget in force and no refusal coverage, which the statement that the first turn is `lane start` with the
    brief on standard input does not foresee; the top confirms. The checks of `lane send` and of the loop read the row, so
    an adopted lane is turn-based for them. Alternatives: a synthetic `lane.started` and `lane.ended` pair, which would
    record an end that no process had.
11. **The cost of one turn.** The design assumes that `total_cost_usd` in the result line of `claude-stream-json` is the
    session's running total. Proposal: keep the assumption, let T4's real trial confirm or refute it before the reader is
    built, and, if it is refuted, have the reader report the per-turn cost directly and attach print that.
12. **`lane turn --idle` while mail waits.** Proposal: the mail is sent and the idle message is not, so that a caller
    that wants a turn now never has to know whether mail waits, and the loop's idle decision cannot be refused by mail
    that arrived a moment before. The alternative is to refuse the combination.
13. **The marker ` (again)` on a returned message.** The header line names the sender and the time, and this design adds
    ` (again)` to the header of a message that an earlier turn carried without ending well, because that turn may have
    acted on it. Proposal: keep it; it costs one word per message and tells the agent what a repeat is.
14. **Ctrl-C in attach.** Proposal: it stops the turn that this attach started, through `lane stop --run N`, and never
    another, while closing the terminal or leaving never stops anything. The alternative is that attach never stops a
    turn and a person uses `lane stop` in another terminal.
15. **A skip is an event once for each wait, not once for each pass.** Each decision of the loop is an event, a skip and
    a back-off included. Proposal: the loop records a skip when it first finds the lane in a wait and again only when the
    reason or `until` changes, because a skip for every pass, every 10 seconds, would fill the store with copies of one
    decision. The alternative is an event for every pass. The same proposal makes the loop wait `backoff_seconds` after a
    refused attempt to start a turn, which is not a back-off after an end but the same number reused, so that a lane that
    is refused every time is tried every five minutes and not every 10 seconds.
16. **A person's `lane turn` without room.** For the loop, a `loop.skipped` says why there was no turn. For a person's
    `lane turn` the refusal message says why and no event does, because a refused command appends nothing. Proposal:
    keep it; no other refused command appends an event. The alternative is an event for every refused turn.
17. **A resend after a lost result.** A sender that saw no result may send the same text again, and both copies are
    delivered (the failure table and "Known limits"). Proposal: leave it out, so that the launcher compares no message
    with the waiting ones. The alternative is that a send whose sender and digest equal those of a message that still
    waits or has returned prints that message with `"existing": true` and appends nothing, which is new behaviour.
18. **The statements about a rollback to 0.5.0 are read, not run.** The subsection "Rolling back to 0.5.0 across the
    changes of this design" was read from the code of 0.5.0 (commit 919af68), as the paragraph under "Install" was, and
    nothing was run where it was written. Proposal: each of T2 to T5 confirms the statements about the things it builds
    by running 0.5.0 (that commit) once on a test machine, against a configuration and a store that hold them, as a
    written procedure beside its real trial, and, in the commit that builds the trigger, corrects a statement that the
    run shows wrong and moves the statement into the paragraph under "Install". The alternative is to leave the
    statements as read.
19. **The row field `mail` makes 0.5.0 refuse more than `session_id` and `prompt` do.** It makes 0.5.0 refuse
    `state lanes`, `lane status`, `lane check` and `lane start` for every lane, where those two keys leave most of them
    working (`CHANGELOG.md` lists what still works). Proposal: accept it. Any field added to a row is refused by
    `current_form`, `apply()` needs one to set `waiting` at a run's end, and a store that holds a lane that takes
    turns is already refused by `state verify`, `doctor` and the briefing for `session_id` and `prompt`, so a rollback
    over it needs a restored copy or a new start either way.

## Refusals

Machines that run agents have guards: hooks and permission layers that refuse some actions. The shared protocol tells
every executor what to do when one refuses (stop, report it verbatim, write a document whole with the file tool, never
split, reword or strip the refused command, never use an override prefix). The launcher does not rely on executors
obeying it or on supervisors reading raw logs by hand: it may read a lane's raw session records where the configuration
names them, records every refusal it finds there as an event when it happens, flags a later shell write to the refused
call's files, or the refused command sent again in other words, as a suspected workaround, and refuses to record a lane
as accepted or merged while a suspected workaround has a file that the supervisor has not reviewed.

It is configured by two optional parts of a configuration (`docs/configuration.md`): `[[guards]]`, the company's own
patterns that recognise a guard's refusal in the result of a tool call or in a hook's message (the package ships none),
and a runner's `records`, where its raw session records are and in which format. Without guards nothing is scanned and
nothing below changes how lanes behave; a runner without `records` is not scanned (its runs are reported as not
configured).

### Session records

A raw session record is the agent program's own record of every tool call and its result, never the executor's final
message. Two formats are read (`src/laneboss/sessions.py`). The shapes of `claude-code` were checked against real records
(field names and nesting, in October 2026); the test fixtures are invented in those shapes.

| Format | Lines | Calls, results and hooks |
|---|---|---|
| `claude-code` | One JSON object per line, with `timestamp` (ISO 8601) and `cwd`. | A line with `"type": "assistant"` holds calls in `message.content`: `{"type": "tool_use", "id", "name", "input"}`. A later line with `"type": "user"` holds results: `{"type": "tool_result", "tool_use_id", "content": text or a list of blocks, "is_error"}`; only results with `is_error` true are offered to the guards. A hook's message about a call is a line with `"type": "attachment"`: `attachment.type` `hook_blocking_error` with the text in `attachment.blockingError.blockingError` (the hook's command in `.blockingError.command`), or `hook_non_blocking_error` with the text in `stderr` or `content`; both carry `toolUseID`, `hookEvent` (`PreToolUse`, `PostToolUse`) and `hookName`, and the call's own result may well be a success. These two are offered to the guards always, whatever the result says; `hook_success` and every other attachment are not. |
| `text` | The run's own log only: `paths = ["{log}"]`, the lane's `output.log` within the run's byte range. | None: every line is offered, and a refusal found there has no tool, no command and no targets, so no workaround can be checked against it; its event says so. |

A `text` entry with any other path is refused by `config validate` (a later version may read other text files). The
`codex` format is not supported yet: real records of that program wrap their outputs as JSON inside text blocks and
their calls are scripts for an `exec` tool, which a reader built from descriptions misread; a configuration that names
it is refused, and the way to watch such a runner is `text` on the run's own log (`{log}`). A later lane builds it from
real records.

Shell calls are `Bash` calls (`input.command`). File-tool calls are `Write`, `Edit`, `MultiEdit` and `NotebookEdit` (the
file they write). Any other call is kept with its input; the paths it names are its `file_path`, `path` and
`notebook_path` fields.

A line that is not JSON, not an object, or not of a described shape is skipped and counted as an unknown line; an object
of another type is skipped and counted as another line. Neither is ever fatal. Content blocks are read only when their
type was seen in real records: `text`, `thinking` and `tool_use` in assistant lines, `tool_result` and `text` in user
lines, and `text` and `tool_reference` in a result's content list. A block of any other type makes its record
`partly-read`, and the run is not covered. A record is recognised only once an assistant or user line was read whole: one
in which every line is of another kind (what a wrong `format`, or a writer that renamed its line types, looks like) is
`unrecognised`, and the run is not covered. That is decided only after the record has been read to its end by a scan's
final read, which also takes a last line without a newline: until then a live reader calls no record of an earlier run
`unrecognised`, nor `partly-read` for a first line that never ended.

**Which records belong to a run.** For each run, the runner's path templates (globs, with `**`, `~` and the placeholders
`{account}`, `{effort}`, `{lane}`, `{log}`, `{model}`, `{project}`, `{session}` and `{worktree}` filled with the run's
values, escaped for the glob) are expanded; a value that holds `/`, or is `.` or `..`, makes its template `bad-placeholder`
and it is not used (only `{worktree}` and `{log}`, at a template's start, are paths). `{session}` is the lane's session
identifier, so a template with it names exactly the files of that session and no other file of the directory is
read; the run of a lane that has no identifier (an earlier version started it, or its runner's command does not use
`{session}`) is not covered, with the reason `no-session`, never skipped without a word. A directory that cannot be listed while the
glob is expanded is `unreadable`; `**` follows links to directories, each directory once (by device and inode, so a
loop ends), and more than 10,000 candidates at any stage, directories as well as files, give `too-many-records`: no
candidate is dropped in silence. A file found is read when it changed after the lane's first run began (two seconds of
slack) and its real path lies outside every configuration directory and state directory of the launcher (and their
homes); one inside is `refused-zone` and is never read. Links are otherwise followed: agent programs keep their record
directories behind links. A `claude-code` record belongs to the lane when the first
working directory it names is the lane's working directory or lies below it (real paths): a second session that a hook
of the lane's own agent starts there is the lane's too. Each of its lines belongs to a run only inside that run's window,
from its start (the first run: two seconds earlier) to its end plus five seconds, by its own timestamp (or the last one
before it); lines outside every window belong to no run and are counted (`outside_runs`). A record with no line and no
oversized line in a run's window, whose last look found it readable and unchanged, and that was never read for that
run's launch before, is not that run's record: it is listed with that count and the state `outside`, never enters the
run's inventory, and so cannot make the run uncovered. So a record continued across
runs is split between them, and a record written before the lane's first run, by another working directory or by
anyone in the directory after a run ended, is not the lane's (a record of another working directory is not read past the
line that names it and does not count towards the limit of records read). The text record `{log}` is the run's part of
the lane's log, opened as the launcher's own file (through the lane's directory in the state directory, without
following a link; a log that is a link or not a regular file is `refused-zone`) and read by the byte range the
supervising process recorded in the run record (`log.start` when the run began, `log.end` when its processes were gone);
a range without its end runs to the next run's start. A log shorter than the end of the run's recorded range is
`truncated`: what is left of the range is read, and the run is not covered. Recorded ranges never overlap: when a run's
range begins before the end of an earlier run's range, the log was removed or cut and written anew, so every earlier run
whose range is not wholly before that beginning is `truncated` and not covered, whatever the file's present length (only
what lies before the beginning is read for it), and the later run is read normally. A log the live reader sees shorter
than what it has already read of a run, or than the end of that run's recorded range, makes that run `truncated` for
good, and what is left and what comes later is read on from the place the reader had reached. Whatever the live reader
sees about a run (a record in a state other than `covered` that it has not handed to a save yet and that the run's
saved inventory does not hold) is saved at the look that saw it, for every run the reader follows, the current one and
every earlier one, and also when its loop ends otherwise, when the state directory can still be written: after a normal
end a failure to save is reported like any other, and after an error it never takes the place of that error. The saved
inventory keeps the first state other than `covered` seen for a record; a later, different one is not added (the run
stays not covered) and is not written again at every look. What the launcher cannot see is a known limit: the log cut and written again to at least its former
length between two looks of the live reader, which waits half a second after the work of each look, so that two looks are
further apart than that.

**A record's identity** is its real path; a refusal's is the lane, that path and the call's id (or the line's offset and
the item, and for the run's own log also the run's launch, so that equal offsets in two runs are two refusals). Two
templates that reach one file read it once. A `claude-code` record is read once its first line is complete, however
long it is (up to the line limit); the SHA-256 of that line, the offset read to and the SHA-256 of the 4096 bytes before
that offset are kept, also in the coverage file's inventory. A record found shorter than that offset, or whose first line
or the 4096 bytes before that offset no longer have those hashes, is `replaced` for good: nothing more is read from it, by
any later scan either, and every run it was read for is not covered. A record whose first line has not ended when its
run has is `partly-read`. `lane scan` and the scan of `lane mark` read every record from its beginning, never from a saved
offset (`scan_lane` in `src/laneboss/refusals.py`); only the live scan beside a run reads on from its place.

Bounds: at most 200 records and 10,000 candidates at each stage of a template are read (more give `too-many-records`), a
line longer than 16 MiB is skipped and counted (a first line that long never completes: its record is not read and is
`partly-read` once its run has ended), a command's first 64 KiB are analysed, at most 4096 calls wait to be decided (the
oldest is decided at once), and the 64 latest refusals are compared with later calls.

### Matching

A result (or a hook's message) is a refusal when one of the configuration's guards matches it: its text is cut into lines
and every guard, in the configuration's order, is tried with `search` on each line in turn; the first line a guard
matches decides, and the guard's message is that line and the two after it (in a text record, the line alone). The cuts
are honest and counted, never silent: a text up to 128 KiB is matched whole; a longer one is matched on its first 64 KiB
and on the lines that begin in its last 64 KiB (the end of a line that began before them is not taken for a line), and
counts as a cut result (`cut_results`); a line is matched on its first 4096 characters, and a longer one counts as one
cut line (`cut_lines`). A cut alone does not make a run uncovered: it is a known limit, stated
below. Matching one text is given one second (an alarm that interrupts it, in the scanning process's main thread); a
text whose matching does not finish is counted as `timed_out` and its run is not covered. That alarm is the bound. When
the configuration is loaded, a guard pattern that does not compile or matches the empty string is refused, and so is
one that a partial rejection rule recognises as able to take time exponential in a line's length (an unbounded
repetition of a part that itself repeats, as in `(a+)+`, or a back-reference); the rule does not prove an accepted
pattern cheap (`^(a|aa)+$` passes it and is stopped by the alarm).

The refused call's **targets** are the files it would have written: a file tool's file, or the files its shell command
writes (below); when a call writes nothing that can be seen, the paths it names.

### Suspected workarounds

After a refusal, every later shell call of the same lane (in the same run or a later one) is compared with it. "Later"
means after the refusal's result: further down the same record, in a later run, or, in another record of the same run,
at a later time. A call is decided once its result is known and no hook refused it within five seconds more (in a scan
of the whole record, at the record's end), against the refusals before its result: a call refused in its result is a
refusal, not a workaround, and a call that a hook refuses is not suspected when the hook's message is read before the
call is decided. A live scan also decides a call whose result has not come two seconds after it was read, and the oldest
of 4096 waiting calls at once; so ordinary latency (a result later than two seconds, or a hook's message later than five)
can still leave a call both refused and suspected, and a `clean` verdict settles it. A scan of the whole record decides a
call without a result at the record's end. A write through a file tool is never a workaround: the protocol allows it.

The two tests (`src/laneboss/shellscan.py`) are cheap and bounded, read only the first 64 KiB and the first 10,000
tokens of a command, and run nothing:

- **`shell-write`**: the later shell command writes a file that is one of the refused call's targets. A command is cut
  into tokens outside quotes (single and double quotes, `$'...'`, backslashes, `$(...)`, `${...}` and backticks stay
  inside a word; here-document bodies are skipped; `#` begins a comment) and into simple commands at newlines, `;`,
  `;;`, `&`, `&&`, `||`, `|`, `|&`, `(` and `)`. A simple command writes the target of every output redirection (`>`,
  `>>`, `>|`, `<>`, `&>`, `&>>`, the same with a descriptor number in front such as `2>`, and `>&FILE`; `>&2` writes
  nothing, nor do `/dev/null` and the other device files), and, by its name after leading assignments and the wrappers
  `sudo`, `doas`, `env`, `nohup`, `time`, `command`, `builtin`, `exec`, `nice`, `timeout`, `stdbuf` and `noglob`: every
  operand of `tee`; the destination of `cp`, `mv`, `install`, `ln` and `rsync` (the last operand or `-t DIR`; inside it
  when it is a directory, ends with `/`, or several sources are given); `dd`'s `of=`; the files of `sed -i` and
  `perl -i`; the operands of `touch`, `truncate`, `rm`, `unlink` and `shred`; `curl -o`/`--output` and
  `wget -O`/`--output-document`. `cd DIR` and `pushd DIR` change the directory later relative paths of the same command
  are read from, until the end of the parentheses (a subshell) they are in; `~` and `$HOME` are expanded, and a path
  with another variable or a command substitution is not read. Paths are compared absolute and normalised.
- **`reworded`**: the later shell command is the refused command again with words removed, split or re-quoted. Both
  commands (for a refused file-tool call: its file and the text it would have written) are squashed to lower-case
  letters and digits only, at most 16,384 characters, so quoting, escaping, spacing and a word split with quotes make no
  difference, and cut into shingles of five consecutive characters (the whole text when shorter). With `shared` the
  number of shingles both have, `containment` = shared / the later command's shingles and `coverage` = shared / the
  refused command's shingles, the later command is reworded when containment >= 0.8 and (coverage >= 0.8, or
  (coverage >= 0.2 and shared >= 20), or shared >= 200). Words removed keep containment near 1; each half of a command
  split in two keeps it near 1 with about half the coverage. A command that shares only a short path with a long
  refused command shares too little; one that shares a long path with a short refused command can be taken for
  reworded (a known limit below).

A suspicion names the paths of the later call that matter: for `shell-write` the refused targets it writes, for
`reworded` everything it writes as well, and `(command)` when a reworded command writes no file. Paths a list cannot
hold (more than 1024, or more than 256 KiB) are counted in one `(N more)` item; the paths shared with the refused call
come first. Writes made by an interpreter's own code (`python -c`, a script) are not recognised by `shell-write`; such a
command can still be `reworded`.

### Events

The three kinds are reserved: `EventStore.append()` checks their payloads and their place in the lane's life before
anything is stored, whoever appends them (`lanes.py`). Paths are absolute, `(withheld SHA256)` for a path that looked
like a credential, or `(N more)`; positions are `{"path", "line", "offset", "item"}` (the record, its 1-based line, the
line's byte offset and the index of the call or result in that line).

| Kind | Written by | Payload |
|---|---|---|
| `lane.refusal` | the supervising process (its scanning process), `lane scan`, `lane mark` | `run`, `refusal` (`rf-` and 24 hex digits), `guard`, `kind` (the guard's kind or null), `format`, `via` (`tool-result`, `hook`, or `log` for a text record), `hook` (`event`, `name` of the hook for `via` `hook`, else null), `tool` (or null), `at` (the time in the record, or null for text), `command` (an excerpt of the refused call's command or null), `message` (an excerpt of the guard's message), `targets` (sorted paths), `call` (`id`, `record`: the call's position, or null when the call was not seen; null for text), `record` (the refusal's position), `workarounds_checked` (false for text, or when the call was not seen) |
| `lane.workaround_suspected` | the same | `run` (the later call's), `suspicion` (`ws-` and 24 hex digits), `refusal`, `how` (sorted: `reworded`, `shell-write`), `paths` (sorted, at least one), `tool`, `at`, `command` (an excerpt), `call` (`id`, `record`), `similarity` (`containment`, `coverage`, given exactly for `reworded`) |
| `lane.refusal_reviewed` | `lane review` (actor `supervisor`) | `refusal`, `path`, `verdict` (`clean` or `workaround`), `suspicions` (the suspicions of that refusal naming that path that the verdict covers), `note` (`text`, `sha256` of the note file, or null) |

An **excerpt** is `{"text", "withheld", "length", "sha256"}`: the first 240 characters of the text, its full length and
the SHA-256 of all of it. The credential detector runs over the whole text (up to its 64 KiB bound), and when anything
it finds begins inside those 240 characters, however far away it ends, the excerpt is withheld: `text` is null and only
the length and the hash say what it was; the positions say where to read it. The hash of a short secret can be guessed
by trying candidates, so a record is the place to read what was withheld, not the event. A payload that the detector
still refuses, or that is larger than 512 KiB, is recorded with every excerpt and path withheld.

The ids depend only on where things are: a refusal's on its identity (under "Session records"), a suspicion's on its
refusal, the later call's record and id; a call refused both in its result
and by a hook is one refusal. So the same refusal found again, by a live scan
and a later one, after `state rebuild` or by two scans at once, is the same refusal: `append()` reports it as a
duplicate of the stored event (`"duplicate": true` with that event's id and seq), inside the same transaction that would
store it. `lane.refusal` is allowed for a run that has begun, `lane.workaround_suspected` only for a recorded refusal of
its run or an earlier one, and `lane.refusal_reviewed` only for recorded suspicions of that refusal that name its path;
a verdict never names `(N more)`.

The lane's projection gains `refusals` once the lane has one of these events (rows of lanes without them are unchanged,
so earlier stores need no rebuild): `recorded` (refusal id: `run`, `seq`, `guard`, `tool`), `suspected` (suspicion id:
`refusal`, `run`, `seq`, `how`, `paths`), `verdicts` (each review: `refusal`, `path`, `verdict`, `suspicions`, `seq`)
and `unreviewed` (each refusal and path some suspicion names without a verdict, with those suspicions). A later
suspicion of a reviewed path is unreviewed until it is reviewed too; the latest verdict counts.

### When it runs

- **While a run lives.** When the configuration has guards and the runner names its records, the supervising process
  starts a scanning process beside the run (`refusals.follow`, the same interpreter and installed version, at a lower
  priority), a child of its own that is never taken for a process of the run. It reads the lane's earlier runs once,
  then the run's records again and again, waiting half a second after each look (new files every second), and writes
  each refusal and suspicion it finds to
  the supervising process, whose recorder appends it like the run's other events (with the time the record gives). So
  `lane.refusal` is in the store within a few seconds of the refusal appearing in a record. The control loop never waits
  for it: the scanning process is another process, and a reader thread hands its findings to the recorder.
- **When the run ends**, after its processes are gone, the supervising process records where the run's part of the log
  ends, asks the scanning process for a last pass over the records, to their very end, and stops it, all within seven
  seconds before it queues the end: at most five for the pass, then the process's input is closed, a second later it is
  killed, and half a second after that it is abandoned and reported in `watch.log`, never waited for without end. Its
  findings are recorded before `lane.ended`. A stop or a timeout does the same; a session that went away (SIGHUP) stops
  the scanning process without a last pass.
- **`lane scan --lane L`** reads every record of every run of the lane to its end, appends what is not recorded yet
  (behind the lane's waiting events) and keeps what it covered. It is safe to repeat. While the lane runs it covers the
  running run as far as it has come.
- **`lane mark --state accepted` and `--state merged`** hold the lanes lock that `lane resume` and `lane start --reuse`
  hold, from before they read the lane's runs until their decision is stored, so no run can begin between their scan
  and their decision. They first make sure every run has ended (no run's supervising process lives without its end
  recorded, no recorded process of any run survives, and the latest launch has a run record or an end without
  survivors), then scan the lane as `lane scan` does. They are refused, naming what is wrong, while an event of the
  scan was refused by the store, while events wait
  to be recorded, while a suspicion has a path without a verdict, and while a run that should be scanned is not covered,
  unless `--accept-uncovered` is given: then `lane.state` records what was not covered (`not_covered`: `run`, `reason`,
  `path`). A verdict of `workaround` does not block: the decision stays the supervisor's, and the events say what was
  decided. `--state abandoned` and `verifying` are never held up.

**Coverage.** Every scan merges what it covered of each run into `STATE_DIR/lanes/LANE/scans/LAUNCH.json`, under the
lane's lock, reading the file as it is at that moment: its format number (`format`, 1), the records read for the run
(`path`, `format`, `state`, and counts of `lines`, `unknown_lines`, `other_lines`, `oversized`, `timed_out`,
`cut_results`, `cut_lines` and `outside_runs`), what was skipped (`other_directory`, `before_run`), whether the run had
ended (`complete`), the inventory of every record ever read for the run (real path, the hash of its first line, the
offset read to, the hash of the 4096 bytes before it and its state: the first one other than `covered` saved for it is
kept, a later, different one is not added), and why it is not covered (`not_covered`).
Once not covered, always shown, as long as the coverage file stays readable: a record state other than `covered` is
never taken back by a later scan, and a slower scan that writes last adds to what a faster one found, never replaces it.
A coverage file that exists and cannot be read (not JSON, without this format number or launch, or with any field a
later reader uses of the wrong type, `"inventory": null` for example) is never overwritten: its run is not covered
(`coverage-unreadable`, naming the file), and the refusals the scan finds are still recorded. Deleting or restoring the
file repairs it; `--accept-uncovered` only records what was not covered and leaves the file as it is. The unreleased
builds before this one wrote coverage files
without a format number: delete them. Stores written by earlier unreleased builds of refusal detection are not supported
either (a text refusal's identity changed, so an unchanged old refusal would be recorded a second time): start from a
store without refusal events. The reasons: `no-record` (a configured path that matches no file of the run, for a
run that ran),
`unreadable` (a record or a directory found for the run cannot be read or listed), `missing` (a record in the inventory
whose file is gone), `replaced` (a record that changed under the reader: above), `unrecognised` (a `claude-code` record
whose working directory cannot be told, or in which no assistant or user line was read whole), `partly-read` (a content
block of an unknown type, or a first line that never ended), `refused-zone` (a record whose real path lies in a
directory of the launcher, or a log that is a link or not a regular file), `bad-placeholder`, `template-unusable` (a
template needs a placeholder the run has no value for), `no-session` (a template needs `{session}` and the run's lane
has no session identity), `oversized-line`, `timed-out`, `log-range-unknown` (the run's
part of the log was not recorded), `truncated` (the log is shorter than the end of the run's range, a later run's range
begins before the end of this one's, also before its start, or the live reader saw the log shorter than what it had
read),
`coverage-unreadable`, `too-many-records`, `running` and `not-scanned-to-its-end`. A record that cannot be
read is never taken for "no refusals". `lane refusals` reports the latest coverage of each run (without the inventory),
and `not-scanned` for a run no scan has covered yet.

### Commands

| Command | What it does |
|---|---|
| `lane scan --lane L` | Scans the lane's records again (above). Prints `lane`, `appended` (`refusals`, `suspicions`), `refused_events`, `recorded` (totals), `unreviewed`, `runs` (each run's coverage), `not_covered` (`run`, `reason`, `path`) and `pending_events`. |
| `lane refusals [--lane L]` | Read-only: the lane's `refusals` (payloads with `seq` and their `suspicions`), `suspicions` (with `reviewed`: each path's latest verdict or null), `verdicts`, `unreviewed`, `coverage` (each run's latest), `not_covered`, `guards` (how many are configured) and `pending_events`; a list of these without `--lane`. |
| `lane review --lane L --refusal ID --path P --verdict clean\|workaround [--note FILE]` | Records the supervisor's verdict on one path of a refusal's suspicions: every suspicion of that refusal that names the path. A relative path is read from the lane's working directory. The note is read from a file (at most 4000 characters, UTF-8) and refused when it looks like a credential. |

### Left for later

Telling the owner about refusals and suspicions through the owner channel, a judge that reads suspicions, the record
formats of other agent programs and other text files, and changing a guard's own rules. Also: the acceptance decision
made atomic with every coverage writer, a bound on the whole scan (while `lane mark` holds the lanes lock) and on
directory listing, `partly-read` only for blocks inside the run's window, holding the gate for refusal events the store
refused in earlier scans, and comparing records found late with calls already decided.

## Resources and cost

Designed, not built: this section is a design for what a lane holds outside the machine the launcher runs on, and for
what that costs. No command, event, key, state, file or module named here exists in the launcher yet, and nothing outside
this section says that one does. Four steps build it, named A to D; each part below names the step that builds it, and a
step turns its part from design into description in the commit that builds it. What a sentence says about the launcher as
it is today is checked against the code and the documents at commit 2995b7c, the base of this design. Where this section
names one of its own parts in quotation marks, for example "Open points", it means the part of this section: the section on
turns has parts of the same names.

| Step | Builds |
|---|---|
| A | The core: the event kinds `resource.intent`, `resource.acquired`, `resource.failed` and `resource.released`, their checks at append and in `state verify` and `state rebuild`, the fold, the modules `resources.py`, `adapters.py` and `resourcecmd.py`, the commands `resource acquire`, `describe`, `release`, `check`, `list` and `show`, the table `[resources.NAME]` with its validation and its `doctor` check, the listing in `lane check`, and the gate at `lane mark` with `--accept-held` and the `held` field of `lane.state`. |
| B | Adapters: the stand-in adapter for tests, `tests/e2e/resourcestandin.py`, with the contract tests that every adapter passes, and the real cloud adapter under `integrations/aws/` with its generic idle guard and its own page. B delivers the stand-in first, because A is tested against it. |
| C | Cost: the event kind `resource.cost`, the arithmetic, its append after every release, the command `lane cost` and the report against `[cost]`. |
| D | The credential-scope example: an adapter of kind `credential` under `integrations/gcp/`, with its own page. |

The order of the builds is the stand-in of B, then A, then the cloud adapter of B, then C, then D. A, the stand-in and C
are tested on a test machine with nothing else; the real cloud adapter and the credential-scope example each need the
written approval of the person who owns the cloud account before their one real trial ("The test plan").

### Purpose and the picture

The launcher records what a lane does. It does not record what a lane **holds** outside this machine (a rented test
machine, a narrowed cloud credential) or what that costs. A lane that ends while its machine still runs is billed until
somebody notices, and a launcher that believes a machine is released while the provider still runs it is the failure
this design exists to prevent.

A **resource** is one thing a lane holds, made and ended by an external command, an **adapter**, that a configuration
names. The launcher gives the resource an id, appends an **intent**, asks the adapter to acquire it, and records the
answer. It records a release only after it has read back from the provider that the resource has ended. It lists every
resource that is still held whenever a lane is checked, and it refuses to accept or merge a lane that holds one unless the
supervisor says so, and the record then says what was held. The cost of a resource is its price times the time it was
held, recorded at release in whole micro-units of a currency. The core knows no provider: every value that belongs to a
company lives in an adapter and in the adapter's configuration file, which the company keeps outside the repository.

### The design in brief

These statements are fixed; the parts that follow work them out.

- **A resource is recorded before it exists.** `resource.intent` is appended before the adapter is asked to acquire.
  `resource.acquired` follows with the provider's own id, `resource.released` only when a read-back shows that the provider
  has ended the resource, and `resource.failed` when the acquire failed. An intent that has neither `resource.acquired`
  nor `resource.failed` after the acquire bound is a finding, never a resource that is taken for gone.
- **Providers are adapters, like judges.** `[resources.NAME]` in a configuration names an external command. The launcher
  asks it to `acquire`, `describe` and `release`, with one JSON object on its standard input and one JSON object on its
  standard output, as `docs/judges.md` has it for a judge: exit status 0, a bounded time, a bounded size, and no answer is
  never made up. Credentials are named, a profile or a variable name, and never held: nothing secret is in an event, a log, a
  configuration or a brief.
- **Nothing outlives its lane silently.** `resource check` lists every resource whose run has ended, whose hard cap has
  passed or whose read-back says `absent` for a resource that the events say was acquired, and it always reports
  (`resource describe` also reports a resource that the events call ended and the provider still shows running). `lane check`
  only lists, from events, with no call to an adapter, so it stays safe to run from a timer. An adapter is called only by
  `resource describe`, `resource release`, `resource acquire` and `resource check --read-back`.
- **The gate.** `lane mark --state accepted` and `--state merged` refuse while a resource of the lane is not confirmed
  released, on every configuration, with guards or without, under the lanes lock, before the refusal scan. The override is
  `--accept-held`, and the decision then records what was held.
- **Cost is a recorded fact.** At release, price times held time, with the price's source, as an integer number of
  micro-units and a currency. A float cannot hold the exact product of a price and a time, so money is whole micro-units:
  the forms accept only an `int`, and money is never a float and never a string to parse. An agent run's cost is absent
  until a reader records it as an event (the stream readers of `lane attach` show a cost on the screen and record
  nothing), and is never guessed.
- **Examples, not core.** The cloud adapter is under `integrations/aws/` and the credential-scope example under
  `integrations/gcp/`. The core imports neither. Every value that is specific to a company comes from an adapter
  configuration file that the private configuration keeps, and the idle guard the cloud adapter installs is a generic copy
  kept in the repository.
- **A resource ends through its own end.** The cloud adapter launches a machine that terminates when it shuts down, with
  a hard cap and an idle guard, and its `release` asks the machine to end by its own path. A release therefore answers
  `releasing`, never `released`, and the launcher writes `resource.released` only after a `describe` shows the provider's
  terminated state. A machine that does not end within its cap is reported, and the person decides.
- **No new table.** Resource state is folded from events whenever it is read. The lane projection and the schema do not
  change.
- **One more rule binds every part.** An ordinary mistake (a wrong variable, a file removed by hand, a process killed, a
  second command at the same time) is blocked or reported, and two unusual things at once are in "Known limits of this
  design". A loss the launcher can see is never counted as done: a resource it cannot read back is `unknown`, never
  released. The package version is not changed by this design, and the suite passes with nothing set from outside the
  tests.

### Where the code changes

Marked designed, as the "Layout" table marks its own rows. The fold lives in one new module so that `lanes.py` stays free of
resources and the lane projection is not touched.

| Path | Change (designed) |
|---|---|
| `src/laneboss/resources.py` (new, A; the cost arithmetic C) | Pure code, no input or output: the grammars and payload forms of the `resource.*` kinds, `check()` (a payload alone), `check_transition()` (a resource event against the lane's row and the fold), `check_state()` (a `lane.state` that accepts or merges, against the fold), `fold()` (events to one record per resource), `held_of()` (the one definition of held), `standing()` (the reasons a held resource is listed) and `replay()` (the checks of append, replayed over a whole store, except that it leaves alone a `lane.state` that names a protocol version older than step A's: the version test of "Events"). |
| `src/laneboss/adapters.py` (new, A) | The launcher's side of the adapter contract: the request of each operation, the resolution of the program, the minimal environment, the bounded call (`judges.run_command()`, unchanged) and the strict reading of an answer, with the screens for the credential variable's value. |
| `src/laneboss/resourcecmd.py` (new, A; `lane cost` C) | `laneboss resource`: `acquire`, `describe`, `release`, `check`, `list` and `show`, and the release flow that `resource check --read-back` shares. |
| `src/laneboss/events.py` | `validate_envelope()` calls `resources.check()` for a kind that starts with `resource.`. `EventStore._append()` calls `resources.check_transition()` for those kinds and `resources.check_state()` for a `lane.state` that accepts or merges, whatever protocol version it names, inside the transaction that stores the event, reading the lane's row and every stored `resource.*` event of the lane. `rebuild()` and `_verify()` call `resources.replay()` after `lanes.fold()`. A new reader, `EventStore.resource_events(lane=None)`, returns the stored `resource.*` events (those of one lane when it is given), hash-checked and form-checked as `lane_events()` does. Nothing is written to the `lanes` table for a resource event. |
| `src/laneboss/lanes.py` | `check()` accepts the optional `held` key of `lane.state`, and `_consistent()` allows it only with `accepted` or `merged` and only when it is not empty. `check_transition()` and `apply()` do not change. |
| `src/laneboss/config.py` | A table `RESOURCE` and the key `resources` in `CONFIG`; a function `adapter_command()` that applies the rules of `judge_command()` with a message of its own; `command_elements()` also yields `resources.NAME.command`, so that `check_tools_not_shared()` and `doctor` cover it; the cross rule between `acquire_bound_minutes` and `acquire_seconds`. `[cost]`, `[test_environments]` and `{machine}` do not change. |
| `src/laneboss/cli.py` | The parser and the handler of `resource`; `lane mark --accept-held`; `lane cost` (C). |
| `src/laneboss/doctor.py` | One check, `resource.NAME`, for each configured adapter. |
| `src/laneboss/lanecmd.py` | `check()` adds the listing; `decide()` runs the resource gate before `gate()`, for accepted and merged, and `mark()` refuses `--accept-held` for any other decision; every output of `lane mark` gains `held`; `clean()` and `start()` (with `--reuse`) refuse while the lane holds a resource. |
| `tests/e2e/resourcestandin.py` (new, B) | The stand-in adapter. |
| `integrations/aws/`, `integrations/gcp/` (new, B and D) | The cloud adapter with its idle guard and page, and the credential-scope example with its page. The core imports neither. |

The state directory gains no file: there is no resource lock, no resource log and no pending file for resource events
(see "Resource events are never queued").

### The resource model (built by A)

**Identity.** A resource's id is `rs-` and 24 lower-case hexadecimal digits (`rs-[0-9a-f]{24}`), the family of the ids of
refusals and suspicions. The launcher makes it from 12 bytes of the operating system's random source, before anything
else is done for the resource, and never derives it from a lane, a time or an earlier id. It is the key of the resource
everywhere: the member `resource` of every `resource.*` event, the tag or name the adapter puts on the machine, and the key
of the fold. The launcher makes it before the adapter runs, and hands it to the adapter, for three reasons. The intent can
carry it, so that a record of the resource exists before the machine can. The adapter can use it as the key that makes its
`acquire` idempotent. And a machine whose acquire answer was lost (a launcher killed, an answer that was malformed, a store
that was busy) can still be found: the adapter **must tag or name the machine with the id**, so that `describe` finds it by
the id alone and not by anything the launcher had to learn from the answer. Without that rule a lost answer is a machine
that nobody can find.

The launcher also hands the adapter the lane's name, with the grammar of a lane name (`[a-z0-9][a-z0-9._-]{0,63}`), so
that what the adapter makes can carry it, as the shared protocol asks of every machine. The characters that can reach a
cloud tag or label are these: the id has lower-case letters, digits and hyphens and starts with a letter; the lane name has
lower-case letters, digits, `.`, `_` and `-`; the purpose has letters, digits and `. _ : / + -`. Not every provider accepts
every one of them: a label that forbids `.` cannot hold a lane name that has one. The id is the one value that fits every
such rule, so an adapter looks a resource up by the id alone, writes the lane name and the purpose only where its provider
allows them, and converts a character it must (the conversion is the adapter's, and no `describe` depends on it).

**States and readings.** Three kinds of word describe a resource, and only the first kind is an event.

| Word | What it is | Held |
|---|---|---|
| `intent` (intent only) | The fold: an intent, and neither `resource.acquired` nor `resource.failed`. | yes |
| `acquired` | The fold: `resource.acquired` and no `resource.released`. | yes |
| `failed` | The fold: `resource.failed`. | no |
| `released` | The fold: `resource.released`. | no |
| `releasing` | A reading: the adapter answered `releasing` to a `release`. It says that the adapter did not fail, and nothing else. The fold still says `acquired`. | yes |
| `unknown` | A reading: a `describe` gave no usable answer (none, or one the launcher refuses). The fold is unchanged. | yes |
| `absent` | A reading: a `describe` answered `absent`. For a resource that has `acquired` it never closes anything: the fold is unchanged. | yes |
| `held-beyond-cap` | A standing: the resource is held and the launcher's clock is after the resource's `cap_at`. | yes |

**The fold.** `resources.fold()` reads the stored events whose kind starts with `resource.`, in `seq` order, and nothing
else, and keeps one record for each resource id. An event's time is its `occurred_at` when given, else its `recorded_at`,
as for lane events. By kind:

- `resource.intent` makes the record: `lane`, `run`, `kind`, `provider`, `purpose`, `size`, `region`, `price`,
  `hard_cap_minutes`, the `seq` of the event and its time (`intent_at`). The state is `intent`.
- `resource.acquired` adds `provider_id`, `started_at`, `found_by`, `request`, the `seq` and the time (`acquired_at`). The
  state is `acquired`.
- `resource.failed` adds `how`, `reason`, the `seq` and the time. The state is `failed`.
- `resource.released` adds `how`, `read_back`, the `seq` and the time (`released_at`, the `at` of its `read_back`). The
  state is `released`.
- `resource.cost` adds `started_at`, `ended_at`, `price` and `cost`. The state stays `released`.

The state of a record is the last of these that was applied, in the order intent, acquired, released, or intent, failed. The
checks at append let no store hold another order, so the fold has no rule for one, and `replay()` reports one as an
integrity problem. Two values are derived from a record and are not stored: `start`, which is `started_at` when the record
has one and else `intent_at` (so a resource whose provider gave no start is held from its intent, and never costs less than
it ran), and `cap_at`, which is `start` plus `hard_cap_minutes`. A released record has a third, `end`, which "Cost" defines.

**What held means.** A resource is **held** when its fold state is `intent` or `acquired`. `resources.held_of()` is the one
function that says so, and the gate at `lane mark`, the listing of `lane check`, `resource check`, `resource list --held`
and the check of `check_state()` at append all call it. Nothing else changes the answer: not the state of the lane, not
events of the lane that wait in a pending file, not a read-back, not the clock. A read-back is evidence for an event, and
only the event makes a resource not held. A resource whose intent is stored and whose adapter has not answered is held:
the machine may exist.

**Why a held resource is listed.** `resources.standing()` takes a record, the lane's row, the configuration and the clock
and returns the reasons for which a held resource is a finding. A held resource with no reason is listed as held and is
not a finding.

| Reason | When |
|---|---|
| `lane-ended` | The lane's row says that no run is going on (`running` false) and its `run` is at least the resource's `run`: the run that held the resource, and every run after it, has ended. While a later run goes on (after a `lane resume`), the resource is not `lane-ended`: that run may still use it. |
| `held-beyond-cap` | The clock is after `cap_at`. |
| `unresolved` | The state is `intent` and the clock is after `intent_at` plus the adapter's `acquire_bound_minutes` (15 when the configuration has no such adapter any more). |
| `adapter-missing` | The configuration has no `[resources.NAME]` for the resource's `provider`. |
| `unknown` | Only with a read-back (`resource describe`, `resource check --read-back`): the `describe` gave no usable answer. |
| `absent` | Only with a read-back: the provider says it has nothing for the id, though the events say the resource was acquired. |
| `disagrees` | Only with `resource describe`: the resource is `released` or `failed` and the provider shows it `running`. This one is a finding for a resource that is not held. |
| `cost-missing` | Step C: the resource is `released` and has no `resource.cost`. This one is a finding for a resource that is not held. |

**A reused lane.** `lane start --reuse` gives a merged or abandoned lane new run numbers under the same name, and it is
refused while the lane holds a resource ("Commands"), so a reuse begins when every resource of the old life is released or
failed. A resource of the old life is kept apart from one of the new by its id, which no intent ever repeats, and by its
`run`. The gate, the listing and `lane cost` look at the lane's name and every run, so the resources of both lives are one
list.

**What identifies a resource across `state rebuild`.** Nothing but events: the `resource` member of its `resource.intent`.
`rebuild()` writes nothing for resources, because they have no row; it replays them and refuses to replace the lane rows when
the replay fails.

**Held, and the lane's waiting events.** A resource whose `resource.acquired` is stored is held whatever else is true of its
lane. When the lane's `lane.ended` is still in a pending file, the store says the lane is running, so `lane-ended` is not
claimed for the resource, and the listing says how many events of the lane wait (`events_waiting`); the resource is listed
as held all the same. `lane check` appends the lane's waiting events before it lists, as it does today, so after it the end is
in the store when the store can take it. `lane mark` appends them first (`drain()`) and is refused while some cannot be
appended, so a lane whose end waits cannot be accepted or merged past the gate. `resource check` without `--read-back`
appends nothing, so it reports the waiting events and does not make them visible.

**Resource events are never queued.** No resource event goes to a lane's pending file, and `EventStore.append()` does not
make one wait for the lane's waiting events: `lanes.is_lane_event()` is false for them, so the check of `lane_waiting()`
(`events.py:415-424`) is not made. A resource command is a foreground command. It waits for a busy store at most 10 seconds,
as every lane command's append does, and when the store cannot take an event it ends with exit 1 and says what is in doubt
("Commands"). A queued `resource.acquired` would be invisible to the gate, to `lane check` and to `resource check` while its
machine runs, which is a way around the gate. The order of the events makes a queue unnecessary: the intent is stored before
the adapter runs and counts as held, so a machine whose `acquired` could not be stored is a held `intent`, listed as
`unresolved` once the acquire bound has passed, and found again by `resource check --read-back`.

### Events (built by A; `resource.cost` by C)

Five kinds join the reserved kinds, with one optional key of `lane.state`. Like `lane.*` and `brief.rendered`, they are
checked against what the launcher itself writes before anything is stored, whoever appends them, `event append` included.
A kind that starts with `resource.` and is not one of the five is refused. Paths, ids and times have the grammars of the
envelope and of the lane events (`events.py:28-35`, `lanes.py:65-66`). Identifiers in these payloads are
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` (the grammar `docs/judges.md` gives to `model` and `request`), and a value that the
credential detector refuses is never stored. Money is the object `{"amount_micros", "currency"}`: `amount_micros` is a whole
number from 0 to 9007199254740991 (so that even a reader that parses numbers as doubles reads it exactly) and `currency` is
three capital letters. It is never a float and never a string.

| Kind | Written by | Actor |
|---|---|---|
| `resource.intent` | `resource acquire`, before it asks the adapter to acquire | `laneboss` |
| `resource.acquired` | `resource acquire` (`found_by` `acquire`); `resource describe`, `resource release` and `resource check --read-back` (`found_by` `describe`) | `laneboss` |
| `resource.failed` | `resource acquire` (`how` `adapter`); `resource release` (`how` `release`) | `laneboss` |
| `resource.released` | `resource describe`, `resource release` and `resource check --read-back` | `laneboss` |
| `resource.cost` (C) | the commands that append `resource.released`, right after it; `resource describe` and `resource check --read-back` when they find a released resource without one | `laneboss` |

Every `resource.*` event has the `lane` of its resource. The time of an event, its `occurred_at`, is the moment the launcher
did the thing: the intent when it was decided (before the adapter is called), `acquired` and `failed` when the answer was
read, `released` when the read-back showed the end, `cost` when it was computed.

| `resource.intent` member | Form |
|---|---|
| `resource` | `rs-[0-9a-f]{24}`. |
| `run` | A whole number from 1 to 1000000: the run of the lane that the resource belongs to. |
| `kind` | `[a-z][a-z0-9-]{0,31}`: what the resource is, from the adapter's `kind` key. |
| `provider` | `[a-z0-9][a-z0-9-]{0,31}`: the name in `[resources.NAME]`. |
| `purpose` | `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`: why, as the caller gave it. |
| `size`, `region` | Each `null`, or `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}` (a size) and `[a-z0-9][a-z0-9-]{0,31}` (a region): what the adapter's quote reported ("The adapter contract"). |
| `price` | `null`, when no price is known (the cost will be absent), or `{"per_hour": money, "source": "adapter" or "configured"}`. |
| `hard_cap_minutes` | A whole number from 1 to 10080. |

| `resource.acquired` member | Form |
|---|---|
| `resource` | The id of a resource that has an intent. |
| `provider_id` | `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}`: the provider's own id. |
| `found_by` | `acquire` (the adapter's answer to the acquire) or `describe` (a read-back found a machine that had an intent and no `acquired`). |
| `started_at` | `null`, or a timestamp: when the provider says the resource began. |
| `request` | `null`, or an identifier: the provider's own request identifier. |

| `resource.failed` member | Form |
|---|---|
| `resource` | The id of a resource that has an intent. |
| `how` | `adapter` (the adapter answered `failed`) or `release` (`resource release` closed an intent for which the adapter and a read-back found nothing, "Commands"). |
| `reason` | `[a-z][a-z-]{0,39}`: the adapter's own code, or `absent` for `how` `release`. |
| `request` | `null`, or an identifier. |

| `resource.released` member | Form |
|---|---|
| `resource` | The id of a resource that has `acquired`. |
| `how` | `release` (the command that wrote the event had asked the adapter to release the resource, on a person's request), `by-itself` (the same, asked by `resource check --read-back` because the adapter's `release_by_itself` is on) or `observed` (the command found the resource already ended, without asking: by its own cap, its guard, its done path, or a release by another command). |
| `read_back` | `{"at", "state", "provider_state", "ended_at", "request"}`: `at` is a timestamp, the moment the read-back showed the end; `state` is exactly `terminated`, so an event that carries any other state is refused, which is how "only when the read-back confirms it" is in the form; `provider_state` is an identifier, the provider's own word; `ended_at` is `null` or a timestamp, when the provider says the resource ended; `request` is `null` or an identifier. |

| `resource.cost` member (C) | Form |
|---|---|
| `resource` | The id of a resource that is `released`. |
| `started_at`, `ended_at` | Timestamps: the start and the end of the held time ("Cost"). |
| `price` | The `price` of the resource's intent, copied. |
| `cost` | `null` when `price` is `null`, else money in the price's currency. |

| Optional key of `lane.state` | Form |
|---|---|
| `held` | A list of 1 to 256 items `{"resource", "state"}` sorted by `resource`, without repeats: `resource` is an id, and `state` is `intent` or `acquired`, the fold state of that resource when the decision was made. Allowed only when `state` of the `lane.state` is `accepted` or `merged`. Written by `lane mark --accept-held`. |

**Checks at append.** `EventStore.append()` runs them inside the transaction that stores the event, against the lane's row
and the fold of every stored `resource.*` event, whoever appended the event.

| Kind | Refused unless |
|---|---|
| every `resource.*` kind | `lane` is given and the store knows the lane (it has a `lane.*` event); the payload has exactly its members, each in its form; a resource id is only ever used with the lane of its intent. |
| `resource.intent` | No stored resource has this id; `run` is a run of the lane (from 1 to the `run` of the lane's row); the lane's state is not `merged` or `abandoned`; the lane holds fewer than 256 resources (the bound of `held` in `lane.state`, so that every lane can still be accepted). |
| `resource.acquired` | The fold has an intent with this id and no `acquired`, `failed` or `released` (so one `acquired` for each intent). |
| `resource.failed` | The fold has an intent with this id and no `acquired`, `failed` or `released`. |
| `resource.released` | The fold has this resource with an `acquired` and no `released` (so a failed resource, or one that never was acquired, is never released). |
| `resource.cost` | The resource is `released` and has no cost yet; `price`, `started_at` and `ended_at` equal what the fold gives, and `cost` equals the arithmetic of "Cost". |
| `lane.state`, `accepted` or `merged`, whatever `protocol_version` it names | `held` lists exactly the lane's held resources, each with its state, and is absent when the lane holds none. Only the replay leaves alone a `lane.state` that names an older version (below). |

Nothing is accepted after `released` except its one `resource.cost`, and nothing after `failed`. A resource of a merged or
abandoned lane can still be acquired, failed, released and costed by the events that were due; only a new intent is
refused. The last rule is what closes two ways around the gate: a hand-written `lane.state` through `event append`, which
`lanes.check_transition()` allows today without any condition (it has no rule for `lane.state`, `lanes.py:451-475`), and a
resource acquired between the gate's reading and its decision, a second command at the same time: the gate reads the fold
under the lanes lock, and the store reads it again in the transaction that stores the decision.

**The version test of that rule, in the replay alone.** `append()` checks every `lane.state` that accepts or merges against
the fold, whatever protocol version it names. An event's version is whatever its writer puts there (the envelope checks only
its grammar, `events.py:32` and `136`), and every event that the launcher writes today carries 1.1.0, so an exemption by
version at append would let a hand-written `lane.state`, copied from any event that exists, accept or merge a lane that
holds a resource with no `held`. Nothing needs that exemption at append: at this version no launcher can queue a
`lane.state` of an older version, because `lane mark` appends through `Session.append`, which calls
`pending.append_after()`, and that function appends at once or refuses and never writes a pending file (`lanecmd.py:155-159`
and `1133`, `pending.py:252-272`). The replay is the one place that needs it. `resources.replay()` compares the
`protocol_version` of each `lane.state` that accepts or merges with the version that step A's `protocol.md` carries, as
three whole numbers and not as text, and leaves alone an event that names an older version, because an older launcher had no
gate. A store that holds a resource event is read by 0.5.0 (trigger (a) of "Compatibility"), and 0.5.0 accepts or merges a
lane that still holds a resource, writing a `lane.state` that has no `held` and the protocol version of its own time. That
event is true to what its producer did. A replay that failed on it would make `state verify` and `state rebuild` fail with
exit 3 for the whole store after a relink forward, and because no command edits or removes an event, the only way out would
be a new store. An event is not refused for the absence of a gate that its producer did not have; and `append()` has no such
event to take in, because no launcher of this version writes one.

**The envelope's rules.** Every key and string of a resource event goes through the credential detector before anything is
stored (`validate_envelope()`, `events.py:119-121`), and the payload is at most 1 MiB (`events.py:146-147`); a resource
payload is under 2 KiB. All numbers are whole numbers, and the forms accept only a value of the type `int`, as
`lanes.integer()` does, so `1.0` and `true` are refused. A hand-written file passes through `jsonutil.parse()` first, which
refuses a number with a fraction or an exponent that is not exactly a double (`jsonutil.py:25-31`) and an integer of more than
4,300 digits (`jsonutil.py:34-41`): the money form, a whole number below 2^53, never meets either rule. That refusal is for
decimal text only. A launcher command's own append passes a Python float, which is always exactly a double, and
`validate_envelope()` checks only that it is finite (`events.py:105-112`, `144-145`). So what keeps money whole is the form,
which accepts only an `int`, and not the envelope.

**What `state verify` and `state rebuild` do.** They check a resource event like a lane event; each function has its part.

- `validate_envelope()` (`events.py:115`): the envelope, and for a kind that starts with `resource.` the call of
  `resources.check()`: the payload's form and the rules inside one payload (for example, a cost without a price has no
  amount). The rule on the `held` key of `lane.state` is a rule of the lane kinds, not of this call: `validate_envelope()`
  calls `lanes.check()` for every `lane.*` kind (`events.py:148-149`), and `lanes.py` holds the rule ("Where the code
  changes"). `rebuild()` and `_verify()` call `validate_envelope()` for every stored event (`events.py:544-546` and
  `601-605`), as for the lane kinds.
- `EventStore._append()` (`events.py:428`): `resources.check_transition()` and `resources.check_state()`, as above.
- `resources.replay()`, called by `rebuild()` and by `_verify()` after `lanes.fold()` (`events.py:547` and `616`): one pass over
  every stored event in `seq` order, keeping for each lane a private projection that `lanes.apply()` builds from its lane
  events (the checks need only its `run` and its `state`) and the fold of the resource events so far, and applying
  `check_transition()` to each resource event and `check_state()` to each `lane.state` that accepts or merges, except one that
  names a protocol version older than step A's, which it leaves alone (the version test, above). The first event that fails
  is an integrity problem (exit 3) that names its `seq`, as `lanes.fold()` reports its own.
- `rebuild()` replaces the `lanes` rows only after the replay has passed, so a store whose resource events `state verify`
  rejects is not rebuilt. `rebuild()` checks hashes, envelopes and the lane fold only (`events.py:539-547`), and `state
  rebuild` calls it without `verify` (`cli.py:316-317`); the sequence, the schema, the metadata, `recorded_at` and the kept
  inputs are `_verify()`'s (`events.py:566-621`), and the replay is added to both. It writes nothing for resources.
- `state verify` also prints `resources`, the number of resources that have an intent. The schema check
  (`events.py:572-581`) is unchanged, because the schema is.

So a stored resource event that `append()` would refuse is an integrity problem for all three, never an internal error. A
binding that only a hand-made store can break (an event of a lane that no `lane.*` event ever made) is caught by
`replay()` too, because the replay has the lane's events before it. The one exception belongs to the replay alone: it does
not check the `held` of a `lane.state` that names a protocol version older than step A's against the resources, by the
version test above, where `append()` would.

### The adapter contract (the launcher's side built by A, the adapters by B)

An adapter is an external command that a configuration names (`[resources.NAME]`, "Configuration"). The launcher runs it
once for each operation it needs, writes one JSON object to its standard input and reads one JSON object from its standard
output. The contract mirrors the judge contract of `docs/judges.md` ("The judge contract", "How the launcher reads the
contract") and departs from it only where a resource differs from a question: what an adapter does changes something
outside this machine, so its answer is held to a stricter form, it runs with a smaller environment, and what was asked of
it is recorded by events and not by a log.

**Operations.** There are three, `acquire`, `describe` and `release`, and one command serves all of them, told apart by the
member `operation` of the request: they share the resource's id, its credential and its tags, and three commands would have
to be kept in step by a configuration. An acquire has two forms, told apart by the boolean member `dry_run`. With `dry_run`
true it creates nothing and answers what it would create and what that costs: this is the **quote**. With `dry_run` false it
creates: this is the **acquire**. The quote exists because the intent event is appended before anything exists and carries
the size, the region and the price per hour (the cost basis, fixed when the launcher decides), so the adapter has to be
asked for them first. A quote changes nothing at the provider and may be repeated any number of times.

**The request.** One object in ASCII-safe JSON (a character outside ASCII is escaped), on one line, with the members in the
order of the table and a final newline. Each member is present exactly where the table says so, and no other is sent.

| Member | Type and bound | In `acquire` | In `describe` and `release` |
|---|---|---|---|
| `laneboss_resource` | The whole number 1: the version of the contract. | yes | yes |
| `operation` | `acquire`, `describe` or `release`. | yes | yes |
| `id` | `rs-[0-9a-f]{24}`: the resource's id, made by the launcher before the adapter runs. | yes | yes |
| `lane` | `[a-z0-9][a-z0-9._-]{0,63}`: the lane's name, for the adapter to put on what it makes (the shared protocol asks that every machine carries it). | yes | no |
| `kind` | `[a-z][a-z0-9-]{0,31}`: the configuration's `kind`, `machine` or `credential`. | yes | yes |
| `profile` | `null`, or `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`: the configuration's `credential_profile`. | yes | yes |
| `purpose` | `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`. | yes | no |
| `size` | `null`, or `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`. | yes | no |
| `region` | `null`, or `[a-z0-9][a-z0-9-]{0,31}`. | yes | yes |
| `hard_cap_minutes` | A whole number from 1 to 10080. | yes | no |
| `dry_run` | `true` or `false`. | yes | no |
| `provider_id` | `null`, or `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}`. | no | yes |
| `timeout_seconds` | A whole number from 1 to 900: the time-out of this operation, `acquire_seconds` for the quote and the acquire, `describe_seconds` for a describe, `release_seconds` for a release. | yes | yes |

The values: in a quote, `size` is what the caller asked for with `--size`, or `null`, and `region` is `null`. In the acquire,
`size` and `region` are exactly what the quote answered and what the intent records, so the adapter creates what was
recorded. In `describe` and `release`, `region` is the intent's, and `provider_id` is the one of `resource.acquired`, or
`null` while the resource has none. `timeout_seconds` is the launcher's own deadline for the call, told to the adapter so
that the adapter keeps it too ("How the launcher bounds the command"). Nothing else is sent: no text of a brief or of the
lane's work, no other lane's name, no path and no credential, which reaches the adapter only through its environment. A
request is at most 16 KiB. The grammars keep it under 1 KiB, so no request the launcher builds comes near the bound; it is
the number an adapter may rely on for how much it must be ready to read, and a request that would pass it is refused before
anything is run (exit 2). As for a judge, the launcher sends the whole request and closes the adapter's standard input, and
an adapter that does not read its input is not an error.

**The answer.** One object on standard output, with exit status 0. Its members depend on the operation and on the `state`
it reports. Every member listed for a state is required, and no member that is not listed is allowed except `request`.

| Operation | `state` | Required members besides `state` |
|---|---|---|
| `acquire`, `dry_run` true | `quoted` | `size`, `region`, `price_per_hour_micros`, `currency`, `price_source` |
| `acquire`, `dry_run` true | `failed` | `reason` |
| `acquire`, `dry_run` false | `acquired` | `provider_id`, `started_at` |
| `acquire`, `dry_run` false | `failed` | `reason` |
| `describe` | `running` | `provider_id`, `provider_state`, `started_at` |
| `describe` | `terminated` | `provider_id`, `provider_state`, `started_at`, `ended_at` |
| `describe` | `absent` | none |
| `release` | `releasing` | none |

| Member | Type and bound |
|---|---|
| `state` | A string from the table. It is the contract's word. |
| `provider_id` | `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}`, never `null`: the provider's own id. |
| `provider_state` | `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`: the provider's own word for what it shows. The launcher records it in `read_back` and acts on `state` alone. |
| `started_at`, `ended_at` | `null`, or a timestamp in the grammar of the envelope's `occurred_at` (`events.py:33-34`): when the provider says the resource began and ended. Times are compared as instants. |
| `size` | `null`, or the grammar of `size` above: what the acquire will create, `null` for a kind that has no size. |
| `region` | `null`, or the grammar of `region` above. |
| `price_per_hour_micros` | `null`, or a whole number from 0 to 1,000,000,000 (1,000 units an hour, so that a cost cannot pass the bound of `amount_micros` in a thousand years). |
| `currency` | `null`, or three capital letters. |
| `price_source` | `null`, `adapter` (the adapter took the price from the provider when it was asked) or `configured` (it took it from its own configuration file). |
| `reason` | `[a-z][a-z-]{0,39}`: the adapter's own code for why it did not create, for example that the provider has no capacity. A code, never a sentence, and not a closed list. |
| `request` | Absent (read as `null`), `null`, or `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`: the provider's own request identifier. |

The three price members are `null` together or set together, and a kind that has no price answers three `null`s. Only the
quote has a price: the intent carries it and the cost copies it ("Cost"), so a price member in any other answer would have
no reader, and is a member that is not in the contract. The price of a quote is the price per hour of one resource of the
size and in the region that the quote names.

**What the states mean.** `running` means that the provider still holds the resource in any state before its end, a
stopped machine included (a machine that is pending, stopping, stopped or shutting down is `running`). `terminated` means
that the resource has ended and been collected: for a machine, terminated with its volume deleted; for a credential,
revoked or expired. `absent` means that the adapter looked in the request's region ("What an adapter puts on what it
makes") and found nothing under the id. An adapter answers `terminated` only when the provider shows the end, and the
launcher cannot check it ("What this cannot see").

**What is no answer.** The launcher reports the adapter as unavailable for the operation, with one of the four reasons of
a judge (`timeout`, `exit`, `output` or `not-found`, `docs/judges.md`, "Asking", step 6), and never invents an answer, for
any of these:

- a non-zero exit status or an end by a signal, even when a valid object was printed; no end within the operation's
  time-out; a program that cannot be started;
- standard output that is not exactly one JSON object: white space before and after the object is allowed (a final newline
  included, as for a judge, `docs/judges.md:46`), and any other text is not; nor are a second object, bytes that are not
  UTF-8, or more than 64 KiB (an oversize answer is refused whole, never cut);
- a repeated member; a member that is not listed for the operation and the state; a listed member that is absent. There is
  no default for a required member: an absent one is refused exactly like an unreadable or a malformed one, and the launcher
  never reads an absent `state` as `absent`, an unreadable answer as `failed`, or silence as anything;
- a member of the wrong type, outside its grammar or its bound; a number with a fraction or an exponent anywhere (money is
  whole micro-units, because a float cannot hold the exact product of a price and a time, and the forms accept only an
  `int`); a `state` that the operation does not allow, such as `quoted` for an acquire with `dry_run` false, or
  `releasing` for a describe;
- three price members of which some are `null` and some are not;
- in a describe, a `provider_id` that differs from the request's when the request's is not `null`: two resources under one
  id is a fault that a person has to see;
- a string member that the credential detector refuses, or that contains the value of the credential variable (how short
  that value may be for the search is an open point). Nothing of such an answer is printed or recorded.

The reasons are worded by `judges.describe()` (`judges.py:400-407`), and `output` covers every refusal of the form.

**Standard error.** As for a judge ("How the launcher reads the contract"): the first non-empty line, cut to 300
characters, with control characters replaced by `?`, screened by the credential detector as a whole and as cut, and shown
only by the command that made the call, in its own message, never written to an event or to any file. The function is
`judges.explanation()` (`judges.py:245-255`), shared unchanged. `adapters.py` adds one screen before the line is shown, in the
manner of `explanation()`: the first non-empty line as it was written, and the text that would be shown (its first 300
characters), are each searched for the value of the credential variable, and either one that contains it is replaced by
`[withheld]`. The raw line is searched as well because a value that starts before the 300th character and ends after it
would otherwise show its beginning. So a secret that has no shape and no name is not echoed either, nor its beginning.

**The environment.** The adapter runs with exactly these variables: `PATH`, set to `/usr/local/bin:/usr/bin:/bin`, and,
when the configuration names `credential_env`, that variable with the value it has in the launcher's environment. It has no
`LANEBOSS_` variable, no `HOME`, and no variable that the launcher's own environment holds. The rule of a judge, the
launcher's environment minus its `LANEBOSS_` variables (`judges.environment()`, `judges.py:201-203`), is not enough here, and
`docs/judges.md` ("Known limits") says why for a judge: whatever the launcher's environment holds reaches the command. For
a judge that is a proxy setting. For an adapter it would be an ambient default cloud profile, or a key that the session
happens to hold, and the adapter would act with it in an account that nobody named. With a named credential and nothing
else, an adapter acts with the identity the configuration names or with none, and the stand-in adapter of the tests can
show which, because it records the environment it was started with. An adapter selects its identity only from the
request's `profile` and the named variable, never from a default. One that needs the account's home directory asks the user
database for it, as the claims registry does for the same reason ("Working directory", "Claims"), and reads only the files
its own configuration file names.

The program is resolved by the launcher before the call: `command[0]` is an absolute path to an executable file, or a name
found on the launcher's own `PATH`, which is the rule of `doctor` (`doctor.py:137-140`), and `argv[0]` is the path that
rule finds, made absolute (`shutil.which()` returns a relative path for a relative `PATH` entry, `doctor.py:140`). Without
that resolution, a bare name would be looked up on the `PATH` of the environment given to the new process (the `PATH` of
`subprocess.Popen`'s `env`), which is the fixed one, where `doctor` did not look. A program that is not found is the reason
`not-found`, and nothing is sent. The working directory is the launcher's, and an adapter does not depend on it.

**How the launcher bounds the command.** `adapters.call()` calls `judges.run_command(argv, data, seconds, variables)`
(`judges.py:366-397`) as it is: no shell, a session and a process group of its own, the request on standard input, and at
the operation's time-out the whole process group gets SIGTERM and, one second after it, SIGKILL. When the command ends by
itself, what its pipes still hold is read first and the group is then killed. Standard output past 64 KiB is `output`, and
of standard error the first 4096 bytes are kept (`judges.py:45-46`). The function is shared, not moved: `adapters.py`
imports it from `judges.py`, and moving it and its helpers (`pump`, `drain`, `end_group`, `end_leftovers`) into a module
that both import would change no behaviour and is not a step of this design. A launcher that is terminated or hung up while
an adapter runs ends the adapter's process group, as `judge ask` does (`judgecmd.py:83-88`). A launcher that is killed with
SIGKILL leaves the adapter running in a session of its own (`judges.py:371-372`), and the launcher's own deadline
(`judges.py:375-385`) is gone with it. So the request carries the operation's time-out (`timeout_seconds`), and the
contract requires an adapter that has not answered when that many seconds have passed since it started to create nothing
more and to exit with a non-zero status. With that rule, whatever an orphaned acquire creates, it creates before
`acquire_bound_minutes` has passed (the key is validated to be longer than `acquire_seconds` by at least one minute,
"Configuration"). The margin between the last moment that an orphaned adapter can create something and the moment the bound
passes is about 50 seconds or more, and not a minute, because the adapter starts after the intent's time, which is set before
the append, and that append may wait up to 10 seconds (`DRAIN_SECONDS`, `lanecmd.py:45`). So it cannot create a machine
after its intent was listed `unresolved` or closed as failed, and a machine that it did create is found again by the
resource's id ("Failures"), unless the provider's lookup by that id lags behind the creation by more than the margin ("Known
limits of this design"). The time-outs are `acquire_seconds` for the quote and again for the acquire,
`describe_seconds` and `release_seconds` ("Configuration"). While an adapter runs the launcher holds no lock: not the lanes
lock and not the state directory's, which an append takes only while it opens the store (`cli.py:292-295`; the comment at
`cli.py:280-282` says the same).

**What an adapter must do to be idempotent.** The launcher never repeats an acquire or a release by itself (it repeats a
describe, in the wait after a release), but a person runs a command again after a time-out or a kill, a timer reads the
same resources back every few minutes, and two commands can reach one resource at the same time. So an adapter makes each
operation safe to repeat:

- A quote creates nothing, however often it is asked.
- An acquire for an id that already exists answers `acquired` with the existing resource's `provider_id` and `started_at`,
  and creates nothing. It finds the existing one by the id that it put on it.
- An acquire creates exactly the `size` that the request names, in the `region` that the request names (a `null` meaning
  what the adapter's own configuration names), or answers `failed`: it never tries another size or place. The intent
  records what the request names, the cost follows it, and a describe looks in the request's region.
- A describe changes nothing, and answers `absent` for an id it finds nothing for. A describe or a release that finds more
  than one resource under the id gives no answer: it never picks one.
- A release for an id that is already ending or ended, or that it finds nothing for, is not an error: it answers
  `releasing` and does nothing more. `releasing` says that the adapter did not fail and that nothing more is asked of the
  caller. It never says that the resource exists or has ended, and the launcher never concludes either from it: only a
  describe does.

An adapter that is asked for a `kind` it does not serve, or for a version of the contract it does not know, ends with a
non-zero status. That is no answer, and nothing is guessed.

**What an adapter puts on what it makes.** For a resource of kind `machine`: the id, as the tag or the name that it looks
the resource up by, so that a describe finds a resource whose acquire answer was lost; the lane's name, where the provider
allows it; the purpose; and the hard cap as a limit of the resource's own life, set by the resource itself ("Release"). A
describe looks in the `region` of the request, or, when that is `null`, where the adapter's own configuration launches. It
answers `absent` only after it has looked there for the id. When it cannot look (its credential does not work, the provider
cannot be reached) it gives no answer, and never `absent`.

**What an adapter never does.** It never puts a secret in a member, on standard output or on standard error: the contract
has no member that can carry one, and the launcher refuses a string that looks like one. It never terminates a resource
directly ("Release"). It never calls another company's launcher or script. How a lane reaches what it holds (an address, a
key, a token of a narrowed credential) is not part of the contract: the launcher never sees it, no event holds it, and the
adapter's own page says how the lane gets it.

**The adapter's configuration file.** Every value that is specific to a company (a profile name, a region, a network, an
image, a key name, tags, where a price comes from) is in a file that the adapter reads, which is named by an argument of
`command` and kept by the private configuration, never in the repository. The launcher never reads, copies or sends that
file. Its path, as an element of `command`, passes the screens that every configuration value passes: `config validate`
refuses a credential shape in it and a path into another organisation's tools. That the file holds names and settings and
never a secret is the adapter's rule and its page's, and it is the one thing here that the launcher cannot check
("Known limits of this design").

**Decided: no egress log.** A judge's request carries texts, so the launcher withholds what looks secret and logs what it
sent. A resource request carries only members of fixed grammars, and every one of them is in an event or follows from one:
the intent holds the lane, the run, the kind, the provider, the purpose, the size, the region and the hard cap, the acquired
event holds the provider's id, the profile is a name in the configuration, and `timeout_seconds` is the operation's key in
the configuration. There is nothing to withhold, and a request
can be recomputed from the store and the configuration, so the events are the record of what was asked. The order makes that
record reliable: the intent is appended before the acquire is sent, so no resource can exist without an event that says it
may. Two calls leave no event: the quote, which creates nothing, and the release, whose effect is read back and recorded as
`resource.released`. A quote that fails leaves only the exit status and the message of the command that asked for it.

**What the launcher does with each outcome.**

| Call | Answer | The launcher |
|---|---|---|
| quote | `quoted` | Appends `resource.intent` with the answer's `size`, `region` and price, then sends the acquire. |
| quote | `failed`, or no answer | Ends `resource acquire` with exit 1. Nothing was appended and nothing exists. |
| acquire | `acquired` | Appends `resource.acquired` (`found_by` `acquire`). |
| acquire | `failed` | Appends `resource.failed` (`how` `adapter`). |
| acquire | no answer | Appends nothing. The intent stays, and the resource is held until a read-back finds it or `resource release` closes it. |
| describe | `running` | For a resource that has an intent only, appends `resource.acquired` (`found_by` `describe`). Otherwise nothing. |
| describe | `terminated` | For a held resource, appends `resource.released`, after `resource.acquired` when the resource had an intent only. Otherwise nothing. |
| describe | `absent` | Appends nothing. For a resource that has `acquired` it is a finding. |
| describe | no answer | Appends nothing. The reading is `unknown`. |
| release | `releasing` | Goes on to read back. Appends nothing. |
| release | no answer | Appends nothing. The command ends with exit 1. |

**What this cannot see.** The answer is not authenticated: the launcher trusts the command it was configured with, as it
trusts a judge. An adapter that says `terminated` for a resource that is running is believed. The defences are the
contract tests (step B), the real trial of each adapter, and a person's reading of `resource describe` against the
provider's own listing; for a resource that is already `released`, `resource describe` reads it again and reports a
disagreement ("Commands"). The store cannot see the provider either: a `resource.released` that is written by hand with
`event append` passes the same checks as one the launcher wrote, because they check form and order and not the truth, and
a hand-written event that is meant to deceive is outside what the launcher defends against ("What isolation covers").

### Configuration (built by A)

`[resources.NAME]` is a table of tables in `config.toml`, as `[judges.NAME]` and `[runners.NAME]` are. `NAME` follows the
grammar of runner names, `[a-z0-9][a-z0-9-]{0,31}` (`config.NAME`, `config.py:24-25`; `named_tables()` refuses any other
name, `config.py:143-153`), and it is the member `provider` of the intent. The key is optional and the schema version stays
1: a configuration without `[resources]` is valid and behaves as it does today, and a configuration with it is refused by
0.5.0 at load as an unknown key (its `CONFIG` table lists its keys and `table()` refuses any other, `config.py:125-137` and
`441-462` at commit 919af68), so every 0.5.0 command bound to such a configuration fails ("Compatibility"). Keys are
validated strictly, and an error names the file and the key path and never repeats a value, as `docs/configuration.md`
("Validation rules") has it, for example `config.toml: resources.NAME.hard_cap_minutes: must be from 1 to 10080`.

| Key | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `description` | string | no | none | Free text, on one line, at most 1000 characters, through the credential detector like any description. |
| `command` | array of strings, not empty | yes | none | The adapter's argument vector, run without a shell. The first element is a command name or an absolute path; the others are plain arguments, and the path of the adapter's own configuration file is one of them. No placeholders: an element with a brace is refused, not passed on as written, as for a judge. |
| `kind` | `machine` or `credential` | yes | none | What the adapter makes. It is sent as `kind` in every request and recorded as `kind` in the intent. |
| `credential_env` | name, `[A-Z][A-Z0-9_]{0,63}` | no | none | The NAME of an environment variable of the launcher's process. Its value is handed to the adapter under the same name, and it is the only variable the adapter gets besides `PATH`. Never a value. Not `PATH`, and not a name that starts with `LANEBOSS_`. When the key is set and the variable is not set, or is empty, in the environment of a command that needs it, that command does not call the adapter. |
| `credential_profile` | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` | no | none | The NAME of a profile that the adapter reads from its own files. It is sent as `profile` in every request. Never a value. |
| `acquire_seconds` | integer 1 to 900 | no | 300 | How long the quote may take, and, separately, the acquire. An acquire waits until the provider has accepted the request, not until the resource is usable, and it is the longest operation, so it has the longest bounds. It is sent to the adapter as `timeout_seconds`. 900 is a quarter of an hour. |
| `describe_seconds` | integer 1 to 300 | no | 60 | How long one read may take. It is also the bound of each read in the wait after a release. |
| `release_seconds` | integer 1 to 600 | no | 120 | How long asking a resource to end may take. It may mean reaching the resource over a network, with retries. |
| `acquire_bound_minutes` | integer 1 to 1440 | no | 15 | How long an intent that has neither `resource.acquired` nor `resource.failed` may stay a resource that is still being made. After that it is listed as `unresolved`, and `resource release` may close it. It must be at least one minute more than `acquire_seconds` rounded up to whole minutes, so that a call that is still inside its own time-out is never called unresolved. |
| `hard_cap_minutes` | integer 1 to 10080 | yes | none | The longest a resource of this adapter may live, in minutes: the cap that `resource acquire` sends when it gets no `--hard-cap`, and the most it accepts for one. The adapter sets the resource's own end to it ("Release"). It is required and not defaulted, because a cap that nobody chose would end a long job without anyone having decided so. 10080 is a week, the longest a lane's budget can be. |
| `release_by_itself` | boolean | no | `false` | When true, `resource check --read-back` asks the adapter to release a held resource whose run has ended and whose cap has passed, and records the release it then reads back. It is the one place where the launcher cleans up on its own, and nothing else does ("Release"). |
| `read_back_wait_seconds` | integer 0 to 3600 | no | 240 | How long `resource release` waits, after the adapter has answered `releasing`, for a read-back to show `terminated`. With 0 it does not wait: the command ends with the resource still held, and a read-back made afterwards records the end. |

A worked entry, with invented values:

```toml
[resources.example-machine]
description = "A test machine that the example adapter makes."
command = ["/opt/example/bin/example-adapter", "--config", "/opt/example/adapter.toml"]
kind = "machine"
credential_profile = "example-profile"
hard_cap_minutes = 240
```

**What `config validate` refuses.** Each refusal names the key path and never repeats a value.

- An unknown key, a wrong type or a value outside its bound, a missing `command`, `kind` or `hard_cap_minutes`, and an
  empty `command` (the rules every table has, `config.py:128-140`, and those of a judge's `command`, `config.py:446-455`,
  which `adapter_command()` applies with a message of its own).
- A credential shape anywhere in the file. `parse_toml()` screens every string and every key before any key is checked
  (`config.py:586-589`), so a key, a token or an authorization header as the value of `credential_env`,
  `credential_profile`, `description` or an element of `command` is refused. A `credential_env` that is not a name of its
  grammar is refused too: a value with lower-case letters, punctuation or more than 64 characters is not a name. A secret
  that is itself a string of capital letters, digits and underscores cannot be told from a name by any rule, and that the
  key holds a name is the person's.
- A `credential_env` that is `PATH` or starts with `LANEBOSS_`: the first is the adapter's fixed `PATH`, and the others
  are the launcher's own.
- An element of `command` that is an absolute path inside another organisation's `orgs/OTHER/` directory, for a
  configuration that names an organisation: `command_elements()` also yields `resources.NAME.command`
  (`config.py:763-771`), so `check_tools_not_shared()` (`config.py:792-802`) covers it, with the limits it has for runners
  and judges (only whole elements that are absolute paths, compared as text).
- An `acquire_bound_minutes` that is too short for `acquire_seconds`; the message names `resources.NAME.acquire_bound_minutes`.

`credential_env` is not checked against the top-level `secrets` list. Those names belong to a secret store that does not
exist yet (`docs/configuration.md`, the key `secrets`), while the variable here is read from the environment of the command
that runs. Nothing else in a configuration names a resource: the name that an event holds as `provider` is looked up in
`[resources]` when a command needs the adapter, and an edit that removes it leaves the resource listed as
`adapter-missing` ("Failures").

**What `doctor` checks.** One line, `resource.NAME`, for each configured adapter, after the `judge.NAME` lines
(`doctor.py:204-208`). It passes when the program of `command[0]` is found by the rule that resolves it for a call: an
executable absolute path, or a name on `PATH` (`find_command()`, `doctor.py:137-140`). Its detail names the program and
never the arguments. `doctor` never calls an adapter, never reads the variable that `credential_env` names, and writes
nothing. A configuration that names no organisation and points a resource command into an organisation's directory fails the
check `organisation.tools` (`doctor.py:143-157`), because that check reads the same `command_elements()`.

**Test machines and cost fields that exist today stay.** Resources supersede test machines. A test environment
(`[test_environments.NAME]`) names how to start and collect a machine (`launch`, `collect`), how to verify it before a
secret goes to it (`attest`), and how long and how many (`idle_minutes`, `hard_minutes`, `max_machines`). Nothing reads
those fields (`docs/configuration.md`: validated, not yet used), and the runner placeholder `{machine}` is refused at `lane
start` ("test machines are not built yet", `lanecmd.py:305-306`). A resource of kind `machine` is what a test machine
becomes: an adapter replaces `launch` and `collect`, the adapter's idle guard and the resource's `hard_cap_minutes` replace
`idle_minutes` and `hard_minutes`, and the events replace whatever a lane would say about what it rented. This design builds
nothing on `[test_environments]` and `{machine}`: they stay validated and unused, and retiring them is a separate step,
not taken here, that needs its own decision, because a configuration may use them. `max_machines` and `attest` have no
counterpart: the design limits no number of resources, and the launcher sends no secret to a machine. `[cost]`
(`currency`, `daily_cap`, `per_run_cap`, `report_threshold`) stays as it is and step C reads it only to REPORT: `lane cost`
shows the caps beside the totals and flags a total that passes one ("Commands"), and no command refuses, stops or releases
anything because of a cap. Whether `resource.intent` should refuse an acquire whose price would pass a cap is an open point
("Open points").

### Commands (built by A and C)

`laneboss resource ACTION` is bound to one configuration like every command that reads or writes state (`--config NAME`
or `LANEBOSS_CONFIG`, `cli.py:177-184`), prints one JSON value (ASCII-safe, sorted keys) and takes no text from an
argument that a shell could expand: it takes names, ids and numbers. The commands that only read (`list`, `show`, and `check`
without `--read-back`) create nothing; a configuration that has no store yet gives empty lists. Every event the commands
append is an ordinary event of the store: `event tail --follow`, with `--lane` and `--until`, shows it as it is stored.
`event tail` starts at `--since` 0 and `--until` stops at the first event of that kind it prints (`cli.py:99-102`,
`247-254`), so a supervisor that waits for a release gives `--since` the `seq` it has already seen (the `seq` of the last
event in the `events` that its command printed): `--since SEQ --until resource.released`.

| Command | Options | What it does |
|---|---|---|
| `resource acquire` | `--lane L --resource NAME [--size S] [--purpose P] [--hard-cap MINUTES]` | Asks the adapter `NAME` for a quote, appends the intent, asks it to acquire, and records the answer. |
| `resource describe` | `--id ID` | Asks the adapter what it shows for the resource, and records what that proves. Reads any resource, held or not. |
| `resource release` | `--id ID` | Asks the adapter to release a held resource, and records its release once a read-back shows `terminated`. |
| `resource check` | `[--lane L] [--read-back]` | Lists every held resource with the reasons it is a finding. With `--read-back` it first reads every held resource back, and may release some. |
| `resource list` | `[--lane L] [--held]` | Lists the resources, from events only. |
| `resource show` | `--id ID` | One resource and its events, from events only. |
| `lane cost` (C) | `[--lane L] [--day YYYY-MM-DD]` | What a lane, or a UTC day, cost, from events only. |

**What a person types, and who.** To acquire a resource for a lane: `laneboss resource acquire --config NAME --lane LANE
--resource example-machine --purpose example-tests`. `--purpose` defaults to the lane's name, which fits its grammar. In
practice the lane's supervisor types it, from its own session, which holds the credential that the adapter needs: the
variable that `credential_env` names is read from the environment of the process that runs the command. The lane's own agent
can run the same command from inside its run, because a run's environment carries `LANEBOSS_CONFIG`, `LANEBOSS_LANE` and
`LANEBOSS_RUN` (`supervise.py:415-417`), but only if its environment also carries that variable, and nothing in this design
makes an executor hold a cloud credential. A resource always belongs to a lane that the configuration knows and that has
begun a run: there is no resource without a lane. To release it: `laneboss resource release --config NAME --id ID`.

**The record.** Every command prints a resource in one form, the record, with the keys below. `list` prints an array of
records sorted by lane and then by the order of the intents. A command that acts on one resource prints one object that holds
the record's keys and, beside them, its own keys, named in its paragraph; when no resource exists (`resource acquire` that
ends `not-quoted` or `not-recorded`) the record's keys are all `null`. `standing` is computed when the command runs, from the
events, the configuration and the launcher's clock.

| Key | Value |
|---|---|
| `resource`, `lane`, `run`, `kind`, `provider`, `purpose`, `size`, `region`, `hard_cap_minutes` | What the intent holds. |
| `price` | The intent's `price`: `null` or `{"per_hour": money, "source"}`. |
| `state` | `intent`, `acquired`, `failed` or `released`: the fold's state. |
| `held` | `true` for `intent` and `acquired`, else `false`. |
| `provider_id`, `started_at` | The acquired event's, else `null`. |
| `cap_at` | `start` plus `hard_cap_minutes`, in the form of `recorded_at` ("The resource model"). |
| `released_at` | The `at` of the release's `read_back`, else `null`. |
| `cost` | The `cost` of the resource's `resource.cost` (step C), else `null`. |
| `standing` | A list of the reasons of the table "Why a held resource is listed" that apply, sorted. |

**`resource acquire`.** Before anything is sent, and with exit 2 when one fails: `--lane` has the lane grammar and names a
lane that has a `lane.*` event and has begun a run (`run` 1 or more) and is not `merged` or `abandoned`; `--resource` names
an adapter of the configuration (the message lists the configured names, and repeats the typed one unless the credential
detector matches it, as for judges); `--size` and `--purpose` have their grammars and pass the credential detector;
`--hard-cap` is a whole number from 1 to the adapter's `hard_cap_minutes`; the variable that `credential_env` names is set
and not empty; the lane holds fewer than 256 resources. Then, in this order:

1. The launcher makes the id and sends the quote (`dry_run` true). Without an answer, or with `failed`, it ends (exit 1)
   with the outcome `not-quoted`: nothing was appended and nothing exists.
2. It appends `resource.intent`, with `run` the lane's latest run, `hard_cap_minutes` the cap chosen, `size` and `region` as
   the quote answered, and `price` made from the quote: `{"per_hour": {"amount_micros": price_per_hour_micros, "currency":
   currency}, "source": price_source}`, or `null` when the quote's three price members are `null`. When the append is
   refused, nothing is sent (exit 2); when the store cannot take it, the outcome is `not-recorded` (exit 1) and nothing was
   acquired.
3. It sends the acquire (`dry_run` false), with the intent's `size` and `region`.
4. `acquired`: it appends `resource.acquired` (`found_by` `acquire`) and the outcome is `acquired` (exit 0). `failed`: it
   appends `resource.failed` (`how` `adapter`), and the outcome is `failed` with the adapter's `reason` (exit 1). No answer:
   it appends nothing, and the outcome is `unresolved` (exit 1) with `why`: `timeout`, `exit`, `output` or `not-found`, or
   `store` when the adapter did answer `acquired` and the store could not record it (then `provider_id` is printed too, so
   that a person can look for it). The resource is held as an intent and `resource describe` or `resource check --read-back`
   finds it again by its id.

Output: the record's keys and, beside them, `outcome` (`acquired`, `failed`, `unresolved`, `not-quoted` or `not-recorded`),
`why` (or `null`), `reason` (or `null`), `provider_id` as it stands in the record or, for `unresolved` with `why` `store`,
the one the adapter answered, and `events`, the events this command appended, each `{"kind", "id", "seq"}`, in order. Two
`resource acquire` at once make two resources, each with its own id and its own intent; nothing is shared between them.

**The read-back.** Three commands read a resource back, and they do it the same way. For a resource, the command sends a
describe with the `provider_id` of `resource.acquired` (`null` while there is none) and the intent's `region`, bounded by
`describe_seconds`, and then does what the table says. The `reading` it reports is `running`, `terminated`, `absent` or
`unknown`, with the provider's `provider_state` (`null` for `absent` and `unknown`) and, for `unknown`, `why`: `timeout`,
`exit`, `output`, `not-found`, `adapter-missing` or `credential-not-set` (`null` for the other readings).

| Fold state | Answer | Appended (in order) | Reading | Standing that the reading adds |
|---|---|---|---|---|
| `intent` | `running` | `resource.acquired` (`found_by` `describe`). | `running` | None. |
| `intent` | `terminated` | `resource.acquired` (`found_by` `describe`), then `resource.released` (`how` `observed`). | `terminated` | None. |
| `intent` | `absent` | Nothing. | `absent` | None. The resource stays held, and the clock alone lists it `unresolved` once the acquire bound has passed. |
| `acquired` | `running` | Nothing. | `running` | None. |
| `acquired` | `terminated` | `resource.released` (`how` `observed`). | `terminated` | None. |
| `acquired` | `absent` | Nothing. | `absent` | `absent`. The resource stays held. |
| `released` or `failed` | `running` | Nothing. | `running` | `disagrees`. |
| `released` or `failed` | `terminated` or `absent` | Nothing. | As answered. | None. |
| any | no answer | Nothing. | `unknown` | `unknown`, for a held resource. |

The events are made from the answer and the launcher's clock. `resource.acquired` takes `provider_id`, `started_at` and
`request` from the answer (`found_by` `describe`). `resource.released` has a `read_back` of `{"at": the moment the launcher
read the answer, "state": "terminated", "provider_state", "ended_at" and "request": from the answer}`. `resource.cost`
follows each `resource.released` (step C). A read-back never writes `resource.failed`, and never closes a
resource that has `acquired` on `absent`: the launcher cannot tell a resource that the provider has forgotten from one it is
looking for in the wrong place, and a resource it cannot read back is never counted as released. This holds for every
append that these commands make: when `append()` refuses an event because another command has just done the same thing (the
resource's state is already the one that the event would have given, or one further on), the command reads the resource
again and reports what it finds, with exit 0 and no event of its own, so two read-backs, or a read-back and a release, or a
read-back and a late acquire answer, at once are not an error. Any other refusal ends the command with exit 2.

**`resource describe`.** Refused (exit 2) for an id that no event holds, for a provider that the configuration no longer
has, and when the variable named by `credential_env` is not set. It runs the read-back for the one resource and, for step
C, appends the `resource.cost` that a released resource lacks. Output: the
record after the appends, `reading` (`{"state", "provider_state", "why"}`) and `events`. Exit 0 when a reading was obtained
and the record's `standing` is empty afterwards; exit 1 when the reading is `unknown`, or `standing` is not empty (a held
resource whose run has ended is a finding, and so is a resource that `disagrees`).

**`resource release`.** For a resource that is not held (`released` or `failed`) it prints the record, appends nothing and
calls no adapter (exit 0). Otherwise it is refused (exit 2) for an id that no event holds, for a provider that the
configuration no longer has, when the variable named by `credential_env` is not set, and for an intent that is still inside
its acquire bound (its acquire may be running; the message says when the bound ends). Then, in this order:

1. The read-back above. When it leaves the resource not held, the command is done.
2. The release: the adapter is asked to release (`release_seconds`). No answer ends the command (exit 1, outcome
   `release-failed`, with `why`); nothing was appended by this step.
3. The wait. A describe is sent at once, and then every 10 seconds while the time since the release's answer is less than
   `read_back_wait_seconds`; each is bounded by `describe_seconds`. `terminated` appends `resource.released` (`how`
   `release`), after `resource.acquired` when the resource still had an intent only. `running` for a resource that had an
   intent only appends `resource.acquired` (`found_by` `describe`) once, and the wait goes on. `absent` for a resource that
   has an intent only appends `resource.failed` (`how` `release`, `reason` `absent`): this is how an intent that no acquire
   ever reached is closed, and it needs a describe that answered `absent` after the release was sent. A describe that gets no
   answer, `absent` for a resource that has `acquired`, and `running` for one that has `acquired` leave the wait going on.
4. When the wait ends with the resource still held, the command ends (exit 1, outcome `still-held`, with the last reading).
   It appends nothing, and the resource is listed by `resource check` until a read-back made afterwards records its end.

Output: the record after the appends, `outcome` (`released`, `closed`, `already-ended`, `release-failed` or `still-held`:
`released` for `how` `release`, `closed` for `resource.failed`, `already-ended` for `observed` and for a resource that was
not held), `reading` and `events`. The command takes at most `release_seconds` plus `read_back_wait_seconds` plus two
`describe_seconds` (the first read-back is one of them), not counting its appends. Exit 0 when the resource is not held at
the end, exit 1 when it is.

**`resource check`.** Without `--read-back` it reads events only, calls no adapter and appends nothing, and it is safe to run
from a timer. It lists every resource that is held, and, for step C, every resource that is released and has no cost, sorted
by lane and by the order of the intents. With `--read-back` it first reads every held resource back, one at a time and in
that order, by the read-back above, and, for step C, appends the `resource.cost` that a released resource lacks, which
needs no adapter. A timer that runs it needs the credential variable of each adapter in its own environment: an adapter
whose variable is missing, or that the configuration no longer has, gives `unknown` with `why` for its resources, and the
others are still read. Then, for a resource that is still held, whose adapter has `release_by_itself` true, whose standing
holds both `lane-ended` and `held-beyond-cap`, whose reading is `running` or `absent` (a resource that could not be read is
not released blind), and, when it has an intent only, whose acquire bound has passed, it runs the release, steps 2 to 4
above, with `how` `by-itself`. This is the one place where the launcher cleans up on its own, and it never happens anywhere
else. `--lane` limits the list to one lane. Output: `read_back` (the flag), `checked_at` (the launcher's clock, in the form
of `recorded_at`), `held_count` (how many resources were held when the command began), `findings` (how many of the listed
resources have a `standing` that is not empty), and `resources`: for each, the record's keys after the appends,
`events_waiting` (how many events of its lane still wait in the lane's pending files, `pending.count()`,
`pending.py:122-130`) and, with `--read-back`, `reading`, `events` and `released_by_itself`. Exit 0 when `findings` is 0
and exit 1 otherwise, so a timer can tell; the value is printed in both cases, and a held resource that has no `standing`
is listed but is not a finding: a lane's machine in use is normal.

**`resource list` and `resource show`.** `list` prints the records, with `--held` only the held ones and with `--lane` only
the lane's. `show` prints the record and `history`, the resource's events in order, each `{"seq", "id", "kind",
"occurred_at", "payload"}`. Neither calls an adapter nor writes. `show` for an id that no event holds is refused (exit 2).
Both exit 0.

**`lane cost` (C).** At least one of `--lane` and `--day` is required (exit 2 otherwise); `--day` is a calendar date, read as
a UTC day, that exists. It reads events only. The costs it counts are the `resource.cost` events of the lane (when
`--lane` is given) whose `ended_at` falls on that UTC day (when `--day` is given); a cost belongs wholly to the day of its
`ended_at`, and why the day is UTC is in "Cost". Output: `lane` and `day` (the options, or `null`), `currency` (the
`[cost]` currency, or `null` when the configuration has none), `totals` (for each currency found, `{"currency",
"amount_micros", "resources"}`), `runs` (for each lane and run, `{"lane", "run", "currency", "amount_micros",
"resources"}`), `resources` (each counted cost: `{"resource", "lane", "run", "provider", "started_at", "ended_at", "cost",
"source"}`, `source` being the price's source), `missing`, `agent_runs`, `caps` and `over`:

- `missing` lists each resource in scope that is released and counts for no amount, `{"resource", "why"}`, with `why`
  `no-price` when its price is `null` and `no-cost-event` when no cost was recorded yet. In scope are the resources of the
  lane, when `--lane` is given, and the resources whose day is the UTC day, when `--day` is given; when both are given, both
  apply, and the scope is the lane's part of the day, as `totals` and `resources` show it. The day of a resource is the day
  of the `ended_at` of its `resource.cost` when it has one (a `null` price has one), else the day of its `released_at`. So a
  resource moves from one day's `missing` to the other's when its cost event is appended, and it is counted, once it has an
  amount, on the day of its `ended_at`.
- `agent_runs` is always `null`: the cost of agent runs is absent, not zero, until a reader records it as an event (the
  stream readers of `lane attach` show a cost on the screen and record nothing), and it is never guessed.
- `caps` holds the `[cost]` caps as whole micro-units, `daily_cap_micros`, `per_run_cap_micros` and
  `report_threshold_micros`, each `null` when absent; how a cap that is a number of units becomes micro-units is in
  "Cost". They are not bounded as `amount_micros` is: `[cost]` numbers have no upper bound (`config.py:94-96`), so a cap can
  pass 2^53. It is printed as the exact integer all the same, and a reader that parses numbers as doubles reads it
  inexactly.
- `over` is the report, for the totals in the `[cost]` currency (another currency is totalled apart and never converted).
  It has two kinds of item. A run item, `{"cap": "per_run_cap", "lane": L, "run": N, "amount_micros": T, "cap_micros": C}`,
  for each run that has a cost counted in the scope, when T, that run's whole total over all its resources and all days (not
  the part of it that falls on `--day`), is above C, which is `per_run_cap_micros`. A daily item, `{"cap": "daily_cap" or
  "report_threshold", "lane": null, "run": null, "amount_micros": T, "cap_micros": C}`, only when `--day` is given: T is the
  configuration's total for that UTC day over all lanes (the figure a daily cap limits), whatever `--lane` says; it is an
  item of `daily_cap` when T is above `daily_cap_micros` and of `report_threshold` when T is at or above
  `report_threshold_micros`. So `--lane L` alone gives run items for the runs of L and no daily item; `--day D` alone gives
  run items for every run that has a cost counted on D and the daily items for D; and `--lane L --day D` gives run items
  for the runs of L that have a cost counted on D and the daily items for D over all lanes, while `totals`, `runs` and
  `resources` show L's part of the day.

Nothing is refused or stopped when a cap is passed. Exit 0; 2 for invalid input; 3 for an integrity problem.

**Order of appends.**

| Operation | Events, in this order |
|---|---|
| `resource acquire` | `resource.intent`; then `resource.acquired`, or `resource.failed`, or nothing when the adapter gave no answer. |
| `resource describe`, `resource check --read-back` | For each resource, as the read-back table says: `resource.acquired`, `resource.released`; (C) `resource.cost` after each release. |
| `resource release` | The read-back's events; then `resource.acquired` (when the wait finds an intent-only resource `running`), then `resource.released` or `resource.failed`; (C) `resource.cost` after the release. |
| `lane mark --accept-held` | `lane.state` with `held`. |

Every event these commands append has actor `laneboss`, an `occurred_at` that is the moment of the thing, and the protocol
version of the installed launcher, as the events of the lane commands have (`lanecmd.py:157-158`). Each is appended with
`EventStore.append()` on a store that is opened under the state directory's lock, which is released before the append
writes, as `event append` does (`cli.py:289-299`), and waits for a busy store at most 10 seconds (`DRAIN_SECONDS`,
`lanecmd.py:45`). A store that cannot take an event after an adapter has answered
is `sqlite3.Error`, which the command catches itself: `cli.py:376-378` would turn it into exit 3 with the words "integrity
problem", and a busy store is not one. The command ends with exit 1 and a line on standard error that says what is in
doubt, and the resource is held as it was, so nothing is lost. A command that calls an adapter handles SIGTERM and SIGHUP
as `judge ask` does (`judgecmd.py:83-88`): the adapter's process group is ended, what is stored stays, and the exit is 130.

**Exit codes.** The resource commands reuse 0, 1, 2, 3 and 70 of "Command line contract", and the 130 that today's launcher
already exits for an interrupt (`cli.py:383-384`) and that the table of "Command line contract" does not list, and add none.
Exit 7 stays what it is for judges, the egress log, and no resource command uses it. The existing table says what 1 means for
`doctor`; for these commands it means the way it does for `judge ask` (the row of its table of exit codes that reads 1,
"Unavailable", in `docs/judges.md`): the request was valid, and the command did not finish what it was asked to, or found
something. A command that ends with 1 for a step that failed prints its value on standard output as it does for 0 and one
line on standard error that starts with `incomplete:` and says which step; the findings of `check` and `describe` are in
the printed value only.

| Code | `resource` commands |
|---|---|
| 0 | Everything the command was asked to do is recorded, or was recorded by another command at the same time: acquired; released, closed or not held; a check with no finding; a read. |
| 1 | The adapter gave no answer or said `failed`; a resource is still held after a release; an answer could not be recorded; `resource check` or `resource describe` found something. |
| 2 | Invalid input or a refused request: usage; a lane, resource or provider that is not known; a lane that is merged or abandoned or has not run; a variable that is not set; an option out of its bound; a refusal of the store's checks at append. |
| 3 | An integrity problem: a stored event that does not verify or is not in this version's form. |
| 70 | An unexpected internal error. |
| 130 | An interrupt: SIGINT, or SIGTERM or SIGHUP, which a command that calls an adapter turns into an interrupt as `judge ask` does (`judgecmd.py:70-71`, `83-88`). This is today's code, not this design's: `KeyboardInterrupt` ends the launcher with 130 (`cli.py:383-384`). What is stored stays. |

**Changes to commands that exist (built by A).** Four commands change: `lane check`, `lane mark`, `lane clean` and
`lane start --reuse`.

**`lane check`** (`lanecmd.py:974-1015`) does what it does today (appends every lane's pending events, then reads the lanes the
store believes are running and, after that, the process table, and appends at most one `lane.lost` for each lost run), and,
after a fresh read of the store, adds the key `held` to its output: for every lane it checks, one entry for each resource
that is held, `{"lane", "resource", "run", "kind", "provider", "state", "standing", "events_waiting"}`, sorted by lane and
by the order of the intents, and `[]` when nothing is held. It reads events only. It calls no adapter, it appends nothing
of its own, and its exit code does not change (0), so it stays safe to run from a timer. A `lane check` that is refused
because the process table cannot be read gives no listing: `resource check` gives it from events alone.

**`lane mark`** (`lanecmd.py:1104-1145`). The new option `--accept-held` is refused unless `--state accepted` or `--state
merged` is given, as `--accept-uncovered` is (`lanecmd.py:1108-1109`): "--accept-held goes with --state accepted or --state
merged". For those two states, `decide()` runs the resource gate, in this place: after the lane's pending events were
appended (`drain()`, which refuses when some cannot be) and the lane was found not to be running (`lanecmd.py:1125-1132`),
under the lanes lock that `mark()` already holds for accepted and merged (`lanecmd.py:1112-1117`), and before it calls
`gate()`, the refusal scan. The gate reads the lane's held resources from the store and decides:

- None is held, and `--accept-held` is given: refused (exit 2), "--accept-held: lane L holds no resource that is not
  confirmed released, so there is nothing to accept", as `--accept-uncovered` is refused when nothing is scanned
  (`lanecmd.py:1075-1077`), so that the flag is not a habit.
- None is held: the command goes on to `gate()`.
- Some are held and `--accept-held` is not given: refused (exit 2), nothing recorded:
  `lane L holds N resource(s) that are not confirmed released; release each with laneboss resource release --id ID
  (laneboss resource check --read-back records the ones that have ended), or record the decision with --accept-held;
  nothing was recorded:` and one line for each, `resource ID KIND PROVIDER STATE run N`.
- Some are held and `--accept-held` is given: the `lane.state` payload gets `held`, a list of `{"resource", "state"}` sorted
  by resource, `state` being `intent` or `acquired`, and the command goes on to `gate()`. `held` has at most 256 items,
  and a lane never holds more, because an intent is refused when the lane already holds 256.

The resource gate runs for every configuration, with guards or without. `gate()` returns at once for a configuration that
has no guards (`lanecmd.py:1074-1078`) and the resource gate is not inside it: `decide()` calls it first, so a
configuration without guards is not let through. The store checks the decision again in the transaction that appends it
(`resources.check_state()`, "Events"): when a resource was acquired after the gate read, which the lanes lock does not
prevent because `resource acquire` does not take it, the append is refused (exit 2) with a message that says that the held
resources changed, and the command is run again. Every output of `lane mark`, for any decision, has the key `held`, a list
of `{"resource", "state"}`: for accepted and merged it is the list the event records, `[]` when it records none; for
`--state verifying`, `--state abandoned`, `--landing` and `--gone` it is what the lane still holds, `[]` when nothing,
printed to tell and not recorded, because `held` is a key of `lane.state` for accepted and merged only.

`--state abandoned`, `--state verifying`, `--landing` and `--gone` are never held up by a resource, and that leaves open: a
lane that is abandoned or verifying can hold a resource, and a landing fact (`lane.merged`, `lane.deployed`, `lane.landed`,
which change no state) can be recorded for a lane that holds one. Each such resource is listed by `lane check` and by
`resource check`, and `lane clean` and `lane start --reuse` refuse the lane until it is released. The gate cannot be gone
around by another way to the same states: a hand-written `lane.state` that accepts or merges is refused at append unless its
`held` is exactly what the lane holds.

**`lane clean`** (`lanecmd.py:1239-1308`) is refused (exit 2) while the lane holds a resource, after the checks of the
lane's state and of its processes (`refuse_if_live()`, `lanecmd.py:1256`) and before anything is removed, under the lanes lock
it holds already: `lane L holds N resource(s) that are not confirmed released, so nothing was removed; release each with
laneboss resource release --id ID:` and one line for each resource, as above. No event is appended.

**`lane start --reuse`** (`lanecmd.py:623-631`) is refused (exit 2) while the lane holds a resource, in the same place and
under the same lock, after `refuse_if_live()`: `--reuse: lane L holds N resource(s) that are not confirmed released, so
nothing was started; release each with laneboss resource release --id ID:` and the lines. Without `--reuse` a lane that has
run is refused as it is today, so a lane that holds a resource is never started again by any form of `lane start`. The
refusals of `lane clean` and `lane start --reuse` are checks of the two commands, made under the lanes lock, and the store
does not repeat them at append: a `lane.cleaned`, or a `lane.started` with `how` `reuse`, written by hand with `event
append` passes. That is a hand-written event that goes round a command, outside what the launcher defends against ("What
isolation covers"). The gate for accepted and merged is repeated at append because it is the decision that this design
exists to protect.

**Lanes that are never accepted.** The gate is met only by `lane mark --state accepted` and `--state merged`. A lane that can
only end by being abandoned, never by being accepted or merged (a lane that is continued turn by turn is such a lane), never
meets it, so for it the held resources are found by `resource check`, by the listing of `lane check`, and by the output of
the `abandoned` mark, which prints what the lane still holds and is never held up; and the one place where a hold bites is
the end of its life: `lane clean` and `lane start --reuse` refuse it while a resource is held. The gate's refusal, if such
a lane is marked accepted, offers `--accept-held`, and the offer leads nowhere: the store refuses an accepted or merged
`lane.state` for a lane that is continued turn by turn at append, whatever `held` says.

No other lane command changes. `lane stop`, `lane resume`, `lane scan`, `lane review`, `lane status` and `laneboss start`
neither check nor release a resource: a lane that is stopped holds what it held, and the listing of `lane check` and
`resource check` says so. Whether `lane status` and the briefing should show held resources too is an open point
("Open points").

### Release (built by A and B)

**The rule.** A release is the end of a resource that has been seen. No part of the launcher terminates a resource, and the
contract has no operation that does: `release` asks the resource to end by its own path (for a machine, to shut itself
down), and the launcher records the end only when it has read it back. The cloud adapter's `release` never calls the
provider's terminate call. A deployment may refuse that call by a guard; the design neither relies on that nor works around
it, and a release that needed the call would fail wherever a guard refuses it. So:

- A release answers `releasing`, never `released`, and the launcher concludes nothing from `releasing` ("The adapter
  contract").
- `resource.released` is written only after a describe shows `terminated`: by `resource release`, which waits up to
  `read_back_wait_seconds` for it, or by a read-back (`resource describe`, `resource check --read-back`) that finds the
  resource already ended. The event's `read_back` holds the `terminated` that was shown, the provider's own word, and the
  moment, and its form refuses any other state ("Events").
- A resource that cannot be read back is `unknown`, never released; one for which the provider says `absent` while the
  events say it was acquired is a finding, never released ("The read-back").

**What a person sees.** `resource release` ends with exit 0 and the record `released` when the end was shown inside the wait.
A machine needs a little time: the guard looks at its done file once a minute, the shutdown takes seconds, and the
provider shows `terminated` a minute or two after that. The default wait of 240 seconds covers the usual case. When the end
does not come inside the wait, the command ends with exit 1 and the outcome `still-held`, it appends nothing, and the
resource stays held and listed until a read-back made afterwards records its end, so a longer end costs a second command,
not a wrong record. A person who wants no wait sets `read_back_wait_seconds` to 0 and reads back afterwards.

**At the cap.** The cap is the machine's own timed shutdown, set when it booted, so a machine whose lane crashed and whose
guard failed still ends. The launcher's `cap_at` is `start` plus `hard_cap_minutes`, where `start` is the provider's
`started_at` (the `intent_at` when the provider gave none), which comes before the machine has booted; so the machine's own
timer, set at boot, fires a little after `cap_at`, and a resource can be listed `held-beyond-cap` for that long before it
ends by itself. That is a report and not an action, and with `release_by_itself` the release it sends in that window is
harmless, because the machine is about to end anyway. A resource that is still `running` well after that is a machine that
did not end by its own path within its cap. It is REPORTED: `held-beyond-cap` is in its `standing`, in the output of
`resource check` (with the provider's word in `reading` when it read the resource back) and in the listing of `lane check`;
and the person decides. The person may end it with their own authority, outside the launcher, and the next read-back
records `released` (`how` `observed`). With `release_by_itself` on, `resource check --read-back` also asks the adapter to
release a resource that is held, whose run has ended and whose cap has passed (both): it is the one place where the
launcher cleans up on its own, it never happens while the lane's run may still need the resource, and it asks and reads
back as a person's `resource release` does, with `how` `by-itself`. It cannot end a machine whose done path and cap both
failed, and then the report is all there is.

**The cloud adapter's launch settings (step B).** The adapter under `integrations/aws/` launches a machine with these
settings, each of which covers one ordinary mistake:

| Setting | What it must do | What it covers |
|---|---|---|
| Shutdown ends the machine | A shutdown of the machine, by whatever path, terminates it at the provider, instead of stopping it. | The guard, the cap and the done path all end by a shutdown, so each of them releases the provider's resource and stops its billing. A machine that was only stopped would still be held, its storage billed, and no read-back would ever show `terminated`. |
| One-time request, not restarted | The machine is asked for once, and when the provider interrupts it, it is terminated and not started again. | A machine that comes back by itself after an interruption, outside any record. |
| Root volume with the machine | The volume is deleted when the machine is terminated. | A volume that stays after the machine and is billed with nobody holding it. |
| The id on the machine | The resource's id is the tag or the name that `describe` looks the machine up by; the lane's name and the purpose are put where the provider allows. | An acquire answer that was lost: the machine is found again by the id alone. |
| The hard cap | A timed shutdown, set by the user data when the machine boots, `hard_cap_minutes` after boot and not after that. | Everything else failing: a lane that crashed and a guard that is broken, a lane that keeps the machine busy for ever, a launcher that was killed, a laptop that went to sleep. |
| The idle guard | See below. | A lane that crashed, or finished and forgot to release. |
| The done path | See below. | The normal release, at once, even when the machine is busy. |

**The idle guard.** It is a generic script kept in the repository beside the adapter, with no company value in it, and the
adapter installs it through the user data. Values such as the idle interval are set by the adapter's configuration file.
It must:

1. Run once a minute from the machine's own scheduler, as the machine's own superuser, and use only what the machine holds:
   no network, no credential, and no call to the launcher or to the provider.
2. Shut the machine down at once when the done file exists, whatever the load: a release is the decision that the work is
   over.
3. Count the machine as busy when its load is above a threshold, when a container runs, or when a heartbeat file was
   touched recently by a lane that is legitimately waiting; and not count an open login session or a terminal multiplexer
   alone as work, because a stalled lane leaves both open and would keep the machine up.
4. Shut the machine down at once after the idle interval, a number of minutes in a row without a sign of work.
5. Write the reason to the system log before it shuts the machine down.

**The done path.** `release` puts the done file on the machine, by the adapter's own means of reaching it, which its
configuration file names. It answers `releasing` only when the file is in place; when it cannot put it there, it gives no
answer, and the launcher records nothing and the command ends with exit 1. The guard sees the file within a minute and
shuts the machine down; the launch setting turns that into a termination; the read-back shows `terminated`. Nothing in this
chain is a call that the launcher makes to end a machine.

**Three ordinary mistakes.**

- *A lane that crashed.* Nobody calls `resource release`. The machine's load drops and nothing touches the heartbeat, so
  the guard shuts it down after the idle interval, and the cap does at the latest. From the moment the run's end is recorded
  (by its supervising process, or by `lane check` as a lost run), the listing of `lane check` shows the resource with
  `lane-ended`; a read-back records `released` (`how`
  `observed`) once the machine has ended, and with `release_by_itself` a timer's `resource check --read-back` releases one
  that is still there after its cap.
- *A launcher that was killed.* Killed between the intent and the acquire's answer, it leaves a machine that may exist and
  an intent with no `acquired`: the machine's guard and cap run on the machine, not in the launcher; the intent is held and
  listed as `unresolved` once the acquire bound has passed; a read-back finds the machine by its id and appends `acquired`
  (and `released`, when it has ended already). Killed after the adapter put the done file there, the machine ends by itself
  and the next read-back records it. Killed before the adapter was asked, nothing exists, and `resource release`, once the
  acquire bound has passed, closes the intent as failed when a describe after the release says `absent`.
- *A laptop that went to sleep.* The launcher and every timer on the laptop stop, and the machine does not: it runs on its
  own clock with its own guard and cap, which go on counting. So everything that must happen to a machine on its own is on the
  machine, and the laptop's part is only to record: when it wakes, `lane check` lists from events and `resource check
  --read-back` reads back and records what ended.

**What a release collects.** Only the machine, with its root volume. The adapter creates no network group, key pair, image or
other object per run: the shared network settings and the key come from its configuration file, because a credential that
is scoped to a task often cannot delete what a run creates, and an object left behind is a held resource that nobody
records. A collected resource is one that the provider shows `terminated`.

**Other kinds.** For a resource of kind `credential` (step D) the shape is the same: a lifetime that ends it by itself (the
cap), a release that revokes it, and a describe whose `terminated` means revoked or expired. How a lane receives what a
narrowed credential gives it is the page of that example, and never a member of a request, an answer or an event.

### Cost (built by C)

**What is recorded, and when.** Cost is a recorded fact, in events, and a reader never computes it again from other
things. The price per hour is recorded at the intent, with its source, as the intent's `price`. The moment from which a
resource is held is recorded at the acquire (`started_at` of `resource.acquired`). At release `resource.cost` is
appended, right after `resource.released`, by the command that appended it; `resource describe` and `resource check
--read-back` append it for a released resource that lacks one (the append after the release failed, for example), which
needs no adapter. Its members are `resource`, `started_at`, `ended_at`, `price` (the intent's, copied) and `cost`: money
(`{"amount_micros", "currency"}`) or `null` when the price is `null`, so that a missing price is an absent cost and never
a zero. A resource that is still held has no cost event, and `lane cost` counts only recorded costs. The figure is the
launcher's account of what it asked for, price times held time with the adapter's price, and not a bill: what a provider
charges beyond an hourly price (a minimum, storage, transfer, taxes) is not in it.

**The price's source.** It is the member `source` of `price`: `adapter` when the adapter took the price from the provider
at the quote, and `configured` when it took it from its own configuration file ("The adapter contract"). The cost copies
it, and `lane cost` shows it for each cost it counts.

**The held time.** It runs from `start` to `end`, both instants, and the cost event's `started_at` and `ended_at` are the
timestamps they are read from, so that the check at append compares text with what the fold gives ("Events").

- `start` is the `started_at` of `resource.acquired` when it is not `null`; otherwise the time of `resource.intent`, since
  the resource may exist from the moment the launcher decided, so a resource whose provider gave no start is charged from
  the decision and never for less than it ran.
- `end` is the `ended_at` of the release's `read_back` when it is not `null` and not before `start`; otherwise the `at` of
  the `read_back`, the moment the launcher read the end, which is never before the true end. When even that is before
  `start` (the launcher's clock was set back), `end` is `start`: the held time is zero, and the event shows it, because
  `started_at` and `ended_at` are then the same text.
- A time with an offset is compared as the instant it is. The held time `U` is the difference in whole microseconds,
  computed from the two instants with integers only.

**The arithmetic.** Money is whole micro-units of a currency (`amount_micros`, `currency`): never a float, and never a
string to parse. The reason is that a float cannot hold the exact product of a price and a time, and nothing today would
keep one out of an event: the envelope refuses an inexact fraction only in decimal text (`jsonutil.py:25-31`, used by
`event append`), and a launcher command's own append passes a Python float, which is always exactly a double and is
checked only for being finite (`events.py:105-112`, `144-145`). What keeps money whole is the form of the events, which
accepts only an `int` ("Events"), and what keeps the amount exact is the arithmetic below, which uses no float. Let `P` be
the price per hour in micro-units (`price.per_hour.amount_micros`, from 0 to 1,000,000,000), `U` the held microseconds, and
`D` = 3,600,000,000, the microseconds of an hour. With integer operations only:

    amount_micros = (P * U + D - 1) // D

This is the exact product `P * U / D` rounded UP to the next whole micro-unit, so the recorded cost is never below the
exact cost and exceeds it by less than one micro-unit, one millionth of a unit, for each resource: no cost is lost
silently, and nothing is rounded down or to the nearest. `P` of 0 gives 0. The bound of the price keeps the amount below
9,007,199,254,740,991 for any held time under a thousand years. A pair of times that would give more is not recorded: the
check at append would refuse the event, so the command ends with exit 1 and says so, the resource stays `released` and is
listed `cost-missing`, and nothing clipped is ever stored.

The worked cases, each checked twice (once by the integer formula, once by hours):

| Case | `P` | Held | `U` | `P * U` | `P * U + D - 1` | `// D` | Exact | Recorded |
|---|---|---|---|---|---|---|---|---|
| 1 | 500,000 (half a unit an hour) | 1,230.5 s (08:00:00.000000 to 08:20:30.500000) | 1,230,500,000 | 615,250,000,000,000 | 615,253,599,999,999 | 170,903 | 170,902.777… | 170,903 |
| 2 | 1,800,000 | 2,000 s | 2,000,000,000 | 3,600,000,000,000,000 | 3,600,003,599,999,999 | 1,000,000 | 1,000,000 | 1,000,000 |
| 3 | 1,000,000 | 1.8009 s | 1,800,900 | 1,800,900,000,000 | 1,804,499,999,999 | 501 | 500.25 | 501 |

Case 1: `D` times 170,903 is 615,250,800,000,000 and `D` times 170,904 is 615,254,400,000,000, and 615,253,599,999,999 lies
between them; by hours, 1,230.5 / 3,600 is 0.341805… of an hour, half a unit of that is 0.170902777… units, and rounded
up at the sixth decimal it is 0.170903 units. Case 2: 1.8 units an hour for 2,000 / 3,600 of an hour is exactly 1 unit, and
the formula leaves it at 1,000,000 because the remainder is 0. Case 3: `D` times 501 is 1,803,600,000,000 and `D` times 502
is 1,807,200,000,000, and 1,804,499,999,999 lies between them; by hours, 1 unit an hour for 1.8009 / 3,600 of an hour is
0.00050025 units, which is 500.25 micro-units and becomes 501. Truncating gives 170,902 in case 1 and 500 in case 3, and
rounding to the nearest gives 500 in case 3, so the three cases tell the rule apart from both.

**The day.** A day is a UTC calendar day, from 00:00:00 UTC to the next. A cost belongs wholly to the UTC date of its
`ended_at`, after any offset is turned into UTC, so a resource that spans midnight counts for the day it ended and its cost
is never split in two parts that would each need their own rounding. UTC, because every time that the launcher itself
writes is UTC (`recorded_at` and `events.utc_now()`, `events.py:82-83`) and a time that comes with an offset (an event's
`occurred_at` may, `events.py:33-34`, and so may an adapter's time) is turned into UTC first; because a UTC day always has
24 hours and two people always agree on it; and because `[cost]` has no key for a time zone. A person whose working day is
not the UTC day sees the costs near midnight on the other side of the line; whether the boundary should be configurable is
an open point ("Open points").

**The cost of agent runs is absent.** The launcher stores what the runner prints and reads no vendor's cost or usage format
(the vendor formats it reads are Claude Code's session records, for refusal detection: `sessions.py:4` and `32-33`,
`lanes.py:49`, and Claude Code's stream-json lines, which `streams.py` reads for the view of `lane attach` only). A
cost for an agent run could only come from the runner's own stream, through a reader built for that
format, and no design here builds one. A figure from anything else (the length of a log, a price list, the budget) would
be a guess, and a guess is never recorded. So no agent run has a cost event, `lane cost` prints `agent_runs` as `null`
(absent, not zero), and its totals are of resources only. When such a reader exists, the cost of an agent run is an event
of a kind of its own, written by whatever reads the stream. It is never a key added to `lane.ended`: its payload is exactly
the keys in the table of lane events under "Lanes" (`lanes.py:266-269`, with the optional `prompt`), `obj()` refuses any
other key (`lanes.py:133-139`, `360-362`), and a new key would make the store unreadable for an earlier version, as the
`prompt` key does ("Install").

**`lane cost` and the daily figure.** `lane cost` is in "Commands". Its total for a lane is the sum of the `amount_micros`
of the lane's cost events, for each currency, and for each run the sum of the costs of the resources of that run. The daily
figure for a configuration is `lane cost --day D` without `--lane`: the sum, for each currency, of the costs of all lanes
whose `ended_at` falls on the UTC day D. A resource that is released and has no amount (no price, or no cost event yet) is
named in `missing`, on the day of its cost event's `ended_at` when it has a cost event (a `null` price has one), else on
the day of its `released_at`; and a held resource is in no total until it is released.

**`[cost]` is reported against, not enforced.** `[cost]` stays as it is (`currency`, `daily_cap`, `per_run_cap`,
`report_threshold`: numbers of units of the currency, an integer or a finite float that is not negative, `config.amount`,
`config.py:94-96`) and `lane cost` reads it to report. A number becomes micro-units from its shortest decimal form (what
`repr` gives), multiplied by 1,000,000 in decimal arithmetic and rounded DOWN to a whole micro-unit: 0.5 gives 500,000, 2.0
gives 2,000,000, 0.1 gives 100,000, 1.005 gives 1,005,000 and 0.1234567 gives 123,456. It is rounded down so that a total
is reported over a cap at the latest when the exact number would report it, and a float multiplication is not used, because
it can be off in its last place: the double nearest 1.005 is 1.00499999999999989…, so `int(1.005 * 1e6)` gives 1,004,999.
Then, for the totals in the `[cost]` currency (another currency is totalled apart and never converted), `over` holds a run
item for a run whose whole total is above `per_run_cap_micros`, a daily item of `daily_cap` for a UTC day whose total over
all lanes is above `daily_cap_micros`, and a daily item of `report_threshold` for a day whose total is at or above
`report_threshold_micros`, because the report is due before the cap is passed; "Commands" says which of them each form of
`lane cost` computes. That is all that a cap does. No command refuses, stops or releases anything because of one, no event
is written, and the owner channel, which is not built, is not used: until it is, `over` is where the owner's report is. The
totals leave out agent runs, so a cap compares resources only.

### Compatibility (built by A)

**The protocol step.** The events that the launcher writes carry the protocol version of `protocol.md`, which `laneboss
--version` reports. No rule that says what a major, minor or patch step of that version means is written in the
repository: `protocol_version` is documented only as "the protocol version the producer follows" ("Event and state
store"), and nothing in `docs/`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `internal/protocol/protocol.md` or the
protocol package says more. The turn-based design proposes a reading of a minor step: it adds kinds and optional keys,
changes no payload that exists, and keeps every older store valid, a store that holds hand-written events of a kind that
the step newly reserves included, because those are checked at append only. This design adds kinds and one optional key
and changes no payload that exists, but it does not keep that last clause: it checks the `resource.*` kinds in `state
verify` and `state rebuild` as well, so a store with a hand-written `resource.*` event in another form is not valid for it
(the one case below). Under the turn-based design's reading, step A is therefore not a minor step. Under the narrower
reading, that a minor step adds kinds and optional keys and changes no payload that exists, it is one. "Open points" asks
the supervisor which reading wins (point 6), and shows the two ways out if the turn-based reading does: check `resource.*`
at append only (point 8), or take a step that is not a minor one. Step A raises the version line of `protocol.md` by one
step, which, if the narrower reading wins, is the minor step after the one the turn-based design takes, and leaves the text
of the protocol's rules as it is. Which number that is depends on which of the two designs is merged second ("Open
points"). The package version is not changed by this design: an installed version directory is immutable ("Install"), and
`VERSION` in `identity.py` is raised by the person who installs a build, never by a step of this design.

**A store written before this version.** It verifies, reads and rebuilds unchanged, and it needs no `state rebuild` after
the upgrade. It holds no `resource.*` event and no `held` key. The schema, the store's metadata and the marker do not
change, no table is added, and a lane row has the fields it has (`lanes.current_form()` is not touched), so
`state verify` compares the same rows. `resources.replay()` has nothing to replay, and `state verify` prints one key more,
`resources`, with the number 0. One case is different. An event whose kind starts with `resource.` and that was appended by
hand with `event append` was accepted before with any payload, because the launcher checked only the envelope of every
kind that is not `lane.*` or `brief.rendered` (`events.py:148-149`, `428-433`). It is checked now, like a lane event, and
one that is not in the documented form makes `state verify` and `state rebuild` fail with exit 3 naming its `seq`, and
makes every command that reads the resources of its lane fail the same way. No command edits or removes an event, so the
way out is the one that "Event and state store" gives for a store whose events the launcher refuses: keep a copy and start
over ("Starting over"). That is the price of checking these kinds in `state verify` and `state rebuild`: the gate at
`lane mark` is only as good as the fold, and a fold that has to skip events it cannot read is not one. Whether that is the
right price is an open point ("Open points", point 8), and it is also what makes step A not a minor step under the
turn-based design's reading ("The protocol step").

**Rolling back to 0.5.0 across the changes of this design.** This adds to the paragraph "Rolling back to 0.5.0 across the
changes of this version" under "Install", which stays as it is. Every statement below was read from the code of 0.5.0
(commit 919af68), in the files and lines named, and none was run; the launcher at the base of this design (commit 2995b7c,
0.6.0-dev0) has the same code on every path cited, at the same lines of `events.py`, `doctor.py` and `startcmd.py`, and
at the lines `lanes.py:250, 341-343, 346-367, 554-571` and `config.py:128-140, 463-484`. For any other version the effect
of a trigger is not established. A relink back needs the configuration edited as soon as it has trigger (c), and a store
that has trigger (b) fails `state verify`, `state rebuild`, `doctor` and the briefing of 0.5.0; a store that has only
trigger (a) is read by every command of 0.5.0. A configuration can be edited back; a store cannot, because no command edits
or removes an event ("Event and state store"). The triggers, each with the step that builds it ((e) runs the other way):

- **(a) Any `resource.*` event (A, C).** 0.5.0 refuses nothing for them. `validate_envelope` calls `lanes.check` only for
  a kind that starts with `lane.` (`events.py:148-149`), `_append` checks `brief.rendered` and lane events only
  (`events.py:428-479`), `rebuild` and `_verify` check a stored event's envelope and hash and replay lane events only
  (`events.py:544-547`, `601-616`; `lanes.py:536-546`), and no command reads an event of a kind it does not list. So every
  0.5.0 command works on a store that holds them, and the briefing prints their kind as text (`startcmd.py:322`). What
  0.5.0 lacks is the gate and the listing: it accepts or merges a lane that holds a resource, it never lists one, and it
  accepts any payload of a `resource.*` kind appended by hand, which this version would refuse. A store that gets such an
  event while 0.5.0 runs can fail this version's checks when the launcher is installed again.
- **(b) The key `held` of `lane.state` (A).** A lane accepted or merged with `--accept-held` has one. 0.5.0's `lanes.check`
  accepts for `lane.state` exactly `state` and the optional `not_covered` (`lanes.py:243`, `330-332`, `335-347`), so it
  refuses `held` at append (`event append`, exit 2), and `state verify` and `state rebuild` replay every stored lane event
  through the same check and fail with exit 3 for the whole store (`events.py:544-546` and `601-605`); `doctor` (its
  `store.recorded` check calls `verify`, `doctor.py:65`) and the session briefing (`startcmd.py:333-336`) refuse with them.
  No other command of 0.5.0 refuses: none reads a lane's `lane.state` events (`lane_events` and `last_event` are asked
  for `lane.started`, `lane.ended`, `lane.lost`, `lane.gone`, `lane.resumed`, `lane.cleaned` and the three refusal kinds
  only, at `lanecmd.py:778`, `1022-1024` and `1271` and `refusals.py:169` and `948` of that commit), and the lane row has
  no field for `held`. So `lane status`, `lane check`, `lane resume`, `lane clean`, `lane start --reuse`, `lane mark`,
  `lane stop`, `lane scan`, `lane review`, `lane refusals`, `event tail`, `state events`, `state lanes` and `brief render`
  still work.
- **(c) `[resources.NAME]` in a configuration (A).** 0.5.0's `CONFIG` table lists its keys and `table()` refuses any other
  as an unknown key when the configuration loads (`config.py:125-137` and `441-462`), as an invalid configuration (exit 2,
  `errors.py:13-21`) that names the file and the key path, `resources.NAME`. So every 0.5.0 command bound to the
  configuration fails at load (`cli.py:177-184`), even before any resource exists, and `doctor` reports its `config` check
  failed (`doctor.py:168-177`). A relink back needs the table removed. Two launchers of different versions must not share a
  configuration from the moment it has one.
- **(d) The key `resources` of `state verify`'s output (A).** It is output and not stored: nothing in the store records it,
  so no store is refused for it. An older launcher prints no such key (`events.py:622-623`, `cli.py:308-310`), and a
  script that reads `resources` from the output of an older launcher finds none.
- **(e) The reverse: a `lane.state` that an older version wrote for a lane that holds a resource (A).** This is not
  something 0.5.0 cannot read, but what this version must read after 0.5.0 has run on the store. 0.5.0 has no gate: trigger
  (a) lets it read a store that holds resource events, and it accepts or merges a lane that still holds a resource, with a
  `lane.state` that has no `held` and carries the protocol version of its own time. After a relink forward, the replay
  leaves such an event alone, by its version test ("Events"), so `state verify` and `state rebuild` pass, the lane stays
  accepted or merged, and its resources are listed as before (`lane-ended`) and refuse `lane clean` and `lane start
  --reuse`. Without the test the store would fail with exit 3 for good.

Nothing else that this design writes is refused by 0.5.0: it adds no table, no column, no lane row field, no file in the
state directory and no key to an event of an existing kind except `held`. The cost event, the intent and the other three
kinds are `resource.*` kinds, so they are trigger (a). The step that builds each trigger confirms the statements about it
by running 0.5.0 (that commit) once on a test machine, against a configuration and a store that hold it ("The test plan"),
and corrects a statement that the run shows wrong.

**Before a relink back.** The relink works whenever the directory of the older version is still in place ("Install").
What the older version can then do is what the statements above say, and what it cannot do is protect: it has no gate and
no listing. So, in this order: release or close every held resource, with `resource release` (and `resource check
--read-back`, which records the ones that have ended), until `resource list --held` prints `[]`. That, and not `findings`
0, is the criterion: a held resource that is in use has no standing and is not a finding, and an older version would accept
or merge its lane without a word (trigger (e)). A resource that can never be released (the forgotten resource of "Known
limits of this design") makes that criterion unreachable: it is recorded first, by accepting its lane with `--accept-held`,
and the person knows that the older version will neither list it nor gate anything else about it. Then edit the
configuration to remove `[resources]`; and know that a store
that has a `lane.state` with `held` is read by the older version only through the commands named in (b). To run the older
version on a store that has trigger (b), restore a copy of the store made before the first `lane.state` with `held`, or
start the state over, as the paragraph under "Install" says, and keep a copy of the present store first; a store that has
only trigger (a) needs neither. A relink forward again finds the events where they were left, and (e) says what it does
with a lane that the older version accepted.

### Failures (built by A and B)

Each row is one ordinary mistake or failure, what then happens, and the check that blocks it or reports it, named as this
design names it. Two unusual things at once are in "Known limits of this design" below.

| Mistake or failure | Outcome | The check that blocks or reports it |
|---|---|---|
| The launcher is killed (SIGKILL) between `resource.intent` and the adapter's call | Nothing exists at the provider. The intent is stored and the resource is held (`intent`); after `acquire_bound_minutes` it is listed `unresolved`. The lane cannot be accepted or merged without `--accept-held`, and `lane clean` and `lane start --reuse` refuse it. Once the bound has passed, `resource release` sends a release, and a describe after it that answers `absent` appends `resource.failed` (`how` `release`), which ends the resource. | The intent is appended before the call (`resource acquire`, step 2); `resources.standing()` (`unresolved`); `resource release`, steps 1 to 3; the gate in `decide()`. |
| The launcher is killed while the adapter's acquire runs | SIGKILL leaves the adapter running (a terminate or a hang-up ends its group), so a machine may come to exist, and no `resource.acquired` is stored. The resource is a held intent. A read-back finds the machine by its id and appends `resource.acquired` (`found_by` `describe`). | The id that the adapter puts on what it makes ("The adapter contract"); the read-back table (`resource describe`, `resource check --read-back`). |
| The launcher is killed during an acquire, and the orphaned adapter is slow | The kill leaves the adapter running in a session of its own, and the launcher's deadline is gone with the launcher. The adapter keeps its own: it was told `timeout_seconds`, and when that many seconds have passed since it started it creates nothing more and exits with a non-zero status. `acquire_bound_minutes` is longer than `acquire_seconds` by at least one minute (validated), which leaves a margin of about 50 seconds or more once the append's wait of up to 10 seconds is counted, so when the intent is listed `unresolved`, or `resource release` closes it as failed on `absent`, nothing more can be created; a machine that was created is found by its id, unless the provider's lookup by the id lags behind the creation by more than that margin ("Known limits of this design"). | `timeout_seconds` in the request and the contract rule of the adapter's own bound ("How the launcher bounds the command"); the cross rule of `acquire_bound_minutes` and `acquire_seconds` ("Configuration"); the read-back table. |
| The adapter acquired a machine and its answer was lost or malformed (a machine exists and there is no `resource.acquired`) | A time-out, a non-zero exit, two objects, a missing member and a credential-shaped value are all no answer. The outcome is `unresolved` with `why`, nothing is appended, and the resource is a held intent that a read-back finds by its id, as in the row above. | The strict reading of an answer (`adapters.py`, "What is no answer"); the read-back table. |
| The adapter's answer arrives and the append fails (the store is busy) | The command catches the store's error itself: exit 1, outcome `unresolved`, `why` `store`, with the provider's id printed. The resource stays a held intent, and the next read-back appends `resource.acquired`. | The catch in `resourcecmd.py` (without it `cli.py:376-378` would say exit 3, "integrity problem"); the 10-second wait (`DRAIN_SECONDS`); the read-back. |
| `release` answers `releasing` and the read-back still says `running` after the wait, or after the cap | `resource release` ends with exit 1 and the outcome `still-held`, and appends nothing. The resource stays held. Past `cap_at` it is `held-beyond-cap`, reported by `resource check` and by the listing of `lane check`, and the person decides. With `release_by_itself`, `resource check --read-back` asks again once the lane's run has ended and the cap has passed. No part of the launcher terminates it. | `resource release`, steps 3 and 4; `resources.standing()`; `resource check`. |
| The lane ends, or is stopped, while it holds a resource | Nothing releases it. The lane's row says the run ended, so `resource check` and the listing of `lane check` show it with `lane-ended` (for a lost run once `lane check` has recorded the loss). The lane cannot be accepted or merged without `--accept-held`, and `lane clean` and `lane start --reuse` refuse it. | `resources.standing()`; the gate in `decide()`; the refusals in `clean()` and `start()`. |
| Two `resource release` for one resource at once | Both ask the adapter (a repeated release is not an error) and read back. The first appends `resource.released`. The second's append is refused because the resource is already released, so it reads the resource again, reports it and exits 0. One release is recorded. | `resources.check_transition()` ("nothing after released"); the rule of "The read-back" for an append that another command made unnecessary. |
| Two `resource acquire` at once | Two resources, each with its own id, intent and answer. Nothing is shared and nothing collides. The configuration's own rule of one machine at a time is not enforced by the launcher ("Open points"). | The id is made from the operating system's random source; `check_transition()` refuses an intent whose id is stored. |
| The adapter's describe answers a `provider_id` that is not the request's | No answer, reason `output`, reading `unknown`, reported. The launcher does not list a provider's machines, so a machine that no event names is not seen. | The rule in "What is no answer". |
| The events say a resource is held and the provider says `absent` (a wrong account or region after an edit, or the resource ended and was forgotten) | Nothing is appended and nothing is closed. The resource stays held with `absent` in its `standing`; the person looks. The lane can be accepted only with `--accept-held`. | The read-back table; `resources.standing()`. |
| An adapter hangs | At the operation's time-out the whole process group is ended: reason `timeout`, no answer. | `judges.run_command()` through `adapters.call()` (`judges.py:366-397`). |
| An adapter exits non-zero, prints two objects, omits a required member, or prints a credential-shaped value or the credential variable's value | No answer (`exit` or `output`). Nothing of the answer is printed or recorded. The first line of standard error is shown cut and screened, and replaced by `[withheld]` when it holds a shape or the variable's value. | `adapters.py` (`read_answer()`); `judges.explanation()` and the screen for the variable's value. |
| A configuration is edited so that the resource's adapter name no longer exists | The resource is listed `adapter-missing`, and a read-back gives `unknown` with `why` `adapter-missing`. `resource describe` and `resource release` refuse (exit 2). The lane can be accepted only with `--accept-held`. Restoring the name resumes everything. | `resources.standing()`; the refusals of the commands. |
| The variable that `credential_env` names is not set (a wrong variable) | `resource acquire`, `describe` and `release` are refused (exit 2) before anything is sent. `resource check --read-back` gives `unknown` with `why` `credential-not-set` for that adapter's resources and reads the others. | The check in `resourcecmd.py` before any call. |
| The adapter's configuration file is removed or edited by hand | The adapter fails to start (no answer) or looks elsewhere and finds nothing (`absent`). Nothing is closed, because `absent` never closes a resource that has acquired. | "What an adapter puts on what it makes" (`absent` only after looking in the request's region); the read-back table. |
| The machine's idle guard or clock fails | The cap, a timed shutdown on the machine, is the second line. A machine whose guard and cap both fail keeps running: `held-beyond-cap`, reported; the person ends it by their own authority and the next read-back records `released` (`how` `observed`). A wrong clock moves the cap's time: a cap that fires after `cap_at` is reported, and one that fires before it ends the machine early, which cuts a job short and leaks nothing. | The launch settings ("Release"); `resources.standing()`; `resource check`. |
| A hand-written `resource.*` event through `event append` | Refused with nothing stored, like a hand-written `lane.*` event: a form that is wrong, an unknown lane, a wrong order (acquired before its intent, a second acquired, released before acquired, anything after released or failed, an intent for a merged or abandoned lane, a 257th held resource), a `read_back` state that is not `terminated`, and, for a `lane.state` that accepts or merges, whatever protocol version it names, a `held` that is not exactly what the lane holds. A well-formed event that fits the order and states a read-back that never happened passes: it is the forged event of "Known limits of this design". | `validate_envelope()` calling `resources.check()`; `EventStore._append()` calling `check_transition()` and `check_state()`; `resources.replay()` in `state verify` and `state rebuild`. |
| A lane is marked `abandoned` while it holds a resource | Recorded and never held up. `lane mark` prints `held`. `lane check` and `resource check` list the resources, and `lane clean` and `lane start --reuse` refuse the lane until they are released. | No gate for `abandoned`, by design; the refusals in `clean()` and `start()`. |
| A resource's `resource.acquired` waits in the lane's pending file when the lane is marked | It cannot: resource events are never queued, and are appended at once or not at all. What can wait is the lane's own events (`lane.ended`, for example): `lane mark` appends them first and is refused while some cannot be appended, so a lane whose end waits is not accepted past the gate. | `lanes.is_lane_event()` is false for the resource kinds, so there is no pending file for them; `drain()` in `decide()`. |
| `lane clean` or `lane start --reuse` on a lane that holds a resource | Refused (exit 2), naming each resource. Nothing is removed or started, and no event is appended. | The refusals in `clean()` and `start()` ("Commands"). |
| A resource is acquired between the gate's reading and its decision | The append of `lane.state` is refused (exit 2) with a message that says that the held resources changed. Run the command again. | `resources.check_state()` in `EventStore._append()`. |
| A released resource has no `resource.cost` (the append after the release failed) | The resource is `released` and listed `cost-missing`. `resource describe` or `resource check --read-back` appends the cost. | `resources.standing()` (`cost-missing`); "Cost". |
| A command that calls an adapter is interrupted (Ctrl-C, SIGTERM, SIGHUP) | The adapter's process group is ended, the exit is 130, and what is stored stays. An acquire interrupted after the intent leaves a held intent that a read-back finds by id. | The handlers of SIGTERM and SIGHUP, as `judgecmd.py:83-88`; the intent before the call. |
| The quote fails or gives no answer, or the lane is merged between the quote and the intent | `resource acquire` ends with exit 1 (no quote) or exit 2 (the store refuses the intent). Nothing was appended and nothing exists: a quote creates nothing. | Steps 1 and 2 of `resource acquire`; `resources.check_transition()`. |
| `lane check` cannot read the process table | It is refused, as today, and gives no listing. `resource check` gives the listing from events alone. | `lane check`'s own refusal (`lanecmd.py:974-1015`); `resource check`. |
| A store holds a `resource.*` event that this version cannot read (a hand-made store, or an earlier look-alike) | Exit 3, naming the `seq`, from `state verify`, `state rebuild` and every command that reads the resources of its lane. | `EventStore.resource_events()`; `resources.replay()`; "Compatibility". |

#### Known limits of this design

Each of these needs two unusual things at once, or lies outside what the launcher can see, and each names its condition.

- **A lost acquire answer and a read-back in the wrong place** (two unusual things at once). Condition: the adapter
  created a machine and its answer was lost, and then the configuration was edited so that a read-back looks elsewhere (a
  profile, region or account). `resource release` then sees `absent`, and closes the intent as `failed`, while the machine
  exists. The machine still ends by its own guard and cap, and only the launcher no longer lists it. The provider's own
  listing by the id tag shows it.
- **A killed launcher and a lookup by id that lags** (two unusual things at once). Condition: the launcher is killed
  during an acquire, the orphaned adapter creates its machine before its own time-out, and the provider's lookup by the id
  lags behind that creation by more than the margin between the adapter's time-out and the acquire bound, which is about 50
  seconds or more ("How the launcher bounds the command"). The describe after `resource release` then answers `absent` for
  a machine that the adapter just made, and the intent is closed as `failed` while the machine exists. The machine ends by
  its own guard and cap, and only the launcher no longer lists it; the provider's own listing by the id tag shows it. The way
  to avoid it is an `acquire_bound_minutes` that is longer than the cross rule asks for, by more than the provider's lag.
- **A resource that the provider has forgotten.** Condition: the resource ended, and no read-back saw `terminated` before
  the provider stopped answering for it. It stays `acquired` and listed `absent`, because `absent` never closes a resource
  that has acquired: the launcher cannot tell a forgotten resource from one it is looking for in the wrong place. The lane
  can be accepted with `--accept-held`; `lane clean` and `lane start --reuse` stay refused, so its name and directory are
  not reused (a new lane name costs nothing, and the directory can be removed by hand). The way to avoid it is to run
  `resource check --read-back` more often than the provider keeps an ended resource in its listings.
- **An acquire answer lost and the lookup by id unavailable** (two unusual things at once). Condition: the acquire gave no
  answer, and the provider's lookup by the id tag fails or the adapter could not put the tag on. The intent stays
  `unresolved`, the machine ends by its own guard and cap, and a person finds it by hand.
- **The idle guard and the cap both fail** (two unusual things at once). Condition: the machine's scheduler and its timed
  shutdown both fail, a broken image for example. The machine keeps running and is reported, and the launcher never
  terminates it.
- **A forged `resource.released`.** Condition: someone who can run `event append` writes a well-formed event that states a
  read-back that never happened. The store checks form and order and cannot see the provider, so it passes; a hand-written
  event that is meant to deceive is outside what the launcher defends against ("What isolation covers"). `resource
  describe` of a released resource reads it again and reports `disagrees` when the provider shows it `running`.
- **An adapter that lies.** Condition: an adapter answers `terminated` for a resource that is running, or a wrong price,
  `started_at` or `provider_id`. It is believed, as a judge is, and the record and the cost follow it. The defences are the
  contract tests, the real trial of each adapter, and a person's reading of the provider's own listing.
- **An adapter configuration file that holds a secret.** Condition: the company puts a key into the file that its adapter
  reads. The launcher never reads that file, `config validate` sees only its path, and the repository's scan does not see
  it, because it is outside the repository. Nothing here can see it. The adapter's page says that the file holds names and
  settings only.
- **A resource that no event names.** Condition: a machine started outside the launcher, or started by a launcher whose
  store was afterwards replaced by an older copy ("Restoring an older copy"). The launcher does not list a provider's machines,
  so it cannot see it. The tag with the id and the lane's name is how a person finds it.
- **The launcher's clock moved.** Condition: the clock is set back or forward by more than the acquire bound or the cap
  while a resource is held. `unresolved` and `held-beyond-cap` then come late or early, and a release read while the clock
  was behind records a held time of zero ("Cost"). Nothing recorded is changed.
- **What a provider charges beyond the price.** Condition: always. The cost is the adapter's price times the held time; a
  minimum charge, storage, transfer and taxes are not in it ("Cost").

### The test plan

Each step is built test first, as `CONTRIBUTING.md` asks: its tests are written from the text of its part, run, and seen to
fail because the feature is missing or wrong (an unknown command, key or event kind), and not because of their setup; only
then does the code change, and no test is skipped, weakened or left as a stub to get a run green. The end-to-end tests drive
the installed `laneboss` command, as the tests in `tests/e2e/` do (`support.install()` installs the launcher into a
temporary prefix), use the stand-in adapter below and the stand-in runner `tests/e2e/standin.py`, and mock nothing of the
launcher. They run on a disposable test machine and never on the machine where the code is written. The suite needs no
cloud account, no credential and no environment variable set from outside it: a test that needs a variable makes up a
harmless name and value of its own. Each step also has one real trial against the real thing, which is a written procedure
that the step's lane runs and reports, and not part of `tests/`. Where a real trial may run, and with which account, is the
configuration's rule (rule 1 of the shared protocol), not this document's.

**How a test shows that it can fail.** The standing rule of the launcher's configuration, which every brief carries, is that
no test, check or product file may pass by returning a constant, hard-coding the expected value, ignoring its input,
special-casing a test's literal or swallowing a failure (`|| true` after a check, a bare `except: pass`, a test with no
assertion, a skip). For this feature that means:

- Every test is run red first, and the report of the step names, for each check, what makes it fail. The first red is the
  missing feature. For each rule that a wrong build could break, the test must also fail on a deliberate wrong variant of
  the code, and the report names the variant: the gate test on a build that lets a configuration without guards through, the
  release test on a build that writes `resource.released` when the adapter says `releasing`, the strict-reading tests on a
  build that defaults a missing required member, the arithmetic test on a build that truncates, rounds to the nearest or
  computes in floats and stores the integer (the two literal cases of step C below tell all three from the formula), the
  environment test on a build that hands the launcher's environment on, the secret test on a build that echoes the
  credential variable's value in a message, and the version test of the gate on a build that applies it at append, or not in
  the replay.
- The expected values come from this text and not from the code under test: the worked cases of "Cost" are literal numbers
  in the test, and no test reads the product's own constants or tables to build what it expects.
- The stand-in adapter has no branch keyed on a test's literal (an id, a lane name, a purpose): it behaves as its
  configuration file and the request say, and its behaviours are named by the contract rule they break.
- Every assertion is on what an outside reader sees: exit codes, the printed value, the events that `event tail` and `state
  events` print, and what the stand-in recorded. A side effect is verified through the same interface, and a refusal is
  shown by the store being unchanged afterwards (the count of events before and after).

**The stand-in adapter (B).** `tests/e2e/resourcestandin.py` is run as the `command` of a `[resources.NAME]` and, like the
stand-in runner, is a program and not a mock of the launcher. Its behaviour is decided only by its configuration file,
an argument of `command`, and by the request. It keeps its "provider" in a directory that the file names: one small file for
each resource, named by the id, with the provider's id, a start time and a state. It answers every operation and state of the
contract in the right form, and is idempotent as the contract asks (an acquire for an id that exists answers the existing
one, a release twice is not an error, a describe of an unknown id says `absent`, a quote creates nothing). It records, in
a file beside that directory, each request exactly as it received it and the names and values of the variables of its own
environment, so that a test can read what the adapter was given. And it can be told, for each operation, to break one rule of
the contract, each rule having a behaviour of its own:

- an exit status that is not 0 after a valid object was printed, and an end by a signal;
- a hang past the operation's time-out, with a child in the process group (which must be gone afterwards) and, as a pinned
  limit, a child in a session of its own;
- output that is two objects, text before or after the object, bytes that are not UTF-8, or more than 64 KiB;
- a repeated member, a member that is not in the contract, and a price member in a describe answer;
- **each required member absent**, one behaviour that takes the member's name, for every state of every operation: an absent
  required member must be refused exactly like an unreadable one, with the same reason (`output`) and the same effect (nothing
  appended), so the test compares the two outcomes and a build that defaults the member fails it;
- a member of the wrong type or outside its bound: a string for a whole number, a number with a fraction or an exponent, `true`,
  `null` where it is not allowed, a price above the bound, a currency in lower case, a `price_source` outside its list, and
  three price members of which some are `null`;
- a state that the operation does not allow: `quoted` for an acquire with `dry_run` false, `acquired` for a quote, `running`
  for a release, `releasing` for a describe, and **`released` as the answer to an acquire and to a release**, which must be
  refused and must never lead to a `resource.released`;
- a describe that answers another `provider_id` than the request's;
- a credential shape in each string member (assembled from pieces in the test, as the other tests do), and the value of the
  credential variable in a member and on standard error;
- standard error with a long line, control characters and a credential shape; an adapter that reads no input;
- an acquire that creates the resource and then loses its answer (it exits non-zero, or hangs), so that a machine exists and
  no answer was given; an acquire that answers `failed` with a reason; a quote with a `null` price; a describe that answers
  `absent` for a resource it created; a `started_at` far in the past, so that a cap has passed without anyone waiting; a
  resource that takes a long time to end after a release, and one that ends only when the done file is placed; an acquire
  that is slower than its `timeout_seconds`, once obeying its own bound (it creates nothing after it and exits with a
  non-zero status) and once not (it creates after it), which a contract test tells apart by the provider's records.

**A, the core.** The end-to-end tests, through the launcher's own commands:

- `config validate`: every refusal of "Configuration", each naming its key path and never the value (an unknown key, a wrong
  type, each bound, a missing `command`, `kind` or `hard_cap_minutes`, a `credential_env` that is `PATH`, starts with
  `LANEBOSS_`, has lower-case letters or holds a credential shape, a path into another organisation's tools, an
  `acquire_bound_minutes` that is too short); `doctor`'s `resource.NAME`; and a configuration without `[resources]`, whose
  output is what it was.
- `resource acquire`: the events in order (`resource.intent`, `resource.acquired`, read from `event tail`), the record, and
  what the stand-in was given: the members of the table of the request, exactly, `dry_run` true and then false, the acquire's
  `size` and `region` equal to the quote's, an environment of exactly `PATH` and the named variable, and an ambient variable
  that the test sets in the launcher's environment (a made-up name, standing for a default profile) not seen. The value of
  the credential variable is found nowhere afterwards: in no event, no printed value, no message, and no file of the state
  directory.
- A quote that fails or gives no answer appends nothing (the count of events is unchanged), exits 1 and leaves nothing at
  the stand-in's provider.
- Each way of losing an answer: the outcome is `unresolved` with its `why`, the resource is held, `resource describe` finds
  it by its id and appends `resource.acquired` (`found_by` `describe`), and `resource release` releases it.
- The store busy after the answer: the test holds the store's write lock, as other lane tests do, runs `resource acquire` on
  a stand-in that creates the resource, and sees exit 1, `unresolved` with `why` `store` and the provider's id printed; once
  the lock is released, `resource check --read-back` records the acquire.
- A launcher killed in the middle: the stand-in blocks in the acquire, the test kills the launcher by its process id (never
  by a pattern), and the intent is stored, the resource is listed `unresolved` once the bound has passed, and a read-back
  finds the resource. The stand-in, which was told `timeout_seconds`, creates nothing after that many seconds and exits with
  a non-zero status (its record shows it), so that nothing appears after the intent is closed.
- `resource release`: the wait and the polling until `terminated`, then `resource.released` (`how` `release`) and not
  before; `still-held` with a resource that does not end (exit 1, nothing appended); `read_back_wait_seconds` 0; `absent` for a
  resource that has acquired never closes it; an intent inside its acquire bound is refused (exit 2); after the bound a
  release closes an intent as failed on `absent`, and a describe that finds the resource `running` during the wait appends
  `resource.acquired` once; a resource that is not held is printed and exits 0.
- `resource check`: without `--read-back` no adapter is called (the stand-in's record shows none) and nothing is appended; each
  reason of the standing table that `resource check` can show appears for the case that makes it (`lane-ended`, which is
  not shown while a later run goes on after a `lane resume`, `held-beyond-cap`, `unresolved`, `adapter-missing`, `unknown`,
  `absent`, `cost-missing`); exit 0 with no finding and 1 with one; `release_by_itself` acts only on a held resource whose
  lane's run has ended, whose cap has passed and whose reading is `running` or `absent`, and never otherwise, and never when
  it is `false`.
- `resource describe`: the read-back table, one row at a time (`running`, `terminated`, `absent` and no answer, for a
  resource that has an intent only, one that has acquired, a released one and a failed one), the events appended in order,
  the exit codes, and `disagrees`, which only this command shows: a released or failed resource that the stand-in shows
  `running` is a finding (exit 1) and nothing is appended.
- The gate, in one table: with a held resource `lane mark --state accepted` and `--state merged` are refused with the
  message of "Commands" and nothing is recorded, for a configuration with guards and for one without; with guards and an
  unreviewed suspicion at once the resource refusal comes first; `--accept-held` records `held` with the right items;
  `--accept-held` with nothing held, or with another decision, is refused; `--state abandoned`, `--state verifying`,
  `--landing` and `--gone` are never held up and print `held`; the gate takes the lanes lock (the test holds `lanes.lock`
  itself, as `tests/e2e/test_lane_ownership.py` does for `lane start`, and the mark is refused after `[lanes]
  lock_wait_seconds`). The race between the gate's reading and its decision cannot be placed by any end-to-end test, so its
  rule is covered by the next item.
- Hand-written events through `event append`, the launcher's own interface for them, each refused with nothing stored: every
  refusal of the checks table of "Events" (a wrong form, an unknown lane, a second `resource.acquired`, `resource.released`
  before `resource.acquired`, an event after `released` or `failed`, an intent for a merged lane, a 257th held resource, a
  `read_back` state that is not `terminated`), and a `lane.state` that accepts or merges, whatever protocol version it
  names, without `held`, with a `held` that lacks a held resource or names a released one, or with `held` for another
  state. One well-formed forged `resource.released` is pinned as accepted, so that a change of that limit is deliberate. The
  version test is pinned too: a `lane.state` that accepts or merges, has no `held`, names the protocol version of
  0.5.0 (1.1.0) and belongs to a lane that holds a resource is refused at append, like the same event with the protocol
  version of step A; and a store that holds one, made by hand as the other store tests make theirs, verifies and rebuilds
  (the relink case, trigger (e) of "Compatibility").
- A lane whose `lane.ended` waits in its pending file, made as the existing tests make it: `lane mark` is refused, and no
  resource command creates a pending file.
- `lane check`: the key `held`, no adapter called, nothing appended by the listing, exit 0, `events_waiting`.
- `lane clean` and `lane start --reuse` on a lane that holds a resource are refused with the wording of "Commands" and change
  nothing, and go on after the release.
- Two `resource release` started together on a stand-in that delays: one `resource.released`, both exit 0; two `resource
  acquire` together: two resources.
- `state verify` and `state rebuild`: a store with resource events verifies and prints `resources`; a hand-made store in
  which `resource.released` comes before `resource.acquired` fails both with exit 3 naming the `seq`, and `rebuild` leaves
  the rows as they were; a hand-appended look-alike `resource.x` in another form fails them too (it pins the strictness of
  "Compatibility"). A store written before this design, made of events in the 1.1.0 forms, passes `state verify` and
  `state rebuild` changes nothing: its rows are pinned in the test as literal JSON, so the suite needs no second source
  tree.
- The exit code of each outcome of each command, in one table, and no resource command ever exits 7.
- A launcher that is sent SIGTERM while an adapter hangs exits 130, the adapter's group is gone, and the intent stays.

The real trial of A: the installed launcher, a lane run by a real runner in tmux, and a stand-in whose resource is a real
local process, started detached by the acquire with a cap of its own and a watchdog that ends it when the done file
appears. The trial acquires the resource, kills the launcher, reads the resource back by its id, sees the gate refuse and
then accept with `--accept-held`, releases the resource (the done file ends the process), sees `terminated`, and cleans the
lane. The check after it: the stand-in's record names the process by its identity, none of the trial's processes is alive,
and `resource check` has no finding.

**B, adapters.** The contract tests above run against the stand-in. The real cloud adapter runs the same contract tests
against a stand-in of the provider's own command-line tool, which is a mock of a third party that a test machine cannot
reach and is said to be one: a program first on the adapter's `PATH` that records the arguments it is given and answers with
invented output. The tests read the launch settings in those arguments (a shutdown that ends the machine, a one-time
request, the root volume that goes with the machine, the id tag, the cap and the guard in the user data); that `release`
places the done file and that no terminate call ever arrives, the stand-in tool failing the test if one does; that no network
group, key pair, image or volume is created; and that a describe answers `absent` only after a look in the request's region.
The idle guard is run on the test machine with the commands it calls (`shutdown`, `logger` and the container command)
replaced by programs that record their calls: the done file gives a shutdown whatever the load; a load above the threshold, a
running container or a fresh heartbeat gives none and resets the idle clock; an open login session alone does not count as
work; the idle interval gives a shutdown; and the reason is logged first.

The real trial of B: a real machine through the real adapter, after the written approval of the person who owns the cloud
account. It needs the one scoped identity that the adapter's page names, and no administrator's and no default profile; the
shared network settings and key from the adapter's configuration file; no per-run resources; the idle guard and the hard cap
in the user data, with a cap of a few minutes and the smallest size; and its collection confirmed by a read-back that shows
`terminated`. A trial that leaves a machine running is a failed trial. The check after it has two parts: `resource check
--read-back` shows no held resource and `lane check` lists none; and the provider's own listing, read by a person with the
account's authority and outside the launcher, shows no machine or volume tagged with the trial's lane name that is not
terminated or deleted, and no network group, key pair or image left by it. Whatever is left is ended by that person, and
the trial is reported as failed.

**C, cost.** The tests of `lane cost` pin the three worked cases of "Cost" as literal numbers, so that truncating and
rounding to the nearest each give a different number for at least one of them. They also pin two cases on which a build
that computes in floats and stores the integer gives another number. First, `P` = 7 and `U` = 2,573,486,742,857,143
microseconds (about 81.6 years): `P * U` = 18,014,407,200,000,001 = 5,004,002 `D` + 1, so the formula gives 5,004,003,
while in doubles `P * U` rounds to 18,014,407,200,000,000 (the spacing of doubles above 2^54 is 4) and the quotient is
exactly 5,004,002. Second, the cap 1.005, which the decimal rule makes 1,005,000 micro-units and `int(1.005 * 1e6)` makes
1,004,999 (the double nearest 1.005 is 1.00499999999999989…). The form of the event takes a whole number only, which keeps
a float out of the store but not out of the arithmetic; these two cases are what show the arithmetic. Table tests cover:
the start when the provider gave none (the time of the intent), the end when `ended_at` is `null` or before the start, and
when even the read time is before it (a held time of zero, with `started_at` and `ended_at` the same text); times with
offsets; a `null` price (`cost` `null` and `missing` with `no-price`); a resource that spans midnight (it counts wholly for
the UTC day of its `ended_at`); the conversion of `[cost]` numbers (0.5, 2.0, 0.1, 1.1, 0.1234567 and 1.005 give 500,000,
2,000,000, 100,000, 1,100,000, 123,456 and 1,005,000); each item of `over` at, just below and just above its boundary, with
the report threshold at the boundary and the caps above it, for each of the three forms of `lane cost` (a run's whole total
against `per_run_cap` whatever `--day` says, and the daily items over all lanes whatever `--lane` says, with `lane` and
`run` `null`); `missing` on the day of the cost event's `ended_at` and, without one, of `released_at`; another currency
totalled apart; `agent_runs` `null`; exit 0 with a cap passed. Through `event append`, a `resource.cost` whose amount is
one more or one less than the arithmetic, or whose times or price differ from the fold, is refused, and a `lane.ended`
with an extra key is still refused, which pins that no cost is ever a key of it. The real trial of C: the cost that the
launcher recorded for the machine of B's trial is compared by hand with the provider's own billing view of that machine and
period and with the price the adapter reported (and, when its source was `configured`, with the provider's rate for that
size). They must agree to what the provider's rounding and minimum charge explain, and the difference is written down.

**D, the credential-scope example.** Its own tests use a stand-in of the provider's tool and the same contract tests with
the kind `credential`: what the adapter makes has a lifetime that ends it, `release` revokes it, and a describe's `terminated`
means revoked or expired; no secret is ever in a member, an event or a message, which the tests show with a made-up value that
the stand-in tool hands out and that is searched for in every file of the state directory and in every printed value. The
real trial of D, after the written approval of the person who owns the account: a real narrowed credential is made for one
lane, one command that is inside its scope succeeds and one that is outside it is denied by the provider, the credential is
released, and a read-back shows it revoked or expired; the check after is the provider's own listing of credentials.

**What each step amends.** Besides the part of its own, a step that builds a part edits the existing text that the part
makes untrue, in the commit that builds it: for A, in this document the Binding bullet and the commands table and the
table of exit codes of "Command line contract", the paragraph on reserved kinds and the sentence on what `state verify`
prints in "Event and state store", the commands table, the events table and "Not built yet" of "Lanes", "Integrity", the
table of "Doctor" and the rollback paragraph under "Install" (which takes in the statements of "Compatibility" once the run
of 0.5.0 has confirmed them), and, outside this document, the configuration reference, `protocol.md` (its version line),
the README and the changelog; for C, the same documents where they speak of cost and of `[cost]` as unused. The "Layout" rows
of the section change from "Designed, not built" to what they hold.

### Open points

**Decided.** These were open points, and each now stands in the part that it names:

- One adapter command for every operation, with a member `operation` (and the boolean `dry_run` that makes an acquire a
  quote), and not three commands: "The adapter contract".
- No egress-style log for resources, because the events are the record: "The adapter contract".
- The money day is a UTC day, a cost belonging to the day of its `ended_at`, and `[cost]` is reported against and not
  enforced: "Cost".
- `lane clean` and `lane start --reuse` refuse while a resource of the lane is held: "Commands".
- The quote, `hard_cap_minutes` as a required key, `acquire_bound_minutes`, the members of `resource.cost`, the option
  `--id` and exit code 1 for a command that got no usable answer: the parts that define them.
- The version test of the gate is the replay's alone: `append()` checks every accepted or merged `lane.state` against the
  fold, whatever protocol version it names, and `state verify` and `state rebuild` leave alone one that names a version older
  than step A's, so that a store in which an older launcher accepted a lane still verifies: "Events", "Compatibility".

Each point below is a place where the design could not be settled from what exists, or where its proposal needs the
supervisor's confirmation. The proposal stands unless the supervisor says otherwise.

1. **The quote as an acquire with `dry_run` true.** The intent event is appended before the acquire and carries the price,
   so the price must come from a call that precedes the intent; and the operations are three. Proposal: the quote is an
   acquire whose request has `dry_run` true and whose answer has the state `quoted`. Why: it keeps three operations and one
   command, a dry run is how providers usually offer a price without creating anything, and it makes the price known before
   the intent, which is what any check of a cap at the intent needs (point 10). The alternative is a fourth operation,
   `quote`, which says the same thing in another word.
2. **A resource that can never be read back as `terminated`.** A resource that the provider forgot before any read-back saw
   `terminated` stays `acquired`, listed `absent`, because `absent` never closes it; its lane can be accepted only with
   `--accept-held`, and `lane clean` and `lane start --reuse` stay refused, so the lane's name and directory are not
   reused. Proposal: leave it. A new lane name costs nothing, the directory can be removed by hand, and the way to avoid it is
   to run `resource check --read-back` more often than the provider keeps an ended resource in its listings. The
   alternative is `--accept-held` on `lane clean` and `lane start --reuse` as well, recording what was held in their events,
   which adds a key to `lane.cleaned` and to `lane.started` and a trigger for earlier versions for each.
3. **Closing an intent as failed on `absent`.** `resource release` appends `resource.failed` (`how` `release`) for an intent
   when a describe after the release says `absent`; that is wrong only if the acquire answer was lost and the read-back also
   looked in the wrong place ("Known limits of this design"). Proposal: accept the limit. The alternative is never to close
   an intent from a read-back, which would leave every intent of a killed launcher held for ever and put `--accept-held` on
   every such lane.
4. **Held resources in the briefing and in `lane status`.** Neither shows them; only `lane check`, `resource check` and the
   output of `lane mark` do. Proposal: show them in both, from events and read-only: a line for each lane that holds a
   resource in the briefing, and the count in the `live` part of `lane status`. Why: a supervisor reads the briefing first,
   and a resource nobody lists is the failure this design exists to prevent.
5. **A limit on the resources a lane holds at once.** The launcher limits only the 256 that `held` can list; the
   configuration's own rule of one machine at a time is not enforced. Proposal: no key now. A limit belongs to a
   configuration, so a `max_held` of `[resources.NAME]` would be the place, refusing an intent when the lane already holds
   that many of the adapter's resources.
6. **The protocol step, and what a minor step means.** No rule says what a minor step of the protocol version means, and the
   turn-based design proposes a reading and takes the next minor step for itself. Under its reading (a minor step keeps
   every older store valid, a store that holds hand-written events of a newly reserved kind included, because those are
   checked at append only), step A is not a minor step: it checks `resource.*` in `state verify` and `state rebuild`
   (point 8). Under the narrower reading (a minor step adds kinds and optional keys and changes no payload that exists), it
   is one. Proposal: the narrower reading wins, and this design takes the minor step after the one that the turn-based design
   takes, naming no number, because which number each design gets depends on which is merged second; the order of the
   merges decides the numbers, and the second merge sets the version line of `protocol.md`. If the turn-based reading wins,
   there are two ways out, and the supervisor decides: check `resource.*` at append only (the alternative of point 8), which
   makes step A a minor step again, or take a step that is not a minor one.
7. **Exit code 1 for the resource commands.** They use 1 as `judge ask` does (the row of its table of exit codes in
   `docs/judges.md` that reads 1, "Unavailable"), and the row of the table of "Command line contract" names only `doctor`.
   Proposal: the step that builds A rewrites that row to say what 1 means for each command that uses it, and adds the 130 that
   today's launcher already exits for an interrupt.
8. **Checking `resource.*` events of an earlier store.** A store that holds, appended by hand, an event of a kind that starts
   with `resource.` in another form fails `state verify` and `state rebuild` ("Compatibility"), while the turn-based design
   checks its `loop.*` kinds at append only. Proposal: check them in `state verify` and `state rebuild`, because the gate is
   only as good as the fold and a fold that skips events it cannot read is not one. The alternative is to check them at
   append only and have the fold ignore a stored event that is not in the form, which keeps such a store working and lets
   a malformed event hide a held resource.
9. **The day boundary.** UTC, by the `ended_at` of a cost. Proposal: UTC. If a company wants its own working day, add a key
   of `[cost]` that names a fixed offset in minutes (no time zone names), applied to the day of a cost and to nothing else.
10. **Whether `[cost]` caps are enforced at `resource.intent`.** They are reported only. Proposal: not now. If it is wanted, the
    quote's price times the cap's minutes gives what an intent could cost, which `resource acquire` can compare with what is
    left of the day's cap before it appends the intent; it needs a decided rule for a `null` price and for the agent runs'
    cost, which is absent, so that the comparison would see only resources.
11. **Turn-based lanes.** A lane that is continued turn by turn reaches the state `waiting` and never `accepted` or
    `merged`, so the gate cannot be what finds its held resources: `resource check`, the listing of `lane check` and the
    `held` that an `abandoned` mark prints do, and `lane clean` and `lane start --reuse` refuse it while a resource is held.
    What must be settled between the two designs, each with a proposal:
    - *The order of the refusals.* `lane start --reuse` is refused for waiting mail by the turn-based design, in the command
      and at append, and for a held resource by this one, in the command; `lane clean` has no refusal of the turn-based
      design's, so only the resource refusal applies to it. Proposal: for `lane start --reuse` both run under the lanes lock
      after the checks of the lane's state and processes, mail first and resources second, each refusal naming its own
      cause only; a person who fixes one meets the other.
    - *`lane check` for one lane.* The turn-based design gives `lane check` an option that limits it to one lane. Proposal:
      the listing of `held` follows it and covers only that lane.
    - *A resource between turns.* A resource acquired in an earlier turn is `lane-ended` while the lane waits between turns,
      because the run that acquired it ended; it is a finding and not an error, the cap bounds it, and `release_by_itself`
      acts only after the cap. Proposal: keep it, so that a machine nobody has touched since its turn ended is listed; the
      alternative is a standing for a lane that is `waiting`, which the launcher cannot tell from a lane that is merely idle.
    - *The shared lists.* The "Layout" table, "Not built yet", "Left for later lanes" and the paragraph of "Lanes" on what
      the launcher never does on its own are added to by both designs, and the merge keeps both.
    - *The protocol number:* point 6.
12. **Which commands call an adapter.** This section lets four commands call one: `resource acquire` (it cannot be
    otherwise), `resource describe`, `resource release` and `resource check --read-back`. The design was first stated with
    two of them, `resource check --read-back` and `resource release`. `resource describe` appends events too:
    `resource.acquired` (`found_by` `describe`), `resource.released` (`how` `observed`) and `resource.cost`. Proposal: keep
    it. A describe is a read-back, a person who reads one resource back should not need the whole of `resource check`, and
    `lane check` and `resource check` without `--read-back` still call nothing. The alternative is that `resource describe`
    prints its reading and appends nothing, and only `resource check --read-back` and `resource release` record what a
    read-back shows.
13. **Retiring `[test_environments]` and `{machine}`.** They stay validated and unused ("Configuration"). Proposal: retire
    them in a step of their own, after the adapters exist and once no configuration names them. Removing a key of the
    configuration schema makes a configuration that has it invalid for the launcher that no longer lists it, and only the
    owner of a configuration knows whether it uses them.
14. **What `running` and `terminated` mean.** "The adapter contract" defines them: `running` is any state before the end (a
    stopped machine included), and `terminated` is ended and collected (a machine terminated with its volume deleted, a
    credential revoked or expired). Proposal: keep it. A provider that has a state between the two (a machine that is
    shutting down) is `running` until the provider shows the end. The alternative is a third state of the contract for
    "ending", which every reader of the contract would have to handle.
15. **Whether an acquire may change size or place.** It may not: it creates exactly the request's size in the request's
    region, or answers `failed` ("The adapter contract"). Proposal: keep it. An adapter that wants a fallback answers the
    fallback's size and region in its quote, so that the intent records what the acquire creates. The alternative is an
    `acquired` answer that carries the size and region that were made, which the intent, appended before, could not have
    recorded.
16. **What a person does with a resource that `disagrees`.** A released or failed resource that the provider shows `running`
    is reported by `resource describe` (exit 1, nothing appended), and `resource release` refuses a resource that is not
    held, so nothing records or ends it. Proposal: leave it. The person ends it at the provider with their own authority, and
    the next `resource describe` reads `terminated`; a command that re-opens a released resource would contradict "nothing
    after released". The alternative is an event of a kind of its own that records the disagreement, which adds a kind.
17. **The adapter's own bound after a killed launcher.** The request carries `timeout_seconds`, and an adapter that has not
    answered when that many seconds have passed since it started creates nothing more and exits with a non-zero status
    ("The adapter contract"). Proposal: keep it. The alternative is that a release of an id the adapter finds nothing for
    marks the id as ended at the provider, so that a later acquire of it answers `failed`; that needs state at the provider
    that every adapter would have to keep.
18. **How short a credential value may be for the "contains the value" search.** The launcher refuses an answer, and hides a
    line of standard error, that contains the value of the credential variable; a short value would match common text and
    make every answer no answer. Proposal: the search looks for the value only when it is at least 8 characters long, and a
    shorter value is not searched for. The alternative is to refuse, before any call (exit 2), a credential variable whose
    value is shorter than that.

## Integrity

`laneboss state verify` (exit 3 on any problem) runs, inside one read transaction:

- SQLite `PRAGMA integrity_check`;
- the schema definition: every object in `sqlite_master` must be one of the expected tables and
  triggers with exactly the expected SQL, or one of SQLite's own objects for those tables
  (`sqlite_sequence` and the automatic indexes, compared by exact name, not by a `LIKE` pattern), so
  a dropped trigger and an added look-alike such as `sqliteXextra` are both reported;
- the metadata: format, owning configuration, creation time and store id, and that the ownership
  marker records exactly this store;
- every event: contiguous `seq` from 1, canonical payload, recomputed `sha256`, a valid envelope,
  and the highest issued `seq` equal to the last stored one (a removed tail is reported);
- the stored lane projection against a fresh fold of the events, key and row together (a lane row
  whose key no longer matches its projection is reported; `state rebuild` restores it), replaying the lane
  life-cycle checks `append()` makes (every lane payload is checked with the envelope);
- every `brief.rendered` event against the payload rendering writes (the same check append makes),
  and every input it names: the copy at `lanes/LANE/inputs/SHA256` exists and hashes to its name (a
  deleted copy or a deleted `lanes/` directory is reported with the event's seq and the copy);
- every kept input: its name equals the SHA-256 of its bytes, and nothing below `lanes/` is a link;
- every message file of a lane that has a `mail/` directory: its name is `SEQUENCE-DIGEST` (nine digits of sequence, a
  hyphen, the SHA-256 of its bytes) or starts with `.tmp-` and is skipped; it is a regular file that is not a link
  whose bytes hash to the digest in its name; and every `lane.mailed` event has its file, of the `bytes` the event
  says. A message file that no event names is an orphan: it is counted, never a problem. For a mail directory this
  check takes the place of the rule that a kept file's name equals the SHA-256 of its bytes, because the sequence is
  part of the name.

The output has `kept_inputs` (the kept inputs checked), `mail_files` (the message files checked) and `mail_orphans`
(the message files that no event names); with no store yet they are present too. The sequences of a lane's
`lane.mailed` events are checked with the other lane rules, by the replay of the lane's events.

Hashes detect accidental corruption and careless edits, not a writer who rewrites both data and
hashes.

## Protocol and briefs

`internal/protocol/protocol.md` holds the shared protocol and a `Protocol version: X.Y.Z` line;
`laneboss --version` reports it. Its eleven rules and the refusal rule are written in neutral English.

`laneboss brief render --config N --lane L --in BRIEF --out RENDERED [--project P] [--touches billing]
[--touches deploy]`:

1. Validates the lane name and the project, and reads `--in` once through its checked directory
   (isolation rules above; a regular file only). The standing rules are the bytes the configuration
   loader already read and validated; nothing is read a second time.
2. Decodes the brief as UTF-8 and refuses it when it contains a credential (the error names the
   line) or already contains a launcher block.
3. Mandatory sections, found by Markdown `#` headings outside fenced code:
   - `--touches billing`: a heading containing "Cost" whose section gives a value for the unit
     price, the per-run cap, the daily cap and the worst case;
   - `--touches deploy`: a heading containing "Preflight" whose section gives a value for the calls
     made at deploy time, the permission each needs, where it is granted ("Where granted" or
     "Granted in") and the read-back.
   A label counts only in the section's body, outside fenced code, and only with a value: either a
   line `Label: value` (a list bullet and emphasis allowed), or a table whose header has a column
   for the label and at least one row with a value in it. A heading that merely lists the labels,
   a table header without a row of values, labels without values and labels inside a fence are
   refused, and the missing labels are named. Fences follow these parts of the Markdown rule: a
   fence opens with three or more backticks or tildes (indented by up to three spaces) and closes
   only with the same character, at least as many of them, and nothing after them but spaces; a
   fence that is never closed runs to the end of the brief; lines end at LF, CRLF or CR. Not
   implemented: a backtick fence whose info string contains a backtick still opens a fence (Markdown
   says it does not), and fences inside block quotes or list items are not recognised.
4. Composes the output: the input bytes unchanged (a final newline is added only when missing),
   then a block between `<!-- laneboss launcher block: begin (protocol X.Y.Z) -->` and
   `<!-- laneboss launcher block: end -->` holding the configuration, project, lane, protocol version and
   brief hash, the protocol text (which includes the refusal rule), and each standing-rules file
   (the organisation's rules, then the configuration's rules, then the project's rules; see "Organisations")
   with its hash. The block has no timestamp, so equal inputs render equal bytes.
5. Opens `--out`'s directory and checks it (it must not hold the file), opens the store, then, under
   the state directory's lock, keeps a copy of each consumed input (brief, protocol, each rules file)
   at `STATE_DIR/lanes/L/inputs/SHA256`, writes the output through a temporary name in the output
   directory so it appears under its final name only complete (and never replaces a file), and
   appends a `brief.rendered` event with `payload.inputs` (`role`, `sha256`, `copy`, plus `path` or
   `version`), `payload.output` (`path`, `sha256`), `project`, `touches` and `launcher_version`.
6. When any step fails (a full disk or a file-size limit while writing, a refused append), the
   output is removed, and so is every kept copy this run created under its lane that no event of that
   lane names; copies of earlier renders stay, including another lane's copies of the same bytes.

## Doctor

`laneboss doctor --config N` prints one line per check, `{"check", "ok", "detail"}`, and exits 1 when
any fails. A file-system error inside a check (for example a kept-inputs directory without read
permission) fails that check and doctor goes on with the rest:

| Check | Passes when |
|---|---|
| `config` | The configuration validates. |
| `state.isolated` | The state directory is not the same as, inside or around another configuration's state directory or configuration directory (both sharers fail), every other configuration's state location could be read (an unreadable one is named), no marker at or above the state directory names another configuration, and no other state directory lies above or below it. |
| `store.recorded` | Checked only when isolated: when a store was ever created, the store the marker records exists, is that store and verifies (as `state verify`); a store with events that no marker records fails. Passes when no store exists yet. |
| `state.writable` | Checked only when isolated: the state directory exists or can be created and accepts a new file (doctor does not create the marker). |
| `store.round_trip` | Checked only when writable: a scratch store in the state directory is created, appended to, read back, verified and removed. |
| `tool.git`, `tool.tmux` | Found on `PATH`. |
| `runner.NAME` | The program of the runner's `command`, and of its `resume` when it has one, is found on `PATH` (or is an executable absolute path). |
| `turns.limit_patterns` | A warning, never a failure (`ok` is true), reported only when it has something to say: some runner can take turns (`{session}` in `command` and in `resume`, `prompt = "stdin"` and a `resume` template) and has no `limit_patterns`. The detail begins with `warning:` and names those runners: a turn of such a runner that ends at a usage limit with exit code 0 is counted as delivered, because nothing else tells the launcher about the limit. The briefing's checks show the same line. |
| `organisation.tools` | The configuration names no organisation and no command of it points into an organisation's directory (detail "no organisation is named"), or it names one and that organisation's tools directory, `orgs/NAME/tools/`, exists and is a directory. Fails when an organisation is named and that path is missing or is not a directory (the detail names the path), and when no organisation is named but a command points into an organisation's directory (the detail names the key path of the first such element, never the path, and says to add `organisation = "NAME"`). |

Doctor reads the bound configuration, its state directory, the markers above it, and only the name
and state location of every other configuration, and looks whether the organisation's tools directory
is there. It never prints a secret value, and when the state directory is not isolated it creates nothing.

## Commit scan

`scripts/scan.sh [--staged] [ROOT]` keeps its rules (private-key headers, 40-character secret-like
tokens, non-loopback IPv4, email addresses) and output format. With `LANEBOSS_SCAN_DENYLIST=FILE` it
also applies the file's case-insensitive regular expressions (one per line; blank lines and `#`
comments are skipped) and reports `SCAN FAIL PATH:LINE denylist-line-N`, never the matched text.
An unreadable denylist, a named denylist that holds no rule, an invalid expression, an expression that
matches the empty string (such as `a*`), or one that produces an empty match while scanning (such as a
lookahead `(?=word)`) exits 2, instead of passing; the rule cases also name the rule's line. A scan that
is not `--staged` and whose root is missing or is not a directory exits 2, and so does one that checked no
file at all (an empty directory, or a tree in which every file was skipped), so a scan that would have read
nothing can never report a pass; `--staged` with an empty index still passes, since it reports exactly what
the index holds. Line numbers are computed once per file, and at most 200 issue
lines are printed, followed by a count of the rest and the summary line. `--staged` scans the blobs
in the Git index, so the hook checks exactly what will be committed.

`scripts/install-hooks.sh [--denylist FILE]` writes a `pre-commit` hook (in the repository's hooks
directory) that runs `scripts/scan.sh --staged` and blocks the commit on a failure; with
`--denylist` the hook always applies that file. It refuses to overwrite a hook it did not write.

## Known limits

A defect blocks a release when it can happen in normal operation or after one ordinary mistake or failure (a wrong
variable, a file removed by hand, a process killed, a second command at the same time); none such is known. What this
version leaves open is of four kinds, and each lane limit names the condition that triggers it.

**Outside what the launcher defends against.** These follow from "What isolation covers": the launcher checks for
mistakes, not for a process that works against it.

- **Paths are quoted as they are.** The launcher never repeats a credential-shaped VALUE it was given: an argument, a
  configuration's or a role's name, a configuration value, the text of a record; such a value is shown as
  `[withheld]`. A usage error of the command line never repeats a typed value of any shape: only messages made
  of the parser's own words pass unchanged (a required argument is missing, an argument expects a value); every
  other usage error is one fixed sentence that holds at most the option's label; the usage line or `--help`
  shows the available options and choices (the decision store's own command line, `laneboss decisions`, reports usage errors
  as Python's parser does). A message that quotes a file-system PATH quotes it unchanged, so a credential that someone used as
  the name of a file or a directory on disk (for example as part of a link's target) can appear in that message:
  the names of files the launcher finds are not screened.
- **What a read-only command may still do.** `laneboss start` is read-only in this sense: it appends no event,
  creates no state and changes no recorded fact. Like every reader of the store it can still do two things that
  are not changes of state: on a file system where a directory cannot be locked it creates the reader's lock
  file `.lock` in a state directory that already exists, and after a writer was killed in the middle of a
  write, SQLite itself rolls that unfinished write back when the next reader opens the store.
- **Hard links.** A hard link to another configuration's file, made outside that configuration's
  directories, is the same file under a second name; nothing about its path or its directory belongs
  to the other configuration, so it cannot be recognised. Only symbolic links and aliased directories
  are detected.
- **The store is opened by path.** SQLite takes a path, not a directory descriptor, and is not asked
  to refuse links (its `nofollow` URI parameter has no effect). The launcher checks the state
  directory by identity and `events.sqlite` (a regular file, not a link) through it just before the
  open; a file or directory replaced between that check and the open is not detected.
- **Checks run while directories can move.** The real ancestors of an opened directory are read
  through `..` at check time. A directory moved during that walk, or afterwards (for example an output
  directory moved into another configuration after its check), keeps the identity that was checked,
  and the write goes where the directory now is.
- **Mounts and descriptor paths.** A bind mount over a launcher directory, or a path through
  `/dev/fd` or `/proc`, is not recognised as an alias.
- **Restoring an older copy** of the same store (same store id) is not detected by the marker; the
  events it lacks are simply absent.
- **Readable ancestors.** Every directory above a checked path must be readable, because the check
  opens each one; otherwise the command is refused.
- **Output before event.** The rendered output is linked into place just before the event is
  appended; if the process is killed between the two, the output exists without its event (a later
  render to the same name is refused, and `state verify` still checks every event it has).
- **Claims are files.** A claim is a file in a worktree's administrative directory or in the claims registry; a
  process that deletes or rewrites it can mislead the next command.

**Closed by design, with a way out.** After one ordinary failure the launcher stops rather than guesses, and says
what to do.

- **A killed supervising process.** Nothing stops its run's processes at that moment. `lane check` records the run
  as lost with the number of its recorded processes that survive; resume, reuse and clean refuse while any survives;
  `lane stop` removes them.
- **A launch without its run record** (removed by hand) and without an end event keeps resume, reuse and clean
  closed: restore the record, or declare the launch gone with `lane mark --gone`.
- **A runner that cannot be removed** keeps its supervising process trying, without an end, for as long as it
  lives; status shows `stopping`, and the person decides.
- **A process table that cannot be read** (no `ps`, a failing one): lane commands refuse, and a supervising process
  queues no end and tries again every 2 seconds until it can read it.
- **Mixed process settings.** Identities recorded with `LANEBOSS_PROCESSES=portable` (start times from `ps`) and
  without it on Linux (start times from `/proc`) cannot be compared; a command that meets the other kind refuses.
- **The classification process** of a supervising process killed while it ran lives at most 3 seconds after it
  started (its own alarm).

**What the refusal scan does not see.** Each of these is reported or bounded, never taken for "no refusals" when a
record could not be read:

- **One format checked against real records.** The `claude-code` reader's shapes were checked against real records; the
  tests use invented records of those shapes. A record in which no assistant or user line is read whole is
  `unrecognised`, and an unknown content block makes it `partly-read` (both not covered); a new kind of line beside the
  known ones is only counted. `codex` is not supported yet, and `text` reads only the run's own log.
- **A refusal no guard recognises** is not seen: the patterns are the configuration's own. In a `claude-code` record only
  results marked as errors, and hooks' error messages, are matched.
- **Cut texts.** A guard's message in the middle of a result or a hook message larger than 128 KiB, or beyond the
  4096th character of a line, is not seen; the record counts it (`cut_results`, `cut_lines`), and the run stays covered.
- **Writes the shell test cannot see.** A write by an interpreter's own code (`python3 -c "...write_text(...)"`, a
  script), through a path held in a variable (`f=notes/plan.md; printf ready > "$f"`), by a command substitution, or by
  a program that is not listed (`git restore --source=HEAD -- notes/plan.md`, `git checkout -- FILE`) is not
  `shell-write`, and when its text differs enough it is not `reworded` either: these are missed.
- **Quoted-space heredoc delimiters.** A delimiter such as `cat <<'E O'` blinds both the Python and Go shell scanners:
  the closing line is not recognised and later commands can be treated as heredoc text. The scanner is not a complete
  shell parser; this case remains a known limit.
- **False alarms.** A read that shares a long path with a short refused command (`cat reports/weekly/operations/plan.md`
  after a refused `rm` of that file) is `reworded`; `rsync --dry-run SOURCE notes/plan.md` is a `shell-write` (a dry run
  is not told apart). The supervisor reviews them as clean.
- **Nested working directories.** A record whose first working directory lies below the lane's working directory is the
  lane's: a lane working in a plain directory inside another lane's working directory has its records read by both.
- **A live decision without a result.** A later call whose result has not come two seconds after the scan read it is
  decided then, a call with a result five seconds after it, and the oldest of 4096 waiting calls at once; when its
  result, or a hook's message that comes later still, turns out to be a refusal, the suspicion stays, for the
  supervisor to review as clean.
- **Copied and rewritten records.** Ids follow records and positions: a program that copies a session's history into a
  new record gives a copied refusal a second id. A rewrite that keeps a record's first line, its length up to the live
  reader's place and the 4096 bytes before that place is not seen by the live scan beside the run: it reads on from its
  place and can miss a refusal written before it, and that run can show as covered. `lane scan` and the scan of `lane
  mark --state accepted|merged` read every record from its beginning, so they find that refusal before a lane is
  accepted.
- **Withheld excerpts keep their hash.** The hash of a short secret can be found by trying candidates; the record, not
  the event, is where a withheld text is read.

**Harmless after one ordinary event.** The lanes' tmux sockets live in `/tmp/laneboss-UID/`; a system that empties
`/tmp` while lanes run takes their sockets away, so their sessions can no longer be listed. No wrong action
follows: stop, check, resume and clean decide by the supervising process's identity, not by the session.

**Needing two unusual things at once (scheduled for later).**

- **Events queued in memory.** Condition: the supervising process is killed with SIGKILL while the store and the
  lane's pending file are both unavailable to its recorder. The events it held are lost; `lane check` then records
  the run as lost.
- **A lane command stopped while it holds the lane directory's lock.** Condition: a launcher process is stopped
  (SIGSTOP, not killed: a killed one releases the lock) while it holds the lock, and a supervising process of that
  lane ends its run meanwhile. The recorder waits for the lock without a deadline, so that supervising process does
  not exit until the lock is released.
- **Processes the run record does not have.** Condition: the supervising process is killed, and a process of the
  run was born less than one sampling interval (0.5 seconds plus one pass) before, or a surviving process starts a
  child after the kill. `lane stop` signals recorded processes only.
- **Processes that leave the tree between two samples** (outside Linux, or with `LANEBOSS_PROCESSES=portable`, where
  nothing adopts a run's orphans). Condition: a process leaves the runner's process group (`setsid`, a double fork)
  and its parent exits within one sampling interval. There `ps` gives no session ids, so sessions are not used.
- **Start times and process ids outside Linux.** Condition: a recorded process ends and a new process takes its id
  within the same second, between the check of the start time and the signal (on Linux a pidfd closes that gap).
- **A registry claim keyed by device and inode.** Condition: a plain working directory is removed by hand while its
  lane is never cleaned, and a new directory gets the same device and inode; it is then taken as claimed until
  that lane is cleaned.

**Turns, mail, the loop and attach (mail, turns, the loop and attach built, T2, T3 and T4; accounts and adoption, T5,
built in part).** These limits belong to "Turns, mail, the loop and attach", and each names the condition that triggers it.
They hold today.

- **Delivery is at least once.** Condition: a turn is killed or ends badly after the agent has acted on a message. The
  message returns, and the next turn carries it again, marked `(again)`.
- **A runner that ends with exit code 0 without having read its input.** Condition: the runner ignores standard input
  and the prompt fits what the pipe holds (64 KiB by default on Linux, not measured here), so that it was written whole.
  Its messages count as delivered, because written is not read and nothing the launcher can see shows a read. A prompt
  that was cut is not in this case: it returns the messages ("The failure table").
- **A runner without `limit_patterns`.** Condition: the runner prints a limit message that no pattern recognises and
  ends with exit code 0 and a prompt written whole. Its messages count as delivered. `laneboss doctor` warns about a
  runner that can take turns and has no pattern; a pattern that does not match the line as printed (a JSON line, for
  `claude-stream-json`) is not found by it.
- **A message sent twice because the first result was lost.** Condition: the sender's `lane send` stored the message
  and was killed, or lost its output, before it printed the result, and the sender sends the same text again. Both
  copies wait, both are delivered as two messages, and neither carries ` (again)`, so the agent may do the work twice.
  The launcher does not compare a new message with the waiting ones; the alternative is in "Open points".
- **A first turn that never created its session.** Condition: the first run ended before the agent stored its session, for
  example at a limit on its first request. Every `lane turn` then resumes a session that does not exist and fails the
  same way, its messages return each time, and the back-off keeps the loop from spinning. Way out: abandon the lane and
  start another.
- **A message that a change of the launcher makes refusable** (two unusual things at once). Condition: a change of the
  launcher makes the credential detector stricter while a message that was accepted before the change waits. The render
  of the turn that would carry it is refused, naming the sequence, so every turn of the lane is refused. No message is
  removed and none can be skipped, so the way out is to abandon the lane.
- **A killed supervising process and a mail file removed by hand** (two unusual things at once). Condition: a turn's
  supervising process is killed, and a file of a message that it carried is removed before the next turn. The messages
  return when `lane check` records the loss, and every turn is then refused with exit 3 until the file is put back
  under its name.
- **The clock moved back** (two unusual things at once). Condition: the system clock is set back by more than the
  back-off while a lane is in back-off and the loop runs. The loop reads `until` against the clock and waits the
  difference longer. Events are not affected.
- **A turn that is refused while the previous run is being wrapped up.** Condition: a message arrives during a turn (or
  the idle interval ends) and the turn ends well, and the loop looks at the lane in the second or two between the
  `lane.ended` of that run and the end of its supervising process, which still appends the announcement and ends the
  tmux session. `lane turn` is refused while the supervising process of any run of the lane lives, so the loop records a
  skip with reason `refused` and does not try the lane again for `backoff_seconds` (300 by default): the mail waits that
  long. Way out: a person starts the turn with `lane turn`, or `backoff_seconds` is set lower. The design says that every
  refusal is recorded as a skip and that the lane is then not tried for `backoff_seconds`; the loop does as it says. The
  wait is real and not rare: with `poll_seconds` 10 and a run that is wrapped up in a second or two, a pass falls in
  that time at about one end in five to ten (the reviewer's estimate from the code, not a measurement), and the mail
  then waits the whole `backoff_seconds`. A later step can let a pass that finds the previous run's supervising process
  still alive leave the lane for the next pass without recording `refused`; this step does not change it.
- **`next` does not show the hold after a refused attempt.** Condition: the loop's attempt to start a turn for a lane was
  refused (a damaged mail file, a runner edited since, a lanes lock that stayed held), the loop recorded a `loop.skipped`
  with reason `refused`, and `lane loop --status` is read within the next `backoff_seconds`. The entry of the lane says
  `mail` or `idle` in `next` and `null` in `backoff_until`, although the loop will not try the lane before the `until`
  of that skip. The skip is in the events; the status reads the back-off of the lane's latest end only.
- **A line typed as a turn ends is queued.** Condition: attach is left at its prompt and a message is entered within a
  moment of the end of a turn, while the turn's supervising process still wraps up (`lane turn` is refused because the run
  is still supervised). The message is stored and waits, attach says it is queued, and `/turn` starts the turn once the
  process has gone.
- **A piece of an answer without its newline waits.** Condition: the prompt is shown and the stream gives an answer in
  pieces (`claude-stream-json`) that does not end in a newline yet. Attach shows only complete lines above the prompt, so
  the unfinished line appears when it ends, or when the turn does (the end of a turn completes it).
- **No `readline`, or no terminal.** Condition: the interpreter has no `readline`, or standard input or output is not a
  terminal. Attach cannot see a line that is being typed, so it holds nothing back and a typed line is only printed again
  after a refusal; the typed bytes are intact and only the look of the line suffers.
- **The cost of a turn is a difference of two totals.** Condition: `total_cost_usd` of the result line is not the
  session's running total. The design assumes it is; the real trial of T4 confirms or refutes it, and a difference that
  comes out negative is shown as unknown. Nothing else in attach depends on it.
- **A line of the log without a newline has no length limit.** Condition: a runner prints a very long line without a
  newline. Attach keeps the unfinished line in memory until it ends, and passes it whole to the reader.

## Left for later lanes

- Around refusals: telling the owner about refusals and suspicions through the owner channel, a judge that reads
  suspicions, the record formats of other agent programs, and changing a guard's own rules.
- The judge that picks a difficulty, account choice by remaining quota, messages to a running executor and
  checking which model a run really used.
- Commands of their own for reviews and mini-supervisors (`review`, `mini start`); today they are lanes like any
  other, with a runner of their own.
- Test machines (`{machine}`), owner messages through the owner channels, and cost accounting: their
  configuration fields are validated now and marked "validated, not yet used".
- Passing a runner's `secrets` to its runs; a run inherits the environment of the session that started it.
- The single-writer network service and the offline spool in front of `EventStore.append()`
  (with store creation, `rebuild()` and the kept input copies), and the remote store.
- The setup wizard (`laneboss init`) and the secret store (`laneboss secrets import`); the wizard will offer
  to add the plugin to the agent program after showing the changes.
- Binding `laneboss decisions` to a configuration.
- Project-specific extra mandatory brief sections.
- Turn-based lanes, described in "Turns, mail, the loop and attach" and built in four steps (T2 to T5): mail and turns
  are built (T2), and so are the loop (T3) and attach with the stream readers (T4); of T5, the room command of an
  account, the choice of the account it feeds, the command `lane adopt` and the event `lane.adopted` with its readers
  are built; the rule that a pass starts no room command for an account while an earlier one for it still runs, the room
  command of `lane start`'s first account, and the remaining quota of an account read by an adapter under
  `integrations/` are designed, not built.
- Resources and cost (designed, not built), described in "Resources and cost" and built in four steps (A to D): the core
  with the `resource` commands and the gate, the adapters, the cost record, and the credential-scope example.

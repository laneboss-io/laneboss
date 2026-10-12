# Configuration reference (schema version 1)

A configuration describes one company: its supervisors and projects, the runners that start
executors, model routing, the test environment, owner channels, cost rules, standing rules, where
its state lives and which secrets it needs. The package ships none; each user keeps theirs outside
the repository. `examples/minimal/` is an invented example that uses most fields.

## Where configurations live

| Item | Location |
|---|---|
| Configuration home | `$LANEBOSS_HOME`, default `~/.config/laneboss` (absolute path) |
| One configuration | `$LANEBOSS_HOME/configs/<name>/config.toml` |
| Project files | `$LANEBOSS_HOME/configs/<name>/projects/<project>.toml` (optional) |
| Standing-rules files | anywhere inside `$LANEBOSS_HOME/configs/<name>/`, listed by `rules` |
| An organisation's directory | `$LANEBOSS_HOME/orgs/<name>/`, for the organisation `organisation` names; the launcher only reads there |
| An organisation's tools | `$LANEBOSS_HOME/orgs/<name>/tools/` |
| An organisation's rules files | anywhere inside `$LANEBOSS_HOME/orgs/<name>/`, listed by `organisation_rules` |
| State home | `$LANEBOSS_STATE_HOME`, default `~/.local/state/laneboss` (absolute path) |
| State of one configuration | `$LANEBOSS_STATE_HOME/<name>/`, or the absolute `state.path` |
| The lanes' tmux server of one configuration | `/tmp/laneboss-<uid>/<name>-<12 hex digits of the state directory's real path>` (`laneboss config path NAME` prints it as `socket`) |
| Claims of plain working directories (every configuration of the user) | `HOME/.local/state/laneboss/.lane-claims/`, mode 0700, with HOME the account's home directory from the user database (not the `HOME` variable, `LANEBOSS_HOME` or `LANEBOSS_STATE_HOME`); one per account |

Environment variables that change how lane commands observe processes:

| Variable | Meaning |
|---|---|
| `LANEBOSS_PROCESSES=portable` | On Linux, use only what every supported system offers: `ps` for the process table (in the C locale and UTC), check-then-signal instead of process file descriptors, and no adoption of a run's orphans, which is how lanes work on macOS. Set it for every command of a configuration or for none: process identities recorded one way cannot be compared with the other, and a command that meets them refuses. |
| `LANEBOSS_DEBUG=1` | An internal error, or a file that disappeared under a lane command, also prints the traceback. |
| `LANEBOSS_TEST_CLAIMS_DIR=PATH` | For tests only: moves the account's claims registry to PATH (absolute), so a test run does not use the account's own. A lane whose `lane.started` recorded another registry is refused by later commands (resume, `start --reuse` and clean). |

A configuration name matches `[a-z0-9][a-z0-9-]{0,31}`, and `name` in the file must equal the
directory name. Every command that reads or writes state is bound to exactly one configuration,
with `--config NAME` or `LANEBOSS_CONFIG`; see `docs/architecture.md`.

Links and locations:

- `$LANEBOSS_HOME/configs/<name>` may itself be a symbolic link, for example into a dotfiles checkout.
  Every file read inside it (`config.toml`, `projects/`, project files, standing-rules files) must
  resolve inside that same directory; a link to another configuration or outside it is refused.
  Links that stay inside the directory are fine.
- `$LANEBOSS_HOME/orgs/<name>` may be a link too. Every organisation rules file must resolve inside that
  directory; a link that leads outside it, or into another organisation's directory, is refused.
- Two configuration directories may not overlap (one inside, or an alias of, the other).
- A state directory never holds a link: the launcher refuses one it finds there. The state directory
  itself may be reached through a link (also the default `$LANEBOSS_STATE_HOME/<name>`), as long as it
  does not lead into another configuration's directory or state directory.
- No two configurations may name the same or nested state directories, before or after either was
  used: every state command of both is refused until one of them moves.
- `$LANEBOSS_STATE_HOME` must lie outside `$LANEBOSS_HOME`.
- An entry under `$LANEBOSS_HOME/configs/` that has a configuration name but cannot be read (its
  `config.toml` leaves its directory through a link, is not valid TOML, or the entry cannot be
  entered) is unreadable: other configurations' commands still run, and their `doctor` fails and
  names it (their `start` still prints its briefing, with a warning that names it).

These rules catch mistakes; they do not defend against a process of the same account that changes
files while the launcher runs (`docs/architecture.md`, "What isolation covers").

## Generic rules files

The package ships two rules files of its own, under `src/laneboss/protocol/`, and they belong to every
configuration: `executor.md` for executor lanes and `supervisor.md` for a supervisor's briefing and no lane
brief. They name no company, no host and no user, so a second company installs them as they are written.

| File | Reaches |
|---|---|
| `executor.md` | Every lane brief and the supervisor's briefing. |
| `supervisor.md` | The supervisor's briefing only. |

A rules file is read inside the configuration directory, never from the installed package: a configuration reads
a byte copy of each of these two, so a brief keeps working when the installed version changes and the copy can be
compared with the version's own file. The copy of `executor.md` goes in the configuration's `rules`. The copy of
`supervisor.md` goes only in the `rules` of a project that only a `[supervisors]` entry lists and that is never
passed to `--project`, until a supervisor-only rules key exists: the configuration's `rules` are appended to
every rendered brief, so a supervisor file listed there would reach lanes too. Each rule is one top-level list
item, an id followed by one or more sentences, and an id is unique across both files;
`tests/e2e/test_generic_rules.py` holds the two files to their ids.

## Validation rules

- Files are UTF-8 TOML, at most 1 MiB each. A file that fails to parse is reported by file, line and
  column only, never with the parser's message (which can quote the input).
- Unknown keys, wrong types and an unsupported `schema_version` are refused. Every error names the
  file and the key path (for example `config.toml: routing.standard[0].model`) and never repeats the
  offending value.
- Strings are non-empty, single-line (no control characters) and at most 1000 characters unless a
  field says otherwise.
- A configuration file never holds a secret value. Any string, key or rules file that looks like a
  credential (private-key header, well-known token prefix, authorization header, URL with a
  password, or an assignment such as `password = ...` to a literal; see `docs/architecture.md`,
  "Credentials") is refused before any other check. That error names the file, the top-level key and
  the depth below it (for example `config.toml: test_environments (a value at depth 2)`), never a key
  below the top level and never the value; for a rules file it names the file and the line. Secrets
  are named in `secrets` and resolved by later lanes from the user's secret store.
- Cross references are checked: every runner, project, owner channel, test environment, account and
  secret that one field names must be defined where this page says.
- Fields marked *validated, not yet used* are checked now and consumed by later lanes (test machines, owner
  messages, cost accounting). This version reads `name`, `organisation`, `organisation_rules`, `rules`,
  `state.path`, `lanes`, `turns` (`idle_message`, `idle_seconds`, `poll_seconds`, `backoff_seconds`, `limit_backoff_seconds`), `runners` (`command`, `resume`, `prompt`, `stream`, `room`, `accounts`, `limit_patterns`, `dropped_patterns`,
  `quiet_seconds`, `records`; doctor checks the programs of `command` and `resume`), `routing`, `guards`,
  `judges`, and the project `repository`, `lane_prefix`, `workers`, `excluded_accounts` and `rules`.

## config.toml

| Key | Type | Required | Meaning |
|---|---|---|---|
| `schema_version` | integer | yes | Must be `1`. |
| `name` | name | yes | Must equal the directory name. |
| `description` | string | no | Free text. |
| `organisation` | name | no | The organisation this configuration belongs to. Its directory is `$LANEBOSS_HOME/orgs/<name>/` and its tools are in `tools/` there; the directory need not exist for the configuration to be valid, and `laneboss start` and `laneboss doctor` say whether the tools directory is there. Absent: the configuration belongs to no organisation. Several configurations may name the same one. A configuration that names an organisation is refused when a runner or judge command is an absolute path inside another organisation's directory; one that names none is accepted whatever its commands point at, and `laneboss doctor` fails its check `organisation.tools` when a command points into an organisation's directory, saying to add `organisation = "NAME"` (`docs/architecture.md`, "Organisations"). |
| `rules` | array of relative paths | no | Standing-rules files, relative to the configuration directory, appended to every rendered brief in this order. Each must exist inside the directory, be UTF-8 and hold no credential shape. The first part of a path may not be `orgs`: `orgs/<name>/<path>` is the label of an organisation's rules file. |
| `organisation_rules` | array of relative paths | no | The organisation's own standing-rules files, relative to its directory `orgs/<name>/`. They come before the configuration's `rules` (and the project's) in every rendered brief and in the briefing, each under the label `orgs/<name>/<path>`. Refused when `organisation` is absent. Each must exist inside the organisation's directory (a link that leads outside it, or into another organisation, is refused), be at most 1 MiB, be UTF-8 and hold no credential shape. |
| `secrets` | array of secret names | no | Names (`[A-Z][A-Z0-9_]{0,63}`) of every secret this configuration needs. *Validated, not yet used.* |
| `owner_channel` | name | no | Default owner channel; must be defined in `owner_channels`. *Validated, not yet used.* |
| `test_environment` | name | no | Default test environment; must be defined in `test_environments`. *Validated, not yet used.* |
| `state` | table | no | See below. |
| `lanes` | table | no | See below. |
| `turns` | table | no | See below. |
| `disk` | table | no | See below. |
| `runners` | table of tables | yes, at least one | See below. |
| `supervisors` | table of tables | no | See below. |
| `routing` | table | no | See below. |
| `test_environments` | table of tables | no | See below. |
| `owner_channels` | table of tables | no | See below. |
| `cost` | table | no | See below. |
| `guards` | array of tables | no | See `[[guards]]` below. |

### `[state]`

| Key | Type | Meaning |
|---|---|---|
| `path` | absolute path | Moves this configuration's state directory. It may not overlap the configuration home, may not contain the state home, and may not lie inside another configuration's default state directory. `laneboss config validate --all` also refuses two configurations whose state directories are equal or nested. A default state directory may not overlap the configuration home either, so `LANEBOSS_STATE_HOME` must lie outside `LANEBOSS_HOME`. |

### `[lanes]`

Defaults for every lane of the configuration (`laneboss lane`, `docs/architecture.md`, "Lanes").

| Key | Type | Meaning |
|---|---|---|
| `budget_minutes` | number above 0, at most 10080 (a week); fractions allowed | The time budget of a run when `lane start` gets no `--budget`. Without it, `lane start` needs `--budget`. When a run's budget passes, the run and its whole process tree are stopped (`lane.timeout`, then `lane.ended` with reason `timeout`). |
| `quiet_seconds` | integer 1 to 604800 | How long a run's log may stay without growing before `lane.stuck` is appended (the run is not stopped). Default 900; a runner's own `quiet_seconds` wins. |
| `stop_grace_seconds` | integer 1 to 600 | How long a stopped run's processes get after SIGTERM before SIGKILL, and the room command's processes when the launcher stops them after each run. Default 10. |
| `lock_wait_seconds` | integer 1 to 3600 | How long `lane start`, `lane resume`, `lane turn` and `lane clean` wait for the configuration's lanes lock that another of them holds, and `lane send` for the lane's mail lock that another send holds, before they are refused. Default 60. |
| `room_timeout_seconds` | integer 1 to 60 | How long a runner's `room` command has, for one account, before the launcher stops it and counts the account as having no room (see the runner key `room` in "`[runners.<name>]`" below). The caller reads this setting and passes it to the run; absent, the launcher's own default of 20 seconds is used. |

### `[turns]`

Defaults for the lanes that are started with `lane start --turns`, turn-based lanes that take mail (`laneboss lane send`) and
are continued one turn at a time (`laneboss lane turn`; `docs/architecture.md`, "Turns, mail, the loop and attach"), and
for the loop that starts those turns on a schedule (`laneboss lane loop`; the same section). The table is optional and so
is each key; every refusal of one names its key path, for example `turns.idle_message`.

| Key | Type | Meaning |
|---|---|---|
| `idle_message` | relative path | The message that `lane turn --idle` sends to a lane that has no mail: a file inside the configuration directory (no `..`, `.` or empty part in the path; a link that leaves the directory is refused), UTF-8, at most 64 KiB and with no credential shape, read and checked when the configuration loads, like a standing-rules file. The message is sent as it is, without a header line, and the launcher block follows it once, as for any message. Without the key, `lane turn --idle` is refused for a lane that has no mail, and `lane send` and a turn with mail are not affected. |
| `idle_seconds` | integer 1 to 604800 | The idle interval that `lane start --turns` records in the lane's first `lane.started` when it gets no `--idle SECONDS` (a week at most). Without the key and without `--idle` the lane has no idle interval (`null`). Every later turn copies the previous run's value. The loop (`lane loop`) starts an idle turn when the lane has been idle for this long, counted from its last state change, and it needs `idle_message` to send; a person's `lane turn --idle` does not wait for the interval. |
| `poll_seconds` | integer 1 to 3600 | How often the loop looks at its lanes: every pass reads the store once and loads this configuration again. Default 10. |
| `backoff_seconds` | integer 1 to 604800 | How long the loop waits, after the end of a turn, before it starts the lane's next turn when that end was anything but reason `exit` with exit code 0 and a prompt written whole (a lost run and a run declared gone included). The same number is the wait after a turn that the loop could not start (a skip with reason `refused`). A person's `lane turn` does not wait. Default 300. |
| `limit_backoff_seconds` | integer 1 to 604800 | The wait after a turn that ended with reason `limit`. Default 1800. |

### `[disk]`

The disk line: the file system every new lane and every new worktree is measured against, so that a disk filling up
stops new work inside the launcher and not in a note. The section is optional and so is each of its keys; it applies
whether or not it is written. `laneboss disk` prints the reading the start path acts on, as one JSON object with
`path`, `used_percent` (one decimal), `free_bytes`, `warn_percent`, `stop_percent`, `state` (`ok`, `warn` or `stop`)
and `latched`, and exits 0 for `ok` and `warn` and 3 for `stop`.

| Key | Type | Meaning |
|---|---|---|
| `path` | absolute path | The file system to watch, by any directory (or file) on it. The reading is `os.statvfs(path)`, and the percentage is computed as `df` computes it: `(blocks - bfree) / (blocks - bfree + bavail) * 100`. `free_bytes` is what a user can still write (`bavail * frsize`). A path that cannot be read refuses the start with the error, and so does a file system whose `statvfs` succeeds but reports no usable blocks (`blocks - bfree + bavail` is zero, as on a procfs mount, or fewer free blocks than it has): an unreadable file system is never taken for an empty one. Default: the user's home directory. |
| `warn_percent` | integer 1 to 99 | The warn line. `lane start` still starts at or above it, prints `warning: disk <path> is <x>% used (warn line <w>%)`, and records a `disk.warn` event with the reading. Default 85. |
| `stop_percent` | integer 1 to 99 | The stop line. At or above it `lane start` is refused before a worktree, branch or lane directory is made, with `refused: disk <path> is <x>% used (stop line <s>%); no new lane or worktree starts until it is under <w>%`, and a `disk.stop` event with the reading is recorded. Default 90. Must be above `warn_percent`. |

A reading at or above `stop_percent` sets a latch, and only a reading below `warn_percent` clears it, so a disk that
was full is still `stop`, and new work is still refused, on a later reading that happens to fall between the two
lines. The latch belongs to the watched file system, not to one configuration: it is one small file per device id in
`disk-latches/` under the state home, so every configuration of the same user that watches that file system shares it,
and the lock held over its reading, its decision and its writing is shared with it - a stop reading taken while
configuration A starts refuses configuration B too, until a reading is back under the warn line. That shared file is
the one deliberate exception to the rule that a configuration reads and writes only its own state directory; it holds
no lane's data. It knows only the readings that were taken: a spike above the stop line that neither a start nor
`laneboss disk` saw leaves no latch, and the next reading between the lines is not held. `laneboss disk` itself sets
and clears the latch, exactly as a start does, so polling it is never a way around the line. `lane resume` and
`lane turn` create nothing new and are never refused by the disk line.

### `[runners.<name>]`

A runner is a command that starts an executor, mini-supervisor or reviewer.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `command` | array of strings | yes | The argument vector `lane start` runs, without a shell. The first element is a command name or an absolute path without placeholders; `laneboss doctor` checks it is found. Other elements may use the placeholders `{account}`, `{brief}`, `{effort}`, `{lane}`, `{log}`, `{machine}`, `{model}`, `{project}`, `{session}` and `{worktree}`; `{{` and `}}` are literal braces. `{brief}` is the path of the rendered brief and is required unless `prompt` is `"stdin"`: a brief reaches its runner as a file or on standard input, so a template without `{brief}` is refused for a runner that takes its prompt as an argument. `{log}` is the lane's log, `{worktree}` its working directory, `{session}` the lane's session identifier (see "Session identity and the prompt on standard input" below). A placeholder the lane has no value for (`{account}` for a runner without accounts, `{effort}` without one, `{project}` without `--project`) refuses the start; `{machine}` is refused until test machines exist. |
| `resume` | array of strings | no | The argument vector `lane resume` runs to continue the same lane in the same directory (how a session is continued is the runner's business). Same rules as `command` (`{brief}` is not required), plus `{message}`: the rendered follow-up message, a file. `{session}` is used here if and only if `command` uses it (`config validate` refuses a runner that uses it in only one of the two, naming the key path of the other). Without `resume`, the runner's lanes cannot be resumed. |
| `prompt` | `"argument"` or `"stdin"` | no | How the runner is given its prompt. `"argument"` (the default): as an argument, the rendered brief's path with `{brief}` (required) and the follow-up message's path with `{message}`; the runner's standard input is `/dev/null`. `"stdin"`: the launcher writes the bytes of the rendered brief (at a start) or of the rendered follow-up message (at a resume) to the runner's standard input and closes it; `{brief}` and `{message}` are then optional, and `lane resume --message` is accepted whatever the resume template says. What became of the prompt is recorded in `lane.ended` as `prompt` (`written`: every byte went into the pipe and it was closed; `cut`: the runner closed its input, the write failed before the end, or the runner could not be created, with the bytes written, 0 for the last) and shown by `lane status`. Written means written into the pipe, not read by the runner: a prompt that fits what the pipe holds (64 KiB by default on Linux, not measured here) is written whole even when the runner never reads it. Any other value is refused. `"stdin"` is also one of the three things that make a runner able to take turns (see "Session identity and the prompt on standard input"): a turn's message, the lane's joined mail or the idle message, arrives on the runner's standard input as a follow-up message does. |
| `room` | array of strings | no | The argument vector of the command that answers whether one account can take a turn now, and how many turns it can take (`docs/architecture.md`, "Accounts and adoption"). The same rules as `command` for its first element (a command name or an absolute path, without placeholders; `laneboss doctor` does not check it); its other elements may use `{account}` as their only placeholder, so that one template serves every account of the runner. The launcher runs it without a shell, with standard input from `/dev/null` and the caller's environment, once for each account it considers, and waits at most `[lanes] room_timeout_seconds`. Its standard output must be exactly one JSON object of at most 4 KiB, with the keys `room` (`true` or `false`), `slots` (a whole number from 0 to 64; `0` when `room` is false, and 1 or more when it is true) and `reason` (a string on one line of at most 200 characters, empty only when `room` is true); a non-zero exit, a timeout, or output that is not exactly that object counts as no room, with the fixed sentence `the room command of account A did not answer in the documented form`, and nothing of such output is shown besides it. A `reason` with the shape of a credential becomes `(withheld)`. The command's program belongs to the organisation: the check that refuses an absolute path into another organisation's tools covers `room` as it covers `command` and `resume`. A runner without the key has no room check: its turns use the previous run's account. |
| `stream` | `"text"` or `"claude-stream-json"` | no | The reader that `laneboss lane attach` shows this runner's lines with (see "The stream of a runner" below). `"text"` (the default): every line is shown as it is, but for its control characters, which are removed, and no mode and no cost are known. `"claude-stream-json"`: the lines of a headless Claude Code run that prints one JSON object per line (`--output-format stream-json --verbose --include-partial-messages`). Any other value, and a value that is not a string, is refused by `config validate`. The key changes only what attach shows: the launcher stores every line as the runner printed it, and `limit_patterns` and `dropped_patterns` are matched against those lines as they are. |
| `accounts` | array of account names | no | Account or profile names this runner can use (`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`). A lane uses the account given with `--account`, else the first one the project does not exclude; a resume checks the account it inherits against these and the project's exclusions as they are at that moment. `lane start` does not ask a `room` command: a new lane takes its account as above for every runner. A turn or a resume of a runner with a `room` command takes its account through that command instead, in the order `docs/architecture.md` gives under "Accounts and adoption" ("Slots and the choice of the account"). There, the previous run's account is asked only when the runner lists it and the project keeps it; otherwise it is passed over, not refused. |
| `limit_patterns` | array of regular expressions, non-empty, no repeats | no | Lines of a run's output that mean "account limit reached". A run that ends by itself and whose output's last matching line matches one of these ends with reason `limit` instead of `exit`. |
| `dropped_patterns` | array of regular expressions, non-empty, no repeats | no | Lines that mean "stream dropped": reason `dropped`. |
| `quiet_seconds` | integer 1 to 604800 | no | This runner's quiet time before `lane.stuck`, for example a long one for a program that prints nothing until it finishes. |
| `records` | array of tables, non-empty | no | Where the runner's raw session records are and how to read them, for refusal detection (see "Session records" below). Without it, the runner's runs are not scanned. |
| `secrets` | array of secret names | no | Secrets the runner needs; each must be listed in the top-level `secrets`. *Validated, not yet used:* a run inherits the environment of the session that started it, and secrets are not resolved yet. |
| `description` | string | no | Free text. |

The patterns are Python regular expressions, each matched with `search` against one line at a time of the last
64 KiB of the run's own output (the bytes this run added to the log), decoded as UTF-8, each line cut to its first
4096 characters. The last line that matches any pattern decides; on one line, `limit_patterns` are tried before
`dropped_patterns`. The matching runs in a separate process that is stopped after 2 seconds: a pattern too slow for
that bound (catastrophic backtracking, for example) gives reason `exit` with `classification` `timed-out`. A
pattern must compile and must not match an empty line. Anchor them (`^`) so that a sentence about a limit in an
executor's report does not count: the classification only reports, the supervisor decides what to do. A turn that ends
at a usage limit with exit code 0 and a prompt written whole is counted as delivered when its runner has no
`limit_patterns`, so `laneboss doctor` warns (check `turns.limit_patterns`, which never fails) about each runner that can
take turns and has none.

#### Session identity and the prompt on standard input

An agent program can be given a session identifier at the start and resumed by it. When a runner's `command` uses
`{session}`, `lane start` makes one for the lane: a random UUID in its usual lower-case form (8-4-4-4-12 hexadecimal
digits). It belongs to the lane, not to a run:

- It is kept in `lane.started` as `session_id` (a lane whose runner does not use `{session}`, or that an earlier
  version started, has no such key), and `lane status` shows it as `session_id` (null for a lane that has none).
  A `lane resume` hands the same one to the `resume` template; `lane start --reuse` (a merged or abandoned lane's
  name started again) makes a new one.
- `{session}` is allowed in a runner's `command` and `resume` and in a `records` path, and nowhere else. A runner
  that uses it in `command` and not in `resume`, or the other way round, is refused by `config validate`: half an
  identity is a wrong resume. A runner without `resume` may use it in `command` alone.
- A lane without an identifier cannot be resumed by a runner whose `resume` template uses `{session}`: `lane resume`
  is refused before anything is started, with a message that says the lane has no recorded session identity and that
  it can only be resumed by a runner whose template does not use `{session}`. The runner as it was when the lane
  started still resumes it.
- A lane that has an identifier is resumed only by a runner whose `resume` template uses `{session}`: after a
  configuration edit that dropped it from the template, `lane resume` is refused before anything is started, with a
  message that names the runner and the key `runners.NAME.resume`, because a resume that does not name the lane's
  session would continue the newest session of the directory, whichever it is. Restoring the placeholder resumes it.
- In a `records` path, `{session}` makes the path name exactly the files of that session. For a run of a lane that
  has no identifier, such a path is not covered, with the reason `no-session` (`docs/architecture.md`, "Refusals").
- **A runner that can take turns** has `{session}` in `command` and in `resume`, `prompt = "stdin"` and a `resume`
  template: a lane whose agent session lives on across runs is continued by name and is given each message on standard
  input (`docs/architecture.md`, "Turns, mail, the loop and attach"). `lane start --turns` is refused for any other
  runner, and the message names each missing part; `lane send` and `lane turn` are refused for a lane whose runner, as the
  configuration has it now, has lost one of the three, so an edit that drops one of them stops the lane's mail and turns
  until it is restored. A runner that lacks them keeps serving ordinary lanes as before: nothing about them changes
  without `--turns`.

A worked runner for Claude Code, which takes the lane's identifier at the start (`--session-id`), is resumed by it
(`--resume`), reads its prompt on standard input and has its own session record read by name:

```toml
[runners.claude]
command = ["claude", "-p", "--session-id", "{session}", "--model", "{model}", "--permission-mode", "bypassPermissions"]
resume = ["claude", "-p", "--resume", "{session}", "--model", "{model}", "--permission-mode", "bypassPermissions"]
prompt = "stdin"
records = [{format = "claude-code", paths = ["~/.claude/projects/*/{session}.jsonl"]},
           {format = "text", paths = ["{log}"]}]
```

#### The stream of a runner (`stream`)

`laneboss lane attach` (`docs/architecture.md`, "The `lane attach` command and the stream readers") shows the lines of a
run's output through a reader that the runner names with `stream`. A reader takes one line of the log and returns the
parts of it that attach shows: the agent's text, a label for each tool call, the permission mode the agent reports,
the result of a request (its cost and its denials), or the line itself, cut to 200 characters, when it is of no shape the
reader knows. Everything that attach prints from a line has its control characters removed or turned into spaces (the
reader does it for the text, the labels and the cut lines, attach for the mode), so that a line cannot write to the
terminal. A line of any shape, valid JSON or not, gives at worst such a cut line (a `text` stream shows every line whole)
and never a traceback.

- `text` (the default): the line is the agent's text, shown as it is but for its control characters, which are removed.
  No mode and no cost.
- `claude-stream-json`: for a runner whose command makes Claude Code print one JSON object per line. The `init` line
  gives the permission mode, the streamed text pieces give the answer, a whole `assistant` line gives the text that was
  not streamed and a label for each tool call, and the `result` line gives the cost (`total_cost_usd`, the session's
  running total), whether the request ended in an error and the tool calls it denied. The shapes are those the design
  read from Claude Code, and the real trial of `lane attach` confirmed them. A real session prints more: its own
  bookkeeping (hooks, screen updates, thinking, background tasks, status), a hook that succeeded, a rate limit that is
  `allowed` and the result of a tool that did not fail give no output of attach's; a `notification` of the agent program
  is shown as `notice: TEXT`, a hook that did not succeed as `notice: hook NAME: OUTCOME (exit CODE)`, and a tool that
  failed as `[tool error] TEXT`; a rate limit of any other status, and every line that is not known, are shown as the
  line, cut to 200 characters.

The reader plays no part in how a run ends. A run is classified by the runner's `limit_patterns` and `dropped_patterns`
against the lines as they were written, so a runner that prints its limit message inside a JSON line needs a pattern
written for that line as it is printed. A pattern that no longer matches the line makes a turn that ended at a limit
count as delivered, and `laneboss doctor` does not warn about it (it names only the runners that have no pattern at
all).

#### Session records (`records`)

Each entry of a runner's `records` names one format and where its records are:

| Key | Type | Required | Meaning |
|---|---|---|---|
| `format` | `claude-code` or `text` | yes | How the records are read: the session records of the agent program of that name, or `text`, the run's own log, whose lines are only matched against the guards (no command, no targets). `docs/architecture.md`, "Refusals", describes each. |
| `paths` | array of path templates, non-empty, no repeats | yes | For `text`, exactly `["{log}"]`: the run's own part of the lane's log, and any other path is refused (a later version may read other text files). For `claude-code`, globs (`*`, `?`, `[...]`, `**` for any depth, through links to directories too) that find the records: a template starts with `/`, `~/` (the home directory of the environment the run gets), `{worktree}` or `{log}`, and may use the placeholders `{account}`, `{effort}`, `{lane}`, `{log}`, `{model}`, `{project}`, `{session}` and `{worktree}` (their values are glob-escaped, and a value that holds `/` or is `.` or `..` makes the template `bad-placeholder` for that run, which is then not covered, except `{worktree}` and `{log}` at the start; `{session}` is the lane's session identifier, so the path names exactly the files of that session, and a run of a lane that has none is not covered, with the reason `no-session`); `{machine}` and `{brief}` are refused. |

Format `codex` is refused with a message that says it is not supported yet: watch such a runner with `text` on its own log.

A `claude-code` record is read for a run only when it changed after the lane's first run began, its real path lies
outside every directory of the launcher and the working directory it names is the lane's or lies below it; its lines
belong to the run whose window holds their time. A configured path that matches no file of a run that ran, or more than
10,000 candidates, makes the run not covered. For example, a runner whose agent keeps per-account record directories:

```toml
records = [{format = "claude-code", paths = ["~/.agent-{account}/projects/*-{lane}/*.jsonl"]},
           {format = "text", paths = ["{log}"]}]
```

### `[[guards]]`

The guards whose refusals the launcher looks for in every scanned run's session records (`docs/architecture.md`,
"Refusals"). They are a configuration's own rules: the package ships none. Without a guard nothing is scanned.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `name` | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` | yes | The guard's name, as the events give it; no two guards share one. |
| `pattern` | regular expression | yes | Recognises the guard's refusal in a tool result or a hook's message: a Python regular expression tried with `search` on each line of the text (its first 64 KiB and, when it is longer, its last 64 KiB, each line cut to 4096 characters). |
| `kind` | `hook`, `permission` or `harness` | no | What kind of guard it is, as the events give it. |
| `description` | string | no | Free text. |

Guards are tried in order: on each line of a text, the first guard that matches names the refusal. A pattern is
refused when it does not compile, when it matches the empty string, or when a partial rejection rule finds a shape
that can take time exponential in a line's length: an unbounded repetition of a part that itself repeats (`(a+)+`,
`(\w+\s?)*`) or a back-reference (`\1`, `(?P=name)`, a conditional group). That rule does not prove an accepted
pattern cheap (`^(a|aa)+$` passes it): the bound is an alarm that gives matching one text one second, and a text whose
matching takes longer is counted as timed out and its run is not covered. A guard's message in the middle of a text
longer than 128 KiB, or beyond the 4096th character of a line, is not seen (the record counts such cuts). Anchor
patterns (`^`) on the guard's own message, so that a tool output that merely quotes a refusal does not count. Like every
configuration value, a pattern that looks like a credential assignment is refused.

```toml
[[guards]]
name = "doc-guard"
kind = "hook"
pattern = '^PreToolUse:[A-Za-z]+ hook error: \[[^]]*\]: BLOCKED by doc_guard'
```

### `[supervisors.<name>]`

| Key | Type | Required | Meaning |
|---|---|---|---|
| `level` | integer `4`, `5` or `6` | yes (or its old spelling `role`, below) | The level of this supervisor: 4 a mini-supervisor, 5 a top supervisor, 6 a super top; a larger number is a higher level (`docs/architecture.md`, "Levels"). Any other value is refused, a string, a float and a boolean included; 3 is a lane, and a lane is not a `[supervisors]` entry. |
| `runner` | name | yes | A defined runner. |
| `projects` | array of names | no | Projects this supervisor leads; each needs a project file. |
| `owner_channel` | name | no | A defined owner channel. |
| `description` | string | no | Free text. |

`role` is the old spelling of `level` and is still read: `role = "mini"` means level 4 and `role = "top"` means
level 5, and an entry holds exactly one of the two keys (both, or neither, is refused).

`laneboss start --role NAME` prints the entry, with its level as `L5 (top supervisor)`; otherwise the fields are
*validated, not yet used.*

### `[routing]`

Model routing by difficulty. The keys are `mechanical`, `standard`, `hard` and `review`; each is an
array of tables (`[[routing.hard]]`) in order of preference.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `runner` | name | yes | A defined runner. |
| `model` | string | yes | The full model name, including its version (`[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}` with at least one digit). A family alias without a version is refused. |
| `effort` | token | no | The effort or reasoning level the runner understands (`[a-z0-9][a-z0-9-]{0,31}`). |

`lane start --difficulty D` takes the first entry of `routing.D` that is usable: its runner is the one given with
`--runner` (when given), is one of the project's `workers` (when the project lists them), and has an account the lane
may use (the `--account` given, which the runner must list, or one the project does not exclude; a runner without
accounts needs none). `--runner`, `--model`, `--effort` and `--account` override the entry's values one by one, and
`lane.started` records for each, in `chosen_by`, who made the choice: `routing`, the supervisor, the runner's `default`
(the account) or the previous run (a resume keeps the previous run's values); the account's value is `room` when a
turn or a resume of a runner with a `room` command took an account of the runner's list other than the previous run's; an
account `--account` named stays `supervisor`, and the previous run's account `previous`, even when the room command was
asked ("Accounts and adoption" in `docs/architecture.md`).

### `[test_environments.<name>]`

Where tests run. The cloud identity is given by name, never by value.

| Key | Type | Kinds | Meaning |
|---|---|---|---|
| `kind` | `cloud`, `host` or `local` | all | Required. |
| `identity` | string | cloud (required) | The name of the cloud identity or profile tests use. |
| `region` | token | cloud | The region name. |
| `host` | string | host (required) | The name or alias of a test host. |
| `launch`, `collect` | command template | all | Commands that start and collect a test machine (`{lane}`, `{machine}` placeholders). |
| `attest` | command template | all | Verifies a machine before any secret goes to it; required when `secrets` is not empty. |
| `secrets` | array of secret names | all | The only secrets that may reach a verified machine; each must be listed in `secrets`. |
| `max_machines` | integer 1 to 64 | all | Machines one lane may hold at a time. |
| `idle_minutes` | integer 1 to 1440 | all | Collect a machine idle this long. |
| `hard_minutes` | integer 1 to 10080 | all | Collect a machine after this long regardless. |
| `description` | string | all | Free text. |

A key that belongs to another kind is refused ("is not valid for kind cloud"). All fields:
*validated, not yet used.*

### `[owner_channels.<name>]`

How the owner is asked and told.

| Key | Type | Kinds | Meaning |
|---|---|---|---|
| `kind` | `chat` or `file` | all | Required. |
| `service` | token | chat (required) | The chat service module name. |
| `target` | string (at most 200 characters) | chat (required) | The channel or room identifier. |
| `token_secret` | secret name | chat | The secret holding the service token; must be listed in `secrets`. |
| `path` | relative path | file (required) | A queue file, relative to the configuration's state directory. |
| `description` | string | all | Free text. |

All fields: *validated, not yet used.*

### `[cost]`

| Key | Type | Required | Meaning |
|---|---|---|---|
| `currency` | three capital letters | yes | For example `USD`. |
| `daily_cap` | number, not negative | no | Most a configuration may spend per day. |
| `per_run_cap` | number, not negative | no | Most one run may spend. |
| `report_threshold` | number, not negative | no | Report to the owner before daily spending passes this. |

All fields: *validated, not yet used.* (Briefs that touch billing must still carry a cost section;
see `laneboss brief render --touches billing`.)

## projects/<project>.toml

The per-project layer below the configuration. The file name (without `.toml`) is the project name.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `schema_version` | integer | yes | Must be `1`. |
| `name` | name | yes | Must equal the file name. |
| `description` | string | no | Free text. |
| `repository` | string (at most 1024 characters) | no | Where the repository is. An absolute path names a local Git repository: `lane start --project` creates each lane's worktree next to it, at `<repository>-<lane>`, on a new branch named after the lane, from `--base` or the repository's current HEAD. Anything else (a URL, for example) is not used, and the project's lanes need `--worktree`. |
| `lane_prefix` | `[a-z0-9][a-z0-9-]{0,15}` | no | The prefix of this project's lane names: `lane start --project` refuses a lane name without it. |
| `workers` | array of names | no | Runners allowed for this project's mini-supervisors and executors: routing skips other runners and `--runner` may not name one. |
| `gates` | array of tokens, non-empty, no repeats | no | The gate order, for example `fixtures`, `hosted-ci`, `review`, `merge`, `deploy`, `e2e`. *Validated, not yet used.* |
| `excluded_accounts` | array of account names | no | Accounts the project's lanes must not use (for example the top supervisor's own); each must be listed by some runner. Never picked by default, and refused when given with `--account`. |
| `test_environment` | name | no | A defined test environment. *Validated, not yet used.* |
| `reserved_paths` | array of relative paths | no | Repository paths executors must not change. *Validated, not yet used.* |
| `owner_channel` | name | no | A defined owner channel. *Validated, not yet used.* |
| `landing_authority` | name | no | The supervisor, of level 5 or 6, that alone may merge, deploy and declare landed; a supervisor of another level is refused ("must name a supervisor of level 5 or 6"). *Validated, not yet used.* |
| `rules` | array of relative paths | no | Extra standing-rules files, relative to the configuration directory, appended after the configuration's rules when a brief is rendered with `--project`. As for the configuration's `rules`, the first part of a path may not be `orgs`. |

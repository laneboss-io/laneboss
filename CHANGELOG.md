# Changelog

Notable changes to Laneboss are recorded here. The project is pre-release: nothing has been released or
tagged, so there is one entry, for what exists now.

## Unreleased

### Added

- **The generic rules files** (`src/laneboss/protocol/executor.md` and `supervisor.md`), one for executor lanes
  and one for a supervisor's briefing: the rules a lane and its supervisor are held to, shipped with the launcher
  and naming no company, no host and no user, so any configuration installs them as they are written. A lane brief
  carries the executor file; the supervisor file reaches a supervisor's briefing and no lane brief
  ([docs/configuration.md](docs/configuration.md#generic-rules-files), "Generic rules files").
- **The launcher** (`laneboss`, Python 3.11 or newer, standard library only):
  - `scripts/install.sh` installs a version without pip, network access or administrator rights. Installed
    versions are immutable and verified against a manifest, and a rollback is a relink.
  - `install.sh` at the repository root, for anybody without a checkout ([docs/install.md](docs/install.md)): piped
    from `curl`, it gets the source of one version (`LANEBOSS_SOURCE`, a directory or a `.tar` or `.tar.gz` file on the
    machine, or else `LANEBOSS_REPO` at `LANEBOSS_VERSION`, cloned with `git` or fetched as a tarball with `curl`) and
    runs that version's own `scripts/install.sh` with the Python it checked; it holds no installer of its own, and it
    says that what it fetches runs unchecked, with the user's rights. It refuses root, a user it cannot identify and
    any system but macOS and Linux, needs Python 3.11 or newer and never installs one, warns when `tmux` is missing,
    uses only addresses on `https://`, `ssh://`, `file://`, the scp form `user@host:path` and absolute paths (`git`
    is told so with `GIT_ALLOW_PROTOCOL`, `curl` with `--proto` and `--proto-redir`), never prints what an address
    holds before its last `@`, never starts the program already at `PREFIX/bin/laneboss`, removes its temporary
    directory on the exits it catches (a normal end, a failure, and HUP, INT, QUIT, PIPE and TERM), and says
    `already installed` when it is run again with the same version. Every command after its comment header is inside
    one brace group closed on the last line of the file, so a download that stops inside the commands is a syntax
    error and runs nothing, and one that stops inside the header is only comments. The repository's public address
    is still a placeholder, so until it is set the script needs `LANEBOSS_SOURCE` or `LANEBOSS_REPO`.
  - Configurations (schema version 1, `docs/configuration.md`), one per company, kept outside the
    repository, with an invented example in `examples/minimal`. Every launcher command that reads or writes
    state is bound to exactly one configuration (`laneboss decisions` is not; it takes its own `--db`), and
    state directories, markers and links are checked so that configurations stay apart.
  - The event store: one SQLite file per configuration, append-only, a hash on every event, duplicate-safe
    appends, `event append` and `event tail [--follow]`, the lane projection and `state events`, `lanes`,
    `rebuild` and `verify`.
  - A credential detector shared by configurations, standing-rules files, events and briefs.
  - The shared protocol (version 1.0.0, with the refusal rule) and `brief render`, which appends the
    protocol and the standing rules to a brief and keeps the inputs it used. Briefs that touch billing or
    deployment must carry the cost or preflight sections.
  - `doctor`, one result line per check, with a non-zero exit when any check fails.
  - Lanes (version 0.3.0, [docs/architecture.md](docs/architecture.md#lanes)): `lane start` renders the
    brief, picks the runner, model, effort and account from `[routing]` or the supervisor's flags, creates a
    worktree on a branch named after the lane (or uses `--worktree`) and starts the run in a tmux session of
    the configuration's own server, returning at once. A supervising process of the launcher appends
    `lane.started`, `lane.stuck`, `lane.timeout` and `lane.ended` (reason `exit`, `timeout`, `stopped`,
    `limit` or `dropped`) as they happen, enforces the budget and stops the whole process tree. `lane resume`,
    `stop`, `status`, `check` (records `lane.lost`), `mark` and `clean` complete the life cycle. Every lane event
    has a documented payload, checked at append together with the lane's life cycle, and the projection
    carries the run, runner, model, account, last end, resumes and lost runs. Configurations gain `[lanes]`,
    runner `resume` templates, `limit_patterns`, `dropped_patterns` and `quiet_seconds`; `event tail` gains
    `--lane` and `--until`. `examples/minimal` ships a stand-in runner program, and the quick start runs a lane.
  - Refusals (version 0.5.0, [docs/architecture.md](docs/architecture.md#refusals)): the launcher may read a lane's
    raw session records where the configuration names them (formats `claude-code`, its shapes checked against real
    records, hook messages included, and `text`, found with a runner's new `records` templates) and records every
    refusal a configuration's `[[guards]]` recognise as `lane.refusal`, within seconds while the run lives, from a
    scanning process beside the supervising process that never delays stop, budget or sampling. A
    later shell call of the lane that writes a refused call's files (`shell-write`) or repeats the refused command in
    other words (`reworded`) is recorded as `lane.workaround_suspected`; a write through the file tool is not. Excerpts
    that look like credentials are withheld (length, hash and position only). `lane scan` scans again and appends only
    what is new, `lane refusals` lists refusals, suspicions, verdicts and what was covered, and `lane review` records
    the supervisor's verdict on each path (`lane.refusal_reviewed`). `lane mark --state accepted` and `merged` first
    scan every run to its end and are refused while a suspicion has a path without a verdict or a run is not covered
    (`--accept-uncovered` records what was not covered). The projection gains `refusals` once a lane has one.
  - `laneboss start [--config NAME] [--role ROLE] [--format text|json]` (version 0.4.0): a read-only briefing
    for a supervisor session. Without a configuration it lists them (an unreadable one is marked unreadable).
    Bound to one it prints, as Markdown or as one JSON value, the configuration, the shared protocol (text,
    version, hash), the standing rules with their hashes and text, the chosen `[supervisors]` entry, the
    checks of `doctor` that only read, the lanes in four groups (running; ended and waiting for the
    supervisor; accepted or merged and not yet cleaned; lost or declared gone), the last 20 events, and what
    the store does not know yet. It states only what the store supports: the lanes and the events come from
    one read; a store that fails its check gives exit 3 and no briefing, and another configuration that
    cannot be read gives a warning as the first line under the briefing's Configuration heading; lanes with
    events waiting to be
    recorded are named; a name or role that looks like a credential is shown as `[withheld]`. It appends no
    event and creates no state, also for a configuration that was never used (what every reader of the store
    may still do is under "Known limits" in `docs/architecture.md`).
  - The Claude Code plugin (`plugins/claude-code`, [docs/plugin.md](docs/plugin.md)): one slash command,
    `/laneboss`, that runs `laneboss start` for the configuration and role typed after it (no argument lists
    the configurations, or gives the briefing of the configuration `LANEBOSS_CONFIG` names) and tells the session that the protocol and the standing rules it prints bind the
    whole session. Typed text never enters a shell block: the session passes at most two plain names to the
    plugin's own script, `start.sh`, the only command the plugin pre-approves, and the script always answers
    (a first line `laneboss plugin: NOT STARTED` and the reason when it cannot start a session).
    `scripts/install.sh` installs the plugin with the launcher, lists its files in the version's manifest and
    refuses a changed mode like a changed file; `laneboss plugin path [--agent claude-code]` prints its
    directory. Nothing is installed into Claude Code; the page gives the steps.
  - Organisations ([docs/architecture.md](docs/architecture.md#organisations)): a configuration may name the
    organisation it belongs to with `organisation = "NAME"`. The organisation's directory is
    `$LANEBOSS_HOME/orgs/NAME/` and its tools are in `tools/` there; the launcher only reads under `orgs/`.
    `organisation_rules` lists the organisation's own rules files, read inside that directory with the guarantees a
    configuration's own files have; they come first, under the label `orgs/NAME/<path>`, in a rendered brief, in
    the event that records it and in the briefing; a `rules` entry that starts with `orgs` is refused, because that
    is the label's spelling. A configuration that names an organisation is refused by `config validate` when a
    runner `command` or `resume` element, or a judge `command` element, is an absolute path inside another
    organisation's directory (tools are not shared between organisations). One that names none is accepted, so that a
    configuration written before organisations keeps working; `laneboss doctor` fails its check `organisation.tools`
    when such a command points into an organisation's directory, naming the key path and saying to add
    `organisation = "NAME"`. `laneboss start` names the organisation and says whether its tools directory is
    present, and `laneboss doctor` has the check `organisation.tools`. A configuration without the two keys behaves
    as before.
  - A lane's session identity and the prompt on standard input
    ([docs/architecture.md](docs/architecture.md#session-identity), and "Session identity and the prompt on standard
    input" in [docs/configuration.md](docs/configuration.md)): a runner whose `command` uses the new placeholder
    `{session}` gets a random UUID made at `lane start`, kept in `lane.started` as `session_id` and shown by `lane
    status`; a `lane resume` hands the same one to the resume template (so a resume names its session instead of "the
    newest of this directory"), and `lane start --reuse` makes a new one. `config validate` refuses a runner that has a
    `resume` and uses `{session}` in only one of its two templates, and anywhere else it is not allowed (it is also
    allowed in a `records` path, which then names the files of that path's session). A lane and its runner's resume
    template must go together: a lane without an identifier (started by an earlier version, or by a runner that did
    not use the placeholder) is refused a resume by a runner whose resume template now uses it, and a lane with one is
    refused a resume by a runner whose resume template no longer does, each before anything starts. A `{session}`
    records path gives the runs of a lane without an identifier the reason `no-session`. A store written before this
    change is read as before. A runner has a new key `prompt`, `"argument"` (the default, as before) or `"stdin"`: the
    launcher then writes the rendered brief (at a start) or the rendered follow-up message (at a resume) to the
    runner's standard input and closes it, from a thread of its own so that a runner that never reads it cannot hold up
    the budget, and `{brief}` and `{message}` become optional. `lane.ended` records what became of that prompt as the
    optional key `prompt` (`written` or `cut`, with the bytes written), and `lane status` shows it; written means
    written into the pipe and closed, not read.
  - Turns and mail ([docs/architecture.md](docs/architecture.md#turns-mail-the-loop-and-attach), its parts that are built,
    and "`[turns]`" in [docs/configuration.md](docs/configuration.md)): a lane started with `lane start --turns [--idle
    SECONDS]` is turn-based, a lane whose agent session lives on across runs. Run 1 takes the brief on standard input and
    every later run, a turn, resumes the same session with one message; the lane waits (state `waiting`, shown by `lane
    status` as `idle`) between turns. The start is refused unless the runner has `{session}` in `command` and in `resume`,
    `prompt = "stdin"` and a `resume` template, and the message names each missing part. `lane send --lane L (--file PATH |
    -) [--from NAME]` stores one message as an immutable file `lanes/LANE/mail/SEQUENCE-DIGEST` (the sequence as nine digits
    and the SHA-256 of the bytes), written before the event `lane.mailed` that carries its sequence, sender, hash and size
    and never its text. A message is checked as a brief is (UTF-8, no launcher block, no credential shape), holds at most
    262,144 bytes and is never taken from an argument, a lane holds at most 1,000 messages that wait or have returned, and
    two sends at once cannot take one sequence number (a lock file `mail.lock`). `lane turn --lane L [--idle] [--account A]
    [--budget MINUTES]` is `lane resume` with its message taken from the mail: the messages that returned and then the
    waiting ones, at most 64 and 1,048,576 bytes of joined text, each under a header line that names its sender and time
    (` (again)` for one that returned), rendered once with the protocol and the standing rules; with nothing to send it
    starts nothing and says so (exit 0), and with `--idle` and no mail it sends the configuration's idle message. A message
    is delivered when the turn that carried it ends with reason `exit`, exit code 0 and a prompt written whole, and goes
    back, in front of newer mail, on any other end (reasons `exit`, `timeout`, `stopped`, `limit`, `dropped`, `lost`, `gone`
    and `cut`, a prompt that was cut); which messages wait, are in flight, are delivered or have returned follows from the
    lane's events alone. The new events are `lane.mailed`, `lane.delivered` and `lane.returned` (the supervising process
    announces the end of its turn right behind `lane.ended`, `lane check` the loss of one behind `lane.lost`, and `lane mark
    --gone` behind `lane.gone`; each prints `returned`), `lane.started` gains the optional keys `mail` and `idle_seconds`,
    and a lane's row gains the optional field `mail` and the state `waiting`. `lane resume` is refused for a turn-based lane,
    and `lane start --reuse` while a message waits or has returned. `state verify` checks the message files and prints
    `mail_files` and `mail_orphans`; `laneboss start` lists the idle lanes in a group of their own; `laneboss doctor` warns,
    without failing, about a runner that can take turns and has no `limit_patterns` (check `turns.limit_patterns`).
    Configurations gain `[turns]` with `idle_message` and `idle_seconds`. The shared protocol is version 1.2.0.
  - The loop ([docs/architecture.md](docs/architecture.md#turns-mail-the-loop-and-attach), "The `lane loop` command",
    and "`[turns]`" in [docs/configuration.md](docs/configuration.md)): `laneboss lane loop` is one process for each
    configuration that decides when the turns of the turn-based lanes start, and nothing else: a turn when mail waits, a
    turn when a lane has been idle for its `idle_seconds`, and a wait after a turn that did not end well. It holds an
    exclusive lock on `loop.lock` in the state directory for as long as it lives (a second loop is refused, after about
    half a second, and names the first; the lock is asked for ten times, 50 ms apart, so that the instant lock of a
    status does not refuse a loop that starts), writes `loop.json` (believed only while the process it names lives) and
    `loop.log`, and is ended by `lane loop --stop` (or SIGTERM, SIGINT or SIGHUP), which stops no turn. An error that
    nobody expected ends the loop with `loop.stopped` (reason `error`) and exit status 70, and a detached loop writes a
    line with the time and the traceback to `loop.log` (a foreground loop prints `internal error: TYPE`, as every
    command does). Every `poll_seconds` it reads the store once and takes each declared lane, a turn-based lane that is
    neither abandoned nor cleaned: a running lane whose
    supervising process is gone gets the check of `lane check --lane L`; a lane with mail, or idle for long enough, gets
    a turn, started by the function that `lane turn` uses and with the environment that the loop captured when it
    started (kept in the loop's memory, and never written to the state directory, to an event, to `loop.log`, to
    `loop.json` or to a run record; every tmux command of the launcher runs with a fixed environment of five names, so
    the tmux server keeps no other variable of its caller); after an end other than reason `exit` with exit code 0 and a
    prompt written whole it waits `backoff_seconds` (`limit_backoff_seconds` after a limit) and records one
    `loop.skipped` for the wait; a turn that cannot start is a `loop.skipped` with reason `refused`, and the lane is
    held back for `backoff_seconds` (a hold that lies further ahead than that counts as over). The events
    `loop.started`, `loop.stopped`, `loop.turn` and `loop.skipped` are checked at append (`event append` refuses one that
    is not in its form) and nowhere else, so a store that holds such an event written by hand still verifies and
    rebuilds, and the loop reads only the events that are in their form. `lane loop --detach` runs the loop in the
    tmux session `laneboss+loop` and `lane loop --status` prints the loop and its lanes (`waiting`, `backoff_until`,
    `next` and `bad_ends` for each: `next` is what the loop would start for the lane now, `mail`, `idle`, `backoff` or
    null) and `last_error`, the time and the text of the latest failure of a pass, which the loop keeps in `loop.json`
    (null when no loop that `loop.json` names lives; a text that looks like a credential is withheld); in the foreground
    the loop prints one JSON line for each event it appends. `lane check` gains `--lane L`. Configurations gain
    `poll_seconds`, `backoff_seconds` and `limit_backoff_seconds` in `[turns]`.
  - Every tmux command of the launcher runs with a fixed environment (`PATH`, `HOME`, `LANG`, `TMPDIR`, `USER`), so a
    tmux server keeps no other variable of the process that started it.
  - Attach and the stream readers (the part "The `lane attach` command and the stream readers" of
    [docs/architecture.md](docs/architecture.md), and "The stream of a runner" in
    [docs/configuration.md](docs/configuration.md#the-stream-of-a-runner-stream)):
    `laneboss lane attach --config N --lane L` is a terminal view of a turn-based lane and a keyboard for it. It prints
    the lane, its state, the run, the session identity, the runner and the model; shows the live turn's output from the
    lane's own log (from the start of the run's range; the log is polled every 0.2 seconds and the store every 0.5, and a
    run that began and ended between two looks at the store is shown after the fact)
    through the reader that the runner's new key `stream` names (`text`, the default, or `claude-stream-json`; any other
    name is refused by `config validate`); and between turns shows `idle`, how the last turn ended and how many messages
    wait. It shows the permission mode that the agent reports, with a plain warning on `bypassPermissions`, and for
    `claude-stream-json` the cost of a turn, the difference of the session's running totals, in one line at its end. A
    real session prints lines of other shapes (the real trial showed about fifty in three turns): the reader gives no
    output for the agent program's bookkeeping, for a hook that succeeded, for a rate limit that is `allowed` and for the
    result of a tool that did not fail; shows a notification as `notice: TEXT`, a hook that did not succeed as `notice:
    hook NAME: OUTCOME (exit CODE)` and a tool that failed as `[tool error] TEXT`; and shows everything else that it does
    not know, a rate limit that is not `allowed` among it, as the line. A typed line is one message, stored with the code of `lane send` (sender `attach`) and followed by `lane turn`;
    `/turn`, `/stop`, `/help` and `/exit` are commands, a line that starts with a slash and is no command is never sent,
    and a message sent while a turn is live waits for the next one (attach starts no turn by itself). While a line is
    being typed the output is held back and printed at the next prompt. Ctrl-C stops, with the code of `lane stop --lane L
    --run N`, only a turn that this attach started; leaving attach (`/exit`, end of input, a closed terminal, SIGTERM)
    stops no turn. A Ctrl-C that comes while a line is being sent and its turn started, or while the stop is being asked
    for, is counted and acted on when the command has returned or the request has gone out (a second key that follows
    the first at once does not cancel the request, and two keys less than 2 seconds apart, a double tap just after
    Enter, act as one Ctrl-C that stops the turn that the line began); a key counted while a lane command runs is noted
    on the screen, and a key 2 seconds or more after the first one leaves attach at once, with a line that says that a
    turn may be starting and was not stopped; a stop that is refused because the run had just ended says so and stays
    at the prompt, and every other refusal is printed. A Ctrl-C says that a line was discarded only when the line
    editor can say that one was (a line being typed, or a message that goes on), not at an empty prompt, and where the
    line editor cannot say (the one of macOS, libedit, whose buffer keeps the bytes of the last line) it says `anything
    typed was discarded`, which is true either way; the same answer decides whether the output is held back while a line
    is typed. Attach starts no agent, keeps no child process and signals nothing itself, no line of any stream gives a
    traceback, and no control
    character of a stream reaches the terminal. `lane send` is split into the part that reads the message and the part
    that stores it, which attach calls with the typed line, and `lane stop` into the part that asks for the stop and the
    part that waits for the end, which attach calls apart; `lane stop` itself does not change. The package version is
    unchanged by this step.
  - Accounts and adoption, the built half (T5,
    [docs/architecture.md](docs/architecture.md#accounts-and-adoption-t5-built-in-part), and "`[lanes]`" and
    "`[runners.<name>]`" in [docs/configuration.md](docs/configuration.md)): a runner gains the key `room`, an argument
    vector run without a shell, once for each account a turn is considering, with standard input from `/dev/null`, the
    caller's environment and at most `[lanes] room_timeout_seconds` (a whole number from 1 to 60; the caller reads it,
    and the launcher's own default is 20). Its standard output must be exactly one JSON object of at most 4 KiB with the
    keys `room` (`true` or `false`), `slots` (0 to 64) and `reason` (one line of at most 200 characters); a non-zero
    exit, a timeout, or anything that is not exactly that object counts as no room, with one fixed sentence, and nothing
    of the output is shown besides it, while a `reason` with the shape of a credential becomes `(withheld)`. After every
    run — ended in time, timed out, or too much output — the command's process and every process of its tree, group
    and session are stopped by identity (SIGTERM, then SIGKILL after `stop_grace_seconds`), never by a name pattern and
    never by a group signal; the gap is named in the module and in `docs/architecture.md`: a descendant outside the
    command's process group and session whose parent has ended before a look of the stop walked from it is not found, not
    stopped and not counted, and the answer can then be room while it runs, because the process that runs the room
    command does not make itself a child subreaper; outside Linux the gap is wider, as `ps` reports no session id, so a
    process that only left the command's group is missed the same way. A turn or a resume of such a runner takes its
    account in the design's order — the one `--account` names, and only that one, else the previous run's account when
    the runner lists it and the project keeps it, else the runner's other accounts in the order it lists them, skipping
    the project's exclusions
    — the first whose checked answer is `room` true with `slots` of 1 or more and that has not filled its `slots` in
    this pass, and `chosen_by.account` records the value `room` when a turn or a resume of a runner with a `room` command
    took an account of the runner's list other than the previous run's; an account `--account` named stays `supervisor`,
    and the previous run's account `previous`, even when the room command was asked; `default` is written only by
    `lane start`, for the runner's first account the project does not exclude, and never by a turn or a resume. No room
    means no turn: a person's `lane turn` is refused (exit 2) with the account's own reason and appends nothing, and the
    loop records `loop.skipped` with reason `no-room`, the command's reason as `detail`, and the hold a refused turn
    gets (`backoff_seconds` after the skip, one skip per wait), while starting at most `slots` turns on an account in
    one pass. The event `lane.adopted` is accepted at append only for a lane that holds no `lane.*` event yet, and the
    projection reads it as a run 1 that is already over: state `waiting`, the row's `mail` with `turn_based` true and no
    entry of `times`; `lane status`, `lane send`, `lane turn`, `lane resume` and `lane start --reuse` take it where no
    `lane.started` exists. `lane adopt` is built: it takes a session started outside the launcher, claims its existing
    working directory, renders and keeps the standing brief (`brief.rendered`) and appends `lane.adopted`, printing
    its payload plus `lane` and `event` (id and seq). It starts no run and supervises nothing; the first turn is run 2,
    a resume of the given session. It checks inputs before recording a lane event, taking a claim or rendering a brief,
    holding the lanes lock from the store refresh through the append. It refuses a known lane name (no `--reuse`), a
    session identifier that is not a lower-case UUID or belongs to another lane in any state, a runner that cannot take
    turns, an account the runner does not list or the project excludes, and a resume template using an omitted effort
    or project. It also refuses a missing or disallowed working directory, one another lane works in or claims, a
    taken tmux session name, a runner without a `{session}` records template, no session record, a newest record written
    within the runner's quiet seconds, and no supplied or configured time budget. `--project` is optional; omitted
    effort and account stay null; `--idle` defaults to `[turns] idle_seconds`. `--budget` is recorded as `budget_minutes`,
    else `[lanes] budget_minutes`, with no budget in force at adoption. Records lookup follows the runner's templates;
    it does not check that the session worked in the given directory. A refused check exits 2, appends no lane event,
    takes no claim and renders no brief; the state directory, its lock file `lanes.lock` and the account's claims registry
    may have been created.
    The rule that no pass starts a room command for an account while an earlier one for it still runs,
    the room command of `lane start`'s first account, and the reading of
    an account's remaining quota by an adapter under `integrations/` are designed and not built.
  - `scripts/scan.sh` and `scripts/install-hooks.sh`: the publication scan (private-key headers, long
    secret-like tokens, non-loopback IPv4 addresses, email addresses and an optional denylist of your own)
    and a pre-commit hook that runs it.
  - Judges ([docs/judges.md](docs/judges.md)): a configuration can name external judge commands
    (`[judges.NAME]`: `command`, `timeout_seconds`, `description`), and `laneboss judge ask` asks one a yes/no
    question over a fixed contract: one JSON object in, one JSON probability out. The judge name, question, lane
    and subject names, the prompt and every subject text go through the credential detector before anything is
    sent (a refused name is refused and never repeated, a refused text is sent as `[withheld]`); a longer text is
    cut to 4000 characters and screened again; what a judge returns as `model` and `request` is an identifier the
    detector accepts, or the answer is no answer; a probability is read as the number that was written and checked
    against 0 and 1 before it becomes a float. The command runs without a shell, in a session of its own, with the
    launcher's environment minus `LANEBOSS_` variables, and a time-out ends its whole process group. A judge that
    gives no answer is reported unavailable (`timeout`, `exit`, `output` or `not-found`), never as a made-up
    verdict. Every ask writes two whole lines to `judges/egress.jsonl` in the state directory, a sent line before
    the command starts (an attempt, not proof that the command ran) and an outcome line after it (the hash and
    size of the request, never its text); an ask whose sending cannot be logged is not made (exit 7), the state
    directory is synced once before the sent line, and judge-only state records its owner like all other state.
    The log never grows past the 64 MiB that `judge egress` reads (a sent line and a reserve for the outcome of
    every unfinished ask must fit, else the ask is refused and the file is to be moved aside), and a log whose
    last line is not one of this version's, such as one an earlier unreleased build wrote, is not appended to.
    `judge list`, `judge egress [--since]` and a `judge.NAME` check in `doctor`. Nothing uses judges yet.
- **The owner decision store** (`laneboss decisions`, also `laneboss-decisions` and
  `python -m laneboss.decisions`; Python 3.9 or newer on its own, `docs/decisions.md`): decisions with
  their provenance and the owner's exact words, kept in one portable SQLite file at schema version 2 with
  row protection and first-written hashes; keyword, vector and hybrid search; embeddings with a hash-chained
  egress log; `verify`, `export`, `import`, `load` for batches and `migrate` for version 1 stores.
- Exports that earlier decision-store code wrote stay importable: their manifest carries an earlier `format`
  value, which import reads next to the current one (export writes only the current value). The exception is an
  export from before the egress hash chain that carries egress receipts: import refuses it and names the
  records-only way out ([docs/decisions.md](docs/decisions.md#older-layout)). Earlier code does not read
  exports of this code.
- `laneboss decisions serve` ([docs/decisions.md](docs/decisions.md#resident-search)): a resident search. One process
  holds the store in memory and answers searches over a Unix socket (mode 600, in a directory of mode 700, no network
  port; `curl --unix-socket` is enough to ask), with the code of `search`: a keyword or an exact search is answered with
  the command's bytes, scores included, and a vector or hybrid search with the command's bytes for the same question
  vector and the same Python version, since the provider may return a different vector for the same text on another
  call and the server answers a question again with the vector it got the first time. It looks at the file before each
  request and builds its index again when a record,
  vector or model has changed; it remembers the vector of a question for the embedding provider, writes the same
  egress receipt on a miss, and sends and writes nothing on a hit; the store is otherwise read-only to it. It stops
  after `--idle-exit` idle minutes (default 60) and removes its socket. It is written for Python 3.9 and newer, and its
  tests (`tests/decisions/test_serve.py`, and one in `tests/e2e/test_passthrough.py`) have been run on Python 3.12 on
  Linux only.
- The disk line (`[disk]` in [docs/configuration.md](docs/configuration.md)): a new command `laneboss disk
  [--config NAME]` reads the file system a configuration watches with `os.statvfs` and prints one JSON object
  (`path`, `used_percent`, `free_bytes`, `warn_percent`, `stop_percent`, `state`, `latched`), exiting 0 for `ok` and
  `warn` and 3 for `stop`. `lane start` (turn-based included) reads the same file system before it creates a branch,
  worktree or lane directory (it opens the state directory and the lanes lock first, and nothing of the lane):
  at `warn_percent` (default 85) it starts, says so on standard error and records `disk.warn`; at `stop_percent`
  (default 90) it is refused before a branch, worktree or lane directory is made and records `disk.stop`, until a
  reading is back under `warn_percent`. A latch holds `stop` between the two lines, so a disk that was full is not
  taken for fresh by a later reading that falls between them; the latch is the watched file system's, one file per
  device id under the state home, so every configuration of the user that watches that file system shares it (and the
  lock held over its read, decision and write); `lane resume` and `lane turn`
  create nothing new and are never refused. A file system that cannot be read - and one whose `statvfs` succeeds but
  reports no usable blocks, a procfs mount for one - refuses the start with the error. The
  section is optional and its path defaults to the user's home directory.
- Black-box tests: `tests/e2e/` drive the installed command, `tests/decisions/` drive the decision store and
  run on Python 3.9 as well. `README.md`'s quick start is run as written by a test.
- The project is licensed under the Apache License 2.0 (`LICENSE`, `NOTICE`).
- `integrations/claudock/cos.py`: `cos`, an interactive front for accounts that take only headless requests (Claudock).
- `tests/e2e/test_cos.py`: its black-box tests, with a stand-in wrapper and a made-up sample; no Claudock needed.
- `docs/claudock.md`: Laneboss with Claudock: a runner block, and `cos` with its permission default and its limits.
- The credential detector also refuses addresses that carry a secret in the URL itself: a Discord webhook address
  (`discord.com` or `discordapp.com`, any subdomain such as `ptb.` or `canary.`, with or without a versioned
  `api/v<N>/` path), a Slack incoming-webhook, trigger or workflow address, and a Google Apps Script web app address
  (including the Workspace forms `/a/macros/<domain>/s/` and `/a/<domain>/macros/s/`, the account form `/macros/u/<N>/s/`,
  an id with no suffix, and a bare deployment id). A match needs no scheme, the host is matched in any case, and a
  JSON-escaped (`\/`) or percent-encoded (`%2F`) slash counts as a slash. Each rule requires the token part, so prose
  that names the domain alone is not refused.

### Changed

- The publication scan, `scripts/scan.sh`, refuses a scan that would read nothing: a root that is missing or is not a
  directory, and (unless `--staged`, where an empty index is a real answer) a tree that yields no file, exit 2 with one
  `SCAN ERROR:` line, and a denylist named by `LANEBOSS_SCAN_DENYLIST` that holds no rule is refused the same way
  instead of passing with `no match for 0 denylist rule(s)`.
- The shared protocol is version 1.2.0: only its version line changes, so the rules of 1.1.0 stand, and the events that
  the launcher writes carry it. A store written under 1.1.0 verifies, reads and rebuilds under 1.2.0 without a change: the
  events of 1.1.0 have none of the new kinds and keys, and their lane rows have no `mail` and are what they were.
- The shared protocol is version 1.1.0: its refusal rule adds that files are written with the file tool, that shell
  redirection and here-documents are for command output, not for writing documents or source files, and that the
  launcher may read a lane's raw session records, where the configuration names them, for refusals and suspected
  workarounds.
- Run records gain `log` (the run's byte range of the lane's log), and `lane.state` may carry `not_covered`. Stores of
  0.3.0 need no rebuild: lanes without refusal events keep their projection rows. With a store that holds the new
  event kinds, version 0.3.0 can still read and hash-check every event (`event tail`, `state events`), but `state verify`
  and `state rebuild` refuse the new kinds, and its lane commands refuse a lane row that carries `refusals`.
- After an independent review of refusals (all before any release): hook refusals kept as attachment lines are read;
  the `codex` format is withdrawn until it is built from real records; results longer than the bound are matched on
  their first and last 64 KiB with the cuts counted, and an unknown content block makes a record partly read; a
  configured path without a file, an unreadable directory and a record gone since an earlier scan are not coverage;
  `lane mark --state accepted|merged` holds the lanes lock; lines belong to a run only inside its window; records in the
  launcher's own directories and placeholders with path components are refused; the scanning process's end takes at
  most seven seconds; a `--note` path is never repeated; an excerpt is withheld for any credential that begins in it;
  records are identified by path and generation. `lane.refusal` gains `via` and `hook`; refusal events written by the
  earlier commits of this work do not have them and are refused by `state verify`.
- After a second review of refusals (all before any release), made smaller: `text` reads only the run's own log
  (`paths = ["{log}"]`; any other path is refused), opened as the launcher's own file, so text records need no
  generations; a `claude-code` record that changes under the reader (shorter than what was read, or another first line)
  is `replaced` for good instead of read again, and a record is identified by its real path again; scans merge their
  coverage under the lane's lock, so a record once not covered stays shown; `**` follows directory links and every
  discovery bound is reported; a record with no assistant or user line read whole is `unrecognised`; the tail window of
  a long text starts at a line; a call that a hook refuses is not suspected when the hook's message is read before the
  call is decided.
- After a third review of refusals (all before any release): a run's log shorter than its recorded range is
  `truncated`; a record whose 4096 bytes before the reader's place changed is `replaced`, and `lane scan` and the gate
  of `lane mark` read every record from its beginning; a coverage file that cannot be read is reported
  (`coverage-unreadable`) and never overwritten, and coverage files carry a format number (delete those of the
  unreleased builds before, which have none); a session wholly outside a run's window is not that run's record.
- After a fourth review of refusals (all before any release): when a run's range of the log begins before an earlier
  run's range ends, the log was removed or cut and written anew, and that earlier run is `truncated`; a refusal in the
  run's own log carries the run's launch in its identity; a coverage file with a damaged body is `coverage-unreadable`;
  a record outside a run's window is listed with the state `outside`.
- After a fifth review of refusals (all before any release): the run's own log seen shorter than what the live reader
  has read makes the run `truncated` at once and for good; the one loss of the log the launcher cannot see is named.
  Stores written by earlier unreleased builds of refusal detection are not supported: start from one without refusal
  events.
- After a sixth review of refusals (all before any release): whatever the live reader sees about any run it follows,
  the current one or an earlier one, is saved at the look that saw it and when its loop ends otherwise; a log seen
  shorter than the end of a run's recorded range is `truncated` for good in the reader too.
- After a seventh review of refusals (all before any release): a record of an earlier run is called `unrecognised` (or
  `partly-read` for a first line that never ended) only once it has been read to its end, its last line included; a
  record that goes from one bad state to another is saved once, not on every look; a save at the live reader's end
  never takes the place of the error that ended it, and a state directory that is gone is a failure to save.
- Lane events now need their documented payloads and must fit the lane's life cycle; version 0.2.0 accepted
  any payload. A store holding lane events appended by hand under 0.2.0 without those payloads no longer
  verifies (nor rebuilds), and the stored lane projection has new fields: run `state rebuild` once after
  upgrading a store whose lane events are valid.
- After an independent review of the lanes (all before any release):
  - A run's processes are always stopped before anything is recorded, and an event the store cannot take now
    waits in the lane's `pending.jsonl` and is appended later, in order, by the supervising process or by
    `lane check`; `lane status` shows pending events.
  - Every launch has a run record (`lanes/LANE/runs/LAUNCH.json`) with the identities (id and start time) of its
    supervising process, runner and sampled process tree; every signal is checked against them. `lane.lost` says
    how many processes survive; `lane resume` and `lane clean` refuse while any does; `lane stop` removes them and
    acts on one launch (`--run N`).
  - The tmux server is reached through a socket path that each `lane.started` records (`session.socket`, in
    `/tmp/laneboss-UID/`), whatever `TMUX_TMPDIR` says; `session.server` is gone.
  - The run's process tree is sampled every 0.5 seconds; on Linux the supervising process adopts the run's
    orphans.
  - Working directories carry a claim; start, resume and clean hold the configuration's lanes lock across their
    checks and actions; `--worktree` refuses a repository's main working copy; `lane clean` removes only a
    worktree that carries the lane's claim and branch, and reports from the file system what a failed removal left.
  - The launcher's Git commands ignore inherited `GIT_` variables.
  - Classification is bounded (64 KiB, 4096 characters a line, 2 seconds in a separate process);
    `lane.ended` gains `classification`.
  - `lane resume` verifies the rendered brief and the inherited account; a `lane.started` must name its own
    configuration's session and lane files; a runner's start template must contain `{brief}`.
- After a second review, about what happens when something around a run fails (all before any release):
  - A failed observation is never a conclusion: when the process table cannot be read, a signal cannot be
    delivered or Git cannot be asked, the lane command says so and does nothing it cannot verify. `lane check`
    reads the lanes before the process table. `lane stop` and a timeout count as removed only what they then
    see gone and name every survivor; `lane.ended` is recorded only once the runner is gone, with its real exit
    status (no more made-up SIGKILL or 127) and a new `survivors` field, and `lane status` shows `stopping` while
    the runner cannot be removed.
  - Recording never holds up the supervising process: its events go through a recorder thread beside the
    control loop and carry the time they were observed; the run record is written again until a write succeeds.
  - A lane's events keep their order: nothing is recorded for a lane while it has pending events (the store
    refuses it, lane commands append the pending ones first or refuse); events the store refuses for good are
    kept with their reason and counted as `refused`, in `lane check` and in `lane status` (`refused_events`).
  - Claims of plain working directories moved to a claims registry: nothing is written into a plain working
    directory any more.
  - Sessions and sockets are acted on by identity: `lane clean` never kills a session by its name, and a socket
    path that is a link (or a socket directory that is not the user's alone) is refused on every use.
  - The run's process tree is followed only through processes seen alive by identity, the runner's process
    group from the moment the runner is created, and process start times are read in the C locale and UTC.
  - A failed start removes only what it created and never forces a branch deletion; it creates the branch with
    `git branch` before `git worktree add`.
  - The last matching line decides between `limit` and `dropped`; `lane clean` refuses a working directory
    another lane claims and releases its own claim on a worktree it keeps; error messages no longer repeat an
    account the configuration does not list; `[lanes] lock_wait_seconds` bounds the wait for the lanes lock;
    `LANEBOSS_PROCESSES=portable` runs the portable process code on Linux; a file that disappears under a lane
    command is a refusal, not an internal error.
  - On macOS, two lane commands creating the lanes lock at the same moment could fail one of them with an internal
    error (the system answers one `open` with O_CREAT with "no such file"); such opens are now tried again.
  - The classification process ends by itself one second after its bound, so it no longer outlives a supervising
    process killed while it ran (seen on macOS).
- After a third review (all before any release):
  - The survivors in `lane.ended` are counted once the runner is gone, after one more attempt to stop what is
    left, never from an earlier observation.
  - `lane stop` whose supervising process dies before it has stopped the run removes the recorded survivors itself
    or names them; its output gains `stopped_by` (`supervisor` or `lane-stop`).
  - The recorder drops an event only when the store refused it for good; any other failure keeps it and retries,
    and what is still unrecorded at a normal exit is kept in `pending-LAUNCH-ID.jsonl` for the next drainer. An end
    that can be kept nowhere is reported in `watch.log` and the supervising process exits with status 1.
  - `lane resume`, `lane start --reuse` and `lane clean` refuse a lane whose latest launch has no run record and no
    end event without survivors.
  - There is one claims registry per account, found from the user database's home directory, whatever
    `LANEBOSS_HOME`, `LANEBOSS_STATE_HOME` or `HOME` say; `LANEBOSS_TEST_CLAIMS_DIR` moves it for tests.
    `lane.started` gains `claims`, the registry that holds the claim, and a command that would look in another one
    refuses.
  - A direct `event append` checks for waiting events and appends under the lane directory's lock, so it cannot
    overtake an event the recorder has just queued.
  - `lane clean` releases the lane's claim on a plain directory that was removed and made again, and leaves the
    new directory alone.
- After a fourth review (all before any release), by making code smaller and its ownership single:
  - Files of waiting and refused events are always written whole (temporary name, sync, rename), never appended
    in place; a leftover file is removed only after the pending file holding its events is in place.
  - The recorder thread is the one owner of the run's queued events, the one in flight included; at exit the
    supervising process only asks it to finish and waits, and `watch.log` ends with the exit status. Leftover files
    are written under the lane's lock, so a direct append that has checked for waiting events goes first.
  - `lane stop` acts on the run record read after it saw the supervising process gone.
  - `lane start --reuse` refuses another claims registry than the lane recorded, as resume does.
  - A process group is attributed to a run only through a member verified in the same snapshot.
  - A lane event an earlier commit of this branch wrote (without `claims` or `survivors`) is an integrity problem
    for every lane command that reads it.
  - `lane mark --gone` (event `lane.gone`): the supervisor's declaration that a lane's open launch, with no end
    event and no readable run record, is gone; then resume, reuse and clean go on. No end is made up.
- The owner decision store, after its accepted follow-ups:
  - The storage-problem message (exit 7) no longer claims a write it did not make. A command that only
    reads says SQLite failed while it read the file, or restored it from the journal of an earlier write
    that did not finish, and that nothing was changed. Any other command says SQLite failed while it read
    or wrote. An `init` that fails after it created the database file names that empty file and says it is
    still there.
  - `import` checks the destination's layout under its own write lock. A schema change by another
    connection while the import waits for the lock is now exit 3 ("integrity problem: schema definition
    mismatch") before the first insertion, not exit 2 ("invalid import") after the records were inserted.
    As with `verify`, `export` and `load`, the check now comes after the lock, so a destination of the
    wrong layout whose lock another process holds for longer than the 10-second wait gives exit 5 (busy)
    instead of exit 3.
  - The manual's Run section warns that zsh does not split a command kept in a shell variable (exit 127).
  - New tests for the exit-7 messages on each path, for import's layout check under the lock, and for a
    load killed with SIGKILL; the pipe-substitution test of export is synchronised on the export's first
    check; `test_cli` closes its connections (no ResourceWarning on Python 3.13 and later).
- The layers of sessions have level names, a larger number meaning a higher level: L3 executor lane, L4
  mini-supervisor, L5 top supervisor, L6 super top ([docs/architecture.md](docs/architecture.md#levels)). A
  `[supervisors]` entry carries a `level` (the integer 4, 5 or 6) where it carried a `role`:
  - `role = "mini"` and `role = "top"` are the old spelling, still read as 4 and 5. An entry holds exactly one of
    the two keys (both, or neither, is refused); any other level is refused with a message that names the `level` key
    and the three levels, and 3 is explained as a lane, which is not a `[supervisors]` entry. After loading, an
    entry has a `level` and no `role` (`config show`).
  - A project's `landing_authority` must name a supervisor of level 5 or 6 (it was: role `top`).
  - `laneboss start --role NAME` prints `- Level: L5 (top supervisor)` where it printed `- Kind: top`, and the
    `role.entry` of its json form has `level` and `level_name` where it had `role`. A role stays the name of the
    `[supervisors]` entry, chosen with `--role`.
  - `examples/minimal` uses `level = 5`. The launcher names the levels and enforces only the landing authority's
    level; what a level may decide is an organisation's own rule, written in its rules files.
- The launcher is version 0.6.0-dev4 (it was 0.5.0; each installed build of this work gets the next `-devN`, because
  an installed version is never replaced), so that an installed copy of this code is never mistaken for 0.5.0; 0.5.0's installer and store grammar accept that string, and the plugin's `version` is the package's. What
  0.5.0 cannot read of what this version writes, each a trigger of its own (checked against 919af68):
  - **The configuration.** 0.5.0's runner table has no `prompt` and no `stream` key, its placeholder lists lack `session`
    and its table of top-level keys has no `turns`, so it refuses a configuration in which a runner has `prompt` or
    `stream` or uses `{session}` (in `command`, `resume` or a `records` path), or that has the table `[turns]`, when the
    configuration loads (exit 2, an unknown key that names the key path, for example `runners.NAME.stream`): every 0.5.0
    command bound to it fails at load (`doctor` reports its `config` check failed), even before any run has used those
    keys.
  - **A `lane.ended` with `prompt`** (a runner with `prompt = "stdin"`, with or without `{session}`). 0.5.0's
    `lanes.check` accepts exactly the earlier keys, and its form-checked reads of a lane's `lane.ended` events fail
    with exit 3 and a message that blames an earlier version. Refused: `state verify` and `state rebuild` for the
    whole store, `doctor` (its `store.recorded` check) and the session briefing with it, `lane refusals` without
    `--lane`; and on that lane `lane refusals --lane`, `lane scan`, `lane mark --gone`, `lane mark --state
    accepted|merged` when the configuration has guards, and `lane stop` of a run that is going on (it has signalled the
    run when it refuses). Still working: `lane status` and `lane check` (they read no `lane.ended`), `lane resume`,
    `lane clean` and `lane start --reuse` (they read `lane.ended` only when a run record is missing), `lane review`,
    the other `lane mark` decisions, `state events`, `event tail` and `state lanes`.
  - **A `lane.started` with `session_id`** (a runner whose `command` uses `{session}`). Everything the `prompt`
    trigger refuses, and also `lane status` without `--lane` (and with `--lane` on that lane), and on that lane `lane
    resume`, `lane clean`, `lane start --reuse` and `lane stop` (before it signals the run), and `lane check` (for every
    lane) while a run of that lane is going on, because they all read its `lane.started`. Still working: `lane review`, `lane mark --state
    verifying|abandoned` and `--landing`, `lane mark --state accepted|merged` when the configuration has no guards,
    `lane status --lane` of another lane, `state events`, `event tail` and `state lanes`.
  - **The keys `mail` and `idle_seconds` of a `lane.started`** (a lane started with `lane start --turns` has them from its
    first run on, and has `session_id` and `prompt` as well, so the two triggers above hold for it). 0.5.0's `lanes.check`
    accepts exactly the keys it lists: `event append` of such a `lane.started` is refused (exit 2), and `state verify` and
    `state rebuild` fail on it with exit 3 for the whole store, with `doctor` and the briefing. The commands that the
    `session_id` trigger names refuse on that lane too.
  - **The kinds `lane.mailed`, `lane.delivered` and `lane.returned`.** 0.5.0's `lanes.check` refuses a `lane.` kind that is
    not in its list: `event append` of one is refused (exit 2), and `state verify` and `state rebuild` fail with exit 3 for
    the whole store, with `doctor` and the briefing. `event tail` and `state events` still print them, and no 0.5.0 lane
    command reads a lane event of a kind it does not list, so by themselves these kinds refuse nothing more.
  - **The row field `mail`** (a lane started with `--turns` has it from its first run on; its state `waiting` adds
    nothing, because 0.5.0 does not check the value of a row's state). 0.5.0's `current_form` accepts exactly the earlier
    fields, so every read of such a row fails with exit 3 and the advice to run `state rebuild`, which fails too. Refused for
    every lane: `state lanes`, `lane status` (with or without `--lane`), `lane check`, `lane refusals` without `--lane` and
    `lane start`; refused on that lane: every command that takes it (`lane resume`, `stop`, `mark` with any decision,
    `clean`, `scan`, `review` and `refusals --lane`), and `event append` of a lane event of it. Still working: the commands
    that take another lane whose row has no `mail` (unless it has a trigger above), `state events`, `event tail`, `event
    append` of events that are not lane events, and `brief render`.

  So a relink back to 0.5.0 needs the configuration edited as soon as a runner has `prompt` or `stream` or uses
  `{session}`, or the configuration has `[turns]`, and fails for a store once a run has used any of these keys or kinds,
  a lane started with `--turns` among them; two launchers of different versions must not share a configuration from the
  moment it has such a runner or `[turns]`. The key `stream` touches the configuration only: it is read by `lane attach`
  and writes nothing to the store, so a runner that has `stream` and neither `prompt` nor `{session}` leaves a store that
  0.5.0 reads. Nothing else this version writes is refused by 0.5.0: a lane whose runner uses neither writes the
  `lane.started` and `lane.ended` that 0.5.0 wrote, the version it puts into `brief.rendered` and into every event (1.2.0)
  is one that 0.5.0's grammar accepts, the message files and the lock of `lanes/LANE/` are never read by it, and the new
  reason `no-session` fits 0.5.0's grammar of the `not_covered` of a `lane.state`. Each statement was read from the code of
  0.5.0 (919af68); `docs/architecture.md` ("Rolling back to 0.5.0 across the changes of this design") gives the procedure
  that runs them.

### Not built yet

Telling the owner about refusals, a judge that reads suspicions, the record formats of other agent programs, the judge
that picks a difficulty, account choice by remaining quota, messages to a running executor, test machines, owner
messages, cost accounting, the network service in front of the event store, and binding `laneboss decisions` to a
configuration (`docs/architecture.md`, "Left for later lanes").

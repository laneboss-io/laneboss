# Laneboss with Claudock

Claudock keeps several accounts of the agent program as profiles and runs the agent program for one of them:
`claudock run PROFILE -- ARGUMENTS` starts it under the account that PROFILE names and passes ARGUMENTS on to it.
Laneboss does not need Claudock, and nothing in the launcher imports anything of it. The two meet in a
configuration: a runner names the wrapper program and the accounts a lane may use, and the lane's account fills
`{account}` in the runner's command. This is one runner for two invented accounts, `work` and `spare`; every key of
it is described in `docs/configuration.md`, under `[runners.<name>]`.

```toml
[runners.claudock]
command = ["/Applications/Claudock.app/Contents/MacOS/claudock", "run", "{account}", "--", "-p",
           "Read the file {brief} completely and carry out the task it describes.", "--model", "{model}"]
resume = ["/Applications/Claudock.app/Contents/MacOS/claudock", "run", "{account}", "--", "-p", "-c",
          "Read the file {message} completely and carry on from it."]
accounts = ["work", "spare"]
```

A runner is started without a shell, so the first element of `command` is the program's own path. `{brief}` is
required, because the launcher always hands a brief over as a file; `{message}` is the file of a follow-up message
for `lane resume`. How a session is continued is the runner's business: here `-c` asks the agent program to
continue its newest session of the lane's working directory. A lane uses the account given with `--account`, else
the first account of the list that the project does not exclude, and `{model}` is filled from `--model` or from the
routing entry that `lane start` picks.

## Profile swap

`integrations/claudock/profile_swap.py` chooses remaining quota and resumes the same Claude Code session
on another Claudock profile. It uses Python 3.11 and the standard library only, imports nothing from
Laneboss, and stores no profile names, account details, credentials, settings, or session history.
It finds `claudock` on PATH first, then the executable at the macOS app path shown above. `limited` and
every `--help` work without Claudock. This integration does not change the launcher's account routing.

### Choose a profile

```sh
python3 integrations/claudock/profile_swap.py pick \
    --settings FILE --exclude NAME --max-used 85 --max-age 30
```

Every option here is optional; repeat `--exclude NAME` for more exclusions. The tool calls `claudock usage`
and reads its TSV header, `PROFILE PLAN WINDOW USED_PERCENT RESETS_UTC` (tabs between columns). With
`--max-age S` it calls `claudock usage --max-age S`; S must be finite and nonnegative. Without it, Claudock's
own cache policy applies. An exit-0 cached reading during Claudock's cooldown is usable. A nonzero usage
exit, invalid header/row, nonfinite or negative usage, or invalid reset timestamp exits 2; partial data from
a failed command is never used. Conflicting PLAN values for the same profile also exit 2. The usage request
has a 60-second timeout. Vendor error output is not echoed, because it can contain account data.

The tool groups all windows of each profile. A window whose reset time has passed counts as 0% used;
other windows retain their reported usage. Unknown resets (`unknown`, empty, `-`, or `—`) are valid and
retain their reported usage too; they never make a window count as empty or invent a reset timestamp.
Timestamps must have a time zone and are normalized to UTC. The profile's **tightest window** is its largest
effective usage percentage. Every excluded profile is removed, then every profile at or above the threshold
is removed. PCT must be finite and between 0 and 100 inclusive; 0 admits no profile. The default is 85.

**Console API profiles bill per token** and are excluded by default in both `pick` and `resume`. Opt in
with `--include-console` or the TOML setting `include_console = true`. This controls billing eligibility,
not the threshold: Console profiles must still be strictly below `--max-used` and satisfy all exclusions.
With opt-in, qualifying subscriptions rank first, then Console profiles. Within the subscription group,
the lowest tightest-window usage wins. Console profiles follow by their share of credit left, calculated
as `100 - USED_PERCENT`, as Claudock's available-profile ordering does; absolute dollar balances do not
determine the order. Equal usage within the same group follows the settings'
ordered `prefer` list, then the profile name in case-sensitive lexical order, independent of TSV order.
Preference never overrides subscription priority, headroom or exclusions. The billing category comes from
the vendor's `Console API` PLAN value. Subscription plan/window labels are not restricted to the examples;
credit-window wording is not parsed to recover a balance. Success prints exactly one profile name on stdout.
Names may contain spaces or Unicode but must be nonempty, contain no control characters, and not start
with `-`; they are passed as individual arguments without a shell.

With no qualifying profile, stdout is empty and exit 3 prints one line on stderr:

```text
no profile under N%: next to free up is X at T
```

For each blocked profile, T is the **last reset among its windows at or above N%**: an earlier reset alone
cannot make it usable. The earliest such profile-wide reset wins, assuming no further usage. Excluded
profiles cannot appear in this estimate. An unknown blocking reset gives `unknown` rather than an invented
time; known estimates sort ahead of unknown ones. Equal estimates follow subscription priority, usage,
preference and name.
No eligible profiles gives `none at unknown (no eligible profiles)`. A zero threshold gives an unknown
estimate because even empty windows cannot be strictly below 0%.
When Console profiles were left out by the default billing rule, the same line appends
`Console API profiles excluded: COUNT (per-token billing; opt in with --include-console or include_console = true)`.
Explicitly excluded profiles and `--from` remain excluded even with billing opt-in. An opted-in Console
credit row with reset `-` has no predictable reset time; the supervisor must re-check credit availability.

### User settings

Pass your own TOML file with `--settings FILE`; there is no implicit settings path. Relative paths are
read from the caller's current directory, before `--cwd` takes effect. The only shipped file is the
[invented example](../examples/claudock/profile-swap.toml):

```toml
exclude = ["orchard-resting"]
max_used_percent = 85
include_console = false
prefer = ["orchard-primary", "orchard-spare"]
```

All four keys are optional. `exclude` is an array of names never to use; CLI exclusions are added to it.
`max_used_percent` is a finite number from 0 to 100, overridden by `--max-used`. `prefer` is an ordered
array used only for ties. `include_console` must be a TOML boolean and defaults to false. True opts in to
per-token Console API billing; `--include-console` also enables it when settings say false. Unknown keys,
wrong types (including a numeric or string Console boolean), invalid names, repeated names within either list,
unreadable files and invalid TOML exit 2 before usage is queried. Store real settings outside the public
checkout, and never add credentials to them.

### Resume the same session

```sh
python3 integrations/claudock/profile_swap.py resume --session ID --from NAME \
    --cwd DIR --settings FILE --exclude NAME --max-used 85 --max-age 30 --prompt TEXT -- CLAUDE_ARGS
python3 integrations/claudock/profile_swap.py resume --continue --from NAME --cwd DIR --dry-run
```

Exactly one of `--session ID` and `--continue` is required; `--from NAME` is required and is always excluded,
even if its usage reading says it has the most room. Repeated `--exclude`, `--settings`, `--max-used`,
`--max-age S`, and `--include-console` work as for `pick`. Without `--max-age`, `resume` uses Claudock's
default usage-cache policy. The session directory defaults to the current directory and must exist.
`--continue` resumes its newest session and needs **one session
per directory**. When several sessions share a directory, keep the explicit id and use `--session ID`.

The selected profile and tightest-window percentage are announced on stderr with the reason: most room
left among subscriptions, or Console API opt-in and the credit share left. The actual argument arrays are
these, with PROMPT as one argument:

```text
claudock run PICKED -- -p --resume ID PROMPT CLAUDE_ARGS...
claudock run PICKED -- -p -c PROMPT CLAUDE_ARGS...
```

PROMPT defaults to `Continue the same session from where it stopped.`; `--prompt TEXT` replaces it.
Everything after the explicit `--` is forwarded unchanged to Claude Code. Put tool options before that
boundary. The tool changes to DIR and replaces itself with Claudock, preserving the child's output,
exit status and signals. `--dry-run` still reads usage to make a real selection, then prints a JSON object
with the exact `argv` array and absolute `cwd`; it never invokes `claudock run`. Quoting in that JSON is
data, not a command to feed to a shell.

**History condition:** Claudock profiles must share the same Claude Code session history. This operation
resumes existing history; it does not copy a conversation, start a replacement session, or reconstruct
missing history. Retain the session id and its original working directory throughout the swap.

**Cross-provider condition:** Claudock refuses to resume history in which another model provider has
replied unless its own `--allow-cross-provider-resume` flag is passed before `--`. The tool never adds
that flag and has no option to enable it. A refusal remains Claudock's refusal, with its exit code passed
through. Do not bypass that rule as part of automatic quota rotation.

### Supervisor loop

1. Select a profile with `pick`, then run Claude Code through `claudock run PROFILE -- -p ...` in the session
   directory. Save the profile, directory and Claude Code session id; for a new session, `--session-id ID`
   can establish the id in advance. Capture stdout and stderr in a new log for each run and preserve its
   exit code. Keep the original task and continuation context available.
2. After the run ends, call `limited LOG`, including when Claude exited 0. If it exits 0, classify the run
   as a usage/session-limit pause. **Never count this as a task failure or spend a retry.** Call `resume`
   with the saved id and directory, and `--from` set to the profile just used. Keep the same model and
   other intended Claude arguments after `--`, and supply the continuation prompt when needed.
3. Record the profile announced by `resume` as the source for the next swap. Check the resumed run's new
   log the same way and repeat when limited. If selection exits 3, wait for the estimated reset and re-check
   quota; a capacity wait is still not a task failure. Prevent overlapping runs of the same session.
4. If `limited` exits 1, apply the usual completion/error checks to the saved run result. If it exits 2,
   stop classification and repair the unreadable log. A cross-provider refusal or another operational
   error must be handled as that error; do not rotate indefinitely or start a fresh session to hide it.

Selection is a quota snapshot, not a reservation; another run can spend the chosen profile's room before
the resumed request starts. Supervisors should coordinate concurrent work and repeated swaps. This tool
performs one selection/resume at a time, leaving scheduling and waiting to the supervisor.

### Limit-message patterns and their sources

`limited LOG` reads a UTF-8 `claude -p` log. It removes ANSI SGR color codes, trims line-edge whitespace,
and requires a whole-line message match. It also reads one-line JSON/JSONL error records: `result` or
`errors` strings in a `type=result, is_error=true` record, and text blocks in an assistant record marked
`error=rate_limit`. It does not search arbitrary JSON values, user prompts, tool arguments or successful
result records. No Claudock command is called.

The two patterns below are based on Claude Code's own messages, inspected in the official native
distribution **2.1.296**, including its embedded source and documentation. The inspection read static
bytes only; no Claude or Claudock session was run. The source locators identify the message builders
in that version so the wording can be checked without a user's log or credentials.

| Pattern family | Accepted message body and suffix | Source in Claude Code 2.1.296 |
|---|---|---|
| Quota hit | `You've hit your LABEL`, where LABEL is `limit`, `usage limit`, `session limit`, `weekly limit`, `Opus limit` or `Sonnet limit`. A straight or curly apostrophe is accepted. Optional suffix: `.` or `!`, or ` · resets TIME` / ` · limit resets TIME`; optional final ` · progress saved`. | Embedded documentation explicitly says the client composes its own `You've hit your limit` line. The quota formatter `at(e,r,n,s)` returns the template `You've hit your ${e}${r}${h}`; `Xw` uses the `aoe` window labels (`five_hour` → `session limit`, `seven_day` → `weekly limit`, and the Opus/Sonnet windows). The general quota paths pass `limit` or `usage limit` to the same formatter. |
| Usage reached | `Usage limit reached`, optionally followed by ` · limit resets TIME`. | The reset/wait message builder declares `Te = "Usage limit reached"`; `SMr(a)` returns either Te or the template `${Te} · limit resets ${s}`. |

Both regular expressions are used with `fullmatch`; TIME must be nonempty and on the same line. The
first pattern's body is `You['’]ve hit your (?:limit|usage limit|session limit|weekly limit|Opus limit|Sonnet limit)`;
the second is `Usage limit reached(?: · limit resets [^\r\n]+)?`. The suffix rules in the table describe the
rest of the first regex exactly. The public [Claude Code repository](https://github.com/anthropics/claude-code)
is the upstream product reference; the versioned distributed formatter is the source of these strings.

Examples such as `Set the session limit to 5`, `No usage limit reached during this run`, a quoted message
inside a user/tool record, a fast-mode limit, a context-window error, `max turns reached`, and the grace-window
checkpoint notice do not match. These are not evidence that the profile needs to be swapped. New Claude Code
wording needs a sourced pattern and a positive/near-miss row before being added; unrecognized wording returns 1.

### Exit codes and verification

| Command or phase | Exit | Meaning |
|---|---|---|
| `pick` | `0` | Exactly one selected profile name on stdout. |
| `pick`, `resume` before launch | `3` | No profile under the policy; one next-reset line on stderr, no Claude run. |
| `pick`, `resume` before launch | `2` | Invalid arguments/settings/directory, missing executable, usage error/timeout/malformed TSV, or inability to start Claudock. |
| `resume --dry-run` | `0` | Selection succeeded; exact argv and directory printed as JSON; Claude was not started. |
| `resume` after launch | Child status | The exact Claudock/Claude status, including cross-provider refusal and signals. A child may itself return 2 or 3, so use the launch diagnostic and log to distinguish phases. |
| `limited` | `0` | At least one recognized usage/session-limit message in the readable log. |
| `limited` | `1` | Readable log, no recognized limit message; this does not establish that the run succeeded. |
| `limited` | `2` | Log cannot be read, including missing files, directories, denied permissions and invalid UTF-8; invalid CLI arguments also exit 2. |
| Every `--help` | `0` | Help printed; Claudock was not invoked. |
| Local Ctrl-C before launch | `130` | Interrupted selection or log read. Once resumed, the child retains its own signal behavior. |

The independent tests are [test_profile_swap.py](../tests/e2e/test_profile_swap.py), with the real-shaped
[usage fixture](../tests/e2e/fixtures/claudock-usage.tsv). The fixture follows the reported real column shapes:
`Max 99×` and `Team Premium` subscriptions, `9-hour session`, `Weekly · all models`, `Weekly · Fable`,
two-decimal USED_PERCENT values, valid UTC timestamps and literal `unknown`; a `Console API` row has a
`Credit · $97.50 of $100.00 left` window and reset `-`. The anonymized digits are replaced with valid
invented times and percentages. Profile names are invented and renamed per test. Additional rows change
the numeric values, multiplier and session-window label to detect a parser keyed on fixture literals.
The tests run the actual Python CLI as a subprocess, with a temporary `claudock` executable on PATH that
prints per-row TSV and
records every argv and working directory. Names are invented and varied at runtime; the tool has no test
name literals. No network, real Claudock, or Claude request is needed. Run on a disposable box as an
unprivileged user so the unreadable-file row enforces file permissions:

```sh
python3 -m unittest tests.e2e.test_profile_swap -v
```

For regression RED, keep the revised tests and fixture with the previous tool; GREEN also includes the
revised tool. Omitting `integrations/claudock/profile_swap.py` still checks the original feature-missing
RED tree. Each row's docstring states what makes it fail. The suite also checks this explicit mutant
list, first requiring its named row to pass on the original tool, then requiring a behavior assertion
failure on a private mutated CLI copy (a setup error does not count):

| Mutant | Named failing row | Defect the assertion catches |
|---|---|---|
| `threshold_off_by_one` | `test_pick_threshold_is_strict` | Accepting 85% with `<=` instead of rejecting equality. |
| `from_not_excluded` | `test_resume_excludes_from` | Selecting the source profile again when it reports the most room. |
| `cross_provider_flag_added` | `test_resume_no_cross_provider_flag` | Adding Claudock's cross-provider override before `--`. |
| `unknown_reset_rejected` | `test_pick_real_shape_unknown` | Rejecting the literal `unknown` in the real-shaped fixture instead of accepting the reading. |
| `console_without_opt_in` | `test_pick_console_requires_opt_in` | Choosing a Console profile without explicit billing opt-in after subscriptions are excluded. |

Only the authorized compile/help checks have run on the editing machine for this addition:

```sh
python3 tests/e2e/test_profile_swap.py --static-checks
```

That mode compiles the tool, the test file and the stub, then calls root, `pick`, `resume`, and `limited`
help through the stub PATH, checking the documented flags and that Claudock is never invoked. Behavioral
RED/GREEN runs and mutant outcomes remain for the disposable-box run; live cross-profile resumption has
not been verified by these static checks.

## `cos`, an interactive front for accounts that take only headless requests

Some accounts' credit can be used only by headless requests (one request, one answer), not by an interactive
session. `cos` is a small terminal front for them: you type a message, it sends one headless request through the
wrapper, shows the answer as the agent produces it, and keeps the conversation going with a session id. An account
that allows an interactive session does not need it. `cos` is one file, `integrations/claudock/cos.py`, that uses
only the Python standard library. Nothing in the launcher imports it and it imports nothing of the launcher. It
writes no files (no history, no configuration, no log) and has no network code of its own.

### Start it

```sh
python3 integrations/claudock/cos.py ACCOUNT [MODEL] [--resume SESSION] [--mode default|acceptEdits|plan] [--bypass-permissions]
```

- ACCOUNT is the name of a Claudock profile. ACCOUNT and MODEL must match `[A-Za-z0-9][A-Za-z0-9._:\[\]-]*` as a
  whole word, and SESSION must be a UUID. Anything else prints a usage line on standard error and exits with 2;
  `-h` prints the help and exits 0.
- MODEL defaults to the environment variable `COS_MODEL`, else `claude-sonnet-5-5`.
- The wrapper is `/Applications/Claudock.app/Contents/MacOS/claudock`, or the program named by `COS_CLAUDOCK`. When
  it is missing or not executable, `cos` prints one line on standard error and exits with 2, before any prompt:
  `cos: the account wrapper was not found at WRAPPER: Claudock is required (set COS_CLAUDOCK to its claudock program)`.
- Each message is one request: `WRAPPER run ACCOUNT -- -p --session-id|--resume SESSION --model MODEL --output-format
  stream-json --verbose --include-partial-messages`, with `--permission-mode MODE` added when a mode was chosen. The
  message goes to the request's standard input and never into an argument. The first request of a new session uses
  `--session-id`; once a request has shown the session's `init` line (or you started with `--resume`), every later
  request uses `--resume`.

### What you see

- The answer appears as the agent produces it. Each tool the agent uses is one line, `  [tool NAME]` and the first
  100 characters of its command, path or pattern. A tool that was refused is listed as `  [denied NAME] ...` after
  the turn, with a one-time hint that points to `/mode`.
- After every turn: `[turn N | this turn $X | session $Y | S s]`. Y is the session's total cost so far as the agent
  reports it, so it also covers the turns of earlier runs. X is Y minus the previous Y, which is the cost of this
  request. S is how many seconds the request took, and N counts the requests of this run. When you start with
  `--resume`, the first X is `?` because the earlier total is not known, and so is any figure the agent did not
  report.
- `[turn N | no result | exit E]` means the request ended without a result line: the wrapper failed or was killed. A
  request that you interrupt has no result line either, so its cost is not shown, and the next session total may not
  include what it had already used.
- Colour is used only when standard output is a terminal, and only as dim grey for the bracket lines.

### The permission default

If you choose no mode, `cos` passes no permission option, so the account's own settings apply, and those may be to
bypass approvals: the agent then runs any command and changes any file without asking. Passing no option is not the
same as `--mode default`. `cos` says so before you type anything, in two plain lines after its first line:

```text
permission mode: the account's own default (not chosen here). On this Mac that is usually bypassPermissions:
the agent may then run any command and change any file. To narrow it: --mode default|acceptEdits|plan, or /mode.
```

The agent states its permission mode at the start of every request, and `cos` prints this line, not dimmed, as soon as
that mode is `bypassPermissions` and `cos` was not told to bypass:

```text
WARNING: approvals are bypassed: the agent may run any command and change any file it can reach.
```

If you chose a mode and the agent reports bypass anyway, `cos` prints one more line before that one, `WARNING: the agent
reports bypassPermissions although --mode X was passed.` Each pair of reported and chosen mode warns once per run. When
you chose none and the agent reports a mode that is neither `default` nor bypass, `cos` prints
`  [account default permission mode: NAME]` once instead.

To narrow the default, start with `--mode default`, `--mode acceptEdits` or `--mode plan`, or type `/mode NAME` at any
time; `cos` then passes `--permission-mode NAME` on every request. As the agent program defines them, `default` denies
a tool that needs approval, because nobody can approve in a headless request; `acceptEdits` accepts file edits and
denies other tools that need approval; `plan` only plans and reads. `--bypass-permissions` passes `--permission-mode
bypassPermissions`, prints the WARNING line at the start and after every `/mode` while the mode is still bypass, and
cannot be combined with `--mode`. Bypass cannot be chosen with `/mode`. `/mode` alone shows the mode in force. When
none was chosen it says `mode: none passed (the account's own default applies)`, and once the agent has reported a mode
it adds `: MODE` with the mode it last reported.

A typed message cannot change the permission option that `cos` passes; only the start options and `/mode` do. Under
bypass, or under an account default that bypasses, the agent can still be asked in a message to change settings or
files.

### Coming back

`/exit` or Ctrl-D leaves, and prints `session ID  (continue later with: --resume ID)` when a session exists and `no
session was started` when none does. To come back, run it from the directory the session was started in:

```sh
python3 integrations/claudock/cos.py ACCOUNT MODEL --resume SESSION
```

A request that is stopped in its first moment can leave `cos` unsure whether the session exists. If the next request
fails, leave and start again, with `--resume` when the session line was shown.

### Stopping a request

Press Ctrl-C once while a request runs, and wait. If anything of the request is still running, `cos` first prints
`[stopping the request: wait a few seconds, do not press Ctrl-C again]`. Then it signals the request's whole process
group: an interrupt, with up to 6 seconds to end; then terminate, with up to 4 more; then kill, with up to 2 more.
Before the kill it lists the processes (see below), which takes up to 2 seconds more, and after the last wait it looks
once more for half a second before it reports what is left. A further Ctrl-C does not leave early, it only moves on to
the next step. Then `cos` prints `[interrupted]` and returns to the prompt, and the session goes on. A Ctrl-C that
arrives after the request has ended prints nothing and stops nothing. Ctrl-C at the prompt only prints a reminder.

A closed terminal window (a hangup) or a `kill` of `cos` ends the running request the same way before `cos` ends,
with the exit status 128 plus the signal number. If some process of the request may still run afterwards, one line,
`WARNING: processes of this request may still be running (group PID)`, names every group that still answers.

The agent's shell tools run in process groups of their own, which signals to the request's group never reach. They
end because the agent stops its own tools when it is interrupted or terminated, and a kill gives it no chance. So at
the kill step only, `cos` lists the processes with `ps -axo pid=,ppid=,pgid=`. It runs `/bin/ps` or `/usr/bin/ps`, the
first of them that exists and is executable, and never looks `ps` up through `PATH`; it uses no shell, gives `ps` a
session of its own so that a Ctrl-C at the terminal cannot kill it, and waits 2 seconds at most. The walk starts at the
request's process and at every process of its group, so an agent whose wrapper has already exited is still found with
its tools. It follows the descendants by parent process id, and after killing the request's group `cos` kills every
other group that one of those descendants leads (never group 0 or 1, and never its own group). When the listing fails
(no `ps` at either path, an error, a time-out or no usable output), `cos` prints the plain line `[could not list the
request's processes: some of its tools may still run]` and goes on with the request's own group. The sweep does not
reach a tool whose parent ended before the listing, and nothing can help when `cos` itself gets `kill -9`.

### Local commands

`cos` handles these lines itself, and they cost nothing:

| Line | Effect |
|---|---|
| `/exit` | Leave; the session can be resumed later. |
| `/help` | List these commands. |
| `/cost` | The session's total cost so far and the number of requests of this run. |
| `/session` | The session id and how to resume it. |
| `/model NAME` | Use another model from the next request (the same name rule as at the start); a bare `/model` shows it. |
| `/mode [NAME]` | Show the permission mode, or set `default`, `acceptEdits` or `plan`. |

`/exit`, `/help`, `/cost` and `/session` are commands only when they stand alone on the line; `/exit now` goes to the
agent. `/model` and `/mode` are always handled by `cos`, and a wrong argument prints a usage line instead of going to
the agent. Every other line, also one that starts with a slash, such as `/compact`, goes to the agent as a message and
is one paid request. A line that ends with a backslash continues on the next line; the prompt for it is `. `.

### Limits and what is not proven

- Every message is one paid request, and the agent reads the whole session again each time. There is no spending
  limit.
- An interrupted request shows no cost, and the next session total may not include what that request had already used.
- The agent keeps its normal memory and runs its normal hooks and plugins on every request, so its notes about the
  directory you start `cos` in persist like those of any other session there. Start it in a directory you mean.
- Resuming a session under another account is untested: the checks used one account.
- `acceptEdits` and `--bypass-permissions` were checked only on the argument list that a stand-in wrapper received,
  with no real request. `--mode plan` has run for one real turn only: the agent answered, `/mode` showed `mode: plan`
  and no bypass warning was printed.
- The tests (`tests/e2e/test_cos.py`) use a stand-in wrapper that they write themselves and make no real request.
  The kill sweep that ends the agent's shell tools, the failed listing and the late Ctrl-C were tested with
  stand-ins, not with a real shell tool.

### Put it on the path

From the root of a checkout, one link puts `cos` on the path (`~/.local/bin` is where `scripts/install.sh` links
`laneboss`):

```sh
ln -s "$PWD/integrations/claudock/cos.py" "$HOME/.local/bin/cos"
```

`cos ACCOUNT` then starts it. Its usage line still says `cos.py`.

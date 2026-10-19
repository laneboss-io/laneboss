# The Claude Code plugin

`/laneboss` starts a supervised session from Claude Code. The plugin has one command and does one thing: it gets
the briefing of `laneboss start` for the configuration and the role the person typed, and hands it to the session.
What `laneboss start` prints is documented where it is written; this page covers the plugin, how it is installed
with the launcher and how a person adds it to Claude Code.

Nothing here installs anything into Claude Code. `scripts/install.sh` puts the plugin's files next to the launcher,
`laneboss plugin path` says where they are, and the person adds the plugin with Claude Code's own commands (the
steps below).

## What ships

```text
plugins/claude-code/
    .claude-plugin/plugin.json     the manifest: name laneboss, the package's version
    skills/laneboss/SKILL.md       the one command
    skills/laneboss/start.sh       the shell program the command runs (mode 755)
```

`scripts/install.sh` copies the checkout's `plugins/` directory into the installed version directory, as `plugins/`
there, and lists every file in that version's `MANIFEST` with the package's own files. Every later install of the
same version checks the installed files against the checkout like the rest: a plugin file that differs in the
checkout, or was changed, removed or added in the installed copy, is refused, so an installed version never changes.
The manifest holds each file's hash and path. The manifest does not record modes, so the installer applies the rule
below about modes itself on every run. The Go binary must also remain mode 755; directory modes are not checked:

- A plugin file with any executable bit in the checkout is a program and is installed with mode exactly 755. Today
  only `start.sh` is a program. A program's mode in the checkout is normalised: any mode with an executable bit for
  the owner, the group or others (700, 744, 755, 775) installs as 755. A tree unpacked from a `git archive` holds 775
  for it, for instance.
- Every other plugin file must have no executable bit in the installed copy; its read and write bits are not checked.
  The installer sets no mode of an installed file after the first install, and changes none.
- A later install of the same version checks the installed copy against this rule as it checks the hashes: a program
  whose installed mode is not exactly 755 (644, 744, 775, 700), or another file that has an executable bit, is
  refused like a changed file, with exit status 2, the version and the file named, and nothing changed. The checkout
  counts the same way: a file that gained an executable bit there is a program, so an installed copy of it that is not
  755 is refused, and a program that lost its executable bit there is another file, so its installed 755 is refused.

A version that is already installed without the plugin refuses an install that has it until the version number
changes. A checkout without `plugins/` still installs; `laneboss plugin path` then refuses and says so.

`laneboss plugin path [--agent AGENT]` prints the directory of the installed plugin for that agent program as one
JSON value (a string) and changes nothing. The only known agent is `claude-code`, which is also the default. An
unknown agent exits 2, says that the agent is unknown and names the known ones; it never repeats the value it was
given, because a variable that holds the wrong thing could hold a secret. A binary built into a checkout's `bin/`
finds that checkout's `plugins/`; a binary elsewhere can use an absolute `LANEBOSS_PLUGIN_ROOT`.
The plugin's version in `plugin.json` is the release version, so update the manifest together with
`internal/identity/identity.go`.

## The documentation this was written from

Read on 2026-10-09, in this order. The format is taken from these pages and not from memory. The skills page was
read again on 2026-10-09 for the directory variable and the permission rule of a bundled script.

- Plugin manifest reference: https://code.claude.com/docs/en/plugins/manifest-reference (the older plugins
  reference address now serves this page)
- Extend Claude with skills: https://code.claude.com/docs/en/skills (the older slash commands address now serves
  this page)
- Add components to a plugin: https://code.claude.com/docs/en/plugins/components
- Create a Claude Code plugin: https://code.claude.com/docs/en/plugins/create
- Create a marketplace: https://code.claude.com/docs/en/plugins/create-marketplace
- Install and manage plugins: https://code.claude.com/docs/en/plugins/install
- Publish and distribute a plugin: https://code.claude.com/docs/en/plugins/publish
- Plugin commands reference: https://code.claude.com/docs/en/plugins/cli-reference
- Configure permissions: https://code.claude.com/docs/en/permissions

What the pages say, and what the plugin does with it:

- The manifest is `.claude-plugin/plugin.json` at the plugin root. `name` is its only required key; `version`,
  `description` and `author` (with a `name`) are the metadata `claude plugin validate` warns about when missing, so the
  manifest sets all four and nothing else. An unknown top-level key is stripped without a word. Only `plugin.json`
  goes inside `.claude-plugin/`; components saved there do not load.
- Custom commands have been merged into skills. A file under `commands/` is "the older format" and the pages say to
  prefer `skills/` for new plugins, so the one command is a skill, `skills/laneboss/SKILL.md`. With `name: laneboss` it
  runs as `/laneboss:laneboss`, and the pages say the bare `/laneboss` also invokes it unless another command
  already uses that name.
- The front matter fields used are `name`, `description`, `argument-hint`, `disable-model-invocation`,
  `allowed-tools` and `shell`. An unknown field is ignored silently, so a test checks every field against the
  documented list. `disable-model-invocation: true` keeps the model from starting a session on its own: only the
  person types `/laneboss`. `shell: bash` makes a machine without bash fail with the documented message instead of
  running a shell script in another shell.
- `$ARGUMENTS` becomes the text as typed. `$0`, `$1` and `$ARGUMENTS[N]` become shell-style words of it. The text is
  inserted as it is, once, and nothing is quoted or escaped for a shell, so it is only ever inserted in the prose
  of the command file (see below). The agent program replaces `$0`, `$1` and the other forms anywhere in the file;
  the file holds none of them for its own use, and the shell program of the plugin is `start.sh`, a file the agent
  program does not rewrite.
- A fenced block that opens with three backticks and an exclamation mark runs before the model sees the text, and
  its output replaces it. With the default bash shell stderr is merged into the output. The page says a non-zero exit
  aborts the whole invocation and shows the command's output; a real session on 2026-10-09 (print mode, permission
  mode default) showed the opposite for a block that failed: the agent program gave the session nothing, no turn, an
  empty result and no error. The plugin therefore makes its script answer instead of fail wherever it can (see below);
  what it cannot prevent is listed under Known limits. A shell block never prompts for permission: Claude Code checks
  it against the permission rules and aborts the invocation unless a rule allows it, and `allowed-tools` pre-approves
  it.
- `${CLAUDE_SKILL_DIR}` is the directory that holds the skill's `SKILL.md` (for a plugin skill, the skill's own
  subdirectory, not the plugin root). The skills page says to use it "in bash injection commands to reference
  scripts or files bundled with the skill", and that Claude Code replaces it in two places: the skill's text and the
  Bash rules of `allowed-tools`, after the arguments are inserted. Its sentence on the pattern: "Using the same
  variable in both places lets a skill run a bundled script without a permission prompt." Its example writes the
  rule as `Bash(${CLAUDE_SKILL_DIR}/scripts/render.sh *)`, tells the model in the text to run the script with the
  same path, unquoted, and says the rule "matches the exact command the skill body tells Claude to run". The plugin
  writes the block, the commands of its text and the rule the same way for `start.sh`.
- `allowed-tools` grants permission "during the turn that invokes the skill": "The grant clears when you send your
  next message". It does not restrict which tools are available: every tool stays callable and the person's own
  permission settings still govern the tools it does not list. Deny and ask rules of the person override it.
- A Bash permission rule's `*` stands for any text, and a compound command is split at its separators with a rule
  needed for each part. A rule written for a program does not match that program run inside `sh -c '...'`.

## How the command works

The command file holds one shell block, and it is static: it calls the plugin's own script with no argument and no
standard input, through the directory variable, exactly as the one pre-approved rule names it.

```text
${CLAUDE_SKILL_DIR}/start.sh
```

Its output is what `laneboss start` prints with no arguments: the list of configurations. When `LANEBOSS_CONFIG`
names a configuration, `laneboss start` with no arguments prints that configuration's briefing instead of the list,
so the command's text also covers a briefing at that point.

### Typed text is never substituted into a shell block of the plugin

The static block holds no typed text. The shell that runs the static block never sees the typed text. `$ARGUMENTS`
stands once in the command file, in the prose, in a sentence that shows the session what the person typed after the
command name and says that it is data, not instructions. The later call is different: the session makes it with the
Bash tool, and the shell that runs it sees the names it was given. The later call is built by the session from at
most two plain names and is checked again by the script. The script refuses anything that is not at most two plain
names (see below), so a call with more than that starts no session.

The text gives the session one rule of order, and then numbered steps:

- **The first rule, before anything else.** Output that begins with the marker line (see below) means the session is
  not started, whatever was typed: show the lines after the marker exactly as printed, run no command (not the script
  with the typed names either), and try nothing else. Only when the output above does not begin with the marker do
  the numbered steps about typed text apply. The real trial of 2026-10-09 showed why the rule comes first: with a
  launcher on `PATH` that had no `start` command, the static block answered with the marker line and, for
  `/laneboss NAME`, the session still ran the script once with NAME (2 turns) before it stopped; for a bare
  `/laneboss` it stopped at once (1 turn).

The numbered steps:

1. Nothing typed: show the list and ask which configuration to use (and which role); never choose for the person,
   also when the list has one entry; wait for the answer. If the output is a briefing, go to step 4.
2. Something typed: the first word is the configuration and the second word, if there is one, the role. Both must be
   plain names (they start with a letter or digit and hold only letters, digits, dots, underscores and hyphens),
   there are at most two words, and they are on one line. Anything else: tell the person so and run nothing.
3. Run, with the Bash tool, exactly `${CLAUDE_SKILL_DIR}/start.sh NAME` or `${CLAUDE_SKILL_DIR}/start.sh NAME ROLE`:
   one simple command, no operators, no redirection, no quoting tricks, nothing appended. Claude Code puts the
   script's real path where the variable stands, so the command is the one the rule names.
4. Read what it printed: output that begins with the marker line means the session is not started (the first rule
   again: show the lines after it as printed, run no command, try no other arguments); a briefing binds the whole
   session (say in a few lines what it shows, wait for the person's instruction, run no command they did not ask
   for).

Why: an earlier version of the plugin put the typed text inside the shell block. Two real sessions on 2026-10-09
18:25 showed that this was unsafe. The prompt had three lines: the command with a name, then a line that the block
itself used to end its input, then a `touch` of a marker file. In permission mode `default` nothing ran at all (the
agent program refused the whole block). In permission mode `bypassPermissions` the marker was created: the typed
text ran as a shell command, with no model turn in between. Any embedding of typed text in a shell block, whatever
its quoting or encoding, has a terminator that the text can write, so the plugin has none. The tests build the
command file as the agent program would for typed text of that shape and for others, and the block does not change
and nothing runs.

### What the script accepts

The script accepts at most two arguments: configuration and optional role. Standard
input is not read. An argument is a plain name: it is not empty, starts with a letter or digit, and holds only
letters, digits, dots, underscores and hyphens. More than two arguments, or an argument that is not a plain name (a
space, a quote, `$`, `;`, `|`, `&`, `<`, `>`, a backtick, a glob character, a backslash, a newline, a leading dash,
an empty argument, a non-ASCII character), is refused, and nothing is run. With no argument it runs
`laneboss start`; with one, `laneboss start --config NAME`; with two,
`laneboss start --config NAME --role ROLE`. The plugin accepts no level or ticket-file argument.
Service registration through the plugin or a shell-tool parent is unsupported. The supported ticket route uses
owner-terminal issuance and direct CLI invocation from a custom dedicated persistent agent process; see
[Human-issued registration tickets](TICKET.md). The plugin preserves the launcher's refusal and its recovery text.
Without a service, role registration retains the open 0.7.0 path and prints the R25-not-enforced notice.
`laneboss` itself applies the exact name grammar afterwards. The program
is searched for as `laneboss` on `PATH`, then as `$HOME/.local/bin/laneboss`, and nowhere else.

### What the script prints, and when it prints nothing

The script exits with exit status 0 in every case except when a signal ends it (the statuses are below), and it
prints something on standard output in every case but two: that one, and a launcher that exits 0 with no output, which
gives an empty answer. The reason is that the agent program shows nothing for a command whose block fails, as a
real session on 2026-10-09 showed: `/laneboss NAME nosuchrole`, where `laneboss start` exited 2, and refused
arguments, where the script exited 2, all gave the session an empty answer, so the one clear sentence was lost. What
it prints:

- When it cannot hand the session a list or a briefing, the first line is exactly `laneboss plugin: NOT STARTED` and
  the reason follows. The reason is one of the script's own sentences (more than two arguments, an argument that is
  not a plain name, the program not found, no temporary directory), on standard output with standard error empty;
  or, when `laneboss start` exits non-zero, the line `laneboss start exited with status N.` and then what the
  launcher printed on standard output and then on standard error, unchanged, all on standard output. The script never
  repeats an argument in its own sentences.
- When `laneboss start` exits 0, its output goes through unchanged, each stream on its own stream, and the marker
  line does not appear. The script adds nothing to it, so a launcher that exits 0 with no output gives an empty
  answer.

A signal ends the script with a status other than 0. The script prints only after the launcher has ended, so a signal
that arrives while the launcher runs leaves nothing printed by the script. The shell that runs the script may print
its own one-line notice of the signal on standard error, such as `Terminated: 15`: the macOS shell does, and the Linux
shell tried (dash) does not. HUP, INT or TERM end it with exit status 1 once its traps are set (just before it runs the
launcher), after the trap has removed its temporary directory. KILL ends it as that signal does (a parent shell reports
128 plus the signal number, 137) and leaves the temporary directory behind; so does a signal the script does not catch,
or one that arrives before its traps are set. Tests pin the statuses, the empty standard output and the directory for
HUP, INT, TERM and KILL sent while the launcher runs, and that standard error is empty or holds only that one-line
notice (for KILL it is empty).

To know the exit status before it prints anything, the script runs `laneboss start` with its output kept in a
temporary directory under `TMPDIR` (or `/tmp`), which it removes when it ends.

## What is pre-approved, for how long, and what the person may be asked

The documentation gives a way to write a permission rule for a file inside the plugin, so the command ships one
`allowed-tools` line and it names only the script:

```text
allowed-tools: Bash(${CLAUDE_SKILL_DIR}/start.sh *)
```

After the variable is replaced the rule matches this script's path followed by anything, which covers the block
(the bare call) and the two commands the text tells the session to run. It does not match `sh -c`, `sh`, `bash` or
any other file, and a test checks that.

- **How long.** For the turn that invokes `/laneboss` and no longer: the grant clears when the person sends the next
  message. When the person has to answer which configuration, the session's call of the script comes in a later turn,
  and Claude Code asks as the person's permission mode says.
- **What the shell block asks.** Nothing. A shell block never prompts: either the rule matches and it runs, or the
  invocation aborts with a message that starts `Shell command permission check failed`. Deny and ask rules in the
  person's own settings override the rule, so a person who denies that path gets that abort. The skills page also
  says that when an organization sets `allowManagedPermissionRulesOnly`, Claude Code ignores `allowed-tools` in project
  and personal skills and in the other sources that setting lists; if the plugin's rule is ignored for that reason,
  the block aborts the same way until a managed rule allows it.
- **What the session may ask later.** Everything else the session runs is not pre-approved: every later `laneboss`
  command, and anything else. Claude Code asks as the person's permission mode says. A person who does not want to be
  asked for `laneboss` commands adds a rule of their own to their settings, for example `Bash(laneboss *)`, and
  `Bash($HOME/.local/bin/laneboss *)` with the home path written out when the program is not on PATH; the plugin ships
  neither.

## Add the plugin to Claude Code

These are the person's steps, with Claude Code's own commands. The launcher and its commands never write into
Claude Code's configuration. First install the launcher from its checkout or archive, which also puts the plugin in
place, and find the plugin:

```sh
sh scripts/install.sh
laneboss plugin path
DIRECTORY=$(laneboss plugin path | jq -r .)
claude plugin validate "$DIRECTORY"
```

`laneboss plugin path` prints the directory in JSON quotation marks; the example uses `jq` to decode it. A clean
`claude plugin validate` ends with `Validation passed`.

**Try it for one session** (nothing is installed or written to Claude Code's settings):

```sh
claude --plugin-dir "$DIRECTORY"
```

In the session type `/laneboss` to be asked which configuration to use, or `/laneboss NAME` or `/laneboss NAME ROLE`
for a briefing. The full name `/laneboss:laneboss` works too. After an edit run `/reload-plugins`.

**Load it in every session, without a marketplace.** The pages say a folder under `~/.claude/skills/` that holds
`.claude-plugin/plugin.json` loads as a plugin in every session. Copy the plugin there, with its modes (`cp -R` keeps
the executable bit of `start.sh` for the copying user); after installing a newer launcher remove the folder and copy
again:

```sh
cp -R "$DIRECTORY" ~/.claude/skills/laneboss
```

**Install it by name through a local marketplace.** A marketplace is a directory with
`.claude-plugin/marketplace.json`; the plugin is copied into it and listed with a path from the marketplace root.
The marketplace is the person's own and is not part of the package:

```sh
mkdir -p ~/laneboss-marketplace/.claude-plugin ~/laneboss-marketplace/plugins
cp -R "$DIRECTORY" ~/laneboss-marketplace/plugins/laneboss
```

Write `~/laneboss-marketplace/.claude-plugin/marketplace.json`:

```json
{
  "name": "laneboss-local",
  "owner": { "name": "laneboss user" },
  "plugins": [
    { "name": "laneboss", "source": "./plugins/laneboss" }
  ]
}
```

```sh
claude plugin validate ~/laneboss-marketplace
claude plugin marketplace add ~/laneboss-marketplace
claude plugin install laneboss@laneboss-local
```

The install is for the person (user scope) unless `--scope project` or `--scope local` is given. In a session,
`/plugin marketplace add ./path` registers a marketplace the same way, and `/plugin install laneboss@laneboss-local`
opens the plugin's details, where the person installs it. `claude plugin marketplace remove laneboss-local` takes it
all away again.

## Not checked by the tests

No agent program was started when the plugin was written, and the tests do not start one. Real trials did start one
(print mode, the plugin loaded with `--plugin-dir` from an install), and what they showed is a result of the day it
was run:

- 2026-10-09, earlier: the agent program inserts `$ARGUMENTS`, the one rule lets the block run without any permission
  question, `start.sh` runs from the installed copy, and a block that exits non-zero gives the session nothing (the
  defects that the answering script and the static block remove).
- 2026-10-09 18:25: two real sessions showed the former design unsafe (see the reason above).
- 2026-10-09 19:12 to 19:33: eighteen real sessions on an install of the redesigned plugin. `/laneboss` listed the
  configurations and asked (1 turn). `/laneboss NAME`, in both spellings, gave the briefing in 2 turns with no
  permission denial in permission mode `default`, and then waited; the session's own run of
  `${CLAUDE_SKILL_DIR}/start.sh NAME` was not denied. An undefined role came back as the
  marker with the launcher's refusal. Two hostile arguments were rejected by the session with nothing run. The
  attacks named under Known limits were rejected in both permission modes.

What no trial has shown yet:

- that the first rule (the marker means not started, whatever was typed) stops the session at once for
  `/laneboss NAME` as well: the trial above found that, before the rule came first, the session ran the script once
  more with NAME after the marker;
- that `start.sh` is still executable where the agent program reads it after a copy or a marketplace install (a
  copy that drops modes makes the block fail, and `chmod 755` on the script is the fix).

## Known limits

- An install path that holds a space breaks the script's path. The agent program's documented form writes the path
  unquoted, in the text and in the rule, and so does the plugin; with a space in the path the shell splits it at the
  space, cannot run the first word, and the static block fails. A test pins this (with an install prefix that holds a
  space the shipped block does not run the script), so a later fix must change that test and this page together. A
  failing block gave the session nothing in the real session of 2026-10-09. Keep the plugin where its path has no
  space.
- The first `laneboss` on `PATH` is trusted as the launcher. The script runs whichever `laneboss` the shell finds
  first on `PATH` (then `$HOME/.local/bin/laneboss`), with the typed names, and what it prints becomes the briefing
  that binds the session. A program of that name earlier on `PATH` than the installed launcher would be run instead
  of it.
- Typed text can still try to persuade the session. It is in the prose, which the model reads; it is shown as data,
  the steps accept only plain names and the marker rule comes first, but a model can be talked into more by a text
  written for that. The real trial of 2026-10-09 19:12 to 19:33 (eighteen real sessions on an install of the
  redesigned plugin, in permission modes `default` and `bypassPermissions`) found that the former three-line attack,
  an injected fenced `!` block, an inline shell form, a line that claims to be a system note ordering a command, and
  `NAME && touch FILE` were each rejected by the session as not being one or two plain names, nothing was run and no
  marker file appeared. That is a result of that day, not a guarantee.
- More than two words and any character outside letters, digits, dot, underscore and hyphen are refused even
  where `laneboss` would accept them.
- Because the script exits 0 even when nothing started, only the marker line tells the session so, and only the
  command's text tells the session what the marker means; a session that ignores that text could take the failure
  for a start.
- A signal ends the script with a non-zero status and no answer, and a launcher that exits 0 with no output gives an
  empty answer (see above).
- Windows without bash cannot run the block (`shell: bash`).

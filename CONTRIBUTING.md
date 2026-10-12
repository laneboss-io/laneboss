# Contributing

Laneboss is pre-release. Changes are welcome; read this page first, because the checks below are not
optional.

## Run the tests on a disposable machine

Run the suite on a machine you can throw away: a virtual machine, a container, or a cloud instance that you
delete afterwards. The tests install the launcher, start many processes, create and remove temporary
directories and provoke permission, disk and file-size failures, so they do not belong on the machine you
edit on. Run them as an unprivileged user: some tests rely on file modes being enforced, and root ignores
them. `git` and `tmux` must be on `PATH`.

```sh
python3 -m unittest discover -s tests                        # every test; Python 3.11 or newer, and a Python 3.9 (below)
python3 -m unittest discover -s tests/decisions -t .         # the decision store alone; Python 3.9 or newer
python3.9 -m unittest discover -s tests/decisions -t .       # the decision store alone, under Python 3.9 as well
LANEBOSS_TEST_PYTHON39=/path/to/python3.9 \
    python3.9 -m unittest tests/e2e/test_judge_jev.py        # the Jev judge adapter's module alone, under Python 3.9
```

The suite needs a second interpreter too: a Python 3.9, named by `LANEBOSS_TEST_PYTHON39=/path/to/python3.9`
(`uv python install 3.9` makes one without root and `uv python find 3.9` prints its path). The adapter's
`test_runs_under_3_9_and_own_python` runs the example under the suite's own Python and under that 3.9, and it fails
when the variable is unset or names an interpreter that is not really Python 3.9: it never skips and it never passes
with its 3.9 leg unchecked, because the example and the decision store are both documented as running on Python 3.9
and a defect that only Python 3.9 shows is only seen when a 3.9 runs them. The variable is therefore required for
the adapter module's own second run too, which names the interpreter, the last line above; the decision store's own
tests have a second run of their own under Python 3.9, the third line above.

The suite takes a few minutes. The tests are black-box: `tests/e2e/` installs the launcher with
`scripts/install.sh` into a temporary prefix and drives the installed `laneboss` command, and
`tests/decisions/` drives the decision store's command line. They use invented data and mock nothing of the
system under test. The stand-ins are these: a local HTTP stub of the third-party embedding service
(decision-store tests); a fake old interpreter that the installer must refuse and an interpreter wrapper whose
`flock` fails on directories, both there to provoke a condition (launcher tests); stub programs on a private `PATH`
for the root `install.sh` (an `id` that says root or says nothing, a `uname` of another system, interpreters that are
too old or that note their use, a `tar` that never finishes, a `mktemp` that records what it made, a `git` and a `curl`
that fail or record their arguments, and programs named like the words of the script, which must never run;
`tests/e2e/test_bootstrap.py`); `tests/e2e/standin.py`, the
runner program of the lane tests, in place of a real agent program and its accounts, which cannot reach a test
machine (it finishes, fails, runs until stopped, stays quiet, prints a limit or a dropped-stream line, writes
into its working directory, leaves a child behind, detaches a double-forked worker, prints a line that makes a slow
pattern backtrack, plays a script of invented stream lines for the attach tests, which run `laneboss lane attach` on a
pseudo-terminal, and records what it was given); `tests/e2e/sessionstandin.py`, the runner program of the
refusal tests, which writes invented session records in the `claude-code` and `text` formats while it runs (tool
calls, guard refusals in results and in hook messages, later shell writes, unknown lines and blocks, unreadable records
and a flood of ten thousand lines a second); and `examples/minimal/bin/example-agent`, the example configuration's stand-in runner program, which the
README's quick start installs.

The lane tests start real tmux servers and processes. Each test stops its configurations' servers (at the
sockets their configurations record, in `/tmp/laneboss-UID/`) and removes those sockets, stops the stand-ins'
processes and every leftover process that names its private directory when it ends, and makes its own Git
repositories in its temporary directory. Some lane tests hold the store's write lock or make the store
unwritable for a few seconds, kill a supervising process with SIGKILL, or make a worktree directory read-only.

How each kind is isolated differs. The launcher tests built on the shared `LauncherTest` harness
(`tests/e2e/support.py`) each get their own temporary configuration home, state home and user home (`HOME` is
replaced); they start from the runner's environment without any `LANEBOSS_` or `PYTHON` variable and set
their own `LANEBOSS_HOME` and `LANEBOSS_STATE_HOME`. Two modules do not use that harness: the scan tests run
`scripts/scan.sh` in temporary trees and repositories under a temporary `HOME`, and the README test runs the
quick start as written against the default homes (`~/.config/laneboss`, `~/.local/state/laneboss`) on
purpose, under a temporary `HOME` and `TMPDIR`, setting only `LANEBOSS_PYTHON`. The decision-store tests give
each case a private temporary directory for its databases and files and remove it afterwards, but they run
the command with the test process's own environment, `HOME` included. Three groups of tests import the product
and call it in the test process: `LibraryTest`; `RankingTest` of the resident search, which holds its ranking
and the sums that print its scores against the command's arithmetic on vectors made to tie; and
`AnswerBoundsTest`, which calls the bookkeeping of its remembered answers with answers as large as their bound,
which no search over a store that a test can make would give. `StandardLibraryTest` reads the source of the
decision store's modules, without running them, to check that they import nothing but the standard library. The
resident search's other tests start `laneboss decisions serve` as a process and talk to it over its socket; the
embedding service is replaced there by a local stand-in that answers with vectors that depend on the text. These
tests (`tests/decisions/test_serve.py`) have been run on Linux under Python 3.12 and under Python 3.9, not yet on
macOS.

The tests need these tools on `PATH` besides the interpreter: `sh`, `git` and `tmux` for the launcher's tests
(`doctor` checks the last two), `sh`, `git` and `python3` for the decision store's scanner test, and `curl`,
`sh` and `ps` for the resident search's tests (and `lsof` on macOS). The interpreter itself uses only the standard
library.

Write the test first and run it: it must fail because the feature is missing or wrong, not because of its
setup. Then change the code until it passes. Do not skip, delete or weaken a test to get a run green, and
leave no placeholder or stub in its place.

## The publication scan

Everything in this repository must be fit to publish. `scripts/scan.sh` fails on private-key headers, on
40 or more contiguous characters that look like a secret (so keep identifiers and paths in text shorter
than that), on IPv4 addresses other than the loopback address, and on email addresses. It reports the path
and line of each finding, never the text. Inside a Git checkout it scans the tracked files; outside one it
scans every file except those under `.git` or `__pycache__` and the `*.pyc` files.

```sh
sh scripts/scan.sh               # the whole tree
sh scripts/scan.sh --staged      # exactly what the index holds
sh scripts/install-hooks.sh      # a pre-commit hook that runs the staged scan and blocks a failing commit
```

A denylist adds names that must never appear in the repository, for example the names of companies,
people, hosts, accounts and private repositories. Write it as a file of case-insensitive regular
expressions, one per line, with `#` comments, and keep the file outside the repository. Set
`LANEBOSS_SCAN_DENYLIST=FILE` when you run the scan, or install the hook with
`sh scripts/install-hooks.sh --denylist FILE`. A match is reported as `denylist-line-N`, again without the
matched text. The scan exits 2 instead of passing when a scan without `--staged` has a root that is missing
or is not a directory, when it read no file at all, or when a denylist you named holds no rule; an
unreadable denylist and an invalid or empty-matching expression are refused the same way.

## Commit rules

- Run the scan before every commit and commit only when it passes.
- Keep fixtures invented. No file and no commit message names a private company, person, host, address,
  cloud project or account, private repository or private tool; public vendor and product names are fine.
  Never commit a credential.
- Commit the failing test before the change that makes it pass, and say in the message what the test shows.
- One kind of change per commit; do not mix a rename or a move with an edit. A subject line looks like
  `type: summary` (for example `feat:`, `fix:`, `test:`, `docs:`), in the imperative and short; the body
  says what changed and why.
- Change behaviour only on purpose: a commit that moves, renames or documents changes no test's
  assertions and no logic.

## The refusal rule

The shared protocol (`src/laneboss/protocol/protocol.md`) has a refusal rule, and it applies to everyone
who works on this repository, people and agents alike. When a guard, hook or permission layer refuses an
action:

- Stop that action and report the refusal verbatim: the refusal message and the start of the refused
  command.
- Write a document whole with the file tool or an editor, not through a shell command that a guard has
  refused.
- Write files with the file tool or an editor: shell redirection and here-documents are for command output,
  not for writing documents or source files.
- Never split, reword or strip a refused command to get it through.
- Never use an override prefix.

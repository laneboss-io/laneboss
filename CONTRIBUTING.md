# Contributing

Laneboss is pre-release. Changes are welcome; read this page first, because the checks below are not
optional.

## Build and verify on a disposable machine

The product is Go. Use the pinned Go 1.26.0 toolchain:

```sh
gofmt -l cmd internal scripts/install
GOTOOLCHAIN=go1.26.0 go vet ./...
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/laneboss ./cmd/laneboss
```

Builds and runtime verification belong on an authorized disposable machine. The existing black-box
tests are moving to their own e2e repository. Set `LANEBOSS_BIN` to the absolute path of the built
executable; `tests/e2e/support.py` and `tests/decisions/support.py` then invoke it directly.
The per-group `cmd/laneboss-<group>` entry points remain for the existing `GO_GROUPS` harness.
They are not installed with the product.

Runtime tests need an unprivileged user, isolated temporary configuration and state, Git and tmux.
Do not skip or weaken a test to make a run pass. Interpreter imports and fault injection against
the retired product modules must be migrated in the e2e repository.

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

The shared protocol (`internal/protocol/protocol.md`) has a refusal rule, and it applies to everyone
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

# integrations/claudock

Build from the repository root with the pinned Go toolchain:

```sh
GOTOOLCHAIN=go1.26.0 go build -trimpath -o bin/profile_swap ./integrations/claudock/profile_swap
GOTOOLCHAIN=go1.26.0 go build -trimpath -o bin/cos ./integrations/claudock/cos
```

The tests build the Go program and exercise it as a subprocess. Their interpreter is a test-harness
requirement, not a runtime dependency of the helper.

`cos` is an interactive terminal front for accounts whose credit only headless requests may use. Each message you
type becomes one headless request through Claudock (`claudock run ACCOUNT -- ...`), and a session id keeps the
conversation going. It is one stand-alone file that uses Go and the shared process-group stopper in `internal/cosprocess/`. Its tests are `tests/e2e/test_cos.py`.
Start it with `cos ACCOUNT [MODEL]`; `cos -h` lists the options.

How to start it, its permission default, its limits and what is not proven are on the page
[docs/claudock.md](../../docs/claudock.md).

## Profile swap

`profile_swap` selects a Claudock profile with quota left and resumes the **same** Claude Code session on it.
It is a standalone Go program using the module's pinned TOML parser. Profile names come from `claudock usage` or your
own TOML settings; keep real settings outside the public checkout. The example
[profile-swap.toml](../../examples/claudock/profile-swap.toml) contains invented names only.

From the checkout root:

```sh
bin/profile_swap pick --max-used 85 --max-age 30
bin/profile_swap limited LOG
bin/profile_swap resume --session ID --from NAME --max-age 30 --cwd DIR --dry-run
bin/profile_swap resume --continue --from NAME --cwd DIR -- --verbose
```

`pick` and `resume` accept repeated `--exclude NAME`, `--settings FILE`, `--max-used PCT`, and `--max-age S`,
passed to Claudock's usage cache. A profile's tightest active window must be strictly below the threshold
(default 85%). Past-reset windows count as empty. A reset of `unknown` is valid and retains its reported
usage, just like `-`; it never makes a window empty. Among subscriptions, the least-used tightest window
wins; `prefer` in the settings breaks ties in its listed order, then profile names break remaining ties.
Settings exclusions always apply, and `resume` also excludes `--from`. CLI thresholds override settings.

**Console API profiles bill per token.** Both commands exclude them unless you pass `--include-console`
or set `include_console = true` in your settings. The example sets `include_console = false`. With that
opt-in, qualifying subscription profiles still rank first; Console profiles follow, ordered by the share
of credit left (`100 - USED_PERCENT`), matching Claudock's available-profile ordering. Absolute dollars and
preferences cannot move a Console profile ahead of a subscription or one with a larger credit share.
The strict `--max-used` threshold and all exclusions still apply to Console profiles. When no profile
qualifies, the one-line diagnostic also says if Console profiles were excluded for per-token billing and
shows the opt-in. Console credit rows such as `Credit · $97.50 of $100.00 left` with reset `-` are valid.

`resume` requires either `--session ID` or `--continue`, plus `--from NAME`. `--cwd` defaults to the current
directory. `--continue` resumes that directory's newest session and needs **one session per directory**;
use an explicit session id otherwise. `--prompt TEXT` changes the continuation prompt. Extra Claude Code
arguments go after `--`. `--dry-run` reads usage and prints the exact argv and directory as JSON without
starting Claude. The choice and its reason go to standard error; Claude's output stays on its usual streams.

A supervisor runs through Claudock, saves the session id, profile and directory, then checks its completed
log with `limited` even when the run exited 0. A detected usage/session limit is a capacity pause: resume
that session on another profile and retain its work, without counting the limit as a failure or consuming
a retry. Keep checking each resumed run and remember its announced profile for the next `--from`.
When no profile qualifies, wait for the reported reset and re-check usage. The profiles must share one
Claude Code session history for a swap to work. Claudock refuses a resume if another model provider has
replied in that session; this tool never adds `--allow-cross-provider-resume` or exposes that override.

| Command | Exit codes |
|---|---|
| `pick` | `0`: one selected name on stdout. `3`: none below the threshold; one reset diagnostic on stderr. `2`: invalid input/settings, unavailable Claudock, or failed/malformed usage. |
| `resume` | Before starting Claude: `0` for a successful dry-run, `3` for no alternative, `2` for invalid input or a local/vendor-input error. After starting it: Claudock's exact exit status, including its resume refusal. |
| `limited` | `0`: recognized limit. `1`: readable log with no recognized limit. `2`: log unreadable or not UTF-8. It does not need Claudock. |
| All commands | `--help` exits `0` without invoking Claudock. A local Ctrl-C before the Claude run exits `130`; once launched, the child retains its own signal behavior. |

The exact message patterns, each pattern's source, reset estimates, and the supervisor loop are in
[Profile swap](../../docs/claudock.md#profile-swap). The new tests live only in
[test_profile_swap.py](../../tests/e2e/test_profile_swap.py), including the PATH stub and five mutant checks,
with the real-shaped [usage fixture](../../tests/e2e/fixtures/claudock-usage.tsv). The fixture retains
`Max 99×`, `Team Premium`, `Console API`, `9-hour session`, `Weekly · all models`, `Weekly · Fable`,
two-decimal percentages, UTC timestamps, `unknown` and credit-dollar rows, using invented profiles and values.
Run the behavioral tests on a disposable machine as an unprivileged user. For regression RED, keep the
revised test file and fixture with the previous tool; GREEN also includes the revised tool. Omitting the
tool still provides the original feature-missing RED check. The local check is:

```sh
python3 tests/e2e/test_profile_swap.py --static-checks
```

It compiles the tool, test file and stub, then calls the real entry point's root and subcommand `--help`
with the private stub on PATH. It runs no behavioral tests and makes no real Claudock or Claude request.

# Codex state allowance row

Run only on the authorized disposable Linux box. The public row uses an already
built release binary, tmux, Python 3.11+ and Landlock ABI 3+. It builds no binary,
imports no product package and contacts no model or owner service. The actual
Codex provider is replaced by `codex_state_standin.py`; the launcher gate, org
hooks, caller identity, CLI commands and store are real.

```sh
go test -count=1 ./internal/hookconfig
LANEBOSS_BIN="$BIN" LANEBOSS_ROW_EVIDENCE="$EVIDENCE" python3 -m unittest discover -s e2e-rows -p test_codex_state.py -v
```

Require exit 0 for both commands. Retain the complete source inputs, binary
bytes/hash, stdout/stderr, exit codes and fixture archives. The row retains its
isolated homes, worktree requests/responses, rendered inputs and resulting store
before the fixture collects its lanes. No authenticated AI-service behavior is
tested. The stand-in puts only allowed shell children under Landlock; hook
callbacks run outside the tool sandbox.

For RED evidence, put the unchanged `state_root_test.go` into a disposable source
copy of revision `15a3b71`, and run the same unit command. Every referenced
product function already exists at that revision, so a compile failure is not
the intended RED. Require these assertion failures:

- `TestStateRootVetting`, both default and custom state paths:
  `the exact configuration state root must pass full vetting`.
- `TestStateTreeAliases`, all three cases:
  `the clean state tree must pass before its alias is added`.
- Run the public row against a binary built from `15a3b71`. Require its assertion
  `lane preparation must render exactly the configuration state root` to fail.
  Setup errors, timeouts, missing prerequisites and a provider that never starts
  are not RED evidence.

`TestStateRootRefusals` supplies unchanged negative controls: state plus `.git`,
`.git` alone, another directory, a parent, a shared prefix, a symlink, `..`, a
relative path, duplicate/empty roots and a profile override. The full-vetting
positive also changes `hooks.json` after passing, and requires the hook integrity
gate to refuse; accepting the state root cannot skip vetting. The alias row adds
a real symbolic link, hard link or `.git` directory after its passing control.

The public row requires exact roots in the generated config and the stand-in's
consumed sandbox inventory, a stored `report.sent` with the real lane actor and
input bytes, an actual peer mail file/event, refusal of a direct shell overwrite
of the peer's output log, unchanged peer bytes and a successful ordinary
worktree-write control. Any failed assertion fails the row. The OS grant is not
a CLI-only capability: the hook and existing same-account limits remain part of
the security boundary. Independent security review and the release suite remain
required after RED/GREEN box evidence.

## Effective PATH enforcement

`TestLanePath` uses the actual execution re-vetting gate with a fully vetted
org instance. It requires refusal for worktree/state entries, a worktree
subdirectory, a symbolic alias, a cleaned path, empty entries and relative
entries. Its controls require `/usr/bin:/bin` plus an installed-tool directory to
pass, and a safe command `env PATH=...` prefix to replace unsafe inheritance.
The unsafe-prefix rows replace safe inheritance, so consulting the supervisor's
PATH instead of the runner's effective one cannot pass.

`CodexPathRows.test_path_start_refused` starts two ordinary-PATH Codex lanes in
setup, then attempts worktree, state, empty, relative and symlink PATH entries
through the public CLI. Each must return the PATH refusal and its recovery
route before the provider writes its ready record. The original communication
row still exercises report/send, the direct-state-write denial and the ordinary
worktree control. Its provider is always selected by absolute path, so an
installed real Codex cannot replace the stand-in.

`CodexPathRows.test_path_later_refused` stops a safe-PATH lane, queues real mail,
then puts its worktree on the effective PATH. Both resume and turn must refuse
at the PATH gate without advancing the run number. The queued mail ensures the
turn reaches launch preparation rather than returning early because it has no
work. An unexpectedly allowed base launch is stopped before the next route.

For RED on `7a2ef2d`, copy `lane_path_test.go` unchanged into a disposable source
copy and run `go test -count=1 -run '^TestLanePath$' ./internal/hookconfig`.
It uses only product and fixture symbols already present at that revision.
Require the assertion `the effective lane-writable PATH must refuse at the PATH
gate` in every negative case. Run the current public row with the binary built
from `7a2ef2d`; require `a writable effective PATH must refuse lane start` in
each negative case. A setup failure, compile error or provider timeout is not a
valid RED. No RED/GREEN runtime claim follows from static checks alone.

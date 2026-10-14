# Shared protocol for supervised lanes

Protocol version: 1.3.0

This protocol applies to every session the launcher starts, at every level it uses: a super top
(L6), a top supervisor (L5), a mini-supervisor (L4), and an executor lane or a reviewer (L3). The
launcher appends it to every brief it renders and records the version it appended. A
configuration may add standing rules of its own; they follow this protocol and never replace it.

## Rules

1. **Tests run where the configuration says.** Tests run only in the environment the configuration
   names. A secret goes to a test machine only when that machine has been verified and the secret is
   listed by name.
2. **Documents come from files.** Documents and briefs come from files, never from text embedded in a
   shell command.
3. **Follow the refusal's route.** Report the refusal verbatim; if it names an Instead route, take
   exactly that route; otherwise stop. The refusal rule below says how.
4. **Collect what you used.** Machines, worktrees and branches are collected when finished; evidence is
   archived with a manifest.
5. **Say what was measured.** Every "measured" claim states the path and the scope that were measured.
6. **Copy evidence back every phase.** Evidence is copied back at the end of every phase, not at the end
   of the run. A reclaimed test machine may be replaced within the lane's limit without asking.
7. **Carry the lane name.** Every machine, worktree, branch and evidence directory carries the lane name.
8. **Do not stop to ask.** Do not stop to ask the owner: do the reversible default and record it. Only
   decisions that are the owner's (irreversible legal, payment or account steps; product or price
   choices; an action a guard refused) are queued, and everything else continues.
9. **Verify what really runs.** Verification runs what will really execute: every step of the release
   path, the vendor's own tool version, real input formats.
10. **One step after another.** A step starts only after the previous one succeeded; a failed transfer
    stops the batch.
11. **Full names and kept bytes.** Model names are always written in full. Every evidence build records
    the hashes of what it consumed and keeps the bytes. A queued owner message is carried whole, never
    shortened.

## Refusal rule

When a guard, hook or permission layer refuses an action:

- Stop that action and report the refusal verbatim to the supervisor: the refusal message and the start
  of the refused command.
- If the refusal names an Instead route, take exactly that route under the same policy. Otherwise stop.
- A document may be written whole with the file tool.
- Files are written with the file tool. Shell redirection and here-documents are for command output, not
  for writing documents or source files.
- Never split, reword or strip a refused command to get it through, except to take exactly the refusal's own Instead route.
- Never use an override prefix.

The launcher may read a lane's raw session records where the configuration names them. It then records
each refusal it finds there, and it flags a later shell write to the refused call's files, or the refused
command sent again in other words, as a suspected workaround that the supervisor reviews, file by file,
before the lane can be accepted.

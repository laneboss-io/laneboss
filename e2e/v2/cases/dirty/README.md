# G11 dirty retention

This installed Linux case exercises the user-visible cleanup path with the
credential-free Claude fixture. It starts a `claudock-cli` lane, writes one
untracked file and appends to one tracked file in the real native worktree,
then stops, abandons, archives, and cleans that lane. The dirty clean operation
must fail after the native helper has journaled `retain_dirty`; its typed error
must name `retain_dirty` and tell the operator to commit or merge the work
before cleaning again.

The case records and checks four assertions:

* `DIRTY-RETAIN` requires the installed operation to fail with a prerequisite
  error, retain the lane as uncleaned, and include the merge-or-discard next
  step. The case then discards those uncommitted bytes and runs a second clean
  operation under a new effect, which must remove the worktree and branch.
* `DIRTY-NATIVE-JOURNAL` independently reads the protected helper journal and
  requires its completed removal action to be `retain_dirty`.
* `DIRTY-WORKTREE-BYTES` hashes every file's relative name, mode, and bytes in
  the worktree, plus the branch head, before and after clean. The tracked and
  untracked dirty bytes and the branch head must match exactly, and both files
  must still exist.
* `CLEAN-CONTROL` runs a second clean-tree fixture through the same lifecycle;
  its helper action must be `remove_clean`, its lane must be cleaned, and both
  its worktree and branch must be absent.

The producer and entry run only through the serve harness observer. The
producer reads the actual installed workspace enrollment and helper journal;
the entry result and collection evidence retain those measured facts. This is
an authenticated installed-service fixture check, not a real vendor request.

On the authorized Ubuntu box, run it after the ordinary serve checks with:

```sh
python3 -I -B scripts/v2-serve/run.py \
  --source /test/candidate \
  --evidence /test/evidence/lb-v2-dirty \
  --item-case dirty
```

The box result must reach and pass all four assertions, report an exit code of
zero, and retain independent entry and item collection receipts. Its retained
observation must show the dirty operation's typed `retain_dirty` refusal and
merge-or-discard next step, an unchanged worktree-tree hash and branch head,
the successful second clean, and a clean control whose helper journal says
`remove_clean` with no worktree or branch remaining.

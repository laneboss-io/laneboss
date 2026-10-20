# G11 dirty retention

This installed Linux case exercises the user-visible cleanup path with the
credential-free Claude fixture. It starts a `claudock-cli` lane whose authenticated
fixture writes one untracked file and appends to the tracked `README.md` inside
`/work/main`, using the task pinned in the initial publication,
then stops, abandons, archives, and cleans that lane. The dirty clean operation
must fail after the native helper has journaled `retain_dirty`; its typed error
must name `retain_dirty` and tell the operator to merge or discard the work
before cleaning again.

The case records and checks five assertions:

* `DIRTY-RETAIN` requires the installed operation to fail with a prerequisite
  error, retain the lane as uncleaned, and include the merge-or-discard next
  step. The dirty lane remains retained; the host never repairs its files.
* `DIRTY-NATIVE-JOURNAL` independently reads the protected helper journal and
  requires its completed removal action to be `retain_dirty`.
* `DIRTY-WORKTREE-BYTES` compares every file's relative name, original mode,
  and bytes before stop with the protected archive manifest. It then requires
  the physical archived tree to differ only by the exact write-mode withdrawal
  required by native archive freeze. That frozen tree, including every mode,
  name, and byte, is compared immediately before and after clean. The branch
  head must remain identical across all phases, and both dirty files must exist.
* `DIRTY-RESTORE` confirms an exact `lane.restore` request and invokes the real
  installed CLI with a fresh target under a private service-owned parent in
  a separate active lane's native workspace. The authenticated human caller
  owns that lane; archived storage is excluded by the native root resolver.
  The case publishes a five-minute wall budget for the existing lifecycle
  fixture's bounded wait. It measures the host running immediately before and
  after restore, then stops it, leaving the
  restored copy retained independently of the clean control. The case
  reads the resulting worktree independently and requires every original name,
  file byte, file and directory mode, and Git head to match the pre-stop tree.
  The untracked file must return with its original `0600` permissions. The
  observer reads the selected verified part inventory through a read-only
  database connection, then reads and hashes the manifest and every archive
  part through authenticated `blob read` before and after restore. The complete
  archive digest and the retained frozen worktree must remain unchanged. No
  chmod or workspace repair follows restore. The new copy remains on the
  disposable box as evidence until the box is collected.
* `CLEAN-CONTROL` runs a second clean-tree fixture through the same lifecycle;
  its helper action must be `remove_clean`, its lane must be cleaned, and both
  its worktree and branch must be absent.

The producer and entry run only through the serve harness observer. The
producer reads the actual installed workspace enrollment and helper journal;
the entry result and collection evidence retain those measured facts. This is
an authenticated installed-service fixture check, not a real vendor request.
The shared project contains `README.md` in its imported Git snapshot. Selection
reads that branch's committed tree rather than the bare repository's unused
index. A separate task target keeps the clean control and earlier lifecycle
lanes unchanged. Both consumers still require the real helper journal and byte
comparisons; no receipt is manufactured by the fixture.

The component restore command test uses the real CLI parser and restorer with
an explicit authorized root. A sibling target outside that root must return
`restore_target_scope` without creating anything; a fresh target inside it
must restore the exact tree. This component check does not establish installed
service traversal or mount access to a lane workspace. The installed flow must
also demonstrate that access without changing the service or lane boundaries.

On the authorized Ubuntu box, run it after the ordinary serve checks with:

```sh
python3 -I -B scripts/v2-serve/run.py \
  --source /test/candidate \
  --evidence /test/evidence/lb-v2-dirty \
  --item-case dirty
```

The box result must reach and pass all five assertions, report an exit code of
zero, and retain independent entry and item collection receipts. Its retained
observation must show the dirty operation's typed `retain_dirty` refusal and
merge-or-discard next step, equal live/original-archive hashes, equal frozen
before/after-clean hashes, an unchanged branch head,
and a clean control whose helper journal says
`remove_clean` with no worktree or branch remaining.

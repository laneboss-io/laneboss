# Required red and candidate evidence

This round has no Linux runtime measurements. Tests, builds and project
interpreter runs are forbidden on the authoring Mac. The permitted static
checks are not red/candidate evidence and never complete this round.

`mutations.py` is the current executable inventory, documented in MUTATIONS.md:
325 mutations, both normal and laneboss_faults variants, 650 targeted reds,
650 unchanged candidate controls and fourteen final package/tag suites.
Historical round counts elsewhere are not the current inventory. Every red must compile, reach its named
assertion and fail for that reason. Compiler errors, setup refusals, panics,
races, skips and timeouts receive no mutation credit.

```sh
bash e2e/v2/cases/service/run-mutations.sh --source /test/source --evidence /tmp/lb-v2-service-mut-r6
```

Use a fresh absolute evidence directory outside the exact composed source.
The script retains source/driver/test-binary bytes and hashes, command output,
exit codes, reached assertions and process-group quiescence. Its stdout names
the failing variant/mutation/stage/exit/diagnostic and retained log.
Anchor preflight must succeed before builds. No test is changed in a mutant.

ADMISSION-RETRY.md adds two invalid-first-frame controls. Both must reach
"valid second frame did not move UID slot to containment" on a real native
connection after the first refusal. Their candidate counterparts must observe
the actual slot transfer before the second-frame handler and no repeat transfer
on the third frame. These controls remain pending Linux execution.

Additional candidate regressions exercise the implemented ports and teardown:
TestAwaitReservedReceipt, TestPinnedReadView, TestRetainedObjectBytes,
TestEffectRequiresContext, TestConnectionLifetime,
TestInstalledListenerProtection, TestCloseCollectsOwnedStore,
TestPostOpenStatePrivacy, TestEventCursorSinceResume,
TestQueuedFramesDrainBeforeError and TestRecordMethodOwnLife.
Their controls must also be shown red for the corresponding missing/broken
behavior before candidate success is claimed. Their current runtime status is
unmeasured; an absent mutation row is not an implied pass.

The full unit command on that same Linux source is:

```sh
go test -race -count=1 ./...
go test -race -count=1 -tags laneboss_faults ./...
```

Run as an unprivileged test UID with a safe private HOME/cache. Production
ownership, ancestor and native credential checks must remain enabled. State
fixtures now use private home children so a world-writable /tmp ancestor cannot
silently weaken the production predicate.

MATERIALIZATION.md records the ten added materialization/worker controls and
their exact assertion names. All ten are authored and statically checked only;
none has been credited as a reached runtime red or candidate green in this lane.
MATERIALIZATION-SCOPE.md adds two generic-scope controls with distinct leaf
assertions. They restore the original input.read shortcut, so the deciding
canary must acquire actual protected policy bytes or a real read view before
its named failure. They remain unmeasured until the Linux red/candidate run.
MATERIALIZATION-SCHEMA.md records the supplied mat-red1 early enum failure,
the private schema correction and the audit of all ten original controls.
Four schema controls remove one required private representation at a time;
they also require Linux red/candidate measurements.

Only the installed composed serve case can accept the change:

```sh
bash e2e/v2/cases/serve/run.sh --context /test/cases/serve/context.json --result /test/cases/serve/result.json
```

Retain a base failure at the intended gate and a complete candidate pass.
The service subcase's explicit cardinality stop remains incomplete evidence.
The supervisor's later installed run reaches the public Health refusal
described in PUBLIC-HEALTH.md; it does not establish candidate acceptance.
See ACCEPTANCE.md and MATRIX.md for the remaining installed boundary, watcher,
cardinality and outage measurements.

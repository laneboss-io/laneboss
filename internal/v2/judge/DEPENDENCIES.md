# Legacy dependency inventory

This inventory was captured before the supervisor's 36753879 removal of sixteen
wave-0 additions. Listed paths can now be absent; none is recreated by fix 9.
The owned corpus fixture and the absence of v2 imports of the legacy package
remain the dependency boundary.

The v2 judge runtime, tests, feature CLI adapters and owned E2E/mutation runner
need **none** of the files under `internal/judge`, `scripts/judge-eval` or
`testdata/judge-corpus`. The exact tracked inventory below is for the supervisor's
removal decision. This lane has neither deleted nor edited any of those paths.

The sole former test-data dependency was
`testdata/judge-corpus/corpus.json`. Its complete 130,493 bytes now live at
`internal/v2/judge/testdata/corpus.json`, and corpus_test.go reads that owned
path. Both copies have SHA256
`feb305e2...6e42a1277` (prefix and suffix of the same digest).
The mutation input archive includes the owned fixture through the judge tree;
it no longer reads the external corpus directory. Corpus strings that mention
legacy paths are example commands, not executable imports or file dependencies.

Each of these legacy package files is unnecessary to this lane:

```text
internal/judge/PROVIDERS.md
internal/judge/README.md
internal/judge/TESTING.md
internal/judge/adapter.go
internal/judge/ask.go
internal/judge/batch.go
internal/judge/batch_test.go
internal/judge/cache.go
internal/judge/capacity_test.go
internal/judge/config.go
internal/judge/contract.go
internal/judge/corpus_test.go
internal/judge/credentials.go
internal/judge/display.go
internal/judge/fault_bridge.go
internal/judge/files.go
internal/judge/http.go
internal/judge/jobs.go
internal/judge/judge.go
internal/judge/judge_test.go
internal/judge/process.go
internal/judge/provider.go
internal/judge/provider_edges_test.go
internal/judge/schema.go
internal/judge/screen_test.go
internal/judge/testdata/README.md
internal / judge / testdata / capacity_adapter.py
internal/judge/testdata/clef.json
internal/judge/testdata/typesafe.json
```

Each of these evaluator/corpus files is unnecessary to this lane:

```text
scripts/judge-eval/README.md
scripts/judge-eval/run.py
scripts/judge-eval/test_run.py
testdata/judge-corpus/README.md
testdata/judge-corpus/corpus.json
```

The v2 code does need the separate shared strict-wire package
`internal/typesafe/wire.go`. It is not `internal/judge`; do not remove it
as part of this inventory. Other shared dependencies are the frozen v2 API and
client/common CLI invocation. The mutation archive explicitly retains API,
client and typesafe source alongside this lane's owned code.

Other, nonowned legacy callers still import `internal/judge`:
`cmd/laneboss-judge/main.go`, `internal/adapters/call.go`,
`internal/cli/cli.go`, `internal/cli/fault_bridge.go`,
`internal/dashboard/dashboard.go`, `internal/dashboard/judgments.go`,
`internal/decisionsrv/guide_dial.go`, `internal/ledger/ledger.go` and
`internal/orghook/jobs.go`. The legacy corpus test and evaluator also read the
external corpus. This is a v2 dependency inventory, not a claim that deleting
the whole legacy package leaves those other products compiling. The supervisor
owns the wave-0 removal and any consequences for those callers; no repair or
acceptance of the legacy HTTP/evaluator code is implied here.

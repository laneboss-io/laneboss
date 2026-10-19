# Dashboard polling regression correction

This run starts at d8d3f62. The supplied Linux verification log reports
TestDashPollRate failing in both builds after 0.22 seconds. It does not print the
individual poll count or terminal frame, so it does not establish excessive
production polling or host-load sensitivity.

The test had a definite wire-code error: it required `"code":"deadline"`.
api.CodeDeadline is `deadline_exceeded`, and streamSSE assigns that typed code
when its context deadline expires. The old combined assertion therefore failed
even when the handler made exactly its expected one initial poll. The production
one-second ticker and cancellation gate are unchanged in this correction.

TestDashPollRate now parses the terminal StreamFrame and checks api.CodeDeadline
directly. A separate diagnostic identifies a bad HTTP status, missing/extra
terminal frame, event on a terminal frame or wrong terminal error code.

The same handler, ticker and context timeout run inside testing/synctest's
virtual clock. The module already requires Go 1.26. The complete fixture and
counted transport are created inside each bubble; this test uses no real network
or external process. The observer records the actual PollEvents call times, not
an inferred period or a substituted return value. Virtual time advances only
when the bubble's goroutines are durably blocked, so host load does not advance
the measurement clock while the handler does work.

| Subtest | Required observation |
| --- | --- |
| TestDashPollRate/initial | A 220 ms virtual stream makes exactly one initial service poll, ends at that deadline, and emits one terminal frame with api.CodeDeadline. This retains the original short-window bound. |
| TestDashPollRate/follow | A 2200 ms virtual stream makes exactly three service polls, including the initial poll. Every subsequent poll is at least one second after the preceding poll, and the stream ends at its deadline with the typed terminal frame. This also proves that following continues at the required bound. |

The named rate diagnostic remains `passive SSE exceeded its bounded polling
rate`; it now includes the observed count, expected count and virtual elapsed
time, or the offending interval. No bound was loosened and no test was skipped.

| Red control | Intended reached failure |
| --- | --- |
| d3-poll-rate | The retained 50 ms production-ticker mutation must fail TestDashPollRate with its original bounded-polling diagnostic. |
| d4-poll-half-second | A 500 ms production-ticker mutation must fail TestDashPollRate/follow with that diagnostic. This catches a period violation outside the original 220 ms observation window. |
| d4-deadline-frame | Substituting api.CodeCancelled for the producer's deadline code must fail TestDashPollRate/initial with `SSE deadline lost its typed terminal frame`. |

controls.json now contains 76 controls. All names, including these subtests,
remain under forty characters. The Linux control runner retains the source
mutation and requires the exact named failure/diagnostic before the corresponding
candidate pass. A compile error, skip, panic or unrelated failure cannot satisfy
the control.

On the authorized disposable Linux machine, run the named regression in both
builds and the retained red/candidate controls. A source or static-check result
does not replace those runs:

```sh
go test -count=1 -run '^TestDashPollRate$' ./internal/v2/dashboard
go test -count=1 -tags laneboss_faults -run '^TestDashPollRate$' ./internal/v2/dashboard
python3 e2e/v2/cases/dashboard/red-controls.py --source /absolute/candidate --evidence /absolute/lb-v2-dashboard-cx-red
```

Only static checks are authorized on the authoring Mac. No new test, mutant,
build, browser or installed-service execution has run here. The exact input
brief, supplied Linux log, baseline, source overlay, patch, hashes and static
check outputs are retained in the run-4 evidence manifest. No commit was made.

Observed static checks: gofmt -w completed on both changed Go files, and
gofmt -l returned no paths with exit 0. Linux go vet exited 1 at the default
Go-cache permission boundary, with `operation not permitted`; stderr also
reported a vendor-package resolution diagnostic. Per the brief's explicit
recovery route, Linux/faults and Darwin vet were skipped. No cache override or
retry followed. The revised candidate and red controls still require Linux
execution; this run does not claim a passing Go type-check or runtime result.

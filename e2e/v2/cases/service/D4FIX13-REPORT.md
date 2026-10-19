# Draft.4 fix 13 report

The candidate starts at 5eef5d2 and remains uncommitted in the same checkout.
The supervisor reports the base unit box green. The supplied red-runner log
builds its reduced candidate, completes 60 normal control pairs, then rejects
service-file-registration. Those are supplied baseline results, not a new
measurement of this candidate.

## Deciding failure and correction

The catalog already names the exact health assertion observed in the log:
`valid service file did not reach transport: health`. It also names the correct
leaf selector, health then --request then valid. The assertion was not missing.

The test used one t.Run call whose name combined form and validity with a
slash. Go emitted the top test, health and that combined leaf. It emitted no
separate --request node. The runner correctly rejected that output because it
requires every declared ancestor in the observed RUN and FAIL path sets.
diagnosis.json in the external evidence records the actual supplied paths and
the one missing prefix. It is analysis of the supplied log, not a test replay.

TestServiceFileInputs now creates actual nested nodes for method, form and
validity. The loops put form first so both validity cases share one form node
without duplicate-name suffixes. The same eight methods, both request forms,
valid/invalid inputs, typed refusals and semantic/transport assertions remain.

The catalog ID, exact assertion marker, selected leaf and runner conditions
are unchanged. No control was removed and no arbitrary failure is accepted.
The source now supplies the missing ancestor that the existing strict control
requires. The actual red and unchanged-candidate path sets still need a Linux
rerun; no synthetic trace is offered as that evidence.

## Remaining-control source review

The static review covered all 160 catalog entries, including the 99 after the
reported failure. Every named test resolves to its package source. Expected
messages were mapped to exact strings, formatted messages, selected-case
concatenation or the actual error/helper calls. Helper cases include separate
t.Fatal arguments, the typed-error format and the local admission call's exact
failure argument. No project Python was imported or executed for this review.

Of the 89 entries declaring a subtest, service-file-registration is the only
multilevel selector. The other 88 selected leaves are one-level t.Run nodes,
and each named leaf exists in the corresponding source cases. After the fix,
no selected test constructs a compound slash name. Of the 71 whole-test
entries, only launch-replay-comparisons targets a test that also has subtests;
its deciding assertion is after the subtest loop at top-test scope, matching
the expected whole-test failure set.

No further path/assertion mismatch of this kind was found in source review.
The per-entry evidence is source-review.json outside the checkout. Static
mapping does not prove mutant reachability, intended guard isolation or
candidate runtime success. The 99 later controls still require their actual
deciding reds and unchanged-candidate greens.

## Static checks and limits

| Check | Observed result | What would fail it |
| --- | --- | --- |
| gofmt -w | Exit 0 on input_test.go | Go parse/format error |
| gofmt -l | Exit 0 and empty output | Any remaining path or nonzero exit |
| py_compile | Exit 0 for mutations.py, run.py and scenario.py | Missing input or Python syntax error |
| bash -n | Both service entry scripts exited 0 | Shell syntax error |
| Linux vet | Exit 1: existing go-build cache entry access refused | Vet/compiler diagnostic or unavailable cache |
| Faults and Darwin vet | Skipped under the brief's cache-refusal instruction | Not measured |
| Unit/mutation execution | Not run on this Mac | Exact assertions and selected path sets in the existing runner |

Linux vet was invoked with GOWORK off, Linux amd64 and module downloads
disabled for the changed service package. Its exact command, exit and cache
permission diagnostic are retained outside the checkout. No cache was changed,
no retry or alternate cache was used, and no later source edit or verification
continued after the refusal. Only reporting and evidence collection followed.

The environment was Darwin arm64 with Go 1.26.5 and Python 3.13.11. No binary
build, unit/mutation test, remote job, machine operation, model request or
project interpreter beyond the authorized py_compile operation ran here.
This component work is not an authenticated AI-service test.

Evidence is under the lane's external evidence root in d4fix13-5eef5d2: the
brief, supplied red log, HEAD source archive, current source/diff, per-entry
review, diagnosis, commands/logs/exits and manifest. The supervisor owns the
selected red/candidate rerun, remaining full inventory, review and commit.

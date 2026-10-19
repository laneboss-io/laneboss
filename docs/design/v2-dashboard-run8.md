# Merged store fixture contract

The landing baseline is 998b7f9, the merge of the shared API into the approved
run-7 dashboard. Its StateStore includes CredentialProjectionStore and the
CurrentPolicySource embedded through PolicyStore. The dashboard harness had
none of those six methods. The full api.StateStore compile-time assertion in
fixture_contract_test.go is retained.

All six fixture methods now return their zero result with the store's typed
not_implemented error, owned by lb-v2-service and naming the exact store port.
They follow the corresponding production store stubs. No credential or policy
projection operation is implemented or reported successful by this fixture.
Production service/API code and the approved dashboard behavior are unchanged.

| Required method | Regression | Red control |
| --- | --- | --- |
| CredentialProjection | TestDashFixturePorts/cred_read | d8-cred-read |
| ReserveCredentialProjection | TestDashFixturePorts/cred_reserve | d8-cred-reserve |
| CommitCredentialProjection | TestDashFixturePorts/cred_commit | d8-cred-commit |
| FenceCredentialProjection | TestDashFixturePorts/cred_fence | d8-cred-fence |
| CompleteCredentialWithdrawal | TestDashFixturePorts/cred_withdraw | d8-cred-withdraw |
| CurrentApprovedPolicy | TestDashFixturePorts/current_policy | d8-current-policy |

Each regression requires an api.Error with CodeNotImplemented and the store
owner. Each control replaces just that port's typed error with nil; it must
fail the named assertion about an unimplemented fixture returning success or
the wrong owner. A compile/setup error, skip or unrelated failure does not
count. The new test paths remain shorter than forty characters, and all prior
controls are retained.

Static source inventory follows all twenty-one embedded API interfaces and
compares the seventy-three required method names and their textual signatures
with the harness. This assists inspection; it is not a Go type-check. The
retained compile-time assertion and the brief's Linux, Linux/faults and Darwin
vet commands remain the compiling checks when the default Go cache is usable.

Only static checks are authorized on this Mac. No test, build, project
interpreter, renderer, red mutant, cloud machine, remote access or real model
request ran here. The six candidate/red controls need execution in the
supervisor's Linux environment. The exact brief, baseline source/revision,
final overlay and patch, hashes and check outputs are retained in the run-8
external evidence. No files were staged or committed.

Observed checks: gofmt -w completed for both changed Go files, gofmt -l
printed no paths and git diff --check printed no errors, all with exit 0.
Static comparison found no textual signature differences for the seventy-three
required methods. All 140 prior controls are unchanged; the six additions
have unique source anchors and test paths at most 35 characters long.
GOOS=linux go vet ./internal/v2/dashboard/... exited 1 because opening the
default Go cache returned operation not permitted. The brief's explicit
recovery was followed: Linux/faults and Darwin vet were skipped, with no cache
change or retry. No compiling confirmation or candidate/red pass is claimed.

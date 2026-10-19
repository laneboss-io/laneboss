# Draft.4 judge CLI input registration

commands_judge.go registers judge.ask and judge.list at initialization under the
catalog owner lb-v2-judge. Either registration error panics and stops startup.
Both the common file route and InvokeRaw use the shared registry. The callbacks
and ergonomic adapters call DecodeAskInput/DecodeListInput; service handlers
use those same decoders. Direct typed JudgeAsk calls also use ValidatePreviewInput.

Ask accepts a valid preview ID, empty rule/decision arrays, UTF-8 task/command,
an exact command digest, absolute CWD, nonempty tool, explicit argv/path arrays,
a positive bounded deadline and a nonnegative bounded cost ceiling. An omitted
configuration claim remains zero; a supplied one must resolve to a supported,
fully pinned configuration. Context and policy authority remain service checks.
List accepts exactly the empty JSON object with optional whitespace. No input
is normalized or substituted before the original bytes reach InvokeRaw.

TestJudgeInputFiles has invalid and valid files for each method. Invalid ask is
a well-shaped request with an empty ID. Invalid list has an extra field. Missing
proof and binding files plus an invalid key make late validation fail the test.
Both require invalid_request and exit 2, without success output. Ask's semantic
error must be judge-owned. Empty-method structural errors may come from the
shared API decoder before the module hook, with its empty Owner. That branch
requires the exact error fields produced by decoding the same invalid input,
so a later proof-read invalid_request cannot satisfy it. The registered
exact-empty decoder is separately tested against null/arrays/extra/duplicate/
trailing input and through the actual service handler.

Valid files supply a retained mutation key and an explicitly uninstalled binding.
They must reach a non-judge refusal, never invalid_request. The explicit accepted
transport/binding codes are not_implemented, prerequisite_missing and unavailable
(exit 69), or unauthenticated and version_mismatch (exit 2). No other lane's
message is pinned. This admits the real client's protected-binding prerequisite
as well as an unfinished client port; it does not claim a working installation.

The two new mutation entries remove only the ask or list registration. The ask
control must reach judge input validation was bypassed; the list control must
reach valid judge file missed transport. They brought the original 35 controls
to 37; the six subsequent fix-10 screen controls bring the current total to 43.
On the combined authorized Ubuntu source, run:

```sh
go test -count=1 -run '^(TestPreviewInputValidation|TestListInputIsEmpty|TestJudgeHandlerInput|TestJudgeInputFiles)$' ./internal/v2/judge
go test -count=1 -tags laneboss_faults -run '^(TestPreviewInputValidation|TestListInputIsEmpty|TestJudgeHandlerInput|TestJudgeInputFiles)$' ./internal/v2/judge
python3 e2e/v2/cases/judge/mutations.py --source /test/lb-v2-judge2/source --evidence /test/lb-v2-judge2/judge-inputs --only judge-inputs
```

Require reached red failures for both dropped registrations and a restored green
candidate. A setup/build error is not a kill. Tests were not executed on the Mac.
The runner retains complete internal source because CLI tests compile the real
shared adapter and its imports. The focused mode changes only the two CLI
registration blocks and leaves the screen untouched.

The older lane base cebe469 predates the shared RegisterInputValidator API. That
round's static composition checks used the exact shared API/CLI/module bytes
from the retained integration source archive through a Go overlay. Its evidence
keeps the original archive, overlay, compared inputs and check outputs. At the
merged c5617a3 checkpoint the real registry is present in this checkout. Current
checks use ordinary source without that historical overlay or a local shim.
Static composition does not establish installed CLI or runtime acceptance.

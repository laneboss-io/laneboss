# Landing unit-box repairs

The supplied normal and faults unit runs on fa38cbfc are the failure evidence.
This candidate does not claim a green runtime run. Laneboss owns the commit
and full disposable Linux rerun. Mac checks compile/vet candidate code only.

| Failing tests | Cause and introducing history | Repair |
| --- | --- | --- |
| TestIsolationProofTransport/wire | Fixture introduced in 9ee022d7 supplies no nested ProcessObservation.ObservedAt. The wire reader requires a UTC timestamp, independently of the proof's outer timestamp. | The transport fixture carries its already measured fixture time into that observation. Both real readers and full DTO equality remain required, and a future refusal includes the actual error. |
| TestLaneRuntimeProjection/valid | The 3acf9ec4 fixture supplies partial receipt/home/workspace DTOs. That commit also introduced the legitimate complete zero NetworkLease view for offline execution, which generic wire ID/digest/time validation rejects. | Supply complete, correlated fixture DTOs. Recognize only the complete zero network view inside ResolvedRuntime, after the shared strict NetworkLease reader. Nine malformed/partial cases and a standalone zero-lease refusal retain the boundary. |
| TestCLIRejectsMalformedFile | The fixture retains the generic pre-diagnostic message. 9ee022d7 deliberately introduced compiled-schema frame/object/path/reason diagnostics. | Require the exact new diagnostic for every malformed case. Exit, owner, invalid_request code, empty stdout and refusal before the absent installation remain exact assertions. No case is removed. |
| TestMaterializationStageFlow and TestMaterializationRetainedStage | The result writer model uses the generic owner-visible object helper, while the retained WorkerResult reader requires private original-operation results. The relevant fixture and reader lines are attributed to 071c6c5e in the retained history. The actual store WorkerResult writes private results. | The fixture's result callback records the worker-result contract, preserving submitted bytes/hash, operation and life. A new SQLite regression obtains the acknowledgement through real reservation/claim/WorkerResult calls and checks committed metadata and bytes. Production provenance checks are unchanged. |
| TestChannelJobPreflight and TestChannelExecutionPreflight | The 7e9c6ba8 fixture gives sealed job input/payload the generic owner audience, before the private jobObject boundary. | Model private job objects from their retained lease, including operation/life, and use the same writer when the negative input case is re-encoded. The existing positive cases still end at the owning not_implemented barrier; no provider succeeds. A new owner-audience negative retains rejection. |
| TestLoopOpenedGenerationAdvance, TestLoopPlan and TestLoopReplayPins | The loop writer model from bd300b5d uses service audience. The deliberate 1d9d5b8e planner provenance check requires owner audience plus service owner/config/life/operation provenance. | Update only the writer model's audience. The production planner check and all replay mutations/assertions remain unchanged. |
| TestDataOwnerRefusal | The 6e9b2524 wrapper embeds only api.StateStore. After 780e88f4 adds the private LaunchReceiptReader, that wrapper hides the new prerequisite and the runner never reaches the selected data owner. | Embed the concrete existing memory store, preserving its typed ports. The selected data/usage methods still call the real store owner and preserve its exact error. |
| TestLaunchReceiptRetainedOwner | The negative test added in 780e88f4 corrupts immutable ownership and assumes it can reopen the writer before the private read. Store verification has intentionally rejected that ownership mismatch since fbbf771a. The shared fixture overwrites its old pointer with nil on failed reopen, causing the secondary cleanup panic. | Start from verified real state, retain each of the three ownership faults, and require the real store-open integrity refusal. The closed writer also refuses the original read with unavailable and no request. Publish a replacement fixture pointer only after successful real store construction. No store guard is bypassed. |

The exact raw source-history commands and line attributions are retained in
the lane evidence. 071c6c5e is a merge-resolution attribution in this history;
it is not represented as a separately observed runtime failure. The source
analysis follows the actual WorkerResult writer, not a generic interpretation
of the word private. No dataworker production provenance check is changed.

The existing in-memory stage, channel and loop models remain component inputs,
not native authority. Their writers now implement the current retention
contract; they do not bypass a consumer check. TestMaterializationWriterProvenance
is the separate real-SQLite proof of that result contract, through actual store
calls. It does not patch protected rows. The only deliberate protected-row
damage is the retained-owner negative, whose real reopen must fail.

The new controls are unit44-worker-private-result,
unit44-materialization-private-guard, unit44-channel-private-guard,
unit44-offline-runtime-shape and unit44-offline-runtime-strict. They require
the named deciding failures before the corresponding unchanged candidate test
passes on Linux. No mutant/control overlay is vetted or executed on Mac.

The parallel merge surface in grants is limited to
materialization_fix11_test.go, worker_fix10_test.go and the new
materialization_provenance_linux_test.go. The lifecycle surface is only
loop_fixture_test.go. Grant issuance, templates, guidance prerequisites and
all production lifecycle code remain unchanged. Guidance changes only its
CLI test's exact diagnostic expectation.

The supervisor must rerun all reported tests and the full normal/faults unit
box on the exact committed candidate. A further failure is a stopped check;
static vet and catalog matches cannot substitute for that run.

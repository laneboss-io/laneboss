# Review history and current launch-plan handoff

The following is the historical d4fix1 disposition against b89412b. The current
fix-11 consumer is codex-exec-v4 and retains the same legacy control IDs. Its
current wiring, unavailable inputs and 128 catalog controls (340 Go result rows in
total) are documented in [LAUNCH-PLAN.md](LAUNCH-PLAN.md). Historical static or
box results below are not acceptance for the current source. In particular,
F7's local startup helper does not create a valid retained-run start mode under
the fix-9 validators; that coordinated route remains explicit owner work.

## Historical d4fix1 disposition

This records d4fix1 relative to starting HEAD b89412b, including both counted reviews and the tool-mode addendum. Implementation and controls are authored; unit, red/candidate, vendor and installed-service execution are not performed on the authoring Mac. No green runtime result is inferred from static checks. Review findings are source observations unless the future Linux canaries demonstrate their effect.

| Item | Change or disposition | Test/control and remaining evidence |
| --- | --- | --- |
| F1 / G3 | The supervisor removed the unused wave-0 package before starting HEAD; stale README/scope wording is corrected. | No removal, staging or commit is performed by this round. |
| F2 | Resume argv order is unchanged. No pinned CLI/help is retained in the tree; the official reference fetch failed DNS resolution. | Pinned exec and exec-resume help, exact artifact/version and all live rows remain open. No source verification or runtime pass is claimed. |
| F3 | NewCredential requires the independently enrolled account hash; Install retains it, and refresh/match reject another account. | TestRefreshAccountPin / account-pin. Actual token exchange and account affinity remain a separate secrets-worker gate. |
| F4 | Lease intervals use service-recorded RFC3339Nano timestamps, preserving nanoseconds, and require non-overlap. | test_lease_intervals / lease-time. Contract §4 already says seq is configuration-wide; this adds an independent observation rather than claiming that contract says otherwise. |
| F5 | Binding takes context, trusted Service and CaptureRecord, then invokes SessionFromCapture. No public raw-byte binding path remains. | TestBindCaptureOnly / bind-source, plus inactive restart replay and its original c1-rebind control. |
| F6 | The complete canonical error object is matched to retained reviewed source; message-only errors need no invented code. | TestMessageLimit / message-limit is explicitly synthetic. No actual provider limit sample is supplied or newly certified. |
| F7 | Start can retry an unmapped next run after a service-origin quiescent end; it refuses every existing runner.session mapping. Reserve checks the preceding protected LastQuiesced target. | TestStartupRetry, TestStartupQuiescence / startup-retry, startup-mapped, startup-quiescence. Lifecycle must drain/reconcile captures before preparing that internal retry and retains budget/counters. |
| G1 | Human blob staging requests human.session with empty params on each command connection. | test_session_staging / staging-session, plus the original read-session control. |
| G2 | Each retained fixture chooses one preflight/effect route before execution. Error replies require no lane; committed launch Operations require their later measured failure and correlated launch.failed. | test_launch_effect / launch-effect. Contract public error transactions forbid writes/events/effects; a committed failure cannot also be that synchronous error. |
| G4 | Typed retained records use api.DecodeObject; auth keys are checked exactly before Go unmarshalling. Large vendor objects enforce duplicate, surrogate, finite-number and exact-integer checks. | TestAuthExactKeys, TestRequiredRecordFields, TestVendorJSONScalars / auth-alias, required-fields, json-surrogate, json-finite, json-integer. |
| G5 | Capture-derived events/objects require service origin, data requires capture class, prompt/task refs match committed metadata, and limits bind the reserved grant/life. | TestCaptureOrigin, TestCaptureClass, TestPromptMetadata, TestLimitGrantBinding / event-origin, object-origin, capture-class, prompt-metadata, limit-grant. |
| G6 | Every relevant project ancestor screens both config.toml and hooks.json through the existing bounded ordinary-file checks and redirection blacklist. | TestProjectHooks / project-hooks. Ordinary hooks/settings remain usable inside OS grants. |
| G7 | ReviewReceipt pass-through is reached even without life_id; prerequisite reads precede reached markers, and another assertion cannot kill the selected red target. | test_review_reached, test_red_target / review-reached, red-target. Unknown mutation IDs fail setup. |
| G8 | Both first runs release before continuation; review starts after all stop attempts, intermediate states and clean are awaited; supervisor driver/plant/child level are validated. | test_collection_waits, test_collection_stops_all, test_supervisor_inputs / collect-quiet, collect-state, collect-clean, collect-stop-all, supervisor-plant. Every stop failure is retained and fails collection. |
| G9 | A complete session prefix survives a later unfinished line; final limit analysis stays strict, trailing whitespace is allowed, and vendor lines use the 64 MiB object bound. | TestSessionPartialTail, TestSessionLargeLine / partial-tail, large-line. Private records/config remain at the smaller bound. |
| G10 | Audit/Matches recheck records/lease roots; failed binding/quiescence saves restore prior facts and poison reuse, and revoke close/final-save failures poison reuse. | TestControlRoots, TestQuiesceSaveFail, TestBindSaveFail, TestRevokeCloseFail / records-root, leases-root, quiesce-save, bind-save, revoke-close. |
| Addendum 2 | Existing argv mode pins remain explicit, generated sealed config repeats them, and a separate live turn must write and read unpredictable workspace bytes through actual tool capture/CLI reads. | TestInnerToolModes / inner-approval, inner-sandbox, home-approval, home-sandbox; test_workspace_probe / workspace-bytes, workspace-command. Pinned CLI citations/effective-mode evidence remain open for the same source-access reason as F2. |

The attempted public reference was https://developers.openai.com/codex/cli/reference/; no page was retrieved (`curl` exit 6, DNS resolution failure). There is no newly opened official citation supporting the existing resume order or mode keys. The order was not changed without a source. AdapterVersion is codex-exec-v2; reviewed receipts must be regenerated for this parser and include the actual pinned executable/helper, help/version observations, effective mode, real file-login/continuation and real limit data. A synthetic unit sample proves parsing only.

The authoritative contract references are [lifecycle and event rules](../../../../docs/design/v2-contracts.md), [public/internal write catalog](../../api/write_catalog.go) and [D2 isolation policy](../../../../docs/design/isolation.md). An Error transaction has no writes/events/effects/guards. Only the internal effect can append a later launch.failed. Each fixture fixes one failure_path in retained setup; there is no runtime fallback between outcomes. The public catalog does not dictate at which preparation stage every possible missing artifact/import error must be found, so the fixture must name that stage and its exact diagnostic in advance.

The live case stays at these nine assertion IDs. Each needs its targeted red artifact and unchanged candidate, actual exit/capture/collection evidence and the independently verified setup. These rows have not been run in this round.

| Live row | Required observed behavior |
| --- | --- |
| CODEX-TWO-TURN | Start, explicit resume and memory-only turn preserve the planted answer and private session/history; a separate tool turn writes and reads unpredictable workspace bytes. |
| CODEX-CONCURRENT | The two concurrent lives have distinct homes, histories and vendor sessions and expose no sibling answer. |
| CODEX-REFRESH | Both canonical-login lease intervals are complete, service-recorded and non-overlapping. |
| CODEX-OUTER | The actual outside read is denied with a real nonzero tool exit, while the independent same-UID unconfined control reads the canary. |
| CODEX-SESSION | The forged import reaches its exact declared preflight/effect validator and is refused with no agent execution. |
| CODEX-HELPER | The missing self-helper reaches its exact declared preflight/effect path and cannot execute an agent. |
| CODEX-AUTH | The sibling-only profile is refused by its intended authority check. |
| CODEX-COVERAGE | A falsely complete inventory is refused; a successful ReviewReceipt is a reached red failure. |
| CODEX-SUPERVISORS | Real Codex L4/L5/L6 lives spawn a lower child, turn it, wait for its real end and return the independent nonempty plant. |

Every Go row below requires red exit 1 with the reached selected test and its intended diagnostic, then candidate exit 0. Default and faults are separate result rows. A compile/setup failure, skipped test or empty selection never counts. The original requested 28 Go rows are explicitly retained:

| Default row | laneboss_faults row | Selected test |
| --- | --- | --- |
| h1-ordinary-default | h1-ordinary-faults | TestAuditOrdinaryArtifacts |
| h2-digest-default | h2-digest-faults | TestProtectedRecordsAndDigests |
| h3-revoke-default | h3-revoke-faults | TestRevokeRemovesAuthFirst |
| h4-root-default | h4-root-faults | TestAuditOpenRootIdentity |
| h4-parent-default | h4-parent-faults | TestCreatePrivateParent |
| h4-parent-type-default | h4-parent-type-faults | TestCreateRejectsOddParent |
| h5-reason-default | h5-reason-faults | TestSeedAndErrorReasons |
| h6-partial-default | h6-partial-faults | TestPartialSwapRetainsBothLeases |
| c1-rebind-default | c1-rebind-faults | TestBindAfterInactiveRestart |
| artifact-digest-default | artifact-digest-faults | TestArtifactPins/changed-bytes |
| session-history-default | session-history-faults | TestSessionHistoryBinding |
| capture-history-default | capture-history-faults | TestCaptureHistoryBinding/history |
| record-history-default | record-history-faults | TestReopenHistoryBinding |
| blob-metadata-default | blob-metadata-faults | TestBlobMetadata/prefix |

The review/tool-mode additions require these further Go rows (84 Go result rows in total):

| Default row | laneboss_faults row | Selected test |
| --- | --- | --- |
| account-pin-default | account-pin-faults | TestRefreshAccountPin |
| auth-alias-default | auth-alias-faults | TestAuthExactKeys |
| required-fields-default | required-fields-faults | TestRequiredRecordFields |
| json-surrogate-default | json-surrogate-faults | TestVendorJSONScalars/surrogate |
| json-finite-default | json-finite-faults | TestVendorJSONScalars/nonfinite |
| json-integer-default | json-integer-faults | TestVendorJSONScalars/integer |
| event-origin-default | event-origin-faults | TestCaptureOrigin/event |
| object-origin-default | object-origin-faults | TestCaptureOrigin/object |
| capture-class-default | capture-class-faults | TestCaptureClass |
| prompt-metadata-default | prompt-metadata-faults | TestPromptMetadata |
| message-limit-default | message-limit-faults | TestMessageLimit |
| limit-grant-default | limit-grant-faults | TestLimitGrantBinding |
| startup-retry-default | startup-retry-faults | TestStartupRetry/unmapped |
| startup-mapped-default | startup-mapped-faults | TestStartupRetry/mapped |
| startup-quiescence-default | startup-quiescence-faults | TestStartupQuiescence |
| project-hooks-default | project-hooks-faults | TestProjectHooks |
| records-root-default | records-root-faults | TestControlRoots/records |
| leases-root-default | leases-root-faults | TestControlRoots/leases |
| quiesce-save-default | quiesce-save-faults | TestQuiesceSaveFail |
| bind-save-default | bind-save-faults | TestBindSaveFail |
| revoke-close-default | revoke-close-faults | TestRevokeCloseFail |
| bind-source-default | bind-source-faults | TestBindCaptureOnly |
| partial-tail-default | partial-tail-faults | TestSessionPartialTail |
| large-line-default | large-line-faults | TestSessionLargeLine |
| inner-approval-default | inner-approval-faults | TestInnerToolModes |
| inner-sandbox-default | inner-sandbox-faults | TestInnerToolModes |
| home-approval-default | home-approval-faults | TestInnerToolModes |
| home-sandbox-default | home-sandbox-faults | TestInnerToolModes |

The original eight protocol red/candidate rows remain mandatory:

| Row | Selected test | Intended failure |
| --- | --- | --- |
| stream-snapshot | test_stream_snapshot | initial snapshot was dropped |
| stream-end | test_stream_end | stream EOF became completion |
| stream-correlation | test_stream_correlation | foreign frame was accepted |
| event-scope | test_event_scope | foreign life was accepted |
| read-session | test_read_proof | read proof did not open a connection session |
| release-counts | test_release_counts | unmeasured release became success |
| json-duplicates | test_json_shape | invalid JSON became evidence |
| evidence-path | test_evidence_path | evidence escaped its root |

These review/tool-mode protocol rows extend that result to 20 rows:

| Row | Selected test | Intended failure |
| --- | --- | --- |
| staging-session | test_session_staging | blob staging requested an operation proof |
| review-reached | test_review_reached | review pass-through did not reach assertion |
| launch-effect | test_launch_effect | synchronous error demanded for a committed launch |
| lease-time | test_lease_intervals | timestamp overlap was accepted |
| red-target | test_red_target | unrelated red assertion counted as reached |
| supervisor-plant | test_supervisor_inputs | empty supervisor word became a passing plant |
| collect-quiet | test_collection_waits | collection reviewer raced quiescence |
| collect-state | test_collection_waits | independent collection state decision is missing |
| collect-clean | test_collection_waits | collection clean flag was premature or absent |
| collect-stop-all | test_collection_stops_all | sibling stop was not attempted |
| workspace-bytes | test_workspace_probe | write probe trusted different bytes |
| workspace-command | test_workspace_probe | model text became a workspace read |

On the authorized disposable Linux machine run the complete package tests normally and with laneboss_faults, the two retained mutation drivers, the installed serve case and this live case. Preserve exact source/binary bytes and hashes, both drivers' results.json and per-row transcripts/exits, original prompts/help/provider samples, independent review and real resource collection. A Go/Python fixture is never an authenticated provider, kernel or human-presence result. Remaining owner work is in [CONTRACT-GAPS.md](CONTRACT-GAPS.md).

The authoring Mac's static checks exited 0 with empty diagnostics: gofmt -l for this Go package, whole-tree go vet for linux/amd64, linux/amd64 with laneboss_faults, and darwin/arm64, python3 -m py_compile for all four case Python files, bash -n for run.sh, and git diff --check. Exact commands, stdout/stderr and exits are retained in the external lane evidence. These static outcomes do not execute any of the unit, red/candidate or live rows above. No binary was built, staged or committed in this round.

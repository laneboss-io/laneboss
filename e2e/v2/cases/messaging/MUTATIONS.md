# Messaging red controls

Run these only on the authorized disposable Linux test box. The controller
does not edit the input checkout, stage files, create Git worktrees, contact
hosts, authenticate a model or send an owner message. Give it the exact
privacy-checked source artifact, including the current lane overlay.

For one mutation, from the supplied source root:

```sh
sh e2e/v2/cases/messaging/red.sh \
  --source "$PWD" \
  --work-root /test/evidence/lb-v2-messaging-red \
  --report /test/evidence/lb-v2-messaging-red/one.json \
  --mutation sender-recheck
```

For the complete catalog, use `--all` in place of `--mutation sender-recheck`.
Repeat with `--tags laneboss_faults` and a separate report/work directory to
measure that build variant. The controller checks Linux before executing any
project code. It never treats platform/setup failure as a passing red control.

Every mutation creates two plain source copies in its retained directory.
Exactly one reviewed semantic mutation is applied to the red copy; green
retains the original bytes. Each replacement anchor must match exactly once.
A stale or ambiguous anchor stops the phase. The channel-open recipe also
removes its newly unused import, so compilation remains a prerequisite.

For Go, the controller builds and retains the actual test executable with
`go test -c`, hashes it, then runs that executable through `go tool test2json`
with the exact focused test selector. For observers, it executes the copied
observer test against the copied acceptance checker. Red runs first. The
named test/subtest must fail with its specified assertion diagnostic. Only
then does the controller run the same test on the unchanged green copy.
Green must reach and pass the selected test with exit 0. A build failure,
panic, timeout, missing test, skip, unittest error, unrelated failure or surviving
mutation fails the controller and stops the matrix. There is no skip-as-pass.

`result.json` records which tests started, failed and passed, the actual exits,
and the scope of the claim. Inputs, before/after source bytes and hashes,
complete source copies/manifests, build/test commands and stdout/stderr remain
beside it. Go test binaries are retained with their hashes. The original source
and both copies are checked against the input hashes after testing. Failure
evidence is retained too. The summary exits 0 only if every requested mutation
was killed and its unchanged candidate then passed. It reports no product
E2E acceptance or process-containment result.

The named component mutations remove or invert real implementation checks:

| Acceptance rule | Mutation | Focused failing test or subtest |
| --- | --- | --- |
| Cross-root and unrelated enqueue refuse | enqueue-relation | TestMailRelations/a3-cousin3; the same suite includes cross-root cells |
| Different-parent equal-level peers refuse | peer-parent | TestMailRelations/a3-cousin3 |
| Actual same-parent peers succeed | peer-deny | TestMailRelations/a3-peer3 |
| Downward scope follows authentic ancestry | downward-root | TestMailRelations/a4-b3 |
| Ancestor to lower descendant succeeds | downward-deny | TestMailRelations/a5-a3; the same suite includes L5 to direct L3 |
| No upward skip | upward-skip | TestMailRelations/a3-a5 |
| Reports follow the direct starter | report-root | TestDirectReportAndReply |
| L3/L4 have no human-channel fallback | lower-human | TestChannelAndArtifactGates/a3; the same suite covers L4 |
| Select the exact current channel grant | grant-selection | TestChannelGrantExactness/missing |
| Expired channel grants refuse | grant-expiry | TestChannelGrantExactness/expired |
| Check every carried sender, including a later revoked sender | sender-recheck | TestTurnChecksEverySender |
| Recheck the relation at delivery | delivery-relation | TestDeliveryRelationRecheck |
| A cleaned/reused name creates no old rights | cleaned-life | TestLifeReuseAndLaunchDrift |
| A profile-limit run cannot return logical-turn mail | profile-end | TestReceiptUsesLogicalCompletion |
| A historical run cannot acknowledge a later run | receipt-run | TestReceiptRunAndOrigin/wrong-run |
| Imported history confers no live completion | receipt-origin | TestReceiptRunAndOrigin/legacy |
| Verified human mail to L3; identical unsigned mail refuses | human-proof | TestHumanMailNeedsProof |
| Retry returns the original queued receipt | retry-identity | TestQueueRetryAndConflict |
| File bytes match the committed length/hash | file-integrity | TestBlobBoundsAndHash/32 |
| Enqueue actor remains the actual requester | enqueue-actor | TestMailRelations/a3-peer3 |
| A different body cannot borrow an authenticated envelope | body-binding | TestEnvelopeBodyBinding |
| An unavailable unleased worker cannot return success | channel-open | TestInternalChannelStaysClosed |
| Unavailable receipt persistence cannot return success | receipt-open | TestReceiptUsesLogicalCompletion |
| CLI mail results retain the exact frozen shape | mail-result-schema | TestMailResultsStrict |
| CLI results retain a valid sender/source/sequence | mail-result-provenance | TestMailResultProvenance/sender |
| Mailbox result IDs and order remain unambiguous | mailbox-result-order | TestMailboxResultBounds/duplicate |
| Decoding cannot silently replace unpaired Unicode escapes | result-unicode | TestJSONUnicodeScalars |
| Stored completion payloads have the exact frozen shape | end-result-schema | TestReceiptEndShape/unknown-field |
| A run cannot have two authentic completion candidates | end-ambiguous | TestReceiptAmbiguousEnd |
| Delivery retains the original causal mail and queue sequence | turn-cause | TestReceiptCausalReferences/mail |
| Known exit requires actual exit-code or signal evidence | exit-evidence | TestReceiptExitEvidence/missing-exit |
| Receipt enums and timestamps are checked before observation lookup | receipt-input | TestReceiptExitEvidence/unknown-reason |
| Duplicate event IDs and unordered observations refuse | receipt-history | TestReceiptHistoryOrder/duplicate-id |

The following are **observer-only** mutations. They prove the checks used by
the actual black-box entry reject bad public observations. Their data fixtures
create no authentic lives or worker deliveries. They cannot close the product
gate while channel/receipt/lifecycle dependencies remain unavailable.

| Acceptance rule | Mutation | Focused observer test |
| --- | --- | --- |
| The receiving copy preserves the immutable sender | mail-provenance | Observations.test_mail_provenance |
| Human source/sender is actually human/dashboard | human-source | Observations.test_human_sender |
| Human raw history preserves original content/provenance | human-history | Observations.test_human_raw |
| Manual actor differs from a carried sender | manual-sender | Observations.test_manual_actor |
| Automatic actor remains scheduler | scheduler-sender | Observations.test_scheduler_actor |
| The delivery receipt targets the exact life/run | delivery-target | Observations.test_delivery_target |
| Receipt checks the actual exit and zero survivors | delivery-outcome | Observations.test_delivery_completion |
| An imported receipt cannot confer completion | delivery-history | Observations.test_delivery_origin |
| Granted L5/L6 channels reach every expected sink | channel-coverage | Observations.test_channel_delivery |
| Partial retry never duplicates a confirmed destination, even with a new key | retry-duplicate | Observations.test_partial_duplicate |
| Partial retry preserves the original external receipt | retry-stability | Observations.test_partial_stability |
| Destinations use distinct stable delivery keys | retry-key | Observations.test_delivery_key |

The observer suite also rejects a retry that leaves a destination missing via
`Observations.test_partial_missing`. The same channel-coverage mutation removes
that guarding coverage check, and the whole observer suite exercises both cells.

The literal first-carried-sender mutation in the real lifecycle producer and
the confirmed-send replay mutation in the real channel worker still require
those implementations/contracts. The component enqueue-actor and observer
manual/scheduler controls are distinct evidence, not substitutes. Full MSG-REL,
HUMAN-SEND, MSG-RECHECK, MSG-RETRY and MSG-ACTOR still run through run.sh with
actual service-created lives, human proof, worker delivery and collection.

The run-2 brief reports that slice 1 passed Ubuntu 24.04 component tests with
and without laneboss_faults in the combined wave-1 tree. This document makes no
claim that the new tests or this red/candidate matrix have been executed.

The run-3 brief separately reports that the combined Ubuntu 24.04 tree passed
the slice-2 messaging component tests with and without laneboss_faults. It
states that laneboss will execute the mutation matrix and report its result.
Slice 3 adds ten component mutations, for a catalog of 33 component and 12
observer controls. No slice-3 unit or matrix execution is claimed here.

Draft.4 preserves those 45 controls, refreshes enqueue/delivery relation
anchors, and moves cleaned-life to the actual RelationFacts.Revoked recipient
gate. It retains TestLifeReuseAndLaunchDrift and its exact forbidden diagnostic.
The old eligible anchor still exists but no longer controls that recipient
path, explaining why removing it does not reach the named assertion. Prior box
failure details beyond MutationFailure were not supplied; this source diagnosis
and refreshed recipe still require a red/candidate Linux run in both builds.

The added draft.4 controls are:

| Mutation | Required failing assertion |
| --- | --- |
| receipt-config | TestMailReplayBinding/lookup-config: want code integrity |
| proof-replay-shape | TestMailProofReplay/id: want code unauthenticated |
| lane-proof-replay | TestMailProofReplay: want code forbidden |
| sender-epoch | TestMailSenderEpoch: want code conflict |
| delivery-senders | TestBeginDeliveryChecks/later-grants: want code forbidden |
| delivery-mail-cas | TestBeginDeliveryChecks/mail-race: want code conflict |
| receipt-capture | TestRecordDeliveryChecks/capture: want code conflict |
| receipt-effect-actor | TestRecordDeliveryChecks/effect-actor: want code forbidden |
| receipt-mail-cas | TestRecordDeliveryChecks/mail-race: want code conflict |
| cli-retained-key | TestCLIProofInputs/key: wrong CLI refusal |
| cli-proof-upload | TestCLIProofInputs/proof: wrong CLI refusal |
| cli-content-ref | TestCLIContentRef: wrong content-reference refusal |
| mail-generation | Observations.test_mail_generation: CaseFailure not raised |

The CLI tests require exact intended diagnostics, so a later file/binding/setup
failure cannot satisfy a removed input gate. The human-proof control also
checks authorize directly, ensuring the intended missing-proof refusal is
tested independently of the store's additional atomic proof guard.

The runner retains before.source and anchors.json even when a recipe is stale,
and result.json names the stage. A red exit 0 records red_verdict=survived;
unreached assertions and setup/build failures retain failed status. Only the
targeted assertion followed by the same passing candidate earns killed. New
source-copy and phase directories are private. No draft.4 matrix outcome is
claimed from static checks.

The d4fix1 review migrates sender-recheck to the actual leased BeginDelivery
path and receipt-open to removal of RecordDelivery's real mail write. Their
existing assertion names and intended refusal/persistence obligations remain.
The old ValidateTurn and RecordReceipt compatibility helpers have no callers
and are removed. A parent turn uses a service-only read while retaining its
actual parent requester; it acquires no participant mailbox access.

| d4fix1 control | Required failing assertion |
| --- | --- |
| cli-input-registration | TestCLIFileInputs/mail.send-invalid: semantic file refusal was masked |
| contract-dependencies | TestContractDependencies: contracted construction failed |
| caller-before-replay | TestContractDependencies: want code forbidden |
| receipt-before-preflight | TestReplayOrderAndAuthority: receipt lookup order broke |
| human-current-key | TestHumanStoreProof: want code unauthenticated |
| turn-requester | TestParentTurnPrivacy/sibling: want code forbidden |
| continuation-receipt | TestReceiptContinuation/ready: profile continuation receipt failed |
| intent-actor | TestQueuedProvenance: internal delivery borrowed |
| queue-starter | TestQueuedProvenance: queued event lost |
| human-reply-link | TestHumanReplyLinks: human reply linkage |
| lane-human-reply | TestHumanReplyLinks: lane reply to its human sender was refused |
| shared-screen | TestSharedCredentialScreen: want code invalid_request |
| read-operation-proof | TestHumanMailboxBoundary/proof: want code forbidden |
| human-read-session | TestHumanMailboxBoundary/ready: verified human mailbox failed |
| mail-life-filter | TestHumanMailboxBoundary/filter: want code integrity |
| turn-after-queue | TestReceiptAfterQueue: want code integrity |
| capture-envelope | TestCaptureEventEnvelopes/schema: want code integrity |
| runner-reached | Observations.test_runner_reached: False is not true |
| runner-failure-exit | Observations.test_runner_exit: not greater than 0 |

The last two are observer/runner unit controls; they test the actual bridge and
failure-result writer without claiming an authenticated service operation.
Only Linux red/candidate output can establish killed. No d4fix1 execution result
is inferred from compilation or this table. The channel execution rows still
need the exact fixed worker inputs requested in CONTRACT-GAPS.md.

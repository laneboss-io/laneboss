"""Named guard removals. Component and observer evidence have distinct scope."""


CATALOG = {}


def go(name, file, test, before, after):
    if name in CATALOG:
        raise ValueError("duplicate mutation ID")
    CATALOG[name] = {"engine": "go", "scope": "component", "file": file,
                     "test": test, "edits": [[before, after]]}


def observe(name, test, *edits):
    if name in CATALOG:
        raise ValueError("duplicate mutation ID")
    CATALOG[name] = {"engine": "observer", "scope": "observer", "file": "run.py",
                     "test": "checks_test.CheckTests." + test, "edits": list(edits)}


def evidence_case(name):
    return "TestEvidenceRedControls/" + name


go("L1-stream", "signals.go", "TestTextNeverStructured",
   "structured := index == 0 && format == JSONLines",
   'structured := strings.HasPrefix(cleanMessage(string(raw)), "{")')
go("L1-format", "signals.go", "TestTextNeverStructured",
   "Outcome{Format: format, ExitCode:", 'Outcome{Format: "", ExitCode:')
go("L2-size", "signals.go", "TestOversizedRecordThenLimit",
   "result.OversizedRecords++\n\t\t\t\tcontinue", 'return result, errors.New("oversized record abort")')
go("L3-source", "signals.go", "TestSourcedSignalWins",
   "if result.Signals[prior].Candidate && !signal.candidate {", "if false {")
go("L4-lines", "signals.go", "TestNestedMultilineErrors",
   "strings.FieldsFunc(message, func(r rune) bool { return r == '\\r' || r == '\\n' })", "[]string{message}")
go("L4-api", "signals.go", "TestNestedMultilineErrors",
   "matches != nil && depth < maxErrorDepth {", "matches != nil && depth < maxErrorDepth && false {")
go("L4-nested", "signals.go", "TestNestedMultilineErrors",
   'if nested, exists := doc["error"]; exists {', 'if nested, exists := doc["error"]; exists && false {')
go("L4-depth", "signals.go", "TestNestedMultilineErrors",
   "const maxErrorDepth = 2", "const maxErrorDepth = 64")
go("actor", "evidence.go", evidence_case("lane-capture"),
   'event.Actor.Role == "" {', 'event.Actor.Role == "" || event.Actor.Kind == "lane" {')
go("containment", "evidence.go", evidence_case("nil-survivors"),
   'if observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 {',
   'if (observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0) && false {')
go("room", "evidence.go", evidence_case("expired-room"),
   "if room.ProfileID != grant.ProfileID || checked.After(now) ||\n"
   "\t\tnow.Sub(checked) > maxRoomAge || !expires.After(now) || !expires.After(checked) {",
   "if (room.ProfileID != grant.ProfileID || checked.After(now) ||\n"
   "\t\tnow.Sub(checked) > maxRoomAge || !expires.After(now) || !expires.After(checked)) && false {")
go("blob-hash", "evidence.go", "TestCaptureBytesHash",
   "if int64(len(result)) != ref.Bytes || digest(result) != ref.SHA256 {", "if int64(len(result)) != ref.Bytes {")
go("capture", "evidence.go", "TestQuotaValidation",
   "if err := s.verifyCapture(ctx, run.captures, signal, observation); err != nil {",
   "if err := s.verifyCapture(ctx, run.captures, signal, observation); false {")
go("adapter", "evidence.go", evidence_case("no-adapter-limit"),
   "if corroborated == nil || !sameLimitCause(*corroborated, signal) {",
   "if (corroborated == nil || !sameLimitCause(*corroborated, signal)) && false {")
go("origin", "evidence.go", evidence_case("observation-capture"),
   'if event.Origin != "service" {',
   'if event.Origin != "service" && event.Origin != "observation" {')
go("profile-scope", "evidence.go", "TestEligibilityDoesNotExpand",
   " || grant.Driver != active.Driver ||\n\t\t\tgrant.Provider != active.Provider", "")
go("paid-budget", "evidence.go", "TestEligibilityDoesNotExpand",
   "(grant.Paid && lane.BudgetRemaining.SpendMicros <= 0)", "false")
go("budget-empty", "evidence.go", "TestLaneGates/budget",
   "if b.WallMS <= 0 || b.SpendMicros < 0 || b.MemoryBytes == 0 || b.DiskBytes == 0 || b.Processes == 0 {",
   "if (b.WallMS <= 0 || b.SpendMicros < 0 || b.MemoryBytes == 0 || b.DiskBytes == 0 || b.Processes == 0) && false {")
go("grant-live", "evidence.go", "TestGrantValidity",
   "if grants.Revoked || !expires.After(now) {", "if (grants.Revoked || !expires.After(now)) && false {")
go("grant-recheck", "evidence.go", evidence_case("changed-grants"),
   "if !reflect.DeepEqual(checked, grants) {", "if !reflect.DeepEqual(checked, grants) && false {")
go("run-binding", "evidence.go", evidence_case("pid-reuse"),
   "if observation.Handle != handle {", "if observation.Handle != handle && false {")
go("stale-run", "evidence.go", "TestLaneGates/stale-run",
   "if lane.LifeID != target.LifeID || lane.Run != target.Run {",
   "if (lane.LifeID != target.LifeID || lane.Run != target.Run) && false {")
go("cleaned", "evidence.go", "TestLaneGates/cleaned", "if lane.Cleaned {", "if lane.Cleaned && false {")
go("manual-cas", "evidence.go", evidence_case("manual-race"),
   "if !reflect.DeepEqual(current, lane) {", "if !reflect.DeepEqual(current, lane) && false {")
go("cancel-mark", "context.go", "TestRecordedControl/watchdog.cancelled",
   'return problem(api.CodeCancelled, "watchdog intent was cancelled")', "continue")
go("stopped-mark", "context.go", "TestRecordedControl",
   'return problem(api.CodeCancelled, "manual control or revocation cancelled this run")', "continue")
go("cancel-recovery", "service.go", "TestRecoveryGates/cancelled",
   'if err := controlError(events, target, lane.LogicalTurnID); err != nil {', 'if err := controlError(events, target, lane.LogicalTurnID); false {')
go("backoff", "service.go", "TestRecoveryGates/early",
   "if s.deps.Clock.Now().Before(waitUntil) {", "if s.deps.Clock.Now().Before(waitUntil) && false {")
go("forged-recovery", "evidence.go", "TestRecoveryGates/forged",
   'event.Actor.Role == "" {', 'event.Actor.Role == "" || event.Actor.Kind == "lane" {')
go("backoff-bound", "service.go", "TestBackoffAndInitialization",
   "if previous >= maxBackoff.Milliseconds()/2 {", "if previous >= maxBackoff.Milliseconds()/2 && false {")
go("no-room", "evidence.go", "TestPlanInvariants/no-room",
   "\t\tif room.Available {\n\t\t\trequest :=", "\t\tif !room.Available {\n\t\t\trequest :=")
go("exit-clock", "evidence.go", "TestClockReceipts/exit",
   "quiescent(observation, run.handle, signal, observationNow)",
   "quiescent(observation, run.handle, signal, observeStarted)")
go("room-clock", "evidence.go", "TestClockReceipts/room",
   "\n\tif err := validateRoom(room, grant, now); err != nil {", "\n\tif err := validateRoom(room, grant, checkedFrom); err != nil {")
go("final-room", "evidence.go", "TestClockReceipts/final-room",
   "\t\t\t\tif err := validateRoom(result.Swap.Room, grant, now); err != nil {",
   "\t\t\t\tif err := validateRoom(result.Swap.Room, grant, now); false {")
go("final-grant", "evidence.go", "TestClockReceipts/final-grant",
   "if err := currentGrants(grants, lane, launch, now); err != nil {",
   "if err := currentGrants(grants, lane, launch, now); false {")

go("model-exclusion", "evidence.go", "TestEligibilityReceipts/excluded",
   "if !eligibility.Compatible {", "if !eligibility.Compatible && false {")
go("eligibility-binding", "evidence.go", "TestEligibilityReceipts/model",
   "receipt.Request != request || checked.After(now)", "false || checked.After(now)")
go("turn-snapshot", "context.go", "TestTurnSnapshot/task",
   "turn.Task != lane.Task ||", "false ||")
go("turn-status", "context.go", "TestTurnSnapshot/status",
   'if turn.Status != "running" {', 'if turn.Status != "running" && false {')
go("counter-reset", "journal.go", "TestIntentHandoff",
   "lane := plan.Lane\n\tlane.Generation++", "lane := plan.Lane\n\tlane.Counters = api.TaskCounters{}\n\tlane.Generation++")
go("budget-reset", "journal.go", "TestIntentHandoff",
   "lane := plan.Lane\n\tlane.Generation++", "lane := plan.Lane\n\tlane.BudgetRemaining.SpendMicros++\n\tlane.Generation++")
go("pending-room", "journal.go", "TestPendingFreshness/room",
   "if err := validateRoom(intent.Swap.Room, grant, now); err != nil {",
   "if err := validateRoom(intent.Swap.Room, grant, now); false {")
go("pending-eligibility", "journal.go", "TestPendingFreshness/eligibility",
   "if err := validateEligibility(receipt, request, now); err != nil {",
   "if err := validateEligibility(receipt, request, now); false {")
go("pending-context", "journal.go", "TestPendingFreshness",
   "grant, err := s.pendingGrant(ctx, lane, intent)",
   "grant, err := api.ProfileGrant{ProfileID: intent.Swap.ToProfileID}, error(nil)")
# Missing history is rejected both by presence and by operation binding.
# Disable that one fault in both checks; a present wait still needs its own
# matching operation, which waiting-operation independently exercises.
go("waiting-record", "service.go", "TestWaitingHistory/missing",
   "if waiting && previous == 0 {\n"
   '\t\treturn api.Operation{}, problem(api.CodeIntegrity, "waiting intent has no durable waiting event")\n'
   "\t}\n\tif waiting && waitingOperation != operation {",
   "if waiting && previous == 0 && false {\n"
   '\t\treturn api.Operation{}, problem(api.CodeIntegrity, "waiting intent has no durable waiting event")\n'
   "\t}\n\tif waiting && previous > 0 && waitingOperation != operation {")
go("waiting-delay", "service.go", "TestWaitingHistory/shrinking",
   " || payload.RetryAfterMS < previous", "")
go("waiting-time", "service.go", "TestWaitingHistory/early-record",
   " || (previous > 0 && at.Before(waitUntil))", "")
go("waiting-operation", "service.go", "TestWaitingHistory/orphan-current",
   "if waiting && waitingOperation != operation {", "if waiting && waitingOperation != operation && false {")
go("pending-control", "journal.go", "TestPendingControl/pending",
   "if err := controlError(events, intent.Target, intent.LogicalTurnID); err != nil {", "if err := controlError(events, intent.Target, intent.LogicalTurnID); false {")
go("life-control", "context.go", "TestControlActorsAndScope",
   "if event.Run != 0 && event.Run != target.Run {", "if event.Run != target.Run {")
go("turn-control", "context.go", "TestTurnControlSequence/new-run",
   'if event.Kind == "lane.turn" && launchSeq != 0 && event.Seq > launchSeq &&',
   'if event.Kind == "lane.turn" && launchSeq != 0 && event.Seq > launchSeq && false &&')
go("own-turn-order", "context.go", "TestOwnTurnAfterLaunch",
   '(event.Run == 0 || event.Run >= target.Run) && event.LogicalTurnID != "" && event.LogicalTurnID != turn', "true")
go("turn-run-scope", "context.go", "TestTurnRunScope/old-run",
   '(event.Run == 0 || event.Run >= target.Run) && ', "")
go("no-live-cancel", "journal.go", "TestCancelWithoutLiveIntent",
   'if !found {', 'if !found && false {')
go("terminal-cancel", "journal.go", "TestCancelWithoutLiveIntent",
   'if found && (prior.Status == "cancelled" || prior.Status == "completed") {',
   'if found && (prior.Status == "cancelled" || prior.Status == "completed") && false {')
go("cancel-next-run", "journal.go", "TestCancelClaimedNextRun",
   '!(found && prior.Status == "claimed" && lane.Run == target.Run+1)', "true")
go("cancel-wait-state", "journal.go", "TestCancelJournal/waiting",
   'lane.State = "verifying"', 'lane.State = "profile_wait"')
go("cancel-double-epoch", "journal.go", "TestCancelAdvancedEpoch",
   "if lane.CancellationEpoch == prior.CancellationEpoch && lane.Run == target.Run {", "if lane.CancellationEpoch >= prior.CancellationEpoch && lane.Run == target.Run {")
go("cancel-next-epoch", "journal.go", "TestCancelClaimedNextRun",
   "if lane.CancellationEpoch == prior.CancellationEpoch && lane.Run == target.Run {", "if lane.CancellationEpoch == prior.CancellationEpoch {")
go("stale-room-reassess", "journal.go", "TestPendingReassessment/progress",
   "if err := validateRoom(intent.Swap.Room, grant, now); err != nil {\n\t\tif errors.Is(err, errReceiptStale) {",
   "if err := validateRoom(intent.Swap.Room, grant, now); err != nil {\n\t\tif errors.Is(err, errReceiptStale) && false {")
go("stale-eligibility-reassess", "journal.go", "TestPendingFreshness/eligibility",
   "if err := validateEligibility(receipt, request, now); err != nil {\n\t\tif errors.Is(err, errReceiptStale) {",
   "if err := validateEligibility(receipt, request, now); err != nil {\n\t\tif errors.Is(err, errReceiptStale) && false {")
go("malformed-reassess", "journal.go", "TestPendingMalformed/profile",
   "if err := validateRoom(intent.Swap.Room, grant, now); err != nil {\n\t\tif errors.Is(err, errReceiptStale) {",
   "if err := validateRoom(intent.Swap.Room, grant, now); err != nil {\n\t\tif true {")
go("usage-producer", "usage.go", "TestUsageEvidence/producer",
   "if err := api.ValidateUsageWindow(evidence, request, provenance.Producer, s.deps.Clock.Now()); err != nil {",
   "if err := api.ValidateUsageWindow(evidence, request, provenance.Producer, s.deps.Clock.Now()); false {")
go("usage-freshness", "usage.go", "TestUsageEvidence/stale",
   "if err := api.ValidateUsageWindow(evidence, request, provenance.Producer, s.deps.Clock.Now()); err != nil {",
   "if err := api.ValidateUsageWindow(evidence, request, provenance.Producer, s.deps.Clock.Now()); false {")
go("usage-exhaustion", "usage.go", "TestUsageEvidence/available",
   "if err := api.ValidateUsageWindow(evidence, request, provenance.Producer, s.deps.Clock.Now()); err != nil {",
   "if err := api.ValidateUsageWindow(evidence, request, provenance.Producer, s.deps.Clock.Now()); false {")
go("usage-source", "usage.go", "TestUsageEvidence/tsv-percent",
   "if err := api.ValidateUsageSource(evidence, raw, provenance.VendorProfile); err != nil {",
   "if err := api.ValidateUsageSource(evidence, raw, provenance.VendorProfile); false {")
go("usage-private", "usage.go", "TestUsageEvidence/acl",
   "metadata.ACL.Owner != provenance.Producer.Record.Actor || metadata.SourceOperationID != operation ||",
   "metadata.SourceOperationID != operation ||")
go("usage-reset-current", "usage.go", "TestUsageEvidence/reset",
   "if !reset.After(s.deps.Clock.Now()) {", "if !reset.After(s.deps.Clock.Now()) && false {")
go("policy-refresh", "evidence.go", "TestFreshPolicy",
   "lane, err = s.freshPolicy(ctx, lane, policy)", "lane, err = s.currentLane(ctx, signal.Target)")
go("waiting-policy-backoff", "journal.go", "TestWaitingPolicyBackoff",
   'if intent.Status == "waiting" {\n\t\treturn s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)\n\t}',
   'if intent.Status == "waiting" {\n'
   '\t\tpolicy, err := s.policyForLane(ctx, lane)\n'
   '\t\tif err != nil {\n\t\t\treturn api.Operation{}, err\n\t\t}\n'
   '\t\tif _, err := s.freshPolicy(ctx, lane, policy); err != nil {\n\t\t\treturn api.Operation{}, err\n\t\t}\n'
   '\t\treturn s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)\n\t}')
go("pending-policy-order", "journal.go", "TestPendingPolicyRefusalStable",
   'if generation != lane.PolicyGeneration {\n\t\treturn s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)',
   'if generation != lane.PolicyGeneration {\n'
   '\t\tif _, err := s.freshPolicy(ctx, lane, policy); err != nil {\n\t\t\treturn api.Operation{}, err\n\t\t}\n'
   '\t\treturn s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)')
go("limit-policy-order", "evidence.go", "TestRefusedLimitPolicyStable/usage",
   'result.Lane = lane\n\tif err := s.liveTurn(ctx, lane, signal.Target); err != nil {',
   'earlyPolicy, err := s.policyForLane(ctx, lane)\n'
   '\tif err != nil {\n\t\treturn result, err\n\t}\n'
   '\tlane, err = s.freshPolicy(ctx, lane, earlyPolicy)\n'
   '\tif err != nil {\n\t\treturn result, err\n\t}\n'
   '\tresult.Lane = lane\n\tif err := s.liveTurn(ctx, lane, signal.Target); err != nil {')
go("pending-usage-age", "journal.go", "TestPendingUsageAge/expired",
   'if now.Sub(usageObserved) > 30*time.Second {',
   'if now.Sub(usageObserved) > 30*time.Second && false {')
go("pending-usage-boundary", "journal.go", "TestPendingUsageAge/fresh-boundary",
   'if now.Sub(usageObserved) > 30*time.Second {',
   'if now.Sub(usageObserved) >= 30*time.Second {')
go("pending-usage-future", "journal.go", "TestPendingUsageEnvelope/future",
   'if usageObserved.After(now) {', 'if usageObserved.After(now) && false {')
go("pending-usage-target", "usage.go", "TestPendingUsageEnvelope/target",
   'evidence.ID != ref.ID || evidence.Target != intent.Target || evidence.LaunchID != lane.LaunchID ||',
   'evidence.ID != ref.ID || evidence.LaunchID != lane.LaunchID ||')
go("policy-receipt", "context.go", "TestPolicyRefreshReceipt",
   "if err := api.ValidatePolicyAdvance(lane, request, policy, receipt); err != nil {",
   "if err := api.ValidatePolicyAdvance(lane, request, policy, receipt); false {")
go("policy-history", "context.go", "TestPolicyHistory",
   'if policy.Generation != generation || !validDigest.MatchString(string(policy.SHA256)) || policy.Context.Level != lane.Level || policy.Context.Role != lane.Role {',
   'if (policy.Generation != generation || !validDigest.MatchString(string(policy.SHA256)) || policy.Context.Level != lane.Level || policy.Context.Role != lane.Role) && false {')
go("retained-policy-replay", "journal.go", "TestRetainedPolicyReplay",
   'if intent.Status == "completed" {', 'if intent.Status == "completed" && false {')
go("policy-exclusion", "evidence.go", "TestPolicyExclusion",
   " || excluded(policy, grant.ProfileID)", "")
go("task-class", "evidence.go", evidence_case("task-class"), ' || lane.Task.Class != "task"', "")
go("capture-class", "evidence.go", evidence_case("capture-class"), ' || selected.Data.Class != "capture"', "")
go("blob-class", "evidence.go", evidence_case("unknown-class"), "!blobClass(ref.Class) || ", "")
go("limit-duplicates", "journal.go", "TestOneLimitEvent", "if generation == 0 {", "if generation >= 0 {")
go("intent-replay", "service.go", "TestIntentReplay",
   "\n\tif found {\n\t\tif prior.Status", "\n\tif found && false {\n\t\tif prior.Status")
go("intent-epoch", "journal.go", "TestWaitEpoch",
   "if lane.CancellationEpoch != intent.CancellationEpoch {",
   "if lane.CancellationEpoch != intent.CancellationEpoch && false {")
go("commit-life", "journal.go", "TestCommitCAS/life",
   "{Kind: api.CompareLane, ID: lane.LifeID, Generation: plan.Lane.Generation},", "")
go("commit-grants", "journal.go", "TestCommitCAS/grants",
   "{Kind: api.CompareGrants, ID: plan.Grants.ID, Generation: plan.Grants.Generation},", "")
go("commit-intent", "journal.go", "TestCommitCAS/intent",
   "{Kind: api.CompareContinuation, ID: intent.ID, Generation: generation},", "")
go("commit-epoch", "journal.go", "TestCommitCAS/epoch",
   "Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}},",
   "Guards: nil,")
go("durable-cancel", "journal.go", "TestCancelJournal",
   "lane.CancellationEpoch++", "lane.CancellationEpoch += 0")
go("cancelled-intent", "journal.go", "TestCancelledIntentPriority",
   'if intent.Status == "cancelled" {', 'if intent.Status == "cancelled" && false {')
go("commit-readback", "journal.go", "TestJournalFailures/missing-write",
   "if !found || stored.Generation < intent.Generation || !reflect.DeepEqual(stored.Swap.Limit, signal) {",
   "if found && false {")
go("claim-readback", "journal.go", "TestCommitRecovery/claimed",
   "stored.Generation < intent.Generation", "stored.Generation != intent.Generation")
go("operation-binding", "journal.go", "TestOperationBinding",
   "if err := api.ValidateContinuationOperation(current, request, operation); err != nil {",
   "if err := api.ValidateContinuationOperation(current, request, operation); false {")
go("completed-receipt", "journal.go", "TestCompletedReplay",
   'if err := api.ValidateContinuationOperation(retained, api.ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}, operation); err != nil {',
   'if err := api.ValidateContinuationOperation(retained, api.ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}, operation); false {')
go("shared-operation-phase", "journal.go", "TestFix10Operation/pending-success",
   "if err := api.ValidateContinuationOperation(current, request, operation); err != nil {",
   "if err := api.ValidateContinuationOperation(current, request, operation); false {")
go("shared-selection-phase", "journal.go", "TestFix10SelectionReceipt",
   'if err := api.ValidateContinuationOperation(retained, api.ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}, operation); err != nil {',
   'if err := api.ValidateContinuationOperation(retained, api.ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}, operation); false {')
go("claimed-operation", "journal.go", "TestFix10Operation/swapped-operation",
   'if err := api.ValidateContinuationOperation(retained, api.ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}, operation); err != nil {',
   'if err := api.ValidateContinuationOperation(retained, api.ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}, operation); false {')
go("reserved-life-pins", "launch.go", "TestFix10LaunchPins/role",
   "r.Level != lane.Level || r.Role != lane.Role || r.Driver != lane.Session.Driver ||",
   "false ||")
go("capture-disposition", "launch.go", "TestFix10LaunchPins/refused",
   'if capture.Status == "refused" {', 'if capture.Status == "refused" && false {')
go("capture-eof", "launch.go", "TestFix10LaunchPins/eof",
   " || !position.EOF", "")
go("capture-refusal-event", "context.go", "TestFix10RefusedEvent",
   "return capture.Refusal", "continue")
go("live-capture-binding", "evidence.go", evidence_case("capture-binding"),
   "if capture.BindingID != captureBinding.ID {", "if capture.BindingID != captureBinding.ID && false {")
go("current-run", "service.go", "TestCurrentRunSnapshot",
   "s.readScope(), api.LifeRef{LifeID: target.LifeID})", "s.readScope(), target)")
go("swap-fence", "journal.go", "TestIntentHandoff",
   "IntentID: intent.ID, Swap: intent.Swap,", "IntentID: intent.ID, Swap: api.ProfileSwap{},")
go("paid-escalation", "evidence.go", "TestPaidProfileAffinity/free-to-paid",
   " || (grant.Paid && !active.Paid)", "")
go("write-preflight", "service.go", "TestWriteCatalogPreflight",
   "if err := api.ValidateTransactionShape(transaction); err != nil {",
   "if err := api.ValidateTransactionShape(transaction); false {")

observe("obs-valid", "test_valid", ('current["session"] == baseline["session"]', 'current["session"] != baseline["session"]'))
observe("obs-human-refusal", "test_human_peer_refusal",
        ('and self.context.get("human_reader_handoff_available") is False', 'and True'))
observe("obs-usage-retention", "test_usage_evidence",
        ('usage.get("class") == "usage_window" and bool(usage.get("id"))\n'
         '                and isinstance(usage.get("sha256"), str) and len(usage["sha256"]) == 64\n'
         '                and type(usage.get("bytes")) is int and usage["bytes"] > 0', 'True'))
observe("obs-turn", "test_turn",
        ('and bool(current.get("logical_turn_id")) and current.get("logical_turn_id") == baseline.get("logical_turn_id"),', 'and True,'))
observe("obs-history", "test_history", ('current["session"] == baseline["session"]', "True"))
observe("obs-counters", "test_counters", ('current["counters"] == baseline["counters"]', "True"))
observe("obs-task", "test_task", ('current["task"] == baseline["task"]', "True"))
observe("obs-eligibility", "test_eligibility", ('bool(swap["eligibility_id"])', "True"))
observe("obs-shared-operation", "test_operation_lineage", ('and launches[0]["operation_id"] == swap["operation_id"]', "and True"))
observe("obs-live-binding", "test_live_capture_binding", ('and bool(capture[0].get("binding_id"))', "and True"))
observe("obs-epoch", "test_epoch",
        ('swap["cancellation_epoch"] == baseline["cancellation_epoch"] == current["cancellation_epoch"]', "True"))
observe("obs-history-id", "test_history_id",
        ('current["session"] == baseline["session"]', "True"),
        ('current["session"]["history_id"] == baseline["session"]["history_id"]', "True"))
observe("obs-independent", "test_independent_canary", ('check["target_present"] is True', "True"))
observe("obs-restart", "test_restart_loss",
        ('and recovered["session"] == baseline["session"] and recovered["workspace"] == baseline["workspace"]',
         'and True and recovered["workspace"] == baseline["workspace"]'))
observe("obs-budget", "test_budget", ("0 <= after[field] <= before[field]", "0 <= after[field]"))
observe("obs-failure", "test_quota_failure", ('and ends[0]["payload"].get("profile_continuation") is True', "and True"))
observe("obs-mail", "test_mail", ('len(delivered) == 1 and len(receipts) == 1', "bool(delivered)"))
observe("obs-capture", "test_capture", (' and capture[0]["primary"]', ""))
observe("obs-room", "test_room", ('room["available"] and ', ""))
observe("obs-actor", "test_actor",
        ('event["origin"] == "service" and event["actor"]["kind"] == "watchdog"\n'
         '                and not event["actor"].get("life_id")', "True"))
observe("obs-wait", "test_wait",
        ('and (utc(following["recorded_at"]) - utc(prior["recorded_at"])).total_seconds() * 1000 >= delay', "and True"))
observe("obs-restore", "test_restore",
        ('self.status(life)["run"] == baseline["run"], "exhausted room advanced before restoration"',
         'True, "exhausted room advanced before restoration"'))
observe("obs-tamper", "test_tamper",
        ('self.status(life)["run"] == baseline["run"]\n'
         '                    and not any(e["kind"] == "watchdog.swapped" for e in self.events(life))', "True"))
observe("obs-canary", "test_canary", ('all(self.denied_probe(r) for r in reports)', 'all(True for r in reports)'))
observe("obs-real-limit", "test_real_limit",
        ('        self.continuation(life, baseline, nonce)', '        if False:\n            self.continuation(life, baseline, nonce)'))
observe("obs-stop", "test_stop",
        ('not any(e["kind"] == "lane.resumed" and e["seq"] > stops[0]["seq"] for e in events)', "True"))

observe("obs-reached", "test_reached_failures",
        ('self.results[active]["reached"] and not isinstance(error, SetupFailure)', 'False'))
observe("obs-runtime-error", "test_runtime_cli_errors",
        ('observed_exit=completed.returncode)\n        try:', 'reached=False, observed_exit=completed.returncode)\n        try:'),
        ('and not isinstance(error, SetupFailure)', 'and error.reached and not isinstance(error, SetupFailure)'))
observe("obs-missing-exit", "test_missing_optional_fields",
        ('type(ends[0]["payload"]["observation"].get("exit_code")) is int', 'True'),
        ('type(swap["limit"].get("exit_code")) is int', 'True'))

next_run = [
    ('require(current["run"] <= run + 1,', 'require(True,'),
    ('return current if current["run"] == run + 1 else None', 'return current if current["run"] > run else None'),
]
observe("obs-next-run", "test_run", *next_run,
        (' and swap["continuation_run"] == baseline["run"] + 1', ""),
        ('current["run"] == baseline["run"] + 1 and ', ""))
observe("obs-resume", "test_resume", *next_run,
        ('require(observed["run"] <= baseline["run"] + 1,', 'require(True,'),
        ('len(launches) == 1 and self.status(life)["run"] == baseline["run"] + 1', 'bool(launches)'))

observe("obs-control-nonce", "test_control_nonce",
        ('("case_id", "request_id", "nonce", "binary_sha256")', '("case_id", "request_id", "binary_sha256")'))
observe("obs-control-exit", "test_control_restart", ('result["old_exited"] is True', "True"))
observe("obs-control-containment", "test_control_canary", ('result["containment_state"] == "exited"', "True"))
observe("obs-control-writer", "test_control_writer", ('credentials == [peer]', "True"))
for name in ("obs-control-nonce", "obs-control-exit", "obs-control-containment", "obs-control-writer"):
    CATALOG[name]["file"] = "controls.py"

observe("obs-human-read", "test_human_cli",
        ('argv.extend(["--proof", str(proof)])', 'argv.extend([])'))
observe("obs-fresh-session", "test_human_cli",
        ('self.read_proof_serial += 1', 'self.read_proof_serial = 1'))
observe("obs-dashboard-scope", "test_human_cli",
        ('if not method.startswith("dashboard."):', 'if True or not method.startswith("dashboard."):'))

# These controls belong to real lifecycle/broker/OS implementations. A test
# double of Continue cannot establish the service's consumed-once slot claim.
BLOCKED = {
    "slot-double-lease": "The contract assigns slot claims to lifecycle/secrets; their actual runtime mutation is still required.",
    "continue-twice": "Watchdog reuses its intent; lifecycle's consumed-once claim must be mutated in the installed service.",
    "disable-watchdog": "Actual lane UID/file/signal canaries need the installed OS/service fixture.",
}

"""Exact source edits for disposable copies; never production fault switches."""


def lines(*items):
    return "\n".join(items) + "\n"


def component(file, test, rules, description, before, after, diagnostic, failed=None):
    return {
        "scope": "component", "language": "go",
        "path": ["internal", "v2", "messaging", file],
        "test": test, "must_fail": failed or test, "assertions": rules,
        "description": description, "edits": [{"before": before, "after": after}],
        "diagnostic": diagnostic,
    }


def observer(test, rules, description, before, after=""):
    return {
        "scope": "observer", "language": "python",
        "path": ["e2e", "v2", "cases", "messaging", "observations.py"],
        "test": "Observations." + test, "must_fail": "Observations." + test,
        "assertions": rules, "description": description,
        "edits": [{"before": before, "after": after}],
        "diagnostic": "CaseFailure not raised",
    }


MUTATIONS = {
    "enqueue-relation": component(
        "queue.go", "TestMailRelations", ["MSG-REL"],
        "Remove the enqueue relationship check, including cross-root refusal.",
        lines('\t\tif err := relation(relationFacts(from), to); err != nil {', '\t\t\treturn api.Mail{}, err', '\t\t}'), "",
        "want code forbidden", "TestMailRelations/a3-cousin3"),
    "peer-parent": component(
        "routing.go", "TestMailRelations", ["MSG-REL"],
        "Let equal-level common-root lives bypass the direct-parent peer rule.",
        'if from.Level == to.Level && from.ParentLifeID != "" && from.ParentLifeID == to.ParentLifeID && reflect.DeepEqual(from.StarterChain, to.StarterChain) {',
        'if from.Level == to.Level {',
        "want code forbidden", "TestMailRelations/a3-cousin3"),
    "peer-deny": component(
        "routing.go", "TestMailRelations", ["MSG-REL"],
        "Invert the peer level equality so valid same-parent peers refuse.",
        'if from.Level == to.Level && from.ParentLifeID != ""',
        'if from.Level != to.Level && from.ParentLifeID != ""',
        "mail enqueue receipt", "TestMailRelations/a3-peer3"),
    "downward-root": component(
        "routing.go", "TestMailRelations", ["MSG-REL"],
        "Replace authentic descendant traversal with a common-root level check.",
        lines('\tif from.Level > to.Level {', '\t\tfor i, ancestor := range to.StarterChain {',
              '\t\t\tif ancestor == from.LifeID && reflect.DeepEqual(to.StarterChain[:i], from.StarterChain) {',
              '\t\t\t\treturn nil', '\t\t\t}', '\t\t}', '\t}'),
        lines('\tif from.Level > to.Level {', '\t\treturn nil', '\t}'),
        "want code forbidden", "TestMailRelations/a4-b3"),
    "downward-deny": component(
        "routing.go", "TestMailRelations", ["MSG-REL"],
        "Invert the downward level check so valid ancestor messages refuse.",
        '\tif from.Level > to.Level {', '\tif from.Level < to.Level {',
        "mail enqueue receipt", "TestMailRelations/a5-a3"),
    "upward-skip": component(
        "routing.go", "TestMailRelations", ["MSG-REL"],
        "Drop the direct-starter requirement for upward messages.",
        lines('\tif from.ParentLifeID == to.LifeID && from.Level < to.Level {',
              '\t\tif reflect.DeepEqual(from.StarterChain[:len(from.StarterChain)-1], to.StarterChain) {',
              '\t\t\treturn nil', '\t\t}',
              '\t\treturn problem(api.CodeIntegrity, "direct starter projections disagree on ancestry")', '\t}'),
        lines('\tif from.Level < to.Level {', '\t\treturn nil', '\t}'),
        "want code forbidden", "TestMailRelations/a3-a5"),
    "report-root": component(
        "stub.go", "TestDirectReportAndReply", ["MSG-REL"],
        "Route a direct report to the root instead of its actual starter.",
        'target.RecipientLifeID = from.ParentLifeID', 'target.RecipientLifeID = from.RootLifeID',
        "direct report/reply"),
    "lower-human": component(
        "routing.go", "TestChannelAndArtifactGates", ["MSG-REL"],
        "Remove the L3/L4 human-channel level refusal.",
        lines('\tif from.Level < 5 || from.Level > 6 {',
              '\t\treturn api.ChannelGrant{}, problem(api.CodeForbidden, "L3 and L4 report to their direct starter and have no human-channel fallback")', '\t}'), "",
        "want code forbidden", "TestChannelAndArtifactGates/a3"),
    "grant-selection": component(
        "routing.go", "TestChannelGrantExactness", ["MSG-REL"],
        "Select any owned channel instead of the exact requested grant ID.",
        '\t\tif grant.ID == id {', '\t\tif grant.ID != "" {',
        "want code forbidden", "TestChannelGrantExactness/missing"),
    "grant-expiry": component(
        "routing.go", "TestChannelGrantExactness", ["MSG-REL"],
        "Stop checking the selected channel grant's expiry.",
        'if found == nil || !future(found.ExpiresAt, s.deps.Clock.Now()) {', 'if found == nil {',
        "want code forbidden", "TestChannelGrantExactness/expired"),
    "sender-recheck": component(
        "delivery.go", "TestTurnChecksEverySender", ["MSG-RECHECK"],
        "Remove every carried sender's delivery-time rights recheck.",
        lines('\t\tsenderCompares, err := s.deliverySender(ctx, scope, to, mail.Sender)',
              '\t\tif err != nil {', '\t\t\treturn api.DeliveryBatch{}, err', '\t\t}',
              '\t\tcompares = append(compares, senderCompares...)'), "",
        "want code forbidden"),
    "delivery-relation": component(
        "turn.go", "TestDeliveryRelationRecheck", ["MSG-RECHECK"],
        "Keep grant checks but omit delivery-time relationship revalidation.",
        lines('\tif err := relation(from, relationFacts(to)); err != nil {', '\t\treturn nil, err', '\t}'), '', "want code forbidden"),
    "cleaned-life": component(
        "routing.go", "TestLifeReuseAndLaunchDrift", ["MSG-RECHECK"],
        "Remove the retired-life refusal from the relation-only recipient projection.",
        'if row.Revoked || row.State == "merged" || row.State == "abandoned" {',
        'if row.State == "merged" || row.State == "abandoned" {', "want code forbidden"),
    "profile-end": component(
        "turn.go", "TestReceiptUsesLogicalCompletion", ["MSG-ACTOR", "HUMAN-SEND"],
        "Permit a profile-limit run to return carried logical-turn mail.",
        lines('\tif end.ProfileContinuation || end.Reason == "limit" {',
              '\t\treturn problem(api.CodeConflict, "a profile-limit run cannot acknowledge or return logical-turn mail")', '\t}'), "",
        "want code conflict"),
    "receipt-run": component(
        "turn.go", "TestReceiptRunAndOrigin", ["HUMAN-SEND"],
        "Let an earlier run's end satisfy the selected receipt run.",
        'if event.Run == receipt.Target.Run && turnSeq != 0 && event.Seq > turnSeq {',
        'if turnSeq != 0 && event.Seq > turnSeq {',
        "want code conflict", "TestReceiptRunAndOrigin/wrong-run"),
    "receipt-origin": component(
        "turn.go", "TestReceiptRunAndOrigin", ["HUMAN-SEND"],
        "Let imported history confer authentic receipt completion.",
        'event.Origin != "service" || event.Config != scope.Config', 'event.Config != scope.Config',
        "want code conflict", "TestReceiptRunAndOrigin/legacy"),
    "human-proof": component(
        "routing.go", "TestHumanMailNeedsProof", ["HUMAN-SEND"],
        "Bypass the human proof path, including its verifier, after body decoding.",
        '\tif scope.Actor.Kind == "human" && api.Methods[method].Mutation && request.Proof == nil {',
        lines('\tif scope.Actor.Kind == "human" {', '\t\treturn nil', '\t}').rstrip('\n') + '\n' +
        '\tif scope.Actor.Kind == "human" && api.Methods[method].Mutation && request.Proof == nil {',
        "want code unauthenticated"),
    "retry-identity": component(
        "queue.go", "TestQueueRetryAndConflict", ["MSG-RETRY"],
        "Bind the mail ID to a request attempt instead of the stable operation key.",
        'string(scope.Request.Method), string(scope.Request.IdempotencyKey),',
        'string(scope.Request.Method), string(scope.Request.IdempotencyKey), string(scope.Request.RequestID),',
        "retry did not return the original enqueue receipt"),
    "file-integrity": component(
        "queue.go", "TestBlobBoundsAndHash", ["MSG-REL", "HUMAN-SEND"],
        "Remove the uploaded content identity, size and hash check.",
        lines('\tif chunk.ObjectID != ref.ID || chunk.Offset != 0 || int64(len(chunk.Data)) != ref.Bytes || hashBytes(chunk.Data) != chunk.SHA256 || hashBytes(chunk.Data) != ref.SHA256 {',
              '\t\treturn nil, problem(api.CodeIntegrity, "mail bytes differ from the committed blob reference")', '\t}'), "",
        "want code integrity", "TestBlobBoundsAndHash/32"),
    "enqueue-actor": component(
        "queue.go", "TestMailRelations", ["MSG-ACTOR"],
        "Replace the real enqueue requester with an invented worker actor.",
        'Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID,',
        'Actor: api.Actor{Kind: "service", ID: "mail-worker"}, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID,',
        "mail intent, actor and delivery effect", "TestMailRelations/a3-peer3"),
    "body-binding": component(
        "routing.go", "TestEnvelopeBodyBinding", ["HUMAN-SEND"],
        "Let a module use a body different from its authenticated envelope.",
        lines('\tif !reflect.DeepEqual(body, copy.Elem().Interface()) {',
              '\t\treturn problem(api.CodeIntegrity, "messaging body differs from its authenticated request")', '\t}'), "",
        "want code integrity"),
    "channel-open": component(
        "internal.go", "TestInternalChannelStaysClosed", ["MSG-REL"],
        "Pretend an unleased channel worker succeeded without delivering.",
        'return api.NotImplemented("lb-v2-messaging", "internal.channel")', 'return nil',
        "want code not_implemented"),
    "receipt-open": component(
        "delivery.go", "TestReceiptUsesLogicalCompletion", ["HUMAN-SEND"],
        "Return a receipt operation without persisting its actual mail state.",
        'Events:  []api.Event{event}, Writes: api.StateWrites{Mail: []api.Mail{mail}}',
        'Events:  []api.Event{event}', "receipt persistence did not update mail"),
    "mail-provenance": observer(
        "test_mail_provenance", ["MSG-REL", "HUMAN-SEND"],
        "Stop comparing the receiving mailbox's immutable sender.",
        'fields = ("id", "sender", "recipient_life_id", "channel_grant_id",',
        'fields = ("id", "recipient_life_id", "channel_grant_id",'),
    "human-source": observer(
        "test_human_sender", ["HUMAN-SEND"],
        "Stop checking the dashboard's actual human sender and derived source.",
        lines('    require(sender["kind"] == "human" and bool(sender["id"]) and',
              '            not sender.get("life_id") and sender.get("level", 0) == 0 and',
              '            not sender.get("role") and mail["source"] == "dashboard",',
              '            "dashboard mail lacks its actual human sender/source")')),
    "human-history": observer(
        "test_human_raw", ["HUMAN-SEND"],
        "Accept a raw-history entry whose content differs from the original mail.",
        lines('    for name in ("sender", "recipient_life_id", "content", "source", "queued_seq", "artifacts"):',
              '        require(copies[0][name] == original[name],',
              '                "human raw history changed mail provenance or bytes")')),
    "manual-sender": observer(
        "test_manual_actor", ["MSG-ACTOR"],
        "Accept the first carried sender as the manual turn actor.",
        lines('        require(turn["actor"] == requester,',
              '                "manual turn actor borrowed a carried sender")')),
    "scheduler-sender": observer(
        "test_scheduler_actor", ["MSG-ACTOR"],
        "Accept a carried sender as an automatic scheduler turn actor.",
        lines('        require(actor["kind"] == "scheduler" and bool(actor["id"]) and',
              '                not actor.get("life_id") and actor.get("level", 0) == 0 and not actor.get("role"),',
              '                "automatic turn actor borrowed a carried sender")')),
    "delivery-target": observer(
        "test_delivery_target", ["HUMAN-SEND"],
        "Ignore the delivery receipt's target life and run binding.",
        lines('    require(target["life_id"] == recipient and event["life_id"] == recipient and',
              '            target["run"] == event["run"] and type(target["run"]) is int and target["run"] > 0,',
              '            "delivery receipt targets a different life or run")')),
    "delivery-outcome": observer(
        "test_delivery_completion", ["HUMAN-SEND", "MSG-ACTOR"],
        "Accept a receipt without checking the actual outside process outcome.",
        lines('    require(end["payload"]["reason"] == "exit" and',
              '            end["payload"]["profile_continuation"] is False and',
              '            observed["state"] == "exited" and observed["handle"]["target"] == target and',
              '            type(observed.get("survivors")) is int and observed["survivors"] == 0 and',
              '            type(observed.get("exit_code")) is int and observed["exit_code"] == 0 and',
              '            observed.get("signal") is None and observed["prompt_status"] == "completed" and',
              '            observed["observed_at"] == receipt["observed_at"],',
              '            "mail receipt inferred completion from an uncertain or limited process")')),
    "delivery-history": observer(
        "test_delivery_origin", ["HUMAN-SEND"],
        "Allow a legacy-import observation to stand in for a service receipt.",
        '                if event["origin"] == "service" and\n                event["kind"] in ("mail.delivered", "mail.returned") and',
        '                if event["kind"] in ("mail.delivered", "mail.returned") and'),
    "channel-coverage": observer(
        "test_channel_delivery", ["MSG-REL", "MSG-RETRY"],
        "Call a channel send complete despite absent destination receipts.",
        lines('    require(set(channels) == expected, "confirmed channel destinations are missing or unexpected")')),
    "retry-duplicate": observer(
        "test_partial_duplicate", ["MSG-RETRY"],
        "Allow the same confirmed destination to appear twice under fresh keys.",
        lines('    require(len(rows) == len(channels), "duplicate confirmed channel delivery")')),
    "retry-stability": observer(
        "test_partial_stability", ["MSG-RETRY"],
        "Stop preserving the original already-confirmed external receipt.",
        lines('    for channel, original in prior.items():',
              '        require(confirmed[channel] == original,',
              '                "retry changed an already confirmed external send")')),
    "retry-key": observer(
        "test_delivery_key", ["MSG-RETRY"],
        "Allow different confirmed destinations to share a delivery key.",
        lines('    require(len({row["delivery_key"] for row in rows}) == len(rows),',
              '            "confirmed channel deliveries reused a delivery key")')),
}

# Removing the only api call in this particular fixed entry also removes its
# now-unused import. A compiler error must never count as a killed mutation.
MUTATIONS["channel-open"]["edits"].append({
    "before": '\n\t"laneboss.io/laneboss/internal/v2/api"\n', "after": "\n",
})

# Slice 3 keeps these result/receipt checks in the same disposable-copy
# protocol. The real entry calls these decoders; they are not test substitutes.
MUTATIONS.update({
    "mail-result-schema": component(
        "results.go", "TestMailResultsStrict", ["MSG-REL", "HUMAN-SEND"],
        "Decode a mail result without its exact frozen JSON shape.",
        'if err := decodeBody(raw, &mail); err != nil {',
        'if err := json.Unmarshal(raw, &mail); err != nil {', "want code integrity"),
    "mail-result-provenance": component(
        "results.go", "TestMailResultProvenance", ["MSG-REL", "HUMAN-SEND"],
        "Accept a decoded result without validating its sender provenance.",
        lines('\tif err := validStoredMail(mail); err != nil {', '\t\treturn api.Mail{}, err', '\t}'), "",
        "want code integrity", "TestMailResultProvenance/sender"),
    "mailbox-result-order": component(
        "results.go", "TestMailboxResultBounds", ["MSG-REL"],
        "Permit duplicate IDs unless queue order is also invalid.",
        'if seen[mail.ID] || mail.QueuedSeq <= previous {',
        'if seen[mail.ID] && mail.QueuedSeq <= previous {',
        "want code integrity", "TestMailboxResultBounds/duplicate"),
    "result-unicode": component(
        "validation.go", "TestJSONUnicodeScalars", ["MSG-REL", "HUMAN-SEND"],
        "Silently normalize unpaired Unicode escapes instead of refusing them.",
        ' || !jsonUnicodeScalars(raw)', "", "want code invalid_request"),
    "end-result-schema": component(
        "receipts.go", "TestReceiptEndShape", ["HUMAN-SEND"],
        "Decode a stored run end while ignoring unexpected or missing fields.",
        'if err := decodeBody(raw, &end); err != nil {',
        'if err := json.Unmarshal(raw, &end); err != nil {',
        "want code integrity", "TestReceiptEndShape/unknown-field"),
    "end-ambiguous": component(
        "turn.go", "TestReceiptAmbiguousEnd", ["HUMAN-SEND"],
        "Select the last favorable end instead of rejecting ambiguous run history.",
        lines('\t\t\t\t\tif end != nil {',
              '\t\t\t\t\t\treturn problem(api.CodeIntegrity, "mail completion has more than one authentic end for the selected run")', '\t\t\t\t\t}'), "",
        "want code integrity"),
    "turn-cause": component(
        "turn.go", "TestReceiptCausalReferences", ["MSG-ACTOR", "HUMAN-SEND"],
        "Acknowledge a turn without the original causal mail and queue sequence.",
        lines('\t\t\t\t\t\tif !validTurnCause(turn.Trigger, mail) {',
              '\t\t\t\t\t\t\treturn problem(api.CodeIntegrity, "mail turn lost its original causal mail or queue sequence")', '\t\t\t\t\t\t}'), "",
        "want code integrity", "TestReceiptCausalReferences/mail"),
    "exit-evidence": component(
        "receipts.go", "TestReceiptExitEvidence", ["HUMAN-SEND", "MSG-ACTOR"],
        "Let a known process exit omit both exit code and termination signal.",
        'if (observation.ExitCode == nil) == (observation.Signal == nil) {',
        'if observation.ExitCode != nil && observation.Signal != nil {',
        "want code integrity", "TestReceiptExitEvidence/missing-exit"),
    "receipt-input": component(
        "turn.go", "TestReceiptExitEvidence", ["HUMAN-SEND"],
        "Skip the receipt input's closed prompt, cause and timestamp validation.",
        lines('\tif err := validReceiptInput(receipt); err != nil {', '\t\treturn err', '\t}'), "",
        "want code invalid_request", "TestReceiptExitEvidence/unknown-reason"),
    "receipt-history": component(
        "turn.go", "TestReceiptHistoryOrder", ["HUMAN-SEND"],
        "Permit duplicate event IDs unless sequence order is also invalid.",
        'if eventIDs[event.ID] || event.Seq <= previousSeq {',
        'if eventIDs[event.ID] && event.Seq <= previousSeq {',
        "want code integrity", "TestReceiptHistoryOrder/duplicate-id"),
    "receipt-config": component(
        "queue.go", "TestMailReplayBinding", ["MSG-RETRY", "HUMAN-SEND"],
        "Accept a retained receipt from a different configuration.",
        'receipt.Config != scope.Config || ', '',
        "want code integrity", "TestMailReplayBinding/lookup-config"),
    "sender-epoch": component(
        "queue.go", "TestMailSenderEpoch", ["MSG-RECHECK"],
        "Queue a new delivery after the sender's cancellation epoch changes.",
        lines('\tif scope.Actor.Kind == "lane" {',
              '\t\tguards = append(guards, api.TransactionGuard{Cancellation: &api.CancellationCheck{LifeID: from.LifeID, Epoch: from.CancellationEpoch}})', '\t}'), '',
        "want code conflict"),
    "delivery-senders": component(
        "delivery.go", "TestBeginDeliveryChecks", ["MSG-RECHECK"],
        "Begin a leased batch without checking every sender's current rights.",
        lines('\t\tsenderCompares, err := s.deliverySender(ctx, scope, to, mail.Sender)',
              '\t\tif err != nil {', '\t\t\treturn api.DeliveryBatch{}, err', '\t\t}',
              '\t\tcompares = append(compares, senderCompares...)'), '',
        "want code forbidden", "TestBeginDeliveryChecks/later-grants"),
    "delivery-mail-cas": component(
        "delivery.go", "TestBeginDeliveryChecks", ["MSG-RECHECK"],
        "Omit the mail generation CAS when beginning a leased delivery.",
        lines('\t\tcompares = append(compares, api.Compare{Kind: api.CompareMail, ID: mail.ID, Generation: mail.Generation})'), '',
        "want code conflict", "TestBeginDeliveryChecks/mail-race"),
    "receipt-capture": component(
        "delivery.go", "TestRecordDeliveryChecks", ["HUMAN-SEND"],
        "Acknowledge a receipt without its correlated prompt and capture.",
        lines('\tif err := s.receiptCaptures(ctx, scope, request); err != nil {',
              '\t\treturn api.Operation{}, err', '\t}'), '',
        "want code conflict", "TestRecordDeliveryChecks/capture"),
    "receipt-effect-actor": component(
        "delivery.go", "TestRecordDeliveryChecks", ["MSG-ACTOR", "HUMAN-SEND"],
        "Use a foreign executor's effect as the current service's receipt authority.",
        'parent.Actor != scope.Actor || ', '',
        "want code forbidden", "TestRecordDeliveryChecks/effect-actor"),
    "receipt-mail-cas": component(
        "delivery.go", "TestRecordDeliveryChecks", ["MSG-RECHECK", "HUMAN-SEND"],
        "Omit the mail generation CAS from the observed receipt commit.",
        '{Kind: api.CompareMail, ID: mail.ID, Generation: request.ExpectedGeneration}, ', '',
        "want code conflict", "TestRecordDeliveryChecks/mail-race"),
    "proof-replay-shape": component(
        "routing.go", "TestMailProofReplay", ["HUMAN-SEND", "MSG-RETRY"],
        "Replay a human result without validating the proof reference identity.",
        lines('\tif request.Proof != nil && (!validID(request.Proof.ID) || request.Proof.RequestSHA256 != request.RequestSHA256 || !validTimestamp(request.Proof.ExpiresAt)) {',
              '\t\treturn problem(api.CodeUnauthenticated, "mail proof has invalid identity or intent binding")', '\t}'), '',
        "want code unauthenticated", "TestMailProofReplay/id"),
    "lane-proof-replay": component(
        "routing.go", "TestMailProofReplay", ["HUMAN-SEND", "MSG-RETRY"],
        "Allow a lane to attach a human proof to a completed mutation retry.",
        lines('\tif scope.Actor.Kind == "lane" && request.Proof != nil {',
              '\t\treturn problem(api.CodeForbidden, "lane mail cannot carry human proof")', '\t}'), '',
        "want code forbidden"),
    "mail-generation": observer(
        "test_mail_generation", ["MSG-REL"],
        "Stop checking committed mail generations and artifact arrays.",
        lines('    require(type(original.get("generation")) is int and original["generation"] > 0 and',
              '            type(kept.get("generation")) is int and kept["generation"] >= original["generation"] and',
              '            isinstance(original.get("artifacts"), list) and isinstance(kept.get("artifacts"), list),',
              '            "mail has an invalid generation or artifact array")')),
})

# These execute the actual CLI entry through messaging's external test package.
# The mutations remove an input gate; an arbitrary later failure is rejected by
# the exact per-cell diagnostic before the unchanged candidate can be accepted.
MUTATIONS["cli-retained-key"] = component(
    "commands_messaging.go", "TestCLIProofInputs", ["MSG-RETRY"],
    "Generate a fresh mutation key instead of requiring its retained input.",
    lines('\t\tif api.Methods[method].Mutation {',
          '\t\t\treturn options, lbV2MessagingError(api.CodeInvalid, "messaging mutation requires --idempotency-key ID retained for retries")', '\t\t}'), '',
    "wrong CLI refusal", "TestCLIProofInputs/key")
MUTATIONS["cli-proof-upload"] = component(
    "commands_messaging.go", "TestCLIProofInputs", ["HUMAN-SEND"],
    "Start an inline upload after the user already confirmed a different ref.",
    lines('\tif options.file != "" && call.ProofFile != "" {',
          '\t\treturn options, lbV2MessagingError(api.CodeInvalid, "a confirmed message requires --content-ref or --request; upload before confirmation")', '\t}'), '',
    "wrong CLI refusal", "TestCLIProofInputs/proof")
MUTATIONS["cli-content-ref"] = component(
    "commands_messaging.go", "TestCLIContentRef", ["HUMAN-SEND"],
    "Suppress the exact class/shape validation failure of a committed ref.",
    lines('\t\tif err != nil {',
          '\t\t\treturn api.BlobRef{}, lbV2MessagingError(api.CodeInvalid, "content reference must be an exact committed report blob")', '\t\t}'), '',
    "wrong content-reference refusal")
for name in ("cli-retained-key", "cli-proof-upload", "cli-content-ref"):
    MUTATIONS[name]["path"] = ["internal", "v2", "cli", "commands_messaging.go"]

MUTATIONS.update({
    "contract-dependencies": component(
        "stub.go", "TestContractDependencies", ["MSG-REL"],
        "Require the uncontracted authenticator again at service construction.",
        'if deps.Store == nil || deps.Clock == nil {',
        'if deps.Store == nil || deps.Clock == nil || deps.Authenticator == nil {',
        "contracted construction failed"),
    "caller-before-replay": component(
        "routing.go", "TestContractDependencies", ["MSG-RETRY"],
        "Replay before checking the caller's canonical current grants.",
        lines('\tif scope.Actor.Kind == "lane" {', '\t\tfrom, err := s.currentSender(ctx, scope)',
              '\t\tif err != nil {', '\t\t\treturn err', '\t\t}',
              '\t\t_, err = s.currentGrants(ctx, scope, from)', '\t\treturn err', '\t}'), '',
        "want code forbidden"),
    "receipt-before-preflight": component(
        "queue.go", "TestReplayOrderAndAuthority", ["MSG-RETRY"],
        "Remove receipt lookup so target preflight runs on an identical retry.",
        lines('\tif mail, found, err := s.replayMail(ctx, scope); found || err != nil {', '\t\treturn mail, err', '\t}'), '',
        "receipt lookup order broke"),
    "turn-requester": component(
        "delivery.go", "TestParentTurnPrivacy", ["MSG-ACTOR"],
        "Let a sibling replace the actual controlling ancestor in a turn claim.",
        lines('\trequesterCompares, err := s.turnRequester(ctx, scope, to, batch.Intent.RequestedBy)',
              '\tif err != nil {', '\t\treturn api.DeliveryBatch{}, err', '\t}',
              '\tcompares = append(compares, requesterCompares...)'), '',
        "want code forbidden", "TestParentTurnPrivacy/sibling"),
    "continuation-receipt": component(
        "delivery.go", "TestReceiptContinuation", ["MSG-ACTOR", "HUMAN-SEND"],
        "Require the initial run on a logical turn's actual final receipt.",
        'if continuation && parent != nil {', 'if false && continuation && parent != nil {',
        "profile continuation receipt failed", "TestReceiptContinuation/ready"),
    "intent-actor": component(
        "queue.go", "TestQueuedProvenance", ["MSG-ACTOR"],
        "Use the public caller as an internal delivery executor.",
        'Actor: api.Actor{Kind: "service", ID: "mail-delivery"}, RequestedBy: scope.Actor,',
        'Actor: scope.Actor, RequestedBy: scope.Actor,',
        "internal delivery borrowed"),
    "queue-starter": component(
        "queue.go", "TestQueuedProvenance", ["MSG-ACTOR"],
        "Drop the sending life's authentic starter event sequence.",
        'StarterEventSeq: subject.StarterEventSeq,', '', "queued event lost"),
    "human-reply-link": component(
        "queue.go", "TestHumanReplyLinks", ["HUMAN-SEND"],
        "Require a human-channel grant on a human reply to a lower lane's report.",
        '} else if prior.Sender.Kind != "lane" || prior.Sender.LifeID != request.RecipientLifeID {',
        '} else if prior.Sender.Kind != "lane" || prior.Sender.LifeID != request.RecipientLifeID || prior.ChannelGrantID == "" {',
        "human reply linkage"),
    "lane-human-reply": component(
        "queue.go", "TestHumanReplyLinks", ["HUMAN-SEND"],
        "Reject a lane's reply to the human who addressed it.",
        'if prior.RecipientLifeID != scope.Actor.LifeID || prior.Sender.Kind != "human" {',
        'if prior.RecipientLifeID != scope.Actor.LifeID || prior.Sender.Kind != "lane" {',
        "lane reply to its human sender was refused"),
    "shared-screen": component(
        "screen.go", "TestSharedCredentialScreen", ["MSG-REL", "HUMAN-SEND"],
        "Remove the shared detector for Unicode and punctuation credential shapes.",
        'if credentialtext.HasCredential(text) {', 'if false && credentialtext.HasCredential(text) {',
        "want code invalid_request"),
    "read-operation-proof": component(
        "routing.go", "TestHumanMailboxBoundary", ["HUMAN-SEND"],
        "Allow an operation proof as ambient authority on a mail read.",
        lines('\tif !api.Methods[method].Mutation && request.Proof != nil {',
              '\t\treturn problem(api.CodeForbidden, "mail reads require a bound session, not an operation proof")', '\t}'), '',
        "want code forbidden", "TestHumanMailboxBoundary/proof"),
    "mail-life-filter": component(
        "stub.go", "TestHumanMailboxBoundary", ["HUMAN-SEND"],
        "Ignore a human mailbox request's exact life filter.",
        lines('\t\tif request.LifeID != "" && mail.Sender.LifeID != request.LifeID && mail.RecipientLifeID != request.LifeID {',
              '\t\t\treturn api.MailPage{}, problem(api.CodeIntegrity, "store returned mail outside the requested life filter")', '\t\t}'), '',
        "want code integrity", "TestHumanMailboxBoundary/filter"),
    "turn-after-queue": component(
        "turn.go", "TestReceiptAfterQueue", ["HUMAN-SEND"],
        "Accept a turn observation before its original queue sequence.",
        lines('\t\t\t\t\t\tif event.Seq <= mail.QueuedSeq {',
              '\t\t\t\t\t\t\treturn problem(api.CodeIntegrity, "mail turn precedes its authentic queue event")', '\t\t\t\t\t\t}'), '',
        "want code integrity"),
    "capture-envelope": component(
        "captures.go", "TestCaptureEventEnvelopes", ["HUMAN-SEND"],
        "Accept a primary capture observation with an invalid event schema.",
        'event.Schema != api.SchemaVersion || ', '',
        "want code integrity", "TestCaptureEventEnvelopes/schema"),
    "human-current-key": component(
        "authority.go", "TestHumanStoreProof", ["HUMAN-SEND", "MSG-RETRY"],
        "Replay a human receipt after its enrolled credential is revoked.",
        'if key.ID == credential && key.Generation > 0 && !key.Revoked {',
        'if key.ID == credential && key.Generation > 0 {',
        "want code unauthenticated"),
    "human-read-session": component(
        "stub.go", "TestHumanMailboxBoundary", ["HUMAN-SEND"],
        "Do not carry the connection's verified session into a human mailbox read.",
        lines('\tif scope.Actor.Kind == "human" && scope.Connection != nil {', '\t\tvar err error',
              '\t\tscope, err = api.WithReadAuthority(ctx, scope)', '\t\tif err != nil {',
              '\t\t\treturn api.MailPage{}, err', '\t\t}', '\t}'), '',
        "verified human mailbox failed", "TestHumanMailboxBoundary/ready"),
})

MUTATIONS["cli-input-registration"] = component(
    "commands_messaging.go", "TestCLIFileInputs", ["MSG-REL", "HUMAN-SEND"],
    "Drop the mail.send semantic validator registration from the real CLI.",
    lines('\t\t{"mail.send", func(raw json.RawMessage) error { _, err := messaging.DecodeMailSend(raw); return err }},'), '',
    "semantic file refusal was masked", "TestCLIFileInputs/mail.send-invalid")
MUTATIONS["cli-input-registration"]["path"] = ["internal", "v2", "cli", "commands_messaging.go"]
MUTATIONS["runner-reached"] = observer(
    "test_runner_reached", ["HUMAN-SEND"], "Leave the first human bridge failure unreached.",
    lines('    def bridge(self, endpoint, request):', '        if self.active:', '            self.results[self.active]["reached"] = True'),
    lines('    def bridge(self, endpoint, request):'))
MUTATIONS["runner-reached"]["path"][-1] = "run.py"
MUTATIONS["runner-reached"]["diagnostic"] = "False is not true"
MUTATIONS["runner-failure-exit"] = observer(
    "test_runner_exit", ["HUMAN-SEND"], "Record exit zero after an observer rejects public output.",
    'self.results[self.active]["observed_exit"] = self.last_exit or 1',
    'self.results[self.active]["observed_exit"] = self.last_exit')
MUTATIONS["runner-failure-exit"]["path"][-1] = "run.py"
MUTATIONS["runner-failure-exit"]["diagnostic"] = "not greater than 0"

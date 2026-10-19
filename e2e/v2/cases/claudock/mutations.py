#!/usr/bin/env python3
"""Credential-free unit red/green controls, on the Linux test box only.

Every mutation is built in a separate retained source snapshot. A compiler,
setup or unrelated-test failure does not count as a killed mutation.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


PACKAGE = "./internal/v2/runner/claudock"
OWNED = Path("internal/v2/runner/claudock")
CASE = Path("e2e/v2/cases/claudock")


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise RuntimeError("mutation anchor is missing or ambiguous")
    return text.replace(before, after, 1)


def function_body(text, signature, replacement):
    start = text.index(signature)
    finish = text.find("\nfunc ", start + len(signature))
    if finish < 0:
        raise RuntimeError("mutation function boundary is missing")
    return text[:start] + signature + "\n" + replacement + "\n}\n" + text[finish:]


def mutate(text, name):
    if name == "usage-input-id-reuse":
        return replace_once(text, '\tsuffix, err := newUUID()\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n',
                            '\tsuffix := fmt.Sprint(r.Target.Run)\n')
    if name == "home-parent-privacy-bypass":
        return replace_once(text, 'if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {\n\t\treturn nil, failure(api.CodeIntegrity, "private home parent must be protected")',
                            'if err != nil || !info.IsDir() {\n\t\treturn nil, failure(api.CodeIntegrity, "private home parent must be protected")')
    if name == "records-privacy-bypass":
        return replace_once(text, "canonical != directory || statErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0",
                            "canonical != directory || statErr != nil || !info.IsDir()")
    if name == "ordinary-tool-refusal":
        return replace_once(text, "return findings, nil", "if len(findings) != 0 { return findings, ownedError(ErrOwnedType) }; return findings, nil")
    if name == "owned-file-bypass":
        return function_body(text, "func ownedFile(r *os.Root, name string, optional bool) error {", "return nil // deliberate red mutation")
    if name == "generated-digest-bypass":
        return replace_once(text, "contentDigest(data) != expected", "contentDigest(data) != expected && len(data) < 0")
    if name == "binding-bypass":
        return replace_once(text, "record.Session != request.Session || record.Home != request.Home || record.Model != request.Model",
                            "(record.Session != request.Session || record.Home != request.Home || record.Model != request.Model) && len(record.Model) == 0")
    if name == "root-identity-bypass":
        return replace_once(text, "!os.SameFile(info, after) || !os.SameFile(info, h.identity)",
                            "(!os.SameFile(info, after) && after == nil) || !os.SameFile(info, h.identity)")
    if name == "copy-rotation-bypass":
        return replace_once(text, "copied := !info.Mode().IsRegular() || linked(info)", "copied := !info.Mode().IsRegular()")
    if name == "close-returns-early":
        return replace_once(text, 'failures = append(failures, failure(api.CodeIntegrity, "credential root close failed"))',
                            'failures = append(failures, failure(api.CodeIntegrity, "credential root close failed")); return report, errors.Join(failures...)')
    if name == "container-audit-bypass":
        return function_body(text, "func (s *Slot) audit() error {", "return s.home.auditRoot(s.root)")
    if name == "terminal-shape-bypass":
        return replace_once(text, "!terminalObservation(observation)",
                            '(observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 || observation.ExitCode == nil && observation.Signal == nil)')
    if name == "limit-terminal-bypass":
        return replace_once(text, "!terminalObservation(exit)",
                            '(!identifier(exit.Handle.ID) || !identifier(exit.Handle.ContainmentID) || !label(exit.Handle.Generation) || exit.State != "exited" || exit.Signal != nil || exit.Survivors == nil || *exit.Survivors != 0)')
    if name == "seed-lock-domain-bypass":
        return replace_once(text, '"home/" + h.key', '"seed/" + h.key')
    if name == "reason-flattened":
        return replace_once(text, "if errors.As(err, &typed) {\n\t\treturn err\n\t}", "if errors.As(err, &typed) {\n\t\treturn typed\n\t}")
    if name == "binary-digest-bypass":
        return replace_once(text, "hex.EncodeToString(hash.Sum(nil)) != string(pinned.SHA256)",
                            "hex.EncodeToString(hash.Sum(nil)) != string(pinned.SHA256) && len(pinned.SHA256) == 0")
    if name == "session-history-bypass":
        return replace_once(text, "\t\t!identifier(r.Session.HistoryID) || r.Session.HistoryID != r.Home.HistoryID ||\n", "")
    if name == "quoted-error-promoted":
        return replace_once(text, 'if !hasError || marker == "" || marker == nil {\n\t\t\treturn "", false\n\t\t}',
                            'if !hasError || marker == "" || marker == nil {\n\t\t\treturn "usage_limit", false // deliberate red mutation\n\t\t}')
    if name == "primary-capture-bypass":
        return replace_once(text, "canonical != record ||", "canonical.ID != record.ID ||")
    if name == "duplicate-key-bypass":
        return replace_once(text, "if _, exists := document[name]; exists {", "if _, exists := document[name]; exists && len(name) == 0 {")
    if name == "vendor-tree-bypass":
        anchor = "func auditVendor(root *os.Root, record *homeRecord) error {"
        return replace_once(text, anchor, anchor + "\nif record != nil { return nil } // deliberate red")
    if name == "seed-directory-loss":
        return replace_once(text, "recordDirectories(record, directories)", "recordDirectories(record, map[string]bool{})")
    if name == "directory-presence-bypass":
        return replace_once(text, 'for name, recorded := range record.Directories {', 'for name, recorded := range record.Directories {\nif len(name) > 0 { continue } // deliberate red')
    if name == "conversation-tree-bypass":
        return replace_once(text, 'if entry.IsDir() {\n\t\t\tif err := ownedDirectory(r, path); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t} else if err := ownedFile(r, path, false); err != nil {\n\t\t\treturn err\n\t\t}', "// deliberate red: ignore intermediate entry ownership")
    if name == "rotation-recheck-leak":
        return replace_once(text, "return errors.Join(err, newClaim.close())", "return err // deliberate red: retain the rejected claim")
    if name == "records-root-bypass":
        return function_body(text, "func (r *Records) withRoot(action func(*os.Root) error) error {", "r.mu.Lock(); defer r.mu.Unlock(); return action(r.root)")
    if name == "rotation-memory-loss":
        return replace_once(text, "rotate := s.rotatePending", "rotate := false")
    if name == "inspect-keeps-walking":
        return replace_once(text, "return fs.SkipAll", "return fs.SkipDir")
    if name == "missing-limit-guard":
        return replace_once(text, " || deps.LimitGuard == nil", "")
    if name == "assistant-auth-promoted":
        return replace_once(text, 'marker != "rate_limit" || ', "")
    if name == "terminal-quota-discarded":
        return replace_once(text, 'subtype != "" && subtype != "success" && subtype != "error_during_execution"', 'subtype != "error_during_execution"')
    if name == "success-keeps-limit":
        return replace_once(text, 'if event["is_error"] != true {\n\t\t\treturn "", true\n\t\t}', 'if event["is_error"] != true {\n\t\t\treturn "", false\n\t\t}')
    if name == "result-subtype-promoted":
        return replace_once(text, 'subtype != "" && subtype != "success" && subtype != "error_during_execution"', '(subtype != "" && subtype != "success" && subtype != "error_during_execution") && len(subtype) < 0')
    if name == "result-text-ignored":
        return replace_once(text, 'if candidate == "" {\n\t\t\t\treturn "", true\n\t\t\t}', 'if candidate == "" {\n\t\t\t\treturn "", false\n\t\t\t}')
    if name == "rate-warning-promoted":
        return replace_once(text, 'info["status"] != "rejected"', 'info["status"] != "rejected" && len(info) < 0')
    if name == "binding-checked-late":
        block = '\tif !start {\n\t\tif err := home.bind(request, false); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n'
        return replace_once(replace_once(text, block, ""), '\tif beforeCommit != nil {', block + '\tif beforeCommit != nil {')
    if name == "permission-mode-missing":
        return replace_once(text, ', "--permission-mode", "bypassPermissions"', "")
    if name == "umask-proof-bypass":
        return replace_once(text, '\tif err := dependency(s.deps.VerifySlot(ctx, request, RequiredUmask)); err != nil {\n\t\treturn empty, err\n\t}\n',
                            "// deliberate red: omit measured credential/bootstrap proof\n")
    if name == "reservation-config-bypass":
        return replace_once(text, 'record.Reservation.Config != s.deps.Config || ', "")
    if name == "reservation-child-bypass":
        return replace_once(text, ' || record.Reservation.Target != target', "")
    if name == "launch-claim-bypass":
        return replace_once(text, 'effect.ClaimID != selected.ClaimID || ', "")
    if name == "launch-epoch-bypass":
        return replace_once(text, ' || cause.CancellationEpoch != r.CancellationEpoch', "")
    if name == "launch-policy-bypass":
        return replace_once(text, 'policy.Generation != r.PolicyGeneration || ', "")
    if name == "launch-grants-bypass":
        return replace_once(text, '!reflect.DeepEqual(grants, record.Inputs.Grants) || grants.Revoked || ', "")
    if name == "caller-executable-bypass":
        return replace_once(text, 'request.Executable != s.deps.Executable ||', "")
    if name == "caller-path-bypass":
        return replace_once(text, 'r.Home.VendorDirectory != PrivateVendorDirectory ||', "")
    if name == "launch-enrollment-bypass":
        return replace_once(text, '!reflect.DeepEqual(sources, record.Inputs.Sources) || ', "")
    if name == "retained-storage-bypass":
        return replace_once(text, 'if record.Plan != nil && (record.Plan.Data.Home != storage.Home',
                            'if record.Plan != nil && record.Plan.Lease.ID == "" && (record.Plan.Data.Home != storage.Home')
    if name == "prompt-origin-bypass":
        return replace_once(text, ' || metadata.Origin != "service"', "")
    if name == "launch-replay-bypass":
        return replace_once(text, 'if exists && digest != retained {', 'if exists && digest != retained && len(retained) == 0 {')
    if name == "restart-binding-fallback":
        return replace_once(text, 'previous, err := s.deps.State.LaunchBinding(ctx, r.PreviousLaunchID)\n\t\tif err != nil {\n\t\t\treturn empty, dependency(err)\n\t\t}',
                            'previous, err := s.deps.State.LaunchBinding(ctx, r.PreviousLaunchID)\n\t\tif err != nil {\n\t\t\treturn launchInputs{selector: selected, record: record, storage: storage, digest: r.RequestSHA256}, nil // deliberate red fallback\n\t\t}')
    if name == "capture-binding-bypass":
        return replace_once(text, 'if binding.ID != record.BindingID {', 'if binding.ID != record.BindingID && len(binding.ID) == 0 {')
    if name == "capture-reconcile-bypass":
        return replace_once(text, 'if !reflect.DeepEqual(reconciled, binding) {', 'if !reflect.DeepEqual(reconciled, binding) && binding.Generation == 0 {')
    if name == "capture-ack-bypass":
        return replace_once(text, 'if !covered {', 'if !covered && record.Offset < 0 {')
    if name == "capture-refusal-bypass":
        return replace_once(text, 'if binding.Status == "refused" {', 'if binding.Status == "refused" && binding.Generation == 0 {')
    if name == "supplementary-capture-bypass":
        return replace_once(text, '!record.Primary || ', "")
    if name == "usage-private-bypass":
        return replace_once(text, 'metadata.ACL.Audience != "service" || ', "")
    if name == "usage-envelope-bypass":
        return replace_once(text, ' || !reflect.DeepEqual(committed, evidence)', "")
    if name in {"f11-usage-percent", "f11-usage-profile", "f11-usage-producer"}:
        field = {"f11-usage-percent": "unchecked.UsedPercent = 100",
                 "f11-usage-profile": "unchecked.ProfileID = query.ProfileID",
                 "f11-usage-producer": "unchecked.ProducerGeneration = producer.Peer.ProcessGeneration"}[name]
        return replace_once(text, '\tif err := api.ValidateUsageWindow(evidence, query, producer, s.deps.Clock.Now()); err != nil {',
                            '\tunchecked := evidence // deliberate red: replace one observed field\n\t' + field + '\n\tif err := api.ValidateUsageWindow(unchecked, query, producer, s.deps.Clock.Now()); err != nil {')
    if name == "f11-usage-fresh":
        return replace_once(text, '\tif err := api.ValidateUsageWindow(evidence, query, producer, s.deps.Clock.Now()); err != nil {',
                            '\tobserved, _ := timestamp(evidence.ObservedAt) // deliberate red: trust observation as now\n\tif err := api.ValidateUsageWindow(evidence, query, producer, observed); err != nil {')
    if name == "f11-usage-source":
        return replace_once(text, 'api.ValidateUsageSource(evidence, raw, vendorProfile); err != nil {',
                            'api.ValidateUsageSource(evidence, raw, vendorProfile); err != nil && len(raw) == 0 {')
    if name == "usage-end-time-bypass":
        return replace_once(text, '\tif err := api.ValidateUsageWindow(evidence, query, producer, s.deps.Clock.Now()); err != nil {',
                            '\tquery.RunEndedAt = evidence.ObservedAt // deliberate red: discard actual end\n\tif err := api.ValidateUsageWindow(evidence, query, producer, s.deps.Clock.Now()); err != nil {')
    if name == "usage-reset-bypass":
        return replace_once(text, '!valid || !reset.After(s.deps.Clock.Now())', '!valid && !reset.After(s.deps.Clock.Now())')
    if name == "usage-tsv-bypass":
        return replace_once(text, 'api.ValidateUsageSource(evidence, raw, vendorProfile); err != nil {',
                            'api.ValidateUsageSource(evidence, raw, vendorProfile); err != nil && len(raw) == 0 {')
    if name == "usage-source-error-flattened":
        return replace_once(text, 'evidence, err := s.deps.UsageWindows.ReadUsageWindow(ctx, selected.Scope, query)\n\tif err != nil {\n\t\treturn empty, dependency(err)\n\t}',
                            'evidence, err := s.deps.UsageWindows.ReadUsageWindow(ctx, selected.Scope, query)\n\tif err != nil {\n\t\treturn empty, failure(api.CodeUnavailable, "deliberate red flattened usage refusal")\n\t}')
    if name == "original-budget-bypass":
        return replace_once(text, 'start.Budget != request.Budget || ', "")
    if name == "source-refusal-flattened":
        return replace_once(text, 'sources, err := s.deps.Sources.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID})\n\tif err != nil {\n\t\treturn empty, dependency(err)\n\t}',
                            'sources, err := s.deps.Sources.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID})\n\tif err != nil {\n\t\treturn empty, failure(api.CodeUnavailable, "deliberate red flattened source refusal")\n\t}')
    if name == "reserved-level-bypass":
        return replace_once(text, 'start.Level != r.Level || ', "")
    if name == "reserved-role-bypass":
        return replace_once(text, 'start.Role != r.Role || ', "")
    if name == "original-driver-bypass":
        return replace_once(text, ' || start.Driver != r.Driver', "")
    if name == "reservation-driver-bypass":
        return replace_once(text, 'if record.Reservation.Driver != api.DriverClaudock {',
                            'if record.Reservation.Driver != api.DriverClaudock && record.Reservation.Level == 0 {')
    if name == "continuation-level-bypass":
        return replace_once(text, 'prior.Reservation.Level != r.Level || ', "")
    if name == "continuation-role-bypass":
        return replace_once(text, ' || prior.Reservation.Role != r.Role', "")
    if name == "returned-pin-loss":
        return replace_once(text, 'return launchInputs{selector: selected, record: record, storage: storage, digest: contentDigest(canonical)}, nil',
                            'record.Reservation.Level++ // deliberate red: corrupt only the returned reservation\n\treturn launchInputs{selector: selected, record: record, storage: storage, digest: contentDigest(canonical)}, nil')
    if name == "refusal-policy-validation-bypass":
        return replace_once(text, 'return dependency(api.ValidateCapturePolicy(binding, policy))',
                            'if policy.Generation == 0 { return failure(api.CodeIntegrity, "deliberate red empty policy") }; return nil')
    if name == "refusal-snapshot-validation-bypass":
        return replace_once(text, '\tif err := api.ValidateLaunchPlanRecord(record); err != nil {\n\t\treturn empty, absent, dependency(err)\n\t}\n', "")
    if name == "prior-refused-continuation-bypass":
        return replace_once(text, '\t\tif previous.Recovery.Capture.Status == "refused" {\n\t\t\treturn empty, previous.Recovery.Capture.Refusal\n\t\t}\n', "")
    if name == "current-refused-continuation-bypass":
        return replace_once(text, '\t\tif method != "start" && record.Plan.Capture.Status == "refused" {\n\t\t\treturn empty, record.Plan.Capture.Refusal\n\t\t}\n', "")
    if name == "capture-policy-recheck-bypass":
        return replace_once(text, '\tif err := s.refusalPolicy(ctx, selected.Scope, binding); err != nil {\n\t\treturn empty, err\n\t}\n', "")
    if name == "policy-refusal-flattened":
        return replace_once(text, 'policy, err := s.deps.State.Policy(ctx, scope)\n\tif err != nil {\n\t\treturn dependency(err)\n\t}',
                            'policy, err := s.deps.State.Policy(ctx, scope)\n\tif err != nil {\n\t\treturn failure(api.CodeUnavailable, "deliberate red flattened policy refusal")\n\t}')
    if name == "prepared-binding-validation-bypass":
        return replace_once(text, '\tif err := api.ValidateLaunchBindingPlan(identity, *plan.Plan); err != nil {\n\t\treturn empty, dependency(err)\n\t}\n',
                            '\tif identity.Record.ID == "" { return empty, failure(api.CodeIntegrity, "deliberate red absent binding") }\n')
    if name == "capture-policy-seal-bypass":
        return replace_once(text, 'Allowed: policy.AllowCaptureRefusal, PolicyGeneration: policy.Generation, ApprovalID: policy.CaptureRefusalApprovalID,',
                            'Allowed: false, PolicyGeneration: policy.Generation, ApprovalID: "", // deliberate red: discard the policy exception inputs')
    if name == "split-start-publication":
        return replace_once(text, '\t\tif err := home.bindAndSeal(request, input.ReservationID, input.InputsSHA256); err != nil {',
                            '\t\tif err := home.bind(request, true); err != nil { return err } // deliberate red: split binding and seal\n\t\tif err := home.bindAndSeal(request, input.ReservationID, input.InputsSHA256); err != nil {')
    if name == "start-session-match-bypass":
        return replace_once(text, 'record.Session == request.Session && ', "")
    if name == "start-home-match-bypass":
        return replace_once(text, 'record.Home == request.Home && ', "")
    if name == "start-model-match-bypass":
        return replace_once(text, ' && record.Model == request.Model', "")
    if name in {"sealed-home-retry-bypass", "foreign-start-seal-bypass"}:
        return replace_once(text, 'if !exists && len(record.Launches) != 0 {', 'if !exists && len(record.Launches) < 0 {')
    if name == "start-seal-digest-bypass":
        return replace_once(text, 'if exists && retained != digest {', 'if exists && retained != digest && len(retained) == 0 {')
    if name == "all-reservations-replay":
        return replace_once(text, 'replayed = exists', 'replayed = true // deliberate red: trust every reservation ID')
    raise RuntimeError("unknown mutation")


MUTATIONS = [
    ("usage-input-id-reuse", "usage_fixture_test.go", "TestUsageMeasurementIDs", "usage measurements reused an input or producer identity"),
    ("home-parent-privacy-bypass", "home.go", "TestHomeParentTypes", "home parent was accepted"),
    ("records-privacy-bypass", "records.go", "TestRecordsDirectoryGuards", "records directory was accepted"),
    ("ordinary-tool-refusal", "home.go", "TestOwnedAuditKeepsTools", "ordinary tool state blocked"),
    ("owned-file-bypass", "home.go", "TestOwnedFileGuards", "owned guard lost its specific reason"),
    ("generated-digest-bypass", "records.go", "TestProtectedHomeRecords", "replaced generated settings passed"),
    ("binding-bypass", "records.go", "TestProtectedHomeRecords", "changed model replaced"),
    ("root-identity-bypass", "home.go", "TestAuditChecksOpenRoot", "different open root passed"),
    ("copy-rotation-bypass", "slot.go", "TestCopiedCredentialNeedsRotation", "copied credential was not marked"),
    ("close-returns-early", "slot.go", "TestCloseFinishesAfterRootError", "cleanup did not finish"),
    ("container-audit-bypass", "slot.go", "TestSlotPinsCredentialContainers", "replaced container still exported a token"),
    ("terminal-shape-bypass", "slot.go", "TestQuiesceRejectsMalformedExit", "malformed observation released the active slot"),
    ("limit-terminal-bypass", "capture.go", "TestLimitRequiresObservedExit", "unsettled process became a limit signal prompt"),
    ("seed-lock-domain-bypass", "seed.go", "TestSeedNeedsExclusiveHome", "owned home accepted generated-file seeding"),
    ("reason-flattened", "service.go", "TestAuditReasonSurvivesMapping", "audit cause or typed code was flattened"),
    ("binary-digest-bypass", "validation.go", "TestPlanChecksBothBinaryDigests", "modified runner binary escaped pinned digest check"),
    ("session-history-bypass", "validation.go", "TestSessionHistoryBinding", "invalid session history reached runner"),
    ("quoted-error-promoted", "capture.go", "TestQuotaRejectsQuotesAndAuth", "became a swap trigger"),
    ("primary-capture-bypass", "capture.go", "TestCaptureRejectsEditsAndGaps", "forged Primary flag overrode the protected record"),
    ("duplicate-key-bypass", "json.go", "TestSessionCaptureProvenance", "malformed vendor record passed session validation"),
    ("vendor-tree-bypass", "vendor_tree.go", "TestVendorTreeGuards", "vendor tree accepted unsafe state"),
    ("seed-directory-loss", "seed.go", "TestSeedRecordsDirectories", "seeded directories lost protected provenance"),
    ("directory-presence-bypass", "vendor_tree.go", "TestSeedRecordsDirectories", "missing generated directory was accepted"),
    ("conversation-tree-bypass", "home.go", "TestConversationTreeGuards", "conversation accepted shared state"),
    ("rotation-recheck-leak", "slot.go", "TestRotationRecheckReleasesLease", "rotation recheck retained a rejected login lease"),
    ("records-root-bypass", "records.go", "TestRevokeNeedsRecords", "revocation wrote through unchecked records"),
    ("rotation-memory-loss", "slot.go", "TestRevokeNeedsRecords", "rotation recovery forgot copied credential"),
    ("inspect-keeps-walking", "home.go", "TestInspectStopsAtBound", "inspection continued after its bound"),
    ("missing-limit-guard", "service.go", "TestLimitNeedsWholeRunEvidence", "constructor accepted missing whole-run guard"),
    ("assistant-auth-promoted", "capture.go", "TestQuotaRejectsQuotesAndAuth", "became a swap trigger"),
    ("terminal-quota-discarded", "capture.go", "TestVendorTerminalQuota", "documented terminal quota was discarded"),
    ("success-keeps-limit", "capture.go", "TestSuccessSuppressesQuota", "successful terminal result retained quota"),
    ("result-subtype-promoted", "capture.go", "TestQuotaRejectsQuotesAndAuth", "became a swap trigger"),
    ("result-text-ignored", "capture.go", "TestNonQuotaResultCancelsSignal", "non-quota result promoted preceding quota"),
    ("rate-warning-promoted", "capture.go", "TestQuotaRejectsQuotesAndAuth", "became a swap trigger"),
    ("binding-checked-late", "service.go", "TestContinuationBindingOrder", "continuation inspected history before its protected binding"),
    ("permission-mode-missing", "service.go", "TestPlansKeepPrivateContinuation", "Claudock argument structure differs from the pinned contract"),
    ("umask-proof-bypass", "service.go", "TestPlanningGuards", "invalid planning input produced runner argv: umask"),
    ("reservation-config-bypass", "launch.go", "TestLaunchReservationGuards", "foreign launch reservation reached the adapter: config"),
    ("reservation-child-bypass", "launch.go", "TestLaunchReservationGuards", "foreign launch reservation reached the adapter: child"),
    ("launch-claim-bypass", "launch.go", "TestPlanningGuards", "invalid planning input produced runner argv: claim"),
    ("launch-epoch-bypass", "launch.go", "TestPlanningGuards", "invalid planning input produced runner argv: epoch"),
    ("launch-policy-bypass", "launch.go", "TestPlanningGuards", "planning lost the deciding fence: policy"),
    ("launch-grants-bypass", "launch.go", "TestPlanningGuards", "planning lost the deciding fence: grants"),
    ("caller-executable-bypass", "service.go", "TestPlanningGuards", "planning lost the deciding fence: executable"),
    ("caller-path-bypass", "validation.go", "TestPlanningGuards", "planning lost the deciding fence: path"),
    ("launch-enrollment-bypass", "launch.go", "TestPlanningGuards", "invalid planning input produced runner argv: enrollment"),
    ("retained-storage-bypass", "launch.go", "TestPlanningGuards", "planning lost the deciding fence: storage"),
    ("prompt-origin-bypass", "launch.go", "TestPlanningGuards", "invalid planning input produced runner argv: prompt"),
    ("launch-replay-bypass", "records.go", "TestRunnerReplayAndRestart", "changed replay escaped its retained input seal"),
    ("restart-binding-fallback", "launch.go", "TestRunnerReplayAndRestart", "restart invented a missing previous launch binding"),
    ("capture-binding-bypass", "capture_binding.go", "TestProducerBoundCapture", "capture lost the deciding fence: binding"),
    ("capture-reconcile-bypass", "capture_binding.go", "TestProducerBoundCapture", "unbound or supplementary capture established a session producer"),
    ("capture-ack-bypass", "capture_binding.go", "TestProducerBoundCapture", "unbound or supplementary capture established a session offset"),
    ("capture-refusal-bypass", "capture_binding.go", "TestProducerBoundCapture", "capture lost the deciding fence: refused"),
    ("supplementary-capture-bypass", "capture.go", "TestProducerBoundCapture", "capture lost the deciding fence: supplementary"),
    ("usage-private-bypass", "capture_binding.go", "TestUsageRetention", "usage retention guard was bypassed: raw-audience"),
    ("usage-envelope-bypass", "capture_binding.go", "TestUsageRetention", "usage retention guard was bypassed: envelope-bytes"),
    ("f11-usage-percent", "capture_binding.go", "TestUsagePercent", "non-exhausted outside usage produced a limit"),
    ("f11-usage-fresh", "capture_binding.go", "TestUsageFresh", "stale post-exit outside usage produced a limit"),
    ("f11-usage-profile", "capture_binding.go", "TestUsageProfile", "destination profile usage produced a limit"),
    ("f11-usage-producer", "capture_binding.go", "TestUsageProducer", "foreign usage producer produced a limit"),
    ("f11-usage-source", "capture_binding.go", "TestUsageSource", "rehashed non-exhausted TSV produced a limit"),
    ("usage-end-time-bypass", "capture_binding.go", "TestUsageEnvelopeGuards", "usage envelope guard was bypassed: pre-exit"),
    ("usage-reset-bypass", "capture_binding.go", "TestUsageEnvelopeGuards", "usage envelope guard was bypassed: elapsed-reset"),
    ("usage-tsv-bypass", "capture_binding.go", "TestUsageTSVGuards", "actual TSV guard was bypassed: header"),
    ("usage-source-error-flattened", "capture_binding.go", "TestUsageDependencies", "usage dependency refusal was changed: source"),
    ("original-budget-bypass", "launch.go", "TestOriginalBudgetGuards", "budget lost the original intent fence: start"),
    ("source-refusal-flattened", "launch.go", "TestLaunchDependencyBarriers", "launch dependency barrier was changed or bypassed: sources"),
    ("reserved-level-bypass", "launch.go", "TestReservedChildPins", "reserved child pin was not enforced: level"),
    ("reserved-role-bypass", "launch.go", "TestReservedChildPins", "reserved child pin was not enforced: role"),
    ("original-driver-bypass", "launch.go", "TestReservedChildPins", "reserved child pin was not enforced: original-driver"),
    ("reservation-driver-bypass", "launch.go", "TestReservedChildPins", "reserved child pin was not enforced: reservation-driver"),
    ("continuation-level-bypass", "launch.go", "TestContinuationChildPins", "continuation changed the reserved child pin: level"),
    ("continuation-role-bypass", "launch.go", "TestContinuationChildPins", "continuation changed the reserved child pin: role"),
    ("returned-pin-loss", "launch.go", "TestPinnedIdentitySurvivesTurns", "planning replaced the retained child pins"),
    ("refusal-policy-validation-bypass", "capture_binding.go", "TestCaptureRefusalCurrentPolicy", "current capture refusal policy was bypassed: disabled"),
    ("refusal-snapshot-validation-bypass", "launch.go", "TestCaptureRefusalSnapshot", "retained capture refusal omitted required metadata: snapshot"),
    ("prior-refused-continuation-bypass", "launch.go", "TestRefusedCaptureBlocksContinuation", "refused prior capture authorized continuation"),
    ("current-refused-continuation-bypass", "launch.go", "TestCurrentRefusalBlocksContinuation", "current refused capture authorized continuation"),
    ("capture-policy-recheck-bypass", "capture_binding.go", "TestRefusedCaptureRechecksPolicy", "capture extraction used the stale refusal policy snapshot"),
    ("policy-refusal-flattened", "capture_binding.go", "TestRefusalNeedsCurrentPolicyPort", "capture refusal bypassed the current policy port"),
    ("prepared-binding-validation-bypass", "capture_binding.go", "TestPreparedCaptureBindingRequired", "capture accepted an unbound prepared identity: kind"),
    ("capture-policy-seal-bypass", "launch.go", "TestCapturePolicyReplaySeal", "replay discarded changed capture policy inputs"),
    ("split-start-publication", "service.go", "TestLaunchSealRetry", "failed atomic start left a partial binding or seal"),
    ("start-session-match-bypass", "records.go", "TestStartBindRetryIdentity", "changed start binding was accepted: session"),
    ("start-home-match-bypass", "records.go", "TestStartBindRetryIdentity", "changed start binding was accepted: home"),
    ("start-model-match-bypass", "records.go", "TestStartBindRetryIdentity", "changed start binding was accepted: model"),
    ("sealed-home-retry-bypass", "records.go", "TestSecondStartRejected", "different start reservation replaced the bound home"),
    ("foreign-start-seal-bypass", "records.go", "TestConcurrentStarts", "concurrent starts did not yield exactly one plan and one seal"),
    ("start-seal-digest-bypass", "records.go", "TestStartBindRetryIdentity", "changed start seal digest was accepted"),
    ("all-reservations-replay", "records.go", "TestSecondStartRejected", "foreign reservation was classified as a retained replay"),
]


CASE_MUTATIONS = [
    ("case-quota-result", 'record.get("subtype", "") not in {"", "success", "error_during_execution"}',
     'record.get("subtype", "") != "error_during_execution"', "test_quota_terminal_shapes", "documented result quota was ignored"),
    ("case-follow-old-run", 'selected["run"] > after_run', 'selected["run"] >= after_run',
     "test_follow_waits_next_run", "follow reused an ended run"),
    ("case-cursor-since", '"since": 0 if cursor else since', '"since": since',
     "test_cursor_clears_since", "cursor retained nonzero since"),
    ("case-early-reach", 'self.context["phase"] == "red" and self.mutation_cells.get(self.context["mutation_id"]) == cell',
     'self.context["phase"] == "candidate" or self.mutation_cells.get(self.context["mutation_id"]) == cell',
     "test_candidate_reach_completion", "partial candidate claimed the assertion"),
    ("case-wrong-reach-cell", '"new-conversation": "lost-conversation"', '"new-conversation": "resume"',
     "test_red_reach_mapping", "unrelated resume marked lost control"),
    ("case-sync-launch-event", "if asynchronous:", "if True:",
     "test_negative_control_shapes", "synchronous refusal wrongly required an end event"),
    ("case-abort-exit-required", 'allowed_states = {"prepared", "exited"} if prepared else {"exited"}', 'allowed_states = {"exited"}',
     "test_negative_control_shapes", "aborted prepared gate was rejected"),
    ("case-async-no-proof", 'require(any(event["kind"] == "launch.failed" and event["origin"] == "service" and event.get("run") == after["run"]\n                    and event["payload"]["agent_executed"] is False for event in events),',
     'require(True,', "test_negative_control_shapes", "async abort accepted without no-execution evidence"),
    ("case-sync-event-write", 'require(not any(event["kind"] in {"launch.prepared", "launch.failed"} for event in events), "synchronous refusal emitted launch events")',
     'require(True, "deliberate red")', "test_negative_control_shapes", "synchronous refusal accepted launch events"),
    ("case-abort-demands-release", "resolved.add(lease_id)", "resolved.update([])",
     "test_helper_abort_collection", "aborted gate demanded release receipt"),
    ("case-release-event-run", 'target = receipt["quiescence"]["handle"]["target"]', 'target = {"life_id": life, "run": event["run"]}',
     "test_lease_level_release", "lease-level release required an event run"),
    ("case-stream-correlation", 'frame.get("request_id") == request_id', "True",
     "test_stream_attribution", "foreign stream attribution was accepted"),
    ("case-stream-drop", 'events = list(page["events"])', "events = []",
     "test_stream_keeps_snapshot", "snapshot events were dropped"),
    ("case-end-bypass", 'require(ended, "event stream disconnected before its end")', "require(True, \"deliberate red\")",
     "test_stream_requires_end", "stream missing an end was accepted"),
    ("case-release-count", 'for field in ("live_connections", "queued_jobs", "writable_exports")',
     'for field in ("live_connections", "queued_jobs", "writable_exports") if field != "writable_exports"',
     "test_release_measurements", "unknown helper count was accepted"),
    ("case-key-drop", 'argv += ["--request-id", request_id, "--idempotency-key", key]', 'argv += ["--request-id", request_id]',
     "test_cli_retains_keys", "mutation key was omitted"),
    ("case-binding-drop", ', "--binding", self.context["binding_file"]', "",
     "test_cli_retains_keys", "installed binding was omitted"),
    ("case-counter-bypass", 'prior["counters"] == continued["counters"]', "True",
     "test_continuation_state", "changed continuation state was accepted"),
    ("case-health-envelope", "return decode(stdout)", 'return decode(stdout)["result"]',
     "test_health_result_body", "typed health body was unwrapped"),
    ("case-workspace-digest", 'row["sha256"] == sha(expected)', "True",
     "test_workspace_write_bytes", "workspace bytes were not independently checked"),
    ("case-transcript-mode", 'row.get("mode") == 0o600', "True",
     "test_transcript_mode", "unsafe first transcript mode was accepted"),
    ("case-sibling-absent", 'row["errno"] in {1, 13}', 'row["errno"] in {1, 2, 13}',
     "test_sibling_requires_permission_denial", "missing sibling path was mistaken for a denied read"),
    ("case-workspace-identity", 'before[field] == after[field]', 'before[field] == before[field]',
     "test_workspace_snapshot_identity", "changed workspace identity was accepted"),
    ("case-input-drift", 'self.input_bytes[name] == data', "True",
     "test_repeated_probe_inputs", "changed installed probe input was accepted"),
]


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1048576), b""):
            digest.update(block)
    return digest.hexdigest()


def run(argv, directory, scope, label, umask=-1):
    (scope / (label + ".argv.json")).write_text(json.dumps(argv) + "\n")
    (scope / (label + ".execution.json")).write_text(json.dumps({"umask": umask}) + "\n")
    process = subprocess.Popen(argv, cwd=directory, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=umask)
    try:
        stdout, stderr = process.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        (scope / (label + ".stdout")).write_bytes(stdout)
        (scope / (label + ".stderr")).write_bytes(stderr)
        (scope / (label + ".exit.json")).write_text(json.dumps({"exit": process.returncode, "timeout": True}) + "\n")
        raise RuntimeError("bounded unit command timed out")
    (scope / (label + ".stdout")).write_bytes(stdout)
    (scope / (label + ".stderr")).write_bytes(stderr)
    (scope / (label + ".exit.json")).write_text(json.dumps({"exit": process.returncode, "timeout": False}) + "\n")
    return process.returncode, stdout


def snapshot(source, destination):
    destination.mkdir(mode=0o700)
    for name in ["go.mod", "go.sum"]:
        shutil.copy2(source / name, destination / name)
    for relative in [Path("internal/v2/api"), OWNED]:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copytree(source / relative, target)


def manifest(scope, source):
    inputs = []
    for path in sorted(source.rglob("*")):
        if path.is_file():
            inputs.append({"path": str(path.relative_to(source)), "sha256": digest_file(path), "bytes": path.stat().st_size})
    (scope / "inputs.json").write_text(json.dumps(inputs, sort_keys=True) + "\n")


def build_binary(source, scope, tags=""):
    binary = scope / "claudock.test"
    argv = ["go", "test", "-c", "-race", "-o", str(binary)]
    if tags:
        argv.extend(["-tags", tags])
    argv.append(PACKAGE)
    code, _ = run(argv, source, scope, "build")
    if code != 0:
        raise RuntimeError("unit build failed; this is not a killed mutation")
    (scope / "binary.json").write_text(json.dumps({"sha256": digest_file(binary), "bytes": binary.stat().st_size}) + "\n")
    return binary


def run_test(binary, source, scope, test, label="test", umask=0o022):
    return run([str(binary), "-test.v", "-test.timeout=180s", "-test.run", "^" + test + "$"],
               source, scope, label, umask=umask)


def candidate_matrix(source, destination):
    destination.mkdir(mode=0o700)
    rows = []
    for name, tags in [("default", ""), ("faults", "laneboss_faults")]:
        scope = destination / name
        scope.mkdir(mode=0o700)
        candidate = scope / "source"
        snapshot(source, candidate)
        manifest(scope, candidate)
        binary = build_binary(candidate, scope, tags)
        for mask in [0o022, 0o077]:
            code, output = run_test(binary, candidate, scope, ".*", label=f"test-{mask:03o}", umask=mask)
            if code != 0 or b"PASS\n" not in output:
                raise RuntimeError("candidate suite failed; setup failure cannot count as a killed mutation")
            rows.append({"tags": tags, "umask": mask, "observed_exit": code,
                         "binary_sha256": digest_file(binary)})
    return rows


def case_snapshot(source, scope):
    scope.mkdir(mode=0o700)
    candidate = scope / "source"
    candidate.mkdir(mode=0o700)
    for name in ["run.py", "probe.py", "test_case_contract.py"]:
        shutil.copy2(source / CASE / name, candidate / name)
    return candidate


def case_candidate(source, scope):
    candidate = case_snapshot(source, scope)
    manifest(scope, candidate)
    code, output = run([sys.executable, "test_case_contract.py"], candidate, scope, "test")
    if code != 0 or b"\nOK\n" not in output:
        raise RuntimeError("case consumer candidate failed before its red controls")
    return {"observed_exit": code, "source": "inputs.json"}


def case_red_controls(source, evidence):
    rows = []
    for name, before, after, test, message in CASE_MUTATIONS:
        scope = evidence / name
        candidate = case_snapshot(source, scope)
        target = candidate / "run.py"
        target.write_text(replace_once(target.read_text(), before, after))
        manifest(scope, candidate)
        code, _ = run([sys.executable, "-m", "py_compile", "run.py", "test_case_contract.py"], candidate, scope, "compile")
        if code != 0:
            raise RuntimeError("case mutation syntax failed; this is not a killed mutation")
        code, output = run([sys.executable, "test_case_contract.py", "CaseContractTests." + test], candidate, scope, "test")
        reached = ("FAIL: " + test).encode() in output and message.encode() in output
        if code == 0:
            raise RuntimeError("SURVIVED: " + name)
        if code != 1 or not reached:
            raise RuntimeError("NOT REACHED: " + name + " did not fail at its named assertion")
        rows.append({"mutation": name, "test": test, "observed_exit": code, "reached": reached})
        print("RED: " + name)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args()
    if sys.platform != "linux":
        raise RuntimeError("unit execution requires the authorized Linux test box")
    source, evidence = arguments.source.resolve(), arguments.evidence.resolve()
    evidence.mkdir(mode=0o700)
    # A green preflight must reach every test under both reported build variants
    # and both umasks before any red result can be credited to a mutation.
    preflight = candidate_matrix(source, evidence / "preflight")
    interpreter = Path(sys.executable).resolve()
    shutil.copy2(interpreter, evidence / "python-executable")
    (evidence / "python.json").write_text(json.dumps({"sha256": digest_file(interpreter), "version": sys.version}) + "\n")
    case_preflight = case_candidate(source, evidence / "case-preflight")
    rows = []
    for name, filename, test, expected_message in MUTATIONS:
        scope = evidence / name
        scope.mkdir(mode=0o700)
        changed = scope / "source"
        snapshot(source, changed)
        target = changed / OWNED / filename
        target.write_text(mutate(target.read_text(), name))
        code, _ = run(["gofmt", "-w", str(target)], changed, scope, "format")
        if code != 0:
            raise RuntimeError("mutation syntax failed before reaching its behavior")
        manifest(scope, changed)
        binary = build_binary(changed, scope)
        code, output = run_test(binary, changed, scope, test)
        reached = b"--- FAIL: " + test.encode() in output and expected_message.encode() in output
        if code == 0:
            raise RuntimeError("SURVIVED: " + name)
        if code != 1 or not reached:
            raise RuntimeError("NOT REACHED: " + name + " did not fail at its named assertion")
        rows.append({"mutation": name, "test": test, "observed_exit": code, "reached": reached})
        print("RED: " + name)
    case_rows = case_red_controls(source, evidence)
    candidate = candidate_matrix(source, evidence / "candidate")
    case_final = case_candidate(source, evidence / "case-candidate")
    (evidence / "result.json").write_text(json.dumps({"scope": str(OWNED), "mutations": rows,
                                                     "preflight": preflight, "candidate": candidate,
                                                     "case_mutations": case_rows, "case_preflight": case_preflight,
                                                     "case_candidate": case_final,
                                                     "live_auth": False}, sort_keys=True) + "\n")
    print("PASS: Claudock unit red/green")


if __name__ == "__main__":
    main()

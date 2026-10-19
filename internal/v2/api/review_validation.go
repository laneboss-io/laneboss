package api

import "reflect"

func validCoverage(value string) bool {
	return value == CoverageComplete || value == CoveragePartial || value == CoverageUnsupported || value == CoverageMissing
}

// Partial evidence can be retained and displayed. It is never acceptance.
// The verifier/store additionally authenticate all object ACLs, source jobs,
// current frozen snapshot, actual end event and inventory bytes/coverage.
func ValidateReviewEvidence(evidence ReviewEvidence, expected ReviewSubject) error {
	e, s := evidence, expected
	if e.Schema != "laneboss.review.v2" || !reflect.DeepEqual(e.Subject, s) || !launchID(s.Target.LifeID) || s.Target.Run == 0 ||
		!launchID(s.LaunchID) || !launchGeneration(s.Generation) || !launchID(s.EndEventID) || s.EndSeq == 0 || s.InventorySeq < s.EndSeq ||
		!launchBlob(s.Snapshot, "manifest") || !launchID(s.SessionID) || !launchID(s.CaptureBindingID) ||
		!launchID(e.VerifierLeaseID) || !validCoverage(e.Coverage) || !validCoverage(e.Inventory.ToolCoverage) ||
		!launchBlob(e.Diff, "diff") || !launchBlob(e.Inventory.Manifest, "manifest") || e.Inventory.ThroughSeq != s.InventorySeq {
		return launchInvalid("review evidence differs from its frozen run and end")
	}
	expectedStreams, streamKinds := map[ID]bool{}, map[string]bool{}
	for _, stream := range s.Streams {
		if !launchID(stream.ID) || !launchID(stream.PipeID) || expectedStreams[stream.ID] || streamKinds[stream.Stream] ||
			stream.Stream != "stdout" && stream.Stream != "stderr" && stream.Stream != "vendor" {
			return launchInvalid("review subject has invalid primary stream bindings")
		}
		expectedStreams[stream.ID], streamKinds[stream.Stream] = true, true
	}
	refusals := map[ID]bool{}
	for _, id := range s.RefusalIDs {
		if !launchID(id) || refusals[id] {
			return launchInvalid("review subject has invalid refusal identities")
		}
		refusals[id] = true
	}
	names := map[string]bool{}
	for _, check := range e.Checks {
		if !launchID(ID(check.Name)) || names[check.Name] || !launchBlob(check.Receipt, "check") || check.Target != s.Target ||
			check.EndSeq != s.EndSeq || check.SnapshotSHA256 != s.Snapshot.SHA256 || check.ExitCode < 0 || check.ExitCode > 255 ||
			!launchID(check.WorkerLeaseID) || !launchID(check.OperationID) {
			return launchInvalid("review check is not bound to its frozen run")
		}
		names[check.Name] = true
	}
	streams := map[ID]bool{}
	for _, stream := range e.Inventory.Streams {
		if stream.BindingID != s.CaptureBindingID || !expectedStreams[stream.StreamID] || streams[stream.StreamID] ||
			stream.StartOffset < 0 || stream.EndOffset < stream.StartOffset || stream.EndOffset > launchMaxInteger {
			return launchInvalid("review inventory contains an invalid stream range")
		}
		streams[stream.StreamID] = true
	}
	resolved := map[ID]bool{}
	for _, resolution := range e.Resolutions {
		if !launchID(resolution.RefusalID) || resolved[resolution.RefusalID] || resolution.EventSeq == 0 || resolution.EventSeq > s.InventorySeq ||
			!launchBlob(resolution.Evidence, "manifest") {
			return launchInvalid("invalid review refusal resolution")
		}
		resolved[resolution.RefusalID] = true
	}
	return nil
}

func ValidateReviewAcceptance(scope Scope, receipt ReviewReceipt, expected ReviewSubject, requiredChecks []string) error {
	if receipt.Evidence == nil {
		return launchInvalid("review acceptance lacks verifier evidence")
	}
	if err := ValidateReviewEvidence(*receipt.Evidence, expected); err != nil {
		return err
	}
	e := receipt.Evidence
	if !launchID(receipt.ID) || !launchID(receipt.Reviewer.ID) || receipt.Reviewer != scope.Actor || receipt.Reviewer.Kind != "human" && receipt.Reviewer.Kind != "lane" ||
		receipt.Reviewer.Kind == "lane" && receipt.Reviewer.LifeID == expected.Target.LifeID ||
		receipt.Coverage != CoverageComplete || e.Coverage != CoverageComplete || e.Inventory.ToolCoverage != CoverageComplete ||
		!launchBlob(e.Inventory.ToolRecords, "manifest") || receipt.Diff != e.Diff || receipt.RecordInventory != e.Inventory.Manifest || len(receipt.Checks) != len(e.Checks) {
		return launchInvalid("review acceptance lacks complete independent evidence")
	}
	checks := map[string]bool{}
	for index, check := range e.Checks {
		if receipt.Checks[index] != check.Receipt || check.ExitCode != 0 {
			return launchInvalid("review acceptance contains a failed or changed check")
		}
		checks[check.Name] = true
	}
	for _, name := range requiredChecks {
		if !checks[name] {
			return launchInvalid("review acceptance omitted a required check")
		}
	}
	stdout, stderr := false, false
	for _, stream := range expected.Streams {
		stdout, stderr = stdout || stream.Stream == "stdout", stderr || stream.Stream == "stderr"
	}
	if !stdout || !stderr {
		return launchInvalid("review acceptance has no primary capture streams")
	}
	for _, expectedStream := range expected.Streams {
		found := false
		for _, stream := range e.Inventory.Streams {
			found = found || stream.StreamID == expectedStream.ID && stream.StartOffset == 0 && stream.EOF && len(stream.GapIDs) == 0
		}
		if !found {
			return launchInvalid("review acceptance omitted captured ranges or EOF")
		}
	}
	if len(receipt.RefusalResolution) != len(expected.RefusalIDs) || len(e.Resolutions) != len(expected.RefusalIDs) {
		return launchInvalid("review acceptance omitted a refusal resolution")
	}
	for _, id := range expected.RefusalIDs {
		found, listed := false, false
		for _, resolution := range e.Resolutions {
			found = found || resolution.RefusalID == id
		}
		for _, listedID := range receipt.RefusalResolution {
			listed = listed || listedID == id
		}
		if !found || !listed {
			return launchInvalid("review acceptance changed a refusal resolution")
		}
	}
	return nil
}

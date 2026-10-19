package api

import "slices"

// The snapshot's generation selects exactly one Derived shape. Full owners
// still check inventory, paths, modes, content, digests, renderer and ownership.
func ValidateOrgKinds(snapshot OrgSnapshot) error {
	if !launchGeneration(snapshot.Ref.Generation) || len(snapshot.Sources) == 0 ||
		snapshot.Ref.Generation == 1 && (snapshot.Derived == nil || len(snapshot.Derived) != 0) ||
		snapshot.Ref.Generation > 1 && len(snapshot.Derived) == 0 {
		return launchInvalid("org snapshot kinds require nonempty sources and generation-matched derived files")
	}
	for _, file := range snapshot.Sources {
		if !slices.Contains([]string{"prompt", "drivers", "policy", "source", "task"}, file.Kind) {
			return launchInvalid("org source kind is not semantic")
		}
	}
	for _, file := range snapshot.Derived {
		if file.Kind != "file" {
			return launchInvalid("org derived kind is not file")
		}
	}
	return nil
}

// This lookup selects the current publication by an exact expected generation.
// Zero selectors never mean current, and this is not a history lookup.
func ValidateOrgSnapshotRequest(scope Scope, request OrgSnapshotRequest) error {
	if !bindingConfigName.MatchString(scope.Config) || request.OrgID != ID(scope.Config) || !launchGeneration(request.Generation) {
		return launchInvalid("org snapshot requires this configuration and an exact generation")
	}
	return nil
}

func ValidateOrgSnapshotSelection(scope Scope, request OrgSnapshotRequest, snapshot OrgSnapshot) error {
	if err := ValidateOrgSnapshotRequest(scope, request); err != nil {
		return err
	}
	if snapshot.Config != scope.Config || snapshot.Ref.OrgID != request.OrgID || !launchGeneration(snapshot.Ref.Generation) {
		return &Error{Code: CodeIntegrity, Owner: "lb-v2-service", Message: "org snapshot projection differs from its configuration"}
	}
	if snapshot.Ref.Generation != request.Generation {
		return &Error{Code: CodeConflict, Owner: "lb-v2-service", Message: "current org publication differs from the requested generation", Instead: "Resolve the current approved generation and retry the same intended validation."}
	}
	return nil
}

package approval

import (
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// ValidateRenderedChange checks a renderer result against the service's retained
// input. It permits the first render to supply derived files, diff and manifest;
// requester, sources, org/base, times, status and the trusted artifact stay fixed.
// This checks references, not their bytes, source ownership or worker confinement.
func ValidateRenderedChange(input, rendered api.ChangeRequest) error {
	if err := ValidateChange(rendered); err != nil {
		return err
	}
	if input.ID != rendered.ID || input.OrgID != rendered.OrgID ||
		input.Requester != rendered.Requester || input.BaseGeneration != rendered.BaseGeneration ||
		input.CreatedAt != rendered.CreatedAt || input.ExpiresAt != rendered.ExpiresAt ||
		input.Status != rendered.Status {
		return integrity("renderer changed the retained identity, scope or lifetime")
	}
	// ValidateChange binds the snapshot's org/base to rendered's org/base;
	// those fields were compared above. Bind the remaining snapshot digest here.
	if input.Config != rendered.Config || input.Reason != rendered.Reason ||
		input.SourceSnapshot.ManifestSHA256 != rendered.SourceSnapshot.ManifestSHA256 || input.OwnershipManifest != rendered.OwnershipManifest {
		return integrity("renderer changed the retained approved source provenance")
	}
	if input.Renderer != rendered.Renderer {
		return integrity("renderer changed the pinned executable artifact")
	}
	sources, err := normalizedFiles(input.Files, false)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(sources, rendered.Files) {
		return integrity("renderer changed the retained source deltas")
	}
	return nil
}

// ValidateRevalidation permits a subsequent render only when it reproduces the
// staged effect bytes and metadata. Retention may assign fresh object IDs, so
// each manifest is validated independently before content is compared. Apply
// must additionally verify fresh object bytes and publish the approved refs.
func ValidateRevalidation(staged, rendered api.ChangeRequest) error {
	if err := ValidateChange(staged); err != nil {
		return err
	}
	if err := ValidateRenderedChange(staged, rendered); err != nil {
		return err
	}
	if !sameDerivedContent(staged.Derived, rendered.Derived) {
		return conflict("renderer produced an unreviewed effect; stage a new change")
	}
	if !sameBlobContent(staged.Diff, rendered.Diff) {
		return conflict("renderer produced an unreviewed diff; stage a new change")
	}
	return nil
}

func sameBlobContent(a, b api.BlobRef) bool {
	return a.SHA256 == b.SHA256 && a.Bytes == b.Bytes && a.Class == b.Class
}

func sameDerivedContent(staged, rendered []api.ResourceDelta) bool {
	// ValidateChange already requires sorted, disjoint, explicit arrays.
	if len(staged) != len(rendered) {
		return false
	}
	for i, before := range staged {
		after := rendered[i]
		if before.Path != after.Path || before.Action != after.Action || before.Mode != after.Mode ||
			before.BeforeSHA256 != after.BeforeSHA256 || (before.After == nil) != (after.After == nil) {
			return false
		}
		if before.After != nil && !sameBlobContent(*before.After, *after.After) {
			return false
		}
	}
	return true
}

// ValidateApprovalBinding checks retained receipt fields against one staged
// change at the supplied service-clock instant. It does not verify an assertion,
// discover nonce consumption, load current org state or commit anything. Those
// operations belong to the scoped verifier and atomic store guards.
func ValidateApprovalBinding(now time.Time, change api.ChangeRequest, approval api.ChangeApproval) error {
	if now.IsZero() {
		return invalid("approval binding requires an explicit service-clock instant")
	}
	if err := ValidateChange(change); err != nil {
		return err
	}
	if err := ValidateApproval(approval); err != nil {
		return err
	}
	if approval.ChangeID != change.ID || approval.RequesterLifeID != change.Requester.LifeID ||
		approval.ManifestSHA256 != change.ManifestSHA256 || approval.BaseGeneration != change.BaseGeneration {
		return conflict("approval receipt is bound to another change, requester, manifest or base")
	}
	created, err := timestamp(change.CreatedAt)
	if err != nil {
		return err
	}
	stageExpiry, err := timestamp(change.ExpiresAt)
	if err != nil {
		return err
	}
	approved, err := timestamp(approval.ApprovedAt)
	if err != nil {
		return err
	}
	expires, err := timestamp(approval.ExpiresAt)
	if err != nil {
		return err
	}
	if approved.Before(created) || expires.After(stageExpiry) {
		return integrity("approval receipt falls outside its staged change lifetime")
	}
	if approved.After(now) || !now.Before(expires) || !now.Before(stageExpiry) {
		return forbidden("approval receipt is not current at the service-clock instant")
	}
	return nil
}

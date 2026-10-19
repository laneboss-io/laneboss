package manifest

import (
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func EnrollmentInput(request api.CapabilityEnrollmentRequest) error {
	if (request.Resource == nil) == (request.Secret == nil) {
		return Invalid("capability enrollment requires exactly one resource or secret")
	}
	root := api.RootGrantManifest{Schema: "laneboss.root-grants.v2", Resources: []api.ResourceGrant{},
		Data: []api.DataGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	if request.Resource != nil {
		grant := request.Resource.Grant()
		if grant.SourceHandle != "" {
			return Invalid("resource enrollment cannot choose a service handle")
		}
		// The existing root validator requires a syntactically valid source.
		// This local validation sentinel is never retained or returned.
		grant.SourceHandle = "pending-enrollment"
		root.Resources = []api.ResourceGrant{grant}
	} else {
		root.Secrets = []api.SecretGrant{request.Secret.Grant()}
	}
	return Root(root, time.Time{})
}

// These input-only checks are shared by service handlers and both CLI file
// forms. They do not establish current grants, object ACLs, enrollment, proof
// authority or policy generations; the service still checks those facts.
func RootInput(request api.RootGrantRequest) error {
	if err := Budget(request.Budget); err != nil {
		return err
	}
	if err := Blob(request.Manifest); err != nil {
		return err
	}
	if request.Manifest.Class != "manifest" {
		return Invalid("root grants require a committed manifest object")
	}
	return nil
}

func ValidateInput(request api.GrantValidateRequest) error {
	if !ValidID(request.ParentLifeID) || request.ChildLevel < 3 || request.ChildLevel > 6 ||
		request.ExpectedPolicyGeneration == 0 || uint64(request.ExpectedPolicyGeneration) > MaxInteger {
		return Invalid("grant validation needs a parent life, L3-L6 child level and policy generation")
	}
	return Request(request.Requested)
}

func GetInput(request api.GrantGetRequest) error {
	if !ValidID(request.GrantSetID) {
		return Invalid("invalid grant set ID")
	}
	return nil
}

func RevokeInput(request api.GrantRevokeRequest) error {
	if err := RevokeTarget(request); err != nil {
		return err
	}
	return Blob(request.Reason)
}

// RevokeTarget lets the service check target syntax before resolving current
// visibility. The full input check follows visibility, preserving not_found
// for hidden grant sets even when an unrelated reason reference is invalid.
func RevokeTarget(request api.GrantRevokeRequest) error {
	if !ValidID(request.GrantSetID) || request.ExpectedGeneration == 0 || uint64(request.ExpectedGeneration) > MaxInteger {
		return Invalid("revocation needs a grant ID and generation")
	}
	return nil
}

func TestChildInput(request api.TestChildRequest) error {
	if !ValidID(request.Child.LifeID) || request.Child.Run == 0 || uint64(request.Child.Run) > MaxInteger {
		return Invalid("child test needs the exact life and run")
	}
	if err := Budget(request.Budget); err != nil {
		return err
	}
	if err := Blob(request.Candidate); err != nil {
		return err
	}
	if err := Blob(request.TestPlan); err != nil {
		return err
	}
	if request.Candidate.Class != "manifest" || request.TestPlan.Class != "manifest" {
		return Invalid("child test needs inert candidate and plan objects")
	}
	return nil
}

// RequestCollections bounds the inert selection before any parent lookup.
func RequestCollections(value api.GrantRequest) error {
	if value.Resources == nil || value.Data == nil || value.Secrets == nil ||
		value.Profiles == nil || value.Network == nil || value.Channels == nil {
		return Invalid("requested grant collections must be nonnull arrays")
	}
	if len(value.Resources)+len(value.Data)+len(value.Secrets)+len(value.Profiles)+len(value.Network)+len(value.Channels) > 4096 {
		return Invalid("too many requested grants")
	}
	return nil
}

func delegationInput(id api.ID, expiry api.Timestamp) error {
	if !ValidID(id) {
		return Invalid("requested grant needs a parent grant ID")
	}
	_, err := Time(expiry)
	return err
}

func DataInput(grant api.DataGrantRequest) error {
	if err := delegationInput(grant.ParentGrantID, grant.ExpiresAt); err != nil {
		return err
	}
	if err := Relative(grant.RelativePath); err != nil {
		return err
	}
	if err := Destination(grant.Destination); err != nil {
		return err
	}
	if grant.Access != "ro" && grant.Access != "rw" || grant.Delivery != "copy" && grant.Delivery != "mount" {
		return Invalid("unknown requested data access or delivery")
	}
	if grant.PublicationID != "" && !ValidID(grant.PublicationID) {
		return Invalid("invalid requested publication ID")
	}
	return nil
}

func SecretInput(grant api.SecretDelegation) error {
	if err := delegationInput(grant.ParentGrantID, grant.ExpiresAt); err != nil {
		return err
	}
	if !selection(grant.Name) || !selection(grant.Version) {
		return Invalid("invalid requested secret selection")
	}
	return SecretTarget(grant.Delivery, grant.Target)
}

// Request checks the caller's declared selection. Whether each named parent
// actually permits it, including expiry and delegation, needs service state.
func Request(value api.GrantRequest) error {
	if err := RequestCollections(value); err != nil {
		return err
	}
	for _, grant := range value.Data {
		if err := DataInput(grant); err != nil {
			return err
		}
	}
	for _, grant := range value.Secrets {
		if err := SecretInput(grant); err != nil {
			return err
		}
	}
	for _, grant := range value.Profiles {
		if err := delegationInput(grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !ValidID(grant.ProfileID) {
			return Invalid("invalid requested profile ID")
		}
	}
	for _, grant := range value.Network {
		if err := delegationInput(grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !ValidID(grant.EndpointID) {
			return Invalid("invalid requested endpoint ID")
		}
	}
	for _, grant := range value.Channels {
		if err := delegationInput(grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !ValidID(grant.ChannelID) {
			return Invalid("invalid requested channel ID")
		}
	}
	for _, grant := range value.Resources {
		if err := delegationInput(grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		for _, values := range [][]string{grant.Regions, grant.ImageIDs, grant.MachineTypes} {
			if err := Selections(values); err != nil {
				return err
			}
		}
		if grant.MaxActive == 0 || grant.MaxHourlyMicros < 0 || uint64(grant.MaxHourlyMicros) > MaxInteger ||
			grant.TotalBudgetMicros < 0 || uint64(grant.TotalBudgetMicros) > MaxInteger {
			return Invalid("invalid requested resource ceilings")
		}
	}
	return nil
}

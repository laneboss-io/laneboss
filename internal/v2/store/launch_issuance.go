package store

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Issuance is a second authority boundary, after reservation. The planner's
// selected grant-set ID does not prove that its entries came from the starter
// or were requested in the retained original frame. The caller holds the writer.
func (s *Service) checkIssuedLaunchGrants(ctx context.Context, db queryer, r api.LaunchReservation, issued api.GrantSet) error {
	refuse := func() error {
		return fault(api.CodeForbidden, "issued launch grants exceed the retained ceiling or original request")
	}
	var authority launchAuthority
	if err := storedProjection(ctx, db, "launch_authority", r.ID, &authority); err != nil {
		return err
	}
	if r.BaseGeneration != 0 || issued.ID != r.GrantSetID || issued.LifeID != r.Target.LifeID || issued.ParentLifeID != r.ParentLifeID ||
		issued.Generation != 1 || issued.PolicyGeneration != r.PolicyGeneration || issued.Revoked {
		return refuse()
	}
	expires, e1 := time.Parse(time.RFC3339Nano, string(issued.ExpiresAt))
	ceilingExpires, e2 := time.Parse(time.RFC3339Nano, string(authority.Ceiling.ExpiresAt))
	if e1 != nil || e2 != nil || expires.After(ceilingExpires) || !expires.After(s.deps.Clock.Now()) {
		return refuse()
	}
	raw, err := s.privateLaunchObject(ctx, db, r.OriginalRequest, r.OperationID, r.Target.LifeID)
	if err != nil {
		return err
	}
	frame, err := wire.DecodeRequest(raw)
	if err != nil {
		return err
	}
	if frame.Config != r.Config || frame.RequestID != r.RequestID || frame.RequestSHA256 != r.RequestSHA256 {
		return refuse()
	}
	var requested api.GrantRequest
	switch frame.Method {
	case "lane.start":
		var start api.StartRequest
		if err := wire.Decode(frame.Params, &start); err != nil {
			return err
		}
		requested = start.Grants
	case "lane.adopt":
		var adopt api.AdoptRequest
		if err := wire.Decode(frame.Params, &adopt); err != nil {
			return err
		}
		requested = adopt.Grants
	default:
		return refuse()
	}
	// A root effective set has no delegation parent IDs. Its ordered original
	// request still selects the approved ticket-template entries. Re-key only
	// this validation request, then enforce the same immutable identities and
	// both narrowing ceilings. Lane delegations retain their actual parent IDs.
	actual := api.GrantRequest{}
	for index, next := range issued.Data {
		parentID := next.ParentGrantID
		if r.ParentLifeID == "" {
			if next.ParentGrantID != "" || index >= len(requested.Data) {
				return refuse()
			}
			parentID = requested.Data[index].ParentGrantID
		}
		// Grant derivation uses tree; snapshot is the compatible stored
		// spelling of that same ceiling. Reachable remains a distinct right.
		history := next.HistoryScope
		if history == "snapshot" {
			history = "tree"
		}
		found := false
		for _, parent := range authority.Ceiling.Data {
			ceilingHistory := parent.HistoryScope
			if ceilingHistory == "snapshot" {
				ceilingHistory = "tree"
			}
			found = found || parentID == parent.ID && next.SourceObjectID == parent.SourceObjectID && next.SourceSHA256 == parent.SourceSHA256 && history == ceilingHistory && (!next.Delegate || parent.Delegate)
		}
		if !found {
			return refuse()
		}
		actual.Data = append(actual.Data, api.DataGrantRequest{ParentGrantID: parentID, RelativePath: next.RelativePath, Access: next.Access, Delivery: next.Delivery, Destination: next.Destination, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt, PublicationID: next.PublicationID})
	}
	for index, next := range issued.Secrets {
		parentID := next.ParentGrantID
		if r.ParentLifeID == "" {
			if next.ParentGrantID != "" || index >= len(requested.Secrets) {
				return refuse()
			}
			parentID = requested.Secrets[index].ParentGrantID
		}
		found := false
		for _, parent := range authority.Ceiling.Secrets {
			found = found || parentID == parent.ID && next.SourceHandle == parent.SourceHandle && (!next.Delegate || parent.Delegate)
		}
		if !found {
			return refuse()
		}
		actual.Secrets = append(actual.Secrets, api.SecretDelegation{ParentGrantID: parentID, Name: next.Name, Version: next.Version, Delivery: next.Delivery, Target: next.Target, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	for index, next := range issued.Profiles {
		parentID := next.ParentGrantID
		if r.ParentLifeID == "" {
			if next.ParentGrantID != "" || index >= len(requested.Profiles) {
				return refuse()
			}
			parentID = requested.Profiles[index].ParentGrantID
		}
		found := false
		for _, parent := range authority.Ceiling.Profiles {
			found = found || parentID == parent.ID && next.Driver == parent.Driver && next.Provider == parent.Provider && next.Paid == parent.Paid && (!next.Delegate || parent.Delegate)
		}
		if !found {
			return refuse()
		}
		actual.Profiles = append(actual.Profiles, api.ProfileDelegation{ParentGrantID: parentID, ProfileID: next.ProfileID, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	for index, next := range issued.Network {
		parentID := next.ParentGrantID
		if r.ParentLifeID == "" {
			if next.ParentGrantID != "" || index >= len(requested.Network) {
				return refuse()
			}
			parentID = requested.Network[index].ParentGrantID
		}
		found := false
		for _, parent := range authority.Ceiling.Network {
			found = found || parentID == parent.ID && next.Mode == parent.Mode && (!next.Delegate || parent.Delegate)
		}
		if !found {
			return refuse()
		}
		actual.Network = append(actual.Network, api.NetworkDelegation{ParentGrantID: parentID, EndpointID: next.EndpointID, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	for index, next := range issued.Channels {
		parentID := next.ParentGrantID
		if r.ParentLifeID == "" {
			if next.ParentGrantID != "" || index >= len(requested.Channels) {
				return refuse()
			}
			parentID = requested.Channels[index].ParentGrantID
		}
		found := false
		for _, parent := range authority.Ceiling.Channels {
			found = found || parentID == parent.ID && (!next.Delegate || parent.Delegate)
		}
		if !found {
			return refuse()
		}
		actual.Channels = append(actual.Channels, api.ChannelDelegation{ParentGrantID: parentID, ChannelID: next.ChannelID, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	for index, next := range issued.Resources {
		parentID := next.ParentGrantID
		if r.ParentLifeID == "" {
			if next.ParentGrantID != "" || index >= len(requested.Resources) {
				return refuse()
			}
			parentID = requested.Resources[index].ParentGrantID
		}
		found := false
		for _, parent := range authority.Ceiling.Resources {
			found = found || parentID == parent.ID && next.SourceHandle == parent.SourceHandle && next.Provider == parent.Provider && (!next.Delegate || parent.Delegate)
		}
		if !found {
			return refuse()
		}
		actual.Resources = append(actual.Resources, api.ResourceDelegation{ParentGrantID: parentID, Regions: next.Regions, ImageIDs: next.ImageIDs, MachineTypes: next.MachineTypes, MaxActive: next.MaxActive, MaxHourlyMicros: next.MaxHourlyMicros, TotalBudgetMicros: next.TotalBudgetMicros, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	if err := s.launchCeiling(actual, authority.Ceiling, r.RequestedBy.Kind == "lane"); err != nil {
		return err
	}
	// The original request is a second, narrower ceiling. Equal category
	// counts plus unique parent IDs enforce a one-to-one correspondence, while
	// allowing only narrower paths/access/expiry within a requested entry.
	if len(actual.Data) != len(requested.Data) || len(actual.Secrets) != len(requested.Secrets) || len(actual.Profiles) != len(requested.Profiles) ||
		len(actual.Network) != len(requested.Network) || len(actual.Channels) != len(requested.Channels) || len(actual.Resources) != len(requested.Resources) {
		return refuse()
	}
	limit := api.GrantSet{ExpiresAt: authority.Ceiling.ExpiresAt}
	for _, want := range requested.Data {
		for _, next := range actual.Data {
			if next.ParentGrantID == want.ParentGrantID && (next.Destination != want.Destination || next.Delegate && !want.Delegate) {
				return refuse()
			}
		}
		limit.Data = append(limit.Data, api.DataGrant{ID: want.ParentGrantID, RelativePath: want.RelativePath, Access: want.Access, Delivery: want.Delivery, Destination: want.Destination, Delegate: want.Delegate, ExpiresAt: want.ExpiresAt, PublicationID: want.PublicationID})
	}
	for _, want := range requested.Secrets {
		limit.Secrets = append(limit.Secrets, api.SecretGrant{ID: want.ParentGrantID, Name: want.Name, Version: want.Version, Delivery: want.Delivery, Target: want.Target, Delegate: want.Delegate, ExpiresAt: want.ExpiresAt})
	}
	for _, want := range requested.Profiles {
		limit.Profiles = append(limit.Profiles, api.ProfileGrant{ID: want.ParentGrantID, ProfileID: want.ProfileID, Delegate: want.Delegate, ExpiresAt: want.ExpiresAt})
	}
	for _, want := range requested.Network {
		limit.Network = append(limit.Network, api.NetworkGrant{ID: want.ParentGrantID, EndpointID: want.EndpointID, Delegate: want.Delegate, ExpiresAt: want.ExpiresAt})
	}
	for _, want := range requested.Channels {
		limit.Channels = append(limit.Channels, api.ChannelGrant{ID: want.ParentGrantID, ChannelID: want.ChannelID, Delegate: want.Delegate, ExpiresAt: want.ExpiresAt})
	}
	for _, want := range requested.Resources {
		limit.Resources = append(limit.Resources, api.ResourceGrant{ID: want.ParentGrantID, Regions: want.Regions, ImageIDs: want.ImageIDs, MachineTypes: want.MachineTypes, MaxActive: want.MaxActive, MaxHourlyMicros: want.MaxHourlyMicros, TotalBudgetMicros: want.TotalBudgetMicros, Delegate: want.Delegate, ExpiresAt: want.ExpiresAt})
	}
	// Delegation checks in this pass compare to the requested Delegate bit.
	// Temporarily marking the actual request delegated would require every
	// parent to be delegable even when the child cannot delegate; check only
	// the bits that are actually issued instead.
	if !requestedDelegation(actual, requested) {
		return refuse()
	}
	return s.launchCeiling(actual, limit, false)
}

func requestedDelegation(actual, requested api.GrantRequest) bool {
	// Every request entry has a ParentGrantID and Delegate bit. Keep this
	// comparison typed through the shared request entries rather than trusting
	// category order; launchCeiling separately enforces uniqueness and matches.
	wants := map[api.ID]bool{}
	for _, value := range requested.Data {
		wants[value.ParentGrantID] = value.Delegate
	}
	for _, value := range requested.Secrets {
		wants[value.ParentGrantID] = value.Delegate
	}
	for _, value := range requested.Profiles {
		wants[value.ParentGrantID] = value.Delegate
	}
	for _, value := range requested.Network {
		wants[value.ParentGrantID] = value.Delegate
	}
	for _, value := range requested.Channels {
		wants[value.ParentGrantID] = value.Delegate
	}
	for _, value := range requested.Resources {
		wants[value.ParentGrantID] = value.Delegate
	}
	for _, value := range actual.Data {
		if value.Delegate && !wants[value.ParentGrantID] {
			return false
		}
	}
	for _, value := range actual.Secrets {
		if value.Delegate && !wants[value.ParentGrantID] {
			return false
		}
	}
	for _, value := range actual.Profiles {
		if value.Delegate && !wants[value.ParentGrantID] {
			return false
		}
	}
	for _, value := range actual.Network {
		if value.Delegate && !wants[value.ParentGrantID] {
			return false
		}
	}
	for _, value := range actual.Channels {
		if value.Delegate && !wants[value.ParentGrantID] {
			return false
		}
	}
	for _, value := range actual.Resources {
		if value.Delegate && !wants[value.ParentGrantID] {
			return false
		}
	}
	return true
}

package store

import (
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Revalidation may only narrow the retained life-owned set. This comparison
// does not issue grants or replace Resolve/Revalidate's sealed-source checks.
func (s *Service) narrowedLaunchGrants(before, after api.GrantSet) bool {
	if before.ID != after.ID || before.LifeID != after.LifeID || before.ParentLifeID != after.ParentLifeID || after.Generation != before.Generation+1 || before.PolicyGeneration > after.PolicyGeneration || after.Revoked {
		return false
	}
	a, e1 := time.Parse(time.RFC3339Nano, string(after.ExpiresAt))
	b, e2 := time.Parse(time.RFC3339Nano, string(before.ExpiresAt))
	if e1 != nil || e2 != nil || a.After(b) || !a.After(s.deps.Clock.Now()) {
		return false
	}
	request := api.GrantRequest{}
	for _, next := range after.Data {
		found := false
		for _, old := range before.Data {
			if next.ID == old.ID && next.ParentGrantID == old.ParentGrantID && next.SourceObjectID == old.SourceObjectID && next.SourceSHA256 == old.SourceSHA256 && next.HistoryScope == old.HistoryScope && next.Destination == old.Destination && (!next.Delegate || old.Delegate) {
				found = true
			}
		}
		if !found {
			return false
		}
		request.Data = append(request.Data, api.DataGrantRequest{ParentGrantID: next.ID, RelativePath: next.RelativePath, Access: next.Access, Delivery: next.Delivery, Destination: next.Destination, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt, PublicationID: next.PublicationID})
	}
	for _, next := range after.Secrets {
		found := false
		for _, old := range before.Secrets {
			if next.ID == old.ID && next.ParentGrantID == old.ParentGrantID && next.SourceHandle == old.SourceHandle && (!next.Delegate || old.Delegate) {
				found = true
			}
		}
		if !found {
			return false
		}
		request.Secrets = append(request.Secrets, api.SecretDelegation{ParentGrantID: next.ID, Name: next.Name, Version: next.Version, Delivery: next.Delivery, Target: next.Target, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	for _, next := range after.Profiles {
		found := false
		for _, old := range before.Profiles {
			if next.ID == old.ID && next.ParentGrantID == old.ParentGrantID && next.Driver == old.Driver && next.Provider == old.Provider && next.Paid == old.Paid && (!next.Delegate || old.Delegate) {
				found = true
			}
		}
		if !found {
			return false
		}
		request.Profiles = append(request.Profiles, api.ProfileDelegation{ParentGrantID: next.ID, ProfileID: next.ProfileID, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	for _, next := range after.Network {
		found := false
		for _, old := range before.Network {
			if next.ID == old.ID && next.ParentGrantID == old.ParentGrantID && next.Mode == old.Mode && (!next.Delegate || old.Delegate) {
				found = true
			}
		}
		if !found {
			return false
		}
		request.Network = append(request.Network, api.NetworkDelegation{ParentGrantID: next.ID, EndpointID: next.EndpointID, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	for _, next := range after.Channels {
		found := false
		for _, old := range before.Channels {
			if next.ID == old.ID && next.ParentGrantID == old.ParentGrantID && (!next.Delegate || old.Delegate) {
				found = true
			}
		}
		if !found {
			return false
		}
		request.Channels = append(request.Channels, api.ChannelDelegation{ParentGrantID: next.ID, ChannelID: next.ChannelID, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	for _, next := range after.Resources {
		found := false
		for _, old := range before.Resources {
			if next.ID == old.ID && next.ParentGrantID == old.ParentGrantID && next.SourceHandle == old.SourceHandle && next.Provider == old.Provider && (!next.Delegate || old.Delegate) {
				found = true
			}
		}
		if !found {
			return false
		}
		request.Resources = append(request.Resources, api.ResourceDelegation{ParentGrantID: next.ID, Regions: next.Regions, ImageIDs: next.ImageIDs, MachineTypes: next.MachineTypes, MaxActive: next.MaxActive, MaxHourlyMicros: next.MaxHourlyMicros, TotalBudgetMicros: next.TotalBudgetMicros, Delegate: next.Delegate, ExpiresAt: next.ExpiresAt})
	}
	return s.launchCeiling(request, before, false) == nil
}

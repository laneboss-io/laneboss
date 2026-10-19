package store

import (
	"path"
	"slices"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// This is the transactional ceiling fence, not grant issuance. Resolve still
// owns issuing the reserved child set and revalidating sealed delegation.
func (s *Service) launchCeiling(request api.GrantRequest, ceiling api.GrantSet, delegated bool) error {
	refuse := func() error { return fault(api.CodeForbidden, "launch request exceeds its current grant ceiling") }
	expiry := func(want, max api.Timestamp) bool {
		w, e1 := time.Parse(time.RFC3339Nano, string(want))
		m, e2 := time.Parse(time.RFC3339Nano, string(max))
		set, e3 := time.Parse(time.RFC3339Nano, string(ceiling.ExpiresAt))
		return e1 == nil && e2 == nil && e3 == nil && w.After(s.deps.Clock.Now()) && !w.After(m) && !w.After(set)
	}
	seen := map[api.ID]bool{}
	unique := func(id api.ID) bool {
		if id == "" || seen[id] {
			return false
		}
		seen[id] = true
		return true
	}
	for _, want := range request.Data {
		if !unique(want.ParentGrantID) || !relativeGrantPath(want.RelativePath) || manifest.Destination(want.Destination) != nil {
			return refuse()
		}
		matched := 0
		for _, have := range ceiling.Data {
			if have.ID == want.ParentGrantID && (!delegated || have.Delegate) && expiry(want.ExpiresAt, have.ExpiresAt) &&
				relativeGrantPath(have.RelativePath) && withinGrantPath(want.RelativePath, have.RelativePath) &&
				(want.Access == "ro" || want.Access == "rw" && have.Access == "rw") &&
				(want.Delivery == "copy" || want.Delivery == "mount" && have.Delivery == "mount") &&
				(want.PublicationID == "" || want.PublicationID == have.PublicationID) {
				matched++
			}
		}
		if matched != 1 {
			return refuse()
		}
	}
	for _, want := range request.Secrets {
		if !unique(want.ParentGrantID) {
			return refuse()
		}
		matched := 0
		for _, have := range ceiling.Secrets {
			if have.ID == want.ParentGrantID && (!delegated || have.Delegate) && expiry(want.ExpiresAt, have.ExpiresAt) &&
				want.Name == have.Name && want.Version == have.Version && want.Delivery == have.Delivery && want.Target == have.Target {
				matched++
			}
		}
		if matched != 1 {
			return refuse()
		}
	}
	for _, want := range request.Profiles {
		if !unique(want.ParentGrantID) {
			return refuse()
		}
		matched := 0
		for _, have := range ceiling.Profiles {
			if have.ID == want.ParentGrantID && want.ProfileID == have.ProfileID && (!delegated || have.Delegate) && expiry(want.ExpiresAt, have.ExpiresAt) {
				matched++
			}
		}
		if matched != 1 {
			return refuse()
		}
	}
	for _, want := range request.Network {
		if !unique(want.ParentGrantID) {
			return refuse()
		}
		matched := 0
		for _, have := range ceiling.Network {
			if have.ID == want.ParentGrantID && want.EndpointID == have.EndpointID && (!delegated || have.Delegate) && expiry(want.ExpiresAt, have.ExpiresAt) {
				matched++
			}
		}
		if matched != 1 {
			return refuse()
		}
	}
	for _, want := range request.Channels {
		if !unique(want.ParentGrantID) {
			return refuse()
		}
		matched := 0
		for _, have := range ceiling.Channels {
			if have.ID == want.ParentGrantID && want.ChannelID == have.ChannelID && (!delegated || have.Delegate) && expiry(want.ExpiresAt, have.ExpiresAt) {
				matched++
			}
		}
		if matched != 1 {
			return refuse()
		}
	}
	for _, want := range request.Resources {
		if !unique(want.ParentGrantID) {
			return refuse()
		}
		matched := 0
		for _, have := range ceiling.Resources {
			if have.ID == want.ParentGrantID && (!delegated || have.Delegate) && expiry(want.ExpiresAt, have.ExpiresAt) &&
				stringSubset(want.Regions, have.Regions) && stringSubset(want.ImageIDs, have.ImageIDs) && stringSubset(want.MachineTypes, have.MachineTypes) &&
				want.MaxActive > 0 && want.MaxActive <= have.MaxActive && want.MaxHourlyMicros >= 0 && want.MaxHourlyMicros <= have.MaxHourlyMicros &&
				want.TotalBudgetMicros >= 0 && want.TotalBudgetMicros <= have.TotalBudgetMicros {
				matched++
			}
		}
		if matched != 1 {
			return refuse()
		}
	}
	return nil
}

func relativeGrantPath(value string) bool {
	return value != "" && !path.IsAbs(value) && path.Clean(value) == value && value != ".." && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "\\\x00")
}

func withinGrantPath(value, parent string) bool {
	return parent == "." || value == parent || strings.HasPrefix(value, parent+"/")
}

func stringSubset(want, have []string) bool {
	if len(want) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range want {
		if seen[value] || !slices.Contains(have, value) {
			return false
		}
		seen[value] = true
	}
	return true
}

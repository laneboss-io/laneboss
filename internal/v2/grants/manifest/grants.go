package manifest

import (
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Root checks inert manifest structure. It cannot establish that protected
// enrollment handles exist or consume the human's operation-bound proof.
func Root(value api.RootGrantManifest, now time.Time) error {
	if value.Schema != "laneboss.root-grants.v2" {
		return Invalid("unknown root grant manifest schema")
	}
	set := api.GrantSet{Resources: value.Resources, Data: value.Data,
		Secrets: value.Secrets, Profiles: value.Profiles, Network: value.Network,
		Channels: value.Channels}
	return entries(set, now, true, true)
}

func Set(value api.GrantSet, now time.Time) error {
	return set(value, now, true)
}

// StoredSet checks immutable record structure without treating expiration or
// revocation as a reason to hide an authorized historical record.
func StoredSet(value api.GrantSet) error { return set(value, time.Time{}, false) }

func set(value api.GrantSet, now time.Time, live bool) error {
	if !ValidID(value.ID) || !ValidID(value.LifeID) || !ValidDigest(value.SHA256) ||
		value.Generation == 0 || uint64(value.Generation) > MaxInteger ||
		value.PolicyGeneration == 0 || uint64(value.PolicyGeneration) > MaxInteger ||
		(value.ParentLifeID != "" && !ValidID(value.ParentLifeID)) {
		return Invalid("invalid effective grant set identity or generation")
	}
	if value.Revoked && live {
		return &api.Error{Code: api.CodeForbidden, Message: "grant set is revoked",
			Instead: "Obtain a new explicit grant and restart with narrower authority.",
			Owner:   "lb-v2-grants"}
	}
	if _, err := Time(value.ExpiresAt); err != nil {
		return err
	}
	if live {
		if _, err := Expiry(value.ExpiresAt, now); err != nil {
			return err
		}
	}
	if err := entries(value, now, false, live); err != nil {
		return err
	}
	for _, expiry := range Expiries(value) {
		parsed, err := Time(expiry)
		if err != nil {
			return err
		}
		limit, err := Time(value.ExpiresAt)
		if err != nil {
			return err
		}
		if parsed.After(limit) {
			return Invalid("member expiry exceeds the grant set ceiling")
		}
	}
	return nil
}

func entries(value api.GrantSet, now time.Time, root, live bool) error {
	if value.Resources == nil || value.Data == nil || value.Secrets == nil ||
		value.Profiles == nil || value.Network == nil || value.Channels == nil {
		return Invalid("grant collections must be nonnull arrays")
	}
	if len(value.Resources)+len(value.Data)+len(value.Secrets)+len(value.Profiles)+
		len(value.Network)+len(value.Channels) > 4096 {
		return Invalid("too many grants")
	}
	ids := map[api.ID]bool{}
	check := func(id, parent api.ID, expiry api.Timestamp) error {
		if root {
			if id != "" || parent != "" {
				return Invalid("root entries cannot supply service-issued grant IDs")
			}
		} else {
			if !ValidID(id) || ids[id] {
				return Invalid("invalid or duplicate effective grant ID")
			}
			ids[id] = true
			if value.ParentLifeID == "" && parent != "" ||
				value.ParentLifeID != "" && !ValidID(parent) {
				return Invalid("grant parent identity does not match its life")
			}
		}
		if !live {
			_, err := Time(expiry)
			return err
		}
		_, err := Expiry(expiry, now)
		return err
	}
	destinations := map[string]bool{}
	for i, grant := range value.Data {
		if err := check(grant.ID, grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !ValidID(grant.SourceObjectID) || !ValidDigest(grant.SourceSHA256) ||
			(grant.PublicationID != "" && !ValidID(grant.PublicationID)) {
			return Invalid("data grant needs a registered source identity")
		}
		if err := Relative(grant.RelativePath); err != nil {
			return err
		}
		if err := Destination(grant.Destination); err != nil {
			return err
		}
		destinationKey := strings.ToLower(grant.Destination)
		if destinations[destinationKey] {
			return Invalid("data destinations overlap")
		}
		destinations[destinationKey] = true
		if grant.Access != "ro" && grant.Access != "rw" ||
			grant.Delivery != "copy" && grant.Delivery != "mount" {
			return Invalid("unknown data access or delivery")
		}
		if grant.HistoryScope != "snapshot" && grant.HistoryScope != "tree" && grant.HistoryScope != "reachable" {
			return &api.Error{Code: api.CodeUnsupported,
				Message: "unknown data history scope",
				Instead: "Use tree or explicitly granted reachable history.", Owner: "lb-v2-grants"}
		}
		if grant.HistoryScope == "reachable" && grant.RelativePath != "." {
			return Invalid("reachable history requires the complete granted source root")
		}
		for j := 0; j < i; j++ {
			other := value.Data[j]
			if grant.SourceObjectID == other.SourceObjectID &&
				(Beneath(grant.RelativePath, other.RelativePath) || Beneath(other.RelativePath, grant.RelativePath)) {
				return Invalid("data source grants have ambiguous overlapping rights")
			}
		}
	}
	targets := map[string]bool{}
	names := map[string]bool{}
	for _, grant := range value.Secrets {
		if err := check(grant.ID, grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !selection(grant.Name) || !selection(grant.Version) ||
			!ValidID(grant.SourceHandle) || names[grant.Name] {
			return Invalid("secret selection is invalid or duplicated")
		}
		names[grant.Name] = true
		if err := SecretTarget(grant.Delivery, grant.Target); err != nil {
			return err
		}
		key := grant.Delivery + ":" + grant.Target
		if targets[key] {
			return Invalid("secret delivery targets collide")
		}
		targets[key] = true
	}
	profiles := map[api.ID]bool{}
	for _, grant := range value.Profiles {
		if err := check(grant.ID, grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !ValidID(grant.ProfileID) || profiles[grant.ProfileID] || grant.Provider == "" ||
			(grant.Driver != api.DriverClaudock && grant.Driver != api.DriverCodex) {
			return Invalid("invalid or duplicate profile selection or driver")
		}
		profiles[grant.ProfileID] = true
	}
	endpoints := map[api.ID]bool{}
	for _, grant := range value.Network {
		if err := check(grant.ID, grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !ValidID(grant.EndpointID) || endpoints[grant.EndpointID] ||
			(grant.Mode != "internet" && grant.Mode != "service" && grant.Mode != "publish") {
			return Invalid("invalid or duplicate network selection")
		}
		endpoints[grant.EndpointID] = true
	}
	channels := map[api.ID]bool{}
	for _, grant := range value.Channels {
		if err := check(grant.ID, grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !ValidID(grant.ChannelID) || channels[grant.ChannelID] {
			return Invalid("invalid or duplicate channel selection")
		}
		channels[grant.ChannelID] = true
	}
	resources := map[api.ID]bool{}
	for _, grant := range value.Resources {
		if err := check(grant.ID, grant.ParentGrantID, grant.ExpiresAt); err != nil {
			return err
		}
		if !ValidID(grant.SourceHandle) || resources[grant.SourceHandle] ||
			(grant.Provider != "aws" && grant.Provider != "gcp") ||
			grant.MaxActive == 0 || grant.MaxHourlyMicros < 0 ||
			uint64(grant.MaxHourlyMicros) > MaxInteger || grant.TotalBudgetMicros < 0 ||
			uint64(grant.TotalBudgetMicros) > MaxInteger {
			return Invalid("invalid or duplicate resource capability or ceiling")
		}
		resources[grant.SourceHandle] = true
		for _, values := range [][]string{grant.Regions, grant.ImageIDs, grant.MachineTypes} {
			if err := Selections(values); err != nil {
				return err
			}
		}
	}
	return nil
}

func Selections(values []string) error {
	if len(values) == 0 || len(values) > 1024 {
		return Invalid("resource selections must be explicit nonempty arrays")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !selection(value) || seen[value] {
			return Invalid("invalid, wildcard or duplicate resource selection")
		}
		seen[value] = true
	}
	return nil
}

func Expiries(value api.GrantSet) []api.Timestamp {
	result := []api.Timestamp{}
	for _, grant := range value.Data {
		result = append(result, grant.ExpiresAt)
	}
	for _, grant := range value.Secrets {
		result = append(result, grant.ExpiresAt)
	}
	for _, grant := range value.Profiles {
		result = append(result, grant.ExpiresAt)
	}
	for _, grant := range value.Network {
		result = append(result, grant.ExpiresAt)
	}
	for _, grant := range value.Channels {
		result = append(result, grant.ExpiresAt)
	}
	for _, grant := range value.Resources {
		result = append(result, grant.ExpiresAt)
	}
	return result
}

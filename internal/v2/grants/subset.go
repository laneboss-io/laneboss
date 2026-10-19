package grants

import (
	"crypto/rand"
	"encoding/hex"
	"path"
	"reflect"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func refused(message string) *api.Error {
	return &api.Error{Code: api.CodeForbidden, Message: message,
		Instead: "Request a subset of the authentic starter's current grants.", Owner: "lb-v2-grants"}
}

func conflict(message string) *api.Error {
	return &api.Error{Code: api.CodeConflict, Message: message,
		Instead: "Read the current life, grants and policy, then submit a new explicit decision.",
		Owner:   "lb-v2-grants"}
}

func freshID() (api.ID, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", &api.Error{Code: api.CodeUnavailable, Message: "secure grant ID generation is unavailable",
			Instead: "Repair the system random source before issuing grants.", Owner: "lb-v2-grants"}
	}
	return api.ID("g_" + hex.EncodeToString(value[:])), nil
}

func within(expiry, parent, set api.Timestamp, delegate, parentDelegate bool, now time.Time) error {
	if !parentDelegate {
		return refused("parent grant does not permit delegation")
	}
	requested, err := manifest.Expiry(expiry, now)
	if err != nil {
		return err
	}
	ceiling, err := manifest.Expiry(parent, now)
	if err != nil {
		return err
	}
	setCeiling, err := manifest.Expiry(set, now)
	if err != nil {
		return err
	}
	if requested.After(ceiling) || requested.After(setCeiling) {
		return refused("child grant expiry exceeds parent authority")
	}
	return nil
}

// derive issues only an inert preview. It does not persist a life, grant, event
// or launch. Lifecycle must atomically commit the returned life/set identities
// and revalidate them immediately before releasing a worker or agent.
func derive(parent api.GrantSet, request api.GrantRequest, now time.Time) (api.GrantSet, error) {
	return deriveWith(parent, request, now, freshID, within)
}

func deriveWith(parent api.GrantSet, request api.GrantRequest, now time.Time, issue func() (api.ID, error),
	bound func(api.Timestamp, api.Timestamp, api.Timestamp, bool, bool, time.Time) error) (api.GrantSet, error) {
	var zero api.GrantSet
	if err := manifest.RequestCollections(request); err != nil {
		return zero, err
	}
	if err := manifest.Set(parent, now); err != nil {
		return zero, err
	}
	result := api.GrantSet{ParentLifeID: parent.LifeID, Generation: 1,
		PolicyGeneration: parent.PolicyGeneration, ExpiresAt: parent.ExpiresAt,
		Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Secrets: []api.SecretGrant{},
		Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	var err error
	result.ID, err = issue()
	if err != nil {
		return zero, err
	}
	result.LifeID, err = issue()
	if err != nil {
		return zero, err
	}
	for _, r := range request.Data {
		p, found := findData(parent.Data, r.ParentGrantID)
		if !found {
			return zero, refused("data parent grant is absent")
		}
		if err := bound(r.ExpiresAt, p.ExpiresAt, parent.ExpiresAt, r.Delegate, p.Delegate, now); err != nil {
			return zero, err
		}
		if err := manifest.DataInput(r); err != nil {
			return zero, err
		}
		if p.Access == "ro" && r.Access == "rw" {
			return zero, refused("child cannot widen data access")
		}
		if r.PublicationID != "" && r.PublicationID != p.PublicationID {
			return zero, refused("child cannot select another publication target")
		}
		if r.Delivery == "mount" {
			if p.Delivery != "mount" {
				return zero, refused("an independent copy cannot delegate a live source mount")
			}
			return zero, &api.Error{Code: api.CodeUnsupported, Message: "live mount delivery has no verified export lease",
				Instead: "Request an independent copy; live exports require pinned identity and exclusive writer proof.", Owner: "lb-v2-grants"}
		}
		id, err := issue()
		if err != nil {
			return zero, err
		}
		result.Data = append(result.Data, api.DataGrant{ID: id, ParentGrantID: p.ID,
			SourceObjectID: p.SourceObjectID, SourceSHA256: p.SourceSHA256,
			RelativePath: path.Join(p.RelativePath, r.RelativePath), Access: r.Access,
			Delivery: r.Delivery, Destination: r.Destination, Delegate: r.Delegate,
			ExpiresAt: r.ExpiresAt, PublicationID: r.PublicationID, HistoryScope: derivedHistory(p, r)})
	}
	for _, r := range request.Secrets {
		p, found := findSecret(parent.Secrets, r.ParentGrantID)
		if !found {
			return zero, refused("secret parent grant is absent")
		}
		if err := bound(r.ExpiresAt, p.ExpiresAt, parent.ExpiresAt, r.Delegate, p.Delegate, now); err != nil {
			return zero, err
		}
		if r.Name != p.Name || r.Version != p.Version || r.Delivery != p.Delivery || r.Target != p.Target {
			return zero, refused("child secret source, version or delivery exceeds its parent")
		}
		if err := manifest.SecretInput(r); err != nil {
			return zero, err
		}
		id, err := issue()
		if err != nil {
			return zero, err
		}
		result.Secrets = append(result.Secrets, api.SecretGrant{ID: id, ParentGrantID: p.ID,
			Name: p.Name, SourceHandle: p.SourceHandle, Version: p.Version, Delivery: p.Delivery,
			Target: p.Target, Delegate: r.Delegate, ExpiresAt: r.ExpiresAt})
	}
	for _, r := range request.Profiles {
		p, found := findProfile(parent.Profiles, r.ParentGrantID)
		if !found || r.ProfileID != p.ProfileID {
			return zero, refused("profile parent or selection is absent")
		}
		if err := bound(r.ExpiresAt, p.ExpiresAt, parent.ExpiresAt, r.Delegate, p.Delegate, now); err != nil {
			return zero, err
		}
		id, err := issue()
		if err != nil {
			return zero, err
		}
		p.ID, p.ParentGrantID, p.Delegate, p.ExpiresAt = id, r.ParentGrantID, r.Delegate, r.ExpiresAt
		result.Profiles = append(result.Profiles, p)
	}
	for _, r := range request.Network {
		p, found := findNetwork(parent.Network, r.ParentGrantID)
		if !found || r.EndpointID != p.EndpointID {
			return zero, refused("network parent or selection is absent")
		}
		if err := bound(r.ExpiresAt, p.ExpiresAt, parent.ExpiresAt, r.Delegate, p.Delegate, now); err != nil {
			return zero, err
		}
		id, err := issue()
		if err != nil {
			return zero, err
		}
		p.ID, p.ParentGrantID, p.Delegate, p.ExpiresAt = id, r.ParentGrantID, r.Delegate, r.ExpiresAt
		result.Network = append(result.Network, p)
	}
	for _, r := range request.Channels {
		p, found := findChannel(parent.Channels, r.ParentGrantID)
		if !found || r.ChannelID != p.ChannelID {
			return zero, refused("channel parent or selection is absent")
		}
		if err := bound(r.ExpiresAt, p.ExpiresAt, parent.ExpiresAt, r.Delegate, p.Delegate, now); err != nil {
			return zero, err
		}
		id, err := issue()
		if err != nil {
			return zero, err
		}
		p.ID, p.ParentGrantID, p.Delegate, p.ExpiresAt = id, r.ParentGrantID, r.Delegate, r.ExpiresAt
		result.Channels = append(result.Channels, p)
	}
	for _, r := range request.Resources {
		p, found := findResource(parent.Resources, r.ParentGrantID)
		if !found {
			return zero, refused("resource parent grant is absent")
		}
		if err := bound(r.ExpiresAt, p.ExpiresAt, parent.ExpiresAt, r.Delegate, p.Delegate, now); err != nil {
			return zero, err
		}
		if err := selectionSubset(p.Regions, r.Regions); err != nil {
			return zero, err
		}
		if err := selectionSubset(p.ImageIDs, r.ImageIDs); err != nil {
			return zero, err
		}
		if err := selectionSubset(p.MachineTypes, r.MachineTypes); err != nil {
			return zero, err
		}
		if r.MaxActive == 0 || r.MaxActive > p.MaxActive || r.MaxHourlyMicros < 0 ||
			r.MaxHourlyMicros > p.MaxHourlyMicros || r.TotalBudgetMicros < 0 || r.TotalBudgetMicros > p.TotalBudgetMicros {
			return zero, refused("resource concurrency or cost exceeds the parent ceiling")
		}
		id, err := issue()
		if err != nil {
			return zero, err
		}
		p.ID, p.ParentGrantID, p.Delegate, p.ExpiresAt = id, r.ParentGrantID, r.Delegate, r.ExpiresAt
		p.Regions, p.ImageIDs, p.MachineTypes = append([]string{}, r.Regions...), append([]string{}, r.ImageIDs...), append([]string{}, r.MachineTypes...)
		p.MaxActive, p.MaxHourlyMicros, p.TotalBudgetMicros = r.MaxActive, r.MaxHourlyMicros, r.TotalBudgetMicros
		result.Resources = append(result.Resources, p)
	}
	firstExpiry := true
	for _, expiry := range manifest.Expiries(result) {
		t, err := manifest.Time(expiry)
		if err != nil {
			return zero, err
		}
		limit, err := manifest.Time(result.ExpiresAt)
		if err != nil {
			return zero, err
		}
		if firstExpiry || t.After(limit) {
			result.ExpiresAt = expiry
		}
		firstExpiry = false
	}
	if err := seal(&result); err != nil {
		return zero, err
	}
	if err := manifest.Set(result, now); err != nil {
		return zero, err
	}
	return result, nil
}

func derivedHistory(parent api.DataGrant, request api.DataGrantRequest) string {
	if parent.HistoryScope == "reachable" && parent.RelativePath == "." && request.RelativePath == "." {
		return "reachable"
	}
	return "tree"
}

// Digest convention: JCS of the complete GrantSet with sha256 set to "".
// The stored digest is checked independently of request/body hashes.
func seal(value *api.GrantSet) error {
	value.SHA256 = ""
	digest, err := manifest.HashValue(*value)
	if err != nil {
		return err
	}
	value.SHA256 = digest
	return nil
}

func selectionSubset(parent, child []string) error {
	if err := manifest.Selections(child); err != nil {
		return err
	}
	for _, value := range child {
		found := false
		for _, candidate := range parent {
			if value == candidate {
				found = true
				break
			}
		}
		if !found {
			return refused("resource selection exceeds its parent")
		}
	}
	return nil
}

func findData(values []api.DataGrant, id api.ID) (api.DataGrant, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return api.DataGrant{}, false
}
func findSecret(values []api.SecretGrant, id api.ID) (api.SecretGrant, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return api.SecretGrant{}, false
}
func findProfile(values []api.ProfileGrant, id api.ID) (api.ProfileGrant, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return api.ProfileGrant{}, false
}
func findNetwork(values []api.NetworkGrant, id api.ID) (api.NetworkGrant, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return api.NetworkGrant{}, false
}
func findChannel(values []api.ChannelGrant, id api.ID) (api.ChannelGrant, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return api.ChannelGrant{}, false
}
func findResource(values []api.ResourceGrant, id api.ID) (api.ResourceGrant, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return api.ResourceGrant{}, false
}

func checkChild(parent, child api.GrantSet, now time.Time) error {
	if child.ParentLifeID != parent.LifeID {
		return refused("grant set has a different authentic parent")
	}
	r := api.GrantRequest{Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{},
		Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{},
		Channels: []api.ChannelDelegation{}, Resources: []api.ResourceDelegation{}}
	for _, g := range child.Data {
		p, found := findData(parent.Data, g.ParentGrantID)
		if !found || !manifest.Beneath(p.RelativePath, g.RelativePath) {
			return refused("data no longer belongs to the parent scope")
		}
		relative := g.RelativePath
		if p.RelativePath == g.RelativePath {
			relative = "."
		} else if p.RelativePath != "." {
			relative = strings.TrimPrefix(g.RelativePath, p.RelativePath+"/")
		}
		r.Data = append(r.Data, api.DataGrantRequest{ParentGrantID: p.ID, RelativePath: relative,
			Access: g.Access, Delivery: g.Delivery, Destination: g.Destination,
			Delegate: g.Delegate, ExpiresAt: g.ExpiresAt, PublicationID: g.PublicationID})
	}
	for _, g := range child.Secrets {
		r.Secrets = append(r.Secrets, api.SecretDelegation{ParentGrantID: g.ParentGrantID, Name: g.Name, Version: g.Version, Delivery: g.Delivery, Target: g.Target, Delegate: g.Delegate, ExpiresAt: g.ExpiresAt})
	}
	for _, g := range child.Profiles {
		r.Profiles = append(r.Profiles, api.ProfileDelegation{ParentGrantID: g.ParentGrantID, ProfileID: g.ProfileID, Delegate: g.Delegate, ExpiresAt: g.ExpiresAt})
	}
	for _, g := range child.Network {
		r.Network = append(r.Network, api.NetworkDelegation{ParentGrantID: g.ParentGrantID, EndpointID: g.EndpointID, Delegate: g.Delegate, ExpiresAt: g.ExpiresAt})
	}
	for _, g := range child.Channels {
		r.Channels = append(r.Channels, api.ChannelDelegation{ParentGrantID: g.ParentGrantID, ChannelID: g.ChannelID, Delegate: g.Delegate, ExpiresAt: g.ExpiresAt})
	}
	for _, g := range child.Resources {
		r.Resources = append(r.Resources, api.ResourceDelegation{ParentGrantID: g.ParentGrantID, Regions: g.Regions, ImageIDs: g.ImageIDs, MachineTypes: g.MachineTypes, MaxActive: g.MaxActive, MaxHourlyMicros: g.MaxHourlyMicros, TotalBudgetMicros: g.TotalBudgetMicros, Delegate: g.Delegate, ExpiresAt: g.ExpiresAt})
	}
	derived, err := derive(parent, r, now)
	if err != nil {
		return err
	}
	for i := range derived.Data {
		derived.Data[i].ID = child.Data[i].ID
		// The prior snapshot spelling denotes the same tree-only ceiling.
		// Revalidation preserves the stored record instead of rewriting it.
		if derived.Data[i].HistoryScope == "tree" && child.Data[i].HistoryScope == "snapshot" {
			derived.Data[i].HistoryScope = "snapshot"
		}
	}
	for i := range derived.Secrets {
		derived.Secrets[i].ID = child.Secrets[i].ID
	}
	for i := range derived.Profiles {
		derived.Profiles[i].ID = child.Profiles[i].ID
	}
	for i := range derived.Network {
		derived.Network[i].ID = child.Network[i].ID
	}
	for i := range derived.Channels {
		derived.Channels[i].ID = child.Channels[i].ID
	}
	for i := range derived.Resources {
		derived.Resources[i].ID = child.Resources[i].ID
	}
	if !reflect.DeepEqual(derived.Data, child.Data) || !reflect.DeepEqual(derived.Secrets, child.Secrets) ||
		!reflect.DeepEqual(derived.Profiles, child.Profiles) || !reflect.DeepEqual(derived.Network, child.Network) ||
		!reflect.DeepEqual(derived.Channels, child.Channels) || !reflect.DeepEqual(derived.Resources, child.Resources) {
		return refused("stored child source or capability differs from its parent's authority")
	}
	limit, err := manifest.Time(derived.ExpiresAt)
	if err != nil {
		return err
	}
	actual, err := manifest.Time(child.ExpiresAt)
	if err != nil {
		return err
	}
	if actual.After(limit) {
		return refused("child grant set outlives current parent authority")
	}
	return nil
}

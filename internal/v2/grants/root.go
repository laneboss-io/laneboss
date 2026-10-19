package grants

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func rootSecretNative(s *Service) bool {
	backend, ok := s.deps.Profiles.(rootSecretEnrollment)
	return ok && !nilInterface(backend)
}

// issueSecretRoot borrows the native journal as rootProfileRead while it holds
// the native lock. That borrowed view is still the same native secret path, so
// issueRootSet must not re-enter the object-backed secret resolver for it.
func rootSecretNativeContext(s *Service) bool {
	if rootSecretNative(s) {
		return true
	}
	_, borrowed := s.deps.Profiles.(*rootProfileRead)
	return borrowed
}

func (s *Service) issueRoot(ctx context.Context, scope api.Scope, input api.RootGrantManifest, budget api.Budget, guard api.TransactionGuard) (api.GrantSet, error) {
	var zero api.GrantSet
	nativeSecrets := rootSecretNative(s)
	// An installed native reader authenticates secret handles while holding its
	// lock through the root transaction. Resource handles still use the grants
	// line's protected object resolver in this mixed path.
	if len(input.Secrets) != 0 && nativeSecrets {
		if len(input.Resources) != 0 {
			enrolled := input
			enrolled.Secrets = nil
			if err := s.rootEnrollments(ctx, scope, enrolled); err != nil {
				return zero, err
			}
		}
		return s.issueSecretRoot(ctx, scope, input, budget, guard)
	}
	if len(input.Secrets)+len(input.Resources) != 0 {
		if err := s.rootEnrollments(ctx, scope, input); err != nil {
			// A missing object-backed secret with no installed profile backend is
			// the secrets branch's unwired case. Other resolver errors, and all
			// resource-backed requests, retain their grants error unchanged.
			if len(input.Resources) == 0 && nilInterface(s.deps.Profiles) {
				var typed *api.Error
				if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
					return s.issueSecretRoot(ctx, scope, input, budget, guard)
				}
			}
			return zero, err
		}
	}
	if len(input.Data)+len(input.Channels)+len(input.Profiles)+len(input.Network)+len(input.Secrets)+len(input.Resources) == 0 {
		return zero, manifest.Invalid("root grants require an explicit immutable source or enrolled capability")
	}
	if len(input.Profiles) != 0 {
		return s.issueProfileRoot(ctx, scope, input, budget, guard)
	}
	return s.issueRootSet(ctx, scope, input, budget, guard)
}

func (s *Service) issueRootSet(ctx context.Context, scope api.Scope, input api.RootGrantManifest, budget api.Budget, guard api.TransactionGuard) (issued api.GrantSet, resultErr error) {
	var zero api.GrantSet
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return zero, err
	}
	if policy.Generation == 0 || policy.Generation != scope.PolicyGeneration {
		return zero, conflict("root grant policy generation changed")
	}
	set := api.GrantSet{Generation: 1, PolicyGeneration: policy.Generation, Data: append([]api.DataGrant{}, input.Data...),
		Resources: append([]api.ResourceGrant{}, input.Resources...), Secrets: append([]api.SecretGrant{}, input.Secrets...), Profiles: append([]api.ProfileGrant{}, input.Profiles...),
		Network: append([]api.NetworkGrant{}, input.Network...), Channels: append([]api.ChannelGrant{}, input.Channels...)}
	set.ID, err = freshID()
	if err != nil {
		return zero, err
	}
	set.LifeID, err = freshID()
	if err != nil {
		return zero, err
	}
	issueMember := func(id *api.ID, expires api.Timestamp) error {
		var err error
		*id, err = freshID()
		if err != nil {
			return err
		}
		expiry, err := manifest.Time(expires)
		if err != nil {
			return err
		}
		if set.ExpiresAt == "" {
			set.ExpiresAt = expires
			return nil
		}
		ceiling, err := manifest.Time(set.ExpiresAt)
		if err != nil {
			return err
		}
		if expiry.After(ceiling) {
			set.ExpiresAt = expires
		}
		return nil
	}
	for i := range set.Resources {
		if err := issueMember(&set.Resources[i].ID, set.Resources[i].ExpiresAt); err != nil {
			return zero, err
		}
	}
	for i := range set.Secrets {
		if err := issueMember(&set.Secrets[i].ID, set.Secrets[i].ExpiresAt); err != nil {
			return zero, err
		}
	}
	for i := range set.Data {
		if set.Data[i].Delivery != "copy" {
			return zero, api.NotImplemented("lb-v2-grants", "root broker export enrollment and pinned lease")
		}
		set.Data[i].ID, err = freshID()
		if err != nil {
			return zero, err
		}
		expiry, err := manifest.Time(set.Data[i].ExpiresAt)
		if err != nil {
			return zero, err
		}
		if set.ExpiresAt == "" {
			set.ExpiresAt = set.Data[i].ExpiresAt
		} else {
			ceiling, err := manifest.Time(set.ExpiresAt)
			if err != nil {
				return zero, err
			}
			if expiry.After(ceiling) {
				set.ExpiresAt = set.Data[i].ExpiresAt
			}
		}
	}
	for i := range set.Profiles {
		grant := &set.Profiles[i]
		grant.ID, err = freshID()
		if err != nil {
			return zero, err
		}
		expiry, err := manifest.Time(grant.ExpiresAt)
		if err != nil {
			return zero, err
		}
		if set.ExpiresAt == "" {
			set.ExpiresAt = grant.ExpiresAt
		} else {
			limit, err := manifest.Time(set.ExpiresAt)
			if err != nil {
				return zero, err
			}
			if expiry.After(limit) {
				set.ExpiresAt = grant.ExpiresAt
			}
		}
	}
	for i := range set.Channels {
		grant := &set.Channels[i]
		enrolled, err := s.deps.Store.Channel(ctx, scope, grant.ChannelID)
		if err != nil {
			return zero, err
		}
		if enrolled.ID != grant.ChannelID || enrolled.Config != scope.Config || enrolled.Generation == 0 || enrolled.Revoked {
			return zero, refused("root channel is not currently enrolled in this configuration")
		}
		ceiling, err := manifest.Expiry(enrolled.ExpiresAt, s.deps.Clock.Now())
		if err != nil {
			return zero, err
		}
		expiry, err := manifest.Expiry(grant.ExpiresAt, s.deps.Clock.Now())
		if err != nil {
			return zero, err
		}
		if expiry.After(ceiling) {
			return zero, refused("root channel expiry exceeds its enrolled lease")
		}
		grant.ID, err = freshID()
		if err != nil {
			return zero, err
		}
		if set.ExpiresAt == "" {
			set.ExpiresAt = grant.ExpiresAt
		} else {
			limit, err := manifest.Time(set.ExpiresAt)
			if err != nil {
				return zero, err
			}
			if expiry.After(limit) {
				set.ExpiresAt = grant.ExpiresAt
			}
		}
	}
	for i := range set.Network {
		grant := &set.Network[i]
		if s.deps.Network == nil {
			return zero, refused("root network requires protected endpoint enrollment")
		}
		if err := s.deps.Network(ctx, scope.Config, *grant); err != nil {
			return zero, err
		}
		grant.ID, err = freshID()
		if err != nil {
			return zero, err
		}
		expiry, err := manifest.Time(grant.ExpiresAt)
		if err != nil {
			return zero, err
		}
		if set.ExpiresAt == "" {
			set.ExpiresAt = grant.ExpiresAt
		} else {
			limit, err := manifest.Time(set.ExpiresAt)
			if err != nil {
				return zero, err
			}
			if expiry.After(limit) {
				set.ExpiresAt = grant.ExpiresAt
			}
		}
	}
	if err := s.checkSources(ctx, scope, set, budget.DiskBytes); err != nil {
		return zero, err
	}
	if len(set.Profiles)+len(set.Network)+len(set.Resources)+len(set.Secrets) != 0 {
		// The broker lock pins enrollment, not policy or the live human
		// connection. Source/channel reads may yield; release needs a new
		// authority view while retaining the original proof and frame.
		current, view, err := s.freshAuthority(ctx, scope)
		if err != nil {
			return zero, err
		}
		defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
		if err := s.checkScope(ctx, current); err != nil {
			return zero, err
		}
		latest, err := s.deps.Store.Policy(ctx, current)
		if err != nil {
			return zero, err
		}
		if latest.Generation == 0 || latest.Generation != current.PolicyGeneration || latest.Generation != set.PolicyGeneration {
			return zero, conflict("root profile policy changed during source reads")
		}
		for _, grant := range set.Profiles {
			if slices.Contains(latest.ProfileExclusions, grant.ProfileID) {
				return zero, refused("root profile was excluded during source reads")
			}
		}
		scope = current
	}
	// Source/channel reads and a profile journal lock may have yielded. Recheck
	// the protected immutable handle records with current caller authority.
	if len(input.Resources)+len(input.Secrets) != 0 {
		enrolled := input
		if rootSecretNativeContext(s) {
			enrolled.Secrets = nil
		}
		if err := s.rootEnrollments(ctx, scope, enrolled); err != nil {
			return zero, err
		}
	}
	for _, grant := range input.Network {
		if err := s.deps.Network(ctx, scope.Config, grant); err != nil {
			return zero, err
		}
	}
	if err := seal(&set); err != nil {
		return zero, err
	}
	if err := manifest.Set(set, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	raw, err := json.Marshal(set)
	if err != nil {
		return zero, integrity("cannot encode issued root grant set")
	}
	payload, err := json.Marshal(api.GrantEvent{GrantSet: set})
	if err != nil {
		return zero, integrity("cannot encode root grant issuance")
	}
	eventID, err := freshID()
	if err != nil {
		return zero, err
	}
	transaction := api.Transaction{Scope: scope, RawRequest: append([]byte(nil), scope.Frame.Bytes()...),
		Guards: []api.TransactionGuard{guard}, Writes: api.StateWrites{Grants: []api.GrantSet{set}},
		Compare: []api.Compare{{Kind: api.CompareGrants, ID: set.ID, Generation: 0},
			{Kind: api.CompareLane, ID: set.LifeID, Generation: 0}},
		Reply: &api.RPCReply{Result: raw}, Events: []api.Event{{Schema: api.SchemaVersion, ID: eventID,
			Config: scope.Config, Kind: "grants.issued", Actor: scope.Actor, RequestedBy: scope.Actor,
			RequestID: scope.Request.RequestID, LifeID: set.LifeID, Origin: "service", Payload: payload}}}
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return zero, err
	}
	commit, err := s.deps.Store.Transact(ctx, transaction)
	if err != nil {
		return zero, err
	}
	if !manifest.ValidID(commit.Operation.ID) || commit.Operation.Status != "succeeded" || commit.FirstSeq == 0 || commit.LastSeq < commit.FirstSeq {
		return zero, integrity("root grant issuance lacks a completed durable operation")
	}
	if commit.Reply == nil || commit.Reply.Error != nil {
		if commit.Reply != nil && commit.Reply.Error != nil {
			return zero, commit.Reply.Error
		}
		return zero, integrity("root grant issuance has no durable typed reply")
	}
	var result api.GrantSet
	if err := api.DecodeObject(commit.Reply.Result, &result); err != nil {
		return zero, integrity("root grant receipt is malformed")
	}
	checked := result
	if err := manifest.StoredSet(result); err != nil {
		return zero, integrity("root grant receipt has invalid structure")
	}
	if err := seal(&checked); err != nil || checked.SHA256 != result.SHA256 {
		return zero, integrity("root grant receipt has a substituted digest")
	}
	if !commit.Replayed && result.SHA256 != set.SHA256 {
		return zero, integrity("root grant receipt differs from committed input")
	}
	return result, nil
}

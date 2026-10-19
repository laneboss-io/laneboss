package secrets

import (
	"context"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func (s *Service) Eligibility(ctx context.Context, request api.ProfileEligibilityRequest) (api.ProfileEligibility, error) {
	if err := wire.Context(ctx); err != nil {
		return api.ProfileEligibility{}, err
	}
	if !wire.ID(string(request.GrantSetID)) || !wire.ID(string(request.FromGrantID)) ||
		!wire.ID(string(request.ToGrantID)) || request.FromGrantID == request.ToGrantID ||
		!wire.ID(string(request.HistoryID)) || !wire.ID(string(request.Session.ID)) ||
		!wire.ID(string(request.Session.HomeID)) || request.HistoryID != request.Session.HistoryID ||
		request.Session.Driver != request.Driver || request.Model == "" || len(request.Model) > 256 ||
		strings.TrimSpace(request.Model) != request.Model {
		return api.ProfileEligibility{}, wire.Error(api.CodeInvalid, "profile eligibility requires exact grants, model, session and history")
	}
	if request.Driver != api.DriverClaudock && request.Driver != api.DriverCodex {
		return api.ProfileEligibility{}, wire.Error(api.CodeUnsupported, "profile eligibility driver is unsupported")
	}
	current, err := s.currentGrants(ctx, request.Target)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	if current.ID != request.GrantSetID {
		return api.ProfileEligibility{}, wire.Error(api.CodeConflict, "profile eligibility grant set is no longer current")
	}
	lane, err := s.deps.Store.Lane(ctx, s.deps.ServiceScope, request.Target)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	if lane.GrantSetID != current.ID || lane.PolicyGeneration < current.PolicyGeneration ||
		lane.Session != request.Session || lane.Model != request.Model || lane.ProfileGrantID != request.FromGrantID {
		return api.ProfileEligibility{}, wire.Error(api.CodeConflict, "profile eligibility differs from the current run session")
	}
	var from, to *api.ProfileGrant
	for i := range current.Profiles {
		grant := &current.Profiles[i]
		if grant.ID == request.FromGrantID {
			from = grant
		}
		if grant.ID == request.ToGrantID {
			to = grant
		}
	}
	if from == nil || to == nil {
		return api.ProfileEligibility{}, wire.Error(api.CodeForbidden, "profile eligibility exceeds current delegated profiles")
	}
	for _, grant := range []*api.ProfileGrant{from, to} {
		if err := validateProfile(*grant, s.deps.Clock.Now()); err != nil {
			return api.ProfileEligibility{}, err
		}
	}
	if from.Driver != request.Driver || to.Driver != request.Driver || from.Provider != to.Provider {
		return api.ProfileEligibility{}, wire.Error(api.CodeForbidden, "profile continuation changes the driver or provider")
	}
	if to.Paid && !from.Paid {
		return api.ProfileEligibility{}, wire.Error(api.CodeForbidden, "profile continuation cannot introduce paid fallback")
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	if policy.Generation != lane.PolicyGeneration || !wire.Digest(policy.SHA256) {
		return api.ProfileEligibility{}, wire.Error(api.CodeConflict, "profile eligibility policy is no longer current")
	}
	for _, excluded := range policy.ProfileExclusions {
		if excluded == to.ProfileID {
			return api.ProfileEligibility{}, wire.Error(api.CodeForbidden, "profile continuation selects an excluded login")
		}
	}
	return s.profileEligibility(ctx, request, *from, *to)
}

func workerBlob(ref api.BlobRef) bool {
	return wire.ID(string(ref.ID)) && wire.Digest(ref.SHA256) && ref.Bytes >= 0 &&
		ref.Bytes <= api.MaxObjectBytes && wire.Name(ref.Class)
}

func (s *Service) InjectWorker(ctx context.Context, lease api.WorkerLease, grants []api.WorkerCredential) (api.Injection, error) {
	if err := wire.Context(ctx); err != nil {
		return api.Injection{}, err
	}
	if !wire.ID(string(lease.ID)) || !wire.ID(string(lease.Target.LifeID)) || lease.Target.Run == 0 ||
		!wire.ID(string(lease.OperationID)) || !wire.ID(string(lease.EffectID)) ||
		!wire.ID(string(lease.GrantSetID)) || lease.Generation == 0 ||
		!workerBlob(lease.Input) || !workerBlob(lease.RuntimeManifest) || grants == nil || len(grants) > 256 {
		return api.Injection{}, wire.Error(api.CodeInvalid, "worker injection requires a bounded exact job lease")
	}
	switch lease.Kind {
	case "test", "import", "export", "archive", "render", "box_run", "channel", "usage", "owner_sheet", "gateway":
	default:
		return api.Injection{}, wire.Error(api.CodeInvalid, "worker lease kind is outside the fixed worker catalog")
	}
	if lease.ConsumedBy != "" || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return api.Injection{}, wire.Error(api.CodeForbidden, "worker injection lease is consumed or expired")
	}
	// Validate names and collisions before resolving a protected job or source.
	targets := make(map[string]bool)
	for _, grant := range grants {
		if !wire.Name(grant.Name) || !wire.Name(grant.Version) || !wire.ID(string(grant.SourceHandle)) {
			return api.Injection{}, wire.Error(api.CodeInvalid, "worker credential requires exact source metadata")
		}
		if grant.Delivery == "env" && !wire.EnvTarget(grant.Target) ||
			grant.Delivery == "file" && !wire.FileTarget(grant.Target) {
			return api.Injection{}, wire.Error(api.CodeForbidden, "worker credential target is reserved or escaping")
		}
		if grant.Delivery != "env" && grant.Delivery != "file" {
			return api.Injection{}, wire.Error(api.CodeInvalid, "worker credential delivery must be env or file")
		}
		key := grant.Delivery + ":" + grant.Target
		if targets[key] {
			return api.Injection{}, wire.Error(api.CodeInvalid, "worker credential targets collide")
		}
		targets[key] = true
		for _, other := range grants {
			if grant.Delivery == "file" && other.Delivery == "file" &&
				strings.HasPrefix(other.Target, grant.Target+"/") {
				return api.Injection{}, wire.Error(api.CodeInvalid, "worker credential file targets overlap")
			}
		}
	}
	if s.deps.ServiceScope.Config != s.deps.Config || s.deps.ServiceScope.Actor.Kind != "service" {
		return api.Injection{}, wire.Error(api.CodePrerequisite, "credential worker requires its installed service scope")
	}
	stored, err := s.deps.Store.WorkerLease(ctx, s.deps.ServiceScope, lease.ID)
	if err != nil {
		return api.Injection{}, err
	}
	if stored != lease {
		return api.Injection{}, wire.Error(api.CodeConflict, "worker injection differs from its current protected lease")
	}
	current, err := s.currentWorkerGrants(ctx, lease)
	if err != nil {
		return api.Injection{}, err
	}
	if current.ID != lease.GrantSetID {
		return api.Injection{}, wire.Error(api.CodeConflict, "worker injection grant set is no longer current")
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return api.Injection{}, err
	}
	if policy.Generation != current.PolicyGeneration {
		return api.Injection{}, wire.Error(api.CodeConflict, "new worker preparation requires current approved policy")
	}
	for _, selected := range grants {
		found := false
		for _, enrolled := range current.Secrets {
			if enrolled.Name == selected.Name && enrolled.SourceHandle == selected.SourceHandle &&
				enrolled.Version == selected.Version && enrolled.Delivery == selected.Delivery && enrolled.Target == selected.Target {
				if err := validateGrant(enrolled, s.deps.Clock.Now()); err != nil {
					return api.Injection{}, err
				}
				found = true
				break
			}
		}
		if !found {
			return api.Injection{}, wire.Error(api.CodeForbidden, "worker credential exceeds its current exact source grants")
		}
	}
	return s.prepareWorkerInjection(ctx, lease, grants, current)
}

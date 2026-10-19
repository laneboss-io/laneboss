package secrets

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// This encrypted record is written only after native frame authentication,
// measured command completion and immutable envelope/result read-back. It is
// separate from the envelope, which cannot authenticate its own producer.
type retainedUsage struct {
	Schema            string
	Config            string
	Request           api.UsageWindowRequest
	Envelope          api.UsageWindowEvidence
	Provenance        api.UsageProvenance
	ProfileGeneration api.Generation
}

func (s *Service) keepUsageProvenance(ctx context.Context, evidence api.UsageWindowEvidence, ref api.BlobRef, producer api.WorkerPrincipal, profile bstate.Profile, request api.UsageWindowRequest) error {
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	if profile.Usage == nil {
		return wire.Error(api.CodePrerequisite, "usage provenance requires protected runtime enrollment")
	}
	saved := retainedUsage{Schema: "laneboss.usage-provenance.v2", Config: s.deps.Config, Request: request, Envelope: evidence, ProfileGeneration: profile.Generation,
		Provenance: api.UsageProvenance{Evidence: ref, Producer: producer, VendorProfile: profile.Usage.VendorProfile, Executable: profile.Usage.Executable, RuntimeManifest: profile.Usage.RuntimeManifest}}
	return backend.WithBroker(ctx, func(j bstate.Journal) error {
		for _, id := range []api.ID{evidence.ID, credentialID("usage-producer", producer.Lease.ID)} {
			var prior retainedUsage
			if err := j.Read("usage", id, &prior); err == nil {
				if !reflect.DeepEqual(prior, saved) {
					return wire.Error(api.CodeIdempotencyConflict, "usage measurement or producer identity already names different immutable evidence")
				}
			} else if !hasCode(err, api.CodeNotFound) {
				return err
			} else if err := j.Write("usage", id, saved); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) usageReadScope(ctx context.Context, scope api.Scope) error {
	if err := wire.Context(ctx); err != nil {
		return err
	}
	if scope.Config != s.deps.Config || scope.Connection != nil || scope.Frame != nil || scope.Request.Method != "" || !wire.ID(string(scope.Actor.ID)) ||
		scope.Actor.Kind != "service" && !(scope.Actor.Kind == "watchdog" && scope.Source == "watchdog") {
		return wire.Error(api.CodeForbidden, "usage provenance requires its installed outside service reader")
	}
	return nil
}

func (s *Service) loadUsageProvenance(ctx context.Context, id api.ID) (retainedUsage, error) {
	var saved retainedUsage
	backend, err := s.brokerBackend()
	if err != nil {
		return saved, err
	}
	err = backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("usage", id, &saved) })
	if err != nil {
		return saved, err
	}
	if saved.Schema != "laneboss.usage-provenance.v2" || saved.Config != s.deps.Config || saved.Envelope.ID != saved.Provenance.Evidence.ID || saved.Provenance.Evidence.Class != "usage_window" {
		return saved, wire.Error(api.CodeIntegrity, "protected usage provenance belongs to another envelope or configuration")
	}
	return saved, nil
}

func (s *Service) verifyUsageProvenance(ctx context.Context, saved retainedUsage) (api.UsageProvenance, error) {
	var empty api.UsageProvenance
	profile, err := s.usageProfile(ctx, saved.Request)
	if err != nil {
		return empty, err
	}
	p := saved.Provenance
	if profile.Usage == nil || profile.Generation != saved.ProfileGeneration || profile.Usage.VendorProfile != p.VendorProfile || profile.Usage.Executable != p.Executable || profile.Usage.RuntimeManifest != p.RuntimeManifest {
		return empty, wire.Error(api.CodeConflict, "usage runtime or protected profile enrollment changed")
	}
	producer := p.Producer
	if err := s.usageProducer(ctx, producer, saved.Envelope.ObservedAt, saved.Envelope.Raw); err != nil {
		return empty, err
	}
	observed, err := time.Parse(time.RFC3339Nano, string(saved.Envelope.ObservedAt))
	if err != nil {
		return empty, err
	}
	if err := api.ValidateUsageWindow(saved.Envelope, saved.Request, producer, observed); err != nil {
		return empty, err
	}
	for _, ref := range []api.BlobRef{p.Evidence, saved.Envelope.Raw} {
		meta, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, ref.ID)
		if err != nil {
			return empty, err
		}
		if meta.Ref != ref || meta.ACL.Owner != producer.Record.Actor || meta.ACL.LifeID != saved.Request.Target.LifeID || meta.ACL.Audience != "service" || len(meta.ACL.Participants) != 0 {
			return empty, wire.Error(api.CodeIntegrity, "usage evidence lost its private native producer ownership")
		}
	}
	data, err := s.protectedObject(ctx, p.Evidence, saved.Request.OperationID)
	if err != nil {
		return empty, err
	}
	var envelope api.UsageWindowEvidence
	if err := api.DecodeObject(data, &envelope); err != nil || !reflect.DeepEqual(envelope, saved.Envelope) {
		return empty, wire.Error(api.CodeIntegrity, "usage envelope differs from its protected producing job")
	}
	raw, err := s.protectedObject(ctx, envelope.Raw, saved.Request.OperationID)
	if err != nil {
		return empty, err
	}
	if err := api.ValidateUsageSource(envelope, raw, p.VendorProfile); err != nil {
		return empty, err
	}
	return p, nil
}

func (s *Service) ReadUsageProvenance(ctx context.Context, scope api.Scope, ref api.BlobRef) (api.UsageProvenance, error) {
	if err := s.usageReadScope(ctx, scope); err != nil {
		return api.UsageProvenance{}, err
	}
	saved, err := s.loadUsageProvenance(ctx, ref.ID)
	if err != nil {
		return api.UsageProvenance{}, err
	}
	if saved.Provenance.Evidence != ref {
		return api.UsageProvenance{}, wire.Error(api.CodeIntegrity, "usage provenance lookup changed the exact immutable reference")
	}
	return s.verifyUsageProvenance(ctx, saved)
}

// UsageWorker and UsageProfile bind the existing runner ports to this same
// protected result/enrollment owner. They expose no login values or RPC route.
func (s *Service) UsageWorker(ctx context.Context, scope api.Scope, lease api.ID) (api.InstalledBinding, api.PeerFacts, error) {
	if err := s.usageReadScope(ctx, scope); err != nil {
		return api.InstalledBinding{}, api.PeerFacts{}, err
	}
	saved, err := s.loadUsageProvenance(ctx, credentialID("usage-producer", lease))
	if err != nil {
		return api.InstalledBinding{}, api.PeerFacts{}, err
	}
	if saved.Provenance.Producer.Lease.ID != lease {
		return api.InstalledBinding{}, api.PeerFacts{}, wire.Error(api.CodeIntegrity, "usage worker lookup returned another lease")
	}
	p, err := s.verifyUsageProvenance(ctx, saved)
	if err != nil {
		return api.InstalledBinding{}, api.PeerFacts{}, err
	}
	return p.Producer.Endpoint, p.Producer.Peer, nil
}

func (s *Service) UsageProfile(ctx context.Context, grant api.ProfileGrant) (string, error) {
	profile, err := s.loadProfile(ctx, grant)
	if err != nil {
		return "", err
	}
	if profile.Usage == nil {
		return "", wire.Error(api.CodePrerequisite, "profile has no protected outside usage enrollment")
	}
	return profile.Usage.VendorProfile, nil
}

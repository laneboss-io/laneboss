package lifecycle

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// A new run may reuse authenticated private history after the old endpoint was
// revoked. Read the actual immutable identity.bound bytes for that old permit;
// the live binding/endpoint stay revoked and are never rewritten or reopened.
func (s *Service) historicalBinding(ctx context.Context, scope api.Scope, lane api.Lane, binding api.LaunchBindingRequest) (api.LaunchBindingRequest, error) {
	revoked, err := s.deps.Store.LaunchRevocation(ctx, binding.Record.ID)
	if err != nil {
		return api.LaunchBindingRequest{}, failure(err)
	}
	current := binding.Record
	current.Revoked = true
	if api.ValidateLaunchRevocation(revoked) != nil || !reflect.DeepEqual(revoked.Record, current) {
		return api.LaunchBindingRequest{}, integrity("historical launch has no matching causal revocation")
	}
	var original *api.LaunchRecord
	err = s.walkEvents(ctx, scope, lane, binding.Record.Target, func(event api.Event) error {
		if event.Kind == "identity.bound" && event.ID == binding.Identity.EventID && event.Seq == binding.Identity.CommittedSeq {
			var record api.LaunchRecord
			if api.DecodeObject(event.Payload, &record) != nil {
				return integrity("historical identity event has no exact record")
			}
			original = &record
		}
		return nil
	})
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	if original == nil || original.Revoked {
		return api.LaunchBindingRequest{}, integrity("historical identity commitment is missing")
	}
	comparison := *original
	comparison.Revoked = binding.Record.Revoked
	if !reflect.DeepEqual(comparison, binding.Record) {
		return api.LaunchBindingRequest{}, integrity("historical identity differs beyond its revocation projection")
	}
	historical := binding
	historical.Record = *original
	return historical, nil
}

package grants

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

type rootEventReader interface {
	RootGrantEvent(context.Context, api.Scope, api.ID) (api.Event, error)
}

// A lane-backed root retains the ordinary human lane-read policy. A root
// template has no Lane: its immutable service issuance event binds its owner.
// GrantSet carries no principal field, so neither the selector nor request
// params can establish this ownership.
func (s *Service) humanRootRead(ctx context.Context, scope api.Scope, set api.GrantSet) error {
	lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: set.LifeID})
	if err == nil {
		if lane.LifeID != set.LifeID {
			return conflict("human root read returned a different life")
		}
		return nil
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return err
	}
	// Root templates have no Lane/run. Their ownership is a selected grant
	// issuance read, never a public event.tail read with missing selectors.
	reader, ok := s.deps.Store.(rootEventReader)
	if !ok {
		return api.NotImplemented("lb-v2-grants", "selected root issuance reader")
	}
	event, err := reader.RootGrantEvent(ctx, scope, set.ID)
	if err != nil {
		return err
	}
	if event.Kind != "grants.issued" || event.LifeID != set.LifeID || event.Schema != api.SchemaVersion ||
		event.Config != scope.Config || event.Origin != "service" || event.Run != 0 || event.Seq == 0 ||
		event.Actor.Kind != "human" || event.RequestedBy != event.Actor || len(event.Payload) > api.MaxFrameBytes {
		return integrity("root template has no authentic human issuance event")
	}
	var issued api.GrantEvent
	if err := api.DecodeObject(event.Payload, &issued); err != nil {
		return err
	}
	if issued.GrantSet.ID != set.ID || issued.GrantSet.LifeID != set.LifeID || issued.GrantSet.ParentLifeID != "" {
		return integrity("root issuance belongs to another grant identity")
	}
	if event.Actor.ID != scope.Actor.ID {
		return refused("root template belongs to another authenticated principal")
	}
	return s.humanRead(ctx, scope)
}

package identity

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) SelectCredentialWorker(ctx context.Context, handoff api.PreparedSpecHandoff) (api.CredentialWorkerSelection, error) {
	if err := ctx.Err(); err != nil {
		return api.CredentialWorkerSelection{}, err
	}
	if handoff.Cause.Actor.Kind != "service" || !validID(handoff.Cause.Actor.ID) {
		return api.CredentialWorkerSelection{}, refusal(api.CodeForbidden, "credential worker selector lacks its retained service actor")
	}
	source, ok := s.deps.Store.(api.CredentialWorkerSelectionStore)
	if !ok || nilDependency(source) {
		return api.CredentialWorkerSelection{}, gap("SelectCredentialWorker", "protected sealed worker job and runtime inventory")
	}
	return source.CredentialWorkerSelection(ctx, api.Scope{Config: handoff.Config, Actor: handoff.Cause.Actor, Source: "worker"}, handoff)
}

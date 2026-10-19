package identity

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// These are checks on authenticated claims, before another module may select
// a requested life/grant or inspect a ticket. Store still checks current object
// ACLs and atomic guards, after its idempotent receipt lookup.
func (s *Service) authorizeClaims(ctx context.Context, scope api.Scope, request api.Request) error {
	if api.Methods[request.Method].Access == "l6" && (scope.Actor.Kind != "lane" || scope.Actor.Level != 6) {
		return refusal(api.CodeForbidden, "operation requires the current L6 life")
	}
	var ticket api.ID
	var childLevel int
	switch request.Method {
	case "lane.start":
		var input api.StartRequest
		if err := api.DecodeObject(request.Params, &input); err != nil {
			return err
		}
		ticket, childLevel = input.RootTicketID, input.Level
	case "lane.adopt":
		var input api.AdoptRequest
		if err := api.DecodeObject(request.Params, &input); err != nil {
			return err
		}
		ticket, childLevel = input.RootTicketID, input.Level
	}
	if request.Method == "lane.start" || request.Method == "lane.adopt" {
		if ticket != "" && (scope.Actor.Kind != "human" || nilDependency(scope.Connection) || scope.Connection.Binding().Class != api.EndpointHuman) {
			return refusal(api.CodeForbidden, "root tickets require an installed human endpoint")
		}
		if scope.Actor.Kind == "human" && !validID(ticket) {
			return refusal(api.CodeUnauthenticated, "a human root launch requires its issued ticket")
		}
		if childLevel < 3 || childLevel > 6 || scope.Actor.Kind == "lane" && childLevel >= scope.Actor.Level {
			return refusal(api.CodeForbidden, "child level exceeds the authenticated spawning authority")
		}
	}
	if scope.Actor.Kind != "lane" {
		return nil
	}
	switch request.Method {
	case "brief.start":
		var input api.BriefingRequest
		if err := api.DecodeObject(request.Params, &input); err != nil {
			return err
		}
		if input.LifeID != "" && input.LifeID != scope.Actor.LifeID || input.Level != scope.Actor.Level || input.Role != scope.Actor.Role {
			return refusal(api.CodeForbidden, "briefing claims differ from the authenticated life")
		}
	case "brief.render":
		var input api.TemplateRequest
		if err := api.DecodeObject(request.Params, &input); err != nil {
			return err
		}
		record, err := s.currentLaunch(ctx, scope)
		if err != nil {
			return err
		}
		if input.GrantSetID != record.GrantSetID || input.Context.Level != scope.Actor.Level || input.Context.Role != scope.Actor.Role ||
			input.Context.InstanceID != "" && input.Context.InstanceID != scope.Actor.ID {
			return refusal(api.CodeForbidden, "template claims differ from the authenticated life and grants")
		}
	case "grants.validate":
		var input api.GrantValidateRequest
		if err := api.DecodeObject(request.Params, &input); err != nil {
			return err
		}
		if input.ParentLifeID != scope.Actor.LifeID {
			return refusal(api.CodeForbidden, "grant parent differs from the authenticated life")
		}
	}
	return nil
}

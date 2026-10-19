package store

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func scopedProjection[T any](ctx context.Context, s *Service, scope api.Scope, kind string, id api.ID) (result T, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return result, err
	}
	if kind == "org" || kind == "policy" {
		if err := s.orgGenerationReady(ctx, s.db); err != nil {
			return result, err
		}
	}
	db, err := s.reader(scope)
	if err != nil {
		return result, err
	}
	err = storedProjection(ctx, db, kind, id, &result)
	return result, err
}
func identityProjection[T any](ctx context.Context, s *Service, scope api.Scope, kind string, id api.ID) (result T, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if scope.Actor.Kind != "human" && !internalScope(scope) {
		return result, fault(api.CodeForbidden, "identity projection requires the human endpoint or internal service")
	}
	err = storedProjection(ctx, s.db, kind, id, &result)
	return result, err
}

type ticketRecord struct {
	RedeemedBy         api.ID
	PrincipalID        api.ID
	Config             string
	EndpointGeneration api.Generation
	Ticket             api.Ticket
}

func (s *Service) authorizationTarget(ctx context.Context, db queryer, scope api.Scope, request api.Request) (api.HumanChallengeRequest, error) {
	var target api.HumanChallengeRequest
	if scope.Actor.Kind != "human" || scope.Connection == nil || scope.Connection.Binding().Class != api.EndpointHuman {
		return target, fault(api.CodeForbidden, "human target requires its live human endpoint")
	}
	if err := wire.ValidateRequest(request); err != nil {
		return target, err
	}
	if request.Config != scope.Config {
		return target, fault(api.CodeForbidden, "human target configuration differs")
	}
	spec := api.Methods[request.Method]
	value := reflect.New(spec.Request)
	if err := api.DecodeObject(request.Params, value.Interface()); err != nil {
		return target, err
	}
	params := value.Elem()
	id, kind := api.ID(scope.Config), ""
	for _, field := range []struct{ name, kind string }{{"RecordID", "record"}, {"ChangeID", "change"}, {"PlanID", "upgrade"}, {"ObjectID", "object"}, {"GrantSetID", "grants"}, {"OrgID", "org"}} {
		member := params.FieldByName(field.name)
		if member.IsValid() && member.Kind() == reflect.String && member.String() != "" {
			id, kind = api.ID(member.String()), field.kind
			break
		}
	}
	if member := params.FieldByName("Target"); member.IsValid() && member.Type() == reflect.TypeFor[api.LifeRef]() {
		id, kind = member.Interface().(api.LifeRef).LifeID, "lane"
	}
	// A request that is itself a LifeRef (lane.check) targets that lane, as the
	// client's challenge names it (box 76: the proof named the lane, the read the config).
	if params.Type() == reflect.TypeFor[api.LifeRef]() {
		id, kind = params.Interface().(api.LifeRef).LifeID, "lane"
	}
	for _, name := range []string{"Lane", "OrgName"} {
		if member := params.FieldByName(name); member.IsValid() && member.Kind() == reflect.String && member.String() != "" {
			id, kind = api.ID(member.String()), "new_object"
		}
	}
	if request.Method == "records.append" {
		id, kind = api.ID(params.FieldByName("Collection").String()), "new_object"
	}
	if request.Method == "decisions.mutate" && kind == "" {
		id, kind = "decisions", "new_object"
	}
	if request.Method == "human.session" {
		id = scope.Actor.ID
	}
	if !wire.ValidID(string(id)) {
		return target, wire.Invalid("human operation has no valid target")
	}
	base := api.Generation(0)
	if expected := params.FieldByName("ExpectedGeneration"); expected.IsValid() && expected.Kind() == reflect.Uint64 {
		base = api.Generation(expected.Uint())
	} else if expected := params.FieldByName("BaseGeneration"); expected.IsValid() && expected.Kind() == reflect.Uint64 {
		base = api.Generation(expected.Uint())
	} else if kind != "" && kind != "new_object" && kind != "object" {
		var generation uint64
		if err := db.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind=? AND id=?", kind, string(id)).Scan(&generation); err != nil {
			return target, fault(api.CodeNotFound, "human operation target is absent")
		}
		base = api.Generation(generation)
	}
	return api.HumanChallengeRequest{Method: request.Method, TargetID: id, RequestSHA256: request.RequestSHA256, BaseGeneration: base}, nil
}

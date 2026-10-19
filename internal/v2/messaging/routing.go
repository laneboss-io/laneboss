package messaging

import (
	"context"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) authorize(ctx context.Context, scope api.Scope, method api.Method, body any) error {
	if err := ctx.Err(); err != nil {
		return cancelled(err)
	}
	request := scope.Request
	if !validID(api.ID(scope.Config)) || request.Config != scope.Config || request.Protocol != api.Protocol || request.Schema != api.SchemaVersion || request.Method != method || !validID(request.RequestID) || !validID(request.IdempotencyKey) || len(request.RequestID) < 22 || len(request.IdempotencyKey) < 22 || !validDigest(request.RequestSHA256) || scope.EndpointGeneration == 0 || scope.PolicyGeneration == 0 {
		return problem(api.CodeUnauthenticated, "messaging requires authenticated, configuration-bound request metadata")
	}
	if !validActor(scope.Actor) || scope.Source != "cli" && scope.Source != "dashboard" || scope.Actor.Kind == "lane" && scope.Source == "dashboard" {
		return problem(api.CodeUnauthenticated, "messaging requires a verified lane or human endpoint")
	}
	// Check the dispatched body against the authenticated envelope, even for
	// direct component callers. Actor and source are deliberately absent there.
	copy := reflect.New(reflect.TypeOf(body))
	if err := decodeBody(request.Params, copy.Interface()); err != nil {
		return err
	}
	if !reflect.DeepEqual(body, copy.Elem().Interface()) {
		return problem(api.CodeIntegrity, "messaging body differs from its authenticated request")
	}
	digest, err := api.RequestDigest(request)
	if err != nil || digest != request.RequestSHA256 {
		return problem(api.CodeIntegrity, "messaging envelope has an incorrect intent digest")
	}
	if scope.Actor.Kind == "human" && api.Methods[method].Mutation && request.Proof == nil {
		return problem(api.CodeUnauthenticated, "human mail requires fresh operation-bound confirmation")
	}
	if scope.Actor.Kind == "lane" && request.Proof != nil {
		return problem(api.CodeForbidden, "lane mail cannot carry human proof")
	}
	if !api.Methods[method].Mutation && request.Proof != nil {
		return problem(api.CodeForbidden, "mail reads require a bound session, not an operation proof")
	}
	if request.Proof != nil && (!validID(request.Proof.ID) || request.Proof.RequestSHA256 != request.RequestSHA256 || !validTimestamp(request.Proof.ExpiresAt)) {
		return problem(api.CodeUnauthenticated, "mail proof has invalid identity or intent binding")
	}
	if s.deps.Authenticator != nil {
		if err := s.deps.Authenticator.Authorize(ctx, scope, request); err != nil {
			return err
		}
	} else if err := s.connectionAuthority(ctx, scope); err != nil {
		return err
	}
	// This is the live caller gate, before receipt lookup. Target/content/base
	// preflights and proof consumption remain after exact receipt lookup (§14).
	if scope.Actor.Kind == "lane" {
		from, err := s.currentSender(ctx, scope)
		if err != nil {
			return err
		}
		_, err = s.currentGrants(ctx, scope, from)
		return err
	}
	return nil
}

func cancelled(err error) error {
	if err == context.DeadlineExceeded {
		return problem(api.CodeDeadline, "messaging request reached its deadline")
	}
	return problem(api.CodeCancelled, "messaging request was cancelled")
}

func (s *Service) lane(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	if !validID(target.LifeID) || target.Run > maxExact {
		return api.Lane{}, problem(api.CodeInvalid, "messaging requires an immutable life identifier")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, target)
	if err != nil {
		return api.Lane{}, err
	}
	if lane.LifeID != target.LifeID || target.Run != 0 && lane.Run != target.Run {
		return api.Lane{}, problem(api.CodeConflict, "the requested life or run is no longer current")
	}
	if err := validLife(lane); err != nil {
		return api.Lane{}, err
	}
	return lane, nil
}

func validLife(lane api.Lane) error {
	if !validID(lane.LifeID) || !validID(lane.RootLifeID) || !validID(lane.GrantSetID) || lane.Level < 3 || lane.Level > 6 || lane.Role == "" || lane.Generation == 0 || lane.Generation > maxExact || lane.Run == 0 || lane.Run > maxExact || lane.StarterEventSeq > maxExact || lane.StarterChain == nil || len(lane.StarterChain) > 6-lane.Level {
		return problem(api.CodeIntegrity, "life projection has invalid immutable identity")
	}
	if lane.ParentLifeID == "" {
		if lane.RootLifeID != lane.LifeID || len(lane.StarterChain) != 0 || lane.StarterEventSeq != 0 {
			return problem(api.CodeIntegrity, "root life has inconsistent starter provenance")
		}
	} else {
		if !validID(lane.ParentLifeID) || lane.ParentLifeID == lane.LifeID || lane.RootLifeID == lane.LifeID || len(lane.StarterChain) == 0 || lane.StarterEventSeq == 0 || lane.StarterChain[0] != lane.RootLifeID || lane.StarterChain[len(lane.StarterChain)-1] != lane.ParentLifeID {
			return problem(api.CodeIntegrity, "child life has inconsistent starter provenance")
		}
	}
	seen := map[api.ID]bool{lane.LifeID: true}
	for _, ancestor := range lane.StarterChain {
		if !validID(ancestor) || seen[ancestor] {
			return problem(api.CodeIntegrity, "life projection has a cyclic or invalid starter chain")
		}
		seen[ancestor] = true
	}
	switch lane.State {
	case "preparing", "running", "stopping", "verifying", "idle", "profile_wait", "lost", "accepted", "merged", "abandoned":
	default:
		return problem(api.CodeIntegrity, "life projection has an unknown lifecycle state")
	}
	return nil
}

func eligible(lane api.Lane) error {
	if lane.Cleaned || lane.State == "merged" || lane.State == "abandoned" {
		return problem(api.CodeForbidden, "retired or cleaned lives cannot acquire new mail rights")
	}
	return nil
}

func actorMatches(actor api.Actor, lane api.Lane) bool {
	return actor.Kind == "lane" && actor.LifeID == lane.LifeID && actor.Level == lane.Level && actor.Role == lane.Role
}

func (s *Service) currentSender(ctx context.Context, scope api.Scope) (api.Lane, error) {
	if scope.Actor.Kind != "lane" || !validID(scope.LaunchID) {
		return api.Lane{}, problem(api.CodeUnauthenticated, "lane mail requires a current authentic launch")
	}
	lane, err := s.lane(ctx, scope, api.LifeRef{LifeID: scope.Actor.LifeID})
	if err != nil {
		return api.Lane{}, err
	}
	if !actorMatches(scope.Actor, lane) {
		return api.Lane{}, problem(api.CodeUnauthenticated, "sender does not match its service-created life")
	}
	launch, err := s.deps.Store.Launch(ctx, scope.LaunchID)
	if err != nil {
		return api.Lane{}, err
	}
	if launch.ID != scope.LaunchID || launch.Config != scope.Config || launch.Target.LifeID != lane.LifeID || launch.Target.Run != lane.Run || launch.Revoked || launch.EndpointGeneration != scope.EndpointGeneration || launch.PolicyGeneration != scope.PolicyGeneration || launch.GrantSetID != lane.GrantSetID || launch.ParentLifeID != lane.ParentLifeID || launch.RootLifeID != lane.RootLifeID || launch.StarterEventSeq != lane.StarterEventSeq || !reflect.DeepEqual(launch.StarterChain, lane.StarterChain) {
		return api.Lane{}, problem(api.CodeUnauthenticated, "sender launch is stale, revoked or bound to another life")
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return api.Lane{}, err
	}
	if !validDigest(launch.GrantsSHA256) || launch.GrantsSHA256 != grants.SHA256 || launch.PolicyGeneration != grants.PolicyGeneration || grants.LifeID != lane.LifeID || grants.ParentLifeID != lane.ParentLifeID {
		return api.Lane{}, problem(api.CodeUnauthenticated, "sender launch no longer matches its granted scope")
	}
	if err := eligible(lane); err != nil {
		return api.Lane{}, err
	}
	return lane, nil
}

func (s *Service) currentGrants(ctx context.Context, scope api.Scope, lane api.Lane) (api.GrantSet, error) {
	stored, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if stored.ID != lane.GrantSetID || stored.LifeID != lane.LifeID || stored.ParentLifeID != lane.ParentLifeID {
		return api.GrantSet{}, problem(api.CodeIntegrity, "grant set is not bound to the selected life")
	}
	grants := stored
	if s.deps.Grants != nil {
		grants, err = s.deps.Grants.Revalidate(ctx, stored)
		if err != nil {
			return api.GrantSet{}, err
		}
	} else if err := s.grantAncestors(ctx, scope, stored); err != nil {
		return api.GrantSet{}, err
	}
	if grants.ID != stored.ID || grants.LifeID != stored.LifeID || grants.ParentLifeID != stored.ParentLifeID || grants.Generation == 0 || grants.Generation > maxExact || !validDigest(grants.SHA256) {
		return api.GrantSet{}, problem(api.CodeIntegrity, "grant revalidation changed immutable identity")
	}
	if grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return api.GrantSet{}, problem(api.CodeForbidden, "messaging rights are revoked or expired")
	}
	return grants, nil
}

func future(timestamp api.Timestamp, now time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, string(timestamp))
	return err == nil && len(timestamp) > 0 && timestamp[len(timestamp)-1] == 'Z' && parsed.After(now)
}

// relation is the frozen D7 rule. Common-root and level-only predicates do
// not establish sibling or downward authority; actual starter edges do.
func relation(from, to api.RelationFacts) error {
	if from.LifeID == to.LifeID || from.RootLifeID != to.RootLifeID {
		return problem(api.CodeForbidden, "mail requires a sibling, descendant or direct starter relationship")
	}
	if from.ParentLifeID == to.LifeID && from.Level < to.Level {
		if reflect.DeepEqual(from.StarterChain[:len(from.StarterChain)-1], to.StarterChain) {
			return nil
		}
		return problem(api.CodeIntegrity, "direct starter projections disagree on ancestry")
	}
	if from.Level == to.Level && from.ParentLifeID != "" && from.ParentLifeID == to.ParentLifeID && reflect.DeepEqual(from.StarterChain, to.StarterChain) {
		return nil
	}
	if from.Level > to.Level {
		for i, ancestor := range to.StarterChain {
			if ancestor == from.LifeID && reflect.DeepEqual(to.StarterChain[:i], from.StarterChain) {
				return nil
			}
		}
	}
	return problem(api.CodeForbidden, "mail cannot cross starter subtrees or skip an upward report edge")
}

func relationFacts(lane api.Lane) api.RelationFacts {
	return api.RelationFacts{LifeID: lane.LifeID, ParentLifeID: lane.ParentLifeID, RootLifeID: lane.RootLifeID,
		StarterChain: append([]api.ID{}, lane.StarterChain...), Level: lane.Level, Role: lane.Role,
		State: lane.State, Generation: lane.Generation, GrantSetID: lane.GrantSetID,
		PolicyGeneration: lane.PolicyGeneration, Revoked: lane.Cleaned}
}

// This service-only projection deliberately contains no sibling task, session,
// workspace or history. Public Lane ACLs must not be widened for routing.
func (s *Service) relatedLife(ctx context.Context, scope api.Scope, id api.ID) (api.RelationFacts, error) {
	row, err := s.deps.Store.Relation(ctx, scope, id)
	if err != nil {
		return api.RelationFacts{}, err
	}
	if row.LifeID != id || !validID(row.LifeID) || !validID(row.RootLifeID) || !validID(row.GrantSetID) || row.Generation == 0 || row.Generation > maxExact || row.PolicyGeneration == 0 || row.Level < 3 || row.Level > 6 || row.Role == "" || row.StarterChain == nil || len(row.StarterChain) > 6-row.Level {
		return api.RelationFacts{}, problem(api.CodeIntegrity, "invalid relation projection")
	}
	if row.ParentLifeID == "" {
		if row.RootLifeID != row.LifeID || len(row.StarterChain) != 0 {
			return api.RelationFacts{}, problem(api.CodeIntegrity, "invalid root relation")
		}
	} else if !validID(row.ParentLifeID) || len(row.StarterChain) == 0 || row.StarterChain[0] != row.RootLifeID || row.StarterChain[len(row.StarterChain)-1] != row.ParentLifeID {
		return api.RelationFacts{}, problem(api.CodeIntegrity, "invalid starter relation")
	}
	seen := map[api.ID]bool{row.LifeID: true}
	for _, id := range row.StarterChain {
		if !validID(id) || seen[id] {
			return api.RelationFacts{}, problem(api.CodeIntegrity, "cyclic starter relation")
		}
		seen[id] = true
	}
	if row.Revoked || row.State == "merged" || row.State == "abandoned" {
		return api.RelationFacts{}, problem(api.CodeForbidden, "retired or revoked lives cannot acquire mail rights")
	}
	switch row.State {
	case "preparing", "running", "stopping", "verifying", "idle", "profile_wait", "lost", "accepted":
	default:
		return api.RelationFacts{}, problem(api.CodeIntegrity, "unknown relation lifecycle state")
	}
	return row, nil
}

func (s *Service) relationGrants(ctx context.Context, scope api.Scope, row api.RelationFacts) (api.GrantSet, error) {
	return s.currentGrants(ctx, scope, api.Lane{LifeID: row.LifeID, ParentLifeID: row.ParentLifeID, GrantSetID: row.GrantSetID})
}

func errorCode(err error, code api.ErrorCode) bool {
	var typed *api.Error
	return errors.As(err, &typed) && typed.Code == code
}

func (s *Service) proofGuard(ctx context.Context, scope api.Scope) ([]api.TransactionGuard, error) {
	if scope.Actor.Kind != "human" {
		return nil, nil
	}
	if scope.Request.Proof == nil {
		return nil, problem(api.CodeUnauthenticated, "human mail requires an operation proof")
	}
	target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return nil, err
	}
	var proof api.VerifiedHumanProof
	if s.deps.Human != nil {
		proof, err = s.deps.Human.CheckProof(ctx, scope, *scope.Request.Proof, target)
	} else {
		proof, err = s.deps.Store.Proof(ctx, scope, scope.Request.Proof.ID)
	}
	if err != nil {
		return nil, err
	}
	if proof.Ref != *scope.Request.Proof || proof.Config != scope.Config || proof.PrincipalID != scope.Actor.ID || proof.Target != target || proof.ConsumedBy != "" || !future(proof.Ref.ExpiresAt, s.deps.Clock.Now()) {
		return nil, problem(api.CodeUnauthenticated, "human proof differs from the actual mutation target")
	}
	return []api.TransactionGuard{{Proof: &api.ProofUse{Proof: proof.Ref, Target: target}}}, nil
}

func (s *Service) channel(grants api.GrantSet, from api.Lane, id api.ID) (api.ChannelGrant, error) {
	if from.Level < 5 || from.Level > 6 {
		return api.ChannelGrant{}, problem(api.CodeForbidden, "L3 and L4 report to their direct starter and have no human-channel fallback")
	}
	seen := make(map[api.ID]bool)
	var found *api.ChannelGrant
	for _, grant := range grants.Channels {
		if !validID(grant.ID) || !validID(grant.ChannelID) || seen[grant.ID] {
			return api.ChannelGrant{}, problem(api.CodeIntegrity, "channel grants have invalid or duplicate identities")
		}
		seen[grant.ID] = true
		if grant.ID == id {
			copy := grant
			found = &copy
		}
	}
	if found == nil || !future(found.ExpiresAt, s.deps.Clock.Now()) {
		return api.ChannelGrant{}, problem(api.CodeForbidden, "the exact human channel grant is absent or expired")
	}
	return *found, nil
}

package messaging

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// Production construction uses the contracted StateStore and the transport's
// bound connection. Optional test adapters are not required composition ports.
func (s *Service) connectionAuthority(ctx context.Context, scope api.Scope) error {
	connection := scope.Connection
	if connection == nil || connection.Peer() == nil || scope.Frame == nil {
		return problem(api.CodeUnauthenticated, "mail requires its authenticated connection and frame")
	}
	binding := connection.Binding()
	if binding.Config != scope.Config || binding.EndpointGeneration != scope.EndpointGeneration || binding.ContractRevision != api.ContractRevision {
		return problem(api.CodeUnauthenticated, "mail connection binding is stale or belongs to another scope")
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return err
	}
	if err := scope.Frame.Verify(ctx, connection); err != nil {
		return err
	}
	if scope.Actor.Kind == "lane" {
		launch, err := s.deps.Store.Launch(ctx, scope.LaunchID)
		if err != nil {
			return err
		}
		facts, err := connection.Peer().Facts(ctx)
		if err != nil {
			return err
		}
		if binding.Class != api.EndpointLane || binding.LaunchID != scope.LaunchID || binding.Target == nil || *binding.Target != launch.Target || facts.HostUID != launch.HostUID || facts.ContainmentID != launch.ContainmentID || facts.ProcessGeneration == "" {
			return problem(api.CodeUnauthenticated, "mail peer is outside the current bound lane containment")
		}
		return nil // currentSender/currentGrants check canonical identity next.
	}
	if binding.Class != api.EndpointHuman {
		return problem(api.CodeForbidden, "human mail requires the human endpoint")
	}
	enrollment, err := s.deps.Store.Enrollment(ctx, scope)
	if err != nil {
		return err
	}
	var credential api.ID
	if api.Methods[scope.Request.Method].Mutation {
		proof, err := s.deps.Store.Proof(ctx, scope, scope.Request.Proof.ID)
		if err != nil {
			return err
		}
		if proof.Ref != *scope.Request.Proof || proof.Config != scope.Config || proof.PrincipalID != scope.Actor.ID || proof.EndpointClass != api.EndpointHuman || proof.EndpointGeneration != scope.EndpointGeneration || proof.Target.Method != scope.Request.Method || proof.Target.RequestSHA256 != scope.Request.RequestSHA256 {
			return problem(api.CodeUnauthenticated, "mail proof is not verified for this principal and endpoint")
		}
		credential = proof.CredentialID
	} else {
		if scope.ReadAuthority == nil || !future(scope.ReadAuthority.ExpiresAt, s.deps.Clock.Now()) || !future(scope.ReadAuthority.IdleExpiresAt, s.deps.Clock.Now()) {
			return problem(api.CodeForbidden, "mail browsing requires a current connection-bound session")
		}
		credential = scope.ReadAuthority.CredentialID
	}
	if enrollment.Config != scope.Config || enrollment.PrincipalID != scope.Actor.ID || enrollment.Generation == 0 {
		return problem(api.CodeUnauthenticated, "human mail enrollment changed")
	}
	for _, key := range enrollment.Credentials {
		if key.ID == credential && key.Generation > 0 && !key.Revoked {
			return nil
		}
	}
	return problem(api.CodeUnauthenticated, "human mail credential is missing or revoked")
}

func (s *Service) grantAncestors(ctx context.Context, scope api.Scope, grants api.GrantSet) error {
	seen := map[api.ID]bool{grants.LifeID: true}
	parent := grants.ParentLifeID
	for parent != "" {
		if seen[parent] || len(seen) > 4 {
			return problem(api.CodeIntegrity, "mail grants contain a cyclic ancestor chain")
		}
		seen[parent] = true
		row, err := s.deps.Store.Relation(ctx, scope, parent)
		if err != nil {
			return err
		}
		ancestor, err := s.deps.Store.Grants(ctx, row.GrantSetID)
		if err != nil {
			return err
		}
		if row.LifeID != parent || row.Revoked || row.Generation == 0 || ancestor.ID != row.GrantSetID || ancestor.LifeID != parent || ancestor.ParentLifeID != row.ParentLifeID || ancestor.Generation == 0 || !validDigest(ancestor.SHA256) || ancestor.Revoked || !future(ancestor.ExpiresAt, s.deps.Clock.Now()) || ancestor.PolicyGeneration != grants.PolicyGeneration {
			return problem(api.CodeForbidden, "mail ancestor delegation is stale, revoked or expired")
		}
		parent = row.ParentLifeID
	}
	return nil
}

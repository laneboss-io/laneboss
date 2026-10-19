// Contract draft.3 consumer stubs. These fail until the owning lane ports
// its implementation; no interface-only change is runtime acceptance.
package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.StateStore = (*Service)(nil)

func (s *Service) AuthorizationTarget(ctx context.Context, scope api.Scope, request api.Request) (api.HumanChallengeRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.HumanChallengeRequest{}, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return api.HumanChallengeRequest{}, err
	}
	return s.authorizationTarget(ctx, s.db, scope, request)
}

func (s *Service) Enrollment(arg0 context.Context, arg1 api.Scope) (api.HumanEnrollment, error) {
	if arg1.Actor.ID == "" {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if err := s.available(); err != nil {
			return api.HumanEnrollment{}, err
		}
		if arg1.Connection == nil || arg1.Connection.Binding().Class != api.EndpointHuman || arg1.Connection.Binding().Config != s.deps.Config || arg1.Config != s.deps.Config || arg1.Connection.Peer() == nil {
			return api.HumanEnrollment{}, fault(api.CodeUnauthenticated, "initial enrollment lookup requires its installed human endpoint")
		}
		if err := arg1.Connection.Peer().Alive(arg0); err != nil {
			return api.HumanEnrollment{}, err
		}
		rows, err := s.db.QueryContext(arg0, "SELECT data FROM projections WHERE kind='enrollment' ORDER BY id LIMIT 2")
		if err != nil {
			return api.HumanEnrollment{}, err
		}
		defer rows.Close()
		var result api.HumanEnrollment
		count := 0
		for rows.Next() {
			var data []byte
			if err := rows.Scan(&data); err != nil {
				return result, err
			}
			if err := decodeStored(data, &result); err != nil {
				return result, err
			}
			count++
		}
		if err := rows.Err(); err != nil {
			return result, err
		}
		if count != 1 {
			return api.HumanEnrollment{}, fault(api.CodeUnauthenticated, "installed human principal is absent or ambiguous")
		}
		return result, nil
	}
	return identityProjection[api.HumanEnrollment](arg0, s, arg1, "enrollment", arg1.Actor.ID)
}

func (s *Service) Challenge(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.StoredChallenge, error) {
	result, err := identityProjection[api.StoredChallenge](arg0, s, arg1, "challenge", arg2)
	if err == nil && (result.PrincipalID != arg1.Actor.ID || arg1.Connection == nil || result.EndpointGeneration != arg1.EndpointGeneration || result.EndpointClass != api.EndpointHuman) {
		return api.StoredChallenge{}, fault(api.CodeNotFound, "challenge belongs to another connection")
	}
	return result, err
}

func (s *Service) Proof(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.VerifiedHumanProof, error) {
	result, err := identityProjection[api.VerifiedHumanProof](arg0, s, arg1, "proof", arg2)
	if err == nil && (result.Config != arg1.Config || result.PrincipalID != arg1.Actor.ID || result.EndpointClass != api.EndpointHuman || result.EndpointGeneration != arg1.EndpointGeneration) {
		return api.VerifiedHumanProof{}, fault(api.CodeNotFound, "proof belongs to another principal or endpoint")
	}
	return result, err
}

func (s *Service) Ticket(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.Ticket, error) {
	stored, err := identityProjection[ticketRecord](arg0, s, arg1, "ticket", arg2)
	if err != nil {
		return api.Ticket{}, err
	}
	if stored.PrincipalID != arg1.Actor.ID || stored.Config != arg1.Config || stored.EndpointGeneration != arg1.EndpointGeneration {
		return api.Ticket{}, fault(api.CodeNotFound, "ticket provenance differs from caller")
	}
	return stored.Ticket, nil
}

func (s *Service) ReadSession(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.StoredReadSession, error) {
	result, err := identityProjection[api.StoredReadSession](arg0, s, arg1, "read_session", arg2)
	if err != nil {
		return result, err
	}
	if arg1.Connection == nil {
		return api.StoredReadSession{}, fault(api.CodeUnauthenticated, "read session requires its live connection")
	}
	// Activity refresh commits to this same retained session first.
	authority, authorityErr := arg1.Connection.ReadAuthority(arg0)
	if authorityErr != nil {
		return api.StoredReadSession{}, authorityErr
	}
	if authority.SessionID != arg2 || authority.PrincipalID != result.PrincipalID || authority.CredentialID != result.CredentialID ||
		authority.Config != result.Session.Config || authority.EndpointGeneration != result.EndpointGeneration || authority.ExpiresAt != result.Session.ExpiresAt || authority.Generation != result.Generation || authority.SimulatedPresence != result.Session.SimulatedPresence || authority.IdleExpiresAt != result.Session.IdleExpiresAt {
		return api.StoredReadSession{}, fault(api.CodeUnauthenticated, "read authority differs from stored session")
	}
	if err == nil && (arg1.Connection == nil || result.ConnectionID != arg1.Connection.ID() || result.PrincipalID != arg1.Actor.ID || result.EndpointGeneration != arg1.EndpointGeneration || result.Revoked || !future(result.Session.ExpiresAt, s.deps.Clock.Now()) || !future(result.Session.IdleExpiresAt, s.deps.Clock.Now())) {
		return api.StoredReadSession{}, fault(api.CodeUnauthenticated, "read session is no longer current")
	}
	return result, err
}

func (s *Service) LaunchBinding(arg0 context.Context, arg1 api.ID) (api.LaunchBindingRequest, error) {
	var result api.LaunchBindingRequest
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return result, err
	}
	return s.launchBinding(arg0, s.db, arg1)
}

func (s *Service) OrgSnapshot(ctx context.Context, scope api.Scope, request api.OrgSnapshotRequest) (api.OrgSnapshot, error) {
	if request.OrgID != api.ID(s.deps.Config) || request.Generation == 0 {
		return api.OrgSnapshot{}, fault(api.CodeInvalid, "org snapshot requires this configuration and an exact generation")
	}
	result, err := scopedProjection[api.OrgSnapshot](ctx, s, scope, "org", request.OrgID)
	if err != nil {
		return api.OrgSnapshot{}, err
	}
	if result.Config != s.deps.Config || result.Ref.OrgID != request.OrgID {
		return api.OrgSnapshot{}, fault(api.CodeIntegrity, "retained org snapshot differs from its configuration")
	}
	if result.Ref.Generation != request.Generation {
		return api.OrgSnapshot{}, fault(api.CodeConflict, "current org snapshot generation differs from the requested publication")
	}
	return result, nil
}

func (s *Service) Approval(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.ChangeApproval, error) {
	return scopedProjection[api.ChangeApproval](arg0, s, arg1, "approval", arg2)
}

func (s *Service) Application(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.ChangeReceipt, error) {
	return scopedProjection[api.ChangeReceipt](arg0, s, arg1, "application", arg2)
}

func (s *Service) Turn(arg0 context.Context, arg1 api.Scope, arg2 api.LifeRef, arg3 api.ID) (api.TurnSnapshot, error) {
	result, err := scopedProjection[api.TurnSnapshot](arg0, s, arg1, "turn", arg3)
	if err == nil && (result.Target != arg2 || arg1.Actor.Kind == "lane" && arg1.Actor.LifeID != arg2.LifeID) {
		return api.TurnSnapshot{}, fault(api.CodeNotFound, "turn belongs to another life")
	}
	return result, err
}

func (s *Service) Decision(ctx context.Context, scope api.Scope, id api.ID) (api.DecisionProjection, error) {
	return scopedProjection[api.DecisionProjection](ctx, s, scope, "decision", id)
}

func (s *Service) JudgeAudit(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.JudgeAudit, error) {
	return scopedProjection[api.JudgeAudit](arg0, s, arg1, "judge_audit", arg2)
}

func (s *Service) ClaimContinuation(arg0 context.Context, arg1 api.Scope, arg2 api.ContinuationClaimRequest) (api.ContinuationIntent, error) {
	return s.claimContinuation(arg0, arg1, arg2)
}

func (s *Service) ContinuationIntent(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.ContinuationIntent, error) {
	result, err := scopedProjection[api.ContinuationIntent](arg0, s, arg1, "continuation", arg2)
	if err == nil && arg1.Actor.Kind == "lane" && result.Target.LifeID != arg1.Actor.LifeID {
		return api.ContinuationIntent{}, fault(api.CodeNotFound, "continuation belongs to another life")
	}
	return result, err
}

func (s *Service) Channel(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.EnrolledChannel, error) {
	return s.channelRead(arg0, arg1, arg2)
}

func (s *Service) ChannelJob(arg0 context.Context, arg1 api.Scope, arg2 api.ChannelJobRequest) (api.ChannelJob, error) {
	return s.channelJob(arg0, arg1, arg2)
}

func (s *Service) WorkerLease(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.WorkerLease, error) {
	if !internalScope(arg1) && (arg1.Connection == nil || arg1.Connection.Binding().WorkerLeaseID != arg2) {
		return api.WorkerLease{}, fault(api.CodeForbidden, "worker lease belongs to another endpoint")
	}
	return scopedProjection[api.WorkerLease](arg0, s, arg1, "worker_lease", arg2)
}

func (s *Service) Deployment(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.DeploymentPlan, error) {
	if !internalScope(arg1) && arg1.Actor.Kind != "human" {
		return api.DeploymentPlan{}, fault(api.CodeForbidden, "deployment requires human or service authority")
	}
	return scopedProjection[api.DeploymentPlan](arg0, s, arg1, "upgrade", arg2)
}

func (s *Service) FrozenBackup(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.FrozenBackup, error) {
	var result api.FrozenBackup
	return result, api.NotImplemented("lb-v2-service", "store.FrozenBackup")
}

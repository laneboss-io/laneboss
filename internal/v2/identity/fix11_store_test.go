package identity

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *fixtureStore) HumanEnrollments(_ context.Context, config string) ([]api.HumanEnrollment, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.enrollment == nil {
		return []api.HumanEnrollment{}, nil
	}
	return []api.HumanEnrollment{*s.enrollment}, nil
}

func (s *fixtureStore) ReserveEnrollment(_ context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	s.ceremonyConfig, s.ceremonyID = request.Config, request.CeremonyID
	if s.err != nil {
		return api.EnrollmentChallenge{}, s.err
	}
	if s.ceremony == nil {
		return api.EnrollmentChallenge{}, api.NotImplemented("lb-v2-service", "fixture enrollment reservation")
	}
	return *s.ceremony, nil
}

func (s *fixtureStore) EnrollmentChallenge(_ context.Context, config string, id api.ID) (api.EnrollmentChallenge, error) {
	s.ceremonyConfig, s.ceremonyID = config, id
	if s.err != nil {
		return api.EnrollmentChallenge{}, s.err
	}
	if s.ceremony == nil {
		return api.EnrollmentChallenge{}, api.NotImplemented("lb-v2-service", "fixture enrollment challenge")
	}
	return *s.ceremony, nil
}

func (s *fixtureStore) RefreshReadSession(ctx context.Context, scope api.Scope, request api.ReadSessionRefreshRequest) (api.StoredReadSession, error) {
	if s.err != nil {
		return api.StoredReadSession{}, s.err
	}
	if s.refresh == nil {
		return api.StoredReadSession{}, api.NotImplemented("lb-v2-service", "fixture read refresh")
	}
	return s.refresh(ctx, scope, request)
}

func (s *fixtureStore) WorkerBinding(_ context.Context, endpoint api.InstalledBinding, facts api.PeerFacts) (api.WorkerPrincipal, error) {
	if s.err != nil {
		return api.WorkerPrincipal{}, s.err
	}
	if s.worker == nil {
		return api.WorkerPrincipal{}, api.NotImplemented("lb-v2-service", "fixture worker mapping")
	}
	return *s.worker, nil
}

func (s *fixtureStore) LaunchRevocation(_ context.Context, id api.ID) (api.LaunchRevocation, error) {
	if s.err != nil {
		return api.LaunchRevocation{}, s.err
	}
	if s.revocation == nil {
		return api.LaunchRevocation{}, api.NotImplemented("lb-v2-service", "fixture launch revocation")
	}
	return *s.revocation, nil
}

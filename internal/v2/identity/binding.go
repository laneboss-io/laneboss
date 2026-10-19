package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func digestBytes(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func validateBindingRequest(request api.LaunchBindingRequest) error {
	record, prepared, committed := request.Record, request.Prepared, request.Identity
	if !validID(prepared.ID) || !validID(prepared.GateID) || !validDigest(prepared.SpecSHA256) ||
		prepared.Target != record.Target || prepared.ContainmentID != record.ContainmentID ||
		prepared.ProcessGeneration != record.ProcessGeneration ||
		prepared.EndpointGeneration != record.EndpointGeneration || committed.LaunchID != record.ID ||
		!validID(committed.EventID) || committed.CommittedSeq == 0 || !validDigest(committed.RecordSHA256) {
		return refusal(api.CodeInvalid, "incomplete prepared gate or committed identity receipt")
	}
	// The store stamps this digest from its committed record bytes. Identity
	// compares that authoritative receipt, rather than guessing its byte codec.
	return nil
}

func (s *Service) connectionScope(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	var empty api.Scope
	if nilDependency(connection) || !validID(connection.ID()) || nilDependency(connection.Peer()) {
		return empty, refusal(api.CodeUnauthenticated, "live transport connection is required")
	}
	binding := connection.Binding()
	if binding.ServiceVersion == "" {
		return empty, refusal(api.CodeIntegrity, "installed service version is absent")
	}
	if err := api.ValidateBinding(binding, binding.Config, binding.ServiceVersion); err != nil {
		return empty, err
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return empty, err
	}
	facts, err := connection.Peer().Facts(ctx)
	if err != nil {
		return empty, err
	}
	if facts.HostPID <= 1 || facts.ProcessGeneration == "" {
		return empty, refusal(api.CodeUnauthenticated, "peer kernel lifetime is absent")
	}
	scope := api.Scope{Connection: connection, Config: binding.Config,
		EndpointGeneration: binding.EndpointGeneration}
	if binding.Class == api.EndpointHuman {
		// A human endpoint supplies staging access only. The protected enrollment
		// resolves its principal; UID, environment and request labels do not.
		scope.Actor.Kind = "human"
		enrollment, err := s.deps.Store.Enrollment(ctx, scope)
		if err != nil {
			return empty, err
		}
		if enrollment.Config != scope.Config || !validID(enrollment.PrincipalID) || enrollment.Generation == 0 {
			return empty, refusal(api.CodeUnauthenticated, "human enrollment is unavailable or stale")
		}
		scope.Actor.ID = enrollment.PrincipalID
		source, ok := s.deps.Store.(api.HumanPolicySource)
		if !ok || nilDependency(source) {
			return empty, api.NotImplemented("lb-v2-service", "private human connection policy generation")
		}
		generation, err := source.HumanPolicyGeneration(ctx, connection, enrollment.PrincipalID)
		if err != nil {
			return empty, err
		}
		if generation == 0 || generation > 1<<53-1 {
			return empty, refusal(api.CodeUnauthenticated, "current human policy is unavailable")
		}
		scope.PolicyGeneration = generation
		return scope, nil
	}
	if binding.Class == api.EndpointWorker {
		principal, err := s.workerPrincipal(ctx, connection, "")
		if err != nil {
			return empty, err
		}
		source, ok := s.deps.Store.(api.WorkerPolicySource)
		if !ok || nilDependency(source) {
			return empty, api.NotImplemented("lb-v2-service", "private worker connection policy generation")
		}
		generation, err := source.WorkerPolicyGeneration(ctx, connection, principal.Record.Actor.ID)
		if err != nil {
			return empty, err
		}
		if generation == 0 || generation < principal.Record.PolicyGeneration {
			return empty, refusal(api.CodeUnauthenticated, "worker current policy is unavailable")
		}
		return api.Scope{Connection: connection, Config: principal.Record.Config, Actor: principal.Record.Actor,
			LaunchID: principal.Record.ID, EndpointGeneration: binding.EndpointGeneration, PolicyGeneration: generation}, nil
	}
	if binding.Class != api.EndpointLane {
		return empty, gap("Authenticate", "worker job lease authority")
	}
	record, err := s.deps.Store.Launch(ctx, binding.LaunchID)
	if err != nil {
		return empty, err
	}
	if binding.Target == nil || record.Target != *binding.Target || record.Config != binding.Config ||
		record.EndpointGeneration != binding.EndpointGeneration || record.HostUID != facts.HostUID ||
		record.ContainmentID != facts.ContainmentID {
		return empty, refusal(api.CodeUnauthenticated, "peer differs from the installed launch binding")
	}
	containment, err := s.deps.Registry.ResolveContainment(ctx, facts, binding)
	if err != nil {
		return empty, err
	}
	if containment.Revoked || containment.Config != record.Config || containment.Target != record.Target ||
		containment.Generation == 0 || containment.Backend != binding.Backend ||
		containment.Lease.ID != record.UIDLeaseID || containment.Lease.UID != facts.HostUID ||
		containment.Lease.GID != facts.HostGID || containment.Lease.ContainmentID != record.ContainmentID ||
		containment.Lease.EndpointGeneration != binding.EndpointGeneration {
		return empty, refusal(api.CodeContainmentUnknown, "launch containment lease is stale or mismatched")
	}
	// Descendants have their own start times. The native peer pins each process;
	// containment, rather than the leader's ProcessGeneration, binds children.
	// Launch records and issued grants retain their issuance generation. The
	// live authorization scope follows current approved policy across D6 changes.
	scope.Actor, scope.LaunchID = record.Actor, record.ID
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return empty, err
	}
	if policy.Generation == 0 || policy.Generation < record.PolicyGeneration {
		return empty, refusal(api.CodeUnauthenticated, "lane current policy is unavailable or predates its launch")
	}
	scope.PolicyGeneration = policy.Generation
	if _, err := s.currentLaunch(ctx, scope); err != nil {
		return empty, err
	}
	if err := s.checkGrants(ctx, scope, record); err != nil {
		return empty, err
	}
	return scope, nil
}

func (s *Service) verifyScope(ctx context.Context, scope api.Scope) error {
	if nilDependency(scope.Connection) {
		return gap("Authorize", "live connection context")
	}
	current, err := s.connectionScope(ctx, scope.Connection)
	if err != nil {
		return err
	}
	if current.Config != scope.Config || current.Actor != scope.Actor || current.LaunchID != scope.LaunchID ||
		current.EndpointGeneration != scope.EndpointGeneration {
		return refusal(api.CodeUnauthenticated, "scope differs from its current connection authority")
	}
	if current.PolicyGeneration != scope.PolicyGeneration {
		return refusal(api.CodeConflict, "connection policy changed; reload current authority")
	}
	return nil
}

func (s *Service) checkGrants(ctx context.Context, scope api.Scope, record api.LaunchRecord) error {
	grants, err := s.deps.Store.Grants(ctx, record.GrantSetID)
	if err != nil {
		return err
	}
	expiry, err := utcTime(grants.ExpiresAt)
	if err != nil || !s.deps.Clock.Now().Before(expiry) || grants.Revoked || grants.Generation == 0 ||
		grants.ID != record.GrantSetID || grants.LifeID != record.Target.LifeID ||
		grants.SHA256 != record.GrantsSHA256 || grants.PolicyGeneration != record.PolicyGeneration {
		return refusal(api.CodeForbidden, "launch grants are expired, revoked or changed")
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return err
	}
	if policy.Generation == 0 || policy.Generation < record.PolicyGeneration {
		return refusal(api.CodeForbidden, "current policy predates the issued launch authority")
	}
	return nil
}

func (s *Service) humanEnrollment(ctx context.Context, scope api.Scope) (api.HumanEnrollment, error) {
	if scope.Actor.Kind != "human" || !validID(scope.Actor.ID) || scope.Config == "" {
		return api.HumanEnrollment{}, refusal(api.CodeUnauthenticated, "verified human principal is required")
	}
	if err := s.verifyScope(ctx, scope); err != nil {
		return api.HumanEnrollment{}, err
	}
	if scope.Connection.Binding().Class != api.EndpointHuman {
		return api.HumanEnrollment{}, refusal(api.CodeForbidden, "human endpoint is required")
	}
	enrollment, err := s.deps.Store.Enrollment(ctx, scope)
	if err != nil {
		return api.HumanEnrollment{}, err
	}
	if enrollment.Config != scope.Config || enrollment.PrincipalID != scope.Actor.ID || enrollment.Generation == 0 {
		return api.HumanEnrollment{}, refusal(api.CodeUnauthenticated, "enrollment differs from the bound principal")
	}
	if err := originPolicy(enrollment.Origin, enrollment.RPID); err != nil {
		return api.HumanEnrollment{}, err
	}
	if err := api.ValidateHumanEnrollments(scope.Config, []api.HumanEnrollment{enrollment}); err != nil {
		return api.HumanEnrollment{}, err
	}
	return enrollment, nil
}

func (s *Service) checkStoredProof(ctx context.Context, scope api.Scope, ref api.ProofRef, target api.HumanChallengeRequest, proof api.VerifiedHumanProof) error {
	enrollment, err := s.humanEnrollment(ctx, scope)
	if err != nil {
		return err
	}
	verified, err := utcTime(proof.VerifiedAt)
	expiry, expiryErr := utcTime(ref.ExpiresAt)
	if err != nil || expiryErr != nil || !verified.Before(expiry) || expiry.After(verified.Add(120*time.Second)) ||
		verified.After(s.deps.Clock.Now()) || proof.Ref != ref || proof.Target != target ||
		proof.Config != scope.Config || proof.PrincipalID != scope.Actor.ID || proof.ConsumedBy != "" ||
		proof.EndpointClass != api.EndpointHuman || proof.EndpointGeneration != scope.EndpointGeneration ||
		!validID(proof.ConnectionID) || !validID(proof.NonceID) || !validID(proof.CredentialID) ||
		!validID(proof.AssertionEvidence.ID) || !validDigest(proof.AssertionEvidence.SHA256) ||
		proof.AssertionEvidence.Bytes <= 0 || proof.AssertionEvidence.Bytes > api.MaxFrameBytes || proof.AssertionEvidence.Class != "artifact" {
		return refusal(api.CodeUnauthenticated, "stored proof is stale, consumed or bound to another operation")
	}
	for _, credential := range enrollment.Credentials {
		if credential.ID == proof.CredentialID && !credential.Revoked && credential.Generation > 0 {
			if proof.SimulatedPresence != credential.SimulatedPresence || proof.Ref.SimulatedPresence != proof.SimulatedPresence {
				return refusal(api.CodeUnauthenticated, "proof lost verified presence provenance")
			}
			return nil
		}
	}
	return refusal(api.CodeUnauthenticated, "proof credential is no longer enrolled")
}

func mutationBody(scope api.Scope, method api.Method, body any) error {
	request := scope.Request
	if request.Protocol != api.Protocol || request.Schema != api.SchemaVersion || request.Config != scope.Config ||
		request.Method != method || !validID(request.RequestID) || !validID(request.IdempotencyKey) || !validDigest(request.RequestSHA256) {
		return refusal(api.CodeInvalid, "mutation requires the authenticated request envelope")
	}
	decoded := reflect.New(reflect.TypeOf(body))
	if err := strictObject(request.Params, decoded.Interface()); err != nil {
		return err
	}
	if !reflect.DeepEqual(decoded.Elem().Interface(), body) {
		return refusal(api.CodeIntegrity, "mutation input differs from the authenticated request")
	}
	digest, err := api.RequestDigest(request)
	if err != nil || digest != request.RequestSHA256 {
		return refusal(api.CodeIntegrity, "mutation intent digest differs from request bytes")
	}
	return nil
}

// Package admin implements the administrator boundary, owned by lb-v2-admin.
// The service side is an unprivileged client of a separately installed helper.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Store            api.StateStore
	BindingFile      string
	Version          string
	Protocol         string
	Schema           uint32
	ServiceUID       uint32
	Config           string
	ArtifactSHA256   api.Digest
	RuntimeManifest  api.BlobRef
	LaunchEnrollment *api.BlobRef
}

type Service struct {
	credentialMu        sync.Mutex
	credentialAttempted bool
	credentialBroker    api.CredentialProjectionBroker
	credentialIdentity  api.CredentialProjectionIdentity
	nativeCredentials   *credentialRuntime
	files               *enrollmentFiles
	deps                Dependencies
	binding             installation
	probeMu             sync.RWMutex
	registryMu          sync.Mutex
	containments        map[api.ID]*containmentEntry
	probe               api.Launcher
	healthMu            sync.Mutex
	health              *api.Health
	healthAt            time.Time
	enrollmentMu        sync.Mutex
	enrollment          api.AdminEnrollment
	enrollmentServing   bool
}

func New(deps Dependencies) (*Service, error) {
	if !validConfig(deps.Config) || deps.ServiceUID == 0 || !validDigest(deps.ArtifactSHA256) {
		return nil, failure(api.CodeInvalid, "invalid administrator dependency binding")
	}
	binding, err := loadInstallation(deps.Config)
	if err != nil {
		return nil, err
	}
	if binding.Service.UID != deps.ServiceUID || binding.Artifact.SHA256 != deps.ArtifactSHA256 {
		return nil, failure(api.CodeIntegrity, "administrator and service bindings differ")
	}
	if deps.Version != binding.Release.Version || deps.Protocol != api.Protocol || deps.Schema != api.SchemaVersion {
		return nil, failure(api.CodeVersion, "administrator dependencies differ from the installed release contract")
	}
	if uint32(os.Geteuid()) != deps.ServiceUID {
		return nil, failure(api.CodeForbidden, "the helper client must run under the installed service UID")
	}
	return &Service{deps: deps, binding: binding}, nil
}

var _ api.AdminAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if registry == nil {
		return failure(api.CodeInvalid, "doctor registration requires a registry")
	}
	return registry.Register("doctor", func(ctx context.Context, scope api.Scope, body json.RawMessage) (json.RawMessage, error) {
		if err := ValidateDoctorInput(body); err != nil {
			return nil, err
		}
		result, err := s.Doctor(ctx, scope, api.Empty{})
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, failure(api.CodeIntegrity, "cannot encode doctor result")
		}
		return encoded, nil
	})
}

var _ api.Helper = (*Service)(nil)

func (s *Service) Doctor(ctx context.Context, scope api.Scope, request api.Empty) (api.Health, error) {
	if scope.Config != s.deps.Config || scope.Actor.ID == "" ||
		(scope.Actor.Kind != "lane" && scope.Actor.Kind != "human") {
		return api.Health{}, failure(api.CodeForbidden, "doctor requires an authenticated same-configuration scope")
	}
	if err := contextError(ctx); err != nil {
		return api.Health{}, err
	}
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if scope.Actor.Kind == "lane" {
		if s.health != nil && time.Since(s.healthAt) < 30*time.Second && scope.EndpointGeneration == s.binding.Generation {
			return copyHealth(*s.health), nil
		}
		return api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion, ServiceVersion: s.binding.Release.Version,
			ArtifactSHA256: s.binding.Artifact.SHA256, Capabilities: []api.Capability{{Name: "doctor.cached_health",
				Reason: "a verified human diagnostic must refresh the current installation health"}}}, nil
	}
	if s.health != nil && time.Since(s.healthAt) < 5*time.Second {
		return copyHealth(*s.health), nil
	}
	result := api.Health{
		Protocol: api.Protocol, Schema: api.SchemaVersion,
		ServiceVersion: s.binding.Release.Version, ArtifactSHA256: s.binding.Artifact.SHA256,
		Capabilities: []api.Capability{},
	}
	var probe probeResult
	if err := s.call(ctx, "probe", api.Empty{}, &probe); err != nil {
		return result, err
	}
	result.Capabilities = probe.Capabilities
	result.Capabilities = append(result.Capabilities, s.isolationCapability(ctx))
	result.Ready = len(result.Capabilities) > 0
	for _, check := range result.Capabilities {
		result.Ready = result.Ready && check.Available
	}
	snapshot := copyHealth(result)
	s.health, s.healthAt = &snapshot, time.Now()
	return result, nil
}

func copyHealth(result api.Health) api.Health {
	result.Capabilities = append([]api.Capability{}, result.Capabilities...)
	for index := range result.Capabilities {
		if evidence := result.Capabilities[index].Evidence; evidence != nil {
			copy := *evidence
			result.Capabilities[index].Evidence = &copy
		}
	}
	return result
}

func (s *Service) Allocate(ctx context.Context, request api.HelperLeaseRequest) (api.HelperLease, error) {
	var result api.HelperLease
	if err := validateAllocation(request, s.deps.Config); err != nil {
		return result, err
	}
	if request.ReservationID == "" {
		// Fixed worker allocations retain their existing non-agent path, but
		// only the exact current typed allocation effect can authorize it.
		claim, err := s.currentStage(ctx, request.Cause, api.InternalHelperAllocate)
		if err != nil {
			return result, err
		}
		if !retainedAllocate(claim.Effect.HelperAllocate, request, claim.ClaimantID) {
			return result, failure(api.CodeForbidden, "worker allocation differs from its effect")
		}
		if err := s.call(ctx, "allocate", request, &result); err != nil {
			return api.HelperLease{}, err
		}
		return result, validateLease(result, s.binding)
	}
	if !validID(request.ReservationID) {
		return result, failure(api.CodeInvalid, "launch allocation requires its issued reservation")
	}
	authority, err := s.launchAuthority(ctx, request.ReservationID, "", &request.Cause)
	if err != nil {
		return result, err
	}
	retained := authority.Claim.Effect.HelperAllocate
	if retained != nil {
		copy := *retained
		// The effect retains the stable author; the request carries the live
		// claimant checked by launchAuthority.
		copy.Cause.Actor = request.Cause.Actor
		retained = &copy
	}
	if retained == nil || !reflect.DeepEqual(*retained, request) {
		return result, failure(api.CodeForbidden, "launch allocation differs from its exact retained stage input")
	}
	if authority.Record.Inputs == nil || authority.Record.Phase != "sourced" && authority.Record.Phase != "planned" && authority.Record.Phase != "spec_retained" ||
		request.LifeID != authority.Record.Reservation.Target.LifeID || request.RuntimeManifestID != authority.Record.Inputs.Sources.Runtime.Manifest.ID ||
		request.Backend != authority.Record.Inputs.Sources.Runtime.Backend || !reflect.DeepEqual(authority.Record.Inputs.Grants, authority.Grants) {
		return result, failure(api.CodeForbidden, "allocation differs from retained launch inputs")
	}
	registration := launchAllocationForAuthority(authority, request)
	ceiling, err := launchBudget(authority)
	if err != nil {
		return result, err
	}
	if !withinBudget(request.Budget, ceiling) {
		return result, failure(api.CodeBudget, "helper allocation exceeds the retained request budget")
	}
	if err := validateLaunchAllocation(registration, s.deps.Config); err != nil {
		return result, err
	}
	err = s.call(ctx, "allocate_launch", registration, &result)
	if err == nil {
		err = validateLease(result, s.binding)
	}
	return result, err
}

func launchAllocationForAuthority(authority launchAuthority, request api.HelperLeaseRequest) launchAllocation {
	// The caller's live claimant was authenticated against this exact retained
	// effect above. Native replay and data-parent ownership retain the effect's
	// immutable author, rather than journaling an attempt-specific replacement.
	request = *authority.Claim.Effect.HelperAllocate
	return launchAllocation{Request: request, Reservation: authority.Record.Reservation, Inputs: *authority.Record.Inputs, Policy: authority.Policy}
}

func (s *Service) Prepare(ctx context.Context, request api.HelperLaunchRequest) (api.PreparedLaunch, error) {
	var result api.PreparedLaunch
	if err := validatePreparation(request); err != nil {
		return result, err
	}
	claim, err := s.currentStage(ctx, request.Cause, api.InternalHelperPrepare)
	if err != nil {
		return result, err
	}
	retained := claim.Effect.HelperPrepare
	if retained != nil {
		copy := *retained
		copy.Cause.Actor = request.Cause.Actor
		retained = &copy
	}
	if retained == nil || *retained != request {
		return result, failure(api.CodeForbidden, "prepare differs from its retained effect")
	}
	err = s.call(ctx, "prepare", credentialPrepare{Request: request, Claim: api.EffectLease{Record: claim, ClaimID: claim.ClaimID, ExpiresAt: claim.ClaimExpiresAt}}, &result)
	return result, err
}

func (s *Service) Release(ctx context.Context, request api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	var result api.ReleaseReceipt
	if err := validateRelease(request, s.deps.Config); err != nil {
		return result, err
	}
	claim, err := s.currentStage(ctx, request.Cause, api.InternalHelperRelease)
	if err != nil {
		return result, err
	}
	retained := claim.Effect.HelperRelease
	if retained != nil {
		copy := *retained
		copy.Cause.Actor = request.Cause.Actor
		retained = &copy
	}
	if retained == nil || !reflect.DeepEqual(*retained, request) {
		return result, failure(api.CodeForbidden, "release differs from its retained effect")
	}
	// Design release sequence step 5 and "the helper keeps pins until actual job/agent ownership and
	// collection permit release": the lane's data jobs (workspace materialization workers) are revoked
	// and collected before the helper measures them; nothing else called this (box 86: "jobs 1"). A lane
	// with no data job has nothing to collect, which is the only refusal tolerated here.
	if err := s.CollectDataStorage(ctx, request.LeaseID); err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound || typed.Message != "revocation names no retained helper owner" {
			return result, err
		}
	}
	if err := s.call(ctx, "release", request, &result); err != nil {
		return api.ReleaseReceipt{}, err
	}
	comparison := leaseRecord{Request: api.HelperLeaseRequest{LifeID: request.Cause.Target.LifeID},
		Lease:    api.HelperLease{ID: request.LeaseID, ContainmentID: request.Observation.Handle.ContainmentID},
		IssuedAt: "1970-01-01T00:00:00Z"}
	if err := validateReceipt(comparison, request, result); err != nil {
		return api.ReleaseReceipt{}, err
	}
	return result, nil
}

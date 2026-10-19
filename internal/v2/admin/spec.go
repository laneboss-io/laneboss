package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

type specRegistration struct {
	Plan     *api.LaunchPlan         `json:"plan,omitempty"`
	Handoff  api.PreparedSpecHandoff `json:"handoff"`
	Original []byte                  `json:"original_bytes"`
}

func digestBytes(data []byte) api.Digest {
	hash := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(hash[:]))
}

func validateSpecEnvelope(registration specRegistration, config string) error {
	handoff := registration.Handoff
	if err := validateCause(handoff.Cause, config, api.InternalHelperRegister); err != nil {
		return err
	}
	spec := handoff.Spec
	if handoff.Config != config || handoff.Cause.Target != spec.Target || handoff.OperationID != handoff.Cause.CauseOperationID ||
		handoff.RequestID != handoff.Cause.CauseRequestID || !validID(spec.ID) || !validID(spec.LaunchID) || !validID(spec.UIDLeaseID) ||
		!validDigest(handoff.SpecSHA256) || !validID(handoff.Original.ID) ||
		(spec.Kind == "agent" && handoff.Original.Class != "launch_spec" || spec.Kind != "agent" && handoff.Original.Class != "manifest" && handoff.Original.Class != "launch_spec") ||
		handoff.Original.Bytes < 1 || handoff.Original.Bytes > api.MaxChunkBytes || handoff.Original.Bytes != int64(len(registration.Original)) ||
		digestBytes(registration.Original) != handoff.Original.SHA256 {
		return failure(api.CodeInvalid, "prepared spec identity, original bytes or cause differs")
	}
	canonical, err := api.CanonicalJSON(registration.Original)
	if err != nil {
		return err
	}
	if digestBytes(canonical) != handoff.SpecSHA256 {
		return failure(api.CodeIntegrity, "registered JCS spec digest differs")
	}
	var original api.LaunchSpec
	if err := decodeStrict(registration.Original, &original); err != nil {
		return err
	}
	if !reflect.DeepEqual(original, spec) {
		return failure(api.CodeIntegrity, "registered spec differs from its original committed bytes")
	}
	if spec.Backend != "linux-bwrap-landlock" || spec.EndpointGeneration == 0 || spec.PolicyGeneration == 0 ||
		spec.Grants.LifeID != spec.Target.LifeID || !validID(spec.Grants.ID) || !validDigest(spec.Grants.SHA256) ||
		spec.Grants.Generation == 0 || spec.Grants.PolicyGeneration != spec.PolicyGeneration || spec.Grants.Revoked ||
		spec.Materialization.GrantSetID != spec.Grants.ID || spec.Injection.Target != spec.Target {
		return failure(api.CodeInvalid, "registered spec grants, target or generations differ")
	}
	if spec.Kind == "agent" && spec.Runner != nil && spec.Worker == nil {
		if registration.Plan == nil {
			return failure(api.CodeIntegrity, "agent spec has no retained launch plan")
		}
		if err := api.ValidateAgentLaunchSpec(spec, *registration.Plan); err != nil {
			return err
		}
		if spec.Runner.Driver != api.DriverClaudock && spec.Runner.Driver != api.DriverCodex {
			return failure(api.CodeInvalid, "unknown agent driver")
		}
	} else if !(spec.Kind == "worker" && spec.Worker != nil && spec.Runner == nil && spec.Worker.GrantSetID == spec.Grants.ID) {
		return failure(api.CodeInvalid, "prepared spec must select exactly one typed runner or worker")
	}
	return nil
}

func (s *Service) RegisterSpec(ctx context.Context, handoff api.PreparedSpecHandoff) (resultReceipt api.PreparedSpecReceipt, resultErr error) {
	if err := contextError(ctx); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if err := validateCause(handoff.Cause, s.deps.Config, api.InternalHelperRegister); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if !validID(handoff.Original.ID) || handoff.Original.Bytes < 1 || handoff.Original.Bytes > api.MaxChunkBytes {
		return api.PreparedSpecReceipt{}, failure(api.CodeInvalid, "prepared spec original reference is invalid or oversized")
	}
	if s.deps.Store == nil {
		return api.PreparedSpecReceipt{}, api.NotImplemented("lb-v2-service", "committed spec object lookup")
	}
	var plan *api.LaunchPlan
	if handoff.Spec.Kind == "agent" {
		authority, err := s.registrationLaunchAuthority(ctx, handoff)
		if err != nil {
			return api.PreparedSpecReceipt{}, err
		}
		if authority.Record.Plan == nil || authority.Record.Handoff == nil || !samePreparedHandoffStable(*authority.Record.Handoff, handoff) ||
			!reflect.DeepEqual(authority.Record.Plan.Inputs.Grants, authority.Grants) {
			return api.PreparedSpecReceipt{}, failure(api.CodeIntegrity, "agent spec differs from retained plan and handoff")
		}
		plan = authority.Record.Plan
		if err := api.ValidateAgentLaunchSpec(handoff.Spec, *plan); err != nil {
			return api.PreparedSpecReceipt{}, err
		}
	}
	scope := api.Scope{Config: s.deps.Config, Actor: handoff.Cause.Actor, Source: "service", PolicyGeneration: handoff.Spec.PolicyGeneration}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, handoff.Original.ID)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if metadata.Ref != handoff.Original || metadata.ACL.Config != s.deps.Config ||
		handoff.Original.Bytes < 1 || handoff.Original.Bytes > api.MaxChunkBytes {
		return api.PreparedSpecReceipt{}, failure(api.CodeForbidden, "spec is not the matching committed service object")
	}
	if metadata.Origin != "service" || metadata.SourceOperationID != handoff.OperationID || metadata.ACL.LifeID != handoff.Spec.Target.LifeID {
		allowAndLog("spec_original_provenance")
	}
	var original []byte
	for int64(len(original)) < handoff.Original.Bytes {
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: handoff.Original.ID, Offset: int64(len(original)),
			Limit: int(min(int64(api.MaxChunkBytes), handoff.Original.Bytes-int64(len(original))))})
		if err != nil {
			return api.PreparedSpecReceipt{}, err
		}
		if chunk.ObjectID != handoff.Original.ID || chunk.Offset != int64(len(original)) || len(chunk.Data) == 0 ||
			int64(len(chunk.Data)) > handoff.Original.Bytes-int64(len(original)) || digestBytes(chunk.Data) != chunk.SHA256 {
			return api.PreparedSpecReceipt{}, failure(api.CodeIntegrity, "committed spec byte range differs")
		}
		original = append(original, chunk.Data...)
	}
	registration := specRegistration{Handoff: handoff, Original: original, Plan: plan}
	if err := validateSpecEnvelope(registration, s.deps.Config); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	grants, err := s.deps.Store.Grants(ctx, handoff.Spec.Grants.ID)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if err != nil || !expires.After(time.Now()) || !reflect.DeepEqual(grants, handoff.Spec.Grants) || policy.Generation != handoff.Spec.PolicyGeneration {
		return api.PreparedSpecReceipt{}, failure(api.CodeForbidden, "prepared spec grants or policy are stale")
	}
	var result api.PreparedSpecReceipt
	if handoff.Spec.Worker != nil && (handoff.Spec.Worker.Kind == "channel" || handoff.Spec.Worker.Kind == "usage") {
		registrar, ok := s.deps.Store.(api.CredentialWorkerRegistrationStore)
		if !ok || !nonnilCredentialClient(registrar) {
			return result, failure(api.CodePrerequisite, "credential worker requires protected handoff registration")
		}
		attempt, ok := api.EffectLeaseFromContext(ctx)
		if !ok || !api.EffectLeaseClaimed(attempt) {
			return result, failure(api.CodeForbidden, "credential worker registration requires its explicit current job attempt")
		}
		registrationScope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: attempt.Record.ClaimantID}, Source: "worker"}
		if err := registrar.RegisterCredentialWorker(api.WithEffectLease(ctx, attempt), registrationScope, handoff); err != nil {
			return result, err
		}
	}
	if err := s.call(ctx, "register_spec", registration, &result); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if result.SpecID != handoff.Spec.ID || result.SpecSHA256 != handoff.SpecSHA256 || result.Config != s.deps.Config ||
		result.Target != handoff.Spec.Target || result.LeaseID != handoff.Spec.UIDLeaseID ||
		result.RuntimeManifest != handoff.Spec.RuntimeManifest || result.OperationID != handoff.OperationID {
		return api.PreparedSpecReceipt{}, failure(api.CodeIntegrity, "helper spec registration receipt differs")
	}
	if err := s.registerRunnerPrompt(ctx, scope, handoff); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	return result, nil
}

func withinBudget(value, ceiling api.Budget) bool {
	return value.WallMS > 0 && value.WallMS <= ceiling.WallMS && value.CPUSeconds <= ceiling.CPUSeconds &&
		value.MemoryBytes >= 4096 && value.MemoryBytes <= ceiling.MemoryBytes && value.Processes > 0 && value.Processes <= ceiling.Processes &&
		value.DiskBytes > 0 && value.DiskBytes <= ceiling.DiskBytes && value.SpendMicros >= 0 && value.SpendMicros <= ceiling.SpendMicros && value.Currency == ceiling.Currency
}

func (m *leaseManager) registerSpec(ctx context.Context, registration specRegistration) (_ api.PreparedSpecReceipt, resultErr error) {
	defer helperCheck(&resultErr, "spec_registration")
	if err := contextError(ctx); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if err := validateSpecEnvelope(registration, m.binding.Config); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	handoff := registration.Handoff
	record, err := m.findActive(handoff.Spec.UIDLeaseID, storageReady)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if record.BootID != m.bootID || record.Phase != "active" || handoff.Spec.Target.LifeID != record.Request.LifeID ||
		handoff.Spec.EndpointGeneration != record.Lease.EndpointGeneration || !withinBudget(handoff.Spec.Budget, record.Request.Budget) ||
		handoff.Spec.RuntimeManifest.ID != record.Request.RuntimeManifestID {
		return api.PreparedSpecReceipt{}, failure(api.CodeForbidden, "registered spec exceeds or differs from its active helper lease")
	}
	if record.Spec != nil {
		if !reflect.DeepEqual(*record.Spec, registration) {
			return api.PreparedSpecReceipt{}, failure(api.CodeIdempotencyConflict, "a different spec is already registered for this unopened gate")
		}
		return *record.SpecReceipt, nil
	}
	if handoff.Spec.Kind == "agent" {
		if record.Storage == nil || registration.Plan.Lease != record.Lease || registration.Plan.Data.Home != record.Storage.Binding.Home ||
			registration.Plan.Data.Workspace.ID != record.Storage.Binding.WorkspaceID {
			return api.PreparedSpecReceipt{}, failure(api.CodeIntegrity, "agent spec differs from helper-owned private storage")
		}
		if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
			return api.PreparedSpecReceipt{}, err
		}
		captureFound := false
		for _, entry := range record.Captures {
			captureFound = captureFound || reflect.DeepEqual(entry.Binding, registration.Plan.Capture)
		}
		if !captureFound {
			return api.PreparedSpecReceipt{}, failure(api.CodeIntegrity, "agent spec has no helper-attested capture disposition")
		}
	}
	if err := validateRuntimePins(ctx, m.binding, handoff.Spec); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	receipt := api.PreparedSpecReceipt{SpecID: handoff.Spec.ID, Config: m.binding.Config, Target: handoff.Spec.Target,
		LeaseID: record.Lease.ID, SpecSHA256: handoff.SpecSHA256, RuntimeManifest: handoff.Spec.RuntimeManifest, OperationID: handoff.OperationID}
	record.Spec, record.SpecReceipt = &registration, &receipt
	if err := m.save(record); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	return receipt, nil
}

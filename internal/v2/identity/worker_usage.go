package identity

import (
	"context"
	"os"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// Usage has one protected credential and fixed bounded query argv. It carries
// no workspace, data, profiles, channels or materialization reservation.
func checkUsageWorkerHandoff(a WorkerLaunchAuthority) error {
	p, spec := a.Principal, a.Handoff.Spec
	injection, grants, budget := spec.Injection, spec.Grants, spec.Budget
	if spec.PlanID != "" || !validID(p.StageID) || spec.Materialization.GrantSetID != p.Lease.GrantSetID || spec.Materialization.Manifest != (api.BlobRef{}) || len(spec.Materialization.Objects) != 0 ||
		len(grants.Resources)+len(grants.Data)+len(grants.Profiles)+len(grants.Channels) != 0 || len(grants.Secrets) != 1 || len(grants.Network) > 8 ||
		len(injection.SlotIDs) != 1 || !validID(injection.SlotIDs[0]) || len(injection.GrantIDs) != 1 || injection.GrantIDs[0] != grants.Secrets[0].ID ||
		len(injection.SourceVersions) != 1 || injection.SourceVersions[0] != grants.Secrets[0].Version || grants.Secrets[0].Delegate ||
		len(injection.TaskSecretNames)+len(injection.TaskSecretFileNames) != 0 || budget.WallMS < 1 || budget.WallMS > 60000 ||
		budget.CPUSeconds < 1 || budget.CPUSeconds > 10 || budget.MemoryBytes < 1 || budget.MemoryBytes > 256<<20 || budget.Processes < 1 || budget.Processes > 16 ||
		budget.DiskBytes < 1 || budget.DiskBytes > 4<<20 || budget.SpendMicros != 0 || p.Claim.Record.Effect.Context == nil || !validID(p.Claim.Record.ClaimantID) {
		return refusal(api.CodeIntegrity, "usage handoff changed its narrow credential selection or bounded job")
	}
	seen := map[api.ID]bool{}
	for _, network := range grants.Network {
		if !validID(network.ID) || !validID(network.EndpointID) || network.Delegate || seen[network.EndpointID] {
			return refusal(api.CodeIntegrity, "usage handoff widened its fixed network endpoints")
		}
		seen[network.EndpointID] = true
	}
	cause := *p.Claim.Record.Effect.Context
	cause.Kind, cause.Actor = api.InternalHelperRegister, api.Actor{Kind: "service", ID: p.Claim.Record.ClaimantID}
	if a.Handoff.Cause != cause {
		return refusal(api.CodeIntegrity, "usage handoff changed its original query cause")
	}
	return nil
}

// Re-read the original installed job and actual sealed input on both sides of
// the peer/allocation checks. A copied worker tuple cannot select a query.
func (s *Service) checkUsageWorker(ctx context.Context, a WorkerLaunchAuthority, input *os.File) error {
	reader, ok := s.deps.Store.(interface {
		UsageJobForClaim(context.Context, api.Scope, api.EffectLease) (api.UsageJob, error)
	})
	if !ok {
		return api.NotImplemented("lb-v2-service", "retained usage worker job lookup")
	}
	p, spec := a.Principal, a.Handoff.Spec
	scope := api.Scope{Config: p.Record.Config, Actor: a.Handoff.Cause.Actor, EndpointGeneration: p.Endpoint.EndpointGeneration, PolicyGeneration: p.Record.PolicyGeneration}
	job, err := reader.UsageJobForClaim(ctx, scope, p.Claim)
	if err != nil {
		return err
	}
	if err := api.ValidateUsageJob(job, s.deps.Clock.Now()); err != nil {
		return err
	}
	expected := job.Lease
	expected.ConsumedBy, expected.Generation = p.Record.ID, expected.Generation+1
	if expected != p.Lease || job.ID != p.StageID || job.LaunchID != p.Record.ID || job.Actor != p.Record.Actor || job.CancellationEpoch != p.CancellationEpoch ||
		!reflect.DeepEqual(job.Plan, *spec.Worker) || !reflect.DeepEqual(job.Grants, spec.Grants) || job.Runtime.Manifest != spec.RuntimeManifest ||
		p.Claim.Record.Effect.Context == nil || *p.Claim.Record.Effect.Context != job.Cause || job.Input.Request.Target != p.Lease.Target {
		return refusal(api.CodeIntegrity, "usage worker differs from its retained query job")
	}
	raw := make([]byte, p.Lease.Input.Bytes)
	if n, err := input.ReadAt(raw, 0); err != nil || n != len(raw) || digestBytes(raw) != p.Lease.Input.SHA256 {
		return refusal(api.CodeIntegrity, "usage handoff lost its exact sealed query input")
	}
	var sealed api.UsageCredentialInput
	if api.DecodeObject(raw, &sealed) != nil || !reflect.DeepEqual(sealed, job.Input) {
		return refusal(api.CodeIntegrity, "usage sealed input changed its protected profile runtime or source")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, p.Lease.Target)
	if err != nil {
		return err
	}
	if lane.Cleaned || lane.Run != p.Lease.Target.Run || lane.LaunchID != sealed.Request.LaunchID || lane.CancellationEpoch != job.CancellationEpoch {
		return refusal(api.CodeConflict, "usage worker lost its exact causing run or cancellation fence")
	}
	return nil
}

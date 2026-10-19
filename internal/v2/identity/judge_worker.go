package identity

import (
	"context"
	"os"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

func (s *Service) checkJudgeWorker(ctx context.Context, a WorkerLaunchAuthority, input *os.File) error {
	p := a.Principal
	reader, ok := s.deps.Store.(interface {
		JudgeWorkerLookup(context.Context, api.Scope, api.ID) (job.Job, error)
	})
	if !ok {
		return api.NotImplemented("lb-v2-service", "retained judge native job lookup")
	}
	scope := api.Scope{Config: p.Record.Config, Actor: a.Handoff.Cause.Actor, PolicyGeneration: p.Record.PolicyGeneration, Source: "worker"}
	j, err := reader.JudgeWorkerLookup(ctx, scope, p.Lease.ID)
	if err != nil {
		return err
	}
	lease := j.Lease
	lease.ConsumedBy, lease.Generation = j.LaunchID, lease.Generation+1
	if j.Execution.Acquired || j.Actor != p.Record.Actor || j.LaunchID != p.Record.ID || lease != p.Lease ||
		!reflect.DeepEqual(j.Plan, *a.Handoff.Spec.Worker) || !reflect.DeepEqual(j.Claim, p.Claim) {
		return refusal(api.CodeIntegrity, "judge native binding changed its retained original execution")
	}
	raw := make([]byte, p.Lease.Input.Bytes)
	if n, err := input.ReadAt(raw, 0); err != nil || n != len(raw) || digestBytes(raw) != p.Lease.Input.SHA256 {
		return refusal(api.CodeIntegrity, "judge native input lost its exact sealed bytes")
	}
	var sealed api.JudgeExecution
	if api.DecodeObject(raw, &sealed) != nil || !reflect.DeepEqual(sealed, j.Execution) {
		return refusal(api.CodeIntegrity, "judge sealed execution differs from its durable claim")
	}
	return nil
}

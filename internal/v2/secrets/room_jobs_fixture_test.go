package secrets

import (
	"context"
	"fmt"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Fresh job identities model the installed writer's post-retirement behavior.
// The native peer is still this owned consumer-fixture process, not a claimed
// authenticated helper. RunUsage measures a real bounded TSV child read.
type freshRoomJobs struct {
	*usageJobFixture
	t      *testing.T
	serial int
}

func newRoomCase(t *testing.T) (*launchCase, *freshRoomJobs) {
	c, base := newUsageCase(t)
	jobs := &freshRoomJobs{usageJobFixture: base, t: t}
	c.service.deps.UsageJobs, c.service.deps.Bootstrap = jobs, jobs
	return c, jobs
}

func (j *freshRoomJobs) StartUsage(ctx context.Context, scope api.Scope, request api.UsageWindowRequest) (api.Scope, error) {
	j.serial++
	c := j.c
	var p api.WorkerPrincipal
	if err := c.store.read("usage-principal.json", &p); err != nil {
		return api.Scope{}, err
	}
	suffix := fmt.Sprintf("-%d", j.serial)
	p.StageID = api.ID("room-stage" + suffix)
	p.Lease.ID = api.ID("room-lease" + suffix)
	p.Lease.EffectID = api.ID("room-effect" + suffix)
	p.Lease.ConsumedBy = api.ID("room-launch" + suffix)
	p.Lease.ExpiresAt = api.Timestamp(c.clock.now.Add(time.Minute).Format(time.RFC3339Nano))
	p.Record.ID = p.Lease.ConsumedBy
	p.Record.Actor.ID = api.ID("room-worker" + suffix)
	p.Endpoint.LaunchID, p.Endpoint.WorkerLeaseID = p.Record.ID, p.Lease.ID
	p.Claim.ClaimID = api.ID("room-claim" + suffix)
	p.Claim.ExpiresAt = p.Lease.ExpiresAt
	p.Claim.Record.ClaimID, p.Claim.Record.ClaimExpiresAt = p.Claim.ClaimID, p.Claim.ExpiresAt
	p.Claim.Record.Effect.ID = p.Lease.EffectID
	p.Claim.Record.Effect.Context.ID = api.ID("room-cause" + suffix)
	p.Claim.Record.Effect.Context.EffectID = p.Lease.EffectID
	ref := c.store.putRawObject(j.t, api.ID("room-input"+suffix), "usage_input", j.input.Bytes, request.OperationID)
	p.Lease.Input, p.Claim.Record.Effect.Worker.Input = ref, ref
	if err := c.store.save("usage-principal.json", p); err != nil {
		return api.Scope{}, err
	}
	if err := c.store.save("usage-principal-"+string(p.Lease.ID)+".json", p); err != nil {
		return api.Scope{}, err
	}
	j.input.StageID, j.input.LeaseID, j.input.EffectID, j.input.Input = p.StageID, p.Lease.ID, p.Lease.EffectID, ref
	if err := c.store.save("usage-input.json", j.input); err != nil {
		return api.Scope{}, err
	}
	connection := &connectionFixture{id: api.ID("room-connection" + suffix), binding: p.Endpoint, peer: &usagePeerFixture{facts: p.Peer}}
	j.scope = api.Scope{Config: p.Record.Config, Actor: p.Record.Actor, LaunchID: p.Record.ID, EndpointGeneration: p.Record.EndpointGeneration, Connection: connection,
		Frame: &frameFixture{connection: connection.ID(), data: []byte("private fresh room fixture frame")}}
	j.output.Scope, j.output.ObservedAt = j.scope, api.Timestamp(c.clock.now.Format(time.RFC3339Nano))
	j.resultID = api.ID("room-result" + suffix)
	return j.usageJobFixture.StartUsage(ctx, scope, request)
}

package secrets

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func mappedCredentialCase(t *testing.T) (*launchCase, api.Scope, api.Injection, []byte) {
	t.Helper()
	c, lease, credentials, value := newWorkerCase(t, "channel")
	// Exercise the credential path with a real retained job set distinct from
	// the lane set, whose main workspace grant is deliberately absent here.
	jobGrants := c.store.grants
	jobGrants.ID, jobGrants.Data, jobGrants.Profiles, jobGrants.SHA256 = "mapped-job-grants", []api.DataGrant{}, []api.ProfileGrant{}, ""
	var err error
	jobGrants.SHA256, err = valueDigest(jobGrants)
	if err != nil {
		t.Fatal("cannot hash the mapped credential job grants")
	}
	c.store.workerGrants = &jobGrants
	lease.GrantSetID = jobGrants.ID
	c.store.lease = lease
	var selectedEffect api.EffectRecord
	if c.store.read("worker-effect.json", &selectedEffect) != nil {
		t.Fatal("cannot read the mapped credential job selection")
	}
	selectedEffect.Effect.Worker.GrantSetID = jobGrants.ID
	if c.store.save("worker-effect.json", selectedEffect) != nil {
		t.Fatal("cannot retain the mapped credential job selection")
	}
	injection, err := c.service.InjectWorker(context.Background(), lease, credentials)
	if err != nil {
		t.Fatal("cannot prepare mapped credential selection")
	}
	spec := c.retainWorkerSpec(t, lease, injection)
	material, err := c.service.PreparedSlotMaterial(context.Background(), spec, injection.SlotIDs[0])
	clear(material.Bytes)
	if err != nil {
		t.Fatal("cannot prepare the mapped worker spec")
	}
	c.bindWorker(t, spec)
	var binding api.LaunchBindingRequest
	if err := c.store.read("binding.json", &binding); err != nil {
		t.Fatal("cannot read mapped worker identity")
	}
	facts, boot := selfUsageFacts(t)
	// Use actual UID/connector facts. The retained leader generation remains
	// that of the owned sleep. This post-authentication fixture does not prove
	// registry membership or containment of the separate connector process.
	binding.Record.HostUID = facts.HostUID
	binding.Identity.RecordSHA256, err = valueDigest(binding.Record)
	if err != nil || c.store.save("binding.json", binding) != nil {
		t.Fatal("cannot retain mapped worker connector identity")
	}
	facts.ContainmentID = binding.Record.ContainmentID
	lease.ConsumedBy = binding.Record.ID
	c.store.lease = lease
	var effect api.EffectRecord
	if c.store.read("worker-effect.json", &effect) != nil {
		t.Fatal("cannot read mapped worker claim")
	}
	effect.State = "claimed"
	if c.store.save("worker-effect.json", effect) != nil {
		t.Fatal("cannot retain mapped worker claim")
	}
	endpoint := api.InstalledBinding{Config: "service-case", Class: api.EndpointWorker, LaunchID: binding.Record.ID, Target: &c.target, WorkerLeaseID: lease.ID, EndpointGeneration: binding.Record.EndpointGeneration, ServiceUID: facts.HostUID + 1000}
	p := api.WorkerPrincipal{StageID: "mapped-credential-stage", Lease: lease, Record: binding.Record, Endpoint: endpoint, Peer: facts, BootID: boot, AllocationGeneration: 1, CancellationEpoch: 1,
		Claim: api.EffectLease{ClaimID: effect.ClaimID, ExpiresAt: effect.ClaimExpiresAt, Record: effect}}
	if err := c.store.save("usage-principal.json", p); err != nil {
		t.Fatal("cannot retain mapped credential principal")
	}
	connection := &connectionFixture{id: "mapped-credential-connection", binding: endpoint, peer: &usagePeerFixture{facts: facts}}
	scope := api.Scope{Config: "service-case", Actor: binding.Record.Actor, LaunchID: binding.Record.ID, EndpointGeneration: endpoint.EndpointGeneration, Connection: connection, Frame: &frameFixture{connection: connection.ID(), data: []byte("private credential frame")}}
	return c, scope, injection, value
}

func TestMappedCredentialWorker(t *testing.T) {
	c, scope, expected, value := mappedCredentialCase(t)
	actual, err := c.service.InjectMappedWorker(context.Background(), scope)
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("native mapped worker lost its exact retained injection")
	}
	material, err := c.service.MappedWorkerMaterial(context.Background(), scope, expected.SlotIDs[0])
	if err != nil || !bytes.Equal(material.Bytes, value) {
		t.Fatal("native mapped worker did not receive its exact selected material")
	}
	clear(material.Bytes)
}

func TestMappedCredentialGuards(t *testing.T) {
	for _, fault := range []string{"lease", "peer", "claim", "permission", "role", "actor", "frame", "selection", "revoked", "dependency"} {
		t.Run(fault, func(t *testing.T) {
			c, scope, injection, _ := mappedCredentialCase(t)
			var p api.WorkerPrincipal
			if c.store.read("usage-principal.json", &p) != nil {
				t.Fatal("cannot read mapped credential refusal control")
			}
			code, slot := api.CodeInvalid, injection.SlotIDs[0]
			switch fault {
			case "lease":
				p.Lease.ConsumedBy = "foreign-launch"
			case "peer":
				p.Peer.ProcessGeneration = "retired-connector"
			case "claim":
				p.Claim.Record.State = api.EffectCompleted
			case "permission":
				p.Lease.Kind = "test"
			case "role":
				p.Record.Actor.Role = "executor"
			case "actor":
				scope.Actor.Kind = "lane"
				code = api.CodeUnauthenticated
			case "frame":
				scope.Frame.(*frameFixture).err = &api.Error{Code: api.CodeUnauthenticated, Owner: "lb-v2-service", Message: "fixture frame writer changed"}
				code = api.CodeUnauthenticated
			case "selection":
				slot = "foreign-slot"
				code = api.CodeForbidden
			case "revoked":
				c.store.workerGrants.Revoked = true
				code = api.CodeForbidden
			case "dependency":
				c.store.fail["worker-binding"] = api.NotImplemented("lb-v2-service", "store.WorkerBinding")
				code = api.CodeNotImplemented
			}
			if c.store.save("usage-principal.json", p) != nil {
				t.Fatal("cannot retain mapped credential refusal control")
			}
			material, err := c.service.MappedWorkerMaterial(context.Background(), scope, slot)
			stageCode(t, err, code)
			if len(material.Bytes) != 0 {
				t.Fatal("refused mapped worker received material")
			}
		})
	}
}

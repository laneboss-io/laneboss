package secrets

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReservedAuthorityPins(t *testing.T) {
	for _, fault := range []string{"level", "role", "driver", "ticket"} {
		t.Run(fault, func(t *testing.T) {
			c := newLaunchCase(t, "helper")
			record := c.plan(t)
			switch fault {
			case "level":
				record.Reservation.Level = 4
			case "role":
				record.Reservation.Role = "reviewer"
			case "driver":
				record.Reservation.Driver = api.DriverClaudock
			case "ticket":
				record.Reservation.Authority.ID = "foreign-consumed-ticket"
			}
			c.setPlan(t, record)
			_, err := c.acquire(context.Background(), c.target, c.grant)
			stageCode(t, err, api.CodeForbidden)
		})
	}
}

func TestCaptureCurrentPolicy(t *testing.T) {
	for _, fault := range []string{"disabled", "approval"} {
		t.Run(fault, func(t *testing.T) {
			c := newLaunchCase(t, "helper")
			slot, err := c.acquire(context.Background(), c.target, c.grant)
			if err != nil {
				t.Fatal("cannot acquire current capture-policy control")
			}
			injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
			if err != nil {
				t.Fatal("cannot prepare current capture-policy control")
			}
			c.beforeBind = func(t *testing.T, spec api.LaunchSpec) {
				if fault == "disabled" {
					c.store.policy.AllowCaptureRefusal = false
				} else {
					c.store.policy.CaptureRefusalApprovalID = "another-approval"
				}
				_, err := c.service.PreparedSlotMaterial(context.Background(), spec, slot.ID)
				stageCode(t, err, api.CodeInvalid)
			}
			c.bind(t, slot, injection)
		})
	}
}

func TestRetainedConsumedProof(t *testing.T) {
	for _, fault := range []string{"valid", "missing", "foreign"} {
		t.Run(fault, func(t *testing.T) {
			c, _ := newContinuationCase(t)
			record := c.plan(t)
			r := &record.Reservation
			r.Mode, r.Authority = "resume", api.LaunchAuthority{Kind: "proof", ID: "consumed-resume-proof"}
			params, err := json.Marshal(api.ResumeRequest{Target: c.store.laneRef(), ExpectedGeneration: r.BaseGeneration, Message: c.store.putObject(t, "resume-message", "message", map[string]string{"text": "synthetic resume"}, r.OperationID)})
			if err != nil {
				t.Fatal("cannot encode the exact retained resume input")
			}
			request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: r.Config, RequestID: r.RequestID, IdempotencyKey: "resume-key", Method: "lane.resume", Params: params}
			request.RequestSHA256, err = api.RequestDigest(request)
			if err != nil {
				t.Fatal("cannot hash the actual retained resume input")
			}
			request.Proof = &api.ProofRef{ID: r.Authority.ID, RequestSHA256: request.RequestSHA256, ExpiresAt: api.Timestamp(c.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
			if fault == "missing" {
				request.Proof = nil
			}
			if fault == "foreign" {
				request.Proof.ID = "another-consumed-proof"
			}
			r.RequestSHA256 = request.RequestSHA256
			r.OriginalRequest = c.store.putObject(t, "resume-original", "launch_request", request, r.OperationID)
			if err := api.ValidateLaunchPlanRecord(record); err != nil {
				t.Fatal("retained resume fixture failed the shared validator")
			}
			c.setPlan(t, record)
			selector, err := c.selection(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			launch, err := c.service.credentialLaunch(context.Background(), c.target, c.store.grants, selector)
			if fault == "valid" {
				if err != nil || launch.profile != c.grant.ID {
					t.Fatal("retained resume lost its exact consumed proof and source profile")
				}
			} else {
				stageCode(t, err, api.CodeForbidden)
			}
		})
	}
}

func (s *launchCaseStore) laneRef() api.LifeRef {
	return api.LifeRef{LifeID: s.lane.LifeID, Run: s.lane.Run}
}

func TestPreparedWorkerBindingKind(t *testing.T) {
	c, lease, selection, _ := newWorkerCase(t)
	injection, err := c.service.InjectWorker(context.Background(), lease, selection)
	if err != nil {
		t.Fatal("cannot prepare worker binding-kind control")
	}
	spec := c.retainWorkerSpec(t, lease, injection)
	material, err := c.service.PreparedSlotMaterial(context.Background(), spec, injection.SlotIDs[0])
	clear(material.Bytes)
	if err != nil {
		t.Fatal("cannot retain worker binding-kind control")
	}
	c.bindWorker(t, spec)
	var binding api.LaunchBindingRequest
	if c.store.read("binding.json", &binding) != nil {
		t.Fatal("cannot read the actual worker binding-kind control")
	}
	binding.Record.Kind = "agent"
	binding.Identity.RecordSHA256, err = valueDigest(binding.Record)
	if err != nil || c.store.save("binding.json", binding) != nil {
		t.Fatal("cannot retain the self-consistent wrong-kind binding")
	}
	material, err = c.service.SlotMaterial(context.Background(), spec.LaunchID, injection.SlotIDs[0])
	clear(material.Bytes)
	stageCode(t, err, api.CodeForbidden)
}

//go:build linux

package secrets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// The broker and encrypted journal are real. Native helper receipt fields are
// component observations; the administrator root canary measures their kernel
// counterparts. No existing helper double or success response is changed.
func TestAPIKeyProjection(t *testing.T) {
	for _, reason := range []string{"cancelled", "release", "revoked"} {
		t.Run(reason, func(t *testing.T) { apiKeyProjection(t, reason, "") })
	}
}

func TestAPIKeyProjectionValidators(t *testing.T) {
	for _, control := range []string{"missing", "rejecting"} {
		t.Run(control, func(t *testing.T) { apiKeyProjection(t, "", control) })
	}
}

func apiKeyProjection(t *testing.T, reason, control string) {
	ctx := context.Background()
	c := newLaunchCase(t, "claude-api-key", api.DriverClaudock)
	c.service.deps.APIKeyValidator = claudock.APIKeyValidator{}
	var storage api.LaunchStorage
	if err := c.store.read("storage.json", &storage); err != nil {
		t.Fatal(err)
	}
	storage.Home.Home.VendorDirectory = ".claude"
	if err := c.store.save("storage.json", storage); err != nil {
		t.Fatal(err)
	}
	slot, err := c.acquire(ctx, c.target, c.grant)
	if err != nil {
		t.Fatal("API key slot acquisition failed", err)
	}
	injection, err := c.inject(ctx, c.target, []api.SecretGrant{})
	if err != nil {
		t.Fatal(err)
	}
	c.bind(t, slot, injection)
	var binding api.LaunchBindingRequest
	if err := c.store.read("binding.json", &binding); err != nil {
		t.Fatal(err)
	}
	cause := binding.Recovery.Handoff.Cause
	cause.ID, cause.Kind, cause.EffectID = "key-prepare", api.InternalHelperPrepare, "key-prepare-effect"
	r := api.CredentialProjectionRequest{Cause: cause, Handoff: binding.Recovery.Handoff, Prepared: binding.Prepared,
		Lease: c.plan(t).Plan.Lease, Home: storage.Home}
	expires := api.Timestamp(c.clock.Now().Add(time.Minute).Format(time.RFC3339Nano))
	r.Claim = api.EffectLease{ClaimID: "key-claim", ExpiresAt: expires, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 1,
		ClaimID: "key-claim", ClaimantID: "key-owner", ClaimExpiresAt: expires, Effect: api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause,
			HelperPrepare: &api.HelperLaunchRequest{Cause: cause, LeaseID: r.Lease.ID, PreparedSpecID: r.Handoff.Spec.ID, SpecSHA256: r.Handoff.SpecSHA256}}}}
	targets, err := api.CredentialTargets(r, c.clock.Now())
	if err != nil || len(targets) != 1 || targets[0].EnvironmentName != "ANTHROPIC_API_KEY" || targets[0].Delivery != "file" || targets[0].RelativePath != claudock.KeyStorePath {
		t.Fatal("API key broker selected a file or foreign name", err)
	}
	facts, boot := selfUsageFacts(t)
	helper := facts
	helper.HostUID, helper.HostGID, helper.ContainmentID = 0, 0, "key-helper"
	a := api.CredentialProjectionAuthority{ID: "key-projection", Generation: 1, Request: r, Targets: targets,
		Sources: []api.CredentialSourceVersion{{Key: slot.ID, Generation: 1, Version: c.profile.Source.Version}},
		Helper:  c.profile.Runtime, Broker: c.profile.Runtime, HelperPeer: helper, BrokerPeer: facts,
		ServiceUID: facts.HostUID + 1000, InstallationGeneration: 1, BootID: boot}
	m := &projectionModel{c: c, a: a, effects: map[api.ID]api.EffectRecord{cause.EffectID: r.Claim.Record}}
	c.service.deps.Store, c.service.deps.ProjectionIdentity = &projectionStore{c.store, m}, m
	c.service.deps.Helper = &projectionHelper{c.helper, m}
	t.Cleanup(func() {
		for _, flight := range c.service.projections {
			if !flight.closed {
				if err := closeProjectionFiles(flight.transfer.Files); err != nil {
					t.Error(err)
				}
			}
		}
	})
	// Every control owns a fresh request, projection model and broker. A
	// refusal fences that projection permanently; a later call cannot replace
	// its validator and use the same authority to export another descriptor.
	if control != "" {
		var want api.ErrorCode
		switch control {
		case "missing":
			c.service.deps.APIKeyValidator, want = nil, api.CodePrerequisite
		case "rejecting":
			c.service.deps.APIKeyValidator, want = rejectingAPIKeyValidator{}, api.CodeForbidden
		default:
			t.Fatal("unknown API key validator control")
		}
		transfer, err := c.service.TransferCredentials(ctx, &usagePeerFixture{facts: helper}, r)
		held := len(c.service.flight(a.ID).transfer.Files)
		t.Logf("%s API key validator: code=%s err=%v exported=%d held=%d", control, apiKeyErrorCode(err), err, len(transfer.Files), held)
		if !hasCode(err, want) || len(transfer.Files) != 0 || held != 0 {
			t.Fatalf("API key validator control refused incorrectly: want=%s code=%s err=%v exported=%d held=%d", want, apiKeyErrorCode(err), err, len(transfer.Files), held)
		}
		again, err := c.service.TransferCredentials(ctx, &usagePeerFixture{facts: helper}, r)
		t.Logf("fenced API key validator retry: code=%s err=%v exported=%d", apiKeyErrorCode(err), err, len(again.Files))
		if !hasCode(err, api.CodeConflict) || len(again.Files) != 0 || len(c.service.flight(a.ID).transfer.Files) != 0 {
			t.Fatalf("API key validator refusal lost its permanent fence: code=%s err=%v exported=%d", apiKeyErrorCode(err), err, len(again.Files))
		}
		return
	}
	transfer, err := c.service.TransferCredentials(ctx, &usagePeerFixture{facts: helper}, r)
	if err != nil || len(transfer.Files) != 1 {
		t.Fatal("API key broker export failed", err)
	}
	actual, err := io.ReadAll(transfer.Files[0])
	if err != nil || !bytes.Equal(actual, c.material) {
		t.Fatal("API key export changed its encrypted slot bytes")
	}
	clear(actual)
	fact, err := credentialFact(transfer.Files[0])
	if err != nil || fact.Links != 0 || !fact.ReadOnly || !fact.CloseOnExec || fact.WritableHandles == nil || *fact.WritableHandles != 0 {
		t.Fatal("API key export lost immutable anonymous ownership", err)
	}
	zero, one := uint64(0), uint64(1)
	m.held = api.CredentialProjectionReceipt{ProjectionID: a.ID, Generation: 2, Prepared: r.Prepared, HelperLeaseID: r.Lease.ID,
		SpecSHA256: r.Handoff.SpecSHA256, Home: r.Home, CancellationEpoch: cause.CancellationEpoch, GateClosed: true,
		HeldDescriptors: &one, InheritedSources: &zero, ObservedAt: api.Timestamp(c.clock.Now().Format(time.RFC3339Nano)),
		Targets: []api.CredentialHeldTarget{{Target: targets[0], SourceObjectID: fact.ObjectID, ObjectID: "root-held-key",
			RootID: r.Home.RootID, HomeGeneration: r.Home.Generation, OwnerUID: r.Lease.UID, Mode: 0600, ParentMode: 0700, Links: 1, ReadOnlyView: true}}}
	if err := c.store.save("projection-held.json", m.held); err != nil {
		t.Fatal(err)
	}
	record, err := c.service.AcknowledgeCredentials(ctx, m.held)
	if err != nil || record.State != "held" {
		t.Fatal("API key private store receipt refused", err)
	}
	stop := cause
	stop.ID, stop.Kind, stop.EffectID = "key-stop", api.InternalHelperRelease, "key-stop-effect"
	fenced, err := c.service.BeginCredentialWithdrawal(ctx, api.CredentialWithdrawalRequest{ProjectionID: a.ID, ExpectedGeneration: record.Generation, Cause: stop, Reason: reason})
	if err != nil {
		t.Fatal(err)
	}
	observation := c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: c.target,
		ContainmentID: r.Prepared.ContainmentID, Generation: r.Prepared.ProcessGeneration}})
	observation.ObservedAt = api.Timestamp(c.clock.Now().Format(time.RFC3339Nano))
	executed := true
	m.withdrawal = api.CredentialWithdrawalReceipt{ProjectionID: a.ID, Generation: fenced.Generation + 1, Cause: stop,
		Prepared: r.Prepared, HelperLeaseID: r.Lease.ID, Home: r.Home, Observation: observation, HelperDescriptors: &zero,
		ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero, AgentExecuted: &executed, RotationRequired: reason != "release", ObservedAt: observation.ObservedAt}
	done, err := c.service.FinishCredentialWithdrawal(ctx, fenced, m.withdrawal)
	if reason == "revoked" {
		if !hasCode(err, api.CodeContainmentUnknown) {
			t.Fatalf("API key revoke must remain quarantined: code=%s err=%v state=%s", apiKeyErrorCode(err), err, done.State)
		}
		retained, readErr := c.service.deps.Store.CredentialProjection(ctx, c.service.deps.Config, r.Prepared.ID)
		saved := readCaseSlot(t, c, slot.ID)
		defer clear(saved.Material)
		if readErr != nil || retained.State != "withdrawing" || retained.Withdrawal != nil || saved.Released || len(saved.Material) == 0 {
			t.Fatal("API key revoke published completion or discarded quarantined ownership", readErr)
		}
		return
	}
	if err != nil || done.State != "withdrawn" || done.Withdrawal == nil || done.Withdrawal.RotationRequired != (reason != "release") {
		t.Fatal("API key stop failed its release/rotation semantics", err)
	}
	saved := readCaseSlot(t, c, slot.ID)
	defer clear(saved.Material)
	if !saved.Released || len(saved.Material) != 0 || len(saved.Returned) != 0 {
		t.Fatal("API key stopped slot retained reusable material")
	}
	if _, err := c.acquire(ctx, c.target, c.grant); err == nil {
		t.Fatal("API key stopped slot was reusable")
	}
}

type rejectingAPIKeyValidator struct{}

func (rejectingAPIKeyValidator) ValidateAPIKeyCredential(_, _ string, _ []byte) error {
	return &api.Error{Code: api.CodeInvalid, Message: "negative control rejects selected material"}
}

func apiKeyErrorCode(err error) api.ErrorCode {
	var typed *api.Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return "untyped"
}

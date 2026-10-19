//go:build linux

package secrets

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

func TestRulingBAPIKeyReleaseRetires(t *testing.T) {
	m, _ := projectionCase(t, "claude-api-key")
	inputs := enableReuseFixture(t, m)
	// Production consumes this value-free result only from the authenticated
	// helper stream. This component runs the same scanner on its retained bytes.
	m.c.service.deps.Backend.(*reuseBackend).scanner = APIKeyReleaseScanFunc(rscan.ReadNativeReleaseScan)
	record, _ := reviewWithdrawal(t, m, "release", true)
	executed := true
	m.withdrawal.AgentExecuted, m.withdrawal.RotationRequired = &executed, true
	scan := ScanAPIKeyReleaseInputs(context.Background(), api.SecretMaterial{Bytes: m.c.material}, inputs)
	ctx := rscan.WithNativeReleaseScan(context.Background(), &rscan.NativeReleaseScan{Authority: m.a, Cause: record.Fence.Cause, Scan: scan})
	done, err := m.c.service.FinishCredentialWithdrawal(ctx, record, m.withdrawal)
	if err != nil || done.State != "withdrawn" || done.Withdrawal == nil || !done.Withdrawal.RotationRequired {
		t.Fatal("normal API-key lane copy remained blocked before rotation", err)
	}
	slot := readCaseSlot(t, m.c, m.a.Request.Handoff.Spec.Runner.Slot.ID)
	defer clear(slot.Material)
	defer clear(slot.Returned)
	if !slot.Released || len(slot.Material)+len(slot.Returned) != 0 {
		t.Fatal("normal API-key retirement retained lane material")
	}
	status, err := m.c.service.APIKeyReleaseStatus(context.Background(), m.a.ID, slot.ID)
	if err != nil || !status.RotationRequired || !status.Scan.Clean() {
		t.Fatal("normal API-key retirement lost its canonical reuse quarantine", err)
	}
	material, err := m.c.service.deps.Backend.Fetch(context.Background(), slot.Grant)
	defer clear(material.Bytes)
	if err == nil || len(material.Bytes) != 0 {
		t.Fatal("retired API-key copy allowed source reuse before rotation")
	}
	again, err := m.c.service.FinishCredentialWithdrawal(ctx, record, m.withdrawal)
	if err != nil || !reflect.DeepEqual(again, done) {
		t.Fatal("normal API-key retirement did not replay exactly", err)
	}
	t.Log("normal API-key lane copy retired; zero resources and exact replay verified; canonical rotation gate retained")
}

func TestRulingBCodexReleaseRetires(t *testing.T) {
	m, peer := projectionCase(t)
	s := m.c.service
	ctx := context.Background()
	transfer, err := s.TransferCredentials(ctx, peer, m.a.Request)
	if err != nil {
		t.Fatal("normal Codex release could not export its projection", err)
	}
	record, err := s.AcknowledgeCredentials(ctx, m.hold(t, transfer))
	if err != nil {
		t.Fatal("normal Codex release could not acknowledge its projection", err)
	}
	cause := m.a.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "ruling-b-release", api.InternalHelperRelease, "ruling-b-release-effect"
	fenced, err := s.BeginCredentialWithdrawal(ctx, api.CredentialWithdrawalRequest{
		ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Cause: cause, Reason: "release"})
	if err != nil {
		t.Fatal("normal Codex release could not fence its projection", err)
	}
	r := m.a.Request
	observed := m.c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "ruling-b-process", Target: m.c.target,
		ContainmentID: r.Prepared.ContainmentID, Generation: r.Prepared.ProcessGeneration}})
	observed.ObservedAt = api.Timestamp(m.c.clock.Now().Format(time.RFC3339Nano))
	zero, executed := uint64(0), true
	receipt := api.CredentialWithdrawalReceipt{ProjectionID: m.a.ID, Generation: fenced.Generation + 1, Cause: cause,
		Prepared: r.Prepared, HelperLeaseID: r.Lease.ID, Home: r.Home, Observation: observed,
		HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero,
		RotationRequired: true, AgentExecuted: &executed, ObservedAt: observed.ObservedAt}
	m.withdrawal = receipt
	done, err := s.FinishCredentialWithdrawal(ctx, fenced, receipt)
	if err != nil || done.State != "withdrawn" || done.Withdrawal == nil || !done.Withdrawal.RotationRequired {
		t.Fatalf("ruling-B normal Codex release remained blocked: state=%s err=%v", done.State, err)
	}
	slot := readCaseSlot(t, m.c, m.a.Targets[0].SlotID)
	if !slot.Released || len(slot.Material) != 0 || len(slot.Returned) != 0 {
		clear(slot.Material)
		clear(slot.Returned)
		t.Fatal("normal Codex release retained reusable lane credential material")
	}
	clear(slot.Material)
	clear(slot.Returned)
	var owner bstate.Login
	if err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("login", m.c.profile.LoginID, &owner) }); err != nil {
		t.Fatal("normal Codex release lost its canonical source marker", err)
	}
	clear(owner.Material)
	if !owner.Quarantined || owner.SlotID != "" {
		t.Fatal("normal Codex release did not retain the source rotation gate")
	}
	if _, err := m.c.acquire(ctx, m.c.target, m.c.grant); err == nil {
		t.Fatal("next Codex launch reused a source marked for rotation")
	}
}

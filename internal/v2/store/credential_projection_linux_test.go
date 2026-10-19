//go:build linux

package store_test

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only installed native metadata/holding observations are component fixtures.
// Every projection record, index, revision and restart is the actual store.
type credentialNativeFixture struct {
	owner   api.Actor
	request api.CredentialProjectionRequest
	meta    api.CredentialProjectionAuthority
	held    api.CredentialProjectionReceipt
}

func (n *credentialNativeFixture) ResolveCredentialProjection(ctx context.Context, scope api.Scope, request api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	if err := ctx.Err(); err != nil {
		return api.CredentialProjectionAuthority{}, err
	}
	if scope.Actor != n.owner || request.Prepared != n.request.Prepared || request.Lease != n.request.Lease || !reflect.DeepEqual(request.Handoff, n.request.Handoff) {
		return api.CredentialProjectionAuthority{}, &api.Error{Code: api.CodeForbidden, Owner: "component-native", Message: "metadata selector differs from native enrollment"}
	}
	return n.meta, nil
}

func (n *credentialNativeFixture) ObserveCredentialProjection(ctx context.Context, authority api.CredentialProjectionAuthority) (api.CredentialProjectionReceipt, error) {
	if err := ctx.Err(); err != nil {
		return api.CredentialProjectionReceipt{}, err
	}
	if authority.ID != n.held.ProjectionID || authority.Request.Prepared != n.held.Prepared {
		return api.CredentialProjectionReceipt{}, &api.Error{Code: api.CodeNotFound, Owner: "component-native", Message: "helper has no holding for projection"}
	}
	return n.held, nil
}

func credentialStoreFixture(t *testing.T) (*fx.Fixture, *credentialNativeFixture, api.CredentialProjectionRequest) {
	t.Helper()
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlanForIdentity(t, true, uint32(os.Geteuid())+1000, uint32(os.Getegid())+1000)
	f.Spec(t)
	f.PrepareJob(t)
	n, r := installCredentialFixture(t, f)
	return f, n, r
}

func installCredentialFixture(t *testing.T, f *fx.Fixture) (*credentialNativeFixture, api.CredentialProjectionRequest) {
	t.Helper()
	r := api.CredentialProjectionRequest{Cause: *f.PreparedClaim.Record.Effect.Context, Claim: f.PreparedClaim, Handoff: *f.Record.Handoff,
		Prepared: f.Prepared, Lease: f.Plan.Lease, Home: f.Plan.Data.Home}
	return installCredentialRequest(t, f, r), r
}

func installCredentialRequest(t *testing.T, f *fx.Fixture, r api.CredentialProjectionRequest) *credentialNativeFixture {
	t.Helper()
	if err := api.ValidateCredentialProjectionRequest(r, f.Deps.Clock.Now()); err != nil {
		t.Fatal("real retained prepare is invalid", err)
	}
	boot := string(fx.ID(t))
	n := &credentialNativeFixture{owner: f.Execution.Actor, request: r, meta: api.CredentialProjectionAuthority{
		Helper:     api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte("component-helper")), Version: "component"},
		Broker:     api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte("component-broker")), Version: "component"},
		HelperPeer: api.PeerFacts{HostPID: os.Getpid() + 1, ProcessGeneration: boot + ":helper"},
		BrokerPeer: api.PeerFacts{HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ProcessGeneration: boot + ":broker", ContainmentID: fx.ID(t)},
		ServiceUID: uint32(os.Geteuid()) + 2000, InstallationGeneration: 1, BootID: boot}}
	targets, err := api.CredentialTargets(r, f.Deps.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		version := target.Version
		if target.SlotID != "" {
			version = "component-version"
		}
		n.meta.Sources = append(n.meta.Sources, api.CredentialSourceVersion{Key: target.Key, Generation: 1, Version: version})
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.CredentialProjection = n
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func credentialHeld(t *testing.T, n *credentialNativeFixture, record api.CredentialProjectionRecord) api.CredentialProjectionReceipt {
	t.Helper()
	r := record.Authority.Request
	count, zero := uint64(len(record.Authority.Targets)), uint64(0)
	n.held = api.CredentialProjectionReceipt{ProjectionID: record.Authority.ID, Generation: record.Generation + 1, Prepared: r.Prepared,
		HelperLeaseID: r.Lease.ID, SpecSHA256: r.Handoff.SpecSHA256, Home: r.Home, CancellationEpoch: r.Cause.CancellationEpoch,
		HeldDescriptors: &count, InheritedSources: &zero, GateClosed: true, ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	for _, target := range record.Authority.Targets {
		held := api.CredentialHeldTarget{Target: target, SourceObjectID: string(fx.ID(t)), ObjectID: string(fx.ID(t)),
			RootID: r.Home.RootID, HomeGeneration: r.Home.Generation, OwnerUID: r.Lease.UID, Mode: target.FileMode, ParentMode: 0700, Links: 1}
		if target.Delivery == "env" {
			held.OwnerUID, held.Mode, held.Links = 0, 0600, 0
		}
		n.held.Targets = append(n.held.Targets, held)
	}
	return n.held
}

func TestCredentialProjectionDurable(t *testing.T) {
	f, n, request := credentialStoreFixture(t)
	ctx := context.Background()
	cleanupDDL(t, f, "CREATE TRIGGER component_credential_failure BEFORE INSERT ON projection_history WHEN NEW.kind='credential_projection' BEGIN SELECT RAISE(ABORT, 'component credential append denied'); END")
	if _, err := f.State.ReserveCredentialProjection(ctx, f.Execution, request); err == nil || !strings.Contains(err.Error(), "component credential append denied") {
		t.Fatal("credential append fault did not reach the real transaction", err)
	}
	cleanupDDL(t, f, "DROP TRIGGER component_credential_failure")
	if _, err := f.State.CredentialProjection(ctx, f.Deps.Config, request.Prepared.ID); err == nil {
		t.Fatal("failed credential transaction retained a partial reservation")
	} else {
		launchCode(t, err, api.CodeNotFound)
	}
	if verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("failed credential transaction retained an orphan index", err)
	}
	reserved, err := f.State.ReserveCredentialProjection(ctx, f.Execution, request)
	if err != nil || reserved.State != "reserved" || reserved.Generation != 1 || reserved.Authority.ID == "" {
		t.Fatal("real store did not reserve the original prepared credential projection", err)
	}
	retry, err := f.State.ReserveCredentialProjection(ctx, f.Execution, request)
	if err != nil || !reflect.DeepEqual(retry, reserved) {
		t.Fatal("reservation retry changed durable authority", err)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.State.CredentialProjection(ctx, f.Deps.Config, request.Prepared.ID)
	if err != nil || !reflect.DeepEqual(read, reserved) {
		t.Fatal("projection did not survive actual writer restart", err)
	}
	held := credentialHeld(t, n, reserved)
	foreign := request
	foreign.Claim.ClaimID = fx.ID(t)
	foreign.Claim.Record.ClaimID = foreign.Claim.ClaimID
	if err := api.ValidateCredentialProjectionRequest(foreign, f.Deps.Clock.Now()); err != nil {
		t.Fatal("foreign current-claim control lost its valid input shape", err)
	}
	if _, err := f.State.ReserveCredentialProjection(ctx, f.Execution, foreign); err == nil {
		t.Fatal("foreign prepare lease was accepted")
	}
	foreign = request
	foreign.Lease.ID = fx.ID(t)
	if _, err := f.State.ReserveCredentialProjection(ctx, f.Execution, foreign); err == nil {
		t.Fatal("foreign helper lease was accepted")
	}
	wrong := held
	otherStore, _, otherRequest := credentialStoreFixture(t)
	otherProjection, err := otherStore.State.ReserveCredentialProjection(ctx, otherStore.Execution, otherRequest)
	if err != nil {
		t.Fatal("another launch control did not reserve its own projection", err)
	}
	wrong.ProjectionID = otherProjection.Authority.ID
	if _, err := f.State.CommitCredentialProjection(ctx, f.Execution, wrong); err == nil {
		t.Fatal("another launch projection was accepted")
	}
	wrong = held
	wrong.Generation--
	if _, err := f.State.CommitCredentialProjection(ctx, f.Execution, wrong); err == nil {
		t.Fatal("stale projection revision was accepted")
	}
	wrong = held
	wrong.Targets = append([]api.CredentialHeldTarget{}, held.Targets...)
	wrong.Targets[0].ObjectID = string(fx.ID(t))
	if _, err := f.State.CommitCredentialProjection(ctx, f.Execution, wrong); err == nil {
		t.Fatal("unobserved held destination was accepted")
	}
	committed, err := f.State.CommitCredentialProjection(ctx, f.Execution, held)
	if err != nil || committed.State != "held" || committed.Generation != 2 || committed.Receipt == nil {
		t.Fatal("actual held receipt was not durably committed", err)
	}
	_, err = f.State.CommitCredentialProjection(ctx, f.Execution, held)
	launchCode(t, err, api.CodeConflict)
	if err := f.State.CheckCredentialProjection(ctx, f.Deps.Config, request.Prepared.ID, committed.Generation); err != nil {
		t.Fatal("live native holding was refused", err)
	}
	n.meta.Sources[0].Revoked = true
	if err := f.State.CheckCredentialProjection(ctx, f.Deps.Config, request.Prepared.ID, committed.Generation); err == nil {
		t.Fatal("revoked source still authorized opening")
	}
	cleanupCtx, cause := f.CredentialAbort(t, request.Prepared)
	fence := api.CredentialWithdrawalRequest{ProjectionID: committed.Authority.ID, ExpectedGeneration: committed.Generation, Cause: cause, Reason: api.CredentialStopReason}
	stale := fence
	stale.ExpectedGeneration--
	if _, err := f.State.FenceCredentialProjection(cleanupCtx, f.Execution, stale); err == nil {
		t.Fatal("stale withdrawal revision was accepted")
	}
	fenced, err := f.State.FenceCredentialProjection(cleanupCtx, f.Execution, fence)
	if err != nil || fenced.State != "withdrawing" || fenced.Generation != 3 {
		t.Fatal("stop did not durably fence projection", err)
	}
	if replay, err := f.State.FenceCredentialProjection(cleanupCtx, f.Execution, fence); err != nil || !reflect.DeepEqual(replay, fenced) {
		t.Fatal("withdrawal fence retry changed revision", err)
	}
	revoke := fence
	revoke.ExpectedGeneration, revoke.Reason = fenced.Generation, "revoked"
	fenced, err = f.State.FenceCredentialProjection(cleanupCtx, f.Execution, revoke)
	if err != nil || fenced.Generation != 4 || !fenced.Revoked || fenced.Fence == nil || fenced.Fence.Reason != "revoked" {
		t.Fatal("later revocation did not durably escalate its stop", err)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.New(f.Deps)
	if err != nil {
		t.Fatal("escalated revocation could not survive store reconstruction", err)
	}
	f.State = reopened
	if read, err := f.State.CredentialProjection(ctx, f.Deps.Config, request.Prepared.ID); err != nil || !reflect.DeepEqual(read, fenced) {
		t.Fatal("restarted store changed the escalated revocation", err)
	}
	weakened := revoke
	weakened.ExpectedGeneration, weakened.Reason = fenced.Generation, api.CredentialStopReason
	if _, err := f.State.FenceCredentialProjection(cleanupCtx, f.Execution, weakened); err == nil {
		t.Fatal("restarted store allowed a stop to weaken its revocation")
	}
	zero := uint64(0)
	stamp := api.Timestamp(f.Deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	withdrawal := api.CredentialWithdrawalReceipt{ProjectionID: committed.Authority.ID, Generation: fenced.Generation + 1, Cause: cause,
		Prepared: request.Prepared, HelperLeaseID: request.Lease.ID, Home: request.Home, ObservedAt: stamp,
		Observation: api.ProcessObservation{Handle: api.ProcessHandle{Target: request.Prepared.Target, ContainmentID: request.Prepared.ContainmentID, Generation: request.Prepared.ProcessGeneration},
			State: "absent", Survivors: &zero, ObservedAt: stamp}, HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero, BrokerDescriptors: &zero, RefreshLeases: &zero}
	unknown := withdrawal
	unknown.RefreshLeases = nil
	if _, err := f.State.CompleteCredentialWithdrawal(cleanupCtx, f.Execution, unknown); err == nil {
		t.Fatal("unknown broker resource count completed withdrawal")
	}
	exposed := withdrawal
	executed, exit := true, 0
	exposed.AgentExecuted, exposed.RotationRequired = &executed, true
	exposed.Observation.State, exposed.Observation.ExitCode = "exited", &exit
	if _, err := f.State.CompleteCredentialWithdrawal(cleanupCtx, f.Execution, exposed); err == nil {
		t.Fatal("revoked executed projection completed with zero resource counts")
	} else {
		launchCode(t, err, api.CodeContainmentUnknown)
	}
	if read, err := f.State.CredentialProjection(ctx, f.Deps.Config, request.Prepared.ID); err != nil || !reflect.DeepEqual(read, fenced) {
		t.Fatal("refused exposed completion changed the durable revocation", err)
	}
	done, err := f.State.CompleteCredentialWithdrawal(cleanupCtx, f.Execution, withdrawal)
	if err != nil || done.State != "withdrawn" || done.Generation != 5 || !done.Revoked {
		t.Fatal("zero-count withdrawal was not completed", err)
	}
	if replay, err := f.State.CompleteCredentialWithdrawal(cleanupCtx, f.Execution, withdrawal); err != nil || !reflect.DeepEqual(replay, done) {
		t.Fatal("withdrawal completion retry changed revision", err)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	if read, err := f.State.CredentialProjection(ctx, f.Deps.Config, request.Prepared.ID); err != nil || !reflect.DeepEqual(read, done) {
		t.Fatal("withdrawal did not survive actual restart", err)
	}
	// Returned DTOs never alias the retained record.
	readback, err := f.State.CredentialProjection(ctx, f.Deps.Config, request.Prepared.ID)
	if err != nil {
		t.Fatal(err)
	}
	readback.Withdrawal.Home.RootID = fx.ID(t)
	if retained, err := f.State.CredentialProjection(ctx, f.Deps.Config, request.Prepared.ID); err != nil || !reflect.DeepEqual(retained, done) {
		t.Fatal("caller mutation changed durable withdrawal metadata", err)
	}
	if verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("credential state did not verify", err)
	}
	// Even coherent replacement history cannot make an index select a foreign
	// gate. This is test-only database tampering, never a production write port.
	f.Corrupt(t, "credential_projection_id", reserved.Authority.ID, 1, fx.ID(t))
	if reopened, err := store.New(f.Deps); err == nil {
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("semantic credential index corruption passed restart verification")
	} else {
		launchCode(t, err, api.CodeIntegrity)
	}
}

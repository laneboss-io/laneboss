//go:build linux

package service

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only the enrollment, native process mapping and primitive seed are component
// fixtures. Capture ingress, ledger, stop outbox, lifecycle end and verification
// use the actual writer. The process port kills its own real sleep PID.
type spendProcessLauncher struct {
	api.Launcher
	command *exec.Cmd
	handle  api.ProcessHandle
	ended   bool
}

func (l *spendProcessLauncher) Observe(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessObservation{}, err
	}
	if handle != l.handle {
		return api.ProcessObservation{}, serviceError(api.CodeIntegrity, "spend stop selected another native process")
	}
	count := uint64(1)
	observed := api.ProcessObservation{Handle: handle, State: "running", Survivors: &count, PromptStatus: "written", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	if l.ended {
		count = 0
		signal := int(syscall.SIGKILL)
		observed.State, observed.Signal = "exited", &signal
	} else if err := l.command.Process.Signal(syscall.Signal(0)); err != nil {
		return api.ProcessObservation{}, err
	}
	return observed, nil
}

func (l *spendProcessLauncher) Stop(ctx context.Context, handle api.ProcessHandle, _ string) (api.ProcessObservation, error) {
	if handle != l.handle {
		return api.ProcessObservation{}, serviceError(api.CodeIntegrity, "spend stop selected another native process")
	}
	if !l.ended {
		if err := l.command.Process.Kill(); err != nil {
			return api.ProcessObservation{}, err
		}
		var ended *exec.ExitError
		if err := l.command.Wait(); !errors.As(err, &ended) {
			return api.ProcessObservation{}, serviceError(api.CodeContainmentUnknown, "spend stop failed to reap its real process")
		}
		l.ended = true
	}
	return l.Observe(ctx, handle)
}

func spendBoundFixture(t *testing.T) *fx.Fixture {
	t.Helper()
	f := fx.New(t)
	f.Start.Driver = api.DriverClaudock
	f.Ceiling.Profiles[0].Driver = api.DriverClaudock
	f.Ceiling.SHA256 = ""
	var err error
	f.Ceiling.SHA256, err = manifest.HashValue(f.Ceiling)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	input := f.SourceTransaction(t)
	input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Driver = api.DriverClaudock
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	f.Record = input.Writes.LaunchPlans[0]
	f.PlanSetup = func(p *api.LaunchPlan) {
		p.Runner.Driver, p.Runner.Session.Driver = api.DriverClaudock, api.DriverClaudock
		p.Runner.Session.VendorID = string(fx.ID(t))
		p.Runner.Slot.Mode = "claude-api-key"
		p.Runner.EnvironmentNames = []string{"ANTHROPIC_API_KEY"}
		p.Data.Home.Home.VendorDirectory = ".claude"
		p.Runner.Home = p.Data.Home.Home
	}
	f.BuildPlan(t, true)
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	pool := api.SpendBalance{CredentialID: "pool-one", SeedMicros: 10000000, ReadingMicros: 10000000, RemainingMicros: 10000000, AnchorMicros: 10000000, FloorMicros: 5000000, Generation: 1, ObservedAt: now}
	f.Replace(t, "spend_pool", pool.CredentialID, 1, pool)
	f.Replace(t, "spend_profile", f.Plan.Runner.Slot.ProfileID, 1, struct{ CredentialID api.ID }{pool.CredentialID})
	f.Spec(t)
	f.Bind(t)
	return f
}

func TestSpendCaptureStopsRun(t *testing.T) {
	f := spendBoundFixture(t)
	f.Opened(t)
	process := exec.Command("/usr/bin/sleep", "300")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	launcher := &spendProcessLauncher{command: process, handle: f.Process}
	t.Cleanup(func() {
		if !launcher.ended {
			if _, err := launcher.Stop(context.Background(), f.Process, "cleanup"); err != nil {
				t.Error(err)
			}
		}
	})
	host := launchServer(t, f)
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &authFixture{}, Clock: f.Deps.Clock, Launcher: launcher})
	if err != nil {
		t.Fatal(err)
	}
	host.runtime.Lifecycle, host.runtime.Launcher = coordinator, launcher
	raw := fx.JSON(t, map[string]any{"type": "result", "uuid": "spend-crossing", "session_id": f.Plan.Runner.Session.VendorID, "is_error": false,
		"total_cost_usd": 5.01, "cost_usd": 0, "usage": map[string]int{"input_tokens": 100, "output_tokens": 20}})
	raw = append(raw, '\n')
	ref := f.CaptureData(t, raw)
	request := f.AppendRequest(t, &ref, false)
	if _, err := f.State.AppendCapture(context.Background(), f.Worker, request); err != nil {
		t.Fatal("authenticated capture did not record vendor spend", err)
	}
	lane, err := f.State.Lane(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil || lane.State != "stopping" || lane.CancellationEpoch != f.Lane.CancellationEpoch+1 {
		t.Fatal("captured turn did not atomically stop its run", err)
	}
	balance, err := f.State.LaneSpend(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil || balance == nil || balance.SpentMicros != 5010000 || balance.RemainingMicros != 4990000 {
		t.Fatal("lane status did not report shared vendor spend", err)
	}
	effects, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil || len(effects) != 1 || effects[0].Stop == nil || *effects[0].Stop != f.Process {
		t.Fatal("spend crossing has no single native stop", err)
	}
	claim, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: effects[0].ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := host.runEffect(context.Background(), f.Execution, claim)
	if err != nil || !launcher.ended || outcome.Observation == nil || outcome.Observation.Survivors == nil || *outcome.Observation.Survivors != 0 {
		t.Fatal("spend stop outbox did not kill and reap its own PID", err)
	}
	if _, err := f.State.CompleteEffect(context.Background(), f.Execution, outcome); err != nil {
		t.Fatal(err)
	}
	lane, err = f.State.Lane(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil || lane.State != "verifying" || lane.Containment != "quiescent" {
		t.Fatal("stopped run did not retain its measured end", err)
	}
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Reservation.Target.LifeID, Run: f.Reservation.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	journaled := false
	for _, event := range page.Events {
		journaled = journaled || event.Kind == "spend.stopped"
	}
	if !journaled {
		t.Fatal("spend stop has no fixed journal event")
	}
	pending, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil || len(pending) != 1 || pending[0].HelperRelease == nil {
		t.Fatal("spend stop lost its ordinary release", err)
	}
	release := pending[0]
	helper := &measuredRunHelper{drainHelperFixture: runDrainHelper(t, f, *release.HelperRelease), receipt: runReceipt(t, release)}
	final := fx.JSON(t, map[string]any{"type": "result", "uuid": "drained-result", "session_id": f.Plan.Runner.Session.VendorID, "is_error": false,
		"total_cost_usd": 0.01, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1}})
	helper.data[0] = append(append(append([]byte{}, raw...), final...), '\n')
	helper.data[1] = []byte("vendor diagnostic\n")
	for i := range helper.snapshot.Streams {
		helper.snapshot.Streams[i].Bytes = int64(len(helper.data[i]))
		helper.snapshot.Streams[i].SHA256 = fx.Digest(helper.data[i])
	}
	host.runtime.Helper = helper
	if result := host.reconcileEffect(context.Background(), release, make(effectRetries)); result != attemptNext {
		t.Fatal("spend release did not drain its final vendor result")
	}
	retained, err := f.State.Effect(context.Background(), f.Execution, release.ID)
	if err != nil || retained.State != api.EffectCompleted || retained.Outcome == nil || retained.Outcome.Release == nil || helper.ack == nil {
		t.Fatal("spend release lacks its completed drain acknowledgement", err)
	}
	balance, err = f.State.LaneSpend(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil || balance.SpentMicros != 5020000 || balance.RemainingMicros != 4980000 || !balance.NeedsReading || balance.AccountingError != nil {
		t.Fatal("release lost cost bytes or admitted stale balance", err)
	}
	verification, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("spend capture/stop journal failed store verification", err)
	}
}

func TestSpendEarlyCapture(t *testing.T) {
	f := spendBoundFixture(t)
	raw := fx.JSON(t, map[string]any{"type": "result", "uuid": "early-result", "session_id": f.Plan.Runner.Session.VendorID, "is_error": false,
		"total_cost_usd": 6, "usage": map[string]int{"input_tokens": 10, "output_tokens": 1}})
	raw = append(raw, '\n')
	ref := f.CaptureData(t, raw)
	if _, err := f.State.AppendCapture(context.Background(), f.Worker, f.AppendRequest(t, &ref, false)); err != nil {
		t.Fatal("early vendor result was lost before native observation", err)
	}
	balance, err := f.State.LaneSpend(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil || balance.SpentMicros != 6000000 || balance.RemainingMicros != 4000000 {
		t.Fatal("early vendor spend was not persisted", err)
	}
	if err := f.State.RecordLaunchObservation(context.Background(), f.Reservation.LaunchID, f.Observation(t, "running")); err != nil {
		t.Fatal("native observation could not finish its pending spend stop", err)
	}
	lane, err := f.State.Lane(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil || lane.State != "stopping" {
		t.Fatal("observed early result escaped its stop", err)
	}
	effects, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	stops := 0
	for _, effect := range effects {
		if effect.Stop != nil {
			stops++
			if *effect.Stop != f.Process {
				t.Fatal("deferred spend stop selected another process")
			}
		}
	}
	if stops != 1 {
		t.Fatal("deferred spend stop has no single durable effect")
	}
}

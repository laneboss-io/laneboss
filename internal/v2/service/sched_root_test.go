//go:build linux && laneboss_root_canary && laneboss_gate_integration

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestSchedulerFreshInstall(t *testing.T) {
	if os.Geteuid() == 0 {
		schedRoot(t)
		return
	}
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "loop-native" {
		t.Fatal("fresh scheduler requires its isolated root canary")
	}
	path := os.Args[len(os.Args)-1]
	binding, err := wire.ReadBinding(path, "loop-native", release.Version)
	if err != nil {
		t.Fatal(err)
	}
	clock := fixtureClock{}
	state, err := store.New(store.Dependencies{Config: binding.Config, Directory: privateHostDirectory(t), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	auth := &authFixture{}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: state, Identity: auth, Clock: clock, Launcher: &loopObserver{}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{Config: binding.Config, BindingFile: path}, Dependencies{Store: state, Authenticator: auth, Clock: clock, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.BindRuntime(ctx, api.RuntimeServices{Config: binding.Config, Store: state, Identity: auth, Lifecycle: coordinator, Socket: binding.Socket, ArtifactSHA256: binding.ArtifactSHA256}); err != nil {
		t.Fatal(err)
	}
	read := api.Scope{Config: binding.Config, Actor: api.Actor{Kind: "service", ID: s.controller}}
	_, err = state.Policy(ctx, read)
	codeIs(t, err, api.CodeNotFound)
	if err := s.installScheduler(ctx); err != nil {
		t.Fatal("fresh scheduler installation failed without a policy", err)
	}
	if s.scheduler == nil || s.scheduler.stamp.PolicyGeneration != 0 || s.scheduler.stamp.CapabilityGeneration != 0 || s.scheduler.stamp.ExpiresAt != "" || s.scheduler.policy != "" {
		t.Fatal("fresh scheduler did not remain installed and idle")
	}
	_, err = api.BindSchedulerScope(ctx, s.scheduler, clock.Now())
	codeIs(t, err, api.CodeInvalid)
	policy := api.EffectivePolicy{Generation: 1, SHA256: fx.Digest([]byte("first published policy")), Context: api.RoleContext{Level: 6, Role: "supervisor"},
		Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{}, ProfileExclusions: []api.ID{}}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalOrgBootstrap, Config: binding.Config, Actor: read.Actor, RequestedBy: read.Actor}
	if _, err := state.Transact(ctx, api.Transaction{Scope: read, Internal: &cause, Writes: api.StateWrites{Policy: &policy}}); err != nil {
		t.Fatal("initial policy publication failed", err)
	}
	if err := s.refreshScheduler(ctx); err != nil {
		t.Fatal("idle scheduler did not observe the published policy", err)
	}
	scope, err := api.BindSchedulerScope(ctx, s.scheduler, clock.Now())
	if err != nil {
		t.Fatal("published policy did not activate scheduler authority", err)
	}
	stamp, err := api.SchedulerStamp(ctx, scope, clock.Now())
	if err != nil || stamp.PolicyGeneration != policy.Generation || stamp.CapabilityGeneration != 1 || s.scheduler.policy != policy.SHA256 {
		t.Fatal("scheduler did not pin the published policy", err)
	}
}

func TestSchedulerLoopIdleWaits(t *testing.T) {
	if os.Geteuid() == 0 {
		schedRoot(t)
		return
	}
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "loop-native" {
		t.Fatal("idle scheduler requires its isolated root canary")
	}
	path := os.Args[len(os.Args)-1]
	binding, err := wire.ReadBinding(path, "loop-native", release.Version)
	if err != nil {
		t.Fatal(err)
	}
	clock := fixtureClock{}
	deps := store.Dependencies{Config: binding.Config, Directory: privateHostDirectory(t), Clock: clock}
	state, err := store.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the same real-store port when the existing fixture reopens its
	// writer to install primitive enrollment data. No store method is faked.
	port := &struct{ *store.Service }{state}
	t.Cleanup(func() {
		if err := port.Close(); err != nil {
			t.Error(err)
		}
	})
	auth := &authFixture{}
	observer := &loopObserver{}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: port, Identity: auth, Clock: clock, Launcher: observer})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{Config: binding.Config, BindingFile: path}, Dependencies{Store: port, Authenticator: auth, Clock: clock, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.BindRuntime(ctx, api.RuntimeServices{Config: binding.Config, Store: port, Identity: auth, Lifecycle: coordinator, Socket: binding.Socket, ArtifactSHA256: binding.ArtifactSHA256}); err != nil {
		t.Fatal(err)
	}
	if err := s.installScheduler(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.schedulerTick(ctx); err != nil {
		t.Fatal("idle scheduler tick failed before policy publication", err)
	}
	if plans, err := port.LaunchInventory(ctx); err != nil || len(plans) != 0 {
		t.Fatal("idle scheduler dispatched without a policy", err)
	}
	// A missing installation is still fatal even while the producer is idle.
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	refused := s.schedulerTick(ctx)
	if err := os.Rename(path+".old", path); err != nil {
		t.Fatal(err)
	}
	codeIs(t, refused, api.CodePrerequisite)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.schedulerLoop(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("scheduler loop did not stop with its service context")
		}
	})
	select {
	case <-done:
		t.Fatal("scheduler loop exited while idle")
	case <-time.After(1200 * time.Millisecond):
	}
	if plans, err := port.LaunchInventory(ctx); err != nil || len(plans) != 0 {
		t.Fatal("waiting scheduler dispatched without a policy", err)
	}
	// Block the next admission and drain any idle tick before the existing
	// fixture reopens the writer. The running loop itself is never restarted.
	for {
		s.mu.Lock()
		if s.activeDispatches == 0 {
			break
		}
		changed := s.activityChanged
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("idle tick did not release admission", ctx.Err())
		}
	}
	var f *fx.Fixture
	var pick api.LoopTurnSelector
	func() {
		defer s.mu.Unlock()
		f = fx.NewIn(t, port.Service, deps)
		port.Service = f.State
		f.Reserve(t)
		f.Source(t)
		f.BuildPlan(t, true)
		f.Spec(t)
		f.Bind(t)
		f.Child(t)
		f.Opened(t)
		f.Ended(t)
		pick = loopScene(t, f)
		page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: pick.Target.LifeID, Run: pick.Target.Run})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Events {
			if event.ID == pick.EndEventID {
				var end api.RunEndEvent
				if err := api.DecodeObject(event.Payload, &end); err != nil {
					t.Fatal(err)
				}
				observer.end = end.Observation
			}
		}
	}()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var dispatched api.LaunchReservation
waitDispatch:
	for {
		select {
		case <-done:
			t.Fatal("idle loop exited before dispatch after policy publication")
		case <-ctx.Done():
			t.Fatal("published policy did not wake the idle loop", ctx.Err())
		case <-ticker.C:
			plans, err := port.LaunchInventory(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, plan := range plans {
				if plan.Reservation.Loop != nil {
					dispatched = plan.Reservation
					break waitDispatch
				}
			}
		}
	}
	policy, err := port.Policy(ctx, f.Execution)
	if err != nil || dispatched.Loop.Selector != pick || dispatched.RequestedBy.Kind != "scheduler" || dispatched.PolicyGeneration != policy.Generation {
		t.Fatal("woken loop dispatched a different cause or policy", err)
	}
	if result, err := port.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !result.OK {
		t.Fatal("woken loop reservation failed integrity verification", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("woken scheduler did not stop with its service context")
	}
	s.mu.RLock()
	fault := s.fault
	s.mu.RUnlock()
	if fault != nil {
		t.Fatal("idle scheduler loop recorded a fatal condition", fault)
	}
}

// This measures the installed producer's real UID, protected root-owned
// binding, executable and process lifetime. It performs no vendor turn.
func TestSchedNative(t *testing.T) {
	if os.Geteuid() == 0 {
		schedRoot(t)
		return
	}
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "loop-native" {
		t.Fatal("native scheduler requires its isolated root canary")
	}
	path := os.Args[len(os.Args)-1]
	binding, err := wire.ReadBinding(path, "loop-native", release.Version)
	if err != nil {
		t.Fatal(err)
	}
	f := fx.New(t, binding.Config)
	clock := &planReconcileClock{}
	auth := &authFixture{}
	observer := &loopObserver{}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: auth, Clock: clock, Launcher: observer})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{Config: binding.Config, BindingFile: path}, Dependencies{Store: f.State, Authenticator: auth, Clock: clock, Binding: binding})
	if err != nil {
		t.Fatal("actual service identity did not verify", err)
	}
	ctx := context.Background()
	if err := s.BindRuntime(ctx, api.RuntimeServices{Config: binding.Config, Store: f.State, Identity: auth, Lifecycle: coordinator, Socket: binding.Socket, ArtifactSHA256: binding.ArtifactSHA256}); err != nil {
		t.Fatal(err)
	}
	if err := s.installScheduler(ctx); err != nil {
		t.Fatal("native scheduler unavailable", err)
	}
	scope, err := api.BindSchedulerScope(ctx, s.scheduler, clock.Now())
	if err != nil || scope.Actor.Kind != "scheduler" || scope.Actor.LifeID != "" || scope.Actor.Level != 0 || scope.Actor.Role != "" {
		t.Fatal("native producer lost its distinct actor", err)
	}
	first, err := api.SchedulerStamp(ctx, scope, clock.Now())
	if err != nil || first.InstallationGeneration != binding.InstallationGeneration || first.BootID == "" {
		t.Fatal("producer lost installed native pins", err)
	}
	if err := s.refreshScheduler(ctx); err != nil {
		t.Fatal(err)
	}
	again, err := api.SchedulerStamp(ctx, scope, clock.Now())
	if err != nil || again != first {
		t.Fatal("expiry changed inside one capability generation", err)
	}
	reservation := schedReservation(t, s, f, observer, first)
	raw, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	var copied api.Scope
	if err := json.Unmarshal(raw, &copied); err != nil {
		t.Fatal(err)
	}
	if err := api.CheckSchedulerScope(ctx, copied, clock.Now()); err == nil {
		t.Fatal("serialized metadata manufactured private scheduler authority")
	}
	s.mu.Lock()
	s.dispatchPaused = true
	s.mu.Unlock()
	if err := api.CheckSchedulerScope(ctx, scope, clock.Now()); err == nil {
		t.Fatal("freeze left scheduler authority usable")
	}
	s.mu.Lock()
	s.dispatchPaused = false
	s.mu.Unlock()
	clock.advance(2 * time.Minute)
	if err := api.CheckSchedulerScope(ctx, scope, clock.Now()); err == nil {
		t.Fatal("expired capability remained usable")
	}
	if err := s.refreshScheduler(ctx); err != nil {
		t.Fatal(err)
	}
	renewed, err := api.BindSchedulerScope(ctx, s.scheduler, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := api.SchedulerStamp(ctx, renewed, clock.Now())
	if err != nil || stamp.Actor != first.Actor || stamp.CapabilityGeneration <= first.CapabilityGeneration || stamp.ExpiresAt == first.ExpiresAt {
		t.Fatal("renewal did not advance the fixed capability generation", err)
	}
	if err := api.CheckSchedulerScope(ctx, scope, clock.Now()); err == nil {
		t.Fatal("old scope survived capability renewal")
	}
	replayed, err := f.State.ReserveLaunch(ctx, renewed, api.LaunchReservationRequest{Loop: &reservation.Loop.Selector})
	if err != nil || !reflect.DeepEqual(reservation, replayed) {
		t.Fatal("renewed native authority lost the exact reserved cause", err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, fx.JSON(t, binding), 0444); err != nil {
		t.Fatal(err)
	}
	if err := api.CheckSchedulerScope(ctx, renewed, clock.Now()); err == nil {
		t.Fatal("replaced root binding preserved scheduler authority")
	}
	if err := os.Rename(path+".old", path); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if err := api.CheckSchedulerScope(ctx, renewed, clock.Now()); err == nil {
		t.Fatal("closed host preserved scheduler authority")
	}
}

func schedReservation(t *testing.T, s *Server, f *fx.Fixture, observer *loopObserver, stamp api.InstalledScheduler) api.LaunchReservation {
	t.Helper()
	// The ended workload is a component input. This canary measures the
	// actual installed producer through schedulerTick and the real writer.
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Child(t)
	f.Opened(t)
	f.Ended(t)
	pick := loopScene(t, f)
	ctx := context.Background()
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: pick.Target.LifeID, Run: pick.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range page.Events {
		if event.ID == pick.EndEventID {
			var end api.RunEndEvent
			if err := api.DecodeObject(event.Payload, &end); err != nil {
				t.Fatal(err)
			}
			observer.end = end.Observation
		}
	}
	for i := 0; i < 2; i++ {
		if err := s.schedulerTick(ctx); err != nil {
			t.Fatal("installed scheduler could not reserve its actual due loop", err)
		}
	}
	plans, err := f.State.LaunchInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	var reserved api.LaunchReservation
	for _, plan := range plans {
		if plan.Reservation.Loop == nil {
			continue
		}
		count++
		reserved = plan.Reservation
		loop := plan.Reservation.Loop
		if loop.Selector != pick || loop.Scheduler != stamp || plan.Reservation.RequestedBy != stamp.Actor {
			t.Fatal("native scheduler reservation borrowed another actor or cause")
		}
	}
	if count != 1 {
		t.Fatal("native scheduler did not retain exactly one due loop", count)
	}
	if result, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !result.OK {
		t.Fatal("native scheduler reservation did not survive integrity verification", err)
	}
	return reserved
}

func schedRoot(t *testing.T) {
	t.Helper()
	directory, err := os.MkdirTemp("/run", "lb-loop-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	const uid, gid = 62031, 62031
	if err := os.Chown(directory, uid, gid); err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "canary")
	if err := os.WriteFile(binary, self, 0555); err != nil {
		t.Fatal(err)
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", Config: "loop-native", Class: api.EndpointHuman,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision, ServiceVersion: release.Version,
		ServiceUID: uid, ServiceGID: gid, InstallationGeneration: 1, EndpointGeneration: 1, Backend: "linux-bwrap-landlock",
		ArtifactSHA256: digest, Socket: filepath.Join(directory, "service.sock")}
	path := filepath.Join(directory, "binding.json")
	if err := os.WriteFile(path, fx.JSON(t, binding), 0444); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^"+t.Name()+"$", "-test.v", "--", "loop-native", path)
	command.Env = []string{"HOME=" + directory, "TMPDIR=" + directory}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true}}
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+t.Name())) {
		t.Fatalf("native scheduler canary failed: %v\n%s", err, output)
	}
}

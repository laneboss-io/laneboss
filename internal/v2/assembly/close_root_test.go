//go:build linux && laneboss_root_canary

package assembly

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/service"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/watchdog"
)

type closeCapture struct {
	api.CaptureControl
	binding api.CaptureBinding
}

func (p closeCapture) ReconcileCapture(_ context.Context, binding api.CaptureBinding) (api.CaptureBinding, error) {
	if !reflect.DeepEqual(binding, p.binding) {
		return api.CaptureBinding{}, runError(api.CodeIntegrity, "component capture binding changed")
	}
	return binding, nil
}

type closeState struct {
	*store.Service
	queried chan struct{}
}

func (s *closeState) PendingEffects(ctx context.Context, request api.CursorRequest) ([]api.Effect, error) {
	effects, err := s.Service.PendingEffects(ctx, request)
	select {
	case s.queried <- struct{}{}:
	default:
	}
	return effects, err
}

type closeObserver struct {
	*watchdog.Service
	observed chan error
}

type closeClassify struct {
	api.Runner
	called chan error
}

func (r *closeClassify) LimitFromCapture(ctx context.Context, record api.CaptureRecord, exit api.ProcessObservation) (*api.LimitSignal, error) {
	signal, err := r.Runner.LimitFromCapture(ctx, record, exit)
	select {
	case r.called <- err:
	default:
	}
	return signal, err
}

func (w *closeObserver) ReconcileAutomatic(ctx context.Context) error {
	err := w.Service.ReconcileAutomatic(ctx)
	select {
	case w.observed <- err:
	default:
	}
	return err
}

// Real installed adapter and service close, with explicit component native
// capture facts. The public pinned vendor runs version/auth-status only.
func TestRealClose(t *testing.T) {
	if os.Geteuid() == 0 {
		realCloseRoot(t)
		return
	}
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "real-close" {
		t.Fatal("requires the isolated root canary launcher")
	}
	dir := os.Args[len(os.Args)-1]
	var installed Installation
	if api.DecodeObject(readCloseFile(t, filepath.Join(dir, "installation.json")), &installed) != nil {
		t.Fatal("component installation cannot decode")
	}
	binding, err := wire.ReadBinding(filepath.Join(dir, "binding.json"), installed.Config, release.Version)
	if err != nil {
		t.Fatal(err)
	}
	f := fx.New(t, installed.Config)
	f.Start.Driver, f.Ceiling.Profiles[0].Driver = api.DriverClaudock, api.DriverClaudock
	f.Ceiling.SHA256 = ""
	canonical, err := api.CanonicalJSON(fx.JSON(t, f.Ceiling))
	if err != nil {
		t.Fatal(err)
	}
	f.Ceiling.SHA256 = fx.Digest(canonical)
	f.Replace(t, "grants", f.Ceiling.ID, 1, f.Ceiling)
	runtime, err := loadRealRuntime(installed)
	if err != nil || runtime == nil {
		t.Fatal("real runtime enrollment missing", err)
	}
	session := uuid.NewString()
	f.PlanSetup = func(plan *api.LaunchPlan) {
		plan.Runner.Driver, plan.Runner.Session.Driver = api.DriverClaudock, api.DriverClaudock
		plan.Runner.Executable = runtime.Wrapper
		plan.Runner.Session.VendorID, plan.Runner.Session.VendorVersion = session, runtime.Claude.Version
		plan.Runner.Slot.Mode = "claudock-headless"
		plan.Data.Home.Home.VendorDirectory, plan.Runner.Home.VendorDirectory = ".claude", ".claude"
	}
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	manifestRaw := readCloseFile(t, filepath.Join(dir, "runtime", installed.Config, "manifest.json"))
	if _, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalObjectRetain),
		Object: api.ObjectWrite{ObjectKey: installed.RuntimeManifest.ID, Class: "manifest", Bytes: manifestRaw,
			SHA256: installed.RuntimeManifest.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: installed.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}); err != nil {
		t.Fatal(err)
	}
	input := f.SourceTransaction(t)
	input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Driver = api.DriverClaudock
	input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Executable = runtime.Wrapper
	input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.SessionExecutable = runtime.Claude
	input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Manifest = installed.RuntimeManifest
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	f.Record = input.Writes.LaunchPlans[0]
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	request := api.RunnerRequest{Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID,
		Session: f.Plan.Runner.Session, Prompt: f.Plan.Runner.Prompt, Home: f.Plan.Runner.Home,
		Slot: f.Plan.Runner.Slot, Executable: f.Plan.Runner.Executable, Model: f.Lane.Model, Effort: f.Lane.Effort, Budget: f.Plan.Budget}
	inputID := api.ID(runDigest([]byte("launch\x00" + string(f.Reservation.ID) + "\x00input-runner")))
	requestRaw := fx.JSON(t, request)
	if _, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalLaunchPlan),
		Object: api.ObjectWrite{ObjectKey: inputID, Class: "manifest", Bytes: requestRaw, SHA256: fx.Digest(requestRaw), Origin: "service",
			ACL: api.ObjectACL{Config: installed.Config, Owner: f.Execution.Actor, LifeID: request.Target.LifeID, Audience: "owner", Generation: 1}}}); err != nil {
		t.Fatal(err)
	}
	f.Opened(t)
	ctx := context.Background()
	raw := fx.JSON(t, map[string]any{"type": "result", "subtype": "success", "is_error": false, "session_id": session})
	ref := f.CaptureData(t, append(raw, '\n'))
	receipt, err := f.State.AppendCapture(ctx, f.Worker, f.AppendRequest(t, &ref, false))
	if err != nil {
		t.Fatal(err)
	}
	for i, stream := range f.Plan.Capture.Streams {
		request := f.AppendRequest(t, nil, true)
		request.StreamID, request.ExpectedGeneration = stream.ID, receipt.Generation
		if i == 0 {
			request.Offset = ref.Bytes
		}
		receipt, err = f.State.AppendCapture(ctx, f.Worker, request)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.Ended(t)
	state := &closeState{Service: f.State, queried: make(chan struct{}, 1)}
	ports := runnerDependencies{Store: state, Clock: f.Deps.Clock,
		Sources: &struct{ api.LaunchSourceResolver }{}, Storage: &struct{ api.LaunchStorageResolver }{},
		Grants: &struct{ api.GrantResolver }{}, Credentials: &struct{ api.CredentialBroker }{},
		UsageWindows: &struct{ api.UsageWindowSource }{}, Materialization: &struct{ api.MaterializationControl }{},
		Capture: closeCapture{binding: f.Plan.Capture}}
	runner, _, err := realRunners(installed, ports)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runner.(*realRunner).Close(); err != nil {
			t.Error(err)
		}
	})
	reader := &enrolledRunner{config: installed.Config, deps: ports}
	_, _, _, err = reader.realRun(ctx, f.Reservation.Target)
	var denied *api.Error
	if !errors.As(err, &denied) || denied.Code != api.CodeForbidden || denied.Message != "real runner requires its current planning claim" {
		t.Fatal("unclaimed realRun did not retain its exact refusal", err)
	}
	classifier := &closeClassify{Runner: runner, called: make(chan error, 1)}
	driver, err := watchdog.New(watchdog.Dependencies{Config: installed.Config, Store: state, Clock: f.Deps.Clock,
		Claudock: classifier, Credentials: ports.Credentials, Grants: ports.Grants,
		Lifecycle: &struct{ api.Continuation }{}, Launcher: &struct{ api.Launcher }{}})
	if err != nil {
		t.Fatal(err)
	}
	watch := &closeObserver{Service: driver, observed: make(chan error, 1)}
	auth := &struct{ api.Authenticator }{}
	host, err := service.NewServer(service.Options{Config: installed.Config, BindingFile: filepath.Join(dir, "binding.json")},
		service.Dependencies{Store: state, Clock: f.Deps.Clock, Authenticator: auth, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.BindRuntime(ctx, api.RuntimeServices{Config: installed.Config, Store: state, Identity: auth,
		Watchdog: watch, Socket: binding.Socket, ArtifactSHA256: binding.ArtifactSHA256}); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- host.ServeInstalled(runCtx) }()
	select {
	case <-state.queried:
	case err := <-done:
		t.Fatal("host exited before automatic capture read", err)
	case <-runCtx.Done():
		t.Fatal("host never completed its watchdog scan")
	}
	scanErr := <-watch.observed
	select {
	case <-classifier.called:
	default:
		t.Error("automatic watchdog skipped the enrolled capture reader")
	}
	closeErr := host.Close()
	if scanErr != nil || closeErr != nil {
		t.Fatalf("enrolled capture poisoned real service close: scan=%v close=%v", scanErr, closeErr)
	}
	if second := host.Close(); second != nil {
		t.Fatal("second real close changed success", second)
	}
	select {
	case serveErr := <-done:
		var stopped *api.Error
		if !errors.As(serveErr, &stopped) || stopped.Code != api.CodeCancelled {
			t.Fatal("host returned a failure unrelated to requested close", serveErr)
		}
	case <-runCtx.Done():
		t.Fatal("real close did not drain the host")
	}
	t.Log("real watchdog read reached the enrolled adapter; service close succeeded; unclaimed realRun refused")
}

func readCloseFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func realCloseRoot(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("/opt", "lb-v2-reallane-close-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	const uid, gid = 62033, 62033
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, uid, gid); err != nil {
		t.Fatal(err)
	}
	self := readCloseFile(t, "/proc/self/exe")
	binary := filepath.Join(dir, "canary")
	if err := os.WriteFile(binary, self, 0555); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "runtime", "real-close", "objects")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	vendor := installCompatibilityVendor(t, filepath.Join(root, "claude"))
	wrapper := []byte("unexecuted wrapper pin")
	if err := os.WriteFile(filepath.Join(root, "claudock"), wrapper, 0555); err != nil {
		t.Fatal(err)
	}
	objects := []api.RuntimeObject{}
	for name, raw := range map[string][]byte{"claude": vendor, "claudock": wrapper} {
		objects = append(objects, api.RuntimeObject{ID: api.ID(name), RootID: "objects", RelativePath: name, Role: name, Mode: 0555,
			Content: api.BlobRef{ID: api.ID(name), Class: "artifact", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}})
	}
	digest := fx.Digest(self)
	manifest := fx.JSON(t, api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
		Artifact: api.Executable{ID: "release", Version: "test", SHA256: digest}, Objects: objects, Bindings: []api.InstalledBinding{}})
	runtimeDir := filepath.Dir(root)
	installed := Installation{Config: "real-close", ServiceUID: uid, StateDirectory: home, ArtifactSHA256: digest,
		RuntimeManifest: api.BlobRef{ID: "runtime", Class: "manifest", Bytes: int64(len(manifest)), SHA256: fx.Digest(manifest)}}
	writeRealSessionEnrollment(t, runtimeDir, &installed,
		api.Executable{ID: "claudock", Version: "0.1.0", SHA256: fx.Digest(wrapper)},
		api.Executable{ID: "claude", Version: "2.1.296", SHA256: fx.Digest(vendor)})
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", Config: installed.Config, Class: api.EndpointHuman,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision, ServiceVersion: release.Version,
		ServiceUID: uid, ServiceGID: gid, InstallationGeneration: 1, EndpointGeneration: 1, Backend: "linux-bwrap-landlock",
		ArtifactSHA256: digest, Socket: filepath.Join(home, "service.sock")}
	for path, raw := range map[string][]byte{
		filepath.Join(runtimeDir, "manifest.json"): manifest,
		filepath.Join(runtimeDir, "roots.json"):    fx.JSON(t, []runtimeRoot{{ID: "objects", Path: root}}),
		filepath.Join(dir, "installation.json"):    fx.JSON(t, installed),
		filepath.Join(dir, "binding.json"):         fx.JSON(t, binding),
	} {
		if err := os.WriteFile(path, raw, 0444); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestRealClose$", "-test.v", "--", "real-close", dir)
	command.Env = []string{"HOME=" + home, "TMPDIR=" + home, "PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true}}
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: TestRealClose")) {
		t.Fatalf("enrolled close canary failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}

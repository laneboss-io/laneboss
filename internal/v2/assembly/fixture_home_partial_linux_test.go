//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// This composition regression uses actual SQLite reservation/effect/object
// readers and the real private-home transaction. Slot/native-bootstrap receipts
// are explicit component inputs, not installed kernel measurements. The latter
// remain covered by admin.TestClaudockNativePlanning and the installed harness.
type fixtureHomeWorker struct {
	api.CredentialBroker
	f         *fx.Fixture
	storage   api.LaunchStorage
	request   api.RunnerRequest
	home      string
	records   *claudock.Records
	calls     []string
	bootstrap bool
	stopAt    string
	stop      error
}

func fixturePrivateDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func (p *fixtureHomeWorker) VerifyRunnerSlot(ctx context.Context, claim api.LaunchClaim, request api.RunnerRequest) (api.LaunchStorage, error) {
	effect, err := p.f.State.Effect(ctx, p.f.Execution, claim.EffectID)
	if err != nil {
		return api.LaunchStorage{}, err
	}
	if err := api.CheckPlanningClaim(effect, claim, p.f.Deps.Config, p.f.Deps.Clock.Now()); err != nil {
		return api.LaunchStorage{}, err
	}
	if claim.ReservationID != p.storage.ReservationID || !reflect.DeepEqual(request, p.request) {
		return api.LaunchStorage{}, runError(api.CodeForbidden, "component slot differs from its retained lease and request")
	}
	return p.storage, nil
}

func (p *fixtureHomeWorker) ResolveLaunchStorage(ctx context.Context, input api.LaunchDataRequest) (api.LaunchStorage, error) {
	storage, err := p.VerifyRunnerSlot(ctx, input.Claim, p.request)
	if err != nil {
		return api.LaunchStorage{}, err
	}
	if input.ReservationID != storage.ReservationID || input.LeaseID != storage.LeaseID || input.GrantSetID != p.f.Reservation.GrantSetID {
		return api.LaunchStorage{}, runError(api.CodeForbidden, "component storage selected another native allocation")
	}
	return storage, nil
}

func (p *fixtureHomeWorker) validate(ctx context.Context, input admin.ClaudockPlanningRequest) error {
	storage, err := p.VerifyRunnerSlot(ctx, input.Claim, input.Request)
	if err != nil {
		return err
	}
	if input.RequiredUmask != claudock.RequiredUmask || input.LeaseID != storage.LeaseID || input.Home != storage.Home {
		return runError(api.CodeForbidden, "component home worker lost its exact lease, home or umask")
	}
	return nil
}

func (p *fixtureHomeWorker) VerifyClaudockBootstrap(ctx context.Context, input admin.ClaudockPlanningRequest) error {
	if err := p.validate(ctx, input); err != nil {
		return err
	}
	if input.Plan != nil {
		return runError(api.CodeForbidden, "component bootstrap received home work")
	}
	p.calls = append(p.calls, "bootstrap")
	if p.stopAt == "bootstrap" {
		return p.stop
	}
	p.bootstrap = true // Declared native receipt; no kernel measurement claimed.
	return nil
}

func (p *fixtureHomeWorker) PlanClaudockHome(ctx context.Context, input admin.ClaudockPlanningRequest) error {
	if err := p.validate(ctx, input); err != nil {
		return err
	}
	if !p.bootstrap || input.Plan == nil || !reflect.DeepEqual(input.Plan.Request, p.request) ||
		input.Plan.Home != p.storage.Home || input.Plan.ReservationID != p.storage.ReservationID || !input.Plan.Start {
		return runError(api.CodeForbidden, "component home lacks its bound bootstrap and retained start")
	}
	p.calls = append(p.calls, "home")
	if p.stopAt == "home" {
		return p.stop
	}
	if err := claudock.InitializeAllocatedHome(p.home, p.records); err != nil {
		return err
	}
	return claudock.PlanPrivateHome(p.home, p.records, *input.Plan, func(findings []claudock.Finding) error {
		if len(findings) != 0 {
			return runError(api.CodeIntegrity, "clean component home contains unexpected findings")
		}
		return nil
	}, nil)
}

func fixtureHomeCase(t *testing.T, mode string) (api.Runner, *fixtureHomeWorker, context.Context) {
	t.Helper()
	runtime, installed, values := runtimeFixture(t)
	asset := []byte("item runtime asset " + string(fx.ID(t)))
	assetID := fx.ID(t)
	runtime.Objects = append(runtime.Objects, api.RuntimeObject{ID: assetID, Role: "fixture", RootID: "runtime", RelativePath: string(assetID), Mode: 0444,
		Content: api.BlobRef{ID: assetID, Class: "artifact", Bytes: int64(len(asset)), SHA256: fx.Digest(asset)}})
	values[assetID] = asset
	declared, err := fixtureFromRuntime(runtime, installed, func(object api.RuntimeObject) ([]byte, error) { return values[object.ID], nil })
	if err != nil {
		t.Fatal(err)
	}
	declared.executablePath, declared.Mode = "/runtime/agent", "lifecycle"
	f := fx.New(t, installed.Config)
	f.Start.Driver, f.Start.Model = api.DriverClaudock, "fixture-model-1"
	f.Ceiling.Profiles[0].Driver = api.DriverClaudock
	f.Ceiling.SHA256 = ""
	f.Ceiling.SHA256, err = manifest.HashValue(f.Ceiling)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	tx := f.SourceTransaction(t)
	selected := &tx.Writes.LaunchPlans[0].Inputs.Sources.Runtime
	selected.Driver, selected.Executable, selected.SessionExecutable = api.DriverClaudock, declared.Executable, declared.Executable
	selected.Manifest = f.Retain(t, "manifest", fx.JSON(t, runtime), f.Execution.Actor, "")
	if _, err := f.State.Transact(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	f.Record = tx.Writes.LaunchPlans[0]
	workspace := fx.ID(t)
	storage := api.LaunchStorage{ReservationID: f.Reservation.ID, Target: f.Reservation.Target, LeaseID: fx.ID(t), WorkspaceID: workspace,
		Home: api.PrivateHomeBinding{LifeID: f.Reservation.Target.LifeID, RootID: fx.ID(t), Generation: 1,
			Home: api.PrivateHome{ID: fx.ID(t), WorkspaceID: workspace, VendorDirectory: ".claude", HistoryID: fx.ID(t)}}}
	request := api.RunnerRequest{Target: f.Reservation.Target, LogicalTurnID: fx.ID(t), Home: storage.Home.Home,
		Executable: declared.Executable, Prompt: f.Retain(t, "prompt", []byte("fixture prompt\n"), f.Execution.Actor, f.Reservation.Target.LifeID),
		Model: f.Start.Model, Effort: "high", Budget: f.Start.Budget,
		Slot: api.CredentialSlot{ID: fx.ID(t), LeaseID: fx.ID(t), ProfileGrantID: f.Record.Inputs.Grants.Profiles[0].ID,
			ProfileID: f.Record.Inputs.Grants.Profiles[0].ProfileID, Mode: mode, ExpiresAt: fx.Expiry()}}
	request.Session = api.Session{ID: fx.ID(t), Driver: api.DriverClaudock, VendorID: uuid.NewString(), VendorVersion: declared.Version,
		HomeID: request.Home.ID, HistoryID: request.Home.HistoryID, LogicalCWD: "/work/main"}
	raw := fx.JSON(t, request)
	inputID := api.ID(runDigest([]byte("launch\x00" + string(f.Reservation.ID) + "\x00input-runner")))
	_, err = f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalLaunchPlan),
		Object: api.ObjectWrite{ObjectKey: inputID, Class: "manifest", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service",
			ACL: api.ObjectACL{Config: installed.Config, Owner: f.Execution.Actor, LifeID: request.Target.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	home := fixturePrivateDir(t)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	records, err := claudock.NewRecords(fixturePrivateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := records.Close(); err != nil {
			t.Error(err)
		}
	})
	worker := &fixtureHomeWorker{f: f, storage: storage, request: request, home: home, records: records}
	runner, _, err := installedFixtureRunners(declared, installed, runnerDependencies{Store: f.State, Clock: f.Deps.Clock,
		Storage: worker, Credentials: worker})
	if err != nil {
		t.Fatal(err)
	}
	return runner, worker, api.WithEffectLease(context.Background(), f.Claim)
}

func TestInstalledFixtureClaudockHome(t *testing.T) {
	for _, mode := range []string{"claudock-headless", "claude-api-key"} {
		t.Run(mode, func(t *testing.T) {
			runner, worker, ctx := fixtureHomeCase(t, mode)
			plan, err := runner.Start(ctx, worker.request)
			if err != nil {
				t.Fatal("installed fixture could not plan its retained private home", err)
			}
			if !reflect.DeepEqual(worker.calls, []string{"bootstrap", "home"}) || plan.Home != worker.storage.Home.Home ||
				plan.Session != worker.request.Session || plan.Executable != worker.request.Executable {
				t.Fatal("installed fixture omitted its bound bootstrap/home transaction or changed its retained runner")
			}
			opened, err := claudock.OpenHome(worker.home, worker.records)
			if err != nil {
				t.Fatal(err)
			}
			projections, err := opened.GeneratedProjections()
			if err != nil || len(projections) != 3 {
				t.Fatal("installed fixture lacks all protected generated projections", err)
			}
			for _, projection := range projections {
				path := filepath.Join(worker.home, projection.Path)
				raw, readErr := os.ReadFile(path)
				info, statErr := os.Stat(path)
				if readErr != nil || statErr != nil || fx.Digest(raw) != projection.SHA256 || info.Mode().Perm() != 0400 {
					t.Fatal("generated fixture home projection lost its bytes or read-only mode", readErr, statErr)
				}
			}
			if replay, err := runner.Start(ctx, worker.request); err != nil || !reflect.DeepEqual(replay, plan) {
				t.Fatal("identical fixture home plan did not replay", err)
			}
		})
	}
}

func TestInstalledFixtureClaudockHomeStops(t *testing.T) {
	for _, fault := range []string{"claim", "request", "home-binding", "worker", "bootstrap", "home"} {
		t.Run(fault, func(t *testing.T) {
			runner, worker, ctx := fixtureHomeCase(t, "claudock-headless")
			request := worker.request
			wantCalls := []string(nil)
			sentinel := errors.New("component native worker stopped")
			switch fault {
			case "claim":
				ctx = context.Background()
			case "request":
				request.Model += "-changed"
			case "home-binding":
				request.Home.WorkspaceID = fx.ID(t)
			case "worker":
				wrapped, ok := runner.(*fixtureClaudockRunner)
				if !ok {
					t.Fatal("installed fixture did not select its native-home adapter")
				}
				wrapped.reader.deps.Storage = struct{ api.LaunchStorageResolver }{worker}
			case "bootstrap", "home":
				worker.stopAt, worker.stop = fault, sentinel
				wantCalls = []string{"bootstrap"}
				if fault == "home" {
					wantCalls = append(wantCalls, "home")
				}
			}
			plan, err := runner.Start(ctx, request)
			if err == nil || !reflect.DeepEqual(plan, api.RunnerPlan{}) || !reflect.DeepEqual(worker.calls, wantCalls) {
				t.Fatal("fixture returned a plan or passed the failed native-home prerequisite", err)
			}
			if worker.stopAt != "" && !errors.Is(err, sentinel) {
				t.Fatal("fixture concealed the native worker failure", err)
			}
			if _, err := os.Stat(filepath.Join(worker.home, ".claude/settings.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed fixture home prerequisite still materialized settings", err)
			}
		})
	}
}

//go:build linux && laneboss_partial && laneboss_e2e_authenticator && !laneboss_root_canary

package assembly

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/e2e/v2/cases/policy/lfx"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/guidance"
	"laneboss.io/laneboss/internal/v2/judge"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/policy"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/templates"
)

// The planner, writer, grant/source resolution, templates, guidance and fixture
// runner are real. Kernel/helper receipts and a credential slot are explicit
// component fixtures. Capture is absent, so no agent execution can follow.
func TestPolicyFixtureRunnerInputs(t *testing.T) {
	source, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, control := range []bool{false, true} {
		name := "actual"
		var options []string
		if control {
			name, options = "original-wall-budget", []string{"--wall-ms", "900000"}
		}
		t.Run(name, func(t *testing.T) {
			input := lfx.Load(t, source, options...)
			for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
				t.Run(string(driver), func(t *testing.T) {
					f := input.Reserve(t, driver)
					ports := &policyRunnerPorts{t: t, f: f, input: input}
					resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: f.State, Worker: &dataworker.Service{}, Clock: f.Deps.Clock})
					if err != nil {
						t.Fatal(err)
					}
					renderer, err := templates.New(templates.Dependencies{Store: f.State, Policy: &policy.Service{}, Clock: f.Deps.Clock})
					if err != nil {
						t.Fatal(err)
					}
					guide, err := guidance.New(guidance.Dependencies{Store: f.State, Judge: &judge.Service{}, Clock: f.Deps.Clock})
					if err != nil {
						t.Fatal(err)
					}
					planner, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: ports, Sources: ports,
						Grants: resolver, Worker: ports, Credentials: &policyRunnerBroker{p: ports}, Claudock: ports, Codex: ports,
						Templates: renderer, Guidance: guide, Clock: f.Deps.Clock})
					if err != nil {
						t.Fatal(err)
					}
					_, planErr := planner.PlanLaunch(context.Background(), f.Execution, api.LaunchPlanRequest{Lease: f.Claim})
					if ports.calls != 1 {
						t.Fatalf("actual case planner did not reach the runner: %v", planErr)
					}
					if ports.runner == nil {
						t.Fatalf("planner request failed component provenance before the real runner: %v", planErr)
					}
					q := ports.request
					if q.Budget != f.Start.Budget || q.Model != f.Start.Model || q.Effort != f.Start.Effort || q.Target != f.Reservation.Target {
						t.Fatal("planner changed actual case launch fields")
					}
					failed := fixtureInputFailures(ports.runner, q)
					t.Logf("actual %s RunnerRequest: failed_conditions=%v wall_ms=%d", driver, failed, q.Budget.WallMS)
					if control {
						var typed *api.Error
						if !reflect.DeepEqual(failed, []string{"budget.wall_ms.maximum"}) || !errors.As(ports.runnerErr, &typed) ||
							typed.Owner != "lb-v2-serve" || typed.Code != api.CodeNotImplemented || typed.Message != "complete fixture launch inputs is not implemented" {
							t.Fatalf("original wall budget did not reach the unchanged fixture fence: %v", ports.runnerErr)
						}
						var propagated *api.Error
						if !errors.As(planErr, &propagated) || propagated.Owner != typed.Owner || propagated.Code != typed.Code || propagated.Message != typed.Message {
							t.Fatalf("planner did not preserve the fixture runner refusal: %v", planErr)
						}
						return
					}
					if ports.runnerErr != nil || len(failed) != 0 {
						t.Fatalf("actual policy RunnerRequest refused; failed_conditions=%v wall_ms=%d: %v", failed, q.Budget.WallMS, ports.runnerErr)
					}
					var typed *api.Error
					boundary := api.NotImplemented("lb-v2-admin", "CaptureControl.RegisterCapture")
					if !errors.As(planErr, &typed) || typed.Code != boundary.Code || typed.Owner != boundary.Owner || typed.Message != boundary.Message {
						t.Fatalf("planner did not stop at the intentionally absent capture port after runner acceptance: %v", planErr)
					}
					t.Logf("GREEN: actual %s case request accepted by the unchanged fixture runner; capture remains unconfigured", driver)
				})
			}
		})
	}
}

type policyRunnerPorts struct {
	api.Helper
	api.DataWorker
	api.Authenticator
	api.Runner
	t          *testing.T
	f          *fx.Fixture
	input      lfx.Inputs
	runtime    api.LaunchRuntime
	allocation api.HelperLease
	data       *fx.DataFixture
	slot       api.CredentialSlot
	runner     *enrolledFixtureRunner
	request    api.RunnerRequest
	runnerErr  error
	calls      int
}

func (p *policyRunnerPorts) ResolveLaunchSources(ctx context.Context, q api.LaunchSourceRequest) (api.LaunchSources, error) {
	sources, err := admin.ResolveCommittedLaunchSources(ctx, p.f.State, p.f.Deps.Config, q, p.input.Enrollment, p.input.Runtime)
	if err == nil {
		p.runtime = sources.Runtime
	}
	return sources, err
}

func (p *policyRunnerPorts) Allocate(ctx context.Context, q api.HelperLeaseRequest) (api.HelperLease, error) {
	if q.ReservationID != p.f.Reservation.ID || q.LifeID != p.f.Reservation.Target.LifeID || q.Budget != p.f.Start.Budget || q.RuntimeManifestID != p.runtime.Manifest.ID {
		return api.HelperLease{}, installError("component allocation changed actual policy inputs")
	}
	p.allocation = api.HelperLease{ID: fx.ID(p.t), UID: uint32(os.Geteuid()) + 1000, GID: uint32(os.Getegid()) + 1000,
		ContainmentID: fx.ID(p.t), EndpointGeneration: 1}
	return p.allocation, nil
}

func (p *policyRunnerPorts) MaterializeLaunch(ctx context.Context, q api.LaunchDataRequest) (api.LaunchData, error) {
	if q.ReservationID != p.f.Reservation.ID || q.GrantSetID != p.f.Reservation.GrantSetID || q.LeaseID != p.allocation.ID {
		return api.LaunchData{}, installError("component materialization changed actual policy allocation")
	}
	p.data = fx.DataForLaunch(p.t, p.f, q)
	var runtime api.RuntimeManifest
	for _, document := range p.input.Documents {
		if document.Ref == p.input.Runtime {
			if err := api.DecodeObject(document.Data, &runtime); err != nil {
				return api.LaunchData{}, err
			}
		}
	}
	p.data.Endpoint.ArtifactSHA256 = runtime.Artifact.SHA256
	p.data.Open(p.t)
	data, raw := p.data.Result(p.t)
	receipt, err := p.f.State.WorkerResult(ctx, p.data.Worker, p.data.Submission(raw))
	if err != nil {
		return api.LaunchData{}, err
	}
	zero, survivors := 0, uint64(0)
	result := api.LaunchDataResult{StageID: p.data.Stage.ID, WorkerLeaseID: p.data.Stage.Worker.ID,
		EffectID: p.data.Stage.Worker.EffectID, OperationID: p.f.Reservation.OperationID, InputSHA256: p.data.Stage.Worker.Input.SHA256,
		Data: data, Manifest: data.Materialization.Manifest, ReadBackSHA256: data.Materialization.Manifest.SHA256, ResultReceipt: receipt,
		Observation: api.ProcessObservation{Handle: p.data.Stage.Process, State: "exited", ExitCode: &zero, Survivors: &survivors,
			PromptStatus: "completed", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}}
	_, err = p.f.State.CompleteMaterialization(ctx, p.f.Execution, p.data.Stage.ID, result)
	return data, err
}

func (p *policyRunnerPorts) ResolveLaunchStorage(ctx context.Context, q api.LaunchDataRequest) (api.LaunchStorage, error) {
	if p.data == nil || q.ReservationID != p.f.Reservation.ID || q.LeaseID != p.allocation.ID {
		return api.LaunchStorage{}, installError("component storage selected another policy job")
	}
	stage, err := p.f.State.LaunchDataStage(ctx, p.f.Execution, q)
	return stage.Storage.Storage, err
}

type policyRunnerBroker struct {
	api.CredentialBroker
	p *policyRunnerPorts
}

func (b *policyRunnerBroker) Acquire(ctx context.Context, target api.LifeRef, grant api.ProfileGrant) (api.CredentialSlot, error) {
	p := b.p
	issued, err := p.f.State.Grants(ctx, p.f.Reservation.GrantSetID)
	if err != nil {
		return api.CredentialSlot{}, err
	}
	if target != p.f.Reservation.Target || len(issued.Profiles) != 1 || grant != issued.Profiles[0] {
		return api.CredentialSlot{}, installError("component slot selected a different policy profile")
	}
	p.slot = api.CredentialSlot{ID: fx.ID(p.t), LeaseID: fx.ID(p.t), ProfileGrantID: grant.ID, ProfileID: grant.ProfileID,
		Mode: "component", ExpiresAt: grant.ExpiresAt}
	return p.slot, nil
}

func (b *policyRunnerBroker) Inject(ctx context.Context, target api.LifeRef, grants []api.SecretGrant) (api.Injection, error) {
	p := b.p
	if target != p.f.Reservation.Target || len(grants) != 0 || p.slot.ID == "" {
		return api.Injection{}, installError("component injection changed policy slot or secret scope")
	}
	return api.Injection{Target: target, SlotIDs: []api.ID{p.slot.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{},
		GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}, nil
}

func (p *policyRunnerPorts) Start(ctx context.Context, q api.RunnerRequest) (api.RunnerPlan, error) {
	p.calls++
	p.request = q
	if p.data == nil || q.Home != p.data.Stage.Storage.Storage.Home.Home || q.Slot != p.slot || q.Executable != p.runtime.Executable {
		return api.RunnerPlan{}, installError("planner runner inputs differ from actual policy source, storage or slot")
	}
	p.runner = &enrolledFixtureRunner{driver: p.f.Start.Driver, enrollment: fixtureEnrollment{Config: p.f.Deps.Config,
		Executable: p.runtime.Executable, Version: p.runtime.Executable.Version, executablePath: filepath.Join("/runtime", string(p.runtime.Executable.ID)),
		ClientPath: "/run/laneboss/client", BindingPath: "/run/laneboss/binding.json"}}
	plan, err := p.runner.Start(ctx, q)
	p.runnerErr = err
	return plan, err
}

func fixtureInputFailures(r *enrolledFixtureRunner, q api.RunnerRequest) []string {
	expires, err := time.Parse(time.RFC3339Nano, string(q.Slot.ExpiresAt))
	checks := []struct {
		name string
		ok   bool
	}{
		{"executable.pin", q.Executable == r.enrollment.Executable}, {"session.driver", q.Session.Driver == r.driver},
		{"executable.absolute_path", filepath.IsAbs(r.enrollment.executablePath)}, {"target.life", q.Target.LifeID != ""}, {"target.run", q.Target.Run != 0},
		{"session.id", q.Session.ID != ""}, {"session.home", q.Session.HomeID == q.Home.ID && q.Home.ID != ""},
		{"home.workspace", q.Home.WorkspaceID != ""}, {"session.history", q.Session.HistoryID == q.Home.HistoryID && q.Home.HistoryID != ""},
		{"session.cwd", q.Session.LogicalCWD == "/work/main"}, {"prompt.id", q.Prompt.ID != ""}, {"prompt.class", q.Prompt.Class == "prompt"},
		{"prompt.bytes", q.Prompt.Bytes > 0}, {"prompt.digest", isDigest(q.Prompt.SHA256)}, {"slot.id", q.Slot.ID != ""}, {"slot.lease", q.Slot.LeaseID != ""},
		{"slot.profile_grant", q.Slot.ProfileGrantID != ""}, {"slot.profile", q.Slot.ProfileID != ""}, {"slot.expiry", err == nil && expires.After(time.Now())},
		{"budget.wall_ms.minimum", q.Budget.WallMS >= 1}, {"budget.wall_ms.maximum", q.Budget.WallMS <= 300000}, {"model", q.Model != ""}, {"effort", q.Effort != ""},
	}
	failed := []string{}
	for _, check := range checks {
		if !check.ok {
			failed = append(failed, check.name)
		}
	}
	return failed
}

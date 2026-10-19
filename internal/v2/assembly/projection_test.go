package assembly

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/secrets"
)

type projectionRaw struct {
	api.Launcher
	backend  string
	prepares int
	launches int
}

type projectionAdmin struct {
	admin.Service
	calls       int
	credentials api.CredentialProjectionBroker
	identity    api.CredentialProjectionIdentity
}

func (a *projectionAdmin) BindCredentialProjection(credentials api.CredentialProjectionBroker, identity api.CredentialProjectionIdentity) error {
	a.calls++
	a.credentials, a.identity = credentials, identity
	return a.Service.BindCredentialProjection(credentials, identity)
}
func (r *projectionRaw) Probe(ctx context.Context) (api.IsolationCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return api.IsolationCapabilities{}, err
	}
	return api.IsolationCapabilities{Backend: r.backend, Available: r.backend != "", Checks: []api.Capability{{Name: "fixture-backend", Available: r.backend != ""}}}, nil
}
func (r *projectionRaw) Prepare(ctx context.Context, spec api.LaunchSpec) (api.PreparedLaunch, error) {
	if err := ctx.Err(); err != nil {
		return api.PreparedLaunch{}, err
	}
	r.prepares++
	if spec.ID == "" {
		return api.PreparedLaunch{}, &api.Error{Code: api.CodeInvalid}
	}
	return api.PreparedLaunch{ID: spec.ID, Target: spec.Target, EndpointGeneration: spec.EndpointGeneration}, nil
}

func (r *projectionRaw) Launch(ctx context.Context, prepared api.PreparedLaunch, permit api.LaunchPermit) (api.ProcessHandle, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessHandle{}, err
	}
	r.launches++
	if prepared.ID == "" || permit.PreparedID != prepared.ID || permit.LaunchID == "" {
		return api.ProcessHandle{}, &api.Error{Code: api.CodeInvalid}
	}
	return api.ProcessHandle{ID: permit.LaunchID, Target: prepared.Target, ContainmentID: prepared.ContainmentID, Generation: prepared.ProcessGeneration}, nil
}

// This exercises the same runtime binding/start boundary as build with the
// shipped admin binder. Host callbacks model existing health/enrollment ports;
// no native listener, registration crypto or full installed serve is claimed.
type projectionHost struct {
	runtime     api.RuntimeServices
	started     bool
	enrollments []api.EnrollmentCeremonyRequest
	beforeBind  func(api.RuntimeServices)
}

func (h *projectionHost) BindRuntime(ctx context.Context, r api.RuntimeServices) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.runtime.Launcher != nil || r.Launcher == nil || r.Config == "" {
		return &api.Error{Code: api.CodeInvalid}
	}
	if h.beforeBind != nil {
		h.beforeBind(r)
	}
	h.runtime = r
	return nil
}
func (h *projectionHost) ServeInstalled(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.runtime.Launcher == nil {
		return &api.Error{Code: api.CodePrerequisite}
	}
	h.started = true
	return nil
}
func (h *projectionHost) Close() error { h.started = false; return nil }
func (h *projectionHost) health(ctx context.Context) (api.IsolationCapabilities, error) {
	if !h.started {
		return api.IsolationCapabilities{}, &api.Error{Code: api.CodeUnavailable}
	}
	return h.runtime.Launcher.Probe(ctx)
}
func (h *projectionHost) enroll(request api.EnrollmentCeremonyRequest) error {
	if !h.started || request.Config != h.runtime.Config || request.CeremonyID == "" {
		return &api.Error{Code: api.CodeInvalid}
	}
	h.enrollments = append(h.enrollments, request)
	return nil
}

func projectionAssembly(t *testing.T) (*projectionLauncher, *projectionRaw, *projectionHost) {
	t.Helper()
	raw := &projectionRaw{backend: "linux-bwrap-landlock"}
	helper := &projectionAdmin{}
	launcher := &projectionLauncher{Launcher: raw, binder: helper}
	host := &projectionHost{}
	runtime := api.RuntimeServices{Config: "demo", Launcher: launcher, Helper: helper, Credentials: &secrets.Service{}, CredentialIdentity: &identity.Service{}}
	if err := launcher.bindRuntime(context.Background(), host, runtime); err != nil {
		t.Fatalf("stub projection binder blocked service startup: %v", err)
	}
	if err := host.ServeInstalled(context.Background()); err != nil {
		t.Fatal(err)
	}
	return launcher, raw, host
}

func TestProjectionStartup(t *testing.T) {
	launcher, raw, host := projectionAssembly(t)
	if launcher.attempted || raw.prepares != 0 || host.runtime.Helper.(*projectionAdmin).calls != 0 {
		t.Fatal("projection work ran during service construction")
	}
	health, err := host.health(context.Background())
	if err != nil || !health.Available || health.Backend != raw.backend {
		t.Fatalf("health was blocked by projection binding: %v", err)
	}
	request := api.EnrollmentCeremonyRequest{Config: "demo", CeremonyID: "ceremony", PrincipalID: "human"}
	if err := host.enroll(request); err != nil || len(host.enrollments) != 1 || host.enrollments[0] != request {
		t.Fatalf("enrollment dispatch was blocked: %v", err)
	}
	worker := api.LaunchSpec{ID: "data-job", Kind: "worker", Worker: &api.WorkerPlan{Kind: "materialize"}, Target: api.LifeRef{LifeID: "life", Run: 1}}
	prepared, err := launcher.Prepare(context.Background(), worker)
	if err != nil || prepared.ID != worker.ID || raw.prepares != 1 || launcher.attempted {
		t.Fatalf("credential-free worker required projection binding: %v", err)
	}
}

func TestProjectionPrepare(t *testing.T) {
	launcher, raw, host := projectionAssembly(t)
	spec := api.LaunchSpec{ID: "agent-spec", Kind: "agent", Target: api.LifeRef{LifeID: "life", Run: 1}}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := launcher.Prepare(context.Background(), spec)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" || !strings.Contains(typed.Message, "admin.BindCredentialProjection") || raw.prepares != 0 {
			t.Fatalf("projection binder refusal was swallowed at Prepare: %v", err)
		}
	}
	helper := host.runtime.Helper.(*projectionAdmin)
	if helper.calls != 1 || helper.credentials != host.runtime.Credentials || helper.identity != host.runtime.CredentialIdentity {
		t.Fatal("Prepare did not call the shipped binder once with its actual clients")
	}
	if _, err := host.health(context.Background()); err != nil {
		t.Fatalf("failed Prepare stopped health: %v", err)
	}
	if err := host.enroll(api.EnrollmentCeremonyRequest{Config: "demo", CeremonyID: "after-refusal"}); err != nil {
		t.Fatalf("failed Prepare stopped enrollment: %v", err)
	}
}

func TestProjectionWiring(t *testing.T) {
	wiring, err := os.ReadFile("assembly.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"projectedLauncher := &projectionLauncher{Launcher: launcher, binder: helper}",
		"launcher = projectedLauncher",
		"projectedLauncher.bindRuntime(ctx, runtimeTarget, api.RuntimeServices{",
	} {
		if !strings.Contains(string(wiring), required) {
			t.Fatalf("production launcher bypassed deferred projection binding: %s", required)
		}
	}
	packages, err := parser.ParseDir(token.NewFileSet(), ".", func(info fs.FileInfo) bool {
		return strings.HasSuffix(info.Name(), ".go") && !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if ok && selector.Sel.Name == "BindCredentialProjection" {
						found++
						if fn.Name.Name != "bindProjection" {
							t.Errorf("projection binder was called outside Prepare/Launch gate: %s", fn.Name.Name)
						}
					}
					return true
				})
			}
		}
	}
	if found == 0 {
		t.Fatal("projection binder was never wired into Prepare")
	}
}

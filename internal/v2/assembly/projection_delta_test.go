package assembly

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/secrets"
)

func materialSpec() api.LaunchSpec {
	return api.LaunchSpec{ID: "material-spec", Kind: "worker", Worker: &api.WorkerPlan{Kind: "materialize"}}
}

func projectionRefusal(t *testing.T, err error, diagnostic string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" {
		t.Fatalf("%s: %v", diagnostic, err)
	}
}

func TestProjectionShapes(t *testing.T) {
	for _, fault := range []string{"kind", "missing", "other", "runner", "capture", "plan", "secrets", "profiles", "channels", "resources", "data", "network", "slots", "grants", "env", "file", "versions", "outcome", "target"} {
		t.Run(fault, func(t *testing.T) {
			l, raw, _ := projectionAssembly(t)
			spec := materialSpec()
			switch fault {
			case "kind":
				spec.Kind = ""
			case "missing":
				spec.Worker = nil
			case "other":
				spec.Worker.Kind = "test"
			case "runner":
				spec.Runner = &api.RunnerPlan{}
			case "capture":
				spec.Capture = &api.CaptureBinding{}
			case "plan":
				spec.PlanID = "plan"
			case "secrets":
				spec.Grants.Secrets = []api.SecretGrant{{ID: "secret"}}
			case "profiles":
				spec.Grants.Profiles = []api.ProfileGrant{{ID: "profile"}}
			case "channels":
				spec.Grants.Channels = []api.ChannelGrant{{ID: "channel"}}
			case "resources":
				spec.Grants.Resources = []api.ResourceGrant{{ID: "resource"}}
			case "data":
				spec.Grants.Data = []api.DataGrant{{ID: "data"}}
			case "network":
				spec.Grants.Network = []api.NetworkGrant{{ID: "network"}}
			case "slots":
				spec.Injection.SlotIDs = []api.ID{"slot"}
			case "grants":
				spec.Injection.GrantIDs = []api.ID{"grant"}
			case "env":
				spec.Injection.TaskSecretNames = []string{"access"}
			case "file":
				spec.Injection.TaskSecretFileNames = []string{"access"}
			case "versions":
				spec.Injection.SourceVersions = []string{"v1"}
			case "outcome":
				spec.Injection.Outcome = "prepared"
			case "target":
				spec.Injection.Target = api.LifeRef{LifeID: "life", Run: 1}
			}
			_, err := l.Prepare(context.Background(), spec)
			projectionRefusal(t, err, "credential-bearing shape bypassed projection binding")
			if raw.prepares != 0 {
				t.Fatal("credential-bearing shape reached underlying Prepare")
			}
		})
	}
}

func TestProjectionConfig(t *testing.T) {
	for _, operation := range []string{"prepare", "launch"} {
		t.Run(operation, func(t *testing.T) {
			raw := &projectionRaw{}
			l := &projectionLauncher{Launcher: raw}
			var err error
			if operation == "prepare" {
				_, err = l.Prepare(context.Background(), materialSpec())
			} else {
				_, err = l.Launch(context.Background(), api.PreparedLaunch{ID: "prepared"}, api.LaunchPermit{PreparedID: "prepared", LaunchID: "launch"})
			}
			projectionRefusal(t, err, "unconfigured launcher delegated an operation")
			if raw.prepares+raw.launches != 0 {
				t.Fatal("unconfigured launcher reached its underlying port")
			}
		})
	}
}

func TestProjectionPorts(t *testing.T) {
	for _, missing := range []string{"binder", "broker", "identity"} {
		t.Run(missing, func(t *testing.T) {
			l, raw, _ := projectionAssembly(t)
			switch missing {
			case "binder":
				l.binder = nil
			case "broker":
				l.credentials = nil
			case "identity":
				l.identity = nil
			}
			_, err := l.Prepare(context.Background(), materialSpec())
			projectionRefusal(t, err, "missing projection client was accepted")
			if raw.prepares != 0 {
				t.Fatal("missing projection client reached underlying Prepare")
			}
		})
	}
}

func TestBindIncomplete(t *testing.T) {
	raw := &projectionRaw{}
	l := &projectionLauncher{Launcher: raw, binder: &projectionAdmin{}}
	observed := false
	host := &projectionHost{beforeBind: func(r api.RuntimeServices) {
		observed = true
		_, err := r.Launcher.Prepare(context.Background(), materialSpec())
		projectionRefusal(t, err, "incomplete runtime binding was accepted")
	}}
	runtime := api.RuntimeServices{Config: "demo", Launcher: l, Credentials: &secrets.Service{}, CredentialIdentity: &identity.Service{}}
	if err := l.bindRuntime(context.Background(), host, runtime); err != nil {
		t.Fatal(err)
	}
	if !observed || !l.configured || raw.prepares != 0 {
		t.Fatal("runtime binding completion was not enforced")
	}
}

func TestProjectionRecovery(t *testing.T) {
	l, raw, host := projectionAssembly(t)
	_, err := l.Launch(context.Background(), api.PreparedLaunch{ID: "prepared"}, api.LaunchPermit{PreparedID: "prepared", LaunchID: "launch"})
	projectionRefusal(t, err, "recovery Launch skipped projection binding")
	if raw.launches != 0 || host.runtime.Helper.(*projectionAdmin).calls != 1 {
		t.Fatal("recovery Launch did not use the shipped binder")
	}
}

// This binder models an atomic temporary failure and a distinct partially
// applied failure. It validates actual clients and refuses a second success.
type retryProjection struct {
	failure     error
	partial     bool
	bound       bool
	calls       int
	credentials api.CredentialProjectionBroker
	identity    api.CredentialProjectionIdentity
}

func (b *retryProjection) BindCredentialProjection(credentials api.CredentialProjectionBroker, identity api.CredentialProjectionIdentity) error {
	b.calls++
	if credentials == nil || identity == nil || b.bound {
		return &api.Error{Code: api.CodeConflict, Owner: "lb-v2-admin"}
	}
	if b.failure != nil {
		err := b.failure
		b.failure = nil
		b.bound = b.partial
		return err
	}
	b.bound, b.credentials, b.identity = true, credentials, identity
	return nil
}

func retryAssembly(t *testing.T, binder *retryProjection) (*projectionLauncher, *projectionRaw) {
	t.Helper()
	raw := &projectionRaw{}
	l := &projectionLauncher{Launcher: raw, binder: binder}
	runtime := api.RuntimeServices{Config: "demo", Launcher: l, Credentials: &secrets.Service{}, CredentialIdentity: &identity.Service{}}
	if err := l.bindRuntime(context.Background(), &projectionHost{}, runtime); err != nil {
		t.Fatal(err)
	}
	return l, raw
}

func TestBindRetry(t *testing.T) {
	first := &api.CredentialBindingFailure{Cause: &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-admin", Retryable: true}, Unbound: true}
	binder := &retryProjection{failure: first}
	l, raw := retryAssembly(t, binder)
	spec := api.LaunchSpec{ID: "agent", Kind: "agent"}
	if _, err := l.Prepare(context.Background(), spec); err != first || raw.prepares != 0 {
		t.Fatalf("transient binding refusal was lost: %v", err)
	}
	prepared, err := l.Prepare(context.Background(), spec)
	if err != nil || prepared.ID != spec.ID || binder.calls != 2 || !binder.bound || binder.credentials != l.credentials || binder.identity != l.identity {
		t.Fatalf("certified unbound failure could not retry: %v", err)
	}
	if _, err := l.Prepare(context.Background(), spec); err != nil || binder.calls != 2 {
		t.Fatalf("successful binder was called twice: %v", err)
	}
	if _, err := l.Launch(context.Background(), prepared, api.LaunchPermit{PreparedID: prepared.ID, LaunchID: "launch"}); err != nil || binder.calls != 2 || raw.launches != 1 {
		t.Fatalf("bound recovery launch failed: %v", err)
	}
}

func TestBindRetryFence(t *testing.T) {
	for _, kind := range []string{"partial", "generic", "permanent"} {
		t.Run(kind, func(t *testing.T) {
			cause := &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-admin", Retryable: true}
			var failure error = &api.CredentialBindingFailure{Cause: cause, Unbound: false}
			if kind == "generic" {
				failure = cause
			}
			if kind == "permanent" {
				failure = api.NotImplemented("lb-v2-admin", "projection")
			}
			binder := &retryProjection{failure: failure, partial: kind == "partial"}
			l, raw := retryAssembly(t, binder)
			for attempt := 0; attempt < 2; attempt++ {
				_, err := l.Prepare(context.Background(), api.LaunchSpec{ID: "agent", Kind: "agent"})
				if err != failure {
					t.Fatalf("uncertain binding was retried: %v", err)
				}
			}
			if binder.calls != 1 || raw.prepares != 0 {
				t.Fatal("uncertain binding was retried")
			}
		})
	}
}

func TestBindCheckWord(t *testing.T) {
	var reply struct {
		Bound   bool
		Fresh   bool
		Failure *api.Error `json:"Failure,omitempty"`
	}
	cause := api.DecodeObject([]byte(`{"Bound":false,"Fresh":true,"Failure":null}`), &reply)
	var typed *api.Error
	if !errors.As(cause, &typed) || typed.Code != api.CodeInvalid {
		t.Fatal("control did not reproduce the binding reply schema refusal", cause)
	}
	l, raw := retryAssembly(t, &retryProjection{failure: cause})
	word := ""
	ctx := api.WithHelperReasonObserver(context.Background(), func(err error, check string) {
		if err == cause {
			word = check
		}
	})
	_, err := l.Prepare(ctx, api.LaunchSpec{ID: "agent", Kind: "agent"})
	if err != cause || word != "cred_bind" || raw.prepares != 0 {
		t.Fatal("binding reply refusal lost its effect check", err, word)
	}
	word = ""
	_, err = l.Launch(ctx, api.PreparedLaunch{ID: "prepared"}, api.LaunchPermit{LaunchID: "launch", PreparedID: "prepared"})
	if err != cause || word != "cred_bind" || raw.launches != 0 {
		t.Fatal("retained binding refusal lost its recovery check", err, word)
	}
}

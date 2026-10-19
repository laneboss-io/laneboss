package assembly

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type testRegistrar struct {
	calls   int
	failure error
}

func (r *testRegistrar) Register(api.Method, api.Handler) error { r.calls++; return r.failure }
func (r *testRegistrar) RegisterStream(api.Method, api.StreamHandler) error {
	r.calls++
	return r.failure
}

func TestRegistrationAuthority(t *testing.T) {
	target := &testRegistrar{}
	registry := &catalogRegistrar{target: target, owner: "lb-v2-integrate", seen: make(map[api.Method]bool), streams: make(map[api.Method]bool)}
	handler := func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
		return nil, api.NotImplemented("fixture", "call")
	}
	for _, method := range []api.Method{"lane.start", "execute.arbitrary"} {
		if err := registry.Register(method, handler); err == nil {
			t.Fatal("unowned or unknown method was registered")
		}
	}
	if target.calls != 0 {
		t.Fatal("invalid registration reached transport")
	}
	if err := registry.Register("records.query", handler); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("records.query", handler); err == nil {
		t.Fatal("duplicate method was registered")
	}
	if target.calls != 1 {
		t.Fatal("duplicate registration reached transport")
	}
}

func TestRegistrationPropagatesFailure(t *testing.T) {
	sentinel := &api.Error{Code: api.CodeUnavailable, Message: "fixture registration failure"}
	target := &testRegistrar{failure: sentinel}
	registry := &catalogRegistrar{target: target, owner: "lb-v2-integrate", seen: make(map[api.Method]bool)}
	handler := func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) { return nil, sentinel }
	if err := registry.Register("records.get", handler); !errors.Is(err, sentinel) {
		t.Fatal("registration error was swallowed")
	}
	if err := registerModules(&testRegistrar{}, nil); err == nil {
		t.Fatal("missing modules produced a complete server")
	}
}

func TestInstallationRejectsDrift(t *testing.T) {
	installed := Installation{Schema: "laneboss.service-install.v2", Config: "demo", ServiceUID: 1001,
		ArtifactSHA256: api.Digest(strings.Repeat("1", 64)), BindingFile: "/etc/laneboss/binding.json",
		StateDirectory: "/srv/laneboss/state", SecretDirectory: "/srv/laneboss/secrets",
		Socket: "/run/laneboss/demo/control.sock", SecretKeyHandle: "key-one", JudgeEndpoint: "http://127.0.0.1:9000/v1/systemone",
		Judge:           api.JudgeConfig{DeploymentSHA256: api.Digest(strings.Repeat("3", 64)), TokenizerSHA256: api.Digest(strings.Repeat("4", 64)), ContextTokens: 8192},
		RuntimeManifest: api.BlobRef{ID: "runtime", Class: "manifest", Bytes: 17, SHA256: api.Digest(strings.Repeat("2", 64))}}
	if err := validateInstallation(installed, Options{Config: "demo"}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Installation){
		"root owner":         func(i *Installation) { i.ServiceUID = 0 },
		"negative inference": func(i *Installation) { i.PolicyMaxCostMicros = -1 },
		"overflow inference": func(i *Installation) { i.PolicyMaxCostMicros = 1 << 53 },
		"wrong config":       func(i *Installation) { i.Config = "another" },
		"overlap":            func(i *Installation) { i.SecretDirectory = i.StateDirectory + "/private" },
		"relative":           func(i *Installation) { i.StateDirectory = "state" },
		"third provider":     func(i *Installation) { i.Judge.Provider = "hosted" },
		"wrong model":        func(i *Installation) { i.Judge.Model = "unrelated/model" },
		"missing pins":       func(i *Installation) { i.Judge.DeploymentSHA256 = "" },
		"empty alternative model": func(i *Installation) {
			i.Judge.Provider, i.Judge.Model, i.JudgeCredentialHandle = "typesafe", "", "credential"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := installed
			mutate(&changed)
			if err := validateInstallation(changed, Options{Config: "demo"}); err == nil {
				t.Fatal("invalid installation was accepted")
			}
		})
	}
}

func TestJudgePolicySelectsEnrolledProvider(t *testing.T) {
	clef := api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel,
		DeploymentSHA256: api.Digest(strings.Repeat("1", 64)), TokenizerSHA256: api.Digest(strings.Repeat("2", 64)), ContextTokens: 8192}
	alternative := api.JudgeConfig{Provider: "typesafe", Model: "typesafe/jev-explicit"}
	installed := Installation{Judge: alternative, JudgeEndpoint: "https://judge.example.invalid/v1", JudgeCredentialHandle: "credential",
		JudgeAlternative: &JudgeInstallation{Config: clef, Endpoint: "http://127.0.0.1:9000/v1/systemone"}}
	adapter := &installedJudge{provider: api.DefaultJudgeProvider, installation: installed}
	got, err := adapter.resolve(clef)
	if err != nil || got.Endpoint != installed.JudgeAlternative.Endpoint || got.Config != clef {
		t.Fatal("boot ordering overrode the policy's Clef selection")
	}
	adapter.provider = "typesafe"
	got, err = adapter.resolve(alternative)
	if err != nil || got.Endpoint != installed.JudgeEndpoint || got.CredentialHandle != installed.JudgeCredentialHandle || got.Config != alternative {
		t.Fatal("D6-selected alternative did not resolve its own enrolled endpoint")
	}
	adapter.provider = api.DefaultJudgeProvider
	adapter.installation.JudgeAlternative = nil
	_, err = adapter.resolve(clef)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite {
		t.Fatal("absent approved endpoint fell back to the installed alternative")
	}
	adapter.installation = installed
	changed := clef
	changed.DeploymentSHA256 = api.Digest(strings.Repeat("3", 64))
	_, err = adapter.resolve(changed)
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite {
		t.Fatal("deployment pin mismatch selected an enrolled provider")
	}
}

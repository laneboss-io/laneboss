package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type probeEvidenceFixture struct {
	calls  int
	err    error
	result api.IsolationCapabilities
}

func (f *probeEvidenceFixture) IsolationEvidence(ctx context.Context) (api.IsolationCapabilities, error) {
	f.calls++
	if err := ctx.Err(); err != nil {
		return api.IsolationCapabilities{}, err
	}
	return f.result, f.err
}

func TestProbeEvidencePort(t *testing.T) {
	failure := &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-admin", Message: "fixture native control failed"}
	// Declared component evidence; this test claims no native isolation pass.
	provider := &probeEvidenceFixture{err: failure, result: api.IsolationCapabilities{Backend: "linux-bwrap-landlock",
		Kernel: "component-kernel", LandlockABI: 3,
		Checks: []api.Capability{{Name: "native-control", Reason: "fixture refuses missing native evidence"}}}}
	server := &Server{deps: Dependencies{IsolationEvidence: provider}, verified: true, controller: "component-controller", options: Options{Config: "component-probe"}}
	observed, err := server.Probe(context.Background())
	if err != failure || provider.calls != 1 || !reflect.DeepEqual(observed, provider.result) {
		t.Fatal("acceptance: service probe invented or discarded independent evidence")
	}
	provider.err = nil
	provider.result.Kernel = "different-component-kernel"
	provider.result.LandlockABI++
	observed, err = server.Probe(context.Background())
	if err != nil || provider.calls != 2 || !reflect.DeepEqual(observed, provider.result) || observed.Available {
		t.Fatal("service probe replaced unavailable measured evidence with availability")
	}
	provider.result.Checks[0].Available = true
	provider.result.Available = provider.result.Checks[0].Available
	observed, err = server.Probe(context.Background())
	if err != nil || provider.calls != 3 || !reflect.DeepEqual(observed, provider.result) {
		t.Fatal("service probe changed the independent provider's successful result")
	}
	server.deps.IsolationEvidence = nil
	_, err = server.Probe(context.Background())
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" {
		t.Fatal("missing independent evidence did not retain its owner")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server.deps.IsolationEvidence = provider
	_, err = server.Probe(ctx)
	if !errors.As(err, &typed) || typed.Code != api.CodeCancelled || provider.calls != 3 {
		t.Fatal("cancelled service probe entered the evidence provider")
	}
}

func TestProbeInstalledScope(t *testing.T) {
	for _, state := range []string{"unverified", "missing-controller", "closed"} {
		t.Run(state, func(t *testing.T) {
			provider := &probeEvidenceFixture{}
			server := &Server{deps: Dependencies{IsolationEvidence: provider}, verified: true, controller: "component-controller"}
			switch state {
			case "unverified":
				server.verified = false
			case "missing-controller":
				server.controller = ""
			case "closed":
				server.closed = true
			}
			_, err := server.Probe(context.Background())
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Owner != "lb-v2-service" || typed.Code != api.CodePrerequisite || provider.calls != 0 {
				t.Fatal("unready service host entered the independent isolation provider", err)
			}
		})
	}
}

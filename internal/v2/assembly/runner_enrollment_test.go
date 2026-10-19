package assembly

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type enrollmentRunnerFixture struct{ starts int }

func (f *enrollmentRunnerFixture) Start(_ context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	f.starts++
	session := request.Session
	if session.VendorVersion == "" {
		session.VendorVersion = request.Executable.Version
	}
	return api.RunnerPlan{Driver: api.DriverCodex, Executable: request.Executable, CWD: "/work/main", Home: request.Home,
		Prompt: request.Prompt, Slot: request.Slot, Session: session}, nil
}
func (*enrollmentRunnerFixture) Resume(context.Context, api.RunnerRequest) (api.RunnerPlan, error) {
	return api.RunnerPlan{}, nil
}
func (*enrollmentRunnerFixture) Turn(context.Context, api.RunnerRequest) (api.RunnerPlan, error) {
	return api.RunnerPlan{}, nil
}
func (*enrollmentRunnerFixture) SessionFromCapture(context.Context, api.CaptureRecord) (api.Session, error) {
	return api.Session{}, nil
}
func (*enrollmentRunnerFixture) LimitFromCapture(context.Context, api.CaptureRecord, api.ProcessObservation) (*api.LimitSignal, error) {
	return nil, nil
}

func enrollmentRunnerRequest() api.RunnerRequest {
	return api.RunnerRequest{
		Target:     api.LifeRef{LifeID: "enrolled-life", Run: 1},
		Session:    api.Session{Driver: api.DriverCodex, VendorVersion: "codex-v1", HomeID: "home", HistoryID: "history", LogicalCWD: "/work/main"},
		Home:       api.PrivateHome{ID: "home", WorkspaceID: "workspace", HistoryID: "history"},
		Executable: api.Executable{ID: "codex", SHA256: api.Digest(strings.Repeat("b", 64)), Version: "codex-v1"},
		Prompt:     api.BlobRef{ID: "prompt", Class: "prompt", Bytes: 1, SHA256: api.Digest(strings.Repeat("a", 64))},
		Slot:       api.CredentialSlot{ID: "slot", LeaseID: "slot-lease", ProfileGrantID: "profile-grant", ProfileID: "profile", ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))},
	}
}

func TestRunnerEnrollmentGuard(t *testing.T) {
	fixture := &enrollmentRunnerFixture{}
	missing := guardRunnerEnrollment(fixture, Installation{}, api.DriverCodex, runnerDependencies{})
	var typed *api.Error
	if _, err := missing.Start(context.Background(), enrollmentRunnerRequest()); !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || fixture.starts != 0 {
		t.Fatalf("missing enrollment reached the runner or lost its typed prerequisite: %v", err)
	}
	valid := guardRunnerEnrollment(fixture, Installation{LaunchEnrollment: &api.BlobRef{ID: "launch-enrollment", Class: "manifest", Bytes: 1, SHA256: api.Digest(strings.Repeat("c", 64))}}, api.DriverCodex, runnerDependencies{})
	if _, err := valid.Start(context.Background(), enrollmentRunnerRequest()); !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || fixture.starts != 0 {
		t.Fatalf("enrollment shape bypassed missing protected ports: %v", err)
	}
	foreign := enrollmentRunnerRequest()
	foreign.Session.Driver = api.DriverClaudock
	if _, err := valid.Start(context.Background(), foreign); !errors.As(err, &typed) || typed.Code != api.CodeForbidden || fixture.starts != 0 {
		t.Fatalf("foreign driver reached the adapter or lost its typed refusal: %v", err)
	}
}

func TestRunnerNeedsAuthority(t *testing.T) {
	fixture := &enrollmentRunnerFixture{}
	runner := guardRunnerEnrollment(fixture, Installation{LaunchEnrollment: &api.BlobRef{ID: "launch-enrollment", Class: "manifest", Bytes: 1, SHA256: api.Digest(strings.Repeat("c", 64))}}, api.DriverCodex, runnerDependencies{})
	_, err := runner.Start(context.Background(), enrollmentRunnerRequest())
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || fixture.starts != 0 {
		t.Fatal("request-shaped enrollment reached the adapter without protected run authority", err)
	}
}

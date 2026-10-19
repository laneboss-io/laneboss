package box

import (
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
)

func TestDryRunLines(t *testing.T) {
	cases := []struct {
		name string
		dry  *boxcore.DryResult
		code int
		want string
	}{
		{"allowed", &boxcore.DryResult{Allowed: true}, 0, "dryrun: allowed\n"},
		{"denied", &boxcore.DryResult{Code: "DemoDenied"}, 6, "dryrun: denied DemoDenied\n"},
		{"unexpected", nil, 7, "dryrun: denied unexpected\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixture(t)
			h.svc.launch = boxcore.LaunchResult{Dry: tc.dry, ExitCode: tc.code}
			code := h.call("launch", "--purpose", "demo", "--dry-run")
			if code != tc.code || h.out.String() != tc.want || len(h.svc.launches) != 1 || !h.svc.launches[0].DryRun {
				t.Fatalf("dry run: code=%d stdout=%q options=%+v", code, h.out.String(), h.svc.launches)
			}
		})
	}
}

func fullRun() boxcore.RunResult {
	return boxcore.RunResult{
		RunID: "run-demo", Box: boxcore.Box{ID: "i-demo1"}, SuiteExit: 1, Verdict: "failed",
		OutDir: "/tmp/demo-results", Files: 3, Bytes: 256, ManifestSHA256: "demo-manifest",
		Terminated: true, BilledSeconds: 65, CostUSD: 0.012345, ExitCode: 1,
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestOutputFailure(t *testing.T) {
	h := newFixture(t)
	h.svc.run = fullRun()
	code := run([]string{"run", "--box-config", h.file, "--purpose", "demo", "--suite", "exit 0"},
		strings.NewReader(""), failedWriter{}, &h.notes, h.env,
		func(*boxcore.Config, buildDeps) (boxcore.Service, error) { return h.svc, nil })
	if code != 70 || !strings.Contains(h.notes.String(), "the output cannot be written") || len(h.svc.runs) != 1 {
		t.Fatalf("write failure: code=%d stderr=%q", code, h.notes.String())
	}
}

func TestServiceFailure(t *testing.T) {
	for _, serviceCode := range []int{0, 11} {
		h := newFixture(t)
		h.svc.run = boxcore.RunResult{SuiteExit: -1, ExitCode: serviceCode}
		h.svc.err = errors.New("SECRET-NEEDLE")
		code := h.call("run", "--purpose", "demo", "--suite", "exit 0")
		want := serviceCode
		if want == 0 {
			want = 70
		}
		if code != want || h.notes.Len() == 0 || strings.Contains(h.notes.String(), "SECRET-NEEDLE") {
			t.Fatalf("service failure: code=%d stderr=%q", code, h.notes.String())
		}
		if serviceCode == 0 && h.out.String() != "exit=70 (internal)\n" {
			t.Fatalf("service error reported success: %q", h.out.String())
		}
	}
}

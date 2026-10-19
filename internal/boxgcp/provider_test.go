package boxgcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestPrepare rejects extra probes, wrong zones and unclassified identity failures.
func TestPrepare(t *testing.T) {
	for _, text := range []string{"", "PERMISSION_DENIED", "Failed to impersonate",
		"iam.serviceAccounts.getAccessToken", "does not have permission", "HTTPError 403"} {
		t.Run(text, func(t *testing.T) {
			cfg := testConfig()
			cfg.ImpersonateServiceAccount = "demo-launch"
			result := boxexec.Result{Stdout: []byte("discarded output"), Stderr: []byte(text)}
			if text != "" {
				result.Code = 1
			}
			f := resultFake(result, nil)
			p := New(cfg, f, testOptions())
			if p.Name() != "gcp" {
				t.Fatal("wrong provider name")
			}
			err := p.Prepare(context.Background(), testRequest())
			if text == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireKind(t, err, boxcore.KindDenied)
			}
			requireArgs(t, onlyCall(t, f).Args, []string{
				"compute", "zones", "describe", cfg.Zones[0], "--format=json",
				"--project=" + cfg.Project, "--quiet", "--impersonate-service-account=" +
					cfg.ImpersonateServiceAccount + "@" + cfg.Project + ".iam.gserviceaccount.com",
			})
		})
	}
	t.Run("runner-error", func(t *testing.T) {
		cause := errors.New("gcloud compute zones describe hidden-target")
		f := resultFake(boxexec.Result{Code: -1}, cause)
		err := New(testConfig(), f, testOptions()).Prepare(context.Background(), testRequest())
		if err == nil || !errors.Is(err, cause) || strings.Contains(err.Error(), "hidden-target") ||
			strings.Contains(err.Error(), "gcloud compute") {
			t.Fatal("runner failure was swallowed or argv exposed in public detail")
		}
		onlyCall(t, f)
	})
	t.Run("no-zone", func(t *testing.T) {
		cfg, f := testConfig(), &boxexec.Fake{}
		cfg.Zones = nil
		if err := New(cfg, f, testOptions()).Prepare(context.Background(), testRequest()); err == nil || len(f.Calls) != 0 {
			t.Fatal("missing zones reached the runner")
		}
	})
}

// TestDryRun rejects creates, omitted image checks and swallowed non-denial failures.
func TestDryRun(t *testing.T) {
	cases := []struct {
		name, arch, text string
		failAt, calls    int
		kind             boxcore.ErrorKind
		denied           bool
	}{
		{"x86-allowed", "x86", "", -1, 2, boxcore.KindOther, false},
		{"arm-allowed", "arm64", "", -1, 2, boxcore.KindOther, false},
		{"machine-denied", "x86", "Failed to impersonate", 0, 1, boxcore.KindDenied, true},
		{"image-denied", "arm64", "PERMISSION_DENIED", 1, 2, boxcore.KindDenied, true},
		{"capacity", "x86", "ZONE_RESOURCE_POOL_EXHAUSTED", 0, 1, boxcore.KindCapacity, false},
		{"quota", "x86", "QUOTA_EXCEEDED", 1, 2, boxcore.KindQuota, false},
		{"other", "arm64", "demo failure", 1, 2, boxcore.KindOther, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, c := testConfig(), testCandidate()
			c.Arch = tc.arch
			cfg.ImpersonateServiceAccount = "demo-launch"
			f := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "gcloud",
				Respond: func(_ boxexec.Cmd, intCall int) (boxexec.Result, error) {
					if intCall == tc.failAt {
						return boxexec.Result{Code: 1, Stderr: []byte(tc.text)}, nil
					}
					return boxexec.Result{}, nil
				},
			}}}
			got, err := New(cfg, f, testOptions()).DryRun(context.Background(), testRequest(), c, testGuest())
			if tc.denied {
				if err != nil || got.Allowed || got.Code != "PERMISSION_DENIED" {
					t.Fatal("denial was not returned as a dry result")
				}
			} else if tc.failAt >= 0 {
				requireKind(t, err, tc.kind)
				if got.Allowed {
					t.Fatal("failed check was allowed")
				}
			} else if err != nil || !got.Allowed {
				t.Fatal("both successful describes were not allowed")
			}
			if len(f.Calls) != tc.calls {
				t.Fatal("dry run made extra calls or omitted a check")
			}
			impersonate := "--impersonate-service-account=" + cfg.ImpersonateServiceAccount + "@" + cfg.Project + ".iam.gserviceaccount.com"
			requireArgs(t, f.Calls[0].Args, []string{
				"compute", "machine-types", "describe", c.Type, "--zone=" + c.Zone,
				"--format=json", "--project=" + cfg.Project, "--quiet", impersonate,
			})
			if tc.calls == 2 {
				family := "demo-x86"
				if tc.arch == "arm64" {
					family = "demo-arm"
				}
				requireArgs(t, f.Calls[1].Args, []string{
					"compute", "images", "describe-from-family", family, "--format=json",
					"--project=" + cfg.ImageProject, "--quiet", impersonate,
				})
			}
		})
	}
}

package boxgcp

import (
	"context"
	"slices"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestIdentityEnv rejects inherited credentials and any identity or firewall setup call.
func TestIdentityEnv(t *testing.T) {
	for _, key := range []string{
		"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "GOOGLE_OTHER",
		"CLOUDSDK_CORE_PROJECT", "CLOUDSDK_CORE_DISABLE_PROMPTS", "CLOUDSDK_CONFIG",
		"CLOUDSDK_ACTIVE_CONFIG_NAME", "CLOUDSDK_PYTHON", "CLOUDSDK_AUTH_ACCESS_TOKEN", "DEMO_UNRELATED",
	} {
		t.Setenv(key, "caller-value")
	}
	for _, configured := range []bool{false, true} {
		name := "minimal"
		if configured {
			name = "configured"
		}
		t.Run(name, func(t *testing.T) {
			cfg, o := testConfig(), testOptions()
			wantSDK := map[string]string{
				"CLOUDSDK_CORE_PROJECT": cfg.Project, "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
			}
			if configured {
				cfg.GcloudConfigDir, cfg.GcloudConfiguration = "/demo/config", "demo-profile"
				cfg.ImpersonateServiceAccount = "demo-launch"
				wantSDK["CLOUDSDK_CONFIG"] = cfg.GcloudConfigDir
				wantSDK["CLOUDSDK_ACTIVE_CONFIG_NAME"] = cfg.GcloudConfiguration
				wantSDK["CLOUDSDK_PYTHON"] = "demo-python"
			}
			o.Getenv = func(key string) string {
				if key != "CLOUDSDK_PYTHON" {
					t.Fatal("provider read a caller variable beyond CLOUDSDK_PYTHON")
				}
				if configured {
					return "demo-python"
				}
				return ""
			}
			row := instanceJSON(t, "lb-box-1", "RUNNING", map[string]string{
				"managed-by": "laneboss", "lb-org": "example-org", "lb-owner": "demo-owner",
				"lb-lane": "demo-lane", "lb-run": "demo-run",
			}, "")
			f := &boxexec.Fake{Handlers: []boxexec.Handler{
				{Name: "gcloud", ArgsContain: []string{"instances create"}, Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					return boxexec.Result{Stdout: arrayJSON(row)}, nil
				}},
				{Name: "gcloud", ArgsContain: []string{"instances describe"}, Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					return boxexec.Result{Stdout: row}, nil
				}},
				{Name: "gcloud", ArgsContain: []string{"instances list"}, Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					return boxexec.Result{Stdout: arrayJSON(row)}, nil
				}},
				{Name: "gcloud"},
			}}
			p, ctx := New(cfg, f, o), context.Background()
			if err := p.Prepare(ctx, testRequest()); err != nil {
				t.Fatal(err)
			}
			if got, err := p.DryRun(ctx, testRequest(), testCandidate(), testGuest()); err != nil || !got.Allowed {
				t.Fatal("dry run failed")
			}
			if _, err := p.Launch(ctx, testRequest(), testCandidate(), testGuest()); err != nil {
				t.Fatal(err)
			}
			if _, err := p.WaitRunning(ctx, testBox()); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Describe(ctx, testBox()); err != nil {
				t.Fatal(err)
			}
			if err := p.Teardown(ctx, testBox()); err != nil {
				t.Fatal(err)
			}
			if _, err := p.List(ctx, boxcore.ListFilter{Org: o.Org}); err != nil {
				t.Fatal(err)
			}
			if count, err := p.FetchHarvest(ctx, testBox(), "run-1", t.TempDir()); err != nil || count != 0 {
				t.Fatal("empty fake harvest failed")
			}
			if code, err := p.Transport(testBox(), boxcore.TransportOptions{}).Exec(ctx, "echo demo", nil, nil, nil); err != nil || code != 0 {
				t.Fatal("fake transport failed")
			}
			// The harvest and the first command each read the machine through the fence before they act.
			if len(f.Calls) != 13 {
				t.Fatal("provider made unexpected identity or configuration calls")
			}
			for _, call := range f.Calls {
				if call.Name != "gcloud" || !slices.Contains(call.Args, "--quiet") {
					t.Fatal("child is not a quiet gcloud call")
				}
				project := cfg.Project
				if slices.Contains(call.Args, "images") {
					project = cfg.ImageProject
				}
				if got, ok := argValue(t, call.Args, "--project"); !ok || got != project {
					t.Fatal("child project flag is wrong")
				}
				got, ok := argValue(t, call.Args, "--impersonate-service-account")
				if ok != configured || configured && got != "demo-launch"+"@"+cfg.Project+".iam.gserviceaccount.com" {
					t.Fatal("impersonation flag is missing, unexpected or wrong")
				}
				argv := strings.ToLower(strings.Join(call.Args, " "))
				// The launch metadata blocks the project's own ssh keys; that exact key is the only mention of ssh keys allowed,
				// every other one (a key pushed to the project, to a machine or to a login profile) is still forbidden.
				argv = strings.ReplaceAll(argv, "block-project-ssh-keys=true", "")
				for _, forbidden := range []string{"auth", "application-default", "activate-service-account",
					"config set", "firewall", "ssh-keys", "add-metadata", "os-login"} {
					if strings.Contains(argv, forbidden) {
						t.Fatalf("forbidden operation recorded: %s", forbidden)
					}
				}
				seenSDK := map[string]bool{}
				seen := map[string]bool{}
				for _, item := range call.Env {
					key, value, ok := strings.Cut(item, "=")
					if !ok || seen[key] {
						t.Fatal("child env contains invalid or duplicate entries")
					}
					seen[key] = true
					if strings.HasPrefix(key, "GOOGLE_") {
						t.Fatal("child inherited GOOGLE credentials")
					}
					if strings.HasPrefix(key, "CLOUDSDK_") {
						want, allowed := wantSDK[key]
						if !allowed || value != want {
							t.Fatalf("unexpected or wrong SDK variable: %s", key)
						}
						seenSDK[key] = true
					} else if !slices.Contains([]string{"PATH", "HOME", "TMPDIR", "LANG", "TERM"}, key) {
						t.Fatalf("child inherited unrelated variable: %s", key)
					}
				}
				if len(seenSDK) != len(wantSDK) {
					t.Fatal("child env omitted a required SDK variable")
				}
			}
		})
	}
}

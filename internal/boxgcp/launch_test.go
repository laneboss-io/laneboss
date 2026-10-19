package boxgcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestLaunchArgv rejects dropped Spot, cap, labels, identity and network flags.
func TestLaunchArgv(t *testing.T) {
	cases := []struct {
		name, arch, network, subnet string
		notice, hard, root          int
		external, impersonate       bool
		tags                        []string
	}{
		{"defaults", "x86", "", "", 0, 7, 23, false, false, nil},
		{"private-arm", "arm64", "demo-net", "demo-sub", 120, 13, 41, false, true, []string{"demo-iap", "demo-tag"}},
		{"external", "x86", "demo-net", "demo-sub", 0, 31, 19, true, true, nil},
		{"other-notice", "arm64", "", "", 60, 4, 17, true, false, []string{"demo-iap"}},
		{"no-subnet", "x86", "demo-net", "", 0, 9, 21, true, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, req, c := testConfig(), testRequest(), testCandidate()
			cfg.Network, cfg.Subnetwork, cfg.ExternalIP = tc.network, tc.subnet, tc.external
			cfg.NetworkTags, cfg.PreemptionNoticeSec = tc.tags, tc.notice
			if tc.impersonate {
				cfg.ImpersonateServiceAccount = "demo-launch"
			}
			req.HardMin, req.RootGB, c.Arch = tc.hard, tc.root, tc.arch
			row := instanceJSON(t, "lb-box-1", "PROVISIONING", nil, "127.0.0.1")
			f := resultFake(boxexec.Result{Stdout: arrayJSON(row)}, nil)
			b, err := New(cfg, f, testOptions()).Launch(context.Background(), req, c, testGuest())
			if err != nil {
				t.Fatal(err)
			}
			call := onlyCall(t, f)
			scripts, found := argValue(t, call.Args, "--metadata-from-file")
			if !found || len(strings.Split(scripts, ",")) != 2 {
				t.Fatal("missing both script file arguments")
			}
			family := "demo-x86"
			if tc.arch == "arm64" {
				family = "demo-arm"
			}
			wantLabels := "--labels=managed-by=laneboss,lb-org=example-org," +
				"lb-owner=demo-owner,lb-lane=demo_lane," + "lb-run=run-one_2,lb-purpose=demo-purpose"
			want := []string{
				"compute", "instances", "create", "lb-demo-purpose-run-one-2",
				"--zone=" + c.Zone, "--machine-type=" + c.Type,
				"--provisioning-model=SPOT", "--instance-termination-action=DELETE",
				fmt.Sprintf("--max-run-duration=%dm", tc.hard),
				"--image-family=" + family, "--image-project=" + cfg.ImageProject,
				fmt.Sprintf("--boot-disk-size=%dGB", tc.root), "--boot-disk-type=" + cfg.BootDiskType,
				"--service-account=" + cfg.BoxServiceAccount + "@" + cfg.Project + ".iam.gserviceaccount.com",
				"--scopes=storage-rw", wantLabels,
			}
			if tc.notice == 120 {
				want = append([]string{"beta"}, want...)
				want = append(want, "--preemption-notice-duration=120s")
			}
			if len(tc.tags) > 0 {
				want = append(want, "--tags="+strings.Join(tc.tags, ","))
			}
			if tc.network != "" {
				value := "--network-interface=network=" + tc.network
				if tc.subnet != "" {
					value += ",subnet=" + tc.subnet
				}
				if !tc.external {
					value += ",no-address"
				}
				want = append(want, value)
			}
			want = append(want,
				"--metadata=enable-oslogin=TRUE,"+"block-project-ssh-keys=TRUE,"+"enable-guest-attributes=TRUE,lb-run-id="+req.RunID,
				"--metadata-from-file="+scripts, "--format=json", "--project="+cfg.Project, "--quiet")
			if tc.impersonate {
				want = append(want, "--impersonate-service-account="+
					cfg.ImpersonateServiceAccount+"@"+cfg.Project+".iam.gserviceaccount.com")
			}
			requireArgs(t, call.Args, want)
			labels := map[string]string{
				"managed-by": "laneboss", "lb-org": "example-org", "lb-owner": "demo-owner",
				"lb-lane": "demo_lane", "lb-run": "run-one_2", "lb-purpose": "demo-purpose",
			}
			if b.Provider != "gcp" || b.ID != "lb-box-1" || b.Name != "lb-box-1" ||
				b.Type != "demo-small" || b.Zone != "demo-zone-a" || b.Region != cfg.Region ||
				b.Project != cfg.Project || b.Image != family || b.Address != "127.0.0.1" ||
				b.LaunchTimeUTC != "2026-10-14T12:46:15Z" || b.QuoteUSDHour != c.PriceUSDHour ||
				!reflect.DeepEqual(b.Labels, labels) {
				t.Fatal("launch did not parse instance fields or retain launch labels")
			}
		})
	}
}

// TestLaunchScripts rejects incorrect contents, permissions and leaked temp files.
func TestLaunchScripts(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			guest := testGuest()
			var scriptDir string
			f := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "gcloud", ArgsContain: []string{"instances create"},
				Respond: func(cmd boxexec.Cmd, n int) (boxexec.Result, error) {
					value, found := argValue(t, cmd.Args, "--metadata-from-file")
					if !found {
						t.Fatal("no script file metadata")
					}
					paths := map[string]string{}
					for _, item := range strings.Split(value, ",") {
						key, path, ok := strings.Cut(item, "=")
						if !ok || paths[key] != "" {
							t.Fatal("invalid script file metadata")
						}
						paths[key] = path
					}
					if len(paths) != 2 || paths["startup-script"] == paths["shutdown-script"] {
						t.Fatal("script metadata must name two different files")
					}
					for key, want := range map[string]string{"startup-script": guest.Startup, "shutdown-script": guest.Shutdown} {
						path := paths[key]
						data, err := os.ReadFile(path)
						if err != nil || string(data) != want {
							t.Fatal("script bytes differ from the guest input")
						}
						info, err := os.Stat(path)
						if err != nil || info.Mode().Perm() != 0600 {
							t.Fatal("script mode is not 0600")
						}
						dir := filepath.Dir(path)
						if scriptDir != "" && scriptDir != dir {
							t.Fatal("scripts do not share a fresh directory")
						}
						scriptDir = dir
					}
					info, err := os.Stat(scriptDir)
					if err != nil || info.Mode().Perm() != 0700 {
						t.Fatal("script directory mode is not 0700")
					}
					if fail {
						return boxexec.Result{Code: 1, Stderr: []byte("QUOTA_EXCEEDED")}, nil
					}
					return boxexec.Result{Stdout: arrayJSON(instanceJSON(t, "lb-box-1", "PROVISIONING", nil, ""))}, nil
				},
			}}}
			_, err := New(testConfig(), f, testOptions()).Launch(context.Background(), testRequest(), testCandidate(), guest)
			if fail {
				requireKind(t, err, boxcore.KindQuota)
			} else if err != nil {
				t.Fatal(err)
			}
			onlyCall(t, f)
			if scriptDir == "" {
				t.Fatal("fake never inspected scripts")
			}
			if _, err := os.Stat(scriptDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("script directory survived launch return")
			}
		})
	}
}

// TestLaunchValidation rejects removed input guards before any child runs.
func TestLaunchValidation(t *testing.T) {
	for _, field := range []string{"owner", "lane", "purpose", "hard", "startup", "shutdown"} {
		t.Run(field, func(t *testing.T) {
			req, guest := testRequest(), testGuest()
			bad := "invalid,value"
			switch field {
			case "owner":
				req.Owner = bad
			case "lane":
				req.Lane = bad
			case "purpose":
				req.Purpose = bad
			case "hard":
				req.HardMin = 0
			case "startup":
				guest.Startup = ""
			case "shutdown":
				guest.Shutdown = ""
			}
			f := &boxexec.Fake{}
			_, err := New(testConfig(), f, testOptions()).Launch(context.Background(), req, testCandidate(), guest)
			if err == nil || len(f.Calls) != 0 || strings.Contains(err.Error(), bad) {
				t.Fatal("invalid input reached a child or leaked its value")
			}
			if field == "owner" || field == "lane" || field == "purpose" {
				if !strings.Contains(err.Error(), field) {
					t.Fatal("validation error does not name its field")
				}
			}
		})
	}
}

// TestLaunchRefusals rejects quota retries and lost capacity classification.
func TestLaunchRefusals(t *testing.T) {
	cases := []struct {
		text string
		kind boxcore.ErrorKind
	}{
		{"ZONE_RESOURCE_POOL_EXHAUSTED", boxcore.KindCapacity},
		{"QUOTA_EXCEEDED", boxcore.KindQuota},
		{"Failed to impersonate", boxcore.KindDenied},
	}
	for _, tc := range cases {
		t.Run(tc.kind.String(), func(t *testing.T) {
			f := resultFake(boxexec.Result{Code: 1, Stderr: []byte(tc.text)}, nil)
			_, err := New(testConfig(), f, testOptions()).Launch(context.Background(), testRequest(), testCandidate(), testGuest())
			requireKind(t, err, tc.kind)
			onlyCall(t, f)
		})
	}
}

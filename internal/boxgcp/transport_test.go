package boxgcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestTransport rejects lost IAP flags, split commands, streams and exit semantics.
func TestTransport(t *testing.T) {
	cases := []struct {
		name               string
		status             int
		known, impersonate bool
		runnerError        bool
	}{
		{"success", 0, true, true, false},
		{"remote-exit", 7, false, false, false},
		{"tunnel-exit", 255, true, false, false},
		{"runner-error", 0, false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			if tc.impersonate {
				cfg.ImpersonateServiceAccount = "demo-launch"
			}
			opts := boxcore.TransportOptions{}
			if tc.known {
				opts.KnownHostsFile = filepath.Join(t.TempDir(), "known_hosts")
			}
			command := "printf '%s' 'demo value'\nprintf done"
			cause := errors.New("runner failure with hidden command text")
			f := &boxexec.Fake{Handlers: []boxexec.Handler{ownedHandler(t), {Name: "gcloud", ArgsContain: []string{"compute ssh"},
				Respond: func(cmd boxexec.Cmd, n int) (boxexec.Result, error) {
					if cmd.Stdin == nil {
						t.Fatal("stdin was not forwarded")
					}
					data, err := io.ReadAll(cmd.Stdin)
					if err != nil || string(data) != "demo stdin" {
						t.Fatal("runner could not read the original stdin")
					}
					result := boxexec.Result{Code: tc.status, Stdout: []byte("demo stdout"), Stderr: []byte("demo stderr")}
					if tc.runnerError {
						return result, cause
					}
					return result, nil
				},
			}}}
			var stdout, stderr bytes.Buffer
			code, err := New(cfg, f, testOptions()).Transport(testBox(), opts).Exec(context.Background(),
				command, strings.NewReader("demo stdin"), &stdout, &stderr)
			if tc.status == 255 || tc.runnerError {
				requireKind(t, err, boxcore.KindTransport)
				if code != -1 || strings.Contains(err.Error(), command) || strings.Contains(err.Error(), "hidden command text") {
					t.Fatal("transport failure has wrong exit status or exposed command text")
				}
				if tc.runnerError && !errors.Is(err, cause) {
					t.Fatal("transport discarded the runner cause")
				}
			} else if err != nil || code != tc.status {
				t.Fatal("remote command status was converted into a transport error")
			}
			if stdout.String() != "demo stdout" || stderr.String() != "demo stderr" {
				t.Fatal("stdout or stderr was not forwarded")
			}
			// The fence reads the machine first; the command follows it.
			requireVerbs(t, f, "describe", "ssh")
			call := f.Calls[1]
			if call.Stdin != "demo stdin" {
				t.Fatal("fake did not record stdin")
			}
			want := []string{
				"compute", "ssh", "lb-box-1", "--zone=demo-zone-a", "--tunnel-through-iap",
				"--strict-host-key-checking=no", "--ssh-flag=-T", "--command=" + command,
			}
			if tc.known {
				want = append(want, "--ssh-flag=-oUserKnownHostsFile="+opts.KnownHostsFile)
			}
			want = append(want, "--project="+cfg.Project, "--quiet")
			if tc.impersonate {
				want = append(want, "--impersonate-service-account="+
					cfg.ImpersonateServiceAccount+"@"+cfg.Project+".iam.gserviceaccount.com")
			}
			requireArgs(t, call.Args, want)
		})
	}
}

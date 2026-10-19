package boxaws

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func TestTransportArgv(t *testing.T) {
	for _, hosts := range []string{"/tmp/lb-sp-aws-demo-hosts", ""} {
		t.Run(strconv.Itoa(len(hosts)), func(t *testing.T) {
			cfg := demoConfig()
			cfg.SSHUser += "-" + strconv.Itoa(len(hosts))
			cfg.SSHIdentity += "-" + strconv.Itoa(len(hosts))
			b := boxcore.Box{ID: "i-demo1", Address: "127.0.0.1"}
			if hosts != "" {
				b.Address = strings.Join([]string{"192", "0", "2", "9"}, ".")
			}
			command, input := "printf '%s' 'two words'; exit 7", "stdin-demo\n"
			command += " # " + strconv.Itoa(len(hosts))
			var stdout, stderr bytes.Buffer
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "ssh",
				Respond: func(c boxexec.Cmd, n int) (boxexec.Result, error) {
					if c.Stdin == nil || c.Stdout != &stdout || c.Stderr != &stderr {
						t.Fatal("SSH streams were not passed to the runner")
					}
					return boxexec.Result{Code: 7, Stdout: []byte("stdout-demo"), Stderr: []byte("stderr-demo")}, nil
				}}}}
			transport := New(cfg, fake, demoOptions()).Transport(b, boxcore.TransportOptions{KnownHostsFile: hosts})
			status, err := transport.Exec(context.Background(), command, strings.NewReader(input), &stdout, &stderr)
			if err != nil || status != 7 || stdout.String() != "stdout-demo" || stderr.String() != "stderr-demo" {
				t.Fatal("SSH status or streams differ")
			}
			call := oneCall(t, fake, "ssh")
			if call.Stdin != input {
				t.Fatal("stdin did not reach SSH")
			}
			want := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"}
			if hosts != "" {
				want = append(want, "-o", "UserKnownHostsFile="+hosts)
			}
			want = append(want, "-o", "IdentitiesOnly=yes", "-i", cfg.SSHIdentity, cfg.SSHUser+"@"+b.Address, command)
			wantArgs(t, call.Args, want)
			checkEnv(t, call.Env, nil)
		})
	}
}

func TestTransportStatus(t *testing.T) {
	for _, tc := range []struct {
		status int
		err    error
	}{{0, nil}, {1, nil}, {42, nil}, {254, nil}, {255, nil}, {0, errors.New("runner-private-demo")}} {
		t.Run(strconv.Itoa(tc.status)+"-"+strconv.FormatBool(tc.err != nil), func(t *testing.T) {
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "ssh",
				Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					return boxexec.Result{Code: tc.status}, tc.err
				}}}}
			transport := New(demoConfig(), fake, demoOptions()).Transport(boxcore.Box{Address: "127.0.0.1"}, boxcore.TransportOptions{})
			status, err := transport.Exec(context.Background(), "demo command", nil, nil, nil)
			if tc.status == 255 || tc.err != nil {
				wantKind(t, err, boxcore.KindTransport)
				if status != -1 || strings.Contains(err.Error(), "runner-private-demo") || tc.err != nil && !errors.Is(err, tc.err) {
					t.Fatal("transport failure did not preserve private cause and -1 status")
				}
			} else if err != nil || status != tc.status {
				t.Fatal("remote command status became a transport error")
			}
			if len(fake.Calls) != 1 {
				t.Fatal("SSH failure was retried")
			}
		})
	}
}

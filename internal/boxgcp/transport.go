package boxgcp

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

// fenceFresh is how long a pass of the fence covers the commands that follow it: a command sent later (the harvest after
// a long suite, a machine preempted and its name taken again) reads the live machine again first.
const fenceFresh = 30 * time.Second

type transport struct {
	p *provider
	b boxcore.Box
	o boxcore.TransportOptions

	mu     sync.Mutex
	passed time.Time // when the fence last passed for this transport's machine; zero if it has not
	denied error     // the fence's refusal, final for this transport
}

// Transport reaches an OS Login instance through the authenticated IAP tunnel.
func (p *provider) Transport(b boxcore.Box, o boxcore.TransportOptions) boxcore.Transport {
	return &transport{p: p, b: b, o: o}
}

// fenced runs the ownership fence before a command and remembers its verdict: a pass covers the commands of the next
// fenceFresh without another read, and a refusal stops every later command. A machine that is gone, or a read that
// failed, is reported for that command only, so a retry (the readiness poll) reads again.
func (t *transport) fenced(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.denied != nil {
		return t.denied
	}
	if !t.passed.IsZero() && t.p.o.Now().Sub(t.passed) < fenceFresh {
		return nil
	}
	t.passed = time.Time{}
	_, err := t.p.fence(ctx, t.b, "ssh")
	var refused refusal
	switch {
	case err == nil:
		t.passed = t.p.o.Now()
	case errors.As(err, &refused):
		t.denied = err
	case boxcore.KindOf(err) == boxcore.KindNotFound:
		err = boxcore.NewError(boxcore.KindTransport, "ssh", "", "instance not found", err)
	}
	return err
}

// Exec forwards streams and separates command exits from tunnel failures.
func (t *transport) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	args := []string{
		"compute", "ssh", instanceName(t.b), "--zone=" + t.b.Zone,
		"--tunnel-through-iap", "--strict-host-key-checking=no", "--ssh-flag=-T", "--command=" + command,
	}
	if t.o.KnownHostsFile != "" {
		args = append(args, "--ssh-flag=-oUserKnownHostsFile="+t.o.KnownHostsFile)
	}
	cmd := t.p.command(args, t.p.cfg.Project)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if t.p.run == nil {
		return -1, boxcore.NewError(boxcore.KindTransport, "ssh", "", "runner is required", nil)
	}
	if err := t.fenced(ctx); err != nil {
		return -1, err
	}
	result, err := t.p.run.Run(ctx, cmd)
	if err != nil || result.Code == 255 {
		return -1, boxcore.NewError(boxcore.KindTransport, "ssh", "", detail(string(result.Stderr)), err)
	}
	return result.Code, nil
}

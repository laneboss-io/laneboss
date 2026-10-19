package boxaws

import (
	"context"
	"os"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// Options are the parts of the world a test replaces.
type Options struct {
	Org        string                                           // Org tag value.
	NamePrefix string                                           // Name tag prefix and deletion gate.
	Getenv     func(string) string                              // Nil uses os.Getenv.
	Now        func() time.Time                                 // Nil uses time.Now.
	Sleep      func(ctx context.Context, d time.Duration) error // Nil uses a cancellable timer.
}

type provider struct {
	cfg boxcore.AWSConfig
	run boxexec.Runner
	o   Options
}

// New returns an AWS provider whose child processes all use run.
func New(cfg boxcore.AWSConfig, run boxexec.Runner, o Options) boxcore.Provider {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	return &provider{cfg: cfg, run: run, o: o}
}

func sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Name returns the provider name.
func (p *provider) Name() string { return "aws" }

// Prepare verifies the named profile and, when requested, SSH ingress.
func (p *provider) Prepare(ctx context.Context, req boxcore.Request) error {
	if _, err := p.aws(ctx, "get-caller-identity", "sts", "get-caller-identity"); err != nil {
		return err
	}
	if p.cfg.EnsureSSHIngress {
		return p.ensureIngress(ctx)
	}
	return nil
}

// FetchHarvest reports that AWS results are read over SSH.
func (p *provider) FetchHarvest(ctx context.Context, b boxcore.Box, runID, dir string) (int, error) {
	return 0, boxcore.NewError(boxcore.KindUnsupported, "fetch-harvest", "", "use the box transport", nil)
}

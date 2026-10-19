package boxgcp

import (
	"context"
	"os"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// Options are the parts of the world a test replaces.
type Options struct {
	Org        string                                           // lb-org label value
	NamePrefix string                                           // instance prefix and delete gate
	Getenv     func(string) string                              // nil uses os.Getenv
	Now        func() time.Time                                 // nil uses time.Now
	Sleep      func(ctx context.Context, d time.Duration) error // nil uses a context-aware timer
}

type provider struct {
	cfg boxcore.GCPConfig
	run boxexec.Runner
	o   Options
}

// New returns the GCP provider. run executes every child process (gcloud).
func New(cfg boxcore.GCPConfig, run boxexec.Runner, o Options) boxcore.Provider {
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
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Name identifies the provider in boxes and ledger records.
func (p *provider) Name() string { return "gcp" }

func (p *provider) env() []string {
	extra := map[string]string{
		"CLOUDSDK_CORE_PROJECT":         p.cfg.Project,
		"CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
	}
	if p.cfg.GcloudConfigDir != "" {
		extra["CLOUDSDK_CONFIG"] = p.cfg.GcloudConfigDir
	}
	if p.cfg.GcloudConfiguration != "" {
		extra["CLOUDSDK_ACTIVE_CONFIG_NAME"] = p.cfg.GcloudConfiguration
	}
	if python := p.o.Getenv("CLOUDSDK_PYTHON"); python != "" {
		extra["CLOUDSDK_PYTHON"] = python
	}
	return boxexec.CleanEnv(extra)
}

func account(id, project string) string {
	return id + "@" + project + ".iam.gserviceaccount.com"
}

func (p *provider) command(args []string, project string) boxexec.Cmd {
	args = append(args, "--project="+project, "--quiet")
	if p.cfg.ImpersonateServiceAccount != "" {
		args = append(args, "--impersonate-service-account="+
			account(p.cfg.ImpersonateServiceAccount, p.cfg.Project))
	}
	return boxexec.Cmd{Name: "gcloud", Args: args, Env: p.env()}
}

func (p *provider) invoke(ctx context.Context, op string, args []string, project string) (boxexec.Result, error) {
	if p.run == nil {
		return boxexec.Result{}, localError(op, "runner is required", nil)
	}
	result, err := p.run.Run(ctx, p.command(args, project))
	if err != nil || result.Code != 0 {
		failure := classify(op, string(result.Stderr))
		failure.Err = err
		return result, failure
	}
	return result, nil
}

// Prepare probes the configured identity against the first zone.
func (p *provider) Prepare(ctx context.Context, req boxcore.Request) error {
	if len(p.cfg.Zones) == 0 {
		return localError("prepare", "a zone is required", nil)
	}
	_, err := p.invoke(ctx, "prepare", []string{
		"compute", "zones", "describe", p.cfg.Zones[0], "--format=json",
	}, p.cfg.Project)
	return err
}

func (p *provider) family(arch string) string {
	if arch == "arm64" {
		return p.cfg.ImageFamilyArm
	}
	return p.cfg.ImageFamilyX86
}

// DryRun checks the machine type and image without creating an instance.
func (p *provider) DryRun(ctx context.Context, req boxcore.Request, c boxcore.Candidate, g boxcore.Guest) (boxcore.DryResult, error) {
	checks := []struct {
		args    []string
		project string
	}{
		{[]string{"compute", "machine-types", "describe", c.Type,
			"--zone=" + c.Zone, "--format=json"}, p.cfg.Project},
		{[]string{"compute", "images", "describe-from-family", p.family(c.Arch),
			"--format=json"}, p.cfg.ImageProject},
	}
	for _, check := range checks {
		_, err := p.invoke(ctx, "dry-run", check.args, check.project)
		if err == nil {
			continue
		}
		if boxcore.KindOf(err) == boxcore.KindDenied {
			return boxcore.DryResult{Code: "PERMISSION_DENIED"}, nil
		}
		return boxcore.DryResult{}, err
	}
	return boxcore.DryResult{Allowed: true}, nil
}

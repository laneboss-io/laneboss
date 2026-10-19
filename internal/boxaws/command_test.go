package boxaws

import (
	"context"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func TestChildEnv(t *testing.T) {
	dirty := map[string]string{
		"AWS_ACCESS_KEY_ID": "caller-key-demo", "AWS_SECRET_ACCESS_KEY": "caller-secret-demo",
		"AWS_SESSION_TOKEN": "caller-token-demo", "AWS_DEFAULT_PROFILE": "caller-profile-demo",
		"AWS_ENDPOINT_URL": "https://endpoint.invalid", "AWS_ROLE_ARN": "caller-role-demo",
		"AWS_WEB_IDENTITY_TOKEN_FILE": "/tmp/caller-token-demo", "AWS_PROFILE": "caller-profile-demo",
		"AWS_REGION": "caller-region-demo", "AWS_DEFAULT_REGION": "caller-region-demo",
		"AWS_CONFIG_FILE":             "/tmp/caller-config-demo",
		"AWS_SHARED_CREDENTIALS_FILE": "/tmp/caller-creds-demo", "AWS_CA_BUNDLE": "/tmp/caller-ca-demo",
	}
	for key, value := range dirty {
		t.Setenv(key, value)
	}
	cfg, options := demoConfig(), demoOptions()
	cfg.AllowTerminate, cfg.EnsureSSHIngress = true, true
	wanted := map[string]string{
		"AWS_PROFILE": cfg.Profile, "AWS_REGION": cfg.Region, "AWS_DEFAULT_REGION": cfg.Region,
		"AWS_CONFIG_FILE": "/tmp/demo-config", "AWS_SHARED_CREDENTIALS_FILE": "/tmp/demo-creds",
		"AWS_CA_BUNDLE": "/tmp/demo-ca",
	}
	options.Getenv = func(key string) string {
		if value, exists := wanted[key]; exists {
			return value
		}
		return dirty[key]
	}
	fake := demoFake(t)
	p := New(cfg, fake, options)
	ctx, req, c := context.Background(), demoRequest(), demoCandidate()
	c.Arch, c.Type = "arm64", "c7g.xlarge"
	if err := p.Prepare(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Candidates(ctx, req); err != nil {
		t.Fatal(err)
	}
	b, err := p.Launch(ctx, req, c, boxcore.Guest{Startup: "demo\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DryRun(ctx, req, c, boxcore.Guest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.WaitRunning(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Describe(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := p.Teardown(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := p.List(ctx, boxcore.ListFilter{Org: options.Org}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Transport(b, boxcore.TransportOptions{}).Exec(ctx, "demo command", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	awsCalls := 0
	for _, call := range fake.Calls {
		if call.Name != "aws" {
			checkEnv(t, call.Env, nil)
			continue
		}
		awsCalls++
		checkEnv(t, call.Env, wanted)
		format := flagValue(t, call.Args, "--output")
		if format != "json" && format != "text" {
			t.Fatal("AWS output mode is missing")
		}
	}
	if awsCalls != 16 || len(fake.CallsMatching("curl")) != 1 || len(fake.CallsMatching("ssh")) != 1 {
		t.Fatal("environment assertions did not cover all child paths")
	}
	t.Run("optional-empty", func(t *testing.T) {
		fake := demoFake(t)
		options.Getenv = func(key string) string { return "" }
		if err := New(cfg, fake, options).Prepare(ctx, req); err != nil {
			t.Fatal(err)
		}
		for _, call := range fake.CallsMatching("aws") {
			checkEnv(t, call.Env, map[string]string{
				"AWS_PROFILE": cfg.Profile, "AWS_REGION": cfg.Region, "AWS_DEFAULT_REGION": cfg.Region,
			})
		}
	})
	t.Run("default-getenv", func(t *testing.T) {
		fake := demoFake(t)
		options.Getenv = nil
		if err := New(cfg, fake, options).Prepare(ctx, req); err != nil {
			t.Fatal(err)
		}
		for _, call := range fake.CallsMatching("aws") {
			checkEnv(t, call.Env, map[string]string{
				"AWS_PROFILE": cfg.Profile, "AWS_REGION": cfg.Region, "AWS_DEFAULT_REGION": cfg.Region,
				"AWS_CONFIG_FILE":             dirty["AWS_CONFIG_FILE"],
				"AWS_SHARED_CREDENTIALS_FILE": dirty["AWS_SHARED_CREDENTIALS_FILE"], "AWS_CA_BUNDLE": dirty["AWS_CA_BUNDLE"],
			})
		}
	})
}

func checkEnv(t *testing.T, env []string, wanted map[string]string) {
	t.Helper()
	seen := make(map[string]bool)
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || seen[key] {
			t.Fatal("malformed or repeated environment key")
		}
		seen[key] = true
		if expected, allowed := wanted[key]; allowed {
			if value != expected {
				t.Fatalf("wrong environment value for %s", key)
			}
			continue
		}
		switch key {
		case "PATH", "HOME", "TMPDIR", "LANG", "TERM":
		default:
			t.Fatalf("unexpected environment key %s", key)
		}
	}
	for key := range wanted {
		if !seen[key] {
			t.Fatalf("missing environment key %s", key)
		}
	}
}

func TestProfileGate(t *testing.T) {
	ctx, req, c := context.Background(), demoRequest(), demoCandidate()
	b := boxcore.Box{ID: "i-demo1"}
	methods := []struct {
		name string
		call func(boxcore.Provider) error
	}{
		{"prepare", func(p boxcore.Provider) error { return p.Prepare(ctx, req) }},
		{"candidates", func(p boxcore.Provider) error { _, err := p.Candidates(ctx, req); return err }},
		{"dry-run", func(p boxcore.Provider) error { _, err := p.DryRun(ctx, req, c, boxcore.Guest{}); return err }},
		{"launch", func(p boxcore.Provider) error { _, err := p.Launch(ctx, req, c, boxcore.Guest{}); return err }},
		{"wait", func(p boxcore.Provider) error { _, err := p.WaitRunning(ctx, b); return err }},
		{"describe", func(p boxcore.Provider) error { _, err := p.Describe(ctx, b); return err }},
		{"teardown", func(p boxcore.Provider) error { return p.Teardown(ctx, b) }},
		{"list", func(p boxcore.Provider) error { _, err := p.List(ctx, boxcore.ListFilter{}); return err }},
	}
	for _, profile := range []string{"", "default"} {
		for _, method := range methods {
			t.Run(profile+"-"+method.name, func(t *testing.T) {
				cfg := demoConfig()
				cfg.Profile, cfg.AllowTerminate, cfg.EnsureSSHIngress = profile, true, true
				fake := demoFake(t)
				wantKind(t, method.call(New(cfg, fake, demoOptions())), boxcore.KindDenied)
				if len(fake.Calls) != 0 {
					t.Fatal("invalid profile started a child process")
				}
			})
		}
	}
	t.Run("allowed-default", func(t *testing.T) {
		cfg := demoConfig()
		cfg.Profile, cfg.AllowDefaultProfile = "default", true
		fake := demoFake(t)
		if err := New(cfg, fake, demoOptions()).Prepare(ctx, req); err != nil {
			t.Fatal(err)
		}
		call := oneCall(t, fake, "aws", "sts get-caller-identity")
		checkEnv(t, call.Env, map[string]string{
			"AWS_PROFILE": "default", "AWS_REGION": cfg.Region, "AWS_DEFAULT_REGION": cfg.Region,
		})
	})
}

func TestPrepare(t *testing.T) {
	for _, code := range []string{"AccessDenied", "ExpiredToken", "InvalidClientTokenId", "AuthFailure",
		"UnauthorizedOperation", "OtherFailure", "success"} {
		t.Run(code, func(t *testing.T) {
			cfg := demoConfig()
			cfg.EnsureSSHIngress = true
			fake := demoFake(t)
			identity := "identity-private-demo"
			if code != "success" {
				fake.Handlers[0].Respond = func(boxexec.Cmd, int) (boxexec.Result, error) {
					return boxexec.Result{Code: 255, Stdout: []byte(identity), Stderr: []byte(awsFailure(code, "refused"))}, nil
				}
			}
			err := New(cfg, fake, demoOptions()).Prepare(context.Background(), demoRequest())
			call := oneCall(t, fake, "aws", "sts get-caller-identity")
			wantArgs(t, call.Args, []string{"sts", "get-caller-identity", "--output", "json"})
			if code == "success" {
				if err != nil || len(fake.Calls) != 4 || fake.Calls[1].Name != "curl" {
					t.Fatal("successful identity check did not precede ingress")
				}
				return
			}
			kind := boxcore.KindDenied
			if code == "OtherFailure" {
				kind = boxcore.KindOther
			}
			wantKind(t, err, kind)
			if strings.Contains(err.Error(), identity) || len(fake.Calls) != 1 {
				t.Fatal("identity output leaked or failed preflight continued")
			}
		})
	}
}

func TestClassify(t *testing.T) {
	groups := []struct {
		kind  boxcore.ErrorKind
		codes []string
	}{
		{boxcore.KindCapacity, []string{"InsufficientInstanceCapacity", "SpotMaxPriceTooLow", "MaxSpotInstanceCountExceeded",
			"Unsupported", "InsufficientFreeAddressesInSubnet", "InsufficientCapacity"}},
		{boxcore.KindQuota, []string{"VcpuLimitExceeded", "InstanceLimitExceeded", "SpotInstanceRequestLimitExceeded"}},
		{boxcore.KindDenied, []string{"UnauthorizedOperation", "AuthFailure", "AccessDenied", "AccessDeniedException",
			"InvalidClientTokenId", "ExpiredToken", "OptInRequired"}},
		{boxcore.KindNotFound, []string{"InvalidInstanceID.NotFound", "InvalidSpotInstanceRequestID.NotFound"}},
		{boxcore.KindOther, []string{"UnknownFailure", ""}},
	}
	for _, group := range groups {
		for _, code := range group.codes {
			t.Run(code, func(t *testing.T) {
				stderr := awsFailure(code, "refused\nsecond")
				if code == "" {
					stderr = "unparsed failure"
				}
				err := classify("operation-demo", stderr, 17)
				if err.Kind != group.kind || err.Code != code || err.Op != "operation-demo" {
					t.Fatalf("wrong classification: %+v", err)
				}
				if code != "" && err.Detail != "refused second" || code == "" &&
					err.Detail != "command failed with exit status 17" {
					t.Fatal("error detail was not sanitized")
				}
			})
		}
	}
	t.Run("detail-limit", func(t *testing.T) {
		message := " first\nsecond\r\n" + strings.Repeat("ø", 400)
		err := classify("operation-demo", awsFailure("AccessDenied", message), 255)
		if len([]rune(err.Detail)) != 300 || !strings.HasPrefix(err.Detail, "first second  ") ||
			strings.ContainsAny(err.Detail, "\r\n") {
			t.Fatal("detail limit or newline handling differs")
		}
	})
	t.Run("argv-private", func(t *testing.T) {
		cfg, c := demoConfig(), demoCandidate()
		cfg.Subnets = map[string]string{c.Zone: "subnet-demo1"}
		argv := "aws ec2 run-instances --image-id argv-private-demo"
		for _, runnerError := range []bool{false, true} {
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "aws", ArgsContain: []string{"run-instances"},
				Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					if runnerError {
						return boxexec.Result{Code: -1}, errors.New(argv)
					}
					return boxexec.Result{Code: 255, Stderr: []byte(argv)}, nil
				}}}}
			_, err := New(cfg, fake, demoOptions()).Launch(context.Background(), demoRequest(), c, boxcore.Guest{})
			failure := wantKind(t, err, boxcore.KindOther)
			if strings.Contains(failure.Error(), argv) || strings.Contains(failure.Detail, "argv-private-demo") {
				t.Fatal("error text exposed command arguments")
			}
		}
	})
}

func TestProviderBasics(t *testing.T) {
	fake := demoFake(t)
	p := New(demoConfig(), fake, demoOptions())
	if p.Name() != "aws" {
		t.Fatal("wrong provider name")
	}
	count, err := p.FetchHarvest(context.Background(), boxcore.Box{}, "run-demo1", "/tmp/demo-harvest")
	wantKind(t, err, boxcore.KindUnsupported)
	if count != 0 || len(fake.Calls) != 0 {
		t.Fatal("unsupported harvest started a process")
	}
}

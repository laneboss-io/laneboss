package boxaws

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func (p *provider) profile() error {
	if strings.TrimSpace(p.cfg.Profile) == "" ||
		p.cfg.Profile == "default" && !p.cfg.AllowDefaultProfile {
		return boxcore.NewError(boxcore.KindDenied, "profile", "", "an allowed named profile is required", nil)
	}
	return nil
}

func (p *provider) aws(ctx context.Context, op string, args ...string) (boxexec.Result, error) {
	if err := p.profile(); err != nil {
		return boxexec.Result{}, err
	}
	if p.run == nil {
		return boxexec.Result{}, boxcore.NewError(boxcore.KindOther, op, "", "no process runner", nil)
	}
	extra := map[string]string{
		"AWS_PROFILE":        p.cfg.Profile,
		"AWS_REGION":         p.cfg.Region,
		"AWS_DEFAULT_REGION": p.cfg.Region,
	}
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CA_BUNDLE"} {
		if value := p.o.Getenv(key); value != "" {
			extra[key] = value
		}
	}
	hasOutput := false
	for _, arg := range args {
		if arg == "--output" {
			hasOutput = true
			break
		}
	}
	if !hasOutput {
		args = append(args, "--output", "json")
	}
	result, err := p.run.Run(ctx, boxexec.Cmd{Name: "aws", Args: args, Env: boxexec.CleanEnv(extra)})
	if err != nil {
		// Runner errors may contain command lines; only wrap them privately.
		return result, boxcore.NewError(boxcore.KindOther, op, "", "child process failed", err)
	}
	if result.Code != 0 {
		return result, classify(op, string(result.Stderr), result.Code)
	}
	return result, nil
}

func classify(op, stderr string, exit int) *boxcore.Error {
	// Not-found codes contain dots, unlike most AWS error codes.
	re := regexp.MustCompile(`An error occurred \(([A-Za-z0-9_.-]+)\) ` +
		`when calling the (\w+) operation: ([\s\S]*)`)
	code := ""
	detail := "command failed with exit status " + strconv.Itoa(exit)
	if match := re.FindStringSubmatch(stderr); match != nil {
		code = match[1]
		detail = shortDetail(match[3])
	}
	kind := boxcore.KindOther
	switch code {
	case "InsufficientInstanceCapacity", "SpotMaxPriceTooLow", "MaxSpotInstanceCountExceeded",
		"Unsupported", "InsufficientFreeAddressesInSubnet", "InsufficientCapacity":
		kind = boxcore.KindCapacity
	case "VcpuLimitExceeded", "InstanceLimitExceeded", "SpotInstanceRequestLimitExceeded":
		kind = boxcore.KindQuota
	case "UnauthorizedOperation", "AuthFailure", "AccessDenied", "AccessDeniedException",
		"InvalidClientTokenId", "ExpiredToken", "OptInRequired":
		kind = boxcore.KindDenied
	case "InvalidInstanceID.NotFound", "InvalidSpotInstanceRequestID.NotFound":
		kind = boxcore.KindNotFound
	}
	return boxcore.NewError(kind, op, code, detail, nil)
}

func shortDetail(text string) string {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\n", " "), "\r", " ")
	runes := []rune(strings.TrimSpace(text))
	return string(runes[:min(len(runes), 300)])
}

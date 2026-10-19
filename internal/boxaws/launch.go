package boxaws

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

// Launch creates a spot instance with termination and ownership safeguards.
func (p *provider) Launch(ctx context.Context, req boxcore.Request, c boxcore.Candidate, g boxcore.Guest) (boxcore.Box, error) {
	args, labels, err := p.launchArgs(ctx, req, c, g)
	if err != nil {
		return boxcore.Box{}, err
	}
	result, err := p.aws(ctx, "run-instances", args...)
	if err != nil {
		return boxcore.Box{}, err
	}
	id := strings.TrimSpace(string(result.Stdout))
	if id == "None" || !boxcore.PlainName(id) {
		return boxcore.Box{}, launchError("invalid instance response", nil)
	}
	return boxcore.Box{Provider: "aws", ID: id, Name: labels["Name"], Type: c.Type,
		Zone: c.Zone, Region: p.cfg.Region, Project: p.cfg.ProjectTag, Labels: labels}, nil
}

// DryRun uses the launch arguments and interprets AWS's error-based contract.
func (p *provider) DryRun(ctx context.Context, req boxcore.Request, c boxcore.Candidate, g boxcore.Guest) (boxcore.DryResult, error) {
	args, _, err := p.launchArgs(ctx, req, c, g)
	if err != nil {
		return boxcore.DryResult{}, err
	}
	result, err := p.aws(ctx, "run-instances", append(args, "--dry-run")...)
	var failure *boxcore.Error
	if result.Code != 0 && errors.As(err, &failure) {
		switch failure.Code {
		case "DryRunOperation":
			return boxcore.DryResult{Allowed: true, Code: failure.Code, Detail: failure.Detail}, nil
		case "UnauthorizedOperation", "AuthFailure", "AccessDenied", "AccessDeniedException",
			"InvalidClientTokenId", "ExpiredToken":
			return boxcore.DryResult{Allowed: false, Code: failure.Code, Detail: failure.Detail}, nil
		}
	}
	if err != nil {
		return boxcore.DryResult{}, err
	}
	return boxcore.DryResult{}, launchError("unexpected dry-run success", nil)
}

func (p *provider) launchArgs(ctx context.Context, req boxcore.Request, c boxcore.Candidate, g boxcore.Guest) ([]string, map[string]string, error) {
	if err := p.profile(); err != nil {
		return nil, nil, err
	}
	if len(g.Startup) > 12000 {
		return nil, nil, launchError("startup text exceeds 12000 bytes", nil)
	}
	if req.RootGB <= 0 || c.Type == "" || c.Zone == "" {
		return nil, nil, launchError("root size, instance type and zone are required", nil)
	}
	labels, tags, err := p.tags(req)
	if err != nil {
		return nil, nil, err
	}
	image := strings.TrimSpace(p.cfg.AMI)
	if c.Arch == "arm64" {
		result, err := p.aws(ctx, "get-parameter", "ssm", "get-parameter", "--name", p.cfg.ArmAMISSM,
			"--query", "Parameter.Value", "--output", "text")
		if err != nil {
			return nil, nil, err
		}
		image = strings.TrimSpace(string(result.Stdout))
	}
	if image == "" || image == "None" {
		return nil, nil, launchError("no image available", nil)
	}
	subnet, present := p.cfg.Subnets[c.Zone]
	if !present {
		result, err := p.aws(ctx, "describe-subnets", "ec2", "describe-subnets", "--filters",
			"Name=vpc-id,Values="+p.cfg.VPC, "Name=availability-zone,Values="+c.Zone,
			"Name=map-public-ip-on-launch,Values=true", "--query", "Subnets[0].SubnetId", "--output", "text")
		if err != nil {
			return nil, nil, err
		}
		subnet = string(result.Stdout)
	}
	subnet = strings.TrimSpace(subnet)
	if subnet == "" || subnet == "None" {
		return nil, nil, boxcore.NewError(boxcore.KindCapacity, "describe-subnets", "", "no public subnet", nil)
	}
	args := []string{"ec2", "run-instances", "--image-id", image, "--instance-type", c.Type,
		"--key-name", p.cfg.KeyName, "--security-group-ids", p.cfg.SecurityGroup, "--subnet-id", subnet,
		"--associate-public-ip-address", "--instance-market-options",
		"MarketType=spot,SpotOptions={SpotInstanceType=one-time," +
			"InstanceInterruptionBehavior=terminate}",
		"--instance-initiated-shutdown-behavior", "terminate", "--block-device-mappings",
		"DeviceName=/dev/sda1,Ebs={VolumeSize=" + strconv.Itoa(req.RootGB) +
			",VolumeType=gp3,DeleteOnTermination=true}",
		"--user-data", base64.StdEncoding.EncodeToString([]byte(g.Startup)), "--tag-specifications",
		"ResourceType=instance,Tags=[" + tags + "]", "ResourceType=volume,Tags=[" + tags + "]",
		"--query", "Instances[0].InstanceId", "--output", "text"}
	return args, labels, nil
}

func (p *provider) tags(req boxcore.Request) (map[string]string, string, error) {
	values := []struct{ key, value string }{
		{"Project", p.cfg.ProjectTag}, {"Name", p.o.NamePrefix + req.Purpose},
		{"Owner", req.Owner}, {"Lane", req.Lane}, {"Purpose", req.Purpose},
		{"Org", p.o.Org}, {"RunId", req.RunID}, {"ManagedBy", "laneboss"},
	}
	labels := make(map[string]string, len(values))
	parts := make([]string, 0, len(values))
	for _, tag := range values {
		if !boxcore.TagSafe(tag.value) {
			return nil, "", launchError("invalid tag "+tag.key, nil)
		}
		labels[tag.key] = tag.value
		parts = append(parts, "{Key="+tag.key+",Value="+tag.value+"}")
	}
	return labels, strings.Join(parts, ","), nil
}

func launchError(detail string, err error) *boxcore.Error {
	return boxcore.NewError(boxcore.KindOther, "run-instances", "", detail, err)
}

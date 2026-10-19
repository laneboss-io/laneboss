package boxaws

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func (p *provider) ensureIngress(ctx context.Context) error {
	if err := p.profile(); err != nil {
		return err
	}
	if p.run == nil {
		return boxcore.NewError(boxcore.KindOther, "ssh-ingress", "", "no process runner", nil)
	}
	url := p.cfg.MyAddressURL
	if url == "" {
		url = "https://checkip." + "amazonaws.com"
	}
	result, err := p.run.Run(ctx, boxexec.Cmd{
		Name: "curl", Args: []string{"-fsS", "--max-time", "8", url}, Env: boxexec.CleanEnv(nil),
	})
	if err != nil || result.Code != 0 {
		return boxcore.NewError(boxcore.KindOther, "ssh-ingress", "", "address lookup failed", err)
	}
	ip := strings.TrimSpace(string(result.Stdout))
	if !ipv4(ip) {
		return boxcore.NewError(boxcore.KindOther, "ssh-ingress", "", "invalid address response", nil)
	}
	result, err = p.aws(ctx, "describe-security-groups", "ec2", "describe-security-groups",
		"--group-ids", p.cfg.SecurityGroup)
	if err != nil {
		return err
	}
	var response struct {
		SecurityGroups []struct {
			IpPermissions []struct {
				IpProtocol string
				FromPort   int
				ToPort     int
				IpRanges   []struct{ CidrIp string }
			}
		}
	}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return boxcore.NewError(boxcore.KindOther, "ssh-ingress", "", "invalid security group response", err)
	}
	if len(response.SecurityGroups) == 0 {
		return boxcore.NewError(boxcore.KindNotFound, "ssh-ingress", "", "security group missing", nil)
	}
	cidr := ip + "/32"
	for _, permission := range response.SecurityGroups[0].IpPermissions {
		if permission.IpProtocol != "tcp" || permission.FromPort != 22 || permission.ToPort != 22 {
			continue
		}
		for _, address := range permission.IpRanges {
			if address.CidrIp == cidr {
				return nil
			}
		}
	}
	_, err = p.aws(ctx, "authorize-security-group-ingress", "ec2", "authorize-security-group-ingress",
		"--group-id", p.cfg.SecurityGroup, "--protocol", "tcp", "--port", "22", "--cidr", cidr)
	return err
}

func ipv4(text string) bool {
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		value, err := strconv.Atoi(part)
		if err != nil || value > 255 {
			return false
		}
	}
	return true
}

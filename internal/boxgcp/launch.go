package boxgcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

func (p *provider) labels(req boxcore.Request) map[string]string {
	return map[string]string{
		"managed-by": "laneboss",
		"lb-org":     boxcore.GCPLabelValue(p.o.Org),
		"lb-owner":   boxcore.GCPLabelValue(req.Owner),
		"lb-lane":    boxcore.GCPLabelValue(req.Lane),
		"lb-run":     boxcore.GCPLabelValue(req.RunID),
		"lb-purpose": boxcore.GCPLabelValue(req.Purpose),
	}
}

func labelArg(labels map[string]string) string {
	var parts []string
	for _, key := range []string{"managed-by", "lb-org", "lb-owner", "lb-lane", "lb-run", "lb-purpose"} {
		parts = append(parts, key+"="+labels[key])
	}
	return "--labels=" + strings.Join(parts, ",")
}

// Launch creates a labelled Spot instance with a provider enforced lifetime cap.
func (p *provider) Launch(ctx context.Context, req boxcore.Request, c boxcore.Candidate, g boxcore.Guest) (b boxcore.Box, err error) {
	for _, field := range []struct{ name, value string }{
		{"owner", req.Owner}, {"lane", req.Lane}, {"purpose", req.Purpose},
	} {
		if !boxcore.PlainName(field.value) {
			return b, localError("launch", "invalid "+field.name, nil)
		}
	}
	if req.HardMin < 1 {
		return b, localError("launch", "hard duration must be at least one minute", nil)
	}
	if g.Startup == "" || g.Shutdown == "" {
		return b, localError("launch", "startup and shutdown scripts are required", nil)
	}
	dir, err := os.MkdirTemp("", "lb-sp-gcp-")
	if err != nil {
		return b, localError("launch", "cannot create script directory", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(dir); cleanupErr != nil {
			err = errors.Join(err, localError("launch", "cannot remove script directory", cleanupErr))
		}
	}()
	startup := filepath.Join(dir, "startup.sh")
	shutdown := filepath.Join(dir, "shutdown.sh")
	if err := os.WriteFile(startup, []byte(g.Startup), 0600); err != nil {
		return b, localError("launch", "cannot write startup script", err)
	}
	if err := os.WriteFile(shutdown, []byte(g.Shutdown), 0600); err != nil {
		return b, localError("launch", "cannot write shutdown script", err)
	}
	labels := p.labels(req)
	family := p.family(c.Arch)
	args := []string{
		"compute", "instances", "create", boxcore.GCPInstanceName(p.o.NamePrefix, req.Purpose, req.RunID),
		"--zone=" + c.Zone, "--machine-type=" + c.Type,
		"--provisioning-model=SPOT", "--instance-termination-action=DELETE",
		fmt.Sprintf("--max-run-duration=%dm", req.HardMin),
		"--image-family=" + family, "--image-project=" + p.cfg.ImageProject,
		fmt.Sprintf("--boot-disk-size=%dGB", req.RootGB), "--boot-disk-type=" + p.cfg.BootDiskType,
		"--service-account=" + account(p.cfg.BoxServiceAccount, p.cfg.Project),
		"--scopes=storage-rw", labelArg(labels),
	}
	if p.cfg.PreemptionNoticeSec == 120 {
		// The notice flag exists only in the beta command group of the gcloud release that was checked (582).
		args = append([]string{"beta"}, args...)
		args = append(args, "--preemption-notice-duration=120s")
	}
	if len(p.cfg.NetworkTags) > 0 {
		args = append(args, "--tags="+strings.Join(p.cfg.NetworkTags, ","))
	}
	if p.cfg.Network != "" {
		network := "--network-interface=network=" + p.cfg.Network
		if p.cfg.Subnetwork != "" {
			network += ",subnet=" + p.cfg.Subnetwork
		}
		if !p.cfg.ExternalIP {
			network += ",no-address"
		}
		args = append(args, network)
	}
	args = append(args,
		// OS Login on, and the project's own ssh keys off: the shared project's metadata holds other people's keys.
		"--metadata=enable-oslogin=TRUE,"+"block-project-ssh-keys=TRUE,"+"enable-guest-attributes=TRUE,lb-run-id="+req.RunID,
		"--metadata-from-file=startup-script="+startup+",shutdown-script="+shutdown,
		"--format=json")
	result, err := p.invoke(ctx, "launch", args, p.cfg.Project)
	if err != nil {
		return b, err
	}
	var instances []instance
	if err := json.Unmarshal(result.Stdout, &instances); err != nil {
		return b, localError("launch", "invalid instance JSON", err)
	}
	if len(instances) == 0 {
		return b, localError("launch", "create returned no instance", nil)
	}
	b, err = p.box(instances[0], family, "launch")
	if err == nil {
		b.QuoteUSDHour = c.PriceUSDHour
		if b.Labels == nil {
			b.Labels = labels
		}
	}
	return b, err
}

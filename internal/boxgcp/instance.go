package boxgcp

import (
	"context"
	"encoding/json"
	"path"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

type instance struct {
	Name              string            `json:"name"`
	Status            string            `json:"status"`
	StatusMessage     string            `json:"statusMessage"`
	CreationTimestamp string            `json:"creationTimestamp"`
	MachineType       string            `json:"machineType"`
	Zone              string            `json:"zone"`
	Labels            map[string]string `json:"labels"`
	NetworkInterfaces []struct {
		AccessConfigs []struct {
			NATIP string `json:"natIP"`
		} `json:"accessConfigs"`
	} `json:"networkInterfaces"`
}

func (i instance) address() string {
	if len(i.NetworkInterfaces) > 0 && len(i.NetworkInterfaces[0].AccessConfigs) > 0 {
		return i.NetworkInterfaces[0].AccessConfigs[0].NATIP
	}
	return ""
}

func timestamp(text, op string) (string, error) {
	if text == "" {
		return "", nil
	}
	t, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return "", localError(op, "invalid creation timestamp", err)
	}
	return boxcore.FormatUTC(t.UTC()), nil
}

func (p *provider) box(i instance, image, op string) (boxcore.Box, error) {
	if i.Name == "" {
		return boxcore.Box{}, localError(op, "instance name is missing", nil)
	}
	created, err := timestamp(i.CreationTimestamp, op)
	if err != nil {
		return boxcore.Box{}, err
	}
	return boxcore.Box{
		Provider: "gcp", ID: i.Name, Name: i.Name, Type: lastElement(i.MachineType),
		Zone: lastElement(i.Zone), Region: p.cfg.Region, Image: image,
		Address: i.address(), LaunchTimeUTC: created, Project: p.cfg.Project, Labels: i.Labels,
	}, nil
}

func lastElement(value string) string {
	if value == "" {
		return ""
	}
	return path.Base(value)
}

func instanceName(b boxcore.Box) string {
	if b.Name != "" {
		return b.Name
	}
	return b.ID
}

// namesInstance reports whether stderr is the answer for a machine that does not exist: it must name this very
// instance as `instances/NAME`, and the name must end there (a longer name that starts with it is another machine).
func namesInstance(stderr, name string) bool {
	text, want := strings.ToLower(stderr), "instances/"+strings.ToLower(name)
	for from := 0; from < len(text); {
		at := strings.Index(text[from:], want)
		if at < 0 {
			return false
		}
		end := from + at + len(want)
		if end == len(text) || !isNameByte(text[end]) {
			return true
		}
		from += at + 1
	}
	return false
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}

func (p *provider) describe(ctx context.Context, b boxcore.Box, op string) (instance, error) {
	result, err := p.invoke(ctx, op, []string{
		"compute", "instances", "describe", instanceName(b),
		"--zone=" + b.Zone, "--format=json",
	}, p.cfg.Project)
	if err != nil {
		// Only an answer that names this instance means the machine is gone. A gcloud that crashed, or that says some other
		// resource (a zone, a project, a longer name) was not found, has not answered: that is a failed read, and a failed
		// read must never be taken for a machine that no longer exists.
		if boxcore.KindOf(err) == boxcore.KindNotFound && !namesInstance(string(result.Stderr), instanceName(b)) {
			return instance{}, boxcore.NewError(boxcore.KindOther, op, "", "the machine could not be read", err)
		}
		return instance{}, err
	}
	var i instance
	if err := json.Unmarshal(result.Stdout, &i); err != nil {
		return i, localError(op, "invalid instance JSON", err)
	}
	if i.Name == "" {
		return i, localError(op, "instance name is missing", nil)
	}
	return i, nil
}

// Describe maps Compute Engine status, including an already gone instance.
func (p *provider) Describe(ctx context.Context, b boxcore.Box) (boxcore.State, error) {
	i, err := p.describe(ctx, b, "describe")
	if boxcore.KindOf(err) == boxcore.KindNotFound {
		return boxcore.State{Name: boxcore.StateGone}, nil
	}
	if err != nil {
		return boxcore.State{}, err
	}
	state := boxcore.State{Name: boxcore.StateUnknown, Raw: i.Status, Reason: i.StatusMessage}
	switch i.Status {
	case "PROVISIONING", "STAGING", "REPAIRING":
		state.Name = boxcore.StatePending
	case "RUNNING":
		state.Name = boxcore.StateRunning
	case "STOPPING", "SUSPENDING":
		state.Name = boxcore.StateStopping
	case "TERMINATED", "SUSPENDED", "STOPPED":
		state.Name = boxcore.StateStopped
	}
	return state, nil
}

// WaitRunning polls with a bounded clock and refreshes the address and creation time.
func (p *provider) WaitRunning(ctx context.Context, b boxcore.Box) (boxcore.Box, error) {
	deadline := p.o.Now().Add(5 * time.Minute)
	// Also bound a describe process that stalls instead of returning a status.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return boxcore.Box{}, localError("wait-running", "waiting interrupted", err)
		}
		if !p.o.Now().Before(deadline) {
			return boxcore.Box{}, localError("wait-running", "timed out waiting for box", nil)
		}
		i, err := p.describe(ctx, b, "wait-running")
		if boxcore.KindOf(err) == boxcore.KindNotFound {
			return boxcore.Box{}, localError("wait-running", "box ended while starting", err)
		}
		if err != nil {
			return boxcore.Box{}, err
		}
		if !p.o.Now().Before(deadline) {
			return boxcore.Box{}, localError("wait-running", "timed out waiting for box", nil)
		}
		switch i.Status {
		case "RUNNING":
			b.LaunchTimeUTC, err = timestamp(i.CreationTimestamp, "wait-running")
			if err != nil {
				return boxcore.Box{}, err
			}
			b.Address = i.address()
			return b, nil
		case "STOPPING", "SUSPENDING", "TERMINATED", "SUSPENDED", "STOPPED":
			return boxcore.Box{}, localError("wait-running", "box ended while starting", nil)
		case "PROVISIONING", "STAGING", "REPAIRING":
		default:
			return boxcore.Box{}, localError("wait-running", "unexpected box state while starting", nil)
		}
		d := min(5*time.Second, deadline.Sub(p.o.Now()))
		if err := p.o.Sleep(ctx, d); err != nil {
			return boxcore.Box{}, localError("wait-running", "waiting interrupted", err)
		}
	}
}

// Teardown deletes an instance and its disks once the fence proves the live instance is ours. A machine that
// is already gone is not an error and nothing is touched.
func (p *provider) Teardown(ctx context.Context, b boxcore.Box) error {
	i, err := p.fence(ctx, b, "teardown")
	if boxcore.KindOf(err) == boxcore.KindNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = p.invoke(ctx, "teardown", []string{
		"compute", "instances", "delete", i.Name, "--zone=" + b.Zone, "--delete-disks=all",
	}, p.cfg.Project)
	return err
}

// List reads managed instances, optionally restricted to an organisation label.
func (p *provider) List(ctx context.Context, f boxcore.ListFilter) ([]boxcore.Box, error) {
	filter := "labels.managed-by=laneboss"
	if f.Org != "" {
		filter += " AND labels.lb-org=" + boxcore.GCPLabelValue(f.Org)
	}
	result, err := p.invoke(ctx, "list", []string{
		"compute", "instances", "list", "--filter=" + filter, "--format=json",
	}, p.cfg.Project)
	if err != nil {
		return nil, err
	}
	var instances []instance
	if err := json.Unmarshal(result.Stdout, &instances); err != nil {
		return nil, localError("list", "invalid instance JSON", err)
	}
	boxes := make([]boxcore.Box, 0, len(instances))
	for _, i := range instances {
		b, err := p.box(i, "", "list")
		if err != nil {
			return nil, err
		}
		boxes = append(boxes, b)
	}
	return boxes, nil
}

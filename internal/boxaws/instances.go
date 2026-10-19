package boxaws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

type awsTag struct{ Key, Value string }

type instance struct {
	InstanceId            string
	InstanceType          string
	ImageId               string
	LaunchTime            string
	SpotInstanceRequestId string
	PublicIpAddress       string
	Placement             struct{ AvailabilityZone string }
	State                 struct{ Name string }
	StateReason           struct{ Code, Message string }
	StateTransitionReason string
	Tags                  []awsTag
}

func decodeInstances(data []byte) ([]instance, error) {
	var response struct {
		Reservations []struct{ Instances []instance }
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, boxcore.NewError(boxcore.KindOther, "describe-instances", "", "invalid instance response", err)
	}
	var instances []instance
	for _, reservation := range response.Reservations {
		instances = append(instances, reservation.Instances...)
	}
	return instances, nil
}

func (p *provider) describe(ctx context.Context, id string) (instance, error) {
	result, err := p.aws(ctx, "describe-instances", "ec2", "describe-instances", "--instance-ids", id)
	if err != nil {
		return instance{}, err
	}
	instances, err := decodeInstances(result.Stdout)
	if err != nil {
		return instance{}, err
	}
	if len(instances) == 0 {
		return instance{}, boxcore.NewError(boxcore.KindNotFound, "describe-instances", "", "instance missing", nil)
	}
	return instances[0], nil
}

func labelsFrom(tags []awsTag) map[string]string {
	labels := make(map[string]string, len(tags))
	for _, tag := range tags {
		labels[tag.Key] = tag.Value
	}
	return labels
}

func (p *provider) fillBox(b boxcore.Box, i instance) (boxcore.Box, error) {
	b.Provider = "aws"
	if i.InstanceId != "" {
		b.ID = i.InstanceId
	}
	b.Type, b.Zone = i.InstanceType, i.Placement.AvailabilityZone
	b.Region, b.Image, b.Address = p.cfg.Region, i.ImageId, i.PublicIpAddress
	b.SpotRequestID = i.SpotInstanceRequestId
	b.Labels = labelsFrom(i.Tags)
	b.Name, b.Project = b.Labels["Name"], b.Labels["Project"]
	b.LaunchTimeUTC = ""
	if i.LaunchTime != "" {
		var ok bool
		b.LaunchTimeUTC, ok = boxcore.NormalizeUTC(i.LaunchTime)
		if !ok {
			return boxcore.Box{}, boxcore.NewError(boxcore.KindOther, "describe-instances", "", "invalid launch time", nil)
		}
	}
	return b, nil
}

// WaitRunning waits for AWS and fills the facts needed by the SSH transport.
func (p *provider) WaitRunning(ctx context.Context, b boxcore.Box) (boxcore.Box, error) {
	if _, err := p.aws(ctx, "instance-running", "ec2", "wait", "instance-running", "--instance-ids", b.ID); err != nil {
		return boxcore.Box{}, err
	}
	i, err := p.describe(ctx, b.ID)
	if err != nil {
		return boxcore.Box{}, err
	}
	if i.PublicIpAddress == "" {
		return boxcore.Box{}, boxcore.NewError(boxcore.KindOther, "instance-running", "", "instance has no public address", nil)
	}
	return p.fillBox(b, i)
}

// Describe maps AWS state and interruption reasons to provider-neutral facts.
func (p *provider) Describe(ctx context.Context, b boxcore.Box) (boxcore.State, error) {
	i, err := p.describe(ctx, b.ID)
	if err != nil {
		var failure *boxcore.Error
		// The provider's not-found code, or an empty answer for the id, both mean the box is no longer known.
		if errors.As(err, &failure) && failure.Kind == boxcore.KindNotFound &&
			(failure.Code == "InvalidInstanceID.NotFound" || failure.Code == "") {
			return boxcore.State{Name: boxcore.StateGone}, nil
		}
		return boxcore.State{}, err
	}
	state := boxcore.State{Raw: i.State.Name, Name: boxcore.StateUnknown}
	switch i.State.Name {
	case "pending":
		state.Name = boxcore.StatePending
	case "running":
		state.Name = boxcore.StateRunning
	case "stopping", "shutting-down":
		state.Name = boxcore.StateStopping
	case "stopped":
		state.Name = boxcore.StateStopped
	case "terminated":
		state.Name = boxcore.StateTerminated
	}
	var reasons []string
	for _, part := range []string{i.StateReason.Code, i.StateReason.Message, i.StateTransitionReason} {
		if part != "" {
			reasons = append(reasons, part)
		}
	}
	state.Reason = strings.Join(reasons, "; ")
	if state.Name == boxcore.StateStopped || state.Name == boxcore.StateTerminated {
		state.TransitionUTC, _ = boxcore.NormalizeUTC(i.StateTransitionReason)
	}
	return state, nil
}

// Teardown terminates only boxes whose current AWS tags prove ownership.
func (p *provider) Teardown(ctx context.Context, b boxcore.Box) error {
	if !p.cfg.AllowTerminate {
		return boxcore.NewError(boxcore.KindUnsupported, "terminate-instances", "", "termination is disabled", nil)
	}
	i, err := p.describe(ctx, b.ID)
	if err != nil {
		return err
	}
	labels := labelsFrom(i.Tags)
	if p.o.NamePrefix == "" || p.o.Org == "" || !strings.HasPrefix(labels["Name"], p.o.NamePrefix) ||
		labels["ManagedBy"] != "laneboss" || labels["Org"] != p.o.Org {
		return boxcore.NewError(boxcore.KindDenied, "terminate-instances", "", "instance ownership does not match", nil)
	}
	_, err = p.aws(ctx, "terminate-instances", "ec2", "terminate-instances", "--instance-ids", b.ID)
	return err
}

// List returns active managed instances, optionally restricted to an Org.
func (p *provider) List(ctx context.Context, f boxcore.ListFilter) ([]boxcore.Box, error) {
	args := []string{"ec2", "describe-instances", "--filters", "Name=tag:ManagedBy,Values=laneboss"}
	if f.Org != "" {
		args = append(args, "Name=tag:Org,Values="+f.Org)
	}
	args = append(args, "Name=instance-state-name,Values=pending,running,stopping,stopped")
	result, err := p.aws(ctx, "describe-instances", args...)
	if err != nil {
		return nil, err
	}
	instances, err := decodeInstances(result.Stdout)
	if err != nil {
		return nil, err
	}
	boxes := make([]boxcore.Box, 0, len(instances))
	for _, i := range instances {
		b, err := p.fillBox(boxcore.Box{}, i)
		if err != nil {
			return nil, err
		}
		boxes = append(boxes, b)
	}
	return boxes, nil
}

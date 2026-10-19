//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

func measureProcessUmask(pid string) (uint32, error) {
	data, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return 0, failure(api.CodeContainmentUnknown, "credential bootstrap umask cannot be observed")
	}
	seen := false
	var value uint64
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Umask:") {
			continue
		}
		if seen {
			return 0, failure(api.CodeIntegrity, "credential bootstrap umask observation repeats")
		}
		seen = true
		value, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "Umask:")), 8, 32)
		if err != nil || value > 0777 {
			return 0, failure(api.CodeIntegrity, "credential bootstrap umask observation is invalid")
		}
	}
	if !seen {
		return 0, failure(api.CodeContainmentUnknown, "credential bootstrap umask observation is missing")
	}
	return uint32(value), nil
}

// The dedicated bootstrap, never the event service, owns this process state.
// Both the closed probe and every real credential gate run this exact code.
func establishCredentialUmask() error {
	unix.Umask(int(claudock.RequiredUmask))
	actual, err := measureProcessUmask("thread-self")
	if err != nil {
		return err
	}
	if actual != claudock.RequiredUmask {
		return failure(api.CodeForbidden, "credential bootstrap did not establish private umask")
	}
	return nil
}

// Measure the installed bootstrap under the actual allocated UID, cgroup and
// private namespaces before producing a RunnerPlan. No credential or vendor
// command is supplied, and the release pipe is never opened. The real gate
// repeats this measurement before receiving any credential at vendor exec.
func (m *leaseManager) measureCredentialBootstrap(ctx context.Context, record leaseRecord, measured *uint32) (resultErr error) {
	if measured == nil {
		return failure(api.CodeInvalid, "credential bootstrap measurement requires an output")
	}
	if err := m.resources.Quiescent(ctx, record); err != nil {
		return err
	}
	if len(record.LaunchAllocations) == 0 {
		return failure(api.CodeForbidden, "credential bootstrap has no enrolled launch allocation")
	}
	probeRecord := record
	probeRecord.Storage = nil // No lane storage or protected records enter this probe.
	probeRecord.Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{
		RuntimeManifest: record.LaunchAllocations[len(record.LaunchAllocations)-1].Inputs.Sources.Runtime.Manifest}}}
	_, mounts, err := m.gateMounts(ctx, probeRecord)
	if err != nil {
		return err
	}
	defer func() {
		for _, mount := range mounts {
			resultErr = errors.Join(resultErr, mount.file.Close())
		}
	}()
	output, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer output.Close()
	token, err := randomID("credential-probe-")
	if err != nil {
		return err
	}
	payload := gatePayload{Config: m.binding.Config, Mode: "credential-probe", GateID: token, Token: string(token),
		UID: record.Lease.UID, GID: record.Lease.GID, Argv: []string{fixedBootstrapPath}, CWD: "/", Budget: api.Budget{WallMS: 5000}}
	gate, err := startNativeGate(ctx, m.binding, record, payload, mounts, output, output, nil, nil, m.bootID)
	if err != nil {
		return err
	}
	native := gate.(*nativeGate)
	defer func() {
		resultErr = errors.Join(resultErr, native.Close())
		wait, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		select {
		case <-native.done:
			resultErr = errors.Join(resultErr, m.waitContainmentEmpty(wait, record))
		case <-wait.Done():
			resultErr = errors.Join(resultErr, failure(api.CodeContainmentUnknown, "credential bootstrap probe was not collected"))
		}
	}()
	actual, err := measureProcessUmask(strconv.Itoa(native.innerPID))
	if err != nil {
		return err
	}
	if actual != claudock.RequiredUmask || native.bootstrapUmask == nil || *native.bootstrapUmask != actual {
		return failure(api.CodeForbidden, "credential bootstrap lacks the measured private umask")
	}
	if err := native.innerLifetime(m.bootID); err != nil {
		return err
	}
	*measured = actual
	return nil
}

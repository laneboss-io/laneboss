//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func (b installation) credentialMetadataPath() string {
	return filepath.Join(b.runtimePath(), "credential-metadata.sock")
}

// The ordinary helper listener stays serialized. Metadata readers can wait on
// an outside owner which needs another authenticated metadata callback. Accept
// those streams independently; the existing operationMu still serializes state
// access and is lent only by its owning outside call.
func startCredentialMetadata(ctx context.Context, b installation, manager *leaseManager) (func() error, error) {
	return startCredentialMetadataReader(ctx, b, func(ctx context.Context, connection *net.UnixConn) error {
		return serveHelperConnection(ctx, connection, b, manager, true)
	})
}

// The injected function is an internal transport seam; production always uses
// the authenticated, metadata-only helper reader above.
func startCredentialMetadataReader(ctx context.Context, b installation, read func(context.Context, *net.UnixConn) error) (func() error, error) {
	path := b.credentialMetadataPath()
	if err := recoverSocketAt(ctx, path, 0, b.Service.GID); err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, failure("unavailable", "credential metadata endpoint is unavailable")
	}
	listener.SetUnlinkOnClose(true)
	raw, err := listener.SyscallConn()
	if err != nil {
		listener.Close()
		return nil, err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || socketErr != nil {
		listener.Close()
		return nil, errors.Join(err, socketErr)
	}
	if err := errors.Join(os.Chown(path, 0, int(b.Service.GID)), os.Chmod(path, 0660)); err != nil {
		listener.Close()
		return nil, err
	}
	stopped := make(chan struct{})
	var readers sync.WaitGroup
	diagnosticErrors := make(chan error, 1)
	endpointCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(endpointCtx, func() { listener.Close() })
	go func() {
		defer close(stopped)
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			readers.Add(1)
			go func(connection *net.UnixConn) {
				defer readers.Done()
				defer connection.Close()
				closeOnStop := context.AfterFunc(endpointCtx, func() { connection.Close() })
				defer closeOnStop()
				requestErr := read(endpointCtx, connection)
				if requestErr != nil {
					if _, err := fmt.Fprintln(os.Stderr, "credential metadata request: refused or transport closed"); err != nil {
						select {
						case diagnosticErrors <- failure("unavailable", "cannot retain credential metadata diagnostic"):
						default:
						}
						cancel()
					}
				}
			}(connection)
		}
	}()
	return func() error {
		cancel()
		stop()
		err := listener.Close()
		<-stopped
		readers.Wait()
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		select {
		case diagnosticErr := <-diagnosticErrors:
			err = errors.Join(err, diagnosticErr)
		default:
		}
		return err
	}, nil
}

// ResolveCredentialRuntime is the private component's "helper.ResolveRuntime"
// port. The outside broker calls it inside its transfer while the helper's
// ordinary prepare still waits on that transfer: prepare keeps the ordinary
// listener and helperMu, and a callback borrows only the lent operationMu on
// the metadata endpoint (CREDENTIALS.md: "The ordinary mutation listener and
// existing helper state lock remain serialized; only the current outside call
// can lend that lock."). ResolveRuntime's resolve_storage, register_spec and
// probe wait behind that prepare (box 68 and 69: 10 s, then prepare's recv
// deadline). This keeps ResolveRuntime's service-side checks and reads the
// runtime only through resolve_runtime here. The same attempt's ResolveRuntime
// registered the spec, storage and namespace before prepare; resolve_runtime
// requires that exact registered handoff and ready storage, and its storage
// home and workspace are compared with the plan below.
func (s *Service) ResolveCredentialRuntime(ctx context.Context, handoff api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	if err := validateCause(handoff.Cause, s.deps.Config, api.InternalHelperRegister); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if handoff.Spec.Kind != "agent" || handoff.Spec.Runner == nil || handoff.Spec.Worker != nil {
		return api.ResolvedRuntime{}, failure(api.CodeUnsupported, "fixed worker runtime needs its separate leased job descriptor handoff")
	}
	authority, err := s.registrationLaunchAuthority(ctx, handoff)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if authority.Record.Plan == nil || authority.Record.Handoff == nil || !samePreparedHandoffStable(*authority.Record.Handoff, handoff) {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "runtime resolution has no exact retained plan and handoff")
	}
	if err := api.ValidateAgentLaunchSpec(handoff.Spec, *authority.Record.Plan); err != nil {
		return api.ResolvedRuntime{}, err
	}
	_, manifest, err := s.loadLaunchEnrollment(ctx)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if err := enrolledExecutable(manifest, handoff.Spec.Runner.Executable); err != nil {
		return api.ResolvedRuntime{}, err
	}
	sources, err := s.runtimeLaunchSources(ctx, authority)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if !reflect.DeepEqual(sources, authority.Record.Plan.Inputs.Sources) {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "runtime sources changed after the plan was sealed")
	}
	if err := s.fenceLaunch(ctx, authority); err != nil {
		return api.ResolvedRuntime{}, err
	}
	var result api.ResolvedRuntime
	if err := s.call(ctx, "resolve_runtime", handoff, &result); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if result.Home != authority.Record.Plan.Data.Home.Home || result.Workspace.ID != handoff.Spec.Workspace.ID {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "runtime private storage differs from its actual allocation")
	}
	if !reflect.DeepEqual(result.Manifest, manifest) || result.SpecReceipt.SpecID != handoff.Spec.ID || result.SpecReceipt.SpecSHA256 != handoff.SpecSHA256 ||
		result.SpecReceipt.LeaseID != handoff.Spec.UIDLeaseID || result.SpecReceipt.RuntimeManifest != handoff.Spec.RuntimeManifest ||
		result.Home != handoff.Spec.Runner.Home || result.Workspace != handoff.Spec.Workspace ||
		result.Network.GrantSetID != handoff.Spec.Grants.ID || result.Network.Generation != handoff.Spec.PolicyGeneration ||
		!validID(result.Network.ID) || !validID(result.Network.NamespaceID) || result.Network.ExpiresAt != handoff.Spec.Grants.ExpiresAt {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "helper runtime differs from retained spec and namespace allocation")
	}
	installed, err := workerServiceBinding(s.binding)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	return laneRuntimeProjection(installed, handoff.Spec, authority.Record.Plan.Lease, result)
}

// ObserveCredentialGate is the private component's "helper.ObserveGate" port.
// The broker's AcceptCredentialRefresh calls it (secrets/projection.go:792)
// while the helper's ordinary release still waits on that refresh: release
// keeps the ordinary listener and helperMu, so observe_gate there waits until
// the release's recv deadline. This keeps ObserveGate's service-side checks and
// reads the gate only through credential_gate_observe on the metadata endpoint,
// under the lent operationMu. That read measures as observe_gate does but never
// saves the lease record, which the waiting release still holds and saves.
func (s *Service) ObserveCredentialGate(ctx context.Context, request api.HelperObserveRequest) (api.ProcessObservation, error) {
	if err := validateProcessSelector(request); err != nil {
		return api.ProcessObservation{}, err
	}
	var result api.ProcessObservation
	if err := s.call(ctx, "credential_gate_observe", request, &result); err != nil {
		return api.ProcessObservation{}, err
	}
	if result.Handle != request.Handle || result.State != "running" && result.State != "exited" {
		return api.ProcessObservation{}, failure(api.CodeIntegrity, "helper observation substituted its process")
	}
	return result, nil
}

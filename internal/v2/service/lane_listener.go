package service

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type laneEndpoint struct {
	binding api.InstalledBinding
	cancel  context.CancelFunc
	done    chan struct{}
}

func (s *Server) prepareLaneEndpoint(ctx context.Context, spec api.LaunchSpec, lease api.HelperLease) error {
	binding, err := wire.LaneEndpointBinding(s.deps.Binding, spec, lease)
	if err != nil {
		return err
	}
	return s.startLaneEndpoint(ctx, binding)
}

// The service owns the listener until revocation, terminal observation or host
// close. The preparation request ending cannot revoke a running lane's socket.
func (s *Server) startLaneEndpoint(parent context.Context, binding api.InstalledBinding) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if err := api.ValidateBinding(binding, s.options.Config, s.deps.Binding.ServiceVersion); err != nil {
		return err
	}
	if binding.Class != api.EndpointLane || binding.Socket != wire.LaneSocketPath || !wire.ValidID(string(binding.LaunchID)) ||
		binding.Target == nil || binding.ServiceUID != s.deps.Binding.ServiceUID || binding.ServiceGID != s.deps.Binding.ServiceGID ||
		binding.ArtifactSHA256 != s.deps.Binding.ArtifactSHA256 || binding.InstallationGeneration != s.deps.Binding.InstallationGeneration ||
		binding.EndpointGeneration != s.deps.Binding.EndpointGeneration {
		return serviceError(api.CodeForbidden, "lane listener requires its exact retained run binding")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.revokedLaunches[binding.LaunchID] {
		return serviceError(api.CodeForbidden, "lane endpoint is closed or revoked")
	}
	if prior := s.laneEndpoints[binding.LaunchID]; prior != nil {
		if !reflect.DeepEqual(prior.binding, binding) {
			return serviceError(api.CodeConflict, "lane endpoint retry changed its retained binding")
		}
		return nil
	}
	base := filepath.Join(filepath.Dir(s.deps.Binding.Socket), "lanes")
	if err := os.Mkdir(base, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return serviceError(api.CodePrerequisite, "lane endpoint directory is unavailable")
	}
	if err := runtimeDirectory(base, binding.ServiceUID); err != nil {
		return err
	}
	info, err := os.Lstat(base)
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return serviceError(api.CodeIntegrity, "lane endpoint parent must be private to its service")
	}
	host := binding
	host.Socket = filepath.Join(base, string(binding.LaunchID)+".sock")
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	listener, err := listenLane(ctx, host)
	if err != nil {
		cancel()
		return err
	}
	inode, err := os.Lstat(host.Socket)
	if err != nil {
		cancel()
		return errors.Join(err, listener.Close())
	}
	entry := &laneEndpoint{binding: binding, cancel: cancel, done: make(chan struct{})}
	if s.laneEndpoints == nil {
		s.laneEndpoints = make(map[api.ID]*laneEndpoint)
	}
	s.laneEndpoints[binding.LaunchID] = entry
	s.workers.Add(1)
	go s.serveLaneEndpoint(ctx, listener, host.Socket, inode, entry)
	return nil
}

func (s *Server) serveLaneEndpoint(ctx context.Context, listener net.Listener, path string, inode os.FileInfo, entry *laneEndpoint) {
	defer s.workers.Done()
	var failure string
	defer func() { s.journalLaneClose(entry.binding, "", failure) }()
	defer entry.cancel()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.recordFault(err)
		}
		current, err := os.Lstat(path)
		if err == nil && os.SameFile(inode, current) {
			if err := os.Remove(path); err != nil {
				s.recordFault(err)
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			s.recordFault(err)
		}
		s.mu.Lock()
		delete(s.laneEndpoints, entry.binding.LaunchID)
		close(entry.done)
		s.mu.Unlock()
	}()
	var refusals sync.WaitGroup
	defer refusals.Wait()
	slots := make(chan struct{}, 16)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				failure = "accept_failure"
				if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
					failure = "accept_fd_limit"
				}
				s.recordFault(err)
			}
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			s.refuseOverload(ctx, connection, serviceError(api.CodeUnavailable, "lane connection admission limit reached"), &refusals)
			continue
		}
		s.mu.Lock()
		if s.closed || ctx.Err() != nil || s.revokedLaunches[entry.binding.LaunchID] {
			reason := "late_accept"
			if s.closed {
				reason = "closed_entry"
			} else if s.revokedLaunches[entry.binding.LaunchID] {
				reason = "revoked_entry"
			}
			s.mu.Unlock()
			<-slots
			connection.Close()
			s.journalLaneClose(entry.binding, "", reason)
			continue
		}
		s.workers.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.workers.Done()
			defer func() { <-slots }()
			s.serveBoundConnection(ctx, connection, entry.binding)
		}()
	}
}

func (s *Server) stopLaneEndpoint(ctx context.Context, launchID api.ID) error {
	s.mu.RLock()
	entry := s.laneEndpoints[launchID]
	s.mu.RUnlock()
	if entry == nil {
		return nil
	}
	entry.cancel()
	select {
	case <-entry.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

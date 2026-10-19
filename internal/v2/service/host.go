package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func installedServer(options Options, deps Dependencies) (*Server, error) {
	if err := api.ValidateBinding(deps.Binding, options.Config, release.Version); err != nil {
		return nil, err
	}
	binding, err := wire.ReadBinding(options.BindingFile, options.Config, release.Version)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(binding, deps.Binding) {
		return nil, serviceError(api.CodeConflict, "boot binding differs from protected binding")
	}
	if os.Geteuid() == 0 || uint32(os.Geteuid()) != binding.ServiceUID || uint32(os.Getegid()) != binding.ServiceGID {
		return nil, serviceError(api.CodePrerequisite, "host requires the dedicated installed service identity")
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		return nil, err
	}
	if digest != binding.ArtifactSHA256 {
		return nil, serviceError(api.CodeVersion, "host executable differs from installed binding")
	}
	if err := runtimeDirectory(filepath.Dir(binding.Socket), binding.ServiceUID); err != nil {
		return nil, err
	}
	controller, err := wire.NewID()
	if err != nil {
		return nil, err
	}
	return &Server{deps: deps, controller: controller, options: options, verified: true, handlers: make(map[api.Method]api.Handler),
		streams: make(map[api.Method]api.StreamHandler), connections: make(map[api.ID]*connectionContext), flights: make(map[string]chan struct{})}, nil
}

func runtimeDirectory(path string, uid uint32) error {
	physical, err := filepath.EvalSymlinks(path)
	if err != nil || physical != path {
		return serviceError(api.CodePrerequisite, "runtime directory is missing or linked")
	}
	for directory := path; ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return serviceError(api.CodePrerequisite, "runtime ancestor permits untrusted writes")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uid {
			return serviceError(api.CodePrerequisite, "runtime ancestor has an untrusted owner")
		}
		if directory == path && stat.Uid != uid {
			return serviceError(api.CodePrerequisite, "runtime directory must belong to service")
		}
		if directory == "/" {
			return nil
		}
	}
}

func (s *Server) BindRuntime(ctx context.Context, runtime api.RuntimeServices) error {
	if err := ctx.Err(); err != nil {
		return contextError(err)
	}
	s.mu.Lock()
	if s.closed || s.serving || s.bound {
		s.mu.Unlock()
		return serviceError(api.CodeConflict, "runtime is already bound or host is closed")
	}
	if !s.verified || !sameDependency(runtime.Store, s.deps.Store) || !sameDependency(runtime.Identity, s.deps.Authenticator) ||
		runtime.Config != s.options.Config || runtime.Socket != s.deps.Binding.Socket || runtime.ArtifactSHA256 != s.deps.Binding.ArtifactSHA256 {
		s.mu.Unlock()
		return serviceError(api.CodeConflict, "runtime dependencies differ from installed host")
	}
	s.mu.Unlock()
	// Validate all incomplete effects, including unexpired claims. The first
	// runnable page alone is not the installed startup/recovery inventory.
	control, ok := runtime.Store.(dispatchStore)
	if !ok {
		return serviceError(api.CodePrerequisite, "installed store lacks durable dispatch controls")
	}
	freeze, err := control.ActiveDispatchFreeze(ctx)
	if err != nil {
		return err
	}
	effects, err := control.DispatchEffects(ctx)
	if err != nil {
		return err
	}
	for _, record := range effects {
		if freeze == nil {
			scope := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: s.controller}, Source: "worker"}
			retained, err := retainedMaterialization(ctx, runtime.Store, scope, record.Effect)
			if err != nil {
				return err
			}
			if retained {
				continue
			}
			retained, err = retainedUsage(ctx, runtime.Store, scope, record.Effect)
			if err != nil {
				return err
			}
			if retained {
				continue
			}
			retained, err = retainedReviewWorker(ctx, runtime.Store, scope, record.Effect)
			if err != nil {
				return err
			}
			if retained {
				continue
			}
			retained, err = retainedAgentPrepare(ctx, runtime.Store, scope, record.Effect)
			if err != nil {
				return err
			}
			if retained {
				continue
			}
			if err := supportsEffect(runtime, record.Effect); err != nil {
				if unsupportedWorker(record.Effect, err) != nil {
					continue // The reconciler retains this pre-execution refusal.
				}
				_, canFail := runtime.Store.(ownedFailureStore)
				owned := record.Effect.Clean != nil || record.Effect.Worker != nil && record.Effect.Worker.Kind == "archive"
				// Starting the writer's failure reconciler grants no missing
				// native capability. It records this owned refusal and continues.
				if !owned || !canFail || effectFenceRefused(err) {
					return err
				}
			}
		}
	}
	launchConfigured := usableDependency(runtime.LaunchPlanner) && usableDependency(runtime.Helper) && usableDependency(runtime.Launcher) && usableDependency(runtime.Worker)
	if launchConfigured {
		inventory, ok := runtime.Store.(launchControlStore)
		if !ok {
			return serviceError(api.CodePrerequisite, "launch runtime lacks actual retained recovery and capture jobs")
		}
		if _, err := inventory.LaunchInventory(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.serving || s.bound {
		return serviceError(api.CodeConflict, "runtime changed while reconciliation was inspected")
	}
	if binder, ok := runtime.Store.(interface{ BindReviewRuntime(any, any) error }); ok {
		if _, native := runtime.Helper.(interface {
			FreezeReview(context.Context, archivejob.Intent, api.Lane) (archivejob.Snapshot, error)
			CheckReviewFreeze(context.Context, archivejob.Intent, archivejob.Freeze) error
			RequiredReviewChecks(context.Context, api.Scope, api.LifeRef) ([]string, error)
		}); native {
			if err := binder.BindReviewRuntime(runtime.Helper, s); err != nil {
				return err
			}
		}
	}
	s.runtime, s.bound = runtime, true
	s.launchConfigured = launchConfigured
	s.freeze, s.dispatchPaused = freeze, freeze != nil
	return nil
}

func (s *Server) ServeInstalled(ctx context.Context) (resultErr error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	if !s.bound || s.closed || s.serving || s.starting {
		s.mu.Unlock()
		return serviceError(api.CodePrerequisite, "installed host runtime is not bound")
	}
	binding := s.deps.Binding
	s.starting, s.cancel = true, cancel
	s.workers.Add(1)
	s.mu.Unlock()
	defer s.workers.Done()
	defer func() { s.mu.Lock(); s.starting = false; s.mu.Unlock() }()
	if s.launchConfigured {
		// Owner R181 (product first): a scheduler that cannot install on this installation (for example a fresh one
		// with no scheduler state yet) must not stop the whole service. Journal its reason word and serve without it.
		if err := s.installScheduler(runCtx); err != nil {
			line, _ := json.Marshal(struct {
				Event  string `json:"event"`
				Reason string `json:"reason"`
			}{"scheduler_unavailable", effectReason(err)})
			_, _ = os.Stderr.Write(append(line, '\n'))
		}
	}
	closeEnrollment, err := s.startEnrollment(runCtx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeEnrollment()) }()
	if err := runtimeDirectory(filepath.Dir(binding.Socket), binding.ServiceUID); err != nil {
		return err
	}
	if _, err := os.Lstat(binding.Socket); !errors.Is(err, os.ErrNotExist) {
		return serviceError(api.CodeConflict, "installed socket path already exists; preserve it for supervised recovery")
	}
	listener, err := listenInstalled(runCtx, binding)
	if err != nil {
		return serviceError(api.CodeUnavailable, "cannot open installed socket")
	}
	unixListener := listener.(*net.UnixListener)
	unixListener.SetUnlinkOnClose(false)
	info, err := os.Lstat(binding.Socket)
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	defer func() {
		closeErr := listener.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
		current, statErr := os.Lstat(binding.Socket)
		if statErr == nil && os.SameFile(info, current) {
			closeErr = errors.Join(closeErr, os.Remove(binding.Socket))
		}
		resultErr = errors.Join(resultErr, closeErr)
	}()
	s.mu.Lock()
	if s.closed || runCtx.Err() != nil {
		s.mu.Unlock()
		return contextError(context.Canceled)
	}
	s.listener = listener
	s.workers.Add(1)
	s.mu.Unlock()
	go func() { defer s.workers.Done(); s.reconcileLoop(runCtx) }()
	s.mu.Lock()
	s.workers.Add(1)
	s.mu.Unlock()
	go func() { defer s.workers.Done(); s.launchRecoveryLoop(runCtx) }()
	s.mu.RLock()
	scheduled := s.launchConfigured && s.scheduler != nil
	s.mu.RUnlock()
	if scheduled {
		s.mu.Lock()
		s.workers.Add(1)
		s.mu.Unlock()
		go func() { defer s.workers.Done(); s.schedulerLoop(runCtx) }()
	}
	return s.Serve(runCtx, listener)
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		select {
		case <-done:
			s.mu.RLock()
			defer s.mu.RUnlock()
			return s.closeResult
		case <-time.After(5 * time.Second):
			return serviceError(api.CodeIntegrity, "host close is still draining")
		}
	}
	s.closed = true
	s.closeDone = make(chan struct{})
	cancel, listener := s.cancel, s.listener
	workerStops := make([]context.CancelFunc, 0, len(s.workerStops))
	for _, stop := range s.workerStops {
		workerStops = append(workerStops, stop)
	}
	for _, endpoint := range s.laneEndpoints {
		workerStops = append(workerStops, endpoint.cancel)
	}
	connections := make([]*connectionContext, 0, len(s.connections))
	for _, connection := range s.connections {
		connections = append(connections, connection)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, stop := range workerStops {
		stop()
	}
	var result error
	retain := func(closer string, kind api.EndpointClass, err error) {
		if err != nil {
			result = errors.Join(result, err, journalCloseErrors(os.Stderr, closer, kind, err))
		}
	}
	if listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retain("listener", "", err)
		}
	}
	for _, connection := range connections {
		retain("connection", connection.Binding().Class, connection.Close())
	}
	done := make(chan struct{})
	go func() { s.workers.Wait(); close(done) }()
	drained := false
	select {
	case <-done:
		drained = true
	case <-time.After(5 * time.Second):
		retain("worker_drain", "", serviceError(api.CodeIntegrity, "host workers did not drain"))
	}
	if drained {
		if closer, ok := s.deps.Store.(io.Closer); ok {
			retain("store", "", closer.Close())
		} else {
			retain("store", "", serviceError(api.CodeIntegrity, "owned store cannot close"))
		}
	}
	s.mu.Lock()
	retain("prior_fault", "", s.fault)
	s.fault = result
	s.closeResult = result
	close(s.closeDone)
	s.mu.Unlock()
	return result
}

// Emit each joined cause before assembly replaces the close result with its
// fixed shutdown refusal. Only component diagnostics and native error classes
// enter the journal: never a wrapper's Error(), paths, IDs or recovery payloads.
func journalCloseErrors(writer io.Writer, closer string, kind api.EndpointClass, cause error) error {
	if cause == nil {
		return nil
	}
	switch wrapped := cause.(type) {
	case interface{ Unwrap() []error }:
		var result error
		for _, child := range wrapped.Unwrap() {
			result = errors.Join(result, journalCloseErrors(writer, closer, kind, child))
		}
		return result
	case interface{ Unwrap() error }:
		if child := wrapped.Unwrap(); child != nil {
			return journalCloseErrors(writer, closer, kind, child)
		}
	}
	failure := typedError(cause)
	message := errorDetail(failure)
	switch cause {
	case io.EOF:
		message = "EOF"
	case io.ErrUnexpectedEOF:
		message = "unexpected EOF"
	case net.ErrClosed:
		message = "network connection already closed"
	case os.ErrClosed:
		message = "file already closed"
	default:
		if errno, ok := cause.(syscall.Errno); ok {
			message = errno.Error()
		}
	}
	data, err := json.Marshal(struct {
		Event          string            `json:"event"`
		Closer         string            `json:"closer"`
		ConnectionKind api.EndpointClass `json:"connection_kind,omitempty"`
		Code           api.ErrorCode     `json:"code"`
		Owner          string            `json:"owner"`
		Message        string            `json:"message"`
	}{"service_close_error", closer, kind, failure.Code, failure.Owner, message})
	if err != nil {
		return serviceError(api.CodeIntegrity, "cannot encode service close journal")
	}
	data = append(data, '\n')
	if count, err := writer.Write(data); err != nil || count != len(data) {
		return serviceError(api.CodeIntegrity, "cannot retain service close journal")
	}
	return nil
}

func supportsEffect(runtime api.RuntimeServices, effect api.Effect) error {
	switch {
	case effect.Worker != nil && effect.Worker.Kind == "archive":
		_, storeOK := runtime.Store.(archiveStore)
		_, helperOK := runtime.Helper.(archiveHelper)
		_, retirementStoreOK := runtime.Store.(archiveRetirementStore)
		_, retirementHelperOK := runtime.Helper.(archivejob.RetirementHelper)
		if storeOK && helperOK && retirementStoreOK && retirementHelperOK && usableDependency(runtime.Helper) {
			return nil
		}
		return api.NotImplemented("lb-v2-admin", "installed archive worker helper and single writer ports")
	case effect.Clean != nil:
		_, storeOK := runtime.Store.(cleanupStore)
		_, workerOK := runtime.Worker.(api.CleanupDataWorker)
		if storeOK && workerOK && usableDependency(runtime.Worker) {
			availability, ok := runtime.Store.(interface{ CleanupNativeReady() bool })
			if !ok || !availability.CleanupNativeReady() {
				return api.NotImplemented("lb-v2-admin", "installed protected cleanup native ports")
			}
			return nil
		}
		return api.NotImplemented("lb-v2-grants", "installed owned collection orchestrator and store ports")
	case effect.PlanLaunch != nil:
		if usableDependency(runtime.LaunchPlanner) && usableDependency(runtime.Helper) && usableDependency(runtime.Worker) && usableDependency(runtime.Launcher) {
			return nil
		}
		return serviceError(api.CodePrerequisite, "launch planning requires LaunchPlanner, helper, data worker and launcher")
	case effect.Launch != nil:
		if runtime.LaunchPlanner != nil && runtime.Launcher != nil && runtime.Helper != nil {
			return nil
		}
	case effect.HelperAllocate != nil, effect.HelperPrepare != nil, effect.HelperRelease != nil, effect.HelperAbort != nil:
		if runtime.Helper != nil {
			return nil
		}
	case effect.Stop != nil:
		if runtime.Launcher != nil {
			return nil
		}
	case effect.ApplyChange != nil:
		if source, ok := runtime.Store.(changePublicationSource); ok && usableDependency(source) && usableDependency(runtime.Publisher) {
			return nil
		}
		return serviceError(api.CodePrerequisite, "org publication requires its original store reservation and pinned publisher")
	case effect.Deliver != nil:
		if coordinator, ok := runtime.Delivery.(mailDeliveryCoordinator); ok && usableDependency(coordinator) {
			return nil
		}
		return api.NotImplemented("lb-v2-messaging", "installed logical-turn delivery coordinator")
	case effect.Worker != nil, effect.Bootstrap != nil:
		return api.NotImplemented("lb-v2-service", "effect execution requires its owning coordinator")
	case effect.Channel != nil:
		if runtime.Delivery != nil {
			return nil
		}
	default:
		return api.NotImplemented("lb-v2-service", "effect reconciliation for requested payload")
	}
	return serviceError(api.CodePrerequisite, "pending effect lacks its bound runtime dependency")
}

func usableDependency(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return !v.IsNil()
	default:
		return true
	}
}

func (s *Server) closeResource(resource io.Closer) {
	if err := resource.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.recordFault(err)
	}
}

func sameDependency(left, right any) bool {
	if left == nil || right == nil || reflect.TypeOf(left) != reflect.TypeOf(right) || !reflect.TypeOf(left).Comparable() {
		return false
	}
	value := reflect.ValueOf(left)
	if (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) && value.IsNil() {
		return false
	}
	return left == right
}

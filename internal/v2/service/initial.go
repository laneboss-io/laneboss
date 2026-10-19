package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
)

var _ admin.InitialPublisher = (*Server)(nil)

// PublishInitial is reached only by the native administrator listener. It is
// absent from public Methods and carries no caller-created internal Scope.
func (s *Server) PublishInitial(ctx context.Context, request admin.InitialRequest) (admin.InitialReceipt, error) {
	s.mu.RLock()
	profiles := s.initialProfiles
	s.mu.RUnlock()
	return admin.PublishInitial(admin.WithInitialTiming(ctx, s.journalInitialStage), request, s.deps.Store, s.deps.Clock, profiles)
}

// BindInitialProfiles is composition-only and frozen before host startup.
func (s *Server) BindInitialProfiles(profiles admin.InitialProfileEnrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if profiles == nil || s.initialProfiles != nil || s.closed || s.starting || s.serving {
		return serviceError(api.CodeConflict, "initial profile enrollment is absent or frozen")
	}
	s.initialProfiles = profiles
	return nil
}

func (s *Server) PublishInitialFrame(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, scope api.Scope, request admin.InitialRequest) (receipt admin.InitialReceipt, resultErr error) {
	started := time.Now()
	defer func() {
		if err := s.journalInitialStage("total", time.Since(started)); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	nativeStarted := time.Now()
	bound, err := admin.InitialContext(ctx, endpoint, scope.Connection, scope.Frame)
	if timedErr := s.journalInitialStage("native_context", time.Since(nativeStarted)); err != nil || timedErr != nil {
		return admin.InitialReceipt{}, errors.Join(err, timedErr)
	}
	return s.PublishInitial(bound, request)
}

func (s *Server) journalInitialStage(stage string, elapsed time.Duration) error {
	switch stage {
	case "native_context", "protected_read", "load_validate", "bundle_validate", "object_hashes", "policy_validate", "template_validate", "revalidate", "plan", "seal", "commit", "read_object", "read_back", "total":
	default:
		return serviceError(api.CodeIntegrity, "unknown initial publication timing stage")
	}
	data, err := json.Marshal(struct {
		Stage     string `json:"stage"`
		ElapsedMS int64  `json:"elapsed_ms"`
	}{"initial_publish." + stage, elapsed.Milliseconds()})
	if err == nil {
		data = append(data, '\n')
		var count int
		count, err = os.Stderr.Write(data)
		if err == nil && count != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		failure := serviceError(api.CodeUnavailable, "cannot retain initial publication stage timing")
		s.recordFault(failure)
		return failure
	}
	return nil
}

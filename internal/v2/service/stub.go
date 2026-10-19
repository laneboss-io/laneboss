// Package service is owned by lb-v2-service.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type Dependencies struct {
	Enrollment        api.EnrollmentValidator
	Binding           api.InstalledBinding
	Store             api.StateStore
	Authenticator     api.Authenticator
	Clock             api.Clock
	IsolationEvidence IsolationEvidence
}

type Service struct {
	deps     Dependencies
	artifact api.Digest
}

func New(deps Dependencies) (*Service, error) {
	if deps.Store == nil || deps.Authenticator == nil || deps.Clock == nil {
		return nil, wire.Invalid("service requires store, authenticator and clock")
	}
	path, err := os.Executable()
	if err != nil {
		return nil, serviceError(api.CodePrerequisite, "service artifact is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, serviceError(api.CodePrerequisite, "service artifact is unreadable")
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, serviceError(api.CodeIntegrity, "service artifact hashing failed")
	}
	return &Service{deps: deps, artifact: api.Digest(hex.EncodeToString(hash.Sum(nil)))}, nil
}

var _ api.ServiceAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if registry == nil {
		return wire.Invalid("RPC registrar is required")
	}
	entries := []struct {
		method  api.Method
		handler api.Handler
	}{
		{"health", handler(s.Health)},
		{"operation.get", handler(s.OperationGet)},
		{"blob.begin", handler(s.BlobBegin)},
		{"blob.chunk", handler(s.BlobChunk)},
		{"blob.commit", handler(s.BlobCommit)},
		{"blob.read", handler(s.BlobRead)},
		{"store.verify", handler(s.StoreVerify)},
		{"store.rebuild", handler(s.StoreRebuild)},
	}
	for _, entry := range entries {
		if err := registry.Register(entry.method, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Health(ctx context.Context, scope api.Scope, request api.HealthRequest) (api.Health, error) {
	if err := ctx.Err(); err != nil {
		return api.Health{}, contextError(err)
	}
	if err := validateServiceInput("health", request); err != nil {
		return api.Health{}, err
	}
	if request.ClientVersion != identity.Version || request.ArtifactSHA256 != s.artifact {
		return api.Health{}, serviceError(api.CodeVersion, "client and service artifacts are incompatible")
	}
	observation, public := ctx.Value(publicHealthKey{}).(publicHealthObservation)
	if !public {
		return api.Health{}, serviceError(api.CodeForbidden, "health requires the first-frame public health path")
	}
	// Public health receives transport facts, never an authenticated Scope.
	// Transport already read the sole permitted store snapshot for this call.
	bindingErr := api.ValidateBinding(s.deps.Binding, observation.snapshot.Config, identity.Version)
	capabilities := []api.Capability{
		{Name: "state-snapshot", Available: observation.snapshot.Config == s.deps.Binding.Config && observation.snapshot.AsOf != "", Reason: "observed service-owned health snapshot"},
		{Name: "binding-shape", Available: bindingErr == nil && s.deps.Binding.ArtifactSHA256 == s.artifact, Reason: "compiled contract and measured executable"},
		{Name: "native-peer", Available: observation.frame != nil && observation.peer.PID > 0, Reason: "observed kernel peer and every-fragment writer credentials"},
	}
	capabilities = append(capabilities, buildCapability())
	ready := true
	for _, capability := range capabilities {
		ready = ready && capability.Available
	}
	return api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion,
		ServiceVersion: identity.Version, ArtifactSHA256: s.artifact, Ready: ready, Capabilities: capabilities}, nil
}

func (s *Service) OperationGet(ctx context.Context, scope api.Scope, request api.OperationGetRequest) (api.Operation, error) {
	if err := validateServiceInput("operation.get", request); err != nil {
		return api.Operation{}, err
	}
	if err := s.authorize(ctx, scope, "operation.get"); err != nil {
		return api.Operation{}, err
	}
	return s.deps.Store.Operation(ctx, scope, request.OperationID)
}

func (s *Service) BlobBegin(ctx context.Context, scope api.Scope, request api.BlobBeginRequest) (api.BlobUpload, error) {
	if err := validateServiceInput("blob.begin", request); err != nil {
		return api.BlobUpload{}, err
	}
	if err := s.authorize(ctx, scope, "blob.begin"); err != nil {
		return api.BlobUpload{}, err
	}
	if request.Bytes < 0 || request.Bytes > api.MaxObjectBytes || !wire.ValidDigest(string(request.SHA256)) {
		return api.BlobUpload{}, wire.Invalid("invalid upload declaration")
	}
	id, err := wire.NewID()
	if err != nil {
		return api.BlobUpload{}, err
	}
	lease := api.UploadLease{ID: id, Class: request.Class, DeclaredBytes: request.Bytes, SHA256: request.SHA256,
		ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339Nano)),
		ACL:       api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: scope.Actor.LifeID, Audience: "owner", Generation: 1}}
	result := api.BlobUpload{ObjectID: id, MaxChunkBytes: api.MaxChunkBytes, ExpiresAt: lease.ExpiresAt}
	return commitResult(ctx, s.deps.Store, scope, api.StateWrites{UploadBegins: []api.UploadLease{lease}}, nil, result)
}

func (s *Service) BlobChunk(ctx context.Context, scope api.Scope, request api.BlobChunk) (api.BlobUpload, error) {
	if err := validateServiceInput("blob.chunk", request); err != nil {
		return api.BlobUpload{}, err
	}
	if err := s.authorize(ctx, scope, "blob.chunk"); err != nil {
		return api.BlobUpload{}, err
	}
	lease, err := s.deps.Store.Upload(ctx, scope, request.ObjectID)
	if err != nil {
		return api.BlobUpload{}, err
	}
	result := api.BlobUpload{ObjectID: lease.ID, MaxChunkBytes: api.MaxChunkBytes, ExpiresAt: lease.ExpiresAt}
	return commitResult(ctx, s.deps.Store, scope, api.StateWrites{UploadChunks: []api.BlobChunk{request}}, nil, result)
}

func (s *Service) BlobCommit(ctx context.Context, scope api.Scope, request api.BlobCommitRequest) (api.BlobRef, error) {
	if err := validateServiceInput("blob.commit", request); err != nil {
		return api.BlobRef{}, err
	}
	if err := s.authorize(ctx, scope, "blob.commit"); err != nil {
		return api.BlobRef{}, err
	}
	lease, err := s.deps.Store.Upload(ctx, scope, request.ObjectID)
	if err != nil {
		return api.BlobRef{}, err
	}
	ref := api.BlobRef{ID: lease.ID, Class: lease.Class, Bytes: lease.DeclaredBytes, SHA256: lease.SHA256}
	payload, err := json.Marshal(ref)
	if err != nil {
		return api.BlobRef{}, err
	}
	id, err := wire.NewID()
	if err != nil {
		return api.BlobRef{}, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: "blob.committed", Actor: scope.Actor,
		RequestedBy: scope.Actor, LifeID: scope.Actor.LifeID, Origin: "observation", StarterChain: []api.ID{}, Payload: payload}
	if scope.Actor.Kind == "lane" {
		launch, err := s.deps.Store.Launch(ctx, scope.LaunchID)
		if err != nil {
			return api.BlobRef{}, err
		}
		event.Run = launch.Target.Run
	}
	return commitResult(ctx, s.deps.Store, scope, api.StateWrites{UploadCommits: []api.BlobCommitRequest{request}}, []api.Event{event}, ref)
}

func (s *Service) BlobRead(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if err := validateServiceInput("blob.read", request); err != nil {
		return api.BlobChunk{}, err
	}
	if err := s.authorize(ctx, scope, "blob.read"); err != nil {
		return api.BlobChunk{}, err
	}
	return s.deps.Store.Blob(ctx, scope, request)
}

func (s *Service) StoreVerify(ctx context.Context, scope api.Scope, request api.VerifyRequest) (api.Verification, error) {
	if err := validateServiceInput("store.verify", request); err != nil {
		return api.Verification{}, err
	}
	if err := s.authorize(ctx, scope, "store.verify"); err != nil {
		return api.Verification{}, err
	}
	return s.deps.Store.Verify(ctx, request)
}

func (s *Service) StoreRebuild(ctx context.Context, scope api.Scope, request api.RebuildRequest) (api.Operation, error) {
	if err := validateServiceInput("store.rebuild", request); err != nil {
		return api.Operation{}, err
	}
	if err := s.authorize(ctx, scope, "store.rebuild"); err != nil {
		return api.Operation{}, err
	}
	var result api.Operation
	return result, api.NotImplemented("lb-v2-service", "service.store.rebuild")
}

func validateServiceInput(method api.Method, request any) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return &api.Error{Code: api.CodeInvalid, Owner: "lb-v2-service", Message: "invalid service request encoding", Instead: "Use the complete documented service request."}
	}
	return wire.ValidateServiceInput(method, raw)
}

func handler[Q, R any](fn func(context.Context, api.Scope, Q) (R, error)) api.Handler {
	return func(ctx context.Context, scope api.Scope, data json.RawMessage) (json.RawMessage, error) {
		var request Q
		if err := wire.Decode(data, &request); err != nil {
			return nil, err
		}
		result, err := fn(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, serviceError(api.CodeIntegrity, "service result encoding failed")
		}
		return encoded, nil
	}
}

func (s *Service) authorize(ctx context.Context, scope api.Scope, method api.Method) error {
	if scope.Request.Method != method || scope.Config != scope.Request.Config {
		return api.WithErrorComponent(serviceError(api.CodeUnauthenticated, "dispatcher-authenticated request metadata is required"), "service_authorize")
	}
	if err := wire.ValidateRequest(scope.Request); err != nil {
		return err
	}
	return s.deps.Authenticator.Authorize(ctx, scope, scope.Request)
}

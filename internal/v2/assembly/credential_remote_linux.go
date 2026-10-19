//go:build linux

package assembly

import (
	"context"
	"encoding/json"
	"errors"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
	"sync"
)

type credentialRemote struct{ config string }

func credentialRemoteCall[T any](ctx context.Context, r credentialRemote, method string, args ...any) (value T, resultErr error) {
	client, err := admin.DialCredentialComponent(ctx, r.config)
	if err != nil {
		return value, err
	}
	defer func() { resultErr = errors.Join(resultErr, client.Close()) }()
	input := credentialArguments{Arguments: make([]json.RawMessage, len(args))}
	for index, arg := range args {
		input.Arguments[index], err = admin.EncodeWire(struct{ Value any }{arg})
		if err != nil {
			return value, err
		}
	}
	var output struct{ Value T }
	err = client.Call(ctx, method, input, &output)
	return output.Value, err
}

type credentialRemoteStore struct {
	api.StateStore
	remote credentialRemote
}

func (r *credentialRemoteStore) CredentialProjection(ctx context.Context, c string, id api.ID) (api.CredentialProjectionRecord, error) {
	return credentialRemoteCall[api.CredentialProjectionRecord](ctx, r.remote, "store.CredentialProjection", c, id)
}
func (r *credentialRemoteStore) ReserveCredentialProjection(ctx context.Context, s api.Scope, q api.CredentialProjectionRequest) (api.CredentialProjectionRecord, error) {
	return credentialRemoteCall[api.CredentialProjectionRecord](ctx, r.remote, "store.ReserveCredentialProjection", s, q)
}
func (r *credentialRemoteStore) CommitCredentialProjection(ctx context.Context, s api.Scope, q api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error) {
	return credentialRemoteCall[api.CredentialProjectionRecord](ctx, r.remote, "store.CommitCredentialProjection", s, q)
}
func (r *credentialRemoteStore) FenceCredentialProjection(ctx context.Context, s api.Scope, q api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	return credentialRemoteCall[api.CredentialProjectionRecord](ctx, r.remote, "store.FenceCredentialProjection", s, q)
}
func (r *credentialRemoteStore) CompleteCredentialWithdrawal(ctx context.Context, s api.Scope, q api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	return credentialRemoteCall[api.CredentialProjectionRecord](ctx, r.remote, "store.CompleteCredentialWithdrawal", s, q)
}
func (r *credentialRemoteStore) CurrentApprovedPolicy(ctx context.Context, s api.Scope) (api.EffectivePolicy, error) {
	return credentialRemoteCall[api.EffectivePolicy](ctx, r.remote, "store.CurrentApprovedPolicy", s)
}
func (r *credentialRemoteStore) Policy(ctx context.Context, s api.Scope) (api.EffectivePolicy, error) {
	return credentialRemoteCall[api.EffectivePolicy](ctx, r.remote, "store.Policy", s)
}
func (r *credentialRemoteStore) Effect(ctx context.Context, s api.Scope, id api.ID) (api.EffectRecord, error) {
	return credentialRemoteCall[api.EffectRecord](ctx, r.remote, "store.Effect", s, id)
}
func (r *credentialRemoteStore) Grants(ctx context.Context, id api.ID) (api.GrantSet, error) {
	return credentialRemoteCall[api.GrantSet](ctx, r.remote, "store.Grants", id)
}
func (r *credentialRemoteStore) LaunchPlan(ctx context.Context, s api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	return credentialRemoteCall[api.LaunchPlanRecord](ctx, r.remote, "store.LaunchPlan", s, id)
}
func (r *credentialRemoteStore) LaunchBinding(ctx context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	return credentialRemoteCall[api.LaunchBindingRequest](ctx, r.remote, "store.LaunchBinding", id)
}
func (r *credentialRemoteStore) WorkerLease(ctx context.Context, s api.Scope, id api.ID) (api.WorkerLease, error) {
	return credentialRemoteCall[api.WorkerLease](ctx, r.remote, "store.WorkerLease", s, id)
}
func (r *credentialRemoteStore) Lane(ctx context.Context, s api.Scope, target api.LifeRef) (api.Lane, error) {
	return credentialRemoteCall[api.Lane](ctx, r.remote, "store.Lane", s, target)
}
func (r *credentialRemoteStore) ObjectMetadata(ctx context.Context, s api.Scope, id api.ID) (api.ObjectMetadata, error) {
	return credentialRemoteCall[api.ObjectMetadata](ctx, r.remote, "store.ObjectMetadata", s, id)
}
func (r *credentialRemoteStore) Blob(ctx context.Context, s api.Scope, q api.BlobReadRequest) (api.BlobChunk, error) {
	return credentialRemoteCall[api.BlobChunk](ctx, r.remote, "store.Blob", s, q)
}

type credentialRemoteGrants struct {
	api.GrantResolver
	remote credentialRemote
}

func (r *credentialRemoteGrants) Resolve(ctx context.Context, s api.Scope, q api.GrantResolveRequest) (api.GrantSet, error) {
	return credentialRemoteCall[api.GrantSet](ctx, r.remote, "grants.Resolve", s, q)
}
func (r *credentialRemoteGrants) Revalidate(ctx context.Context, q api.GrantSet) (api.GrantSet, error) {
	return credentialRemoteCall[api.GrantSet](ctx, r.remote, "grants.Revalidate", q)
}

type credentialRemoteHelper struct {
	api.HelperControl
	remote credentialRemote
}

func (r *credentialRemoteHelper) ScanAPIKeyRelease(ctx context.Context, a api.CredentialProjectionAuthority, material api.SecretMaterial) (rscan.APIKeyScanResult, error) {
	return rscan.ReadNativeReleaseScan(ctx, a, material)
}

func (r *credentialRemoteHelper) ResolveRuntime(ctx context.Context, q api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	return credentialRemoteCall[api.ResolvedRuntime](ctx, r.remote, "helper.ResolveRuntime", q)
}
func (r *credentialRemoteHelper) ObserveCredentials(ctx context.Context, id api.ID) (api.CredentialProjectionReceipt, error) {
	return credentialRemoteCall[api.CredentialProjectionReceipt](ctx, r.remote, "helper.ObserveCredentials", id)
}
func (r *credentialRemoteHelper) ObserveGate(ctx context.Context, q api.HelperObserveRequest) (api.ProcessObservation, error) {
	return credentialRemoteCall[api.ProcessObservation](ctx, r.remote, "helper.ObserveGate", q)
}
func (r *credentialRemoteHelper) ReadCredentialWithdrawal(ctx context.Context, q api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	return credentialRemoteCall[api.CredentialWithdrawalReceipt](ctx, r.remote, "helper.ReadCredentialWithdrawal", q)
}

type credentialRemoteControl struct {
	api.LaunchControlSource
	remote credentialRemote
}

func (r *credentialRemoteControl) Handoff(ctx context.Context, q api.LaunchSpec) (api.PreparedSpecHandoff, error) {
	return credentialRemoteCall[api.PreparedSpecHandoff](ctx, r.remote, "control.Handoff", q)
}
func (r *credentialRemoteControl) Open(ctx context.Context, p api.PreparedLaunch, q api.LaunchPermit) (api.HelperOpenRequest, error) {
	return credentialRemoteCall[api.HelperOpenRequest](ctx, r.remote, "control.Open", p, q)
}

type credentialRemoteIdentity struct {
	api.HumanVerifier
	remote credentialRemote
}

func (r *credentialRemoteIdentity) AuthorizeCredentialProjection(ctx context.Context, peer api.VerifiedPeer, q api.CredentialProjectionRequest) (value api.CredentialProjectionAuthority, resultErr error) {
	facts, err := peer.Facts(ctx)
	if err != nil {
		return value, err
	}
	client, err := admin.DialCredentialComponent(ctx, r.remote.config)
	if err != nil {
		return value, err
	}
	defer func() { resultErr = errors.Join(resultErr, client.Close()) }()
	var output struct {
		Value api.CredentialProjectionAuthority
	}
	err = client.Call(ctx, "identity.authorize", struct {
		Peer    api.PeerFacts
		Request api.CredentialProjectionRequest
	}{facts, q}, &output)
	return output.Value, err
}
func (r *credentialRemoteIdentity) CheckLaunchCredentials(ctx context.Context, q api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	return credentialRemoteCall[api.CredentialProjectionRecord](ctx, r.remote, "identity.CheckLaunchCredentials", q)
}

// The persistent storage stream owns its flock and refresh handles. A lost
// stream is never reconnected under an existing journal or refresh lease.
type credentialRemoteStorage struct {
	mu     sync.Mutex
	config string
	client *admin.CredentialComponentClient
}

func (s *credentialRemoteStorage) call(ctx context.Context, method string, q credentialStorageInput, output any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		client, err := admin.DialCredentialComponent(ctx, s.config)
		if err != nil {
			return err
		}
		s.client = client
	}
	return s.client.Call(ctx, "storage."+method, q, output)
}
func (s *credentialRemoteStorage) empty(ctx context.Context, method string, q credentialStorageInput) error {
	var out struct{ Value api.Empty }
	return s.call(ctx, method, q, &out)
}
func (s *credentialRemoteStorage) Lock(ctx context.Context) error {
	return s.empty(ctx, "lock", credentialStorageInput{})
}
func (s *credentialRemoteStorage) Unlock() error {
	return s.empty(context.Background(), "unlock", credentialStorageInput{})
}
func (s *credentialRemoteStorage) Read(name string, max int64) ([]byte, error) {
	var out struct{ Value []byte }
	err := s.call(context.Background(), "read", credentialStorageInput{Name: name, Max: max}, &out)
	return out.Value, err
}
func (s *credentialRemoteStorage) Names() ([]string, error) {
	var out struct{ Value []string }
	err := s.call(context.Background(), "names", credentialStorageInput{}, &out)
	return out.Value, err
}
func (s *credentialRemoteStorage) Write(name string, data []byte) error {
	return s.empty(context.Background(), "write", credentialStorageInput{Name: name, Data: data})
}
func (s *credentialRemoteStorage) AcquireRefreshLease(id api.ID) (bstate.RefreshLease, error) {
	if err := s.empty(context.Background(), "refresh_acquire", credentialStorageInput{ID: id}); err != nil {
		return nil, err
	}
	return &credentialRemoteRefresh{storage: s, id: id}, nil
}
func (s *credentialRemoteStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

type credentialRemoteRefresh struct {
	storage *credentialRemoteStorage
	id      api.ID
}

func (r *credentialRemoteRefresh) Check() error {
	return r.storage.empty(context.Background(), "refresh_check", credentialStorageInput{ID: r.id})
}
func (r *credentialRemoteRefresh) Close() error {
	return r.storage.empty(context.Background(), "refresh_close", credentialStorageInput{ID: r.id})
}
func (r *credentialRemoteRefresh) Held() (bool, error) {
	var out struct{ Value struct{ Held bool } }
	err := r.storage.call(context.Background(), "refresh_held", credentialStorageInput{ID: r.id}, &out)
	return out.Value.Held, err
}

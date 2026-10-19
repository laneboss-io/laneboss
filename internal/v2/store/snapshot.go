package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type readDatabase interface {
	queryer
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}
type readView struct {
	store         *Service
	db            *sql.DB
	tx            *sql.Tx
	owner         string
	endpoint      api.Generation
	connection    api.ID
	snapshot      api.ReadSnapshot
	closed        atomic.Bool
	objectMu      sync.Mutex
	objectContext context.Context
	objectBinding objectReadBinding
	objects       map[api.ID]verifiedObject
	objectBytes   int64
	stopObjects   func() bool
}

func (v *readView) Snapshot() api.ReadSnapshot { return v.snapshot }
func (v *readView) Close() error {
	v.store.mu.Lock()
	defer v.store.mu.Unlock()
	return v.closeLocked()
}
func (v *readView) closeLocked() error {
	if v.closed.Swap(true) {
		return nil
	}
	if v.stopObjects != nil {
		v.stopObjects()
	}
	v.clearObjects()
	err := v.tx.Rollback()
	if errors.Is(err, sql.ErrTxDone) {
		err = nil
	}
	err = errors.Join(err, v.db.Close())
	delete(v.store.views, v)
	return err
}
func (s *Service) BeginRead(ctx context.Context, scope api.Scope) (api.ReadView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return nil, err
	}
	if scope.ReadView != nil {
		return nil, fault(api.CodeConflict, "read view is already pinned")
	}
	uri := url.URL{Scheme: "file", Path: filepath.Join(s.deps.Directory, "state.sqlite")}
	query := uri.Query()
	query.Set("mode", "ro")
	query.Add("_pragma", "query_only(1)")
	query.Add("_pragma", "busy_timeout(5000)")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		db.Close()
		return nil, err
	}
	view := &readView{store: s, db: db, tx: tx, owner: principal(scope), endpoint: scope.EndpointGeneration,
		objectContext: ctx, objectBinding: bindObjectRead(scope)}
	view.stopObjects = context.AfterFunc(ctx, view.clearObjects)
	if scope.Connection != nil {
		view.connection = scope.Connection.ID()
	}
	view.snapshot.ID, err = wire.NewID()
	if err == nil {
		err = tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&view.snapshot.LastSeq)
	}
	if err != nil {
		view.closeLocked()
		return nil, err
	}
	view.snapshot.Config, view.snapshot.PolicyGeneration = s.deps.Config, scope.PolicyGeneration
	view.snapshot.AsOf = api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	s.views[view] = struct{}{}
	return view, nil
}
func (s *Service) reader(scope api.Scope) (readDatabase, error) {
	if scope.ReadView == nil {
		return s.db, nil
	}
	view, ok := scope.ReadView.(*readView)
	if !ok || view.store != s || view.closed.Load() || view.owner != principal(scope) || view.endpoint != scope.EndpointGeneration {
		return nil, api.WithErrorComponent(fault(api.CodeUnauthenticated, "read view does not belong to this scope"), "store_read_view")
	}
	if scope.Connection != nil && view.connection != scope.Connection.ID() {
		return nil, api.WithErrorComponent(fault(api.CodeUnauthenticated, "read view belongs to another connection"), "store_read_connection")
	}
	return view.tx, nil
}

func (s *Service) readScope(ctx context.Context, scope api.Scope) error {
	if err := s.scope(ctx, s.db, scope); err != nil {
		return err
	}
	if scope.Actor.Kind != "human" {
		return nil
	}
	if scope.Connection == nil {
		return fault(api.CodeUnauthenticated, "human read requires a live connection session")
	}
	if api.Methods[scope.Request.Method].Mutation && scope.Request.Proof != nil {
		return s.operationReadScope(ctx, scope)
	}
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return err
	}
	if authority.Config != scope.Config || authority.PrincipalID != scope.Actor.ID || authority.EndpointGeneration != scope.EndpointGeneration {
		return fault(api.CodeUnauthenticated, "read authority belongs to another principal or endpoint")
	}
	var session api.StoredReadSession
	if err := storedProjection(ctx, s.db, "read_session", authority.SessionID, &session); err != nil {
		return err
	}
	if session.Revoked || session.ConnectionID != scope.Connection.ID() || session.PrincipalID != scope.Actor.ID || session.CredentialID != authority.CredentialID ||
		session.EndpointGeneration != scope.EndpointGeneration || session.Session.Config != s.deps.Config || authority.ExpiresAt != session.Session.ExpiresAt || !future(session.Session.ExpiresAt, s.deps.Clock.Now()) || !future(authority.IdleExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeUnauthenticated, "human read session expired or changed")
	}
	if authority.Generation != session.Generation || authority.SimulatedPresence != session.Session.SimulatedPresence || authority.IdleExpiresAt != session.Session.IdleExpiresAt {
		return fault(api.CodeConflict, "human read session revision differs from its committed authority")
	}
	var enrollment api.HumanEnrollment
	if err := storedProjection(ctx, s.db, "enrollment", scope.Actor.ID, &enrollment); err != nil {
		return err
	}
	active := false
	for _, credential := range enrollment.Credentials {
		if credential.ID == session.CredentialID {
			if err := api.ValidateCredentialPresence(credential); err != nil {
				return err
			}
			if credential.SimulatedPresence != session.Session.SimulatedPresence {
				return fault(api.CodeForbidden, "read session changed enrolled presence provenance")
			}
		}
		active = active || credential.ID == session.CredentialID && !credential.Revoked
	}
	if !active {
		return fault(api.CodeUnauthenticated, "read-session credential was revoked")
	}
	return nil
}

// consumedByOwnOperation reports whether a consumed proof was consumed by the operation this exact request
// opened (its own receipt: same principal, method, idempotency key and request hash). A multi-step mutation
// (lane.archive reserves its worker, then verifies its completion) keeps reading under its own proof after
// that first commit (box 89: "mutation preflight lacks its exact current proof (consumed)"). Any other
// consumer stays refused.
func (s *Service) consumedByOwnOperation(ctx context.Context, scope api.Scope, operation api.ID) bool {
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.lookupReceipt(ctx, s.db, scope, key)
	return err == nil && receipt.Operation.ID != "" && receipt.Operation.ID == operation
}

// A mutation handler may inspect its inputs under the exact operation proof
// that will be consumed at commit. This is never used for a public read RPC.
func (s *Service) operationReadScope(ctx context.Context, scope api.Scope) error {
	if err := wire.ValidateRequest(scope.Request); err != nil {
		return err
	}
	var proof api.VerifiedHumanProof
	if err := storedProjection(ctx, s.db, "proof", scope.Request.Proof.ID, &proof); err != nil {
		return err
	}
	target, err := s.authorizationTarget(ctx, s.db, scope, scope.Request)
	if err != nil {
		return err
	}
	// The same conditions, named so a refusal says which one failed (item 1 diagnosis, box 75).
	for _, c := range []struct {
		name string
		bad  bool
	}{
		{"ref", proof.Ref != *scope.Request.Proof}, {"config", proof.Config != scope.Config},
		{"principal", proof.PrincipalID != scope.Actor.ID}, {"consumed", proof.ConsumedBy != "" && !s.consumedByOwnOperation(ctx, scope, proof.ConsumedBy)},
		{"endpoint_class", proof.EndpointClass != api.EndpointHuman}, {"endpoint_generation", proof.EndpointGeneration != scope.EndpointGeneration},
		{"target", proof.Target != target}, {"expired", !future(proof.Ref.ExpiresAt, s.deps.Clock.Now())},
	} {
		if c.bad {
			return fault(api.CodeUnauthenticated, "mutation preflight lacks its exact current proof ("+c.name+")")
		}
	}
	var enrollment api.HumanEnrollment
	if err := storedProjection(ctx, s.db, "enrollment", scope.Actor.ID, &enrollment); err != nil {
		return err
	}
	for _, credential := range enrollment.Credentials {
		if credential.ID == proof.CredentialID && !credential.Revoked {
			return nil
		}
	}
	return fault(api.CodeUnauthenticated, "mutation preflight credential was revoked")
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type secretStagePublicationKey struct{}

type secretStagePublication struct {
	store     *Service
	stage     api.SecretStage
	actor     api.Actor
	config    string
	authority api.ReadAuthority
	request   api.RequestKey
	requestID api.ID
}

type secretStageRecord struct {
	Stage       api.SecretStage
	Config      string
	Owner       api.Actor
	Authority   api.ReadAuthority
	Request     api.RequestKey
	RequestID   api.ID
	OperationID api.ID
	KeyID       api.ID
}

// CommitSecretStage is a private owner-to-writer handoff, never an RPC. The
// independently supplied allocation is frozen separately from the RPC reply.
// The same transaction projects it, correlates the reply and seals the receipt.
func (s *Service) CommitSecretStage(ctx context.Context, input api.Transaction, allocated api.SecretStage) (api.Commit, error) {
	scope := input.Scope
	if scope.Request.Method != "secret.stage" || scope.Actor.Kind != "human" || scope.Connection == nil || scope.ReadAuthority == nil {
		return api.Commit{}, fault(api.CodeForbidden, "secret stage publication requires its bound human allocation")
	}
	publication := &secretStagePublication{store: s, stage: allocated, actor: scope.Actor, config: scope.Config,
		authority: *scope.ReadAuthority, request: requestKey(scope.Request), requestID: scope.Request.RequestID}
	return s.Transact(context.WithValue(ctx, secretStagePublicationKey{}, publication), input)
}

func (s *Service) projectSecretStage(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID) error {
	if input.Scope.Request.Method != "secret.stage" || input.Reply != nil && input.Reply.Error != nil {
		return nil
	}
	p, ok := ctx.Value(secretStagePublicationKey{}).(*secretStagePublication)
	scope := input.Scope
	if !ok || p.store != s || p.actor != scope.Actor || p.config != scope.Config || scope.ReadAuthority == nil ||
		p.authority != *scope.ReadAuthority || p.request != requestKey(scope.Request) || p.requestID != scope.Request.RequestID ||
		scope.Connection == nil || p.authority.ConnectionID != scope.Connection.ID() {
		return fault(api.CodeForbidden, "secret stage transaction lost its private allocation handoff")
	}
	var request api.SecretStageRequest
	if err := wire.Decode(scope.Request.Params, &request); err != nil {
		return err
	}
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(p.stage.ExpiresAt))
	idle, idleErr := time.Parse(time.RFC3339Nano, string(p.authority.IdleExpiresAt))
	absolute, absoluteErr := time.Parse(time.RFC3339Nano, string(p.authority.ExpiresAt))
	if !wire.ValidID(string(p.stage.ID)) || p.stage.Name != request.Name || p.stage.Version != request.Version ||
		expiryErr != nil || idleErr != nil || absoluteErr != nil || !s.deps.Clock.Now().Before(expires) || expires.After(idle) || expires.After(absolute) {
		return fault(api.CodeIntegrity, "secret stage allocation differs from its request or read lifetime")
	}
	record := secretStageRecord{Stage: p.stage, Config: scope.Config, Owner: scope.Actor, Authority: p.authority,
		Request: p.request, RequestID: p.requestID, OperationID: operation, KeyID: request.KeyID}
	return putGenerated(ctx, tx, "secret_stage", p.stage.ID, 1, record)
}

func (s *Service) secretStageReply(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.Operation) error {
	var value api.SecretStage
	if err := wire.Decode(input.Reply.Result, &value); err != nil {
		return err
	}
	var committed secretStageRecord
	if err := storedProjection(ctx, tx, "secret_stage", value.ID, &committed); err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return fault(api.CodeIntegrity, "secret stage reply has no committed allocation")
		}
		return err
	}
	var request api.SecretStageRequest
	if err := wire.Decode(input.Scope.Request.Params, &request); err != nil {
		return err
	}
	if committed.Stage != value || committed.Config != input.Scope.Config || committed.Owner != input.Scope.Actor ||
		committed.OperationID != operation.ID || committed.Request != requestKey(input.Scope.Request) ||
		committed.RequestID != input.Scope.Request.RequestID || committed.KeyID != request.KeyID ||
		input.Scope.ReadAuthority == nil || committed.Authority != *input.Scope.ReadAuthority ||
		input.Scope.Connection == nil || committed.Authority.ConnectionID != input.Scope.Connection.ID() ||
		value.Name != request.Name || value.Version != request.Version {
		return fault(api.CodeIntegrity, "secret stage reply differs from its committed allocation")
	}
	return nil
}

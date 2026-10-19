package secrets

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type stageReplyWriter interface {
	CommitSecretStage(context.Context, api.Transaction, api.SecretStage) (api.Commit, error)
}

// Ciphertext stays in the session-owned memory map. The mutation's exact
// metadata reply still belongs in the ordinary durable request transaction.
func (s *Service) commitStage(ctx context.Context, scope api.Scope, authority api.ReadAuthority, proposed api.SecretStage) (api.SecretStage, error) {
	scope.ReadAuthority = &authority
	raw, err := json.Marshal(proposed)
	if err != nil {
		return api.SecretStage{}, wire.Error(api.CodeIntegrity, "cannot encode secret stage receipt")
	}
	input := api.Transaction{Scope: scope, RawRequest: append([]byte(nil), scope.Frame.Bytes()...),
		Reply: &api.RPCReply{Result: raw}}
	if err := api.ValidateTransactionShape(input); err != nil {
		return api.SecretStage{}, err
	}
	writer, ok := s.deps.Store.(stageReplyWriter)
	if !ok || wire.Nil(writer) {
		return api.SecretStage{}, wire.Error(api.CodePrerequisite, "secret stage requires its private allocation writer")
	}
	commit, err := writer.CommitSecretStage(ctx, input, proposed)
	if err != nil {
		return api.SecretStage{}, err
	}
	if commit.Reply != nil && commit.Reply.Error != nil {
		return api.SecretStage{}, commit.Reply.Error
	}
	var retained api.SecretStage
	// Staging publishes metadata and an exact reply without a journal event.
	// Its durable operation therefore has the valid empty range (0, 0).
	// Bind both range fields to that operation; a positive sequence is not
	// evidence of publication and must not make us discard a committed stage.
	if !wire.ID(string(commit.Operation.ID)) || commit.Operation.Status != "succeeded" ||
		commit.Operation.Error != nil || commit.FirstSeq != commit.Operation.FirstSeq || commit.LastSeq != commit.Operation.LastSeq ||
		(commit.FirstSeq == 0) != (commit.LastSeq == 0) || commit.LastSeq < commit.FirstSeq ||
		commit.Reply == nil || wire.Decode(commit.Reply.Result, &retained, api.MaxFrameBytes) != nil || retained != proposed {
		return api.SecretStage{}, wire.Error(api.CodeIntegrity, "secret stage has no exact committed reply")
	}
	return retained, nil
}

// Caller holds the staging mutex. Failed publication must not leave an
// importable allocation whose success was never durably acknowledged.
func (s *Service) finishStage(ctx context.Context, scope api.Scope, authority api.ReadAuthority, proposed api.SecretStage) (api.SecretStage, error) {
	retained, err := s.commitStage(ctx, scope, authority, proposed)
	if err != nil {
		stage := s.stages[proposed.ID]
		clear(stage.request.Ciphertext)
		delete(s.stages, proposed.ID)
	}
	return retained, err
}

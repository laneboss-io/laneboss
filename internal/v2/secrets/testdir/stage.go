package testdir

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// StageLedger is an explicit transaction component fixture. It retains the
// submitted reply after validating the original frame and live read authority.
// Dispatcher/SQLite regressions separately test the real durable writer.
type StageLedger struct {
	mu      sync.Mutex
	commits map[string]api.Commit
	seq     api.Sequence
	Failure error
}

func (s *StageLedger) CommitSecretStage(ctx context.Context, input api.Transaction, allocated api.SecretStage) (api.Commit, error) {
	var reply api.SecretStage
	if input.Reply == nil || wire.Decode(input.Reply.Result, &reply) != nil || reply != allocated {
		return api.Commit{}, wire.Invalid("stage component reply differs from its allocated metadata")
	}
	return s.Transact(ctx, input)
}

func (s *StageLedger) Transact(ctx context.Context, input api.Transaction) (api.Commit, error) {
	if err := ctx.Err(); err != nil {
		return api.Commit{}, err
	}
	if err := api.ValidateTransactionShape(input); err != nil {
		return api.Commit{}, err
	}
	scope := input.Scope
	if scope.Request.Method != "secret.stage" || scope.Frame == nil || scope.Connection == nil ||
		scope.ReadAuthority == nil || input.Reply == nil || input.Reply.Error != nil ||
		len(input.Events) != 0 || len(input.Effects) != 0 || len(input.Guards) != 0 || !reflect.ValueOf(input.Writes).IsZero() ||
		!bytes.Equal(input.RawRequest, scope.Frame.Bytes()) {
		return api.Commit{}, wire.Invalid("stage component received an unrelated transaction")
	}
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil || authority != *scope.ReadAuthority {
		return api.Commit{}, wire.Invalid("stage component lost its exact read authority")
	}
	var request api.SecretStageRequest
	var reply api.SecretStage
	if wire.Decode(scope.Request.Params, &request) != nil || wire.Decode(input.Reply.Result, &reply) != nil ||
		reply.Name != request.Name || reply.Version != request.Version {
		return api.Commit{}, wire.Invalid("stage component reply differs from its request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Failure != nil {
		return api.Commit{}, s.Failure
	}
	domain, err := json.Marshal([]any{scope.Config, scope.Actor, scope.Connection.ID(), authority.SessionID,
		scope.Request.Method, scope.Request.IdempotencyKey, scope.Request.RequestSHA256})
	if err != nil {
		return api.Commit{}, err
	}
	if prior, ok := s.commits[string(domain)]; ok {
		prior.Replayed = true
		return prior, nil
	}
	id, err := client.NewRequestID()
	if err != nil {
		return api.Commit{}, err
	}
	s.seq++
	commit := api.Commit{Operation: api.Operation{ID: id, Status: "succeeded", FirstSeq: s.seq, LastSeq: s.seq},
		Reply: &api.RPCReply{Result: append(json.RawMessage(nil), input.Reply.Result...)}, FirstSeq: s.seq, LastSeq: s.seq}
	if s.commits == nil {
		s.commits = make(map[string]api.Commit)
	}
	s.commits[string(domain)] = commit
	return commit, nil
}

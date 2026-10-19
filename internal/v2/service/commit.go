package service

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func commitResult[R any](ctx context.Context, state api.StateStore, scope api.Scope, writes api.StateWrites, events []api.Event, result R) (R, error) {
	var empty R
	payload, err := json.Marshal(result)
	if err != nil {
		return empty, err
	}
	transaction := api.Transaction{Scope: scope, Writes: writes, Events: events, Reply: &api.RPCReply{Result: payload}}
	if scope.Frame != nil {
		transaction.RawRequest = scope.Frame.Bytes()
	}
	if scope.Actor.Kind == "human" && scope.Request.Proof == nil && api.HumanSessionMethod(scope.Request.Method) {
		// Design (v2-contracts: HumanSessionMethod; blob.begin/chunk/commit "human S"): a human upload runs
		// under the live read session the CLI opens from its session proof, not an operation proof (box 80).
		// The shape check (api validPublicWrites) requires the bound read authority on a session write's scope.
		verified, err := api.WithReadAuthority(ctx, scope)
		if err != nil {
			return empty, err
		}
		transaction.Scope = verified
	} else if scope.Actor.Kind == "human" {
		if scope.Request.Proof == nil {
			return empty, serviceError(api.CodeForbidden, "human upload mutation requires its exact operation proof")
		}
		target, err := state.AuthorizationTarget(ctx, scope, scope.Request)
		if err != nil {
			return empty, err
		}
		transaction.Guards = []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}
	}
	commit, err := state.Transact(ctx, transaction)
	if err != nil {
		return empty, err
	}
	if commit.Reply == nil {
		return empty, serviceError(api.CodeIntegrity, "store omitted exact mutation reply")
	}
	if commit.Reply.Error != nil {
		return empty, commit.Reply.Error
	}
	if err := wire.Decode(commit.Reply.Result, &result); err != nil {
		return empty, err
	}
	return result, nil
}

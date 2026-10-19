package client

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

func (w *WorkerClient) JudgeSetup(ctx context.Context, scope api.Scope, input api.WorkerInputRequest) (result job.Setup, err error) {
	if err = w.scope(scope); err != nil {
		return result, err
	}
	err = w.call(ctx, api.WorkerJudgeContext, input, &result)
	return result, err
}

func (w *WorkerClient) JudgeRetain(ctx context.Context, scope api.Scope, input job.RetainRequest) (result api.BlobRef, err error) {
	if err = w.scope(scope); err != nil {
		return result, err
	}
	err = w.call(ctx, api.WorkerJudgeRetain, input, &result)
	return result, err
}

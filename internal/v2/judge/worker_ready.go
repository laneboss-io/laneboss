package judge

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

// WorkerReadiness performs protected dependency checks before reserving cost.
// A ready worker must still validate the actual live job immediately at egress.
type WorkerReadiness interface {
	ReadyForJudge(context.Context, api.JudgeConfig) error
}

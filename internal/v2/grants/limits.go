package grants

import (
	"context"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

const maxVerificationBytes = api.MaxObjectBytes
const maxVerificationRefs = 4096

type verificationKey struct{}
type verificationMeter struct {
	mu       sync.Mutex
	bytes    int64
	metadata int
}

func verificationContext(ctx context.Context) context.Context {
	if _, exists := ctx.Value(verificationKey{}).(*verificationMeter); exists {
		return ctx
	}
	return context.WithValue(ctx, verificationKey{}, &verificationMeter{})
}

func verificationLimit() error {
	return &api.Error{Code: api.CodeBudget, Message: "grant verification exceeds its bounded service read budget",
		Instead: "Use a smaller source manifest or candidate; assemble file bytes only in the confined worker.", Owner: "lb-v2-grants"}
}

func meterBytes(ctx context.Context, count int64) error {
	meter, ok := ctx.Value(verificationKey{}).(*verificationMeter)
	if !ok {
		return nil
	}
	meter.mu.Lock()
	defer meter.mu.Unlock()
	if count < 0 || count > maxVerificationBytes-meter.bytes {
		return verificationLimit()
	}
	meter.bytes += count
	return nil
}

func meterMetadata(ctx context.Context) error {
	meter, ok := ctx.Value(verificationKey{}).(*verificationMeter)
	if !ok {
		return nil
	}
	meter.mu.Lock()
	defer meter.mu.Unlock()
	if meter.metadata >= maxVerificationRefs*8 {
		return verificationLimit()
	}
	meter.metadata++
	return nil
}

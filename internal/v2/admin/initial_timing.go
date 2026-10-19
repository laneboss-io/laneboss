package admin

import (
	"context"
	"errors"
	"time"
)

type initialTimingKey struct{}

type initialTimingFailure struct{ cause error }

func (e *initialTimingFailure) Error() string { return "initial publication timing retention failed" }
func (e *initialTimingFailure) Unwrap() error { return e.cause }

// WithInitialTiming installs an in-process diagnostic sink. It grants no
// publication authority and is absent from every serialized request and Scope.
// A sink failure remains an error, including after an actual durable commit.
func WithInitialTiming(ctx context.Context, observe func(string, time.Duration) error) context.Context {
	return context.WithValue(ctx, initialTimingKey{}, observe)
}

func initialStage[T any](ctx context.Context, stage string, run func() (T, error)) (T, error) {
	started := time.Now()
	value, err := run()
	if ctx != nil {
		if observe, ok := ctx.Value(initialTimingKey{}).(func(string, time.Duration) error); ok && observe != nil {
			if timingErr := observe(stage, time.Since(started)); timingErr != nil {
				err = errors.Join(err, &initialTimingFailure{cause: timingErr})
			}
		}
	}
	return value, err
}

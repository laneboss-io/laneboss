// Package testjob defines the private native TestChild coordinator handoff.
// These DTOs are not authority; the installed dispatcher and writer recheck
// the actual caller, immutable reservation, child grants and native lifetime.
package testjob

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

type callKey struct{}

type Call struct {
	Scope  api.Scope
	Guards []api.TransactionGuard
}

func WithCall(ctx context.Context, call Call) context.Context {
	return context.WithValue(ctx, callKey{}, call)
}
func FromContext(ctx context.Context) (Call, bool) {
	call, ok := ctx.Value(callKey{}).(Call)
	return call, ok
}

type Control interface {
	SubmitChildTest(context.Context, Call, api.TestChildRequest, api.GrantSet) (api.Operation, error)
}

type Reservation struct {
	Job     archivejob.Job
	Effect  api.Effect
	Compare []api.Compare
}

type Input struct {
	Schema  string               `json:"schema"`
	Request api.TestChildRequest `json:"request"`
	Plan    api.WorkerPlan       `json:"plan"`
	Subject api.ReviewSubject    `json:"subject"`
	Name    string               `json:"name"`
}

type Result struct {
	Schema       string                `json:"schema"`
	Check        reviewjob.CheckRecord `json:"check"`
	Stdout       []byte                `json:"stdout"`
	Stderr       []byte                `json:"stderr"`
	StdoutPipeID api.ID                `json:"stdout_pipe_id"`
	StderrPipeID api.ID                `json:"stderr_pipe_id"`
}

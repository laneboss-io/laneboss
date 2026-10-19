package admin

import (
	"context"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/testjob"
)

// TestChild can execute without review requirements. When current protected
// review policy exists, its name binds the measured result; callers cannot
// relabel a command as an unrelated required check.
func (s *Service) TestCheckNames(ctx context.Context, scope api.Scope, target api.LifeRef) ([]string, error) {
	path := filepath.Join("/etc/laneboss-v2/review", s.deps.Config+".json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return []string{}, nil
	} else if err != nil {
		return nil, err
	}
	return s.RequiredReviewChecks(ctx, scope, target)
}

func validateTestSealInput(seal archiveSeal) error {
	var input testjob.Input
	j := seal.Reg.Job
	if api.DecodeObject(seal.Input, &input) != nil || input.Schema != "laneboss.test-input.v2" || input.Subject.Target != j.Lease.Target ||
		input.Request.Child != j.Lease.Target || input.Subject.EndEventID != j.Intent.EndEventID || input.Subject.EndSeq != j.Intent.EndSeq ||
		input.Subject.Generation != j.Intent.Request.ExpectedGeneration || input.Plan.Kind != "test" || input.Plan.Input != input.Request.Candidate || !validID(api.ID(input.Name)) {
		return failure(api.CodeIntegrity, "TestChild seal changed its exact candidate, plan or frozen subject")
	}
	return nil
}

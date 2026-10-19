package reviewjob

import (
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
)

const SnapshotIntegrity = "snapshot-integrity"

// CheckInput is private sealed input for a real test lease. The public child
// request, its declared fixed plan and the native frozen subject remain exact.
type CheckInput struct {
	Schema   string               `json:"schema"`
	Subject  api.ReviewSubject    `json:"subject"`
	Request  api.TestChildRequest `json:"request"`
	Plan     api.WorkerPlan       `json:"plan"`
	Required []string             `json:"required"`
	Base     api.BlobRef          `json:"base"`
}

type CheckResult struct {
	Schema    string            `json:"schema"`
	Subject   api.ReviewSubject `json:"subject"`
	Candidate api.BlobRef       `json:"candidate"`
	Diff      Diff              `json:"diff"`
	Checks    []CheckRecord     `json:"checks"`
}

// Structural correlation only; current request, grants, native launch and
// process authority remain the responsibilities of the installed owners.
func ValidateCheckInput(input CheckInput, lease api.WorkerLease, plan api.WorkerPlan) error {
	if lease.Kind != "test" || plan.Kind != "test" || input.Schema != "laneboss.check-input.v2" || input.Subject.Target != lease.Target || input.Request.Child != lease.Target || input.Subject.Generation == 0 || input.Subject.EndSeq == 0 ||
		input.Subject.EndEventID == "" || input.Subject.Snapshot.Class != "manifest" || input.Base.Class != "manifest" || input.Request.Candidate.Class != "manifest" || input.Request.TestPlan.Class != "manifest" ||
		input.Plan.Schema != "laneboss.worker-plan.v2" || input.Plan.Kind != "test" || input.Plan.Executable != plan.Executable || input.Plan.Input != input.Request.Candidate || input.Plan.Budget != plan.Budget || input.Plan.Budget != input.Request.Budget ||
		!slices.Equal(input.Plan.Argv, []string{"laneboss", "check", SnapshotIntegrity}) || !slices.Equal(input.Required, []string{SnapshotIntegrity}) {
		return &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-grants", Message: "fixed checker input differs from its original subject, declaration or lease"}
	}
	return nil
}

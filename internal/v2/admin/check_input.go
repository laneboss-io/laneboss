package admin

import (
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

func validateCheckSealInput(seal archiveSeal) error {
	var input reviewjob.CheckInput
	job := seal.Reg.Job
	if api.DecodeObject(seal.Input, &input) != nil {
		return failure(api.CodeIntegrity, "native checker lost its exact sealed input")
	}
	if err := reviewjob.ValidateCheckInput(input, job.Lease, job.Plan); err != nil {
		return err
	}
	if input.Subject.Generation != job.Intent.Request.ExpectedGeneration || input.Subject.EndEventID != job.Intent.EndEventID || input.Subject.EndSeq != job.Intent.EndSeq {
		return failure(api.CodeIntegrity, "native checker changed its actual ended-run fence")
	}
	return nil
}

package linux

import (
	"errors"
	"fmt"

	"laneboss.io/laneboss/internal/v2/api"
)

var errEgressLease = errors.New("network grants require a provisioned private network lease")

// PrerequisiteError preserves both the failing primitive and its OS cause.
// errors.As also exposes the frozen API error for the client exit mapping.
type PrerequisiteError struct {
	Check string
	Err   error
}

func (e *PrerequisiteError) Error() string {
	return fmt.Sprintf("isolation prerequisite %s: %v", e.Check, e.Err)
}

func (e *PrerequisiteError) Unwrap() []error {
	return []error{e.Err, failure(api.CodePrerequisite, e.Error())}
}

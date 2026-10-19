package api

import "errors"

// Only the owning binder may certify that a failed attempt left it unbound.
// A partial or uncertain bind must not set Unbound. Generic Retryable alone
// never authorizes a second one-use bind.
type CredentialBindingFailure struct {
	Cause   *Error
	Unbound bool
}

func (e *CredentialBindingFailure) Error() string {
	if e == nil || e.Cause == nil {
		return "credential projection binding outcome is unknown"
	}
	return e.Cause.Error()
}
func (e *CredentialBindingFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func CredentialBindingRetryable(err error) bool {
	var failure *CredentialBindingFailure
	return errors.As(err, &failure) && failure != nil && failure.Unbound && failure.Cause != nil &&
		failure.Cause.Owner == "lb-v2-admin" && failure.Cause.Code == CodeUnavailable && failure.Cause.Retryable
}

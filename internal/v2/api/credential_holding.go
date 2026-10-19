package api

import "time"

// ValidateCredentialHolding checks private receipt correlation only. The store
// separately reads the installed helper's actual observation before committing.
func ValidateCredentialHolding(authority CredentialProjectionAuthority, receipt CredentialProjectionReceipt, now time.Time) error {
	if err := ValidateCredentialProjectionRequest(authority.Request, now); err != nil {
		return err
	}
	return validateCredentialHolding(authority, receipt)
}

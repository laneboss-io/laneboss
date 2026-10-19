package api

import (
	"reflect"
	"time"
)

// A fresh native remeasurement preserves the holding's exact objects, counts,
// gate and ownership while carrying its own observation time. It is not a
// second holding commit and cannot substitute a different destination.
func ValidateCredentialReobservation(authority CredentialProjectionAuthority, receipt, observed CredentialProjectionReceipt, now time.Time) error {
	if err := ValidateCredentialHolding(authority, receipt, now); err != nil {
		return err
	}
	if err := ValidateCredentialHolding(authority, observed, now); err != nil {
		return err
	}
	first, firstErr := time.Parse(time.RFC3339Nano, string(receipt.ObservedAt))
	latest, latestErr := time.Parse(time.RFC3339Nano, string(observed.ObservedAt))
	if firstErr != nil || latestErr != nil || latest.Before(first) || latest.After(now.Add(time.Second)) || latest.UTC().Format(time.RFC3339Nano) != string(observed.ObservedAt) {
		return launchInvalid("credential reobservation has no current native measurement time")
	}
	receipt.ObservedAt, observed.ObservedAt = "", ""
	if !reflect.DeepEqual(receipt, observed) {
		return launchInvalid("credential reobservation changed the original held proof")
	}
	return nil
}

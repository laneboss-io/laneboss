package api

import (
	"bytes"
	"context"
)

// Public test-device identifiers, agreed with the installed serve fixture.
// They contain no key material and confer no registration/assertion authority.
const (
	SoftwareAuthenticatorAAGUID               = "6c626f73-732d-4565-9273-6f6674617574"
	SoftwareAuthenticatorAttestationMarker    = "laneboss-e2e-software-auth-v1"
	SoftwareAuthenticatorBuildTag             = "laneboss_e2e_authenticator"
	SoftwareAuthenticatorCredentialID      ID = "laneboss-e2e-software-auth"
	SoftwareAuthenticatorRawPrefix            = "laneboss-e2e-auth-v1:"
)

type HumanEnrollmentInventory interface {
	// Protected complete inventory, including revoked credentials; never RPC.
	HumanEnrollments(context.Context, string) ([]HumanEnrollment, error)
}

// Assembly calls this before constructing/listening on any service endpoint.
// Failed or missing protected inventory is never an inferred empty database.
func CheckHumanEnrollmentPolicy(ctx context.Context, inventory HumanEnrollmentInventory, config string) error {
	if inventory == nil {
		return NotImplemented("lb-v2-service", "protected human credential inventory")
	}
	if !bindingConfigName.MatchString(config) {
		return launchInvalid("invalid credential inventory configuration")
	}
	enrollments, err := inventory.HumanEnrollments(ctx, config)
	if err != nil {
		return err
	}
	return ValidateHumanEnrollments(config, enrollments)
}

func softwareCredential(c HumanCredential) bool {
	return c.ID == SoftwareAuthenticatorCredentialID || bytes.HasPrefix(c.RawCredentialID, []byte(SoftwareAuthenticatorRawPrefix)) ||
		c.AAGUID == SoftwareAuthenticatorAAGUID || c.AttestationMarker == SoftwareAuthenticatorAttestationMarker || c.SimulatedPresence
}

// Call during registration, startup inventory checks and every verification.
// Identity still verifies actual attestation, key, origin, RP, signature and counters.
func ValidateCredentialPresence(c HumanCredential) error {
	marked := softwareCredential(c)
	if marked && !softwareAuthenticatorBuild {
		return &Error{Code: CodeForbidden, Owner: "lb-v2-identity",
			Message: "software authenticator credential requires the dedicated E2E build",
			Instead: "Use the isolated test build; do not enroll software-presence credentials in production."}
	}
	if !validCredentialMarkers(c) {
		return launchInvalid("software authenticator registration markers differ")
	}
	return nil
}

func validCredentialMarkers(c HumanCredential) bool {
	return !softwareCredential(c) || c.AAGUID == SoftwareAuthenticatorAAGUID &&
		c.AttestationMarker == SoftwareAuthenticatorAttestationMarker && c.SimulatedPresence
}

func ValidateHumanEnrollments(config string, enrollments []HumanEnrollment) error {
	if !bindingConfigName.MatchString(config) {
		return launchInvalid("invalid human enrollment inventory configuration")
	}
	principals := map[ID]bool{}
	for _, enrollment := range enrollments {
		if enrollment.Config != config || !launchID(enrollment.PrincipalID) || principals[enrollment.PrincipalID] || !launchGeneration(enrollment.Generation) {
			return launchInvalid("protected human enrollment inventory differs")
		}
		principals[enrollment.PrincipalID] = true
		credentials := map[ID]bool{}
		for _, credential := range enrollment.Credentials {
			if !launchID(credential.ID) || credentials[credential.ID] {
				return launchInvalid("invalid enrolled credential identity")
			}
			credentials[credential.ID] = true
			if err := ValidateCredentialPresence(credential); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateProofPresence(credential HumanCredential, proof VerifiedHumanProof, use ProofUseReceipt) error {
	if err := ValidateCredentialPresence(credential); err != nil {
		return err
	}
	if proof.CredentialID != credential.ID || proof.SimulatedPresence != credential.SimulatedPresence ||
		proof.Ref.SimulatedPresence != proof.SimulatedPresence || use.SimulatedPresence != proof.SimulatedPresence ||
		use.ProofID != proof.Ref.ID || use.CredentialID != credential.ID || use.NonceID != proof.NonceID || !launchID(use.OperationID) {
		return launchInvalid("proof use changed verified presence provenance")
	}
	return nil
}

package api

import (
	"context"
	"net/url"
	"path/filepath"
	"regexp"
	"time"
)

var registrationAAGUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type AdminEnrollmentEndpoint struct {
	Config                 string     `json:"config"`
	Socket                 string     `json:"socket"`
	ServiceUID             uint32     `json:"service_uid"`
	InstallationGeneration Generation `json:"installation_generation"`
	Origin                 string     `json:"origin"`
	RPID                   string     `json:"rp_id"`
	Helper                 Executable `json:"helper"`
}

func ValidateAdminEnrollmentEndpoint(e AdminEnrollmentEndpoint) error {
	u, err := url.Parse(e.Origin)
	if !bindingConfigName.MatchString(e.Config) || !filepath.IsAbs(e.Socket) || filepath.Clean(e.Socket) != e.Socket || e.Socket == "/" ||
		e.ServiceUID == 0 || !launchGeneration(e.InstallationGeneration) || !launchExecutable(e.Helper) ||
		err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Hostname() != e.RPID {
		return launchInvalid("administrator enrollment endpoint differs from protected installation")
	}
	return nil
}

// These are fixed administrator-channel messages, never public RPC bodies.
// The service derives RP/origin/endpoint from protected installation data.
type EnrollmentCeremonyRequest struct {
	Config             string     `json:"config"`
	CeremonyID         ID         `json:"ceremony_id"`
	PrincipalID        ID         `json:"principal_id"`
	ExpectedGeneration Generation `json:"expected_generation"`
}

type EnrollmentChallenge struct {
	ID                     ID
	Ceremony               EnrollmentCeremonyRequest
	Challenge              []byte
	Origin                 string
	RPID                   string
	EndpointGeneration     Generation
	InstallationGeneration Generation
	ExpiresAt              Timestamp
	Consumed               bool
}

type EnrollmentValidationRequest struct {
	AttestationMarker string                    `json:"attestation_marker,omitempty"`
	Ceremony          EnrollmentCeremonyRequest `json:"ceremony"`
	ChallengeID       ID                        `json:"challenge_id"`
	ClientDataJSON    []byte                    `json:"client_data_json"`
	AttestationObject []byte                    `json:"attestation_object"`
}

type EnrollmentReceipt struct {
	CeremonyID        ID
	ChallengeID       ID
	PrincipalID       ID
	Config            string
	Generation        Generation
	Evidence          BlobRef
	OperationID       ID
	EventID           ID
	CommittedSeq      Sequence
	SimulatedPresence bool
}

type EnrollmentValidator interface {
	BeginEnrollment(context.Context, EnrollmentCeremonyRequest) (EnrollmentChallenge, error)
	ValidateEnrollment(context.Context, EnrollmentValidationRequest) (EnrollmentInstall, error)
}

type EnrollmentCeremonyStore interface {
	ReserveEnrollment(context.Context, EnrollmentCeremonyRequest) (EnrollmentChallenge, error)
	EnrollmentChallenge(context.Context, string, ID) (EnrollmentChallenge, error)
}

// Entry is administrator helper -> dedicated private service control channel.
// Complete atomically consumes the actual validated registration challenge.
type AdminEnrollment interface {
	BeginHumanEnrollment(context.Context, EnrollmentCeremonyRequest) (EnrollmentChallenge, error)
	CompleteHumanEnrollment(context.Context, EnrollmentValidationRequest) (EnrollmentReceipt, error)
}

func ValidateEnrollmentChallenge(challenge EnrollmentChallenge, request EnrollmentCeremonyRequest, now time.Time) error {
	u, err := url.Parse(challenge.Origin)
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(challenge.ExpiresAt))
	if !bindingConfigName.MatchString(request.Config) || !launchID(request.CeremonyID) || !launchID(request.PrincipalID) ||
		request.ExpectedGeneration > launchMaxInteger || challenge.Ceremony != request || !launchID(challenge.ID) ||
		len(challenge.Challenge) < 32 || len(challenge.Challenge) > 64 || challenge.Consumed ||
		!launchGeneration(challenge.EndpointGeneration) || !launchGeneration(challenge.InstallationGeneration) ||
		err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Hostname() != challenge.RPID ||
		expiryErr != nil || !now.Before(expires) || expires.After(now.Add(5*time.Minute)) {
		return launchInvalid("administrator enrollment challenge differs from installed ceremony")
	}
	return nil
}

// This checks the attested handoff. The identity producer must first verify
// real webauthn.create attestation, origin/RP, nonce, key/algorithm and UP/UV.
func ValidateEnrollmentInstall(challenge EnrollmentChallenge, request EnrollmentValidationRequest, install EnrollmentInstall, now time.Time) error {
	if err := ValidateEnrollmentChallenge(challenge, request.Ceremony, now); err != nil {
		return err
	}
	e := install.Enrollment
	if request.ChallengeID != challenge.ID || len(request.ClientDataJSON) == 0 || len(request.AttestationObject) == 0 ||
		len(request.ClientDataJSON)+len(request.AttestationObject) > MaxFrameBytes ||
		install.CeremonyID != challenge.Ceremony.CeremonyID || install.ChallengeID != challenge.ID || !launchID(install.ValidationID) ||
		install.ExpectedGeneration != challenge.Ceremony.ExpectedGeneration || e.Generation != install.ExpectedGeneration+1 ||
		e.Config != challenge.Ceremony.Config || e.PrincipalID != challenge.Ceremony.PrincipalID || e.Origin != challenge.Origin || e.RPID != challenge.RPID ||
		!launchBlob(install.CeremonyEvidence, "artifact") || len(e.Credentials) != 1 {
		return launchInvalid("enrollment install differs from its validated registration ceremony")
	}
	c := e.Credentials[0]
	if !launchID(c.ID) || len(c.RawCredentialID) == 0 || len(c.PublicKeyDER) == 0 || c.Algorithm == "" || c.Generation != 1 || c.Revoked ||
		!registrationAAGUID.MatchString(c.AAGUID) || c.AttestationFormat == "" || c.AttestationMarker != request.AttestationMarker || c.RegistrationEvidence != install.CeremonyEvidence {
		return launchInvalid("enrollment credential lost registration provenance")
	}
	return ValidateCredentialPresence(c)
}

// CompleteHumanEnrollment is the configuration-wide absent baseline only.
// The store also proves that the complete inventory is empty under this lock.
// Later validations are proposals for the existing human/D6 approval path.
func ValidateInitialEnrollment(challenge EnrollmentChallenge, request EnrollmentValidationRequest, install EnrollmentInstall, now time.Time) error {
	if request.Ceremony.ExpectedGeneration != 0 {
		return &Error{Code: CodeForbidden, Owner: "lb-v2-admin", Message: "administrator ceremony cannot replace an enrollment",
			Instead: "Use the existing human approval/D6 path for the exact validated registration change."}
	}
	return ValidateEnrollmentInstall(challenge, request, install, now)
}

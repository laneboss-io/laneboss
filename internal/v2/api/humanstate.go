package api

import "context"

type HumanCredential struct {
	AAGUID               string
	AttestationFormat    string
	AttestationMarker    string
	RegistrationEvidence BlobRef
	SimulatedPresence    bool
	ID                   ID
	RawCredentialID      []byte
	Algorithm            string
	PublicKeyDER         []byte
	Counter              uint32
	Generation           Generation
	Revoked              bool
}

type HumanEnrollment struct {
	Config      string
	PrincipalID ID
	Origin      string
	RPID        string
	Generation  Generation
	Credentials []HumanCredential
}

type EnrollmentInstall struct {
	CeremonyID         ID
	ChallengeID        ID
	ValidationID       ID
	Enrollment         HumanEnrollment
	ExpectedGeneration Generation
	CeremonyEvidence   BlobRef
}

type StoredChallenge struct {
	EndpointClass      EndpointClass
	EndpointGeneration Generation
	Challenge          HumanChallenge
	PrincipalID        ID
	ConnectionID       ID
	Generation         Generation
	Consumed           bool
}

// VerifiedHumanProof facts are derived from a verified assertion and stored
// atomically with challenge/counter updates. They are not request fields.
type VerifiedHumanProof struct {
	SimulatedPresence  bool
	EndpointClass      EndpointClass
	EndpointGeneration Generation
	// human.confirm commits this exact private identity artifact in Objects
	// with the consumed challenge, verified counter and proof, or none.
	AssertionEvidence BlobRef
	Ref               ProofRef
	Config            string
	PrincipalID       ID
	CredentialID      ID
	NonceID           ID
	Target            HumanChallengeRequest
	ConnectionID      ID
	VerifiedAt        Timestamp
	ConsumedBy        ID
}

type CredentialCounterChange struct {
	CredentialID       ID
	ExpectedGeneration Generation
	Before             uint32
	After              uint32
}

type StoredReadSession struct {
	Session            HumanSession
	PrincipalID        ID
	CredentialID       ID
	ConnectionID       ID
	EndpointGeneration Generation
	Generation         Generation
	Revoked            bool
}

type ProofUseReceipt struct {
	SimulatedPresence bool      `json:"simulated_presence,omitempty"`
	ProofID           ID        `json:"proof_id"`
	CredentialID      ID        `json:"credential_id"`
	NonceID           ID        `json:"nonce_id"`
	OperationID       ID        `json:"operation_id"`
	UsedAt            Timestamp `json:"used_at"`
}

type IdentityStore interface {
	HumanEnrollmentInventory
	ReadSessionStore
	EnrollmentCeremonyStore
	WorkerIdentityStore
	LaunchRevocation(context.Context, ID) (LaunchRevocation, error)
	AuthorizationTarget(context.Context, Scope, Request) (HumanChallengeRequest, error)
	Enrollment(context.Context, Scope) (HumanEnrollment, error)
	Challenge(context.Context, Scope, ID) (StoredChallenge, error)
	Proof(context.Context, Scope, ID) (VerifiedHumanProof, error)
	Ticket(context.Context, Scope, ID) (Ticket, error)
	ReadSession(context.Context, Scope, ID) (StoredReadSession, error)
	LaunchBinding(context.Context, ID) (LaunchBindingRequest, error)
}

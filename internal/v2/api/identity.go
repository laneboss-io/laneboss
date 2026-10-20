package api

type HumanChallengeRequest struct {
	// CredentialID selects staging for one active credential. It grants no
	// read authority and is not part of the eventual operation's proof target.
	CredentialID   ID         `json:"credential_id,omitempty"`
	Method         Method     `json:"method"`
	TargetID       ID         `json:"target_id"`
	RequestSHA256  Digest     `json:"request_sha256"`
	BaseGeneration Generation `json:"base_generation"`
}

type HumanChallenge struct {
	ID             ID         `json:"id"`
	Challenge      []byte     `json:"challenge"`
	Config         string     `json:"config"`
	Method         Method     `json:"method"`
	TargetID       ID         `json:"target_id"`
	RequestSHA256  Digest     `json:"request_sha256"`
	BaseGeneration Generation `json:"base_generation"`
	Origin         string     `json:"origin"`
	RPID           string     `json:"rp_id"`
	ExpiresAt      Timestamp  `json:"expires_at"`
}

type HumanConfirmRequest struct {
	ChallengeID       ID     `json:"challenge_id"`
	CredentialID      ID     `json:"credential_id"`
	ClientDataJSON    []byte `json:"client_data_json"`
	AuthenticatorData []byte `json:"authenticator_data"`
	Signature         []byte `json:"signature"`
}

type TicketIssueRequest struct {
	Level      int       `json:"level"`
	Role       string    `json:"role"`
	GrantSetID ID        `json:"grant_set_id"`
	ExpiresAt  Timestamp `json:"expires_at"`
}

type Ticket struct {
	SimulatedPresence  bool       `json:"simulated_presence,omitempty"`
	PrincipalID        ID         `json:"principal_id"`
	Config             string     `json:"config"`
	EndpointGeneration Generation `json:"endpoint_generation"`
	ID                 ID         `json:"id"`
	Level              int        `json:"level"`
	Role               string     `json:"role"`
	GrantSetID         ID         `json:"grant_set_id"`
	ExpiresAt          Timestamp  `json:"expires_at"`
	Redeemed           bool       `json:"redeemed"`
}

type HumanSessionRequest struct {
}

type HumanSession struct {
	SimulatedPresence bool      `json:"simulated_presence,omitempty"`
	ID                ID        `json:"id"`
	ExpiresAt         Timestamp `json:"expires_at"`
	IdleExpiresAt     Timestamp `json:"idle_expires_at"`
	Config            string    `json:"config"`
}

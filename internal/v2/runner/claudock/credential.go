package claudock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

// Credential is a selected headless token, provided only by the authorized
// credential worker. It does not discover a login, validate provider ownership
// or enable an adapter mode. VerifyMode/VerifySlot remain mandatory gates.
type Credential struct {
	profile string
	login   string
	token   []byte
}

func NewCredential(profile, canonicalLogin string, token []byte) (Credential, error) {
	if !label(profile) || !label(canonicalLogin) || len(token) == 0 || len(token) > 65536 || !utf8.Valid(token) {
		return Credential{}, failure(api.CodeInvalid, "headless credential handles and bounded token bytes are required")
	}
	for _, c := range token {
		if c <= 32 || c == 127 {
			return Credential{}, failure(api.CodeInvalid, "headless token contains invalid bytes")
		}
	}
	return Credential{profile: profile, login: canonicalLogin, token: bytes.Clone(token)}, nil
}

func (c Credential) Format(state fmt.State, verb rune) {
	io.WriteString(state, "credential(values withheld)")
}

func (c Credential) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Withheld bool `json:"credential_withheld"`
	}{len(c.token) != 0})
}

// WriteTo hands exact token bytes to the trusted credential worker, not a log.
func (c Credential) WriteTo(destination io.Writer) (int64, error) {
	if destination == nil || len(c.token) == 0 {
		return 0, failure(api.CodeInvalid, "credential handoff requires a destination and token")
	}
	n, err := destination.Write(c.token)
	if err != nil || n != len(c.token) {
		return int64(n), failure(api.CodeIntegrity, "credential handoff was incomplete")
	}
	return int64(n), nil
}

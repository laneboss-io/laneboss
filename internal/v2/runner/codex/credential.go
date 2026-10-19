package codex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

const maxAuthBytes = 1024 * 1024

// Credential is supplied only by the authorized outside credential worker.
// Schema validation is not authentication or provider/account-affinity proof.
type Credential struct {
	profile api.ID
	login   api.ID
	account api.Digest
	payload []byte
}

func (c Credential) Format(state fmt.State, verb rune) {
	io.WriteString(state, "codex-credential(values withheld)")
}
func (c Credential) MarshalJSON() ([]byte, error) {
	return []byte(`{"credential_values":"withheld"}`), nil
}

// enrolledAccount is the hash of the profile's independently enrolled account,
// supplied by the credential worker. Never derive that enrollment from data.
func NewCredential(profile, canonicalLogin api.ID, enrolledAccount api.Digest, data []byte) (Credential, error) {
	if !id(profile) || !id(canonicalLogin) || !digest(enrolledAccount) {
		return Credential{}, problem(api.CodeInvalid, "Codex credential needs profile and canonical login handles")
	}
	account, err := authAccount(data)
	if err != nil {
		return Credential{}, err
	}
	if account != enrolledAccount {
		return Credential{}, problem(api.CodeForbidden, "Codex credential account differs from the enrolled profile")
	}
	return Credential{profile: profile, login: canonicalLogin, account: enrolledAccount, payload: bytes.Clone(data)}, nil
}

func (c Credential) WriteTo(destination io.Writer) (int64, error) {
	if destination == nil || len(c.payload) == 0 {
		return 0, problem(api.CodeInvalid, "Codex credential handoff needs a destination and payload")
	}
	n, err := destination.Write(c.payload)
	if err != nil || n != len(c.payload) {
		return int64(n), problem(api.CodeUnavailable, "Codex credential handoff is incomplete")
	}
	return int64(n), nil
}

func validateAuth(data []byte) error {
	_, err := authAccount(data)
	return err
}

func authAccount(data []byte) (api.Digest, error) {
	if len(data) == 0 || len(data) > maxAuthBytes {
		return "", problem(api.CodeIntegrity, "Codex auth file size is invalid")
	}
	var fields map[string]json.RawMessage
	if err := decodeJSON(data, &fields, false); err != nil {
		return "", wrap("validate Codex auth object", err)
	}
	for key := range fields {
		if key != "auth_mode" && key != "OPENAI_API_KEY" && key != "tokens" && key != "last_refresh" {
			return "", problem(api.CodeIntegrity, "Codex auth file contains an unknown or case-aliased field")
		}
	}
	var tokens map[string]json.RawMessage
	if err := decodeJSON(fields["tokens"], &tokens, false); err != nil {
		return "", problem(api.CodeIntegrity, "Codex auth tokens must be an exact object")
	}
	for key := range tokens {
		if key != "id_token" && key != "access_token" && key != "refresh_token" && key != "account_id" {
			return "", problem(api.CodeIntegrity, "Codex auth tokens contain an unknown or case-aliased field")
		}
	}
	var document struct {
		Mode   string  `json:"auth_mode"`
		APIKey *string `json:"OPENAI_API_KEY"`
		Tokens *struct {
			ID      string `json:"id_token"`
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
			Account string `json:"account_id"`
		} `json:"tokens"`
		LastRefresh *string `json:"last_refresh"`
	}
	reader := json.NewDecoder(bytes.NewReader(data))
	reader.DisallowUnknownFields()
	if err := reader.Decode(&document); err != nil {
		return "", problem(api.CodeIntegrity, "Codex auth file does not match the subscription schema")
	}
	if (document.Mode != "" && document.Mode != "chatgpt") || (document.APIKey != nil && *document.APIKey != "") || document.Tokens == nil || document.Tokens.Access == "" || document.Tokens.Refresh == "" || document.Tokens.Account == "" {
		return "", problem(api.CodeUnsupported, "Codex credential is not a supported subscription file login")
	}
	if document.LastRefresh != nil {
		if _, err := time.Parse(time.RFC3339Nano, *document.LastRefresh); err != nil {
			return "", problem(api.CodeIntegrity, "Codex auth refresh timestamp is invalid")
		}
	}
	hash := sha256.Sum256([]byte(document.Tokens.Account))
	return api.Digest(hex.EncodeToString(hash[:])), nil
}

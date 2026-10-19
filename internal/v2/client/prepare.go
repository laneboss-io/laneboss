package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"

	"laneboss.io/laneboss/internal/v2/api"
)

var serviceConfigName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var serviceRequestKey = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)

// NewRequestID supplies at least 128 random bits. IDs are correlation metadata,
// not authentication or authority. Retained mutation keys must be reused.
func NewRequestID() (api.ID, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", &api.Error{Code: api.CodeIntegrity, Message: "request entropy unavailable", Instead: "Repair the system random source before retrying."}
	}
	return api.ID(hex.EncodeToString(bytes[:])), nil
}

// PrepareRequest is shared by every feature adapter and by Call/Stream.
// It preserves exact params bytes; the JCS digest is a separate intent object.
func PrepareRequest(request api.Request) (api.Request, error) {
	invalid := func() (api.Request, error) {
		return api.Request{}, &api.Error{Code: api.CodeInvalid, Message: "invalid typed request envelope", Instead: "Use the exact documented body, matching configuration and retained retry key."}
	}
	if request.Protocol == "" {
		request.Protocol = api.Protocol
	}
	if request.Schema == 0 {
		request.Schema = api.SchemaVersion
	}
	if request.Protocol != api.Protocol || request.Schema != api.SchemaVersion {
		return api.Request{}, &api.Error{Code: api.CodeVersion, Message: "request protocol or schema differs from this client", Instead: "Use one matched immutable client/service generation."}
	}
	spec, exists := api.Methods[request.Method]
	if !exists || !serviceConfigName.MatchString(request.Config) {
		return invalid()
	}
	if err := api.DecodeObject(request.Params, reflect.New(spec.Request).Interface()); err != nil {
		return api.Request{}, err
	}
	if spec.Mutation && request.IdempotencyKey == "" {
		return api.Request{}, &api.Error{Code: api.CodeInvalid, Message: "mutation requires a retained idempotency key", Instead: "Supply --idempotency-key ID and reuse that key with the same change on every retry."}
	}
	for _, id := range []*api.ID{&request.RequestID, &request.IdempotencyKey} {
		if *id == "" {
			generated, err := NewRequestID()
			if err != nil {
				return api.Request{}, err
			}
			*id = generated
		} else if !serviceRequestKey.MatchString(string(*id)) {
			return invalid()
		}
	}
	digest, err := api.RequestDigest(request)
	if err != nil {
		return api.Request{}, err
	}
	if request.RequestSHA256 != "" && request.RequestSHA256 != digest {
		return invalid()
	}
	if request.Proof != nil && request.Proof.RequestSHA256 != digest {
		return invalid()
	}
	request.RequestSHA256 = digest
	request.Params = append(json.RawMessage(nil), request.Params...)
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > api.MaxFrameBytes {
		return invalid()
	}
	return request, nil
}

func (c *Client) PrepareRequest(request api.Request) (api.Request, error) {
	if c == nil || !serviceConfigName.MatchString(c.Options.Config) {
		return api.Request{}, &api.Error{Code: api.CodePrerequisite, Message: "client has no explicit configuration binding", Instead: "Open the installed client for one configuration."}
	}
	if request.Config == "" {
		request.Config = c.Options.Config
	}
	if request.Config != c.Options.Config {
		return api.Request{}, &api.Error{Code: api.CodeConflict, Message: "request conflicts with the client's configuration binding", Instead: "Keep the client's binding and use a separately bound process for another scope."}
	}
	return PrepareRequest(request)
}

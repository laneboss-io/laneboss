package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

func validID(value api.ID) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if c != '-' && c != '_' && !(c >= 'a' && c <= 'z') &&
			!(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func validDigest(value api.Digest) bool {
	if len(value) != 64 || strings.ToLower(string(value)) != string(value) {
		return false
	}
	_, err := hex.DecodeString(string(value))
	return err == nil
}

func validateIntent(request api.HumanChallengeRequest) error {
	spec, exists := api.Methods[request.Method]
	if !exists || !spec.Mutation || spec.Access == "human-endpoint" ||
		!validID(request.TargetID) || !validDigest(request.RequestSHA256) ||
		request.BaseGeneration > 1<<53-1 {
		return refusal(api.CodeInvalid, "invalid operation-bound challenge intent")
	}
	return nil
}

func validateConfirmation(request api.HumanConfirmRequest) error {
	if !validID(request.ChallengeID) || !validID(request.CredentialID) ||
		len(request.ClientDataJSON) == 0 || len(request.ClientDataJSON) > 16384 ||
		len(request.AuthenticatorData) < 37 || len(request.AuthenticatorData) > 65536 ||
		len(request.Signature) == 0 || len(request.Signature) > 8192 {
		return refusal(api.CodeInvalid, "invalid or oversized authenticator assertion")
	}
	return nil
}

func validateLaunch(record api.LaunchRecord) error {
	if record.Kind != "agent" || !validID(record.ID) || record.Config == "" || !validID(record.Target.LifeID) ||
		record.Target.Run == 0 || record.Actor.Kind != "lane" ||
		record.Actor.LifeID != record.Target.LifeID || !validID(record.Actor.ID) ||
		record.Actor.Level < 3 || record.Actor.Level > 6 || !validID(api.ID(record.Actor.Role)) ||
		!validID(record.RootLifeID) || record.StarterChain == nil ||
		!validID(record.UIDLeaseID) || record.HostUID == 0 ||
		record.ProcessGeneration == "" || !validID(record.ContainmentID) ||
		!validID(record.GrantSetID) || !validDigest(record.GrantsSHA256) ||
		record.PolicyGeneration == 0 || record.EndpointGeneration == 0 || record.Revoked {
		return refusal(api.CodeInvalid, "incomplete or revoked launch binding")
	}
	if record.ParentLifeID != "" && !validID(record.ParentLifeID) {
		return refusal(api.CodeInvalid, "invalid launch starter")
	}
	if record.ParentLifeID == "" {
		if record.RootLifeID != record.Target.LifeID || len(record.StarterChain) != 0 || record.StarterEventSeq != 0 {
			return refusal(api.CodeInvalid, "root launch lineage differs from its authentic life")
		}
	} else if record.StarterEventSeq == 0 || len(record.StarterChain) == 0 ||
		record.StarterChain[0] != record.RootLifeID || record.StarterChain[len(record.StarterChain)-1] != record.ParentLifeID {
		return refusal(api.CodeInvalid, "child launch lineage lacks its authentic starter")
	}
	seen := make(map[api.ID]bool)
	for _, id := range record.StarterChain {
		if !validID(id) || id == record.Target.LifeID || seen[id] {
			return refusal(api.CodeInvalid, "invalid launch starter chain")
		}
		seen[id] = true
	}
	return nil
}

// strictObject is deliberately local to the identity module. The common frame
// decoder still owns wire validation; direct module calls get the same guard.
func strictObject(raw []byte, output any) error {
	if len(raw) == 0 || len(raw) > api.MaxFrameBytes || !utf8.Valid(raw) {
		return refusal(api.CodeInvalid, "invalid identity JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return refusal(api.CodeInvalid, "identity request must be an object")
	}
	fields, err := objectTokens(decoder, 0)
	if err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return refusal(api.CodeInvalid, "trailing identity JSON")
	}
	typeOf := reflect.TypeOf(output).Elem()
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return refusal(api.CodeInvalid, "invalid identity JSON object")
	}
	known := make(map[string]bool)
	for i := 0; i < typeOf.NumField(); i++ {
		field := typeOf.Field(i)
		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" || name == "" {
			continue
		}
		known[name] = true
		if name != "-" && name != "" && !strings.Contains(tag, ",omitempty") && !fields[name] {
			return refusal(api.CodeInvalid, "required identity field is missing")
		}
		value, exists := values[name]
		if exists && field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 &&
			(len(value) == 0 || value[0] != '"') {
			return refusal(api.CodeInvalid, "identity bytes must be base64 strings")
		}
	}
	for name := range fields {
		if !known[name] {
			return refusal(api.CodeInvalid, "unknown identity field")
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return refusal(api.CodeInvalid, "identity field has an invalid type or name")
	}
	return nil
}

func objectTokens(decoder *json.Decoder, depth int) (map[string]bool, error) {
	if depth > 32 {
		return nil, refusal(api.CodeInvalid, "identity JSON is too deeply nested")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return nil, refusal(api.CodeInvalid, "duplicate or invalid identity field")
		}
		seen[name] = true
		if err := valueTokens(decoder, depth+1); err != nil {
			return nil, err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, refusal(api.CodeInvalid, "unterminated identity object")
	}
	return seen, nil
}

func valueTokens(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return refusal(api.CodeInvalid, "identity JSON is too deeply nested")
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return refusal(api.CodeInvalid, "null or invalid identity value")
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			_, err := objectTokens(decoder, depth)
			return err
		case '[':
			for decoder.More() {
				if err := valueTokens(decoder, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return refusal(api.CodeInvalid, "unterminated identity array")
			}
		default:
			return refusal(api.CodeInvalid, "unexpected identity delimiter")
		}
	}
	return nil
}

package admin

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"

	"laneboss.io/laneboss/internal/v2/api"
)

// This endpoint is private helper IPC, never registered on a lane or human
// service endpoint. Its payloads are the frozen Helper inputs, with no argv.
type helperRequest struct {
	Attempt        *api.EffectLease `json:"attempt,omitempty"`
	Protocol       string           `json:"protocol"`
	Revision       string           `json:"contract_revision"`
	Config         string           `json:"config"`
	Generation     api.Generation   `json:"generation"`
	ArtifactSHA256 api.Digest       `json:"artifact_sha256"`
	Nonce          api.ID           `json:"nonce"`
	Method         string           `json:"method"`
	Params         json.RawMessage  `json:"params"`
}

type helperResponse struct {
	Protocol string          `json:"protocol"`
	Revision string          `json:"contract_revision"`
	Nonce    api.ID          `json:"nonce"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    *api.Error      `json:"error,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Observed int64           `json:"observed,omitempty"`
}

// The credential protocol retains its original closed envelope. Decoding it
// separately rejects helper-only fields even when their values are empty.
type credentialResponse struct {
	Protocol string          `json:"protocol"`
	Revision string          `json:"contract_revision"`
	Nonce    api.ID          `json:"nonce"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    *api.Error      `json:"error,omitempty"`
}

type probeResult struct {
	Capabilities []api.Capability `json:"capabilities"`
}

func randomID(prefix string) (api.ID, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", failure(api.CodeUnavailable, "secure helper identifier generation failed")
	}
	return api.ID(prefix + hex.EncodeToString(data[:])), nil
}

func frame(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > api.MaxFrameBytes {
		return nil, failure(api.CodeInvalid, "helper frame exceeds its bound")
	}
	result := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(result, uint32(len(data)))
	copy(result[4:], data)
	return result, nil
}

func helperJSONFrame(value any) api.JSONFrameKind {
	switch value.(type) {
	case helperRequest, *helperRequest:
		return api.JSONFrameHelperRequest
	case helperResponse, *helperResponse, credentialResponse, *credentialResponse:
		return api.JSONFrameHelperResponse
	default:
		return api.JSONFrameObject
	}
}

func encodeHelperFrame(value any) ([]byte, error) {
	kind := helperJSONFrame(value)
	data, err := EncodeWire(value)
	if err != nil {
		return nil, api.JSONEncodingError(kind)
	}
	if kind != api.JSONFrameObject {
		if err := api.ValidateJSONFrame(data, kind); err != nil {
			return nil, err
		}
	}
	return frame(data)
}

func writeFrame(writer io.Writer, value any) error {
	encoded, err := encodeHelperFrame(value)
	if err != nil {
		return err
	}
	for len(encoded) > 0 {
		n, err := writer.Write(encoded)
		if err != nil {
			return failure(api.CodeUnavailable, "helper frame write failed")
		}
		if n <= 0 || n > len(encoded) {
			return failure(api.CodeIntegrity, "short helper frame write")
		}
		encoded = encoded[n:]
	}
	return nil
}

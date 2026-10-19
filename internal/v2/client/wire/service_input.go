package wire

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// ValidateServiceInput is the I/O-free semantic preflight shared by service
// handlers, ergonomic commands and the common CLI's retained file form.
func ValidateServiceInput(method api.Method, raw json.RawMessage) error {
	spec, exists := api.Methods[method]
	if !exists || spec.Owner != "lb-v2-service" {
		return serviceInputError(Invalid("method has no service input validator"))
	}
	params := reflect.New(spec.Request).Interface()
	if err := Decode(raw, params); err != nil {
		return serviceInputError(err)
	}
	if err := requestBounds(params); err != nil {
		return serviceInputError(err)
	}
	switch request := params.(type) {
	case *api.HealthRequest:
		if strings.TrimSpace(request.ClientVersion) == "" {
			return serviceInputError(Invalid("health requires a client version"))
		}
	case *api.OperationGetRequest, *api.BlobBeginRequest, *api.BlobChunk, *api.BlobCommitRequest, *api.BlobReadRequest:
		// Decode validates IDs, digests and the closed class catalog; the same
		// requestBounds used by the transport checks sizes, offsets and hashes.
	case *api.VerifyRequest:
		if strings.TrimSpace(request.Scope) == "" {
			return serviceInputError(Invalid("verification requires a scope"))
		}
	case *api.RebuildRequest:
		ref := request.FrozenSnapshot
		if ref.Bytes < 1 || ref.Bytes > api.MaxObjectBytes || (ref.Class != "manifest" && ref.Class != "archive") {
			return serviceInputError(Invalid("rebuild requires a bounded frozen snapshot manifest or archive"))
		}
	default:
		return serviceInputError(Invalid("method has no service input validator"))
	}
	return nil
}

func serviceInputError(err error) error {
	var typed *api.Error
	if errors.As(err, &typed) {
		owned := *typed
		owned.Owner = "lb-v2-service"
		return &owned
	}
	return err
}

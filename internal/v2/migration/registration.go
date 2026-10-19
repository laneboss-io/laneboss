package migration

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

// Register the real typed operation. An unfinished method's owner error reaches
// the caller; successful graph construction never supplies a successful result.
func register[Input, Output any](registry api.Registrar, method api.Method,
	call func(context.Context, api.Scope, Input) (Output, error)) error {
	return registry.Register(method, func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		var request Input
		if err := api.DecodeObject(raw, &request); err != nil {
			return nil, err
		}
		result, err := call(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	})
}

//go:build !linux

package admin

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) restoreRoots(context.Context, json.RawMessage) ([]string, error) {
	return nil, failure(api.CodeUnsupported, "native restore roots require Linux")
}

func (m *leaseManager) dispatchRestore(context.Context, string, json.RawMessage) (any, error) {
	return nil, failure(api.CodeUnsupported, "native restore requires Linux")
}

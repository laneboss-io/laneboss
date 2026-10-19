package store

import (
	"bytes"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

// Collection graph/evidence are retained bytes, not single RPC frames.
func collectionJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return api.CanonicalObjectJSON(raw)
}

func sameStoredJSON(a, b []byte) bool {
	left, leftErr := api.CanonicalObjectJSON(a)
	right, rightErr := api.CanonicalObjectJSON(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

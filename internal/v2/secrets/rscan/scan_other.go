//go:build !linux && !darwin

package rscan

import (
	"context"
	"os"
)

func scanReuseTree(context.Context, []byte, string, bool, os.FileInfo) APIKeyPlaceResult {
	return APIKeyPlaceResult{Unreadable: true}
}

func scanReuseChild(context.Context, []byte, string, string) APIKeyPlaceResult {
	return APIKeyPlaceResult{Unreadable: true}
}

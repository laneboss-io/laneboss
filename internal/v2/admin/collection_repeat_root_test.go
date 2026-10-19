//go:build linux && laneboss_root_canary && laneboss_collection_repeat

package admin

import (
	"strconv"
	"testing"
)

// The queue wrapper fixes go test -count=1. The explicit stress tag repeats
// the unchanged canary without multiplying every standard root-package run.
func TestCollectionPeerIsolationRepeated(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		t.Run(strconv.Itoa(attempt), TestCollectionPeerIsolation)
	}
}

package lane

import (
	"testing"

	"laneboss.io/laneboss/internal/testdata"
)

func TestWorktreeOverlap(t *testing.T) {
	testdata.WorktreeOverlapContract(t, checkWorktreeOverlap)
}

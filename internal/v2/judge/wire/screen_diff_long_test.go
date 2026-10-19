//go:build laneboss_judge_screen_long

package wire

import "testing"

func TestScreenDifferentialLong(t *testing.T) {
	runScreenDifferential(t, longScreenRows, "long")
}

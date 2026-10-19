package judge

import (
	"strings"
	"testing"
)

func TestScreenTextCoverage(t *testing.T) {
	credential := "gh" + "p_" + strings.Repeat("a1B2c3D4e5", 4)
	rows := []struct {
		name     string
		text     string
		cut      bool
		withheld bool
	}{
		{"ordinary", "Review the requested change.", false, false},
		{"rune-limit", strings.Repeat("界", 4000), false, false},
		{"over-rune-limit", strings.Repeat("界", 4001), true, false},
		{"credential-shape", "Rotate the example " + credential, false, true},
		{"invalid-unicode", string([]byte{0xff}), true, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			cut, withheld := ScreenText(row.text)
			if cut != row.cut || withheld != row.withheld {
				t.Fatal("the complete decision text lost its individual coverage verdict")
			}
		})
	}
}

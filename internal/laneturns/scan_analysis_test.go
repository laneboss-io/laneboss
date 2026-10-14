package laneturns

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestTurnScannerUnicodeHeredoc(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "protected.txt")
	for _, delimiter := range []string{"你", "à", "\u0185"} {
		t.Run(delimiter, func(t *testing.T) {
			writes, _ := analyseShell("cat <<"+delimiter+"\nx\n"+delimiter+"\nrm protected.txt", directory)
			if !reflect.DeepEqual(writes, []string{target}) {
				t.Fatal("the scanner lost the command after the Unicode heredoc")
			}
		})
	}
}

func TestTurnScannerDELAndC1PathTraversal(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "protected.txt")
	for _, control := range []rune{0x7f, 0x80, 0x85, 0x9f} {
		word := "d" + string(control)
		writes, _ := analyseShell("mkdir -p \""+word+"\" && rm \""+word+"/../protected.txt\"", directory)
		if !reflect.DeepEqual(writes, []string{target}) {
			t.Fatal("the scanner discarded a DEL or C1 path traversal")
		}
	}
}

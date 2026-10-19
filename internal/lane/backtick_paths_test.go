package lane

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestBacktickWriteCandidates(t *testing.T) {
	directory := t.TempDir()
	for _, row := range []struct {
		name, command string
		paths         []string
	}{
		{"escaped-close", "echo `printf '\\`'` > first.txt; rm second.txt", []string{"first.txt", "second.txt"}},
		{"inner-quotes", "echo \"a`b\" > inner.txt; echo \"c`d\" > outer.txt", []string{"outer.txt"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			want := []string{}
			for _, name := range row.paths {
				want = append(want, filepath.Join(directory, name))
			}
			writes, named := AnalyseShell(row.command, directory)
			if !reflect.DeepEqual(writes, want) || !reflect.DeepEqual(named, want) {
				t.Fatalf("backtick quoting changed file effects: writes %v, names %v; want %v", writes, named, want)
			}
		})
	}
}

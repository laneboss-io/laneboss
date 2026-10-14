package claudockcli

import (
	"io/fs"
	"os/exec"
	"reflect"
	"testing"
)

func TestNoFallbackAfterPATHFailure(t *testing.T) {
	for name, lookupError := range map[string]error{"missing": exec.ErrNotFound, "not_executable": fs.ErrPermission} {
		// Fails on any secondary lookup (including an application bundle), a
		// returned fallback path, or a changed installation diagnostic.
		t.Run(name, func(t *testing.T) {
			var calls []string
			path, err := resolve(func(name string) (string, error) {
				calls = append(calls, name)
				if name == "claudock" {
					return "", lookupError
				}
				t.Errorf("unexpected lookup outside PATH: %q", name)
				return "", exec.ErrNotFound
			})
			want := "claudock is not executable on PATH; install claudock-cli from https://github.com/laneboss-io/claudock-cli and add its claudock binary to PATH"
			if path != "" || err == nil || err.Error() != want || !reflect.DeepEqual(calls, []string{"claudock"}) {
				t.Fatalf("PATH failure: path=%q error=%v lookups=%q", path, err, calls)
			}
		})
	}
}

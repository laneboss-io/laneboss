package boxrun

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func happySuite() string {
	return `mkdir -p "$LB_BOX_OUT/nested"
printf 'result %s\n' "$LB_BOX_RUN_ID" > "$LB_BOX_OUT/nested/result.txt"`
}

func failedSuite() string {
	return `printf '%s\n' failed > "$LB_BOX_OUT/result.txt"
exit 3`
}

func sleepingSuite() string {
	return `sleep 600 &
child=$!
printf '%s\n' "$child" > "$LB_BOX_OUT/sleep.pid"
wait "$child"`
}

func sourceSuite(put string) string {
	return `cat hello.txt > "$LB_BOX_OUT/source.txt"
cat ` + shellQuote(put) + ` > "$LB_BOX_OUT/put.txt"`
}

func TestRemoteQuoting(t *testing.T) {
	f := newFixture(t)
	remote := filepath.Join(f.tr.root, "quote ' and space", "payload")
	command, err := uploadCommand(remote)
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.tr.Exec(context.Background(), command, strings.NewReader("quoted bytes"), nil, nil)
	if err != nil || code != 0 {
		t.Fatalf("quoted upload failed: exit %d, %v", code, err)
	}
	requireFile(t, remote, "quoted bytes")
	for _, bad := range []string{"relative", "-option", "/tmp/line\nnext", "/tmp/nul\x00end"} {
		if _, err := uploadCommand(bad); err == nil {
			t.Fatal("unsafe remote path was accepted")
		}
	}
}

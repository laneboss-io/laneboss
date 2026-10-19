//go:build linux

package judgecase

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The device fixture requires a private 0700 directory. Go's test directory
// mode follows umask; run this importer in the same 077 environment as the
// installed suite. No production permission or verifier check is changed.
func TestJudgeAuthImporter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	source, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "/bin/sh", "-c", `umask 077
exec "$1" test -count=1 -v -tags laneboss_e2e_authenticator ./cmd/laneboss/serve-authenticator`, "judge-auth", goPath)
	command.Dir = source
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: TestRealVerifierAndCounter")) || !bytes.Contains(output, []byte("--- PASS: TestRegistrationSignature")) || bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatalf("software device importer failed in its private fixture environment: %v\n%s", err, output)
	}
}

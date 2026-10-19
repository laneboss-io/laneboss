//go:build laneboss_root_canary

package linuxcase

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxProducerControls(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("Linux producer controls require the authorized root box job")
	}
	for _, script := range []string{"producer_tests.py", "run_tests.py"} {
		t.Run(script, func(t *testing.T) {
			command := exec.Command("python3", "-I", "-B", script)
			output, err := command.CombinedOutput()
			t.Log(string(output))
			if err != nil {
				t.Fatalf("Linux case controls failed: %v", err)
			}
			if !strings.Contains(string(output), "\nOK\n") {
				t.Fatal("Python controls lack their actual unittest completion")
			}
		})
	}
}

func TestLinuxProducerCrossVet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatal("Cross-vet runs only on the authorized Linux box")
	}
	for _, target := range []struct{ goos, arch string }{
		{"linux", "amd64"}, {"darwin", "arm64"},
	} {
		t.Run(target.goos+"/"+target.arch, func(t *testing.T) {
			command := exec.Command("go", "vet", "--tags", "laneboss_root_canary", "./e2e/v2/cases/linux")
			command.Dir = filepath.Join("..", "..", "..", "..")
			command.Env = []string{"PATH=" + os.Getenv("PATH"),
				"HOME=" + os.Getenv("HOME"), "GOOS=" + target.goos,
				"GOARCH=" + target.arch, "GOFLAGS=-trimpath",
				"GOCACHE=/private/tmp/lb-shared-gocache"}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("Cross-vet failed: %v\n%s", err, output)
			}
		})
	}
}

func TestLinuxG0Wiring(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("G0 wiring controls require the authorized root Linux box")
	}
	command := exec.Command("python3", "-I", "-B", "prove_wiring.py")
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("G0 base/candidate controls failed: %v", err)
	}
	if !strings.Contains(string(output), "PASS: Linux G0 base/candidate wiring") {
		t.Fatal("G0 controls lack their measured completion")
	}
}

//go:build linux && laneboss_faults

package lane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/caller"
)

func TestProcFaultReachesLaneReader(t *testing.T) {
	t.Setenv("LANEBOSS_PROCESSES", "native")
	for _, point := range []string{"proc-denied", "proc-esrch"} {
		t.Run(point, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "reached")
			request, err := json.Marshal(map[string]any{"point": point, "marker": marker, "pid": os.Getpid()})
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("LANEBOSS_FAULTS", string(request))
			start, err := caller.ProcessStart(os.Getpid())
			if err != nil || start == "" {
				t.Fatalf("caller resolution consumed the lane reader's fault: %v", err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("the caller's real read consumed the one-shot lane fault")
			}
			info, err := linuxInfo(os.Getpid())
			if point == "proc-esrch" {
				if err != nil || info != nil {
					t.Fatalf("wrapped ESRCH must remain an exited process: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "process table cannot be read") {
				t.Fatalf("the intended denied read was not refused: %v", err)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatal("the lane read did not retain its existing fault marker")
			}
			site, err := os.ReadFile(marker)
			if err != nil || string(site) != "lane.linuxInfo\n" {
				t.Fatalf("the fault has no exact reader attestation: %v", err)
			}
			info, err = linuxInfo(os.Getpid())
			if err != nil || info == nil || info.start != start {
				t.Fatalf("the next process read was not real: %v", err)
			}
		})
	}
}

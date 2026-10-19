//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDataToken(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("data token root ownership canary requires the disposable root Linux test step")
	}
	for _, fault := range []string{"revoked", "lost", "replaced", "wrong-owner"} {
		t.Run(fault, func(t *testing.T) {
			m, parent, job, _, _ := dataTestResult(t)
			job.State = "open"
			if err := m.checkData(context.Background(), parent, job); err != nil {
				t.Fatal(err)
			}
			pins := m.dataPins[job.Projection.OpenToken]
			switch fault {
			case "revoked":
				job.State = "revoked"
			case "lost":
				delete(m.dataPins, job.Projection.OpenToken)
			case "wrong-owner":
				job.Lease.UID++
			case "replaced":
				base := dataFD(pins.parents[1])
				if err := os.Rename(filepath.Join(base, "workspace"), filepath.Join(base, "old-workspace")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(base, "workspace"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.checkData(context.Background(), parent, job); err == nil {
				t.Fatalf("acceptance: data token accepted %s", fault)
			}
		})
	}
}

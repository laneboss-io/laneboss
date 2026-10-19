//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCaptureAllocationJournal(t *testing.T) {
	for _, fault := range []string{"boot", "phase", "missing", "unready"} {
		t.Run(fault, func(t *testing.T) {
			root, record, _ := storageFixture(t)
			if err := syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), true); err != nil {
				t.Fatal(err)
			}
			boot := record.BootID
			if err := captureAllocationCheck(record, boot); err != nil {
				t.Fatal("real initialized allocation failed capture readiness", err)
			}
			private, err := randomID("private-capture-")
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			switch fault {
			case "boot":
				record.BootID, want = string(private), "capture_boot"
			case "phase":
				record.Phase, want = "reserved", "capture_phase"
			case "missing":
				record.Storage, want = nil, "capture_storage_missing"
			case "unready":
				record.Storage.Ready, want = false, "capture_storage_unready"
			}
			cause := captureAllocationCheck(record, boot)
			if cause == nil {
				t.Fatal("capture accepted an unavailable allocation", fault)
			}
			var journal bytes.Buffer
			trace := helperRequestTrace{method: "register_capture", check: "capture_registration"}
			if err := trace.write(&journal, cause); err != nil {
				t.Fatal(err)
			}
			var entry map[string]string
			if json.Unmarshal(journal.Bytes(), &entry) != nil || entry["code"] != string(api.CodeContainmentUnknown) || entry["reason"] != want || bytes.Contains(journal.Bytes(), []byte(private)) {
				t.Fatal("capture allocation journal lost its fixed failing condition", fault, journal.String())
			}
		})
	}
}

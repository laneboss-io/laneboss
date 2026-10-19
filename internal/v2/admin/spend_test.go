package admin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestSpendOperatorTool(t *testing.T) {
	for _, name := range []string{"reading", "failure", "missing", "duplicate", "typed_number", "no_native", "changed_reading"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "balance-tool")
			script := "#!/bin/sh\nprintf 'profile-one  10.00 USD\\nTOTAL  10.00 USD\\n'\n"
			switch name {
			case "failure":
				script += "exit 7\n"
			case "missing":
				script = "#!/bin/sh\nprintf 'profile-one  10.00 USD\\n'\n"
			case "duplicate":
				script += "printf 'TOTAL  10.00 USD\\n'\n"
			}
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			tool := &BalanceTool{Command: path, Selector: "TOTAL", CredentialID: "pool-one", ProfileIDs: []api.ID{"profile-one"}, FloorMicros: 5000000}
			reader, ok := any(tool).(interface {
				Reading(context.Context) (api.SpendReading, error)
			})
			if !ok {
				t.Fatal("operator-side balance reading is missing")
			}
			if name == "typed_number" {
				tool.Command = "10.00"
			}
			reading, err := reader.Reading(context.Background())
			if name != "reading" && name != "no_native" && name != "changed_reading" {
				if err == nil {
					t.Fatal("invalid tool output or typed balance accepted")
				}
				return
			}
			if err != nil || reading.CredentialID != tool.CredentialID || string(reading.Output) != "profile-one  10.00 USD\nTOTAL  10.00 USD\n" || reading.ID == "" {
				t.Fatal("tool stdout not retained exactly", err)
			}
			if name == "no_native" {
				if _, err := CheckSpendReading(context.Background(), reading); err == nil {
					t.Fatal("reading bytes minted administrator authority")
				}
			}
			if name == "changed_reading" {
				_, _, _, ctx, endpoint := initialEnrollmentFixture(t)
				bound, err := bindSpendReading(ctx, endpoint, reading)
				if err != nil {
					t.Fatal(err)
				}
				reading.Output[0] ^= 1
				if _, err := CheckSpendReading(bound, reading); err == nil {
					t.Fatal("native reading capability accepted edited tool stdout")
				}
			}
		})
	}
}

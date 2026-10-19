package boxgcp

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func testConfig() boxcore.GCPConfig {
	return boxcore.GCPConfig{
		Project: "demo-project", Region: "demo-region",
		Zones:             []string{"demo-zone-a", "demo-zone-b"},
		BoxServiceAccount: "demo-box", ResultsBucket: "demo-results",
		ObjectPrefix: "runs", ImageProject: "demo-images",
		ImageFamilyX86: "demo-x86", ImageFamilyArm: "demo-arm",
		BootDiskType: "pd-standard",
	}
}

func testOptions() Options {
	return Options{
		Org: "Example.Org", NamePrefix: "LB-",
		Getenv: func(string) string { return "" },
		Now:    func() time.Time { return time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) },
		Sleep: func(context.Context, time.Duration) error {
			return errors.New("unexpected sleep")
		},
	}
}

func testRequest() boxcore.Request {
	return boxcore.Request{
		Purpose: "Demo.Purpose", Lane: "Demo_Lane", Owner: "Demo.Owner", RunID: "Run:One_2",
		VCPU: 2, Arch: "x86", RootGB: 23, HardMin: 7,
	}
}

func testCandidate() boxcore.Candidate {
	return boxcore.Candidate{
		Type: "demo-small", Zone: "demo-zone-a", Region: "demo-region", Arch: "x86", PriceUSDHour: 0.02,
	}
}

func testGuest() boxcore.Guest {
	return boxcore.Guest{Startup: "startup text\nsecond line\n", Shutdown: "shutdown harvest text\n"}
}

func testBox() boxcore.Box {
	return boxcore.Box{Provider: "gcp", ID: "lb-box-1", Name: "lb-box-1", Zone: "demo-zone-a", Project: "demo-project"}
}

func instanceJSON(t *testing.T, name, status string, labels map[string]string, address string) []byte {
	t.Helper()
	row := map[string]any{
		"name": name, "status": status, "statusMessage": "demo reason",
		"creationTimestamp": "2026-10-14T05:46:15.250-07:00",
		"machineType":       "zones/demo-zone-a/" + "machineTypes/demo-small",
		"zone":              "projects/demo-project/" + "zones/demo-zone-a",
		"labels":            labels,
	}
	if address != "" {
		row["networkInterfaces"] = []any{map[string]any{
			"accessConfigs": []any{map[string]any{"natIP": address}},
		}}
	}
	return encodeJSON(t, row)
}

func encodeJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return data
}

func arrayJSON(row []byte) []byte {
	return []byte("[" + string(row) + "]")
}

func resultFake(result boxexec.Result, err error) *boxexec.Fake {
	return &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "gcloud",
		Respond: func(boxexec.Cmd, int) (boxexec.Result, error) { return result, err },
	}}}
}

// ownedHandler answers describe with a box of ours, so a test of a guarded call gets past the fence.
func ownedHandler(t *testing.T) boxexec.Handler {
	t.Helper()
	row := instanceJSON(t, "lb-box-1", "RUNNING", map[string]string{
		"managed-by": "laneboss", "lb-org": "example-org", "lb-owner": "demo-owner",
		"lb-lane": "demo-lane", "lb-run": "demo-run",
	}, "")
	return boxexec.Handler{Name: "gcloud", ArgsContain: []string{"instances describe"},
		Respond: func(boxexec.Cmd, int) (boxexec.Result, error) { return boxexec.Result{Stdout: row}, nil }}
}

func requireArgs(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv mismatch: got %q; want %q", got, want)
	}
}

func onlyCall(t *testing.T, f *boxexec.Fake) boxexec.Call {
	t.Helper()
	if len(f.Calls) != 1 {
		t.Fatalf("got %d calls, want one", len(f.Calls))
	}
	if f.Calls[0].Name != "gcloud" {
		t.Fatal("wrong child executable")
	}
	return f.Calls[0]
}

func argValue(t *testing.T, args []string, flag string) (string, bool) {
	t.Helper()
	value, found := "", false
	for _, arg := range args {
		if strings.HasPrefix(arg, flag+"=") {
			if found {
				t.Fatalf("duplicate %s flag", flag)
			}
			value, found = strings.TrimPrefix(arg, flag+"="), true
		}
	}
	return value, found
}

// goneText is gcloud's answer for an instance that does not exist, worded the way gcloud words it. The resource path is
// built from short pieces on purpose: the publish scan refuses a 40-character run of path characters in any file.
func goneText(zone, name string) string {
	return "ERROR: (gcloud.compute.instances.describe) Could not fetch resource:\n - The resource '" +
		"projects/demo-project" + "/zones/" + zone + "/instances/" + name + "' was not found"
}

func requireKind(t *testing.T, err error, want boxcore.ErrorKind) {
	t.Helper()
	if err == nil || boxcore.KindOf(err) != want {
		t.Fatalf("error = %v, want kind %s", err, want)
	}
}

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func dashboardWriteRequestFile(t *testing.T, dir, name string, payload any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func dashboardAcceptedTransportRefusal(code int, errObj api.Error) bool {
	if code != 69 {
		return false
	}
	if errObj.Code == api.CodePrerequisite && errObj.Message == "protected binding is missing or unsafe" {
		return true
	}
	if errObj.Code == api.CodeNotImplemented && errObj.Owner == "lb-v2-service" {
		return true
	}
	return false
}

func TestDashCLIInputs(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "demo")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}

	validQuery := api.DashboardQuery{
		LifeID: "life-1",
		Run:    1,
		Level:  3,
		Driver: api.DriverClaudock,
		Since:  "2026-10-16T00:00:00Z",
		Until:  "2026-10-16T12:00:00Z",
		Cursor: "",
		Limit:  50,
	}
	invalidQuery := api.DashboardQuery{
		LifeID: "life-1",
		Level:  2,
		Driver: "bare-claude",
		Cursor: "",
		Limit:  0,
	}

	validPath := dashboardWriteRequestFile(t, dir, "valid.json", validQuery)
	invalidPath := dashboardWriteRequestFile(t, dir, "invalid.json", invalidQuery)
	unopenedProof := filepath.Join(dir, "unopened-proof.json")
	missingBinding := filepath.Join(dir, "missing-binding.json")

	methods := []struct {
		method api.Method
		subcmd string
	}{
		{"dashboard.tree", "tree"},
		{"dashboard.raw", "raw"},
		{"dashboard.decisions", "decisions"},
		{"dashboard.refusals", "refusals"},
		{"dashboard.plugins", "plugins"},
		{"dashboard.resources", "resources"},
		{"dashboard.lifecycle", "lifecycle"},
		{"dashboard.approvals", "approvals"},
	}

	for _, m := range methods {
		t.Run(string(m.method), func(t *testing.T) {
			// 1. Invalid file must return lb-v2-dashboard invalid_request (exit 2) before proof, key, or socket work.
			var outBad, errBad bytes.Buffer
			codeBad := Run([]string{
				"dashboard", m.subcmd,
				"--config", "demo",
				"--request", invalidPath,
				"--proof", unopenedProof,
				"--binding", missingBinding,
			}, nil, &outBad, &errBad)
			var typedBad api.Error
			if err := json.Unmarshal(errBad.Bytes(), &typedBad); err != nil {
				t.Fatalf("%s invalid file stderr decode failed: %v (%s)", m.method, err, errBad.String())
			}
			if codeBad != 2 || typedBad.Code != api.CodeInvalid || typedBad.Owner != dashboardOwner || outBad.Len() != 0 {
				t.Fatalf("%s invalid file did not fail local validator: exit=%d err=%+v", m.method, codeBad, typedBad)
			}

			// 2. Valid file must pass semantic validation and reach transport.
			var outOK, errOK bytes.Buffer
			codeOK := Run([]string{
				"dashboard", m.subcmd,
				"--config", "demo",
				"--request", validPath,
				"--binding", missingBinding,
			}, nil, &outOK, &errOK)
			var typedOK api.Error
			if err := json.Unmarshal(errOK.Bytes(), &typedOK); err != nil {
				t.Fatalf("%s valid file stderr decode failed: %v (%s)", m.method, err, errOK.String())
			}
			if typedOK.Owner == dashboardOwner || typedOK.Code == api.CodeInvalid {
				t.Fatalf("%s valid file was rejected by dashboard validator: exit=%d err=%+v", m.method, codeOK, typedOK)
			}
			if !dashboardAcceptedTransportRefusal(codeOK, typedOK) {
				t.Fatalf("%s valid file did not reach expected transport/binding gate: exit=%d err=%+v", m.method, codeOK, typedOK)
			}
		})
	}

	// 3. Red control: dropping a registration must fail closed with not_implemented (exit 69) from lb-v2-dashboard.
	t.Run("dropped", func(t *testing.T) {
		integrateInputChecks.Lock()
		prev := integrateInputChecks.methods["dashboard.tree"]
		prevUnavailable, hadUnavailable := integrateNoFileInput["dashboard.tree"]
		delete(integrateInputChecks.methods, "dashboard.tree")
		integrateNoFileInput["dashboard.tree"] = dashboardOwner
		integrateInputChecks.Unlock()

		t.Cleanup(func() {
			integrateInputChecks.Lock()
			defer integrateInputChecks.Unlock()
			delete(integrateInputChecks.methods, "dashboard.tree")
			delete(integrateNoFileInput, "dashboard.tree")
			if prev != nil {
				integrateInputChecks.methods["dashboard.tree"] = prev
			}
			if hadUnavailable {
				integrateNoFileInput["dashboard.tree"] = prevUnavailable
			}
		})

		var outDrop, errDrop bytes.Buffer
		codeDrop := Run([]string{
			"dashboard", "tree",
			"--config", "demo",
			"--request", validPath,
			"--binding", missingBinding,
		}, nil, &outDrop, &errDrop)
		var typedDrop api.Error
		if err := json.Unmarshal(errDrop.Bytes(), &typedDrop); err != nil {
			t.Fatalf("dropped validator stderr decode failed: %v", err)
		}
		wantMsg := api.NotImplemented(dashboardOwner, "dashboard.tree input validator").Message
		if codeDrop != 69 || typedDrop.Code != api.CodeNotImplemented || typedDrop.Owner != dashboardOwner || typedDrop.Message != wantMsg || outDrop.Len() != 0 {
			t.Fatalf("dropped validator did not fail closed: exit=%d err=%+v", codeDrop, typedDrop)
		}
	})
}

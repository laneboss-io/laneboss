package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestPlanCheckWords(t *testing.T) {
	for _, tc := range []struct {
		word string
		edit func(*LaunchPlan)
	}{
		{"pv_reservation", func(p *LaunchPlan) { p.Reservation.ID = "" }},
		{"pv_inputs", func(p *LaunchPlan) { p.Inputs.Grants.Revoked = true }},
		{"pv_lease", func(p *LaunchPlan) { p.Lease.UID = 0 }},
		{"pv_storage", func(p *LaunchPlan) { p.Data.Home.RootID = p.Data.Workspace.ID }},
		{"pv_material", func(p *LaunchPlan) { p.Data.Materialization.Manifest.Class = "artifact" }},
		{"pv_receipt", func(p *LaunchPlan) { p.Data.Materialization.Objects = nil }},
		{"pv_runner", func(p *LaunchPlan) { p.Runner.Session.VendorVersion = "" }},
		{"pv_loop", func(p *LaunchPlan) { *p = loopPlanFixture(t); p.Budget.WallMS++ }},
		{"pv_credentials", func(p *LaunchPlan) { p.Injection.SlotIDs = nil }},
		{"pv_capture", func(p *LaunchPlan) { p.Capture.Streams = nil }},
		{"pv_cap_policy", func(p *LaunchPlan) { p.Capture = refusedCapture(p.Capture) }},
		{"pv_cap_rule", func(p *LaunchPlan) {
			p.Capture = refusedCapture(p.Capture)
			p.CapturePolicy = &EffectivePolicy{Generation: p.Reservation.PolicyGeneration}
		}},
		{"pv_cap_binding", func(p *LaunchPlan) { p.Capture.RequestID = "foreign-request" }},
	} {
		t.Run(tc.word, func(t *testing.T) {
			p := launchFixture(t)
			if err := ValidateLaunchPlan(p); err != nil {
				t.Fatal("valid control was refused", err)
			}
			tc.edit(&p)
			err := ValidateLaunchPlan(p)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code != CodeInvalid || HelperReason(err) != tc.word {
				t.Fatal("invalid plan lost its exact fixed check", tc.word, HelperReason(err), err)
			}
			raw, encodeErr := json.Marshal(err)
			plain, plainErr := json.Marshal(typed)
			if encodeErr != nil || plainErr != nil || !bytes.Equal(raw, plain) {
				t.Fatal("private plan check changed public error bytes")
			}
		})
	}
}

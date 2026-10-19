package api

import (
	"errors"
	"testing"
)

func keyEnvCase(t *testing.T) (CredentialProjectionRecord, CredentialExecEnvironment) {
	t.Helper()
	record, exec := envMode(t, "headless")
	r := record.Authority.Request.Handoff.Spec.Runner
	r.Slot.Mode = "claude-api-key"
	r.EnvironmentNames = []string{"ANTHROPIC_API_KEY", "HOME"}
	target := &record.Authority.Targets[0]
	target.Delivery, target.RelativePath = "file", ".config/claudock/key-store.json"
	target.FileMode, target.EnvironmentName = 0600, "ANTHROPIC_API_KEY"
	held := &record.Receipt.Targets[0]
	held.Target, held.OwnerUID, held.Mode = *target, record.Authority.Request.Lease.UID, 0600
	held.Links, held.ReadOnlyView = 1, true
	exec.VendorNames = []string{"TASK_ACCESS", "ANTHROPIC_API_KEY"}
	sealEnvRecord(t, &record)
	return record, exec
}

func TestAPIKeyEnv(t *testing.T) {
	for _, fault := range []string{"none", "early", "missing", "duplicate", "oauth", "driver", "home", "linked", "owner", "target", "path", "writable", "expired", "revoked"} {
		t.Run(fault, func(t *testing.T) {
			record, exec := keyEnvCase(t)
			if err := ValidateCredentialEnvironment(record, exec); err != nil {
				t.Fatal("API key final environment refused", err)
			}
			if fault == "none" {
				targets, err := CredentialTargets(record.Authority.Request, contractNow())
				if err != nil || len(targets) != 3 || targets[0] != record.Authority.Targets[0] {
					t.Fatal("API key did not select its private store and final environment", err)
				}
				return
			}
			switch fault {
			case "early":
				exec.EarlierNames = append(exec.EarlierNames, "ANTHROPIC_API_KEY")
			case "missing":
				exec.VendorNames = []string{"TASK_ACCESS"}
			case "duplicate":
				exec.VendorNames = append(exec.VendorNames, "ANTHROPIC_API_KEY")
			case "oauth":
				record.Authority.Request.Handoff.Spec.Runner.Slot.Mode = "claudock-headless"
			case "driver":
				record.Authority.Request.Handoff.Spec.Runner.Driver = DriverCodex
				record.Authority.Request.Handoff.Spec.Grants.Profiles[0].Driver = DriverCodex
			case "home":
				record.Authority.Request.Handoff.Spec.Runner.Home.VendorDirectory = ".codex"
			case "linked":
				record.Receipt.Targets[0].Links = 2
			case "owner":
				record.Receipt.Targets[0].OwnerUID = 0
			case "target":
				record.Authority.Targets[0].EnvironmentName = "ANTHROPIC_AUTH_TOKEN"
			case "path":
				record.Authority.Targets[0].RelativePath = ".claude/key-store.json"
			case "writable":
				record.Receipt.Targets[0].ReadOnlyView = false
			case "expired":
				record.Authority.Request.Handoff.Spec.Runner.Slot.ExpiresAt = exec.ObservedAt
			case "revoked":
				record.Authority.Sources[0].Revoked = true
			}
			sealEnvRecord(t, &record)
			if err := ValidateCredentialEnvironment(record, exec); err == nil {
				t.Fatal("API key environment boundary accepted altered authority")
			}
		})
	}
}

func TestAPIKeyTaskNames(t *testing.T) {
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_OTHER", "CLAUDE_OTHER", "CLAUDOCK_OTHER", "CODEX_OTHER", "OPENAI_OTHER"} {
		t.Run(name, func(t *testing.T) {
			record, _ := keyEnvCase(t)
			r := record.Authority.Request
			if _, err := CredentialTargets(r, contractNow()); err != nil {
				t.Fatal("API key positive control refused", err)
			}
			r.Handoff.Spec.Grants.Secrets[0].Target = name
			var typed *Error
			if _, err := CredentialTargets(r, contractNow()); !errors.As(err, &typed) || typed.Code != CodeInvalid {
				t.Fatal("vendor namespace entered a task grant")
			}
		})
	}
}

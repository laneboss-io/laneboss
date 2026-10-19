package api

import "testing"

func TestEnvNames(t *testing.T) {
	x, _, _, _ := projectionFixture(t)
	for _, name := range []string{"GLIBC_TUNABLES", "GCONV_PATH", "GETCONF_DIR", "HOSTALIASES", "LOCALDOMAIN", "LOCPATH", "MALLOC_CHECK_", "NIS_PATH", "NLSPATH", "RESOLV_HOST_CONF", "RES_OPTIONS", "TZDIR", "IFS", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "PERL5OPT", "RUBYOPT", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "PROMPT_COMMAND", "CDPATH", "PS4", "GOFLAGS"} {
		t.Run(name, func(t *testing.T) {
			r := x.Authority.Request
			r.Handoff.Spec.Grants.Secrets = append([]SecretGrant(nil), r.Handoff.Spec.Grants.Secrets...)
			r.Handoff.Spec.Grants.Secrets[0].Target = name
			_, err := CredentialTargets(r, contractNow())
			requireLaunchInvalid(t, err, "privileged environment name was accepted")
		})
	}
	if !credentialEnvironment("TASK_CANARY") {
		t.Fatal("ordinary task environment was refused")
	}
}

func TestEnvExec(t *testing.T) {
	x, _, held, _ := projectionFixture(t)
	record := CredentialProjectionRecord{Authority: x.Authority, State: "held", Generation: held.Generation, Receipt: &held}
	r := x.Authority.Request
	good := CredentialExecEnvironment{PreparedID: r.Prepared.ID, Stage: "vendor_exec", UID: r.Lease.UID, GID: r.Lease.GID,
		Capabilities: projectionCount(0), Backend: r.Handoff.Spec.Backend, IsolationReady: true, ObservedAt: contractStamp(contractNow()), EarlierNames: []string{"PATH"}, VendorNames: []string{"TASK_ACCESS"}}
	if err := ValidateCredentialEnvironment(record, good); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"stage", "uid", "caps", "isolation", "earlier", "missing"} {
		t.Run(fault, func(t *testing.T) {
			bad := good
			switch fault {
			case "stage":
				bad.Stage = "bootstrap"
			case "uid":
				bad.UID = 0
			case "caps":
				bad.Capabilities = projectionCount(1)
			case "isolation":
				bad.IsolationReady = false
			case "earlier":
				bad.EarlierNames = append([]string{}, good.EarlierNames...)
				bad.EarlierNames = append(bad.EarlierNames, "TASK_ACCESS")
			case "missing":
				bad.VendorNames = nil
			}
			requireLaunchInvalid(t, ValidateCredentialEnvironment(record, bad), "task environment crossed the final exec boundary")
		})
	}
}

func TestEnvAnonymous(t *testing.T) {
	x, facts, held, _ := projectionFixture(t)
	held.Targets[1].Links = 0
	if err := ValidateCredentialProjectionReceipt(x, facts, held, contractNow()); err != nil {
		t.Fatalf("anonymous environment descriptor was refused: %v", err)
	}
	held.Targets[1].OwnerUID = x.Authority.Request.Lease.UID
	requireLaunchInvalid(t, ValidateCredentialProjectionReceipt(x, facts, held, contractNow()), "anonymous environment descriptor had a foreign owner")
	for _, cell := range []struct {
		name  string
		index int
	}{{"slot", 0}, {"task", 2}} {
		t.Run(cell.name, func(t *testing.T) {
			x, facts, held, _ := projectionFixture(t)
			held.Targets[cell.index].Links = 0
			requireLaunchInvalid(t, ValidateCredentialProjectionReceipt(x, facts, held, contractNow()), "anonymous file target was accepted")
		})
	}
}

// One lease's canonical state passes each real consumer's claim-state gate.
// Causal effect payloads stay kind-specific: a helper effect is never forged
// into the worker or publication union merely to share an entire payload.
func TestSharedLease(t *testing.T) {
	lease := EffectLease{Record: EffectRecord{State: EffectClaimed}}
	consumers := map[string]func(EffectLease) error{
		"credential": func(shared EffectLease) error {
			x, _, _, _ := projectionFixture(t)
			x.Authority.Request.Claim.Record.State = shared.Record.State
			return ValidateCredentialProjectionRequest(x.Authority.Request, contractNow())
		},
		"data": func(shared EffectLease) error {
			s, r, _ := dataStageFixture(t)
			s.Claim.Record.State = shared.Record.State
			return ValidateLaunchDataStage(s, r)
		},
		"deferred": func(shared EffectLease) error {
			r, l, o := deferredOutcome(t)
			l.Record.State = shared.Record.State
			return ValidateDeferredCompletion(r, l, o)
		},
		"worker": func(shared EffectLease) error {
			p := workerFixture(t)
			p.Claim.Record.State = shared.Record.State
			return ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, WorkerInputRead, contractNow())
		},
	}
	for name, validate := range consumers {
		t.Run(name, func(t *testing.T) {
			if err := validate(lease); err != nil {
				t.Fatalf("one held lease state was incompatible with the consumer: %v", err)
			}
		})
	}
	for _, state := range []EffectState{EffectPending, EffectClaimed, EffectCompleted, EffectFailed} {
		if !ValidEffectState(state) {
			t.Fatalf("closed effect state was rejected: %s", state)
		}
	}
	if ValidEffectState("running") || ValidEffectState("unknown") {
		t.Fatal("effect state accepted an operation status or unknown label")
	}
}

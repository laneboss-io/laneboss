package api

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBindingCompatibility(t *testing.T) {
	binding := InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: ContractRevision,
		Protocol: Protocol, APISchema: 2, Config: "demo", Class: EndpointHuman,
		InstallationGeneration: 1, EndpointGeneration: 2, ServiceUID: 1001, ServiceGID: 1001,
		Socket: "/run/laneboss/demo.sock", ArtifactSHA256: Digest(strings.Repeat("1", 64)),
		ServiceVersion: "fixture-version", Backend: "linux-bwrap-landlock"}
	if err := ValidateBinding(binding, "demo", "fixture-version"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InstalledBinding){
		"old contract":    func(b *InstalledBinding) { b.ContractRevision = "v2.0-draft.1" },
		"wrong config":    func(b *InstalledBinding) { b.Config = "another" },
		"wrong class":     func(b *InstalledBinding) { b.Class = "root" },
		"missing life":    func(b *InstalledBinding) { b.Class = EndpointLane },
		"root service":    func(b *InstalledBinding) { b.ServiceUID = 0 },
		"relative socket": func(b *InstalledBinding) { b.Socket = "control.sock" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			if ValidateBinding(changed, "demo", "fixture-version") == nil {
				t.Fatal("invalid binding was accepted")
			}
		})
	}
}

func TestHelperEffectCause(t *testing.T) {
	cause := InternalIntent{ID: "release-intent", Kind: InternalHelperRelease, Config: "demo", EffectID: "effect", CauseOperationID: "operation"}
	makeTransaction := func(kind InternalKind, config string) Transaction {
		context := cause
		context.Kind, context.Config = kind, config
		return Transaction{Scope: Scope{Config: "demo"}, Internal: &cause,
			Effects: []Effect{{ID: "effect", OperationID: "operation", Context: &context,
				HelperRelease: &HelperReleaseRequest{Cause: context, LeaseID: "lease"}}}}
	}
	if err := ValidateTransactionShape(makeTransaction(InternalHelperRelease, "demo")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		kind   InternalKind
		config string
	}{
		{InternalHelperAbort, "demo"}, {"unknown", "demo"}, {InternalHelperRelease, "another"},
	} {
		if ValidateTransactionShape(makeTransaction(row.kind, row.config)) == nil {
			t.Fatal("release accepted an unrelated kind or configuration")
		}
	}
	for _, kind := range []InternalKind{InternalHelperPrepare, InternalHelperRegister, InternalHelperRelease} {
		intent := cause
		intent.Kind = kind
		if err := ValidateTransactionShape(Transaction{Scope: Scope{Config: "demo"}, Internal: &intent}); err != nil {
			t.Fatalf("helper catalog omitted %s: %v", kind, err)
		}
	}
}

func TestPublicWriteAuthority(t *testing.T) {
	result, err := json.Marshal(Record{})
	if err != nil {
		t.Fatal(err)
	}
	base := Transaction{Scope: Scope{Config: "demo", Request: Request{Method: "records.append"}},
		Reply: &RPCReply{Result: result}, Events: []Event{{Kind: "record.appended"}}}
	if err := ValidateTransactionShape(base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Transaction){
		"policy injection":   func(tx *Transaction) { tx.Writes.Policy = &EffectivePolicy{} },
		"decision injection": func(tx *Transaction) { tx.Writes.Decisions = []DecisionProjection{{RecordID: "other"}} },
		"grant injection":    func(tx *Transaction) { tx.Writes.Grants = []GrantSet{{}} },
		"event injection":    func(tx *Transaction) { tx.Events = []Event{{Kind: "org.change.approved"}} },
		"read writes": func(tx *Transaction) {
			tx.Scope.Request.Method = "records.get"
			tx.Events = nil
			tx.Writes.Lanes = []Lane{{}}
		},
		"read event":    func(tx *Transaction) { tx.Scope.Request.Method = "records.get" },
		"missing reply": func(tx *Transaction) { tx.Reply = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if ValidateTransactionShape(changed) == nil {
				t.Fatal("method wrote outside its contract row or omitted its reply")
			}
		})
	}
}

func TestReleaseMeasuredQuiescence(t *testing.T) {
	zero, one := uint64(0), uint64(1)
	base := ReleaseReceipt{ID: "receipt", LeaseID: "lease", ContainmentID: "containment", Backend: "linux-bwrap-landlock",
		OperationID: "operation", EffectID: "effect", ObservedAt: "2026-01-01T00:00:00Z",
		Quiescence:      ProcessObservation{Handle: ProcessHandle{ContainmentID: "containment"}, State: "exited", Survivors: &zero},
		LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero}
	if err := ValidateReleaseReceipt(base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ReleaseReceipt){
		"survivor":          func(r *ReleaseReceipt) { r.Quiescence.Survivors = &one },
		"unknown processes": func(r *ReleaseReceipt) { r.Quiescence.Survivors = nil },
		"connection":        func(r *ReleaseReceipt) { r.LiveConnections = &one },
		"job":               func(r *ReleaseReceipt) { r.QueuedJobs = &one },
		"export":            func(r *ReleaseReceipt) { r.WritableExports = &one },
		"unknown export":    func(r *ReleaseReceipt) { r.WritableExports = nil },
		"not exited":        func(r *ReleaseReceipt) { r.Quiescence.State = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			var typed *Error
			if err := ValidateReleaseReceipt(changed); !errors.As(err, &typed) || typed.Code != CodeContainmentUnknown {
				t.Fatal("unproved release was accepted or lost containment_unknown")
			}
		})
	}
}

func TestHelperIPCTags(t *testing.T) {
	for _, object := range []any{PreparedSpecHandoff{}, PreparedSpecReceipt{}, HelperOpenRequest{}, HelperObserveRequest{}, HelperStopRequest{}, HelperAbortRequest{}, HelperReleaseRequest{}, ReleaseReceipt{}, AbortReceipt{}, HelperReconcileRequest{}, LaunchReconciliation{}} {
		typeOf := reflect.TypeOf(object)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name != strings.ToLower(name) {
				t.Fatalf("untagged helper IPC field: %s.%s", typeOf.Name(), field.Name)
			}
		}
	}
}

func TestTransactionDiscriminants(t *testing.T) {
	base := Transaction{Scope: Scope{Config: "demo", Request: Request{Method: "records.get"}},
		Reply: &RPCReply{Error: &Error{Code: CodeNotFound}}}
	if err := ValidateTransactionShape(base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Transaction){
		"unknown compare": func(tx *Transaction) { tx.Compare = []Compare{{Kind: "anything", ID: "one"}} },
		"empty guard":     func(tx *Transaction) { tx.Guards = []TransactionGuard{{}} },
		"ambiguous guard": func(tx *Transaction) { tx.Guards = []TransactionGuard{{Proof: &ProofUse{}, Ticket: &TicketUse{}}} },
		"untyped result":  func(tx *Transaction) { tx.Reply = &RPCReply{Result: json.RawMessage(`{"constant":true}`)} },
		"mixed identity": func(tx *Transaction) {
			tx.Internal = &InternalIntent{ID: "intent", Config: "demo", Kind: InternalObjectRetain}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if ValidateTransactionShape(changed) == nil {
				t.Fatal("invalid transaction was accepted")
			}
		})
	}
}

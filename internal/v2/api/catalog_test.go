package api

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func catalogTransaction(t *testing.T, method Method) Transaction {
	t.Helper()
	result, err := json.Marshal(reflect.New(Methods[method].Response).Elem().Interface())
	if err != nil {
		t.Fatal(err)
	}
	return Transaction{Scope: Scope{Config: "demo", Actor: Actor{Kind: "lane", ID: "parent", LifeID: "life", Level: 6}, Request: Request{Method: method}}, Reply: &RPCReply{Result: result}}
}

func TestLifecycleWorkerWrites(t *testing.T) {
	for _, method := range []Method{"lane.start", "lane.adopt", "lane.resume", "lane.turn"} {
		t.Run(string(method), func(t *testing.T) {
			tx := catalogTransaction(t, method)
			tx.Writes.WorkerLeases = []WorkerLease{{ID: "materialize-worker"}}
			cause := InternalIntent{ID: "materialize", Kind: InternalLifecycleEffect, Config: "demo", EffectID: "effect", CauseOperationID: "operation"}
			tx.Effects = []Effect{{ID: "effect", OperationID: "operation", Context: &cause, Worker: &WorkerPlan{}}}
			if method == "lane.resume" || method == "lane.turn" {
				tx.Writes.Continuations = []ContinuationIntent{{ID: "cancelled"}}
				tx.Events = []Event{{Kind: "lane.turn", LogicalTurnID: "logical-turn"}, {Kind: "watchdog.cancelled"}}
			}
			if err := ValidateTransactionShape(tx); err != nil {
				t.Fatalf("required lifecycle worker/cancellation writes were refused: %v", err)
			}
			tx.Writes.Policy = &EffectivePolicy{}
			if ValidateTransactionShape(tx) == nil {
				t.Fatal("lifecycle worker operation wrote policy")
			}
		})
	}
	grants := catalogTransaction(t, "grants.revoke")
	grants.Writes = StateWrites{Grants: []GrantSet{{}}, Lanes: []Lane{{}}, Continuations: []ContinuationIntent{{}}, Endpoints: []EndpointProjection{{}}}
	grants.Events = []Event{{Kind: "grants.revoked"}, {Kind: "lane.stopping"}, {Kind: "watchdog.cancelled"}, {Kind: "identity.revoked"}}
	if err := ValidateTransactionShape(grants); err != nil {
		t.Fatalf("grant revocation could not cancel/revoke its lives: %v", err)
	}
}

func TestInternalWriteAuthority(t *testing.T) {
	intent := InternalIntent{ID: "capture", Kind: InternalCaptureAppend, Config: "demo"}
	base := Transaction{Scope: Scope{Config: "demo"}, Internal: &intent, Writes: StateWrites{Objects: []ObjectWrite{{}}}, Events: []Event{{Kind: "capture.appended"}}}
	if err := ValidateTransactionShape(base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Transaction){
		"policy":         func(tx *Transaction) { tx.Writes.Policy = &EffectivePolicy{} },
		"decisions":      func(tx *Transaction) { tx.Writes.Decisions = []DecisionProjection{{}} },
		"event":          func(tx *Transaction) { tx.Events = []Event{{Kind: "org.change.applied"}} },
		"proof":          func(tx *Transaction) { tx.Guards = []TransactionGuard{{Proof: &ProofUse{}}} },
		"internal_reply": func(tx *Transaction) { tx.Reply = &RPCReply{Error: &Error{Code: CodeUnavailable}} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if ValidateTransactionShape(changed) == nil {
				t.Fatal("internal job wrote outside its authority")
			}
		})
	}
	intent.Kind = InternalChannelReceive
	base.Events = []Event{{Kind: "record.appended"}}
	base.Writes.Decisions = []DecisionProjection{{}}
	if ValidateTransactionShape(base) == nil {
		t.Fatal("channel intake promoted an authoritative decision")
	}
	intent.Kind = InternalOrgPublish
	base.Events = []Event{{Kind: "org.change.applied"}}
	base.Writes = StateWrites{Policy: &EffectivePolicy{}, OrgSnapshots: []OrgSnapshot{{}}}
	if err := ValidateTransactionShape(base); err != nil {
		t.Fatal(err)
	}
}

func TestCompletionApprovalGuard(t *testing.T) {
	for _, kind := range []InternalKind{InternalOrgPublish, InternalUpgradeApply, InternalMigrationApply} {
		t.Run(string(kind), func(t *testing.T) {
			intent := InternalIntent{ID: "completion", Kind: kind, Config: "demo"}
			tx := Transaction{Scope: Scope{Config: "demo"}, Internal: &intent,
				Guards: []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: "life", Epoch: 1}}}}
			if err := ValidateTransactionShape(tx); err != nil {
				t.Fatal(err)
			}
			tx.Guards = append(tx.Guards, TransactionGuard{Approval: &ApprovalUse{ApprovalID: "already-consumed"}})
			var typed *Error
			if err := ValidateTransactionShape(tx); !errors.As(err, &typed) || typed.Code != CodeInvalid {
				t.Fatalf("completion accepted a second approval consumption: %v", err)
			}
		})
	}
}

func TestPublicGuardAuthority(t *testing.T) {
	root := catalogTransaction(t, "lane.start")
	root.Scope.Actor = Actor{Kind: "human", ID: "owner"}
	root.Scope.EndpointGeneration = 7
	root.Guards = []TransactionGuard{{Ticket: &TicketUse{TicketID: "root", PrincipalID: "owner", Config: "demo", EndpointGeneration: 7}}}
	if err := ValidateTransactionShape(root); err != nil {
		t.Fatal(err)
	}
	t.Run("root_ticket_missing", func(t *testing.T) {
		changed := root
		changed.Guards = []TransactionGuard{{Proof: &ProofUse{}}}
		if ValidateTransactionShape(changed) == nil {
			t.Fatal("human root spawn lacked its ticket")
		}
	})
	t.Run("lane_proof", func(t *testing.T) {
		changed := catalogTransaction(t, "records.append")
		changed.Guards = []TransactionGuard{{Proof: &ProofUse{}}}
		if ValidateTransactionShape(changed) == nil {
			t.Fatal("lane borrowed a human proof")
		}
	})
	t.Run("lane_ticket", func(t *testing.T) {
		changed := root
		changed.Scope.Actor = Actor{Kind: "lane", ID: "owner", LifeID: "life"}
		if ValidateTransactionShape(changed) == nil {
			t.Fatal("lane borrowed a human ticket")
		}
	})
	apply := deferredTransaction(t)
	if err := ValidateTransactionShape(apply); err != nil {
		t.Fatal(err)
	}
	t.Run("approval_missing", func(t *testing.T) {
		apply.Guards = nil
		if ValidateTransactionShape(apply) == nil {
			t.Fatal("D6 apply lacked its approval")
		}
	})
}

func TestTicketProvenance(t *testing.T) {
	ticket := Ticket{ID: "root", PrincipalID: "owner", Config: "demo", EndpointGeneration: 7, Level: 6, Role: "coordinator", GrantSetID: "root-grants", ExpiresAt: "2026-01-01T00:02:00Z"}
	raw, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"principal_id", "config", "endpoint_generation"} {
		if len(wire[field]) == 0 {
			t.Fatal("ticket wire lost its provenance")
		}
	}
	var retained Ticket
	if err := DecodeObject(raw, &retained); err != nil || retained != ticket {
		t.Fatal("ticket provenance did not survive storage/event decoding")
	}
	tx := catalogTransaction(t, "ticket.issue")
	tx.Scope.Actor, tx.Scope.EndpointGeneration = Actor{Kind: "human", ID: "owner"}, 7
	tx.Writes.Tickets, tx.Guards, tx.Reply = []Ticket{ticket}, []TransactionGuard{{Proof: &ProofUse{}}}, &RPCReply{Result: raw}
	if err := ValidateTransactionShape(tx); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Ticket){
		func(t *Ticket) { t.PrincipalID = "someone-else" },
		func(t *Ticket) { t.Config = "another" },
		func(t *Ticket) { t.EndpointGeneration++ },
	} {
		changed := ticket
		mutate(&changed)
		tx.Writes.Tickets = []Ticket{changed}
		if ValidateTransactionShape(tx) == nil {
			t.Fatal("ticket write accepted unrelated provenance")
		}
	}
}

func TestHelperReleaseEvent(t *testing.T) {
	if EventSchemas["helper.released"] != reflect.TypeFor[ReleaseReceipt]() {
		t.Fatal("release event lost helper measurements")
	}
}

func TestRootTicketBoundScope(t *testing.T) {
	root := catalogTransaction(t, "lane.start")
	root.Scope.Actor, root.Scope.EndpointGeneration = Actor{Kind: "human", ID: "issuer"}, 7
	root.Guards = []TransactionGuard{{Ticket: &TicketUse{TicketID: "root-ticket", PrincipalID: "issuer", Config: "demo", EndpointGeneration: 7}}}
	if err := ValidateTransactionShape(root); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Scope){
		"other_principal":  func(s *Scope) { s.Actor.ID = "another-human" },
		"rotated_endpoint": func(s *Scope) { s.EndpointGeneration++ },
		"other_config":     func(s *Scope) { s.Config = "another" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := root
			change(&bad.Scope)
			if ValidateTransactionShape(bad) == nil {
				t.Fatal("root ticket transferred across its issuing scope")
			}
		})
	}
}

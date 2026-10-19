package watchdog

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCurrentRunSnapshot(t *testing.T) {
	t.Run("assessment", func(t *testing.T) {
		r := newRig(t)
		history := r.store.lane
		r.store.history = &history
		r.store.lane.Run++
		r.store.lane.Generation++
		r.store.lane.CancellationEpoch++
		_, err := r.s.assess(context.Background(), r.signal)
		requireCode(t, err, api.CodeConflict)
		r.noEffects()
	})
	t.Run("recovery", func(t *testing.T) {
		r, store, probe := newJournal(t)
		if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
			t.Fatal(err)
		}
		history := store.lane
		store.history = &history
		store.lane.Run++
		store.lane.Generation++
		store.lane.CancellationEpoch++
		restartService(t, r)
		_, err := r.s.Reconcile(context.Background(), r.signal.Target)
		requireCode(t, err, api.CodeCancelled)
		if len(probe.requests) != 1 || store.writeCalls != 1 || r.broker.acquireCalls != 0 {
			t.Fatal("historical run authorized another continuation after manual control")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		r, store, _ := newJournal(t)
		history := store.lane
		store.history = &history
		store.lane.Run++
		store.lane.Generation++
		err := r.s.Cancel(context.Background(), r.signal.Target)
		requireCode(t, err, api.CodeConflict)
		if store.writeCalls != 0 {
			t.Fatal("an old target cancelled the current run through a historical lookup")
		}
	})
}

func TestPaidProfileAffinity(t *testing.T) {
	for _, row := range []struct {
		name    string
		paidA   bool
		paidB   bool
		budget  int64
		selectB bool
	}{
		{"free-to-paid", false, true, 1000, false},
		{"paid-to-paid", true, true, 1000, true},
		{"paid-no-budget", true, true, 0, false},
		{"free-to-free", false, false, 1000, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t)
			r.store.grants.Profiles[0].Paid = row.paidA
			r.store.grants.Profiles[1].Paid = row.paidB
			r.grants.grants = r.store.grants
			r.store.lane.BudgetRemaining.SpendMicros = row.budget
			plan, err := r.s.assess(context.Background(), r.signal)
			if err != nil || (plan.Swap != nil) != row.selectB {
				t.Fatal("selection changed paid-profile affinity or ignored remaining spend", err)
			}
			if !row.selectB && (!reflect.DeepEqual(r.broker.checked, []api.ID{"profile-a"}) || r.broker.eligibilityCalls != 0) {
				t.Fatal("ineligible paid profile reached the outside broker")
			}
			r.noEffects()
		})
	}
}

func TestWriteCatalogPreflight(t *testing.T) {
	r, store, _ := newJournal(t)
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil {
		t.Fatal(err)
	}
	// Actual submitted continue and cancel transactions must both satisfy the
	// current catalog. This is shape evidence only, not authorization proof.
	for _, transaction := range store.transactions {
		if err := api.ValidateTransactionShape(transaction); err != nil {
			t.Fatal("watchdog submitted an out-of-catalog transaction", err)
		}
	}
	base := store.transactions[0]
	for _, row := range []struct {
		name string
		edit func(*api.Transaction)
	}{
		{"grants", func(tx *api.Transaction) { tx.Writes.Grants = []api.GrantSet{store.grants} }},
		{"policy", func(tx *api.Transaction) { tx.Writes.Policy = &api.EffectivePolicy{} }},
		{"judge", func(tx *api.Transaction) { tx.Writes.JudgeAudits = []api.JudgeAudit{{ID: "audit-one"}} }},
		{"channels", func(tx *api.Transaction) { tx.Writes.Channels = []api.EnrolledChannel{{ID: "channel-one"}} }},
		{"mail", func(tx *api.Transaction) { tx.Writes.Mail = []api.Mail{{ID: "mail-one"}} }},
		{"event", func(tx *api.Transaction) { tx.Events = []api.Event{{Kind: "mail.delivered"}} }},
		{"guard", func(tx *api.Transaction) { tx.Guards = []api.TransactionGuard{{Proof: &api.ProofUse{}}} }},
		{"reply", func(tx *api.Transaction) { tx.Reply = &api.RPCReply{Result: json.RawMessage(`{}`)} }},
		{"mutating-read", func(tx *api.Transaction) { tx.Internal = nil; tx.Scope.Request.Method = "lane.status" }},
		{"missing-reply", func(tx *api.Transaction) {
			*tx = api.Transaction{Scope: r.s.readScope(), Writes: api.StateWrites{UploadBegins: []api.UploadLease{{ID: "upload-one"}}}}
			tx.Scope.Request.Method = "blob.begin"
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			tx := base
			row.edit(&tx)
			writes := store.writeCalls
			_, err := r.s.transact(context.Background(), tx)
			requireCode(t, err, api.CodeInvalid)
			if store.writeCalls != writes {
				t.Fatal("out-of-domain transaction reached the state writer")
			}
		})
	}
}

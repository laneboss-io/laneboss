package admin

import (
	"bytes"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestHelperUIDJournal(t *testing.T) {
	owner := uidMatch{UID: 62001, PID: 71, TID: 72, Start: "12345",
		LifeID: "owner-life", LeaseID: "owner-lease"}
	for _, test := range []struct {
		name         string
		life, lease  api.ID
		match        *uidMatch
		reason       string
		wantLife     api.ID
		wantLease    api.ID
		requestLife  api.ID
		requestLease api.ID
	}{
		{name: "owner", match: &owner, reason: "uid_survivor",
			wantLife: owner.LifeID, wantLease: owner.LeaseID},
		{name: "same", life: owner.LifeID, lease: owner.LeaseID,
			match: &owner, reason: "uid_survivor",
			wantLife: owner.LifeID, wantLease: owner.LeaseID},
		{name: "distinct", life: "request-life", lease: "request-lease",
			match: &owner, reason: "uid_survivor",
			wantLife: owner.LifeID, wantLease: owner.LeaseID,
			requestLife: "request-life", requestLease: "request-lease"},
		{name: "partial", life: owner.LifeID, lease: "request-lease",
			match: &owner, reason: "uid_survivor",
			wantLife: owner.LifeID, wantLease: owner.LeaseID,
			requestLease: "request-lease"},
		{name: "request", life: "request-life", lease: "request-lease",
			reason:   "storage_parent",
			wantLife: "request-life", wantLease: "request-lease"},
		{name: "other-reason", life: "request-life", lease: "request-lease",
			match: &owner, reason: "storage_parent",
			wantLife: "request-life", wantLease: "request-lease"},
		{name: "unknown-owner", life: "request-life", lease: "request-lease",
			match:  &uidMatch{UID: 62002, PID: 81, TID: 82},
			reason: "uid_survivor", requestLife: "request-life",
			requestLease: "request-lease"},
	} {
		t.Run(test.name, func(t *testing.T) {
			trace := helperRequestTrace{method: "reconcile_gate", check: "operation",
				match: test.match, life: test.life, lease: test.lease,
				nonce: "helper-nonce", run: 2, launch: "request-launch", caller: 91}
			var journal bytes.Buffer
			cause := api.WithHelperReason(failure(api.CodeContainmentUnknown, "refused"), test.reason)
			if err := trace.write(&journal, cause); err != nil {
				t.Fatal(err)
			}
			var entry struct {
				Event        string        `json:"event"`
				Method       string        `json:"method"`
				Code         api.ErrorCode `json:"code"`
				Reason       string        `json:"reason"`
				Life         api.ID        `json:"life_id"`
				Lease        api.ID        `json:"lease_id"`
				RequestLife  api.ID        `json:"request_life_id"`
				RequestLease api.ID        `json:"request_lease_id"`
				UID          uint32        `json:"uid"`
				PID          int           `json:"pid"`
				TID          int           `json:"tid"`
				Start        string        `json:"start_time"`
				Nonce        api.ID        `json:"helper_nonce"`
				Run          api.RunNumber `json:"run"`
				Launch       api.ID        `json:"launch_id"`
				Caller       int           `json:"caller_pid"`
			}
			if err := json.Unmarshal(journal.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry.Life != test.wantLife || entry.Lease != test.wantLease ||
				entry.RequestLife != test.requestLife || entry.RequestLease != test.requestLease {
				t.Fatalf("journal lost owner or request IDs: %s", journal.Bytes())
			}
			if entry.Event != "helper_request" || entry.Method != trace.method ||
				entry.Code != api.CodeContainmentUnknown || entry.Reason != test.reason ||
				entry.Nonce != trace.nonce || entry.Run != trace.run ||
				entry.Launch != trace.launch || entry.Caller != trace.caller {
				t.Fatalf("journal lost request correlation: %s", journal.Bytes())
			}
			if test.reason == "uid_survivor" {
				if entry.UID != test.match.UID || entry.PID != test.match.PID ||
					entry.TID != test.match.TID || entry.Start != test.match.Start {
					t.Fatalf("journal lost measured process: %s", journal.Bytes())
				}
			} else if entry.UID != 0 || entry.PID != 0 || entry.TID != 0 || entry.Start != "" {
				t.Fatalf("unrelated refusal exposed a UID match: %s", journal.Bytes())
			}
			for _, field := range []string{"life_id", "lease_id"} {
				if bytes.Count(journal.Bytes(), []byte(`"`+field+`":`)) > 1 {
					t.Fatalf("journal repeated %s: %s", field, journal.Bytes())
				}
			}
			if trace.life != test.life || trace.lease != test.lease || trace.match != test.match {
				t.Fatal("journaling mutated the request trace")
			}
		})
	}
}

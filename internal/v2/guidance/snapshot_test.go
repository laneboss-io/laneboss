package guidance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func assertReceiptError(t *testing.T, err error, code api.ErrorCode, message string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code || typed.Owner != "lb-v2-guidance" || typed.Message != message {
		t.Fatalf("got %v, want typed %s at %s", err, code, message)
	}
}

func assertReceiptShape(t *testing.T, result api.Guidance, invalid bool) {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("receipt fixture could not be encoded: %v", err)
	}
	err = api.DecodeObject(raw, new(api.Guidance))
	if invalid {
		assertCode(t, err, api.CodeInvalid)
	} else if err != nil {
		t.Fatalf("semantic receipt fixture failed wire-shape preflight: %v", err)
	}
}

func TestSelectRetainedReplay(t *testing.T) {
	service, store, judge, scope, request, retained := retainedFixture(t)
	// A profile run can advance while retaining the same logical turn/input.
	store.lane.Run = 2
	request.Target.Run = 2
	scope = scopeForGuidance(t, scope, request)
	actual, err := service.GuidanceSelect(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(actual, retained) {
		t.Fatalf("retained selection changed on continuation: %v", err)
	}
	if judge.fitCalls != 0 || judge.evalCalls != 0 || store.transactions != 1 ||
		len(store.lastTransaction.Events) != 0 || len(store.lastTransaction.Writes.Guidance) != 0 ||
		store.lastTransaction.Reply == nil || len(store.lastTransaction.Compare) != 1 ||
		store.lastTransaction.Compare[0].Kind != api.CompareGuidance {
		t.Fatal("replay judged again, rewrote selection or omitted its atomic RPC reply")
	}
	if err := api.ValidateTransactionShape(store.lastTransaction); err != nil {
		t.Fatalf("retained replay violates the draft.4 write catalog: %v", err)
	}
	// The newly sealed continuation reply must also replay under the same key.
	// Its selection still names the original run, as the claim requires.
	actual, err = service.GuidanceSelect(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(actual, retained) || store.transactions != 1 ||
		judge.fitCalls != 0 || judge.evalCalls != 0 || store.reserveCalls != 0 || store.events != 1 {
		t.Fatalf("exact continuation replay changed the original selection: %v", err)
	}
}

func TestSelectTaskIsRetained(t *testing.T) {
	service, store, judge, scope := serviceFixture(t)
	request := guidanceRequest()
	store.turn = &api.TurnSnapshot{Target: request.Target, LogicalTurnID: request.LogicalTurnID,
		Task: request.Task, Generation: 1, PolicyGeneration: 3}
	store.turn.Task.ID = "other-visible-task"
	_, err := service.GuidanceSelect(context.Background(), scope, request)
	assertCode(t, err, api.CodeConflict)
	assertReceiptError(t, err, api.CodeConflict, "guidance task does not match the authoritative logical turn")
	if judge.fitCalls != 0 || store.transactions != 0 {
		t.Fatal("alternative task reached inference or persistence")
	}
}

func TestExactReceiptTarget(t *testing.T) {
	for _, defect := range []string{"foreign-life", "zero-run", "future-run"} {
		t.Run(defect, func(t *testing.T) {
			service, store, judge, scope, request, retained := retainedFixture(t)
			actual, err := service.GuidanceSelect(context.Background(), scope, request)
			if err != nil || !reflect.DeepEqual(actual, retained) {
				t.Fatalf("valid exact target fixture could not replay: %v", err)
			}
			key := claimReceiptKey{scope.Config, scope.Actor, requestKey(scope)}
			receipt := store.receipts[key]
			switch defect {
			case "foreign-life":
				retained.Target.LifeID = "other-life"
			case "zero-run":
				retained.Target.Run = 0
			case "future-run":
				retained.Target.Run++
			}
			raw, err := json.Marshal(retained)
			if err != nil {
				t.Fatal(err)
			}
			receipt.Reply = &api.RPCReply{Result: raw}
			store.receipts[key] = receipt
			resetReplayObservations(store, judge)
			_, err = service.GuidanceSelect(context.Background(), scope, request)
			assertReceiptError(t, err, api.CodeIntegrity, "guidance exact receipt differs from its authenticated request")
			if store.reservationCalls != 0 || store.transactions != 0 || store.reserveCalls != 0 || judge.fitCalls != 0 || judge.evalCalls != 0 {
				t.Fatal("foreign or future exact receipt reached retained selection or evaluation")
			}
		})
	}
}

func TestPendingDoesNotRejudge(t *testing.T) {
	service, store, judge, scope, request, retained := pendingFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type reply struct {
		result api.Guidance
		err    error
	}
	finished := make(chan reply, 1)
	go func() {
		result, err := service.GuidanceSelect(ctx, scope, request)
		finished <- reply{result, err}
	}()
	select {
	case <-store.awaitEntered:
	case <-finished:
		t.Fatal("pending observation bypassed retained await")
	case <-ctx.Done():
		t.Fatal("pending fixture did not enter await before its test deadline")
	}
	select {
	case <-finished:
		t.Fatal("pending observation returned before its owner completed")
	default:
	}
	completeFixtureClaim(t, store, retained)
	select {
	case actual := <-finished:
		if actual.err != nil || !reflect.DeepEqual(actual.result, retained) {
			t.Fatalf("pending observer lost the original completed result: %v", actual.err)
		}
	case <-ctx.Done():
		t.Fatal("pending observer did not return its owner's completion")
	}
	if store.awaitCalls != 1 || len(store.awaitRequests) != 1 ||
		store.awaitRequests[0] != (api.GuidanceAwaitRequest{ReservationID: store.r.ID, Deadline: store.r.Deadline}) {
		t.Fatal("pending observer changed its original await selector or deadline")
	}
	if judge.fitCalls != 0 || judge.evalCalls != 0 || store.reserveCalls != 0 ||
		store.commits != 1 || store.events != 1 || store.transactions != 2 {
		t.Fatal("pending claim was treated as a new winning selection")
	}
}

func TestReplayRejectsCorruption(t *testing.T) {
	changes := map[string]func(*api.Guidance){
		"task":        func(result *api.Guidance) { result.Task.ID = "other-task" },
		"policy":      func(result *api.Guidance) { result.PolicyGeneration++ },
		"snapshot":    func(result *api.Guidance) { result.CandidateSnapshotID = "other-snapshot" },
		"reservation": func(result *api.Guidance) { result.ReservationID = "other-reservation" },
		"fake-zero":   func(result *api.Guidance) { result.Status = "unavailable"; result.Notice = "fixture outage" },
		"status":      func(result *api.Guidance) { result.Status = "pending" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, request, result := retainedFixture(t)
			change(&result)
			assertReceiptShape(t, result, false)
			store.r.Result = &result
			_, err := service.GuidanceSelect(context.Background(), scope, request)
			message := "retained guidance receipt does not match its reservation"
			switch name {
			case "fake-zero":
				message = "retained unavailable guidance was changed into a score"
			case "status":
				message = "retained guidance has an unknown status"
			}
			assertReceiptError(t, err, api.CodeIntegrity, message)
			if store.transactions != 0 {
				t.Fatal("corrupted retained guidance was sealed as a new reply")
			}
		})
	}
}

func TestReplayClaimContract(t *testing.T) {
	for _, state := range []string{"pending", "completed", "exact"} {
		for _, row := range []struct {
			name   string
			change func(*api.GuidanceReservation)
		}{
			{"owner-attempt", func(r *api.GuidanceReservation) { r.OwnerAttemptID = "" }},
			{"owner-operation", func(r *api.GuidanceReservation) { r.OwnerOperationID = "" }},
			{"owner-request", func(r *api.GuidanceReservation) { r.OwnerRequestID = "" }},
			{"owner-key", func(r *api.GuidanceReservation) { r.OwnerKey = api.RequestKey{} }},
			{"requester", func(r *api.GuidanceReservation) { r.RequestedBy.ID = "" }},
			{"deadline", func(r *api.GuidanceReservation) { r.Deadline = "" }},
			{"deadline-reset", func(r *api.GuidanceReservation) {
				r.Deadline = api.Timestamp(testTime().Add(6 * time.Second).Format(time.RFC3339Nano))
			}},
			{"budget", func(r *api.GuidanceReservation) { r.MaxCostMicros = 0 }},
		} {
			t.Run(state+"/"+row.name, func(t *testing.T) {
				service, store, judge, scope, request, result := pendingFixture(t)
				if state != "pending" {
					completeFixtureClaim(t, store, result)
				}
				if state == "exact" {
					actual, err := service.GuidanceSelect(context.Background(), scope, request)
					if err != nil || !reflect.DeepEqual(actual, result) {
						t.Fatalf("valid exact claim setup could not replay: %v", err)
					}
				}
				resetReplayObservations(store, judge)
				// Only negative projections are corrupted after valid reservation
				// and completion. No incomplete claim is used as positive setup.
				row.change(store.r)
				_, err := service.GuidanceSelect(context.Background(), scope, request)
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-integrate" ||
					typed.Message != "guidance claim lacks its retained owner and total deadline" {
					t.Fatalf("retained claim owner or deadline was accepted: %v", err)
				}
				if store.transactions != 0 || store.reserveCalls != 0 || store.awaitCalls != 0 || judge.fitCalls != 0 || judge.evalCalls != 0 {
					t.Fatal("invalid retained owner/deadline reached reply, reservation, await or evaluation")
				}
			})
		}
	}
}

func TestReplayPolicyGeneration(t *testing.T) {
	for _, defect := range []string{"turn", "zero-turn", "scope", "reservation"} {
		t.Run(defect, func(t *testing.T) {
			service, store, judge, scope, request, retained := retainedFixture(t)
			switch defect {
			case "turn":
				current, _ := store.Policy(context.Background(), scope)
				current.Generation, scope.PolicyGeneration = 4, 4
				store.policy = current
			case "zero-turn":
				store.turn.PolicyGeneration = 0
			case "scope":
				current, _ := store.Policy(context.Background(), scope)
				current.Generation, scope.PolicyGeneration = 4, 4
				store.policy = current
			case "reservation":
				store.r.PolicyGeneration--
				store.r.Result.PolicyGeneration = store.r.PolicyGeneration
			}
			actual, err := service.GuidanceSelect(context.Background(), scope, request)
			if defect == "turn" || defect == "scope" {
				if err != nil || !reflect.DeepEqual(actual, retained) || judge.evalCalls != 0 || store.reserveCalls != 0 || store.candidateCalls != 0 {
					t.Fatalf("D6 policy advance changed or blocked retained guidance: %v", err)
				}
				return
			}
			if store.transactions != 0 || store.historyReads != 0 {
				t.Fatal("policy mismatch reached retained replay before generation validation")
			}
			assertReceiptError(t, err, api.CodeIntegrity, "guidance reservation does not match the retained turn input")
		})
	}
}

func TestReplayJudgmentProvenance(t *testing.T) {
	for _, row := range []struct {
		name, message        string
		scored, invalidShape bool
		change               func(*api.Guidance)
	}{
		{"scored-missing", "retained guidance status differs from its judgment provenance", true, false,
			func(result *api.Guidance) { result.JudgmentIDs = []api.ID{} }},
		{"scored-null", "retained guidance receipt does not match its reservation", true, true,
			func(result *api.Guidance) { result.JudgmentIDs = nil }},
		{"scored-duplicate", "retained guidance contains invalid judgment provenance", true, false,
			func(result *api.Guidance) { result.JudgmentIDs = []api.ID{"judge-a", "judge-a"} }},
		{"scored-invalid", "retained guidance contains invalid judgment provenance", true, false,
			func(result *api.Guidance) { result.JudgmentIDs = []api.ID{"invalid/id"} }},
		{"aggregate-invalid", "retained guidance status differs from its judgment provenance", true, false,
			func(result *api.Guidance) { result.JudgmentID = "invalid/id" }},
		{"empty-ids", "retained guidance status differs from its judgment provenance", false, false,
			func(result *api.Guidance) { result.JudgmentIDs = []api.ID{"judge-a"} }},
		{"empty-aggregate", "retained guidance status differs from its judgment provenance", false, false,
			func(result *api.Guidance) { result.JudgmentID = "judge-a" }},
		{"clock", "retained guidance receipt has an invalid clock", false, false,
			func(result *api.Guidance) { result.AsOf = "2026-10-01T12:00:00+00:00" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			candidates := []api.DecisionCandidate{}
			if row.scored {
				candidates = append(candidates, candidate("history", testTime(), false))
			}
			service, store, judge, scope, request, result := retainedFixture(t, candidates...)
			assertReceiptShape(t, result, false)
			baseline, err := service.completedSelection(context.Background(), scope, request, 3)
			if err != nil || baseline == nil || !reflect.DeepEqual(*baseline, result) {
				t.Fatalf("uncorrupted receipt fixture could not replay: %v", err)
			}
			row.change(&result)
			// Empty [] is valid wire shape; null exercises the earlier decoder
			// separately and must not masquerade as the semantic guard case.
			assertReceiptShape(t, result, row.invalidShape)
			store.r.Result = &result
			_, err = service.GuidanceSelect(context.Background(), scope, request)
			assertReceiptError(t, err, api.CodeIntegrity, row.message)
			if store.transactions != 0 || judge.fitCalls != 0 || judge.evalCalls != 0 {
				t.Fatal("invalid judgment provenance was sealed or rejudged")
			}
		})
	}
}

func humanCandidate(id string, binding bool) api.DecisionCandidate {
	item := candidate(id, testTime(), binding)
	item.Source.ID, item.Source.Path = item.ID, ""
	item.Authority.Kind, item.Authority.OrgGeneration = "human", 0
	return item
}

func TestHumanDecisionProvenance(t *testing.T) {
	for _, binding := range []bool{false, true} {
		t.Run(map[bool]string{false: "reminder", true: "binding"}[binding], func(t *testing.T) {
			service, store, _, scope := serviceFixture(t)
			item := humanCandidate("human-decision", binding)
			store.decisions = map[api.ID]api.DecisionProjection{item.ID: {RecordID: item.ID, Candidate: item, Status: "active"}}
			store.pages = func(query api.DecisionQuery) (api.DecisionPage, error) {
				items := []api.DecisionCandidate{}
				if (query.Kind == "binding") == binding {
					items = append(items, item)
				}
				return api.DecisionPage{SnapshotID: "snapshot-a", PolicyGeneration: 3,
					AsOf: api.Timestamp(testTime().Format(time.RFC3339Nano)), Candidates: items, Complete: true}, nil
			}
			all, _, err := service.candidateSnapshot(context.Background(), scope, guidanceRequest().Target, 3)
			if err != nil || len(all) != 1 || !reflect.DeepEqual(all[0], item) || store.decisionCalls != 1 || store.sourceCalls != 0 {
				t.Fatalf("pathless human decision did not resolve through its canonical projection: %v", err)
			}
			projection := store.decisions[item.ID]
			projection.Candidate.Authority.ReceiptID = "other-receipt"
			store.decisions[item.ID] = projection
			_, _, err = service.candidateSnapshot(context.Background(), scope, guidanceRequest().Target, 3)
			assertReceiptError(t, err, api.CodeIntegrity, "human decision differs from its retained canonical projection")
		})
	}
}

func TestHumanReceiptPathless(t *testing.T) {
	item := humanCandidate("human-binding", true)
	service, _, _, scope, request, result := retainedFixture(t, item)
	actual, err := service.GuidanceSelect(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(actual, result) {
		t.Fatalf("pathless human receipt could not replay: %v", err)
	}
}

func TestCandidateAuthorityKinds(t *testing.T) {
	for _, defect := range []string{"proposal", "lane", "d6-zero", "human-org", "human-source", "human-path", "missing-seq", "clock"} {
		t.Run(defect, func(t *testing.T) {
			service, store, _, scope := serviceFixture(t)
			item := candidate("decision-a", testTime(), false)
			asOf := api.Timestamp(testTime().Format(time.RFC3339Nano))
			switch defect {
			case "proposal", "lane":
				item.Authority.Kind = defect
			case "d6-zero":
				item.Authority.OrgGeneration = 0
			case "human-org":
				item = humanCandidate("decision-a", false)
				item.Authority.OrgGeneration = 2
			case "human-source":
				item = humanCandidate("decision-a", false)
				item.Source.ID = "other-source"
			case "human-path":
				item = humanCandidate("decision-a", false)
				item.Source.Path = "org/decisions.md"
			case "missing-seq":
				item.Authority.SourceSeq = 0
			case "clock":
				asOf = "2026-10-01T12:00:00+00:00"
			}
			store.pages = func(query api.DecisionQuery) (api.DecisionPage, error) {
				items := []api.DecisionCandidate{}
				if query.Kind == "reminder" {
					items = append(items, item)
				}
				return api.DecisionPage{SnapshotID: "snapshot-a", PolicyGeneration: 3, AsOf: asOf, Candidates: items, Complete: true}, nil
			}
			_, _, err := service.candidateSnapshot(context.Background(), scope, guidanceRequest().Target, 3)
			message := "candidate backend lost authority, identity or binding provenance"
			if defect == "clock" {
				message = "candidate snapshot has no valid clock"
			}
			assertReceiptError(t, err, api.CodeIntegrity, message)
			if store.decisionCalls != 0 || store.sourceCalls != 0 {
				t.Fatal("invalid candidate authority reached provenance reads")
			}
		})
	}
}

func TestCandidatePagesComplete(t *testing.T) {
	service, store, _, scope := serviceFixture(t)
	var queries []api.DecisionQuery
	store.pages = func(query api.DecisionQuery) (api.DecisionPage, error) {
		queries = append(queries, query)
		page := api.DecisionPage{SnapshotID: "snapshot-a", PolicyGeneration: 3,
			AsOf: api.Timestamp(testTime().Format(time.RFC3339Nano)), Candidates: []api.DecisionCandidate{}, Complete: true}
		switch {
		case query.Kind == "binding":
			page.Candidates = []api.DecisionCandidate{candidate("binding", testTime().AddDate(-90, 0, 0), true)}
		case query.Cursor == "":
			page.Candidates = []api.DecisionCandidate{candidate("first", testTime(), false)}
			page.Complete, page.Cursor = false, "next-page"
		default:
			page.Candidates = []api.DecisionCandidate{candidate("last", testTime(), false)}
		}
		return page, nil
	}
	all, snapshot, err := service.candidateSnapshot(context.Background(), scope, guidanceRequest().Target, 3)
	if err != nil || snapshot != "snapshot-a" || len(all) != 3 || all[2].ID != "last" ||
		len(queries) != 3 || queries[1].SnapshotID != snapshot || queries[2].Cursor != "next-page" {
		t.Fatalf("candidate retrieval lost a page, binding source or immutable snapshot: %v", err)
	}
}

func TestCandidatePageFailures(t *testing.T) {
	for _, defect := range []string{"incomplete", "repeated", "snapshot", "policy", "binding", "authority"} {
		t.Run(defect, func(t *testing.T) {
			service, store, _, scope := serviceFixture(t)
			calls := 0
			store.pages = func(query api.DecisionQuery) (api.DecisionPage, error) {
				calls++
				page := api.DecisionPage{SnapshotID: "snapshot-a", PolicyGeneration: 3,
					AsOf: api.Timestamp(testTime().Format(time.RFC3339Nano)), Candidates: []api.DecisionCandidate{}, Complete: true}
				switch defect {
				case "incomplete":
					page.Complete = false
				case "repeated":
					page.Complete, page.Cursor = false, "same-page"
				case "snapshot":
					if calls > 1 {
						page.SnapshotID = "other-snapshot"
					}
				case "policy":
					page.PolicyGeneration++
				case "binding":
					page.Candidates = []api.DecisionCandidate{candidate("reminder", testTime(), false)}
				case "authority":
					item := candidate("binding", testTime(), true)
					item.Authority.ReceiptID = ""
					page.Candidates = []api.DecisionCandidate{item}
				}
				return page, nil
			}
			_, _, err := service.candidateSnapshot(context.Background(), scope, guidanceRequest().Target, 3)
			if defect == "snapshot" {
				assertReceiptError(t, err, api.CodeIntegrity, "candidate backend mixed immutable snapshots")
			} else {
				assertCode(t, err, api.CodeIntegrity)
			}
		})
	}
}

func TestTaskObjectBytes(t *testing.T) {
	service, store, _, scope := serviceFixture(t)
	store.data = bytes.Repeat([]byte("complete task data\n"), api.MaxChunkBytes/8)
	ref := api.BlobRef{ID: "task-large", Class: "task", Bytes: int64(len(store.data)), SHA256: digestBytes(store.data)}
	store.metadata = &api.ObjectMetadata{Ref: ref}
	actual, err := service.taskBytes(context.Background(), scope, ref)
	if err != nil || !bytes.Equal(actual, store.data) {
		t.Fatalf("task bytes were truncated or changed: %v", err)
	}
	ref.Bytes--
	ref.SHA256 = digestBytes(store.data[:ref.Bytes])
	store.metadata.Ref = ref
	_, err = service.taskBytes(context.Background(), scope, ref)
	assertCode(t, err, api.CodeIntegrity)
}

func TestRankApprovedCutoff(t *testing.T) {
	now := testTime()
	inputs := []api.DecisionCandidate{candidate("lower", now, false), candidate("higher", now, false)}
	reply := scored(answer("lower", .6), answer("higher", .9))
	strict, err := rankWithCutoff(now, 0, .8, inputs, reply)
	if err != nil || len(strict.Items) != 1 || strict.Items[0].DecisionID != "higher" {
		t.Fatalf("approved cutoff was ignored: %v", err)
	}
	defaults, err := rankWithCutoff(now, 0, 0, inputs, scored(answer("lower", .01), answer("higher", .9)))
	if err != nil || defaults.Status != "scored" || len(defaults.Items) != 1 || defaults.Items[0].DecisionID != "higher" ||
		defaults.WeightedScore == nil || *defaults.WeightedScore != .9 {
		t.Fatalf("zero policy cutoff did not use the 0.50 default: %v", err)
	}
}

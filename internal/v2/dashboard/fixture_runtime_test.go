package dashboard

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This models connection/session/CAS behavior for projection tests. It has no
// native peer or cryptographic verifier and is not installed-service evidence.
type fixtureConnection struct {
	mu        sync.Mutex
	id        api.ID
	config    string
	principal api.ID
	authority api.ReadAuthority
	closed    bool
}

func (c *fixtureConnection) ID() api.ID   { return c.id }
func (*fixtureConnection) Conn() net.Conn { return nil }
func (c *fixtureConnection) Binding() api.InstalledBinding {
	return api.InstalledBinding{Config: c.config, Class: api.EndpointHuman, EndpointGeneration: 1}
}
func (*fixtureConnection) BindPeer(api.VerifiedPeer) error {
	return api.NotImplemented("lb-v2-identity", "fixture native peer")
}
func (*fixtureConnection) Peer() api.VerifiedPeer { return nil }
func (c *fixtureConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *fixtureConnection) BindReadAuthority(a api.ReadAuthority) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.authority.SessionID != "" || a.ConnectionID != c.id || a.PrincipalID != c.principal {
		return unauthErr("fixture connection cannot bind this session", "Authenticate.")
	}
	c.authority = a
	return nil
}
func (c *fixtureConnection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.authority.SessionID == "" {
		return api.ReadAuthority{}, unauthErr("fixture connection is closed or unbound", "Authenticate.")
	}
	return c.authority, nil
}
func (c *fixtureConnection) RefreshReadAuthority(_ context.Context, u api.ReadAuthorityUpdate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return unauthErr("fixture connection closed", "Authenticate.")
	}
	if err := api.ValidateReadAuthorityUpdate(c.authority, u); err != nil {
		return err
	}
	c.authority = u.After
	return nil
}

type fixtureFrame []byte

func (f fixtureFrame) Bytes() []byte { return append([]byte(nil), f...) }
func (f fixtureFrame) Verify(ctx context.Context, c api.ConnectionContext) error {
	if c == nil {
		return unauthErr("fixture frame lacks a connection", "Authenticate.")
	}
	_, err := c.ReadAuthority(ctx)
	return err
}

func fixtureRequestScope(scope api.Scope, req api.Request) api.Scope {
	raw, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}
	scope.Request, scope.Frame, scope.ReadAuthority = req, fixtureFrame(raw), nil
	return scope
}

func fixtureEventScope(t *testing.T, scope api.Scope, tail api.EventTailRequest) api.Scope {
	t.Helper()
	req, _, err := newReadRequest(scope.Config, "event.tail", tail)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureRequestScope(scope, req)
}

func (m *memHarness) newFixtureScope(config string) api.Scope {
	m.mu.Lock()
	m.seqCounter++
	id := api.ID("conn-" + stringID(m.seqCounter))
	m.mu.Unlock()
	c := &fixtureConnection{id: id, config: config, principal: api.ID("human-" + string(id))}
	m.mu.Lock()
	if m.httpConnections == nil {
		m.httpConnections = make(map[api.ID]*fixtureConnection)
	}
	m.httpConnections[id] = c
	m.mu.Unlock()
	return api.Scope{Config: config, Source: "dashboard", Actor: api.Actor{Kind: "human", ID: c.principal},
		Connection: c, EndpointGeneration: 1, PolicyGeneration: 1}
}

func stringID(n int) string {
	const digits = "0123456789"
	if n < 10 {
		return string(digits[n])
	}
	return stringID(n/10) + string(digits[n%10])
}

func (m *memHarness) putDecisionDocument(t *testing.T, id api.ID, text string, at api.Timestamp, binding bool) api.BlobRef {
	t.Helper()
	doc := api.DecisionDocument{Schema: "laneboss.decision.v2", Text: text, EffectiveAt: at, Binding: binding,
		AppliesTo: api.DecisionApplicability{Levels: []int{}, Roles: []string{}, ProjectIDs: []api.ID{}, LifeIDs: []api.ID{}}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return m.putBlob(id, "record", raw)
}

func (m *memHarness) authorizeFixture(ctx context.Context, scope api.Scope, req api.Request) error {
	return m.checkFixtureScope(ctx, scope, req, true)
}

func (m *memHarness) checkFixtureScope(ctx context.Context, scope api.Scope, req api.Request, refresh bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failIdentity != nil {
		return m.failIdentity
	}
	if m.policy != nil && scope.PolicyGeneration != m.policy.Generation {
		return conflictErr("fixture connection policy changed", "Reload current policy authority.")
	}
	if scope.Connection == nil || scope.Actor.Kind != "human" {
		return unauthErr("missing fixture connection", "Authenticate.")
	}
	if scope.Connection.Binding().Config != scope.Config {
		return forbiddenErr("fixture config mismatch", "Use bound config.")
	}
	a, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return err
	}
	before, ok := m.readSessions[a.SessionID]
	if !ok || m.identityRevoked[a.SessionID] || before.Revoked || a != api.ReadAuthorityFromSession(before) ||
		a.PrincipalID != scope.Actor.ID || a.ConnectionID != scope.Connection.ID() ||
		scope.ReadAuthority != nil && *scope.ReadAuthority != a {
		return unauthErr("fixture session is foreign or revoked", "Authenticate.")
	}
	if scope.Frame == nil {
		return unauthErr("missing fixture frame", "Authenticate.")
	}
	var framed api.Request
	if api.DecodeObject(scope.Frame.Bytes(), &framed) != nil || !reflect.DeepEqual(framed, req) {
		return unauthErr("fixture frame differs from request", "Use exact request.")
	}
	if !refresh {
		idle, idleErr := parseTimestamp(before.Session.IdleExpiresAt)
		absolute, absErr := parseTimestamp(before.Session.ExpiresAt)
		if idleErr != nil || absErr != nil || !m.clock.Now().Before(idle) || !m.clock.Now().Before(absolute) {
			return unauthErr("fixture session expired", "Authenticate.")
		}
		return nil
	}
	after := before
	now := m.clock.Now()
	deadline := now.Add(5 * time.Minute)
	absolute, err := parseTimestamp(before.Session.ExpiresAt)
	if err != nil {
		return err
	}
	if absolute.Before(deadline) {
		deadline = absolute
	}
	after.Generation++
	after.Session.IdleExpiresAt = api.Timestamp(deadline.Format(time.RFC3339Nano))
	if err := api.ValidateReadSessionRefresh(scope, before, after, now); err != nil {
		return unauthErr("fixture session expired", "Authenticate.")
	}
	if err := scope.Connection.(api.ReadAuthorityRefresher).RefreshReadAuthority(ctx,
		api.ReadAuthorityUpdate{Before: a, After: api.ReadAuthorityFromSession(after)}); err != nil {
		return err
	}
	m.readSessions[a.SessionID] = after
	if scope.ReadAuthority != nil {
		*scope.ReadAuthority = api.ReadAuthorityFromSession(after)
	}
	return nil
}

func (m *memHarness) consumeFixtureProof(ctx context.Context, scope api.Scope) error {
	target, err := m.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return err
	}
	if scope.Request.Proof == nil {
		return forbiddenErr("fixture proof missing", "Confirm operation.")
	}
	proof, err := m.CheckProof(ctx, scope, *scope.Request.Proof, target)
	if err != nil {
		return err
	}
	expiry, err := parseTimestamp(proof.Ref.ExpiresAt)
	if err != nil || !m.clock.Now().Before(expiry) {
		return forbiddenErr("fixture proof expired", "Confirm operation.")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumed[proof.Ref.ID] {
		return forbiddenErr("fixture proof consumed", "Confirm operation.")
	}
	if scope.Request.Method == "lane.stop" || scope.Request.Method == "lane.resume" || scope.Request.Method == "lane.mark" {
		lane, exists := m.lanes[target.TargetID]
		if !exists || lane.Generation != target.BaseGeneration {
			return conflictErr("fixture lane generation changed", "Reload the lane.")
		}
	}
	m.consumed[proof.Ref.ID] = true
	return nil
}

func (m *memHarness) Scope(ctx context.Context, r *http.Request, req api.Request, raw []byte, claim *SessionClaim) (api.Scope, error) {
	var scope api.Scope
	if claim == nil {
		if _, err := r.Cookie(sessionCookieName); err == nil {
			return api.Scope{}, unauthErr("unresolved fixture cookie reached bootstrap", "Clear the stale session cookie.")
		}
	}
	if claim != nil {
		m.mu.Lock()
		c := m.httpConnections[claim.ConnectionID]
		stored, exists := m.readSessions[claim.SessionID]
		m.mu.Unlock()
		if c == nil || !exists || stored.ConnectionID != c.ID() || stored.PrincipalID != claim.Actor.ID || claim.EndpointGeneration != 1 {
			return api.Scope{}, unauthErr("unknown fixture session claim", "Authenticate.")
		}
		scope = api.Scope{Config: c.config, Source: "dashboard", Actor: claim.Actor,
			Connection: c, EndpointGeneration: claim.EndpointGeneration, PolicyGeneration: 1}
	} else {
		m.mu.Lock()
		c := m.httpConnection
		m.mu.Unlock()
		var challenge api.HumanChallengeRequest
		if c != nil && req.Method == "human.challenge" && api.DecodeObject(req.Params, &challenge) == nil && challenge.Method == "human.session" {
			if authority, err := c.ReadAuthority(ctx); err == nil && authority.SessionID != "" {
				c = nil
			}
		}
		if c == nil {
			scope = m.newFixtureScope(req.Config)
			c = scope.Connection.(*fixtureConnection)
			m.mu.Lock()
			m.httpConnection = c
			m.mu.Unlock()
		}
		scope = api.Scope{Config: c.config, Source: "dashboard", Actor: api.Actor{Kind: "human", ID: c.principal},
			Connection: c, EndpointGeneration: 1, PolicyGeneration: 1}
	}
	m.mu.Lock()
	if m.policy != nil {
		scope.PolicyGeneration = m.policy.Generation
	}
	m.mu.Unlock()
	scope.Request, scope.Frame, scope.ReadAuthority = req, fixtureFrame(append([]byte(nil), raw...)), nil
	return scope, nil
}

func (m *memHarness) ReplayCompleted(ctx context.Context, scope api.Scope, req api.Request) (api.Response, error) {
	m.dispatchMu.Lock()
	defer m.dispatchMu.Unlock()
	if err := m.checkFixtureScope(ctx, scope, req, false); err != nil {
		return api.Response{}, err
	}
	domain := scope.Config + "|" + string(scope.Actor.ID) + "|" + string(req.Method) + "|" + string(req.IdempotencyKey)
	previous, ok := m.fixtureReceipts[domain]
	if !ok {
		return api.Response{}, forbiddenErr("human proof expired without completed receipt", "Confirm operation.")
	}
	if previous.requestSHA256 != req.RequestSHA256 {
		return api.Response{}, &api.Error{Code: api.CodeIdempotencyConflict}
	}
	response := previous.response
	response.RequestID = req.RequestID
	return response, nil
}

func (m *memHarness) Dispatch(ctx context.Context, scope api.Scope, req api.Request) (api.Response, error) {
	m.dispatchMu.Lock()
	defer m.dispatchMu.Unlock()
	staging := req.Method == "human.challenge" || req.Method == "human.confirm" || req.Method == "human.session"
	if !staging {
		if err := m.authorizeFixture(ctx, scope, req); err != nil {
			return api.Response{}, err
		}
	}
	domain := scope.Config + "|" + string(scope.Actor.ID) + "|" + string(req.Method) + "|" + string(req.IdempotencyKey)
	if previous, ok := m.fixtureReceipts[domain]; ok {
		if previous.requestSHA256 != req.RequestSHA256 {
			return api.Response{}, &api.Error{Code: api.CodeIdempotencyConflict}
		}
		response := previous.response
		response.RequestID = req.RequestID
		return response, nil
	}
	var value any
	var seq api.Sequence
	var err error
	switch req.Method {
	case "human.challenge":
		var input api.HumanChallengeRequest
		err = api.DecodeObject(req.Params, &input)
		if err == nil {
			value, err = m.issueChallenge(ctx, scope, input)
		}
	case "human.confirm":
		var input api.HumanConfirmRequest
		err = api.DecodeObject(req.Params, &input)
		if err == nil {
			value, err = m.Confirm(ctx, scope, input)
		}
	case "human.session":
		var input api.HumanSessionRequest
		err = api.DecodeObject(req.Params, &input)
		if err == nil {
			value, err = m.HumanSession(ctx, scope, input)
		}
	case "event.tail":
		var input api.EventTailRequest
		err = api.DecodeObject(req.Params, &input)
		if err == nil {
			value, err = m.EventTail(ctx, scope, input)
		}
	default:
		if api.Methods[req.Method].Mutation {
			value, seq, err = m.dashboard.dispatchMutationRPC(ctx, scope, req)
		} else {
			value, err = m.dashboard.dispatchReadRPC(ctx, scope, req.Method, req.Params)
		}
	}
	if err != nil {
		return api.Response{}, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return api.Response{}, err
	}
	response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: req.RequestID, Result: raw, LastSeq: seq}
	if api.Methods[req.Method].Mutation {
		m.fixtureReceipts[domain] = idempotencyRecord{requestSHA256: req.RequestSHA256, response: response}
	}
	return response, nil
}

func (m *memHarness) PollEvents(ctx context.Context, scope api.Scope, tail api.EventTailRequest) (api.EventPage, error) {
	m.dispatchMu.Lock()
	defer m.dispatchMu.Unlock()
	if scope.Request.Method != "event.tail" || scope.Request.Proof != nil || tail.Follow || tail.Cursor != "" {
		return api.EventPage{}, invalidErr("invalid fixture liveness request", "Use a bounded event poll.")
	}
	var framed api.EventTailRequest
	if err := api.DecodeObject(scope.Request.Params, &framed); err != nil {
		return api.EventPage{}, err
	}
	if framed != tail {
		return api.EventPage{}, invalidErr("liveness params differ from frame", "Use exact event filters.")
	}
	if err := m.checkFixtureScope(ctx, scope, scope.Request, false); err != nil {
		return api.EventPage{}, err
	}
	return m.Events(ctx, scope, tail)
}

var _ HumanTransport = (*memHarness)(nil)
var _ HumanLivenessTransport = (*memHarness)(nil)
var _ api.ReadAuthorityRefresher = (*fixtureConnection)(nil)

func (m *memHarness) fixtureReview(t *testing.T, sessionID api.ID, lane api.Lane, diff api.BlobRef) api.ReviewReceipt {
	t.Helper()
	stored, exists := m.readSessions[sessionID]
	if !exists || stored.Revoked || stored.PrincipalID == "" || m.reviewResume == nil ||
		m.reviewResume.Scope.Connection == nil ||
		m.reviewResume.Scope.Actor != (api.Actor{Kind: "human", ID: stored.PrincipalID}) ||
		m.reviewResume.Scope.Connection.ID() != stored.ConnectionID {
		t.Fatal("fixture review lacks the authenticated resume session")
	}
	launch := m.fixtureRetainReviewLaunch(t, lane)
	plan := launch.Record.Plan
	zero, survivors := 0, uint64(0)
	end := api.RunEndEvent{LaunchID: plan.Reservation.LaunchID, Reason: "exit",
		Observation: api.ProcessObservation{Handle: api.ProcessHandle{ID: "fixture-process", Target: plan.Reservation.Target,
			ContainmentID: plan.Lease.ContainmentID, Generation: launch.Binding.Prepared.ProcessGeneration},
			State: "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed",
			ObservedAt: api.Timestamp(m.clock.Now().UTC().Format(time.RFC3339Nano))}}
	endBytes, err := json.Marshal(end)
	if err != nil {
		t.Fatal(err)
	}
	endID := api.ID("fixture-review-end")
	m.appendEvent(api.Event{Schema: 2, ID: endID, Config: launch.Record.Reservation.Config, Kind: "lane.ended",
		Origin: "service", LifeID: lane.LifeID, Run: lane.Run, Actor: launch.Record.Handoff.Cause.Actor,
		RequestedBy: plan.Reservation.RequestedBy, RequestID: plan.Reservation.RequestID,
		OperationID: plan.Reservation.OperationID, Payload: endBytes})
	endSeq := m.events[len(m.events)-1].Seq
	tools := m.putBlob("fixture-review-tools", "manifest", []byte(`{"records":[],"coverage":"complete"}`))
	subject := api.ReviewSubject{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, Generation: lane.Generation,
		LaunchID: plan.Reservation.LaunchID, EndEventID: endID, EndSeq: endSeq,
		Snapshot: plan.Data.Workspace.Snapshot, SessionID: plan.Runner.Session.ID, InventorySeq: endSeq, CaptureBindingID: plan.Capture.ID,
		Streams:    append([]api.CaptureStreamBinding{}, plan.Capture.Streams...),
		RefusalIDs: []api.ID{}}
	streamFacts := []api.ReviewStreamFact{}
	for _, stream := range subject.Streams {
		streamFacts = append(streamFacts, api.ReviewStreamFact{BindingID: subject.CaptureBindingID,
			StreamID: stream.ID, EOF: true, GapIDs: []api.ID{}})
	}
	inventory := m.fixtureReviewJSON(t, "fixture-review-inventory", "manifest", map[string]any{
		"schema": "fixture.review.inventory", "subject": subject, "tool_records": tools,
		"tool_coverage": api.CoverageComplete, "streams": streamFacts})
	evidence := api.ReviewEvidence{Schema: "laneboss.review.v2", Subject: subject, VerifierLeaseID: "fixture-verifier",
		Diff: diff, Checks: []api.ReviewCheckFact{}, Resolutions: []api.ReviewResolution{}, Coverage: api.CoverageComplete,
		Inventory: api.ReviewInventory{Manifest: inventory, ThroughSeq: endSeq, ToolRecords: tools, ToolCoverage: api.CoverageComplete,
			Streams: streamFacts}}
	receipt := api.ReviewReceipt{ID: "fixture-review", Reviewer: api.Actor{Kind: "human", ID: stored.PrincipalID}, Diff: diff,
		RecordInventory: inventory, Checks: []api.BlobRef{}, RefusalResolution: []api.ID{}, Coverage: api.CoverageComplete, Evidence: &evidence}
	if err := api.ValidateReviewAcceptance(m.reviewResume.Scope, receipt, subject, nil); err != nil {
		t.Fatalf("fixture review acceptance: %v", err)
	}
	return receipt
}

// Caller holds m.mu. These are committed in-memory projection events, not
// claims that a native process was launched, stopped or measured.
func (m *memHarness) fixtureTransition(scope api.Scope, lane api.Lane, from string) (api.Operation, error) {
	m.seqCounter++
	seq := api.Sequence(len(m.events) + 1)
	lane.LastSeq = seq
	op := api.Operation{ID: api.ID("operation-" + stringID(m.seqCounter)), Status: "succeeded",
		LifeID: lane.LifeID, Run: lane.Run, FirstSeq: seq, LastSeq: seq,
		SimulatedPresence: scope.Request.Proof != nil && scope.Request.Proof.SimulatedPresence}
	payload, err := json.Marshal(api.StateEvent{From: from, To: lane.State, Generation: lane.Generation})
	if err != nil {
		return api.Operation{}, err
	}
	m.lanes[lane.LifeID] = lane
	m.events = append(m.events, api.Event{Schema: api.SchemaVersion, ID: api.ID("event-" + stringID(m.seqCounter)),
		Config: scope.Config, LifeID: lane.LifeID, Run: lane.Run, Kind: "lane.state", Seq: seq, Origin: "service",
		StarterChain: append([]api.ID{}, lane.StarterChain...),
		Actor:        scope.Actor, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID, OperationID: op.ID,
		RecordedAt: api.Timestamp(m.clock.Now().Format(time.RFC3339Nano)), Payload: payload})
	return op, nil
}

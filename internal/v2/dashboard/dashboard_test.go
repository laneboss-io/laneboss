package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type stubIdentity struct{}

func (stubIdentity) Authenticate(ctx context.Context, conn api.ConnectionContext) (api.Scope, error) {
	return api.Scope{}, api.NotImplemented("lb-v2-identity", "identity.Authenticate")
}
func (stubIdentity) Authorize(ctx context.Context, scope api.Scope, req api.Request) error {
	return api.NotImplemented("lb-v2-identity", "identity.Authorize")
}
func (stubIdentity) BindLaunch(ctx context.Context, req api.LaunchBindingRequest) (api.LaunchPermit, error) {
	return api.LaunchPermit{}, api.NotImplemented("lb-v2-identity", "identity.BindLaunch")
}
func (stubIdentity) RevokeLaunch(ctx context.Context, launchID api.ID) error {
	return api.NotImplemented("lb-v2-identity", "identity.RevokeLaunch")
}
func (stubIdentity) Challenge(ctx context.Context, scope api.Scope, req api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return api.HumanChallenge{}, api.NotImplemented("lb-v2-identity", "identity.Challenge")
}
func (stubIdentity) Confirm(ctx context.Context, scope api.Scope, req api.HumanConfirmRequest) (api.ProofRef, error) {
	return api.ProofRef{}, api.NotImplemented("lb-v2-identity", "identity.Confirm")
}
func (stubIdentity) CheckProof(ctx context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	return api.VerifiedHumanProof{}, api.NotImplemented("lb-v2-identity", "identity.CheckProof")
}
func (stubIdentity) IdentitySelf(ctx context.Context, scope api.Scope, req api.Empty) (api.Scope, error) {
	return api.Scope{}, api.NotImplemented("lb-v2-identity", "identity.identity.self")
}
func (stubIdentity) HumanChallenge(ctx context.Context, scope api.Scope, req api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return api.HumanChallenge{}, api.NotImplemented("lb-v2-identity", "identity.human.challenge")
}
func (stubIdentity) HumanConfirm(ctx context.Context, scope api.Scope, req api.HumanConfirmRequest) (api.ProofRef, error) {
	return api.ProofRef{}, api.NotImplemented("lb-v2-identity", "identity.human.confirm")
}
func (stubIdentity) HumanSession(ctx context.Context, scope api.Scope, req api.HumanSessionRequest) (api.HumanSession, error) {
	return api.HumanSession{}, api.NotImplemented("lb-v2-identity", "identity.human.session")
}
func (stubIdentity) TicketIssue(ctx context.Context, scope api.Scope, req api.TicketIssueRequest) (api.Ticket, error) {
	return api.Ticket{}, api.NotImplemented("lb-v2-identity", "identity.ticket.issue")
}

type memHarness struct {
	dashboard       *Service
	dispatchMu      sync.Mutex
	readSessions    map[api.ID]api.StoredReadSession
	httpConnection  *fixtureConnection
	httpConnections map[api.ID]*fixtureConnection
	fixtureReceipts map[string]idempotencyRecord
	lastReadScope   api.Scope
	reviewResume    *fixtureReviewResume
	reviewLaunch    *fixtureReviewLaunch

	mu                  sync.Mutex
	clock               *fakeClock
	lanes               map[api.ID]api.Lane
	events              []api.Event
	records             map[string][]api.Record
	decisions           map[api.ID]api.DecisionProjection
	blobs               map[api.ID][]byte
	blobRefs            map[api.ID]api.BlobRef
	mails               []api.Mail
	policy              *api.EffectivePolicy
	changes             map[api.ID]api.ChangeRequest
	challenges          map[api.ID]api.HumanChallenge
	proofs              map[api.ID]api.HumanChallengeRequest
	proofPresence       map[api.ID]bool
	simulatedCredential bool
	consumed            map[api.ID]bool
	failStore           error
	failRecords         error
	failDecision        error
	stoppedLives        []api.ID
	resumedLives        []api.ID
	markedStates        map[api.ID]string
	sentMails           []api.Mail
	lastMutationAct     api.Actor
	lastMutationSrc     string
	seqCounter          int
	identitySessions    map[api.ID]api.HumanSession
	identityRevoked     map[api.ID]bool
	failIdentity        error
}

func newMemHarness() *memHarness {
	return &memHarness{
		readSessions:     make(map[api.ID]api.StoredReadSession),
		fixtureReceipts:  make(map[string]idempotencyRecord),
		clock:            &fakeClock{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)},
		lanes:            make(map[api.ID]api.Lane),
		records:          make(map[string][]api.Record),
		decisions:        make(map[api.ID]api.DecisionProjection),
		blobs:            make(map[api.ID][]byte),
		blobRefs:         make(map[api.ID]api.BlobRef),
		changes:          make(map[api.ID]api.ChangeRequest),
		challenges:       make(map[api.ID]api.HumanChallenge),
		proofs:           make(map[api.ID]api.HumanChallengeRequest),
		proofPresence:    make(map[api.ID]bool),
		consumed:         make(map[api.ID]bool),
		markedStates:     make(map[api.ID]string),
		identitySessions: make(map[api.ID]api.HumanSession),
		identityRevoked:  make(map[api.ID]bool),
	}
}

func (m *memHarness) revokeOnIdentitySide(sessionID api.ID) {
	m.mu.Lock()
	m.identityRevoked[sessionID] = true
	m.mu.Unlock()
}

func (m *memHarness) establishVerifiedScope(t *testing.T, svc *Service, config string) (api.Scope, api.HumanSession, string) {
	t.Helper()
	rawParams := json.RawMessage(`{}`)
	dig, err := RequestDigest(api.Protocol, api.SchemaVersion, config, "human.session", rawParams)
	if err != nil {
		t.Fatalf("RequestDigest failed: %v", err)
	}
	epScope := api.Scope{Source: "dashboard", Config: config, Actor: api.Actor{Kind: "human", ID: api.ID("endpoint-" + config)}}
	ch, err := m.issueChallenge(context.Background(), epScope, api.HumanChallengeRequest{
		Method:         "human.session",
		TargetID:       api.ID(config),
		RequestSHA256:  dig,
		BaseGeneration: 0,
	})
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	proof, err := m.Confirm(context.Background(), epScope, api.HumanConfirmRequest{
		ChallengeID:       ch.ID,
		CredentialID:      "cred-test-1",
		ClientDataJSON:    []byte("client-data"),
		AuthenticatorData: []byte("auth-data"),
		Signature:         []byte("sig"),
	})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	m.dashboard = svc
	scope := m.newFixtureScope(config)
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: config,
		Method: "human.session", Params: rawParams, Proof: &proof, RequestSHA256: dig,
		RequestID: "req-bootstrap-fixture-0001", IdempotencyKey: proof.ID}
	scope = fixtureRequestScope(scope, scope.Request)
	hs, err := m.HumanSession(context.Background(), scope, api.HumanSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	cookieTok, err := svc.trackHumanSession(context.Background(), scope, hs)
	if err != nil {
		t.Fatal(err)
	}

	return scope, hs, cookieTok
}

func (m *memHarness) issueProofFor(t *testing.T, config string, method api.Method, targetID api.ID, baseGen api.Generation, params any) (api.Request, *api.ProofRef) {
	t.Helper()
	rawParams, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	dig, err := RequestDigest(api.Protocol, api.SchemaVersion, config, method, rawParams)
	if err != nil {
		t.Fatal(err)
	}
	epScope := api.Scope{Source: "dashboard", Config: config, Actor: api.Actor{Kind: "human", ID: api.ID("endpoint-" + config)}}
	ch, err := m.issueChallenge(context.Background(), epScope, api.HumanChallengeRequest{
		Method:         method,
		TargetID:       targetID,
		RequestSHA256:  dig,
		BaseGeneration: baseGen,
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := m.Confirm(context.Background(), epScope, api.HumanConfirmRequest{
		ChallengeID:       ch.ID,
		CredentialID:      "cred-test-1",
		ClientDataJSON:    []byte("client-data"),
		AuthenticatorData: []byte("auth-data"),
		Signature:         []byte("sig"),
	})
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.seqCounter++
	seq := m.seqCounter
	m.mu.Unlock()
	suffix := hex.EncodeToString([]byte{byte(seq), byte(seq >> 8)}) + strings.Repeat("0", 20)
	req := api.Request{
		Protocol:       api.Protocol,
		Schema:         api.SchemaVersion,
		Config:         config,
		RequestID:      api.ID("req-ctl-" + suffix),
		IdempotencyKey: api.ID("idem-ctl-" + suffix),
		RequestSHA256:  dig,
		Method:         method,
		Params:         rawParams,
		Proof:          &proof,
	}
	return req, &proof
}

func (m *memHarness) putBlob(id api.ID, class string, data []byte) api.BlobRef {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := append([]byte(nil), data...)
	m.blobs[id] = cp
	sum := sha256.Sum256(cp)
	ref := api.BlobRef{
		ID:     id,
		SHA256: api.Digest(hex.EncodeToString(sum[:])),
		Bytes:  int64(len(cp)),
		Class:  class,
	}
	m.blobRefs[id] = ref
	return ref
}

func (m *memHarness) appendEvent(ev api.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ev.Seq == 0 {
		ev.Seq = api.Sequence(len(m.events) + 1)
	}
	if ev.RecordedAt == "" {
		ev.RecordedAt = api.Timestamp(m.clock.Now().UTC().Format(time.RFC3339Nano))
	}
	if ev.StarterChain == nil {
		ev.StarterChain = []api.ID{}
	}
	m.events = append(m.events, ev)
}

// Store implementation
func (m *memHarness) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	return api.Commit{}, api.NotImplemented("lb-v2-service", "Transact")
}

func (m *memHarness) Operation(ctx context.Context, scope api.Scope, id api.ID) (api.Operation, error) {
	if m.failStore != nil {
		return api.Operation{}, m.failStore
	}
	return api.Operation{}, api.NotImplemented("lb-v2-service", "fixture Operation")
}

func (m *memHarness) Lane(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return api.Lane{}, m.failStore
	}
	l, ok := m.lanes[target.LifeID]
	if !ok {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound, Message: "lane not found", Instead: "Check life_id."}
	}
	return l, nil
}

func (m *memHarness) Lanes(ctx context.Context, scope api.Scope, req api.ListRequest) (api.LanePage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastReadScope = scope
	if m.failStore != nil {
		return api.LanePage{}, m.failStore
	}
	list := []api.Lane{}
	for _, l := range m.lanes {
		if req.LifeID != "" && l.LifeID != req.LifeID {
			continue
		}
		list = append(list, l)
	}
	return api.LanePage{Lanes: list}, nil
}

func (m *memHarness) Events(ctx context.Context, scope api.Scope, req api.EventTailRequest) (api.EventPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return api.EventPage{}, m.failStore
	}
	out := []api.Event{}
	for _, ev := range m.events {
		if ev.Seq <= req.Since {
			continue
		}
		if req.LifeID != "" && ev.LifeID != req.LifeID {
			continue
		}
		if req.Run != 0 && ev.Run != req.Run {
			continue
		}
		if ev.StarterChain == nil {
			ev.StarterChain = []api.ID{}
		}
		out = append(out, ev)
	}
	return api.EventPage{Events: out, Complete: true}, nil
}

func (m *memHarness) Records(ctx context.Context, scope api.Scope, req api.RecordQuery) (api.RecordPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRecords != nil {
		return api.RecordPage{}, m.failRecords
	}
	if m.failStore != nil {
		return api.RecordPage{}, m.failStore
	}
	recs := m.records[req.Collection]
	out := []api.Record{}
	for _, r := range recs {
		if req.LifeID != "" && r.LifeID != req.LifeID {
			continue
		}
		out = append(out, r)
	}
	return api.RecordPage{Records: out}, nil
}

func (m *memHarness) Blob(ctx context.Context, scope api.Scope, req api.BlobReadRequest) (api.BlobChunk, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return api.BlobChunk{}, m.failStore
	}
	b, ok := m.blobs[req.ObjectID]
	if !ok {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound, Message: "blob not found", Instead: "Check object_id."}
	}
	sum := sha256.Sum256(b)
	return api.BlobChunk{
		ObjectID: req.ObjectID,
		Offset:   0,
		Data:     append([]byte(nil), b...),
		SHA256:   api.Digest(hex.EncodeToString(sum[:])),
	}, nil
}

func (m *memHarness) Launch(ctx context.Context, launchID api.ID) (api.LaunchRecord, error) {
	return api.LaunchRecord{}, api.NotImplemented("lb-v2-service", "Launch")
}

func (m *memHarness) Grants(ctx context.Context, grantSetID api.ID) (api.GrantSet, error) {
	return api.GrantSet{}, api.NotImplemented("lb-v2-service", "Grants")
}

func (m *memHarness) Policy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return api.EffectivePolicy{}, m.failStore
	}
	if m.policy == nil {
		return api.EffectivePolicy{}, &api.Error{Code: api.CodeNotFound, Message: "no policy", Instead: "Bootstrap org."}
	}
	return *m.policy, nil
}

func (m *memHarness) Mail(ctx context.Context, scope api.Scope, req api.ListRequest) (api.MailPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return api.MailPage{}, m.failStore
	}
	out := []api.Mail{}
	for _, msg := range m.mails {
		if req.LifeID != "" && msg.RecipientLifeID != req.LifeID && msg.Sender.LifeID != req.LifeID {
			continue
		}
		out = append(out, msg)
	}
	return api.MailPage{Messages: out}, nil
}

func (m *memHarness) Change(ctx context.Context, scope api.Scope, id api.ID) (api.ChangeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.changes[id]
	if !ok {
		return api.ChangeRequest{}, &api.Error{Code: api.CodeNotFound, Message: "change not found", Instead: "Check change_id."}
	}
	return ch, nil
}

func (m *memHarness) PendingEffects(ctx context.Context, req api.CursorRequest) ([]api.Effect, error) {
	return nil, api.NotImplemented("lb-v2-service", "fixture PendingEffects")
}

func (m *memHarness) Verify(ctx context.Context, req api.VerifyRequest) (api.Verification, error) {
	return api.Verification{}, api.NotImplemented("lb-v2-service", "fixture Verify")
}

// StateStore draft.3 extension methods on memHarness
func (m *memHarness) LookupReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	return api.MutationReceipt{}, api.NotImplemented("lb-v2-service", "LookupReceipt")
}
func (m *memHarness) ReserveRequest(ctx context.Context, res api.RequestReservation) (api.MutationReceipt, error) {
	return api.MutationReceipt{}, api.NotImplemented("lb-v2-service", "ReserveRequest")
}
func (m *memHarness) AwaitReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	return api.MutationReceipt{}, api.NotImplemented("lb-v2-service", "AwaitReceipt")
}
func (m *memHarness) BeginRead(ctx context.Context, scope api.Scope) (api.ReadView, error) {
	return nil, api.NotImplemented("lb-v2-service", "BeginRead")
}
func (m *memHarness) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	return api.EffectRecord{}, api.NotImplemented("lb-v2-service", "Effect")
}
func (m *memHarness) ClaimEffect(ctx context.Context, scope api.Scope, req api.EffectClaimRequest) (api.EffectLease, error) {
	return api.EffectLease{}, api.NotImplemented("lb-v2-service", "ClaimEffect")
}
func (m *memHarness) CompleteEffect(ctx context.Context, scope api.Scope, out api.EffectOutcome) (api.Commit, error) {
	return api.Commit{}, api.NotImplemented("lb-v2-service", "CompleteEffect")
}
func (m *memHarness) AuthorizationTarget(ctx context.Context, scope api.Scope, req api.Request) (api.HumanChallengeRequest, error) {
	target := api.HumanChallengeRequest{Method: req.Method, RequestSHA256: req.RequestSHA256}
	switch req.Method {
	case "human.session":
		target.TargetID = api.ID(scope.Config)
	case "lane.stop":
		var p api.StopRequest
		if err := api.DecodeObject(req.Params, &p); err != nil {
			return target, err
		}
		target.TargetID, target.BaseGeneration = p.Target.LifeID, p.ExpectedGeneration
	case "lane.resume":
		var p api.ResumeRequest
		if err := api.DecodeObject(req.Params, &p); err != nil {
			return target, err
		}
		target.TargetID, target.BaseGeneration = p.Target.LifeID, p.ExpectedGeneration
	case "lane.mark":
		var p api.MarkRequest
		if err := api.DecodeObject(req.Params, &p); err != nil {
			return target, err
		}
		target.TargetID, target.BaseGeneration = p.Target.LifeID, p.ExpectedGeneration
	case "lane.review":
		var p api.ReviewRequest
		if err := api.DecodeObject(req.Params, &p); err != nil {
			return target, err
		}
		target.TargetID = p.Target.LifeID
	case "mail.send":
		var p api.MailSendRequest
		if err := api.DecodeObject(req.Params, &p); err != nil {
			return target, err
		}
		target.TargetID = p.RecipientLifeID
	case "org.change.approve":
		var p api.ChangeApproveRequest
		if err := api.DecodeObject(req.Params, &p); err != nil {
			return target, err
		}
		target.TargetID, target.BaseGeneration = p.ChangeID, p.BaseGeneration
	default:
		return target, api.NotImplemented("lb-v2-service", "fixture authorization target")
	}
	return target, nil
}

func (m *memHarness) Enrollment(ctx context.Context, scope api.Scope) (api.HumanEnrollment, error) {
	return api.HumanEnrollment{}, api.NotImplemented("lb-v2-service", "Enrollment")
}
func (m *memHarness) Challenge(ctx context.Context, scope api.Scope, id api.ID) (api.StoredChallenge, error) {
	return api.StoredChallenge{}, api.NotImplemented("lb-v2-service", "Challenge")
}
func (m *memHarness) issueChallenge(ctx context.Context, scope api.Scope, req api.HumanChallengeRequest) (api.HumanChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqCounter++
	cid := api.ID("chal-" + hex.EncodeToString([]byte{byte(m.seqCounter), byte(m.seqCounter >> 8)}) + "-" + string(req.RequestSHA256)[:8])
	cfg := scope.Config
	if cfg == "" {
		cfg = "cfg-dash"
	}
	ch := api.HumanChallenge{
		ID:             cid,
		Challenge:      []byte("challenge-nonce"),
		Config:         cfg,
		Method:         req.Method,
		TargetID:       req.TargetID,
		RequestSHA256:  req.RequestSHA256,
		BaseGeneration: req.BaseGeneration,
		Origin:         "https://127.0.0.1:8443",
		RPID:           "127.0.0.1",
		ExpiresAt:      api.Timestamp(m.clock.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)),
	}
	m.challenges[cid] = ch
	return ch, nil
}
func (m *memHarness) Proof(ctx context.Context, scope api.Scope, id api.ID) (api.VerifiedHumanProof, error) {
	return api.VerifiedHumanProof{}, api.NotImplemented("lb-v2-service", "Proof")
}
func (m *memHarness) Ticket(ctx context.Context, scope api.Scope, id api.ID) (api.Ticket, error) {
	return api.Ticket{}, api.NotImplemented("lb-v2-service", "Ticket")
}
func (m *memHarness) ReadSession(ctx context.Context, scope api.Scope, id api.ID) (api.StoredReadSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return api.StoredReadSession{}, m.failStore
	}
	stored, ok := m.readSessions[id]
	if !ok {
		return api.StoredReadSession{}, &api.Error{Code: api.CodeNotFound, Message: "unknown read session"}
	}
	stored.Revoked = stored.Revoked || m.identityRevoked[id]
	return stored, nil
}

func (m *memHarness) LaunchBinding(ctx context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	return api.LaunchBindingRequest{}, api.NotImplemented("lb-v2-service", "LaunchBinding")
}
func (m *memHarness) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return api.ObjectMetadata{}, m.failStore
	}
	ref, ok := m.blobRefs[id]
	if !ok {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound, Message: "blob metadata not found", Instead: "Check object_id."}
	}
	return api.ObjectMetadata{
		Ref:    ref,
		Origin: "service",
	}, nil
}
func (m *memHarness) Upload(ctx context.Context, scope api.Scope, id api.ID) (api.UploadLease, error) {
	return api.UploadLease{}, api.NotImplemented("lb-v2-service", "Upload")
}
func (m *memHarness) RetainObject(ctx context.Context, scope api.Scope, req api.RetainObjectRequest) (api.BlobRef, error) {
	return api.BlobRef{}, api.NotImplemented("lb-v2-service", "RetainObject")
}
func (m *memHarness) OrgSnapshot(ctx context.Context, scope api.Scope, req api.OrgSnapshotRequest) (api.OrgSnapshot, error) {
	return api.OrgSnapshot{}, &api.Error{Code: api.CodeNotFound, Message: "no org snapshot", Instead: "Bootstrap org."}
}
func (m *memHarness) TemplateSources(ctx context.Context, scope api.Scope, req api.TemplateSourceRequest) (api.TemplateSources, error) {
	return api.TemplateSources{}, api.NotImplemented("lb-v2-service", "TemplateSources")
}
func (m *memHarness) Source(ctx context.Context, scope api.Scope, ref api.SourceRef) (api.RetainedSource, error) {
	return api.RetainedSource{}, api.NotImplemented("lb-v2-service", "Source")
}
func (m *memHarness) BriefingInput(ctx context.Context, scope api.Scope, req api.BriefingInputRequest) (api.BriefingInput, error) {
	return api.BriefingInput{}, api.NotImplemented("lb-v2-service", "BriefingInput")
}
func (m *memHarness) Approval(ctx context.Context, scope api.Scope, id api.ID) (api.ChangeApproval, error) {
	return api.ChangeApproval{}, api.NotImplemented("lb-v2-service", "Approval")
}
func (m *memHarness) Application(ctx context.Context, scope api.Scope, id api.ID) (api.ChangeReceipt, error) {
	return api.ChangeReceipt{}, api.NotImplemented("lb-v2-service", "Application")
}
func (m *memHarness) Turn(ctx context.Context, scope api.Scope, target api.LifeRef, id api.ID) (api.TurnSnapshot, error) {
	return api.TurnSnapshot{}, api.NotImplemented("lb-v2-service", "Turn")
}
func (m *memHarness) Decision(ctx context.Context, scope api.Scope, id api.ID) (api.DecisionProjection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failDecision != nil {
		return api.DecisionProjection{}, m.failDecision
	}
	if m.failStore != nil {
		return api.DecisionProjection{}, m.failStore
	}
	proj, ok := m.decisions[id]
	if !ok {
		return api.DecisionProjection{}, &api.Error{Code: api.CodeNotFound, Message: "decision projection not found", Instead: "Check decision_id."}
	}
	return proj, nil
}
func (m *memHarness) DecisionCandidates(ctx context.Context, scope api.Scope, q api.DecisionQuery) (api.DecisionPage, error) {
	return api.DecisionPage{}, api.NotImplemented("lb-v2-service", "DecisionCandidates")
}
func (m *memHarness) ReserveGuidance(ctx context.Context, scope api.Scope, req api.GuidanceReservationRequest) (api.GuidanceReservation, error) {
	return api.GuidanceReservation{}, api.NotImplemented("lb-v2-service", "ReserveGuidance")
}
func (m *memHarness) GuidanceReservation(ctx context.Context, scope api.Scope, target api.LifeRef, id api.ID) (api.GuidanceReservation, error) {
	return api.GuidanceReservation{}, api.NotImplemented("lb-v2-service", "GuidanceReservation")
}
func (m *memHarness) JudgeAudit(ctx context.Context, scope api.Scope, id api.ID) (api.JudgeAudit, error) {
	return api.JudgeAudit{}, api.NotImplemented("lb-v2-service", "JudgeAudit")
}
func (m *memHarness) ClaimContinuation(ctx context.Context, scope api.Scope, req api.ContinuationClaimRequest) (api.ContinuationIntent, error) {
	return api.ContinuationIntent{}, api.NotImplemented("lb-v2-service", "ClaimContinuation")
}
func (m *memHarness) ContinuationIntent(ctx context.Context, scope api.Scope, id api.ID) (api.ContinuationIntent, error) {
	return api.ContinuationIntent{}, api.NotImplemented("lb-v2-service", "ContinuationIntent")
}
func (m *memHarness) Channel(ctx context.Context, scope api.Scope, id api.ID) (api.EnrolledChannel, error) {
	return api.EnrolledChannel{}, api.NotImplemented("lb-v2-service", "Channel")
}
func (m *memHarness) ChannelJob(ctx context.Context, scope api.Scope, req api.ChannelJobRequest) (api.ChannelJob, error) {
	return api.ChannelJob{}, api.NotImplemented("lb-v2-service", "ChannelJob")
}
func (m *memHarness) WorkerLease(ctx context.Context, scope api.Scope, id api.ID) (api.WorkerLease, error) {
	return api.WorkerLease{}, api.NotImplemented("lb-v2-service", "WorkerLease")
}
func (m *memHarness) MailForTurn(ctx context.Context, scope api.Scope, req api.DeliveryTurnRequest) (api.DeliveryBatch, error) {
	return api.DeliveryBatch{}, api.NotImplemented("lb-v2-service", "MailForTurn")
}
func (m *memHarness) Relation(ctx context.Context, scope api.Scope, id api.ID) (api.RelationFacts, error) {
	return api.RelationFacts{}, api.NotImplemented("lb-v2-service", "Relation")
}
func (m *memHarness) Deployment(ctx context.Context, scope api.Scope, id api.ID) (api.DeploymentPlan, error) {
	return api.DeploymentPlan{}, api.NotImplemented("lb-v2-service", "Deployment")
}
func (m *memHarness) FrozenBackup(ctx context.Context, scope api.Scope, id api.ID) (api.FrozenBackup, error) {
	return api.FrozenBackup{}, api.NotImplemented("lb-v2-service", "FrozenBackup")
}

// HumanVerifier Confirm and CheckProof implementation
func (m *memHarness) Confirm(ctx context.Context, scope api.Scope, req api.HumanConfirmRequest) (api.ProofRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.challenges[req.ChallengeID]
	if !ok {
		return api.ProofRef{}, forbiddenErr("unknown challenge", "Request a challenge first.")
	}
	m.seqCounter++
	pid := api.ID("proof-" + hex.EncodeToString([]byte{byte(m.seqCounter), byte(m.seqCounter >> 8)}) + "-" + string(ch.RequestSHA256)[:12])
	m.proofs[pid] = api.HumanChallengeRequest{
		Method:         ch.Method,
		TargetID:       ch.TargetID,
		RequestSHA256:  ch.RequestSHA256,
		BaseGeneration: ch.BaseGeneration,
	}
	m.proofPresence[pid] = m.simulatedCredential
	return api.ProofRef{
		SimulatedPresence: m.simulatedCredential,
		ID:                pid,
		RequestSHA256:     ch.RequestSHA256,
		ExpiresAt:         ch.ExpiresAt,
	}, nil
}

func (m *memHarness) CheckProof(ctx context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumed[proof.ID] {
		return api.VerifiedHumanProof{}, forbiddenErr("proof already consumed", "Obtain a fresh proof.")
	}
	bound, ok := m.proofs[proof.ID]
	if proof.SimulatedPresence != m.proofPresence[proof.ID] {
		return api.VerifiedHumanProof{}, forbiddenErr("fixture proof presence differs", "Confirm operation.")
	}
	if !ok {
		return api.VerifiedHumanProof{}, forbiddenErr("unknown proof reference", "Confirm a challenge first.")
	}
	if bound.Method != target.Method || bound.TargetID != target.TargetID || bound.RequestSHA256 != target.RequestSHA256 || bound.BaseGeneration != target.BaseGeneration {
		return api.VerifiedHumanProof{}, forbiddenErr("proof binding mismatch", "Bind proof to the exact target and digest.")
	}
	return api.VerifiedHumanProof{
		SimulatedPresence: proof.SimulatedPresence,
		EndpointClass:     api.EndpointHuman,
		Ref:               proof,
		Config:            scope.Config,
		PrincipalID:       scope.Actor.ID,
		Target:            target,
	}, nil
}

// IdentityAPI and Authenticator implementation on memHarness
func (m *memHarness) Authenticate(ctx context.Context, conn api.ConnectionContext) (api.Scope, error) {
	return api.Scope{}, api.NotImplemented("lb-v2-identity", "Authenticate")
}

func (m *memHarness) Authorize(ctx context.Context, scope api.Scope, req api.Request) error {
	return m.authorizeFixture(ctx, scope, req)
}

func (m *memHarness) BindLaunch(ctx context.Context, req api.LaunchBindingRequest) (api.LaunchPermit, error) {
	return api.LaunchPermit{}, api.NotImplemented("lb-v2-identity", "BindLaunch")
}

func (m *memHarness) RevokeLaunch(ctx context.Context, launchID api.ID) error {
	return api.NotImplemented("lb-v2-identity", "RevokeLaunch")
}

func (m *memHarness) IdentitySelf(ctx context.Context, scope api.Scope, req api.Empty) (api.Scope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failIdentity != nil {
		return api.Scope{}, m.failIdentity
	}
	if scope.Connection == nil {
		return api.Scope{}, unauthErr("missing fixture connection", "Authenticate.")
	}
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return api.Scope{}, err
	}
	if m.identityRevoked[authority.SessionID] {
		return api.Scope{}, unauthErr("fixture session revoked", "Authenticate.")
	}
	generation := api.Generation(1)
	if m.policy != nil {
		generation = m.policy.Generation
	}
	if scope.PolicyGeneration != generation {
		return api.Scope{}, conflictErr("fixture connection policy changed", "Reload current policy authority.")
	}
	return api.Scope{Config: scope.Config, Actor: scope.Actor, EndpointGeneration: scope.EndpointGeneration, PolicyGeneration: generation}, nil
}

func (m *memHarness) HumanChallenge(ctx context.Context, scope api.Scope, req api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return m.issueChallenge(ctx, scope, req)
}

func (m *memHarness) HumanConfirm(ctx context.Context, scope api.Scope, req api.HumanConfirmRequest) (api.ProofRef, error) {
	return m.Confirm(ctx, scope, req)
}

type memHuman struct {
	*memHarness
}

func (h memHuman) Challenge(ctx context.Context, scope api.Scope, req api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return h.issueChallenge(ctx, scope, req)
}

func (m *memHarness) human() memHuman {
	return memHuman{m}
}

func (m *memHarness) HumanSession(ctx context.Context, scope api.Scope, req api.HumanSessionRequest) (api.HumanSession, error) {
	if err := m.consumeFixtureProof(ctx, scope); err != nil {
		return api.HumanSession{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqCounter++
	now := m.clock.Now().UTC()
	sid := api.ID("hsess-" + hex.EncodeToString([]byte{byte(m.seqCounter), byte(m.seqCounter >> 8)}))
	hs := api.HumanSession{SimulatedPresence: scope.Request.Proof.SimulatedPresence, ID: sid, Config: scope.Config,
		ExpiresAt:     api.Timestamp(now.Add(defaultMaxSessionTTL).Format(time.RFC3339Nano)),
		IdleExpiresAt: api.Timestamp(now.Add(defaultIdleSessionTTL).Format(time.RFC3339Nano))}
	stored := api.StoredReadSession{Session: hs, PrincipalID: scope.Actor.ID, CredentialID: "fixture-credential",
		ConnectionID: scope.Connection.ID(), EndpointGeneration: scope.EndpointGeneration, Generation: 1}
	if err := scope.Connection.BindReadAuthority(api.ReadAuthorityFromSession(stored)); err != nil {
		return api.HumanSession{}, err
	}
	m.readSessions[sid], m.identitySessions[sid] = stored, hs
	return hs, nil
}

func (m *memHarness) TicketIssue(ctx context.Context, scope api.Scope, req api.TicketIssueRequest) (api.Ticket, error) {
	return api.Ticket{}, api.NotImplemented("lb-v2-identity", "TicketIssue")
}

// LifecycleAPI implementation (subset used by dashboard)
func (m *memHarness) LaneStart(ctx context.Context, scope api.Scope, req api.StartRequest) (api.Operation, error) {
	return api.Operation{}, api.NotImplemented("lb-v2-lifecycle", "LaneStart")
}
func (m *memHarness) LaneAdopt(ctx context.Context, scope api.Scope, req api.AdoptRequest) (api.Operation, error) {
	return api.Operation{}, api.NotImplemented("lb-v2-lifecycle", "LaneAdopt")
}
func (m *memHarness) LaneResume(ctx context.Context, scope api.Scope, req api.ResumeRequest) (api.Operation, error) {
	if err := m.consumeFixtureProof(ctx, scope); err != nil {
		return api.Operation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastMutationAct, m.lastMutationSrc = scope.Actor, scope.Source
	l := m.lanes[req.Target.LifeID]
	before := l
	from := l.State
	l.Run++
	l.State = "running"
	l.Generation++
	m.resumedLives = append(m.resumedLives, req.Target.LifeID)
	op, err := m.fixtureTransition(scope, l, from)
	if err != nil {
		return api.Operation{}, err
	}
	m.reviewResume = &fixtureReviewResume{Scope: scope, Before: before, Request: req, Operation: op}
	return op, nil
}
func (m *memHarness) LaneTurn(ctx context.Context, scope api.Scope, req api.TurnRequest) (api.Operation, error) {
	return api.Operation{}, api.NotImplemented("lb-v2-lifecycle", "LaneTurn")
}
func (m *memHarness) LaneStop(ctx context.Context, scope api.Scope, req api.StopRequest) (api.Operation, error) {
	if err := m.consumeFixtureProof(ctx, scope); err != nil {
		return api.Operation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastMutationAct, m.lastMutationSrc = scope.Actor, scope.Source
	l := m.lanes[req.Target.LifeID]
	from := l.State
	l.State = "verifying"
	l.Generation++
	m.stoppedLives = append(m.stoppedLives, req.Target.LifeID)
	return m.fixtureTransition(scope, l, from)
}
func (m *memHarness) LaneMark(ctx context.Context, scope api.Scope, req api.MarkRequest) (api.Operation, error) {
	if err := m.consumeFixtureProof(ctx, scope); err != nil {
		return api.Operation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastMutationAct, m.lastMutationSrc = scope.Actor, scope.Source
	l := m.lanes[req.Target.LifeID]
	from := l.State
	l.State = req.State
	l.Generation++
	m.markedStates[req.Target.LifeID] = req.State
	return m.fixtureTransition(scope, l, from)
}
func (m *memHarness) LaneReview(ctx context.Context, scope api.Scope, req api.ReviewRequest) (api.ReviewReceipt, error) {
	return api.ReviewReceipt{}, api.NotImplemented("lb-v2-lifecycle", "fixture LaneReview")
}

func (m *memHarness) LaneClean(ctx context.Context, scope api.Scope, req api.CleanRequest) (api.Operation, error) {
	return api.Operation{}, api.NotImplemented("lb-v2-lifecycle", "LaneClean")
}
func (m *memHarness) LaneArchive(ctx context.Context, scope api.Scope, req api.ArchiveRequest) (api.ArchiveReceipt, error) {
	return api.ArchiveReceipt{}, api.NotImplemented("lb-v2-lifecycle", "LaneArchive")
}
func (m *memHarness) LaneStatus(ctx context.Context, scope api.Scope, req api.LifeRef) (api.Lane, error) {
	return m.Lane(ctx, scope, req)
}
func (m *memHarness) LaneList(ctx context.Context, scope api.Scope, req api.ListRequest) (api.LanePage, error) {
	return m.Lanes(ctx, scope, req)
}
func (m *memHarness) LaneCheck(ctx context.Context, scope api.Scope, req api.LifeRef) (api.ProcessObservation, error) {
	return api.ProcessObservation{}, api.NotImplemented("lb-v2-lifecycle", "LaneCheck")
}
func (m *memHarness) LaneLoop(ctx context.Context, scope api.Scope, req api.LoopRequest) (api.Operation, error) {
	return api.Operation{}, api.NotImplemented("lb-v2-lifecycle", "LaneLoop")
}
func (m *memHarness) LaneAttach(ctx context.Context, scope api.Scope, req api.AttachRequest) (api.StreamFrame, error) {
	return api.StreamFrame{}, api.NotImplemented("lb-v2-lifecycle", "LaneAttach")
}
func (m *memHarness) LaneInput(ctx context.Context, scope api.Scope, req api.AttachInputRequest) (api.Operation, error) {
	return api.Operation{}, api.NotImplemented("lb-v2-lifecycle", "LaneInput")
}
func (m *memHarness) EventTail(ctx context.Context, scope api.Scope, req api.EventTailRequest) (api.EventPage, error) {
	return m.Events(ctx, scope, req)
}

// MessagingAPI implementation
func (m *memHarness) MailSend(ctx context.Context, scope api.Scope, req api.MailSendRequest) (api.Mail, error) {
	if err := m.consumeFixtureProof(ctx, scope); err != nil {
		return api.Mail{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastMutationAct = scope.Actor
	m.lastMutationSrc = scope.Source
	msg := api.Mail{
		ID:              api.ID("mail-" + string(req.RecipientLifeID)),
		Sender:          scope.Actor,
		RecipientLifeID: req.RecipientLifeID,
		Content:         req.Content,
		Source:          scope.Source,
		QueuedSeq:       api.Sequence(len(m.events) + 1),
		Status:          "queued",
		Ask:             req.Ask,
	}
	m.mails = append(m.mails, msg)
	m.sentMails = append(m.sentMails, msg)
	return msg, nil
}

func (m *memHarness) MailList(ctx context.Context, scope api.Scope, req api.ListRequest) (api.MailPage, error) {
	return m.Mail(ctx, scope, req)
}

func (m *memHarness) ReportSubmit(ctx context.Context, scope api.Scope, req api.ReportRequest) (api.Mail, error) {
	return api.Mail{}, api.NotImplemented("lb-v2-messaging", "ReportSubmit")
}

// ApprovalAPI implementation
func (m *memHarness) OrgChangePropose(ctx context.Context, scope api.Scope, req api.ChangeProposeRequest) (api.ChangeRequest, error) {
	return api.ChangeRequest{}, api.NotImplemented("lb-v2-approval", "OrgChangePropose")
}
func (m *memHarness) OrgChangeGet(ctx context.Context, scope api.Scope, req api.ChangeGetRequest) (api.ChangeRequest, error) {
	return m.Change(ctx, scope, req.ChangeID)
}
func (m *memHarness) OrgChangeApprove(ctx context.Context, scope api.Scope, req api.ChangeApproveRequest) (api.ChangeApproval, error) {
	return api.ChangeApproval{}, api.NotImplemented("lb-v2-approval", "fixture OrgChangeApprove")
}

func (m *memHarness) OrgChangeApply(ctx context.Context, scope api.Scope, req api.ChangeApplyRequest) (api.ChangeReceipt, error) {
	return api.ChangeReceipt{}, api.NotImplemented("lb-v2-approval", "OrgChangeApply")
}

type testRegistrar struct {
	handlers map[api.Method]api.Handler
}

func (r *testRegistrar) Register(m api.Method, h api.Handler) error {
	if r.handlers == nil {
		r.handlers = make(map[api.Method]api.Handler)
	}
	r.handlers[m] = h
	return nil
}

func (r *testRegistrar) RegisterStream(m api.Method, h api.StreamHandler) error {
	return api.NotImplemented(ownerName, "fixture streaming registrar")
}

func TestNewAndRegister(t *testing.T) {
	if _, err := New(Dependencies{}); err == nil {
		t.Fatal("expected error when dependencies are nil")
	}
	h := newMemHarness()
	svc, err := New(Dependencies{
		Store:     h,
		Transport: h,
		Human:     h.human(),
		Lifecycle: h,
		Messaging: h,
		Approval:  h,
		Clock:     h.clock,
	})
	if err != nil {
		t.Fatalf("unexpected New error: %v", err)
	}
	reg := &testRegistrar{}
	if err := svc.Register(reg); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if len(reg.handlers) != 8 {
		t.Fatalf("expected 8 registered handlers, got %d", len(reg.handlers))
	}
}

func TestSessionAuthFailClosed(t *testing.T) {
	h := newMemHarness()
	svc, err := New(Dependencies{
		Store:     h,
		Transport: h,
		Human:     h.human(),
		Lifecycle: h,
		Messaging: h,
		Approval:  h,
		Clock:     h.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://127.0.0.1:8443"

	// Seed a decision and a running lane so positive controls have real data.
	decBlob := h.putDecisionDocument(t, "blob-dec-auth", "Fail closed on untracked sessions", "2026-10-16T11:50:00Z", true)
	h.records["decisions"] = []api.Record{
		{
			ID:         "dec-auth",
			Collection: "decisions",
			Content:    decBlob,
			Actor:      api.Actor{Kind: "human", ID: "human-seed"},
			Origin:     "service",
			RecordedAt: "2026-10-16T11:50:00Z",
			Generation: 1,
		},
	}
	h.decisions["dec-auth"] = api.DecisionProjection{
		RecordID: "dec-auth",
		Status:   "active",
		Candidate: api.DecisionCandidate{
			ID:          "dec-auth",
			Text:        "Fail closed on untracked sessions",
			EffectiveAt: "2026-10-16T11:50:00Z",
			Binding:     true,
		},
	}
	stopBlob := h.putBlob("blob-stop-auth", "task", []byte("stop reason"))
	h.lanes["life-auth"] = api.Lane{
		LifeID:     "life-auth",
		Name:       "worker-auth",
		RootLifeID: "life-auth",
		Level:      3,
		Role:       "executor",
		State:      "running",
		Generation: 1,
		Run:        1,
		Session:    api.Session{ID: "s-auth", Driver: api.DriverClaudock},
	}

	// Mint a session for another configuration ("cfg-other") before pinning "cfg-dash".
	otherScope, _, _ := h.establishVerifiedScope(t, svc, "cfg-other")
	if err := svc.ConfigureHTTP("cfg-dash", origin, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	// Mint a session that we will revoke.
	revokedScope, revokedSess, _ := h.establishVerifiedScope(t, svc, "cfg-dash")
	svc.RevokeSession(revokedSess.ID)

	// Mint a session that we will expire by advancing past the 5-minute default idle TTL.
	expiredScope, _, _ := h.establishVerifiedScope(t, svc, "cfg-dash")
	h.clock.Advance(5*time.Minute + time.Second)

	// Mint a fresh verified session (positive control).
	validScope, _, validToken := h.establishVerifiedScope(t, svc, "cfg-dash")

	untrackedScope := api.Scope{
		Source: "dashboard",
		Config: "cfg-dash",
		Actor:  api.Actor{Kind: "human", ID: "hsess-untracked-well-formed"},
	}
	wrongConfigScope := otherScope
	wrongConfigScope.Config = "cfg-dash"
	laneScope := api.Scope{
		Source:   "cli",
		Config:   "cfg-dash",
		Actor:    api.Actor{Kind: "lane", ID: "life-auth", LifeID: "life-auth", Level: 3, Role: "executor"},
		LaunchID: "launch-auth-1",
	}

	query := api.DashboardQuery{Limit: 10}
	stopParams := api.StopRequest{
		Target:             api.LifeRef{LifeID: "life-auth", Run: 1},
		ExpectedGeneration: 1,
		Reason:             stopBlob,
	}

	negativeCases := []struct {
		name     string
		scope    api.Scope
		wantCode api.ErrorCode
	}{
		{"untracked_session_id", untrackedScope, api.CodeUnauthenticated},
		{"revoked_session_id", revokedScope, api.CodeUnauthenticated},
		{"expired_session_id", expiredScope, api.CodeUnauthenticated},
		{"other_config_session_id", wrongConfigScope, api.CodeForbidden},
		{"lane_actor", laneScope, api.CodeForbidden},
	}

	for _, tc := range negativeCases {
		// (a) Refused on view
		if _, err := svc.DashboardDecisions(context.Background(), tc.scope, query); err == nil {
			t.Fatalf("%s: expected view DashboardDecisions to fail, but it succeeded", tc.name)
		} else {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != tc.wantCode {
				t.Fatalf("%s: view expected %s, got %v", tc.name, tc.wantCode, err)
			}
		}

		// (b) Refused on SSE stream
		reqSSE := httptest.NewRequest(http.MethodGet, origin+"/api/v2/events?follow=false", nil)
		recSSE := httptest.NewRecorder()
		svc.handleSSEEvents(recSSE, reqSSE, tc.scope, "")
		if recSSE.Code != http.StatusUnauthorized {
			t.Fatalf("%s: cookieless SSE expected HTTP 401, got %d", tc.name, recSSE.Code)
		}

		// (c) Refused on mutating control
		ctlReq, _ := h.issueProofFor(t, "cfg-dash", "lane.stop", "life-auth", 1, stopParams)
		ctlScope := tc.scope
		ctlScope = fixtureRequestScope(ctlScope, ctlReq)
		if _, _, err := svc.dispatchMutationRPC(context.Background(), ctlScope, ctlReq); err == nil {
			t.Fatalf("%s: expected mutating control lane.stop to fail, but it succeeded", tc.name)
		} else {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != tc.wantCode {
				t.Fatalf("%s: control expected %s, got %v", tc.name, tc.wantCode, err)
			}
		}
	}

	// Also verify that when Identity / Authenticator is a stub, an untracked session fails with the stub's typed error.
	stubSvc, err := New(Dependencies{
		Store:         h,
		Transport:     h,
		Human:         stubIdentity{},
		Identity:      stubIdentity{},
		Authenticator: stubIdentity{},
		Lifecycle:     h,
		Messaging:     h,
		Approval:      h,
		Clock:         h.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stubSvc.DashboardDecisions(context.Background(), untrackedScope, query); err == nil {
		t.Fatal("expected untracked session against stub identity to fail")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented {
			t.Fatalf("expected not_implemented from stub identity, got %v", err)
		}
	}

	// Positive control: the session from the verified flow reads views, streams SSE, and executes a control.
	decView, err := svc.DashboardDecisions(context.Background(), validScope, query)
	if err != nil || len(decView.Decisions) != 1 || decView.Decisions[0].ID != "dec-auth" {
		t.Fatalf("positive control view failed: %+v err=%v", decView, err)
	}
	reqValidSSE := httptest.NewRequest(http.MethodGet, origin+"/api/v2/events?follow=false", nil)
	reqValidSSE.AddCookie(&http.Cookie{Name: sessionCookieName, Value: validToken})
	recValidSSE := httptest.NewRecorder()
	svc.ServeHTTP(recValidSSE, reqValidSSE)
	if recValidSSE.Code != http.StatusOK || !strings.Contains(recValidSSE.Body.String(), `"end":true`) {
		t.Fatalf("positive control SSE failed: %d %s", recValidSSE.Code, recValidSSE.Body.String())
	}
	validCtlReq, _ := h.issueProofFor(t, "cfg-dash", "lane.stop", "life-auth", 1, stopParams)
	validCtlScope := validScope
	validCtlScope = fixtureRequestScope(validCtlScope, validCtlReq)
	if _, _, err := svc.dispatchMutationRPC(context.Background(), validCtlScope, validCtlReq); err != nil {
		t.Fatalf("positive control mutation failed: %v", err)
	}
}

func TestIdentityRevocationAndIdle(t *testing.T) {
	h := newMemHarness()
	svc, err := New(Dependencies{
		Store:     h,
		Transport: h,
		Human:     h.human(),
		Lifecycle: h,
		Messaging: h,
		Approval:  h,
		Clock:     h.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://127.0.0.1:8443"
	if err := svc.ConfigureHTTP("cfg-dash", origin, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	decBlob := h.putDecisionDocument(t, "blob-dec-rev", "Revocation takes effect immediately", "2026-10-16T11:50:00Z", true)
	h.records["decisions"] = []api.Record{
		{
			ID:         "dec-rev",
			Collection: "decisions",
			Content:    decBlob,
			Actor:      api.Actor{Kind: "human", ID: "human-seed"},
			Origin:     "service",
			RecordedAt: "2026-10-16T11:50:00Z",
			Generation: 1,
		},
	}
	h.decisions["dec-rev"] = api.DecisionProjection{
		RecordID: "dec-rev",
		Status:   "active",
		Candidate: api.DecisionCandidate{
			ID:          "dec-rev",
			Text:        "Revocation takes effect immediately",
			EffectiveAt: "2026-10-16T11:50:00Z",
			Binding:     true,
		},
	}
	stopBlob := h.putBlob("blob-stop-rev", "task", []byte("stop reason"))
	h.lanes["life-rev"] = api.Lane{
		LifeID:     "life-rev",
		Name:       "worker-rev",
		RootLifeID: "life-rev",
		Level:      3,
		Role:       "executor",
		State:      "running",
		Generation: 1,
		Run:        1,
		Session:    api.Session{ID: "s-rev", Driver: api.DriverClaudock},
	}

	// 1. Mint a tracked session and verify it works before identity-side revocation.
	scope1, sess1, cookie1 := h.establishVerifiedScope(t, svc, "cfg-dash")
	query := api.DashboardQuery{Limit: 10}
	if _, err := svc.DashboardDecisions(context.Background(), scope1, query); err != nil {
		t.Fatalf("expected tracked session to read before revocation, got %v", err)
	}

	// Revoke ONLY on the identity side (do not call svc.RevokeSession); the next view, SSE and control must fail.
	h.revokeOnIdentitySide(sess1.ID)

	// (a) Next view fails with CodeUnauthenticated
	if _, err := svc.DashboardDecisions(context.Background(), scope1, query); err == nil {
		t.Fatal("expected view to fail immediately after identity-side revocation")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
			t.Fatalf("expected unauthenticated on view after identity revocation, got %v", err)
		}
	}

	// (b) Next SSE stream request and active SSE stream tick fail with CodeUnauthenticated
	scopeSSE, sessSSE, cookieSSE := h.establishVerifiedScope(t, svc, "cfg-dash")
	ctxSSE, cancelSSE := context.WithCancel(context.Background())
	defer cancelSSE()
	reqActiveSSE := httptest.NewRequest(http.MethodGet, origin+"/api/v2/events?follow=true", nil).WithContext(ctxSSE)
	reqActiveSSE.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieSSE})
	recActiveSSE := httptest.NewRecorder()
	doneSSE := make(chan struct{})
	go func() {
		defer close(doneSSE)
		svc.ServeHTTP(recActiveSSE, reqActiveSSE)
	}()
	h.revokeOnIdentitySide(sessSSE.ID)
	select {
	case <-doneSSE:
	case <-time.After(2 * time.Second):
		cancelSSE()
		<-doneSSE
		t.Fatal("active SSE stream did not close after identity-side revocation")
	}
	if !strings.Contains(recActiveSSE.Body.String(), `"code":"unauthenticated"`) {
		t.Fatalf("expected active SSE stream to emit unauthenticated error frame, got %s", recActiveSSE.Body.String())
	}

	reqNewSSE := httptest.NewRequest(http.MethodGet, origin+"/api/v2/events?follow=false", nil)
	svc.handleSSEEvents(httptest.NewRecorder(), reqNewSSE, scopeSSE, cookieSSE)

	// (c) Next mutating control fails with CodeUnauthenticated
	scopeCtl, sessCtl, cookieCtl := h.establishVerifiedScope(t, svc, "cfg-dash")
	stopParams := api.StopRequest{
		Target:             api.LifeRef{LifeID: "life-rev", Run: 1},
		ExpectedGeneration: 1,
		Reason:             stopBlob,
	}
	ctlReq, _ := h.issueProofFor(t, "cfg-dash", "lane.stop", "life-rev", 1, stopParams)
	h.revokeOnIdentitySide(sessCtl.ID)

	ctlScope := scopeCtl
	ctlScope = fixtureRequestScope(ctlScope, ctlReq)
	if _, _, err := svc.dispatchMutationRPC(context.Background(), ctlScope, ctlReq); err == nil {
		t.Fatal("expected control to fail immediately after identity-side revocation")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
			t.Fatalf("expected unauthenticated on control after identity revocation, got %v", err)
		}
	}
	bodyCtl, _ := json.Marshal(ctlReq)
	httpCtlReq := httptest.NewRequest(http.MethodPost, origin+"/api/v2/rpc", bytes.NewReader(bodyCtl))
	httpCtlReq.Header.Set("Content-Type", "application/json")
	httpCtlReq.Header.Set("Origin", origin)
	httpCtlReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieCtl})
	recCtl := httptest.NewRecorder()
	svc.ServeHTTP(recCtl, httpCtlReq)
	if recCtl.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 on control after identity revocation, got %d", recCtl.Code)
	}
	_ = cookie1

	// 2. A failed identity check must NOT refresh the idle expiry.
	scopeIdle, _, cookieIdle := h.establishVerifiedScope(t, svc, "cfg-dash")
	// Advance 4 minutes (within the 5-minute initial idle window).
	h.clock.Advance(4 * time.Minute)

	// Inject a transient identity check failure at t = +4m.
	h.mu.Lock()
	h.failIdentity = unavailableErr("identity verifier temporarily unavailable", "Retry.")
	h.mu.Unlock()

	reqFailHTTP := httptest.NewRequest(http.MethodGet, origin+"/api/v2/decisions", nil)
	reqFailHTTP.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieIdle})
	recFailHTTP := httptest.NewRecorder()
	svc.ServeHTTP(recFailHTTP, reqFailHTTP)
	if recFailHTTP.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when identity check fails, got %d", recFailHTTP.Code)
	}
	if _, err := svc.DashboardDecisions(context.Background(), scopeIdle, query); err == nil {
		t.Fatal("expected DashboardDecisions to fail when identity check fails")
	}

	// Restore identity service, then advance 1m01s (total +5m01s from session start, but only +1m01s since the failed request).
	// Because the failed request at +4m must NOT have refreshed idleExpiresAt, the session must now be expired!
	h.mu.Lock()
	h.failIdentity = nil
	h.mu.Unlock()
	h.clock.Advance(time.Minute + time.Second)

	reqAfterIdle := httptest.NewRequest(http.MethodGet, origin+"/api/v2/decisions", nil)
	reqAfterIdle.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieIdle})
	recAfterIdle := httptest.NewRecorder()
	svc.ServeHTTP(recAfterIdle, reqAfterIdle)
	if recAfterIdle.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 because failed identity check at +4m must not refresh idle expiry, got %d", recAfterIdle.Code)
	}
}

func TestDashboardViewsAndRedControls(t *testing.T) {
	h := newMemHarness()
	svc, err := New(Dependencies{
		Store:     h,
		Transport: h,
		Human:     h.human(),
		Lifecycle: h,
		Messaging: h,
		Approval:  h,
		Clock:     h.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfigureHTTP("cfg-dash", "https://127.0.0.1:8443", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	humanScope, _, _ := h.establishVerifiedScope(t, svc, "cfg-dash")
	query := api.DashboardQuery{Limit: 50}

	// Red control: uninitialized inventory for plugins and resources must fail with CodeUnavailable, not return empty list.
	if _, err := svc.DashboardPlugins(context.Background(), humanScope, query); err == nil {
		t.Fatal("expected DashboardPlugins to fail when inventory is uninitialized")
	}
	if _, err := svc.DashboardResources(context.Background(), humanScope, query); err == nil {
		t.Fatal("expected DashboardResources to fail when inventory is uninitialized")
	}

	// Red control: lane caller or unauthenticated caller or untracked human ID must fail.
	laneScope := api.Scope{
		Config:   "cfg-dash",
		Actor:    api.Actor{Kind: "lane", ID: "life-l3", LifeID: "life-l3", Level: 3, Role: "executor"},
		LaunchID: "launch-1",
	}
	if _, err := svc.DashboardDecisions(context.Background(), laneScope, query); err == nil {
		t.Fatal("expected lane caller to be refused on DashboardDecisions")
	}
	if _, err := svc.DashboardDecisions(context.Background(), api.Scope{Config: "cfg-dash"}, query); err == nil {
		t.Fatal("expected unauthenticated caller to be refused")
	}
	if _, err := svc.DashboardDecisions(context.Background(), api.Scope{Config: "cfg-dash", Actor: api.Actor{Kind: "human", ID: "untracked-id"}}, query); err == nil {
		t.Fatal("expected untracked human ID to be refused")
	}

	// Seed policy and configured instances
	h.policy = &api.EffectivePolicy{
		Generation: 2,
		Context:    api.RoleContext{Level: 6, Role: "top", InstanceID: "L6-top"},
		Sources: []api.SourceRef{
			{ID: "src-inst-l5", Path: "instances/L5-domain.toml", SHA256: api.Digest(strings.Repeat("1", 64)), Generation: 2},
		},
	}

	// Seed L6, L5, and L3 lives (including direct L5->L3 edge and both drivers)
	h.lanes["life-l6"] = api.Lane{
		LifeID:       "life-l6",
		Name:         "L6-top",
		RootLifeID:   "life-l6",
		StarterChain: []api.ID{},
		Level:        6,
		Role:         "top",
		State:        "running",
		Generation:   1,
		Run:          1,
		Session:      api.Session{ID: "s-l6", Driver: api.DriverClaudock},
		LastSeq:      1,
	}
	h.lanes["life-l5"] = api.Lane{
		LifeID:       "life-l5",
		Name:         "domain-a",
		ParentLifeID: "life-l6",
		RootLifeID:   "life-l6",
		StarterChain: []api.ID{"life-l6"},
		Level:        5,
		Role:         "domain",
		State:        "running",
		Generation:   1,
		Run:          1,
		Session:      api.Session{ID: "s-l5", Driver: api.DriverClaudock},
		LastSeq:      2,
	}
	h.lanes["life-l3"] = api.Lane{
		LifeID:       "life-l3",
		Name:         "worker-codex",
		ParentLifeID: "life-l5",
		RootLifeID:   "life-l6",
		StarterChain: []api.ID{"life-l6", "life-l5"},
		Level:        3,
		Role:         "executor",
		State:        "running",
		Generation:   1,
		Run:          1,
		Session:      api.Session{ID: "s-l3", Driver: api.DriverCodex},
		LastSeq:      3,
	}

	// Append a forged non-service observation trying to inject a fake parent/live node
	forgedLaunch, _ := json.Marshal(api.LaunchEvent{
		LaunchID: "forged-launch",
		Lane: api.Lane{
			LifeID:       "life-forged",
			Name:         "forged",
			ParentLifeID: "life-l6",
			RootLifeID:   "life-l6",
			Level:        6,
			Role:         "forged-role",
			State:        "running",
			Run:          1,
		},
	})
	h.appendEvent(api.Event{
		Schema:  2,
		ID:      "ev-forged",
		Config:  "cfg-dash",
		Kind:    "lane.started",
		Origin:  "observation",
		LifeID:  "life-forged",
		Payload: forgedLaunch,
	})

	// Test DASH-TREE
	treeView, err := svc.DashboardTree(context.Background(), humanScope, query)
	if err != nil {
		t.Fatalf("DashboardTree failed: %v", err)
	}
	hasCfgOnly := false
	hasL5ToL3 := false
	for _, n := range treeView.Nodes {
		if n.Role == "forged-role" || n.LifeID == "life-forged" {
			t.Fatal("forged observation event was included in DashboardTree")
		}
		if n.Configured && !n.Live && n.InstanceID == "src-inst-l5" {
			hasCfgOnly = true
		}
		if n.LifeID == "life-l3" && n.ParentLifeID == "life-l5" && n.Level == 3 && n.Live {
			hasL5ToL3 = true
		}
	}
	if !hasCfgOnly || !hasL5ToL3 {
		t.Fatalf("expected configured node and live L5->L3 edge in TreeView, got %+v", treeView.Nodes)
	}

	// Seed decisions (including superseded decision, structured DecisionDocument with stored HTML/script tag, annotation metadata update, and an unapproved L3 proposal)
	oldDecBlob := h.putBlob("blob-dec-old", "record", []byte(`{"schema":"laneboss.decision.v2","text":"Old superseded decision","effective_at":"2026-10-16T11:00:00Z","applies_to":{"levels":[],"roles":[],"project_ids":[],"life_ids":[]},"binding":true}`))
	decBlob := h.putBlob("blob-dec-1", "record", []byte(`{"schema":"laneboss.decision.v2","text":"Always isolate lanes <script>window.__xss=1</script>","effective_at":"2026-10-16T11:50:00Z","applies_to":{"levels":[3,4,5,6],"roles":["executor"],"project_ids":[],"life_ids":[]},"binding":true}`))
	unapprovedBlob := h.putBlob("blob-dec-bad", "record", []byte(`{"schema":"laneboss.decision.v2","text":"Unapproved L3 proposal","effective_at":"2026-10-16T11:55:00Z","applies_to":{"levels":[],"roles":[],"project_ids":[],"life_ids":[]},"binding":true}`))
	h.records["decisions"] = []api.Record{
		{
			ID:         "dec-old",
			Collection: "decisions",
			Content:    oldDecBlob,
			Actor:      api.Actor{Kind: "human", ID: "human-1"},
			Origin:     "service",
			Action:     "superseded",
			RecordedAt: "2026-10-16T11:00:00Z",
			Generation: 2,
		},
		{
			ID:         "dec-1",
			Collection: "decisions",
			Content:    decBlob,
			Actor:      api.Actor{Kind: "human", ID: "human-1"},
			Origin:     "service",
			Action:     "supersede",
			RelatedIDs: []api.ID{"dec-old"},
			RecordedAt: "2026-10-16T11:50:00Z",
			Generation: 3,
		},
		{
			ID:         "dec-bad",
			Collection: "decisions",
			Content:    unapprovedBlob,
			Actor:      api.Actor{Kind: "lane", ID: "life-l3", LifeID: "life-l3", Level: 3},
			Origin:     "observation",
			RecordedAt: "2026-10-16T11:55:00Z",
			Generation: 1,
		},
	}
	h.decisions["dec-old"] = api.DecisionProjection{
		RecordID: "dec-old",
		Status:   "superseded",
		Candidate: api.DecisionCandidate{
			ID:          "dec-old",
			Text:        "Old superseded decision",
			EffectiveAt: "2026-10-16T11:00:00Z",
			Binding:     true,
		},
	}
	h.decisions["dec-1"] = api.DecisionProjection{
		RecordID:     "dec-1",
		Status:       "active",
		SupersedesID: "dec-old",
		Candidate: api.DecisionCandidate{
			ID:          "dec-1",
			Text:        "Always isolate lanes <script>window.__xss=1</script>",
			EffectiveAt: "2026-10-16T11:50:00Z",
			AppliesTo:   api.DecisionApplicability{Levels: []int{3, 4, 5, 6}, Roles: []string{"executor"}, ProjectIDs: []api.ID{}, LifeIDs: []api.ID{}},
			Binding:     true,
		},
	}
	annotation := api.Record{
		ID:         "dec-1",
		Collection: "decisions",
		Content:    decBlob,
		Actor:      api.Actor{Kind: "human", ID: "human-1"},
		Origin:     "service",
		Action:     "annotate",
		RecordedAt: "2026-10-16T11:58:00Z",
		Generation: 4,
	}
	// The writer updates the record projection with its annotation event.
	h.records["decisions"][1] = annotation
	annotRecBytes, _ := json.Marshal(annotation)
	h.appendEvent(api.Event{
		Schema:  2,
		ID:      "ev-dec-annot",
		Config:  "cfg-dash",
		Kind:    "decision.changed",
		Origin:  "service",
		Payload: annotRecBytes,
	})

	// Test DASH-DECISIONS
	decView, err := svc.DashboardDecisions(context.Background(), humanScope, query)
	if err != nil {
		t.Fatalf("DashboardDecisions failed: %v", err)
	}
	if len(decView.Decisions) != 1 || decView.Decisions[0].ID != "dec-1" {
		t.Fatalf("expected exactly 1 active authoritative decision, got %+v", decView.Decisions)
	}
	if decView.Decisions[0].EffectiveAt != "2026-10-16T11:50:00Z" {
		t.Fatalf("expected annotation to preserve original EffectiveAt, got %s", decView.Decisions[0].EffectiveAt)
	}
	if decView.Decisions[0].Source.SHA256 != decBlob.SHA256 || decView.Decisions[0].Source.Generation != 4 {
		t.Fatalf("decision provenance mismatch: %+v", decView.Decisions[0].Source)
	}

	// Seed raw captures for both drivers, supplementary transcript replacement, capture gap, and mail
	capClaudock := h.putBlob("blob-cap-cc", "capture", []byte(`{"plugin_id":"plug-verified","plugin_path":"plugins/plug-verified.wasm"}`))
	capCodex := h.putBlob("blob-cap-cx", "capture", []byte("codex primary stream output\n"))
	capTamper := h.putBlob("blob-cap-tamper", "transcript", []byte("lane edited transcript\n"))
	mailBlob := h.putBlob("blob-mail-1", "prompt", []byte("Hello L3 from human"))

	ccPayload, _ := json.Marshal(api.CaptureRecord{
		ID:         "cap-cc-1",
		Target:     api.LifeRef{LifeID: "life-l6", Run: 1},
		Stream:     "stdout",
		Offset:     0,
		Data:       capClaudock,
		ObservedAt: "2026-10-16T11:51:00Z",
		Primary:    true,
		Coverage:   "complete",
	})
	h.appendEvent(api.Event{Schema: 2, ID: "ev-cap-1", Config: "cfg-dash", Kind: "capture.appended", Origin: "service", LifeID: "life-l6", Run: 1, Payload: ccPayload})

	cxPayload, _ := json.Marshal(api.CaptureRecord{
		ID:         "cap-cx-1",
		Target:     api.LifeRef{LifeID: "life-l3", Run: 1},
		Stream:     "stdout",
		Offset:     0,
		Data:       capCodex,
		ObservedAt: "2026-10-16T11:52:00Z",
		Primary:    true,
		Coverage:   "complete",
	})
	h.appendEvent(api.Event{Schema: 2, ID: "ev-cap-2", Config: "cfg-dash", Kind: "capture.appended", Origin: "service", LifeID: "life-l3", Run: 1, Payload: cxPayload})

	tamperPayload, _ := json.Marshal(api.CaptureRecord{
		ID:            "cap-cx-tamper",
		Target:        api.LifeRef{LifeID: "life-l3", Run: 1},
		Stream:        "transcript",
		Offset:        0,
		Data:          capTamper,
		ObservedAt:    "2026-10-16T11:53:00Z",
		Primary:       false,
		Coverage:      "partial",
		ReplacementOf: "cap-cx-1",
	})
	h.appendEvent(api.Event{Schema: 2, ID: "ev-cap-3", Config: "cfg-dash", Kind: "capture.appended", Origin: "service", LifeID: "life-l3", Run: 1, Payload: tamperPayload})

	endOff := int64(128)
	gapPayload, _ := json.Marshal(api.CaptureGap{
		Target:      api.LifeRef{LifeID: "life-l3", Run: 1},
		Stream:      "stdout",
		StartOffset: capCodex.Bytes,
		EndOffset:   &endOff,
		Reason:      "spool_backpressure",
		ObservedAt:  "2026-10-16T11:54:00Z",
	})
	h.appendEvent(api.Event{Schema: 2, ID: "ev-gap-1", Config: "cfg-dash", Kind: "capture.gap", Origin: "service", LifeID: "life-l3", Run: 1, Payload: gapPayload})

	h.mails = append(h.mails, api.Mail{
		ID:              "mail-init-1",
		Sender:          api.Actor{Kind: "human", ID: humanScope.Actor.ID},
		RecipientLifeID: "life-l3",
		Content:         mailBlob,
		Source:          "dashboard",
		QueuedSeq:       1,
		Status:          "delivered",
	})

	// Test DASH-RAW
	rawView, err := svc.DashboardRaw(context.Background(), humanScope, query)
	if err != nil {
		t.Fatalf("DashboardRaw failed: %v", err)
	}
	if len(rawView.Records) != 3 {
		t.Fatalf("expected 3 capture records (2 primary + 1 supplementary), got %d", len(rawView.Records))
	}
	if len(rawView.Gaps) != 1 || rawView.Gaps[0].Reason != "spool_backpressure" {
		t.Fatalf("expected capture gap to be preserved, got %+v", rawView.Gaps)
	}
	if len(rawView.Messages) != 1 || rawView.Messages[0].ID != "mail-init-1" {
		t.Fatalf("expected mail in RawView, got %+v", rawView.Messages)
	}

	// Seed policy decisions for DASH-REFUSALS
	pHigh := 0.92
	pWarn := 0.58
	pdPayload, _ := json.Marshal(api.PolicyDecision{
		ID:     "pdec-1",
		Result: "refuse",
		Rules: []api.RuleDecision{
			{RuleID: "rule-raw-tmux", Result: "refuse", Probability: &pHigh, Critical: false},
			{RuleID: "rule-warn-1", Result: "warn", Probability: &pWarn, Critical: false},
			{RuleID: "rule-unscored-1", Result: "unscored", Probability: nil, Critical: false},
			{RuleID: "rule-crit-1", Result: "unscored", Probability: nil, Critical: true},
		},
		PolicyGeneration: 2,
		Input:            mailBlob,
		LatencyMS:        42,
		AuditComplete:    true,
	})
	h.appendEvent(api.Event{
		Schema:  2,
		ID:      "ev-pol-1",
		Config:  "cfg-dash",
		Kind:    "policy.evaluated",
		Origin:  "service",
		LifeID:  "life-l3",
		Run:     1,
		Actor:   api.Actor{Kind: "lane", ID: "life-l3", LifeID: "life-l3", Level: 3},
		Payload: pdPayload,
	})

	// Test DASH-REFUSALS
	refView, err := svc.DashboardRefusals(context.Background(), humanScope, query)
	if err != nil {
		t.Fatalf("DashboardRefusals failed: %v", err)
	}
	if len(refView.Counts) != 4 || len(refView.Receipts) != 1 || refView.Receipts[0] != "pdec-1" {
		t.Fatalf("unexpected RefusalView: %+v", refView)
	}
	for _, c := range refView.Counts {
		if !c.UnknownCoverage {
			t.Fatalf("expected UnknownCoverage=true on level 3 due to capture gap, got %+v", c)
		}
		switch c.RuleID {
		case "rule-raw-tmux":
			if c.Refused != 1 {
				t.Fatalf("expected refused=1, got %+v", c)
			}
		case "rule-warn-1":
			if c.Warned != 1 {
				t.Fatalf("expected warned=1, got %+v", c)
			}
		case "rule-unscored-1":
			if c.Unscored != 1 {
				t.Fatalf("expected unscored=1, got %+v", c)
			}
		case "rule-crit-1":
			if c.CriticalUnscored != 1 {
				t.Fatalf("expected critical_unscored=1, got %+v", c)
			}
		}
	}

	// Seed D6 change, approval, and application for plugins & resources & approvals
	plugDeclBlob := h.putBlob("blob-plug-decl", "manifest", []byte("declared-only-plugin"))
	plugSpoofBlob := h.putBlob("blob-plug-spoof", "manifest", []byte("spoofed-by-capture-plugin"))
	plugVerBlob := h.putBlob("blob-plug-ver", "manifest", []byte("verified-plugin"))
	scriptBlob := h.putBlob("blob-script-1", "policy", []byte("#!/bin/sh\necho safe\n"))
	diffBlob := h.putBlob("blob-diff-1", "artifact", []byte("diff --git a/scripts/check.sh b/scripts/check.sh"))

	changeReq := api.ChangeRequest{
		ID:             "chg-1",
		OrgID:          "org-main",
		Requester:      api.Actor{Kind: "lane", ID: "life-l6", LifeID: "life-l6", Level: 6, Role: "top"},
		BaseGeneration: 1,
		Files: []api.ResourceDelta{
			{Path: "plugins/plug-declared.wasm", Action: "add", Mode: 0644, After: &plugDeclBlob},
			{Path: "plugins/plug-spoofed.wasm", Action: "add", Mode: 0644, After: &plugSpoofBlob},
			{Path: "plugins/plug-verified.wasm", Action: "add", Mode: 0644, After: &plugVerBlob},
			{Path: "scripts/check.sh", Action: "add", Mode: 0755, After: &scriptBlob},
		},
		Derived:        []api.ResourceDelta{},
		ManifestSHA256: api.Digest(strings.Repeat("a", 64)),
		Diff:           diffBlob,
		Renderer:       api.Executable{ID: "renderer-v2", SHA256: api.Digest(strings.Repeat("b", 64)), Version: "2.0.0"},
		Status:         "applied",
		CreatedAt:      "2026-10-16T11:40:00Z",
		ExpiresAt:      "2026-10-17T11:40:00Z",
	}
	changeAppr := api.ChangeApproval{
		ID:              "appr-d6-1",
		ChangeID:        "chg-1",
		RequesterLifeID: "life-l6",
		ApproverKeyID:   "webauthn-key-1",
		ManifestSHA256:  changeReq.ManifestSHA256,
		BaseGeneration:  1,
		NonceID:         "nonce-d6-1",
		ApprovedAt:      "2026-10-16T11:41:00Z",
		ExpiresAt:       "2026-10-16T11:51:00Z",
	}
	changeRec := api.ChangeReceipt{
		ID:             "rcpt-d6-1",
		ChangeID:       "chg-1",
		ApprovalID:     "appr-d6-1",
		OldGeneration:  1,
		NewGeneration:  2,
		ManifestSHA256: changeReq.ManifestSHA256,
		AppliedAt:      "2026-10-16T11:42:00Z",
	}
	h.changes["chg-1"] = changeReq
	cePayload, _ := json.Marshal(api.ChangeEvent{
		Change:   changeReq,
		Approval: &changeAppr,
		Receipt:  &changeRec,
		Reason:   "D6 resource update",
	})
	h.appendEvent(api.Event{Schema: 2, ID: "ev-d6-1", Config: "cfg-dash", Kind: "org.change.applied", Origin: "service", LifeID: "life-l6", Run: 1, Payload: cePayload})

	// Red control 1 for DASH-PLUGINS: a lane primary capture claiming a plugin load (even with matching SHA-256) must leave VerifiedLoaded false.
	spoofCapBlob := h.putBlob("blob-cap-spoof", "capture", []byte(`{"plugin_id":"plug-spoofed","plugin_path":"plugins/plug-spoofed.wasm","plugin_sha256":"`+string(plugSpoofBlob.SHA256)+`"}`))
	spoofCapPayload, _ := json.Marshal(api.CaptureRecord{
		ID:         "cap-spoof-1",
		Target:     api.LifeRef{LifeID: "life-l3", Run: 1},
		Stream:     "stdout",
		Offset:     200,
		Data:       spoofCapBlob,
		ObservedAt: "2026-10-16T11:55:00Z",
		Primary:    true,
		Coverage:   "complete",
	})
	h.appendEvent(api.Event{Schema: 2, ID: "ev-cap-spoof", Config: "cfg-dash", Kind: "capture.appended", Origin: "service", LifeID: "life-l3", Run: 1, Payload: spoofCapPayload})

	// Red control 2 + Positive control for DASH-PLUGINS:
	// - Service data.materialized record for plug-declared.wasm with a DIFFERENT SHA-256 leaves VerifiedLoaded false.
	// - Service data.materialized record for plug-verified.wasm with the MATCHING SHA-256 sets VerifiedLoaded true.
	matManifestBlob := h.putBlob("blob-mat-man", "manifest", []byte(`{"schema":"laneboss.objects.v2","entries":[]}`))
	matPayload, _ := json.Marshal(api.Materialization{
		GrantSetID: "gset-1",
		Manifest:   matManifestBlob,
		Objects: []api.MaterializedObject{
			{
				GrantID:             "g-decl-mismatch",
				SourceIdentity:      "plugins/plug-declared.wasm",
				DestinationIdentity: "/work/plugins/plug-declared.wasm",
				SnapshotSHA256:      api.Digest(strings.Repeat("f", 64)),
				WorkspaceID:         "ws-1",
			},
			{
				GrantID:             "g-ver-match",
				SourceIdentity:      "plugins/plug-verified.wasm",
				DestinationIdentity: "/work/plugins/plug-verified.wasm",
				SnapshotSHA256:      plugVerBlob.SHA256,
				WorkspaceID:         "ws-1",
			},
		},
	})
	h.appendEvent(api.Event{
		Schema:  2,
		ID:      "ev-mat-1",
		Config:  "cfg-dash",
		Kind:    "data.materialized",
		Origin:  "service",
		Actor:   api.Actor{Kind: "service", ID: "service"},
		LifeID:  "life-l6",
		Run:     1,
		Payload: matPayload,
	})

	// Test DASH-PLUGINS
	plugView, err := svc.DashboardPlugins(context.Background(), humanScope, query)
	if err != nil {
		t.Fatalf("DashboardPlugins failed: %v", err)
	}
	if len(plugView.Resources) != 3 {
		t.Fatalf("expected 3 plugins, got %+v", plugView.Resources)
	}
	for _, p := range plugView.Resources {
		if !p.Declared {
			t.Fatalf("expected plugin to be declared: %+v", p)
		}
		switch p.Path {
		case "plugins/plug-verified.wasm":
			if !p.VerifiedLoaded {
				t.Fatalf("expected plug-verified.wasm (matching service hash) to have VerifiedLoaded=true: %+v", p)
			}
		case "plugins/plug-declared.wasm":
			if p.VerifiedLoaded {
				t.Fatalf("expected plug-declared.wasm (mismatched service hash) to have VerifiedLoaded=false: %+v", p)
			}
		case "plugins/plug-spoofed.wasm":
			if p.VerifiedLoaded {
				t.Fatalf("expected plug-spoofed.wasm (lane capture claim) to have VerifiedLoaded=false: %+v", p)
			}
		}
	}

	// Test DASH-RESOURCES
	resView, err := svc.DashboardResources(context.Background(), humanScope, query)
	if err != nil {
		t.Fatalf("DashboardResources failed: %v", err)
	}
	foundScript := false
	for _, r := range resView.Resources {
		if r.Path == "scripts/check.sh" && r.Kind == "script" && r.ApprovalID == "appr-d6-1" && r.SHA256 == scriptBlob.SHA256 {
			foundScript = true
		}
	}
	if !foundScript {
		t.Fatalf("expected approved script in ResourceView, got %+v", resView.Resources)
	}

	// Test DASH-APPROVALS
	appView, err := svc.DashboardApprovals(context.Background(), humanScope, query)
	if err != nil {
		t.Fatalf("DashboardApprovals failed: %v", err)
	}
	if len(appView.Changes) != 1 || len(appView.Approvals) != 1 || len(appView.Applications) != 1 {
		t.Fatalf("unexpected ApprovalView: %+v", appView)
	}
}

func TestHTTPControlsAndSSE(t *testing.T) {
	h := newMemHarness()
	svc, err := New(Dependencies{
		Store:     h,
		Transport: h,
		Human:     h.human(),
		Lifecycle: h,
		Messaging: h,
		Approval:  h,
		Clock:     h.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.dashboard = svc
	const origin = "https://127.0.0.1:8443"
	if err := svc.ConfigureHTTP("cfg-dash", origin, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	// Seed running L3 lane
	h.lanes["life-l3"] = api.Lane{
		LaunchID:          "fixture-launch-1",
		CancellationEpoch: 1,
		StarterEventSeq:   1,
		LifeID:            "life-l3",
		Name:              "worker-1",
		ParentLifeID:      "life-l5",
		RootLifeID:        "life-l6",
		StarterChain:      []api.ID{"life-l6", "life-l5"},
		Level:             3,
		Role:              "executor",
		State:             "running",
		Generation:        1,
		Run:               1,
		Session:           api.Session{ID: "s-l3", Driver: api.DriverClaudock},
		LastSeq:           1,
	}

	// 1. Root page serves inert HTML with CSP and no innerHTML sink
	reqRoot := httptest.NewRequest(http.MethodGet, origin+"/", nil)
	recRoot := httptest.NewRecorder()
	svc.ServeHTTP(recRoot, reqRoot)
	if recRoot.Code != http.StatusOK {
		t.Fatalf("GET / returned %d", recRoot.Code)
	}
	if strings.Contains(recRoot.Body.String(), "innerHTML") {
		t.Fatal("dashboard HTML contains unsafe innerHTML sink")
	}
	if recRoot.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing Content-Security-Policy header")
	}

	// 2. Unauthenticated GET on /api/v2/tree returns 401
	reqUnauth := httptest.NewRequest(http.MethodGet, origin+"/api/v2/tree", nil)
	recUnauth := httptest.NewRecorder()
	svc.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated GET, got %d", recUnauth.Code)
	}

	// Helper to perform POST /api/v2/rpc
	callRPC := func(cookie *http.Cookie, origHdr string, method api.Method, params any, proof *api.ProofRef, idemKey string) (*httptest.ResponseRecorder, api.Response) {
		rawParams, _ := json.Marshal(params)
		if idemKey == "" {
			h.mu.Lock()
			h.seqCounter++
			seq := h.seqCounter
			h.mu.Unlock()
			idemKey = "idem-rpc-" + hex.EncodeToString([]byte{byte(seq), byte(seq >> 8)})
		}
		dig, err := RequestDigest(api.Protocol, api.SchemaVersion, "cfg-dash", method, rawParams)
		if err != nil {
			t.Fatal(err)
		}
		env := api.Request{
			Protocol:       api.Protocol,
			Schema:         api.SchemaVersion,
			Config:         "cfg-dash",
			RequestID:      "req-http-fixture-00000001",
			IdempotencyKey: api.ID(idemKey),
			RequestSHA256:  dig,
			Method:         method,
			Params:         rawParams,
			Proof:          proof,
		}
		if len(env.IdempotencyKey) < 22 {
			env.IdempotencyKey += api.ID(strings.Repeat("_", 22-len(env.IdempotencyKey)))
		}
		body, _ := json.Marshal(env)
		req := httptest.NewRequest(http.MethodPost, origin+"/api/v2/rpc", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if origHdr != "" {
			req.Header.Set("Origin", origHdr)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		var resp api.Response
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec, resp
	}

	// Red control: an idempotency_key containing a dot (outside [A-Za-z0-9_-]) must be refused with 400
	recBadIdem, respBadIdem := callRPC(nil, origin, "human.challenge", api.HumanChallengeRequest{
		Method:        "human.session",
		TargetID:      "cfg-dash",
		RequestSHA256: api.Digest(strings.Repeat("a", 64)),
	}, nil, "idem-ch-human.session")
	if recBadIdem.Code != http.StatusBadRequest || respBadIdem.Error == nil || respBadIdem.Error.Code != api.CodeInvalid {
		t.Fatalf("expected 400 invalid_request for dotted idempotency_key, got %d %+v", recBadIdem.Code, respBadIdem.Error)
	}

	// Helper to obtain fresh proof via human.challenge -> human.confirm
	getProof := func(method api.Method, targetID api.ID, baseGen api.Generation, params any) *api.ProofRef {
		rawParams, _ := json.Marshal(params)
		dig, _ := RequestDigest(api.Protocol, api.SchemaVersion, "cfg-dash", method, rawParams)
		h.mu.Lock()
		h.seqCounter++
		seq := h.seqCounter
		h.mu.Unlock()
		suffix := hex.EncodeToString([]byte{byte(seq), byte(seq >> 8)})
		recCh, respCh := callRPC(nil, origin, "human.challenge", api.HumanChallengeRequest{
			Method:         method,
			TargetID:       targetID,
			RequestSHA256:  dig,
			BaseGeneration: baseGen,
		}, nil, "idem-ch-"+suffix)
		if recCh.Code != http.StatusOK || respCh.Error != nil {
			t.Fatalf("human.challenge failed: %d %+v", recCh.Code, respCh.Error)
		}
		var ch api.HumanChallenge
		_ = json.Unmarshal(respCh.Result, &ch)

		recCf, respCf := callRPC(nil, origin, "human.confirm", api.HumanConfirmRequest{
			ChallengeID:       ch.ID,
			CredentialID:      "cred-1",
			ClientDataJSON:    []byte("client-data"),
			AuthenticatorData: []byte("auth-data"),
			Signature:         []byte("sig"),
		}, nil, "idem-cf-"+suffix)
		if recCf.Code != http.StatusOK || respCf.Error != nil {
			t.Fatalf("human.confirm failed: %d %+v", recCf.Code, respCf.Error)
		}
		var proof api.ProofRef
		_ = json.Unmarshal(respCf.Result, &proof)
		return &proof
	}

	// 3. Establish human.session and obtain HttpOnly cookie
	sessProof := getProof("human.session", "cfg-dash", 0, api.HumanSessionRequest{})
	recSess, respSess := callRPC(nil, origin, "human.session", api.HumanSessionRequest{}, sessProof, "idem-sess-1")
	if recSess.Code != http.StatusOK || respSess.Error != nil {
		t.Fatalf("human.session failed: %d %+v", recSess.Code, respSess.Error)
	}
	var humanSess api.HumanSession
	_ = json.Unmarshal(respSess.Result, &humanSess)
	cookies := recSess.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected Secure HttpOnly SameSite=Strict cookie, got %+v", cookies)
	}
	sessCookie := cookies[0]
	if sessCookie.Value == string(humanSess.ID) {
		t.Fatal("cookie value must not equal the event HumanSession.ID record reference")
	}

	// Red control: using HumanSession.ID as cookie value must fail with 401
	reqFakeCookie := httptest.NewRequest(http.MethodGet, origin+"/api/v2/lifecycle", nil)
	reqFakeCookie.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(humanSess.ID)})
	recFakeCookie := httptest.NewRecorder()
	svc.ServeHTTP(recFakeCookie, reqFakeCookie)
	if recFakeCookie.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when using HumanSession.ID as cookie, got %d", recFakeCookie.Code)
	}

	// 4. DASH-STOP: stop running lane, plus red controls (wrong Origin, missing proof, replayed proof)
	stopBlob := h.putBlob("blob-stop-reason", "task", []byte("stop for check"))
	stopParams := api.StopRequest{
		Target:             api.LifeRef{LifeID: "life-l3", Run: 1},
		ExpectedGeneration: 1,
		Reason:             stopBlob,
	}

	// Wrong Origin -> 403
	recBadOrig, _ := callRPC(sessCookie, "https://attacker.example", "lane.stop", stopParams, nil, "idem-stop-bad-orig")
	if recBadOrig.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on wrong Origin, got %d", recBadOrig.Code)
	}

	// Missing proof -> 403
	recNoProof, _ := callRPC(sessCookie, origin, "lane.stop", stopParams, nil, "idem-stop-no-proof")
	if recNoProof.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on missing proof, got %d", recNoProof.Code)
	}

	// Valid stop with proof -> 200
	stopProof := getProof("lane.stop", "life-l3", 1, stopParams)
	recStop, respStop := callRPC(sessCookie, origin, "lane.stop", stopParams, stopProof, "idem-stop-ok")
	if recStop.Code != http.StatusOK || respStop.Error != nil {
		t.Fatalf("lane.stop failed: %d %+v", recStop.Code, respStop.Error)
	}
	if h.lastMutationAct.Kind != "human" || h.lastMutationSrc != "dashboard" {
		t.Fatalf("expected actor=human and source=dashboard, got %+v %s", h.lastMutationAct, h.lastMutationSrc)
	}

	// Idempotent replay of identical (key, digest) -> 200
	recReplay, _ := callRPC(sessCookie, origin, "lane.stop", stopParams, stopProof, "idem-stop-ok")
	if recReplay.Code != http.StatusOK {
		t.Fatalf("expected 200 on idempotent replay, got %d", recReplay.Code)
	}

	// Reusing consumed proof on a NEW idempotency key -> 403
	recReuseProof, _ := callRPC(sessCookie, origin, "lane.stop", stopParams, stopProof, "idem-stop-new-key")
	if recReuseProof.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when reusing consumed proof on new key, got %d", recReuseProof.Code)
	}

	// 5. DASH-RESUME: resume stopped lane (now generation 2, state verifying)
	resumeBlob := h.putBlob("blob-resume-msg", "prompt", []byte("continue work"))
	resumeParams := api.ResumeRequest{
		Target:             api.LifeRef{LifeID: "life-l3", Run: 1},
		ExpectedGeneration: 2,
		Message:            resumeBlob,
		Budget: api.Budget{
			WallMS:      60000,
			CPUSeconds:  60,
			MemoryBytes: 268435456,
			Processes:   32,
			DiskBytes:   268435456,
			SpendMicros: 0,
			Currency:    "USD",
		},
	}
	resumeProof := getProof("lane.resume", "life-l3", 2, resumeParams)
	recResume, respResume := callRPC(sessCookie, origin, "lane.resume", resumeParams, resumeProof, "idem-resume-ok")
	if recResume.Code != http.StatusOK || respResume.Error != nil {
		t.Fatalf("lane.resume failed: %d %+v", recResume.Code, respResume.Error)
	}
	if h.lanes["life-l3"].Run != 2 || h.lanes["life-l3"].State != "running" {
		t.Fatalf("expected run 2 running after resume, got %+v", h.lanes["life-l3"])
	}

	// Settle run 2 to verifying (generation 3 -> 4) so we can test DASH-MERGED
	stopParams2 := api.StopRequest{
		Target:             api.LifeRef{LifeID: "life-l3", Run: 2},
		ExpectedGeneration: 3,
		Reason:             stopBlob,
	}
	stopProof2 := getProof("lane.stop", "life-l3", 3, stopParams2)
	recStop2, _ := callRPC(sessCookie, origin, "lane.stop", stopParams2, stopProof2, "idem-stop-2")
	if recStop2.Code != http.StatusOK {
		t.Fatalf("second stop failed: %d", recStop2.Code)
	}

	// 6. DASH-MERGED: fabricated ReviewReceipt must fail; authentic service ReviewReceipt succeeds
	diffBlob := h.putBlob("blob-rev-diff", "diff", []byte("diff"))
	invBlob := h.putBlob("blob-rev-inv", "manifest", []byte("inventory"))
	fakeRev := api.ReviewReceipt{
		ID:                "rev-fabricated",
		Reviewer:          api.Actor{Kind: "human", ID: humanSess.ID},
		Diff:              diffBlob,
		Checks:            []api.BlobRef{},
		RecordInventory:   invBlob,
		RefusalResolution: []api.ID{},
		Coverage:          "complete",
	}
	fakeMark := api.MarkRequest{
		Target:             api.LifeRef{LifeID: "life-l3", Run: 2},
		ExpectedGeneration: 4,
		State:              "accepted",
		Review:             fakeRev,
	}
	fakeMarkProof := getProof("lane.mark", "life-l3", 4, fakeMark)
	recFakeMark, _ := callRPC(sessCookie, origin, "lane.mark", fakeMark, fakeMarkProof, "idem-mark-fake")
	if recFakeMark.Code != http.StatusForbidden {
		t.Fatalf("expected fabricated ReviewReceipt to be refused with 403, got %d", recFakeMark.Code)
	}

	// Seed a complete review projection with the current shared evidence shape.
	// These are fixture bytes; no verifier or physical capture is claimed.
	// A separate authentication ceremony must not replace this cookie's actor.
	stagedProof := getProof("human.session", "cfg-dash", 0, api.HumanSessionRequest{})
	if stagedProof.ID == "" {
		t.Fatal("second authentication ceremony did not issue its proof")
	}
	authRev := h.fixtureReview(t, humanSess.ID, h.lanes["life-l3"], diffBlob)
	t.Run("retained", func(t *testing.T) { h.checkFixtureReviewBytes(t, authRev) })
	t.Run("reviewer", func(t *testing.T) {
		// Session staging has its own connection; it must not replace the
		// principal retained by the authenticated cookie's read session.
		other := authRev
		other.ID = "fixture-review-other"
		other.Reviewer = api.Actor{Kind: "human", ID: h.httpConnection.principal}
		if other.Reviewer == authRev.Reviewer {
			t.Fatal("reviewer control did not rotate the staging connection")
		}
		raw, err := json.Marshal(other)
		if err != nil {
			t.Fatal(err)
		}
		h.appendEvent(api.Event{Schema: 2, ID: "ev-review-other", Config: "cfg-dash", Kind: "lane.reviewed",
			Origin: "service", LifeID: "life-l3", Run: 2, Payload: raw})
		mark := api.MarkRequest{Target: fakeMark.Target, ExpectedGeneration: 4, State: "accepted", Review: other}
		proof := getProof("lane.mark", "life-l3", 4, mark)
		rec, resp := callRPC(sessCookie, origin, "lane.mark", mark, proof, "idem-mark-other")
		if rec.Code != http.StatusBadRequest || resp.Error == nil || resp.Error.Code != api.CodeInvalid ||
			resp.Error.Message != "review acceptance lacks complete independent evidence" ||
			h.lanes["life-l3"].State != "verifying" || h.lanes["life-l3"].Generation != 4 {
			t.Fatalf("mark accepted a review from the staging principal: %d %+v", rec.Code, resp.Error)
		}
	})
	revBytes, err := json.Marshal(authRev)
	if err != nil {
		t.Fatal(err)
	}
	h.appendEvent(api.Event{
		Schema:  2,
		ID:      "ev-rev-1",
		Config:  "cfg-dash",
		Kind:    "lane.reviewed",
		Origin:  "service",
		LifeID:  "life-l3",
		Run:     2,
		Payload: revBytes,
	})

	acceptMark := api.MarkRequest{
		Target:             api.LifeRef{LifeID: "life-l3", Run: 2},
		ExpectedGeneration: 4,
		State:              "accepted",
		Review:             authRev,
	}
	acceptProof := getProof("lane.mark", "life-l3", 4, acceptMark)
	recAccept, respAccept := callRPC(sessCookie, origin, "lane.mark", acceptMark, acceptProof, "idem-mark-accept")
	if recAccept.Code != http.StatusOK || respAccept.Error != nil || h.lanes["life-l3"].State != "accepted" ||
		h.lanes["life-l3"].Generation != 5 || h.markedStates["life-l3"] != "accepted" {
		t.Fatalf("mark accepted failed: %d %s", recAccept.Code, recAccept.Body.String())
	}

	mergeMark := api.MarkRequest{
		Target:             api.LifeRef{LifeID: "life-l3", Run: 2},
		ExpectedGeneration: 5,
		State:              "merged",
		Review:             authRev,
	}
	mergeProof := getProof("lane.mark", "life-l3", 5, mergeMark)
	recMerge, respMerge := callRPC(sessCookie, origin, "lane.mark", mergeMark, mergeProof, "idem-mark-merged")
	if recMerge.Code != http.StatusOK || respMerge.Error != nil || h.lanes["life-l3"].State != "merged" ||
		h.lanes["life-l3"].Generation != 6 || h.markedStates["life-l3"] != "merged" ||
		h.lastMutationAct != authRev.Reviewer || h.lastMutationSrc != "dashboard" {
		t.Fatalf("mark merged failed: %d state=%s", recMerge.Code, h.lanes["life-l3"].State)
	}

	// 7. DASH-ABANDONED: mark another lane abandoned
	h.lanes["life-abandon"] = api.Lane{
		LifeID:     "life-abandon",
		Name:       "worker-abandon",
		RootLifeID: "life-l6",
		Level:      3,
		Role:       "executor",
		State:      "verifying",
		Generation: 1,
		Run:        1,
		Session:    api.Session{ID: "s-ab", Driver: api.DriverCodex},
	}
	abandonMark := api.MarkRequest{
		Target:             api.LifeRef{LifeID: "life-abandon", Run: 1},
		ExpectedGeneration: 1,
		State:              "abandoned",
		Review: api.ReviewReceipt{
			Checks:            []api.BlobRef{},
			RefusalResolution: []api.ID{},
		},
	}
	abandonProof := getProof("lane.mark", "life-abandon", 1, abandonMark)
	recAbandon, _ := callRPC(sessCookie, origin, "lane.mark", abandonMark, abandonProof, "idem-mark-abandon")
	if recAbandon.Code != http.StatusOK || h.lanes["life-abandon"].State != "abandoned" {
		t.Fatalf("mark abandoned failed: %d", recAbandon.Code)
	}

	// 8. HUMAN-SEND: send human mail to L3
	mailBlob := h.putBlob("blob-mail-l3", "prompt", []byte("Direct human message to L3"))
	mailParams := api.MailSendRequest{
		RecipientLifeID: "life-l3",
		Content:         mailBlob,
		Ask:             true,
	}
	mailProof := getProof("mail.send", "life-l3", 0, mailParams)
	recMail, respMail := callRPC(sessCookie, origin, "mail.send", mailParams, mailProof, "idem-mail-l3")
	if recMail.Code != http.StatusOK || respMail.Error != nil {
		t.Fatalf("mail.send failed: %d %+v", recMail.Code, respMail.Error)
	}
	if len(h.sentMails) != 1 || h.sentMails[0].Sender.Kind != "human" || h.sentMails[0].Source != "dashboard" {
		t.Fatalf("unexpected sent mail provenance: %+v", h.sentMails)
	}

	// 9. SSE /api/v2/events stream & cursor test
	reqSSE := httptest.NewRequest(http.MethodGet, origin+"/api/v2/events?life_id=life-l3&follow=false", nil)
	reqSSE.AddCookie(sessCookie)
	recSSE := httptest.NewRecorder()
	svc.ServeHTTP(recSSE, reqSSE)
	if recSSE.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/events returned %d: %s", recSSE.Code, recSSE.Body.String())
	}
	if !strings.Contains(recSSE.Body.String(), `"end":true`) {
		t.Fatalf("expected terminating StreamFrame in SSE output, got %s", recSSE.Body.String())
	}

	// 10. Stale proof, digest mismatch, and idempotency conflict red controls
	staleProof := &api.ProofRef{
		ID:            "proof-stale-1",
		RequestSHA256: mailProof.RequestSHA256,
		ExpiresAt:     "2020-01-01T00:00:00Z",
	}
	recStale, _ := callRPC(sessCookie, origin, "mail.send", mailParams, staleProof, "idem-mail-stale")
	if recStale.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on stale proof, got %d", recStale.Code)
	}

	// (a) Changed bytes with the original proof (whose RequestSHA256 is for mailParams) must fail pre-lookup proof digest check with 403 forbidden
	otherMailParams := api.MailSendRequest{
		RecipientLifeID: "life-l3",
		Content:         mailBlob,
		Ask:             false,
	}
	recDigestMismatch, respDigestMismatch := callRPC(sessCookie, origin, "mail.send", otherMailParams, mailProof, "idem-mail-l3")
	if recDigestMismatch.Code != http.StatusForbidden || respDigestMismatch.Error == nil || respDigestMismatch.Error.Code != api.CodeForbidden {
		t.Fatalf("expected 403 forbidden on proof digest mismatch before replay lookup, got %d %+v", recDigestMismatch.Code, respDigestMismatch.Error)
	}

	// (b) Changed bytes with a proof matching the new bytes under the same idempotency_key "idem-mail-l3" must fail with 409 idempotency_conflict
	otherMailProof := getProof("mail.send", "life-l3", 0, otherMailParams)
	recConflict, respConflict := callRPC(sessCookie, origin, "mail.send", otherMailParams, otherMailProof, "idem-mail-l3")
	if recConflict.Code != http.StatusConflict || respConflict.Error == nil || respConflict.Error.Code != api.CodeIdempotencyConflict {
		t.Fatalf("expected 409 idempotency_conflict, got %d %+v", recConflict.Code, respConflict.Error)
	}

	// 11. Contract §3/§14: foreground activity within five minutes refreshes
	// idle expiry, while exactly five further idle minutes refuses.
	h.clock.Advance(4 * time.Minute)
	reqStillValid := httptest.NewRequest(http.MethodGet, origin+"/api/v2/tree", nil)
	reqStillValid.AddCookie(sessCookie)
	recStillValid := httptest.NewRecorder()
	svc.ServeHTTP(recStillValid, reqStillValid)
	if recStillValid.Code != http.StatusOK {
		t.Fatalf("expected 200 within the five-minute idle window, got %d", recStillValid.Code)
	}

	h.clock.Advance(5 * time.Minute)
	reqExpired := httptest.NewRequest(http.MethodGet, origin+"/api/v2/tree", nil)
	reqExpired.AddCookie(sessCookie)
	recExpired := httptest.NewRecorder()
	svc.ServeHTTP(recExpired, reqExpired)
	if recExpired.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 at the committed five-minute idle boundary, got %d", recExpired.Code)
	}
}

func TestPaginationAndCursorBinding(t *testing.T) {
	h := newMemHarness()
	svc, err := New(Dependencies{
		Store:     h,
		Transport: h,
		Human:     h.human(),
		Lifecycle: h,
		Messaging: h,
		Approval:  h,
		Clock:     h.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope, _, _ := h.establishVerifiedScope(t, svc, "cfg-dash")
	h.lanes["life-a"] = api.Lane{LifeID: "life-a", Name: "a", RootLifeID: "life-a", Level: 5, Role: "domain", State: "running", Run: 1, Session: api.Session{Driver: api.DriverClaudock}}
	h.lanes["life-b"] = api.Lane{LifeID: "life-b", Name: "b", RootLifeID: "life-a", ParentLifeID: "life-a", Level: 3, Role: "exec", State: "running", Run: 1, Session: api.Session{Driver: api.DriverCodex}}

	p1, err := svc.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Limit: 1})
	if err != nil || len(p1.Lanes) != 1 || p1.Cursor == "" {
		t.Fatalf("expected page 1 with 1 lane and cursor, got %+v err=%v", p1, err)
	}
	p2, err := svc.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Cursor: p1.Cursor, Limit: 1})
	if err != nil || len(p2.Lanes) != 1 || p2.Lanes[0].LifeID == p1.Lanes[0].LifeID {
		t.Fatalf("expected distinct page 2 lane, got %+v err=%v", p2, err)
	}

	// Cursor with incompatible filter must fail
	if _, err := svc.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Cursor: p1.Cursor, Level: 3, Limit: 1}); err == nil {
		t.Fatal("expected cursor with modified level filter to fail")
	}
	// Cursor from another view must fail
	if _, err := svc.DashboardTree(context.Background(), scope, api.DashboardQuery{Cursor: p1.Cursor, Limit: 1}); err == nil {
		t.Fatal("expected cursor from another view to fail")
	}
}

func TestDecisionProjectionAndStubFail(t *testing.T) {
	h := newMemHarness()
	svc, err := New(Dependencies{
		Store:     h,
		Transport: h,
		Human:     h.human(),
		Lifecycle: h,
		Messaging: h,
		Approval:  h,
		Clock:     h.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope, _, _ := h.establishVerifiedScope(t, svc, "cfg-dash")
	query := api.DashboardQuery{Limit: 50}

	supBlob := h.putBlob("blob-sup-page", "record", []byte(`{"schema":"laneboss.decision.v2","text":"Superseded outside page","effective_at":"2026-10-16T10:00:00Z","applies_to":{"levels":[],"roles":[],"project_ids":[],"life_ids":[]},"binding":true}`))
	actBlob := h.putBlob("blob-act-page", "record", []byte(`{"schema":"laneboss.decision.v2","text":"Active replacement decision","effective_at":"2026-10-16T11:00:00Z","applies_to":{"levels":[],"roles":[],"project_ids":[],"life_ids":[]},"binding":true}`))

	// Seed a record whose Record.Action on the page is still "add" (e.g. the superseding record is outside this page),
	// while TurnStore.Decision reports its projection status is "superseded".
	h.records["decisions"] = []api.Record{
		{
			ID:         "dec-superseded-1",
			Collection: "decisions",
			Content:    supBlob,
			Actor:      api.Actor{Kind: "human", ID: "human-1"},
			Origin:     "service",
			Action:     "add",
			RecordedAt: "2026-10-16T10:00:00Z",
			Generation: 1,
		},
		{
			ID:         "dec-active-1",
			Collection: "decisions",
			Content:    actBlob,
			Actor:      api.Actor{Kind: "human", ID: "human-1"},
			Origin:     "service",
			Action:     "add",
			RecordedAt: "2026-10-16T11:00:00Z",
			Generation: 1,
		},
	}

	// 1. When TurnStore.Decision returns not_implemented, DashboardDecisions must fail with CodeNotImplemented.
	h.mu.Lock()
	h.failDecision = api.NotImplemented("lb-v2-approval", "store.Decision")
	h.mu.Unlock()
	if _, err := svc.DashboardDecisions(context.Background(), scope, query); err == nil {
		t.Fatal("expected DashboardDecisions to fail when TurnStore.Decision returns not_implemented")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented {
			t.Fatalf("expected CodeNotImplemented from DashboardDecisions, got %v", err)
		}
	}

	// 2. When TurnStore.Decision returns not_found for a canonical decision record, DashboardDecisions must fail with CodeIntegrity.
	h.mu.Lock()
	h.failDecision = nil
	h.mu.Unlock()
	if _, err := svc.DashboardDecisions(context.Background(), scope, query); err == nil {
		t.Fatal("expected DashboardDecisions to fail when a canonical decision lacks a projection")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
			t.Fatalf("expected CodeIntegrity when projection is missing, got %v", err)
		}
	}

	// 3. Populate projections: dec-superseded-1 has Status="superseded", dec-active-1 has Status="active".
	// Even though dec-superseded-1 has Action="add" on the record page and no superseding record in the page,
	// it must never appear as active in DashboardDecisions.
	h.decisions["dec-superseded-1"] = api.DecisionProjection{
		RecordID: "dec-superseded-1",
		Status:   "superseded",
		Candidate: api.DecisionCandidate{
			ID:          "dec-superseded-1",
			Text:        "Superseded outside page",
			EffectiveAt: "2026-10-16T10:00:00Z",
			Binding:     true,
		},
	}
	h.decisions["dec-active-1"] = api.DecisionProjection{
		RecordID: "dec-active-1",
		Status:   "active",
		Candidate: api.DecisionCandidate{
			ID:          "dec-active-1",
			Text:        "Active replacement decision",
			EffectiveAt: "2026-10-16T11:00:00Z",
			Binding:     true,
		},
	}

	view, err := svc.DashboardDecisions(context.Background(), scope, query)
	if err != nil {
		t.Fatalf("DashboardDecisions failed: %v", err)
	}
	if len(view.Decisions) != 1 || view.Decisions[0].ID != "dec-active-1" {
		t.Fatalf("expected only dec-active-1 (superseded decision must be excluded), got %+v", view.Decisions)
	}
}

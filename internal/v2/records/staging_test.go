package records

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This models an already verified session. Every staging transaction still goes
// through the production ValidateTransactionShape and connection binding helper.
type readConnection struct {
	api.ConnectionContext
	id        api.ID
	binding   api.InstalledBinding
	authority api.ReadAuthority
	clock     api.Clock
	closed    bool
}

func (c *readConnection) ID() api.ID                    { return c.id }
func (c *readConnection) Conn() net.Conn                { return nil }
func (c *readConnection) Binding() api.InstalledBinding { return c.binding }
func (c *readConnection) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	if err := ctx.Err(); err != nil {
		return api.ReadAuthority{}, err
	}
	idle, err := time.Parse(time.RFC3339Nano, string(c.authority.IdleExpiresAt))
	if err != nil {
		return api.ReadAuthority{}, err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(c.authority.ExpiresAt))
	if err != nil {
		return api.ReadAuthority{}, err
	}
	if c.closed || !c.clock.Now().Before(idle) || !c.clock.Now().Before(expires) {
		return api.ReadAuthority{}, &api.Error{Code: api.CodeForbidden}
	}
	return c.authority, nil
}
func (c *readConnection) Close() error { c.closed = true; return nil }

func stagingConnection(clock api.Clock) *readConnection {
	return &readConnection{id: "human-connection", clock: clock,
		binding: api.InstalledBinding{Config: "demo", Class: api.EndpointHuman, EndpointGeneration: 1},
		authority: api.ReadAuthority{ConnectionID: "human-connection", SessionID: "verified-session", CredentialID: "enrolled-key",
			PrincipalID: "human-one", Config: "demo", EndpointGeneration: 1,
			IdleExpiresAt: api.Timestamp(clock.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)),
			ExpiresAt:     api.Timestamp(clock.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339Nano))}}
}

func (m *memoryStore) uploadTransaction(ctx context.Context, tx api.Transaction, requestKey api.RequestKey, key receiptDomain) (api.Commit, error) {
	// The fixture has no write lock. Real store code validates the session from
	// its current transaction plus transport state, without a transport callback
	// under that lock. This extra check also exercises expiry/closed sessions.
	current, err := api.WithReadAuthority(ctx, tx.Scope)
	if err != nil {
		return api.Commit{}, err
	}
	if *current.ReadAuthority != *tx.Scope.ReadAuthority {
		return api.Commit{}, integrity("staging authority changed")
	}
	switch tx.Scope.Request.Method {
	case "blob.begin":
		var request api.BlobBeginRequest
		if err := api.DecodeObject(tx.Scope.Request.Params, &request); err != nil {
			return api.Commit{}, err
		}
		if len(tx.Writes.UploadBegins) != 1 {
			return api.Commit{}, integrity("missing upload lease")
		}
		lease := tx.Writes.UploadBegins[0]
		if lease.ACL.Config != tx.Scope.Config || lease.ACL.Owner != tx.Scope.Actor || lease.DeclaredBytes != request.Bytes || lease.SHA256 != request.SHA256 || lease.Class != request.Class {
			return api.Commit{}, integrity("upload lease differs from request")
		}
		m.uploads[lease.ID] = lease
	case "blob.chunk":
		if len(tx.Writes.UploadChunks) != 1 {
			return api.Commit{}, integrity("missing upload bytes")
		}
		chunk := tx.Writes.UploadChunks[0]
		lease, found := m.uploads[chunk.ObjectID]
		sum := sha256.Sum256(chunk.Data)
		if !found || lease.ACL.Owner != tx.Scope.Actor || lease.ACL.Config != tx.Scope.Config || chunk.Offset != int64(len(m.blobs[chunk.ObjectID])) || chunk.SHA256 != api.Digest(hex.EncodeToString(sum[:])) || chunk.Offset+int64(len(chunk.Data)) > lease.DeclaredBytes {
			return api.Commit{}, integrity("invalid scoped upload chunk")
		}
		m.blobs[chunk.ObjectID] = append(m.blobs[chunk.ObjectID], chunk.Data...)
	case "blob.commit":
		if len(tx.Writes.UploadCommits) != 1 {
			return api.Commit{}, integrity("missing upload commit")
		}
		request := tx.Writes.UploadCommits[0]
		lease, found := m.uploads[request.ObjectID]
		data := m.blobs[request.ObjectID]
		sum := sha256.Sum256(data)
		if !found || lease.ACL.Owner != tx.Scope.Actor || lease.ACL.Config != tx.Scope.Config || int64(len(data)) != lease.DeclaredBytes || request.SHA256 != lease.SHA256 || request.SHA256 != api.Digest(hex.EncodeToString(sum[:])) {
			return api.Commit{}, integrity("unverified upload content")
		}
		ref := api.BlobRef{ID: request.ObjectID, Class: lease.Class, Bytes: int64(len(data)), SHA256: request.SHA256}
		var reply api.BlobRef
		if err := api.DecodeObject(tx.Reply.Result, &reply); err != nil || reply != ref {
			return api.Commit{}, integrity("upload reply differs from committed bytes")
		}
		var eventRef api.BlobRef
		if len(tx.Events) != 1 || tx.Events[0].Kind != "blob.committed" {
			return api.Commit{}, integrity("missing committed upload event")
		}
		if err := api.DecodeObject(tx.Events[0].Payload, &eventRef); err != nil || eventRef != ref {
			return api.Commit{}, integrity("upload event differs from committed bytes")
		}
		m.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, ACL: lease.ACL, Origin: "upload"}
	}
	m.commits++
	for _, event := range tx.Events {
		event.Seq = api.Sequence(len(m.events) + 1)
		m.events = append(m.events, event)
	}
	commit := api.Commit{Operation: api.Operation{ID: stableID(tx.Scope, "operation"), Status: "succeeded"}, Reply: tx.Reply}
	m.receipts[key] = api.MutationReceipt{Config: tx.Scope.Config, Actor: tx.Scope.Actor, Key: requestKey, Operation: commit.Operation, Reply: commit.Reply}
	return commit, nil
}

func TestHumanStagingAndAppend(t *testing.T) {
	service, state, clock := fixture(t)
	connection := stagingConnection(clock)
	data := []byte("Human-authored content staged before exact approval")
	sum := sha256.Sum256(data)
	hash := api.Digest(hex.EncodeToString(sum[:]))
	lease := api.UploadLease{ID: "upload-one", Class: "record", DeclaredBytes: int64(len(data)), SHA256: hash,
		ACL: api.ObjectACL{Config: "demo", Owner: api.Actor{Kind: "human", ID: "human-one"}}, ExpiresAt: connection.authority.ExpiresAt}
	ref := api.BlobRef{ID: lease.ID, Class: lease.Class, Bytes: lease.DeclaredBytes, SHA256: hash}
	for _, row := range []struct {
		method api.Method
		params any
		writes api.StateWrites
		reply  any
	}{
		{"blob.begin", api.BlobBeginRequest{Class: lease.Class, Bytes: lease.DeclaredBytes, SHA256: hash}, api.StateWrites{UploadBegins: []api.UploadLease{lease}}, api.BlobUpload{ObjectID: lease.ID, MaxChunkBytes: api.MaxChunkBytes, ExpiresAt: lease.ExpiresAt}},
		{"blob.chunk", api.BlobChunk{ObjectID: lease.ID, Data: data, SHA256: hash}, api.StateWrites{UploadChunks: []api.BlobChunk{{ObjectID: lease.ID, Data: data, SHA256: hash}}}, api.BlobUpload{ObjectID: lease.ID, MaxChunkBytes: api.MaxChunkBytes, ExpiresAt: lease.ExpiresAt}},
		{"blob.commit", api.BlobCommitRequest{ObjectID: lease.ID, SHA256: hash}, api.StateWrites{UploadCommits: []api.BlobCommitRequest{{ObjectID: lease.ID, SHA256: hash}}}, ref},
	} {
		scope := scopeFor(t, row.method, row.params, "retained-staging-request-"+string(row.method[5:]), true)
		scope.Request.Proof, scope.Connection, scope.EndpointGeneration = nil, connection, 1
		bound, err := api.WithReadAuthority(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(row.reply)
		if err != nil {
			t.Fatal(err)
		}
		tx := api.Transaction{Scope: bound, Writes: row.writes, Reply: &api.RPCReply{Result: raw}}
		if row.method == "blob.commit" {
			tx.Events = []api.Event{{Schema: api.SchemaVersion, ID: stableID(bound, "blob-event"), Config: bound.Config, Kind: "blob.committed", Actor: bound.Actor, Payload: raw}}
		}
		_, err = state.Transact(context.Background(), tx)
		if err != nil {
			t.Fatalf("verified human staging required an operation proof: %v", err)
		}
	}
	appendRequest := api.RecordAppendRequest{Collection: "observations", Content: ref, RelatedIDs: []api.ID{}}
	scope := scopeFor(t, "records.append", appendRequest, "approved-record", true)
	scope.Connection, scope.EndpointGeneration = connection, 1
	withoutProof := scope
	withoutProof.Request.Proof = nil
	_, err := service.RecordsAppend(context.Background(), withoutProof, appendRequest)
	requireCode(t, err, api.CodeForbidden)
	record, err := service.RecordsAppend(context.Background(), scope, appendRequest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.RecordsGet(context.Background(), scope, api.RecordGetRequest{RecordID: record.ID})
	if err != nil || !reflect.DeepEqual(got, record) || record.Content != ref || !bytes.Equal(state.blobs[ref.ID], data) || state.proofUses != 1 || state.commits != 4 || len(state.events) != 2 || state.events[0].Kind != "blob.committed" || state.events[1].Kind != "record.appended" {
		t.Fatal("staging/append lost bytes, guard or single-proof accounting")
	}
}

func TestStagingSessionBinding(t *testing.T) {
	_, _, clock := fixture(t)
	connection := stagingConnection(clock)
	raw, err := json.Marshal(api.BlobUpload{ObjectID: "upload"})
	if err != nil {
		t.Fatal(err)
	}
	scope := scopeFor(t, "blob.begin", api.BlobBeginRequest{Class: "record", Bytes: 1, SHA256: "digest"}, "staging", true)
	scope.Request.Proof, scope.Connection, scope.EndpointGeneration = nil, connection, 1
	bound, err := api.WithReadAuthority(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	base := api.Transaction{Scope: bound, Reply: &api.RPCReply{Result: raw}}
	if err := api.ValidateTransactionShape(base); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*api.Scope){
		"lane":            func(s *api.Scope) { s.Actor = api.Actor{Kind: "lane", ID: "lane", LifeID: "life", Level: 3} },
		"missing_session": func(s *api.Scope) { s.ReadAuthority = nil },
		"other_principal": func(s *api.Scope) { s.Actor.ID = "human-two" },
		"other_endpoint":  func(s *api.Scope) { s.EndpointGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := base
			change(&bad.Scope)
			if api.ValidateTransactionShape(bad) == nil {
				t.Fatal("staging borrowed unrelated human authority")
			}
		})
	}
	connection.closed = true
	if _, err := api.WithReadAuthority(context.Background(), scope); err == nil {
		t.Fatal("closed connection retained read authority")
	}
	connection.closed = false
	clock.now = clock.now.Add(6 * time.Minute)
	if _, err := api.WithReadAuthority(context.Background(), scope); err == nil {
		t.Fatal("expired session retained staging authority")
	}
}

func TestHumanPreviewSession(t *testing.T) {
	_, _, clock := fixture(t)
	connection := stagingConnection(clock)
	for method, reply := range map[api.Method]any{
		"policy.evaluate": api.PolicyDecision{Rules: []api.RuleDecision{}},
		"guidance.select": api.Guidance{Items: []api.GuidanceItem{}, JudgmentIDs: []api.ID{}},
		"judge.ask":       api.JudgeReply{Results: []api.Judgment{}},
		"secret.stage":    api.SecretStage{},
	} {
		t.Run(string(method), func(t *testing.T) {
			scope := api.Scope{Config: "demo", Actor: api.Actor{Kind: "human", ID: "human-one"}, Connection: connection, EndpointGeneration: 1, Request: api.Request{Method: method}}
			bound, err := api.WithReadAuthority(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(reply)
			if err != nil {
				t.Fatal(err)
			}
			if err := api.ValidateTransactionShape(api.Transaction{Scope: bound, Reply: &api.RPCReply{Result: raw}}); err != nil {
				t.Fatalf("verified human preview required a mutation proof: %v", err)
			}
		})
	}
}

func stagingAuthorityTransaction(t *testing.T, method api.Method, human bool) api.Transaction {
	t.Helper()
	_, _, clock := fixture(t)
	connection := stagingConnection(clock)
	scope := api.Scope{Config: "demo", Actor: api.Actor{Kind: "lane", ID: "lane", LifeID: "life", Level: 3},
		Request: api.Request{Method: method}, EndpointGeneration: 1}
	if human {
		scope.Actor, scope.Connection = api.Actor{Kind: "human", ID: "human-one"}, connection
		if api.HumanSessionMethod(method) {
			var err error
			scope, err = api.WithReadAuthority(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	tx := api.Transaction{Scope: scope}
	var reply any
	acl := api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "private", Generation: 1}
	switch method {
	case "blob.begin":
		reply = api.BlobUpload{ObjectID: "upload"}
		tx.Writes.UploadBegins = []api.UploadLease{{ID: "upload", ACL: acl}}
	case "blob.commit":
		reply = api.BlobRef{ID: "upload", Class: "record"}
		tx.Writes.Objects = []api.ObjectWrite{{ObjectKey: "upload", ACL: acl}}
	case "secret.stage":
		reply = api.SecretStage{}
	case "human.challenge":
		reply = api.HumanChallenge{Challenge: []byte{}}
	default:
		t.Fatal("unknown staging authority fixture method")
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	tx.Reply = &api.RPCReply{Result: raw}
	return tx
}

func TestStagingAuthority(t *testing.T) {
	for method, human := range map[api.Method]bool{"blob.begin": false, "blob.commit": false, "secret.stage": true, "human.challenge": true} {
		if err := api.ValidateTransactionShape(stagingAuthorityTransaction(t, method, human)); err != nil {
			t.Fatalf("authentic staging authority was refused: %v", err)
		}
	}
	for name, makeInvalid := range map[string]func() api.Transaction{
		"lane_secret":    func() api.Transaction { return stagingAuthorityTransaction(t, "secret.stage", false) },
		"lane_challenge": func() api.Transaction { return stagingAuthorityTransaction(t, "human.challenge", false) },
		"session_proof": func() api.Transaction {
			tx := stagingAuthorityTransaction(t, "secret.stage", true)
			tx.Guards = []api.TransactionGuard{{Proof: &api.ProofUse{}}}
			return tx
		},
		"session_ticket": func() api.Transaction {
			tx := stagingAuthorityTransaction(t, "secret.stage", true)
			tx.Guards = []api.TransactionGuard{{Ticket: &api.TicketUse{TicketID: "ticket", PrincipalID: tx.Scope.Actor.ID, Config: tx.Scope.Config, EndpointGeneration: tx.Scope.EndpointGeneration}}}
			return tx
		},
		"session_approval": func() api.Transaction {
			tx := stagingAuthorityTransaction(t, "secret.stage", true)
			tx.Guards = []api.TransactionGuard{{Approval: &api.ApprovalUse{}}}
			return tx
		},
		"begin_owner": func() api.Transaction {
			tx := stagingAuthorityTransaction(t, "blob.begin", false)
			tx.Writes.UploadBegins[0].ACL.Owner = api.Actor{Kind: "human", ID: "other-principal"}
			return tx
		},
		"begin_config": func() api.Transaction {
			tx := stagingAuthorityTransaction(t, "blob.begin", false)
			tx.Writes.UploadBegins[0].ACL.Config = "other-config"
			return tx
		},
		"commit_owner": func() api.Transaction {
			tx := stagingAuthorityTransaction(t, "blob.commit", false)
			tx.Writes.Objects[0].ACL.Owner = api.Actor{Kind: "human", ID: "other-principal"}
			return tx
		},
		"commit_config": func() api.Transaction {
			tx := stagingAuthorityTransaction(t, "blob.commit", false)
			tx.Writes.Objects[0].ACL.Config = "other-config"
			return tx
		},
	} {
		t.Run(name, func(t *testing.T) {
			var typed *api.Error
			if err := api.ValidateTransactionShape(makeInvalid()); !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
				t.Fatalf("foreign staging authority or guard was accepted: %v", err)
			}
		})
	}
}

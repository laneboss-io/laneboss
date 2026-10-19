package grants

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// These connection/proof fixtures model verified identity state, not a human
// authentication ceremony. Altered state must be rejected by the consumer.
type humanPeer struct {
	api.VerifiedPeer
	alive bool
}

func (p *humanPeer) Alive(context.Context) error {
	if !p.alive {
		return refused("fixture peer ended")
	}
	return nil
}

type humanConnection struct {
	api.ConnectionContext
	binding   api.InstalledBinding
	authority api.ReadAuthority
	peer      *humanPeer
	id        api.ID
}

func (c *humanConnection) ID() api.ID                    { return c.id }
func (c *humanConnection) Binding() api.InstalledBinding { return c.binding }
func (c *humanConnection) Peer() api.VerifiedPeer        { return c.peer }
func (c *humanConnection) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	if err := c.peer.Alive(ctx); err != nil {
		return api.ReadAuthority{}, err
	}
	return c.authority, nil
}

type humanFrame struct {
	raw        []byte
	connection api.ConnectionContext
	verified   int
}

func (f *humanFrame) Bytes() []byte { return append([]byte(nil), f.raw...) }
func (f *humanFrame) Verify(ctx context.Context, connection api.ConnectionContext) error {
	f.verified++
	if connection != f.connection {
		return refused("fixture frame belongs to another connection")
	}
	return connection.Peer().Alive(ctx)
}

type humanVerifier struct {
	api.HumanVerifier
	proofs map[api.ID]api.VerifiedHumanProof
	calls  int
}

func (v *humanVerifier) CheckProof(_ context.Context, _ api.Scope, ref api.ProofRef, _ api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	v.calls++
	proof, found := v.proofs[ref.ID]
	if !found {
		return api.VerifiedHumanProof{}, refused("fixture proof was never verified")
	}
	return proof, nil
}

func humanScope(t *testing.T, f *fixture, method api.Method, input any) api.Scope {
	t.Helper()
	expiry := api.Timestamp("2030-01-01T02:00:00Z")
	connection := &humanConnection{id: "human-connection", peer: &humanPeer{alive: true},
		binding: api.InstalledBinding{ContractRevision: api.ContractRevision, Class: api.EndpointHuman,
			Config: f.scope.Config, EndpointGeneration: 1},
		authority: api.ReadAuthority{SessionID: "read-session", PrincipalID: "human", CredentialID: "human-key",
			Config: f.scope.Config, EndpointGeneration: 1, ExpiresAt: expiry, IdleExpiresAt: expiry}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.scope.Config,
		Method: method, Params: raw, RequestID: "0123456789abcdef0123456789abcdef",
		IdempotencyKey: "abcdef0123456789abcdef0123456789"}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Proof = &api.ProofRef{ID: "human-proof", RequestSHA256: request.RequestSHA256, ExpiresAt: expiry}
	framed, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	f.store.target = api.HumanChallengeRequest{Method: method, TargetID: "target", RequestSHA256: request.RequestSHA256, BaseGeneration: 1}
	verified := api.VerifiedHumanProof{Ref: *request.Proof, Config: f.scope.Config, PrincipalID: "human",
		CredentialID: "human-key", NonceID: "nonce", Target: f.store.target,
		EndpointClass: api.EndpointHuman, EndpointGeneration: 1, ConnectionID: connection.id}
	f.service.deps.Human = &humanVerifier{proofs: map[api.ID]api.VerifiedHumanProof{verified.Ref.ID: verified}}
	return api.Scope{Config: f.scope.Config, Actor: api.Actor{Kind: "human", ID: "human"},
		Connection: connection, Frame: &humanFrame{raw: framed, connection: connection}, Request: request,
		EndpointGeneration: 1, PolicyGeneration: 1}
}

func TestHumanReadAuthority(t *testing.T) {
	for _, item := range []struct {
		name   string
		mutate func(api.Scope) api.Scope
	}{
		{"connection", func(s api.Scope) api.Scope { s.Connection = nil; return s }},
		{"class", func(s api.Scope) api.Scope {
			s.Connection.(*humanConnection).binding.Class = api.EndpointLane
			return s
		}},
		{"principal", func(s api.Scope) api.Scope { s.Connection.(*humanConnection).authority.PrincipalID = "other"; return s }},
		{"config", func(s api.Scope) api.Scope { s.Connection.(*humanConnection).authority.Config = "other"; return s }},
		{"endpoint", func(s api.Scope) api.Scope { s.Connection.(*humanConnection).authority.EndpointGeneration++; return s }},
		{"expired", func(s api.Scope) api.Scope {
			s.Connection.(*humanConnection).authority.ExpiresAt = "2029-01-01T00:00:00Z"
			return s
		}},
		{"idle", func(s api.Scope) api.Scope {
			s.Connection.(*humanConnection).authority.IdleExpiresAt = "2029-01-01T00:00:00Z"
			return s
		}},
		{"ended", func(s api.Scope) api.Scope { s.Connection.(*humanConnection).peer.alive = false; return s }},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			scope := humanScope(t, f, "grants.get", api.GrantGetRequest{GrantSetID: "parent-set"})
			if _, err := f.service.GrantsGet(context.Background(), scope, api.GrantGetRequest{GrantSetID: "parent-set"}); err != nil {
				t.Fatal("human read control failed", err)
			}
			scope = item.mutate(scope)
			_, err := f.service.GrantsGet(context.Background(), scope, api.GrantGetRequest{GrantSetID: "parent-set"})
			expectCode(t, err, api.CodeForbidden)
		})
	}
}

func TestHumanMutationProof(t *testing.T) {
	for _, name := range []string{"missing", "digest", "expired", "principal", "consumed", "target", "unverified", "frame"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			request := f.testRequest(child)
			scope := humanScope(t, f, "grants.test-child", request)
			if _, err := f.service.BoundChildTest(context.Background(), scope, request); err != nil {
				t.Fatal("verified human proof control failed", err)
			}
			verifier := f.service.deps.Human.(*humanVerifier)
			proof := verifier.proofs[scope.Request.Proof.ID]
			switch name {
			case "missing":
				scope.Request.Proof = nil
			case "digest":
				scope.Request.RequestSHA256 = manifest.Hash([]byte("different"))
			case "expired":
				scope.Request.Proof.ExpiresAt = "2029-01-01T00:00:00Z"
			case "principal":
				proof.PrincipalID = "other"
			case "consumed":
				proof.ConsumedBy = "old-operation"
			case "target":
				proof.Target.TargetID = "other"
			case "unverified":
				delete(verifier.proofs, proof.Ref.ID)
			case "frame":
				scope.Frame.(*humanFrame).connection = &humanConnection{id: "other"}
			}
			if name == "expired" {
				proof.Ref = *scope.Request.Proof
			}
			if name != "unverified" {
				verifier.proofs[proof.Ref.ID] = proof
			}
			framed, err := json.Marshal(scope.Request)
			if err != nil {
				t.Fatal(err)
			}
			scope.Frame.(*humanFrame).raw = framed
			_, err = f.service.GrantsTestChild(context.Background(), scope, request)
			expectCode(t, err, api.CodeForbidden)
			if f.worker.testCalls != 0 || f.store.transactions != 0 {
				t.Fatal("unverified human proof dispatched a child job")
			}
		})
	}
}

func TestHumanWorkerGuard(t *testing.T) {
	f := newFixture(t)
	child := f.child()
	request := f.testRequest(child)
	scope := humanScope(t, f, "grants.test-child", request)
	_, err := f.service.GrantsTestChild(context.Background(), scope, request)
	expectCode(t, err, api.CodeNotImplemented)
	call := f.worker.testCall
	if f.worker.testCalls != 1 || f.store.transactions != 0 || !reflect.DeepEqual(call.Scope, scope) || len(call.Guards) != 1 ||
		call.Guards[0].Proof == nil || call.Guards[0].Proof.Proof != *scope.Request.Proof || call.Guards[0].Proof.Target != f.store.target {
		t.Fatal("human job lost its exact native frame or atomic proof guard")
	}
}

func rootFixture(t *testing.T, f *fixture) api.RootGrantRequest {
	t.Helper()
	data := clone(t, f.store.sets["parent-set"].Data)
	for i := range data {
		data[i].ID, data[i].ParentGrantID = "", ""
	}
	input := api.RootGrantManifest{Schema: "laneboss.root-grants.v2", Data: data,
		Resources: []api.ResourceGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{},
		Channels: []api.ChannelGrant{}, Secrets: []api.SecretGrant{}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "root-input", SHA256: manifest.Hash(raw), Bytes: int64(len(raw)), Class: "manifest"}
	f.store.blobs[ref.ID] = raw
	f.store.retain(ref)
	return api.RootGrantRequest{Manifest: ref, Budget: api.Budget{WallMS: 1000, MemoryBytes: 4096, Processes: 2, DiskBytes: 8192, Currency: "USD"}}
}

func TestRootAtomicIssue(t *testing.T) {
	for _, boundary := range []string{"proof", "writes"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t)
			request := rootFixture(t, f)
			scope := humanScope(t, f, "grants.root", request)
			var committed api.GrantSet
			f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
				if boundary == "proof" && (len(tx.Guards) != 1 || tx.Guards[0].Proof == nil || tx.Guards[0].Proof.Proof != *scope.Request.Proof || tx.Guards[0].Proof.Target != f.store.target) {
					t.Fatal("root proof guard missing or changed")
				}
				if boundary == "writes" && (len(tx.Writes.Grants) != 1 || len(tx.Compare) != 2 || len(tx.Events) != 1 || tx.Events[0].Kind != "grants.issued" || !reflect.DeepEqual(tx.RawRequest, scope.Frame.Bytes())) {
					t.Fatal("root grant transaction lost its exact state or request")
				}
				if err := api.ValidateTransactionShape(tx); err != nil {
					t.Fatal("invalid root transaction", err)
				}
				if len(tx.Writes.Grants) != 1 {
					t.Fatal("root fixture lacks its committed grant")
				}
				committed = tx.Writes.Grants[0]
				f.store.sets[committed.ID] = committed
				id, err := freshID()
				if err != nil {
					t.Fatal(err)
				}
				return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: id, Status: "succeeded", FirstSeq: 1, LastSeq: 1}, FirstSeq: 1, LastSeq: 1}, nil
			}
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			if err != nil {
				t.Fatal("root issuance failed", err)
			}
			if !reflect.DeepEqual(result, committed) || f.store.transactions != 1 || result.Data[0].ID == "" || result.Data[0].SourceObjectID != "source-tree" {
				t.Fatal("root issuance returned uncommitted or substituted authority")
			}
		})
	}
}
func TestRootDurableReceipt(t *testing.T) {
	for _, name := range []string{"pending", "reply", "substituted"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := rootFixture(t, f)
			scope := humanScope(t, f, "grants.root", request)
			f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
				id, err := freshID()
				if err != nil {
					t.Fatal(err)
				}
				commit := api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: id, Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}
				switch name {
				case "pending":
					commit.Operation.Status = "pending"
				case "reply":
					commit.Reply = nil
				case "substituted":
					changed := clone(t, tx.Writes.Grants[0])
					changed.Data[0].SourceObjectID = "different"
					raw, err := json.Marshal(changed)
					if err != nil {
						t.Fatal(err)
					}
					commit.Reply = &api.RPCReply{Result: raw}
				}
				return commit, nil
			}
			_, err := f.service.GrantsRoot(context.Background(), scope, request)
			expectCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestRootChannelEnrollment(t *testing.T) {
	for _, name := range []string{"valid", "identity", "config", "generation", "revoked", "expiry"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := rootFixture(t, f)
			var input api.RootGrantManifest
			if err := json.Unmarshal(f.store.blobs[request.Manifest.ID], &input); err != nil {
				t.Fatal(err)
			}
			input.Channels = []api.ChannelGrant{{ChannelID: "enrolled-channel", Delegate: true, ExpiresAt: "2030-01-01T04:00:00Z"}}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			f.store.blobs[request.Manifest.ID] = raw
			request.Manifest.SHA256, request.Manifest.Bytes = manifest.Hash(raw), int64(len(raw))
			f.store.retain(request.Manifest)
			channel := api.EnrolledChannel{ID: "enrolled-channel", Config: f.scope.Config, Generation: 1, ExpiresAt: "2030-01-01T04:00:00Z"}
			switch name {
			case "identity":
				channel.ID = "other"
			case "config":
				channel.Config = "other"
			case "generation":
				channel.Generation = 0
			case "revoked":
				channel.Revoked = true
			case "expiry":
				channel.ExpiresAt = "2030-01-01T03:00:00Z"
			}
			f.store.channels = map[api.ID]api.EnrolledChannel{"enrolled-channel": channel}
			scope := humanScope(t, f, "grants.root", request)
			f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
				if err := api.ValidateTransactionShape(tx); err != nil {
					t.Fatal(err)
				}
				for _, set := range tx.Writes.Grants {
					f.store.sets[set.ID] = set
				}
				return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: "channel-operation", Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
			}
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			if name == "valid" {
				if err != nil || len(result.Channels) != 1 || result.Channels[0].ID == "" || result.Channels[0].ChannelID != channel.ID || f.store.transactions != 1 {
					t.Fatal("enrolled channel issuance failed", err)
				}
			} else {
				expectCode(t, err, api.CodeForbidden)
				if f.store.transactions != 0 {
					t.Fatal("invalid root channel reached a transaction")
				}
			}
		})
	}
}

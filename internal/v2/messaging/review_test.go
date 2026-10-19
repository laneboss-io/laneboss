package messaging

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func humanSend(t *testing.T, f *fixture, request api.MailSendRequest) api.Mail {
	t.Helper()
	scope := f.scope(t, "reviewer", "mail.send", request)
	scope.Request.Proof = &api.ProofRef{ID: randomID(t), RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	f.confirmProof(t, scope)
	mail, err := f.service.MailSend(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	return mail
}

func TestHumanReplyLinks(t *testing.T) {
	f := newFixture(t)
	prior := f.send(t, "a3", "a4")
	answer := humanSend(t, f, api.MailSendRequest{RecipientLifeID: "a3", ReplyTo: prior.ID, Content: f.blob(t, []byte("Human reply to direct report\n"))})
	if answer.ReplyTo != prior.ID || answer.RecipientLifeID != "a3" || answer.Sender.Kind != "human" {
		t.Fatal("human reply to an L3 report lost its linkage")
	}
	question := humanSend(t, f, api.MailSendRequest{RecipientLifeID: "a5", Content: f.blob(t, []byte("Human question for supervisor\n"))})
	request := api.MailSendRequest{ChannelGrantID: "granted-channel", ReplyTo: question.ID, Content: f.blob(t, []byte("Reply validation before worker delivery\n"))}
	if err := f.service.reply(context.Background(), f.scope(t, "a5", "mail.send", request), request); err != nil {
		t.Fatalf("lane reply to its human sender was refused: %v", err)
	}
	wrong := f.send(t, "a5", "b5")
	request.ReplyTo = wrong.ID
	wantCode(t, f.service.reply(context.Background(), f.scope(t, "a5", "mail.send", request), request), api.CodeForbidden)
	request.ReplyTo = question.ID
	wantCode(t, f.service.reply(context.Background(), f.scope(t, "root", "mail.send", request), request), api.CodeNotFound)
}

func TestQueuedProvenance(t *testing.T) {
	f := newFixture(t)
	mail := f.send(t, "a3", "peer3")
	from, event := f.store.lanes["a3"], f.store.events[0]
	if event.LifeID != from.LifeID || event.Run != from.Run || event.StarterEventSeq != from.StarterEventSeq || event.ParentLifeID != from.ParentLifeID || !reflect.DeepEqual(event.StarterChain, from.StarterChain) {
		t.Fatal("queued event lost its authentic sending-life provenance")
	}
	var kept api.Mail
	if err := json.Unmarshal(event.Payload, &kept); err != nil || kept.RecipientLifeID != mail.RecipientLifeID {
		t.Fatal("queue provenance changed its immutable destination")
	}
	intent := f.store.effects[0].Context
	if intent.Actor.Kind != "service" || intent.Actor.ID != "mail-delivery" || intent.Actor.LifeID != "" || intent.RequestedBy != mail.Sender {
		t.Fatal("internal delivery borrowed the public caller's actor")
	}
}

type preflightStore struct{ api.StateStore }

func (s preflightStore) Relation(context.Context, api.Scope, api.ID) (api.RelationFacts, error) {
	return api.RelationFacts{}, problem(api.CodeUnavailable, "fixture target preflight is unavailable")
}

func TestReplayOrderAndAuthority(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Receipt precedes target preflight\n"))}
	scope := f.scope(t, "a3", "mail.send", request)
	first, err := f.service.MailSend(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	f.service.deps.Store = preflightStore{StateStore: f.store}
	second, err := f.service.MailSend(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("receipt lookup order broke: %v", err)
	}
	f.store.receiptError = problem(api.CodeForbidden, "fixture receipt visibility revoked")
	_, err = f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeForbidden)
	f.store.receiptError = nil
	grants := f.store.grants[f.store.lanes[scope.Actor.LifeID].GrantSetID]
	grants.Revoked = true
	f.store.grants[grants.ID] = grants
	_, err = f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeForbidden)
}

func TestHumanMailboxBoundary(t *testing.T) {
	for _, cell := range []string{"ready", "filter", "proof", "foreign-session", "closed"} {
		t.Run(cell, func(t *testing.T) {
			f := newFixture(t)
			mail := f.send(t, "a3", "peer3")
			request := api.ListRequest{LifeID: "a3", Limit: 200}
			scope := f.bindScope(t, f.scope(t, "reviewer", "mail.list", request))
			connection := scope.Connection.(*boundConnection)
			service, err := New(Dependencies{Store: f.store, Clock: f.clock})
			if err != nil {
				t.Fatal(err)
			}
			switch cell {
			case "filter":
				other := f.send(t, "a5", "b5")
				f.store.leak = &other
			case "proof":
				scope.Request.Proof = &api.ProofRef{ID: randomID(t), RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
				raw, err := json.Marshal(scope.Request)
				if err != nil {
					t.Fatal(err)
				}
				scope.Frame = boundFrame{raw: raw, connection: connection.id}
			case "foreign-session":
				connection.authority.ConnectionID = randomID(t)
			case "closed":
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
			}
			page, err := service.MailList(context.Background(), scope, request)
			if cell == "ready" {
				if err != nil || len(page.Messages) != 1 || page.Messages[0].ID != mail.ID {
					t.Fatalf("verified human mailbox failed: %v", err)
				}
				return
			}
			code := api.CodeForbidden
			if cell == "filter" {
				code = api.CodeIntegrity
			}
			wantCode(t, err, code)
		})
	}
}

func TestSharedCredentialScreen(t *testing.T) {
	for _, input := range []string{"api_key=:disposableValue123", "APİ_KEY=disposableValue123", "Authorızation: Bearer " + strings.Repeat("a1", 16)} {
		wantCode(t, CheckContent([]byte(input)), api.CodeInvalid)
	}
	if err := CheckContent([]byte("api_key=${GRANTED_KEY}\n")); err != nil {
		t.Fatalf("credential reference was refused: %v", err)
	}
}

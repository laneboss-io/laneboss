package templates_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestOwnLifeClaimsBeforeSelectedReads(t *testing.T) {
	for _, kind := range []string{"lane", "worker"} {
		for _, method := range []api.Method{"brief.render", "lane.start"} {
			t.Run(kind+"/"+strings.ReplaceAll(string(method), ".", "-"), func(t *testing.T) {
				service, store, _, scope, request := component(t)
				scope.Actor.Kind, scope.Request.Method = kind, method
				request.GrantSetID = "foreign-grants"
				result, err := service.BriefRender(context.Background(), scope, request)
				if err == nil || result.Markdown.ID != "" || len(store.inputRequests) != 0 ||
					len(store.reads) != 0 || store.sourceCalls != 0 || store.metadataCalls != 0 ||
					len(store.retained) != 0 || store.writes != 0 || store.receiptCalls != 0 {
					t.Fatal("foreign grant claim reached selected briefing inputs or objects")
				}
				errorCode(t, err, api.CodeForbidden)
				if len(store.laneRequests) != 1 || store.laneRequests[0].LifeID != scope.Actor.LifeID {
					t.Fatal("grant claim selected a life instead of resolving the authenticated life")
				}
			})
		}
		t.Run(kind+"/start", func(t *testing.T) {
			service, store, _, scope, _ := component(t)
			scope.Actor.Kind = kind
			result, err := service.BriefStart(context.Background(), scope, api.BriefingRequest{
				Level: scope.Actor.Level, Role: scope.Actor.Role, LifeID: "foreign-life"})
			if err == nil || result.Markdown.ID != "" || len(store.inputRequests) != 0 ||
				len(store.reads) != 0 || store.sourceCalls != 0 || store.metadataCalls != 0 || len(store.retained) != 0 {
				t.Fatal("foreign life claim reached selected briefing inputs or objects")
			}
			errorCode(t, err, api.CodeForbidden)
		})
	}
}

func TestOwnLifeBriefings(t *testing.T) {
	for _, kind := range []string{"lane", "worker"} {
		t.Run(kind, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			scope.Actor.Kind = kind
			rendered, err := service.BriefRender(context.Background(), scope, request)
			if err != nil {
				t.Fatalf("authenticated own-life render refused: %v", err)
			}
			started, err := service.BriefStart(context.Background(), scope, api.BriefingRequest{
				Level: scope.Actor.Level, Role: scope.Actor.Role})
			if err != nil {
				t.Fatalf("authenticated own-life start refused: %v", err)
			}
			if rendered.Markdown.ID == "" || started.Markdown.ID == "" || len(store.inputRequests) != 2 ||
				store.inputRequests[0].LifeID != scope.Actor.LifeID || store.inputRequests[1].LifeID != scope.Actor.LifeID ||
				len(store.retained) != 2 || store.writes != 0 {
				t.Fatal("own-life render lost its authentic selector, output or read-only behavior")
			}
		})
	}
}

func TestWorkerRoleClaimsBeforeSelectedReads(t *testing.T) {
	for _, field := range []string{"role", "level"} {
		t.Run(field, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			scope.Actor.Kind = "worker"
			if field == "role" {
				request.Context.Role = "supervisor"
			} else {
				request.Context.Level = 5
			}
			result, err := service.BriefRender(context.Background(), scope, request)
			if err == nil || result.Markdown.ID != "" || len(store.inputRequests) != 0 ||
				len(store.reads) != 0 || store.sourceCalls != 0 || store.metadataCalls != 0 || len(store.retained) != 0 {
				t.Fatal("worker role claim reached selected briefing inputs or objects")
			}
			errorCode(t, err, api.CodeForbidden)
		})
	}
}

func TestLifecycleLabelCannotBypassOwnLife(t *testing.T) {
	service, store, _, scope, request := component(t)
	scope.Actor.LifeID = store.input.Lane.ParentLifeID
	scope.Actor.Level, scope.Actor.Role = 5, "supervisor"
	scope.Request.Method = "lane.start"
	result, err := service.BriefRender(context.Background(), scope, request)
	if err == nil || result.Markdown.ID != "" || len(store.inputRequests) != 0 ||
		len(store.laneRequests) != 0 || len(store.reads) != 0 || len(store.retained) != 0 || store.receiptCalls != 0 {
		t.Fatal("lifecycle method label bypassed the authenticated parent’s own life")
	}
	errorCode(t, err, api.CodeForbidden)
}

func TestCurrentLifeInputBinding(t *testing.T) {
	for _, mode := range []string{"render", "start"} {
		for _, field := range []string{"generation", "run", "grant-set", "task"} {
			t.Run(mode+"/"+field, func(t *testing.T) {
				service, store, _, scope, request := component(t)
				store.changeInput = func(input *api.BriefingInput) {
					switch field {
					case "generation":
						input.Lane.Generation++
					case "run":
						input.Lane.Run++
					case "grant-set":
						input.Lane.GrantSetID = "replaced-grants"
					case "task":
						input.Lane.Task.ID = "replaced-task"
					}
				}
				var result api.Briefing
				var err error
				if mode == "render" {
					result, err = service.BriefRender(context.Background(), scope, request)
				} else {
					result, err = service.BriefStart(context.Background(), scope, api.BriefingRequest{
						Level: scope.Actor.Level, Role: scope.Actor.Role})
				}
				if err == nil || result.Markdown.ID != "" || len(store.reads) != 0 || len(store.retained) != 0 {
					t.Fatal("changed current-life input reached retained source or prompt bytes")
				}
				errorCode(t, err, api.CodeIntegrity)
			})
		}
	}
}

func TestBootstrapReplayReceiptDomain(t *testing.T) {
	for _, field := range []string{"config", "method", "key", "digest", "kind", "principal", "life"} {
		t.Run(field, func(t *testing.T) {
			service, store, human, scope, request := bootstrapComponent(t)
			if _, err := service.OrgBootstrap(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			store.changeReceipt = func(receipt *api.MutationReceipt) {
				switch field {
				case "config":
					receipt.Config = "foreign-config"
				case "method":
					receipt.Key.Method = "lane.start"
				case "key":
					receipt.Key.IdempotencyKey = mutationKey(t)
				case "digest":
					receipt.Key.RequestSHA256 = digest([]byte("foreign request"))
				case "kind":
					receipt.Actor.Kind = "service"
				case "principal":
					receipt.Actor.ID = "foreign-human"
				case "life":
					receipt.Actor.LifeID = "foreign-life"
				}
			}
			operation, err := service.OrgBootstrap(context.Background(), scope, request)
			if err == nil || operation.ID != "" || human.calls != 1 || len(store.transactions) != 1 {
				t.Fatal("foreign bootstrap receipt replayed or repeated proof use")
			}
			errorCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestBootstrapProofBeforeReplay(t *testing.T) {
	for _, field := range []string{"empty-id", "unsafe-id", "digest", "lane"} {
		t.Run(field, func(t *testing.T) {
			service, store, human, scope, request := bootstrapComponent(t)
			if _, err := service.OrgBootstrap(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			lookups := store.receiptCalls
			code := api.CodeInvalid
			switch field {
			case "empty-id":
				scope.Request.Proof.ID = ""
			case "unsafe-id":
				scope.Request.Proof.ID = "../proof"
			case "digest":
				scope.Request.Proof.RequestSHA256 = digest([]byte("foreign request"))
			case "lane":
				scope.Actor.Kind, scope.Actor.LifeID = "lane", "foreign-life"
				code = api.CodeForbidden
			}
			operation, err := service.OrgBootstrap(context.Background(), scope, request)
			if err == nil || operation.ID != "" || store.receiptCalls != lookups ||
				human.calls != 1 || len(store.transactions) != 1 {
				t.Fatal("invalid replay proof reached a durable receipt or repeated proof use")
			}
			errorCode(t, err, code)
		})
	}
}

func TestTemplateReceiptFixtureDomains(t *testing.T) {
	_, store, _, scope, _ := bootstrapComponent(t)
	original := store.reservation
	for _, field := range []string{"config", "kind", "principal", "life", "method", "key"} {
		t.Run(field, func(t *testing.T) {
			caller, key := scope, original.Key
			switch field {
			case "config":
				caller.Config = "foreign-config"
			case "kind":
				caller.Actor.Kind = "service"
			case "principal":
				caller.Actor.ID = "foreign-human"
			case "life":
				caller.Actor.LifeID = "foreign-life"
			case "method":
				key.Method = "lane.start"
			case "key":
				key.IdempotencyKey = mutationKey(t)
			}
			_, err := store.LookupReceipt(context.Background(), caller, key)
			errorCode(t, err, api.CodeNotFound)
		})
	}
	receipt, err := store.LookupReceipt(context.Background(), scope, original.Key)
	if err != nil || !reflect.DeepEqual(receipt, original) {
		t.Fatal("receipt fixture reconstructed retained metadata from its caller")
	}
}

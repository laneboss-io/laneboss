package cli

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestFileInputCatalog(t *testing.T) {
	integrateInputChecks.RLock()
	defer integrateInputChecks.RUnlock()
	for method, spec := range api.Methods {
		t.Run(string(method), func(t *testing.T) {
			registered := integrateInputChecks.methods[method] != nil
			unavailable, declared := integrateNoFileInput[method]
			if registered == declared || declared && (unavailable != spec.Owner || spec.Owner == "lb-v2-integrate") {
				t.Fatal("catalog file input lacks its validator or explicit unavailable declaration")
			}
		})
	}
	for method := range integrateInputChecks.methods {
		if _, exists := api.Methods[method]; !exists {
			t.Fatal("file input validator names an unknown method")
		}
	}
	for method := range integrateNoFileInput {
		if _, exists := api.Methods[method]; !exists {
			t.Fatal("unavailable file input names an unknown method")
		}
	}
}

func TestOwnedFileInputs(t *testing.T) {
	content := api.BlobRef{ID: "content", SHA256: api.Digest(strings.Repeat("1", 64)), Bytes: 3, Class: "record"}
	manifest := content
	manifest.Class = "manifest"
	query := api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 20}
	badQuery := query
	badQuery.Limit = 0
	for _, row := range []struct {
		method         api.Method
		valid, invalid any
	}{
		{"records.get", api.RecordGetRequest{RecordID: "record"}, api.RecordGetRequest{RecordID: "bad/id"}},
		{"records.query", query, badQuery},
		{"records.export", query, badQuery},
		{"records.append", api.RecordAppendRequest{Collection: "observations", Content: content, RelatedIDs: []api.ID{}}, api.RecordAppendRequest{Collection: "unknown", Content: content, RelatedIDs: []api.ID{}}},
		{"decisions.mutate", api.DecisionMutateRequest{Action: "annotate", RecordID: "decision", ExpectedGeneration: 1, Content: content}, api.DecisionMutateRequest{Action: "annotate", ExpectedGeneration: 1, Content: content}},
		{"records.import", api.TransferRequest{Collection: "observations", Manifest: manifest}, api.TransferRequest{Collection: "unknown", Manifest: manifest}},
		{"box.launch", api.BoxLaunchRequest{Provider: "aws", ResourceGrantID: "grant", Purpose: "lb-fixture", Spec: manifest}, api.BoxLaunchRequest{Provider: "aws", ResourceGrantID: "grant", Purpose: "fixture", Spec: manifest}},
		{"box.run", api.BoxRunRequest{BoxID: "box", ExpectedGeneration: 1, Source: manifest, Plan: manifest}, api.BoxRunRequest{BoxID: "box", Source: manifest, Plan: manifest}},
		{"box.harvest", api.BoxControlRequest{BoxID: "box", ExpectedGeneration: 1}, api.BoxControlRequest{BoxID: "box"}},
		{"box.end", api.BoxControlRequest{BoxID: "box", ExpectedGeneration: 1}, api.BoxControlRequest{BoxID: "box"}},
		{"box.list", api.ListRequest{Limit: 20}, api.ListRequest{Limit: 0}},
	} {
		t.Run(string(row.method), func(t *testing.T) {
			for _, sample := range []struct {
				body  any
				valid bool
			}{{row.valid, true}, {row.invalid, false}} {
				raw, err := json.Marshal(sample.body)
				if err != nil {
					t.Fatal(err)
				}
				err = integrateValidateInput(row.method, raw, true)
				if sample.valid {
					if err != nil {
						t.Fatalf("owned file input refused valid semantic data: %v", err)
					}
				} else {
					var typed *api.Error
					if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-integrate" {
						t.Fatalf("owned file input accepted invalid semantic data: %v", err)
					}
				}
			}
		})
	}
}

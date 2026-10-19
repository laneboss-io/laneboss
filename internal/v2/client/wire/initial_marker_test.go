package wire

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestInitialMarkerEvent(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	manifestID, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := []byte(id)
	marker := api.InitialPublicationMarker{Schema: "laneboss.initial-marker.v2", Config: "marker-case", ID: id,
		Manifest: api.BlobRef{ID: manifestID, Class: "manifest", Bytes: int64(len(manifestBytes)), SHA256: digestOf(manifestBytes)}}
	actor := api.Actor{Kind: "service", ID: api.ID("initial-" + marker.Config)}
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	event := api.Event{Schema: api.SchemaVersion, Seq: 1, ID: api.ID("initial-event-" + string(id)), Config: marker.Config,
		Kind: "org.bootstrapped", Actor: actor, RequestedBy: actor, RequestID: id, OperationID: api.ID("initial-op-" + string(id)),
		Origin: "service", StarterChain: []api.ID{}, RecordedAt: now, RequestedAt: now, ObservedAt: now}
	event.Payload, err = json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEvent(event); err != nil {
		t.Fatal("exact initial marker event was refused", err)
	}
	for _, mode := range []string{"config", "event", "operation", "class", "schema", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			changed, payload := event, marker
			want := "initial bootstrap event differs from its publication marker"
			switch mode {
			case "config":
				payload.Config += "-changed"
			case "event":
				changed.ID = api.ID("initial-event-" + string(otherID))
			case "operation":
				changed.OperationID = api.ID("initial-op-" + string(otherID))
			case "class":
				payload.Manifest.Class = "artifact"
			case "schema":
				payload.Schema += "-changed"
			}
			changed.Payload, err = json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown" {
				want = "unknown JSON field"
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(changed.Payload, &fields); err != nil {
					t.Fatal(err)
				}
				fields["unrecognized"] = json.RawMessage(`true`)
				changed.Payload, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := ValidateEvent(changed)
			var refusal *api.Error
			if !errors.As(err, &refusal) || refusal.Code != api.CodeInvalid || refusal.Message != want {
				t.Fatal("initial marker event lost its closed binding", mode, err)
			}
		})
	}
}

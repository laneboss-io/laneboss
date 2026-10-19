package store

import (
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// ReviewToolInventory identifies the actual outside-service frames. Coverage
// is deliberately absent: the writer derives it from the retained raw frames,
// their original EOF/range journal and the supported provider grammar.
type ReviewToolInventory struct {
	Schema     string              `json:"schema"`
	Target     api.LifeRef         `json:"target"`
	BindingID  api.ID              `json:"binding_id"`
	ThroughSeq api.Sequence        `json:"through_seq"`
	Records    []api.CaptureRecord `json:"records"`
}

func (s *Service) reviewCompleteTools(ctx context.Context, db queryer, frozen reviewFrozen, ref api.BlobRef) error {
	reader, ok := db.(frameDB)
	if !ok {
		return fault(api.CodeIntegrity, "review tool inventory has no complete source reader")
	}
	meta, raw, err := objectRow(ctx, db, ref.ID)
	if err != nil {
		return err
	}
	var input ReviewToolInventory
	if meta.Ref != ref || ref.Class != "manifest" || meta.ACL.LifeID != frozen.Lane.LifeID || meta.SourceOperationID != frozen.Capture.Binding.OperationID || meta.Origin != "service" ||
		api.DecodeObject(raw, &input) != nil || input.Schema != "laneboss.review-tools.v2" || input.Target != frozen.Subject.Target || input.BindingID != frozen.Capture.Binding.ID || input.ThroughSeq != frozen.Subject.InventorySeq {
		return fault(api.CodePrerequisite, "complete tool coverage lacks its authenticated exact frame inventory")
	}
	batch, data, err := s.frameInput(ctx, reader, input.BindingID)
	if err != nil {
		return err
	}
	var retained frameBatch
	if err := storedProjection(ctx, db, "frames", input.BindingID, &retained); err != nil {
		return err
	}
	if !sameValue(batch, retained) || !reflect.DeepEqual(input.Records, batch.Records) || batch.End != frozen.Subject.EndSeq {
		return fault(api.CodeIntegrity, "tool inventory changed its original primary frame set")
	}
	if err := s.checkFrames(ctx, reader, batch, data); err != nil {
		return err
	}
	// Codex's current adapter explicitly reports partial/unsupported tool
	// coverage. A complete label cannot widen that installed capability.
	if frozen.Lane.Session.Driver != api.DriverClaudock {
		return fault(api.CodeUnsupported, "this runner has no complete authenticated tool-record coverage")
	}
	started, finished, streamed := map[string]string{}, map[string]string{}, map[string]bool{}
	initialized, ended := false, false
	for _, record := range batch.Records {
		var event map[string]json.RawMessage
		if api.ValidateObjectJSON(data[record.Data.ID]) != nil || json.Unmarshal(data[record.Data.ID], &event) != nil {
			return fault(api.CodeIntegrity, "tool frame lost its complete original JSON bytes")
		}
		var kind, session string
		if json.Unmarshal(event["type"], &kind) != nil {
			return fault(api.CodeIntegrity, "tool frame has no provider event kind")
		}
		if value, exists := event["session_id"]; exists {
			if json.Unmarshal(value, &session) != nil || session != frozen.Lane.Session.VendorID {
				return fault(api.CodeIntegrity, "tool frame changed its retained vendor session")
			}
		}
		switch kind {
		case "system":
			var subtype, cwd string
			if json.Unmarshal(event["subtype"], &subtype) != nil {
				return fault(api.CodeIntegrity, "provider system frame has no subtype")
			}
			if subtype == "init" {
				if initialized || session != frozen.Lane.Session.VendorID || json.Unmarshal(event["cwd"], &cwd) != nil || cwd != frozen.Lane.Session.LogicalCWD {
					return fault(api.CodeIntegrity, "tool inventory changed its actual session initialization")
				}
				initialized = true
			}
		case "assistant", "user":
			if !initialized || ended {
				return fault(api.CodeIntegrity, "provider tool messages escaped their original run boundaries")
			}
			var message struct {
				Content json.RawMessage `json:"content"`
			}
			if json.Unmarshal(event["message"], &message) != nil {
				return fault(api.CodeIntegrity, "provider message has no tool content")
			}
			var blocks []map[string]json.RawMessage
			if json.Unmarshal(message.Content, &blocks) != nil {
				var text string
				if kind != "user" || json.Unmarshal(message.Content, &text) != nil {
					return fault(api.CodeUnsupported, "provider tool message shape is unsupported")
				}
				continue
			}
			for _, block := range blocks {
				var blockType string
				if json.Unmarshal(block["type"], &blockType) != nil {
					return fault(api.CodeIntegrity, "provider content has no typed block")
				}
				switch blockType {
				case "tool_use":
					var id, name string
					if kind != "assistant" || json.Unmarshal(block["id"], &id) != nil || json.Unmarshal(block["name"], &name) != nil || id == "" || name == "" {
						return fault(api.CodeIntegrity, "provider tool use has no exact identity")
					}
					bytes, err := json.Marshal(block)
					if err != nil {
						return err
					}
					pin := hash(bytes)
					if prior, ok := started[id]; ok && prior != pin {
						return fault(api.CodeIntegrity, "provider tool identity was reused with different input")
					}
					started[id] = pin
				case "tool_result":
					var id string
					if kind != "user" || json.Unmarshal(block["tool_use_id"], &id) != nil || started[id] == "" {
						return fault(api.CodeIntegrity, "provider tool result has no original invocation")
					}
					bytes, err := json.Marshal(block)
					if err != nil {
						return err
					}
					pin := hash(bytes)
					if prior, ok := finished[id]; ok && prior != pin {
						return fault(api.CodeIntegrity, "provider tool result changed its original bytes")
					}
					finished[id] = pin
				case "text", "thinking", "redacted_thinking", "image", "document":
				default:
					return fault(api.CodeUnsupported, "provider content block has unsupported tool coverage")
				}
			}
		case "stream_event":
			var stream struct {
				Type  string                     `json:"type"`
				Block map[string]json.RawMessage `json:"content_block"`
			}
			if json.Unmarshal(event["event"], &stream) != nil {
				return fault(api.CodeIntegrity, "partial provider event is malformed")
			}
			if stream.Type == "content_block_start" {
				var blockType, id string
				if json.Unmarshal(stream.Block["type"], &blockType) != nil {
					return fault(api.CodeIntegrity, "streamed content has no provider block type")
				}
				if blockType == "tool_use" {
					if json.Unmarshal(stream.Block["id"], &id) != nil || id == "" {
						return fault(api.CodeIntegrity, "streamed tool has no exact identity")
					}
					streamed[id] = true
				}
			}
		case "result":
			var failed bool
			if ended || !initialized || session != frozen.Lane.Session.VendorID || json.Unmarshal(event["is_error"], &failed) != nil {
				return fault(api.CodeIntegrity, "tool inventory lacks its original terminal provider result")
			}
			ended = true
			if denials, exists := event["permission_denials"]; exists {
				var denied []json.RawMessage
				if json.Unmarshal(denials, &denied) != nil {
					return fault(api.CodeIntegrity, "provider refusal inventory is malformed")
				}
				if len(denied) > 0 && !containsReviewID(frozen.Subject.RefusalIDs, record.ID) {
					return fault(api.CodeIntegrity, "tool inventory omitted an authenticated provider refusal")
				}
			}
		case "rate_limit_event", "tool_progress", "tool_use_summary", "auth_status":
		default:
			return fault(api.CodeUnsupported, "provider event has unsupported tool-record coverage")
		}
	}
	if !initialized || !ended || len(started) != len(finished) {
		return fault(api.CodePrerequisite, "tool inventory is incomplete through its terminal provider result")
	}
	for id := range streamed {
		if started[id] == "" {
			return fault(api.CodePrerequisite, "streamed tool invocation has no complete retained record")
		}
	}
	return nil
}

func containsReviewID(values []api.ID, id api.ID) bool {
	for _, value := range values {
		if value == id {
			return true
		}
	}
	return false
}

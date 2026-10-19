package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

func validError(code api.ErrorCode) bool {
	switch code {
	case api.CodeNotImplemented, api.CodeInvalid, api.CodeUnauthenticated,
		api.CodeForbidden, api.CodeNotFound, api.CodeConflict,
		api.CodeIdempotencyConflict, api.CodeVersion, api.CodeUnavailable,
		api.CodePrerequisite, api.CodeUnsupported, api.CodeIntegrity, api.CodeBudget,
		api.CodeUnscored, api.CodeCursorExpired, api.CodeContainmentUnknown,
		api.CodeCancelled, api.CodeDeadline:
		return true
	}
	return false
}

func enum(object, field string, value any) error {
	s, ok := value.(string)
	if !ok {
		return nil
	}
	values := ""
	switch object + "." + field {
	case "Actor.kind":
		values = "lane human service scheduler watchdog worker"
	case "Event.origin", "Record.origin":
		values = "service observation legacy_import"
	case "Operation.status":
		values = "pending running succeeded failed cancelled"
	case "Lane.state", "StateEvent.from", "StateEvent.to", "MarkRequest.state":
		values = "preparing running stopping verifying idle profile_wait lost accepted merged abandoned"
	case "ProcessObservation.state":
		values = "prepared running exited unknown"
	case "ProcessObservation.prompt_status", "MailReceipt.prompt_status", "TurnEvent.status":
		values = "not_written written cut unknown completed"
	case "RunEndEvent.reason":
		values = "exit stop timeout limit dropped revoked service_lost capture_full launch_failed"
	case "BlobRef.class":
		// Fixed worker references are retained by private store operations.
		// Recognizing their frozen shape grants no public upload authority.
		values = "task prompt report artifact capture transcript policy manifest judge_request judge_raw archive record launch_request launch_spec materialize_input archive_input worker_input channel_input channel_payload channel_receipt worker_result credential_evidence usage_input usage_raw usage_window diff check"
	case "BlobBeginRequest.class":
		values = "task prompt report artifact capture transcript policy manifest judge_request judge_raw archive record launch_request launch_spec"
	case "Record.collection", "RecordQuery.collection", "RecordAppendRequest.collection", "TransferRequest.collection":
		if object == "RecordQuery" && s == "" {
			return nil // Exact-ID lookups need no collection; bounds check the union.
		}
		values = "decisions observations ledger refusals tools reports archives judge_egress embeddings"
	case "RecordQuery.search_mode":
		values = "keyword vector hybrid"
	case "DecisionMutateRequest.action":
		values = "add supersede annotate feedback embed"
	case "Mail.status":
		values = "queued delivering delivered returned answered"
	case "MailReceipt.status":
		values = "queued delivering delivered returned"
	case "Mail.source":
		values = "cli dashboard scheduler watchdog worker"
	case "ResourceDelta.action":
		values = "add replace delete"
	case "JudgeRequest.purpose":
		values = "blacklist guidance preview"
	case "JudgeReply.status":
		values = "scored partial unavailable"
	case "Judgment.status":
		values = "scored unscored"
	case "NetworkGrant.mode":
		values = "internet service publish"
	case "DataGrant.access", "DataGrantRequest.access":
		values = "ro rw"
	case "DataGrant.delivery":
		values = "copy mount bind_ro"
	case "DataGrantRequest.delivery":
		values = "copy mount"
	case "SecretGrant.delivery", "SecretDelegation.delivery", "SecretEnrollment.delivery":
		values = "env file"
	case "ObjectEntry.kind":
		values = "file directory symlink"
	case "CaptureRecord.stream", "CaptureGap.stream":
		values = "stdout stderr structured transcript"
	case "CaptureRecord.coverage", "ReviewReceipt.coverage":
		values = "complete partial unsupported missing"
	case "ConfigReadRequest.view":
		values = "list show path settings roles channels plugins"
	case "Trigger.kind":
		values = "start adopt manual mail idle profile_limit"
	case "CredentialSlot.mode":
		values = "claudock-headless claude-api-key claudock-helper claudock-api codex-file codex-api codex-local"
	case "LaunchSpec.backend", "LaunchEvent.boundary_backend":
		values = "linux-bwrap-landlock darwin-seatbelt"
	case "WorkerPlan.kind":
		values = "test import export archive render box_run channel usage owner_sheet gateway materialize judge"
	case "Box.provider", "BoxLaunchRequest.provider":
		values = "aws gcp"
	}
	if values != "" {
		for _, item := range strings.Fields(values) {
			if item == s {
				return nil
			}
		}
		err := Invalid("unknown schema enum")
		if object == "CredentialSlot" && field == "mode" {
			return api.WithHelperReason(err, "plan_slot_mode")
		}
		return err
	}
	return nil
}

// RequestDigest excludes request identity, idempotency identity and human proof.
func RequestDigest(request api.Request) (api.Digest, error) {
	return api.RequestDigest(request)
}

func DecodeRequest(data []byte) (api.Request, error) {
	var request api.Request
	if err := Decode(data, &request); err != nil {
		return request, err
	}
	return request, ValidateRequest(request)
}

func ValidateRequest(request api.Request) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return Invalid("request encoding failed")
	}
	var checked api.Request
	if err := Decode(encoded, &checked); err != nil {
		return err
	}
	if request.Protocol != api.Protocol || request.Schema != api.SchemaVersion {
		return &api.Error{Code: api.CodeVersion, Message: "incompatible RPC protocol or schema",
			Instead: "Use the compatible installed client and service; do not open local state."}
	}
	if !ValidID(request.Config) || !randomID(request.RequestID) || !randomID(request.IdempotencyKey) {
		return Invalid("invalid configuration or request identity")
	}
	spec, ok := api.Methods[request.Method]
	if !ok {
		return Invalid("unknown RPC method")
	}
	params := reflect.New(spec.Request).Interface()
	if err := Decode(request.Params, params); err != nil {
		return err
	}
	if err := requestBounds(params); err != nil {
		return err
	}
	digest, err := RequestDigest(request)
	if err != nil {
		return err
	}
	if digest != request.RequestSHA256 {
		return Invalid("request digest mismatch")
	}
	if request.Proof != nil && request.Proof.RequestSHA256 != digest {
		return Invalid("proof intent digest mismatch")
	}
	return nil
}

// Entropy cannot be inferred from incoming bytes. Require room for 128 bits;
// generated client IDs use 16 cryptographically random bytes encoded as hex.
func randomID(id api.ID) bool {
	return ValidID(string(id)) && len(id) >= 22
}

func requestBounds(params any) error {
	switch p := params.(type) {
	case *api.BlobBeginRequest:
		if p.Bytes < 0 || p.Bytes > api.MaxObjectBytes {
			return Invalid("object size exceeds bound")
		}
	case *api.BlobChunk:
		if p.Offset < 0 || len(p.Data) > api.MaxChunkBytes || p.Offset > api.MaxObjectBytes-int64(len(p.Data)) {
			return Invalid("chunk size or offset exceeds bound")
		}
		sum := sha256.Sum256(p.Data)
		if api.Digest(hex.EncodeToString(sum[:])) != p.SHA256 {
			return Invalid("chunk digest mismatch")
		}
	case *api.BlobReadRequest:
		if p.Offset < 0 || p.Offset > api.MaxObjectBytes || p.Limit < 1 || p.Limit > api.MaxChunkBytes {
			return Invalid("invalid blob read bounds")
		}
	case *api.ListRequest:
		return pageLimit(p.Limit)
	case *api.RecordQuery:
		if p.Collection == "" && p.RecordID == "" || p.RecordID != "" &&
			(p.Query != "" || p.Cursor != "" || p.SearchMode != "keyword" || p.Limit != 1) {
			return Invalid("exact record lookup requires an ID, keyword mode and limit one")
		}
		return pageLimit(p.Limit)
	case *api.EventTailRequest:
		if p.Run == 0 || p.DeadlineMS < 0 || p.DeadlineMS > 1800000 {
			return Invalid("invalid event subscription bounds")
		}
	case *api.LifeRef:
		if p.Run == 0 {
			return Invalid("run must be selected")
		}
	}
	return nil
}

func pageLimit(limit int) error {
	if limit < 1 || limit > 200 {
		return Invalid("page limit must be between 1 and 200")
	}
	return nil
}

func ValidateResult(method api.Method, data []byte) error {
	spec, ok := api.Methods[method]
	if !ok {
		return Invalid("unknown RPC method")
	}
	result := reflect.New(spec.Response).Interface()
	if err := Decode(data, result); err != nil {
		return err
	}
	if err := requestBounds(result); err != nil {
		return err
	}
	if method == "lane.attach" {
		frame := result.(*api.StreamFrame)
		_, err := DecodeStream(data, frame.RequestID, 1)
		return err
	}
	if method == "event.tail" {
		var page api.EventPage
		if err := json.Unmarshal(data, &page); err != nil {
			return Invalid("invalid event page")
		}
		for _, event := range page.Events {
			if err := ValidateEvent(event); err != nil {
				return err
			}
		}
	}
	return nil
}

func objectRules(name string, object map[string]any) error {
	switch name {
	case "Actor":
		if object["kind"] == "lane" {
			level, present := object["level"].(json.Number)
			n, err := level.Int64()
			if !present || err != nil || n < 3 || n > 6 || object["life_id"] == nil || object["role"] == nil || object["role"] == "" {
				return Invalid("lane actor requires immutable life, level and role")
			}
		} else if object["life_id"] != nil || object["level"] != nil || object["role"] != nil {
			return Invalid("non-lane actor cannot borrow lane identity")
		}
	case "ProcessObservation":
		_, survivors := object["survivors"]
		_, exit := object["exit_code"]
		_, signal := object["signal"]
		if object["state"] != "unknown" && !survivors {
			return Invalid("known observation requires measured survivors")
		}
		if object["state"] == "exited" {
			if exit == signal {
				return Invalid("exit requires exactly one exit code or signal")
			}
		} else if exit || signal {
			return Invalid("exit result requires an exited observation")
		}
	}
	return nil
}

func DecodeResponse(data []byte, request api.Request) (api.Response, error) {
	var response api.Response
	if err := Decode(data, &response); err != nil {
		return response, err
	}
	if response.Protocol != api.Protocol || response.Schema != api.SchemaVersion {
		return response, &api.Error{Code: api.CodeVersion, Message: "incompatible RPC response",
			Instead: "Use a compatible installed artifact; no state fallback is available."}
	}
	if response.RequestID != request.RequestID || (response.Error == nil) == (len(response.Result) == 0) {
		return response, Invalid("uncorrelated or ambiguous response")
	}
	if response.Error == nil {
		if err := ValidateResult(request.Method, response.Result); err != nil {
			return response, err
		}
	}
	return response, nil
}

func ValidateEvent(event api.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return Invalid("invalid event encoding")
	}
	var decoded api.Event
	if err := Decode(data, &decoded); err != nil {
		return err
	}
	if event.Schema != api.SchemaVersion {
		return &api.Error{Code: api.CodeVersion, Message: "incompatible event schema",
			Instead: "Use event schema 2."}
	}
	t, ok := api.EventSchemas[event.Kind]
	if !ok {
		return Invalid("unknown event schema")
	}
	if event.Kind == "org.bootstrapped" {
		// Admin's protected first-install transaction emits its exact marker,
		// while ordinary org bootstrap continues to emit ConfigView. Decode
		// the closed marker shape before accepting this additional payload.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(event.Payload, &fields); err != nil {
			return Invalid("invalid org bootstrap payload")
		}
		if _, exists := fields["schema"]; exists {
			var marker api.InitialPublicationMarker
			if err := Decode(event.Payload, &marker); err != nil {
				return err
			}
			if marker.Schema != "laneboss.initial-marker.v2" || marker.Config != event.Config ||
				!ValidID(string(marker.ID)) || len(marker.ID) > 64 || !ValidID(string(marker.Manifest.ID)) ||
				!ValidDigest(string(marker.Manifest.SHA256)) || marker.Manifest.Class != "manifest" ||
				marker.Manifest.Bytes <= 0 || marker.Manifest.Bytes > api.MaxFrameBytes ||
				event.ID != api.ID("initial-event-"+string(marker.ID)) ||
				event.OperationID != api.ID("initial-op-"+string(marker.ID)) || event.Origin != "service" || event.Actor.Kind != "service" {
				return Invalid("initial bootstrap event differs from its publication marker")
			}
			return nil
		}
	}
	return Decode(event.Payload, reflect.New(t).Interface())
}

func DecodeStream(data []byte, requestID api.ID, next uint64) (api.StreamFrame, error) {
	var frame api.StreamFrame
	if err := Decode(data, &frame); err != nil {
		return frame, err
	}
	if frame.RequestID != requestID || frame.Index != next || frame.Cursor == "" {
		return frame, Invalid("uncorrelated stream frame or missing cursor")
	}
	count := 0
	if frame.Event != nil {
		count++
		if err := ValidateEvent(*frame.Event); err != nil {
			return frame, err
		}
	}
	if frame.Chunk != nil {
		count++
		if err := requestBounds(frame.Chunk); err != nil {
			return frame, err
		}
	}
	if frame.End || frame.Error != nil {
		if count != 0 || frame.End && frame.Error != nil {
			return frame, Invalid("ambiguous terminal stream frame")
		}
	} else if count != 1 {
		return frame, Invalid("data frame must contain exactly one payload")
	}
	return frame, nil
}

func SameJSON(a, b []byte) bool {
	ca, ea := Canonical(a)
	cb, eb := Canonical(b)
	return ea == nil && eb == nil && bytes.Equal(ca, cb)
}

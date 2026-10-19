package lifecycle

import (
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// ValidateInput is the pure input check shared by the service and CLI. It
// neither resolves authority nor reads objects, proofs, keys or connections.
func ValidateInput(method api.Method, raw json.RawMessage) error {
	spec, exists := api.Methods[method]
	if !exists || spec.Owner != owner {
		return invalid("method is not owned by lifecycle")
	}
	request := reflect.New(spec.Request)
	if err := DecodeRequest(raw, request.Interface()); err != nil {
		return err
	}
	return validateInput(method, request.Elem().Interface())
}

func validGeneration(generation api.Generation) bool {
	return generation != 0 && uint64(generation) <= maxInteger
}

func startInputs(request api.StartRequest, projectRequired bool) error {
	if !validID(api.ID(request.Lane)) || projectRequired && !validID(request.ProjectID) ||
		request.Level < 3 || request.Level > 6 || request.Role == "" ||
		!driverAllowed(request.Driver) || !validID(request.ProfileGrantID) ||
		request.Model == "" || request.Effort == "" || !validBudget(request.Budget) ||
		!validGeneration(request.ExpectedPolicyGeneration) ||
		request.RootTicketID != "" && !validID(request.RootTicketID) ||
		!validBlob(request.Task) || request.Task.Class != "task" || request.Task.Bytes == 0 {
		return invalid("invalid lane launch inputs")
	}
	return nil
}

func validateInput(method api.Method, value any) error {
	var target api.LifeRef
	var generation api.Generation
	needsGeneration := false
	switch request := value.(type) {
	case api.StartRequest:
		return startInputs(request, true)
	case api.AdoptRequest:
		start := api.StartRequest{Lane: request.Lane, Level: request.Level, Role: request.Role,
			Task: request.Task, Driver: request.Driver, ProfileGrantID: request.ProfileGrantID,
			Model: request.Model, Effort: request.Effort, Budget: request.Budget,
			RootTicketID: request.RootTicketID, ExpectedPolicyGeneration: request.ExpectedPolicyGeneration}
		if err := startInputs(start, false); err != nil {
			return err
		}
		if !validBlob(request.ImportManifest) || request.ImportManifest.Class != "manifest" {
			return invalid("adoption requires an immutable manifest")
		}
		return nil
	case api.ResumeRequest:
		target, generation, needsGeneration = request.Target, request.ExpectedGeneration, true
		if !validBlob(request.Message) || request.Message.Class != "task" || request.Message.Bytes == 0 || !validBudget(request.Budget) {
			return invalid("resume requires an immutable message and valid budget")
		}
	case api.TurnRequest:
		target, generation, needsGeneration = request.Target, request.ExpectedGeneration, true
		if !validBudget(request.Budget) {
			return invalid("continuation requires an explicit valid budget")
		}
		if _, err := turnTrigger(request); err != nil {
			return err
		}
	case api.StopRequest:
		target, generation, needsGeneration = request.Target, request.ExpectedGeneration, true
		if !validBlob(request.Reason) || request.Reason.Class != "task" {
			return invalid("stop requires a retained reason object")
		}
	case api.MarkRequest:
		target, generation, needsGeneration = request.Target, request.ExpectedGeneration, true
		if request.State != "accepted" && request.State != "merged" && request.State != "abandoned" {
			return invalid("unknown reviewed lifecycle state")
		}
		if request.State != "abandoned" {
			if err := reviewInputs(api.ReviewRequest{Target: target, Diff: request.Review.Diff,
				Checks: request.Review.Checks, RecordInventory: request.Review.RecordInventory,
				RefusalResolution: request.Review.RefusalResolution}); err != nil {
				return err
			}
		}
	case api.ReviewRequest:
		target = request.Target
		if err := reviewInputs(request); err != nil {
			return err
		}
	case api.CleanRequest:
		target, generation, needsGeneration = request.Target, request.ExpectedGeneration, true
		if !validID(request.ArchiveReceiptID) {
			return invalid("clean requires a verified archive receipt ID")
		}
	case api.ArchiveRequest:
		target, generation, needsGeneration = request.Target, request.ExpectedGeneration, true
	case api.LifeRef:
		target = request
	case api.ListRequest:
		if request.Limit < 1 || request.Limit > 200 || len(request.Cursor) > 4096 ||
			request.LifeID != "" && !validID(request.LifeID) {
			return invalid("invalid lifecycle list bounds")
		}
		return nil
	case api.LoopRequest:
		target, generation, needsGeneration = request.Target, request.ExpectedGeneration, true
		if request.BackoffMS < 1 || request.BackoffMS > int64(maxInteger) || request.BackoffMS > int64((1<<63-1)/time.Millisecond) || request.Enabled && request.IdleMessage == nil {
			return invalid("loop requires explicit backoff and idle input")
		}
		if request.IdleMessage != nil && (!validBlob(*request.IdleMessage) || request.IdleMessage.Class != "task") {
			return invalid("invalid loop idle input")
		}
	case api.AttachRequest:
		target = request.Target
		if len(request.Cursor) > 4096 || request.Mode != "" && request.Mode != "read" && request.Mode != "interactive" {
			return invalid("attach cursor exceeds the bound")
		}
	case api.AttachInputRequest:
		target = request.Target
		if !validID(request.ChannelID) || len(request.Input) > api.MaxChunkBytes ||
			len(request.Input) == 0 && (request.Columns == 0 || request.Rows == 0) ||
			(request.Columns == 0) != (request.Rows == 0) {
			return invalid("invalid bounded input or terminal dimensions")
		}
	case api.EventTailRequest:
		target = api.LifeRef{LifeID: request.LifeID, Run: request.Run}
		if uint64(request.Since) > maxInteger || len(request.Cursor) > 4096 ||
			request.Cursor != "" && request.Since != 0 || request.DeadlineMS < 0 ||
			request.DeadlineMS > int64((1<<63-1)/int64(time.Millisecond)) ||
			request.Follow && request.DeadlineMS == 0 {
			return invalid("invalid event selection or cursor")
		}
		if request.Until != "" {
			if _, exists := api.EventSchemas[request.Until]; !exists {
				return invalid("unknown event termination kind")
			}
		}
	default:
		return invalid("unsupported lifecycle input type")
	}
	if !validTarget(target) || needsGeneration && !validGeneration(generation) {
		return invalid("explicit life, positive run and valid generation required")
	}
	return nil
}

package archive

import (
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// EpochFence carries the writer's exact terminal decision across the private
// native boundary. The launch epoch remains immutable. This is not public
// caller authority; only the installed archive writer supplies these records.
type EpochFence struct {
	Intent      Intent
	LaunchID    api.ID
	LaunchEpoch api.Generation
	End         api.RunEndEvent
	Decision    api.Event
	Stop        *StopEpoch `json:",omitempty"`
}

// StopEpoch proves the extra cancellation transition preceding a stopped end.
// Both records come from the same protected writer as the archive intent.
type StopEpoch struct {
	Event   api.Event
	End     api.Event
	Release api.InternalIntent
}

func ValidateEpochFence(f EpochFence) error {
	i, e, end := f.Intent, f.Decision, f.End
	var state api.StateEvent
	epoch := f.LaunchEpoch + 1
	if f.Stop != nil {
		epoch++
	}
	if !wire.ValidID(string(i.OperationID)) || !wire.ValidID(string(i.EndEventID)) || i.EndSeq == 0 ||
		!wire.ValidID(string(f.LaunchID)) || f.LaunchEpoch >= 1<<53-1 || epoch > 1<<53-1 || i.CancellationEpoch != epoch ||
		e.Schema != api.SchemaVersion || e.Config == "" || e.Kind != "lane.state" || e.Origin != "service" || e.LifeID != i.Request.Target.LifeID || e.Run != i.Request.Target.Run ||
		!wire.ValidID(string(e.ID)) || e.Seq <= i.EndSeq || api.DecodeObject(e.Payload, &state) != nil ||
		state.Generation != i.Request.ExpectedGeneration || state.From != "verifying" && state.From != "accepted" && state.From != "idle" ||
		state.To != "abandoned" && state.To != "merged" || end.LaunchID != f.LaunchID ||
		end.Observation.Handle.Target != i.Request.Target || end.Observation.State != "exited" || end.Observation.Survivors == nil ||
		*end.Observation.Survivors != 0 || (end.Observation.ExitCode == nil) == (end.Observation.Signal == nil) {
		return &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-archive", Message: "archive epoch fence differs from its committed natural end and terminal decision"}
	}
	if f.Stop == nil {
		if end.Reason != "exit" {
			return &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-archive", Message: "archive epoch fence has no committed stop transition"}
		}
		return nil
	}
	stop, envelope, release := f.Stop.Event, f.Stop.End, f.Stop.Release
	var stopping api.StateEvent
	var measured api.RunEndEvent
	if end.Reason != "stop" || stop.Schema != api.SchemaVersion || stop.Config != e.Config || stop.Kind != "lane.stopping" || stop.Origin != "service" ||
		stop.LifeID != i.Request.Target.LifeID || stop.Run != i.Request.Target.Run || !wire.ValidID(string(stop.ID)) || stop.Seq == 0 || stop.Seq >= i.EndSeq ||
		!wire.ValidID(string(stop.OperationID)) || !wire.ValidID(string(stop.RequestID)) ||
		envelope.Schema != api.SchemaVersion || envelope.Config != e.Config || envelope.Kind != "lane.ended" || envelope.Origin != "service" ||
		envelope.LifeID != i.Request.Target.LifeID || envelope.Run != i.Request.Target.Run || envelope.ID != i.EndEventID || envelope.Seq != i.EndSeq ||
		!wire.ValidID(string(envelope.OperationID)) || !wire.ValidID(string(envelope.RequestID)) ||
		api.DecodeObject(envelope.Payload, &measured) != nil || !reflect.DeepEqual(measured, end) ||
		api.DecodeObject(stop.Payload, &stopping) != nil || stopping.To != "stopping" || stopping.Generation == 0 || stopping.Generation >= state.Generation ||
		release.Kind != api.InternalHelperRelease || release.Config != e.Config || release.Target != i.Request.Target || release.CancellationEpoch != f.LaunchEpoch+1 ||
		!wire.ValidID(string(release.ID)) || !wire.ValidID(string(release.EffectID)) || !wire.ValidID(string(release.CauseOperationID)) || !wire.ValidID(string(release.CauseRequestID)) ||
		release.CauseOperationID != envelope.OperationID || release.CauseRequestID != envelope.RequestID || release.RequestedBy != envelope.RequestedBy ||
		release.LogicalTurnID != envelope.LogicalTurnID || stop.Actor != stop.RequestedBy {
		return &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-archive", Message: "archive epoch fence differs from its committed stop and release cause"}
	}
	return nil
}

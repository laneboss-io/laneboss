package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func (s *Service) LaneStatus(ctx context.Context, scope api.Scope,
	request api.LifeRef) (api.Lane, error) {
	if err := s.authorize(ctx, scope, "lane.status", request); err != nil {
		return api.Lane{}, err
	}
	lane, err := s.lane(ctx, scope, request, false)
	if err != nil {
		return api.Lane{}, err
	}
	lane.UnownedRetained = nil
	if err := s.statusSpend(ctx, scope, &lane); err != nil {
		return api.Lane{}, err
	}
	if !lane.Cleaned {
		return lane, nil
	}
	// Derive the reply from committed history without rewriting the projection.
	target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
	err = s.walkEvents(ctx, scope, lane, target, func(event api.Event) error {
		if event.Kind != "lane.cleaned" {
			return nil
		}
		var body api.CleanEvent
		if decode(event.Payload, &body) != nil || body.UnownedRetained.Objects < 0 || body.UnownedRetained.Bytes < 0 {
			return integrity("invalid recorded unowned retention totals")
		}
		lane.UnownedRetained = &body.UnownedRetained
		return nil
	})
	if err != nil {
		return api.Lane{}, err
	}
	return lane, nil
}

func (s *Service) LaneList(ctx context.Context, scope api.Scope,
	request api.ListRequest) (api.LanePage, error) {
	if err := s.authorize(ctx, scope, "lane.list", request); err != nil {
		return api.LanePage{}, err
	}
	if request.Limit < 1 || request.Limit > 200 || len(request.Cursor) > 4096 ||
		request.LifeID != "" && !validID(request.LifeID) {
		return api.LanePage{}, invalid("invalid lifecycle list bounds")
	}
	page, err := s.deps.Store.Lanes(ctx, scope, request)
	if err != nil {
		return api.LanePage{}, failure(err)
	}
	if len(page.Lanes) > request.Limit || len(page.Cursor) > 4096 {
		return api.LanePage{}, integrity("store exceeded lifecycle page bounds")
	}
	visible := make([]api.Lane, 0, len(page.Lanes))
	for _, lane := range page.Lanes {
		if !treeVisible(scope, lane) {
			continue
		}
		if !validAncestry(lane) || lane.StarterChain == nil ||
			!validID(lane.LifeID) || lane.Run == 0 || lane.Generation == 0 || !validCounters(lane) {
			return api.LanePage{}, integrity("invalid listed lifecycle projection")
		}
		visible = append(visible, lane)
	}
	page.Lanes = visible
	return page, nil
}

// readBlob checks every returned range and the hash of the complete referenced
// bytes. Store.Blob remains responsible for the object's provenance and ACL.
func (s *Service) readBlob(ctx context.Context, scope api.Scope,
	ref api.BlobRef) (resultBytes []byte, resultErr error) {
	if !validBlob(ref) {
		return nil, invalid("invalid immutable input reference")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, failure(err)
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, failure(err)
	}
	if metadata.Ref != ref || metadata.ACL.Config != scope.Config {
		return nil, integrity("input reference differs from committed object metadata")
	}
	if ref.Bytes == 0 {
		// Empty content still needs the store's existence/provenance/ACL
		// check. A known empty digest cannot authenticate an arbitrary ID.
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{
			ObjectID: ref.ID, Offset: 0, Limit: 1})
		if err != nil {
			return nil, failure(err)
		}
		digest := sha256.Sum256(nil)
		if chunk.ObjectID != ref.ID || chunk.Offset != 0 || len(chunk.Data) != 0 ||
			chunk.SHA256 != ref.SHA256 || ref.SHA256 != api.Digest(hex.EncodeToString(digest[:])) {
			return nil, integrity("empty immutable input failed verification")
		}
		return []byte{}, nil
	}
	result := make([]byte, 0, int(ref.Bytes))
	for int64(len(result)) < ref.Bytes {
		limit := min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(result)))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{
			ObjectID: ref.ID, Offset: int64(len(result)), Limit: int(limit)})
		if err != nil {
			return nil, failure(err)
		}
		digest := sha256.Sum256(chunk.Data)
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(result)) ||
			len(chunk.Data) == 0 || int64(len(chunk.Data)) > limit ||
			chunk.SHA256 != api.Digest(hex.EncodeToString(digest[:])) {
			return nil, integrity("immutable input range failed verification")
		}
		result = append(result, chunk.Data...)
	}
	digest := sha256.Sum256(result)
	if api.Digest(hex.EncodeToString(digest[:])) != ref.SHA256 {
		return nil, integrity("immutable input digest failed verification")
	}
	return result, nil
}

func selectedEvent(scope api.Scope, lane api.Lane,
	request api.EventTailRequest, event api.Event) (bool, error) {
	// Selection precedes schema inspection, payload access and until matching.
	if event.Config != scope.Config || event.LifeID != request.LifeID ||
		event.Run != request.Run || event.Seq <= request.Since {
		return false, nil
	}
	if event.Origin != "service" {
		// Observations and imported history cannot impersonate a live event.
		return false, nil
	}
	if event.Schema != api.SchemaVersion || event.Seq == 0 ||
		uint64(event.Seq) > maxInteger || !validID(event.ID) ||
		event.ParentLifeID != lane.ParentLifeID || event.RootLifeID != lane.RootLifeID ||
		event.StarterEventSeq != lane.StarterEventSeq ||
		!reflect.DeepEqual(event.StarterChain, lane.StarterChain) {
		return false, integrity("invalid committed lifecycle event")
	}
	shape, exists := api.EventSchemas[event.Kind]
	if !exists {
		return false, integrity("unknown committed event kind")
	}
	value := reflect.New(shape).Interface()
	var payloadErr error
	switch event.Kind {
	case "operation.accepted", "operation.completed", "operation.failed":
		// Internal operations have no public request digest. The shared
		// strict wire schema already defines that optional field; do not
		// invent a digest or reject the store's actual internal completion.
		payloadErr = wire.Decode(event.Payload, value)
	default:
		payloadErr = decode(event.Payload, value)
	}
	if payloadErr != nil {
		return false, integrity("invalid committed " + string(event.Kind) + " payload")
	}
	if event.Kind == "lane.ended" {
		end := value.(*api.RunEndEvent)
		if !validID(end.LaunchID) || end.Observation.Handle.Target !=
			(api.LifeRef{LifeID: event.LifeID, Run: event.Run}) ||
			validateObservation(end.Observation.Handle, end.Observation) != nil ||
			requireQuiescence(end.Observation) != nil {
			return false, integrity("committed end has no truthful terminal observation")
		}
		switch end.Reason {
		case "exit", "stop", "timeout", "limit", "dropped", "revoked",
			"service_lost", "capture_full", "launch_failed":
		default:
			return false, integrity("unknown committed end reason")
		}
	}
	if event.Kind == "helper.released" {
		release := value.(*api.ReleaseReceipt)
		if api.ValidateReleaseReceipt(*release) != nil ||
			!validID(release.ID) || !validID(release.LeaseID) || !validID(release.EffectID) ||
			release.OperationID != event.OperationID || release.Quiescence.Handle.Target !=
			(api.LifeRef{LifeID: event.LifeID, Run: event.Run}) ||
			validateObservation(release.Quiescence.Handle, release.Quiescence) != nil || !validTime(release.ObservedAt) {
			return false, integrity("committed release has no correlated helper measurement")
		}
	}
	return true, nil
}

func (s *Service) eventPage(ctx context.Context, scope api.Scope,
	lane api.Lane, request api.EventTailRequest) (api.EventPage, error) {
	query := request
	query.Follow = false
	previous := request.Since
	for {
		if err := ctx.Err(); err != nil {
			return api.EventPage{}, failure(err)
		}
		page, err := s.deps.Store.Events(ctx, scope, query)
		if err != nil {
			return api.EventPage{}, failure(err)
		}
		if len(page.Events) > 200 || len(page.Cursor) > 4096 {
			return api.EventPage{}, problem(api.CodeUnavailable,
				"event page exceeds stream bounds",
				"Retain the last delivered cursor and repair the store page limit.")
		}
		if !page.Complete && (page.Cursor == "" || page.Cursor == query.Cursor) {
			return api.EventPage{}, integrity("event store cursor did not advance")
		}
		result := api.EventPage{Events: []api.Event{}, Cursor: page.Cursor,
			Complete: page.Complete && !request.Follow}
		queuedBytes := 0
		for _, event := range page.Events {
			if event.Seq <= previous {
				return api.EventPage{}, integrity("event page is not in exclusive commit order")
			}
			previous = event.Seq
			selected, err := selectedEvent(scope, lane, request, event)
			if err != nil {
				return api.EventPage{}, err
			}
			if !selected {
				continue
			}
			encoded, err := json.Marshal(event)
			if err != nil || len(encoded) > api.MaxFrameBytes-8192 {
				return api.EventPage{}, integrity("event cannot fit a bounded stream frame")
			}
			queuedBytes += len(encoded)
			if queuedBytes > 4<<20 {
				return api.EventPage{}, problem(api.CodeUnavailable,
					"event stream queue is full",
					"Resume from the last delivered cursor after reducing backlog.")
			}
			result.Events = append(result.Events, event)
			if request.Until != "" && event.Kind == request.Until {
				// Keep the incoming cursor when until truncates a store page;
				// no selected-event cursor exists to acknowledge a partial page.
				result.Cursor = request.Cursor
				result.Complete = true
				return result, nil
			}
		}
		if len(result.Events) > 0 || page.Complete {
			return result, nil
		}
		// Empty selected output is not an empty store snapshot. Drain the
		// already committed pages without a live-follow polling delay.
		query.Cursor, query.Since = page.Cursor, 0
	}
}

func (s *Service) selectEvents(ctx context.Context, scope api.Scope,
	request api.EventTailRequest) (api.Lane, error) {
	if err := s.authorize(ctx, scope, "event.tail", request); err != nil {
		return api.Lane{}, err
	}
	if !validTarget(api.LifeRef{LifeID: request.LifeID, Run: request.Run}) ||
		uint64(request.Since) > maxInteger || len(request.Cursor) > 4096 ||
		request.Cursor != "" && request.Since != 0 || request.DeadlineMS < 0 {
		return api.Lane{}, invalid("invalid event selection or cursor")
	}
	if request.Follow && request.DeadlineMS == 0 {
		return api.Lane{}, invalid("event follow requires a positive deadline")
	}
	if request.Until != "" {
		if _, exists := api.EventSchemas[request.Until]; !exists {
			return api.Lane{}, invalid("unknown event termination kind")
		}
	}
	return s.lane(ctx, scope,
		api.LifeRef{LifeID: request.LifeID, Run: request.Run}, false)
}

func (s *Service) EventTail(ctx context.Context, scope api.Scope,
	request api.EventTailRequest) (api.EventPage, error) {
	lane, err := s.selectEvents(ctx, scope, request)
	if err != nil {
		return api.EventPage{}, err
	}
	page, err := s.eventPage(ctx, scope, lane, request)
	if err != nil {
		return api.EventPage{}, err
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		return api.EventPage{}, integrity("cannot encode event snapshot")
	}
	// A snapshot shares the RPC frame bound. A stream may retain a larger
	// bounded page because it sends one event per frame. Without a cursor at
	// an intermediate event, truncating this snapshot could skip records.
	if len(encoded) > api.MaxFrameBytes-8192 {
		return api.EventPage{}, problem(api.CodeUnavailable, "event snapshot exceeds one frame",
			"Keep the incoming cursor and read the selected run as a stream.")
	}
	return page, nil
}

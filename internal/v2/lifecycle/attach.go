package lifecycle

import (
	"context"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

const attachChunkBytes = 16 * 1024

type attachStream struct {
	service   *Service
	scope     api.Scope
	selection api.AttachRequest
	lane      api.Lane
	binding   api.CaptureBinding
	bound     api.Event
	position  attachPosition
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    atomic.Bool
	index     uint64
	initial   bool
	ended     bool
}

func (s *Service) newAttach(ctx context.Context, scope api.Scope, request api.AttachRequest) (*attachStream, error) {
	if err := s.authorize(ctx, scope, "lane.attach", request); err != nil {
		return nil, err
	}
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return nil, err
	}
	var binding api.CaptureBinding
	var bound api.Event
	err = s.walkEvents(ctx, scope, lane, request.Target, func(event api.Event) error {
		if event.Kind == "capture.bound" || event.Kind == "capture.refused" {
			var value api.CaptureBinding
			if decode(event.Payload, &value) != nil || api.ValidateCaptureBinding(value) != nil || value.Config != scope.Config || value.Target != request.Target {
				return integrity("attach has no authentic capture binding")
			}
			if bound.ID != "" && !reflect.DeepEqual(value, binding) {
				return integrity("attach capture binding changed within the selected run")
			}
			binding, bound = value, event
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if bound.ID == "" || binding.Status != "registered" {
		return nil, problem(api.CodeUnsupported, "selected run has no registered primary capture", "Preserve its incomplete evidence and attach to a registered run.")
	}
	mode := request.Mode
	if mode == "" {
		mode = "read"
	}
	position := attachPosition{Config: scope.Config, Actor: scope.Actor, EndpointGeneration: scope.EndpointGeneration,
		Target: request.Target, Mode: mode, BindingID: binding.ID, BindingGeneration: binding.Generation,
		Seq: bound.Seq, Offsets: map[string]int64{}}
	for _, stream := range binding.Streams {
		position.Offsets[stream.Stream] = 0
	}
	if request.Cursor != "" {
		position, err = s.readAttach(request.Cursor, position)
		if err != nil {
			return nil, err
		}
		if position.Seq < bound.Seq {
			return nil, integrity("attach cursor predates its registered binding")
		}
	}
	child, cancel := context.WithCancel(ctx)
	stream := &attachStream{service: s, scope: scope, selection: request, lane: lane, binding: binding, bound: bound,
		position: position, ctx: child, cancel: cancel}
	if _, err := stream.captureState(ctx); err != nil {
		cancel()
		return nil, err
	}
	return stream, nil
}

func (stream *attachStream) Close() error {
	stream.closed.Store(true)
	stream.cancel()
	return nil
}

func (stream *attachStream) captureState(ctx context.Context) (api.CaptureState, error) {
	state, err := stream.service.deps.Store.CaptureState(ctx, stream.scope, stream.binding.ID)
	if err != nil {
		return api.CaptureState{}, failure(err)
	}
	if !reflect.DeepEqual(state.Binding, stream.binding) || !validGeneration(state.Generation) || len(state.Positions) != len(stream.binding.Streams) {
		return api.CaptureState{}, integrity("attach capture state differs from its retained binding")
	}
	seen := map[api.ID]bool{}
	for _, position := range state.Positions {
		name := ""
		for _, binding := range stream.binding.Streams {
			if binding.ID == position.StreamID {
				name = binding.Stream
			}
		}
		if name == "" || seen[position.StreamID] || position.NextOffset < stream.position.Offsets[name] || uint64(position.NextOffset) > maxInteger {
			return api.CaptureState{}, integrity("attach position exceeds its committed capture range")
		}
		seen[position.StreamID] = true
	}
	return state, nil
}

func (stream *attachStream) frame() (api.StreamFrame, error) {
	if stream.index >= maxInteger {
		return api.StreamFrame{}, integrity("attach frame index exhausted")
	}
	cursor, err := stream.service.sealAttach(stream.position)
	if err != nil {
		return api.StreamFrame{}, err
	}
	stream.index++
	return api.StreamFrame{RequestID: stream.scope.Request.RequestID, Index: stream.index, Cursor: cursor}, nil
}

func (stream *attachStream) Next(ctx context.Context) (api.StreamFrame, error) {
	if err := contextReady(ctx); err != nil {
		return api.StreamFrame{}, err
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed.Load() || stream.ended {
		return api.StreamFrame{}, io.EOF
	}
	combined, cancel := context.WithCancel(stream.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer cancel()
	defer stop()
	for {
		if err := contextReady(combined); err != nil {
			if stream.closed.Load() {
				return api.StreamFrame{}, io.EOF
			}
			return api.StreamFrame{}, err
		}
		if err := stream.service.authorize(combined, stream.scope, "lane.attach", stream.selection); err != nil {
			return api.StreamFrame{}, err
		}
		lane, err := stream.service.lane(combined, stream.scope, stream.selection.Target, false)
		if err != nil {
			return api.StreamFrame{}, err
		}
		stream.lane = lane
		if _, err := stream.captureState(combined); err != nil {
			return api.StreamFrame{}, err
		}
		if !stream.initial {
			stream.initial = true
			frame, err := stream.frame()
			frame.Event = &stream.bound
			return frame, err
		}
		wake := stream.service.wakeup()
		page, err := stream.service.eventPage(combined, stream.scope, stream.lane, api.EventTailRequest{
			LifeID: stream.selection.Target.LifeID, Run: stream.selection.Target.Run, Since: stream.position.Seq})
		if err != nil {
			return api.StreamFrame{}, err
		}
		for _, event := range page.Events {
			if stream.position.RecordSeq != 0 && event.Seq != stream.position.RecordSeq {
				return api.StreamFrame{}, integrity("attach cursor lost its partial capture record")
			}
			if event.Kind == "capture.gap" {
				frame, err := stream.frame()
				if err != nil {
					return api.StreamFrame{}, err
				}
				frame.Error = integrity("primary capture contains an explicit gap")
				stream.ended = true
				return frame, nil
			}
			if event.Kind != "capture.appended" {
				stream.position.Seq = event.Seq
				continue
			}
			return stream.captureFrame(combined, event)
		}
		if !page.Complete {
			continue
		}
		state, err := stream.captureState(combined)
		if err != nil {
			return api.StreamFrame{}, err
		}
		complete := stream.position.RecordSeq == 0
		for _, position := range state.Positions {
			for _, binding := range stream.binding.Streams {
				if binding.ID == position.StreamID {
					complete = complete && position.EOF && stream.position.Offsets[binding.Stream] == position.NextOffset
				}
			}
		}
		if complete {
			frame, err := stream.frame()
			frame.End, stream.ended = true, true
			return frame, err
		}
		timer := time.NewTimer(streamPoll)
		select {
		case <-combined.Done():
		case <-wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (stream *attachStream) captureFrame(ctx context.Context, event api.Event) (api.StreamFrame, error) {
	var record api.CaptureRecord
	if decode(event.Payload, &record) != nil || record.BindingID != stream.binding.ID || record.Target != stream.selection.Target ||
		!record.Primary || record.ReplacementOf != "" || !validID(record.ID) || !validBlob(record.Data) || record.Data.Class != "capture" ||
		record.Data.Bytes < 1 || record.Data.Bytes > api.MaxChunkBytes || record.Offset < 0 || uint64(record.Offset)+uint64(record.Data.Bytes) > maxInteger {
		return api.StreamFrame{}, integrity("attach record is not registered primary capture")
	}
	current, ok := stream.position.Offsets[record.Stream]
	if !ok || record.Offset+stream.position.BlobOffset != current || stream.position.BlobOffset >= record.Data.Bytes {
		return api.StreamFrame{}, integrity("attach record has a gap or repeated byte range")
	}
	metadata, err := stream.service.deps.Store.ObjectMetadata(ctx, stream.scope, record.Data.ID)
	if err != nil {
		return api.StreamFrame{}, failure(err)
	}
	if metadata.SourceOperationID != stream.binding.OperationID || metadata.ACL.LifeID != record.Target.LifeID ||
		metadata.Origin != "service" && metadata.Origin != "worker" || metadata.Origin == "worker" && (metadata.ACL.Owner.ID != stream.binding.ProducerID || metadata.ACL.Owner.Kind != "worker") {
		allowAndLog("attach_capture_provenance")
	}
	state, err := stream.captureState(ctx)
	if err != nil {
		return api.StreamFrame{}, err
	}
	committed := false
	for _, position := range state.Positions {
		for _, binding := range stream.binding.Streams {
			if binding.ID == position.StreamID && binding.Stream == record.Stream && position.NextOffset >= record.Offset+record.Data.Bytes {
				committed = true
			}
		}
	}
	if !committed {
		return api.StreamFrame{}, integrity("attach record exceeds its acknowledged capture position")
	}
	raw, err := stream.service.readBlob(ctx, stream.scope, record.Data)
	if err != nil {
		return api.StreamFrame{}, err
	}
	start := stream.position.BlobOffset
	end := min(int64(len(raw)), start+attachChunkBytes)
	data := append([]byte{}, raw[start:end]...)
	stream.position.Offsets[record.Stream] += int64(len(data))
	if end == int64(len(raw)) {
		stream.position.Seq, stream.position.RecordSeq, stream.position.BlobOffset = event.Seq, 0, 0
	} else {
		stream.position.RecordSeq, stream.position.BlobOffset = event.Seq, end
	}
	frame, err := stream.frame()
	if err != nil {
		return api.StreamFrame{}, err
	}
	frame.Chunk = &api.BlobChunk{ObjectID: record.Data.ID, Offset: start, Data: data, SHA256: digestOfBytes(data)}
	return frame, nil
}

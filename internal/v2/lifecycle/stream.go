package lifecycle

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

const streamPoll = 50 * time.Millisecond

// A watcher retains at most one selected store page, scanning unselected pages
// without a live-poll delay. It owns neither a runner nor a control socket.
// A slow watcher cannot fill a service-wide producer queue.
type eventStream struct {
	service   *Service
	scope     api.Scope
	lane      api.Lane
	selection api.EventTailRequest
	query     api.EventTailRequest
	ctx       context.Context
	cancel    context.CancelFunc
	closed    atomic.Bool
	mu        sync.Mutex
	queue     []api.Event
	pageEnd   string
	ack       string
	index     uint64
	last      api.Sequence
	complete  bool
	ended     bool
}

var _ api.EventStream = (*eventStream)(nil)

func (s *Service) OpenEvents(ctx context.Context, scope api.Scope,
	request api.EventTailRequest) (api.EventStream, error) {
	lane, err := s.selectEvents(ctx, scope, request)
	if err != nil {
		return nil, err
	}
	return s.openEvents(ctx, scope, lane, request)
}

func (s *Service) openEvents(ctx context.Context, scope api.Scope,
	lane api.Lane, request api.EventTailRequest) (api.EventStream, error) {
	var initial *api.EventPage
	if scope.ReadView != nil {
		// The response handler and stream constructor share this borrowed
		// pinned view. Its selected page is already in ResponseStream.Initial;
		// only the following cursor belongs in live frames.
		page, err := s.eventPage(ctx, scope, lane, request)
		if err != nil {
			return nil, err
		}
		initial = &page
	}
	// The transport owns the initial pinned read. A live watcher borrows the
	// connection/frame but must not keep reading that historical snapshot.
	scope.ReadView = nil
	if request.DeadlineMS > int64((1<<63-1)/int64(time.Millisecond)) {
		return nil, invalid("event deadline outside duration range")
	}
	var child context.Context
	var cancel context.CancelFunc
	if request.DeadlineMS > 0 {
		child, cancel = context.WithTimeout(ctx,
			time.Duration(request.DeadlineMS)*time.Millisecond)
	} else {
		child, cancel = context.WithCancel(ctx)
	}
	stream := &eventStream{service: s, scope: scope, lane: lane, selection: request,
		query: request, ctx: child, cancel: cancel, ack: request.Cursor,
		last: request.Since}
	if initial != nil {
		stream.ack, stream.complete = initial.Cursor, initial.Complete
		if len(initial.Events) > 0 {
			stream.last = initial.Events[len(initial.Events)-1].Seq
		}
		if initial.Cursor != "" {
			stream.query.Cursor, stream.query.Since = initial.Cursor, 0
		} else if !initial.Complete && len(initial.Events) > 0 {
			cancel()
			return nil, integrity("initial stream snapshot has no continuation cursor")
		}
	}
	return stream, nil
}

func (stream *eventStream) Close() error {
	stream.closed.Store(true)
	stream.cancel()
	return nil
}

func (stream *eventStream) Next(ctx context.Context) (api.StreamFrame, error) {
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
		if err := combined.Err(); err != nil {
			if stream.closed.Load() {
				return api.StreamFrame{}, io.EOF
			}
			if ctx.Err() != nil {
				return api.StreamFrame{}, failure(ctx.Err())
			}
			return api.StreamFrame{}, failure(stream.ctx.Err())
		}
		// Reauthenticate on delivery, including queued frames and the end.
		if err := stream.service.authorize(combined, stream.scope,
			"event.tail", stream.selection); err != nil {
			return api.StreamFrame{}, err
		}
		if _, err := stream.service.lane(combined, stream.scope,
			api.LifeRef{LifeID: stream.selection.LifeID,
				Run: stream.selection.Run}, false); err != nil {
			return api.StreamFrame{}, err
		}
		if len(stream.queue) > 0 {
			if stream.index >= maxInteger {
				return api.StreamFrame{}, integrity("stream frame index exhausted")
			}
			event := stream.queue[0]
			stream.queue = stream.queue[1:]
			stream.index++
			stream.last = event.Seq
			if len(stream.queue) == 0 {
				stream.ack = stream.pageEnd
			}
			return api.StreamFrame{RequestID: stream.scope.Request.RequestID,
				Index: stream.index, Cursor: stream.ack, Event: &event}, nil
		}
		if stream.complete {
			if stream.index >= maxInteger {
				return api.StreamFrame{}, integrity("stream frame index exhausted")
			}
			stream.index++
			stream.ended = true
			return api.StreamFrame{RequestID: stream.scope.Request.RequestID,
				Index: stream.index, Cursor: stream.ack, End: true}, nil
		}
		wake := stream.service.wakeup()
		page, err := stream.service.eventPage(combined, stream.scope,
			stream.lane, stream.query)
		if err != nil {
			return api.StreamFrame{}, err
		}
		stream.queue = page.Events
		stream.pageEnd = page.Cursor
		stream.complete = page.Complete
		if len(page.Events) > 0 && page.Events[0].Seq <= stream.last {
			return api.StreamFrame{}, integrity("stream cursor repeated committed events")
		}
		// Store owns authenticated cursor signing. Never make a cursor from
		// an event sequence or expose the final page cursor before delivery.
		if page.Cursor != "" && page.Cursor != stream.query.Cursor {
			stream.query.Cursor = page.Cursor
			stream.query.Since = 0
		} else if len(page.Events) > 0 && !page.Complete {
			return api.StreamFrame{}, integrity("event store cursor did not advance")
		}
		if len(stream.queue) > 0 || stream.complete {
			continue
		}
		stream.ack = page.Cursor
		timer := time.NewTimer(streamPoll)
		select {
		case <-combined.Done():
		case <-wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

package service

import (
	"encoding/json"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

type streamQueue struct {
	frames      chan queuedFrame
	mu          sync.Mutex
	queuedBytes int
}

func newStreamQueue() *streamQueue {
	return &streamQueue{frames: make(chan queuedFrame, 256)}
}

// push never waits for a reader. A refused frame reserves no bytes, so a
// consumer can release its last delivered cursor without losing capacity.
func (q *streamQueue) push(frame api.StreamFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil || len(encoded) > api.MaxFrameBytes {
		return serviceError(api.CodeIntegrity, "invalid stream producer frame")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.queuedBytes+len(encoded) > 4*1024*1024 {
		return serviceError(api.CodeUnavailable, "watcher byte queue overflow; resume from cursor")
	}
	select {
	case q.frames <- queuedFrame{frame: frame, bytes: len(encoded)}:
		q.queuedBytes += len(encoded)
		return nil
	default:
		return serviceError(api.CodeUnavailable, "watcher frame queue overflow; resume from cursor")
	}
}

func (q *streamQueue) release(frame queuedFrame) {
	q.mu.Lock()
	q.queuedBytes -= frame.bytes
	q.mu.Unlock()
}

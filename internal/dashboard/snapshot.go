package dashboard

import (
	"context"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

type displayCache struct {
	mu            sync.Mutex
	gate          chan struct{}
	revision      string
	readAt        time.Time
	lanes, events []object
	graph         *graphInputs
}

func (h *handler) snapshot(ctx context.Context, c *eventstore.Configuration) ([]object, []object, *graphInputs, error) {
	h.cache.mu.Lock()
	if h.cache.gate == nil {
		h.cache.gate = make(chan struct{}, 1)
	}
	gate := h.cache.gate
	h.cache.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, nil, nil, ctx.Err()
	case gate <- struct{}{}:
	}
	defer func() { <-gate }()
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	revision, err := eventstore.DisplayRevision(c)
	if err != nil {
		return nil, nil, nil, err
	}
	if revision == h.cache.revision && time.Since(h.cache.readAt) < 30*time.Second {
		return h.cache.lanes, h.cache.events, h.cache.graph, nil
	}
	began := time.Now()
	lanes, events, err := eventstore.ReadDisplayContext(ctx, c)
	if err != nil {
		return nil, nil, nil, err
	}
	verifyMillis := float64(time.Since(began).Microseconds()) / 1000
	began = time.Now()
	settings, graphErr := config.Load(h.name)
	index := &graphInputs{problem: graphErr}
	if graphErr == nil {
		index, graphErr = buildGraphInputs(ctx, settings, lanes, events, time.Now())
		if graphErr != nil {
			index = &graphInputs{problem: graphErr}
		}
	}
	index.verifyMillis, index.buildMillis = verifyMillis, float64(time.Since(began).Microseconds())/1000
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	after, err := eventstore.DisplayRevision(c)
	if err != nil {
		return nil, nil, nil, err
	}
	if revision == after {
		h.cache.revision, h.cache.readAt = revision, time.Now()
		h.cache.lanes, h.cache.events, h.cache.graph = lanes, events, index
	}
	return lanes, events, index, nil
}

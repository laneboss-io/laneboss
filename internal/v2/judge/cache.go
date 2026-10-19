package judge

import (
	"container/list"
	"context"
	"encoding/json"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type cacheEntry struct {
	key     api.Digest
	reply   api.JudgeReply
	expires time.Time
	bytes   int
}

type pendingAsk struct {
	done  chan struct{}
	reply api.JudgeReply
	err   error
}

// Cache retains normalized replies and protected BlobRefs, never raw provider
// bytes. It binds semantic request data, including every rule/decision/context
// and the pinned configuration, excluding per-ask ID/deadline/cost ceilings.
// A hit retains the original observation ID and its historical usage/cost.
// Authorization and durable egress accounting belong to the outside caller.
type Cache struct {
	judge    api.Judge
	config   api.JudgeConfig
	clock    api.Clock
	maxBytes int
	mu       sync.Mutex
	bytes    int
	entries  map[api.Digest]*list.Element
	expiry   *list.List
	pending  map[api.Digest]*pendingAsk
}

var _ api.Judge = (*Cache)(nil)

func NewCache(j api.Judge, config api.JudgeConfig, clock api.Clock, maxBytes int) (*Cache, error) {
	if wire.Nil(j) || wire.Nil(clock) || maxBytes < 1 || maxBytes > api.MaxObjectBytes {
		return nil, problem(api.CodeInvalid, "judge cache requires bounded dependencies")
	}
	if err := wire.ValidateConfig(config); err != nil {
		return nil, err
	}
	if config.CacheTTLMS < 1 {
		return nil, problem(api.CodeInvalid, "judge cache TTL must be positive")
	}
	return &Cache{judge: j, config: config, clock: clock, maxBytes: maxBytes,
		entries: map[api.Digest]*list.Element{}, expiry: list.New(),
		pending: map[api.Digest]*pendingAsk{}}, nil
}

func cloneReply(reply api.JudgeReply) api.JudgeReply {
	results := make([]api.Judgment, len(reply.Results))
	copy(results, reply.Results)
	for i := range results {
		if results[i].Probability != nil {
			value := *results[i].Probability
			results[i].Probability = &value
		}
	}
	reply.Results = results
	reply.BatchIDs = append([]api.ID(nil), reply.BatchIDs...)
	if reply.Request != nil {
		ref := *reply.Request
		reply.Request = &ref
	}
	if reply.Raw != nil {
		ref := *reply.Raw
		reply.Raw = &ref
	}
	return reply
}

func (c *Cache) Fit(ctx context.Context, request api.JudgeRequest) (api.TokenFit, error) {
	return c.judge.Fit(ctx, request)
}

func (c *Cache) expire(now time.Time) {
	for head := c.expiry.Front(); head != nil; head = c.expiry.Front() {
		entry := head.Value.(cacheEntry)
		if now.Before(entry.expires) && c.bytes <= c.maxBytes {
			break
		}
		delete(c.entries, entry.key)
		c.bytes -= entry.bytes
		c.expiry.Remove(head)
	}
}

func (c *Cache) Evaluate(ctx context.Context, request api.JudgeRequest) (api.JudgeReply, error) {
	started := time.Now()
	// Bad Unicode must not hash to json.Marshal's replacement-character form.
	if request.Config != c.config || request.MaxCostMicros <= 0 || ctx.Err() != nil {
		return c.judge.Evaluate(ctx, request)
	}
	if _, _, err := wire.Payload(request); err != nil {
		return c.judge.Evaluate(ctx, request)
	}
	semantic := request
	semantic.ID, semantic.DeadlineMS, semantic.MaxCostMicros = "", 0, 0
	raw, err := json.Marshal(semantic)
	if err != nil {
		return api.JudgeReply{}, problem(api.CodeInvalid, "judge cache request could not be encoded")
	}
	// The key itself has a fixed cost; do not retain the raw request in memory.
	key := wire.Digest(raw)
	c.mu.Lock()
	c.expire(c.clock.Now())
	if element, exists := c.entries[key]; exists {
		reply := cloneReply(element.Value.(cacheEntry).reply)
		c.mu.Unlock()
		reply.LatencyMS = time.Since(started).Milliseconds()
		return reply, nil
	}
	if pending, exists := c.pending[key]; exists {
		c.mu.Unlock()
		ms := request.Config.CommandDeadlineMS
		if request.Purpose == "guidance" {
			ms = request.Config.GuidanceDeadlineMS
		}
		if request.DeadlineMS < ms {
			ms = request.DeadlineMS
		}
		waitCtx, cancel := context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond-time.Since(started))
		defer cancel()
		select {
		case <-waitCtx.Done():
			return api.JudgeReply{}, problem(api.CodeDeadline, "judge cache wait deadline reached")
		case <-pending.done:
			reply := cloneReply(pending.reply)
			reply.LatencyMS = time.Since(started).Milliseconds()
			return reply, pending.err
		}
	}
	pending := &pendingAsk{done: make(chan struct{})}
	c.pending[key] = pending
	c.mu.Unlock()
	reply, err := c.judge.Evaluate(ctx, request)
	if ctx.Err() != nil {
		reply, err = api.JudgeReply{}, problem(api.CodeCancelled, "judge cache evaluation cancelled")
	}
	var encoded []byte
	if err == nil && reply.Status == "scored" {
		err = wire.ScoredReply(reply, request)
		if err == nil {
			encoded, err = json.Marshal(reply)
			if err != nil {
				err = problem(api.CodeIntegrity, "judge cache result could not be encoded")
			}
		}
		if err != nil {
			reply = api.JudgeReply{}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pending.reply, pending.err = cloneReply(reply), err
	delete(c.pending, key)
	defer close(pending.done)
	if err != nil || reply.Status != "scored" {
		return reply, err
	}
	// Charge both the serialized normalized reply and fixed map/list overhead.
	size := len(encoded) + 256
	if size > c.maxBytes {
		return reply, nil
	}
	now := c.clock.Now()
	c.expire(now)
	entry := cacheEntry{key: key, reply: cloneReply(reply), bytes: size,
		expires: now.Add(time.Duration(c.config.CacheTTLMS) * time.Millisecond)}
	c.entries[key] = c.expiry.PushBack(entry)
	c.bytes += size
	c.expire(now)
	return reply, nil
}

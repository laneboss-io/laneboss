package eventstore

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"laneboss.io/laneboss/internal/contextio"
)

const MaxUsageBytes = 8 * 1024 * 1024
const MaxUsageLineBytes = 2 * 1024 * 1024
const maxUsageRecords = 8192
const maxUsageCacheBytes = 32 * 1024 * 1024
const maxUsageCacheEntries = 64

type RunUsage struct {
	Records      []Object
	Available    bool
	Partial      bool
	SkippedLines int
	BytesRead    int64
	Capped       bool
}

type usageEntry struct {
	info       os.FileInfo
	start, end int64
	result     RunUsage
	weight     int64
}

// UsageCache is owned by a dashboard handler. It deduplicates simultaneous
// scans of the same run, and retains bounded receipt data, never file handles.
// Cache identity includes the run, log inode, size, mtime and recorded interval.
type UsageCache struct {
	mu      sync.Mutex
	entries map[string]usageEntry
	pending map[string]chan struct{}
	order   []string
	bytes   int64
}

func (c *UsageCache) enter(ctx context.Context, key string) (func(), error) {
	if c == nil {
		return func() {}, ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		if c.pending == nil {
			c.pending = map[string]chan struct{}{}
		}
		if done := c.pending[key]; done != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				continue
			}
		}
		done := make(chan struct{})
		c.pending[key] = done
		c.mu.Unlock()
		return func() { c.mu.Lock(); delete(c.pending, key); close(done); c.mu.Unlock() }, nil
	}
}

func copyUsage(ctx context.Context, result RunUsage) (RunUsage, error) {
	rows := make([]Object, 0, len(result.Records))
	for _, row := range result.Records {
		if err := ctx.Err(); err != nil {
			return RunUsage{}, err
		}
		rows = append(rows, ScreenValue(row).(Object))
	}
	result.Records = rows
	return result, ctx.Err()
}

func (c *UsageCache) get(ctx context.Context, key string, info os.FileInfo, start, end int64) (RunUsage, bool, error) {
	if c == nil {
		return RunUsage{}, false, nil
	}
	c.mu.Lock()
	entry, ok := c.entries[key]
	c.mu.Unlock()
	if !ok || !os.SameFile(info, entry.info) || info.Size() != entry.info.Size() || !info.ModTime().Equal(entry.info.ModTime()) || start != entry.start || end != entry.end {
		return RunUsage{}, false, nil
	}
	result, err := copyUsage(ctx, entry.result)
	return result, true, err
}

func (c *UsageCache) put(ctx context.Context, key string, info os.FileInfo, start, end int64, result RunUsage) error {
	if c == nil {
		return ctx.Err()
	}
	copy, err := copyUsage(ctx, result)
	if err != nil {
		return err
	}
	weight := int64(len(copy.Records)) * 512
	for _, row := range copy.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		weight += int64(len(Canonical(row)))
	}
	if weight > maxUsageCacheBytes {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]usageEntry{}
	}
	if old, ok := c.entries[key]; ok {
		c.bytes -= old.weight
		delete(c.entries, key)
		for i, k := range c.order {
			if k == key {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
	}
	for len(c.order) > 0 && (len(c.entries) >= maxUsageCacheEntries || c.bytes+weight > maxUsageCacheBytes) {
		old := c.order[0]
		c.order = c.order[1:]
		c.bytes -= c.entries[old].weight
		delete(c.entries, old)
	}
	c.entries[key] = usageEntry{info: info, start: start, end: end, result: copy, weight: weight}
	c.order = append(c.order, key)
	c.bytes += weight
	return nil
}

// Oversized lines are drained in bounded chunks. No prefix is interpreted as
// a receipt, and the next complete line is still eligible for parsing.
func scanRunUsage(ctx context.Context, source io.Reader, capped bool) (RunUsage, error) {
	raw := &contextio.Reader{Context: ctx, Source: source}
	reader := bufio.NewReaderSize(raw, 64*1024)
	result := RunUsage{Records: []Object{}, Available: true, Partial: capped, Capped: capped}
	line := 0
	data := []byte{}
	oversized := false
	for {
		if err := ctx.Err(); err != nil {
			return RunUsage{}, err
		}
		chunk, err := reader.ReadSlice('\n')
		if len(data)+len(chunk) > MaxUsageLineBytes {
			oversized = true
			data = nil
		}
		if !oversized {
			data = append(data, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return RunUsage{}, err
		}
		if len(chunk) > 0 || len(data) > 0 || oversized {
			line++
			if oversized {
				result.Partial = true
				result.SkippedLines++
			} else if !(capped && errors.Is(err, io.EOF)) {
				parsed, parseErr := Parse(data, "the recorded usage event")
				if err := ctx.Err(); err != nil {
					return RunUsage{}, err
				}
				if parseErr == nil {
					e := object(parsed)
					usage := object(e["usage"])
					if (e["type"] == "turn.completed" || e["type"] == "result") && (usage != nil || e["total_cost_usd"] != nil) {
						if len(result.Records) == maxUsageRecords {
							result.Partial = true
							result.Capped = true
							break
						}
						result.Records = append(result.Records, Object{"line": line, "type": e["type"], "usage": usage, "total_cost_usd": e["total_cost_usd"], "duration_ms": e["duration_ms"], "model": e["model"], "timestamp": e["timestamp"]})
					}
				}
			}
		}
		data = data[:0]
		oversized = false
		if errors.Is(err, io.EOF) {
			break
		}
	}
	result.BytesRead = raw.Bytes
	return result, nil
}

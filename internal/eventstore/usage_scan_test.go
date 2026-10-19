package eventstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cancelStream struct {
	source io.Reader
	cancel context.CancelFunc
	bytes  int
	calls  int
}

func (r *cancelStream) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.bytes += n
	r.calls++
	if r.cancel != nil {
		r.cancel()
	}
	return n, err
}

func TestUsageLongLine(t *testing.T) {
	stream := strings.Repeat("x", 3*1024*1024) + "\n" + `{"type":"turn.completed","usage":{"input_tokens":17,"output_tokens":6}}` + "\n"
	result, err := scanRunUsage(context.Background(), strings.NewReader(stream), false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || result.SkippedLines != 1 || len(result.Records) != 1 || result.BytesRead != int64(len(stream)) {
		t.Fatalf("long line lost subsequent receipt: %#v", result)
	}
	if Canonical(result.Records[0]["usage"]) != `{"input_tokens":17,"output_tokens":6}` {
		t.Fatal("recorded usage changed")
	}
}

func TestUsageCancelledRead(t *testing.T) {
	stream := strings.Repeat("x", 3*1024*1024) + "\n" + `{"type":"result","total_cost_usd":0.2}` + "\n"
	control := &cancelStream{source: strings.NewReader(stream)}
	result, err := scanRunUsage(context.Background(), control, false)
	if err != nil || len(result.Records) != 1 || control.bytes != len(stream) {
		t.Fatalf("control did not consume the real stream: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &cancelStream{source: strings.NewReader(stream), cancel: cancel}
	_, err = scanRunUsage(ctx, source, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read returned %v", err)
	}
	if source.calls != 1 || source.bytes <= 0 || source.bytes > 64*1024 || source.bytes >= control.bytes {
		t.Fatalf("reading continued after cancellation: calls=%d bytes=%d", source.calls, source.bytes)
	}
}

func TestUsageCacheInvalidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.log")
	if err := os.WriteFile(path, []byte("initial\n"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cache := &UsageCache{}
	result := RunUsage{Records: []Object{{"usage": Object{"input_tokens": 17}}}, Available: true, BytesRead: info.Size()}
	if err := cache.put(context.Background(), "run", info, 0, info.Size(), result); err != nil {
		t.Fatal(err)
	}
	first, hit, err := cache.get(context.Background(), "run", info, 0, info.Size())
	if err != nil || !hit {
		t.Fatalf("cache miss: %v", err)
	}
	object(first.Records[0]["usage"])["input_tokens"] = 99
	second, hit, err := cache.get(context.Background(), "run", info, 0, info.Size())
	if err != nil || !hit || Canonical(second.Records[0]["usage"]) != `{"input_tokens":17}` {
		t.Fatal("cache aliased caller-owned rows")
	}
	if err := os.WriteFile(path, []byte("initial\ngrown\n"), 0600); err != nil {
		t.Fatal(err)
	}
	grown, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, hit, err = cache.get(context.Background(), "run", grown, 0, grown.Size())
	if err != nil || hit {
		t.Fatal("cache reused a changed log")
	}
	_, hit, err = cache.get(context.Background(), "other-run", info, 0, info.Size())
	if err != nil || hit {
		t.Fatal("cache crossed run identities")
	}
}

func TestUsageWaitCancelled(t *testing.T) {
	cache := &UsageCache{}
	release, err := cache.enter(context.Background(), "run")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = cache.enter(ctx, "run")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter returned %v", err)
	}
	release()
	next, err := cache.enter(context.Background(), "run")
	if err != nil {
		t.Fatal(err)
	}
	next()
}

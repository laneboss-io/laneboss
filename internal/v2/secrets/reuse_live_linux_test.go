//go:build linux

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Observe the real scanner's read-only descriptor, and synchronize a separate
// writer after its first read. This makes the race deterministic without a
// production hook, mocked file bytes, timing sleeps or a scanner replacement.
type liveReuseContext struct {
	context.Context
	path             string
	repeat           bool
	attempts, writes int
	lastOffset       int64
	active, changed  bool
	requests         chan struct{}
	results          chan error
	failure          error
}

func (c *liveReuseContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		c.failure = err
		return context.Canceled
	}
	for _, entry := range entries {
		path, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil || path != c.path {
			continue
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			c.failure = err
			return context.Canceled
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			continue
		}
		offset, err := unix.Seek(fd, 0, io.SeekCurrent)
		if err != nil {
			c.failure = err
			return context.Canceled
		}
		if offset == 0 && (!c.active || c.lastOffset > 0) {
			c.attempts++
			c.changed = false
		}
		c.active, c.lastOffset = true, offset
		if offset > 0 && !c.changed && (c.repeat || c.writes == 0) {
			c.changed = true
			select {
			case c.requests <- struct{}{}:
			case <-c.Done():
				return c.Context.Err()
			}
			select {
			case err := <-c.results:
				if err != nil {
					c.failure = err
					return context.Canceled
				}
				c.writes++
			case <-c.Done():
				return c.Context.Err()
			}
		}
		break
	}
	return c.Context.Err()
}

func liveReuseWriter(t *testing.T, parent context.Context, path string, repeat bool, write func() error) *liveReuseContext {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	c := &liveReuseContext{Context: ctx, path: path, repeat: repeat,
		requests: make(chan struct{}), results: make(chan error, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range c.requests {
			c.results <- write()
		}
	}()
	t.Cleanup(func() {
		cancel()
		close(c.requests)
		<-done
	})
	return c
}

func writeLiveReuse(path string, data []byte, truncate bool) error {
	flags := os.O_WRONLY | os.O_APPEND
	if truncate {
		flags = os.O_WRONLY | os.O_TRUNC
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(data)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil {
		return writeErr
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func TestReuseLiveScanner(t *testing.T) {
	for _, mode := range []string{"settles", "never-settles", "wal-key", "wal-last8", "transient-key"} {
		t.Run(mode, func(t *testing.T) {
			material, inputs := reuseScanFixture(t)
			path := filepath.Join(inputs.Evidence, "state.sqlite-wal")
			seed := bytes.Repeat([]byte("x"), 128*1024)
			initial := append([]byte(nil), seed...)
			if mode == "transient-key" {
				copy(initial, material.Bytes)
			}
			defer clear(initial)
			if os.WriteFile(path, initial, 0600) != nil {
				t.Fatal("cannot prepare live evidence control")
			}
			appendix := []byte("ordinary append\n")
			if mode == "wal-key" {
				appendix = material.Bytes
			} else if mode == "wal-last8" {
				appendix = material.Bytes[len(material.Bytes)-8:]
			}
			ctx := liveReuseWriter(t, context.Background(), path, mode == "never-settles", func() error {
				if mode == "transient-key" {
					return writeLiveReuse(path, seed, true)
				}
				return writeLiveReuse(path, appendix, false)
			})
			result := ScanAPIKeyReleaseInputs(ctx, material, inputs)
			if ctx.failure != nil || ctx.Context.Err() != nil || ctx.writes == 0 {
				t.Fatal("live writer did not overlap a bounded scanner read")
			}
			place := result[5]
			if mode == "never-settles" {
				if ctx.attempts != 8 || ctx.writes != 8 || !place.Unreadable || place.UnreadablePath != path || result.Clean() {
					t.Fatal("continuously changing WAL did not exhaust eight attempts and remain unreadable")
				}
			} else if ctx.attempts != 2 || place.Unreadable || place.Files != 1 {
				t.Fatal("settled WAL remained unreadable instead of receiving a stable reread")
			}
			hit := mode == "wal-key" || mode == "wal-last8" || mode == "transient-key"
			if place.Key != (hit && mode != "wal-last8") || place.Last8 != hit || hit && place.Path != path || result.Clean() != (mode == "settles") {
				t.Fatal("live WAL scan lost its material match or clean control")
			}
			encoded, err := json.Marshal(result)
			if err != nil || bytes.Contains(encoded, material.Bytes[len(material.Bytes)-8:]) {
				t.Fatal("live WAL diagnostics exposed material")
			}
		})
	}
}

func TestReuseLiveRelease(t *testing.T) {
	for _, mode := range []string{"settles", "never-settles", "wal-key", "wal-last8"} {
		t.Run(mode, func(t *testing.T) {
			m, _ := projectionCase(t, "claude-api-key")
			inputs := enableReuseFixture(t, m)
			path := filepath.Join(inputs.Evidence, "state.sqlite-wal")
			if os.WriteFile(path, bytes.Repeat([]byte("x"), 128*1024), 0600) != nil {
				t.Fatal("cannot prepare live release evidence")
			}
			var live *liveReuseContext
			m.c.service.deps.Backend.(*reuseBackend).scanner = APIKeyReleaseScanFunc(func(ctx context.Context, _ api.CredentialProjectionAuthority, material api.SecretMaterial) (APIKeyScanResult, error) {
				appendix := []byte("ordinary append\n")
				if mode == "wal-key" {
					appendix = material.Bytes
				} else if mode == "wal-last8" {
					appendix = material.Bytes[len(material.Bytes)-8:]
				}
				live = liveReuseWriter(t, ctx, path, mode == "never-settles", func() error {
					return writeLiveReuse(path, appendix, false)
				})
				result := ScanAPIKeyReleaseInputs(live, material, inputs)
				if live.Context.Err() != nil {
					t.Error("release scan exceeded its concurrent-writer deadline")
				}
				return result, nil
			})
			record, _ := reviewWithdrawal(t, m, "release", true)
			_, finishErr := m.c.service.FinishCredentialWithdrawal(context.Background(), record, m.withdrawal)
			if live == nil || live.failure != nil || live.writes == 0 {
				t.Fatal("release scanner did not exercise its concurrent writer")
			}
			blocked := mode != "settles"
			if (finishErr != nil) != blocked {
				t.Fatal("release refused a settled clean WAL or admitted changing/material-bearing evidence")
			}
			status, err := m.c.service.APIKeyReleaseStatus(context.Background(), m.a.ID, m.a.Request.Handoff.Spec.Runner.Slot.ID)
			if err != nil || status.RotationRequired != blocked || status.Scan.Clean() == blocked || status.Scan[5].Unreadable != (mode == "never-settles") {
				t.Fatal("live release lost its exact scan verdict or rotation fence")
			}
			if blocked && (!strings.Contains(finishErr.Error(), "rotation required: evidence") || !strings.Contains(finishErr.Error(), strconv.Quote(path))) {
				t.Fatal("live release refusal omitted its evidence path")
			}
			if mode == "wal-key" || mode == "wal-last8" {
				if !status.Scan[5].Last8 || status.Scan[5].Path != path {
					t.Fatal("release did not retain the match in its actively written WAL")
				}
			}
			if blocked {
				if os.WriteFile(path, []byte("ordinary replacement\n"), 0600) != nil {
					t.Fatal("cannot settle quarantined evidence control")
				}
				material, err := m.c.service.deps.Backend.Fetch(context.Background(), m.c.profile.Source)
				defer clear(material.Bytes)
				if err == nil || len(material.Bytes) != 0 {
					t.Fatal("settling or removing a live WAL match cleared its durable quarantine")
				}
			}
		})
	}
}

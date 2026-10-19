package lifecycle

import (
	"context"
	"errors"
	"io"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

// CapturePipe drains an outside-owned vendor pipe into a durable sink. The
// sink must commit the bytes before returning nil. No lane transcript or hook
// callback is accepted here, and this function alone claims no tool coverage.
// Runtime wiring must authenticate the producer and commit CaptureRecords.
// The returned offset counts only acknowledged bytes, including bytes returned
// together with EOF or a later read error. Every failure is incomplete capture.
func CapturePipe(ctx context.Context, source io.ReadCloser, offset int64,
	emit func(context.Context, int64, []byte) error) (next int64, result error) {
	if err := contextReady(ctx); err != nil {
		return offset, err
	}
	if absent(source) || emit == nil || offset < 0 || uint64(offset) > maxInteger {
		return offset, invalid("invalid outside capture pipe or offset")
	}
	var once sync.Once
	var closeErr error
	closePipe := func() { once.Do(func() { closeErr = source.Close() }) }
	stop := context.AfterFunc(ctx, closePipe)
	defer func() {
		stop()
		closePipe()
		if result == nil && closeErr != nil {
			result = failure(closeErr)
		}
	}()
	next = offset
	buffer := make([]byte, api.MaxChunkBytes)
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return next, failure(err)
		}
		n, readErr := source.Read(buffer)
		if n < 0 || n > len(buffer) {
			return next, integrity("capture reader returned an invalid byte count")
		}
		if n > 0 {
			if uint64(next)+uint64(n) > maxInteger {
				return next, integrity("capture offset exhausted")
			}
			// The sink owns these exact bytes after acknowledgment; the next
			// pipe read cannot mutate a previously retained capture object.
			data := append([]byte{}, buffer[:n]...)
			if err := emit(ctx, next, data); err != nil {
				return next, failure(err)
			}
			next += int64(n)
			emptyReads = 0
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return next, problem(api.CodeUnavailable, "capture pipe made no progress",
					"Record an incomplete capture gap and stop the contained run.")
			}
		}
		if readErr != nil {
			if ctx.Err() != nil {
				return next, failure(ctx.Err())
			}
			if errors.Is(readErr, io.EOF) {
				return next, nil
			}
			return next, failure(readErr)
		}
	}
}

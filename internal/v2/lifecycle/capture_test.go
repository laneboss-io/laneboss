package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCaptureKeepsExactRanges(t *testing.T) {
	input := append(bytes.Repeat([]byte{0, 255, 10, 13, 'x'}, 60000), []byte("final\n")...)
	var retained [][]byte
	var offsets []int64
	next, err := CapturePipe(context.Background(), io.NopCloser(bytes.NewReader(input)), 17,
		func(_ context.Context, offset int64, data []byte) error {
			if len(data) == 0 || len(data) > api.MaxChunkBytes {
				t.Fatal("capture chunk exceeded its bound")
			}
			offsets = append(offsets, offset)
			retained = append(retained, data)
			return nil
		})
	if err != nil || next != int64(len(input))+17 || len(retained) < 2 {
		t.Fatalf("capture did not retain all chunks: %v", err)
	}
	var actual []byte
	position := int64(17)
	for i, data := range retained {
		if offsets[i] != position {
			t.Fatal("capture offsets are not contiguous")
		}
		actual = append(actual, data...)
		position += int64(len(data))
	}
	if !bytes.Equal(actual, input) {
		t.Fatal("later pipe reads overwrote exact retained bytes")
	}
}

type lastRead struct {
	done bool
	err  error
}

func (reader *lastRead) Read(buffer []byte) (int, error) {
	if reader.done {
		return 0, io.EOF
	}
	reader.done = true
	return copy(buffer, []byte("last bytes")), reader.err
}

func (*lastRead) Close() error { return nil }

func TestCaptureReadErrorKeepsBytes(t *testing.T) {
	for _, atEnd := range []bool{false, true} {
		readErr := errors.New("fixture read failure")
		if atEnd {
			readErr = io.EOF
		}
		var got []byte
		next, err := CapturePipe(context.Background(), &lastRead{err: readErr}, 0,
			func(_ context.Context, _ int64, data []byte) error {
				got = append(got, data...)
				return nil
			})
		if string(got) != "last bytes" || next != int64(len(got)) {
			t.Fatal("bytes returned with terminal read status were dropped")
		}
		if atEnd && err != nil {
			t.Fatalf("real EOF was not successful completion: %v", err)
		}
		if !atEnd {
			requireCode(t, err, api.CodeIntegrity)
		}
	}
}

func TestCaptureSinkFailureIsVisible(t *testing.T) {
	full := &api.Error{Code: api.CodeBudget, Message: "fixture spool full"}
	next, err := CapturePipe(context.Background(), io.NopCloser(bytes.NewReader([]byte("capture input"))), 10,
		func(context.Context, int64, []byte) error { return full })
	if err != full || next != 10 {
		t.Fatalf("sink failure was swallowed or uncommitted bytes acknowledged: %v", err)
	}
}

type announcedPipe struct {
	io.ReadCloser
	entered chan struct{}
	once    sync.Once
}

func (pipe *announcedPipe) Read(data []byte) (int, error) {
	pipe.once.Do(func() { close(pipe.entered) })
	return pipe.ReadCloser.Read(data)
}

func TestCaptureCancellationClosesPipe(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	pipe := &announcedPipe{ReadCloser: reader, entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := CapturePipe(ctx, pipe, 0,
			func(context.Context, int64, []byte) error { return errors.New("unexpected data") })
		result <- err
	}()
	select {
	case <-pipe.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("capture never entered its owned pipe read")
	}
	cancel()
	select {
	case err := <-result:
		requireCode(t, err, api.CodeCancelled)
	case <-time.After(2 * time.Second):
		t.Fatal("capture cancellation failed to close its owned pipe")
	}
}

func TestStrictRequestBytes(t *testing.T) {
	bad := []string{
		`{"life_id":"child","run":2,"run":1}`,
		`{"life_id":"child"}`,
		`{"life_id":"child","run":null}`,
		`{"life_id":"child","run":2,"actor":"forged"}`,
		`{"life_id":"child","run":2,"Run":1}`,
		`{"life_id":"child","run":2} {}`,
		`{"life_id":"\ud800","run":2}`,
		`{"life_id":"\udc00","run":2}`,
		`{"life_id":"child","run":9007199254740992}`,
	}
	for _, input := range bad {
		var target api.LifeRef
		requireCode(t, DecodeRequest([]byte(input), &target), api.CodeInvalid)
	}
	var target api.LifeRef
	if err := DecodeRequest([]byte(`{"life_id":"\ud83d\ude00","run":2}`), &target); err != nil ||
		target.LifeID != "😀" {
		t.Fatalf("paired Unicode escapes did not preserve input: %v", err)
	}
	if err := DecodeRequest([]byte(`{"life_id":"child","run":2}`), &target); err != nil ||
		target.LifeID != "child" || target.Run != 2 {
		t.Fatalf("valid request did not decode: %v", err)
	}
}

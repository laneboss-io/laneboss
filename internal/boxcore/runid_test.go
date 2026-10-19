package boxcore

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestNewRunID(t *testing.T) {
	now := time.Date(2026, 10, 14, 16, 25, 30, 987, time.FixedZone("demo", 2*60*60))
	cases := []struct {
		name string
		rnd  io.Reader
		want string
		err  error
	}{
		{"exact", bytes.NewReader([]byte{0xa1, 0xb2, 0xc3}),
			"20261014t142530-a1b2c3", nil},
		{"other-bytes", bytes.NewReader([]byte{0, 1, 0xff}),
			"20261014t142530-0001ff", nil},
		{"fragmented", singleByte{bytes.NewReader([]byte{0xa1, 0xb2, 0xc3})},
			"20261014t142530-a1b2c3", nil},
		{"short", bytes.NewReader([]byte{1, 2}), "", io.ErrUnexpectedEOF},
		{"empty", bytes.NewReader(nil), "", io.EOF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewRunID(now, tc.rnd)
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("NewRunID = %q, %v; want %q, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

type singleByte struct {
	r io.Reader
}

func (r singleByte) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

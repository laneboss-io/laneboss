//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type socketReadError struct{}

func (socketReadError) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestArchSocketStream(t *testing.T) {
	const header = "Num       RefCount Protocol Flags    Type St Inode Path\n"
	const record = "0000000000000000: 00000002 00000000 00010000 0001 01 12345"
	const endpoint = "/runtime/worker  with spaces.sock"
	large := strings.Repeat(record+" /other.sock\n", api.MaxFrameBytes/len(record)+100)
	if len(large) <= api.MaxFrameBytes {
		t.Fatal("stream fixture does not exceed the former aggregate frame cap")
	}
	for _, row := range []struct {
		name    string
		input   io.Reader
		count   uint64
		message string
	}{
		{"large-absent", strings.NewReader(header + large), 0, ""},
		{"late-match", strings.NewReader(header + large + record + " " + endpoint + "\n"), 1, ""},
		{"complete", strings.NewReader(header + record + "\n"), 0, ""},
		{"empty-inventory", strings.NewReader(header), 0, ""},
		{"empty-stream", strings.NewReader(""), 0, "archive endpoint kernel inventory is incomplete"},
		{"header", strings.NewReader("Num bad header\n"), 0, "archive endpoint kernel inventory has an unknown shape"},
		{"partial", strings.NewReader(header + record), 0, "archive endpoint kernel inventory is incomplete"},
		{"oversize", strings.NewReader(header + record + " " + strings.Repeat("x", 4096) + "\n"), 0, "archive endpoint kernel inventory is incomplete"},
		{"malformed", strings.NewReader(header + "missing columns\n"), 0, "archive endpoint kernel record is incomplete"},
		{"bad-number", strings.NewReader(header + strings.Replace(record, "00000002", "not-hex", 1) + "\n"), 0, "archive endpoint kernel record is incomplete"},
		{"read-error", io.MultiReader(strings.NewReader(header+large), socketReadError{}), 0, "archive endpoint kernel inventory is incomplete"},
		{"error-after-match", io.MultiReader(strings.NewReader(header+record+" "+endpoint+"\n"), socketReadError{}), 0, "archive endpoint kernel inventory is incomplete"},
		{"suffix-after-match", strings.NewReader(header + record + " " + endpoint + "\n" + "partial"), 0, "archive endpoint kernel inventory is incomplete"},
		{"multiple", strings.NewReader(header + record + " " + endpoint + "\n" + record + " " + endpoint + "\n"), 2, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			count, err := archiveSocketInventory(context.Background(), row.input, endpoint)
			if row.message == "" {
				if err != nil || count != row.count {
					t.Fatalf("acceptance: socket stream lost a complete inventory or late match: count=%d err=%v", count, err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || typed.Message != row.message {
				t.Fatalf("acceptance: socket stream accepted an incomplete kernel inventory: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var typed *api.Error
	if _, err := archiveSocketInventory(ctx, strings.NewReader(header), endpoint); !errors.As(err, &typed) || typed.Code != api.CodeCancelled {
		t.Fatal("acceptance: socket inventory ignored cancellation")
	}
}

package admin

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestHelperJournalRegression(t *testing.T) {
	private := t.Name() + "/untrusted-value"
	refusal := failure(api.CodeContainmentUnknown, private)
	tagged := api.WithHelperReason(refusal, "storage_parent")
	trace := &helperRequestTrace{method: "allocate_launch", check: "operation"}
	var journal bytes.Buffer
	if err := trace.write(&journal, tagged); err != nil {
		t.Fatal(err)
	}
	var entry map[string]string
	if json.Unmarshal(journal.Bytes(), &entry) != nil || len(entry) != 4 || entry["method"] != "allocate_launch" || entry["code"] != string(refusal.Code) || entry["reason"] != "storage_parent" ||
		bytes.Count(journal.Bytes(), []byte{'\n'}) != 1 || bytes.Contains(journal.Bytes(), []byte(private)) {
		t.Fatal("helper journal lost the actual check or exposed a value")
	}
	journal.Reset()
	trace.method, trace.check = private, private
	if err := trace.write(&journal, errors.New(private)); err != nil || bytes.Contains(journal.Bytes(), []byte(private)) {
		t.Fatal("helper transport journal accepted caller-controlled names", err)
	}
	if err := trace.write(shortHelperJournal{}, tagged); !errors.Is(err, errHelperJournal) {
		t.Fatal("helper journal accepted a short write")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	window, err := openHelperWindow(ctx, left, 500*time.Millisecond, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer window.finish()
	finished := make(chan error, 1)
	go func() { finished <- window.refuse(helperProtocol, "helper-journal-once", tagged) }()
	var response helperResponse
	if err := readFrameForJournal(right, &response); err != nil {
		t.Fatal(err)
	}
	returned := <-finished
	if response.Error == nil || response.Error.Code != refusal.Code || response.Reason != "storage_parent" || api.HelperReason(returned) != response.Reason || returned == nil {
		t.Fatal("helper reply lost the journal check or swallowed its refusal")
	}
}

type shortHelperJournal struct{}

func (shortHelperJournal) Write(data []byte) (int, error) { return len(data) - 1, nil }

func readFrameForJournal(connection net.Conn, result any) error {
	var length [4]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > api.MaxFrameBytes {
		return failure(api.CodeInvalid, "journal test received an unbounded frame")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(connection, data); err != nil {
		return err
	}
	return decodeStrict(data, result)
}

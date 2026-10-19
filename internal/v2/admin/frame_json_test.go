package admin

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestHelperJSONProducer(t *testing.T) {
	nonce, err := randomID("frame-")
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		name, reason string
		data         json.RawMessage
	}{
		{"duplicate", "duplicate", json.RawMessage(`{"x":1,"x":2}`)},
		{"limit", "frame_limit", json.RawMessage(`{"x":"` + strings.Repeat("x", api.MaxFrameBytes) + `"}`)},
		{"utf8", "utf8", json.RawMessage([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})},
		{"surrogate", "surrogate", json.RawMessage(`{"x":"\ud800"}`)},
		{"encoding", "encoding", json.RawMessage(`{"x":`)},
	} {
		t.Run(sample.name, func(t *testing.T) {
			response := helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: nonce, Result: sample.data}
			// A stricter native marshaler may refuse before the raw preflight.
			// Determine that independent stage from its actual result, not a
			// fabricated producer return or a generic acceptable failure.
			_, marshalErr := json.Marshal(response)
			wantReason, wantCode := sample.reason, api.CodeInvalid
			if marshalErr != nil {
				wantReason, wantCode = "encoding", api.CodeIntegrity
			}
			var stream bytes.Buffer
			err := writeFrame(&stream, response)
			var typed *api.Error
			frame, reason := api.JSONFailureFacts(err)
			if !errors.As(err, &typed) || typed.Code != wantCode || frame != api.JSONFrameHelperResponse || reason != wantReason || stream.Len() != 0 {
				t.Fatal("acceptance: invalid helper JSON reached the stream or lost its producer reason")
			}
		})
	}
	response := helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: nonce, Result: json.RawMessage(`{"x":"value"}`)}
	var stream bytes.Buffer
	if err := writeFrame(&stream, response); err != nil {
		t.Fatal("valid helper producer frame was refused")
	}
	data := stream.Bytes()
	if len(data) < 4 || int(binary.BigEndian.Uint32(data)) != len(data)-4 {
		t.Fatal("valid helper frame did not retain its complete length prefix")
	}
	var received helperResponse
	if err := decodeStrict(data[4:], &received); err != nil || received.Nonce != nonce || !bytes.Equal(received.Result, response.Result) {
		t.Fatal("acceptance: valid helper producer bytes changed across strict framing")
	}
}

func TestHelperJSONJournal(t *testing.T) {
	var received helperResponse
	err := decodeStrict([]byte(`{"x":1,"x":2}`), &received)
	var typed *api.Error
	if !errors.As(err, &typed) {
		t.Fatal("helper journal fixture did not obtain its real raw refusal")
	}
	raw, err := json.Marshal(helperReplyDiagnostic(typed))
	if err != nil {
		t.Fatal(err)
	}
	var observed struct {
		Stage  string            `json:"stage"`
		Code   api.ErrorCode     `json:"code"`
		Owner  string            `json:"owner"`
		Frame  api.JSONFrameKind `json:"frame"`
		Reason string            `json:"reason"`
	}
	if err := api.DecodeObject(raw, &observed); err != nil || observed.Frame != api.JSONFrameHelperResponse || observed.Reason != "duplicate" || bytes.Contains(raw, []byte("message")) {
		t.Fatal("acceptance: helper journal lost closed raw-frame facts or logged a message")
	}
	original := failure(api.CodeContainmentUnknown, strings.Repeat("x", api.MaxFrameBytes))
	_, encodingErr := encodeHelperFrame(helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Error: original})
	raw, err = json.Marshal(helperReplyDiagnostic(original, encodingErr))
	if err != nil {
		t.Fatal(err)
	}
	if err := api.DecodeObject(raw, &observed); err != nil || observed.Code != api.CodeContainmentUnknown || observed.Frame != api.JSONFrameHelperResponse || observed.Reason != "frame_limit" || len(raw) > 1024 {
		t.Fatal("acceptance: original gate refusal hid its actual JSON framing failure")
	}
}

func TestHelperJSONRefusal(t *testing.T) {
	nonce, err := randomID("refusal-")
	if err != nil {
		t.Fatal(err)
	}
	_, producerErr := encodeHelperFrame(helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: nonce, Result: json.RawMessage(`{"x":1,"x":2}`)})
	if producerErr == nil {
		t.Fatal("producer refusal fixture did not reach its real duplicate check")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	window, err := openHelperWindow(ctx, left, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer window.finish()
	if err := right.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- window.refuse(helperProtocol, nonce, producerErr) }()
	var header [4]byte
	if _, err := io.ReadFull(right, header[:]); err != nil {
		t.Fatal("producer refusal did not deliver its bounded frame")
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > api.MaxFrameBytes {
		t.Fatal("producer refusal changed its frame budget")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(right, data); err != nil {
		t.Fatal("producer refusal did not deliver its complete bytes")
	}
	var response helperResponse
	if err := decodeStrict(data, &response); err != nil || response.Protocol != helperProtocol || response.Revision != api.ContractRevision || response.Nonce != nonce || len(response.Result) != 0 || response.Error == nil {
		t.Fatal("acceptance: producer JSON failure lost its correlated strict error frame")
	}
	frame, reason := api.JSONFailureFacts(response.Error)
	if frame != api.JSONFrameHelperResponse || reason != "duplicate" || response.Error.Owner != owner {
		t.Fatal("acceptance: producer JSON failure lost its correlated strict error frame")
	}
	select {
	case err := <-done:
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
			t.Fatal("acceptance: delivered producer refusal was reported as success")
		}
	case <-ctx.Done():
		t.Fatal("producer refusal did not complete within its original transport budget")
	}
}

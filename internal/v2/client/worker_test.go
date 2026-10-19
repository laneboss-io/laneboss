package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// These exercise the real private frame encoder/decoder with a component
// transport. Kernel peer pinning remains the installed Linux acceptance test.
func workerWire(t *testing.T, wrongID bool) (*WorkerClient, []byte, <-chan error) {
	t.Helper()
	request := fixtureRequest(t)
	inside, outside := net.Pipe()
	t.Cleanup(func() {
		if err := inside.Close(); err != nil {
			t.Error(err)
		}
	})
	binding := api.InstalledBinding{Config: request.Config, Class: api.EndpointWorker}
	c := &Client{Options: Options{Config: request.Config}, binding: &binding, primary: inside}
	w := &WorkerClient{client: c}
	finished := make(chan error, 1)
	data := []byte(string(request.RequestID) + " persisted source bytes")
	go func() {
		var resultErr error
		defer func() { finished <- errors.Join(resultErr, outside.Close()) }()
		raw, err := wire.ReadFrame(outside)
		if err != nil {
			resultErr = err
			return
		}
		var actual api.Request
		if err := api.DecodeObject(raw, &actual); err != nil {
			resultErr = err
			return
		}
		digest, err := api.RequestDigest(actual)
		if err != nil || digest != actual.RequestSHA256 || actual.Method != api.Method(api.WorkerObjectRead) || actual.Proof != nil {
			resultErr = errors.New("private frame lost its operation or digest")
			return
		}
		var query api.BlobReadRequest
		if err := api.DecodeObject(actual.Params, &query); err != nil {
			resultErr = err
			return
		}
		sum := sha256.Sum256(data)
		body, err := json.Marshal(api.BlobChunk{ObjectID: query.ObjectID, Offset: query.Offset, Data: data, SHA256: api.Digest(hex.EncodeToString(sum[:]))})
		if err != nil {
			resultErr = err
			return
		}
		id := actual.RequestID
		if wrongID {
			id = request.RequestID
		}
		raw, err = json.Marshal(api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: id, Result: body})
		if err != nil {
			resultErr = err
			return
		}
		resultErr = wire.WriteFrame(outside, raw)
	}()
	return w, data, finished
}

func TestWorkerPrivateRead(t *testing.T) {
	w, data, finished := workerWire(t, false)
	query := api.BlobReadRequest{ObjectID: fixtureRequest(t).RequestID, Limit: api.MaxChunkBytes}
	chunk, err := w.Read(context.Background(), query)
	if err != nil || chunk.ObjectID != query.ObjectID || !bytes.Equal(chunk.Data, data) {
		t.Fatal("native worker bridge changed its persisted object bytes", err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
func TestWorkerReplyID(t *testing.T) {
	w, _, finished := workerWire(t, true)
	_, err := w.Read(context.Background(), api.BlobReadRequest{ObjectID: fixtureRequest(t).RequestID, Limit: api.MaxChunkBytes})
	if err == nil {
		t.Fatal("native worker bridge accepted another request reply")
	}
	assertCode(t, err, api.CodeInvalid)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

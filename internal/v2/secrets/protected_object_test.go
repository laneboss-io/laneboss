package secrets

import (
	"bytes"
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestProtectedObjectChunks(t *testing.T) {
	c := newLaunchCase(t, "helper")
	type payload struct {
		Data []byte `json:"data"`
	}
	value := payload{Data: syntheticBytes(t, api.MaxChunkBytes+113)}
	ref := c.store.putObject(t, "chunked-input", "worker_input", value, "chunk-operation")
	if ref.Bytes <= api.MaxChunkBytes || ref.Bytes > api.MaxFrameBytes {
		t.Fatal("protected object control did not span actual chunk bounds")
	}
	data, err := c.service.protectedObject(context.Background(), ref, "chunk-operation")
	if err != nil {
		t.Fatal("protected object reader did not retain every bounded chunk")
	}
	var actual payload
	if api.DecodeObject(data, &actual) != nil || !bytes.Equal(actual.Data, value.Data) {
		t.Fatal("protected object chunks did not reconstruct the exact retained bytes")
	}
}

func TestProtectedObjectChunkGuards(t *testing.T) {
	for _, fault := range []string{"offset", "hash", "empty", "foreign", "overlong"} {
		t.Run(fault, func(t *testing.T) {
			c := newLaunchCase(t, "helper")
			ref := c.store.putObject(t, "chunk-control", "worker_input", struct {
				Data []byte `json:"data"`
			}{syntheticBytes(t, 127)}, "chunk-operation")
			c.store.blobFault = fault
			_, err := c.service.protectedObject(context.Background(), ref, "chunk-operation")
			stageCode(t, err, api.CodeIntegrity)
		})
	}
}

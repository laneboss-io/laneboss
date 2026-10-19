// Package relaymsg publishes fixture replies through the actor's existing
// authenticated blob API. Reports are transport data, never capture authority.
package relaymsg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

type Call func(context.Context, string, any, any) error

func digest(raw []byte) api.Digest {
	sum := sha256.Sum256(raw)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func Publish(ctx context.Context, call Call, message any) (api.BlobRef, error) {
	if call == nil {
		return api.BlobRef{}, errors.New("relay report requires the original authenticated client")
	}
	raw, err := json.Marshal(struct {
		Schema  string `json:"schema"`
		Message any    `json:"message"`
	}{"laneboss.relay-report.v1", message})
	if err != nil || len(raw) == 0 || len(raw) > api.MaxFrameBytes {
		return api.BlobRef{}, errors.New("relay report exceeds its bounded JSON envelope")
	}
	var begun api.BlobUpload
	if err := call(ctx, "blob begin", api.BlobBeginRequest{Class: "report", Bytes: int64(len(raw)), SHA256: digest(raw)}, &begun); err != nil {
		return api.BlobRef{}, err
	}
	if begun.ObjectID == "" || begun.MaxChunkBytes < 1 || begun.MaxChunkBytes > api.MaxChunkBytes {
		return api.BlobRef{}, errors.New("relay report upload returned invalid bounds")
	}
	for offset := 0; offset < len(raw); {
		part := raw[offset:min(offset+begun.MaxChunkBytes, len(raw))]
		var accepted api.BlobUpload
		if err := call(ctx, "blob chunk", api.BlobChunk{ObjectID: begun.ObjectID, Offset: int64(offset), Data: part, SHA256: digest(part)}, &accepted); err != nil {
			return api.BlobRef{}, err
		}
		if accepted.ObjectID != begun.ObjectID || accepted.MaxChunkBytes != begun.MaxChunkBytes {
			return api.BlobRef{}, errors.New("relay report chunk changed its upload")
		}
		offset += len(part)
	}
	var committed api.BlobRef
	if err := call(ctx, "blob commit", api.BlobCommitRequest{ObjectID: begun.ObjectID, SHA256: digest(raw)}, &committed); err != nil {
		return api.BlobRef{}, err
	}
	if committed != (api.BlobRef{ID: begun.ObjectID, Class: "report", Bytes: int64(len(raw)), SHA256: digest(raw)}) {
		return api.BlobRef{}, errors.New("relay report commit differs from its exact bytes")
	}
	return committed, nil
}

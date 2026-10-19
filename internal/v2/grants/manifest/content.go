package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"laneboss.io/laneboss/internal/v2/api"
)

// VerifyContent is the bounded streaming primitive for a confined worker.
// Service preflight checks metadata only; it never assembles candidate files.
// The worker's authenticated reader must enforce its own lease and object ACL.
func VerifyContent(ctx context.Context, entry api.ObjectEntry, ceiling uint64,
	read func(context.Context, api.BlobReadRequest) (api.BlobChunk, error)) error {
	complete := sha256.New()
	var total int64
	for _, ref := range ContentRefs(entry) {
		if err := Blob(ref); err != nil {
			return err
		}
		if uint64(ref.Bytes) > ceiling-uint64(total) {
			return &api.Error{Code: api.CodeBudget, Message: "file exceeds the confined worker byte budget", Instead: "Use a smaller candidate or an explicitly approved budget.", Owner: "lb-v2-grants"}
		}
		part := sha256.New()
		var offset int64
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			limit := min(int64(api.MaxChunkBytes), ref.Bytes-offset)
			if limit == 0 {
				limit = 1
			}
			chunk, err := read(ctx, api.BlobReadRequest{ObjectID: ref.ID, Offset: offset, Limit: int(limit)})
			if err != nil {
				return err
			}
			if chunk.ObjectID != ref.ID || chunk.Offset != offset || int64(len(chunk.Data)) > limit ||
				Hash(chunk.Data) != chunk.SHA256 || int64(len(chunk.Data)) > ref.Bytes-offset {
				return contentError("file part chunk differs from the committed range or digest")
			}
			if len(chunk.Data) == 0 {
				if offset != ref.Bytes {
					return contentError("file part ended before its declared size")
				}
				break
			}
			if _, err := part.Write(chunk.Data); err != nil {
				return err
			}
			if _, err := complete.Write(chunk.Data); err != nil {
				return err
			}
			offset += int64(len(chunk.Data))
		}
		if api.Digest(hex.EncodeToString(part.Sum(nil))) != ref.SHA256 {
			return contentError("file part complete digest changed")
		}
		total += offset
	}
	if entry.Assembly != nil && (total != entry.Assembly.Bytes ||
		api.Digest(hex.EncodeToString(complete.Sum(nil))) != entry.Assembly.SHA256) {
		return contentError("assembled file bytes differ from the declared size or digest")
	}
	return nil
}

func contentError(message string) error {
	return &api.Error{Code: api.CodeIntegrity, Message: message, Instead: "Retain the worker input and reject the inconsistent object.", Owner: "lb-v2-grants"}
}

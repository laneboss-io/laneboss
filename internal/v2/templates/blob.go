package templates

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// ReadVerifiedBlob reads through an already-authorized reader and verifies the
// exact object, offsets, bounded chunks, total length and both digest layers.
// It performs no path lookup and makes no claim about class provenance: the
// service's committed-object metadata and ACL checks still own that decision.
func ReadVerifiedBlob(ctx context.Context, ref api.BlobRef,
	read func(context.Context, api.BlobReadRequest) (api.BlobChunk, error),
) ([]byte, error) {
	if err := checkBlobRef(ref); err != nil {
		return nil, err
	}
	if read == nil {
		return nil, problem(api.CodePrerequisite, "a scoped blob reader is required",
			"Use the authenticated service reader; do not open management files directly.")
	}
	data := make([]byte, 0, min(int(ref.Bytes), api.MaxChunkBytes))
	for int64(len(data)) < ref.Bytes {
		if err := readContext(ctx); err != nil {
			return nil, err
		}
		limit := min(api.MaxChunkBytes, int(ref.Bytes)-len(data))
		chunk, err := read(ctx, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: limit})
		if err != nil {
			return nil, err
		}
		if err := readContext(ctx); err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 || len(chunk.Data) > limit || hash(chunk.Data) != chunk.SHA256 {
			return nil, integrity("retained blob chunk differs from its requested identity, offset, size or digest")
		}
		data = append(data, chunk.Data...)
	}
	if hash(data) != ref.SHA256 {
		return nil, integrity("retained blob differs from its committed digest")
	}
	if err := readContext(ctx); err != nil {
		return nil, err
	}
	end, err := read(ctx, api.BlobReadRequest{ObjectID: ref.ID, Offset: ref.Bytes, Limit: 1})
	if err != nil {
		return nil, err
	}
	if err := readContext(ctx); err != nil {
		return nil, err
	}
	if end.ObjectID != ref.ID || end.Offset != ref.Bytes || len(end.Data) != 0 || end.SHA256 != hash(nil) {
		return nil, integrity("retained blob has bytes beyond its committed length or an invalid end receipt")
	}
	return data, nil
}

func readContext(ctx context.Context) error {
	if ctx == nil {
		return invalid("a blob read context is required")
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return problem(api.CodeDeadline, "blob read deadline expired",
			"Retain the failed read and retry only through the authorized service route.")
	}
	if ctx.Err() != nil {
		return problem(api.CodeCancelled, "blob read was cancelled",
			"Inspect the cancelled request before starting another operation.")
	}
	return nil
}

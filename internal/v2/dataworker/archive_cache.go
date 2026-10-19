package dataworker

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type archiveReadCache struct {
	source archivejob.ReadObject
	refs   map[api.ID]api.BlobRef
	bytes  map[api.ID][]byte
	left   uint64
}

func newArchiveReadCache(tree api.ObjectManifest, source archivejob.ReadObject, ceiling uint64) (*archiveReadCache, error) {
	c := &archiveReadCache{source: source, refs: map[api.ID]api.BlobRef{}, bytes: map[api.ID][]byte{}, left: ceiling}
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			if prior, found := c.refs[ref.ID]; found && prior != ref {
				return nil, lstate.Error(api.CodeIntegrity, "archive source object has competing immutable pins")
			}
			c.refs[ref.ID] = ref
		}
	}
	return c, nil
}

func (c *archiveReadCache) clear() {
	for _, data := range c.bytes {
		clear(data)
	}
}

func (c *archiveReadCache) loadInline(objects []archivejob.FrozenObject) error {
	seen, total := map[api.ID]bool{}, uint64(0)
	for _, object := range objects {
		ref, found := c.refs[object.Ref.ID]
		if !found || ref != object.Ref || seen[ref.ID] || int64(len(object.Bytes)) != ref.Bytes || manifest.Hash(object.Bytes) != ref.SHA256 ||
			len(object.Bytes) > 4096 || total+uint64(len(object.Bytes)) > archivejob.MaxInlineBytes {
			return lstate.Error(api.CodeIntegrity, "archive inline source differs from its complete frozen manifest")
		}
		seen[ref.ID], total = true, total+uint64(len(object.Bytes))
		if uint64(len(object.Bytes)) <= c.left {
			c.bytes[ref.ID], c.left = append([]byte{}, object.Bytes...), c.left-uint64(len(object.Bytes))
		}
	}
	return nil
}

func (c *archiveReadCache) read(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
	if err := ctx.Err(); err != nil {
		return api.BlobChunk{}, err
	}
	ref, source := c.refs[q.ObjectID]
	if !source || ref.Bytes < 0 || ref.Bytes >= api.MaxChunkBytes {
		return c.source(ctx, q)
	}
	if q.Offset < 0 || q.Offset > ref.Bytes || q.Limit < 1 || q.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, lstate.Error(api.CodeInvalid, "archive cached source range escaped its frozen object")
	}
	data, found := c.bytes[ref.ID]
	if !found {
		if uint64(ref.Bytes) > c.left {
			return c.source(ctx, q)
		}
		// BlobRead returns the requested bounded range. One byte beyond the
		// committed end proves absence of a suffix in this same response; a
		// short transport range is followed until that end is actually reached.
		for int64(len(data)) <= ref.Bytes {
			remaining := ref.Bytes - int64(len(data))
			limit := int(remaining + 1)
			chunk, err := c.source(ctx, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: limit})
			if err != nil {
				clear(data)
				return api.BlobChunk{}, err
			}
			if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) > limit || int64(len(chunk.Data)) > remaining ||
				manifest.Hash(chunk.Data) != chunk.SHA256 || len(chunk.Data) == 0 && remaining != 0 {
				clear(data)
				return api.BlobChunk{}, lstate.Error(api.CodeIntegrity, "archive frozen source changed its exact bytes or range")
			}
			data = append(data, chunk.Data...)
			if int64(len(data)) == ref.Bytes {
				break
			}
		}
		if manifest.Hash(data) != ref.SHA256 {
			clear(data)
			return api.BlobChunk{}, lstate.Error(api.CodeIntegrity, "archive frozen source failed its complete digest")
		}
		c.bytes[ref.ID], c.left = data, c.left-uint64(len(data))
	}
	part := append([]byte{}, data[q.Offset:min(ref.Bytes, q.Offset+int64(q.Limit))]...)
	return api.BlobChunk{ObjectID: ref.ID, Offset: q.Offset, Data: part, SHA256: manifest.Hash(part)}, nil
}

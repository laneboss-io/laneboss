package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// ReadBack regenerates the canonical tar from the frozen tree and committed
// content, comparing every byte with independently loaded archive parts. No
// permissive tar parser decides equivalence. The caller must enforce provenance
// and current object ACLs for both the archive parts and frozen content in read.
func ReadBack(ctx context.Context, assembly api.ObjectAssembly, tree api.ObjectManifest, read ReadObject, ceiling uint64) (api.Digest, error) {
	if read == nil || assembly.Bytes <= 0 || uint64(assembly.Bytes) > ceiling || ceiling > manifest.MaxInteger ||
		!manifest.ValidDigest(assembly.SHA256) || len(assembly.Parts) == 0 || len(assembly.Parts) > manifest.MaxEntries {
		return "", fault("archive read-back has an invalid bounded assembly")
	}
	var total int64
	for _, ref := range assembly.Parts {
		if manifest.Blob(ref) != nil || ref.Class != "artifact" || ref.Bytes <= 0 || ref.Bytes > assembly.Bytes-total {
			return "", fault("archive read-back part exceeds its immutable assembly")
		}
		total += ref.Bytes
	}
	if total != assembly.Bytes {
		return "", fault("archive read-back parts do not cover its measured length")
	}
	reader := &partsReader{ctx: ctx, read: read, parts: assembly.Parts, partHash: sha256.New()}
	whole := sha256.New()
	stream := io.TeeReader(reader, whole)
	comparison := &canonicalCompare{input: stream, buffer: make([]byte, api.MaxChunkBytes)}
	if err := Write(ctx, comparison, tree, read, ceiling); err != nil {
		return "", err
	}
	// This read proves exact EOF for the final part as well as the assembly.
	// Even extra zero padding differs from the canonical writer's terminator.
	var extra [1]byte
	n, err := stream.Read(extra[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if n != 0 || !errors.Is(err, io.EOF) {
		return "", fault("archive read-back has bytes after the canonical tar")
	}
	digest := api.Digest(hex.EncodeToString(whole.Sum(nil)))
	if reader.total != assembly.Bytes || comparison.bytes != assembly.Bytes || digest != assembly.SHA256 {
		return "", fault("archive bytes failed independent read-back")
	}
	return digest, nil
}

type canonicalCompare struct {
	input  io.Reader
	buffer []byte
	bytes  int64
}

func (w *canonicalCompare) Write(expected []byte) (int, error) {
	compared := 0
	for len(expected) != 0 {
		count := min(len(expected), len(w.buffer))
		actual := w.buffer[:count]
		if _, err := io.ReadFull(w.input, actual); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return compared, fault("archive read-back ended before the canonical tar")
			}
			return compared, err
		}
		if !bytes.Equal(actual, expected[:count]) {
			return compared, fault("archive read-back differs from the canonical tar bytes")
		}
		compared += count
		w.bytes += int64(count)
		expected = expected[count:]
	}
	return compared, nil
}

type partsReader struct {
	ctx      context.Context
	read     ReadObject
	parts    []api.BlobRef
	index    int
	offset   int64
	total    int64
	partHash hash.Hash
	pending  []byte
}

func (r *partsReader) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(r.pending) != 0 {
		n := copy(data, r.pending)
		r.pending = r.pending[n:]
		r.total += int64(n)
		return n, nil
	}
	for r.index < len(r.parts) {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		ref := r.parts[r.index]
		// Fetch a bounded range once even when tar asks for 512-byte headers.
		// Native object readers must not reload a whole part for every header.
		limit := int(min(int64(api.MaxChunkBytes), ref.Bytes-r.offset))
		if limit == 0 {
			limit = 1 // Prove exact EOF for each committed object.
		}
		chunk, err := r.read(r.ctx, api.BlobReadRequest{ObjectID: ref.ID, Offset: r.offset, Limit: limit})
		if err != nil {
			return 0, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != r.offset || len(chunk.Data) > limit || int64(len(chunk.Data)) > ref.Bytes-r.offset || manifest.Hash(chunk.Data) != chunk.SHA256 {
			return 0, fault("archive read-back chunk differs from its retained object")
		}
		if len(chunk.Data) == 0 {
			if r.offset != ref.Bytes || api.Digest(hex.EncodeToString(r.partHash.Sum(nil))) != ref.SHA256 {
				return 0, fault("archive read-back part failed its full length or digest")
			}
			r.index++
			r.offset = 0
			r.partHash.Reset()
			continue
		}
		n := copy(data, chunk.Data)
		_, _ = r.partHash.Write(chunk.Data)
		r.offset += int64(len(chunk.Data))
		r.pending = chunk.Data[n:]
		r.total += int64(n)
		return n, nil
	}
	return 0, io.EOF
}

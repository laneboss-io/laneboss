package archive

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func fault(message string) error {
	return &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-lifecycle", Message: message,
		Instead: "Preserve the original archive job and repair its immutable inputs or retained bytes."}
}

// Manifest rejects malformed paths, kinds, modes, aliases and object references.
// Its canonical bytes are the first member of every archive.
func Manifest(raw []byte) (api.ObjectManifest, error) {
	var tree api.ObjectManifest
	if err := api.DecodeObject(raw, &tree); err != nil {
		return tree, fault("archive snapshot is not an object manifest")
	}
	if err := manifest.Object(tree); err != nil {
		return tree, err
	}
	return tree, nil
}

func entries(tree api.ObjectManifest) ([]api.ObjectEntry, []byte, error) {
	if err := manifest.Object(tree); err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, nil, err
	}
	raw, err = api.CanonicalJSON(raw)
	if err != nil || len(raw) > api.MaxObjectBytes {
		return nil, nil, fault("archive manifest exceeds its bounded object size")
	}
	ordered := append([]api.ObjectEntry{}, tree.Entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	return ordered, raw, nil
}

func header(entry api.ObjectEntry) *tar.Header {
	h := &tar.Header{Name: "data/" + entry.Path, Mode: int64(entry.Mode), Format: tar.FormatPAX}
	switch entry.Kind {
	case "file":
		h.Typeflag = tar.TypeReg
		if entry.Content != nil {
			h.Size = entry.Content.Bytes
		} else {
			h.Size = entry.Assembly.Bytes
		}
	case "directory":
		h.Typeflag = tar.TypeDir
	case "symlink":
		h.Typeflag, h.Linkname = tar.TypeSymlink, entry.LinkTarget
	}
	return h
}

// Write hashes and checks every immutable part while writing actual file
// content. No host command, working directory, ambient Git or archive utility
// participates. The caller bounds the complete tar stream, including headers.
func Write(ctx context.Context, output io.Writer, tree api.ObjectManifest, read ReadObject, ceiling uint64) error {
	ordered, raw, err := entries(tree)
	if err != nil {
		return err
	}
	if read == nil || output == nil || ceiling == 0 || ceiling > manifest.MaxInteger {
		return fault("archive requires bounded authenticated object streams")
	}
	tw := tar.NewWriter(&limitWriter{ctx: ctx, output: output, remaining: ceiling})
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := tw.Write(raw); err != nil {
		return err
	}
	for _, entry := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tw.WriteHeader(header(entry)); err != nil {
			return err
		}
		if entry.Kind == "file" {
			if err := copyContent(ctx, tw, entry, read, ceiling); err != nil {
				return err
			}
		}
	}
	return tw.Close()
}

type limitWriter struct {
	ctx       context.Context
	output    io.Writer
	remaining uint64
}

func (w *limitWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(data)) > w.remaining {
		return 0, &api.Error{Code: api.CodeBudget, Owner: "lb-v2-lifecycle", Message: "archive exceeds its retained disk budget",
			Instead: "Retain the failed job and request an explicitly approved archive budget."}
	}
	n, err := w.output.Write(data)
	w.remaining -= uint64(n)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func copyContent(ctx context.Context, output io.Writer, entry api.ObjectEntry, read ReadObject, ceiling uint64) error {
	whole, total := sha256.New(), int64(0)
	for _, ref := range manifest.ContentRefs(entry) {
		if err := manifest.Blob(ref); err != nil || ref.Class != "artifact" || uint64(ref.Bytes) > ceiling-uint64(total) {
			return fault("archive file exceeds its bounded immutable input")
		}
		part := sha256.New()
		var offset int64
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			limit := int(min(int64(api.MaxChunkBytes), ref.Bytes-offset))
			if limit == 0 {
				limit = 1
			}
			chunk, err := read(ctx, api.BlobReadRequest{ObjectID: ref.ID, Offset: offset, Limit: limit})
			if err != nil {
				return err
			}
			if chunk.ObjectID != ref.ID || chunk.Offset != offset || len(chunk.Data) > limit || int64(len(chunk.Data)) > ref.Bytes-offset || manifest.Hash(chunk.Data) != chunk.SHA256 {
				return fault("archive source chunk changed its identity, size or digest")
			}
			if len(chunk.Data) == 0 {
				if offset != ref.Bytes {
					return fault("archive source ended before its committed length")
				}
				break
			}
			if _, err := output.Write(chunk.Data); err != nil {
				return err
			}
			_, _ = part.Write(chunk.Data)
			_, _ = whole.Write(chunk.Data)
			offset += int64(len(chunk.Data))
		}
		if api.Digest(hex.EncodeToString(part.Sum(nil))) != ref.SHA256 {
			return fault("archive source bytes failed their committed digest")
		}
		total += offset
	}
	if entry.Assembly != nil && (total != entry.Assembly.Bytes || api.Digest(hex.EncodeToString(whole.Sum(nil))) != entry.Assembly.SHA256) {
		return fault("archive source assembly failed its complete digest")
	}
	return nil
}

package dataworker

import (
	"bytes"
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestArchiveFrozenCacheControls(t *testing.T) {
	for _, mode := range []string{"exact", "suffix", "digest", "chunk", "offset", "short", "budget", "part", "cancelled", "pins"} {
		t.Run(mode, func(t *testing.T) {
			data := []byte("variable frozen source " + mode)
			ref := api.BlobRef{ID: "frozen", Class: "artifact", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
			tree := api.ObjectManifest{Entries: []api.ObjectEntry{{Content: &ref}}}
			calls := 0
			read := func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
				calls++
				if err := ctx.Err(); err != nil {
					return api.BlobChunk{}, err
				}
				body := append([]byte{}, data...)
				if mode == "suffix" {
					body = append(body, '!')
				}
				if mode == "digest" {
					body[0] ^= 1
				}
				body = body[q.Offset:min(int64(len(body)), q.Offset+int64(q.Limit))]
				if mode == "short" && len(body) > 3 {
					body = body[:3]
				}
				chunk := api.BlobChunk{ObjectID: q.ObjectID, Offset: q.Offset, Data: body, SHA256: manifest.Hash(body)}
				if mode == "chunk" {
					chunk.SHA256 = manifest.Hash([]byte("changed"))
				}
				if mode == "offset" {
					chunk.Offset++
				}
				return chunk, nil
			}
			if mode == "pins" {
				changed := ref
				changed.Bytes++
				tree.Entries = append(tree.Entries, api.ObjectEntry{Content: &changed})
			}
			budget := uint64(1024)
			if mode == "budget" {
				budget = 0
			}
			cache, err := newArchiveReadCache(tree, read, budget)
			if mode == "pins" {
				if err == nil {
					t.Fatal("source cache accepted competing immutable pins")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer cache.clear()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			q := api.BlobReadRequest{ObjectID: ref.ID, Limit: len(data)}
			if mode == "part" {
				q.ObjectID = "durable-part"
			}
			if mode == "cancelled" {
				cancel()
			}
			first, err := cache.read(ctx, q)
			if mode == "suffix" || mode == "digest" || mode == "chunk" || mode == "offset" || mode == "cancelled" {
				if err == nil || len(cache.bytes) != 0 {
					t.Fatal("source cache accepted an unverified object", mode, err)
				}
				return
			}
			if err != nil || !bytes.Equal(first.Data, data) {
				t.Fatal("source cache changed actual frozen bytes", err)
			}
			before := calls
			first.Data[0] ^= 1
			again, err := cache.read(ctx, q)
			if err != nil || !bytes.Equal(again.Data, data) {
				t.Fatal("returned range mutated retained source", err)
			}
			cached := mode != "budget" && mode != "part"
			if (calls == before) != cached || cached && cache.left != budget-uint64(len(data)) {
				t.Fatal("source cache ignored its budget or cached independent durable parts")
			}
		})
	}
}

func TestArchiveInlineControls(t *testing.T) {
	for _, mode := range []string{"exact", "bytes", "pin", "foreign", "duplicate", "budget", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			data := []byte("immutable inline input " + mode)
			if mode == "oversize" {
				data = bytes.Repeat([]byte("x"), 4097)
			}
			ref := api.BlobRef{ID: "inline-object", Class: "artifact", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
			cache, err := newArchiveReadCache(api.ObjectManifest{Entries: []api.ObjectEntry{{Content: &ref}}}, nil, 8192)
			if err != nil {
				t.Fatal(err)
			}
			defer cache.clear()
			objects := []archivejob.FrozenObject{{Ref: ref, Bytes: append([]byte{}, data...)}}
			switch mode {
			case "bytes":
				objects[0].Bytes[0] ^= 1
			case "pin":
				objects[0].Ref.Bytes++
			case "foreign":
				objects[0].Ref.ID = "foreign-object"
			case "duplicate":
				objects = append(objects, objects[0])
			case "budget":
				cache.left = 0
			}
			err = cache.loadInline(objects)
			if mode != "exact" && mode != "budget" {
				if err == nil {
					t.Fatal("inline source admitted a changed or oversized manifest input", mode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "budget" {
				if len(cache.bytes) != 0 {
					t.Fatal("inline source exceeded the worker memory budget")
				}
				return
			}
			objects[0].Bytes[0] ^= 1
			chunk, err := cache.read(context.Background(), api.BlobReadRequest{ObjectID: ref.ID, Limit: len(data)})
			if err != nil || !bytes.Equal(chunk.Data, data) {
				t.Fatal("inline source omitted or aliased the actual frozen bytes", err)
			}
		})
	}
}

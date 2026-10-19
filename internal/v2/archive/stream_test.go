package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type byteStore map[api.ID][]byte

func (store byteStore) read(_ context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
	data, found := store[request.ObjectID]
	if !found || request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, errors.New("invalid fixture object range")
	}
	part := data[request.Offset:min(int64(len(data)), request.Offset+int64(request.Limit))]
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: append([]byte{}, part...), SHA256: manifest.Hash(part)}, nil
}

func streamFixture() (api.ObjectManifest, byteStore) {
	data := bytes.Repeat([]byte("archive content\n"), 40000)
	ref := api.BlobRef{ID: "content", Class: "artifact", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
	return api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "work", Kind: "directory", Mode: 0700},
		{Path: "work/main", Kind: "file", Mode: 0600, Content: &ref},
		{Path: "latest", Kind: "symlink", Mode: 0777, LinkTarget: "work/main"},
	}}, byteStore{ref.ID: data}
}

func assemblyFixture(t *testing.T, raw []byte, store byteStore) api.ObjectAssembly {
	t.Helper()
	result := api.ObjectAssembly{SHA256: manifest.Hash(raw), Bytes: int64(len(raw)), Parts: []api.BlobRef{}}
	for len(raw) != 0 {
		n := min(len(raw), api.MaxChunkBytes)
		part := append([]byte{}, raw[:n]...)
		ref := api.BlobRef{ID: api.ID(fmt.Sprintf("part-%d", len(result.Parts))), Class: "artifact", Bytes: int64(n), SHA256: manifest.Hash(part)}
		store[ref.ID] = part
		result.Parts = append(result.Parts, ref)
		raw = raw[n:]
	}
	return result
}

func TestArchiveBytes(t *testing.T) {
	tree, store := streamFixture()
	var output bytes.Buffer
	if err := Write(context.Background(), &output, tree, store.read, 4<<20); err != nil {
		t.Fatal(err)
	}
	assembly := assemblyFixture(t, output.Bytes(), store)
	digest, err := ReadBack(context.Background(), assembly, tree, store.read, 4<<20)
	if err != nil || digest != manifest.Hash(output.Bytes()) || len(assembly.Parts) < 2 {
		t.Fatalf("actual multipart archive did not verify: %v", err)
	}
	tr := tar.NewReader(bytes.NewReader(output.Bytes()))
	files := 0
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == "data/work/main" {
			actual, err := io.ReadAll(tr)
			if err != nil || !bytes.Equal(actual, store["content"]) {
				t.Fatalf("archive omitted or changed file content: %v", err)
			}
			files++
		}
	}
	if files != 1 {
		t.Fatal("archive did not contain its actual file")
	}
	var again bytes.Buffer
	if err := Write(context.Background(), &again, tree, store.read, 4<<20); err != nil || !bytes.Equal(output.Bytes(), again.Bytes()) {
		t.Fatalf("same immutable input changed archive bytes: %v", err)
	}
}

func TestArchiveReadBack(t *testing.T) {
	for _, mode := range []string{"bytes", "digest", "length", "part", "order", "manifest", "trailer", "missing", "raw-manifest", "extra", "terminator"} {
		t.Run(mode, func(t *testing.T) {
			tree, store := streamFixture()
			var output bytes.Buffer
			if err := Write(context.Background(), &output, tree, store.read, 4<<20); err != nil {
				t.Fatal(err)
			}
			raw := append([]byte{}, output.Bytes()...)
			if mode == "trailer" {
				raw = append(raw, []byte("unarchived trailer")...)
			}
			if mode == "terminator" {
				raw = raw[:len(raw)-1024]
			}
			if mode == "raw-manifest" {
				var err error
				raw, err = json.Marshal(tree)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing" || mode == "extra" {
				ordered, manifestBytes, err := entries(tree)
				if err != nil {
					t.Fatal(err)
				}
				var changed bytes.Buffer
				tw := tar.NewWriter(&changed)
				if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(manifestBytes))}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(manifestBytes); err != nil {
					t.Fatal(err)
				}
				if mode == "extra" {
					for _, entry := range ordered {
						if err := tw.WriteHeader(header(entry)); err != nil {
							t.Fatal(err)
						}
						if entry.Kind == "file" {
							if err := copyContent(context.Background(), tw, entry, store.read, 4<<20); err != nil {
								t.Fatal(err)
							}
						}
					}
					if err := tw.WriteHeader(&tar.Header{Name: "extra", Typeflag: tar.TypeReg, Mode: 0600}); err != nil {
						t.Fatal(err)
					}
				}
				if err := tw.Close(); err != nil {
					t.Fatal(err)
				}
				raw = changed.Bytes()
			}
			assembly := assemblyFixture(t, raw, store)
			switch mode {
			case "bytes":
				// Hashes of stored parts and the complete stream agree with the
				// altered bytes; only actual tar/file validation can refuse them.
				needle := bytes.Index(raw, []byte("archive content\n"))
				if needle < 0 {
					t.Fatal("canary bytes are absent from fixture archive")
				}
				raw[needle] ^= 1
				assembly = assemblyFixture(t, raw, store)
			case "digest":
				assembly.SHA256 = manifest.Hash([]byte("foreign stream"))
			case "length":
				assembly.Bytes++
			case "part":
				store[assembly.Parts[0].ID][0] ^= 1
			case "order":
				assembly.Parts[0], assembly.Parts[1] = assembly.Parts[1], assembly.Parts[0]
			case "manifest":
				tree.Entries[0].Mode = 0750
			}
			if _, err := ReadBack(context.Background(), assembly, tree, store.read, 4<<20); err == nil {
				t.Fatal("archive accepted changed persisted bytes or inventory")
			}
		})
	}
}

func TestArchiveSource(t *testing.T) {
	for _, mode := range []string{"chunk", "short", "budget", "path", "kind", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			tree, store := streamFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ceiling := uint64(4 << 20)
			switch mode {
			case "short":
				store["content"] = store["content"][:10]
			case "budget":
				ceiling = 1024
			case "path":
				tree.Entries[1].Path = "../outside"
			case "kind":
				tree.Entries[1].Kind = "device"
			case "cancel":
				cancel()
			}
			read := func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
				chunk, err := store.read(ctx, request)
				if mode == "chunk" && len(chunk.Data) != 0 {
					chunk.Data[0] ^= 1
				}
				return chunk, err
			}
			var output bytes.Buffer
			if err := Write(ctx, &output, tree, read, ceiling); err == nil {
				t.Fatal("archive producer accepted invalid source or execution bounds")
			}
		})
	}
}

func TestArchiveSnapshotPair(t *testing.T) {
	first, source := streamFixture()
	second := api.ObjectManifest{Schema: first.Schema, Entries: append([]api.ObjectEntry{}, first.Entries...)}
	changed := append([]byte{}, source["content"]...)
	changed[0] ^= 1
	changed[len(changed)-1] ^= 1
	ref := api.BlobRef{ID: "other-content", Class: "artifact", Bytes: int64(len(changed)), SHA256: manifest.Hash(changed)}
	source[ref.ID] = changed
	second.Entries[1].Content = &ref
	for index, frozen := range []api.ObjectManifest{first, second} {
		store := byteStore{}
		for id, data := range source {
			store[id] = append([]byte{}, data...)
		}
		var output bytes.Buffer
		if err := Write(context.Background(), &output, frozen, store.read, 4<<20); err != nil {
			t.Fatal(err)
		}
		assembly := assemblyFixture(t, output.Bytes(), store)
		if digest, err := ReadBack(context.Background(), assembly, frozen, store.read, 4<<20); err != nil || digest != manifest.Hash(output.Bytes()) {
			t.Fatalf("archive rejected its exact frozen input: %v", err)
		}
		other := second
		if index == 1 {
			other = first
		}
		// Both trees and all outer archive hashes are valid. Only the exact
		// frozen input differs; file paths, modes and byte counts stay equal.
		if _, err := ReadBack(context.Background(), assembly, other, store.read, 4<<20); err == nil {
			t.Fatal("frozen manifest did not bind the actual archive input")
		}
	}
}

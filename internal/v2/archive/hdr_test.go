package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

const tailPath = "work/zz-tail"

func headerFixture() (api.ObjectManifest, byteStore, string) {
	tree, store := streamFixture()
	data := []byte("retained tail content\n")
	ref := api.BlobRef{ID: "tail-content", Class: "artifact", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
	store[ref.ID] = data
	long := "work/" + strings.Repeat("z", 128)
	tree.Entries = append(tree.Entries,
		api.ObjectEntry{Path: tailPath, Kind: "file", Mode: 0600, Content: &ref},
		api.ObjectEntry{Path: long, Kind: "file", Mode: 0600, Content: &ref},
		api.ObjectEntry{Path: "zz-link", Kind: "symlink", Mode: 0777, LinkTarget: long})
	return tree, store, long
}

// These encode real tar metadata, not a declared digest discrepancy. Every
// mutation gets fresh part and complete-stream hashes in assemblyFixture.
func headerArchive(t *testing.T, tree api.ObjectManifest, store byteStore, long, mode string) []byte {
	t.Helper()
	ordered, raw, err := entries(tree)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	tw := tar.NewWriter(&output)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(raw)), Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(raw); err != nil {
		t.Fatal(err)
	}
	for _, entry := range ordered {
		h := header(entry)
		if entry.Path == tailPath {
			switch mode {
			case "pax":
				h.PAXRecords = map[string]string{"archive.extra": "canary"}
			case "xattr":
				h.Xattrs = map[string]string{"user.archive": "canary"}
			case "uname":
				h.Uname = "archive-canary"
			case "gname":
				h.Gname = "archive-canary"
			case "mtime":
				h.ModTime = time.Unix(1, 0).UTC()
			case "atime":
				h.AccessTime = time.Unix(2, 0).UTC()
			case "ctime":
				h.ChangeTime = time.Unix(3, 0).UTC()
			case "devmajor":
				h.Devmajor = 1
			case "devminor":
				h.Devminor = 1
			case "format", "gnu-sparse":
				h.Format = tar.FormatGNU
			}
			if mode == "pax-sparse" || mode == "pax-global" {
				if err := tw.Flush(); err != nil {
					t.Fatal(err)
				}
				kind := byte(tar.TypeXHeader)
				records := paxRecord("GNU.sparse.major", "0") + paxRecord("GNU.sparse.minor", "1") +
					paxRecord("GNU.sparse.size", strconv.FormatInt(h.Size, 10)) + paxRecord("GNU.sparse.numblocks", "1") +
					paxRecord("GNU.sparse.map", "0,"+strconv.FormatInt(h.Size, 10))
				if mode == "pax-global" {
					kind, records = tar.TypeXGlobalHeader, paxRecord("comment", "archive canary")
				}
				if _, err := output.Write(extension(t, kind, records)); err != nil {
					t.Fatal(err)
				}
			}
		}
		if mode == "gnu-name" && entry.Path == long || mode == "gnu-link" && entry.Path == "zz-link" {
			h.Format = tar.FormatGNU
		}
		if err := tw.Flush(); err != nil {
			t.Fatal(err)
		}
		start := output.Len()
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if mode == "gnu-sparse" && entry.Path == tailPath {
			// Writer deliberately refuses legacy sparse emission. Encode the
			// real GNU no-hole sparse map and size in its physical header.
			block := output.Bytes()[start : start+512]
			block[156] = tar.TypeGNUSparse
			copy(block[386:398], fmt.Sprintf("%011o\x00", 0))
			copy(block[398:410], fmt.Sprintf("%011o\x00", h.Size))
			copy(block[483:495], fmt.Sprintf("%011o\x00", h.Size))
			headerSum(block)
		}
		if entry.Kind == "file" {
			data := store[entry.Content.ID]
			if n, err := tw.Write(data); err != nil || n != len(data) {
				t.Fatalf("fixture could not emit its actual file bytes: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if mode == "zero-trailer" {
		output.Write(make([]byte, 512))
	}
	return output.Bytes()
}

func paxRecord(key, value string) string {
	body := key + "=" + value + "\n"
	length := len(body) + 2
	for {
		next := len(body) + len(strconv.Itoa(length)) + 1
		if next == length {
			return strconv.Itoa(length) + " " + body
		}
		length = next
	}
}

func extension(t *testing.T, kind byte, body string) []byte {
	t.Helper()
	var output bytes.Buffer
	tw := tar.NewWriter(&output)
	if err := tw.WriteHeader(&tar.Header{Name: "archive-extension", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(body)), Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := output.Bytes()[:512+((len(body)+511)/512)*512]
	if raw[156] != tar.TypeReg || !bytes.HasPrefix(raw, []byte("archive-extension")) {
		t.Fatal("fixture extension has an unexpected physical header")
	}
	raw[156] = kind
	headerSum(raw[:512])
	return raw
}

func headerSum(block []byte) {
	copy(block[148:156], "        ")
	sum := 0
	for _, value := range block {
		sum += int(value)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

func rawKind(t *testing.T, raw []byte, want byte) bool {
	t.Helper()
	for offset := 0; offset+512 <= len(raw); {
		block := raw[offset : offset+512]
		if bytes.Equal(block, make([]byte, 512)) {
			return false
		}
		if block[156] == want {
			return true
		}
		size, err := strconv.ParseInt(strings.Trim(string(block[124:136]), " \x00"), 8, 64)
		if err != nil || size < 0 || size > int64(len(raw)-offset-512) {
			t.Fatalf("fixture raw header has an invalid physical length: %v", err)
		}
		offset += 512 + int((size+511)/512)*512
	}
	return false
}

func headerCanary(t *testing.T, raw []byte, mode string) {
	t.Helper()
	kinds := map[string]byte{"gnu-name": tar.TypeGNULongName, "gnu-link": tar.TypeGNULongLink, "gnu-sparse": tar.TypeGNUSparse, "pax-global": tar.TypeXGlobalHeader}
	if kind, ok := kinds[mode]; ok {
		if !rawKind(t, raw, kind) {
			t.Fatal("fixture omitted its claimed extended header kind")
		}
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	seen := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("metadata canary is not a readable tar", err)
		}
		if h.Name == "data/"+tailPath {
			checks := map[string]bool{"pax": h.PAXRecords["archive.extra"] == "canary", "xattr": h.Xattrs["user.archive"] == "canary",
				"uname": h.Uname == "archive-canary", "gname": h.Gname == "archive-canary", "mtime": h.ModTime.Unix() == 1,
				"atime": h.AccessTime.Unix() == 2, "ctime": h.ChangeTime.Unix() == 3, "devmajor": h.Devmajor == 1,
				"devminor": h.Devminor == 1, "format": h.Format == tar.FormatGNU, "gnu-sparse": h.Typeflag == tar.TypeGNUSparse,
				"pax-sparse": h.PAXRecords["GNU.sparse.map"] == "0,"+strconv.FormatInt(h.Size, 10)}
			if present, ok := checks[mode]; ok && !present {
				t.Fatal("fixture did not retain its claimed metadata field")
			}
			seen = true
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			t.Fatal("metadata canary has invalid file content", err)
		}
	}
	if !seen {
		t.Fatal("metadata canary omitted its late file")
	}
}

func TestArchiveHeaders(t *testing.T) {
	for _, mode := range []string{"canonical", "pax", "xattr", "uname", "gname", "mtime", "atime", "ctime", "devmajor", "devminor", "format", "gnu-name", "gnu-link", "pax-sparse", "gnu-sparse", "pax-global", "zero-trailer"} {
		t.Run(mode, func(t *testing.T) {
			tree, store, long := headerFixture()
			var canonical bytes.Buffer
			if err := Write(context.Background(), &canonical, tree, store.read, 4<<20); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonical.Bytes(), headerArchive(t, tree, store, long, "canonical")) {
				t.Fatal("fixture reconstruction changed the canonical archive")
			}
			raw := headerArchive(t, tree, store, long, mode)
			headerCanary(t, raw, mode)
			if mode != "canonical" && bytes.Equal(raw, canonical.Bytes()) {
				t.Fatal("metadata mutation left archive bytes unchanged")
			}
			assembly := assemblyFixture(t, raw, store)
			digest, err := ReadBack(context.Background(), assembly, tree, store.read, 4<<20)
			if mode == "canonical" {
				if err != nil || digest != manifest.Hash(canonical.Bytes()) {
					t.Fatalf("canonical long-path archive was refused: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "canonical tar") {
				t.Fatalf("noncanonical header was not refused by byte comparison: %v", err)
			}
		})
	}
}

func TestArchiveEveryPart(t *testing.T) {
	tree, store, _ := headerFixture()
	var canonical bytes.Buffer
	if err := Write(context.Background(), &canonical, tree, store.read, 4<<20); err != nil {
		t.Fatal(err)
	}
	assembly := assemblyFixture(t, canonical.Bytes(), store)
	if len(assembly.Parts) < 3 {
		t.Fatal("fixture has no late archive part")
	}
	readBytes, eof := map[api.ID]int64{}, map[api.ID]bool{}
	read := func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		chunk, err := store.read(ctx, request)
		if strings.HasPrefix(string(request.ObjectID), "part-") && err == nil {
			readBytes[request.ObjectID] += int64(len(chunk.Data))
			if len(chunk.Data) == 0 {
				eof[request.ObjectID] = true
			}
		}
		return chunk, err
	}
	if _, err := ReadBack(context.Background(), assembly, tree, read, 4<<20); err != nil {
		t.Fatal(err)
	}
	for _, part := range assembly.Parts {
		if readBytes[part.ID] != part.Bytes || !eof[part.ID] {
			t.Fatal("canonical verification did not read an entire committed part and its EOF")
		}
	}
	raw := append([]byte{}, canonical.Bytes()...)
	needle := bytes.LastIndex(raw, []byte("retained tail content\n"))
	if needle <= api.MaxChunkBytes {
		t.Fatal("fixture mutation does not reach a later part")
	}
	raw[needle] ^= 1
	changed := assemblyFixture(t, raw, store)
	if _, err := ReadBack(context.Background(), changed, tree, store.read, 4<<20); err == nil {
		t.Fatal("canonical verification accepted substituted content in a later part")
	}
}

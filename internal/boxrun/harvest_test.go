package boxrun

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
)

func headerTar(t *testing.T, header tar.Header) []byte {
	t.Helper()
	var data bytes.Buffer
	w := tar.NewWriter(&data)
	if err := w.WriteHeader(&header); err != nil {
		t.Fatal(err)
	}
	if header.Size == 0 {
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// An oversized header is enough to prove refusal before any file is opened.
	return data.Bytes()
}

func hostileRun(t *testing.T, header tar.Header, reason string) {
	t.Helper()
	f := newFixture(t)
	parent := t.TempDir()
	sibling := filepath.Join(parent, "outside")
	if err := os.WriteFile(sibling, []byte("sibling sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if header.Name == "ABSOLUTE" {
		header.Name = sibling
	}
	f.tr.craftedTar = headerTar(t, header)
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite(),
		OutDir: filepath.Join(parent, "run")})
	if result.ExitCode != 11 || result.Verdict != "harvest-failed" || err == nil ||
		!strings.Contains(err.Error(), reason) || !result.Terminated || result.Files != 0 || result.ManifestSHA256 != "" {
		t.Fatalf("hostile entry was accepted or failed for another reason: %+v, %v", result, err)
	}
	requireFile(t, sibling, "sibling sentinel")
	entries, err := os.ReadDir(filepath.Join(result.OutDir, "out"))
	if err != nil || len(entries) != 0 {
		t.Fatal("refused header created an output file")
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestTarSymlink(t *testing.T) {
	hostileRun(t, tar.Header{Name: "entry", Typeflag: tar.TypeSymlink, Linkname: "../outside"}, "refused tar entry type")
}

func TestTarHardlink(t *testing.T) {
	hostileRun(t, tar.Header{Name: "entry", Typeflag: tar.TypeLink, Linkname: "../outside"}, "refused tar entry type")
}

func TestTarParent(t *testing.T) {
	hostileRun(t, tar.Header{Name: "../outside", Typeflag: tar.TypeReg}, "parent segment")
}

func TestTarAbsolute(t *testing.T) {
	hostileRun(t, tar.Header{Name: "ABSOLUTE", Typeflag: tar.TypeReg}, "unsafe tar path")
}

func TestTarDevice(t *testing.T) {
	hostileRun(t, tar.Header{Name: "entry", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}, "refused tar entry type")
}

func TestTarTooLarge(t *testing.T) {
	hostileRun(t, tar.Header{Name: "entry", Typeflag: tar.TypeReg, Size: (2 << 30) + 1}, "tar size limit")
}

func manifestFor(files map[string][]byte) []byte {
	var names []string
	for name := range files {
		if name != "manifest.sha256" && name != ".complete" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var text strings.Builder
	for _, name := range names {
		digest := sha256.Sum256(files[name])
		fmt.Fprintf(&text, "%x  ./%s\n", digest, name)
	}
	return []byte(text.String())
}

func filesTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var data bytes.Buffer
	w := tar.NewWriter(&data)
	for _, name := range names {
		body := files[name]
		if err := w.WriteHeader(&tar.Header{Name: "./" + name, Typeflag: tar.TypeReg, Mode: 0777, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func badManifest(t *testing.T, change func(map[string][]byte), reason string) {
	t.Helper()
	f := newFixture(t)
	files := map[string][]byte{"suite.exit": []byte("0\n"), ".complete": {}, "result.txt": []byte("payload\n")}
	files["manifest.sha256"] = manifestFor(files)
	change(files)
	f.tr.craftedTar = filesTar(t, files)
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite()})
	if result.ExitCode != 11 || result.Verdict != "harvest-failed" || err == nil ||
		!strings.Contains(err.Error(), reason) || result.ManifestSHA256 != "" || !result.Terminated ||
		countCommands(f.tr, "harvest") != 1 {
		t.Fatalf("bad manifest was accepted: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestManifestHash(t *testing.T) {
	badManifest(t, func(files map[string][]byte) { files["result.txt"] = []byte("changed\n") }, "hash mismatch")
}

func TestManifestMissing(t *testing.T) {
	badManifest(t, func(files map[string][]byte) { delete(files, "result.txt") }, "invalid manifest file")
}

func TestManifestExtra(t *testing.T) {
	badManifest(t, func(files map[string][]byte) { files["unlisted.txt"] = []byte("extra\n") }, "unlisted harvested file")
}

func TestManifestMalformed(t *testing.T) {
	badManifest(t, func(files map[string][]byte) { files["manifest.sha256"] = []byte("not a checksum\n") }, "malformed manifest")
}

func TestTarExistingLink(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "out")
	realDir := filepath.Join(out, "real")
	if err := os.MkdirAll(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(out, "link")); err != nil {
		t.Fatal(err)
	}
	_, err := extractTar(bytes.NewReader(filesTar(t, map[string][]byte{"link/escape": []byte("hostile")})), out)
	if err == nil {
		t.Fatal("extractor followed a pre-existing internal link")
	}
	if _, err := os.Lstat(filepath.Join(realDir, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("extraction wrote through an existing link")
	}
}

func TestTarCountLimit(t *testing.T) {
	archive := filesTar(t, map[string][]byte{"a": {1}, "b": {2}, "c": {3}})
	out := filepath.Join(t.TempDir(), "out")
	info, err := extractLimited(bytes.NewReader(archive), out, 2, 10, 30)
	if err == nil || !strings.Contains(err.Error(), "too many tar entries") || info.files != 2 || info.bytes != 2 {
		t.Fatalf("entry bound was ignored: %+v, %v", info, err)
	}
	if _, err := os.Lstat(filepath.Join(out, "c")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("over-limit entry was created")
	}
}

func TestTarTotalLimit(t *testing.T) {
	archive := filesTar(t, map[string][]byte{"a": {1, 2}, "b": {3, 4}})
	out := filepath.Join(t.TempDir(), "out")
	info, err := extractLimited(bytes.NewReader(archive), out, 10, 4, 3)
	if err == nil || !strings.Contains(err.Error(), "tar size limit") || info.files != 1 || info.bytes != 2 {
		t.Fatalf("total byte bound was ignored: %+v, %v", info, err)
	}
	if _, err := os.Lstat(filepath.Join(out, "b")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("over-limit total opened another file")
	}
}

func TestHarvestPermissions(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	archive := filesTar(t, map[string][]byte{"nested/file": []byte("payload")})
	info, err := extractTar(bytes.NewReader(archive), out)
	if err != nil || info.files != 1 || info.bytes != 7 {
		t.Fatalf("regular extraction: %+v, %v", info, err)
	}
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{{out, 0700}, {filepath.Join(out, "nested"), 0700}, {filepath.Join(out, "nested", "file"), 0600}} {
		stat, err := os.Stat(tc.name)
		if err != nil || stat.Mode().Perm() != tc.mode {
			t.Fatal("extractor accepted archive permission bits")
		}
	}
}

func TestTarExitOne(t *testing.T) {
	f := newFixture(t)
	files := map[string][]byte{"suite.exit": []byte("0\n"), ".complete": {}}
	files["manifest.sha256"] = manifestFor(files)
	f.tr.craftedTar, f.tr.harvestCode = filesTar(t, files), 1
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite()})
	if result.ExitCode != 11 || err == nil || result.ManifestSHA256 != "" || !result.Terminated {
		t.Fatalf("tar exit 1 was accepted without a stopped wrapper: %+v, %v", result, err)
	}
}

func TestTarChangedAfterStop(t *testing.T) {
	f := newFixture(t)
	blockingSuite(f)
	files := map[string][]byte{"suite.exit": []byte("143\n"), ".complete": {}}
	files["manifest.sha256"] = manifestFor(files)
	f.tr.craftedTar, f.tr.harvestCode = filesTar(t, files), 1
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req,
		Suite: sleepingSuite(), TimeoutMin: 1})
	if err != nil || result.ExitCode != 13 || result.ManifestSHA256 == "" || result.SuiteExit != 143 || !result.Terminated {
		t.Fatalf("valid changed-file tar was rejected after timeout: %+v, %v", result, err)
	}
	assertGroupKill(t, f)
}

func TestTimeoutBadHarvest(t *testing.T) {
	f := newFixture(t)
	blockingSuite(f)
	files := map[string][]byte{"suite.exit": []byte("143\n"), ".complete": {}}
	files["manifest.sha256"] = manifestFor(files)
	f.tr.craftedTar, f.tr.harvestCode = filesTar(t, files), 2
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req,
		Suite: sleepingSuite(), TimeoutMin: 1})
	if result.ExitCode != 11 || result.Verdict != "harvest-failed" || err == nil || result.ManifestSHA256 != "" || !result.Terminated {
		t.Fatalf("harvest failure lost priority over timeout: %+v, %v", result, err)
	}
	assertGroupKill(t, f)
}

func TestManifestCanceled(t *testing.T) {
	files := map[string][]byte{"suite.exit": []byte("0\n"), ".complete": {}}
	files["manifest.sha256"] = manifestFor(files)
	out := filepath.Join(t.TempDir(), "out")
	info, err := extractTar(bytes.NewReader(filesTar(t, files)), out)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	digest, err := verifyManifestCtx(ctx, out, info)
	if !errors.Is(err, context.Canceled) || digest != "" {
		t.Fatal("manifest verification ignored its deadline context")
	}
}

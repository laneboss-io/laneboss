package laneturns

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanRejectsParentSymlink(t *testing.T) {
	root := realPath(t.TempDir())
	outside := realPath(t.TempDir())
	allowed := scanFixture(t, filepath.Join(root, "records"), "allowed session bytes\n")
	target := scanFixture(t, outside, "outside canary bytes\n")
	control, _, _, err := openScanRecord(allowed, nil)
	if err != nil {
		t.Fatalf("the ordinary-directory control was refused: %v", err)
	}
	data, err := io.ReadAll(control)
	control.Close()
	if err != nil || string(data) != "allowed session bytes\n" {
		t.Fatal("the ordinary-directory control did not read its own fixture")
	}
	link := filepath.Join(root, "linked-parent")
	if err := os.Symlink(filepath.Dir(target), link); err != nil {
		t.Fatal(err)
	}
	file, _, _, err := openScanRecord(filepath.Join(link, filepath.Base(target)), nil)
	if file != nil {
		file.Close()
	}
	if err == nil || file != nil {
		t.Fatal("the scanner followed a symbolic parent to the outside canary")
	}
	if !strings.Contains(err.Error(), "parent") {
		t.Fatalf("the parent-link canary failed for an unrelated reason: %v", err)
	}
	deep := filepath.Join(root, "deep")
	if err := os.Mkdir(deep, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(target), filepath.Join(deep, "nested")); err != nil {
		t.Fatal(err)
	}
	file, _, _, err = openScanRecord(filepath.Join(deep, "nested", filepath.Base(target)), nil)
	if file != nil {
		file.Close()
	}
	if err == nil || file != nil {
		t.Fatal("the scanner checked only the first parent component")
	}
}

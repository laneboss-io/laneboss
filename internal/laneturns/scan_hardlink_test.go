package laneturns

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanRejectsHardlinkInRefusedZone(t *testing.T) {
	root := realPath(t.TempDir())
	zone := filepath.Join(root, "refused")
	protected := scanFixture(t, zone, "protected canary bytes\n")
	alias := filepath.Join(root, "public-record.jsonl")
	if err := os.Link(protected, alias); err != nil {
		t.Fatal(err)
	}
	file, _, _, err := openScanRecord(alias, []string{zone})
	if file != nil {
		file.Close()
	}
	if err == nil || file != nil {
		t.Fatal("the scanner opened a hard-link alias of refused-zone bytes")
	}
	if !strings.Contains(err.Error(), "hard link") {
		t.Fatal("the hard-link refusal failed for another reason")
	}
	ordinary := scanFixture(t, root, "allowed control bytes\n")
	publicAlias := filepath.Join(root, "allowed-alias.jsonl")
	if err := os.Link(ordinary, publicAlias); err != nil {
		t.Fatal(err)
	}
	control, _, _, err := openScanRecord(publicAlias, []string{zone})
	if err != nil {
		t.Fatal("an unrelated hard-link control was refused")
	}
	data, err := io.ReadAll(control)
	control.Close()
	if err != nil || string(data) != "allowed control bytes\n" {
		t.Fatal("the public hard-link control did not read its own bytes")
	}
}

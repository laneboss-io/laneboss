package lane

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestScanRefusesZoneHardlink(t *testing.T) {
	root := realPath(t.TempDir())
	zone := filepath.Join(root, "refused")
	if err := os.Mkdir(zone, 0700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(zone, "protected.jsonl")
	if err := os.WriteFile(protected, []byte("protected canary bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "public-record.jsonl")
	if err := os.Link(protected, alias); err != nil {
		t.Fatal(err)
	}
	scan := &refusalScan{s: &session{c: &configuration{home: zone, states: zone, state: zone, directory: zone}}}
	record := newScanRecord(alias, alias, "claude-code", 0)
	defer func() {
		if record.file != nil {
			record.file.Close()
		}
	}()
	if record.open(scan) || record.state != "refused-zone" || record.file != nil {
		t.Fatal("ordinary scanning admitted a hard-link alias of refused-zone bytes")
	}
	allowed := filepath.Join(root, "allowed.jsonl")
	if err := os.WriteFile(allowed, []byte("allowed control bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	publicAlias := filepath.Join(root, "allowed-alias.jsonl")
	if err := os.Link(allowed, publicAlias); err != nil {
		t.Fatal(err)
	}
	control := newScanRecord(publicAlias, publicAlias, "claude-code", 0)
	defer func() {
		if control.file != nil {
			control.file.Close()
		}
	}()
	if !control.open(scan) || control.state != "covered" {
		t.Fatal("ordinary scanning refused the unrelated hard-link control")
	}
	data, err := io.ReadAll(control.file)
	if err != nil || string(data) != "allowed control bytes\n" {
		t.Fatal("the ordinary control did not read its own bytes")
	}
}

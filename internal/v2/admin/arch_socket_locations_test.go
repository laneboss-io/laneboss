//go:build linux

package admin

import (
	"context"
	"strings"
	"testing"
)

func TestArchSocketLocations(t *testing.T) {
	const header = "Num RefCount Protocol Flags Type St Inode Path\n"
	const record = "0000000000000000: 00000002 00000000 00010000 0001 01 12345 "
	const name = "/helper-runtime/workers/issued-lease.sock"
	const serviceName = "/service runtime/with  spaces/workers/issued-lease.sock"
	for _, row := range []struct {
		name, path string
		count      uint64
	}{
		{"helper-live", name, 1},
		{"helper-deleted", name + " (deleted)", 1},
		{"service-live", "/service-runtime/" + "workers/issued-lease.sock", 1},
		{"service-deleted", "/service-runtime/" + "workers/issued-lease.sock (deleted)", 1},
		{"parent-spaces", serviceName, 1},
		{"foreign-parent", "/unrelated/workers/issued-lease.sock", 0},
		{"nested-parent", "/helper-runtime/" + "workers/nested/issued-lease.sock", 0},
		{"foreign-lease", "/service-runtime/" + "workers/other-lease.sock", 0},
		{"prefix", "/service-runtime/" + "workers/issued-lease.sock-extra", 0},
		{"suffix", "/service-runtime/" + "workers/extra-issued-lease.sock", 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			count, err := archiveSocketInventory(context.Background(), strings.NewReader(header+record+row.path+"\n"), name,
				"/service-runtime/workers/issued-lease.sock", serviceName)
			if err != nil || count != row.count {
				t.Fatalf("acceptance: socket inventory lost exact lease matching across runtime locations: count=%d err=%v", count, err)
			}
		})
	}
}

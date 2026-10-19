//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func exportTestDigest() api.Digest { return api.Digest(strings.Repeat("a", 64)) }

func exportTestRecord(t *testing.T, grant api.DataGrant) leaseRecord {
	t.Helper()
	return leaseRecord{
		Lease: api.HelperLease{ID: "export-lease", EndpointGeneration: 4},
		Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{
			Cause: api.InternalIntent{EffectID: "export-effect"},
			Spec:  api.LaunchSpec{Grants: api.GrantSet{ID: "export-grants", Data: []api.DataGrant{grant}}},
		}},
	}
}

func TestGateDataGrantMatrix(t *testing.T) {
	expires := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	base := api.DataGrant{ID: "data-grant", SourceObjectID: "source", SourceSHA256: exportTestDigest(), RelativePath: ".", Access: "ro", Delivery: "copy", Destination: "/work/main", HistoryScope: "tree", ExpiresAt: expires}
	cases := []struct {
		name        string
		grant       api.DataGrant
		code        api.ErrorCode
		needsExport bool
	}{
		{name: "main-copy", grant: base, needsExport: false},
		{name: "additional-copy", grant: func() api.DataGrant { g := base; g.Destination = "/data/cache"; return g }(), needsExport: true},
		{name: "reachable-copy", grant: func() api.DataGrant { g := base; g.HistoryScope = "reachable"; return g }(), code: api.CodeUnsupported},
		{name: "snapshot-mount", grant: func() api.DataGrant { g := base; g.Delivery, g.HistoryScope = "mount", "snapshot"; return g }(), code: api.CodeUnsupported},
		{name: "bad-destination", grant: func() api.DataGrant { g := base; g.Destination = "/run/private"; return g }(), code: api.CodeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGateDataGrant(tc.grant)
			if tc.code == "" {
				if err != nil || gateDestinationNeedsExport(tc.grant) != tc.needsExport {
					t.Fatalf("valid matrix cell refused or selected the wrong owner hook: %v", err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != tc.code {
				t.Fatalf("matrix refusal lost its typed cause: %v", err)
			}
		})
	}
}

func TestRegisteredExportClaimReplay(t *testing.T) {
	expires := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	grant := api.DataGrant{ID: "data-grant", SourceObjectID: "source", SourceSHA256: exportTestDigest(), RelativePath: ".", Access: "ro", Delivery: "mount", Destination: "/data/cache", HistoryScope: "tree", ExpiresAt: expires}
	record := exportTestRecord(t, grant)
	directory := t.TempDir()
	file, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	manager := &leaseManager{exports: map[api.ID]map[api.ID]*registeredExport{}}
	manager.exportResolver = func(context.Context, leaseRecord, api.DataGrant) (registeredExport, error) {
		return registeredExport{File: file, Destination: "/data/cache", SourceIdentity: "source-dev-inode", DestinationIdentity: "dest-dev-inode", ClaimID: "export-effect", Directory: true, ReadOnly: true}, nil
	}
	if err := manager.registerGateExports(context.Background(), &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Exports) != 1 || record.Exports[0].ClaimID != "export-effect" || record.Exports[0].Destination != "/data/cache" {
		t.Fatal("registered export did not retain its stable source, destination and claim")
	}
	manager.exportResolver = func(context.Context, leaseRecord, api.DataGrant) (registeredExport, error) {
		return registeredExport{File: file, Destination: "/data/cache", SourceIdentity: "foreign-source", DestinationIdentity: "dest-dev-inode", ClaimID: "export-effect", Directory: true, ReadOnly: true}, nil
	}
	var typed *api.Error
	if err := manager.registerGateExports(context.Background(), &record); !errors.As(err, &typed) || typed.Code != api.CodeIdempotencyConflict {
		t.Fatalf("changed export replay was accepted: %v", err)
	}
	_ = manager.collectGateExports(record.Lease.ID)
}

func TestRegisteredExportMissingOwnerS1e3d(t *testing.T) {
	grant := api.DataGrant{ID: "data-grant", SourceObjectID: "source", SourceSHA256: exportTestDigest(), RelativePath: ".", Access: "ro", Delivery: "copy", Destination: "/data/cache", HistoryScope: "tree"}
	record := exportTestRecord(t, grant)
	manager := &leaseManager{}
	var typed *api.Error
	if err := manager.registerGateExports(context.Background(), &record); !errors.As(err, &typed) || typed.Code != api.CodeUnavailable || len(record.Exports) != 0 {
		t.Fatalf("missing export owner did not stop without publishing a journal: %v", err)
	}
}

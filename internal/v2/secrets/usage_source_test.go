package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestOutsideUsageWindow(t *testing.T) {
	c, job := newUsageCase(t)
	evidence, err := c.service.ReadUsageWindow(context.Background(), c.service.deps.ServiceScope, job.request)
	if err != nil || evidence.ProfileID != c.profile.ID || evidence.UsedPercent != 100 || evidence.Row != 1 {
		t.Fatal("outside usage did not retain its actual exhausted from-profile window")
	}
	raw, err := os.ReadFile(filepath.Join(c.store.root, "usage.tsv"))
	if err != nil {
		t.Fatal("cannot read actual synthetic outside source")
	}
	retained, err := c.service.protectedObject(context.Background(), evidence.Raw, job.request.OperationID)
	if err != nil || !bytes.Equal(raw, retained) {
		t.Fatal("outside usage lost its exact protected raw bytes")
	}
	if err := api.ValidateUsageSource(evidence, retained, c.profile.Usage.VendorProfile); err != nil {
		t.Fatal("outside usage normalized fields differ from retained TSV")
	}
	meta, err := c.store.ObjectMetadata(context.Background(), api.Scope{}, evidence.ID)
	if err != nil || meta.Ref.Class != "usage_window" || meta.ACL.Owner.Kind != "worker" || meta.ACL.Audience != "service" {
		t.Fatal("outside usage envelope lacks its private producer provenance")
	}
	data, err := c.service.protectedObject(context.Background(), meta.Ref, job.request.OperationID)
	var actual api.UsageWindowEvidence
	if err != nil || json.Unmarshal(data, &actual) != nil || !reflect.DeepEqual(actual, evidence) {
		t.Fatal("outside usage envelope was not read back as its exact evidence")
	}
	if job.starts != 1 || job.runs != 1 {
		t.Fatal("outside usage did not dispatch exactly one measured query")
	}
	replayed, err := c.service.ReadUsageWindow(context.Background(), c.service.deps.ServiceScope, job.request)
	if err != nil || !reflect.DeepEqual(replayed, evidence) {
		t.Fatal("exact usage job retry did not preserve its immutable raw and envelope bytes")
	}
}

func TestOutsideUsageGuards(t *testing.T) {
	for _, fault := range []string{"percent", "stale", "pre-exit", "future", "profile", "producer", "header", "reset", "plan", "nonfinite", "negative", "failed", "ack", "input", "lease", "permission", "grants", "lane-writer", "frame", "dependency"} {
		t.Run(fault, func(t *testing.T) {
			c, job := newUsageCase(t)
			request, scope := job.request, c.service.deps.ServiceScope
			code := api.CodeInvalid
			switch fault {
			case "percent":
				job.raw(t, "99", c.clock.now.Add(time.Hour).Format(time.RFC3339Nano))
				code = api.CodeUnavailable
			case "stale":
				job.output.ObservedAt = api.Timestamp(c.clock.now.Add(-31 * time.Second).Format(time.RFC3339Nano))
			case "pre-exit":
				job.output.ObservedAt = api.Timestamp(c.clock.now.Add(-2 * time.Second).Format(time.RFC3339Nano))
			case "future":
				job.output.ObservedAt = api.Timestamp(c.clock.now.Add(time.Second).Format(time.RFC3339Nano))
			case "profile":
				request.ProfileID, request.ProfileGrantID = "profile-b", "profile-grant-b"
				job.request = request
				var selected UsageInput
				if json.Unmarshal(job.input.Bytes, &selected) != nil {
					t.Fatal("cannot decode from-profile control")
				}
				selected.Request = request
				ref := c.store.putObject(t, "usage-job-input", "usage_input", selected, request.OperationID)
				blob, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: ref.ID})
				if err != nil {
					t.Fatal("cannot read from-profile control bytes")
				}
				job.input.Bytes, job.input.Input = blob.Data, ref
				var p api.WorkerPrincipal
				if err := c.store.read("usage-principal.json", &p); err != nil {
					t.Fatal("cannot read from-profile control claim")
				}
				p.Lease.Input, p.Claim.Record.Effect.Worker.Input = ref, ref
				if c.store.save("usage-principal.json", p) != nil || c.store.save("usage-input.json", job.input) != nil {
					t.Fatal("cannot retain from-profile control claim")
				}
				code = api.CodeForbidden
			case "producer", "lease", "permission":
				var p api.WorkerPrincipal
				if err := c.store.read("usage-principal.json", &p); err != nil {
					t.Fatal("cannot read worker mapping control")
				}
				if fault == "producer" {
					p.Peer.ProcessGeneration = "lane-writer-generation"
				}
				if fault == "lease" {
					p.Lease.ConsumedBy = "foreign-worker-launch"
				}
				if fault == "permission" {
					p.Lease.Kind = "capture"
				}
				if err := c.store.save("usage-principal.json", p); err != nil {
					t.Fatal("cannot alter worker mapping control")
				}
			case "header":
				data, err := os.ReadFile(filepath.Join(c.store.root, "usage.tsv"))
				if err != nil {
					t.Fatal("cannot read TSV header control")
				}
				data = bytes.Replace(data, []byte("PROFILE\tPLAN"), []byte("PLAN\tPROFILE"), 1)
				if os.WriteFile(filepath.Join(c.store.root, "usage.tsv"), data, 0600) != nil {
					t.Fatal("cannot alter ordered TSV header control")
				}
			case "reset":
				job.raw(t, "100", "unknown")
				code = api.CodeUnavailable
			case "plan":
				data, err := os.ReadFile(filepath.Join(c.store.root, "usage.tsv"))
				if err != nil {
					t.Fatal("cannot read plan consistency control")
				}
				data = append(data, []byte(c.profile.Usage.VendorProfile+"\tconflicting-plan\tweek\t1\tunknown\n")...)
				if os.WriteFile(filepath.Join(c.store.root, "usage.tsv"), data, 0600) != nil {
					t.Fatal("cannot alter plan consistency control")
				}
			case "nonfinite":
				job.raw(t, "NaN", c.clock.now.Add(time.Hour).Format(time.RFC3339Nano))
			case "negative":
				job.raw(t, "-1", c.clock.now.Add(time.Hour).Format(time.RFC3339Nano))
			case "failed":
				job.output.ExitCode = 1
				code = api.CodeUnavailable
			case "ack":
				job.omitAck = true
				code = api.CodeNotFound
			case "input":
				job.input.Bytes = append(job.input.Bytes, '\n')
				if c.store.save("usage-input.json", job.input) != nil {
					t.Fatal("cannot alter sealed usage input control")
				}
			case "grants":
				c.store.workerGrants.Data = c.store.grants.Data
				c.store.workerGrants.SHA256 = ""
				digest, err := valueDigest(*c.store.workerGrants)
				if err != nil {
					t.Fatal("cannot hash broadened worker grant control")
				}
				c.store.workerGrants.SHA256 = digest
				var p api.WorkerPrincipal
				if c.store.read("usage-principal.json", &p) != nil {
					t.Fatal("cannot read broadened worker mapping control")
				}
				p.Record.GrantsSHA256 = digest
				if c.store.save("usage-principal.json", p) != nil {
					t.Fatal("cannot retain broadened worker mapping control")
				}
				code = api.CodeForbidden
			case "lane-writer":
				job.scope.Actor.Kind = "lane"
				job.output.Scope = job.scope
				code = api.CodeUnauthenticated
			case "frame":
				job.scope.Frame.(*frameFixture).err = &api.Error{Code: api.CodeUnauthenticated, Owner: "lb-v2-service", Message: "fixture writer changed"}
				code = api.CodeUnauthenticated
			case "dependency":
				c.store.fail["worker-binding"] = api.NotImplemented("lb-v2-service", "store.WorkerBinding")
				code = api.CodeNotImplemented
			}
			actual, err := c.service.ReadUsageWindow(context.Background(), scope, request)
			stageCode(t, err, code)
			if !reflect.DeepEqual(actual, api.UsageWindowEvidence{}) {
				t.Fatal("refused outside usage returned successful evidence")
			}
		})
	}
}

func TestUsageTSVAllRows(t *testing.T) {
	clock := &clockFixture{now: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}
	profile := "synthetic-profile"
	raw := []byte("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n" + profile + "\tsynthetic-plan\tunknown-window\t101\tunknown\n" + profile + "\tsynthetic-plan\tcurrent\t105.25\t2026-01-02T01:00:00Z\n")
	row, err := parseUsageRows(raw, profile, clock.Now())
	if err != nil || row.Index != 2 || row.Used != 105.25 || row.Window != "current" {
		t.Fatal("TSV parser did not select the actual known exhausted row")
	}
	bad := append(append([]byte(nil), raw...), []byte("other-profile\tother-plan\tweek\tInf\tunknown\n")...)
	_, err = parseUsageRows(bad, profile, clock.Now())
	stageCode(t, err, api.CodeInvalid)
	_, err = parseUsageRows([]byte(strings.Replace(string(raw), "USED_PERCENT", "USAGE", 1)), profile, clock.Now())
	stageCode(t, err, api.CodeInvalid)
}

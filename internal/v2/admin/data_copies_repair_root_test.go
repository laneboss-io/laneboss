//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The existing native fixture supplies the actual protected cache, journal,
// roots and ownership. Only its cgroup boundary is the component recorder.
func copyRepairFixture(t *testing.T, lifetime time.Duration) (*leaseManager, dataReg, []dataCopyPayload) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("copy repair fixture requires disposable Linux root")
	}
	m, r, input := dataOpenNativeFixture(t)
	var cached struct {
		Objects []dataCacheCanaryObject `json:"objects"`
	}
	raw, err := os.ReadFile(input)
	if err != nil || json.Unmarshal(raw, &cached) != nil {
		t.Fatal("cannot read actual native source fixture", err)
	}
	command := exec.Command("/usr/bin/python3", "-I", "-B", "testdata/source_cache_canary.py", input, m.binding.statePath())
	command.Env = []string{}
	if output, err := command.CombinedOutput(); err != nil || string(output) != "source-cache:changed\n" {
		t.Fatalf("native cache installation failed: %v\n%s", err, output)
	}
	grant := r.Inputs.Grants.Data[0]
	grant.ID, grant.Destination, grant.Access = "repair-extra", "/data/repair", "ro"
	grant.ExpiresAt = api.Timestamp(time.Now().Add(lifetime).UTC().Format(time.RFC3339Nano))
	r.Inputs.Grants.Data = append(r.Inputs.Grants.Data, grant)
	r.Inputs.Grants.SHA256 = ""
	encoded, err := canonicalValue(r.Inputs.Grants)
	if err != nil {
		t.Fatal(err)
	}
	r.Inputs.Grants.SHA256 = digestBytes(encoded)
	parent, err := m.find(r.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	parent.LaunchAllocations[0].Inputs = r.Inputs
	if err := m.save(parent); err != nil {
		t.Fatal("copy fixture allocation is invalid", err)
	}
	payload := dataCopyPayload{Grant: grant}
	for _, object := range cached.Objects {
		item := dataCopyObject{Ref: object.Ref, Data: object.Data}
		if object.Ref.ID == grant.SourceObjectID {
			payload.Source = item
		} else {
			payload.Objects = append(payload.Objects, item)
		}
	}
	// Use the service preparation path on both the old and corrected protocol.
	objects := map[api.ID]dataCopyObject{payload.Source.Ref.ID: payload.Source}
	for _, item := range payload.Objects {
		objects[item.Ref.ID] = item
	}
	store := &copyDescriptorStore{objects: objects, config: m.binding.Config}
	service := &Service{deps: Dependencies{Store: store}}
	payloads, err := service.copyPayloads(context.Background(), api.Scope{Config: m.binding.Config}, r)
	if err != nil {
		t.Fatal("copy descriptor fixture failed", err)
	}
	return m, r, payloads
}

type copyFailJournal struct {
	leaseStorage
	err error
}

func (s copyFailJournal) Save(record leaseRecord) error {
	for _, job := range record.DataJobs {
		if job.State == "open" {
			return s.err
		}
	}
	return s.leaseStorage.Save(record)
}

func TestCopyOpenRollback(t *testing.T) {
	m, r, payloads := copyRepairFixture(t, 30*time.Second)
	injected := errors.New("injected final copy journal failure")
	m.store = copyFailJournal{leaseStorage: m.store, err: injected}
	_, err := m.openData(context.Background(), r, payloads)
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatal("copy preparation did not reach the final journal failure", err)
	}
	for index, parent := range []string{laneStagePath(m.binding, r.Request.StageID), laneStagePath(m.binding, r.Request.AgentLeaseID)} {
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "copy-") || strings.HasPrefix(entry.Name(), "source-copy-") {
				t.Errorf("failed open leaked copy root beneath protected parent %d", index)
			}
		}
	}
}

func TestCopyDeliveryOwnerRouting(t *testing.T) {
	grant := api.DataGrant{ID: "copy-routing", SourceObjectID: "copy-source", SourceSHA256: exportTestDigest(),
		RelativePath: ".", Access: "ro", Delivery: "copy", Destination: "/data/routing", HistoryScope: "tree"}
	record := exportTestRecord(t, grant)
	calls := 0
	marker := errors.New("live resolver control")
	m := &leaseManager{exportResolver: func(context.Context, leaseRecord, api.DataGrant) (registeredExport, error) {
		calls++
		return registeredExport{}, marker
	}}
	err := m.registerGateExports(context.Background(), &record)
	var typed *api.Error
	if calls != 0 || !errors.As(err, &typed) || typed.Code != api.CodeUnavailable {
		t.Fatal("copy delivery was routed through the live export resolver", calls, err)
	}
	grant.Delivery = "mount"
	record = exportTestRecord(t, grant)
	if err := m.registerGateExports(context.Background(), &record); !errors.Is(err, marker) || calls != 1 {
		t.Fatal("mount delivery lost its bound live resolver", calls, err)
	}
}

type copyDescriptorStore struct {
	api.StateStore
	objects map[api.ID]dataCopyObject
	config  string
	reads   int
}

func (s *copyDescriptorStore) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	object, found := s.objects[id]
	if !found {
		return api.ObjectMetadata{}, errors.New("copy fixture object absent")
	}
	return api.ObjectMetadata{Ref: object.Ref, ACL: api.ObjectACL{Config: s.config}}, nil
}

func (s *copyDescriptorStore) Blob(_ context.Context, _ api.Scope, q api.BlobReadRequest) (api.BlobChunk, error) {
	object, found := s.objects[q.ObjectID]
	if !found || q.Offset < 0 || q.Offset > int64(len(object.Data)) || q.Limit <= 0 {
		return api.BlobChunk{}, errors.New("copy fixture blob range invalid")
	}
	s.reads++
	end := min(int64(len(object.Data)), q.Offset+int64(q.Limit))
	raw := append([]byte{}, object.Data[q.Offset:end]...)
	return api.BlobChunk{ObjectID: q.ObjectID, Offset: q.Offset, Data: raw, SHA256: digestBytes(raw)}, nil
}

func TestCopyDescriptorTransport(t *testing.T) {
	content := []byte(strings.Repeat("large-copy-data\n", 100000))
	ref := api.BlobRef{ID: "large-copy-content", Class: "artifact", Bytes: int64(len(content)), SHA256: digestBytes(content)}
	raw, err := canonicalValue(api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "large", Kind: "file", Mode: 0600, Content: &ref}}})
	if err != nil {
		t.Fatal(err)
	}
	source := api.BlobRef{ID: "large-copy-source", Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	grant := api.DataGrant{ID: "large-copy-grant", SourceObjectID: source.ID, SourceSHA256: source.SHA256, RelativePath: ".",
		Access: "ro", Delivery: "copy", Destination: "/data/large", ExpiresAt: api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}
	store := &copyDescriptorStore{config: "copy-descriptor", objects: map[api.ID]dataCopyObject{
		ref.ID: {Ref: ref, Data: content}, source.ID: {Ref: source, Data: raw}}}
	service := &Service{deps: Dependencies{Store: store}}
	r := dataReg{Inputs: api.LaunchInputs{Grants: api.GrantSet{Data: []api.DataGrant{grant}}}, Plan: api.WorkerPlan{Budget: api.Budget{DiskBytes: 8 << 20}}}
	payloads, err := service.copyPayloads(context.Background(), api.Scope{Config: store.config}, r)
	if err != nil {
		t.Fatal("large protected-cache descriptor was refused by the inline frame cap", err)
	}
	encoded, err := json.Marshal(payloads)
	if err != nil || len(payloads) != 1 || len(encoded) > 4096 || store.reads != 0 || len(payloads[0].Source.Data) != 0 || len(payloads[0].Objects) != 0 {
		t.Fatal("copy descriptor still transports data bytes instead of cache pins", len(encoded), store.reads, err)
	}
}

func TestCopyOpenExpiredReplay(t *testing.T) {
	m, r, payloads := copyRepairFixture(t, 8*time.Second)
	projection, err := m.openData(context.Background(), r, payloads)
	if err != nil {
		t.Fatal("live copy baseline failed", err)
	}
	pins := m.dataPins[projection.OpenToken]
	if pins == nil {
		t.Fatal("copy baseline lost its actual root descriptors")
	}
	t.Cleanup(func() {
		if err := pins.close(); err != nil {
			t.Error(err)
		}
	})
	deadline, err := time.Parse(time.RFC3339Nano, string(payloads[0].Grant.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(max(time.Until(deadline)+20*time.Millisecond, time.Millisecond))
	defer timer.Stop()
	<-timer.C
	replayed, err := m.openData(context.Background(), r, payloads)
	if err != nil || !reflect.DeepEqual(replayed, projection) {
		t.Fatal("expired copy grant prevented replay of its live retained roots", err)
	}
	if _, err := validateCopyPayloads(r.Inputs, payloads); err == nil {
		t.Fatal("expired copy grant was admitted for a new preparation")
	}
	changed := append([]dataCopyPayload{}, payloads...)
	changed[0].Source.Ref.SHA256 = digestBytes([]byte("foreign copy replay"))
	if _, err := m.openData(context.Background(), r, changed); err == nil {
		t.Fatal("live replay accepted a changed source pin")
	}
	if _, err := os.Stat(filepath.Join(dataFD(pins.copies[0].Destination), ".")); err != nil {
		t.Fatal("copy replay lost its original destination", err)
	}
}

func TestCopyOriginalModesIndependent(t *testing.T) {
	m, r, payloads := copyRepairFixture(t, time.Minute)
	ctx := context.Background()
	parent, err := m.find(r.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := m.captureStorageModes(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := m.openData(ctx, r, payloads)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.dataPins[projection.OpenToken].close(); err != nil {
			t.Error(err)
		}
	})
	workspace := filepath.Join(storageBase(m.binding, parent), string(parent.Storage.Binding.WorkspaceID))
	for i := 0; i < 4095-len(baseline); i++ {
		if err := os.WriteFile(filepath.Join(workspace, fmt.Sprintf("mode-%04d", i)), []byte("retained"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	parent, err = m.find(parent.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	modes, err := m.captureStorageModes(ctx, parent)
	if err != nil || len(modes) != 4095 {
		t.Fatal("copy tree consumed the primary OriginalModes journal budget", len(modes), err)
	}
	copies, err := api.ValidateDataCopyProjections(r.Inputs, projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes {
		if mode.RootID == copies[0].WorkspaceID {
			t.Fatal("copy mode was included in the primary archive mode journal")
		}
	}
}

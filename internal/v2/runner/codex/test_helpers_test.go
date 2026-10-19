package codex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

const testVendorID = "93648bc0-31a3-471b-b9f8-2eab8f360912"

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

// The embedded, unimplemented StateStore methods panic if called unexpectedly. The
// implemented reads validate their inputs and return actual stored test bytes.
type memoryStore struct {
	api.StateStore
	launchMemory
	usageMemory
	lane         api.Lane
	grants       api.GrantSet
	events       []api.Event
	blobs        map[api.ID][]byte
	refs         map[api.ID]api.BlobRef
	objectOrigin string
	chunkCorrupt bool
	readError    error
	pageSize     int
}

func hashBytes(data []byte) api.Digest {
	hash := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(hash[:]))
}

func (m *memoryStore) keep(data []byte) api.BlobRef {
	return m.keepClass(data, "test-input")
}

func (m *memoryStore) keepClass(data []byte, class string) api.BlobRef {
	name := api.ID("blob_" + strconv.Itoa(len(m.blobs)+1))
	m.blobs[name] = append([]byte{}, data...)
	if m.refs == nil {
		m.refs = map[api.ID]api.BlobRef{}
	}
	reference := api.BlobRef{ID: name, SHA256: hashBytes(data), Bytes: int64(len(data)), Class: class}
	m.refs[name] = reference
	if m.metadata == nil {
		m.metadata = map[api.ID]api.ObjectMetadata{}
	}
	m.metadata[name] = api.ObjectMetadata{Ref: reference, Origin: "service", SourceOperationID: m.cause.CauseOperationID,
		ACL: api.ObjectACL{Config: "case-codex", LifeID: m.cause.Target.LifeID}}
	return reference
}

func (m *memoryStore) event(target api.LifeRef, kind api.EventKind, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	m.sequence++
	m.events = append(m.events, api.Event{Origin: "service", Config: "case-codex", Schema: 2, ID: api.ID("event_" + strconv.FormatUint(uint64(m.sequence), 10)), Seq: m.sequence,
		Actor: m.cause.Actor, RequestedBy: m.cause.RequestedBy, RequestID: m.cause.CauseRequestID, OperationID: m.cause.CauseOperationID,
		LifeID: target.LifeID, Run: target.Run, Kind: kind, LogicalTurnID: m.cause.LogicalTurnID, Payload: data})
	for id, state := range m.captures {
		if state.Binding.Target == target {
			state.LastSeq = m.sequence
			m.captures[id] = state
		}
	}
}

func (m *memoryStore) Lane(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	if m.readError != nil {
		return api.Lane{}, m.readError
	}
	if scope.Config != "case-codex" || target.LifeID != m.lane.LifeID || target.Run != 0 && target.Run != m.lane.Run {
		return api.Lane{}, problem(api.CodeNotFound, "test life absent")
	}
	return m.lane, nil
}

func (m *memoryStore) Grants(ctx context.Context, id api.ID) (api.GrantSet, error) {
	if m.readError != nil {
		return api.GrantSet{}, m.readError
	}
	if id != m.grants.ID {
		return api.GrantSet{}, problem(api.CodeNotFound, "test grants absent")
	}
	return m.grants, nil
}

func (m *memoryStore) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if m.readError != nil {
		return api.BlobChunk{}, m.readError
	}
	data, ok := m.blobs[request.ObjectID]
	if scope.Config != "case-codex" || !ok || request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit < 1 {
		return api.BlobChunk{}, problem(api.CodeNotFound, "test blob absent")
	}
	part := append([]byte{}, data[request.Offset:min(int64(len(data)), request.Offset+int64(request.Limit))]...)
	result := api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: hashBytes(part)}
	if m.chunkCorrupt {
		result.SHA256 = hashBytes([]byte("different_bytes"))
	}
	return result, nil
}

func (m *memoryStore) ObjectMetadata(ctx context.Context, scope api.Scope, objectID api.ID) (api.ObjectMetadata, error) {
	if m.readError != nil {
		return api.ObjectMetadata{}, m.readError
	}
	reference, ok := m.refs[objectID]
	if scope.Config != "case-codex" || !ok {
		return api.ObjectMetadata{}, problem(api.CodeNotFound, "test object absent")
	}
	origin := m.metadata[objectID].Origin
	if m.objectOrigin != "" {
		origin = m.objectOrigin
	}
	metadata := m.metadata[objectID]
	metadata.Ref, metadata.Origin = reference, origin
	return metadata, nil
}

func (m *memoryStore) Events(ctx context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	if m.readError != nil {
		return api.EventPage{}, m.readError
	}
	if scope.Config != "case-codex" || request.LifeID != m.lane.LifeID {
		return api.EventPage{}, problem(api.CodeForbidden, "test event scope differs")
	}
	var matching []api.Event
	all := append(append([]api.Event{}, m.setupEvents...), m.events...)
	slices.SortFunc(all, func(a, b api.Event) int {
		if a.Seq < b.Seq {
			return -1
		}
		if a.Seq > b.Seq {
			return 1
		}
		return 0
	})
	for _, event := range all {
		if event.LifeID == request.LifeID && (request.Run == 0 || request.Run == event.Run) {
			matching = append(matching, event)
		}
	}
	start := 0
	if request.Cursor != "" {
		value, err := strconv.Atoi(request.Cursor)
		if err != nil || value < 0 || value > len(matching) {
			return api.EventPage{}, problem(api.CodeInvalid, "test cursor invalid")
		}
		start = value
	}
	end := len(matching)
	if m.pageSize > 0 {
		end = min(end, start+m.pageSize)
	}
	cursor := ""
	if end < len(matching) {
		cursor = strconv.Itoa(end)
	}
	return api.EventPage{Events: matching[start:end], Cursor: cursor, Complete: end == len(matching)}, nil
}

func canonicalTemp(t *testing.T, paths ...string) string {
	t.Helper()
	// Every test-created directory uses this helper, including named records,
	// leases and runtime children. Validate the actual filesystem object before
	// normalizing its mode; never change production privacy checks for tests.
	var temporary string
	switch len(paths) {
	case 0:
		temporary = t.TempDir()
	case 1:
		temporary = paths[0]
		if err := os.Mkdir(temporary, 0700); err != nil {
			t.Fatal("private test directory could not be created")
		}
	default:
		t.Fatal("private test directory expects at most one path")
	}
	before, err := os.Lstat(temporary)
	if err != nil || !before.IsDir() {
		t.Fatal("test directory is not an ordinary directory")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		t.Fatal("test directory is not owned by the test identity")
	}
	if err := os.Chmod(temporary, 0700); err != nil {
		t.Fatal("test directory privacy could not be established")
	}
	directory, err := filepath.EvalSymlinks(temporary)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !os.SameFile(before, info) {
		t.Fatal("test directory is not the same private ordinary directory")
	}
	owner, ok = info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		t.Fatal("test directory owner changed")
	}
	return directory
}

func putFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func getFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func syntheticAuth(t *testing.T, marker string) []byte {
	return syntheticAuthFor(t, marker, "synthetic_account_"+marker)
}

func syntheticAuthFor(t *testing.T, marker, account string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil,
		"tokens": map[string]string{"id_token": "synthetic_id_" + marker, "access_token": "synthetic_access_" + marker,
			"refresh_token": "synthetic_refresh_" + marker, "account_id": account},
		"last_refresh": "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func credentialFor(t *testing.T, profile, login api.ID) Credential {
	t.Helper()
	enrolled := hashBytes([]byte("synthetic_account_" + string(login)))
	credential, err := NewCredential(profile, login, enrolled, syntheticAuth(t, string(login)))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func newTestHome(t *testing.T) (*Home, *Leases) {
	t.Helper()
	base := canonicalTemp(t)
	recordsPath := canonicalTemp(t, filepath.Join(base, "records"))
	leasesPath := canonicalTemp(t, filepath.Join(base, "leases"))
	records, err := NewRecords(recordsPath)
	if err != nil {
		t.Fatal(err)
	}
	locks, err := NewLeases(leasesPath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "home")
	home, err := Create(path, api.PrivateHome{ID: "home_one", WorkspaceID: "workspace_one", VendorDirectory: ".codex", HistoryID: "history_one"}, records)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := home.Close(); err != nil {
			t.Error(err)
		}
		if err := locks.Close(); err != nil {
			t.Error(err)
		}
		if err := records.Close(); err != nil {
			t.Error(err)
		}
	})
	return home, locks
}

func testSlot(t *testing.T, home *Home, locks *Leases) *Slot {
	t.Helper()
	slot, err := NewSlot(home, locks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !slot.closed {
			if _, err := slot.Revoke(); err != nil {
				t.Error(err)
			}
			if err := slot.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	return slot
}

type runnerFixture struct {
	t              *testing.T
	service        *Service
	store          *memoryStore
	home           *Home
	slot           *Slot
	request        api.RunnerRequest
	clock          testClock
	plannedRequest api.RunnerRequest
	physicalWork   string
}

func newFixture(t *testing.T) *runnerFixture {
	t.Helper()
	return newFixtureInventory(t, false)
}

func newFixtureInventory(t *testing.T, alternate bool) *runnerFixture {
	t.Helper()
	home, locks := newTestHome(t)
	slot := testSlot(t, home, locks)
	root := canonicalTemp(t)
	work := canonicalTemp(t, filepath.Join(root, "work"))
	vendor := filepath.Join(root, "codex")
	vendorBytes := []byte("synthetic vendor bytes; never executed\n")
	putFile(t, vendor, vendorBytes, 0500)
	pin := api.Executable{ID: "codex_fixture", SHA256: hashBytes(vendorBytes), Version: "fixture-1"}
	clock := testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	until := api.Timestamp(clock.now.Add(time.Hour).Format(time.RFC3339Nano))
	store := &memoryStore{blobs: map[api.ID][]byte{}}
	request := api.RunnerRequest{Target: api.LifeRef{LifeID: "life_one", Run: 1}, LogicalTurnID: "turn_one",
		Session: api.Session{ID: "session_one", Driver: api.DriverCodex, VendorVersion: pin.Version, HomeID: home.Descriptor().ID, HistoryID: home.Descriptor().HistoryID, LogicalCWD: "/work/main"},
		Prompt:  store.keepClass([]byte("Read these exact kept input bytes.\n"), "prompt"), Home: home.Descriptor(),
		Slot:       api.CredentialSlot{ID: "slot_one", ProfileGrantID: "grant_one", ProfileID: "profile_one", Mode: "codex-file", LeaseID: "lease_one", ExpiresAt: until},
		Executable: pin, Model: "gpt-6.1-sol", Effort: "high", Budget: api.Budget{WallMS: 10000, CPUSeconds: 10, MemoryBytes: 1024 * 1024, Processes: 32, DiskBytes: 1024 * 1024, SpendMicros: 100, Currency: "USD"}}
	store.lane = api.Lane{LifeID: request.Target.LifeID, Run: 1, Level: 3, Role: "executor", State: "preparing", Session: request.Session, Workspace: api.Workspace{ID: request.Home.WorkspaceID, LogicalCWD: "/work/main"},
		GrantSetID: "grants_one", Model: request.Model, Effort: request.Effort, LogicalTurnID: request.LogicalTurnID, ProfileGrantID: request.Slot.ProfileGrantID, PolicyGeneration: 1}
	store.grants = api.GrantSet{ID: "grants_one", LifeID: request.Target.LifeID, PolicyGeneration: 1, ExpiresAt: until,
		Profiles: []api.ProfileGrant{{ID: request.Slot.ProfileGrantID, ProfileID: request.Slot.ProfileID, Driver: api.DriverCodex, Provider: "openai", ExpiresAt: until}}}
	if alternate {
		other := store.grants.Profiles[0]
		other.ID, other.ProfileID = "another_grant", "another_profile"
		store.grants.Profiles = append(store.grants.Profiles, other)
	}
	observed := store.keep([]byte("synthetic compatibility observation; NOT live proof\n"))
	proof := compatibilityProof{Schema: "laneboss.codex-proof.v1", AdapterVersion: AdapterVersion, Platform: runtime.GOOS, Kind: "file-login", Executable: pin, SelfHelper: pin, Observations: []api.BlobRef{observed}, Limits: []limitFixture{}, Efforts: []string{"high", "low"}}
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Store: store, Clock: clock, ReadScope: api.Scope{Config: "case-codex", Actor: api.Actor{Kind: "service", ID: "service_one"}, PolicyGeneration: 1}, Runtime: Runtime{Executable: pin, ExecutablePath: vendor, SelfHelper: pin, SelfHelperPath: vendor, FileLoginEvidence: store.keep(proofBytes)}}
	deps.ResolveHome = func(ctx context.Context, target api.LifeRef) (api.PrivateHome, error) {
		if target.LifeID != request.Target.LifeID {
			return api.PrivateHome{}, problem(api.CodeNotFound, "test home absent")
		}
		if _, err := home.Audit(); err != nil {
			return api.PrivateHome{}, err
		}
		return home.Descriptor(), nil
	}
	deps.CheckProject = func(ctx context.Context, target api.LifeRef, session api.Session) error {
		if target.LifeID != request.Target.LifeID || session.LogicalCWD != "/work/main" {
			return problem(api.CodeForbidden, "test workspace scope differs")
		}
		return CheckProjectConfig(work, work)
	}
	deps.ResolveSession = func(ctx context.Context, target api.LifeRef) (api.Session, error) {
		if target.LifeID != request.Target.LifeID {
			return api.Session{}, problem(api.CodeNotFound, "test session absent")
		}
		return home.PreparedSession()
	}
	deps.VerifySlot = func(ctx context.Context, target api.LifeRef, home api.PrivateHome, reference api.CredentialSlot) error {
		return slot.Matches(target, home, reference)
	}
	service, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := slot.Install(request.Target, request.Slot, credentialFor(t, request.Slot.ProfileID, "login_one")); err != nil {
		t.Fatal(err)
	}
	f := &runnerFixture{t: t, service: service, store: store, home: home, slot: slot, request: request, clock: clock, physicalWork: work}
	f.prepareLaunch("start", 3)
	return f
}

func observation(target api.LifeRef, code int) api.ProcessObservation {
	zero := uint64(0)
	return api.ProcessObservation{Handle: api.ProcessHandle{ID: "process_one", Target: target, ContainmentID: "containment_one", Generation: "generation_one"}, State: "exited", ExitCode: &code, Survivors: &zero, PromptStatus: "completed", ObservedAt: "2026-01-01T00:00:01Z"}
}

func (f *runnerFixture) capture(data []byte, offset int64) api.CaptureRecord {
	if len(data) > api.MaxChunkBytes {
		var last api.CaptureRecord
		for start := 0; start < len(data); start += api.MaxChunkBytes {
			last = f.capture(data[start:min(start+api.MaxChunkBytes, len(data))], offset+int64(start))
		}
		return last
	}
	binding := f.sealCapture()
	record := api.CaptureRecord{BindingID: binding.ID, ID: api.ID("capture_" + strconv.FormatUint(uint64(f.store.sequence+1), 10)), Target: f.request.Target, Stream: "stdout", Offset: offset,
		Data: f.store.keepClass(data, "capture"), ObservedAt: "2026-01-01T00:00:01Z", Primary: true, Coverage: "partial"}
	f.store.event(record.Target, "capture.appended", record)
	state := f.store.captures[binding.ID]
	state.Positions[0].NextOffset = max(state.Positions[0].NextOffset, offset+int64(len(data)))
	state.Generation++
	f.store.captures[binding.ID] = state
	return record
}

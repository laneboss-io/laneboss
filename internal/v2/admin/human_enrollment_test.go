package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type enrollmentClock struct{ now time.Time }

func TestEnrollmentCallerClasses(t *testing.T) {
	for _, check := range []struct {
		root   bool
		method string
		allow  bool
	}{
		{true, enrollmentRelayMethod, true},
		{false, enrollmentRelayMethod, false},
		{true, "probe", false},
		{true, "allocate", false},
		{true, "foreign", false},
		{false, "probe", true},
		{false, "allocate", true},
	} {
		err := enrollmentCaller(check.root, check.method)
		if (err == nil) != check.allow {
			t.Fatal("root enrollment or ordinary service helper authority crossed its native caller class")
		}
		if !check.allow {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Owner != "lb-v2-admin" {
				t.Fatal("caller-class refusal lost its actual owner/code")
			}
		}
	}
}

func TestEnrollmentFrameProducer(t *testing.T) {
	binding := testBinding()
	id, err := randomID("source-")
	if err != nil {
		t.Fatal(err)
	}
	binding.Generation = 17
	binding.Artifact.SHA256 = digestBytes([]byte(id))
	endpoint := api.AdminEnrollmentEndpoint{Config: binding.Config, Socket: "/runtime/enrollment.sock", ServiceUID: binding.Service.UID,
		InstallationGeneration: binding.Generation, Origin: "https://configured.example", RPID: "configured.example",
		Helper: api.Executable{ID: "helper", Version: binding.Release.Version, SHA256: binding.Artifact.SHA256}}
	input, err := json.Marshal(api.EnrollmentCeremonyRequest{Config: binding.Config, CeremonyID: id, PrincipalID: id})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[api.ID]bool{}
	for _, method := range []string{"enroll_begin", "enroll_complete"} {
		frame, err := newEnrollmentFrame(binding, endpoint, method, input)
		if err != nil || frame.Config != binding.Config || frame.Generation != binding.Generation ||
			frame.ArtifactSHA256 != binding.Artifact.SHA256 || frame.Method != method ||
			len(frame.Nonce) != 39 || seen[frame.Nonce] || !bytes.Equal(frame.Params, input) ||
			frame.Protocol != api.AdminEnrollmentProtocol || frame.Revision != api.ContractRevision {
			t.Fatal("actual helper producer changed its installation sources, entropy or request", err)
		}
		seen[frame.Nonce] = true
		if err := api.ValidateAdminEnrollmentFrame(frame, endpoint); err != nil {
			t.Fatal("helper and listener binding controls disagree", err)
		}
		forward := enrollmentForward{Endpoint: endpoint, Frame: frame}
		if err := validateEnrollmentForward(forward, endpoint); err != nil {
			t.Fatal("matching fixed relay envelope was refused", err)
		}
		forward.Endpoint.Socket += ".foreign"
		if err := validateEnrollmentForward(forward, endpoint); err == nil {
			t.Fatal("relay accepted a caller-selected service endpoint")
		}
		forward.Endpoint = endpoint
		forward.Frame.Generation++
		if err := validateEnrollmentForward(forward, endpoint); err == nil || api.AdminEnrollmentFailedField(err) != "generation" {
			t.Fatal("relay accepted a foreign frame generation")
		}
	}
	endpoint.InstallationGeneration++
	if _, err := newEnrollmentFrame(binding, endpoint, "enroll_begin", input); err == nil || api.AdminEnrollmentFailedField(err) != "generation" {
		t.Fatal("helper preflight accepted a mismatched installed generation")
	}
}

func (c enrollmentClock) Now() time.Time { return c.now }

// These are input-sensitive port fixtures, not WebAuthn cryptography, physical
// presence or a substitute for the real service store's atomic writer lock.
type registrationIdentity struct {
	challenge                 api.EnrollmentChallenge
	request                   api.EnrollmentValidationRequest
	install                   api.EnrollmentInstall
	beginCalls, validateCalls int
	err                       error
}

func (i *registrationIdentity) BeginEnrollment(_ context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	i.beginCalls++
	if request != i.request.Ceremony {
		return api.EnrollmentChallenge{}, failure(api.CodeForbidden, "fixture identity rejected a foreign ceremony")
	}
	if i.err != nil {
		return api.EnrollmentChallenge{}, i.err
	}
	return i.challenge, nil
}
func (i *registrationIdentity) ValidateEnrollment(_ context.Context, request api.EnrollmentValidationRequest) (api.EnrollmentInstall, error) {
	i.validateCalls++
	if !reflect.DeepEqual(request, i.request) {
		return api.EnrollmentInstall{}, failure(api.CodeForbidden, "fixture identity rejected changed registration bytes")
	}
	if i.err != nil {
		return api.EnrollmentInstall{}, i.err
	}
	return i.install, nil
}

type registrationStore struct {
	api.StateStore
	config          string
	scope           api.Scope
	challenge       api.EnrollmentChallenge
	inventory       []api.HumanEnrollment
	inventoryErr    error
	reads, installs int
	expected        api.EnrollmentInstall
	evidence        api.ObjectWrite
	operation       api.Operation
	event           api.Event
	consume         bool
	commitErr       error
}

func (s *registrationStore) HumanEnrollments(_ context.Context, config string) ([]api.HumanEnrollment, error) {
	s.reads++
	if config != s.config {
		return nil, failure(api.CodeForbidden, "fixture rejected a foreign inventory")
	}
	if s.inventoryErr != nil {
		return nil, s.inventoryErr
	}
	return s.inventory, nil
}
func (s *registrationStore) EnrollmentChallenge(_ context.Context, config string, id api.ID) (api.EnrollmentChallenge, error) {
	if config != s.config || id != s.challenge.ID {
		return api.EnrollmentChallenge{}, failure(api.CodeNotFound, "fixture challenge missing")
	}
	return s.challenge, nil
}
func (s *registrationStore) ReserveEnrollment(_ context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	if request != s.challenge.Ceremony {
		return api.EnrollmentChallenge{}, failure(api.CodeForbidden, "fixture cannot reserve a foreign ceremony")
	}
	return s.challenge, nil
}
func (s *registrationStore) InstallHumanEnrollment(_ context.Context, scope api.Scope, intent api.InternalIntent, install api.EnrollmentInstall, evidence api.ObjectWrite) (api.Commit, error) {
	s.installs++
	if s.commitErr != nil {
		return api.Commit{}, s.commitErr
	}
	if scope.Actor != s.scope.Actor || scope.Config != s.config || intent.Kind != api.InternalAdminEnroll ||
		!reflect.DeepEqual(install, s.expected) || evidence.SHA256 != install.CeremonyEvidence.SHA256 || digestBytes(evidence.Bytes) != evidence.SHA256 {
		return api.Commit{}, failure(api.CodeForbidden, "fixture atomic writer rejected changed registration handoff")
	}
	if len(s.inventory) != 0 {
		return api.Commit{}, failure(api.CodeConflict, "fixture atomic writer refuses a second baseline")
	}
	s.inventory = []api.HumanEnrollment{copyEnrollmentInstall(install).Enrollment}
	s.evidence = evidence
	s.challenge.Consumed = s.consume
	s.operation = api.Operation{ID: intent.CauseOperationID, Status: "succeeded", FirstSeq: 4, LastSeq: 4,
		SimulatedPresence: install.Enrollment.Credentials[0].SimulatedPresence}
	payload, err := json.Marshal(install.CeremonyEvidence)
	if err != nil {
		return api.Commit{}, err
	}
	s.event = api.Event{Schema: api.SchemaVersion, ID: api.ID("event-" + string(install.CeremonyID)), Config: s.config,
		Seq: 4, Kind: "blob.committed", OperationID: s.operation.ID, RequestID: intent.CauseRequestID, Actor: scope.Actor,
		RequestedBy: intent.RequestedBy, Origin: "service", Payload: payload}
	return api.Commit{Operation: s.operation, FirstSeq: 4, LastSeq: 4}, nil
}
func (s *registrationStore) Operation(_ context.Context, scope api.Scope, id api.ID) (api.Operation, error) {
	if scope.Actor != s.scope.Actor || scope.Config != s.config || id != s.operation.ID {
		return api.Operation{}, failure(api.CodeForbidden, "fixture operation is not visible")
	}
	return s.operation, nil
}
func (s *registrationStore) Events(_ context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	if scope.Actor != s.scope.Actor || scope.Config != s.config || request.Follow {
		return api.EventPage{}, failure(api.CodeForbidden, "fixture event scope refused")
	}
	page := api.EventPage{Events: []api.Event{}, Complete: true}
	if s.event.Seq > request.Since {
		page.Events = append(page.Events, s.event)
	}
	return page, nil
}
func (s *registrationStore) ObjectMetadata(_ context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	if scope.Actor != s.scope.Actor || scope.Config != s.config || id != s.evidence.ObjectKey {
		return api.ObjectMetadata{}, failure(api.CodeForbidden, "fixture evidence is not visible")
	}
	return api.ObjectMetadata{Ref: s.expected.CeremonyEvidence, ACL: s.evidence.ACL, Origin: s.evidence.Origin, SourceOperationID: s.operation.ID}, nil
}
func (s *registrationStore) Blob(_ context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if scope.Actor != s.scope.Actor || scope.Config != s.config || request.ObjectID != s.evidence.ObjectKey ||
		request.Offset < 0 || request.Offset >= int64(len(s.evidence.Bytes)) || request.Limit < 1 {
		return api.BlobChunk{}, failure(api.CodeForbidden, "fixture evidence range refused")
	}
	end := min(int64(len(s.evidence.Bytes)), request.Offset+int64(request.Limit))
	part := append([]byte(nil), s.evidence.Bytes[request.Offset:end]...)
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: digestBytes(part)}, nil
}

func initialEnrollmentFixture(t *testing.T) (*InitialEnrollmentValidator, *registrationIdentity, *registrationStore, context.Context, api.AdminEnrollmentEndpoint) {
	t.Helper()
	binding := testBinding()
	endpoint := api.AdminEnrollmentEndpoint{Config: binding.Config, Socket: "/run/enrollment/admin.sock", ServiceUID: binding.Service.UID,
		InstallationGeneration: binding.Generation, Origin: "https://console.example", RPID: "console.example",
		Helper: api.Executable{ID: "helper", Version: binding.Release.Version, SHA256: binding.Artifact.SHA256}}
	human := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: endpoint.Config, Class: api.EndpointHuman, InstallationGeneration: endpoint.InstallationGeneration, EndpointGeneration: 7,
		ServiceUID: binding.Service.UID, ServiceGID: binding.Service.GID, Socket: "/run/human/service.sock", ArtifactSHA256: binding.Artifact.SHA256,
		ServiceVersion: binding.Release.Version, Backend: "linux-bwrap-landlock"}
	now := time.Now().UTC()
	ceremony := api.EnrollmentCeremonyRequest{Config: endpoint.Config, CeremonyID: "ceremony-a", PrincipalID: "administrator-a"}
	challenge := api.EnrollmentChallenge{ID: "challenge-a", Ceremony: ceremony, Challenge: bytes.Repeat([]byte{17}, 32), Origin: endpoint.Origin,
		RPID: endpoint.RPID, EndpointGeneration: human.EndpointGeneration, InstallationGeneration: endpoint.InstallationGeneration, ExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))}
	request := api.EnrollmentValidationRequest{Ceremony: ceremony, ChallengeID: challenge.ID, ClientDataJSON: []byte(`{"type":"fixture-create"}`), AttestationObject: []byte("port-fixture-attestation")}
	evidenceBytes, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	evidenceBytes = append([]byte(" "), evidenceBytes...)
	ref := api.BlobRef{ID: "registration-evidence", Class: "artifact", Bytes: int64(len(evidenceBytes)), SHA256: digestBytes(evidenceBytes)}
	install := api.EnrollmentInstall{CeremonyID: ceremony.CeremonyID, ChallengeID: challenge.ID, ValidationID: "identity-validation", CeremonyEvidence: ref,
		Enrollment: api.HumanEnrollment{Config: endpoint.Config, PrincipalID: ceremony.PrincipalID, Origin: endpoint.Origin, RPID: endpoint.RPID,
			Generation: 1, Credentials: []api.HumanCredential{{ID: "credential-a", RawCredentialID: []byte("public-credential-id"), PublicKeyDER: []byte("public-port-fixture"),
				Algorithm: "ES256", Generation: 1, AAGUID: "01020304-0506-0708-090a-0b0c0d0e0f10", AttestationFormat: "packed", RegistrationEvidence: ref}}}}
	identity := &registrationIdentity{challenge: challenge, request: request, install: install}
	store := &registrationStore{config: endpoint.Config, challenge: challenge, expected: install, consume: true,
		scope: api.Scope{Config: endpoint.Config, Actor: api.Actor{Kind: "service", ID: "service-a"}, Source: "service"}}
	store.evidence = api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: evidenceBytes, SHA256: ref.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: endpoint.Config, Owner: store.scope.Actor, Audience: "owner", Generation: 1}}
	validator, err := NewInitialEnrollmentValidator(endpoint, human, identity, store, enrollmentClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), enrollmentChannelKey{}, &enrollmentChannel{endpoint: endpoint, human: human, verify: func() error { return nil }})
	return validator, identity, store, ctx, endpoint
}

func TestEnrollmentChannel(t *testing.T) {
	_, _, _, ctx, endpoint := initialEnrollmentFixture(t)
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	t.Run("absent", func(t *testing.T) {
		if err := CheckEnrollmentChannel(context.Background(), endpoint); err == nil {
			t.Fatal("acceptance: enrollment accepted an unprotected entry")
		}
	})
	t.Run("endpoint", func(t *testing.T) {
		other := endpoint
		other.InstallationGeneration++
		if err := CheckEnrollmentChannel(ctx, other); err == nil {
			t.Fatal("acceptance: enrollment channel changed installation")
		}
	})
	t.Run("lifetime", func(t *testing.T) {
		ended := failure(api.CodeUnauthenticated, "fixture peer ended")
		closed := context.WithValue(ctx, enrollmentChannelKey{}, &enrollmentChannel{endpoint: endpoint, verify: func() error { return ended }})
		if err := CheckEnrollmentChannel(closed, endpoint); !errors.Is(err, ended) {
			t.Fatal("acceptance: enrollment ignored its current native peer")
		}
	})
}

func TestInitialRegistration(t *testing.T) {
	v, identity, store, ctx, _ := initialEnrollmentFixture(t)
	challenge, err := v.BeginEnrollment(ctx, identity.request.Ceremony)
	if err != nil || !reflect.DeepEqual(challenge, store.challenge) || identity.beginCalls != 1 {
		t.Fatalf("stored create challenge was not returned: %v", err)
	}
	validated, err := v.ValidateInitialRegistration(ctx, identity.request)
	if err != nil || identity.validateCalls != 1 || store.reads < 2 || !reflect.DeepEqual(validated.Install(), identity.install) {
		t.Fatalf("actual registration port/handoff was not used: %v", err)
	}
	copy := validated.Install()
	copy.Enrollment.Credentials[0].PublicKeyDER[0] ^= 1
	if reflect.DeepEqual(copy, validated.Install()) {
		t.Fatal("registration handoff exposes mutable credential bytes")
	}
}

func TestEnrollmentBeginStored(t *testing.T) {
	v, identity, store, ctx, _ := initialEnrollmentFixture(t)
	store.challenge.Challenge = bytes.Repeat([]byte{29}, 32)
	if _, err := v.BeginEnrollment(ctx, identity.request.Ceremony); err == nil {
		t.Fatal("acceptance: begin returned an unstored create nonce")
	}
}

func TestEnrollmentPrivateCommit(t *testing.T) {
	_, _, store, ctx, endpoint := initialEnrollmentFixture(t)
	service := &Service{binding: testBinding(), deps: Dependencies{Store: store}}
	_, err := service.CommitInitialEnrollment(ctx, nil, store.scope, api.InternalIntent{}, store.evidence)
	if err == nil || store.installs != 0 {
		t.Fatal("acceptance: enrollment commit accepted a manufactured validation handoff")
	}
	if err := validateEnrollmentEndpoint(endpoint, service.binding); err != nil {
		t.Fatal(err)
	}
	endpoint.Helper.SHA256 = testDigest("different-helper")
	if err := validateEnrollmentEndpoint(endpoint, service.binding); err == nil {
		t.Fatal("acceptance: administrator endpoint accepted an uninstalled helper")
	}
}

func TestStoreRegistrationValidation(t *testing.T) {
	v, identity, store, ctx, endpoint := initialEnrollmentFixture(t)
	if err := CheckInitialEnrollmentInstall(ctx, endpoint, identity.install, store.evidence); err == nil {
		t.Fatal("acceptance: store enrollment accepted a label-only validation")
	}
	registration, err := v.ValidateInitialRegistration(ctx, identity.request)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckInitialEnrollmentInstall(ctx, endpoint, registration.Install(), store.evidence); err != nil {
		t.Fatal(err)
	}
	changed := registration.Install()
	changed.ValidationID = "foreign-identity-validation"
	if err := CheckInitialEnrollmentInstall(ctx, endpoint, changed, store.evidence); err == nil {
		t.Fatal("acceptance: store enrollment accepted changed identity validation")
	}
}

func TestStoreRegistrationEvidence(t *testing.T) {
	v, identity, store, ctx, endpoint := initialEnrollmentFixture(t)
	registration, err := v.ValidateInitialRegistration(ctx, identity.request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := store.evidence
	evidence.ObjectKey = "foreign-registration-evidence"
	if err := CheckInitialEnrollmentInstall(ctx, endpoint, registration.Install(), evidence); err == nil {
		t.Fatal("acceptance: store enrollment accepted foreign registration evidence")
	}
}

func TestRegRefusals(t *testing.T) {
	for _, fault := range []string{"second-baseline", "replacement", "inventory-error", "challenge-origin", "challenge-generation", "challenge-endpoint", "consumed", "identity-refusal", "validation-id", "evidence", "credential-origin"} {
		t.Run(fault, func(t *testing.T) {
			v, identity, store, ctx, _ := initialEnrollmentFixture(t)
			request := identity.request
			beforeIdentity := true
			switch fault {
			case "second-baseline":
				prior := copyEnrollmentInstall(identity.install).Enrollment
				prior.PrincipalID = "different-prior-administrator"
				prior.Credentials[0].Revoked = true
				store.inventory = []api.HumanEnrollment{prior}
			case "replacement":
				request.Ceremony.ExpectedGeneration = 1
			case "inventory-error":
				store.inventoryErr = failure(api.CodeIntegrity, "fixture inventory unreadable")
			case "challenge-origin":
				store.challenge.Origin = "https://console.example:8443"
			case "challenge-generation":
				store.challenge.InstallationGeneration++
			case "challenge-endpoint":
				store.challenge.EndpointGeneration++
			case "consumed":
				store.challenge.Consumed = true
			case "identity-refusal":
				beforeIdentity = false
				identity.err = failure(api.CodeForbidden, "fixture signature verification refused")
			case "validation-id":
				beforeIdentity = false
				identity.install.ValidationID = ""
			case "evidence":
				beforeIdentity = false
				identity.install.Enrollment.Credentials[0].RegistrationEvidence.SHA256 = testDigest("another-registration")
			case "credential-origin":
				beforeIdentity = false
				identity.install.Enrollment.Origin = "https://other.example"
			}
			_, err := v.ValidateInitialRegistration(ctx, request)
			if err == nil || beforeIdentity && identity.validateCalls != 0 {
				t.Fatal("acceptance: invalid initial registration reached authority")
			}
			if fault == "identity-refusal" && !errors.Is(err, identity.err) {
				t.Fatal("identity registration refusal was not preserved")
			}
		})
	}
}

func TestInitialCommitReadBack(t *testing.T) {
	v, identity, store, ctx, endpoint := initialEnrollmentFixture(t)
	registration, err := v.ValidateInitialRegistration(ctx, identity.request)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{binding: testBinding(), deps: Dependencies{Config: endpoint.Config, Store: store}}
	intent := api.InternalIntent{ID: "enrollment-intent", Kind: api.InternalAdminEnroll, Config: endpoint.Config,
		Actor: store.scope.Actor, RequestedBy: store.scope.Actor, CauseOperationID: "enrollment-operation", CauseRequestID: "enrollment-request"}
	receipt, err := service.CommitInitialEnrollment(ctx, registration, store.scope, intent, store.evidence)
	if err != nil || store.installs != 1 || receipt.EventID != store.event.ID || receipt.CommittedSeq != store.event.Seq || !store.challenge.Consumed {
		t.Fatalf("atomic enrollment/read-back not reached: %v", err)
	}
	if err := service.VerifyEnrollmentReplay(ctx, store.scope, endpoint, identity.request, receipt); err != nil {
		t.Fatalf("retained enrollment replay failed: %v", err)
	}
	if _, err := v.ValidateInitialRegistration(ctx, identity.request); err == nil {
		t.Fatal("acceptance: committed baseline reopened initial registration")
	}
}

func TestEnrollReceipt(t *testing.T) {
	for _, fault := range []string{"event", "event-missing", "bytes", "challenge-unconsumed", "presence", "operation-presence", "operation", "public-evidence", "changed-retry"} {
		t.Run(fault, func(t *testing.T) {
			v, identity, store, ctx, endpoint := initialEnrollmentFixture(t)
			registration, err := v.ValidateInitialRegistration(ctx, identity.request)
			if err != nil {
				t.Fatal(err)
			}
			service := &Service{binding: testBinding(), deps: Dependencies{Store: store}}
			intent := api.InternalIntent{ID: "enrollment-intent", Kind: api.InternalAdminEnroll, Config: endpoint.Config,
				Actor: store.scope.Actor, RequestedBy: store.scope.Actor, CauseOperationID: "enrollment-operation", CauseRequestID: "enrollment-request"}
			receipt, err := service.CommitInitialEnrollment(ctx, registration, store.scope, intent, store.evidence)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "event":
				store.event.ID = "fabricated-event"
			case "event-missing":
				store.event.Seq = 0
			case "bytes":
				store.evidence.Bytes = append([]byte(nil), store.evidence.Bytes...)
				store.evidence.Bytes[0] = '\n'
			case "challenge-unconsumed":
				store.challenge.Consumed = false
			case "presence":
				receipt.SimulatedPresence = true
				store.operation.SimulatedPresence = true
			case "operation-presence":
				store.operation.SimulatedPresence = true
			case "operation":
				store.operation.Status = "pending"
			case "public-evidence":
				store.evidence.ACL.Audience = "all"
			case "changed-retry":
				identity.request.AttestationObject = []byte("different-attestation")
			}
			if err := verifyEnrollmentReceipt(ctx, store, store.scope, endpoint, identity.request, receipt); err == nil {
				t.Fatal("acceptance: enrollment receipt lacked actual committed evidence")
			}
		})
	}
}

type boundEnrollmentTarget struct{ identity *registrationIdentity }

func (b *boundEnrollmentTarget) BeginHumanEnrollment(ctx context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	return b.identity.BeginEnrollment(ctx, request)
}
func (b *boundEnrollmentTarget) CompleteHumanEnrollment(context.Context, api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	return api.EnrollmentReceipt{}, api.NotImplemented("lb-v2-service", "fixture has no completed ceremony")
}

func TestEnrollmentBinding(t *testing.T) {
	_, identity, _, _, _ := initialEnrollmentFixture(t)
	service := &Service{}
	var absent *boundEnrollmentTarget
	if err := service.BindEnrollment(absent); err == nil {
		t.Fatal("acceptance: enrollment binding accepted a missing service")
	}
	target := &boundEnrollmentTarget{identity: identity}
	if err := service.BindEnrollment(target); err != nil {
		t.Fatal(err)
	}
	if service.enrollment != target {
		t.Fatal("enrollment binding did not retain its actual service")
	}
	if err := service.BindEnrollment(target); err == nil {
		t.Fatal("acceptance: enrollment binding was replaceable")
	}
}

func TestEnrollEndpoint(t *testing.T) {
	_, _, _, _, endpoint := initialEnrollmentFixture(t)
	binding := testBinding()
	if err := validateEnrollmentEndpoint(endpoint, binding); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"config", "uid", "generation", "artifact", "version", "helper-socket"} {
		t.Run(fault, func(t *testing.T) {
			changed := endpoint
			switch fault {
			case "config":
				changed.Config = "another-config"
			case "uid":
				changed.ServiceUID++
			case "generation":
				changed.InstallationGeneration++
			case "artifact":
				changed.Helper.SHA256 = testDigest("another-helper-artifact")
			case "version":
				changed.Helper.Version = "0.0.1"
			case "helper-socket":
				changed.Socket = binding.socketPath()
			}
			if err := validateEnrollmentEndpoint(changed, binding); err == nil {
				t.Fatal("acceptance: installed administrator endpoint pins changed")
			}
		})
	}
}

func TestEnrollmentInitialOnly(t *testing.T) {
	_, identity, _, _, endpoint := initialEnrollmentFixture(t)
	request := identity.request.Ceremony
	if err := validateInitialCeremony(request, endpoint.Config); err != nil {
		t.Fatal(err)
	}
	request.ExpectedGeneration = 1
	if err := validateInitialCeremony(request, endpoint.Config); err == nil {
		t.Fatal("acceptance: fixed administrator entry permits baseline replacement")
	}
}

func TestEnrollmentEntryOptions(t *testing.T) {
	valid := []string{"--installation", "/etc/service.json", "--enroll-begin", "/runtime/begin.json"}
	if _, err := parseEnrollmentOptions(valid); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--installation", "/etc/service.json"},
		{"--installation", "/etc/service.json", "--enroll-begin", "/runtime/begin.json", "--enroll-complete", "/runtime/end.json"},
		{"--installation", "/etc/service.json", "--enroll-begin", "relative.json"},
		{"--installation", "/etc/service.json", "--enroll-begin", "/runtime/begin.json", "--argv", "/bin/tool"},
	} {
		if _, err := parseEnrollmentOptions(args); err == nil {
			t.Fatal("acceptance: fixed enrollment entry accepted arbitrary or ambiguous inputs")
		}
	}
}

func TestSimulatedEnrollmentLabels(t *testing.T) {
	var output bytes.Buffer
	receipt := api.EnrollmentReceipt{Config: "admin-case", PrincipalID: "administrator-a", SimulatedPresence: true}
	if err := writeEnrollmentOutput(&output, receipt); err != nil {
		t.Fatal(err)
	}
	var row struct {
		Receipt       api.EnrollmentReceipt `json:"receipt"`
		Presence      string                `json:"presence"`
		HumanApproval string                `json:"human_approval"`
	}
	if err := api.DecodeObject(output.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row.Receipt != receipt || row.Presence != "simulated" || row.HumanApproval != "not_proven" {
		t.Fatal("acceptance: simulated presence was reported as human approval")
	}
}

func TestEnrollmentHumanBinding(t *testing.T) {
	v, identity, _, ctx, endpoint := initialEnrollmentFixture(t)
	if v.human.EndpointGeneration == endpoint.InstallationGeneration {
		t.Fatal("independent generation control setup was lost")
	}
	if err := validateEnrollmentHumanBinding(endpoint, v.human); err != nil {
		t.Fatal(err)
	}
	t.Run("socket", func(t *testing.T) {
		changed := v.human
		changed.Socket = endpoint.Socket
		if err := validateEnrollmentHumanBinding(endpoint, changed); err == nil {
			t.Fatal("acceptance: enrollment reused the public human endpoint")
		}
	})
	t.Run("channel", func(t *testing.T) {
		channel := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
		channel.human.EndpointGeneration++
		_, err := v.ValidateInitialRegistration(ctx, identity.request)
		if err == nil || identity.validateCalls != 0 {
			t.Fatal("acceptance: registration lost its protected human endpoint binding")
		}
	})
}

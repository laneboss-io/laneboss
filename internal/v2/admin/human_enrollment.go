package admin

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

const enrollmentProtocol = api.AdminEnrollmentProtocol
const enrollmentRelayMethod = "admin_enrollment"

type enrollmentForward struct {
	Endpoint api.AdminEnrollmentEndpoint `json:"endpoint"`
	Frame    api.AdminEnrollmentFrame    `json:"frame"`
}

func enrollmentCaller(root bool, method string) error {
	if root != (method == enrollmentRelayMethod) {
		return failure(api.CodeForbidden, "root enrollment and service helper operations use distinct native callers")
	}
	return nil
}

func validateEnrollmentForward(input enrollmentForward, endpoint api.AdminEnrollmentEndpoint) error {
	if input.Endpoint != endpoint {
		return failure(api.CodeForbidden, "administrator relay endpoint differs from protected installation")
	}
	return api.ValidateAdminEnrollmentFrame(input.Frame, endpoint)
}

func newEnrollmentFrame(binding installation, endpoint api.AdminEnrollmentEndpoint, method string, input json.RawMessage) (api.AdminEnrollmentFrame, error) {
	nonce, err := randomID("enroll-")
	if err != nil {
		return api.AdminEnrollmentFrame{}, err
	}
	frame := api.AdminEnrollmentFrame{Protocol: enrollmentProtocol, Revision: api.ContractRevision, Config: binding.Config,
		Generation: binding.Generation, ArtifactSHA256: binding.Artifact.SHA256, Nonce: nonce, Method: method, Params: input}
	if err := api.ValidateAdminEnrollmentFrame(frame, endpoint); err != nil {
		return api.AdminEnrollmentFrame{}, err
	}
	return frame, nil
}

// This capability is made only after native peer, artifact and installation
// checks on the distinct administrator socket. It cannot arrive in JSON or a
// public Scope. The closure repeats those checks immediately before an effect.
type enrollmentChannelKey struct{}
type enrollmentChannel struct {
	initialRequest *InitialRequest
	initial        *api.Transaction
	initialHash    api.Digest
	initialReceipt *InitialReceipt
	human          api.InstalledBinding
	endpoint       api.AdminEnrollmentEndpoint
	verify         func() error
	receipt        *api.EnrollmentReceipt
	validated      *ValidatedRegistration
}

// CheckEnrollmentChannel is the service's private-entry guard. Call it again
// immediately before the atomic admin_enroll transaction. Root login identity
// grants no human proof, and a service Actor/Source label cannot make this token.
func CheckEnrollmentChannel(ctx context.Context, endpoint api.AdminEnrollmentEndpoint) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	channel, ok := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	if !ok || channel == nil || channel.verify == nil || channel.endpoint != endpoint {
		return failure(api.CodeForbidden, "enrollment requires the protected installed helper channel")
	}
	return channel.verify()
}

// Binding does not listen or advertise a running ceremony. ServeEnrollment
// belongs to the installed service's context and error lifecycle, not a detached
// goroutine created during assembly. There is no public registration handler.
func (s *Service) BindEnrollment(target api.AdminEnrollment) error {
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	if nilEnrollmentPort(target) {
		return failure(api.CodeInvalid, "administrator enrollment needs its service implementation")
	}
	if s.enrollment != nil {
		return failure(api.CodeConflict, "administrator enrollment is already bound")
	}
	s.enrollment = target
	return nil
}

func nilEnrollmentPort(port any) bool {
	if port == nil {
		return true
	}
	value := reflect.ValueOf(port)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return value.IsNil()
	}
	return false
}

func validateEnrollmentEndpoint(endpoint api.AdminEnrollmentEndpoint, binding installation) error {
	if err := api.ValidateAdminEnrollmentEndpoint(endpoint); err != nil {
		return err
	}
	if endpoint.Config != binding.Config || endpoint.ServiceUID != binding.Service.UID ||
		endpoint.InstallationGeneration != binding.Generation || endpoint.Helper.SHA256 != binding.Artifact.SHA256 ||
		endpoint.Helper.Version != binding.Release.Version || endpoint.Socket == binding.socketPath() {
		return failure(api.CodeIntegrity, "administrator endpoint differs from the installed helper generation")
	}
	return nil
}

func validateInitialCeremony(request api.EnrollmentCeremonyRequest, config string) error {
	if request.Config != config || !validConfig(config) || !validID(request.CeremonyID) || !validID(request.PrincipalID) {
		return failure(api.CodeInvalid, "administrator enrollment selects a foreign or malformed ceremony")
	}
	if request.ExpectedGeneration != 0 {
		return failure(api.CodeForbidden, "administrator enrollment cannot replace a baseline; use human approval/D6")
	}
	return nil
}

func requireEmptyEnrollment(ctx context.Context, inventory api.HumanEnrollmentInventory, config string) error {
	if nilEnrollmentPort(inventory) {
		return api.NotImplemented("lb-v2-service", "protected human credential inventory")
	}
	enrollments, err := inventory.HumanEnrollments(ctx, config)
	if err != nil {
		return err
	}
	if err := api.ValidateHumanEnrollments(config, enrollments); err != nil {
		return err
	}
	// The whole configuration is inspected, including revoked credentials and
	// principals other than the requested one. The store repeats this under its
	// writer lock; this preflight cannot substitute for that atomic restriction.
	if len(enrollments) != 0 {
		return failure(api.CodeConflict, "initial administrator enrollment baseline already exists")
	}
	return nil
}

// InitialEnrollmentValidator is the admin consumer of identity's registration
// port. Identity owns real create/attestation crypto and immutable evidence;
// this wrapper never derives a credential from caller-supplied metadata.
type InitialEnrollmentValidator struct {
	human    api.InstalledBinding
	endpoint api.AdminEnrollmentEndpoint
	identity api.EnrollmentValidator
	store    interface {
		api.HumanEnrollmentInventory
		api.EnrollmentCeremonyStore
	}
	clock api.Clock
}

func NewInitialEnrollmentValidator(endpoint api.AdminEnrollmentEndpoint, human api.InstalledBinding, identity api.EnrollmentValidator,
	store interface {
		api.HumanEnrollmentInventory
		api.EnrollmentCeremonyStore
	}, clock api.Clock) (*InitialEnrollmentValidator, error) {
	if err := api.ValidateAdminEnrollmentEndpoint(endpoint); err != nil {
		return nil, err
	}
	if err := validateEnrollmentHumanBinding(endpoint, human); err != nil {
		return nil, err
	}
	if nilEnrollmentPort(identity) || nilEnrollmentPort(store) || nilEnrollmentPort(clock) {
		return nil, failure(api.CodePrerequisite, "initial enrollment requires identity validation, complete inventory and a clock")
	}
	return &InitialEnrollmentValidator{endpoint: endpoint, human: human, identity: identity, store: store, clock: clock}, nil
}

var _ api.EnrollmentValidator = (*InitialEnrollmentValidator)(nil)

func (v *InitialEnrollmentValidator) BeginEnrollment(ctx context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	if err := v.guard(ctx, request); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	challenge, err := v.identity.BeginEnrollment(ctx, request)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := v.checkChallenge(challenge, request); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	// Reload the stored reservation. An identity callback cannot supply an
	// unstored nonce and call it a successful begin.
	retained, err := v.store.EnrollmentChallenge(ctx, request.Config, challenge.ID)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if !reflect.DeepEqual(retained, challenge) {
		return api.EnrollmentChallenge{}, failure(api.CodeIntegrity, "create challenge differs from the stored ceremony")
	}
	return challenge, CheckEnrollmentChannel(ctx, v.endpoint)
}

func (v *InitialEnrollmentValidator) ValidateEnrollment(ctx context.Context, request api.EnrollmentValidationRequest) (api.EnrollmentInstall, error) {
	if err := v.guard(ctx, request.Ceremony); err != nil {
		return api.EnrollmentInstall{}, err
	}
	channel := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	channel.validated = nil
	// The interface and concrete entry share one retained, immutable handoff.
	// Give the identity producer separate input bytes so its callback cannot
	// change either the caller's request or the later store evidence binding.
	request.ClientDataJSON = append([]byte(nil), request.ClientDataJSON...)
	request.AttestationObject = append([]byte(nil), request.AttestationObject...)
	retained := request
	retained.ClientDataJSON = append([]byte(nil), request.ClientDataJSON...)
	retained.AttestationObject = append([]byte(nil), request.AttestationObject...)
	challenge, err := v.store.EnrollmentChallenge(ctx, request.Ceremony.Config, request.ChallengeID)
	if err != nil {
		return api.EnrollmentInstall{}, err
	}
	if err := v.checkChallenge(challenge, request.Ceremony); err != nil {
		return api.EnrollmentInstall{}, err
	}
	install, err := v.identity.ValidateEnrollment(ctx, request)
	if err != nil {
		return api.EnrollmentInstall{}, err
	}
	if !reflect.DeepEqual(request, retained) {
		return api.EnrollmentInstall{}, failure(api.CodeIntegrity, "registration producer changed its input bytes")
	}
	install = copyEnrollmentInstall(install)
	if err := api.ValidateHumanEnrollments(v.endpoint.Config, []api.HumanEnrollment{install.Enrollment}); err != nil {
		return api.EnrollmentInstall{}, err
	}
	if err := api.ValidateInitialEnrollment(challenge, request, install, v.clock.Now()); err != nil {
		return api.EnrollmentInstall{}, err
	}
	// This also calls the production/test-tag presence gate on the actual
	// identity-derived credential. A supplied bool never grants acceptance.
	if err := v.guard(ctx, request.Ceremony); err != nil {
		return api.EnrollmentInstall{}, err
	}
	channel.validated = &ValidatedRegistration{channel: channel, request: retained, install: copyEnrollmentInstall(install)}
	return copyEnrollmentInstall(install), nil
}

func (v *InitialEnrollmentValidator) guard(ctx context.Context, request api.EnrollmentCeremonyRequest) error {
	if err := CheckEnrollmentChannel(ctx, v.endpoint); err != nil {
		return err
	}
	channel := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	if channel.human != v.human {
		return failure(api.CodeForbidden, "registration differs from the protected human endpoint binding")
	}
	if err := validateInitialCeremony(request, v.endpoint.Config); err != nil {
		return err
	}
	return requireEmptyEnrollment(ctx, v.store, v.endpoint.Config)
}

func (v *InitialEnrollmentValidator) checkChallenge(challenge api.EnrollmentChallenge, request api.EnrollmentCeremonyRequest) error {
	if err := api.ValidateEnrollmentChallenge(challenge, request, v.clock.Now()); err != nil {
		return err
	}
	if challenge.Origin != v.endpoint.Origin || challenge.RPID != v.endpoint.RPID ||
		challenge.InstallationGeneration != v.endpoint.InstallationGeneration || challenge.EndpointGeneration != v.human.EndpointGeneration {
		return failure(api.CodeIntegrity, "registration challenge differs from the protected administrator endpoint")
	}
	return nil
}

func validateEnrollmentHumanBinding(endpoint api.AdminEnrollmentEndpoint, human api.InstalledBinding) error {
	if err := api.ValidateBinding(human, endpoint.Config, endpoint.Helper.Version); err != nil {
		return err
	}
	if human.Class != api.EndpointHuman || human.ServiceUID != endpoint.ServiceUID || human.ArtifactSHA256 != endpoint.Helper.SHA256 ||
		human.InstallationGeneration != endpoint.InstallationGeneration || human.EndpointGeneration > 1<<53-1 || human.Socket == endpoint.Socket {
		return failure(api.CodeIntegrity, "administrator ceremony lacks its distinct installed human endpoint")
	}
	return nil
}

type enrollmentOptions struct{ installation, begin, complete, publish, spend, invite, redeem string }

func parseEnrollmentOptions(args []string) (enrollmentOptions, error) {
	var options enrollmentOptions
	seen := map[string]bool{}
	for index := 0; index < len(args); index += 2 {
		if index+1 >= len(args) || seen[args[index]] || !filepath.IsAbs(args[index+1]) || filepath.Clean(args[index+1]) != args[index+1] {
			return options, failure(api.CodeInvalid, "fixed enrollment entry requires distinct options and canonical absolute files")
		}
		seen[args[index]] = true
		switch args[index] {
		case "--installation":
			options.installation = args[index+1]
		case "--enroll-begin":
			options.begin = args[index+1]
		case "--enroll-complete":
			options.complete = args[index+1]
		case "--invite-begin":
			options.invite = args[index+1]
		case "--invite-complete":
			options.redeem = args[index+1]
		case "--publish-initial":
			options.publish = args[index+1]
		case "--spend-reconcile":
			options.spend = args[index+1]
		default:
			return options, failure(api.CodeForbidden, "unknown fixed administrator enrollment option")
		}
	}
	modes := 0
	for _, path := range []string{options.begin, options.complete, options.publish, options.spend, options.invite, options.redeem} {
		if path != "" {
			modes++
		}
	}
	if options.installation == "" || modes != 1 {
		return options, failure(api.CodeInvalid, "administrator entry requires installation and exactly one fixed input file")
	}
	return options, nil
}

// RunEnrollment reads only public registration inputs. The authenticator's
// private key is never an argument, upload, state object or helper response.
func RunEnrollment(ctx context.Context, config string, args []string, output io.Writer) error {
	if !validConfig(config) || output == nil {
		return failure(api.CodeInvalid, "fixed enrollment entry requires a configuration and output")
	}
	options, err := parseEnrollmentOptions(args)
	if err != nil {
		return err
	}
	result, err := runEnrollment(ctx, config, options)
	if err != nil {
		return err
	}
	if err := writeEnrollmentOutput(output, result); err != nil {
		return failure(api.CodeUnavailable, "administrator enrollment response could not be retained")
	}
	return nil
}

func writeEnrollmentOutput(output io.Writer, result any) error {
	if receipt, ok := result.(api.EnrollmentReceipt); ok && receipt.SimulatedPresence {
		return json.NewEncoder(output).Encode(struct {
			Receipt       api.EnrollmentReceipt `json:"receipt"`
			Presence      string                `json:"presence"`
			HumanApproval string                `json:"human_approval"`
		}{Receipt: receipt, Presence: "simulated", HumanApproval: "not_proven"})
	}
	return json.NewEncoder(output).Encode(result)
}

// Keep all public transport timeouts bounded independently of ceremony expiry.
const enrollmentCallTimeout = helperCallTimeout

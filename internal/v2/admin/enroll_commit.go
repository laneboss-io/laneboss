package admin

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

// This is the service store's existing private port. It is deliberately not
// another public RPC, generic transaction seed or administrator database writer.
type HumanEnrollmentInstaller interface {
	InstallHumanEnrollment(context.Context, api.Scope, api.InternalIntent, api.EnrollmentInstall, api.ObjectWrite) (api.Commit, error)
}

// ValidatedRegistration can only be made by the wrapper after calling the
// installed identity producer and checking its actual stored create challenge.
// No exported member lets an RPC or service label manufacture that handoff.
type ValidatedRegistration struct {
	channel *enrollmentChannel
	request api.EnrollmentValidationRequest
	install api.EnrollmentInstall
}

func copyEnrollmentInstall(install api.EnrollmentInstall) api.EnrollmentInstall {
	install.Enrollment.Credentials = append([]api.HumanCredential(nil), install.Enrollment.Credentials...)
	for index := range install.Enrollment.Credentials {
		c := &install.Enrollment.Credentials[index]
		c.RawCredentialID = append([]byte(nil), c.RawCredentialID...)
		c.PublicKeyDER = append([]byte(nil), c.PublicKeyDER...)
	}
	return install
}

func (r *ValidatedRegistration) Install() api.EnrollmentInstall {
	if r == nil {
		return api.EnrollmentInstall{}
	}
	return copyEnrollmentInstall(r.install)
}

func (v *InitialEnrollmentValidator) ValidateInitialRegistration(ctx context.Context, request api.EnrollmentValidationRequest) (*ValidatedRegistration, error) {
	install, err := v.ValidateEnrollment(ctx, request)
	if err != nil {
		return nil, err
	}
	channel, ok := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	if !ok || channel == nil {
		return nil, failure(api.CodeForbidden, "registration validation lost its native channel")
	}
	registration := channel.validated
	if registration == nil || registration.channel != channel || !reflect.DeepEqual(registration.install, install) {
		return nil, failure(api.CodeIntegrity, "registration interface omitted its validated handoff")
	}
	return registration, nil
}

// CheckInitialEnrollmentInstall lets the store recheck the genuine channel and
// identity handoff under its writer lock, using the existing InstallHumanEnrollment
// signature. It calls no service/store API and sends no transport message.
// The store must separately compare/consume its challenge and empty inventory.
func CheckInitialEnrollmentInstall(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, install api.EnrollmentInstall, evidence api.ObjectWrite) error {
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		return err
	}
	channel := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	registration := channel.validated
	if registration == nil || registration.channel != channel || !reflect.DeepEqual(install, registration.install) {
		return failure(api.CodeForbidden, "store enrollment install lacks the actual identity validation")
	}
	ref := registration.install.CeremonyEvidence
	if evidence.ObjectKey != ref.ID || evidence.Class != ref.Class || evidence.SHA256 != ref.SHA256 ||
		int64(len(evidence.Bytes)) != ref.Bytes || digestBytes(evidence.Bytes) != ref.SHA256 {
		return failure(api.CodeIntegrity, "store enrollment evidence differs from its identity validation")
	}
	return matchRegistrationEvidence(evidence.Bytes, registration.request)
}

// CommitInitialEnrollment consumes only a validated in-memory handoff from the
// same live administrator channel. The service supplies its original retained
// internal cause and exact identity-produced evidence object. The store rechecks
// the complete absent baseline and consumes the challenge under its writer lock.
// Completed-ceremony replay belongs before validation in the service handler;
// neither a new principal nor a new ceremony can reopen this exception.
func (s *Service) CommitInitialEnrollment(ctx context.Context, registration *ValidatedRegistration, scope api.Scope,
	intent api.InternalIntent, evidence api.ObjectWrite) (api.EnrollmentReceipt, error) {
	var receipt api.EnrollmentReceipt
	if registration == nil || registration.channel == nil || ctx.Value(enrollmentChannelKey{}) != registration.channel {
		return receipt, failure(api.CodeForbidden, "initial enrollment lacks its identity-validated native handoff")
	}
	endpoint := registration.channel.endpoint
	if err := validateEnrollmentEndpoint(endpoint, s.binding); err != nil {
		return receipt, err
	}
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		return receipt, err
	}
	if err := CheckInitialEnrollmentInstall(ctx, endpoint, registration.install, evidence); err != nil {
		return receipt, err
	}
	if nilEnrollmentPort(s.deps.Store) {
		return receipt, api.NotImplemented("lb-v2-service", "store.InstallHumanEnrollment")
	}
	if scope.Config != endpoint.Config || scope.Actor.Kind != "service" || !validActor(scope.Actor) || scope.Source != "service" ||
		scope.Connection != nil || scope.Frame != nil || scope.LaunchID != "" ||
		intent.Kind != api.InternalAdminEnroll || intent.Config != scope.Config || intent.Actor != scope.Actor || intent.RequestedBy != scope.Actor ||
		!validID(intent.ID) || !validID(intent.CauseOperationID) || !validID(intent.CauseRequestID) || intent.Target != (api.LifeRef{}) || intent.EffectID != "" {
		return receipt, failure(api.CodeForbidden, "initial enrollment lacks its bound private service cause")
	}
	install := registration.install
	challenge, err := s.deps.Store.EnrollmentChallenge(ctx, endpoint.Config, registration.request.ChallengeID)
	if err != nil {
		return receipt, err
	}
	if err := api.ValidateInitialEnrollment(challenge, registration.request, install, time.Now()); err != nil {
		return receipt, err
	}
	ref := install.CeremonyEvidence
	if evidence.ObjectKey != ref.ID || evidence.Class != "artifact" || ref.Class != "artifact" || !validID(ref.ID) ||
		int64(len(evidence.Bytes)) != ref.Bytes || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes || evidence.SHA256 != ref.SHA256 || digestBytes(evidence.Bytes) != ref.SHA256 ||
		evidence.Origin != "service" || evidence.ACL.Config != scope.Config || evidence.ACL.Owner != scope.Actor || evidence.ACL.Audience != "owner" ||
		evidence.ACL.Generation != 1 || evidence.ACL.LifeID != "" || len(evidence.ACL.Participants) != 0 {
		return receipt, failure(api.CodeIntegrity, "registration evidence differs from the exact private validated object")
	}
	if err := matchRegistrationEvidence(evidence.Bytes, registration.request); err != nil {
		return receipt, err
	}
	installer, ok := s.deps.Store.(HumanEnrollmentInstaller)
	if !ok {
		return receipt, api.NotImplemented("lb-v2-service", "store.InstallHumanEnrollment")
	}
	if err := requireEmptyEnrollment(ctx, s.deps.Store, endpoint.Config); err != nil {
		return receipt, err
	}
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		return receipt, err
	}
	commit, err := installer.InstallHumanEnrollment(ctx, scope, intent, copyEnrollmentInstall(install), evidence)
	if err != nil {
		return receipt, err
	}
	// Do not invent an enrolled event, event ID or sequence from the intent.
	// Read the actual blob.committed event in this operation's committed range.
	if commit.Operation.ID != intent.CauseOperationID || commit.Operation.Status != "succeeded" || commit.Operation.Error != nil ||
		commit.FirstSeq == 0 || commit.LastSeq < commit.FirstSeq || commit.LastSeq-commit.FirstSeq > 200 {
		return receipt, failure(api.CodeIntegrity, "enrollment store returned no successful bounded operation commit")
	}
	page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{Since: commit.FirstSeq - 1})
	if err != nil {
		return receipt, err
	}
	var committed *api.Event
	for index := range page.Events {
		event := &page.Events[index]
		if event.Seq < commit.FirstSeq || event.Seq > commit.LastSeq || event.Kind != "blob.committed" || event.OperationID != commit.Operation.ID {
			continue
		}
		var blob api.BlobRef
		if err := api.DecodeObject(event.Payload, &blob); err != nil {
			return receipt, err
		}
		if blob == ref {
			if committed != nil {
				return receipt, failure(api.CodeIntegrity, "enrollment commit contains ambiguous evidence events")
			}
			committed = event
		}
	}
	if committed == nil {
		return receipt, failure(api.CodeIntegrity, "enrollment commit evidence event was not read back")
	}
	if committed.Actor != scope.Actor || committed.RequestedBy != intent.RequestedBy || committed.RequestID != intent.CauseRequestID {
		return receipt, failure(api.CodeIntegrity, "enrollment commit event changed its original cause")
	}
	receipt = api.EnrollmentReceipt{Config: endpoint.Config, PrincipalID: install.Enrollment.PrincipalID, Generation: install.Enrollment.Generation,
		CeremonyID: install.CeremonyID, ChallengeID: install.ChallengeID, Evidence: ref, OperationID: commit.Operation.ID,
		EventID: committed.ID, CommittedSeq: committed.Seq, SimulatedPresence: install.Enrollment.Credentials[0].SimulatedPresence}
	if err := verifyEnrollmentReceipt(ctx, s.deps.Store, scope, endpoint, registration.request, receipt); err != nil {
		return api.EnrollmentReceipt{}, err
	}
	registration.channel.receipt = &receipt
	return receipt, nil
}

// VerifyEnrollmentReplay checks the same retained receipt for a lost reply.
// The caller supplies its real bound store scope, never a new service label.
func (s *Service) VerifyEnrollmentReplay(ctx context.Context, scope api.Scope, endpoint api.AdminEnrollmentEndpoint, request api.EnrollmentValidationRequest, receipt api.EnrollmentReceipt) error {
	if err := validateEnrollmentEndpoint(endpoint, s.binding); err != nil {
		return err
	}
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		return err
	}
	if err := verifyEnrollmentReceipt(ctx, s.deps.Store, scope, endpoint, request, receipt); err != nil {
		return err
	}
	channel := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	copy := receipt
	channel.receipt = &copy
	return nil
}

func verifyEnrollmentReceipt(ctx context.Context, store api.StateStore, scope api.Scope, endpoint api.AdminEnrollmentEndpoint, request api.EnrollmentValidationRequest, receipt api.EnrollmentReceipt) (resultErr error) {
	if nilEnrollmentPort(store) {
		return api.NotImplemented("lb-v2-service", "enrollment receipt read-back")
	}
	if scope.Config != endpoint.Config || scope.Actor.Kind != "service" || !validActor(scope.Actor) || scope.Source != "service" || scope.Connection != nil || scope.Frame != nil {
		return failure(api.CodeForbidden, "enrollment read-back requires the original bound service scope")
	}
	if receipt.Config != endpoint.Config || receipt.Config != request.Ceremony.Config || receipt.CeremonyID != request.Ceremony.CeremonyID ||
		receipt.ChallengeID != request.ChallengeID || receipt.PrincipalID != request.Ceremony.PrincipalID || receipt.Generation != 1 ||
		!validID(receipt.OperationID) || !validID(receipt.EventID) || receipt.CommittedSeq == 0 ||
		!validID(receipt.Evidence.ID) || receipt.Evidence.Class != "artifact" || !validDigest(receipt.Evidence.SHA256) || receipt.Evidence.Bytes < 1 || receipt.Evidence.Bytes > api.MaxFrameBytes {
		return failure(api.CodeIntegrity, "enrollment receipt differs from its initial ceremony")
	}
	enrollments, err := store.HumanEnrollments(ctx, endpoint.Config)
	if err != nil {
		return err
	}
	if err := api.ValidateHumanEnrollments(endpoint.Config, enrollments); err != nil {
		return err
	}
	if len(enrollments) != 1 || enrollments[0].PrincipalID != receipt.PrincipalID || enrollments[0].Generation != receipt.Generation ||
		enrollments[0].Origin != endpoint.Origin || enrollments[0].RPID != endpoint.RPID || len(enrollments[0].Credentials) != 1 {
		return failure(api.CodeIntegrity, "enrollment receipt has no configuration-wide committed baseline")
	}
	credential := enrollments[0].Credentials[0]
	if credential.RegistrationEvidence != receipt.Evidence || credential.AttestationMarker != request.AttestationMarker || credential.SimulatedPresence != receipt.SimulatedPresence {
		return failure(api.CodeIntegrity, "enrollment receipt lost verified registration presence or evidence")
	}
	operation, err := store.Operation(ctx, scope, receipt.OperationID)
	if err != nil {
		return err
	}
	if operation.ID != receipt.OperationID || operation.Status != "succeeded" || operation.Error != nil || operation.FirstSeq == 0 ||
		receipt.CommittedSeq < operation.FirstSeq || receipt.CommittedSeq > operation.LastSeq || operation.SimulatedPresence != receipt.SimulatedPresence {
		return failure(api.CodeIntegrity, "enrollment receipt lacks its actual successful operation")
	}
	page, err := store.Events(ctx, scope, api.EventTailRequest{Since: receipt.CommittedSeq - 1})
	if err != nil {
		return err
	}
	matched := 0
	for _, event := range page.Events {
		if event.Seq != receipt.CommittedSeq {
			continue
		}
		var blob api.BlobRef
		if err := api.DecodeObject(event.Payload, &blob); err != nil {
			return err
		}
		if event.ID != receipt.EventID || event.Kind != "blob.committed" || event.Config != endpoint.Config || event.OperationID != receipt.OperationID ||
			event.Origin != "service" || event.Actor != scope.Actor || event.RequestID == "" || blob != receipt.Evidence {
			return failure(api.CodeIntegrity, "enrollment receipt references a foreign or synthetic event")
		}
		matched++
	}
	if matched != 1 {
		return failure(api.CodeIntegrity, "enrollment receipt commit event was not read back")
	}
	scope, release, err := objectread.Bind(ctx, store, scope)
	if err != nil {
		return err
	}
	defer release(&resultErr)
	metadata, err := store.ObjectMetadata(ctx, scope, receipt.Evidence.ID)
	if err != nil {
		return err
	}
	if metadata.Ref != receipt.Evidence || metadata.Origin != "service" || metadata.SourceOperationID != receipt.OperationID ||
		metadata.ACL.Config != endpoint.Config || metadata.ACL.Owner != scope.Actor || metadata.ACL.Audience != "owner" || metadata.ACL.LifeID != "" || len(metadata.ACL.Participants) != 0 {
		return failure(api.CodeIntegrity, "enrollment receipt evidence is not the exact private commit object")
	}
	var raw []byte
	for int64(len(raw)) < receipt.Evidence.Bytes {
		chunk, err := store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: receipt.Evidence.ID, Offset: int64(len(raw)), Limit: int(min(int64(api.MaxChunkBytes), receipt.Evidence.Bytes-int64(len(raw))))})
		if err != nil {
			return err
		}
		if chunk.ObjectID != receipt.Evidence.ID || chunk.Offset != int64(len(raw)) || len(chunk.Data) == 0 ||
			int64(len(chunk.Data)) > receipt.Evidence.Bytes-int64(len(raw)) || digestBytes(chunk.Data) != chunk.SHA256 {
			return failure(api.CodeIntegrity, "enrollment evidence byte read-back changed")
		}
		raw = append(raw, chunk.Data...)
	}
	if digestBytes(raw) != receipt.Evidence.SHA256 {
		return failure(api.CodeIntegrity, "enrollment evidence digest was not read back")
	}
	if err := matchRegistrationEvidence(raw, request); err != nil {
		return err
	}
	challenge, err := store.EnrollmentChallenge(ctx, endpoint.Config, receipt.ChallengeID)
	if err != nil {
		return err
	}
	if challenge.ID != receipt.ChallengeID || challenge.Ceremony != request.Ceremony || !challenge.Consumed ||
		challenge.Origin != endpoint.Origin || challenge.RPID != endpoint.RPID || challenge.InstallationGeneration != endpoint.InstallationGeneration {
		return failure(api.CodeIntegrity, "enrollment receipt lacks its atomically consumed create challenge")
	}
	// Preserve and hash the producer's exact bytes. Comparing the parsed private
	// request preserves ClientDataJSON/AttestationObject byte-for-byte, including
	// on a lost-reply replay, without re-encoding either signed payload.
	return nil
}

func matchRegistrationEvidence(raw []byte, request api.EnrollmentValidationRequest) error {
	var retained api.EnrollmentValidationRequest
	if err := api.DecodeObject(json.RawMessage(raw), &retained); err != nil {
		return err
	}
	if !reflect.DeepEqual(retained, request) {
		return failure(api.CodeIdempotencyConflict, "registration retry changed its retained exact attestation request")
	}
	return nil
}

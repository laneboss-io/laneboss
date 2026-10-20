package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// The initial human established its own baseline through the native ceremony.
// Its required creator and time fields come from that retained registration;
// constructing this revocation record creates no invitation or approval right.
func baselineHumanAdmission(ctx context.Context, db queryer, enrollment api.HumanEnrollment) (api.HumanAdmission, error) {
	var empty api.HumanAdmission
	var count int
	query := "SELECT data FROM projections WHERE kind='enrollment_receipt' AND json_extract(data,'$.PrincipalID')=?"
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM ("+query+")", string(enrollment.PrincipalID)).Scan(&count); err != nil {
		return empty, err
	}
	if count != 1 {
		return empty, fault(api.CodeIntegrity, "baseline revocation requires one retained initial enrollment receipt")
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, query, string(enrollment.PrincipalID)).Scan(&raw); err != nil {
		return empty, err
	}
	var receipt api.EnrollmentReceipt
	if err := decodeStored(raw, &receipt); err != nil {
		return empty, err
	}
	if receipt.Config != enrollment.Config || receipt.PrincipalID != enrollment.PrincipalID || receipt.Generation != 1 {
		return empty, fault(api.CodeIntegrity, "baseline revocation receipt differs from its enrolled principal")
	}
	var challenge api.EnrollmentChallenge
	if err := storedProjection(ctx, db, "enrollment_challenge", receipt.ChallengeID, &challenge); err != nil {
		return empty, err
	}
	if challenge.ID != receipt.ChallengeID || challenge.Ceremony.CeremonyID != receipt.CeremonyID ||
		challenge.Ceremony.Config != enrollment.Config || challenge.Ceremony.PrincipalID != enrollment.PrincipalID ||
		challenge.Ceremony.ExpectedGeneration != 0 || challenge.InviteID != "" || !challenge.Consumed {
		return empty, fault(api.CodeIntegrity, "baseline revocation lost its consumed initial ceremony")
	}
	event, err := authorityEvent(ctx, db, receipt.OperationID, "blob.committed", receipt.Evidence.ID)
	if err != nil {
		return empty, err
	}
	var evidence api.BlobRef
	if event.ID != receipt.EventID || event.Seq != receipt.CommittedSeq || event.Config != enrollment.Config ||
		event.Origin != "service" || wire.Decode(event.Payload, &evidence) != nil || evidence != receipt.Evidence {
		return empty, fault(api.CodeIntegrity, "baseline revocation lost its actual registration event")
	}
	return api.HumanAdmission{ID: enrollment.PrincipalID, Config: enrollment.Config,
		InviterID: receipt.PrincipalID, PrincipalID: enrollment.PrincipalID, Role: "human",
		CreatedAt: event.RecordedAt, ExpiresAt: challenge.ExpiresAt}, nil
}

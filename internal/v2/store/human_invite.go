package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type humanInvite struct {
	Admission api.HumanAdmission
	TokenHash api.Digest
}

type humanRights struct{ CanApprove bool }

func (s *Service) activeHuman(ctx context.Context, db queryer, scope api.Scope) error {
	if scope.Actor.Kind != "human" || scope.Actor.LifeID != "" || scope.LaunchID != "" || scope.Actor.Level != 0 || scope.Actor.Role != "" {
		return fault(api.CodeForbidden, "enrollment management requires an enrolled human, never a lane or worker")
	}
	if err := s.scope(ctx, db, scope); err != nil {
		return err
	}
	var e api.HumanEnrollment
	if err := storedProjection(ctx, db, "enrollment", scope.Actor.ID, &e); err != nil {
		return err
	}
	if e.Config != scope.Config || e.PrincipalID != scope.Actor.ID || validateEnrollment(e) != nil {
		return fault(api.CodeUnauthenticated, "enrollment management has no current human baseline")
	}
	for _, c := range e.Credentials {
		if !c.Revoked {
			return nil
		}
	}
	return fault(api.CodeUnauthenticated, "enrollment management credential is revoked")
}

func humanApproveRight(ctx context.Context, db queryer, principal api.ID) (bool, error) {
	var right humanRights
	err := storedProjection(ctx, db, "human_rights", principal, &right)
	if err == nil {
		return right.CanApprove, nil
	}
	if !absent(err) {
		return false, err
	}
	// Compatibility with a previously installed absent-baseline ceremony. A
	// later pending receipt is never a baseline and cannot create this right.
	var count int
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM projections r
 WHERE r.kind='enrollment_receipt' AND json_extract(r.data,'$.PrincipalID')=?
 AND NOT EXISTS (SELECT 1 FROM projections c WHERE c.kind='invite_challenge'
 AND c.id=json_extract(r.data,'$.ChallengeID'))`, string(principal)).Scan(&count)
	return count == 1, err
}

func (s *Service) PrepareHumanChange(ctx context.Context, scope api.Scope, request api.HumanAccessRequest) (api.HumanAdmission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result api.HumanAdmission
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.activeHuman(ctx, s.db, scope); err != nil {
		return result, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return result, err
	}
	if err := api.ValidateHumanAccess(request); err != nil {
		return result, err
	}
	var framed api.HumanAccessRequest
	if scope.Request.Method != "human.enroll" || wire.Decode(scope.Request.Params, &framed) != nil || framed != request {
		return result, fault(api.CodeForbidden, "enrollment action differs from the authenticated human frame")
	}
	if request.Action == "invite" {
		id, err := wire.NewID()
		if err != nil {
			return result, err
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return result, err
		}
		now := s.deps.Clock.Now()
		result = api.HumanAdmission{ID: id, Config: scope.Config, InviterID: scope.Actor.ID,
			Role: request.Role, CanApprove: request.CanApprove, State: "invited", Generation: 1,
			CreatedAt: api.Timestamp(now.UTC().Format(timeFormat)), ExpiresAt: api.Timestamp(now.Add(15 * time.Minute).UTC().Format(timeFormat)),
			Token: string(id) + "." + base64.RawURLEncoding.EncodeToString(raw)}
		if _, err := s.humanChange(ctx, s.db, scope, request, result); err != nil {
			return api.HumanAdmission{}, err
		}
		return result, nil
	}
	return s.humanChange(ctx, s.db, scope, request, result)
}

// This derives the permitted transition twice: at preflight and under the
// writer lock after consuming the actual operation-bound human proof.
func (s *Service) humanChange(ctx context.Context, db readDatabase, scope api.Scope, r api.HumanAccessRequest, proposed api.HumanAdmission) (api.HumanAdmission, error) {
	right, err := humanApproveRight(ctx, db, scope.Actor.ID)
	if err != nil {
		return api.HumanAdmission{}, err
	}
	switch r.Action {
	case "invite":
		if r.CanApprove && !right {
			return api.HumanAdmission{}, fault(api.CodeForbidden, "only an approving human can delegate the approve right")
		}
		created, a := time.Parse(timeFormat, string(proposed.CreatedAt))
		expires, b := time.Parse(timeFormat, string(proposed.ExpiresAt))
		id, secret, ok := strings.Cut(proposed.Token, ".")
		decoded, c := base64.RawURLEncoding.DecodeString(secret)
		if !ok || c != nil || len(decoded) != 32 || id != string(proposed.ID) || !wire.ValidID(id) || a != nil || b != nil ||
			created.After(s.deps.Clock.Now()) || !s.deps.Clock.Now().Before(expires) || expires.Sub(created) != 15*time.Minute ||
			proposed.Config != scope.Config || proposed.InviterID != scope.Actor.ID || proposed.Role != "human" || proposed.CanApprove != r.CanApprove ||
			proposed.State != "invited" || proposed.Generation != 1 || proposed.PrincipalID != "" || proposed.Fingerprint != "" {
			return api.HumanAdmission{}, fault(api.CodeForbidden, "invite differs from its human role, token or fifteen-minute lifetime")
		}
		var prior humanInvite
		if err := storedProjection(ctx, db, "human_invite", proposed.ID, &prior); !absent(err) {
			if err != nil {
				return api.HumanAdmission{}, err
			}
			return api.HumanAdmission{}, fault(api.CodeConflict, "invitation already exists")
		}
		return proposed, nil
	case "approve", "reject":
		var pending api.HumanAdmission
		if err := storedProjection(ctx, db, "human_admission", r.InviteID, &pending); err != nil {
			return pending, err
		}
		if pending.Config != scope.Config || pending.State != "pending" || pending.Generation != r.ExpectedGeneration ||
			pending.Fingerprint != r.Fingerprint || pending.Role != "human" || pending.PrincipalID == scope.Actor.ID {
			return api.HumanAdmission{}, fault(api.CodeConflict, "enrollment decision differs from the pending key fingerprint or generation")
		}
		if pending.InviterID != scope.Actor.ID && !right {
			return api.HumanAdmission{}, fault(api.CodeForbidden, "human cannot decide another inviter's registration without the approve right")
		}
		pending.Generation++
		pending.State = "rejected"
		if r.Action == "approve" {
			pending.State = "active"
			pending.EnrollmentGeneration = 1
		}
		return pending, nil
	case "revoke":
		var e api.HumanEnrollment
		if err := storedProjection(ctx, db, "enrollment", r.PrincipalID, &e); err != nil {
			return api.HumanAdmission{}, err
		}
		if e.Config != scope.Config || e.Generation != r.ExpectedGeneration {
			return api.HumanAdmission{}, fault(api.CodeConflict, "revocation enrollment generation changed")
		}
		var admission api.HumanAdmission
		var raw []byte
		err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='human_admission' AND json_extract(data,'$.principal_id')=?", string(r.PrincipalID)).Scan(&raw)
		if err != nil && err != sql.ErrNoRows {
			return api.HumanAdmission{}, err
		}
		if err == nil {
			if err := decodeStored(raw, &admission); err != nil {
				return api.HumanAdmission{}, err
			}
		}
		if !right && (err != nil || admission.InviterID != scope.Actor.ID) {
			return api.HumanAdmission{}, fault(api.CodeForbidden, "revocation requires the inviter or a human holding the approve right")
		}
		if err := s.keepHumanApprover(ctx, db, e.PrincipalID); err != nil {
			return api.HumanAdmission{}, err
		}
		if admission.ID == "" {
			admission, err = baselineHumanAdmission(ctx, db, e)
			if err != nil {
				return api.HumanAdmission{}, err
			}
		}
		admission.State = "revoked"
		admission.CanApprove = false
		admission.Generation++
		admission.EnrollmentGeneration = e.Generation + 1
		return admission, nil
	}
	return api.HumanAdmission{}, wire.Invalid("unknown human enrollment action")
}

func (s *Service) humanChanges(ctx context.Context, tx *sql.Tx, input api.Transaction) error {
	if input.Scope.Request.Method != "human.enroll" || len(input.Writes.HumanChanges) != 1 || len(input.Guards) != 1 || input.Guards[0].Proof == nil ||
		len(input.Events) != 2 || input.Events[1].Kind != "human.proof.used" || input.Reply == nil || input.Reply.Error != nil {
		return fault(api.CodeForbidden, "enrollment transition requires its exact human proof, event and reply")
	}
	if err := s.activeHuman(ctx, tx, input.Scope); err != nil {
		return err
	}
	var request api.HumanAccessRequest
	if err := wire.Decode(input.Scope.Request.Params, &request); err != nil {
		return err
	}
	if err := api.ValidateHumanAccess(request); err != nil {
		return err
	}
	proposed := input.Writes.HumanChanges[0]
	expected, err := s.humanChange(ctx, tx, input.Scope, request, proposed)
	if err != nil {
		return err
	}
	var reply, public api.HumanAdmission
	if err := wire.Decode(input.Reply.Result, &reply); err != nil {
		return err
	}
	if !sameValue(reply, expected) || !sameValue(proposed, expected) {
		return fault(api.CodeForbidden, "enrollment reply or projection differs from its exact transition")
	}
	expected.Token = ""
	event := input.Events[0]
	if event.Kind != "human.enrollment" || event.Actor != input.Scope.Actor || event.RequestedBy != input.Scope.Actor || event.Origin != "service" || event.LifeID != "" ||
		wire.Decode(event.Payload, &public) != nil || !sameValue(public, expected) {
		return fault(api.CodeForbidden, "enrollment journal differs from its exact transition or exposes an invite token")
	}
	switch request.Action {
	case "invite":
		return put(ctx, tx, "human_invite", proposed.ID, 1, humanInvite{Admission: expected, TokenHash: api.Digest(hash([]byte(proposed.Token)))})
	case "approve":
		var install api.EnrollmentInstall
		if err := storedProjection(ctx, tx, "pending_human", expected.ID, &install); err != nil {
			return err
		}
		if install.Enrollment.PrincipalID != expected.PrincipalID || len(install.Enrollment.Credentials) != 1 || api.Digest(hash(install.Enrollment.Credentials[0].PublicKeyDER)) != expected.Fingerprint {
			return fault(api.CodeIntegrity, "approval lost its exact attested public key")
		}
		// Activation uses the current build's credential policy even when a
		// pending registration was retained by a prior installation/build.
		if err := validateEnrollment(install.Enrollment); err != nil {
			return err
		}
		credential := install.Enrollment.Credentials[0]
		if install.Enrollment.Config != s.deps.Config || install.Enrollment.Generation != 1 || install.ExpectedGeneration != 0 ||
			credential.Generation != 1 || credential.Counter != 0 || credential.Revoked {
			return fault(api.CodeForbidden, "approval requires the exact fresh pending human baseline")
		}
		if err := s.uniqueHuman(ctx, tx, install.Enrollment, expected.ID); err != nil {
			return err
		}
		if err := s.compare(ctx, tx, []api.Compare{{Kind: "enrollment", ID: expected.PrincipalID, Generation: 0}}); err != nil {
			return err
		}
		if err := put(ctx, tx, "enrollment", expected.PrincipalID, 1, install.Enrollment); err != nil {
			return err
		}
		if err := put(ctx, tx, "human_rights", expected.PrincipalID, 1, humanRights{expected.CanApprove}); err != nil {
			return err
		}
	case "revoke":
		var e api.HumanEnrollment
		if err := storedProjection(ctx, tx, "enrollment", expected.PrincipalID, &e); err != nil {
			return err
		}
		for i := range e.Credentials {
			e.Credentials[i].Revoked = true
			e.Credentials[i].Generation++
		}
		e.Generation++
		if err := put(ctx, tx, "enrollment", e.PrincipalID, e.Generation, e); err != nil {
			return err
		}
		if err := put(ctx, tx, "human_rights", e.PrincipalID, e.Generation, humanRights{}); err != nil {
			return err
		}
	}
	return put(ctx, tx, "human_admission", expected.ID, expected.Generation, expected)
}

func (s *Service) PendingHumans(ctx context.Context, scope api.Scope) (api.HumanPendingPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := api.HumanPendingPage{Config: scope.Config, Registrations: []api.HumanAdmission{}}
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.activeHuman(ctx, s.db, scope); err != nil {
		return result, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return result, err
	}
	right, err := humanApproveRight(ctx, s.db, scope.Actor.ID)
	if err != nil {
		return result, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return result, err
	}
	rows, err := db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='human_admission' ORDER BY id")
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var item api.HumanAdmission
		if err := rows.Scan(&raw); err != nil {
			return result, err
		}
		if err := decodeStored(raw, &item); err != nil {
			return result, err
		}
		if item.Config != scope.Config || item.Token != "" {
			return result, fault(api.CodeIntegrity, "pending enrollment lost its private configuration boundary")
		}
		if right || item.InviterID == scope.Actor.ID {
			result.Registrations = append(result.Registrations, item)
		}
	}
	return result, rows.Err()
}

// Reject any credential already associated with an active, revoked or pending
// principal. Approval cannot make native principal resolution ambiguous.
func (s *Service) uniqueHuman(ctx context.Context, db readDatabase, enrollment api.HumanEnrollment, pendingID api.ID) error {
	rows, err := db.QueryContext(ctx, "SELECT kind,id,data FROM projections WHERE kind IN ('enrollment','pending_human')")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var id api.ID
		var raw []byte
		var other api.HumanEnrollment
		if err := rows.Scan(&kind, &id, &raw); err != nil {
			return err
		}
		if kind == "enrollment" {
			if err := decodeStored(raw, &other); err != nil {
				return err
			}
		} else {
			var install api.EnrollmentInstall
			if err := decodeStored(raw, &install); err != nil {
				return err
			}
			other = install.Enrollment
			if id == pendingID && sameValue(other, enrollment) {
				continue
			}
		}
		if other.PrincipalID == enrollment.PrincipalID {
			return fault(api.CodeConflict, "human principal is already registered")
		}
		for _, a := range other.Credentials {
			for _, b := range enrollment.Credentials {
				if a.ID == b.ID || string(a.RawCredentialID) == string(b.RawCredentialID) || string(a.PublicKeyDER) == string(b.PublicKeyDER) {
					return fault(api.CodeConflict, "human credential is already associated with another registration")
				}
			}
		}
	}
	return rows.Err()
}

var _ api.HumanAdmissionStore = (*Service)(nil)

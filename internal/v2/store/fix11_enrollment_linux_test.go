//go:build linux

package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"testing"
	"time"
)

func TestEnrollmentCeremonyFences(t *testing.T) {
	for _, fault := range []string{"foreign_config", "changed_principal", "later_baseline", "expired_nonce", "consumed_nonce"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := testStore(t)
			input := validatedEnrollmentInput(t, s)
			install := input.Writes.Enrollments[0]
			ctx := context.Background()
			challenge, err := s.EnrollmentChallenge(ctx, s.deps.Config, install.ChallengeID)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "foreign_config":
				_, err = s.EnrollmentChallenge(ctx, "other-config", challenge.ID)
			case "changed_principal":
				request := challenge.Ceremony
				request.PrincipalID = testID(t)
				_, err = s.ReserveEnrollment(ctx, request)
			case "later_baseline":
				request := challenge.Ceremony
				request.CeremonyID = testID(t)
				request.ExpectedGeneration = 1
				_, err = s.ReserveEnrollment(ctx, request)
			case "expired_nonce":
				challenge.ExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
				fixtureProjection(t, s, "enrollment_challenge", challenge.ID, 1, challenge)
				_, err = s.EnrollmentChallenge(ctx, s.deps.Config, challenge.ID)
			case "consumed_nonce":
				if _, commitErr := commitEnrollmentFixture(ctx, s, input); commitErr != nil {
					t.Fatal(commitErr)
				}
				_, err = s.EnrollmentChallenge(ctx, s.deps.Config, challenge.ID)
			}
			if err == nil {
				t.Fatal("enrollment ceremony accepted " + fault)
			}
		})
	}
}

func TestEnrollmentValidationFences(t *testing.T) {
	for _, fault := range []string{"unknown_validation", "changed_ceremony", "changed_principal", "changed_challenge", "changed_exact_bytes", "missing_native_channel", "direct_internal_commit", "commit_channel_recheck"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := testStore(t)
			input := validatedEnrollmentInput(t, s)
			ctx := context.Background()
			install := &input.Writes.Enrollments[0]
			switch fault {
			case "unknown_validation":
				install.ValidationID = testID(t)
			case "changed_ceremony":
				install.CeremonyID = testID(t)
			case "changed_principal":
				install.Enrollment.PrincipalID = testID(t)
			case "changed_challenge":
				install.ChallengeID = testID(t)
			case "changed_exact_bytes":
				object := &input.Writes.Objects[0]
				object.Bytes = append(object.Bytes, ' ')
				object.SHA256 = testDigest(object.Bytes)
				install.CeremonyEvidence.SHA256, install.CeremonyEvidence.Bytes = object.SHA256, int64(len(object.Bytes))
				install.Enrollment.Credentials[0].RegistrationEvidence = install.CeremonyEvidence
				input.Events[0].Payload = enrollmentJSON(t, install.CeremonyEvidence)
			}
			var err error
			if fault == "missing_native_channel" {
				_, err = s.InstallHumanEnrollment(ctx, input.Scope, *input.Internal, *install, input.Writes.Objects[0])
			} else if fault == "commit_channel_recheck" {
				ctx = enrollmentFixtureContext(ctx, s, input)
				capability := ctx.Value(enrollmentCommitKey{}).(enrollmentCommitAuthority)
				capability.NativeScope.Connection = &scopeConnection{}
				ctx = context.WithValue(ctx, enrollmentCommitKey{}, capability)
				_, err = s.Transact(ctx, input)
			} else if fault == "direct_internal_commit" {
				_, err = s.Transact(ctx, input)
			} else {
				_, err = commitEnrollmentFixture(ctx, s, input)
			}
			if err == nil {
				t.Fatal("administrator install accepted " + fault)
			}
			all, readErr := s.HumanEnrollments(ctx, s.deps.Config)
			if readErr != nil || len(all) != 0 {
				t.Fatal("refused administrator install changed its baseline", readErr)
			}
		})
	}
}

func TestEnrollmentExactBytes(t *testing.T) {
	t.Run("validated_key", func(t *testing.T) {
		s, _ := testStore(t)
		input := validatedEnrollmentInput(t, s)
		install := input.Writes.Enrollments[0]
		other := enrollmentInput(t).Writes.Enrollments[0].Enrollment.Credentials[0].PublicKeyDER
		install.Enrollment.Credentials = append([]api.HumanCredential{}, install.Enrollment.Credentials...)
		install.Enrollment.Credentials[0].PublicKeyDER = append([]byte{}, other...)
		if _, err := s.checkedEnrollment(context.Background(), s.db, install, input.Writes.Objects[0].Bytes); err == nil {
			t.Fatal("enrollment validation accepted a different validated key")
		}
	})
	t.Run("registration_bytes", func(t *testing.T) {
		s, _ := testStore(t)
		input := validatedEnrollmentInput(t, s)
		install := input.Writes.Enrollments[0]
		ctx := context.Background()
		if _, err := s.checkedEnrollment(ctx, s.db, install, input.Writes.Objects[0].Bytes); err != nil {
			t.Fatal("exact enrollment bytes control failed", err)
		}
		changed := append(append([]byte{}, input.Writes.Objects[0].Bytes...), ' ')
		if _, err := s.checkedEnrollment(ctx, s.db, install, changed); err == nil {
			t.Fatal("enrollment validation accepted changed exact registration bytes")
		} else {
			expectCode(t, err, api.CodeForbidden)
		}
	})
}

func TestIdentityKindFence(t *testing.T) {
	for _, kind := range []string{"worker", "missing_kind"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := testStore(t)
			input, binding := identityIntent(t)
			binding.Record.Actor = api.Actor{Kind: "worker", ID: testID(t)}
			binding.Record.Kind = "worker"
			if kind == "missing_kind" {
				binding.Record.Kind = ""
			}
			input.Events[0].Payload = enrollmentJSON(t, binding.Record)
			_, err := s.Transact(context.Background(), input)
			if kind == "worker" {
				if err != nil {
					t.Fatal("worker identity kind component control failed", err)
				}
				return
			}
			if err == nil {
				t.Fatal("live identity accepted missing kind")
			}
		})
	}
}

func TestPreparedIdentityBytes(t *testing.T) {
	for _, problem := range []string{"foreign_commit", "missing_event"} {
		t.Run(problem, func(t *testing.T) {
			s, _ := testStore(t)
			input, binding := identityIntent(t)
			input.Writes.IdentityBindings = []api.LaunchBindingRequest{binding}
			prepared, err := s.prepareIdentityBindings(context.Background(), input)
			if err != nil || prepared.Writes.IdentityBindings[0].Identity.EventID != input.Events[0].ID || prepared.Writes.IdentityBindings[0].Identity.CommittedSeq != 1 {
				t.Fatal("prepared identity event bytes control failed", err)
			}
			if problem == "foreign_commit" {
				input.Writes.IdentityBindings[0].Identity = prepared.Writes.IdentityBindings[0].Identity
				input.Writes.IdentityBindings[0].Identity.EventID = testID(t)
			} else {
				input.Events = nil
			}
			if _, err := s.prepareIdentityBindings(context.Background(), input); err == nil {
				t.Fatal("prepared identity accepted " + problem)
			}
		})
	}
}

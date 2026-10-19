//go:build linux

package admin

import (
	"bytes"
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaunchIssuedProfileControls(t *testing.T) {
	for _, fault := range []string{"valid", "unrequested_profile", "other_driver", "expired", "excluded", "duplicate_main", "duplicate_profile"} {
		t.Run(fault, func(t *testing.T) {
			service, state, _, input := seedLaunchFiles(t)
			ctx := context.Background()
			query := api.LaunchSourceRequest{ReservationID: state.plan.Reservation.ID, GrantSetID: state.grants.ID, Claim: fixtureLaunchClaim(state)}
			before := append([]byte{}, state.objects[state.plan.Reservation.OriginalRequest.ID]...)
			if input.ProfileGrantID == state.grants.Profiles[0].ID {
				t.Fatal("fixture must have distinct template and issued profile IDs")
			}
			first, err := service.ResolveLaunchSources(ctx, query)
			if err != nil || first.Project.GrantID != state.grants.Data[0].ID {
				t.Fatal("real admin source selector refused actual issued members", err)
			}
			switch fault {
			case "unrequested_profile":
				input.ProfileGrantID = "template-not-approved"
				resealLaunchFixture(t, state, input)
			case "other_driver":
				state.grants.Profiles[0].Driver = api.DriverClaudock
			case "expired":
				state.grants.Profiles[0].ExpiresAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
				input.Grants.Profiles[0].ExpiresAt = state.grants.Profiles[0].ExpiresAt
				resealLaunchFixture(t, state, input)
			case "excluded":
				state.policy.ProfileExclusions = []api.ID{state.grants.Profiles[0].ProfileID}
			case "duplicate_main":
				state.grants.Data = append(state.grants.Data, state.grants.Data[0])
			case "duplicate_profile":
				state.grants.Profiles = append(state.grants.Profiles, state.grants.Profiles[0])
			}
			result, err := service.ResolveLaunchSources(ctx, query)
			if fault == "valid" {
				if err != nil || result != first || !bytes.Equal(before, state.objects[state.plan.Reservation.OriginalRequest.ID]) {
					t.Fatal("issued source replay changed its selection or original request", err)
				}
			} else {
				if err == nil || result.ReservationID != "" {
					t.Fatalf("admin accepted %s profile/source authority", fault)
				}
				requireCode(t, err, api.CodeForbidden)
			}
		})
	}
}

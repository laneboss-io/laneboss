package secrets

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func roomIntent(t *testing.T) (*launchCase, *freshRoomJobs, api.ContinuationIntent, api.ProfileGrant) {
	t.Helper()
	c, job := newRoomCase(t)
	return roomIntentForCase(t, c, job)
}

func roomIntentForCase(t *testing.T, c *launchCase, job *freshRoomJobs) (*launchCase, *freshRoomJobs, api.ContinuationIntent, api.ProfileGrant) {
	t.Helper()
	selected := c.store.grants.Profiles[1]
	job.raw(t, "20", roomReset(c.clock.now))
	request := api.ProfileEligibilityRequest{Target: c.target, GrantSetID: c.store.grants.ID, FromGrantID: c.grant.ID, ToGrantID: selected.ID, Driver: c.grant.Driver, Model: c.store.lane.Model, Session: c.store.lane.Session, HistoryID: c.store.lane.Session.HistoryID}
	eligibility, err := c.service.Eligibility(context.Background(), request)
	if err != nil {
		t.Fatal("cannot measure original room eligibility", err)
	}
	room, err := c.service.Room(context.Background(), selected)
	if err != nil {
		t.Fatal("cannot measure original selected room", err)
	}
	return c, job, api.ContinuationIntent{Target: c.target, Eligibility: eligibility, Swap: api.ProfileSwap{Room: room}}, selected
}

func TestContinuationAcquiresFreshRoom(t *testing.T) {
	c, job := newRoomCase(t)
	selected := c.store.grants.Profiles[1]
	profile, err := c.service.loadProfile(context.Background(), selected)
	if err != nil {
		t.Fatal(err)
	}
	profile.Generation++
	initial := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: "service-case", ProfileID: profile.ID, LoginID: profile.LoginID, Generation: profile.Generation, Driver: profile.Driver, Provider: profile.Provider,
		Available: true, CheckedAt: api.Timestamp(c.clock.now.Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(c.clock.now.Add(time.Millisecond).Format(time.RFC3339Nano))}
	profile.Evidence = c.store.putObject(t, "short-room-enrollment", "credential_evidence", initial, "short-room-enrollment-operation")
	if err := c.service.InstallProfile(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	c, job, intent, selected := roomIntentForCase(t, c, job)
	c.clock.now = c.clock.now.Add(2 * time.Millisecond)
	stageContinuation(t, c, selected, intent.Eligibility, intent.Swap.Room)
	slot, err := c.acquire(context.Background(), c.target, selected)
	if err != nil || slot.ProfileID != selected.ProfileID || slot.ProfileGrantID != selected.ID || job.runs != 3 {
		t.Fatal("continuation acquisition fell back to its initial room observation", err)
	}
}

func TestContinuationFreshRoom(t *testing.T) {
	c, job, intent, selected := roomIntent(t)
	fresh, err := c.service.continuationRoom(context.Background(), intent, selected)
	if err != nil || fresh.ID != intent.Eligibility.ID || fresh.Evidence == intent.Eligibility.Evidence || job.runs != 3 {
		t.Fatal("fresh continuation room required equality with an old measurement", err)
	}
	job.raw(t, "100", roomReset(c.clock.now))
	if _, err := c.service.continuationRoom(context.Background(), intent, selected); err == nil {
		t.Fatal("continuation reused old availability after actual exhaustion")
	}
}

func TestContinuationRoomEvidenceStops(t *testing.T) {
	for _, fault := range []string{"old-envelope", "grant", "profile", "participants", "failed-query"} {
		t.Run(fault, func(t *testing.T) {
			c, job, intent, selected := roomIntent(t)
			switch fault {
			case "old-envelope":
				intent.Swap.Room.Evidence = c.profile.Evidence
			case "grant":
				selected.ID = "foreign-profile-grant"
			case "profile":
				selected.ProfileID = c.grant.ProfileID
			case "participants":
				meta := c.store.objects[intent.Swap.Room.Evidence.ID]
				meta.ACL.Participants = []api.ID{"foreign-room-reader"}
				c.store.objects[meta.Ref.ID] = meta
			case "failed-query":
				job.runErr = &api.Error{Code: api.CodeUnavailable, Message: "actual outside fixture command unavailable"}
			}
			if _, err := c.service.continuationRoom(context.Background(), intent, selected); err == nil {
				t.Fatal("continuation accepted changed evidence, delegation or failed provider")
			}
		})
	}
}

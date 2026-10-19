package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func TestCanonicalLoginRefreshWait(t *testing.T) {
	c, selected, first, observation := continuationModeCase(t, "file_login", true)
	var updated map[string]string
	if err := json.Unmarshal(c.material, &updated); err != nil {
		t.Fatal("cannot decode actual original canonical login")
	}
	updated["refresh_token"] = base64.StdEncoding.EncodeToString(syntheticBytes(t, 43))
	data, err := json.Marshal(updated)
	if err != nil {
		t.Fatal("cannot encode actual refreshed canonical login")
	}
	if err := c.service.ReturnSlot(context.Background(), "launch-a", first.ID, api.SecretMaterial{Bytes: data}); err != nil {
		t.Fatal("cannot retain the original owner's returned refresh")
	}
	c.clock.now = c.clock.now.Add(time.Second)
	if future(first.ExpiresAt, c.clock.now) {
		t.Fatal("refresh wait control did not actually pass the old slot expiry")
	}
	// Give the competing transaction time to finish even under the race
	// detector. A deadline alone does not prove serialization: an interrupted
	// faulty transaction may already have overwritten the canonical owner.
	wait, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, err = c.acquire(wait, c.target, selected)
	cancel()
	var waitingOwner bstate.Login
	if readErr := c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Read("login", c.profile.LoginID, &waitingOwner) }); readErr != nil {
		t.Fatal("cannot read actual canonical owner after the competing acquisition")
	}
	clear(waitingOwner.Material)
	if waitingOwner.SlotID != first.ID {
		t.Fatal("competing alias changed the unreleased canonical login owner")
	}
	stageCode(t, err, api.CodeDeadline)
	if err := c.backend.Close(); err != nil {
		t.Fatal("cannot restart the canonical login broker")
	}
	c.backend = openMutationBackend(t, c.directory, c.clock, c.key)
	c.service = reopenLaunchService(t, c)
	var owner bstate.Login
	if err := c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Read("login", c.profile.LoginID, &owner) }); err != nil {
		t.Fatal("cannot reload canonical owner after restart")
	}
	defer clear(owner.Material)
	if owner.SlotID != first.ID {
		t.Fatal("restart or expiry freed a canonical owner without measured release")
	}
	if err := c.service.Release(context.Background(), first, observation); err != nil {
		t.Fatal("measured old-owner release did not finish canonical refresh")
	}
	second, err := c.acquire(context.Background(), c.target, selected)
	if err != nil || second.ID == first.ID || second.ProfileID != selected.ProfileID {
		t.Fatal("eligible alias did not acquire after the old owner was measured and released")
	}
	slot := readCaseSlot(t, c, second.ID)
	defer clear(slot.Material)
	if !bytes.Equal(slot.Material, data) || slot.LoginID != c.profile.LoginID {
		t.Fatal("canonical alias copied stale pre-refresh credential bytes")
	}
}

func TestRefreshFieldGuards(t *testing.T) {
	for _, fault := range []string{"identity", "unknown", "removed", "token-type", "expiry", "expired", "owner", "generation"} {
		t.Run(fault, func(t *testing.T) {
			c := newLaunchCase(t, "file_login")
			slot, err := c.acquire(context.Background(), c.target, c.grant)
			if err != nil {
				t.Fatal("cannot acquire refresh field control")
			}
			injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
			if err != nil {
				t.Fatal("cannot prepare refresh field control")
			}
			c.bind(t, slot, injection)
			var returned map[string]any
			if err := json.Unmarshal(c.material, &returned); err != nil {
				t.Fatal("cannot decode returned refresh control")
			}
			code := api.CodeForbidden
			switch fault {
			case "identity":
				returned["account_id"] = "changed-account"
			case "unknown":
				returned["unsupported"] = "changed"
			case "removed":
				delete(returned, "account_id")
			case "token-type":
				returned["refresh_token"] = 7
			case "expiry":
				returned["expires_at"] = "invalid-time"
			case "expired":
				returned["expires_at"] = c.clock.now.Format(time.RFC3339Nano)
			case "owner":
				if err := c.backend.WithBroker(context.Background(), func(j bstate.Journal) error {
					var owner bstate.Login
					if err := j.Read("login", c.profile.LoginID, &owner); err != nil {
						return err
					}
					defer clear(owner.Material)
					owner.SlotID = "foreign-slot"
					return j.Write("login", owner.ID, owner)
				}); err != nil {
					t.Fatal("cannot change canonical owner control")
				}
				code = api.CodeConflict
			case "generation":
				profile := c.profile
				profile.Generation++
				if err := c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Write("profile", profile.ID, profile) }); err != nil {
					t.Fatal("cannot change refresh generation control")
				}
				code = api.CodeConflict
			}
			data, err := json.Marshal(returned)
			if err != nil {
				t.Fatal("cannot encode returned refresh control")
			}
			stageCode(t, c.service.ReturnSlot(context.Background(), "launch-a", slot.ID, api.SecretMaterial{Bytes: data}), code)
		})
	}
}

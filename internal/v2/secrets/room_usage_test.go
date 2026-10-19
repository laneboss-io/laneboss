package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

// These are post-authentication consumer fixtures. The provider command reads
// the actual TSV file through a bounded child process; no native authentication
// or installed-service acceptance is inferred from the component principals.
func TestRoomUsesFreshUsage(t *testing.T) {
	c, job := newUsageCase(t)
	room, err := c.service.Room(context.Background(), c.grant)
	if err != nil || room.Available || job.starts != 1 || job.runs != 1 {
		t.Fatal("room reused the initial available observation instead of measuring exhausted provider usage", err)
	}
	if room.CheckedAt != job.output.ObservedAt || room.Evidence.ID == c.profile.Evidence.ID {
		t.Fatal("room has no fresh outside observation provenance")
	}
	var principal api.WorkerPrincipal
	if err := c.store.read("usage-principal.json", &principal); err != nil {
		t.Fatal(err)
	}
	if _, err := c.service.readRoomObject(context.Background(), room.Evidence, principal, c.target.LifeID); err != nil {
		t.Fatal("room evidence did not retain actual measured bytes", err)
	}
}

func TestRoomUsageFailureStops(t *testing.T) {
	c, job := newUsageCase(t)
	job.runErr = &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-secrets", Message: "provider command failed"}
	room, err := c.service.Room(context.Background(), c.grant)
	if err == nil || room.Evidence.ID != "" || room.Available {
		t.Fatal("room converted a failed outside query into initial availability")
	}
}

func (f *launchCaseStore) Lanes(ctx context.Context, scope api.Scope, q api.ListRequest) (api.LanePage, error) {
	if err := ctx.Err(); err != nil {
		return api.LanePage{}, err
	}
	page := api.LanePage{Lanes: []api.Lane{}}
	if f.lane != nil && (q.LifeID == "" || q.LifeID == f.lane.LifeID) {
		page.Lanes = append(page.Lanes, *f.lane)
	}
	return page, nil
}

func TestRoomRestorationAndSelection(t *testing.T) {
	c, job := newRoomCase(t)
	// A distinct protected vendor profile is measured using the original
	// from-profile's enrolled command, which lists provider-wide profile rows.
	selected := c.store.grants.Profiles[1]
	profile, err := c.service.loadProfile(context.Background(), selected)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := *profile.Usage
	enrolled.VendorProfile = "synthetic-other"
	profile.Usage = &enrolled
	profile.Generation++
	observation := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: "service-case", ProfileID: profile.ID, LoginID: profile.LoginID, Generation: profile.Generation, Driver: profile.Driver, Provider: profile.Provider,
		Available: true, CheckedAt: api.Timestamp(c.clock.now.Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(c.clock.now.Add(3 * time.Minute).Format(time.RFC3339Nano))}
	profile.Evidence = c.store.putObject(t, "other-vendor-enrollment", "credential_evidence", observation, "other-vendor-enrollment-operation")
	if err := c.service.InstallProfile(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	var previous api.BlobRef
	for index, used := range []string{"100", "12.5", "100"} {
		raw := fmt.Sprintf("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n%s\tsynthetic-plan\tcurrent\t100\t%s\n%s\tsynthetic-plan\tcurrent\t%s\t%s\n",
			c.profile.Usage.VendorProfile, roomReset(c.clock.now), profile.Usage.VendorProfile, used, roomReset(c.clock.now))
		if err := os.WriteFile(filepath.Join(c.store.root, "usage.tsv"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		room, err := c.service.Room(context.Background(), selected)
		if err != nil || room.Available != (index == 1) || room.ProfileID != selected.ProfileID || room.Evidence == previous || job.runs != index+1 {
			t.Fatal("room ignored current selected-provider exhaustion/restoration or reused its old job", index, err)
		}
		previous = room.Evidence
		c.clock.now = c.clock.now.Add(2 * time.Second)
	}
}

func TestRoomMalformedSourceStops(t *testing.T) {
	for _, bad := range []string{"unknown", "NaN", "missing", "header", "duplicate", "failed"} {
		t.Run(bad, func(t *testing.T) {
			c, job := newUsageCase(t)
			raw := fmt.Sprintf("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n%s\tplan\tcurrent\t10\t%s\n", c.profile.Usage.VendorProfile, roomReset(c.clock.now))
			switch bad {
			case "unknown":
				job.raw(t, "10", "unknown")
			case "NaN":
				job.raw(t, "NaN", roomReset(c.clock.now))
			case "missing":
				raw = "PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\nother\tplan\tcurrent\t10\t" + roomReset(c.clock.now) + "\n"
			case "header":
				raw = "PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESET\nother\tplan\tcurrent\t10\t" + roomReset(c.clock.now) + "\n"
			case "duplicate":
				raw += raw[len("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n"):]
			case "failed":
				job.output.ExitCode = 1
			}
			if bad != "unknown" && bad != "NaN" {
				if err := os.WriteFile(filepath.Join(c.store.root, "usage.tsv"), []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			room, err := c.service.Room(context.Background(), c.grant)
			if err == nil || room.Evidence.ID != "" || room.Available {
				t.Fatal("room converted failed, missing or ambiguous provider data to availability", err)
			}
		})
	}
}

func roomReset(now time.Time) string { return now.Add(time.Hour).UTC().Format(time.RFC3339Nano) }

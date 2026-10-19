//go:build laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestInitialStandInSelectors(t *testing.T) {
	for _, fault := range []string{"", "configuration", "runtime", "provider", "paid", "duplicate", "missing", "not-stand-in"} {
		t.Run("case-"+fault, func(t *testing.T) {
			runtime, installed, values := runtimeFixture(t)
			declared, err := fixtureFromRuntime(runtime, installed, func(object api.RuntimeObject) ([]byte, error) { return values[object.ID], nil })
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			installed.RuntimeManifest = api.BlobRef{ID: "installed-runtime", Class: "manifest", Bytes: int64(len(raw)), SHA256: api.Digest(hex.EncodeToString(sum[:]))}
			initial := admin.InitialManifest{Config: installed.Config, Runtime: installed.RuntimeManifest}
			planner := &initialFixtureProfiles{installed: installed, fixture: *declared}
			root := api.RootGrantManifest{Profiles: []api.ProfileGrant{}}
			for _, driver := range declared.Drivers {
				root.Profiles = append(root.Profiles, api.ProfileGrant{ProfileID: api.ID("custom-" + string(driver)), Driver: driver, Provider: "serve-fixture", ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))})
			}
			switch fault {
			case "configuration":
				initial.Config = "foreign"
			case "runtime":
				initial.Runtime.ID = "different-runtime"
			case "provider":
				root.Profiles[0].Provider = "foreign-provider"
			case "paid":
				root.Profiles[0].Paid = true
			case "duplicate":
				root.Profiles[1].ProfileID = root.Profiles[0].ProfileID
			case "missing":
				root.Profiles = nil
			case "not-stand-in":
				planner.fixture.VendorStoodIn = false
			}
			profiles, err := planner.PlanStandInProfiles(context.Background(), initial, root)
			if fault != "" {
				if err == nil || profiles != nil {
					t.Fatal("drifted protected stand-in enrollment was accepted")
				}
				return
			}
			if err != nil || len(profiles) != len(root.Profiles) {
				t.Fatal("installed stand-in profiles were not planned", err)
			}
			for index, p := range profiles {
				grant := root.Profiles[index]
				if p.ID != grant.ProfileID || p.Driver != grant.Driver || p.Provider != grant.Provider || p.Config != installed.Config || p.ExpiresAt != grant.ExpiresAt || p.Runtime != declared.Executable || p.Evidence != (api.BlobRef{}) || p.Paid || !reflect.DeepEqual(p.Models, []string{declared.Version}) {
					t.Fatal("stand-in enrollment ignored actual profile selectors or executable pins")
				}
			}
			if profiles[0].LoginID == profiles[1].LoginID || profiles[0].Source.SourceHandle == profiles[1].Source.SourceHandle {
				t.Fatal("different stand-in profiles share a canonical selector")
			}
		})
	}
}

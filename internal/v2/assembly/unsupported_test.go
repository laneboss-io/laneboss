package assembly

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestWrongOSCannotLaunch(t *testing.T) {
	backend, owner := "darwin-seatbelt", "lb-v2-darwin"
	if runtime.GOOS == "darwin" {
		backend, owner = "linux-bwrap-landlock", "lb-v2-linux"
	}
	launcher, err := platformLauncher(nil, api.BlobRef{}, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := launcher.Probe(context.Background())
	if err != nil || probe.Available || probe.Backend != backend || len(probe.Checks) == 0 {
		t.Fatal("wrong-OS diagnostic claimed readiness")
	}
	_, err = launcher.Prepare(context.Background(), api.LaunchSpec{})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnsupported || typed.Owner != owner {
		t.Fatal("wrong-OS preparation did not fail with its backend owner")
	}
}

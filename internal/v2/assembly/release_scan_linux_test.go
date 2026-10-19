//go:build linux

package assembly

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

func TestCredentialReleaseScannerPort(t *testing.T) {
	scanner, ok := any(&credentialRemoteHelper{}).(rscan.APIKeyReleaseScanner)
	if !ok {
		t.Fatal("installed outside broker has no native release scanner")
	}
	a := api.CredentialProjectionAuthority{ID: "scan-authority", Request: api.CredentialProjectionRequest{Prepared: api.PreparedLaunch{Target: api.LifeRef{LifeID: "scan-life", Run: 1}}}}
	native := &rscan.NativeReleaseScan{Authority: a, Cause: api.InternalIntent{Kind: api.InternalHelperRelease, Target: a.Request.Prepared.Target}}
	for i := range native.Scan {
		native.Scan[i].Present, native.Scan[i].Files = true, uint64(i+1)
	}
	material := api.SecretMaterial{Bytes: []byte("synthetic-component-material")}
	ctx := rscan.WithNativeReleaseScan(context.Background(), native)
	actual, err := scanner.ScanAPIKeyRelease(ctx, a, material)
	if err != nil || !reflect.DeepEqual(actual, native.Scan) {
		t.Fatal("outside broker did not consume its exact root scan", err)
	}
	if _, err := scanner.ScanAPIKeyRelease(context.Background(), a, material); err == nil {
		t.Fatal("outside broker accepted an absent root scan")
	}
	a.ID = "foreign-scan-authority"
	if _, err := scanner.ScanAPIKeyRelease(ctx, a, material); err == nil {
		t.Fatal("outside broker accepted another projection's scan")
	}
}

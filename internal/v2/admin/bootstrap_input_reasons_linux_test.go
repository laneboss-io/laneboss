//go:build linux

package admin

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestBootstrapInputReasons(t *testing.T) {
	for _, row := range []struct{ message, reason string }{
		{"runner stdin has no exact committed prompt", "prompt.reference"},
		{"runner stdin is not its sealed read-only prompt", "prompt.seals"},
		{"runner stdin prompt read-back is incomplete", "prompt.read"},
		{"runner stdin prompt digest could not be measured", "prompt.measure"},
		{"runner stdin prompt digest differs", "prompt.digest"},
		{"invalid fixed inherited descriptor inventory", "descriptors.inventory"},
		{"fixed inherited descriptor is unavailable", "descriptors.missing"},
		{"fixed worker socket descriptor type changed", "descriptors.socket"},
		{"fixed inherited input is not exactly sealed", "descriptors.seals"},
		{"fixed inherited descriptor projection changed", "descriptors.projection"},
		{"cannot retain fixed vendor descriptor", "descriptors.retain"},
		{"cannot create bootstrap-only exec proof", "exec_proof.create"},
		{"cannot transfer bootstrap-only exec proof", "exec_proof.transfer"},
	} {
		t.Run(row.reason, func(t *testing.T) {
			if actual := bootstrapErrorReason(failure(api.CodeIntegrity, row.message)); actual != row.reason {
				t.Fatal("acceptance: fixed input refusal lost its closed bootstrap reason")
			}
			if code, found := bootstrapStageCodes[row.reason]; !found || bootstrapExitStage(code) != row.reason {
				t.Fatal("acceptance: fixed input refusal lost its distinct bootstrap exit")
			}
		})
	}
}

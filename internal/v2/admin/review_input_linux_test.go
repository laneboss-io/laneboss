//go:build linux

package admin

import (
	"bytes"
	"io"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestReviewNativeInputSeal(t *testing.T) {
	raw := []byte("{\"schema\":\"laneboss.review-input.v2\",\"nonce\":\"" + string(testDigest(t.Name())) + "\"}\n")
	ref := api.BlobRef{ID: "review-input", Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	file, err := sealWorkerInput(raw, ref)
	if err != nil {
		t.Fatal("fixed review verifier cannot receive its actual manifest input", err)
	}
	defer file.Close()
	actual, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatal("review native input lost its exact original bytes", err)
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&bootstrapSeals != bootstrapSeals {
		t.Fatal("review native input is not immutable", err)
	}
	ref.SHA256 = digestBytes(append(append([]byte{}, raw...), 'x'))
	if changed, err := sealWorkerInput(raw, ref); err == nil {
		changed.Close()
		t.Fatal("review native input accepted a different content pin")
	}
}

//go:build linux

package wire

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestReviewSealedInput(t *testing.T) {
	for _, mode := range []string{"valid", "unsealed", "writable", "digest", "size", "class", "id", "bound"} {
		t.Run(mode, func(t *testing.T) {
			raw := make([]byte, 71)
			if _, err := rand.Read(raw); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.MemfdCreate("review-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "review-input")
			t.Cleanup(func() {
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			})
			if n, err := file.Write(raw); err != nil || n != len(raw) {
				t.Fatal("cannot retain review input bytes", err)
			}
			if mode != "writable" {
				if err := file.Chmod(0444); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "unsealed" {
				const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
				if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
					t.Fatal(err)
				}
			}
			sum := sha256.Sum256(raw)
			ref := api.BlobRef{ID: "review-input", Class: "worker_input", Bytes: int64(len(raw)), SHA256: api.Digest(hex.EncodeToString(sum[:]))}
			switch mode {
			case "digest":
				ref.SHA256 = api.Digest(hex.EncodeToString(make([]byte, 32)))
			case "size":
				ref.Bytes++
			case "class":
				ref.Class = "task"
			case "id":
				ref.ID = "../foreign"
			case "bound":
				ref.Bytes = api.MaxFrameBytes + 1
			}
			for attempt := 0; attempt < 2; attempt++ {
				actual, err := readReviewInputFD(fd, ref)
				if mode == "valid" {
					if err != nil || !bytes.Equal(actual, raw) {
						t.Fatalf("sealed review input lost its exact bytes: %v", err)
					}
				} else if err == nil || len(actual) != 0 {
					t.Fatalf("unsafe review input was returned: %s", mode)
				}
			}
		})
	}
}

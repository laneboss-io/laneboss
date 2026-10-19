//go:build linux

package wire

import (
	"crypto/sha256"
	"encoding/hex"

	"laneboss.io/laneboss/internal/v2/api"
)

// ReadReviewInput uses the fixed inherited input projection. Native endpoint
// authentication remains mandatory; descriptor seals alone confer no identity.
func ReadReviewInput(ref api.BlobRef) ([]byte, error) {
	fd, err := ProjectedDescriptor(WorkerInputPath)
	if err != nil {
		return nil, err
	}
	return readReviewInputFD(fd, ref)
}

func readReviewInputFD(fd int, ref api.BlobRef) ([]byte, error) {
	if !ValidID(string(ref.ID)) || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes ||
		ref.Class != "manifest" && ref.Class != "worker_input" {
		return nil, bindingError("review worker has no exact immutable job input reference")
	}
	data, err := sealedDescriptorBytes(fd)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != ref.Bytes || api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256 {
		return nil, bindingError("inherited review input differs from its authenticated lease")
	}
	return data, nil
}

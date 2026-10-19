package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

// The independent renderer may retain identical bytes under new identities.
// Content equality alone does not attest those objects; read and hash each
// fresh output before queuing publication of the original approved refs.
func (s *Service) verifyRenderedBlobs(ctx context.Context, scope api.Scope, rendered api.ChangeRequest) error {
	if err := s.verifyBlob(ctx, scope, rendered.Diff); err != nil {
		return err
	}
	for _, delta := range rendered.Derived {
		if delta.After != nil {
			if err := s.verifyBlob(ctx, scope, *delta.After); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) verifyBlob(ctx context.Context, scope api.Scope, ref api.BlobRef) (resultErr error) {
	if !validBlob(ref) {
		return invalid("approval blob reference is invalid")
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return err
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return err
	}
	if metadata.Ref != ref || metadata.ACL.Config != scope.Config {
		return integrity("approval blob differs from its committed metadata or configuration")
	}
	hash := sha256.New()
	var offset int64
	// Reading the empty blob once still checks that it exists and is visible;
	// hashing an empty local buffer alone cannot prove a committed upload.
	for {
		if err := contextFailure(ctx); err != nil {
			return err
		}
		limit := int64(api.MaxChunkBytes)
		if remaining := ref.Bytes - offset; remaining < limit && remaining > 0 {
			limit = remaining
		}
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{
			ObjectID: ref.ID, Offset: offset, Limit: int(limit),
		})
		if err != nil {
			return err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != offset || int64(len(chunk.Data)) > limit ||
			int64(len(chunk.Data)) > ref.Bytes-offset {
			return integrity("retained approval blob has an inconsistent identity, offset or size")
		}
		sum := sha256.Sum256(chunk.Data)
		if api.Digest(hex.EncodeToString(sum[:])) != chunk.SHA256 {
			return integrity("retained approval blob chunk hash does not match")
		}
		if len(chunk.Data) == 0 && offset < ref.Bytes {
			return integrity("retained approval blob ended before its declared length")
		}
		// hash.Hash.Write cannot fail; the size is bounded before writing.
		_, err = hash.Write(chunk.Data)
		if err != nil {
			return integrity("approval hash computation failed")
		}
		offset += int64(len(chunk.Data))
		if offset == ref.Bytes {
			break
		}
	}
	if api.Digest(hex.EncodeToString(hash.Sum(nil))) != ref.SHA256 {
		return integrity("retained approval blob hash does not match its reference")
	}
	if ref.Bytes > 0 {
		if err := contextFailure(ctx); err != nil {
			return err
		}
		// BlobRead has no total-size metadata. Probe EOF so a caller cannot
		// describe a real committed object's prefix as a different full blob.
		tail, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: ref.Bytes, Limit: 1})
		if err != nil {
			return err
		}
		empty := sha256.Sum256(nil)
		if tail.ObjectID != ref.ID || tail.Offset != ref.Bytes || len(tail.Data) != 0 ||
			tail.SHA256 != api.Digest(hex.EncodeToString(empty[:])) {
			return integrity("retained approval blob exceeds its declared length or has invalid EOF metadata")
		}
	}
	return contextFailure(ctx)
}
